"""Tenant-scoped, interruptible runtime worker service."""

from __future__ import annotations

import math
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol

from assurance_lab.runtime.postgres import (
    RuntimeCatalogConflict,
    RuntimeCatalogError,
    RuntimeCatalogIntegrityError,
    RuntimeCatalogNotFound,
    RuntimeCatalogOutcomeUnknown,
)

WorkerState = Literal[
    "created",
    "running",
    "backoff",
    "stopping",
    "stopped",
    "failed",
]
WorkerEventCode = Literal[
    "worker-started",
    "materialization-completed",
    "burst-completed",
    "worker-idle",
    "catalog-outcome-unknown",
    "catalog-unavailable",
    "worker-fatal-conflict",
    "worker-fatal-integrity",
    "worker-fatal-not-found",
    "worker-fatal-unexpected",
    "worker-stopped",
]

_TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")
_MAX_COUNTER = 2**63 - 1


def _system_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


class RuntimeMaterializer(Protocol):
    """Database-authoritative due-run materialization surface."""

    def materialize_due_runs(
        self,
        *,
        tenant_id: str,
        through: datetime | None = None,
    ) -> int: ...


class RuntimeRunOnce(Protocol):
    """At-most-one-run scheduler surface."""

    def run_once(self) -> object | None: ...


class InterruptibleWaiter(Protocol):
    """Wait surface retained as a seam for deterministic service tests."""

    def wait(self, stop_event: threading.Event, delay_seconds: float) -> bool:
        """Return true when the stop event interrupted the wait."""


class _EventWaiter:
    __slots__ = ()

    def wait(self, stop_event: threading.Event, delay_seconds: float) -> bool:
        return stop_event.wait(delay_seconds)


@dataclass(frozen=True, slots=True)
class RuntimeWorkerEvent:
    """Bounded, secret-free event safe for operational telemetry."""

    sequence: int
    observed_at: datetime
    tenant_id: str
    code: WorkerEventCode
    value: int | None = None

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or not 1 <= self.sequence <= _MAX_COUNTER:
            raise ValueError("worker event sequence is invalid")
        if (
            self.observed_at.tzinfo is None
            or self.observed_at.utcoffset() is None
            or self.observed_at.microsecond != 0
        ):
            raise ValueError("worker event time must be second-precision timezone-aware")
        if _TENANT_RE.fullmatch(self.tenant_id) is None:
            raise ValueError("worker event tenant id is invalid")
        if self.value is not None and (
            type(self.value) is not int or not 0 <= self.value <= _MAX_COUNTER
        ):
            raise ValueError("worker event value is invalid")


class RuntimeWorkerEventSink(Protocol):
    """Non-authoritative telemetry sink."""

    def __call__(self, event: RuntimeWorkerEvent) -> None: ...


@dataclass(frozen=True, slots=True)
class RuntimeWorkerStatus:
    """Atomic, secret-free worker status snapshot."""

    tenant_id: str
    state: WorkerState
    stop_requested: bool
    run_in_progress: bool
    cycles: int
    materializations: int
    materialized_runs: int
    runs_processed: int
    idle_cycles: int
    transient_failures: int
    consecutive_failures: int
    event_sink_failures: int
    current_backoff_seconds: float
    last_event_code: WorkerEventCode | None
    fatal_code: WorkerEventCode | None


class TenantRuntimeWorker:
    """Continuously materialize and execute work for exactly one tenant.

    The service drains the currently executing ``run_once`` call after a stop
    request, but checks the stop event before every subsequent claim.  Catalog
    availability and ambiguous-outcome errors receive bounded exponential
    backoff.  Persisted-state conflicts, missing identities, integrity failures,
    and unknown exceptions escape immediately.
    """

    __slots__ = (
        "_backoff_base_seconds",
        "_backoff_max_seconds",
        "_claim_in_progress",
        "_consecutive_failures",
        "_current_backoff_seconds",
        "_cycles",
        "_event_sequence",
        "_event_sink",
        "_event_sink_failures",
        "_fatal_code",
        "_idle_cycles",
        "_idle_poll_seconds",
        "_last_event_code",
        "_lock",
        "_materialization_interval_seconds",
        "_materializations",
        "_materialized_runs",
        "_materializer",
        "_max_runs_per_cycle",
        "_monotonic",
        "_now",
        "_run_once",
        "_running",
        "_runs_processed",
        "_state",
        "_stop_event",
        "_tenant_id",
        "_transient_failures",
        "_waiter",
    )

    def __init__(
        self,
        materializer: RuntimeMaterializer,
        scheduler: RuntimeRunOnce,
        *,
        tenant_id: str,
        max_runs_per_cycle: int = 32,
        materialization_interval_seconds: float = 30.0,
        idle_poll_seconds: float = 2.0,
        backoff_base_seconds: float = 1.0,
        backoff_max_seconds: float = 60.0,
        event_sink: RuntimeWorkerEventSink | None = None,
        monotonic: Callable[[], float] | None = None,
        now: Callable[[], datetime] | None = None,
        waiter: InterruptibleWaiter | None = None,
    ) -> None:
        if not callable(getattr(materializer, "materialize_due_runs", None)):
            raise TypeError("runtime materializer must implement materialize_due_runs()")
        if not callable(getattr(scheduler, "run_once", None)):
            raise TypeError("runtime scheduler must implement run_once()")
        if _TENANT_RE.fullmatch(tenant_id) is None:
            raise ValueError("runtime worker tenant id is invalid")
        if (
            type(max_runs_per_cycle) is not int
            or max_runs_per_cycle < 1
            or max_runs_per_cycle > 1_000
        ):
            raise ValueError("runtime worker burst limit is invalid")
        for label, value, minimum, maximum in (
            (
                "materialization interval",
                materialization_interval_seconds,
                0.1,
                86_400.0,
            ),
            ("idle poll interval", idle_poll_seconds, 0.01, 300.0),
            ("backoff base", backoff_base_seconds, 0.01, 300.0),
            ("backoff maximum", backoff_max_seconds, 0.01, 3_600.0),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int | float)
                or not math.isfinite(float(value))
                or not minimum <= float(value) <= maximum
            ):
                raise ValueError(f"runtime worker {label} is invalid")
        if float(backoff_max_seconds) < float(backoff_base_seconds):
            raise ValueError("runtime worker backoff maximum is below its base")
        if event_sink is not None and not callable(event_sink):
            raise TypeError("runtime worker event sink must be callable")
        if monotonic is not None and not callable(monotonic):
            raise TypeError("runtime worker monotonic clock must be callable")
        if now is not None and not callable(now):
            raise TypeError("runtime worker wall clock must be callable")
        if waiter is not None and not callable(getattr(waiter, "wait", None)):
            raise TypeError("runtime worker waiter must implement wait()")

        self._materializer = materializer
        self._run_once = scheduler
        self._tenant_id = tenant_id
        self._max_runs_per_cycle = max_runs_per_cycle
        self._materialization_interval_seconds = float(
            materialization_interval_seconds
        )
        self._idle_poll_seconds = float(idle_poll_seconds)
        self._backoff_base_seconds = float(backoff_base_seconds)
        self._backoff_max_seconds = float(backoff_max_seconds)
        self._event_sink = event_sink
        self._monotonic = monotonic or time.monotonic
        self._now = now or _system_now
        self._waiter = waiter or _EventWaiter()
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._running = False
        self._claim_in_progress = False
        self._state: WorkerState = "created"
        self._cycles = 0
        self._materializations = 0
        self._materialized_runs = 0
        self._runs_processed = 0
        self._idle_cycles = 0
        self._transient_failures = 0
        self._consecutive_failures = 0
        self._event_sink_failures = 0
        self._current_backoff_seconds = 0.0
        self._event_sequence = 0
        self._last_event_code: WorkerEventCode | None = None
        self._fatal_code: WorkerEventCode | None = None

    def request_stop(self) -> None:
        """Request graceful drain and interrupt any current idle/backoff wait."""

        with self._lock:
            self._stop_event.set()
            if self._state in {"running", "backoff"}:
                self._state = "stopping"

    def status(self) -> RuntimeWorkerStatus:
        """Return one lock-consistent status snapshot."""

        with self._lock:
            return RuntimeWorkerStatus(
                tenant_id=self._tenant_id,
                state=self._state,
                stop_requested=self._stop_event.is_set(),
                run_in_progress=self._claim_in_progress,
                cycles=self._cycles,
                materializations=self._materializations,
                materialized_runs=self._materialized_runs,
                runs_processed=self._runs_processed,
                idle_cycles=self._idle_cycles,
                transient_failures=self._transient_failures,
                consecutive_failures=self._consecutive_failures,
                event_sink_failures=self._event_sink_failures,
                current_backoff_seconds=self._current_backoff_seconds,
                last_event_code=self._last_event_code,
                fatal_code=self._fatal_code,
            )

    def _observed_at(self) -> datetime:
        value = self._now()
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise RuntimeError("runtime worker wall clock returned invalid time")
        return value.astimezone(UTC).replace(microsecond=0)

    def _emit(self, code: WorkerEventCode, *, value: int | None = None) -> None:
        with self._lock:
            self._event_sequence += 1
            sequence = self._event_sequence
            self._last_event_code = code
        sink = self._event_sink
        if sink is None:
            return
        event = RuntimeWorkerEvent(
            sequence=sequence,
            observed_at=self._observed_at(),
            tenant_id=self._tenant_id,
            code=code,
            value=value,
        )
        try:
            sink(event)
        except Exception:
            with self._lock:
                self._event_sink_failures += 1

    def _set_running(self) -> None:
        with self._lock:
            if not self._stop_event.is_set():
                self._state = "running"
            self._consecutive_failures = 0
            self._current_backoff_seconds = 0.0

    def _transient_backoff(self, code: WorkerEventCode) -> float:
        with self._lock:
            self._transient_failures += 1
            self._consecutive_failures += 1
            exponent = min(self._consecutive_failures - 1, 30)
            delay = float(
                min(
                    self._backoff_base_seconds * (2**exponent),
                    self._backoff_max_seconds,
                )
            )
            self._current_backoff_seconds = delay
            self._state = "stopping" if self._stop_event.is_set() else "backoff"
        self._emit(code, value=round(delay * 1_000))
        return delay

    def _mark_fatal(self, code: WorkerEventCode) -> None:
        with self._lock:
            self._state = "failed"
            self._fatal_code = code
            self._current_backoff_seconds = 0.0
        self._emit(code)

    @staticmethod
    def _fatal_code_for(error: Exception) -> WorkerEventCode:
        if isinstance(error, RuntimeCatalogConflict):
            return "worker-fatal-conflict"
        if isinstance(error, RuntimeCatalogIntegrityError):
            return "worker-fatal-integrity"
        if isinstance(error, RuntimeCatalogNotFound):
            return "worker-fatal-not-found"
        return "worker-fatal-unexpected"

    def _wait(self, delay: float) -> bool:
        return self._waiter.wait(self._stop_event, delay)

    def _invoke_run_once(self) -> tuple[bool, object | None]:
        """Linearize a claim attempt against ``request_stop``."""

        with self._lock:
            if self._stop_event.is_set():
                return False, None
            self._claim_in_progress = True
        try:
            return True, self._run_once.run_once()
        finally:
            with self._lock:
                self._claim_in_progress = False

    def run_forever(self) -> None:
        """Run until stopped, or raise immediately on a fatal condition."""

        with self._lock:
            if self._running:
                raise RuntimeError("runtime worker is already running")
            if self._state not in {"created", "stopped"}:
                raise RuntimeError("runtime worker cannot be restarted from this state")
            self._running = True
            self._state = "stopping" if self._stop_event.is_set() else "running"

        next_materialization_at = self._monotonic()
        try:
            self._emit("worker-started")
            while not self._stop_event.is_set():
                with self._lock:
                    self._cycles += 1
                try:
                    if self._monotonic() >= next_materialization_at:
                        created = self._materializer.materialize_due_runs(
                            tenant_id=self._tenant_id,
                            through=None,
                        )
                        if (
                            type(created) is not int
                            or created < 0
                            or created > _MAX_COUNTER
                        ):
                            raise RuntimeError(
                                "runtime materializer returned an invalid count"
                            )
                        with self._lock:
                            self._materializations += 1
                            self._materialized_runs += created
                        self._set_running()
                        self._emit("materialization-completed", value=created)
                        next_materialization_at = (
                            self._monotonic()
                            + self._materialization_interval_seconds
                        )

                    processed = 0
                    idle = False
                    while (
                        processed < self._max_runs_per_cycle
                        and not self._stop_event.is_set()
                    ):
                        started, result = self._invoke_run_once()
                        if not started:
                            break
                        self._set_running()
                        if result is None:
                            idle = True
                            break
                        processed += 1
                        with self._lock:
                            self._runs_processed += 1
                    if processed:
                        self._emit("burst-completed", value=processed)
                    if self._stop_event.is_set():
                        break
                    if processed == self._max_runs_per_cycle:
                        continue
                    if idle:
                        with self._lock:
                            self._idle_cycles += 1
                        self._emit("worker-idle")
                    until_materialization = max(
                        0.0,
                        next_materialization_at - self._monotonic(),
                    )
                    delay = min(self._idle_poll_seconds, until_materialization)
                    if delay > 0 and self._wait(delay):
                        break
                except (
                    RuntimeCatalogConflict,
                    RuntimeCatalogIntegrityError,
                    RuntimeCatalogNotFound,
                ):
                    raise
                except RuntimeCatalogOutcomeUnknown:
                    delay = self._transient_backoff("catalog-outcome-unknown")
                    if self._stop_event.is_set() or self._wait(delay):
                        break
                except RuntimeCatalogError:
                    delay = self._transient_backoff("catalog-unavailable")
                    if self._stop_event.is_set() or self._wait(delay):
                        break
        except Exception as exc:
            self._mark_fatal(self._fatal_code_for(exc))
            raise
        else:
            with self._lock:
                self._state = "stopped"
                self._current_backoff_seconds = 0.0
            self._emit("worker-stopped")
        finally:
            with self._lock:
                self._running = False
