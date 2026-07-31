from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import UTC, datetime
from typing import cast

import pytest

from assurance_lab.runtime.postgres import (
    RuntimeCatalogConflict,
    RuntimeCatalogError,
    RuntimeCatalogIntegrityError,
    RuntimeCatalogNotFound,
    RuntimeCatalogOutcomeUnknown,
)
from assurance_lab.runtime.worker import (
    RuntimeWorkerEvent,
    RuntimeWorkerEventSink,
    TenantRuntimeWorker,
)


class _Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


class _Waiter:
    def __init__(
        self,
        clock: _Clock,
        *,
        stop_after: int | None = None,
    ) -> None:
        self.clock = clock
        self.stop_after = stop_after
        self.delays: list[float] = []

    def wait(self, stop_event: threading.Event, delay_seconds: float) -> bool:
        self.delays.append(delay_seconds)
        self.clock.value += delay_seconds
        if self.stop_after is not None and len(self.delays) >= self.stop_after:
            stop_event.set()
        return stop_event.is_set()


class _Materializer:
    def __init__(self, outcomes: list[int | Exception] | None = None) -> None:
        self.outcomes = list(outcomes or [0])
        self.calls: list[tuple[str, object]] = []

    def materialize_due_runs(
        self,
        *,
        tenant_id: str,
        through: datetime | None = None,
    ) -> int:
        self.calls.append((tenant_id, through))
        outcome = self.outcomes.pop(0) if len(self.outcomes) > 1 else self.outcomes[0]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class _Scheduler:
    def __init__(
        self,
        outcomes: list[object | Exception | None] | None = None,
        *,
        before_return: Callable[[], None] | None = None,
    ) -> None:
        self.outcomes = list(outcomes or [None])
        self.before_return = before_return
        self.calls = 0

    def run_once(self) -> object | None:
        self.calls += 1
        outcome = self.outcomes.pop(0) if len(self.outcomes) > 1 else self.outcomes[0]
        if self.before_return is not None:
            self.before_return()
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _worker(
    materializer: _Materializer,
    scheduler: _Scheduler,
    clock: _Clock,
    waiter: _Waiter,
    *,
    max_runs_per_cycle: int = 32,
    materialization_interval_seconds: float = 30.0,
    idle_poll_seconds: float = 2.0,
    backoff_base_seconds: float = 1.0,
    backoff_max_seconds: float = 60.0,
    event_sink: Callable[[RuntimeWorkerEvent], None] | None = None,
) -> TenantRuntimeWorker:
    return TenantRuntimeWorker(
        materializer,
        scheduler,
        tenant_id="tenant-a",
        max_runs_per_cycle=max_runs_per_cycle,
        materialization_interval_seconds=materialization_interval_seconds,
        idle_poll_seconds=idle_poll_seconds,
        backoff_base_seconds=backoff_base_seconds,
        backoff_max_seconds=backoff_max_seconds,
        event_sink=cast(RuntimeWorkerEventSink | None, event_sink),
        monotonic=clock,
        now=lambda: datetime(2026, 7, 29, 1, 2, 3, tzinfo=UTC),
        waiter=waiter,
    )


def test_idle_worker_materializes_immediately_and_stops_interruptibly() -> None:
    clock = _Clock()
    waiter = _Waiter(clock, stop_after=1)
    materializer = _Materializer([3])
    scheduler = _Scheduler([None])
    events: list[RuntimeWorkerEvent] = []
    worker = _worker(
        materializer,
        scheduler,
        clock,
        waiter,
        event_sink=events.append,
    )

    worker.run_forever()

    assert materializer.calls == [("tenant-a", None)]
    assert scheduler.calls == 1
    assert waiter.delays == [2.0]
    assert [event.code for event in events] == [
        "worker-started",
        "materialization-completed",
        "worker-idle",
        "worker-stopped",
    ]
    status = worker.status()
    assert status.state == "stopped"
    assert status.materializations == 1
    assert status.materialized_runs == 3
    assert status.idle_cycles == 1
    assert status.stop_requested is True


def test_burst_limit_rechecks_outer_cycle_without_idle_sleep() -> None:
    clock = _Clock()
    waiter = _Waiter(clock, stop_after=1)
    materializer = _Materializer([0])
    scheduler = _Scheduler([object(), object(), object(), object(), object(), None])
    events: list[RuntimeWorkerEvent] = []
    worker = _worker(
        materializer,
        scheduler,
        clock,
        waiter,
        max_runs_per_cycle=2,
        event_sink=events.append,
    )

    worker.run_forever()

    assert scheduler.calls == 6
    assert [event.value for event in events if event.code == "burst-completed"] == [
        2,
        2,
        1,
    ]
    assert waiter.delays == [2.0]
    assert worker.status().runs_processed == 5
    assert worker.status().cycles == 3


def test_periodic_materialization_uses_database_authoritative_horizon() -> None:
    clock = _Clock()
    waiter = _Waiter(clock, stop_after=4)
    materializer = _Materializer([0])
    scheduler = _Scheduler([None])
    worker = _worker(
        materializer,
        scheduler,
        clock,
        waiter,
        materialization_interval_seconds=5,
        idle_poll_seconds=2,
    )

    worker.run_forever()

    assert materializer.calls == [("tenant-a", None), ("tenant-a", None)]
    assert waiter.delays == [2.0, 2.0, 1.0, 2.0]
    assert worker.status().materializations == 2


def test_stop_during_active_run_drains_it_without_a_new_claim() -> None:
    clock = _Clock()
    waiter = _Waiter(clock)
    materializer = _Materializer([0])
    holder: dict[str, TenantRuntimeWorker] = {}
    scheduler = _Scheduler(
        [object(), object()],
        before_return=lambda: holder["worker"].request_stop(),
    )
    worker = _worker(materializer, scheduler, clock, waiter)
    holder["worker"] = worker

    worker.run_forever()

    assert scheduler.calls == 1
    assert waiter.delays == []
    assert worker.status().runs_processed == 1
    assert worker.status().state == "stopped"


def test_stop_before_start_performs_no_catalog_operation() -> None:
    clock = _Clock()
    waiter = _Waiter(clock)
    materializer = _Materializer([0])
    scheduler = _Scheduler([None])
    worker = _worker(materializer, scheduler, clock, waiter)

    worker.request_stop()
    worker.run_forever()

    assert materializer.calls == []
    assert scheduler.calls == 0
    assert worker.status().state == "stopped"


def test_transient_catalog_errors_recover_with_exponential_backoff() -> None:
    clock = _Clock()
    waiter = _Waiter(clock, stop_after=3)
    materializer = _Materializer(
        [
            RuntimeCatalogOutcomeUnknown("ambiguous"),
            RuntimeCatalogError("database unavailable"),
            2,
        ]
    )
    scheduler = _Scheduler([None])
    events: list[RuntimeWorkerEvent] = []
    worker = _worker(
        materializer,
        scheduler,
        clock,
        waiter,
        backoff_base_seconds=1,
        backoff_max_seconds=8,
        event_sink=events.append,
    )

    worker.run_forever()

    assert waiter.delays == [1.0, 2.0, 2.0]
    assert [event.code for event in events if event.code.startswith("catalog-")] == [
        "catalog-outcome-unknown",
        "catalog-unavailable",
    ]
    status = worker.status()
    assert status.transient_failures == 2
    assert status.consecutive_failures == 0
    assert status.materializations == 1
    assert status.materialized_runs == 2


def test_scheduler_catalog_error_uses_same_retry_policy() -> None:
    clock = _Clock()
    waiter = _Waiter(clock, stop_after=2)
    materializer = _Materializer([0])
    scheduler = _Scheduler([RuntimeCatalogError("offline"), None])
    worker = _worker(materializer, scheduler, clock, waiter)

    worker.run_forever()

    assert scheduler.calls == 2
    assert waiter.delays == [1.0, 2.0]
    assert worker.status().transient_failures == 1


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (RuntimeCatalogConflict("conflict"), "worker-fatal-conflict"),
        (RuntimeCatalogIntegrityError("integrity"), "worker-fatal-integrity"),
        (RuntimeCatalogNotFound("missing"), "worker-fatal-not-found"),
        (ValueError("programmer defect"), "worker-fatal-unexpected"),
    ],
)
def test_integrity_and_programmer_errors_fail_fast(
    error: Exception,
    code: str,
) -> None:
    clock = _Clock()
    waiter = _Waiter(clock)
    materializer = _Materializer([error])
    scheduler = _Scheduler([None])
    worker = _worker(materializer, scheduler, clock, waiter)

    with pytest.raises(type(error)):
        worker.run_forever()

    assert waiter.delays == []
    status = worker.status()
    assert status.state == "failed"
    assert status.fatal_code == code


def test_event_sink_failure_is_counted_and_never_breaks_work() -> None:
    clock = _Clock()
    waiter = _Waiter(clock, stop_after=1)
    materializer = _Materializer([1])
    scheduler = _Scheduler([object(), None])

    def broken_sink(_event: RuntimeWorkerEvent) -> None:
        raise RuntimeError("telemetry backend rejected event")

    worker = _worker(
        materializer,
        scheduler,
        clock,
        waiter,
        event_sink=broken_sink,
    )

    worker.run_forever()

    status = worker.status()
    assert status.state == "stopped"
    assert status.runs_processed == 1
    assert status.event_sink_failures == 5
    assert status.fatal_code is None


def test_event_payload_is_bounded_and_does_not_include_exception_text() -> None:
    clock = _Clock()
    waiter = _Waiter(clock, stop_after=1)
    secret = "do-not-export-this-database-password"
    materializer = _Materializer([RuntimeCatalogError(secret)])
    scheduler = _Scheduler([None])
    events: list[RuntimeWorkerEvent] = []
    worker = _worker(
        materializer,
        scheduler,
        clock,
        waiter,
        event_sink=events.append,
    )

    worker.run_forever()

    rendered = repr(events)
    assert secret not in rendered
    assert events[-2].code == "catalog-unavailable"
