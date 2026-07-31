"""Deterministic UTC window derivation and one-run reconciliation."""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Protocol

from assurance_lab.control_plane.models import ControlConfiguration
from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.runtime.models import (
    ControlRun,
    ControlRunExecutionError,
    ControlRunExecutionRequest,
    ControlRunExecutionResult,
    ControlRunExecutor,
    ControlRunOutcomeUnknown,
    RegisteredControlProfile,
    RuntimeWorkerIdentity,
    sha256_digest,
    utc_second,
)


def _ceil_div(value: int, divisor: int) -> int:
    return -(-value // divisor)


def due_window_ends(
    configuration: ControlConfiguration,
    *,
    applied_at: datetime,
    superseded_at: datetime | None,
    through: datetime,
    limit: int = 10_000,
) -> tuple[datetime, ...]:
    """Return deterministic window ends for one deployment validity interval.

    Every returned half-open window ``[end-window_seconds, end)`` is wholly
    inside ``[applied_at, superseded_at)``.  A window is due only after its
    configured collection lag.  UTC Unix-epoch boundaries are the sole anchor.
    """

    applied = utc_second(applied_at, label="deployment application time")
    horizon = utc_second(through, label="materialization horizon")
    superseded = (
        None
        if superseded_at is None
        else utc_second(superseded_at, label="deployment supersession time")
    )
    if superseded is not None and superseded <= applied:
        raise ValueError("deployment validity interval must be non-empty")
    if type(limit) is not int or limit < 1 or limit > 100_000:
        raise ValueError("window materialization limit is invalid")
    if not configuration.enabled:
        return ()
    schedule = configuration.schedule
    interval = schedule.interval_seconds
    window = schedule.window_seconds
    lag = schedule.collection_lag_seconds
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    applied_seconds = int((applied - epoch).total_seconds())
    horizon_seconds = int((horizon - epoch).total_seconds())
    first_end = _ceil_div(applied_seconds + window, interval) * interval
    last_end = ((horizon_seconds - lag) // interval) * interval
    if superseded is not None:
        superseded_seconds = int((superseded - epoch).total_seconds())
        last_end = min(last_end, (superseded_seconds // interval) * interval)
    if last_end < first_end:
        return ()
    count = ((last_end - first_end) // interval) + 1
    if count > limit:
        raise ValueError("due window count exceeds the bounded materialization limit")
    return tuple(
        epoch + timedelta(seconds=first_end + (index * interval))
        for index in range(count)
    )


class RuntimeSchedulerStore(Protocol):
    """Persistence surface used by :class:`RuntimeScheduler`."""

    def claim_next_run(
        self,
        *,
        worker: RuntimeWorkerIdentity,
        lease_token_digest: str,
        leased_at: datetime,
        lease_ttl_seconds: int,
    ) -> ControlRun | None: ...

    def configuration_bytes_for_run(
        self,
        *,
        tenant_id: str,
        run_id: str,
    ) -> bytes: ...

    def control_profile(
        self,
        *,
        tenant_id: str,
        profile_digest: str,
    ) -> RegisteredControlProfile: ...

    def complete_run(
        self,
        *,
        worker: RuntimeWorkerIdentity,
        run_id: str,
        lease_token_digest: str,
        lease_fence: int,
        result: ControlRunExecutionResult,
        completed_at: datetime,
    ) -> ControlRun: ...

    def fail_run(
        self,
        *,
        worker: RuntimeWorkerIdentity,
        run_id: str,
        lease_token_digest: str,
        lease_fence: int,
        failure_digest: str,
        failed_at: datetime,
        retry_at: datetime | None,
    ) -> ControlRun: ...


def _system_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _failure_digest(
    run: ControlRun,
    *,
    code: str,
    retryable: bool,
) -> str:
    return sha256_digest(
        canonical_json_bytes(
            {
                "attempt_count": run.attempt_count,
                "code": code,
                "lease_fence": run.lease_fence,
                "retryable": retryable,
                "run_id": run.run_id,
            }
        )
    )


class RuntimeScheduler:
    """Claim, execute, and close at most one deterministic run."""

    __slots__ = (
        "_base_retry_seconds",
        "_executor",
        "_lease_ttl_seconds",
        "_max_attempts",
        "_max_retry_seconds",
        "_now",
        "_store",
        "_token_bytes",
        "_worker",
    )

    def __init__(
        self,
        store: RuntimeSchedulerStore,
        executor: ControlRunExecutor,
        worker: RuntimeWorkerIdentity,
        *,
        now: Callable[[], datetime] | None = None,
        token_bytes: Callable[[int], bytes] | None = None,
        lease_ttl_seconds: int = 300,
        max_attempts: int = 8,
        base_retry_seconds: int = 30,
        max_retry_seconds: int = 3_600,
    ) -> None:
        required = (
            "claim_next_run",
            "complete_run",
            "configuration_bytes_for_run",
            "control_profile",
            "fail_run",
        )
        if any(not callable(getattr(store, name, None)) for name in required):
            raise TypeError("runtime store does not implement scheduler persistence")
        if not callable(getattr(executor, "ensure_executed", None)):
            raise TypeError("runtime executor must implement ensure_executed()")
        if (
            type(lease_ttl_seconds) is not int
            or lease_ttl_seconds < 15
            or lease_ttl_seconds > 3_600
        ):
            raise ValueError("run lease TTL is outside the supported range")
        if type(max_attempts) is not int or max_attempts < 1 or max_attempts > 32:
            raise ValueError("run attempt limit is outside the supported range")
        persisted_attempt_limit = getattr(store, "max_run_attempts", max_attempts)
        if (
            type(persisted_attempt_limit) is not int
            or persisted_attempt_limit != max_attempts
        ):
            raise ValueError(
                "scheduler and runtime store must use the same run attempt limit"
            )
        if (
            type(base_retry_seconds) is not int
            or type(max_retry_seconds) is not int
            or base_retry_seconds < 1
            or max_retry_seconds < base_retry_seconds
            or max_retry_seconds > 86_400
        ):
            raise ValueError("run retry backoff is outside the supported range")
        self._store = store
        self._executor = executor
        self._worker = worker
        self._now = now or _system_now
        self._token_bytes = token_bytes or secrets.token_bytes
        self._lease_ttl_seconds = lease_ttl_seconds
        self._max_attempts = max_attempts
        self._base_retry_seconds = base_retry_seconds
        self._max_retry_seconds = max_retry_seconds

    def _time(self) -> datetime:
        return utc_second(self._now(), label="scheduler clock")

    def _token_digest(self) -> str:
        token = self._token_bytes(32)
        if type(token) is not bytes or len(token) < 16:
            raise RuntimeError("run lease entropy source returned invalid bytes")
        return f"sha256:{hashlib.sha256(token).hexdigest()}"

    def _fail(
        self,
        run: ControlRun,
        *,
        lease_token_digest: str,
        code: str,
        retryable: bool,
    ) -> ControlRun:
        failed_at = self._time()
        can_retry = retryable and run.attempt_count < self._max_attempts
        retry_at: datetime | None = None
        if can_retry:
            exponent = min(run.attempt_count - 1, 30)
            delay = min(
                self._base_retry_seconds * (2**exponent),
                self._max_retry_seconds,
            )
            retry_at = failed_at + timedelta(seconds=delay)
        return self._store.fail_run(
            worker=self._worker,
            run_id=run.run_id,
            lease_token_digest=lease_token_digest,
            lease_fence=run.lease_fence,
            failure_digest=_failure_digest(
                run,
                code=code,
                retryable=can_retry,
            ),
            failed_at=failed_at,
            retry_at=retry_at,
        )

    def run_once(self) -> ControlRun | None:
        """Execute at most one run.

        An executor-side ambiguous outcome becomes a retryable, secret-free
        failure for the same stable run id.  A database-side ambiguous closure
        is allowed to escape from ``complete_run``/``fail_run``; converting a
        possibly committed closure into another assertion would be unsafe.
        """

        lease_token_digest = self._token_digest()
        run = self._store.claim_next_run(
            worker=self._worker,
            lease_token_digest=lease_token_digest,
            leased_at=self._time(),
            lease_ttl_seconds=self._lease_ttl_seconds,
        )
        if run is None:
            return None
        try:
            configuration_bytes = self._store.configuration_bytes_for_run(
                tenant_id=run.request.tenant_id,
                run_id=run.run_id,
            )
            profile = self._store.control_profile(
                tenant_id=run.request.tenant_id,
                profile_digest=run.request.control_profile_digest,
            )
        except Exception:
            return self._fail(
                run,
                lease_token_digest=lease_token_digest,
                code="runtime-input-unavailable",
                retryable=True,
            )
        if (
            not isinstance(profile, RegisteredControlProfile)
            or profile.tenant_id != run.request.tenant_id
            or profile.profile_id != run.request.control_profile_id
            or profile.profile_digest != run.request.control_profile_digest
        ):
            return self._fail(
                run,
                lease_token_digest=lease_token_digest,
                code="runtime-input-integrity",
                retryable=False,
            )
        try:
            request = ControlRunExecutionRequest(
                run_id=run.run_id,
                run_request_bytes=run.request.canonical_bytes(),
                tenant_id=run.request.tenant_id,
                control_id=run.request.control_id,
                deployment_operation_id=run.request.deployment_operation_id,
                deployment_receipt_digest=(
                    run.request.deployment_receipt_digest
                ),
                configuration_digest=run.request.configuration_digest,
                configuration_bytes=configuration_bytes,
                control_profile_id=run.request.control_profile_id,
                control_profile_digest=run.request.control_profile_digest,
                control_profile_media_type=profile.media_type,
                control_profile_bytes=profile.profile_bytes,
                window_start=run.request.window_start,
                window_end=run.request.window_end,
                attempt_count=run.attempt_count,
                lease_fence=run.lease_fence,
            )
        except (TypeError, ValueError):
            return self._fail(
                run,
                lease_token_digest=lease_token_digest,
                code="runtime-input-integrity",
                retryable=False,
            )
        try:
            result = self._executor.ensure_executed(request)
        except ControlRunOutcomeUnknown:
            return self._fail(
                run,
                lease_token_digest=lease_token_digest,
                code="executor-outcome-unknown",
                retryable=True,
            )
        except ControlRunExecutionError as exc:
            return self._fail(
                run,
                lease_token_digest=lease_token_digest,
                code=exc.code,
                retryable=exc.retryable,
            )
        except Exception:
            return self._fail(
                run,
                lease_token_digest=lease_token_digest,
                code="executor-unhandled",
                retryable=True,
            )
        if (
            not isinstance(result, ControlRunExecutionResult)
            or result.run_id != run.run_id
            or result.lease_fence != run.lease_fence
        ):
            return self._fail(
                run,
                lease_token_digest=lease_token_digest,
                code="executor-result-mismatch",
                retryable=False,
            )
        return self._store.complete_run(
            worker=self._worker,
            run_id=run.run_id,
            lease_token_digest=lease_token_digest,
            lease_fence=run.lease_fence,
            result=result,
            completed_at=self._time(),
        )


def sorted_unique_runs(runs: Sequence[ControlRun]) -> tuple[ControlRun, ...]:
    """Small deterministic helper for operator/API projections."""

    by_id = {run.run_id: run for run in runs}
    if len(by_id) != len(runs):
        raise ValueError("control run collection contains duplicate identities")
    return tuple(
        sorted(
            runs,
            key=lambda run: (
                run.request.due_at,
                run.request.tenant_id,
                run.request.control_id,
                run.run_id,
            ),
        )
    )
