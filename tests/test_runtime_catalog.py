from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from assurance_lab.control_plane import (
    ControlConfiguration,
    ElasticSourceConfiguration,
    EvidenceConfiguration,
    ScheduleConfiguration,
)
from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.runtime import (
    ControlRun,
    ControlRunClosure,
    ControlRunExecutionError,
    ControlRunExecutionRequest,
    ControlRunExecutionResult,
    ControlRunRequest,
    RegisteredControlProfile,
    RuntimeScheduler,
    RuntimeWorkerIdentity,
    due_window_ends,
)

_NOW = datetime(2026, 7, 29, 9, 0, tzinfo=UTC)
_PROFILE_BYTES = canonical_json_bytes(
    {
        "control": "alert-completeness",
        "required_fields": ["@timestamp", "event.id"],
        "version": 1,
    }
)
_PROFILE = f"sha256:{hashlib.sha256(_PROFILE_BYTES).hexdigest()}"
_OPERATION = f"sha256:{'2' * 64}"
_REVISION = f"sha256:{'3' * 64}"
_DEPLOYMENT_RECEIPT = f"sha256:{'4' * 64}"
_EVIDENCE = f"sha256:{'5' * 64}"
_EXECUTOR_RECEIPT = f"sha256:{'6' * 64}"
_TOKEN = f"sha256:{hashlib.sha256(bytes.fromhex('77' * 32)).hexdigest()}"


def _profile(
    *,
    profile_id: str = "alert-window-v1",
) -> RegisteredControlProfile:
    return RegisteredControlProfile(
        tenant_id="acme-bank",
        profile_id=profile_id,
        profile_digest=_PROFILE,
        media_type="application/vnd.control-assurance.profile.v1+json",
        profile_bytes=_PROFILE_BYTES,
        registered_at=_NOW,
        registered_by="security-architect@example.invalid",
    )


def _configuration(
    *,
    enabled: bool = True,
    interval_seconds: int = 900,
    window_seconds: int = 900,
    collection_lag_seconds: int = 120,
) -> ControlConfiguration:
    return ControlConfiguration(
        tenant_id="acme-bank",
        control_id="alert-completeness",
        display_name="Alert completeness",
        description="Collects one exact half-open Security alert window.",
        environment="production",
        owner_group="secops/platform",
        control_profile_id="alert-window-v1",
        control_profile_digest=_PROFILE,
        source=ElasticSourceConfiguration(
            endpoint_origin="https://elastic.acme.invalid",
            parent_credential_ref="vault://kv/secops/elastic-parent",
        ),
        schedule=ScheduleConfiguration(
            interval_seconds=interval_seconds,
            window_seconds=window_seconds,
            collection_lag_seconds=collection_lag_seconds,
        ),
        evidence=EvidenceConfiguration(
            custody_ref="s3-object-lock://evidence/acme-bank/alerts",
            signing_key_ref="vault-transit://assurance/runtime",
            retention_days=365,
        ),
        enabled=enabled,
    )


def _request(
    *,
    operation_id: str = _OPERATION,
    window_start: datetime = _NOW,
    window_end: datetime = _NOW + timedelta(minutes=15),
    due_at: datetime = _NOW + timedelta(minutes=17),
) -> ControlRunRequest:
    configuration = _configuration()
    return ControlRunRequest(
        tenant_id=configuration.tenant_id,
        control_id=configuration.control_id,
        deployment_operation_id=operation_id,
        deployment_operation_sequence=1,
        deployment_receipt_digest=_DEPLOYMENT_RECEIPT,
        control_profile_id=configuration.control_profile_id,
        control_profile_digest=configuration.control_profile_digest,
        revision_id=_REVISION,
        configuration_digest=configuration.digest,
        window_start=window_start,
        window_end=window_end,
        due_at=due_at,
    )


def _leased_run(
    *,
    request: ControlRunRequest | None = None,
    attempt_count: int = 1,
    leased_at: datetime | None = None,
) -> ControlRun:
    request = request or _request()
    leased_at = leased_at or request.due_at
    return ControlRun(
        run_id=request.run_id,
        request=request,
        state="leased",
        state_version=attempt_count,
        attempt_count=attempt_count,
        lease_fence=attempt_count,
        lease_owner="scheduler-a",
        lease_token_digest=_TOKEN,
        leased_at=leased_at,
        lease_expires_at=leased_at + timedelta(minutes=5),
    )


def test_due_windows_use_epoch_anchored_utc_half_open_intervals() -> None:
    configuration = _configuration()

    ends = due_window_ends(
        configuration,
        applied_at=datetime(2026, 7, 29, 9, 3, tzinfo=UTC),
        superseded_at=datetime(2026, 7, 29, 10, 7, tzinfo=UTC),
        through=datetime(2026, 7, 29, 10, 30, tzinfo=UTC),
    )

    assert ends == (
        datetime(2026, 7, 29, 9, 30, tzinfo=UTC),
        datetime(2026, 7, 29, 9, 45, tzinfo=UTC),
        datetime(2026, 7, 29, 10, 0, tzinfo=UTC),
    )
    assert ends[0] - timedelta(seconds=configuration.schedule.window_seconds) >= (
        datetime(2026, 7, 29, 9, 3, tzinfo=UTC)
    )
    assert ends[-1] <= datetime(2026, 7, 29, 10, 7, tzinfo=UTC)


def test_due_windows_respect_collection_lag_and_normalize_to_utc() -> None:
    korea = timezone(timedelta(hours=9))
    configuration = _configuration(
        interval_seconds=300,
        window_seconds=120,
        collection_lag_seconds=90,
    )

    before_lag = due_window_ends(
        configuration,
        applied_at=datetime(2026, 7, 29, 18, 0, tzinfo=korea),
        superseded_at=None,
        through=datetime(2026, 7, 29, 18, 6, 29, tzinfo=korea),
    )
    after_lag = due_window_ends(
        configuration,
        applied_at=datetime(2026, 7, 29, 18, 0, tzinfo=korea),
        superseded_at=None,
        through=datetime(2026, 7, 29, 18, 6, 30, tzinfo=korea),
    )

    assert before_lag == ()
    assert after_lag == (datetime(2026, 7, 29, 9, 5, tzinfo=UTC),)


def test_disabled_configuration_deploys_but_has_no_due_windows() -> None:
    assert due_window_ends(
        _configuration(enabled=False),
        applied_at=_NOW,
        superseded_at=None,
        through=_NOW + timedelta(days=30),
    ) == ()


def test_due_window_derivation_fails_closed_on_unbounded_backlog() -> None:
    with pytest.raises(ValueError, match="bounded"):
        due_window_ends(
            _configuration(
                interval_seconds=60,
                window_seconds=60,
                collection_lag_seconds=0,
            ),
            applied_at=_NOW,
            superseded_at=None,
            through=_NOW + timedelta(hours=2),
            limit=10,
        )


def test_run_identity_binds_deployment_operation_and_exact_window() -> None:
    first = _request()
    second = _request(operation_id=f"sha256:{'a' * 64}")
    later = _request(
        window_start=_NOW + timedelta(minutes=15),
        window_end=_NOW + timedelta(minutes=30),
        due_at=_NOW + timedelta(minutes=32),
    )

    assert first.run_id != second.run_id
    assert first.run_id != later.run_id
    assert ControlRunRequest.model_validate_json(first.canonical_bytes()) == first


def test_registered_profile_requires_exact_canonical_content_address() -> None:
    assert _profile().profile_bytes == _PROFILE_BYTES
    with pytest.raises(ValidationError, match="not canonical"):
        RegisteredControlProfile(
            tenant_id="acme-bank",
            profile_id="alert-window-v1",
            profile_digest=f"sha256:{hashlib.sha256(b'{\"version\": 1}').hexdigest()}",
            media_type="application/json",
            profile_bytes=b'{"version": 1}',
            registered_at=_NOW,
            registered_by="architect@example.invalid",
        )


def test_executor_request_rejects_noncanonical_configuration_bytes() -> None:
    configuration = _configuration()
    run_request = _request()
    noncanonical = configuration.canonical_bytes().replace(b":", b": ", 1)
    with pytest.raises(ValidationError, match="digest differs"):
        ControlRunExecutionRequest(
            run_id=run_request.run_id,
            run_request_bytes=run_request.canonical_bytes(),
            tenant_id=configuration.tenant_id,
            control_id=configuration.control_id,
            deployment_operation_id=_OPERATION,
            deployment_receipt_digest=_DEPLOYMENT_RECEIPT,
            configuration_digest=configuration.digest,
            configuration_bytes=noncanonical,
            control_profile_id=configuration.control_profile_id,
            control_profile_digest=configuration.control_profile_digest,
            control_profile_media_type=_profile().media_type,
            control_profile_bytes=_PROFILE_BYTES,
            window_start=_NOW,
            window_end=_NOW + timedelta(minutes=15),
            attempt_count=1,
            lease_fence=1,
        )


def test_executor_request_rejects_run_id_substitution() -> None:
    configuration = _configuration()
    expected = _request()
    substituted = _request(operation_id=f"sha256:{'e' * 64}")
    with pytest.raises(ValidationError, match="run request digest differs"):
        ControlRunExecutionRequest(
            run_id=expected.run_id,
            run_request_bytes=substituted.canonical_bytes(),
            tenant_id=configuration.tenant_id,
            control_id=configuration.control_id,
            deployment_operation_id=expected.deployment_operation_id,
            deployment_receipt_digest=expected.deployment_receipt_digest,
            configuration_digest=configuration.digest,
            configuration_bytes=configuration.canonical_bytes(),
            control_profile_id=configuration.control_profile_id,
            control_profile_digest=configuration.control_profile_digest,
            control_profile_media_type=_profile().media_type,
            control_profile_bytes=_PROFILE_BYTES,
            window_start=expected.window_start,
            window_end=expected.window_end,
            attempt_count=1,
            lease_fence=1,
        )


def test_closure_digest_changes_when_any_evidence_binding_changes() -> None:
    request = _request()
    closure = ControlRunClosure(
        run_id=request.run_id,
        tenant_id=request.tenant_id,
        control_id=request.control_id,
        deployment_operation_id=request.deployment_operation_id,
        deployment_receipt_digest=request.deployment_receipt_digest,
        configuration_digest=request.configuration_digest,
        control_profile_id=request.control_profile_id,
        control_profile_digest=request.control_profile_digest,
        window_start=request.window_start,
        window_end=request.window_end,
        attempt_count=1,
        lease_fence=1,
        evidence_digest=_EVIDENCE,
        executor_receipt_digest=_EXECUTOR_RECEIPT,
        completed_at=request.due_at + timedelta(seconds=1),
    )

    changed = closure.model_copy(update={"evidence_digest": f"sha256:{'f' * 64}"})

    assert closure.digest != changed.digest
    assert ControlRunClosure.model_validate_json(closure.canonical_bytes()) == closure


class _Store:
    max_run_attempts = 8

    def __init__(self, run: ControlRun) -> None:
        self.run = run
        self.claimed = False
        self.completed: list[ControlRunExecutionResult] = []
        self.failures: list[tuple[str, datetime | None]] = []

    def claim_next_run(
        self,
        *,
        worker: RuntimeWorkerIdentity,
        lease_token_digest: str,
        leased_at: datetime,
        lease_ttl_seconds: int,
    ) -> ControlRun | None:
        assert worker.worker_id == "scheduler-a"
        assert lease_token_digest == _TOKEN
        assert leased_at == self.run.leased_at
        assert lease_ttl_seconds == 300
        if self.claimed:
            return None
        self.claimed = True
        return self.run

    def configuration_bytes_for_run(
        self,
        *,
        tenant_id: str,
        run_id: str,
    ) -> bytes:
        assert tenant_id == self.run.request.tenant_id
        assert run_id == self.run.run_id
        return _configuration().canonical_bytes()

    def control_profile(
        self,
        *,
        tenant_id: str,
        profile_digest: str,
    ) -> RegisteredControlProfile:
        assert tenant_id == self.run.request.tenant_id
        assert profile_digest == self.run.request.control_profile_digest
        return _profile()

    def complete_run(
        self,
        *,
        worker: RuntimeWorkerIdentity,
        run_id: str,
        lease_token_digest: str,
        lease_fence: int,
        result: ControlRunExecutionResult,
        completed_at: datetime,
    ) -> ControlRun:
        self.completed.append(result)
        return ControlRun(
            run_id=self.run.run_id,
            request=self.run.request,
            state="succeeded",
            state_version=self.run.state_version + 1,
            attempt_count=self.run.attempt_count,
            lease_fence=self.run.lease_fence,
            completed_at=completed_at,
            evidence_digest=result.evidence_digest,
            executor_receipt_digest=result.executor_receipt_digest,
            closure_digest=f"sha256:{'8' * 64}",
        )

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
    ) -> ControlRun:
        self.failures.append((failure_digest, retry_at))
        return ControlRun(
            run_id=self.run.run_id,
            request=self.run.request,
            state="failed",
            state_version=self.run.state_version + 1,
            attempt_count=self.run.attempt_count,
            lease_fence=self.run.lease_fence,
            retry_at=retry_at,
            failed_at=failed_at,
            failure_digest=failure_digest,
        )


class _Executor:
    def __init__(self, *, mismatch: bool = False, error: str | None = None) -> None:
        self.requests: list[ControlRunExecutionRequest] = []
        self.mismatch = mismatch
        self.error = error

    def ensure_executed(
        self,
        request: ControlRunExecutionRequest,
    ) -> ControlRunExecutionResult:
        self.requests.append(request)
        if self.error is not None:
            raise ControlRunExecutionError(self.error, retryable=True)
        return ControlRunExecutionResult(
            run_id=(
                f"sha256:{'9' * 64}" if self.mismatch else request.run_id
            ),
            lease_fence=request.lease_fence,
            evidence_digest=_EVIDENCE,
            executor_receipt_digest=_EXECUTOR_RECEIPT,
        )


def _worker() -> RuntimeWorkerIdentity:
    return RuntimeWorkerIdentity(
        tenant_id="acme-bank",
        worker_id="scheduler-a",
        credential_digest=f"sha256:{'a' * 64}",
    )


def test_scheduler_hands_executor_exact_configuration_and_closes_digests() -> None:
    run = _leased_run()
    leased_at = run.leased_at
    assert leased_at is not None
    store = _Store(run)
    executor = _Executor()
    scheduler = RuntimeScheduler(
        store,
        executor,
        _worker(),
        now=lambda: leased_at,
        token_bytes=lambda count: bytes.fromhex("77" * count),
    )

    result = scheduler.run_once()

    assert result is not None and result.state == "succeeded"
    assert len(executor.requests) == 1
    assert executor.requests[0].idempotency_key == run.run_id
    assert executor.requests[0].run_request_bytes == run.request.canonical_bytes()
    assert executor.requests[0].configuration_digest == _configuration().digest
    assert executor.requests[0].control_profile_bytes == _PROFILE_BYTES
    assert store.completed[0].evidence_digest == _EVIDENCE
    assert store.completed[0].executor_receipt_digest == _EXECUTOR_RECEIPT
    assert store.failures == []


def test_scheduler_retries_bounded_error_but_mismatch_is_terminal() -> None:
    run = _leased_run()
    leased_at = run.leased_at
    assert leased_at is not None
    retry_store = _Store(run)
    retry_scheduler = RuntimeScheduler(
        retry_store,
        _Executor(error="connector-timeout"),
        _worker(),
        now=lambda: leased_at,
        token_bytes=lambda count: bytes.fromhex("77" * count),
    )
    mismatch_store = _Store(run)
    mismatch_scheduler = RuntimeScheduler(
        mismatch_store,
        _Executor(mismatch=True),
        _worker(),
        now=lambda: leased_at,
        token_bytes=lambda count: bytes.fromhex("77" * count),
    )

    retry = retry_scheduler.run_once()
    terminal = mismatch_scheduler.run_once()

    assert retry is not None and retry.retry_at == leased_at + timedelta(seconds=30)
    assert terminal is not None and terminal.retry_at is None
    assert retry_store.failures[0][0].startswith("sha256:")
    assert mismatch_store.failures[0][0].startswith("sha256:")


def test_scheduler_never_calls_executor_for_profile_identity_mismatch() -> None:
    run = _leased_run()
    leased_at = run.leased_at
    assert leased_at is not None
    store = _Store(run)
    store.control_profile = lambda **_kwargs: _profile(profile_id="other-profile")  # type: ignore[method-assign]
    executor = _Executor()
    scheduler = RuntimeScheduler(
        store,
        executor,
        _worker(),
        now=lambda: leased_at,
        token_bytes=lambda count: bytes.fromhex("77" * count),
    )

    result = scheduler.run_once()

    assert result is not None and result.state == "failed"
    assert result.retry_at is None
    assert executor.requests == []


def test_scheduler_rejects_attempt_limit_drift_between_process_and_store() -> None:
    run = _leased_run()
    store = _Store(run)
    store.max_run_attempts = 7

    with pytest.raises(ValueError, match="same run attempt limit"):
        RuntimeScheduler(store, _Executor(), _worker(), max_attempts=8)


def test_runtime_schema_contains_database_side_integrity_and_tenancy_guards() -> None:
    schema = (
        Path(__file__).parents[1] / "deploy" / "postgres" / "runtime-schema.sql"
    ).read_text(encoding="utf-8")

    assert "sha256(configuration_bytes)" in schema
    assert "sha256(receipt_bytes)" in schema
    assert "sha256(request_bytes)" in schema
    assert "sha256(closure_bytes)" in schema
    assert "sha256(profile_bytes)" in schema
    assert "control_profiles_immutable" in schema
    assert "FORCE ROW LEVEL SECURITY" in schema
    assert "control_assurance_runtime.session_tenant()" in schema
    assert "control_assurance_runtime.role_entitlements" in schema
    assert "control_run_claims_immutable" in schema
    assert "control_run_outcomes_immutable" in schema
    assert "current runtime deployment must strictly advance" in schema
    assert (
        "CONSTRAINT runtime_deployment_exact_identity_unique\n"
        "        UNIQUE (tenant_id, control_id, operation_id)"
    ) in schema
    assert "array_agg(version ORDER BY version)" in schema
    assert "ARRAY[1, 2, 3]::integer[]" in schema
    assert schema.count(
        "REFERENCES control_assurance_runtime.deployment_history"
    ) == 4
