from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, cast

import pytest

from assurance_lab.connectors.contract import ConnectorDescriptor
from assurance_lab.connectors.defender_xdr import (
    DEFENDER_XDR_CAPTURE_MEDIA_TYPE,
    DEFENDER_XDR_CONNECTOR_ID,
)
from assurance_lab.connectors.managed_evidence import ManagedAuthorizationProfile
from assurance_lab.control_plane.models import (
    ControlConfiguration,
    DefenderSourceConfiguration,
    EvidenceConfiguration,
    ScheduleConfiguration,
)
from assurance_lab.controls.alert_window import (
    ALERT_WINDOW_PROFILE_MEDIA_TYPE,
    AlertWindowProfile,
    Criterion,
    DefenderAlertSource,
    TotalRecordCount,
)
from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.runtime.evidence_publication import (
    ManagedEvidencePublication,
    ManagedEvidencePublicationError,
)
from assurance_lab.runtime.execution_identity import (
    EXECUTION_ENVIRONMENT_IDENTITY_MEDIA_TYPE,
    ExecutionEnvironmentIdentity,
)
from assurance_lab.runtime.execution_journal import (
    ExecutionAttemptState,
    ExecutionJournalConflict,
    ExecutionJournalNotFound,
    ExecutionJournalOutcomeUnknown,
    ExecutionJournalRecord,
    stable_execution_request_bytes,
)
from assurance_lab.runtime.execution_plan import (
    ControlRunExecutionPlan,
    verify_control_run_execution_plan,
)
from assurance_lab.runtime.executor import (
    DurableControlRunExecutor,
    PreparedExecutionEnvironment,
)
from assurance_lab.runtime.managed_source import PreparedManagedSource
from assurance_lab.runtime.models import (
    ControlRunExecutionError,
    ControlRunExecutionRequest,
    ControlRunExecutionResult,
    ControlRunRequest,
    sha256_digest,
)

_START = datetime(2026, 7, 29, 1, 0, tzinfo=UTC)
_END = _START + timedelta(minutes=5)
_PREPARED = _END + timedelta(minutes=2)
_SOURCE_REVISION = "oci:sha256:0123456789abcdef"
_OPERATION = f"sha256:{'1' * 64}"
_DEPLOYMENT = f"sha256:{'2' * 64}"
_REVISION = f"sha256:{'3' * 64}"
_EVIDENCE = f"sha256:{'4' * 64}"
_CUSTODY_PROFILE = f"sha256:{'5' * 64}"
_SOURCE_IDENTITY_MEDIA_TYPE = (
    "application/vnd.control-assurance.defender-runtime-identity.v1+json"
)
_CUSTODY_IDENTITY_MEDIA_TYPE = (
    "application/vnd.control-assurance.custody-runtime-identity.v1+json"
)


def _profile() -> AlertWindowProfile:
    return AlertWindowProfile(
        profile_id="defender-alert-count",
        profile_version="1.0.0",
        title="Defender alert count",
        source=DefenderAlertSource(),
        criteria=(
            Criterion(
                criterion_id="alert-observed",
                description="At least one alert was observed.",
                metric=TotalRecordCount(),
                comparison="ge",
                expected_count=1,
            ),
        ),
    )


def _execution_request(
    *,
    attempt_count: int = 1,
    lease_fence: int | None = None,
) -> ControlRunExecutionRequest:
    profile = _profile()
    configuration = ControlConfiguration(
        tenant_id="bank-a",
        control_id="defender-alert-count",
        display_name="Defender alert count",
        description="Recomputes an exact closed Defender alert window.",
        environment="production",
        owner_group="security/detection",
        control_profile_id=profile.profile_id,
        control_profile_digest=profile.digest,
        source=DefenderSourceConfiguration(
            tenant_id="11111111-1111-4111-8111-111111111111",
            client_id="22222222-2222-4222-8222-222222222222",
            client_credential_ref=(
                "azure-keyvault://bank-vault/secrets/"
                "defender-profile/0123456789abcdef0123456789abcdef"
            ),
        ),
        schedule=ScheduleConfiguration(
            interval_seconds=300,
            collection_lag_seconds=120,
            window_seconds=300,
        ),
        evidence=EvidenceConfiguration(
            custody_ref="s3-object-lock://evidence/bank-a/defender",
            signing_key_ref="vault-transit://assurance/runtime",
            retention_days=30,
        ),
    )
    run = ControlRunRequest(
        tenant_id=configuration.tenant_id,
        control_id=configuration.control_id,
        deployment_operation_id=_OPERATION,
        deployment_operation_sequence=7,
        deployment_receipt_digest=_DEPLOYMENT,
        control_profile_id=profile.profile_id,
        control_profile_digest=profile.digest,
        revision_id=_REVISION,
        configuration_digest=configuration.digest,
        window_start=_START,
        window_end=_END,
        due_at=_PREPARED,
    )
    return ControlRunExecutionRequest(
        run_id=run.run_id,
        run_request_bytes=run.canonical_bytes(),
        tenant_id=configuration.tenant_id,
        control_id=configuration.control_id,
        deployment_operation_id=run.deployment_operation_id,
        deployment_receipt_digest=run.deployment_receipt_digest,
        configuration_digest=configuration.digest,
        configuration_bytes=configuration.canonical_bytes(),
        control_profile_id=profile.profile_id,
        control_profile_digest=profile.digest,
        control_profile_media_type=ALERT_WINDOW_PROFILE_MEDIA_TYPE,
        control_profile_bytes=profile.canonical_bytes(),
        window_start=_START,
        window_end=_END,
        attempt_count=attempt_count,
        lease_fence=lease_fence or attempt_count,
    )


def _source(
    request: ControlRunExecutionRequest,
    plan: ControlRunExecutionPlan,
) -> PreparedManagedSource:
    _reopened, connector_request = verify_control_run_execution_plan(
        plan.canonical_bytes(),
        expected_request=request,
    )
    descriptor = ConnectorDescriptor(
        connector_id=DEFENDER_XDR_CONNECTOR_ID,
        connector_version="0.1.0",
        capture_media_type=DEFENDER_XDR_CAPTURE_MEDIA_TYPE,
    )
    authorization = ManagedAuthorizationProfile(
        profile_id="defender-workload-alert-read-v1",
        provider_id="microsoft-entra",
        authorization_binding_digest=sha256_digest(b"authorization"),
        credential_reference_digest=sha256_digest(b"credential"),
        permission_ids=("microsoft-graph:ThreatHunting.Read.All",),
        resource_scope_digests=(sha256_digest(b"graph"),),
    )

    def unused(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("fake publisher must not call connector callbacks")

    return PreparedManagedSource(
        descriptor=descriptor,
        source_locator_digest=sha256_digest(b"https://graph.microsoft.com"),
        connector_request=connector_request,
        connector_request_bytes=plan.connector_request_bytes,
        authorization_profile=authorization,
        connector_receipt_verifier_id="test/defender-receipt-v1",
        pam_receipt_verifier_id="test/defender-pam-v1",
        _capture=unused,
        receipt_verifier=unused,
        pam_receipt_verifier=unused,
    )


class _UnusedCustody:
    def put_file(self, *_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError

    def put_bytes(self, *_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError

    def verify_acknowledgement_scope(self, *_args: Any, **_kwargs: Any) -> bool:
        raise AssertionError

    def reverify_acknowledgement(self, *_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError


class _UnusedSigner:
    key_id = "test"
    public_key_bytes = b"\x00" * 32

    def sign(self, _message: bytes) -> Any:
        raise AssertionError


def _execution_identity(
    request: ControlRunExecutionRequest,
    plan: ControlRunExecutionPlan,
    *,
    source_anchor: bytes = b"graph",
) -> ExecutionEnvironmentIdentity:
    source_identity = canonical_json_bytes(
        {
            "kind": "defender-runtime-identity",
            "media_type": _SOURCE_IDENTITY_MEDIA_TYPE,
            "schema_version": "1.0.0",
            "graph_origin_digest": sha256_digest(source_anchor),
        }
    )
    custody_identity = canonical_json_bytes(
        {
            "configuration_digest": request.configuration_digest,
            "control_id": request.control_id,
            "deployment_profile_digest": _CUSTODY_PROFILE,
            "execution_plan_digest": plan.digest,
            "media_type": _CUSTODY_IDENTITY_MEDIA_TYPE,
            "run_id": request.run_id,
            "schema_version": "1.0.0",
            "tenant_id": request.tenant_id,
        }
    )
    return ExecutionEnvironmentIdentity(
        run_id=request.run_id,
        tenant_id=request.tenant_id,
        control_id=request.control_id,
        configuration_digest=request.configuration_digest,
        execution_plan_digest=plan.digest,
        source_revision=plan.source_revision,
        source_kind="defender-xdr",
        source_identity_media_type=_SOURCE_IDENTITY_MEDIA_TYPE,
        source_identity_bytes=source_identity,
        source_identity_digest=sha256_digest(source_identity),
        custody_identity_media_type=_CUSTODY_IDENTITY_MEDIA_TYPE,
        custody_identity_bytes=custody_identity,
        custody_identity_digest=sha256_digest(custody_identity),
        custody_deployment_profile_digest=_CUSTODY_PROFILE,
    )


@dataclass(slots=True)
class _Provider:
    journal: _Journal
    calls: int = 0
    substitute_identity: bool = False
    fail_stage: str | None = None

    def prepare(
        self,
        request: ControlRunExecutionRequest,
        plan: ControlRunExecutionPlan,
        *,
        expected_identity_bytes: bytes | None = None,
    ) -> PreparedExecutionEnvironment:
        assert self.journal.state == "publishing"
        self.calls += 1
        if self.fail_stage is not None:
            raise ManagedEvidencePublicationError(
                self.fail_stage,
                "prepared environment is intentionally unavailable",
            )
        identity = _execution_identity(
            request,
            plan,
            source_anchor=(
                b"substituted" if self.substitute_identity else b"graph"
            ),
        )
        return PreparedExecutionEnvironment(
            source=_source(request, plan),
            custody=_UnusedCustody(),
            receipt_signer=_UnusedSigner(),
            execution_identity_bytes=identity.canonical_bytes(),
            execution_identity_digest=identity.digest,
            execution_identity_media_type=(
                EXECUTION_ENVIRONMENT_IDENTITY_MEDIA_TYPE
            ),
            custody_deployment_profile_digest=(
                identity.custody_deployment_profile_digest
            ),
        )


def _fake_publication(plan: ControlRunExecutionPlan) -> ManagedEvidencePublication:
    """Create an exact-class seam value; publication validity is tested elsewhere."""

    receipt = canonical_json_bytes({"run_id": plan.run_id})
    acknowledgement = canonical_json_bytes({"version_id": "test-version"})
    publication = object.__new__(ManagedEvidencePublication)
    values: dict[str, object] = {
        "run_id": plan.run_id,
        "artifact_set_id": plan.artifact_set_id,
        "custody_scope_id": plan.custody_scope_id,
        "executor_receipt_id": plan.executor_receipt_id,
        "cab_id": f"cab:{sha256_digest(b'cab')}",
        "evidence_digest": _EVIDENCE,
        "executor_receipt_digest": sha256_digest(receipt),
        "executor_receipt_bytes": receipt,
        "custody_acknowledgement_digest": sha256_digest(acknowledgement),
        "custody_acknowledgement_bytes": acknowledgement,
        "job_digest": sha256_digest(b"job"),
        "source_receipt_digest": sha256_digest(b"source"),
        "records_digest": sha256_digest(b"records"),
        "pam_receipt_digest": sha256_digest(b"pam"),
        "evaluation_digest": sha256_digest(b"evaluation"),
        "record_count": 1,
        "exact_versions_reverified": True,
    }
    for name, value in values.items():
        object.__setattr__(publication, name, value)
    return publication


@dataclass(slots=True)
class _Publisher:
    calls: int = 0
    fail_once: bool = False
    substitute_artifact_id: bool = False

    def __call__(
        self,
        request: ControlRunExecutionRequest,
        plan: ControlRunExecutionPlan,
        source: PreparedManagedSource,
        **kwargs: Any,
    ) -> ManagedEvidencePublication:
        assert request.run_id == plan.run_id
        assert type(source) is PreparedManagedSource
        assert kwargs["source_revision"] == plan.source_revision
        assert kwargs["execution_environment_identity_bytes"] == (
            _execution_identity(request, plan).canonical_bytes()
        )
        self.calls += 1
        if self.fail_once and self.calls == 1:
            raise ManagedEvidencePublicationError(
                "source-capture",
                "source capture failed",
            )
        publication = _fake_publication(plan)
        if self.substitute_artifact_id:
            object.__setattr__(
                publication,
                "artifact_set_id",
                sha256_digest(b"substituted"),
            )
        return publication


class _Journal:
    def __init__(self) -> None:
        self.request: ControlRunExecutionRequest | None = None
        self.plan_bytes: bytes | None = None
        self.worker_id = ""
        self.token = ""
        self.state: Literal[
            "absent",
            "prepared",
            "publishing",
            "completed",
            "failed",
            "uncertain",
        ] = "absent"
        self.revision = 0
        self.error_code: str | None = None
        self.result: ControlRunExecutionResult | None = None
        self.receipt_bytes: bytes | None = None
        self.execution_identity_bytes: bytes | None = None
        self.execution_identity_digest: str | None = None
        self.calls: list[str] = []
        self.raise_begin_after_commit = False
        self.raise_bind_after_commit = False
        self.raise_bind_conflict_with_takeover = False
        self.raise_complete_after_commit = False

    def _record(self) -> ExecutionJournalRecord:
        assert self.request is not None
        assert self.plan_bytes is not None
        stable = stable_execution_request_bytes(self.request)
        publishing_at = (
            _PREPARED if self.state in {"publishing", "completed"} else None
        )
        finished_at = (
            _PREPARED
            if self.state in {"completed", "failed", "uncertain"}
            else None
        )
        return ExecutionJournalRecord(
            request=self.request,
            stable_request_digest=sha256_digest(stable),
            stable_request_bytes=stable,
            execution_plan_digest=sha256_digest(self.plan_bytes),
            execution_plan_bytes=self.plan_bytes,
            execution_identity_digest=self.execution_identity_digest,
            execution_identity_bytes=self.execution_identity_bytes,
            state=cast(ExecutionAttemptState, self.state),
            revision=self.revision,
            highest_lease_fence=self.request.lease_fence,
            worker_id=self.worker_id,
            lease_token_digest=self.token,
            prepared_at=_PREPARED,
            publishing_at=publishing_at,
            finished_at=finished_at,
            error_code=self.error_code,
            completion_lease_fence=(
                None if self.result is None else self.result.lease_fence
            ),
            evidence_digest=(
                None if self.result is None else self.result.evidence_digest
            ),
            executor_receipt_digest=(
                None
                if self.result is None
                else self.result.executor_receipt_digest
            ),
            executor_receipt_bytes=self.receipt_bytes,
        )

    def prepare(
        self,
        request: ControlRunExecutionRequest,
        *,
        worker_id: str,
        lease_token_digest: str,
        execution_plan_bytes: bytes | None,
    ) -> ExecutionJournalRecord:
        self.calls.append(
            "prepare:recover" if execution_plan_bytes is None else "prepare:new"
        )
        if self.state == "absent":
            if execution_plan_bytes is None:
                raise ExecutionJournalNotFound
            self.request = request
            self.plan_bytes = execution_plan_bytes
            self.worker_id = worker_id
            self.token = lease_token_digest
            self.state = "prepared"
            self.revision = 0
            return self._record()
        assert self.request is not None
        if self.state == "completed":
            return self._record()
        if request.lease_fence > self.request.lease_fence:
            if (
                self.state == "publishing"
                and self.execution_identity_bytes is not None
            ):
                raise ExecutionJournalConflict(
                    "identity-bound publishing execution requires reconciliation"
                )
            self.request = request
            self.worker_id = worker_id
            self.token = lease_token_digest
            self.state = "prepared"
            self.revision = 0
            self.error_code = None
            return self._record()
        assert request.lease_fence == self.request.lease_fence
        assert worker_id == self.worker_id
        assert lease_token_digest == self.token
        return self._record()

    def get(self, *, tenant_id: str, run_id: str) -> ExecutionJournalRecord:
        self.calls.append("get")
        assert self.request is not None
        assert tenant_id == self.request.tenant_id
        assert run_id == self.request.run_id
        return self._record()

    def begin_publishing(self, **kwargs: Any) -> ExecutionJournalRecord:
        self.calls.append("begin")
        assert kwargs["expected_revision"] == 0
        self.state = "publishing"
        self.revision = 1
        if self.raise_begin_after_commit:
            self.raise_begin_after_commit = False
            raise ExecutionJournalOutcomeUnknown
        return self._record()

    def bind_execution_identity(self, **kwargs: Any) -> ExecutionJournalRecord:
        self.calls.append("bind")
        assert self.state == "publishing"
        assert kwargs["expected_revision"] == 1
        supplied_bytes = kwargs["execution_identity_bytes"]
        supplied_digest = kwargs["execution_identity_digest"]
        if self.execution_identity_bytes is None:
            self.execution_identity_bytes = supplied_bytes
            self.execution_identity_digest = supplied_digest
        else:
            assert self.execution_identity_bytes == supplied_bytes
            assert self.execution_identity_digest == supplied_digest
        if self.raise_bind_conflict_with_takeover:
            self.raise_bind_conflict_with_takeover = False
            assert self.request is not None
            self.request = _execution_request(attempt_count=2, lease_fence=2)
            self.worker_id = "executor-b"
            self.token = sha256_digest(b"executor-b-lease-token")
            raise ExecutionJournalConflict("simulated concurrent takeover")
        if self.raise_bind_after_commit:
            self.raise_bind_after_commit = False
            raise ExecutionJournalOutcomeUnknown
        return self._record()

    def mark_failed(self, **kwargs: Any) -> ExecutionJournalRecord:
        self.calls.append("failed")
        self.state = "failed"
        self.revision = kwargs["expected_revision"] + 1
        self.error_code = kwargs["error_code"]
        return self._record()

    def mark_uncertain(self, **kwargs: Any) -> ExecutionJournalRecord:
        self.calls.append("uncertain")
        self.state = "uncertain"
        self.revision = kwargs["expected_revision"] + 1
        self.error_code = kwargs["error_code"]
        return self._record()

    def mark_completed(self, **kwargs: Any) -> ExecutionJournalRecord:
        self.calls.append("completed")
        self.state = "completed"
        self.revision = kwargs["expected_revision"] + 1
        self.result = kwargs["result"]
        self.receipt_bytes = kwargs["executor_receipt_bytes"]
        if self.raise_complete_after_commit:
            self.raise_complete_after_commit = False
            raise ExecutionJournalOutcomeUnknown
        return self._record()


def _executor(
    tmp_path: Path,
    journal: _Journal,
    provider: _Provider,
    publisher: _Publisher,
    *,
    source_revision: str = _SOURCE_REVISION,
    now: datetime = _PREPARED,
    nonce_counter: list[int] | None = None,
) -> DurableControlRunExecutor:
    tmp_path.chmod(0o700)
    observed = nonce_counter if nonce_counter is not None else []

    def nonce_bytes(size: int) -> bytes:
        observed.append(size)
        return b"\xab" * size

    return DurableControlRunExecutor(
        journal,
        provider,
        work_root=tmp_path.absolute(),
        worker_id="executor-a",
        source_revision=source_revision,
        now=lambda: now,
        nonce_bytes=nonce_bytes,
        publish=publisher,
    )


def test_new_run_is_journaled_before_any_external_dependency(
    tmp_path: Path,
) -> None:
    journal = _Journal()
    provider = _Provider(journal)
    publisher = _Publisher()
    request = _execution_request()

    result = _executor(tmp_path, journal, provider, publisher).ensure_executed(
        request
    )

    assert result.evidence_digest == _EVIDENCE
    assert journal.calls == [
        "prepare:recover",
        "prepare:new",
        "begin",
        "bind",
        "completed",
    ]
    assert provider.calls == 1
    assert publisher.calls == 1


def test_completed_retry_never_calls_source_or_publisher(tmp_path: Path) -> None:
    journal = _Journal()
    provider = _Provider(journal)
    publisher = _Publisher()
    executor = _executor(tmp_path, journal, provider, publisher)
    request = _execution_request()
    first = executor.ensure_executed(request)

    retried = executor.ensure_executed(request)

    assert retried == first
    assert provider.calls == 1
    assert publisher.calls == 1


def test_lost_completion_acknowledgement_is_recovered_by_exact_receipt(
    tmp_path: Path,
) -> None:
    journal = _Journal()
    journal.raise_complete_after_commit = True
    provider = _Provider(journal)
    publisher = _Publisher()

    result = _executor(tmp_path, journal, provider, publisher).ensure_executed(
        _execution_request()
    )

    assert result.evidence_digest == _EVIDENCE
    assert journal.calls[-2:] == ["completed", "get"]
    assert publisher.calls == 1


def test_lost_begin_acknowledgement_rereads_state_before_publication(
    tmp_path: Path,
) -> None:
    journal = _Journal()
    journal.raise_begin_after_commit = True
    provider = _Provider(journal)
    publisher = _Publisher()

    result = _executor(tmp_path, journal, provider, publisher).ensure_executed(
        _execution_request()
    )

    assert result.evidence_digest == _EVIDENCE
    assert "get" in journal.calls
    assert publisher.calls == 1


def test_lost_identity_bind_acknowledgement_is_reopened_before_publication(
    tmp_path: Path,
) -> None:
    journal = _Journal()
    journal.raise_bind_after_commit = True
    provider = _Provider(journal)
    publisher = _Publisher()

    result = _executor(tmp_path, journal, provider, publisher).ensure_executed(
        _execution_request()
    )

    assert result.evidence_digest == _EVIDENCE
    assert journal.calls[-3:] == ["bind", "get", "completed"]
    assert journal.execution_identity_bytes is not None
    assert publisher.calls == 1


def test_identity_bind_conflict_does_not_accept_another_attempt(
    tmp_path: Path,
) -> None:
    journal = _Journal()
    journal.raise_bind_conflict_with_takeover = True
    provider = _Provider(journal)
    publisher = _Publisher()

    with pytest.raises(ControlRunExecutionError) as raised:
        _executor(tmp_path, journal, provider, publisher).ensure_executed(
            _execution_request()
        )

    assert raised.value.code == "executor-identity-conflict"
    assert raised.value.retryable is False
    assert journal.request is not None
    assert journal.request.lease_fence == 2
    assert journal.worker_id == "executor-b"
    assert publisher.calls == 0


def test_higher_fence_reuses_frozen_nonce_after_uncertain_capture(
    tmp_path: Path,
) -> None:
    journal = _Journal()
    provider = _Provider(journal)
    publisher = _Publisher(fail_once=True)
    nonce_calls: list[int] = []
    executor = _executor(
        tmp_path,
        journal,
        provider,
        publisher,
        nonce_counter=nonce_calls,
    )

    with pytest.raises(ControlRunExecutionError) as raised:
        executor.ensure_executed(_execution_request())
    first_plan = journal.plan_bytes
    result = executor.ensure_executed(
        _execution_request(attempt_count=2, lease_fence=2)
    )

    assert raised.value.code == "executor-source-capture"
    assert result.evidence_digest == _EVIDENCE
    assert journal.plan_bytes == first_plan
    assert nonce_calls == [32]
    assert publisher.calls == 2


def test_bound_execution_identity_drift_stops_before_publication(
    tmp_path: Path,
) -> None:
    journal = _Journal()
    provider = _Provider(journal)
    publisher = _Publisher(fail_once=True)
    executor = _executor(tmp_path, journal, provider, publisher)

    with pytest.raises(ControlRunExecutionError):
        executor.ensure_executed(_execution_request())
    assert journal.execution_identity_bytes is not None
    provider.substitute_identity = True

    with pytest.raises(ControlRunExecutionError) as raised:
        executor.ensure_executed(
            _execution_request(attempt_count=2, lease_fence=2)
        )

    assert raised.value.code == "executor-publication-integrity"
    assert raised.value.retryable is False
    assert publisher.calls == 1
    assert journal.state == "failed"


def test_deterministic_environment_drift_is_not_retried(
    tmp_path: Path,
) -> None:
    journal = _Journal()
    provider = _Provider(journal, fail_stage="execution-identity")
    publisher = _Publisher()

    with pytest.raises(ControlRunExecutionError) as raised:
        _executor(tmp_path, journal, provider, publisher).ensure_executed(
            _execution_request()
        )

    assert raised.value.code == "executor-execution-identity"
    assert raised.value.retryable is False
    assert journal.state == "failed"
    assert publisher.calls == 0


def test_build_revision_change_cannot_resume_old_plan(tmp_path: Path) -> None:
    journal = _Journal()
    provider = _Provider(journal)
    publisher = _Publisher()
    request = _execution_request()
    _executor(tmp_path, journal, provider, publisher).ensure_executed(request)
    assert journal.plan_bytes is not None
    journal.state = "prepared"
    journal.revision = 0
    journal.result = None
    journal.receipt_bytes = None

    with pytest.raises(ControlRunExecutionError) as raised:
        _executor(
            tmp_path,
            journal,
            provider,
            publisher,
            source_revision="oci:sha256:upgraded",
        ).ensure_executed(request)

    assert raised.value.code == "executor-revision-mismatch"
    assert raised.value.retryable is False
    assert cast(str, journal.state) == "failed"
    assert provider.calls == 1


def test_expired_frozen_retention_is_not_silently_extended(
    tmp_path: Path,
) -> None:
    journal = _Journal()
    provider = _Provider(journal)
    publisher = _Publisher()
    request = _execution_request()
    executor = _executor(tmp_path, journal, provider, publisher)
    with pytest.raises(ControlRunExecutionError):
        # Seed only the plan by making the first publication uncertain.
        publisher.fail_once = True
        executor.ensure_executed(request)
    assert journal.plan_bytes is not None
    journal.state = "prepared"
    journal.revision = 0
    journal.error_code = None

    with pytest.raises(ControlRunExecutionError) as raised:
        _executor(
            tmp_path,
            journal,
            provider,
            publisher,
            now=_PREPARED + timedelta(days=31),
        ).ensure_executed(request)

    assert raised.value.code == "executor-plan-expired"
    assert cast(str, journal.state) == "failed"


def test_publication_identity_substitution_is_fail_closed(
    tmp_path: Path,
) -> None:
    journal = _Journal()
    provider = _Provider(journal)
    publisher = _Publisher(substitute_artifact_id=True)

    with pytest.raises(ControlRunExecutionError) as raised:
        _executor(tmp_path, journal, provider, publisher).ensure_executed(
            _execution_request()
        )

    assert raised.value.code == "executor-publication-integrity"
    assert raised.value.retryable is False
    assert journal.state == "uncertain"
    assert journal.result is None


def test_completed_old_attempt_is_projected_to_current_scheduler_fence(
    tmp_path: Path,
) -> None:
    journal = _Journal()
    provider = _Provider(journal)
    publisher = _Publisher()
    executor = _executor(tmp_path, journal, provider, publisher)
    executor.ensure_executed(_execution_request())

    result = executor.ensure_executed(
        _execution_request(attempt_count=2, lease_fence=2)
    )

    assert result.lease_fence == 2
    assert result.evidence_digest == _EVIDENCE
    assert provider.calls == 1
    assert publisher.calls == 1
