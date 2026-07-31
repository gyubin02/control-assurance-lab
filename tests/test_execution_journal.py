from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from assurance_lab.control_plane.models import (
    ControlConfiguration,
    ElasticSourceConfiguration,
    EvidenceConfiguration,
    ScheduleConfiguration,
)
from assurance_lab.controls.alert_window import (
    ALERT_WINDOW_PROFILE_MEDIA_TYPE,
    AlertWindowProfile,
    Criterion,
    ElasticAlertSource,
    EqualsPredicate,
    MatchingRecordCount,
)
from assurance_lab.evidence.admission import DetachedSignature
from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.runtime.execution_identity import ExecutionEnvironmentIdentity
from assurance_lab.runtime.execution_journal import (
    ExecutionJournalConflict,
    ExecutionJournalIntegrityError,
    ExecutionJournalNotFound,
    PostgresExecutionJournal,
    stable_execution_request_bytes,
)
from assurance_lab.runtime.execution_plan import (
    create_control_run_execution_plan,
    verify_control_run_execution_plan,
)
from assurance_lab.runtime.execution_recovery import (
    AbandonedPublishingAttempt,
    ComputeFenceAttestation,
    CredentialDrainAttestation,
    PAMDrainAnchor,
    PublishingRecoveryAuthorization,
    PublishingRecoveryJournalExpectation,
    PublishingRecoveryRequest,
    PublishingRecoveryRequestIntent,
    RecoveryActorAssertion,
    RecoveryActorVerificationPolicy,
    SuccessorLeaseClaim,
    WorkloadFenceLocator,
    credential_drain_lifecycle_snapshot_digest,
    issue_compute_fence_attestation,
    issue_credential_drain_attestation,
    issue_publishing_recovery_authorization,
    issue_recovery_actor_action,
    migrate_legacy_pam_recovery_scopes,
    migrate_recovery_actor_assertion,
    publishing_recovery_checker_action_digest,
    publishing_recovery_execution_binding_digest,
    publishing_recovery_pam_scope_digest,
)
from assurance_lab.runtime.models import (
    ControlRunExecutionRequest,
    ControlRunExecutionResult,
    ControlRunRequest,
    sha256_digest,
)

_START = datetime(2026, 7, 29, 1, 0, tzinfo=UTC)
_END = _START + timedelta(minutes=5)
_PREPARED = _END + timedelta(minutes=2)
_OPERATION = f"sha256:{'1' * 64}"
_DEPLOYMENT = f"sha256:{'2' * 64}"
_REVISION = f"sha256:{'3' * 64}"
_TOKEN_ONE = f"sha256:{'4' * 64}"
_TOKEN_TWO = f"sha256:{'5' * 64}"
_EVIDENCE = f"sha256:{'6' * 64}"
_RECEIPT_BYTES = canonical_json_bytes(
    {
        "media_type": "application/vnd.control-assurance.executor-receipt.v1+json",
        "outcome": "sealed",
    }
)
_RECEIPT = sha256_digest(_RECEIPT_BYTES)
_NONCE = "ab" * 32
_RULE = "12345678-1234-4234-9234-123456789abc"


def _profile() -> AlertWindowProfile:
    return AlertWindowProfile(
        profile_id="high-alert-window",
        profile_version="1.0.0",
        title="High alert window",
        source=ElasticAlertSource(
            fields=("@timestamp", "kibana.alert.rule.uuid", "kibana.alert.severity"),
            rule_uuids=(_RULE,),
        ),
        criteria=(
            Criterion(
                criterion_id="high-alert-observed",
                description="At least one high alert was observed.",
                metric=MatchingRecordCount(
                    all=(
                        EqualsPredicate(
                            field="kibana.alert.severity",
                            value="high",
                        ),
                    )
                ),
                comparison="ge",
                expected_count=1,
            ),
        ),
    )


def _execution_request(
    *,
    tenant_id: str = "bank-a",
    attempt_count: int = 1,
) -> ControlRunExecutionRequest:
    profile = _profile()
    configuration = ControlConfiguration(
        tenant_id=tenant_id,
        control_id="high-alert-control",
        display_name="High alert control",
        description="Recomputes high-alert evidence for one closed window.",
        environment="production",
        owner_group="security/detection",
        control_profile_id=profile.profile_id,
        control_profile_digest=profile.digest,
        source=ElasticSourceConfiguration(
            endpoint_origin="https://elastic.bank.invalid",
            index_alias=".alerts-security.alerts-payments",
            parent_credential_ref=(
                "azure-keyvault://bank-vault/secrets/"
                "elastic-parent/0123456789abcdef0123456789abcdef"
            ),
            lease_ttl_seconds=900,
        ),
        schedule=ScheduleConfiguration(
            interval_seconds=300,
            collection_lag_seconds=120,
            window_seconds=300,
        ),
        evidence=EvidenceConfiguration(
            custody_ref=f"s3-object-lock://evidence/{tenant_id}/high-alerts",
            signing_key_ref="vault-transit://assurance/runtime",
            retention_days=365,
        ),
    )
    run = ControlRunRequest(
        tenant_id=tenant_id,
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
        tenant_id=tenant_id,
        control_id=configuration.control_id,
        deployment_operation_id=_OPERATION,
        deployment_receipt_digest=_DEPLOYMENT,
        configuration_digest=configuration.digest,
        configuration_bytes=configuration.canonical_bytes(),
        control_profile_id=profile.profile_id,
        control_profile_digest=profile.digest,
        control_profile_media_type=ALERT_WINDOW_PROFILE_MEDIA_TYPE,
        control_profile_bytes=profile.canonical_bytes(),
        window_start=_START,
        window_end=_END,
        attempt_count=attempt_count,
        lease_fence=attempt_count,
    )


def _plan_bytes(request: ControlRunExecutionRequest, *, nonce: str = _NONCE) -> bytes:
    return create_control_run_execution_plan(
        request,
        capture_nonce=nonce,
        prepared_at=_PREPARED,
    ).canonical_bytes()


def _execution_identity_bytes(
    request: ControlRunExecutionRequest,
    plan_bytes: bytes,
    *,
    deployment_profile_digest: str = f"sha256:{'7' * 64}",
) -> bytes:
    plan, _ = verify_control_run_execution_plan(
        plan_bytes,
        expected_request=request,
    )
    source_media_type = "application/vnd.control-assurance.elastic-runtime-identity.v1+json"
    source_bytes = canonical_json_bytes(
        {
            "kind": "elastic-runtime-identity",
            "media_type": source_media_type,
        }
    )
    custody_media_type = "application/vnd.control-assurance.custody-runtime-identity.v1+json"
    custody_bytes = canonical_json_bytes(
        {
            "configuration_digest": request.configuration_digest,
            "control_id": request.control_id,
            "deployment_profile_digest": deployment_profile_digest,
            "execution_plan_digest": plan.digest,
            "media_type": custody_media_type,
            "run_id": request.run_id,
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
        source_kind=plan.source_kind,
        source_identity_media_type=source_media_type,
        source_identity_bytes=source_bytes,
        source_identity_digest=sha256_digest(source_bytes),
        custody_identity_media_type=custody_media_type,
        custody_identity_bytes=custody_bytes,
        custody_identity_digest=sha256_digest(custody_bytes),
        custody_deployment_profile_digest=deployment_profile_digest,
    ).canonical_bytes()


def _row(
    request: ControlRunExecutionRequest,
    plan_bytes: bytes,
    *,
    state: str,
    revision: int,
    worker_id: str = "executor-a",
    token: str = _TOKEN_ONE,
    highest_fence: int | None = None,
    publishing: datetime | None = None,
    finished: datetime | None = None,
    error_code: str | None = None,
    completed: bool = False,
    identity_bound: bool = False,
) -> dict[str, object]:
    highest = request.lease_fence if highest_fence is None else highest_fence
    execution_identity_bytes = _execution_identity_bytes(request, plan_bytes)
    return {
        "tenant_id": request.tenant_id,
        "run_id": request.run_id,
        "stable_request_digest": sha256_digest(stable_execution_request_bytes(request)),
        "stable_request_bytes": stable_execution_request_bytes(request),
        "run_request_bytes": request.run_request_bytes,
        "control_id": request.control_id,
        "deployment_operation_id": request.deployment_operation_id,
        "deployment_operation_sequence": 7,
        "deployment_receipt_digest": request.deployment_receipt_digest,
        "revision_id": _REVISION,
        "configuration_digest": request.configuration_digest,
        "configuration_bytes": request.configuration_bytes,
        "control_profile_id": request.control_profile_id,
        "control_profile_digest": request.control_profile_digest,
        "control_profile_media_type": request.control_profile_media_type,
        "control_profile_bytes": request.control_profile_bytes,
        "window_start": request.window_start,
        "window_end": request.window_end,
        "execution_plan_digest": sha256_digest(plan_bytes),
        "execution_plan_bytes": plan_bytes,
        "execution_identity_digest": (
            sha256_digest(execution_identity_bytes) if identity_bound or completed else None
        ),
        "execution_identity_bytes": (
            execution_identity_bytes if identity_bound or completed else None
        ),
        "highest_lease_fence": highest,
        "completion_lease_fence": request.lease_fence if completed else None,
        "evidence_digest": _EVIDENCE if completed else None,
        "executor_receipt_digest": _RECEIPT if completed else None,
        "executor_receipt_bytes": _RECEIPT_BYTES if completed else None,
        "attempt_count": request.attempt_count,
        "attempt_worker_id": worker_id,
        "attempt_lease_token_digest": token,
        "attempt_state": state,
        "attempt_revision": revision,
        "attempt_prepared_at": _PREPARED,
        "attempt_publishing_at": publishing,
        "attempt_finished_at": finished,
        "attempt_error_code": error_code,
    }


class _Cursor:
    def __init__(self, rows: tuple[Mapping[str, Any], ...] = ()) -> None:
        self.rows = rows

    def fetchone(self) -> Mapping[str, Any] | None:
        return None if not self.rows else self.rows[0]

    def fetchall(self) -> Sequence[Mapping[str, Any]]:
        return self.rows


class _ScriptedConnection:
    def __init__(
        self,
        script: tuple[tuple[str, _Cursor | BaseException], ...],
        *,
        schema_versions: tuple[int, ...] = (1, 2, 3, 4, 5, 6),
    ) -> None:
        self.script = list(script)
        self.schema_versions = schema_versions
        self.executed: list[tuple[str, tuple[object, ...]]] = []
        self.commits = 0
        self.rollbacks = 0

    def execute(
        self,
        query: str,
        params: Sequence[object] = (),
    ) -> _Cursor:
        normalized = " ".join(query.split()).lower()
        bound = tuple(params)
        assert normalized.count("%s") == len(bound)
        self.executed.append((normalized, bound))
        if normalized.startswith("set transaction isolation level"):
            return _Cursor()
        if "assert_session_principal(" in normalized:
            return _Cursor(({"assert_session_principal": True},))
        if "select set_config(" in normalized:
            return _Cursor()
        if "control_assurance_execution.schema_migrations" in normalized:
            return _Cursor(({"versions": list(self.schema_versions)},))
        if not self.script:
            raise AssertionError(f"unexpected SQL: {normalized}")
        expected, result = self.script.pop(0)
        assert expected in normalized
        if isinstance(result, BaseException):
            raise result
        return result

    @contextmanager
    def transaction(self) -> Iterator[object]:
        try:
            yield object()
        except BaseException:
            self.rollbacks += 1
            raise
        else:
            self.commits += 1


class _Pool:
    def __init__(self, connection: _ScriptedConnection) -> None:
        self.connection_value = connection

    @contextmanager
    def connection(self) -> Iterator[_ScriptedConnection]:
        yield self.connection_value


class _RecoverySigner:
    def __init__(self, seed: bytes, *, key_id: str) -> None:
        self._private = Ed25519PrivateKey.from_private_bytes(seed)
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_key_bytes(self) -> bytes:
        return self._private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, message: bytes) -> DetachedSignature:
        import base64

        return DetachedSignature(
            key_id=self.key_id,
            algorithm="ed25519",
            signature=base64.b64encode(self._private.sign(message)).decode("ascii"),
        )


def _recovery_material(
    request: ControlRunExecutionRequest,
    plan: bytes,
) -> tuple[
    bytes,
    PublishingRecoveryJournalExpectation,
    _RecoverySigner,
    _RecoverySigner,
    _RecoverySigner,
    _RecoverySigner,
    _RecoverySigner,
    RecoveryActorVerificationPolicy,
    datetime,
]:
    def digest(character: str) -> str:
        return f"sha256:{character * 64}"

    recovery_now = _PREPARED + timedelta(minutes=9)
    old_expires = _PREPARED + timedelta(minutes=1)
    successor_expires = _PREPARED + timedelta(minutes=30)
    requested = _PREPARED + timedelta(minutes=2)
    fence_effective = _PREPARED + timedelta(minutes=3)
    fence_observed = _PREPARED + timedelta(minutes=4)
    fence_attested = _PREPARED + timedelta(minutes=5)
    drain_not_before = fence_effective + timedelta(minutes=2)
    drain_checked = drain_not_before + timedelta(minutes=1)
    drain_attested = drain_checked + timedelta(minutes=1)
    approved = drain_attested + timedelta(minutes=1)
    authorization_expires = approved + timedelta(minutes=10)
    execution_identity_digest = sha256_digest(_execution_identity_bytes(request, plan))
    old = AbandonedPublishingAttempt(
        lease_fence=1,
        attempt_count=1,
        worker_id="executor-a",
        worker_credential_digest=digest("8"),
        lease_token_digest=_TOKEN_ONE,
        leased_at=_PREPARED - timedelta(minutes=5),
        lease_expires_at=old_expires,
        publishing_at=_PREPARED,
    )
    successor = SuccessorLeaseClaim(
        lease_fence=2,
        attempt_count=2,
        worker_id="executor-b",
        worker_credential_digest=digest("9"),
        lease_token_digest=_TOKEN_TWO,
        leased_at=old_expires,
        lease_expires_at=successor_expires,
    )
    connector_request_digest = digest("a")
    pam_scopes = migrate_legacy_pam_recovery_scopes(
        authority_classes=("source",),
        connector_ids=("elastic-security",),
        connector_request_digests=(connector_request_digest,),
    )
    pam_scope_digest = publishing_recovery_pam_scope_digest(pam_scopes)
    execution_binding = publishing_recovery_execution_binding_digest(
        tenant_id=request.tenant_id,
        run_id=request.run_id,
        execution_plan_digest=sha256_digest(plan),
        execution_identity_digest=execution_identity_digest,
        abandoned_lease_fence=old.lease_fence,
        pam_scope_digest=pam_scope_digest,
    )
    actor_policy = RecoveryActorVerificationPolicy(
        audience="control-assurance-recovery",
        maker_issuer_id="idp:maker",
        checker_issuer_id="idp:checker",
    )
    final_signer = _RecoverySigner(
        b"\x31" * 32,
        key_id="recovery-authority-v2",
    )
    fence_signer = _RecoverySigner(
        b"\x32" * 32,
        key_id="fence-authority-v2",
    )
    drain_signer = _RecoverySigner(
        b"\x33" * 32,
        key_id="drain-authority-v2",
    )
    maker_signer = _RecoverySigner(
        b"\x34" * 32,
        key_id="maker-idp-v2",
    )
    checker_signer = _RecoverySigner(
        b"\x35" * 32,
        key_id="checker-idp-v2",
    )
    maker = RecoveryActorAssertion(
        subject_id="user:recovery-maker",
        session_digest=digest("b"),
        role="maker",
        authenticated_at=requested - timedelta(minutes=2),
        mfa_verified_at=requested - timedelta(minutes=1),
    )
    request_expires = requested + timedelta(hours=1)
    request_intent = PublishingRecoveryRequestIntent(
        tenant_id=request.tenant_id,
        run_id=request.run_id,
        control_id=request.control_id,
        configuration_digest=request.configuration_digest,
        execution_plan_digest=sha256_digest(plan),
        execution_identity_digest=execution_identity_digest,
        abandoned_attempt=old,
        successor_claim=successor,
        pam_scopes=pam_scopes,
        pam_scope_digest=pam_scope_digest,
        pam_execution_binding_digest=execution_binding,
        reason="old-worker-unreachable",
        incident_reference_digest=digest("c"),
        requested_at=requested,
        request_expires_at=request_expires,
        request_nonce="1" * 64,
    )
    maker_action = migrate_recovery_actor_assertion(
        maker,
        issuer_id=actor_policy.maker_issuer_id,
        audience=actor_policy.audience,
        tenant_id=request.tenant_id,
        run_id=request.run_id,
        action="request",
        action_digest=request_intent.digest,
        acted_at=requested,
        expires_at=request_expires,
        action_nonce="2" * 64,
        idp_key_fingerprint=sha256_digest(maker_signer.public_key_bytes),
    )
    signed_maker_action = issue_recovery_actor_action(
        maker_action,
        signer=maker_signer,
    )
    recovery_request = PublishingRecoveryRequest(
        intent_digest=request_intent.digest,
        intent=request_intent,
        signed_maker_action=signed_maker_action,
    )
    fence = ComputeFenceAttestation(
        recovery_request_digest=recovery_request.digest,
        tenant_id=request.tenant_id,
        run_id=request.run_id,
        abandoned_attempt_digest=old.digest,
        workload=WorkloadFenceLocator(
            cluster_uid="cluster:production-1",
            namespace="assurance-runtime",
            service_account_uid="service-account:runtime",
            pod_uid="pod:old-worker",
            node_uid="node:runtime-1",
            container_image_digest=digest("d"),
            worker_id=old.worker_id,
            worker_credential_digest=old.worker_credential_digest,
        ),
        method="pod-runtime-terminated",
        old_process_absent=True,
        old_workload_egress_denied=False,
        node_reachable_at_observation=True,
        kubernetes_delete_operation_digest=digest("e"),
        proof_media_type=("application/vnd.control-assurance.kubernetes-fence-proof.v1+json"),
        proof_digest=digest("f"),
        relaunch_fence_operation_digest=digest("7"),
        relaunch_fence_effective_at=fence_effective,
        relaunch_fence_valid_until=successor_expires,
        fencing_controller_id="system:fence-controller",
        fencing_controller_credential_digest=digest("0"),
        fencing_authority_key_fingerprint=sha256_digest(fence_signer.public_key_bytes),
        fence_requested_at=requested,
        fence_effective_at=fence_effective,
        isolation_observed_at=fence_observed,
        attested_at=fence_attested,
    )
    signed_fence = issue_compute_fence_attestation(
        fence,
        signer=fence_signer,
    )
    anchor = PAMDrainAnchor(
        authority_class="source",
        connector_id="elastic-security",
        connector_request_digest=connector_request_digest,
        scope_digest=pam_scope_digest,
        execution_binding_digest=execution_binding,
        lifecycle_record_id="pam:source:recovery",
        lifecycle_record_digest=digest("1"),
        lifecycle_sequence=1,
        lifecycle_revision=1,
        state="never-issued",
        expiry_basis="not-issued",
        created_at=requested,
        maximum_residual_exposure_ends_at=requested,
        settled_at=requested,
    )
    drain = CredentialDrainAttestation(
        recovery_request_digest=recovery_request.digest,
        compute_fence_attestation_digest=fence.digest,
        tenant_id=request.tenant_id,
        run_id=request.run_id,
        abandoned_attempt_digest=old.digest,
        scope_digest=pam_scope_digest,
        execution_binding_digest=execution_binding,
        anchors=(anchor,),
        lifecycle_snapshot_digest=credential_drain_lifecycle_snapshot_digest(
            scope_digest=pam_scope_digest,
            execution_binding_digest=execution_binding,
            snapshot_high_watermark=1,
            anchors=(anchor,),
        ),
        lifecycle_record_count=1,
        snapshot_high_watermark=1,
        maximum_residual_exposure_ends_at=requested,
        fence_effective_at=fence_effective,
        maximum_inflight_seconds=60,
        clock_skew_seconds=60,
        post_fence_inflight_deadline=drain_not_before,
        drain_not_before=drain_not_before,
        checked_at=drain_checked,
        attested_at=drain_attested,
        issuance_fence_operation_digest=digest("3"),
        issuance_fence_effective_at=fence_effective,
        issuance_fence_valid_until=successor_expires,
        issuance_fence_high_watermark=1,
        drain_controller_id="system:drain-controller",
        drain_controller_credential_digest=digest("2"),
        drain_authority_key_fingerprint=sha256_digest(drain_signer.public_key_bytes),
        pam_query_evidence_media_type=("application/vnd.control-assurance.pam-drain-proof.v1+json"),
        pam_query_evidence_digest=digest("3"),
    )
    signed_drain = issue_credential_drain_attestation(
        drain,
        signer=drain_signer,
    )
    checker = RecoveryActorAssertion(
        subject_id="user:recovery-checker",
        session_digest=digest("4"),
        role="checker",
        authenticated_at=approved - timedelta(minutes=2),
        mfa_verified_at=approved - timedelta(minutes=1),
    )
    authorization_values: dict[str, object] = {
        "tenant_id": request.tenant_id,
        "run_id": request.run_id,
        "control_id": request.control_id,
        "configuration_digest": request.configuration_digest,
        "execution_plan_digest": sha256_digest(plan),
        "execution_identity_digest": execution_identity_digest,
        "recovery_request_digest": recovery_request.digest,
        "recovery_request": recovery_request,
        "compute_fence_attestation_digest": fence.digest,
        "signed_compute_fence_attestation_digest": signed_fence.digest,
        "signed_compute_fence_attestation": signed_fence,
        "credential_drain_attestation_digest": drain.digest,
        "signed_credential_drain_attestation_digest": signed_drain.digest,
        "signed_credential_drain_attestation": signed_drain,
        "abandoned_attempt": old,
        "successor_claim": successor,
        "change_approval_digest": digest("5"),
        "approved_at": approved,
        "not_before": drain_not_before,
        "issued_at": approved,
        "expires_at": authorization_expires,
        "authorization_nonce": "6" * 64,
        "recovery_authority_id": "system:recovery-authority",
        "recovery_authority_key_fingerprint": sha256_digest(final_signer.public_key_bytes),
    }
    checker_action_digest = publishing_recovery_checker_action_digest(
        tenant_id=request.tenant_id,
        run_id=request.run_id,
        recovery_request_digest=recovery_request.digest,
        signed_compute_fence_attestation_digest=signed_fence.digest,
        signed_credential_drain_attestation_digest=signed_drain.digest,
        abandoned_attempt_digest=old.digest,
        successor_claim_digest=successor.digest,
        change_approval_digest=digest("5"),
        approved_at=approved,
        not_before=drain_not_before,
        issued_at=approved,
        expires_at=authorization_expires,
        authorization_nonce="6" * 64,
        recovery_authority_id="system:recovery-authority",
        recovery_authority_key_fingerprint=sha256_digest(final_signer.public_key_bytes),
    )
    checker_action = migrate_recovery_actor_assertion(
        checker,
        issuer_id=actor_policy.checker_issuer_id,
        audience=actor_policy.audience,
        tenant_id=request.tenant_id,
        run_id=request.run_id,
        action="approve",
        action_digest=checker_action_digest,
        acted_at=approved,
        expires_at=authorization_expires,
        action_nonce="4" * 64,
        idp_key_fingerprint=sha256_digest(checker_signer.public_key_bytes),
    )
    signed_checker_action = issue_recovery_actor_action(
        checker_action,
        signer=checker_signer,
    )
    authorization_values["signed_checker_action_digest"] = signed_checker_action.digest
    authorization_values["signed_checker_action"] = signed_checker_action
    authorization = PublishingRecoveryAuthorization.model_validate(authorization_values)
    envelope = issue_publishing_recovery_authorization(
        authorization,
        signer=final_signer,
        fence_verifier=fence_signer,
        drain_verifier=drain_signer,
        maker_verifier=maker_signer,
        checker_verifier=checker_signer,
        actor_policy=actor_policy,
    )
    expectation = PublishingRecoveryJournalExpectation(
        tenant_id=request.tenant_id,
        run_id=request.run_id,
        control_id=request.control_id,
        configuration_digest=request.configuration_digest,
        execution_plan_digest=sha256_digest(plan),
        execution_identity_digest=execution_identity_digest,
        recovery_request_digest=recovery_request.digest,
        pam_scope_digest=pam_scope_digest,
        pam_execution_binding_digest=execution_binding,
        pam_snapshot_high_watermark=drain.snapshot_high_watermark,
        pam_lifecycle_record_count=drain.lifecycle_record_count,
        relaunch_fence_operation_digest=(fence.relaunch_fence_operation_digest),
        issuance_fence_operation_digest=(drain.issuance_fence_operation_digest),
        abandoned_lease_fence=1,
        abandoned_attempt_count=1,
        abandoned_attempt_revision=1,
        abandoned_worker_id="executor-a",
        abandoned_lease_token_digest=_TOKEN_ONE,
        abandoned_publishing_at=_PREPARED,
        successor_lease_fence=2,
        successor_attempt_count=2,
        successor_worker_id="executor-b",
        successor_lease_token_digest=_TOKEN_TWO,
    )
    return (
        envelope.canonical_bytes(),
        expectation,
        final_signer,
        fence_signer,
        drain_signer,
        maker_signer,
        checker_signer,
        actor_policy,
        recovery_now,
    )


def test_plan_is_prepared_once_and_completion_retry_returns_exact_receipt() -> None:
    request = _execution_request()
    plan = _plan_bytes(request)
    execution_identity_bytes = _execution_identity_bytes(request, plan)
    execution_identity_digest = sha256_digest(execution_identity_bytes)
    prepared = _row(request, plan, state="prepared", revision=0)
    publishing = _row(
        request,
        plan,
        state="publishing",
        revision=1,
        publishing=_PREPARED,
    )
    bound = _row(
        request,
        plan,
        state="publishing",
        revision=1,
        publishing=_PREPARED,
        identity_bound=True,
    )
    completed = _row(
        request,
        plan,
        state="completed",
        revision=2,
        publishing=_PREPARED,
        finished=_PREPARED,
        completed=True,
    )
    current = "from control_assurance_execution.executions as execution"
    connection = _ScriptedConnection(
        (
            (current, _Cursor()),
            (
                "insert into control_assurance_execution.executions",
                _Cursor(({"run_id": request.run_id},)),
            ),
            ("insert into control_assurance_execution.execution_attempts", _Cursor()),
            (current, _Cursor((prepared,))),
            (current, _Cursor((prepared,))),
            (
                "update control_assurance_execution.execution_attempts",
                _Cursor(({"lease_fence": 1},)),
            ),
            (current, _Cursor((publishing,))),
            (current, _Cursor((publishing,))),
            (
                "update control_assurance_execution.executions",
                _Cursor(({"run_id": request.run_id},)),
            ),
            (current, _Cursor((bound,))),
            (current, _Cursor((bound,))),
            (
                "update control_assurance_execution.execution_attempts",
                _Cursor(({"lease_fence": 1},)),
            ),
            (
                "update control_assurance_execution.executions",
                _Cursor(({"run_id": request.run_id},)),
            ),
            (current, _Cursor((completed,))),
            (current, _Cursor((completed,))),
        )
    )
    journal = PostgresExecutionJournal(_Pool(connection))
    result = ControlRunExecutionResult(
        run_id=request.run_id,
        lease_fence=1,
        evidence_digest=_EVIDENCE,
        executor_receipt_digest=_RECEIPT,
    )

    first = journal.prepare(
        request,
        worker_id="executor-a",
        lease_token_digest=_TOKEN_ONE,
        execution_plan_bytes=plan,
    )
    second = journal.begin_publishing(
        tenant_id=request.tenant_id,
        run_id=request.run_id,
        lease_fence=1,
        worker_id="executor-a",
        lease_token_digest=_TOKEN_ONE,
        expected_revision=first.revision,
    )
    bound_record = journal.bind_execution_identity(
        tenant_id=request.tenant_id,
        run_id=request.run_id,
        lease_fence=1,
        worker_id="executor-a",
        lease_token_digest=_TOKEN_ONE,
        expected_revision=second.revision,
        execution_identity_digest=execution_identity_digest,
        execution_identity_bytes=execution_identity_bytes,
    )
    third = journal.mark_completed(
        tenant_id=request.tenant_id,
        run_id=request.run_id,
        lease_fence=1,
        worker_id="executor-a",
        lease_token_digest=_TOKEN_ONE,
        expected_revision=bound_record.revision,
        result=result,
        executor_receipt_bytes=_RECEIPT_BYTES,
    )
    retried = journal.mark_completed(
        tenant_id=request.tenant_id,
        run_id=request.run_id,
        lease_fence=1,
        worker_id="executor-a",
        lease_token_digest=_TOKEN_ONE,
        expected_revision=bound_record.revision,
        result=result,
        executor_receipt_bytes=_RECEIPT_BYTES,
    )

    assert (first.state, second.state, third.state) == (
        "prepared",
        "publishing",
        "completed",
    )
    assert retried.result == result
    assert retried.execution_plan_bytes == plan
    assert retried.executor_receipt_bytes == _RECEIPT_BYTES
    assert third.execution_identity_digest == execution_identity_digest
    assert connection.commits == 5
    assert not connection.script
    assert not any(
        query.startswith(("create ", "alter ", "drop ")) for query, _ in connection.executed
    )


def test_higher_fence_cannot_supersede_identity_bound_publishing() -> None:
    first = _execution_request(attempt_count=1)
    second = _execution_request(attempt_count=2)
    plan = _plan_bytes(first)
    publishing = _row(
        first,
        plan,
        state="publishing",
        revision=1,
        publishing=_PREPARED,
        identity_bound=True,
    )
    current = "from control_assurance_execution.executions as execution"
    connection = _ScriptedConnection(((current, _Cursor((publishing,))),))
    journal = PostgresExecutionJournal(_Pool(connection))

    with pytest.raises(
        ExecutionJournalConflict,
        match="identity-bound publishing execution requires reconciliation",
    ):
        journal.prepare(
            second,
            worker_id="executor-b",
            lease_token_digest=_TOKEN_TWO,
            execution_plan_bytes=None,
        )

    assert not connection.script
    assert not any(query.startswith(("update ", "insert ")) for query, _ in connection.executed)


def test_signed_recovery_atomically_adopts_exact_successor_in_publishing() -> None:
    first = _execution_request(attempt_count=1)
    second = _execution_request(attempt_count=2)
    plan = _plan_bytes(first)
    (
        authorization_bytes,
        expectation,
        final_signer,
        fence_signer,
        drain_signer,
        maker_signer,
        checker_signer,
        actor_policy,
        recovery_now,
    ) = _recovery_material(first, plan)
    old = _row(
        first,
        plan,
        state="publishing",
        revision=1,
        publishing=_PREPARED,
        identity_bound=True,
    )
    successor = _row(
        second,
        plan,
        state="publishing",
        revision=1,
        worker_id="executor-b",
        token=_TOKEN_TWO,
        publishing=recovery_now,
        identity_bound=True,
    )
    current = "from control_assurance_execution.executions as execution"
    connection = _ScriptedConnection(
        (
            (current, _Cursor((old,))),
            ("select date_trunc(", _Cursor(({"recovery_now": recovery_now},))),
            (
                "consume_publishing_recovery_authorization",
                _Cursor(({"consumed": True},)),
            ),
            (current, _Cursor((successor,))),
        )
    )

    recovered = PostgresExecutionJournal(_Pool(connection)).recover_identity_bound_publication(
        authorization_bytes,
        journal_expectation=expectation,
        verifier=final_signer,
        fence_verifier=fence_signer,
        drain_verifier=drain_signer,
        maker_verifier=maker_signer,
        checker_verifier=checker_signer,
        actor_policy=actor_policy,
    )

    assert (
        recovered.request.lease_fence,
        recovered.request.attempt_count,
        recovered.worker_id,
        recovered.lease_token_digest,
        recovered.state,
        recovered.revision,
    ) == (2, 2, "executor-b", _TOKEN_TWO, "publishing", 1)
    routine_calls = [
        params
        for query, params in connection.executed
        if "consume_publishing_recovery_authorization" in query
    ]
    assert len(routine_calls) == 1
    assert routine_calls[0][0] == authorization_bytes
    assert len(routine_calls[0]) == 13
    assert all(type(value) is bytes for value in routine_calls[0])
    assert connection.commits == 1
    assert connection.rollbacks == 0
    assert not connection.script


def test_recovery_replay_is_rejected_and_transaction_rolls_back() -> None:
    request = _execution_request()
    plan = _plan_bytes(request)
    (
        authorization_bytes,
        expectation,
        final_signer,
        fence_signer,
        drain_signer,
        maker_signer,
        checker_signer,
        actor_policy,
        recovery_now,
    ) = _recovery_material(request, plan)
    old = _row(
        request,
        plan,
        state="publishing",
        revision=1,
        publishing=_PREPARED,
        identity_bound=True,
    )
    current = "from control_assurance_execution.executions as execution"
    connection = _ScriptedConnection(
        (
            (current, _Cursor((old,))),
            ("select date_trunc(", _Cursor(({"recovery_now": recovery_now},))),
            (
                "consume_publishing_recovery_authorization",
                _Cursor(({"consumed": False},)),
            ),
        )
    )

    with pytest.raises(ExecutionJournalConflict, match="authorization-consumed"):
        PostgresExecutionJournal(_Pool(connection)).recover_identity_bound_publication(
            authorization_bytes,
            journal_expectation=expectation,
            verifier=final_signer,
            fence_verifier=fence_signer,
            drain_verifier=drain_signer,
            maker_verifier=maker_signer,
            checker_verifier=checker_signer,
            actor_policy=actor_policy,
        )

    assert connection.commits == 0
    assert connection.rollbacks == 1
    assert not connection.script


@pytest.mark.parametrize(
    ("expectation_change", "state_change"),
    (
        ({"abandoned_worker_id": "executor-stale"}, {}),
        ({"execution_plan_digest": f"sha256:{'d' * 64}"}, {}),
        ({"execution_identity_digest": f"sha256:{'e' * 64}"}, {}),
        (
            {},
            {
                "state": "uncertain",
                "revision": 2,
                "finished": _PREPARED + timedelta(minutes=1),
                "error_code": "publisher-outcome-unknown",
            },
        ),
    ),
)
def test_recovery_rejects_stale_tuple_plan_identity_or_state_drift(
    expectation_change: dict[str, object],
    state_change: dict[str, object],
) -> None:
    request = _execution_request()
    plan = _plan_bytes(request)
    (
        authorization_bytes,
        expectation,
        final_signer,
        fence_signer,
        drain_signer,
        maker_signer,
        checker_signer,
        actor_policy,
        _,
    ) = _recovery_material(request, plan)
    expectation = PublishingRecoveryJournalExpectation.model_validate(
        {
            **expectation.model_dump(mode="python"),
            **expectation_change,
        }
    )
    state_value = state_change.get("state", "publishing")
    revision_value = state_change.get("revision", 1)
    finished_value = state_change.get("finished")
    error_value = state_change.get("error_code")
    assert isinstance(state_value, str)
    assert type(revision_value) is int
    assert finished_value is None or isinstance(finished_value, datetime)
    assert error_value is None or isinstance(error_value, str)
    old = _row(
        request,
        plan,
        state=state_value,
        revision=revision_value,
        publishing=_PREPARED,
        finished=finished_value,
        error_code=error_value,
        identity_bound=True,
    )
    current = "from control_assurance_execution.executions as execution"
    connection = _ScriptedConnection(((current, _Cursor((old,))),))

    with pytest.raises(ExecutionJournalConflict, match="durable state"):
        PostgresExecutionJournal(_Pool(connection)).recover_identity_bound_publication(
            authorization_bytes,
            journal_expectation=expectation,
            verifier=final_signer,
            fence_verifier=fence_signer,
            drain_verifier=drain_signer,
            maker_verifier=maker_signer,
            checker_verifier=checker_signer,
            actor_policy=actor_policy,
        )

    assert not connection.script
    assert not any(
        "consume_publishing_recovery_authorization" in query for query, _ in connection.executed
    )


def test_recovery_rejects_signed_successor_swapped_by_caller() -> None:
    request = _execution_request()
    plan = _plan_bytes(request)
    (
        authorization_bytes,
        expectation,
        final_signer,
        fence_signer,
        drain_signer,
        maker_signer,
        checker_signer,
        actor_policy,
        recovery_now,
    ) = _recovery_material(request, plan)
    swapped = PublishingRecoveryJournalExpectation.model_validate(
        {
            **expectation.model_dump(mode="python"),
            "successor_worker_id": "executor-c",
        }
    )
    old = _row(
        request,
        plan,
        state="publishing",
        revision=1,
        publishing=_PREPARED,
        identity_bound=True,
    )
    current = "from control_assurance_execution.executions as execution"
    connection = _ScriptedConnection(
        (
            (current, _Cursor((old,))),
            ("select date_trunc(", _Cursor(({"recovery_now": recovery_now},))),
        )
    )

    with pytest.raises(ExecutionJournalConflict, match="journal-binding-mismatch"):
        PostgresExecutionJournal(_Pool(connection)).recover_identity_bound_publication(
            authorization_bytes,
            journal_expectation=swapped,
            verifier=final_signer,
            fence_verifier=fence_signer,
            drain_verifier=drain_signer,
            maker_verifier=maker_signer,
            checker_verifier=checker_signer,
            actor_policy=actor_policy,
        )

    assert connection.rollbacks == 1
    assert not connection.script
    assert not any(
        "consume_publishing_recovery_authorization" in query for query, _ in connection.executed
    )


def test_execution_identity_binding_is_exact_idempotent_and_fenced() -> None:
    request = _execution_request()
    plan = _plan_bytes(request)
    execution_identity_bytes = _execution_identity_bytes(request, plan)
    execution_identity_digest = sha256_digest(execution_identity_bytes)
    current = "from control_assurance_execution.executions as execution"
    bound = _row(
        request,
        plan,
        state="publishing",
        revision=1,
        publishing=_PREPARED,
        identity_bound=True,
    )
    exact_connection = _ScriptedConnection(((current, _Cursor((bound,))),))
    exact = PostgresExecutionJournal(_Pool(exact_connection))

    retried = exact.bind_execution_identity(
        tenant_id=request.tenant_id,
        run_id=request.run_id,
        lease_fence=1,
        worker_id="executor-a",
        lease_token_digest=_TOKEN_ONE,
        expected_revision=1,
        execution_identity_digest=execution_identity_digest,
        execution_identity_bytes=execution_identity_bytes,
    )

    assert retried.execution_identity_bytes == execution_identity_bytes
    assert not exact_connection.script
    assert not any(
        query.startswith("update control_assurance_execution.executions")
        for query, _ in exact_connection.executed
    )

    changed_bytes = _execution_identity_bytes(
        request,
        plan,
        deployment_profile_digest=f"sha256:{'8' * 64}",
    )
    changed_connection = _ScriptedConnection(((current, _Cursor((bound,))),))
    with pytest.raises(ExecutionJournalConflict, match="differs"):
        PostgresExecutionJournal(_Pool(changed_connection)).bind_execution_identity(
            tenant_id=request.tenant_id,
            run_id=request.run_id,
            lease_fence=1,
            worker_id="executor-a",
            lease_token_digest=_TOKEN_ONE,
            expected_revision=1,
            execution_identity_digest=sha256_digest(changed_bytes),
            execution_identity_bytes=changed_bytes,
        )

    stale_connection = _ScriptedConnection(((current, _Cursor((bound,))),))
    with pytest.raises(ExecutionJournalConflict, match="stale publishing"):
        PostgresExecutionJournal(_Pool(stale_connection)).bind_execution_identity(
            tenant_id=request.tenant_id,
            run_id=request.run_id,
            lease_fence=1,
            worker_id="executor-a",
            lease_token_digest=_TOKEN_ONE,
            expected_revision=9,
            execution_identity_digest=execution_identity_digest,
            execution_identity_bytes=execution_identity_bytes,
        )


def test_execution_identity_must_be_one_canonical_object_with_exact_digest() -> None:
    request = _execution_request()
    plan = _plan_bytes(request)
    execution_identity_bytes = _execution_identity_bytes(request, plan)
    connection = _ScriptedConnection(())
    journal = PostgresExecutionJournal(_Pool(connection))

    with pytest.raises(ExecutionJournalConflict, match="canonical"):
        journal.bind_execution_identity(
            tenant_id=request.tenant_id,
            run_id=request.run_id,
            lease_fence=1,
            worker_id="executor-a",
            lease_token_digest=_TOKEN_ONE,
            expected_revision=1,
            execution_identity_digest=sha256_digest(b"[]"),
            execution_identity_bytes=b"[]",
        )
    with pytest.raises(ExecutionJournalConflict, match="canonical"):
        journal.bind_execution_identity(
            tenant_id=request.tenant_id,
            run_id=request.run_id,
            lease_fence=1,
            worker_id="executor-a",
            lease_token_digest=_TOKEN_ONE,
            expected_revision=1,
            execution_identity_digest=sha256_digest(b"{}"),
            execution_identity_bytes=b"{}",
        )
    with pytest.raises(ExecutionJournalConflict, match="canonical"):
        journal.bind_execution_identity(
            tenant_id=request.tenant_id,
            run_id=request.run_id,
            lease_fence=1,
            worker_id="executor-a",
            lease_token_digest=_TOKEN_ONE,
            expected_revision=1,
            execution_identity_digest=f"sha256:{'a' * 64}",
            execution_identity_bytes=execution_identity_bytes,
        )
    assert connection.executed == []


def test_execution_identity_cannot_cross_its_journaled_run() -> None:
    request = _execution_request()
    plan = _plan_bytes(request)
    other = _execution_request(tenant_id="bank-b")
    other_plan = _plan_bytes(other)
    crossed_bytes = _execution_identity_bytes(other, other_plan)
    current = "from control_assurance_execution.executions as execution"
    publishing = _row(
        request,
        plan,
        state="publishing",
        revision=1,
        publishing=_PREPARED,
    )
    connection = _ScriptedConnection(((current, _Cursor((publishing,))),))

    with pytest.raises(ExecutionJournalConflict, match="crosses"):
        PostgresExecutionJournal(_Pool(connection)).bind_execution_identity(
            tenant_id=request.tenant_id,
            run_id=request.run_id,
            lease_fence=1,
            worker_id="executor-a",
            lease_token_digest=_TOKEN_ONE,
            expected_revision=1,
            execution_identity_digest=sha256_digest(crossed_bytes),
            execution_identity_bytes=crossed_bytes,
        )

    assert not connection.script
    assert not any(
        query.startswith("update control_assurance_execution.executions")
        for query, _ in connection.executed
    )


def test_stale_fence_and_different_recovery_plan_are_rejected() -> None:
    first = _execution_request(attempt_count=1)
    second = _execution_request(attempt_count=2)
    plan = _plan_bytes(first)
    current_row = _row(
        second,
        plan,
        state="prepared",
        revision=0,
        worker_id="executor-b",
        token=_TOKEN_TWO,
    )
    current = "from control_assurance_execution.executions as execution"
    stale_connection = _ScriptedConnection(((current, _Cursor((current_row,))),))
    stale = PostgresExecutionJournal(_Pool(stale_connection))

    with pytest.raises(ExecutionJournalConflict, match="stale"):
        stale.prepare(
            first,
            worker_id="executor-a",
            lease_token_digest=_TOKEN_ONE,
            execution_plan_bytes=plan,
        )

    publishing = _row(
        first,
        plan,
        state="publishing",
        revision=1,
        publishing=_PREPARED,
    )
    changed_connection = _ScriptedConnection(((current, _Cursor((publishing,))),))
    changed = PostgresExecutionJournal(_Pool(changed_connection))
    with pytest.raises(ExecutionJournalConflict, match="plan differs"):
        changed.prepare(
            second,
            worker_id="executor-b",
            lease_token_digest=_TOKEN_TWO,
            execution_plan_bytes=_plan_bytes(second, nonce="cd" * 32),
        )


def test_cas_substitution_and_conflicting_completion_fail_closed() -> None:
    request = _execution_request()
    plan = _plan_bytes(request)
    prepared = _row(request, plan, state="prepared", revision=0)
    current = "from control_assurance_execution.executions as execution"
    cas_connection = _ScriptedConnection(((current, _Cursor((prepared,))),))
    journal = PostgresExecutionJournal(_Pool(cas_connection))
    with pytest.raises(ExecutionJournalConflict, match="compare-and-swap"):
        journal.begin_publishing(
            tenant_id=request.tenant_id,
            run_id=request.run_id,
            lease_fence=1,
            worker_id="executor-a",
            lease_token_digest=_TOKEN_ONE,
            expected_revision=9,
        )

    completed = _row(
        request,
        plan,
        state="completed",
        revision=2,
        publishing=_PREPARED,
        finished=_PREPARED,
        completed=True,
    )
    conflict_connection = _ScriptedConnection(((current, _Cursor((completed,))),))
    conflict = PostgresExecutionJournal(_Pool(conflict_connection))
    other_receipt_bytes = canonical_json_bytes({"outcome": "different"})
    with pytest.raises(ExecutionJournalConflict, match="differs"):
        conflict.mark_completed(
            tenant_id=request.tenant_id,
            run_id=request.run_id,
            lease_fence=1,
            worker_id="executor-a",
            lease_token_digest=_TOKEN_ONE,
            expected_revision=1,
            result=ControlRunExecutionResult(
                run_id=request.run_id,
                lease_fence=1,
                evidence_digest=f"sha256:{'9' * 64}",
                executor_receipt_digest=sha256_digest(other_receipt_bytes),
            ),
            executor_receipt_bytes=other_receipt_bytes,
        )

    substituted = request.model_copy(update={"run_request_bytes": request.run_request_bytes + b" "})
    empty_connection = _ScriptedConnection(())
    with pytest.raises(ValueError, match="independent validation"):
        PostgresExecutionJournal(_Pool(empty_connection)).prepare(
            substituted,
            worker_id="executor-a",
            lease_token_digest=_TOKEN_ONE,
            execution_plan_bytes=plan,
        )
    assert empty_connection.executed == []


def test_executor_receipt_must_be_one_exact_canonical_json_object() -> None:
    request = _execution_request()
    noncanonical = b'{ "outcome": "sealed" }'
    connection = _ScriptedConnection(())
    journal = PostgresExecutionJournal(_Pool(connection))

    with pytest.raises(ExecutionJournalConflict, match="canonical result"):
        journal.mark_completed(
            tenant_id=request.tenant_id,
            run_id=request.run_id,
            lease_fence=1,
            worker_id="executor-a",
            lease_token_digest=_TOKEN_ONE,
            expected_revision=1,
            result=ControlRunExecutionResult(
                run_id=request.run_id,
                lease_fence=1,
                evidence_digest=_EVIDENCE,
                executor_receipt_digest=sha256_digest(noncanonical),
            ),
            executor_receipt_bytes=noncanonical,
        )
    assert connection.executed == []


def test_completion_requires_a_bound_execution_environment_identity() -> None:
    request = _execution_request()
    plan = _plan_bytes(request)
    publishing = _row(
        request,
        plan,
        state="publishing",
        revision=1,
        publishing=_PREPARED,
    )
    current = "from control_assurance_execution.executions as execution"
    connection = _ScriptedConnection(((current, _Cursor((publishing,))),))

    with pytest.raises(ExecutionJournalConflict, match="compare-and-swap"):
        PostgresExecutionJournal(_Pool(connection)).mark_completed(
            tenant_id=request.tenant_id,
            run_id=request.run_id,
            lease_fence=1,
            worker_id="executor-a",
            lease_token_digest=_TOKEN_ONE,
            expected_revision=1,
            result=ControlRunExecutionResult(
                run_id=request.run_id,
                lease_fence=1,
                evidence_digest=_EVIDENCE,
                executor_receipt_digest=_RECEIPT,
            ),
            executor_receipt_bytes=_RECEIPT_BYTES,
        )
    assert not connection.script


def test_tenant_scope_is_set_before_lookup_and_missing_plan_cannot_create() -> None:
    request = _execution_request()
    current = "from control_assurance_execution.executions as execution"
    connection = _ScriptedConnection(((current, _Cursor()),))
    journal = PostgresExecutionJournal(_Pool(connection))

    with pytest.raises(ExecutionJournalNotFound):
        journal.get(tenant_id="bank-b", run_id=request.run_id)

    settings = [
        params
        for query, params in connection.executed
        if "assert_session_principal(" in query
    ]
    lookups = [params for query, params in connection.executed if current in query]
    assert settings == [("bank-b", "worker")]
    assert lookups == [("bank-b", request.run_id)]


def test_outdated_execution_journal_schema_is_rejected_before_lookup() -> None:
    request = _execution_request()
    connection = _ScriptedConnection((), schema_versions=(1, 2, 4))

    with pytest.raises(
        ExecutionJournalIntegrityError,
        match="schema version is unsupported",
    ):
        PostgresExecutionJournal(_Pool(connection)).get(
            tenant_id=request.tenant_id,
            run_id=request.run_id,
        )

    assert not any(
        "from control_assurance_execution.executions as execution" in query
        for query, _ in connection.executed
    )


def test_schema_enforces_rls_immutability_database_clocks_and_no_public_access() -> None:
    schema = (
        Path(__file__).parents[1] / "deploy" / "postgres" / "execution-journal-schema.sql"
    ).read_text(encoding="utf-8")
    required = (
        "FORCE ROW LEVEL SECURITY",
        "control_assurance_execution.session_tenant()",
        "execution journal requires UTF8 database encoding",
        "immutable execution identity",
        "immutable execution environment identity",
        "execution environment identity requires current publishing attempt",
        "identity-bound publishing execution requires reconciliation",
        "execution_identity_boundary",
        "COALESCE((",
        "immutable execution completion",
        "immutable execution attempt identity",
        "DEFERRABLE INITIALLY DEFERRED",
        "statement_timestamp()",
        "transaction_timestamp()",
        "REVOKE ALL ON ALL TABLES",
        "REVOKE ALL ON ALL FUNCTIONS",
        "executor_receipt_bytes",
        "execution_identity_digest",
        "jsonb_typeof",
        "publishing_recovery_authorizations",
        "consume_publishing_recovery_authorization",
        "SECURITY DEFINER",
        "signed_authorization_bytes",
        "recovery_request_intent_bytes",
        "signed_maker_action_bytes",
        "signed_checker_action_bytes",
        "signed_compute_fence_bytes",
        "signed_credential_drain_bytes",
        "pam_snapshot_high_watermark",
        "relaunch_fence_operation_digest",
        "issuance_fence_operation_digest",
        "recovery-superseded",
        "publishing_recovery_update_guard",
        "publishing_recovery_delete_guard",
        "ON CONFLICT (authorization_id) DO NOTHING",
        "PostgreSQL does not verify Ed25519",
        "maker-IdP, and checker-IdP",
        "never to PUBLIC or a runtime worker role",
        "publishing recovery v2 requires an explicit v1 archive migration",
        "installed_versions IS DISTINCT FROM ARRAY[1, 2, 3, 4, 5, 6]",
    )
    assert all(fragment in schema for fragment in required)
    assert "configure_login_role" in schema
    assert "\nGRANT EXECUTE ON FUNCTION" not in schema
    assert schema.count("BEGIN;") == 1
    assert schema.count("COMMIT;") == 1
