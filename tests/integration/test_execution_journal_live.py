"""Opt-in live PostgreSQL fencing, RLS, and crash-recovery coverage.

The live environment deliberately uses three database identities:

* ``CONTROL_ASSURANCE_POSTGRES_ADMIN_DSN`` is a PostgreSQL 17 test-cluster
  administrator used only for adversarial audit assertions.
* ``CONTROL_ASSURANCE_POSTGRES_MIGRATION_DSN`` is the exact database and
  schema owner.  It installs the schema and provisions the two runtime
  identities.
* ``CONTROL_ASSURANCE_POSTGRES_DSN`` is the ordinary runtime role.  It needs
  schema ``USAGE`` plus ``SELECT``/``INSERT``/``UPDATE`` on executions and
  attempts and ``SELECT`` on schema migrations.  It must not receive EXECUTE
  on the publishing-recovery routine.
* ``CONTROL_ASSURANCE_POSTGRES_RECOVERY_DSN`` is the dedicated recovery role.
  It needs schema ``USAGE``, ``SELECT`` on migrations/executions/attempts, and
  EXECUTE only on the publishing-recovery routine.  The routine performs the
  privileged transition as its definer.

Neither runtime identity may be a superuser or hold ``BYPASSRLS``.
"""

from __future__ import annotations

import base64
import importlib
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

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
    ExecutionJournalNotFound,
    ExecutionJournalRecord,
    PostgresExecutionJournal,
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
    SignedPublishingRecoveryAuthorization,
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

_DSN = os.environ.get("CONTROL_ASSURANCE_POSTGRES_DSN")
_ADMIN_DSN = os.environ.get("CONTROL_ASSURANCE_POSTGRES_ADMIN_DSN")
_MIGRATION_DSN = os.environ.get("CONTROL_ASSURANCE_POSTGRES_MIGRATION_DSN")
_RECOVERY_DSN = os.environ.get("CONTROL_ASSURANCE_POSTGRES_RECOVERY_DSN")
_TENANT_ID = os.environ.get("CONTROL_ASSURANCE_POSTGRES_EXECUTION_TENANT")
pytestmark = pytest.mark.skipif(
    not all(
        (
            _DSN,
            _ADMIN_DSN,
            _MIGRATION_DSN,
            _RECOVERY_DSN,
            _TENANT_ID,
        )
    ),
    reason="separated PostgreSQL execution-journal DSNs are not configured",
)
_START = datetime(2026, 7, 29, 1, 0, tzinfo=UTC)
_END = _START + timedelta(minutes=5)
_PREPARED = _END + timedelta(minutes=2)
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
_RULE = "12345678-1234-4234-9234-123456789abc"


def _install_schema(dsn: str) -> None:
    assert _DSN is not None
    assert _RECOVERY_DSN is not None
    assert _TENANT_ID is not None
    psycopg = importlib.import_module("psycopg")
    schema = (
        Path(__file__).parents[2] / "deploy" / "postgres" / "execution-journal-schema.sql"
    ).read_text(encoding="utf-8")
    runtime_role = _database_principal(_DSN)
    recovery_role = _database_principal(_RECOVERY_DSN)
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(schema)
        for role, principal_kind in (
            (runtime_role, "worker"),
            (recovery_role, "recovery"),
        ):
            row = connection.execute(
                """
                SELECT control_assurance_execution.configure_login_role(
                    %s, %s::name, %s
                )
                """,
                (_TENANT_ID, role, principal_kind),
            ).fetchone()
            assert row == (True,)


def _database_principal(dsn: str) -> str:
    psycopg = importlib.import_module("psycopg")
    with psycopg.connect(dsn, autocommit=True) as connection:
        row = connection.execute("SELECT current_user").fetchone()
    assert row is not None and type(row[0]) is str
    return row[0]


def _assert_live_role_boundaries() -> tuple[str, str]:
    """Prove the minimum live GRANT matrix before exercising recovery."""

    assert _ADMIN_DSN is not None
    assert _DSN is not None
    assert _RECOVERY_DSN is not None
    runtime_role = _database_principal(_DSN)
    recovery_role = _database_principal(_RECOVERY_DSN)
    assert runtime_role != recovery_role
    psycopg = importlib.import_module("psycopg")
    routine = (
        "control_assurance_execution."
        "consume_publishing_recovery_authorization("
        "bytea,bytea,bytea,bytea,bytea,bytea,bytea,"
        "bytea,bytea,bytea,bytea,bytea,bytea)"
    )
    legacy_routine = (
        "control_assurance_execution."
        "consume_publishing_recovery_authorization("
        "bytea,bytea,bytea,bytea,bytea,bytea,bytea,bytea)"
    )
    with psycopg.connect(_ADMIN_DSN, autocommit=True) as connection:
        roles = connection.execute(
            """
            SELECT rolname, rolsuper, rolbypassrls
            FROM pg_catalog.pg_roles
            WHERE rolname IN (%s, %s)
            """,
            (runtime_role, recovery_role),
        ).fetchall()
        privileges = connection.execute(
            """
            SELECT
                has_schema_privilege(%s, 'control_assurance_execution', 'USAGE'),
                has_table_privilege(
                    %s,
                    'control_assurance_execution.schema_migrations',
                    'SELECT'
                ),
                has_table_privilege(
                    %s,
                    'control_assurance_execution.executions',
                    'SELECT'
                ),
                has_table_privilege(
                    %s,
                    'control_assurance_execution.execution_attempts',
                    'SELECT'
                ),
                has_table_privilege(
                    %s,
                    'control_assurance_execution.executions',
                    'INSERT'
                ),
                has_table_privilege(
                    %s,
                    'control_assurance_execution.executions',
                    'UPDATE'
                ),
                has_table_privilege(
                    %s,
                    'control_assurance_execution.execution_attempts',
                    'INSERT'
                ),
                has_table_privilege(
                    %s,
                    'control_assurance_execution.execution_attempts',
                    'UPDATE'
                ),
                has_function_privilege(%s, %s, 'EXECUTE'),
                has_table_privilege(
                    %s,
                    'control_assurance_execution.publishing_recovery_authorizations',
                    'SELECT'
                ),
                has_schema_privilege(%s, 'control_assurance_execution', 'USAGE'),
                has_table_privilege(
                    %s,
                    'control_assurance_execution.schema_migrations',
                    'SELECT'
                ),
                has_table_privilege(
                    %s,
                    'control_assurance_execution.executions',
                    'SELECT'
                ),
                has_table_privilege(
                    %s,
                    'control_assurance_execution.execution_attempts',
                    'SELECT'
                ),
                has_function_privilege(%s, %s, 'EXECUTE'),
                has_table_privilege(
                    %s,
                    'control_assurance_execution.executions',
                    'INSERT'
                ),
                has_table_privilege(
                    %s,
                    'control_assurance_execution.executions',
                    'UPDATE'
                ),
                has_table_privilege(
                    %s,
                    'control_assurance_execution.execution_attempts',
                    'INSERT'
                ),
                has_table_privilege(
                    %s,
                    'control_assurance_execution.execution_attempts',
                    'UPDATE'
                ),
                has_table_privilege(
                    %s,
                    'control_assurance_execution.publishing_recovery_authorizations',
                    'INSERT'
                )
            """,
            (
                runtime_role,
                runtime_role,
                runtime_role,
                runtime_role,
                runtime_role,
                runtime_role,
                runtime_role,
                runtime_role,
                runtime_role,
                routine,
                runtime_role,
                recovery_role,
                recovery_role,
                recovery_role,
                recovery_role,
                recovery_role,
                routine,
                recovery_role,
                recovery_role,
                recovery_role,
                recovery_role,
                recovery_role,
            ),
        ).fetchone()
        legacy_routine_registration = connection.execute(
            "SELECT to_regprocedure(%s)",
            (legacy_routine,),
        ).fetchone()
    assert sorted(roles) == sorted(
        (
            (runtime_role, False, False),
            (recovery_role, False, False),
        )
    )
    assert privileges == (
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        False,
        False,
        True,
        True,
        True,
        True,
        True,
        False,
        False,
        False,
        False,
        False,
    )
    assert legacy_routine_registration == (None,)
    return runtime_role, recovery_role


def _execution_request(
    tenant_id: str,
    *,
    attempt_count: int,
    identity_seed: str,
) -> ControlRunExecutionRequest:
    operation = sha256_digest(f"{identity_seed}:operation".encode())
    deployment = sha256_digest(f"{identity_seed}:deployment".encode())
    revision = sha256_digest(f"{identity_seed}:revision".encode())
    control_id = f"high-alert-{identity_seed[:24]}"
    profile = AlertWindowProfile(
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
    configuration = ControlConfiguration(
        tenant_id=tenant_id,
        control_id=control_id,
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
        deployment_operation_id=operation,
        deployment_operation_sequence=7,
        deployment_receipt_digest=deployment,
        control_profile_id=profile.profile_id,
        control_profile_digest=profile.digest,
        revision_id=revision,
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
        deployment_operation_id=operation,
        deployment_receipt_digest=deployment,
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


def _execution_identity_bytes(
    request: ControlRunExecutionRequest,
    plan_bytes: bytes,
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
    deployment_profile_digest = f"sha256:{'7' * 64}"
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
        return DetachedSignature(
            key_id=self.key_id,
            algorithm="ed25519",
            signature=base64.b64encode(self._private.sign(message)).decode("ascii"),
        )


def _live_recovery_material(
    bound: ExecutionJournalRecord,
) -> tuple[
    bytes,
    PublishingRecoveryJournalExpectation,
    _RecoverySigner,
    _RecoverySigner,
    _RecoverySigner,
    _RecoverySigner,
    _RecoverySigner,
    RecoveryActorVerificationPolicy,
]:
    def digest(character: str) -> str:
        return f"sha256:{character * 64}"

    assert bound.publishing_at is not None
    assert bound.execution_identity_digest is not None
    requested = bound.publishing_at + timedelta(seconds=1)
    successor_expires = requested + timedelta(minutes=30)
    old = AbandonedPublishingAttempt(
        lease_fence=bound.request.lease_fence,
        attempt_count=bound.request.attempt_count,
        worker_id=bound.worker_id,
        worker_credential_digest=digest("8"),
        lease_token_digest=bound.lease_token_digest,
        leased_at=bound.publishing_at - timedelta(minutes=5),
        lease_expires_at=requested,
        publishing_at=bound.publishing_at,
    )
    successor = SuccessorLeaseClaim(
        lease_fence=old.lease_fence + 1,
        attempt_count=old.attempt_count + 1,
        worker_id="executor-b",
        worker_credential_digest=digest("9"),
        lease_token_digest=_TOKEN_TWO,
        leased_at=requested,
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
        tenant_id=bound.request.tenant_id,
        run_id=bound.request.run_id,
        execution_plan_digest=bound.execution_plan_digest,
        execution_identity_digest=bound.execution_identity_digest,
        abandoned_lease_fence=old.lease_fence,
        pam_scope_digest=pam_scope_digest,
    )
    actor_policy = RecoveryActorVerificationPolicy(
        audience="control-assurance-recovery",
        maker_issuer_id="idp:maker",
        checker_issuer_id="idp:checker",
    )
    final_signer = _RecoverySigner(
        b"\x41" * 32,
        key_id="live-recovery-authority-v2",
    )
    fence_signer = _RecoverySigner(
        b"\x42" * 32,
        key_id="live-fence-authority-v2",
    )
    drain_signer = _RecoverySigner(
        b"\x43" * 32,
        key_id="live-drain-authority-v2",
    )
    maker_signer = _RecoverySigner(
        b"\x44" * 32,
        key_id="live-maker-idp-v2",
    )
    checker_signer = _RecoverySigner(
        b"\x45" * 32,
        key_id="live-checker-idp-v2",
    )
    maker = RecoveryActorAssertion(
        subject_id="user:live-recovery-maker",
        session_digest=digest("b"),
        role="maker",
        authenticated_at=requested - timedelta(minutes=2),
        mfa_verified_at=requested - timedelta(minutes=1),
    )
    request_expires = requested + timedelta(hours=1)
    request_intent = PublishingRecoveryRequestIntent(
        tenant_id=bound.request.tenant_id,
        run_id=bound.request.run_id,
        control_id=bound.request.control_id,
        configuration_digest=bound.request.configuration_digest,
        execution_plan_digest=bound.execution_plan_digest,
        execution_identity_digest=bound.execution_identity_digest,
        abandoned_attempt=old,
        successor_claim=successor,
        pam_scopes=pam_scopes,
        pam_scope_digest=pam_scope_digest,
        pam_execution_binding_digest=execution_binding,
        reason="old-worker-terminated",
        incident_reference_digest=digest("c"),
        requested_at=requested,
        request_expires_at=request_expires,
        request_nonce="1" * 64,
    )
    maker_action = migrate_recovery_actor_assertion(
        maker,
        issuer_id=actor_policy.maker_issuer_id,
        audience=actor_policy.audience,
        tenant_id=bound.request.tenant_id,
        run_id=bound.request.run_id,
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
        tenant_id=bound.request.tenant_id,
        run_id=bound.request.run_id,
        abandoned_attempt_digest=old.digest,
        workload=WorkloadFenceLocator(
            cluster_uid="cluster:live-integration",
            namespace="assurance-runtime",
            service_account_uid="service-account:runtime",
            pod_uid="pod:old-live-worker",
            node_uid="node:live-runtime",
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
        relaunch_fence_effective_at=requested,
        relaunch_fence_valid_until=successor_expires,
        fencing_controller_id="system:live-fence-controller",
        fencing_controller_credential_digest=digest("0"),
        fencing_authority_key_fingerprint=sha256_digest(fence_signer.public_key_bytes),
        fence_requested_at=requested,
        fence_effective_at=requested,
        isolation_observed_at=requested,
        attested_at=requested,
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
        lifecycle_record_id="pam:source:live-recovery",
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
        tenant_id=bound.request.tenant_id,
        run_id=bound.request.run_id,
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
        fence_effective_at=requested,
        maximum_inflight_seconds=0,
        clock_skew_seconds=0,
        post_fence_inflight_deadline=requested,
        drain_not_before=requested,
        checked_at=requested,
        attested_at=requested,
        issuance_fence_operation_digest=digest("3"),
        issuance_fence_effective_at=requested,
        issuance_fence_valid_until=successor_expires,
        issuance_fence_high_watermark=1,
        drain_controller_id="system:live-drain-controller",
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
        subject_id="user:live-recovery-checker",
        session_digest=digest("4"),
        role="checker",
        authenticated_at=requested - timedelta(minutes=2),
        mfa_verified_at=requested - timedelta(minutes=1),
    )
    authorization_expires = requested + timedelta(minutes=10)
    checker_action_digest = publishing_recovery_checker_action_digest(
        tenant_id=bound.request.tenant_id,
        run_id=bound.request.run_id,
        recovery_request_digest=recovery_request.digest,
        signed_compute_fence_attestation_digest=signed_fence.digest,
        signed_credential_drain_attestation_digest=signed_drain.digest,
        abandoned_attempt_digest=old.digest,
        successor_claim_digest=successor.digest,
        change_approval_digest=digest("5"),
        approved_at=requested,
        not_before=requested,
        issued_at=requested,
        expires_at=authorization_expires,
        authorization_nonce="6" * 64,
        recovery_authority_id="system:live-recovery-authority",
        recovery_authority_key_fingerprint=sha256_digest(final_signer.public_key_bytes),
    )
    checker_action = migrate_recovery_actor_assertion(
        checker,
        issuer_id=actor_policy.checker_issuer_id,
        audience=actor_policy.audience,
        tenant_id=bound.request.tenant_id,
        run_id=bound.request.run_id,
        action="approve",
        action_digest=checker_action_digest,
        acted_at=requested,
        expires_at=authorization_expires,
        action_nonce="4" * 64,
        idp_key_fingerprint=sha256_digest(checker_signer.public_key_bytes),
    )
    signed_checker_action = issue_recovery_actor_action(
        checker_action,
        signer=checker_signer,
    )
    authorization = PublishingRecoveryAuthorization(
        tenant_id=bound.request.tenant_id,
        run_id=bound.request.run_id,
        control_id=bound.request.control_id,
        configuration_digest=bound.request.configuration_digest,
        execution_plan_digest=bound.execution_plan_digest,
        execution_identity_digest=bound.execution_identity_digest,
        recovery_request_digest=recovery_request.digest,
        recovery_request=recovery_request,
        compute_fence_attestation_digest=fence.digest,
        signed_compute_fence_attestation_digest=signed_fence.digest,
        signed_compute_fence_attestation=signed_fence,
        credential_drain_attestation_digest=drain.digest,
        signed_credential_drain_attestation_digest=signed_drain.digest,
        signed_credential_drain_attestation=signed_drain,
        abandoned_attempt=old,
        successor_claim=successor,
        signed_checker_action_digest=signed_checker_action.digest,
        signed_checker_action=signed_checker_action,
        change_approval_digest=digest("5"),
        approved_at=requested,
        not_before=requested,
        issued_at=requested,
        expires_at=authorization_expires,
        authorization_nonce="6" * 64,
        recovery_authority_id="system:live-recovery-authority",
        recovery_authority_key_fingerprint=sha256_digest(final_signer.public_key_bytes),
    )
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
        tenant_id=bound.request.tenant_id,
        run_id=bound.request.run_id,
        control_id=bound.request.control_id,
        configuration_digest=bound.request.configuration_digest,
        execution_plan_digest=bound.execution_plan_digest,
        execution_identity_digest=bound.execution_identity_digest,
        recovery_request_digest=recovery_request.digest,
        pam_scope_digest=pam_scope_digest,
        pam_execution_binding_digest=execution_binding,
        pam_snapshot_high_watermark=drain.snapshot_high_watermark,
        pam_lifecycle_record_count=drain.lifecycle_record_count,
        relaunch_fence_operation_digest=(fence.relaunch_fence_operation_digest),
        issuance_fence_operation_digest=(drain.issuance_fence_operation_digest),
        abandoned_lease_fence=old.lease_fence,
        abandoned_attempt_count=old.attempt_count,
        abandoned_attempt_revision=old.attempt_revision,
        abandoned_worker_id=old.worker_id,
        abandoned_lease_token_digest=old.lease_token_digest,
        abandoned_publishing_at=old.publishing_at,
        successor_lease_fence=successor.lease_fence,
        successor_attempt_count=successor.attempt_count,
        successor_worker_id=successor.worker_id,
        successor_lease_token_digest=successor.lease_token_digest,
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
    )


def _complete(
    journal: PostgresExecutionJournal,
    request: ControlRunExecutionRequest,
    result: ControlRunExecutionResult,
    *,
    worker_id: str,
    lease_token_digest: str,
) -> ExecutionJournalRecord | ExecutionJournalConflict:
    try:
        return journal.mark_completed(
            tenant_id=request.tenant_id,
            run_id=request.run_id,
            lease_fence=request.lease_fence,
            worker_id=worker_id,
            lease_token_digest=lease_token_digest,
            expected_revision=1,
            result=result,
            executor_receipt_bytes=_RECEIPT_BYTES,
        )
    except ExecutionJournalConflict as exc:
        return exc


@pytest.mark.skipif(
    not _RECOVERY_DSN,
    reason="CONTROL_ASSURANCE_POSTGRES_RECOVERY_DSN is not configured",
)
def test_live_signed_recovery_is_atomic_single_use_and_append_only() -> None:
    assert _ADMIN_DSN is not None
    assert _DSN is not None
    assert _RECOVERY_DSN is not None
    assert _MIGRATION_DSN is not None
    _install_schema(_MIGRATION_DSN)
    _assert_live_role_boundaries()
    assert _TENANT_ID is not None
    tenant_id = _TENANT_ID
    identity_seed = uuid.uuid4().hex
    first = _execution_request(
        tenant_id,
        attempt_count=1,
        identity_seed=identity_seed,
    )
    plan = create_control_run_execution_plan(
        first,
        capture_nonce=uuid.uuid4().hex + uuid.uuid4().hex,
        prepared_at=_PREPARED,
    ).canonical_bytes()
    identity_bytes = _execution_identity_bytes(first, plan)
    runtime_journal = PostgresExecutionJournal.from_dsn(
        _DSN,
        min_size=2,
        max_size=4,
    )
    try:
        prepared = runtime_journal.prepare(
            first,
            worker_id="executor-a",
            lease_token_digest=_TOKEN_ONE,
            execution_plan_bytes=plan,
        )
        publishing = runtime_journal.begin_publishing(
            tenant_id=tenant_id,
            run_id=first.run_id,
            lease_fence=1,
            worker_id="executor-a",
            lease_token_digest=_TOKEN_ONE,
            expected_revision=prepared.revision,
        )
        bound = runtime_journal.bind_execution_identity(
            tenant_id=tenant_id,
            run_id=first.run_id,
            lease_fence=1,
            worker_id="executor-a",
            lease_token_digest=_TOKEN_ONE,
            expected_revision=publishing.revision,
            execution_identity_digest=sha256_digest(identity_bytes),
            execution_identity_bytes=identity_bytes,
        )
    finally:
        runtime_journal.close_pool()

    recovery_journal = PostgresExecutionJournal.from_dsn(
        _RECOVERY_DSN,
        min_size=2,
        max_size=4,
    )
    try:
        (
            authorization_bytes,
            expectation,
            final_signer,
            fence_signer,
            drain_signer,
            maker_signer,
            checker_signer,
            actor_policy,
        ) = _live_recovery_material(bound)
        recovery_envelope = SignedPublishingRecoveryAuthorization.model_validate_json(
            authorization_bytes,
            strict=True,
        )

        # The signed old lease expires one second after PostgreSQL's persisted
        # publishing clock.  Waiting beyond that boundary makes both the model
        # and the routine use a live database validity window.
        # PostgreSQL rounds timestamptz(0) values to the nearest second, so a
        # persisted publishing time can be almost half a second ahead of wall
        # time.  Two seconds keeps this boundary deterministic on slow and fast
        # CI hosts alike.
        time.sleep(2.1)

        swapped = PublishingRecoveryJournalExpectation.model_validate(
            {
                **expectation.model_dump(mode="python"),
                "successor_worker_id": "executor-c",
            }
        )
        with pytest.raises(
            ExecutionJournalConflict,
            match="journal-binding-mismatch",
        ):
            recovery_journal.recover_identity_bound_publication(
                authorization_bytes,
                journal_expectation=swapped,
                verifier=final_signer,
                fence_verifier=fence_signer,
                drain_verifier=drain_signer,
                maker_verifier=maker_signer,
                checker_verifier=checker_signer,
                actor_policy=actor_policy,
            )

        psycopg = importlib.import_module("psycopg")
        with (
            psycopg.connect(_ADMIN_DSN, autocommit=False) as connection,
            connection.transaction(),
        ):
            connection.execute(
                "SELECT set_config('control_assurance.tenant_id', %s, true)",
                (tenant_id,),
            )
            before = connection.execute(
                """
                SELECT count(*)
                FROM control_assurance_execution.publishing_recovery_authorizations
                WHERE tenant_id = %s AND run_id = %s
                """,
                (tenant_id, first.run_id),
            ).fetchone()
            assert before is not None and before[0] == 0

        def recover_once(
            _: int,
        ) -> ExecutionJournalRecord | ExecutionJournalConflict:
            try:
                return recovery_journal.recover_identity_bound_publication(
                    authorization_bytes,
                    journal_expectation=expectation,
                    verifier=final_signer,
                    fence_verifier=fence_signer,
                    drain_verifier=drain_signer,
                    maker_verifier=maker_signer,
                    checker_verifier=checker_signer,
                    actor_policy=actor_policy,
                )
            except ExecutionJournalConflict as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = tuple(executor.map(recover_once, range(2)))
        recovered = tuple(item for item in outcomes if isinstance(item, ExecutionJournalRecord))
        rejected = tuple(item for item in outcomes if isinstance(item, ExecutionJournalConflict))
        assert len(recovered) == 1
        assert len(rejected) == 1
        assert recovered[0].state == "publishing"
        assert recovered[0].request.lease_fence == 2
        assert recovered[0].worker_id == "executor-b"

        with pytest.raises(ExecutionJournalConflict):
            recovery_journal.recover_identity_bound_publication(
                authorization_bytes,
                journal_expectation=expectation,
                verifier=final_signer,
                fence_verifier=fence_signer,
                drain_verifier=drain_signer,
                maker_verifier=maker_signer,
                checker_verifier=checker_signer,
                actor_policy=actor_policy,
            )
    finally:
        recovery_journal.close_pool()

    psycopg = importlib.import_module("psycopg")
    with psycopg.connect(_ADMIN_DSN, autocommit=False) as connection:
        with connection.transaction():
            connection.execute(
                "SELECT set_config('control_assurance.tenant_id', %s, true)",
                (tenant_id,),
            )
            attempts = connection.execute(
                """
                SELECT lease_fence, state, error_code
                FROM control_assurance_execution.execution_attempts
                WHERE tenant_id = %s AND run_id = %s
                ORDER BY lease_fence
                """,
                (tenant_id, first.run_id),
            ).fetchall()
            assert [tuple(row) for row in attempts] == [
                (1, "uncertain", "recovery-superseded"),
                (2, "publishing", None),
            ]
            recovery_rows = connection.execute(
                """
                SELECT
                    authorization_id,
                    signed_authorization_bytes,
                    recovery_request_intent_bytes,
                    signed_maker_action_bytes,
                    maker_action_bytes,
                    signed_checker_action_bytes,
                    checker_action_bytes,
                    pam_scope_digest,
                    pam_snapshot_high_watermark,
                    pam_lifecycle_record_count,
                    relaunch_fence_operation_digest,
                    issuance_fence_operation_digest,
                    abandoned_worker_credential_digest,
                    successor_worker_credential_digest
                FROM control_assurance_execution.publishing_recovery_authorizations
                WHERE tenant_id = %s AND run_id = %s
                """,
                (tenant_id, first.run_id),
            ).fetchall()
            assert len(recovery_rows) == 1
            authorization = recovery_envelope.authorization
            request = authorization.recovery_request
            assert recovery_rows[0][0] == recovery_envelope.authorization_id
            assert bytes(recovery_rows[0][1]) == authorization_bytes
            assert bytes(recovery_rows[0][2]) == request.intent.canonical_bytes()
            assert bytes(recovery_rows[0][3]) == (request.signed_maker_action.canonical_bytes())
            assert bytes(recovery_rows[0][4]) == (
                request.signed_maker_action.actor_action.canonical_bytes()
            )
            assert bytes(recovery_rows[0][5]) == (
                authorization.signed_checker_action.canonical_bytes()
            )
            assert bytes(recovery_rows[0][6]) == (
                authorization.signed_checker_action.actor_action.canonical_bytes()
            )
            assert recovery_rows[0][7] == request.pam_scope_digest
            assert recovery_rows[0][8] == (
                authorization.credential_drain_attestation.snapshot_high_watermark
            )
            assert recovery_rows[0][9] == (
                authorization.credential_drain_attestation.lifecycle_record_count
            )
            assert recovery_rows[0][10] == (
                authorization.compute_fence_attestation.relaunch_fence_operation_digest
            )
            assert recovery_rows[0][11] == (
                authorization.credential_drain_attestation.issuance_fence_operation_digest
            )
            assert recovery_rows[0][12] == f"sha256:{'8' * 64}"
            assert recovery_rows[0][13] == f"sha256:{'9' * 64}"
            transition_clock = connection.execute(
                """
                SELECT
                    abandoned.finished_at,
                    successor.prepared_at,
                    successor.publishing_at,
                    recovery.consumed_at,
                    recovery.successor_leased_at
                FROM control_assurance_execution
                    .publishing_recovery_authorizations AS recovery
                JOIN control_assurance_execution.execution_attempts AS abandoned
                  ON abandoned.tenant_id = recovery.tenant_id
                 AND abandoned.run_id = recovery.run_id
                 AND abandoned.lease_fence =
                    recovery.abandoned_lease_fence
                JOIN control_assurance_execution.execution_attempts AS successor
                  ON successor.tenant_id = recovery.tenant_id
                 AND successor.run_id = recovery.run_id
                 AND successor.lease_fence = recovery.successor_lease_fence
                WHERE recovery.tenant_id = %s AND recovery.run_id = %s
                """,
                (tenant_id, first.run_id),
            ).fetchone()
            assert transition_clock is not None
            assert transition_clock[0] == transition_clock[3]
            assert transition_clock[1] == transition_clock[4]
            assert transition_clock[2] == transition_clock[3]

        with (
            pytest.raises(Exception, match="append-preserving"),
            connection.transaction(),
        ):
            connection.execute(
                "SELECT set_config('control_assurance.tenant_id', %s, true)",
                (tenant_id,),
            )
            connection.execute(
                """
                UPDATE control_assurance_execution.publishing_recovery_authorizations
                SET successor_worker_id = 'executor-c'
                WHERE tenant_id = %s AND run_id = %s
                """,
                (tenant_id, first.run_id),
            )


def test_live_execution_journal_recovers_one_plan_and_one_completion() -> None:
    assert _ADMIN_DSN is not None
    assert _DSN is not None
    assert _MIGRATION_DSN is not None
    _install_schema(_MIGRATION_DSN)
    assert _TENANT_ID is not None
    tenant_id = _TENANT_ID
    identity_seed = uuid.uuid4().hex
    first = _execution_request(
        tenant_id,
        attempt_count=1,
        identity_seed=identity_seed,
    )
    plan = create_control_run_execution_plan(
        first,
        capture_nonce=uuid.uuid4().hex + uuid.uuid4().hex,
        prepared_at=_PREPARED,
    ).canonical_bytes()
    execution_identity_bytes = _execution_identity_bytes(first, plan)
    execution_identity_digest = sha256_digest(execution_identity_bytes)
    journal = PostgresExecutionJournal.from_dsn(
        _DSN,
        min_size=2,
        max_size=4,
    )
    try:
        prepared = journal.prepare(
            first,
            worker_id="executor-a",
            lease_token_digest=_TOKEN_ONE,
            execution_plan_bytes=plan,
        )
        publishing = journal.begin_publishing(
            tenant_id=tenant_id,
            run_id=first.run_id,
            lease_fence=1,
            worker_id="executor-a",
            lease_token_digest=_TOKEN_ONE,
            expected_revision=prepared.revision,
        )
        assert publishing.state == "publishing"
        bound = journal.bind_execution_identity(
            tenant_id=tenant_id,
            run_id=first.run_id,
            lease_fence=1,
            worker_id="executor-a",
            lease_token_digest=_TOKEN_ONE,
            expected_revision=publishing.revision,
            execution_identity_digest=execution_identity_digest,
            execution_identity_bytes=execution_identity_bytes,
        )
        assert bound.execution_identity_digest == execution_identity_digest
    finally:
        # Process loss after the side-effect boundary but before an outcome.
        journal.close_pool()

    second = _execution_request(
        tenant_id,
        attempt_count=2,
        identity_seed=identity_seed,
    )
    recovery = PostgresExecutionJournal.from_dsn(
        _DSN,
        min_size=2,
        max_size=4,
    )
    try:
        with pytest.raises(
            ExecutionJournalConflict,
            match="identity-bound publishing execution requires reconciliation",
        ):
            recovery.prepare(
                second,
                worker_id="executor-b",
                lease_token_digest=_TOKEN_TWO,
                execution_plan_bytes=None,
            )
        result = ControlRunExecutionResult(
            run_id=first.run_id,
            lease_fence=1,
            evidence_digest=_EVIDENCE,
            executor_receipt_digest=_RECEIPT,
        )
        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = tuple(
                executor.map(
                    lambda _: _complete(
                        recovery,
                        first,
                        result,
                        worker_id="executor-a",
                        lease_token_digest=_TOKEN_ONE,
                    ),
                    range(2),
                )
            )
        completed = tuple(item for item in outcomes if isinstance(item, ExecutionJournalRecord))
        assert len(completed) == 2
        assert all(item.state == "completed" for item in completed)
        assert all(item.result == result for item in completed)
        assert all(item.executor_receipt_bytes == _RECEIPT_BYTES for item in completed)
        assert bound.execution_plan_digest == completed[0].execution_plan_digest

        recovered = recovery.prepare(
            second,
            worker_id="executor-b",
            lease_token_digest=_TOKEN_TWO,
            execution_plan_bytes=None,
        )
        assert recovered.state == "completed"
        assert recovered.request.lease_fence == 1
        assert recovered.execution_identity_bytes == execution_identity_bytes

        with pytest.raises(ExecutionJournalConflict, match="stale lease"):
            recovery.begin_publishing(
                tenant_id=tenant_id,
                run_id=second.run_id,
                lease_fence=2,
                worker_id="executor-b",
                lease_token_digest=_TOKEN_TWO,
                expected_revision=publishing.revision,
            )
        other_receipt = canonical_json_bytes({"outcome": "other"})
        with pytest.raises(ExecutionJournalConflict, match="differs"):
            recovery.mark_completed(
                tenant_id=tenant_id,
                run_id=first.run_id,
                lease_fence=1,
                worker_id="executor-a",
                lease_token_digest=_TOKEN_ONE,
                expected_revision=1,
                result=ControlRunExecutionResult(
                    run_id=first.run_id,
                    lease_fence=1,
                    evidence_digest=f"sha256:{'9' * 64}",
                    executor_receipt_digest=sha256_digest(other_receipt),
                ),
                executor_receipt_bytes=other_receipt,
            )
    finally:
        recovery.close_pool()

    reread = PostgresExecutionJournal.from_dsn(
        _DSN,
        min_size=1,
        max_size=2,
    )
    try:
        durable = reread.get(tenant_id=tenant_id, run_id=second.run_id)
        assert durable.state == "completed"
        assert durable.execution_plan_bytes == plan
        assert durable.executor_receipt_bytes == _RECEIPT_BYTES
        assert durable.execution_identity_digest == execution_identity_digest
        with pytest.raises(ExecutionJournalNotFound):
            reread.get(
                tenant_id=tenant_id,
                run_id=f"sha256:{'f' * 64}",
            )
    finally:
        reread.close_pool()

    psycopg = importlib.import_module("psycopg")
    with (
        psycopg.connect(_DSN, autocommit=False) as connection,
        connection.transaction(),
    ):
        connection.execute(
            "SELECT set_config('control_assurance.tenant_id', %s, true)",
            (tenant_id,),
        )
        attempts = connection.execute(
            """
            SELECT lease_fence, state, error_code
            FROM control_assurance_execution.execution_attempts
            WHERE tenant_id = %s AND run_id = %s
            ORDER BY lease_fence
            """,
            (tenant_id, second.run_id),
        ).fetchall()
        assert [tuple(row) for row in attempts] == [
            (1, "completed", None),
        ]
        # A legacy caller-controlled GUC cannot change the tenant derived from
        # the authenticated PostgreSQL session user.
        connection.execute(
            "SELECT set_config('control_assurance.tenant_id', %s, true)",
            ("another-tenant",),
        )
        count = connection.execute(
            """
            SELECT
                control_assurance_execution.session_tenant(),
                count(*)
            FROM control_assurance_execution.executions
            WHERE run_id = %s
            GROUP BY control_assurance_execution.session_tenant()
            """,
            (second.run_id,),
        ).fetchone()
        assert count == (tenant_id, 1)

    with (
        psycopg.connect(_DSN, autocommit=False) as connection,
        pytest.raises(Exception, match="immutable execution identity"),
        connection.transaction(),
    ):
        connection.execute(
            "SELECT set_config('control_assurance.tenant_id', %s, true)",
            (tenant_id,),
        )
        connection.execute(
            """
            UPDATE control_assurance_execution.executions
            SET execution_plan_bytes = %s
            WHERE tenant_id = %s AND run_id = %s
            """,
            (b"{}", tenant_id, second.run_id),
        )

    with (
        psycopg.connect(_ADMIN_DSN, autocommit=False) as connection,
        pytest.raises(Exception, match="append-preserving"),
        connection.transaction(),
    ):
        connection.execute(
            "SELECT set_config('control_assurance.tenant_id', %s, true)",
            (tenant_id,),
        )
        connection.execute(
            """
            DELETE FROM control_assurance_execution.executions
            WHERE tenant_id = %s AND run_id = %s
            """,
            (tenant_id, second.run_id),
        )
