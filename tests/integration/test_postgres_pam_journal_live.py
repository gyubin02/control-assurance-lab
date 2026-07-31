"""Opt-in live PostgreSQL CAS, reconnect, and PAM crash-recovery coverage.

The migration owner provisions one exact broker login and explicitly binds
every opaque journal namespace to the broker's tenant before use.
"""

from __future__ import annotations

import hashlib
import importlib
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier

import pytest

from assurance_lab.connectors.defender_pam import (
    DefenderPamError,
    DefenderTokenRecord,
)
from assurance_lab.connectors.elastic_pam import (
    ElasticLeaseRecord,
    ElasticPamError,
    ElasticPamPolicy,
)
from assurance_lab.connectors.postgres_pam_journal import (
    PAMExecutionBinding,
    PAMIssuanceFence,
    PAMLifecycleRecord,
    PostgresDefenderTokenJournal,
    PostgresElasticLeaseJournal,
    PostgresPamIssuanceJournal,
    PostgresPamRecoveryError,
)
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
from assurance_lab.runtime.execution_plan import create_control_run_execution_plan
from assurance_lab.runtime.models import ControlRunExecutionRequest, ControlRunRequest

_MIGRATION_DSN = os.environ.get(
    "CONTROL_ASSURANCE_POSTGRES_PAM_MIGRATION_DSN"
)
_ADMIN_DSN = os.environ.get("CONTROL_ASSURANCE_POSTGRES_PAM_ADMIN_DSN")
_BROKER_DSN = os.environ.get("CONTROL_ASSURANCE_POSTGRES_PAM_BROKER_DSN")
_TENANT_ID = os.environ.get("CONTROL_ASSURANCE_POSTGRES_PAM_TENANT")
pytestmark = pytest.mark.skipif(
    not all((_ADMIN_DSN, _MIGRATION_DSN, _BROKER_DSN, _TENANT_ID)),
    reason="separated PostgreSQL PAM DSNs are not configured",
)
_DIGEST = f"sha256:{'a' * 64}"
_OTHER_DIGEST = f"sha256:{'b' * 64}"
_CREATED = 1_700_000_000_000
_RULE_UUID = "12345678-1234-4234-9234-123456789abc"


def _database_principal(dsn: str) -> str:
    psycopg = importlib.import_module("psycopg")
    with psycopg.connect(dsn, autocommit=True) as connection:
        row = connection.execute("SELECT current_user").fetchone()
    assert row is not None and type(row[0]) is str
    return row[0]


def _install_schema() -> None:
    assert _MIGRATION_DSN is not None
    assert _BROKER_DSN is not None
    assert _TENANT_ID is not None
    psycopg = importlib.import_module("psycopg")
    schema = (
        Path(__file__).parents[2] / "deploy" / "postgres" / "pam-journal-schema.sql"
    ).read_text(encoding="utf-8")
    broker_role = _database_principal(_BROKER_DSN)
    with psycopg.connect(_MIGRATION_DSN, autocommit=True) as connection:
        connection.execute(schema)
        row = connection.execute(
            """
            SELECT control_assurance_pam.configure_login_role(
                %s, %s::name, 'broker'
            )
            """,
            (_TENANT_ID, broker_role),
        ).fetchone()
        assert row == (True,)


def _configure_namespace(namespace_digest: str, purpose: str) -> None:
    assert _MIGRATION_DSN is not None
    assert _TENANT_ID is not None
    psycopg = importlib.import_module("psycopg")
    with psycopg.connect(_MIGRATION_DSN, autocommit=True) as connection:
        row = connection.execute(
            """
            SELECT control_assurance_pam.configure_journal_namespace(
                %s, %s, %s
            )
            """,
            (namespace_digest, _TENANT_ID, purpose),
        ).fetchone()
    assert row == (True,)


def _digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _plan_bound_execution(
    suffix: str,
) -> tuple[PAMExecutionBinding, PAMExecutionBinding]:
    assert _TENANT_ID is not None
    now = datetime.now(UTC).replace(microsecond=0)
    window_end = now - timedelta(minutes=1)
    window_start = window_end - timedelta(minutes=5)
    prepared_at = window_end + timedelta(seconds=1)
    tenant_id = _TENANT_ID
    profile = AlertWindowProfile(
        profile_id="postgres-pam-live",
        profile_version="1.0.0",
        title="PostgreSQL PAM live profile",
        source=ElasticAlertSource(
            fields=(
                "@timestamp",
                "kibana.alert.rule.uuid",
                "kibana.alert.severity",
            ),
            rule_uuids=(_RULE_UUID,),
            workflow_statuses=("open",),
            alert_statuses=("active",),
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
        control_id="postgres-pam-live",
        display_name="PostgreSQL PAM live control",
        description="Exercises the durable issuance fence.",
        environment="test",
        owner_group="security/runtime",
        control_profile_id=profile.profile_id,
        control_profile_digest=profile.digest,
        source=ElasticSourceConfiguration(
            endpoint_origin="https://elastic.invalid",
            index_alias=".alerts-security.alerts-default",
            parent_credential_ref=(f"azure-keyvault://bank-vault/secrets/elastic-parent/{suffix}"),
            lease_ttl_seconds=900,
        ),
        schedule=ScheduleConfiguration(
            interval_seconds=300,
            collection_lag_seconds=120,
            window_seconds=300,
        ),
        evidence=EvidenceConfiguration(
            custody_ref=f"s3-object-lock://evidence/{tenant_id}/alerts",
            signing_key_ref=f"vault-transit://assurance/{tenant_id}",
            retention_days=365,
        ),
    )
    operation_digest = _digest(f"{suffix}:deployment-operation")
    receipt_digest = _digest(f"{suffix}:deployment-receipt")
    revision_digest = _digest(f"{suffix}:revision")
    run_request = ControlRunRequest(
        tenant_id=tenant_id,
        control_id=configuration.control_id,
        deployment_operation_id=operation_digest,
        deployment_operation_sequence=1,
        deployment_receipt_digest=receipt_digest,
        control_profile_id=profile.profile_id,
        control_profile_digest=profile.digest,
        revision_id=revision_digest,
        configuration_digest=configuration.digest,
        window_start=window_start,
        window_end=window_end,
        due_at=now + timedelta(minutes=2),
    )
    request = ControlRunExecutionRequest(
        run_id=run_request.run_id,
        run_request_bytes=run_request.canonical_bytes(),
        tenant_id=tenant_id,
        control_id=configuration.control_id,
        deployment_operation_id=operation_digest,
        deployment_receipt_digest=receipt_digest,
        configuration_digest=configuration.digest,
        configuration_bytes=configuration.canonical_bytes(),
        control_profile_id=profile.profile_id,
        control_profile_digest=profile.digest,
        control_profile_media_type=ALERT_WINDOW_PROFILE_MEDIA_TYPE,
        control_profile_bytes=profile.canonical_bytes(),
        window_start=window_start,
        window_end=window_end,
        attempt_count=1,
        lease_fence=1,
    )
    plan = create_control_run_execution_plan(
        request,
        capture_nonce=hashlib.sha256(f"{suffix}:nonce".encode()).hexdigest(),
        prepared_at=prepared_at,
        source_revision="test:postgres-17",
    )
    now_epoch_millis = time.time_ns() // 1_000_000
    successor_expiry = now_epoch_millis + 10_000
    execution_identity_digest = _digest(f"{suffix}:execution-identity")
    return (
        PAMExecutionBinding.from_execution_plan(
            plan,
            execution_identity_digest=execution_identity_digest,
            lease_fence=1,
            lease_expires_at_epoch_millis=now_epoch_millis + 30_000,
        ),
        PAMExecutionBinding.from_execution_plan(
            plan,
            execution_identity_digest=execution_identity_digest,
            lease_fence=2,
            lease_expires_at_epoch_millis=successor_expiry,
        ),
    )


def _recover_defender(
    journal: PostgresDefenderTokenJournal,
    acquisition_id: str,
) -> tuple[DefenderTokenRecord, ...]:
    recovered: list[DefenderTokenRecord] = []
    for record in journal.unsettled():
        if record.acquisition_id != acquisition_id:
            continue
        if record.state == "prepared":
            recovered.append(
                journal.mark_uncertain(
                    acquisition_id=record.acquisition_id,
                    expected_revision=record.revision,
                    now_epoch_millis=_CREATED + 3,
                    error="recovered prepared token request",
                )
            )
        else:
            recovered.append(
                journal.close(
                    acquisition_id=record.acquisition_id,
                    expected_revision=record.revision,
                    expected_state="issued",
                    closure="abandoned-after-crash",
                    now_epoch_millis=_CREATED + 3,
                    error="issued token was abandoned after process recovery",
                )
            )
    return tuple(recovered)


def test_live_postgres_pam_fencing_immutability_and_crash_recovery() -> None:
    assert _BROKER_DSN is not None
    _install_schema()
    suffix = uuid.uuid4().hex
    namespace_digest = f"sha256:{hashlib.sha256(suffix.encode('ascii')).hexdigest()}"
    other_namespace_digest = (
        f"sha256:{hashlib.sha256(f'{suffix}-other'.encode('ascii')).hexdigest()}"
    )
    _configure_namespace(namespace_digest, "connector-lifecycle")
    _configure_namespace(other_namespace_digest, "isolation-probe")
    lease_id = suffix + uuid.uuid4().hex
    acquisition_id = uuid.uuid4().hex + uuid.uuid4().hex
    policy = ElasticPamPolicy(".alerts-security.alerts-default")

    elastic = PostgresElasticLeaseJournal.from_dsn(
        _BROKER_DSN,
        journal_namespace_digest=namespace_digest,
        min_size=2,
        max_size=4,
    )
    try:
        prepared = elastic.prepare(
            lease_id=lease_id,
            key_name=f"control-assurance-{lease_id[:32]}",
            policy=policy,
            request_digest=_DIGEST,
            endpoint_origin_digest=_OTHER_DIGEST,
            now_epoch_millis=_CREATED,
        )

        def activate(index: int) -> ElasticLeaseRecord | ElasticPamError:
            try:
                return elastic.activate(
                    lease_id=lease_id,
                    expected_revision=prepared.revision,
                    key_id=f"key-{index}",
                    expiration_epoch_millis=_CREATED + 900_000,
                    now_epoch_millis=_CREATED + 1,
                )
            except ElasticPamError as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as executor:
            activation_results = tuple(executor.map(activate, range(2)))
        activated = tuple(
            result for result in activation_results if isinstance(result, ElasticLeaseRecord)
        )
        rejected = tuple(
            result for result in activation_results if isinstance(result, ElasticPamError)
        )
        assert len(activated) == 1
        assert len(rejected) == 1
        assert activated[0].revision == 1
    finally:
        # Simulates process loss after Elasticsearch issued the key.
        elastic.close_pool()

    elastic_recovery = PostgresElasticLeaseJournal.from_dsn(
        _BROKER_DSN,
        journal_namespace_digest=namespace_digest,
        min_size=1,
        max_size=2,
    )
    try:
        persisted = elastic_recovery.get(lease_id)
        assert persisted.state == "active"
        pending = elastic_recovery.begin_revocation(
            lease_id=lease_id,
            expected_revision=persisted.revision,
            reason="recovery",
        )
    finally:
        # Simulates loss of the first idempotent invalidation response.
        elastic_recovery.close_pool()

    elastic_finalizer = PostgresElasticLeaseJournal.from_dsn(
        _BROKER_DSN,
        journal_namespace_digest=namespace_digest,
        min_size=1,
        max_size=2,
    )
    try:
        repeated = elastic_finalizer.begin_revocation(
            lease_id=lease_id,
            expected_revision=pending.revision,
            reason="recovery",
        )
        revoked = elastic_finalizer.mark_revoked(
            lease_id=lease_id,
            expected_revision=repeated.revision,
            now_epoch_millis=_CREATED + 4,
        )
        assert revoked.state == "revoked"
        assert revoked.revoke_attempts == 2
        assert all(record.lease_id != lease_id for record in elastic_finalizer.unsettled())
    finally:
        elastic_finalizer.close_pool()

    defender = PostgresDefenderTokenJournal.from_dsn(
        _BROKER_DSN,
        journal_namespace_digest=namespace_digest,
        min_size=2,
        max_size=4,
    )
    try:
        token_prepared = defender.prepare(
            acquisition_id=acquisition_id,
            request_digest=_DIGEST,
            token_endpoint_digest=_OTHER_DIGEST,
            graph_origin_digest=_DIGEST,
            scope_digest=_OTHER_DIGEST,
            credential_mode="federated-rs256",
            credential_reference_digest=_DIGEST,
            token_request_profile_digest=_OTHER_DIGEST,
            now_epoch_millis=_CREATED,
            conservative_exposure_end_epoch_millis=_CREATED + 3_960_000,
        )

        def issue(index: int) -> DefenderTokenRecord | DefenderPamError:
            try:
                return defender.mark_issued(
                    acquisition_id=acquisition_id,
                    expected_revision=token_prepared.revision,
                    now_epoch_millis=_CREATED + 1,
                    expires_epoch_millis=_CREATED + 300_001,
                    assertion_id_digest=_DIGEST,
                    response_request_id_digest=(_OTHER_DIGEST if index == 0 else None),
                )
            except DefenderPamError as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as executor:
            issue_results = tuple(executor.map(issue, range(2)))
        assert sum(isinstance(result, DefenderTokenRecord) for result in issue_results) == 1
        assert sum(isinstance(result, DefenderPamError) for result in issue_results) == 1
    finally:
        # Simulates loss after a token was issued but before lifecycle closure.
        defender.close_pool()

    defender_recovery = PostgresDefenderTokenJournal.from_dsn(
        _BROKER_DSN,
        journal_namespace_digest=namespace_digest,
        min_size=1,
        max_size=2,
    )
    try:
        first_recovery = _recover_defender(
            defender_recovery,
            acquisition_id,
        )
        second_recovery = _recover_defender(
            defender_recovery,
            acquisition_id,
        )
        assert len(first_recovery) == 1
        assert first_recovery[0].state == "closed"
        assert first_recovery[0].closure == "abandoned-after-crash"
        assert second_recovery == ()
    finally:
        defender_recovery.close_pool()

    isolated = PostgresElasticLeaseJournal.from_dsn(
        _BROKER_DSN,
        journal_namespace_digest=other_namespace_digest,
        min_size=1,
        max_size=2,
    )
    try:
        with pytest.raises(ElasticPamError, match="does not exist"):
            isolated.get(lease_id)
        assert isolated.unsettled() == ()
    finally:
        isolated.close_pool()

    transition_lease_id = uuid.uuid4().hex + uuid.uuid4().hex
    transition_acquisition_id = uuid.uuid4().hex + uuid.uuid4().hex
    transition_elastic = PostgresElasticLeaseJournal.from_dsn(
        _BROKER_DSN,
        journal_namespace_digest=namespace_digest,
        min_size=1,
        max_size=2,
    )
    transition_defender = PostgresDefenderTokenJournal.from_dsn(
        _BROKER_DSN,
        journal_namespace_digest=namespace_digest,
        min_size=1,
        max_size=2,
    )
    try:
        transition_elastic.prepare(
            lease_id=transition_lease_id,
            key_name=f"control-assurance-{transition_lease_id[:32]}",
            policy=policy,
            request_digest=_DIGEST,
            endpoint_origin_digest=_OTHER_DIGEST,
            now_epoch_millis=_CREATED,
        )
        transition_defender.prepare(
            acquisition_id=transition_acquisition_id,
            request_digest=_DIGEST,
            token_endpoint_digest=_OTHER_DIGEST,
            graph_origin_digest=_DIGEST,
            scope_digest=_OTHER_DIGEST,
            credential_mode="federated-rs256",
            credential_reference_digest=_DIGEST,
            token_request_profile_digest=_OTHER_DIGEST,
            now_epoch_millis=_CREATED,
            conservative_exposure_end_epoch_millis=_CREATED + 3_960_000,
        )
        transition_defender.mark_issued(
            acquisition_id=transition_acquisition_id,
            expected_revision=0,
            now_epoch_millis=_CREATED + 1,
            expires_epoch_millis=_CREATED + 300_001,
            assertion_id_digest=_DIGEST,
            response_request_id_digest=None,
        )
    finally:
        transition_elastic.close_pool()
        transition_defender.close_pool()

    psycopg = importlib.import_module("psycopg")
    with psycopg.connect(_BROKER_DSN, autocommit=True) as connection:
        with pytest.raises(Exception, match="immutable Elastic PAM"):
            connection.execute(
                """
                UPDATE control_assurance_pam.elastic_jit_leases
                SET request_digest = %s
                WHERE journal_namespace_digest = %s
                  AND lease_id = %s
                """,
                (_OTHER_DIGEST, namespace_digest, lease_id),
            )
        with pytest.raises(Exception, match="immutable Defender PAM"):
            connection.execute(
                """
                UPDATE control_assurance_pam.defender_token_lifecycle
                SET scope_digest = %s
                WHERE journal_namespace_digest = %s
                  AND acquisition_id = %s
                """,
                (_DIGEST, namespace_digest, acquisition_id),
            )
        with pytest.raises(Exception, match="invalid Elastic PAM"):
            connection.execute(
                """
                UPDATE control_assurance_pam.elastic_jit_leases
                SET state = 'revoked',
                    revoked_epoch_millis = %s,
                    revoke_attempts = 1,
                    revision = 2
                WHERE journal_namespace_digest = %s
                  AND lease_id = %s
                """,
                (
                    _CREATED + 5,
                    namespace_digest,
                    transition_lease_id,
                ),
            )
        with pytest.raises(Exception, match="invalid Defender PAM"):
            connection.execute(
                """
                UPDATE control_assurance_pam.defender_token_lifecycle
                SET state = 'uncertain',
                    closure = 'token-request-ambiguous',
                    issued_epoch_millis = NULL,
                    closed_epoch_millis = %s,
                    access_token_expires_epoch_millis = NULL,
                    assertion_id_digest = NULL,
                    response_request_id_digest = NULL,
                    last_error = 'invalid direct transition'
                WHERE journal_namespace_digest = %s
                  AND acquisition_id = %s
                """,
                (
                    _CREATED + 5,
                    namespace_digest,
                    transition_acquisition_id,
                ),
            )


def test_live_plan_bound_issuance_fence_is_atomic_complete_and_expires() -> None:
    assert _BROKER_DSN is not None
    assert _ADMIN_DSN is not None
    assert _MIGRATION_DSN is not None
    _install_schema()
    suffix = uuid.uuid4().hex
    namespace_digest = _digest(f"{suffix}:pam-namespace")
    _configure_namespace(namespace_digest, "plan-bound-issuance")
    old_binding, successor_binding = _plan_bound_execution(suffix)
    source_scope = old_binding.scope(
        authority_class="source",
        connector_id="elastic-security",
        connector_request_digest=old_binding.pam_scopes[-1].connector_request_digest,
    )
    signing_scope = old_binding.scope(
        authority_class="signing",
        connector_id="vault-transit",
        connector_request_digest=old_binding.pam_scopes[1].connector_request_digest,
    )
    journal = PostgresPamIssuanceJournal.from_dsn(
        _BROKER_DSN,
        journal_namespace_digest=namespace_digest,
        min_size=3,
        max_size=8,
    )
    now_epoch_millis = time.time_ns() // 1_000_000
    maximum_exposure = now_epoch_millis + 20_000
    try:
        journal.register_execution_binding(
            old_binding,
            registered_at_epoch_millis=now_epoch_millis,
        )
        source_prepared = journal.prepare_lifecycle(
            old_binding,
            source_scope,
            lifecycle_record_id=f"elastic:{suffix}",
            credential_reference_digest=None,
            created_epoch_millis=now_epoch_millis,
            maximum_residual_exposure_ends_epoch_millis=maximum_exposure,
        )
        signing_prepared = journal.prepare_lifecycle(
            old_binding,
            signing_scope,
            lifecycle_record_id=f"signing:{suffix}",
            credential_reference_digest=None,
            created_epoch_millis=now_epoch_millis,
            maximum_residual_exposure_ends_epoch_millis=maximum_exposure,
        )
        effective_at = time.time_ns() // 1_000_000
        operation_digest = _digest(f"{suffix}:issuance-fence")
        start = Barrier(3)

        def race_issue() -> PAMLifecycleRecord | PostgresPamRecoveryError:
            start.wait()
            issued_at = time.time_ns() // 1_000_000
            try:
                return journal.mark_lifecycle_issued(
                    old_binding,
                    lifecycle_record_id=source_prepared.lifecycle_record_id,
                    expected_revision=source_prepared.revision,
                    issued_epoch_millis=issued_at,
                    expires_epoch_millis=issued_at + 2_000,
                    maximum_residual_exposure_ends_epoch_millis=maximum_exposure,
                )
            except PostgresPamRecoveryError as exc:
                return exc

        def race_prepare() -> PAMLifecycleRecord | PostgresPamRecoveryError:
            start.wait()
            created_at = time.time_ns() // 1_000_000
            try:
                return journal.prepare_lifecycle(
                    old_binding,
                    source_scope,
                    lifecycle_record_id=f"elastic:{suffix}:racing",
                    credential_reference_digest=None,
                    created_epoch_millis=created_at,
                    maximum_residual_exposure_ends_epoch_millis=maximum_exposure,
                )
            except PostgresPamRecoveryError as exc:
                return exc

        def race_fence() -> PAMIssuanceFence:
            start.wait()
            return journal.install_recovery_issuance_fence(
                old_binding,
                successor_binding,
                operation_digest=operation_digest,
                effective_at_epoch_millis=effective_at,
                valid_until_epoch_millis=(successor_binding.lease_expires_at_epoch_millis),
            )

        with ThreadPoolExecutor(max_workers=3) as executor:
            issue_future = executor.submit(race_issue)
            prepare_future = executor.submit(race_prepare)
            fence_future = executor.submit(race_fence)
            issue_result = issue_future.result()
            prepare_result = prepare_future.result()
            fence = fence_future.result()

        assert isinstance(
            issue_result,
            (PAMLifecycleRecord, PostgresPamRecoveryError),
        )
        assert isinstance(
            prepare_result,
            (PAMLifecycleRecord, PostgresPamRecoveryError),
        )
        assert isinstance(fence, PAMIssuanceFence)
        assert fence.valid_until_epoch_millis == (successor_binding.lease_expires_at_epoch_millis)

        with pytest.raises(PostgresPamRecoveryError, match="conflicted"):
            journal.prepare_lifecycle(
                old_binding,
                source_scope,
                lifecycle_record_id=f"elastic:{suffix}:stale",
                credential_reference_digest=None,
                created_epoch_millis=time.time_ns() // 1_000_000,
                maximum_residual_exposure_ends_epoch_millis=maximum_exposure,
            )
        with pytest.raises(PostgresPamRecoveryError, match="conflicted"):
            journal.mark_lifecycle_issued(
                old_binding,
                lifecycle_record_id=signing_prepared.lifecycle_record_id,
                expected_revision=signing_prepared.revision,
                issued_epoch_millis=time.time_ns() // 1_000_000,
                expires_epoch_millis=maximum_exposure - 1,
                maximum_residual_exposure_ends_epoch_millis=maximum_exposure,
            )

        legacy = PostgresElasticLeaseJournal.from_dsn(
            _BROKER_DSN,
            journal_namespace_digest=namespace_digest,
            min_size=1,
            max_size=2,
        )
        try:
            legacy_id = uuid.uuid4().hex + uuid.uuid4().hex
            with pytest.raises(ElasticPamError, match="conflicted"):
                legacy.prepare(
                    lease_id=legacy_id,
                    key_name=f"control-assurance-{legacy_id[:32]}",
                    policy=ElasticPamPolicy(
                        ".alerts-security.alerts-default",
                    ),
                    request_digest=source_scope.connector_request_digest,
                    endpoint_origin_digest=_OTHER_DIGEST,
                    now_epoch_millis=time.time_ns() // 1_000_000,
                )
        finally:
            legacy.close_pool()

        successor_created = time.time_ns() // 1_000_000
        successor_prepared = journal.prepare_lifecycle(
            successor_binding,
            source_scope,
            lifecycle_record_id=f"elastic:{suffix}:successor",
            credential_reference_digest=None,
            created_epoch_millis=successor_created,
            maximum_residual_exposure_ends_epoch_millis=successor_created + 2_000,
        )
        successor_issued = journal.mark_lifecycle_issued(
            successor_binding,
            lifecycle_record_id=successor_prepared.lifecycle_record_id,
            expected_revision=successor_prepared.revision,
            issued_epoch_millis=successor_created + 1,
            expires_epoch_millis=successor_created + 1_000,
            maximum_residual_exposure_ends_epoch_millis=successor_created + 2_000,
        )
        snapshot = journal.lifecycle_snapshot(old_binding)

        successful_race_records = tuple(
            result
            for result in (issue_result, prepare_result)
            if isinstance(result, PAMLifecycleRecord)
        )
        expected_record_ids = {
            source_prepared.lifecycle_record_id,
            signing_prepared.lifecycle_record_id,
            *(record.lifecycle_record_id for record in successful_race_records),
        }
        assert snapshot.matching_record_count == len(expected_record_ids)
        assert {record.lifecycle_record_id for record in snapshot.records} == (expected_record_ids)
        assert all(
            record.lifecycle_sequence <= fence.snapshot_high_watermark
            for record in snapshot.records
        )
        assert successor_issued.lifecycle_sequence > fence.snapshot_high_watermark

        psycopg = importlib.import_module("psycopg")
        with psycopg.connect(_BROKER_DSN, autocommit=True) as connection:
            database_count = connection.execute(
                """
                SELECT
                    count(*) FILTER (
                        WHERE lifecycle_sequence <= %s
                    )::integer,
                    count(*) FILTER (
                        WHERE lifecycle_sequence > %s
                    )::integer
                FROM control_assurance_pam.lifecycle_records
                WHERE journal_namespace_digest = %s
                  AND execution_binding_digest = %s
                """,
                (
                    fence.snapshot_high_watermark,
                    fence.snapshot_high_watermark,
                    namespace_digest,
                    old_binding.execution_binding_digest,
                ),
            ).fetchone()
            assert database_count == (snapshot.matching_record_count, 0)
            sequences = tuple(
                row[0]
                for row in connection.execute(
                    """
                    SELECT lifecycle_sequence
                    FROM control_assurance_pam.lifecycle_records
                    WHERE journal_namespace_digest = %s
                    ORDER BY lifecycle_sequence
                    """,
                    (namespace_digest,),
                ).fetchall()
            )
            assert sequences == tuple(sorted(set(sequences)))
            assert tuple(record.lifecycle_sequence for record in snapshot.records) == tuple(
                sequence for sequence in sequences if sequence <= fence.snapshot_high_watermark
            )

        delay_seconds = max(
            0.0,
            (successor_binding.lease_expires_at_epoch_millis - (time.time_ns() // 1_000_000) + 250)
            / 1_000,
        )
        time.sleep(delay_seconds)
        with pytest.raises(PostgresPamRecoveryError, match="conflicted"):
            journal.prepare_lifecycle(
                successor_binding,
                source_scope,
                lifecycle_record_id=f"elastic:{suffix}:expired-successor",
                credential_reference_digest=None,
                created_epoch_millis=time.time_ns() // 1_000_000,
                maximum_residual_exposure_ends_epoch_millis=maximum_exposure + 10_000,
            )
        with pytest.raises(PostgresPamRecoveryError, match="conflicted"):
            journal.prepare_lifecycle(
                old_binding,
                source_scope,
                lifecycle_record_id=f"elastic:{suffix}:old-after-expiry",
                credential_reference_digest=None,
                created_epoch_millis=time.time_ns() // 1_000_000,
                maximum_residual_exposure_ends_epoch_millis=maximum_exposure + 10_000,
            )
    finally:
        journal.close_pool()

    psycopg = importlib.import_module("psycopg")
    sql = importlib.import_module("psycopg.sql")
    probe_role = f"pam_runtime_probe_{suffix[:12]}"
    with psycopg.connect(_ADMIN_DSN, autocommit=True) as connection:
        server_version = int(connection.execute("SHOW server_version_num").fetchone()[0])
        assert 170000 <= server_version < 180000
        versions = tuple(
            row[0]
            for row in connection.execute(
                """
                SELECT version
                FROM control_assurance_pam.schema_migrations
                ORDER BY version
                """
            ).fetchall()
        )
        assert versions == (1, 2, 3)
        public_acl_count = connection.execute(
            """
            SELECT
                (
                    SELECT count(*)
                    FROM pg_class AS relation
                    CROSS JOIN LATERAL aclexplode(
                        coalesce(
                            relation.relacl,
                            acldefault('r', relation.relowner)
                        )
                    ) AS privilege
                    JOIN pg_namespace AS namespace
                      ON namespace.oid = relation.relnamespace
                    WHERE namespace.nspname = 'control_assurance_pam'
                      AND privilege.grantee = 0
                )
                +
                (
                    SELECT count(*)
                    FROM pg_proc AS procedure
                    CROSS JOIN LATERAL aclexplode(
                        coalesce(
                            procedure.proacl,
                            acldefault('f', procedure.proowner)
                        )
                    ) AS privilege
                    JOIN pg_namespace AS namespace
                      ON namespace.oid = procedure.pronamespace
                    WHERE namespace.nspname = 'control_assurance_pam'
                      AND privilege.grantee = 0
                )
            """
        ).fetchone()[0]
        assert public_acl_count == 0
        callable_function_count = connection.execute(
            """
            SELECT count(*)
            FROM pg_proc AS procedure
            JOIN pg_namespace AS namespace
              ON namespace.oid = procedure.pronamespace
            WHERE namespace.nspname = 'control_assurance_pam'
              AND procedure.prorettype != 'trigger'::regtype
            """
        ).fetchone()[0]
        assert callable_function_count > 0

        connection.execute(
            sql.SQL(
                "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS"
            ).format(sql.Identifier(probe_role))
        )
        try:
            connection.execute(
                sql.SQL("GRANT USAGE ON SCHEMA control_assurance_pam TO {}").format(
                    sql.Identifier(probe_role)
                )
            )
            connection.execute(
                sql.SQL(
                    "GRANT SELECT ON control_assurance_pam.schema_migrations, "
                    "control_assurance_pam.execution_bindings, "
                    "control_assurance_pam.execution_binding_scopes, "
                    "control_assurance_pam.lifecycle_records, "
                    "control_assurance_pam.issuance_fences TO {}"
                ).format(sql.Identifier(probe_role))
            )
            connection.execute(
                sql.SQL("GRANT INSERT ON control_assurance_pam.lifecycle_records TO {}").format(
                    sql.Identifier(probe_role)
                )
            )
            connection.execute(
                sql.SQL(
                    "GRANT UPDATE (state, issued_epoch_millis, "
                    "expires_epoch_millis, settled_epoch_millis, "
                    "maximum_residual_exposure_ends_epoch_millis, revision) "
                    "ON control_assurance_pam.lifecycle_records TO {}"
                ).format(sql.Identifier(probe_role))
            )
            connection.execute(
                sql.SQL(
                    "GRANT USAGE ON SEQUENCE control_assurance_pam.lifecycle_sequence TO {}"
                ).format(sql.Identifier(probe_role))
            )
            privileges = connection.execute(
                """
                SELECT
                    has_table_privilege(%s, %s, 'SELECT'),
                    has_table_privilege(%s, %s, 'INSERT'),
                    has_column_privilege(%s, %s, 'state', 'UPDATE'),
                    has_table_privilege(%s, %s, 'DELETE'),
                    has_table_privilege(%s, %s, 'UPDATE'),
                    has_table_privilege(%s, %s, 'INSERT'),
                    has_sequence_privilege(%s, %s, 'USAGE'),
                    has_function_privilege(
                        %s,
                        'control_assurance_pam.guard_lifecycle_mutation()',
                        'EXECUTE'
                    )
                """,
                (
                    probe_role,
                    "control_assurance_pam.lifecycle_records",
                    probe_role,
                    "control_assurance_pam.lifecycle_records",
                    probe_role,
                    "control_assurance_pam.lifecycle_records",
                    probe_role,
                    "control_assurance_pam.lifecycle_records",
                    probe_role,
                    "control_assurance_pam.execution_bindings",
                    probe_role,
                    "control_assurance_pam.issuance_fences",
                    probe_role,
                    "control_assurance_pam.lifecycle_sequence",
                    probe_role,
                ),
            ).fetchone()
            assert privileges == (
                True,
                True,
                True,
                False,
                False,
                False,
                True,
                False,
            )
        finally:
            connection.execute(
                sql.SQL("DROP OWNED BY {}").format(
                    sql.Identifier(probe_role),
                )
            )
            connection.execute(
                sql.SQL("DROP ROLE {}").format(
                    sql.Identifier(probe_role),
                )
            )
