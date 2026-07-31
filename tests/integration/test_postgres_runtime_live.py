"""Opt-in real PostgreSQL runtime fencing, HA claims, and crash reclaim.

The live environment uses separate migration-owner, profile-registrar,
deployment-reconciler, and worker login roles.  A single all-purpose runtime
credential would hide privilege regressions in the production topology.
"""

from __future__ import annotations

import hashlib
import importlib
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from assurance_lab.control_plane import (
    ControlConfiguration,
    DeploymentApplyError,
    DeploymentApplyRequest,
    ElasticSourceConfiguration,
    EvidenceConfiguration,
    ScheduleConfiguration,
)
from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.runtime import (
    ControlRun,
    ControlRunExecutionResult,
    PostgresRuntimeCatalog,
    RegisteredControlProfile,
    RuntimeDeploymentReceipt,
    RuntimeWorkerIdentity,
)
from assurance_lab.runtime.postgres import RuntimeCatalogConflict

_MIGRATION_DSN = os.environ.get(
    "CONTROL_ASSURANCE_POSTGRES_RUNTIME_MIGRATION_DSN"
)
_REGISTRAR_DSN = os.environ.get(
    "CONTROL_ASSURANCE_POSTGRES_RUNTIME_REGISTRAR_DSN"
)
_RECONCILER_DSN = os.environ.get(
    "CONTROL_ASSURANCE_POSTGRES_RUNTIME_RECONCILER_DSN"
)
_WORKER_DSN = os.environ.get("CONTROL_ASSURANCE_POSTGRES_RUNTIME_WORKER_DSN")
_TENANT_ID = os.environ.get("CONTROL_ASSURANCE_POSTGRES_RUNTIME_TENANT")
_REQUIRED = (
    _MIGRATION_DSN,
    _REGISTRAR_DSN,
    _RECONCILER_DSN,
    _WORKER_DSN,
    _TENANT_ID,
)
pytestmark = pytest.mark.skipif(
    not all(_REQUIRED),
    reason="separated PostgreSQL runtime DSNs are not configured",
)


def _digest(label: str) -> str:
    return f"sha256:{hashlib.sha256(label.encode()).hexdigest()}"


_PROFILE_BYTES = canonical_json_bytes(
    {
        "control": "live-postgresql-runtime",
        "required_fields": ["@timestamp", "event.id"],
        "version": 1,
    }
)
_PROFILE_DIGEST = f"sha256:{hashlib.sha256(_PROFILE_BYTES).hexdigest()}"


def _profile(tenant_id: str) -> RegisteredControlProfile:
    return RegisteredControlProfile(
        tenant_id=tenant_id,
        profile_id="runtime-live-v1",
        profile_digest=_PROFILE_DIGEST,
        media_type="application/vnd.control-assurance.profile.v1+json",
        profile_bytes=_PROFILE_BYTES,
        registered_at=datetime(2026, 7, 29, 0, 0, tzinfo=UTC),
        registered_by="postgres-live-test",
    )


def _configuration(
    tenant_id: str,
    control_id: str,
    *,
    enabled: bool = True,
) -> ControlConfiguration:
    return ControlConfiguration(
        tenant_id=tenant_id,
        control_id=control_id,
        display_name="Live PostgreSQL runtime",
        description="Exercises exact runtime deployment and fenced run closure.",
        environment="test",
        owner_group="secops/platform",
        control_profile_id="runtime-live-v1",
        control_profile_digest=_PROFILE_DIGEST,
        source=ElasticSourceConfiguration(
            endpoint_origin="https://elastic.integration.invalid",
            parent_credential_ref="vault://integration/elastic-parent",
        ),
        schedule=ScheduleConfiguration(
            interval_seconds=60,
            collection_lag_seconds=0,
            window_seconds=60,
        ),
        evidence=EvidenceConfiguration(
            custody_ref=f"s3-object-lock://evidence/{tenant_id}/{control_id}",
            signing_key_ref="vault-transit://integration/runtime",
            retention_days=30,
        ),
        enabled=enabled,
    )


def _apply_request(
    configuration: ControlConfiguration,
    *,
    sequence: int,
    fence: int,
    operation_label: str,
) -> DeploymentApplyRequest:
    return DeploymentApplyRequest(
        operation_id=_digest(operation_label),
        tenant_id=configuration.tenant_id,
        control_id=configuration.control_id,
        revision_id=_digest(f"revision:{operation_label}"),
        configuration_digest=configuration.digest,
        configuration_bytes=configuration.canonical_bytes(),
        operation_sequence=sequence,
        lease_fence=fence,
    )


def _worker(tenant_id: str, worker_id: str) -> RuntimeWorkerIdentity:
    return RuntimeWorkerIdentity(
        tenant_id=tenant_id,
        worker_id=worker_id,
        credential_digest=_digest(f"credential:{worker_id}"),
    )


def _database_principal(dsn: str) -> str:
    psycopg = importlib.import_module("psycopg")
    with psycopg.connect(dsn, autocommit=True) as connection:
        row = connection.execute("SELECT current_user").fetchone()
    assert row is not None and type(row[0]) is str
    return row[0]


def _install_schema() -> None:
    assert _MIGRATION_DSN is not None
    assert _REGISTRAR_DSN is not None
    assert _RECONCILER_DSN is not None
    assert _WORKER_DSN is not None
    assert _TENANT_ID is not None
    psycopg = importlib.import_module("psycopg")
    schema = (
        Path(__file__).parents[2] / "deploy" / "postgres" / "runtime-schema.sql"
    ).read_text(encoding="utf-8")
    roles = (
        (_database_principal(_REGISTRAR_DSN), "registrar"),
        (_database_principal(_RECONCILER_DSN), "reconciler"),
        (_database_principal(_WORKER_DSN), "worker"),
    )
    with psycopg.connect(_MIGRATION_DSN, autocommit=True) as connection:
        connection.execute(schema)
        for role, principal_kind in roles:
            row = connection.execute(
                """
                SELECT control_assurance_runtime.configure_login_role(
                    %s, %s::name, %s
                )
                """,
                (_TENANT_ID, role, principal_kind),
            ).fetchone()
            assert row == (True,)


def _database_now(dsn: str) -> datetime:
    psycopg = importlib.import_module("psycopg")
    with psycopg.connect(dsn, autocommit=True) as connection:
        row = connection.execute(
            "SELECT date_trunc('second', transaction_timestamp())"
        ).fetchone()
    assert row is not None and isinstance(row[0], datetime)
    return row[0].astimezone(UTC)


def test_live_runtime_schema_installs_exact_deployment_identity() -> None:
    assert _MIGRATION_DSN is not None
    _install_schema()
    psycopg = importlib.import_module("psycopg")
    with psycopg.connect(_MIGRATION_DSN, autocommit=True) as connection:
        row = connection.execute(
            """
            SELECT pg_get_constraintdef(oid)
            FROM pg_constraint
            WHERE connamespace =
                    'control_assurance_runtime'::regnamespace
              AND conrelid =
                    'control_assurance_runtime.deployment_history'::regclass
              AND conname = 'runtime_deployment_exact_identity_unique'
              AND contype = 'u'
            """
        ).fetchone()
    assert row == ("UNIQUE (tenant_id, control_id, operation_id)",)


def _insert_past_deployment(
    dsn: str,
    configuration: ControlConfiguration,
    *,
    operation_id: str,
    revision_id: str,
    applied_at: datetime,
) -> RuntimeDeploymentReceipt:
    psycopg = importlib.import_module("psycopg")
    receipt = RuntimeDeploymentReceipt(
        tenant_id=configuration.tenant_id,
        control_id=configuration.control_id,
        operation_id=operation_id,
        operation_sequence=1,
        lease_fence_at_commit=1,
        revision_id=revision_id,
        configuration_digest=configuration.digest,
        control_profile_id=configuration.control_profile_id,
        control_profile_digest=configuration.control_profile_digest,
        previous_operation_id=None,
        previous_receipt_digest=None,
        applied_at=applied_at,
    )
    schedule = configuration.schedule
    with psycopg.connect(dsn) as connection, connection.transaction():
        connection.execute(
            "SELECT set_config('control_assurance.tenant_id', %s, true)",
            (configuration.tenant_id,),
        )
        connection.execute(
            """
            INSERT INTO control_assurance_runtime.deployment_history (
                operation_id, tenant_id, control_id, operation_sequence,
                revision_id, configuration_digest, configuration_bytes,
                control_profile_id, control_profile_digest,
                enabled, interval_seconds, collection_lag_seconds,
                window_seconds, lease_fence_at_commit,
                previous_operation_id, previous_receipt_digest,
                receipt_digest, receipt_bytes, applied_at
            )
            VALUES (
                %s, %s, %s, 1, %s, %s, %s, %s, %s,
                true, %s, %s, %s, 1, NULL, NULL, %s, %s, %s
            )
            """,
            (
                operation_id,
                configuration.tenant_id,
                configuration.control_id,
                revision_id,
                configuration.digest,
                configuration.canonical_bytes(),
                configuration.control_profile_id,
                configuration.control_profile_digest,
                schedule.interval_seconds,
                schedule.collection_lag_seconds,
                schedule.window_seconds,
                receipt.digest,
                receipt.canonical_bytes(),
                applied_at,
            ),
        )
        connection.execute(
            """
            INSERT INTO
                control_assurance_runtime.deployment_operation_fences (
                    operation_id, tenant_id, control_id,
                    highest_lease_fence_seen
                )
            VALUES (%s, %s, %s, 1)
            """,
            (
                operation_id,
                configuration.tenant_id,
                configuration.control_id,
            ),
        )
        connection.execute(
            """
            INSERT INTO control_assurance_runtime.current_deployed_controls (
                tenant_id, control_id, operation_id, operation_sequence,
                revision_id, configuration_digest, configuration_bytes,
                control_profile_id, control_profile_digest,
                enabled, interval_seconds, collection_lag_seconds,
                window_seconds, deployment_receipt_digest,
                lease_fence_at_commit, applied_at
            )
            VALUES (
                %s, %s, %s, 1, %s, %s, %s, %s, %s,
                true, %s, %s, %s, %s, 1, %s
            )
            """,
            (
                configuration.tenant_id,
                configuration.control_id,
                operation_id,
                revision_id,
                configuration.digest,
                configuration.canonical_bytes(),
                configuration.control_profile_id,
                configuration.control_profile_digest,
                schedule.interval_seconds,
                schedule.collection_lag_seconds,
                schedule.window_seconds,
                receipt.digest,
                applied_at,
            ),
        )
    return receipt


def test_live_runtime_target_materialization_claim_crash_and_exact_closure() -> None:
    assert _REGISTRAR_DSN is not None
    assert _RECONCILER_DSN is not None
    assert _WORKER_DSN is not None
    assert _TENANT_ID is not None
    _install_schema()
    suffix = uuid.uuid4().hex[:16]

    target_tenant = _TENANT_ID
    target_control = f"target-{suffix}"
    enabled = _configuration(target_tenant, target_control)
    first = _apply_request(
        enabled,
        sequence=1,
        fence=1,
        operation_label=f"target-first:{suffix}",
    )
    registrar = PostgresRuntimeCatalog.from_dsn(
        _REGISTRAR_DSN,
        min_size=2,
        max_size=4,
    )
    reconciler = PostgresRuntimeCatalog.from_dsn(
        _RECONCILER_DSN,
        min_size=2,
        max_size=4,
    )
    try:
        missing_configuration = _configuration(
            target_tenant,
            f"missing-{suffix}",
        )
        with pytest.raises(DeploymentApplyError, match="profile-not-found"):
            reconciler.ensure_applied(
                _apply_request(
                    missing_configuration,
                    sequence=1,
                    fence=1,
                    operation_label=f"missing-profile:{suffix}",
                )
            )
        with ThreadPoolExecutor(max_workers=2) as executor:
            profiles = tuple(
                executor.map(
                    lambda _index: registrar.register_control_profile(
                        _profile(target_tenant)
                    ),
                    range(2),
                )
            )
        assert profiles[0] == profiles[1]
        assert registrar.profile_bytes(
            tenant_id=target_tenant,
            profile_digest=_PROFILE_DIGEST,
        ) == _PROFILE_BYTES
        alias = _profile(target_tenant).model_copy(
            update={"profile_id": "runtime-live-alias"}
        )
        with pytest.raises(RuntimeCatalogConflict, match="collides"):
            registrar.register_control_profile(alias)
        with ThreadPoolExecutor(max_workers=2) as executor:
            acknowledgements = tuple(
                executor.map(
                    lambda _index: reconciler.ensure_applied(first),
                    range(2),
                )
            )
        assert len({ack.target_receipt_digest for ack in acknowledgements}) == 1
        assert reconciler.deployment_receipt(
            tenant_id=target_tenant,
            operation_id=first.operation_id,
        ).digest == acknowledgements[0].target_receipt_digest
        recovered = reconciler.ensure_applied(
            first.model_copy(update={"lease_fence": 2})
        )
        assert recovered.target_receipt_digest == acknowledgements[0].target_receipt_digest
        with pytest.raises(DeploymentApplyError, match="stale"):
            reconciler.ensure_applied(first)

        disabled = _configuration(target_tenant, target_control, enabled=False)
        second = _apply_request(
            disabled,
            sequence=2,
            fence=1,
            operation_label=f"target-disabled:{suffix}",
        )
        reconciler.ensure_applied(second)
        current = reconciler.current_deployed_control(
            tenant_id=target_tenant,
            control_id=target_control,
        )
        assert current.operation_id == second.operation_id
        assert current.configuration.enabled is False
        history = reconciler.deployment_history_for_control(
            tenant_id=target_tenant,
            control_id=target_control,
        )
        assert tuple(item.operation_id for item in history) == (
            first.operation_id,
            second.operation_id,
        )
        assert history[1].applied_at > history[0].applied_at
    finally:
        reconciler.close()
        registrar.close()

    run_tenant = target_tenant
    run_control = f"runs-{suffix}"
    run_configuration = _configuration(run_tenant, run_control)
    operation_id = _digest(f"run-deployment:{suffix}")
    revision_id = _digest(f"run-revision:{suffix}")
    database_now = _database_now(_WORKER_DSN)
    profile_catalog = PostgresRuntimeCatalog.from_dsn(
        _REGISTRAR_DSN,
        min_size=1,
        max_size=2,
    )
    try:
        profile_catalog.register_control_profile(_profile(run_tenant))
    finally:
        profile_catalog.close()
    receipt = _insert_past_deployment(
        _RECONCILER_DSN,
        run_configuration,
        operation_id=operation_id,
        revision_id=revision_id,
        applied_at=database_now - timedelta(minutes=5),
    )
    first_process = PostgresRuntimeCatalog.from_dsn(
        _WORKER_DSN,
        min_size=2,
        max_size=4,
    )
    try:
        def materialize(_index: int) -> int:
            return first_process.materialize_due_runs(
                tenant_id=run_tenant,
                through=database_now,
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            inserted = tuple(executor.map(materialize, range(2)))
        assert sum(inserted) >= 4

        claim_time = database_now

        def claim(index: int) -> ControlRun | None:
            return first_process.claim_next_run(
                worker=_worker(run_tenant, f"worker-{index}"),
                lease_token_digest=_digest(f"lease-{index}"),
                leased_at=claim_time,
                lease_ttl_seconds=15,
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            claims = tuple(executor.map(claim, range(2)))
        claimed = tuple(item for item in claims if item is not None)
        assert len(claimed) == 2
        assert len({item.run_id for item in claimed}) == 2
        # There are multiple due runs, so each worker receives a different
        # immutable run. Claim one separately and simulate a process crash.
        crashed = claimed[0]
        crashed_worker_index = claims.index(crashed)
        crashed_worker = _worker(run_tenant, f"worker-{crashed_worker_index}")
        crashed_token = _digest(f"lease-{crashed_worker_index}")
        assert crashed.request.deployment_receipt_digest == receipt.digest
    finally:
        first_process.close()

    recovered_process = PostgresRuntimeCatalog.from_dsn(
        _WORKER_DSN,
        min_size=2,
        max_size=4,
    )
    try:
        assert crashed.lease_expires_at is not None
        recovery_time = crashed.lease_expires_at
        recovery_worker = _worker(run_tenant, "recovery-worker")
        recovery_token = _digest("recovery-token")
        reclaimed = None
        # Other due runs sort ahead of the expired one until claimed. Drain
        # them with distinct leases; SKIP LOCKED and run identity remain exact.
        for index in range(16):
            candidate = recovered_process.claim_next_run(
                worker=recovery_worker,
                lease_token_digest=(
                    recovery_token
                    if index == 0
                    else _digest(f"recovery-token-{index}")
                ),
                leased_at=recovery_time,
                lease_ttl_seconds=15,
            )
            assert candidate is not None
            if candidate.run_id == crashed.run_id:
                reclaimed = candidate
                recovery_token = (
                    recovery_token
                    if index == 0
                    else _digest(f"recovery-token-{index}")
                )
                break
        assert reclaimed is not None
        assert reclaimed.lease_fence == crashed.lease_fence + 1
        result = ControlRunExecutionResult(
            run_id=reclaimed.run_id,
            lease_fence=reclaimed.lease_fence,
            evidence_digest=_digest("live-evidence"),
            executor_receipt_digest=_digest("live-executor-receipt"),
        )
        completed = recovered_process.complete_run(
            worker=recovery_worker,
            run_id=reclaimed.run_id,
            lease_token_digest=recovery_token,
            lease_fence=reclaimed.lease_fence,
            result=result,
            completed_at=recovery_time + timedelta(seconds=1),
        )
        assert completed.state == "succeeded"
        closure = recovered_process.run_closure(
            tenant_id=run_tenant,
            run_id=reclaimed.run_id,
        )
        assert closure.evidence_digest == result.evidence_digest
        assert closure.executor_receipt_digest == result.executor_receipt_digest
        assert closure.deployment_receipt_digest == receipt.digest
        assert closure.control_profile_id == run_configuration.control_profile_id
        assert (
            closure.control_profile_digest
            == run_configuration.control_profile_digest
        )

        stale_result = ControlRunExecutionResult(
            run_id=crashed.run_id,
            lease_fence=crashed.lease_fence,
            evidence_digest=_digest("stale-evidence"),
            executor_receipt_digest=_digest("stale-executor-receipt"),
        )
        with pytest.raises(RuntimeCatalogConflict):
            recovered_process.complete_run(
                worker=crashed_worker,
                run_id=crashed.run_id,
                lease_token_digest=crashed_token,
                lease_fence=crashed.lease_fence,
                result=stale_result,
                completed_at=recovery_time + timedelta(seconds=2),
            )
    finally:
        recovered_process.close()
