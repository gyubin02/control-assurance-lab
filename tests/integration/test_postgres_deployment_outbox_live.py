"""Opt-in real PostgreSQL fencing, crash-reclaim, and reconnect coverage."""

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
    Actor,
    ControlConfiguration,
    ControlPlaneConflict,
    DeploymentOperation,
    DeploymentWorkerIdentity,
    ElasticSourceConfiguration,
    EvidenceConfiguration,
    ScheduleConfiguration,
)
from assurance_lab.control_plane.postgres_store import PostgresControlPlaneStore

_CONTROL_DSN = os.environ.get("CONTROL_ASSURANCE_POSTGRES_CONTROL_DSN")
_RECONCILER_DSN = os.environ.get(
    "CONTROL_ASSURANCE_POSTGRES_RECONCILER_DSN"
)
_MIGRATION_DSN = os.environ.get("CONTROL_ASSURANCE_POSTGRES_MIGRATION_DSN")
_TENANT_ID = os.environ.get("CONTROL_ASSURANCE_POSTGRES_TENANT")
_CONTROL_ROLE = os.environ.get("CONTROL_ASSURANCE_POSTGRES_CONTROL_ROLE")
_AUTH_ROLE = os.environ.get("CONTROL_ASSURANCE_POSTGRES_AUTH_ROLE")
_RECONCILER_ROLE = os.environ.get(
    "CONTROL_ASSURANCE_POSTGRES_RECONCILER_ROLE"
)
pytestmark = pytest.mark.skipif(
    not all(
        (
            _CONTROL_DSN,
            _RECONCILER_DSN,
            _MIGRATION_DSN,
            _TENANT_ID,
            _CONTROL_ROLE,
            _AUTH_ROLE,
            _RECONCILER_ROLE,
        )
    ),
    reason="separated deployment PostgreSQL DSNs are not configured",
)
_NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)


def _actor(tenant_id: str, subject: str) -> Actor:
    return Actor(
        tenant_id=tenant_id,
        subject=subject,
        display_name=subject,
        roles=frozenset(
            {"viewer", "editor", "approver", "deployer", "auditor"}
        ),
        groups=("secops/platform",),
        authenticated_at=_NOW,
        session_id_digest=f"sha256:{'1' * 64}",
        mfa=True,
    )


def _worker(tenant_id: str, worker_id: str) -> DeploymentWorkerIdentity:
    return DeploymentWorkerIdentity(
        tenant_id=tenant_id,
        worker_id=worker_id,
        credential_digest=f"sha256:{'2' * 64}",
    )


def _configuration(tenant_id: str, control_id: str) -> ControlConfiguration:
    return ControlConfiguration(
        tenant_id=tenant_id,
        control_id=control_id,
        display_name="PostgreSQL deployment fencing",
        description="Exercises durable deployment intent and exact acknowledgement.",
        environment="test",
        owner_group="secops/platform",
        control_profile_id="alert-window-v1",
        control_profile_digest=f"sha256:{'3' * 64}",
        source=ElasticSourceConfiguration(
            endpoint_origin="https://elastic.integration.invalid",
            parent_credential_ref="vault://integration/elastic-parent",
        ),
        schedule=ScheduleConfiguration(
            interval_seconds=900,
            collection_lag_seconds=120,
            window_seconds=900,
        ),
        evidence=EvidenceConfiguration(
            custody_ref=f"s3-object-lock://evidence/{tenant_id}/{control_id}",
            signing_key_ref="vault-transit://integration/control-plane",
            retention_days=30,
        ),
    )


def _install_schema(dsn: str) -> None:
    psycopg = importlib.import_module("psycopg")
    schema = (
        Path(__file__).parents[2]
        / "deploy"
        / "postgres"
        / "control-plane-schema.sql"
    ).read_text(encoding="utf-8")
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(
            """
            DROP SCHEMA IF EXISTS
                control_assurance_boundary,
                control_assurance_auth,
                control_assurance
            CASCADE
            """
        )
        connection.execute(schema)
        connection.execute(
            """
            SELECT control_assurance_boundary.configure_runtime_roles(
                %s,
                %s::name,
                %s::name,
                %s::name
            )
            """,
            (
                _TENANT_ID,
                _CONTROL_ROLE,
                _AUTH_ROLE,
                _RECONCILER_ROLE,
            ),
        )


def test_live_outbox_concurrency_crash_reclaim_and_pool_reconnect() -> None:
    assert _CONTROL_DSN is not None
    assert _RECONCILER_DSN is not None
    assert _MIGRATION_DSN is not None
    assert _TENANT_ID is not None
    assert _CONTROL_ROLE is not None
    assert _RECONCILER_ROLE is not None
    _install_schema(_MIGRATION_DSN)
    suffix = uuid.uuid4().hex[:16]
    tenant_id = _TENANT_ID
    control_id = f"fencing-{suffix}"
    editor = _actor(tenant_id, "oidc:editor")
    control_store = PostgresControlPlaneStore.from_dsn(
        _CONTROL_DSN,
        tenant_id=tenant_id,
        expected_role=_CONTROL_ROLE,
        min_size=1,
        max_size=2,
    )
    reconciler_store = PostgresControlPlaneStore.from_dsn(
        _RECONCILER_DSN,
        tenant_id=tenant_id,
        expected_role=_RECONCILER_ROLE,
        role_kind="reconciler",
        min_size=2,
        max_size=4,
    )
    try:
        revision = control_store.create_draft(
            actor=editor,
            configuration=_configuration(tenant_id, control_id),
            expected_parent_revision_id=None,
            created_at=_NOW,
        )
        revision = control_store.submit(
            actor=editor,
            revision_id=revision.revision_id,
            expected_state_version=revision.state_version,
            submitted_at=_NOW,
        )
        revision, _ = control_store.decide(
            actor=_actor(tenant_id, "oidc:approver"),
            revision_id=revision.revision_id,
            expected_state_version=revision.state_version,
            decision="approved",
            comment="Live fenced reconciliation scope reviewed.",
            decided_at=_NOW,
        )
        desired, pending = control_store.activate_with_operation(
            actor=_actor(tenant_id, "oidc:deployer"),
            revision_id=revision.revision_id,
            expected_deployment_version=None,
            activated_at=_NOW,
        )
        assert desired.revision_id == pending.revision_id
        assert pending.state == "pending"
        assert pending.retry_of_operation_id is None

        def lease(index: int) -> DeploymentOperation | None:
            token = f"sha256:{hashlib.sha256(str(index).encode()).hexdigest()}"
            return reconciler_store.lease_next_deployment_operation(
                worker=_worker(tenant_id, f"worker-{index}"),
                lease_token_digest=token,
                leased_at=_NOW,
                lease_ttl_seconds=30,
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = tuple(executor.map(lease, range(2)))
        claimed = tuple(result for result in outcomes if result is not None)
        assert len(claimed) == 1
        first = claimed[0]
        assert first.operation_id == pending.operation_id
        assert first.lease_fence == 1
    finally:
        # Simulates process death with no failure/ack write.
        reconciler_store.close()
        control_store.close()

    control_reopened = PostgresControlPlaneStore.from_dsn(
        _CONTROL_DSN,
        tenant_id=tenant_id,
        expected_role=_CONTROL_ROLE,
        min_size=1,
        max_size=2,
    )
    reconciler_reopened = PostgresControlPlaneStore.from_dsn(
        _RECONCILER_DSN,
        tenant_id=tenant_id,
        expected_role=_RECONCILER_ROLE,
        role_kind="reconciler",
        min_size=1,
        max_size=2,
    )
    try:
        reclaimed_at = _NOW + timedelta(seconds=30)
        token = f"sha256:{hashlib.sha256(b'reclaimed').hexdigest()}"
        reclaimed = reconciler_reopened.lease_next_deployment_operation(
            worker=_worker(tenant_id, "recovery-worker"),
            lease_token_digest=token,
            leased_at=reclaimed_at,
            lease_ttl_seconds=30,
        )
        assert reclaimed is not None
        assert reclaimed.operation_id == pending.operation_id
        assert reclaimed.lease_fence == 2
        with pytest.raises(ControlPlaneConflict, match="stale"):
            reconciler_reopened.acknowledge_deployment_applied(
                worker=_worker(tenant_id, first.lease_owner or "impossible"),
                operation_id=pending.operation_id,
                lease_token_digest=first.lease_token_digest or "impossible",
                lease_fence=1,
                applied_configuration_digest=pending.configuration_digest,
                target_receipt_digest=f"sha256:{'4' * 64}",
                applied_at=reclaimed_at + timedelta(seconds=1),
            )
        applied = reconciler_reopened.acknowledge_deployment_applied(
            worker=_worker(tenant_id, "recovery-worker"),
            operation_id=pending.operation_id,
            lease_token_digest=token,
            lease_fence=2,
            applied_configuration_digest=pending.configuration_digest,
            target_receipt_digest=f"sha256:{'4' * 64}",
            applied_at=reclaimed_at + timedelta(seconds=1),
        )
        assert applied.state == "applied"

        second_configuration = _configuration(
            tenant_id,
            control_id,
        ).model_copy(update={"display_name": "PostgreSQL deployment fencing v2"})
        second_revision = control_reopened.create_draft(
            actor=editor,
            configuration=second_configuration,
            expected_parent_revision_id=revision.revision_id,
            created_at=reclaimed_at + timedelta(seconds=2),
        )
        second_revision = control_reopened.submit(
            actor=editor,
            revision_id=second_revision.revision_id,
            expected_state_version=second_revision.state_version,
            submitted_at=reclaimed_at + timedelta(seconds=2),
        )
        second_revision, _ = control_reopened.decide(
            actor=_actor(tenant_id, "oidc:approver"),
            revision_id=second_revision.revision_id,
            expected_state_version=second_revision.state_version,
            decision="approved",
            comment="Second live fenced configuration reviewed.",
            decided_at=reclaimed_at + timedelta(seconds=2),
        )
        control_reopened.activate(
            actor=_actor(tenant_id, "oidc:deployer"),
            revision_id=second_revision.revision_id,
            expected_deployment_version=1,
            activated_at=reclaimed_at + timedelta(seconds=2),
        )
        terminal_token = (
            f"sha256:{hashlib.sha256(b'terminal-operation').hexdigest()}"
        )
        terminal_lease = reconciler_reopened.lease_next_deployment_operation(
            worker=_worker(tenant_id, "recovery-worker"),
            lease_token_digest=terminal_token,
            leased_at=reclaimed_at + timedelta(seconds=3),
            lease_ttl_seconds=30,
        )
        assert terminal_lease is not None
        terminal = reconciler_reopened.fail_deployment_operation(
            worker=_worker(tenant_id, "recovery-worker"),
            operation_id=terminal_lease.operation_id,
            lease_token_digest=terminal_token,
            lease_fence=terminal_lease.lease_fence,
            failure_digest=f"sha256:{'5' * 64}",
            failed_at=reclaimed_at + timedelta(seconds=4),
            retry_at=None,
        )
        retry = control_reopened.request_deployment_retry(
            actor=_actor(tenant_id, "oidc:deployer"),
            failed_operation_id=terminal.operation_id,
            requested_at=reclaimed_at + timedelta(seconds=5),
        )
        assert retry.operation_sequence == 3
        assert retry.state == "pending"
        assert retry.retry_of_operation_id == terminal.operation_id
        assert (
            control_reopened.get_deployment_operation(
                tenant_id=tenant_id,
                operation_id=terminal.operation_id,
            ).state
            == "failed"
        )
    finally:
        reconciler_reopened.close()
        control_reopened.close()

    verified = PostgresControlPlaneStore.from_dsn(
        _CONTROL_DSN,
        tenant_id=tenant_id,
        expected_role=_CONTROL_ROLE,
        min_size=1,
        max_size=2,
    )
    try:
        persisted_retry = verified.get_deployment_operation(
            tenant_id=tenant_id,
            operation_id=retry.operation_id,
        )
        assert persisted_retry.retry_of_operation_id == terminal.operation_id
        operation = verified.latest_applied_operation(
            tenant_id=tenant_id,
            control_id=control_id,
        )
        assert operation.operation_id == pending.operation_id
        assert operation.lease_fence == 2
        count, _ = verified.verify_audit_chain(tenant_id=tenant_id)
        assert count == 14
    finally:
        verified.close()
