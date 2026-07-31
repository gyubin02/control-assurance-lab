"""Opt-in PostgreSQL control-plane concurrency and reconnect test.

This module is skipped unless ``CONTROL_ASSURANCE_POSTGRES_DSN`` is explicitly
set.  It validates concurrent writers against one PostgreSQL database and a
fresh connection pool after reconnect; it does not claim to simulate a real
cluster promotion or network partition.
"""

from __future__ import annotations

import importlib
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from assurance_lab.control_plane.models import (
    Actor,
    ControlConfiguration,
    ElasticSourceConfiguration,
    EvidenceConfiguration,
    ScheduleConfiguration,
)
from assurance_lab.control_plane.postgres_store import PostgresControlPlaneStore
from assurance_lab.control_plane.store import ControlPlaneConflict

_DSN = os.environ.get("CONTROL_ASSURANCE_POSTGRES_CONTROL_DSN")
_MIGRATION_DSN = os.environ.get("CONTROL_ASSURANCE_POSTGRES_MIGRATION_DSN")
_TENANT_ID = os.environ.get("CONTROL_ASSURANCE_POSTGRES_TENANT")
_DATABASE_ROLE = os.environ.get("CONTROL_ASSURANCE_POSTGRES_CONTROL_ROLE")
_AUTH_ROLE = os.environ.get("CONTROL_ASSURANCE_POSTGRES_AUTH_ROLE")
_RECONCILER_ROLE = os.environ.get(
    "CONTROL_ASSURANCE_POSTGRES_RECONCILER_ROLE"
)
pytestmark = pytest.mark.skipif(
    not all(
        (
            _DSN,
            _MIGRATION_DSN,
            _TENANT_ID,
            _DATABASE_ROLE,
            _AUTH_ROLE,
            _RECONCILER_ROLE,
        )
    ),
    reason="separated control-plane PostgreSQL DSNs are not configured",
)
_NOW = datetime(2026, 7, 29, 3, 0, tzinfo=UTC)


def _actor(tenant_id: str, subject: str) -> Actor:
    return Actor(
        tenant_id=tenant_id,
        subject=subject,
        display_name=subject,
        roles=frozenset(
            {
                "viewer",
                "editor",
                "approver",
                "deployer",
                "auditor",
            }
        ),
        groups=("secops/platform",),
        authenticated_at=_NOW,
        session_id_digest=f"sha256:{'1' * 64}",
        mfa=True,
    )


def _configuration(tenant_id: str, control_id: str) -> ControlConfiguration:
    return ControlConfiguration(
        tenant_id=tenant_id,
        control_id=control_id,
        display_name="PostgreSQL live concurrency control",
        description="Opt-in test for generation CAS and immutable audit ordering.",
        environment="test",
        owner_group="secops/platform",
        control_profile_id="alert-window-v1",
        control_profile_digest=f"sha256:{'2' * 64}",
        source=ElasticSourceConfiguration(
            endpoint_origin="https://elastic.integration.invalid",
            parent_credential_ref="vault://kv/integration/elastic-parent",
        ),
        schedule=ScheduleConfiguration(
            interval_seconds=900,
            collection_lag_seconds=120,
            window_seconds=900,
        ),
        evidence=EvidenceConfiguration(
            custody_ref=(
                f"s3-object-lock://integration-evidence/{tenant_id}/{control_id}"
            ),
            signing_key_ref="vault-transit://integration/signing/control-plane",
            retention_days=30,
        ),
    )


def _install_schema(dsn: str) -> None:
    try:
        psycopg = importlib.import_module("psycopg")
    except ImportError as exc:  # pragma: no cover - only reached in opt-in setup
        pytest.skip(f"psycopg is not installed: {exc}")
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
                _DATABASE_ROLE,
                _AUTH_ROLE,
                _RECONCILER_ROLE,
            ),
        )


def test_live_concurrent_generation_cas_and_pool_reconnect() -> None:
    assert _DSN is not None
    assert _MIGRATION_DSN is not None
    assert _TENANT_ID is not None
    assert _DATABASE_ROLE is not None
    _install_schema(_MIGRATION_DSN)
    suffix = uuid.uuid4().hex[:16]
    tenant_id = _TENANT_ID
    control_id = f"concurrency-{suffix}"
    configuration = _configuration(tenant_id, control_id)
    editor = _actor(tenant_id, "oidc:live-editor")
    store = PostgresControlPlaneStore.from_dsn(
        _DSN,
        tenant_id=tenant_id,
        expected_role=_DATABASE_ROLE,
        min_size=2,
        max_size=4,
    )

    def create() -> tuple[str, Any]:
        try:
            revision = store.create_draft(
                actor=editor,
                configuration=configuration,
                expected_parent_revision_id=None,
                created_at=_NOW,
            )
        except ControlPlaneConflict as exc:
            return "conflict", exc
        return "created", revision

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = tuple(executor.map(lambda _: create(), range(2)))
        assert sorted(outcome for outcome, _ in outcomes) == ["conflict", "created"]
        created = next(value for outcome, value in outcomes if outcome == "created")
        submitted = store.submit(
            actor=editor,
            revision_id=created.revision_id,
            expected_state_version=created.state_version,
            submitted_at=_NOW,
        )
        approved, decision = store.decide(
            actor=_actor(tenant_id, "oidc:live-approver"),
            revision_id=submitted.revision_id,
            expected_state_version=submitted.state_version,
            decision="approved",
            comment="Live PostgreSQL scope and immutable evidence settings reviewed.",
            decided_at=_NOW,
        )
        active = store.activate(
            actor=_actor(tenant_id, "oidc:live-deployer"),
            revision_id=approved.revision_id,
            expected_deployment_version=None,
            activated_at=_NOW,
        )
        assert decision.revision_id == approved.revision_id
        assert active.revision_id == approved.revision_id
        pending = store.list_deployment_operations(
            tenant_id=tenant_id,
            control_id=control_id,
        )
        assert len(pending) == 1
        assert pending[0].state == "pending"
    finally:
        store.close()

    # A new pool exercises persisted state and audit verification after all
    # sockets from the first pool are gone.  Real promotion remains an operator
    # environment test, not something this local test claims to emulate.
    reopened = PostgresControlPlaneStore.from_dsn(
        _DSN,
        tenant_id=tenant_id,
        expected_role=_DATABASE_ROLE,
        min_size=1,
        max_size=2,
    )
    try:
        summary = reopened.list_controls(tenant_id=tenant_id)
        assert len(summary) == 1
        assert summary[0].active_deployment is not None
        assert (
            reopened.list_deployment_operations(
                tenant_id=tenant_id,
                control_id=control_id,
            )[0].state
            == "pending"
        )
        count, head = reopened.verify_audit_chain(tenant_id=tenant_id)
        assert count == 4
        assert head.startswith("sha256:")
    finally:
        reopened.close()
