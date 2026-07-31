from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from assurance_lab.control_plane.models import (
    ActiveDeployment,
    Actor,
    ConfigurationRevision,
    ControlConfiguration,
    ElasticSourceConfiguration,
    EvidenceConfiguration,
    ScheduleConfiguration,
    revision_identity,
)
from assurance_lab.control_plane.postgres_store import (
    PostgresControlPlaneStore,
)
from assurance_lab.control_plane.store import (
    ControlPlaneConflict,
    ControlPlaneIntegrityError,
    ControlPlaneNotFound,
    ControlPlaneStoreError,
)

_NOW = datetime(2026, 7, 29, 3, 0, tzinfo=UTC)
_SESSION_DIGEST = f"sha256:{'1' * 64}"
_PROFILE_DIGEST = f"sha256:{'2' * 64}"
_DATABASE_ROLE = "assurance_control_runtime"


class _Cursor:
    def __init__(
        self,
        rows: Sequence[Mapping[str, Any]] = (),
        *,
        rowcount: int = 0,
    ) -> None:
        self._rows = list(rows)
        self.rowcount = rowcount

    def fetchone(self) -> Mapping[str, Any] | None:
        return None if not self._rows else self._rows[0]

    def fetchall(self) -> Sequence[Mapping[str, Any]]:
        return tuple(self._rows)


class _ScriptedConnection:
    def __init__(self, script: Sequence[tuple[str, _Cursor]]) -> None:
        self.script = list(script)
        self.executed: list[tuple[str, tuple[object, ...]]] = []
        self.commits = 0
        self.rollbacks = 0

    def execute(
        self,
        query: str,
        params: Sequence[object] = (),
    ) -> _Cursor:
        normalized = " ".join(query.split()).lower()
        parameter_tuple = tuple(params)
        self.executed.append((normalized, parameter_tuple))
        if normalized.startswith("set transaction isolation level"):
            return _Cursor()
        if "select set_config(" in normalized:
            return _Cursor()
        if "control_assurance.runtime_identity()" in normalized:
            return _Cursor(
                (
                    {
                        "session_user": _DATABASE_ROLE,
                        "current_user": _DATABASE_ROLE,
                        "current_role": _DATABASE_ROLE,
                        "login_role": _DATABASE_ROLE,
                        "tenant_id": "acme-bank",
                        "role_kind": "control",
                        "schema_versions": [1, 2, 3, 4, 5, 6],
                    },
                )
            )
        if "pg_advisory_xact_lock" in normalized:
            return _Cursor()
        if not self.script:
            raise AssertionError(f"unexpected SQL: {normalized}")
        expected, cursor = self.script.pop(0)
        assert expected in normalized
        return cursor

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
        self._connection = connection
        self.leases = 0

    @contextmanager
    def connection(self) -> Iterator[_ScriptedConnection]:
        self.leases += 1
        yield self._connection


def _store(
    pool: _Pool,
    **kwargs: Any,
) -> PostgresControlPlaneStore:
    return PostgresControlPlaneStore(
        pool,
        tenant_id="acme-bank",
        expected_role=_DATABASE_ROLE,
        **kwargs,
    )


def _actor(subject: str = "oidc:alice") -> Actor:
    return Actor(
        tenant_id="acme-bank",
        subject=subject,
        display_name=subject,
        roles=frozenset({"viewer", "editor"}),
        groups=("secops/platform",),
        authenticated_at=_NOW,
        session_id_digest=_SESSION_DIGEST,
        mfa=True,
    )


def _configuration(
    *,
    control_id: str = "elastic-alert-completeness",
) -> ControlConfiguration:
    return ControlConfiguration(
        tenant_id="acme-bank",
        control_id=control_id,
        display_name="Elastic alert completeness",
        description="Proves the exact alert window closes without partial shards.",
        environment="production",
        owner_group="secops/platform",
        control_profile_id="alert-window-v1",
        control_profile_digest=_PROFILE_DIGEST,
        source=ElasticSourceConfiguration(
            endpoint_origin="https://elastic.acme.example",
            index_alias=".alerts-security.alerts-default",
            parent_credential_ref="vault://kv/secops/elastic-jit-parent",
        ),
        schedule=ScheduleConfiguration(
            interval_seconds=900,
            collection_lag_seconds=120,
            window_seconds=900,
        ),
        evidence=EvidenceConfiguration(
            custody_ref="s3-object-lock://assurance-evidence/acme-bank/elastic",
            signing_key_ref="vault-transit://assurance/signing/elastic-prod",
            retention_days=365,
        ),
    )


def _revision_row(
    configuration: ControlConfiguration,
    *,
    state: str = "draft",
    state_version: int = 0,
    submitted_at: datetime | None = None,
    decided_at: datetime | None = None,
) -> dict[str, Any]:
    revision_id = revision_identity(
        tenant_id=configuration.tenant_id,
        control_id=configuration.control_id,
        generation=1,
        parent_revision_id=None,
        configuration_digest=configuration.digest,
    )
    return {
        "revision_id": revision_id,
        "tenant_id": configuration.tenant_id,
        "control_id": configuration.control_id,
        "generation": 1,
        "parent_revision_id": None,
        "configuration_digest": configuration.digest,
        "configuration_bytes": configuration.canonical_bytes(),
        "state": state,
        "state_version": state_version,
        "created_by": "oidc:alice",
        "created_at": _NOW,
        "submitted_at": submitted_at,
        "decided_at": decided_at,
    }


def test_create_draft_uses_audit_then_control_locks_and_canonical_bytes() -> None:
    configuration = _configuration()
    row = _revision_row(configuration)
    connection = _ScriptedConnection(
        (
            ("from control_assurance.control_revisions", _Cursor()),
            ("insert into control_assurance.control_revisions", _Cursor(rowcount=1)),
            ("from control_assurance.control_audit_events", _Cursor()),
            ("insert into control_assurance.control_audit_events", _Cursor(rowcount=1)),
            ("from control_assurance.control_revisions", _Cursor((row,))),
        )
    )
    store = _store(_Pool(connection))

    revision = store.create_draft(
        actor=_actor(),
        configuration=configuration,
        expected_parent_revision_id=None,
        created_at=_NOW,
    )

    assert revision == ConfigurationRevision(**row)
    assert isinstance(configuration.source, ElasticSourceConfiguration)
    assert not connection.script
    advisory = [
        params[0]
        for query, params in connection.executed
        if "pg_advisory_xact_lock" in query
    ]
    assert advisory == [
        "control-assurance:audit:acme-bank",
        "control-assurance:control:acme-bank:elastic-alert-completeness",
    ]
    revision_insert = next(
        params
        for query, params in connection.executed
        if "insert into control_assurance.control_revisions" in query
    )
    assert revision_insert[6] == configuration.canonical_bytes()
    assert configuration.source.parent_credential_ref.encode() in revision_insert[6]
    assert connection.commits == 2
    assert connection.rollbacks == 0


def test_submit_cas_failure_rolls_back_without_writing_audit() -> None:
    configuration = _configuration()
    row = _revision_row(configuration)
    connection = _ScriptedConnection(
        (
            ("from control_assurance.control_revisions", _Cursor((row,))),
            ("from control_assurance.control_revisions", _Cursor((row,))),
            ("update control_assurance.control_revisions", _Cursor(rowcount=0)),
        )
    )
    store = _store(_Pool(connection))

    with pytest.raises(ControlPlaneConflict, match="concurrently"):
        store.submit(
            actor=_actor(),
            revision_id=row["revision_id"],
            expected_state_version=0,
            submitted_at=_NOW,
        )

    assert connection.rollbacks == 1
    assert not any(
        "insert into control_assurance.control_audit_events" in query
        for query, _ in connection.executed
    )
    assert not connection.script


def test_decision_is_persisted_before_state_transition_and_audit() -> None:
    configuration = _configuration()
    submitted = _revision_row(
        configuration,
        state="submitted",
        state_version=1,
        submitted_at=_NOW,
    )
    approved = {
        **submitted,
        "state": "approved",
        "state_version": 2,
        "decided_at": _NOW,
    }
    connection = _ScriptedConnection(
        (
            ("from control_assurance.control_revisions", _Cursor((submitted,))),
            ("from control_assurance.control_revisions", _Cursor((submitted,))),
            ("insert into control_assurance.approval_decisions", _Cursor(rowcount=1)),
            ("update control_assurance.control_revisions", _Cursor(rowcount=1)),
            ("from control_assurance.control_audit_events", _Cursor()),
            ("insert into control_assurance.control_audit_events", _Cursor(rowcount=1)),
            ("from control_assurance.control_revisions", _Cursor((approved,))),
        )
    )
    store = _store(_Pool(connection))
    approver = _actor("oidc:bob")

    revision, decision = store.decide(
        actor=approver,
        revision_id=submitted["revision_id"],
        expected_state_version=1,
        decision="approved",
        comment="Read-only scope and rollback evidence reviewed.",
        decided_at=_NOW,
    )

    assert revision.state == "approved"
    assert decision.decided_by == "oidc:bob"
    assert decision.actor_session_digest == _SESSION_DIGEST
    statements = [query for query, _ in connection.executed]
    decision_insert = next(
        index
        for index, query in enumerate(statements)
        if "insert into control_assurance.approval_decisions" in query
    )
    state_update = next(
        index
        for index, query in enumerate(statements)
        if "update control_assurance.control_revisions" in query
    )
    audit_insert = next(
        index
        for index, query in enumerate(statements)
        if "insert into control_assurance.control_audit_events" in query
    )
    assert decision_insert < state_update < audit_insert
    assert connection.rollbacks == 0
    assert not connection.script


def test_each_transaction_sets_deadlines_tenant_and_schema_gate() -> None:
    connection = _ScriptedConnection(
        (("from control_assurance.control_revisions", _Cursor()),)
    )
    store = _store(
        _Pool(connection),
        statement_timeout_ms=9_000,
        lock_timeout_ms=2_000,
    )

    with pytest.raises(ControlPlaneNotFound, match="not found"):
        store.get_revision(
            tenant_id="acme-bank",
            revision_id=f"sha256:{'a' * 64}",
        )

    set_config = [
        params
        for query, params in connection.executed
        if "select set_config(" in query
    ]
    assert set_config == [("9000ms",), ("2000ms",)]
    assert any("runtime_identity()" in query for query, _ in connection.executed)


def test_unsupported_schema_fails_closed_before_tenant_data() -> None:
    class _OldSchemaConnection(_ScriptedConnection):
        def execute(
            self,
            query: str,
            params: Sequence[object] = (),
        ) -> _Cursor:
            normalized = " ".join(query.split()).lower()
            if "control_assurance.runtime_identity()" in normalized:
                self.executed.append((normalized, tuple(params)))
                return _Cursor(
                    (
                        {
                            "session_user": _DATABASE_ROLE,
                            "current_user": _DATABASE_ROLE,
                            "current_role": _DATABASE_ROLE,
                            "login_role": _DATABASE_ROLE,
                            "tenant_id": "acme-bank",
                            "role_kind": "control",
                            "schema_versions": [1, 2, 3, 4, 5],
                        },
                    )
                )
            return super().execute(query, params)

    connection = _OldSchemaConnection(())
    store = _store(_Pool(connection))
    with pytest.raises(ControlPlaneStoreError, match="binding is missing"):
        store.audit_events(tenant_id="acme-bank")
    assert connection.rollbacks == 1
    assert not any(
        "control_audit_events" in query for query, _ in connection.executed
    )


def test_cross_tenant_call_is_rejected_before_pool_lease() -> None:
    connection = _ScriptedConnection(())
    pool = _Pool(connection)
    store = _store(pool)

    with pytest.raises(
        ControlPlaneStoreError,
        match="differs from the deployment",
    ):
        store.audit_events(tenant_id="other-bank")

    assert pool.leases == 0
    assert connection.executed == []


def test_list_controls_verifies_optional_active_pointer() -> None:
    configuration = _configuration()
    row = _revision_row(
        configuration,
        state="approved",
        state_version=2,
        submitted_at=_NOW,
        decided_at=_NOW,
    )
    active = ActiveDeployment(
        tenant_id=configuration.tenant_id,
        control_id=configuration.control_id,
        revision_id=row["revision_id"],
        configuration_digest=configuration.digest,
        activated_by="oidc:carol",
        activated_at=_NOW,
        deployment_version=3,
    )
    joined = {
        **row,
        "active_revision_id": active.revision_id,
        "active_configuration_digest": active.configuration_digest,
        "active_activated_by": active.activated_by,
        "active_activated_at": active.activated_at,
        "active_deployment_version": active.deployment_version,
        "active_revision_tenant_id": active.tenant_id,
        "active_revision_control_id": active.control_id,
        "active_revision_configuration_digest": active.configuration_digest,
        "active_revision_state": "approved",
    }
    connection = _ScriptedConnection((("with latest as", _Cursor((joined,))),))
    store = _store(_Pool(connection))

    summaries = store.list_controls(tenant_id="acme-bank")

    assert len(summaries) == 1
    assert summaries[0].latest_revision.revision_id == active.revision_id
    assert summaries[0].active_deployment == active
    assert any(
        "set transaction isolation level repeatable read" in query
        for query, _ in connection.executed
    )

    joined["active_revision_state"] = "retired"
    second = _ScriptedConnection((("with latest as", _Cursor((joined,))),))
    with pytest.raises(ControlPlaneIntegrityError, match="approved revision"):
        _store(_Pool(second)).list_controls(
            tenant_id="acme-bank"
        )


def test_activation_appends_outbox_before_audit_in_the_same_transaction() -> None:
    configuration = _configuration()
    approved = _revision_row(
        configuration,
        state="approved",
        state_version=2,
        submitted_at=_NOW,
        decided_at=_NOW,
    )
    connection = _ScriptedConnection(
        (
            ("from control_assurance.control_revisions", _Cursor((approved,))),
            ("from control_assurance.control_revisions", _Cursor((approved,))),
            ("from control_assurance.active_deployments", _Cursor()),
            ("insert into control_assurance.active_deployments", _Cursor(rowcount=1)),
            ("from control_assurance.deployment_operations", _Cursor()),
            ("from control_assurance.deployment_operations", _Cursor()),
            (
                "select coalesce(max(operation_sequence)",
                _Cursor(({"current_sequence": 0},)),
            ),
            (
                "insert into control_assurance.deployment_operations",
                _Cursor(rowcount=1),
            ),
            ("from control_assurance.control_audit_events", _Cursor()),
            ("insert into control_assurance.control_audit_events", _Cursor(rowcount=1)),
        )
    )
    store = _store(_Pool(connection))
    deployment, operation = store.activate_with_operation(
        actor=_actor("oidc:deployer"),
        revision_id=approved["revision_id"],
        expected_deployment_version=None,
        activated_at=_NOW,
    )

    assert deployment.revision_id == approved["revision_id"]
    assert operation.revision_id == deployment.revision_id
    assert operation.state == "pending"
    assert operation.retry_of_operation_id is None
    statements = [query for query, _ in connection.executed]
    operation_insert = next(
        index
        for index, query in enumerate(statements)
        if "insert into control_assurance.deployment_operations" in query
    )
    audit_insert = next(
        index
        for index, query in enumerate(statements)
        if "insert into control_assurance.control_audit_events" in query
    )
    assert operation_insert < audit_insert
    assert connection.commits == 1
    assert connection.rollbacks == 0
    assert not connection.script


def test_schema_contains_database_enforced_immutability_rls_and_cas() -> None:
    schema = (
        Path(__file__).parents[1]
        / "deploy"
        / "postgres"
        / "control-plane-schema.sql"
    ).read_text(encoding="utf-8")

    for required in (
        "control_revisions_one_in_flight",
        "guard_revision_lineage",
        "guard_revision_update",
        "guard_decision_insert",
        "guard_active_deployment",
        "guard_deployment_operation_insert",
        "guard_deployment_operation_update",
        "guard_audit_append",
        "deployment_operations_one_unresolved",
        "deployment_operations_no_delete",
        "retry_of_operation_id",
        "immutable deployment retry lineage",
        "schema_migrations_no_rewrite",
        "BEFORE UPDATE OR DELETE OR TRUNCATE ON control_assurance.approval_decisions",
        "BEFORE UPDATE OR DELETE OR TRUNCATE ON control_assurance.control_audit_events",
        "ENABLE ROW LEVEL SECURITY",
        "FORCE ROW LEVEL SECURITY",
        "control_assurance.session_tenant()",
        "control_assurance_boundary.runtime_role_bindings",
        "session_user",
        "schema_migrations",
        "durable fenced deployment outbox",
    ):
        assert required in schema
