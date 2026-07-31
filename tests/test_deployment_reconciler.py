from __future__ import annotations

import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from assurance_lab.control_plane import (
    Actor,
    ConfigurationRevision,
    ControlConfiguration,
    ControlPlaneConflict,
    ControlPlaneNotFound,
    ControlPlaneService,
    DeploymentApplyRequest,
    DeploymentOperation,
    DeploymentOutcomeUnknown,
    DeploymentReconciler,
    DeploymentTargetAcknowledgement,
    DeploymentWorkerIdentity,
    ElasticSourceConfiguration,
    EvidenceConfiguration,
    ScheduleConfiguration,
    SQLiteControlPlaneStore,
)
from assurance_lab.control_plane.models import Role
from assurance_lab.evidence.canonical import canonical_json_bytes

_NOW = datetime(2026, 7, 29, 9, 0, tzinfo=UTC)
_SESSION = f"sha256:{'1' * 64}"
_PROFILE = f"sha256:{'2' * 64}"
_RECEIPT = f"sha256:{'3' * 64}"


def _actor(subject: str, *roles: Role) -> Actor:
    return Actor(
        tenant_id="acme-bank",
        subject=subject,
        display_name=subject,
        roles=frozenset(roles),
        groups=("secops/platform",),
        authenticated_at=_NOW,
        session_id_digest=_SESSION,
        mfa=True,
    )


def _configuration(
    *,
    display_name: str = "Elastic alert completeness",
) -> ControlConfiguration:
    return ControlConfiguration(
        tenant_id="acme-bank",
        control_id="elastic-alert-completeness",
        display_name=display_name,
        description="Reconciles one exact read-only alert collection configuration.",
        environment="production",
        owner_group="secops/platform",
        control_profile_id="alert-window-v1",
        control_profile_digest=_PROFILE,
        source=ElasticSourceConfiguration(
            endpoint_origin="https://elastic.acme.example",
            parent_credential_ref="vault://kv/secops/elastic-parent",
        ),
        schedule=ScheduleConfiguration(
            interval_seconds=900,
            collection_lag_seconds=120,
            window_seconds=900,
        ),
        evidence=EvidenceConfiguration(
            custody_ref="s3-object-lock://evidence/acme-bank/elastic",
            signing_key_ref="vault-transit://assurance/elastic",
            retention_days=365,
        ),
    )


def _approved(
    service: ControlPlaneService,
    configuration: ControlConfiguration,
    *,
    parent: str | None,
) -> ConfigurationRevision:
    editor = _actor("oidc:editor", "viewer", "editor")
    revision = service.create_revision(
        editor,
        configuration,
        expected_parent_revision_id=parent,
    )
    revision = service.submit_revision(
        editor,
        revision.revision_id,
        expected_state_version=revision.state_version,
    )
    revision, _ = service.decide_revision(
        _actor("oidc:approver", "viewer", "approver"),
        revision.revision_id,
        expected_state_version=revision.state_version,
        decision="approved",
        comment="Exact configuration and recovery path reviewed.",
    )
    return revision


def _activate(
    service: ControlPlaneService,
    revision_id: str,
    expected_version: int | None,
) -> DeploymentOperation:
    deployment, operation = service.activate_revision_with_operation(
        _actor("oidc:deployer", "viewer", "deployer"),
        revision_id,
        expected_deployment_version=expected_version,
    )
    assert deployment.revision_id == operation.revision_id
    assert deployment.configuration_digest == operation.configuration_digest
    return operation


def _worker(worker_id: str = "reconciler-a") -> DeploymentWorkerIdentity:
    return DeploymentWorkerIdentity(
        tenant_id="acme-bank",
        worker_id=worker_id,
        credential_digest=f"sha256:{'4' * 64}",
    )


class _Target:
    def __init__(self) -> None:
        self.requests: list[DeploymentApplyRequest] = []

    def ensure_applied(
        self,
        request: DeploymentApplyRequest,
    ) -> DeploymentTargetAcknowledgement:
        self.requests.append(request)
        return DeploymentTargetAcknowledgement(
            operation_id=request.operation_id,
            lease_fence=request.lease_fence,
            applied_configuration_digest=request.configuration_digest,
            target_receipt_digest=_RECEIPT,
        )


class _Clock:
    def __init__(self, value: datetime = _NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def _service(
    tmp_path: Path,
) -> tuple[ControlPlaneService, SQLiteControlPlaneStore]:
    store = SQLiteControlPlaneStore(tmp_path / "control-plane.sqlite3")
    return ControlPlaneService(store, now=lambda: _NOW), store


def test_activation_atomically_enqueues_intent_but_does_not_claim_application(
    tmp_path: Path,
) -> None:
    service, store = _service(tmp_path)
    revision = _approved(service, _configuration(), parent=None)
    operation = _activate(service, revision.revision_id, None)

    assert operation.state == "pending"
    assert operation.kind == "apply"
    assert operation.retry_of_operation_id is None
    with pytest.raises(ControlPlaneNotFound, match="applied"):
        service.applied_deployment_operation(
            _actor("oidc:viewer", "viewer"),
            operation.control_id,
        )
    desired = service.active_deployment(
        _actor("oidc:viewer", "viewer"),
        operation.control_id,
    )
    assert desired.revision_id == operation.revision_id

    connection = sqlite3.connect(tmp_path / "control-plane.sqlite3")
    try:
        connection.execute(
            """
            CREATE TRIGGER reject_operation_insert
            BEFORE INSERT ON deployment_operations
            BEGIN
                SELECT RAISE(ABORT, 'simulated outbox failure');
            END
            """
        )
        connection.commit()
    finally:
        connection.close()
    # A second control proves desired selection and outbox append share one
    # transaction: the injected outbox failure leaves no selection pointer.
    second = _configuration(display_name="Second")
    second = second.model_copy(
        update={"control_id": "second-control", "display_name": "Second control"}
    )
    second_revision = _approved(service, second, parent=None)
    with pytest.raises(ControlPlaneConflict, match="activation"):
        service.activate_revision(
            _actor("oidc:deployer", "viewer", "deployer"),
            second_revision.revision_id,
            expected_deployment_version=None,
        )
    with pytest.raises(ControlPlaneNotFound):
        store.get_active_deployment(
            tenant_id="acme-bank",
            control_id="second-control",
        )


def test_sqlite_v2_outbox_migrates_without_changing_existing_operation_identity(
    tmp_path: Path,
) -> None:
    service, _store = _service(tmp_path)
    revision = _approved(service, _configuration(), parent=None)
    operation = _activate(service, revision.revision_id, None)
    database = tmp_path / "control-plane.sqlite3"

    connection = sqlite3.connect(database)
    try:
        schema_row = connection.execute(
            """
            SELECT sql
            FROM sqlite_master
            WHERE type = 'table' AND name = 'deployment_operations'
            """
        ).fetchone()
        assert schema_row is not None
        old_schema = str(schema_row[0]).replace(
            "                        retry_of_operation_id TEXT,\n",
            "",
        ).replace(
            """                        FOREIGN KEY (retry_of_operation_id)
                            REFERENCES deployment_operations(operation_id),
""",
            "",
        )
        columns = tuple(
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(deployment_operations)"
            )
            if row[1] != "retry_of_operation_id"
        )
        column_list = ", ".join(columns)
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "ALTER TABLE deployment_operations RENAME TO deployment_operations_v3"
        )
        connection.execute(old_schema)
        connection.execute(
            f"""
            INSERT INTO deployment_operations ({column_list})
            SELECT {column_list}
            FROM deployment_operations_v3
            """
        )
        connection.execute("DROP TABLE deployment_operations_v3")
        connection.execute("PRAGMA user_version=2")
        connection.execute("COMMIT")
    finally:
        connection.close()

    migrated = SQLiteControlPlaneStore(database)
    persisted = migrated.get_deployment_operation(
        tenant_id=operation.tenant_id,
        operation_id=operation.operation_id,
    )
    assert persisted == operation
    assert persisted.retry_of_operation_id is None
    connection = sqlite3.connect(database)
    try:
        assert connection.execute("PRAGMA user_version").fetchone() == (3,)
    finally:
        connection.close()


def test_reconciler_requires_exact_target_acknowledgement(tmp_path: Path) -> None:
    service, store = _service(tmp_path)
    revision = _approved(service, _configuration(), parent=None)
    operation = _activate(service, revision.revision_id, None)
    target = _Target()
    result = DeploymentReconciler(
        store,
        target,
        _worker(),
        now=lambda: _NOW,
        token_bytes=lambda _: b"a" * 32,
    ).run_once()

    assert result is not None
    assert result.state == "applied"
    assert result.operation_id == operation.operation_id
    assert result.applied_configuration_digest == operation.configuration_digest
    assert result.target_receipt_digest == _RECEIPT
    assert target.requests[0].idempotency_key == operation.operation_id
    assert (
        service.applied_deployment_operation(
            _actor("oidc:viewer", "viewer"),
            operation.control_id,
        )
        == result
    )
    audit_actor = _actor("oidc:auditor", "auditor")
    events = service.audit_events(audit_actor)
    assert [event.action for event in events] == [
        "revision-created",
        "revision-submitted",
        "revision-approved",
        "revision-activated",
        "deployment-leased",
        "deployment-applied",
    ]
    assert service.verify_audit_chain(audit_actor) == (
        6,
        events[-1].event_digest,
    )


def test_expired_lease_is_reclaimed_with_a_higher_fence_and_stale_ack_fails(
    tmp_path: Path,
) -> None:
    service, store = _service(tmp_path)
    revision = _approved(service, _configuration(), parent=None)
    operation = _activate(service, revision.revision_id, None)
    old_token = f"sha256:{hashlib.sha256(b'old').hexdigest()}"
    new_token = f"sha256:{hashlib.sha256(b'new').hexdigest()}"
    first = store.lease_next_deployment_operation(
        worker=_worker("reconciler-a"),
        lease_token_digest=old_token,
        leased_at=_NOW,
        lease_ttl_seconds=30,
    )
    assert first is not None and first.lease_fence == 1
    reclaimed_at = _NOW + timedelta(seconds=30)
    second = store.lease_next_deployment_operation(
        worker=_worker("reconciler-b"),
        lease_token_digest=new_token,
        leased_at=reclaimed_at,
        lease_ttl_seconds=30,
    )
    assert second is not None
    assert second.operation_id == operation.operation_id
    assert second.lease_fence == 2
    assert second.attempt_count == 2

    with pytest.raises(ControlPlaneConflict, match="stale"):
        store.acknowledge_deployment_applied(
            worker=_worker("reconciler-a"),
            operation_id=operation.operation_id,
            lease_token_digest=old_token,
            lease_fence=1,
            applied_configuration_digest=operation.configuration_digest,
            target_receipt_digest=_RECEIPT,
            applied_at=reclaimed_at + timedelta(seconds=1),
        )
    applied = store.acknowledge_deployment_applied(
        worker=_worker("reconciler-b"),
        operation_id=operation.operation_id,
        lease_token_digest=new_token,
        lease_fence=2,
        applied_configuration_digest=operation.configuration_digest,
        target_receipt_digest=_RECEIPT,
        applied_at=reclaimed_at + timedelta(seconds=1),
    )
    assert applied.state == "applied"


def test_concurrent_workers_claim_exactly_one_operation(tmp_path: Path) -> None:
    service, store = _service(tmp_path)
    revision = _approved(service, _configuration(), parent=None)
    operation = _activate(service, revision.revision_id, None)

    def lease(index: int) -> DeploymentOperation | None:
        token = f"sha256:{hashlib.sha256(str(index).encode()).hexdigest()}"
        return store.lease_next_deployment_operation(
            worker=_worker(f"reconciler-{index}"),
            lease_token_digest=token,
            leased_at=_NOW,
            lease_ttl_seconds=60,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(lease, range(2)))
    claimed = tuple(item for item in outcomes if item is not None)
    assert len(claimed) == 1
    assert claimed[0].operation_id == operation.operation_id


def test_concurrent_reconcilers_begin_one_external_apply(
    tmp_path: Path,
) -> None:
    service, store = _service(tmp_path)
    revision = _approved(service, _configuration(), parent=None)
    operation = _activate(service, revision.revision_id, None)
    target = _Target()

    def reconcile(index: int) -> DeploymentOperation | None:
        return DeploymentReconciler(
            store,
            target,
            _worker(f"reconciler-{index}"),
            now=lambda: _NOW,
            token_bytes=lambda _: bytes([index + 1]) * 32,
        ).run_once()

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(reconcile, range(2)))

    assert len(target.requests) == 1
    assert target.requests[0].operation_id == operation.operation_id
    applied = tuple(
        result for result in outcomes if result is not None
    )
    assert len(applied) == 1
    assert applied[0].state == "applied"


def test_sqlite_outbox_request_and_terminal_history_are_database_guarded(
    tmp_path: Path,
) -> None:
    service, _store = _service(tmp_path)
    revision = _approved(service, _configuration(), parent=None)
    operation = _activate(service, revision.revision_id, None)
    connection = sqlite3.connect(tmp_path / "control-plane.sqlite3")
    try:
        with pytest.raises(
            sqlite3.IntegrityError,
            match=r"immutable|invalid deployment operation transition",
        ):
            connection.execute(
                """
                UPDATE deployment_operations
                SET retry_of_operation_id = ?
                WHERE operation_id = ?
                """,
                (f"sha256:{'8' * 64}", operation.operation_id),
            )
        connection.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM deployment_operations WHERE operation_id = ?",
                (operation.operation_id,),
            )
        connection.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="request invariants"):
            connection.execute(
                """
                INSERT INTO deployment_operations (
                    operation_id, tenant_id, control_id, operation_sequence,
                    kind, revision_id, configuration_digest,
                    predecessor_operation_id, requested_by, requested_at,
                    requester_session_digest, state, state_version,
                    attempt_count, lease_fence
                ) VALUES (?, ?, ?, 2, 'apply', ?, ?, NULL, ?, ?, ?,
                          'pending', 0, 0, 0)
                """,
                (
                    f"sha256:{'9' * 64}",
                    operation.tenant_id,
                    operation.control_id,
                    operation.revision_id,
                    operation.configuration_digest,
                    revision.created_by,
                    _NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    _SESSION,
                ),
            )
    finally:
        connection.close()


def test_unknown_outcome_retries_same_idempotency_key_then_applies(
    tmp_path: Path,
) -> None:
    service, store = _service(tmp_path)
    revision = _approved(service, _configuration(), parent=None)
    operation = _activate(service, revision.revision_id, None)
    clock = _Clock()

    class AmbiguousThenObserved(_Target):
        def ensure_applied(
            self,
            request: DeploymentApplyRequest,
        ) -> DeploymentTargetAcknowledgement:
            self.requests.append(request)
            if len(self.requests) == 1:
                raise DeploymentOutcomeUnknown()
            return DeploymentTargetAcknowledgement(
                operation_id=request.operation_id,
                lease_fence=request.lease_fence,
                applied_configuration_digest=request.configuration_digest,
                target_receipt_digest=_RECEIPT,
            )

    target = AmbiguousThenObserved()
    tokens = iter((b"a" * 32, b"b" * 32))
    reconciler = DeploymentReconciler(
        store,
        target,
        _worker(),
        now=clock,
        token_bytes=lambda _: next(tokens),
        base_retry_seconds=30,
    )
    failed = reconciler.run_once()
    assert failed is not None
    assert failed.state == "failed"
    assert failed.retry_at == _NOW + timedelta(seconds=30)
    clock.value = failed.retry_at
    applied = reconciler.run_once()
    assert applied is not None and applied.state == "applied"
    assert [request.operation_id for request in target.requests] == [
        operation.operation_id,
        operation.operation_id,
    ]
    assert [request.lease_fence for request in target.requests] == [1, 2]


def test_rollback_is_a_new_operation_with_applied_lineage(tmp_path: Path) -> None:
    service, store = _service(tmp_path)
    first_revision = _approved(service, _configuration(), parent=None)
    first_operation = _activate(
        service,
        first_revision.revision_id,
        None,
    )
    first_applied = DeploymentReconciler(
        store,
        _Target(),
        _worker(),
        now=lambda: _NOW,
        token_bytes=lambda _: b"a" * 32,
    ).run_once()
    assert first_applied is not None and first_applied.state == "applied"

    second_revision = _approved(
        service,
        _configuration(display_name="Elastic alert completeness v2"),
        parent=first_revision.revision_id,
    )
    second_operation = _activate(
        service,
        second_revision.revision_id,
        1,
    )
    second_applied = DeploymentReconciler(
        store,
        _Target(),
        _worker(),
        now=lambda: _NOW,
        token_bytes=lambda _: b"b" * 32,
    ).run_once()
    assert second_applied is not None and second_applied.state == "applied"

    rollback = service.request_rollback(
        _actor("oidc:deployer", "viewer", "deployer"),
        first_revision.revision_id,
        expected_predecessor_operation_id=second_operation.operation_id,
    )
    assert rollback.kind == "rollback"
    assert rollback.operation_sequence == 3
    assert rollback.predecessor_operation_id == second_operation.operation_id
    assert rollback.retry_of_operation_id is None
    assert rollback.revision_id == first_operation.revision_id
    assert store.get_deployment_operation(
        tenant_id="acme-bank",
        operation_id=first_operation.operation_id,
    ).state == "applied"


def test_failure_digest_is_canonical_and_exception_text_is_not_persisted(
    tmp_path: Path,
) -> None:
    service, store = _service(tmp_path)
    revision = _approved(service, _configuration(), parent=None)
    operation = _activate(service, revision.revision_id, None)

    class LeakyTarget:
        def ensure_applied(
            self,
            request: DeploymentApplyRequest,
        ) -> DeploymentTargetAcknowledgement:
            raise RuntimeError("Authorization: Bearer must-not-enter-state")

    failed = DeploymentReconciler(
        store,
        LeakyTarget(),
        _worker(),
        now=lambda: _NOW,
        token_bytes=lambda _: b"a" * 32,
        max_attempts=1,
    ).run_once()
    assert failed is not None and failed.state == "failed"
    expected = canonical_json_bytes(
        {
            "attempt_count": 1,
            "code": "adapter-unhandled",
            "lease_fence": 1,
            "operation_id": operation.operation_id,
            "retryable": False,
        }
    )
    assert failed.failure_digest == (
        f"sha256:{hashlib.sha256(expected).hexdigest()}"
    )
    retry = service.retry_deployment(
        _actor("oidc:deployer", "viewer", "deployer"),
        failed.operation_id,
    )
    assert retry.operation_id != failed.operation_id
    assert retry.operation_sequence == 2
    assert retry.state == "pending"
    assert retry.retry_of_operation_id == failed.operation_id
    assert (
        store.get_deployment_operation(
            tenant_id="acme-bank",
            operation_id=retry.operation_id,
        ).retry_of_operation_id
        == failed.operation_id
    )
    assert store.get_deployment_operation(
        tenant_id="acme-bank",
        operation_id=failed.operation_id,
    ).state == "failed"
    database_bytes = (tmp_path / "control-plane.sqlite3").read_bytes()
    assert b"must-not-enter-state" not in database_bytes
