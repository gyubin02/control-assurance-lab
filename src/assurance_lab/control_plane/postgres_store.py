"""HA-safe PostgreSQL repository for immutable control-plane state.

The database schema is installed separately from
``deploy/postgres/control-plane-schema.sql``.  Every write transaction takes
the tenant audit-head advisory lock before the tenant/control advisory lock.
That order is deliberate: it gives each tenant one canonical audit order while
still making revision generation and deployment-pointer changes safe across
multiple application instances.

The module has no mandatory psycopg import.  Production callers can use
``from_dsn`` when the ``control-plane`` extra is installed; tests and embedding
applications may inject any pool implementing :class:`ConnectionPool`.
"""

from __future__ import annotations

import hashlib
import importlib
from collections.abc import Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Protocol, cast

from assurance_lab.control_plane.models import (
    ActiveDeployment,
    Actor,
    ApprovalDecision,
    AuditAction,
    AuditEvent,
    ConfigurationRevision,
    ControlConfiguration,
    ControlSummary,
    DeploymentOperation,
    DeploymentOperationKind,
    DeploymentWorkerIdentity,
    RevisionState,
    audit_event_bytes,
    decision_identity,
    deployment_operation_identity,
    revision_identity,
)
from assurance_lab.control_plane.postgres_security import (
    RuntimeBoundaryExpectation,
    RuntimeRoleKind,
    identity_matches,
    runtime_identity_row,
)
from assurance_lab.control_plane.store import (
    ControlPlaneConflict,
    ControlPlaneIntegrityError,
    ControlPlaneNotFound,
    ControlPlaneStoreError,
)
from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)

_GENESIS_DIGEST: Final = f"sha256:{'0' * 64}"
_DEFAULT_STATEMENT_TIMEOUT_MS: Final = 15_000
_DEFAULT_LOCK_TIMEOUT_MS: Final = 5_000
_DETAIL_LIMITS = JSONLimits(
    max_bytes=64 * 1024,
    max_line_bytes=64 * 1024,
    max_depth=16,
    max_collection_items=1_024,
    max_string_length=8_192,
)
_CONFLICT_SQLSTATES = frozenset(
    {
        "23503",  # foreign_key_violation
        "23505",  # unique_violation
        "40001",  # serialization_failure
        "40P01",  # deadlock_detected
        "55P03",  # lock_not_available
    }
)


class Cursor(Protocol):
    """Small DB-API surface used by the store."""

    rowcount: int

    def fetchone(self) -> Mapping[str, Any] | None: ...

    def fetchall(self) -> Sequence[Mapping[str, Any]]: ...


class Connection(Protocol):
    """Psycopg-compatible connection surface used by the store."""

    def execute(
        self,
        query: str,
        params: Sequence[object] = (),
    ) -> Cursor: ...

    def transaction(self) -> AbstractContextManager[object]: ...


class ConnectionPool(Protocol):
    """Injectable pool surface; psycopg_pool.ConnectionPool satisfies it."""

    def connection(self) -> AbstractContextManager[Connection]: ...


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _utc_second(value: datetime, *, label: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
    converted = value.astimezone(UTC)
    if converted.microsecond:
        raise ValueError(f"{label} must use whole UTC seconds")
    return converted


def _require_digest(value: str, *, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise ValueError(f"{label} must be a canonical SHA-256 digest")
    return value


def _stored_time(value: object) -> datetime:
    if isinstance(value, datetime):
        return _utc_second(value, label="stored timestamp")
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ControlPlaneIntegrityError("stored timestamp is invalid") from exc
        return _utc_second(parsed, label="stored timestamp")
    raise ControlPlaneIntegrityError("stored timestamp is invalid")


def _stored_bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray | memoryview):
        return bytes(value)
    raise ControlPlaneIntegrityError("stored binary value is invalid")


def _sqlstate(exc: BaseException) -> str | None:
    value = getattr(exc, "sqlstate", None)
    return value if isinstance(value, str) else None


class PostgresControlPlaneStore:
    """PostgreSQL implementation of the control-plane repository protocol."""

    __slots__ = (
        "_expectation",
        "_lock_timeout_ms",
        "_owns_pool",
        "_pool",
        "_statement_timeout_ms",
    )

    def __init__(
        self,
        pool: ConnectionPool,
        *,
        tenant_id: str,
        expected_role: str,
        role_kind: RuntimeRoleKind = "control",
        statement_timeout_ms: int = _DEFAULT_STATEMENT_TIMEOUT_MS,
        lock_timeout_ms: int = _DEFAULT_LOCK_TIMEOUT_MS,
        owns_pool: bool = False,
    ) -> None:
        if not callable(getattr(pool, "connection", None)):
            raise TypeError("PostgreSQL pool must provide connection()")
        if role_kind not in {"control", "reconciler"}:
            raise ValueError("control-plane store role kind is invalid")
        self._expectation = RuntimeBoundaryExpectation(
            tenant_id=tenant_id,
            login_role=expected_role,
            role_kind=role_kind,
        )
        for label, value in (
            ("statement timeout", statement_timeout_ms),
            ("lock timeout", lock_timeout_ms),
        ):
            if type(value) is not int or value < 100 or value > 120_000:
                raise ValueError(f"{label} is outside the supported range")
        if lock_timeout_ms > statement_timeout_ms:
            raise ValueError("lock timeout cannot exceed statement timeout")
        self._pool = pool
        self._statement_timeout_ms = statement_timeout_ms
        self._lock_timeout_ms = lock_timeout_ms
        self._owns_pool = owns_pool

    @classmethod
    def from_dsn(
        cls,
        dsn: str,
        *,
        tenant_id: str,
        expected_role: str,
        role_kind: RuntimeRoleKind = "control",
        min_size: int = 2,
        max_size: int = 16,
        connect_timeout_seconds: int = 10,
        statement_timeout_ms: int = _DEFAULT_STATEMENT_TIMEOUT_MS,
        lock_timeout_ms: int = _DEFAULT_LOCK_TIMEOUT_MS,
    ) -> PostgresControlPlaneStore:
        """Build an owned psycopg3 pool without importing psycopg at module load."""

        if type(dsn) is not str or not dsn:
            raise ValueError("PostgreSQL DSN is required")
        if (
            type(min_size) is not int
            or type(max_size) is not int
            or min_size < 1
            or max_size < min_size
            or max_size > 256
        ):
            raise ValueError("PostgreSQL pool size is invalid")
        if (
            type(connect_timeout_seconds) is not int
            or connect_timeout_seconds < 1
            or connect_timeout_seconds > 60
        ):
            raise ValueError("PostgreSQL connect timeout is invalid")
        try:
            pool_module = importlib.import_module("psycopg_pool")
            rows_module = importlib.import_module("psycopg.rows")
        except ImportError as exc:
            raise ControlPlaneStoreError(
                "PostgreSQL support requires the 'control-plane' optional dependency"
            ) from exc
        pool_type = pool_module.ConnectionPool
        row_factory = rows_module.dict_row
        pool = pool_type(
            conninfo=dsn,
            min_size=min_size,
            max_size=max_size,
            timeout=float(connect_timeout_seconds),
            kwargs={
                "autocommit": True,
                "connect_timeout": connect_timeout_seconds,
                "row_factory": row_factory,
            },
            open=True,
        )
        return cls(
            cast(ConnectionPool, pool),
            tenant_id=tenant_id,
            expected_role=expected_role,
            role_kind=role_kind,
            statement_timeout_ms=statement_timeout_ms,
            lock_timeout_ms=lock_timeout_ms,
            owns_pool=True,
        )

    def close(self) -> None:
        """Close a pool created by :meth:`from_dsn`; injected pools stay owned by callers."""

        if self._owns_pool:
            close = getattr(self._pool, "close", None)
            if callable(close):
                close()

    @contextmanager
    def _transaction(
        self,
        *,
        tenant_id: str,
        isolation: str = "READ COMMITTED",
    ) -> Iterator[Connection]:
        if isolation not in {"READ COMMITTED", "REPEATABLE READ"}:
            raise ValueError("unsupported PostgreSQL isolation level")
        if tenant_id != self._expectation.tenant_id:
            raise ControlPlaneStoreError(
                "tenant differs from the deployment database binding"
            )
        try:
            with self._pool.connection() as connection, connection.transaction():
                connection.execute(f"SET TRANSACTION ISOLATION LEVEL {isolation}")
                connection.execute(
                    "SELECT set_config('statement_timeout', %s, true)",
                    (f"{self._statement_timeout_ms}ms",),
                )
                connection.execute(
                    "SELECT set_config('lock_timeout', %s, true)",
                    (f"{self._lock_timeout_ms}ms",),
                )
                if not identity_matches(
                    runtime_identity_row(connection, self._expectation),
                    self._expectation,
                ):
                    raise ControlPlaneStoreError(
                        "PostgreSQL runtime role binding is missing or unsupported"
                    )
                yield connection
        except (
            ControlPlaneConflict,
            ControlPlaneIntegrityError,
            ControlPlaneNotFound,
            ControlPlaneStoreError,
            TypeError,
            ValueError,
        ):
            raise
        except Exception as exc:
            state = _sqlstate(exc)
            if state in _CONFLICT_SQLSTATES:
                raise ControlPlaneConflict(
                    "PostgreSQL control-plane state changed concurrently"
                ) from exc
            if state == "57014":
                raise ControlPlaneStoreError(
                    "PostgreSQL control-plane operation exceeded its deadline"
                ) from exc
            raise ControlPlaneStoreError("PostgreSQL control-plane operation failed") from exc

    @staticmethod
    def _lock_audit_head(connection: Connection, tenant_id: str) -> None:
        connection.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (f"control-assurance:audit:{tenant_id}",),
        )

    @staticmethod
    def _lock_control(connection: Connection, tenant_id: str, control_id: str) -> None:
        connection.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (f"control-assurance:control:{tenant_id}:{control_id}",),
        )

    @staticmethod
    def _revision(row: Mapping[str, Any]) -> ConfigurationRevision:
        try:
            return ConfigurationRevision(
                revision_id=cast(str, row["revision_id"]),
                tenant_id=cast(str, row["tenant_id"]),
                control_id=cast(str, row["control_id"]),
                generation=cast(int, row["generation"]),
                parent_revision_id=cast(str | None, row["parent_revision_id"]),
                configuration_digest=cast(str, row["configuration_digest"]),
                configuration_bytes=_stored_bytes(row["configuration_bytes"]),
                state=cast(RevisionState, row["state"]),
                state_version=cast(int, row["state_version"]),
                created_by=cast(str, row["created_by"]),
                created_at=_stored_time(row["created_at"]),
                submitted_at=(
                    None
                    if row["submitted_at"] is None
                    else _stored_time(row["submitted_at"])
                ),
                decided_at=(
                    None if row["decided_at"] is None else _stored_time(row["decided_at"])
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ControlPlaneIntegrityError("stored revision failed validation") from exc

    @staticmethod
    def _deployment(row: Mapping[str, Any]) -> ActiveDeployment:
        try:
            return ActiveDeployment(
                tenant_id=cast(str, row["tenant_id"]),
                control_id=cast(str, row["control_id"]),
                revision_id=cast(str, row["revision_id"]),
                configuration_digest=cast(str, row["configuration_digest"]),
                activated_by=cast(str, row["activated_by"]),
                activated_at=_stored_time(row["activated_at"]),
                deployment_version=cast(int, row["deployment_version"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ControlPlaneIntegrityError("stored deployment failed validation") from exc

    @staticmethod
    def _operation(row: Mapping[str, Any]) -> DeploymentOperation:
        def optional_time(name: str) -> datetime | None:
            value = row[name]
            return None if value is None else _stored_time(value)

        try:
            return DeploymentOperation(
                operation_id=cast(str, row["operation_id"]),
                tenant_id=cast(str, row["tenant_id"]),
                control_id=cast(str, row["control_id"]),
                operation_sequence=cast(int, row["operation_sequence"]),
                kind=cast(DeploymentOperationKind, row["kind"]),
                revision_id=cast(str, row["revision_id"]),
                configuration_digest=cast(str, row["configuration_digest"]),
                predecessor_operation_id=cast(
                    str | None, row["predecessor_operation_id"]
                ),
                retry_of_operation_id=cast(
                    str | None, row["retry_of_operation_id"]
                ),
                requested_by=cast(str, row["requested_by"]),
                requested_at=_stored_time(row["requested_at"]),
                requester_session_digest=cast(
                    str, row["requester_session_digest"]
                ),
                state=cast(Any, row["state"]),
                state_version=cast(int, row["state_version"]),
                attempt_count=cast(int, row["attempt_count"]),
                lease_fence=cast(int, row["lease_fence"]),
                lease_owner=cast(str | None, row["lease_owner"]),
                lease_token_digest=cast(str | None, row["lease_token_digest"]),
                leased_at=optional_time("leased_at"),
                lease_expires_at=optional_time("lease_expires_at"),
                retry_at=optional_time("retry_at"),
                applied_at=optional_time("applied_at"),
                applied_configuration_digest=cast(
                    str | None, row["applied_configuration_digest"]
                ),
                target_receipt_digest=cast(
                    str | None, row["target_receipt_digest"]
                ),
                failed_at=optional_time("failed_at"),
                failure_digest=cast(str | None, row["failure_digest"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ControlPlaneIntegrityError(
                "stored deployment operation failed validation"
            ) from exc

    @staticmethod
    def _audit(row: Mapping[str, Any]) -> AuditEvent:
        try:
            return AuditEvent(
                tenant_id=cast(str, row["tenant_id"]),
                sequence=cast(int, row["sequence"]),
                previous_event_digest=cast(str, row["previous_event_digest"]),
                event_digest=cast(str, row["event_digest"]),
                action=cast(AuditAction, row["action"]),
                object_id=cast(str, row["object_id"]),
                actor_subject=cast(str, row["actor_subject"]),
                actor_session_digest=cast(str, row["actor_session_digest"]),
                occurred_at=_stored_time(row["occurred_at"]),
                details_digest=cast(str, row["details_digest"]),
                details_bytes=_stored_bytes(row["details_bytes"]),
                event_bytes=_stored_bytes(row["event_bytes"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ControlPlaneIntegrityError("stored audit event failed validation") from exc

    def _append_audit(
        self,
        connection: Connection,
        *,
        actor: Actor | DeploymentWorkerIdentity,
        action: AuditAction,
        object_id: str,
        occurred_at: datetime,
        details: dict[str, Any],
    ) -> AuditEvent:
        try:
            details_bytes = canonical_json_bytes(details, limits=_DETAIL_LIMITS)
        except StrictJSONError as exc:
            raise ControlPlaneStoreError(
                "audit details exceed their canonical profile"
            ) from exc
        last = connection.execute(
            """
            SELECT sequence, event_digest
            FROM control_assurance.control_audit_events
            WHERE tenant_id = %s
            ORDER BY sequence DESC
            LIMIT 1
            """,
            (actor.tenant_id,),
        ).fetchone()
        sequence = 1 if last is None else cast(int, last["sequence"]) + 1
        previous = (
            _GENESIS_DIGEST if last is None else cast(str, last["event_digest"])
        )
        details_digest = _sha256(details_bytes)
        event_bytes = audit_event_bytes(
            tenant_id=actor.tenant_id,
            sequence=sequence,
            previous_event_digest=previous,
            action=action,
            object_id=object_id,
            actor_subject=actor.subject,
            actor_session_digest=actor.session_id_digest,
            occurred_at=occurred_at,
            details_digest=details_digest,
        )
        event = AuditEvent(
            tenant_id=actor.tenant_id,
            sequence=sequence,
            previous_event_digest=previous,
            event_digest=_sha256(event_bytes),
            action=action,
            object_id=object_id,
            actor_subject=actor.subject,
            actor_session_digest=actor.session_id_digest,
            occurred_at=occurred_at,
            details_digest=details_digest,
            details_bytes=details_bytes,
            event_bytes=event_bytes,
        )
        connection.execute(
            """
            INSERT INTO control_assurance.control_audit_events (
                tenant_id, sequence, previous_event_digest, event_digest, action,
                object_id, actor_subject, actor_session_digest, occurred_at,
                details_digest, details_bytes, event_bytes
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                event.tenant_id,
                event.sequence,
                event.previous_event_digest,
                event.event_digest,
                event.action,
                event.object_id,
                event.actor_subject,
                event.actor_session_digest,
                event.occurred_at,
                event.details_digest,
                event.details_bytes,
                event.event_bytes,
            ),
        )
        return event

    def create_draft(
        self,
        *,
        actor: Actor,
        configuration: ControlConfiguration,
        expected_parent_revision_id: str | None,
        created_at: datetime,
    ) -> ConfigurationRevision:
        if configuration.tenant_id != actor.tenant_id:
            raise ControlPlaneConflict("configuration belongs to another tenant")
        created_at = _utc_second(created_at, label="revision creation time")
        configuration_bytes = configuration.canonical_bytes()
        revision_id = ""
        with self._transaction(tenant_id=actor.tenant_id) as connection:
            self._lock_audit_head(connection, actor.tenant_id)
            self._lock_control(
                connection,
                configuration.tenant_id,
                configuration.control_id,
            )
            latest_row = connection.execute(
                """
                SELECT *
                FROM control_assurance.control_revisions
                WHERE tenant_id = %s AND control_id = %s
                ORDER BY generation DESC
                LIMIT 1
                FOR UPDATE
                """,
                (configuration.tenant_id, configuration.control_id),
            ).fetchone()
            if latest_row is None:
                if expected_parent_revision_id is not None:
                    raise ControlPlaneConflict("first revision cannot declare a parent")
                generation = 1
                parent_revision_id = None
            else:
                latest = self._revision(latest_row)
                if latest.state in {"draft", "submitted"}:
                    raise ControlPlaneConflict("another revision is still in flight")
                if expected_parent_revision_id != latest.revision_id:
                    raise ControlPlaneConflict(
                        "new revision is not based on the latest generation"
                    )
                generation = latest.generation + 1
                parent_revision_id = latest.revision_id
            revision_id = revision_identity(
                tenant_id=configuration.tenant_id,
                control_id=configuration.control_id,
                generation=generation,
                parent_revision_id=parent_revision_id,
                configuration_digest=configuration.digest,
            )
            connection.execute(
                """
                INSERT INTO control_assurance.control_revisions (
                    revision_id, tenant_id, control_id, generation,
                    parent_revision_id, configuration_digest, configuration_bytes,
                    state, state_version, created_by, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, 'draft', 0, %s, %s)
                """,
                (
                    revision_id,
                    configuration.tenant_id,
                    configuration.control_id,
                    generation,
                    parent_revision_id,
                    configuration.digest,
                    configuration_bytes,
                    actor.subject,
                    created_at,
                ),
            )
            self._append_audit(
                connection,
                actor=actor,
                action="revision-created",
                object_id=revision_id,
                occurred_at=created_at,
                details={
                    "configuration_digest": configuration.digest,
                    "control_id": configuration.control_id,
                    "generation": generation,
                    "parent_revision_id": parent_revision_id,
                },
            )
        return self.get_revision(
            tenant_id=configuration.tenant_id,
            revision_id=revision_id,
        )

    def get_revision(
        self,
        *,
        tenant_id: str,
        revision_id: str,
    ) -> ConfigurationRevision:
        with self._transaction(tenant_id=tenant_id) as connection:
            row = connection.execute(
                """
                SELECT *
                FROM control_assurance.control_revisions
                WHERE tenant_id = %s AND revision_id = %s
                """,
                (tenant_id, revision_id),
            ).fetchone()
        if row is None:
            raise ControlPlaneNotFound("configuration revision was not found")
        return self._revision(row)

    def list_revisions(
        self,
        *,
        tenant_id: str,
        control_id: str,
        limit: int = 100,
    ) -> tuple[ConfigurationRevision, ...]:
        if type(limit) is not int or limit < 1 or limit > 1_000:
            raise ValueError("revision list limit is outside the supported range")
        with self._transaction(tenant_id=tenant_id) as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM control_assurance.control_revisions
                WHERE tenant_id = %s AND control_id = %s
                ORDER BY generation DESC
                LIMIT %s
                """,
                (tenant_id, control_id, limit),
            ).fetchall()
        return tuple(self._revision(row) for row in rows)

    def list_controls(
        self,
        *,
        tenant_id: str,
        limit: int = 100,
    ) -> tuple[ControlSummary, ...]:
        """List one latest generation per control with a verified active pointer."""

        if type(limit) is not int or limit < 1 or limit > 1_000:
            raise ValueError("control list limit is outside the supported range")
        with self._transaction(
            tenant_id=tenant_id,
            isolation="REPEATABLE READ",
        ) as connection:
            rows = connection.execute(
                """
                WITH latest AS (
                    SELECT DISTINCT ON (tenant_id, control_id) *
                    FROM control_assurance.control_revisions
                    WHERE tenant_id = %s
                    ORDER BY tenant_id, control_id, generation DESC
                )
                SELECT
                    latest.*,
                    deployment.revision_id AS active_revision_id,
                    deployment.configuration_digest AS active_configuration_digest,
                    deployment.activated_by AS active_activated_by,
                    deployment.activated_at AS active_activated_at,
                    deployment.deployment_version AS active_deployment_version,
                    active_revision.tenant_id AS active_revision_tenant_id,
                    active_revision.control_id AS active_revision_control_id,
                    active_revision.configuration_digest
                        AS active_revision_configuration_digest,
                    active_revision.state AS active_revision_state
                FROM latest
                LEFT JOIN control_assurance.active_deployments AS deployment
                  ON deployment.tenant_id = latest.tenant_id
                 AND deployment.control_id = latest.control_id
                LEFT JOIN control_assurance.control_revisions AS active_revision
                  ON active_revision.revision_id = deployment.revision_id
                ORDER BY latest.control_id
                LIMIT %s
                """,
                (tenant_id, limit),
            ).fetchall()
        summaries: list[ControlSummary] = []
        for row in rows:
            latest = self._revision(row)
            if row["active_revision_id"] is None:
                deployment = None
            else:
                deployment = self._deployment(
                    {
                        "tenant_id": latest.tenant_id,
                        "control_id": latest.control_id,
                        "revision_id": row["active_revision_id"],
                        "configuration_digest": row["active_configuration_digest"],
                        "activated_by": row["active_activated_by"],
                        "activated_at": row["active_activated_at"],
                        "deployment_version": row["active_deployment_version"],
                    }
                )
                if (
                    row["active_revision_tenant_id"] != deployment.tenant_id
                    or row["active_revision_control_id"] != deployment.control_id
                    or row["active_revision_configuration_digest"]
                    != deployment.configuration_digest
                    or row["active_revision_state"] != "approved"
                ):
                    raise ControlPlaneIntegrityError(
                        "active deployment pointer differs from its approved revision"
                    )
            summaries.append(
                ControlSummary(
                    latest_revision=latest,
                    active_deployment=deployment,
                )
            )
        return tuple(summaries)

    def _locked_revision(
        self,
        connection: Connection,
        *,
        tenant_id: str,
        revision_id: str,
    ) -> ConfigurationRevision:
        initial = connection.execute(
            """
            SELECT *
            FROM control_assurance.control_revisions
            WHERE tenant_id = %s AND revision_id = %s
            """,
            (tenant_id, revision_id),
        ).fetchone()
        if initial is None:
            raise ControlPlaneNotFound("configuration revision was not found")
        initial_revision = self._revision(initial)
        self._lock_control(
            connection,
            initial_revision.tenant_id,
            initial_revision.control_id,
        )
        row = connection.execute(
            """
            SELECT *
            FROM control_assurance.control_revisions
            WHERE tenant_id = %s AND revision_id = %s
            FOR UPDATE
            """,
            (tenant_id, revision_id),
        ).fetchone()
        if row is None:
            raise ControlPlaneNotFound("configuration revision was not found")
        return self._revision(row)

    def submit(
        self,
        *,
        actor: Actor,
        revision_id: str,
        expected_state_version: int,
        submitted_at: datetime,
    ) -> ConfigurationRevision:
        submitted_at = _utc_second(submitted_at, label="revision submission time")
        with self._transaction(tenant_id=actor.tenant_id) as connection:
            self._lock_audit_head(connection, actor.tenant_id)
            current = self._locked_revision(
                connection,
                tenant_id=actor.tenant_id,
                revision_id=revision_id,
            )
            if current.state != "draft" or current.state_version != expected_state_version:
                raise ControlPlaneConflict("revision state changed concurrently")
            cursor = connection.execute(
                """
                UPDATE control_assurance.control_revisions
                SET state = 'submitted', state_version = state_version + 1,
                    submitted_at = %s
                WHERE tenant_id = %s AND revision_id = %s
                  AND state = 'draft' AND state_version = %s
                """,
                (
                    submitted_at,
                    actor.tenant_id,
                    revision_id,
                    expected_state_version,
                ),
            )
            if cursor.rowcount != 1:
                raise ControlPlaneConflict("revision state changed concurrently")
            self._append_audit(
                connection,
                actor=actor,
                action="revision-submitted",
                object_id=revision_id,
                occurred_at=submitted_at,
                details={
                    "control_id": current.control_id,
                    "from_state": "draft",
                    "generation": current.generation,
                    "to_state": "submitted",
                },
            )
        return self.get_revision(tenant_id=actor.tenant_id, revision_id=revision_id)

    def decide(
        self,
        *,
        actor: Actor,
        revision_id: str,
        expected_state_version: int,
        decision: str,
        comment: str,
        decided_at: datetime,
    ) -> tuple[ConfigurationRevision, ApprovalDecision]:
        if decision not in {"approved", "rejected"}:
            raise ValueError("decision must be approved or rejected")
        if not comment or len(comment) > 2_000:
            raise ValueError("decision comment is empty or too long")
        decided_at = _utc_second(decided_at, label="revision decision time")
        approval: ApprovalDecision | None = None
        with self._transaction(tenant_id=actor.tenant_id) as connection:
            self._lock_audit_head(connection, actor.tenant_id)
            current = self._locked_revision(
                connection,
                tenant_id=actor.tenant_id,
                revision_id=revision_id,
            )
            if (
                current.state != "submitted"
                or current.state_version != expected_state_version
            ):
                raise ControlPlaneConflict("revision state changed concurrently")
            decision_id = decision_identity(
                revision_id=revision_id,
                tenant_id=actor.tenant_id,
                decision=cast(Any, decision),
                decided_by=actor.subject,
                decided_at=decided_at,
                comment=comment,
                actor_session_digest=actor.session_id_digest,
            )
            approval = ApprovalDecision(
                decision_id=decision_id,
                revision_id=revision_id,
                tenant_id=actor.tenant_id,
                decision=cast(Any, decision),
                decided_by=actor.subject,
                decided_at=decided_at,
                comment=comment,
                actor_session_digest=actor.session_id_digest,
            )
            connection.execute(
                """
                INSERT INTO control_assurance.approval_decisions (
                    decision_id, revision_id, tenant_id, decision, decided_by,
                    decided_at, comment, actor_session_digest
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    approval.decision_id,
                    approval.revision_id,
                    approval.tenant_id,
                    approval.decision,
                    approval.decided_by,
                    approval.decided_at,
                    approval.comment,
                    approval.actor_session_digest,
                ),
            )
            cursor = connection.execute(
                """
                UPDATE control_assurance.control_revisions
                SET state = %s, state_version = state_version + 1, decided_at = %s
                WHERE tenant_id = %s AND revision_id = %s
                  AND state = 'submitted' AND state_version = %s
                """,
                (
                    decision,
                    decided_at,
                    actor.tenant_id,
                    revision_id,
                    expected_state_version,
                ),
            )
            if cursor.rowcount != 1:
                raise ControlPlaneConflict("revision state changed concurrently")
            self._append_audit(
                connection,
                actor=actor,
                action=cast(AuditAction, f"revision-{decision}"),
                object_id=revision_id,
                occurred_at=decided_at,
                details={
                    "comment_digest": _sha256(comment.encode()),
                    "control_id": current.control_id,
                    "decision_id": approval.decision_id,
                    "generation": current.generation,
                },
            )
        if approval is None:  # pragma: no cover - transaction cannot skip assignment
            raise ControlPlaneIntegrityError("approval decision was not persisted")
        return (
            self.get_revision(tenant_id=actor.tenant_id, revision_id=revision_id),
            approval,
        )

    def _create_deployment_operation(
        self,
        connection: Connection,
        *,
        actor: Actor,
        revision: ConfigurationRevision,
        kind: DeploymentOperationKind,
        requested_at: datetime,
        expected_predecessor_operation_id: str | None = None,
        enforce_predecessor: bool = False,
        retry_of_operation_id: str | None = None,
    ) -> DeploymentOperation:
        unresolved = connection.execute(
            """
            SELECT operation_id
            FROM control_assurance.deployment_operations
            WHERE tenant_id = %s AND control_id = %s
              AND (
                    state IN ('pending', 'leased')
                    OR (state = 'failed' AND retry_at IS NOT NULL)
              )
            LIMIT 1
            """,
            (actor.tenant_id, revision.control_id),
        ).fetchone()
        if unresolved is not None:
            raise ControlPlaneConflict(
                "control already has an unresolved deployment operation"
            )
        previous_row = connection.execute(
            """
            SELECT operation_id
            FROM control_assurance.deployment_operations
            WHERE tenant_id = %s AND control_id = %s AND state = 'applied'
            ORDER BY operation_sequence DESC
            LIMIT 1
            """,
            (actor.tenant_id, revision.control_id),
        ).fetchone()
        predecessor_operation_id = (
            None
            if previous_row is None
            else cast(str, previous_row["operation_id"])
        )
        if (
            enforce_predecessor
            and predecessor_operation_id != expected_predecessor_operation_id
        ):
            raise ControlPlaneConflict(
                "applied deployment operation changed concurrently"
            )
        sequence_row = connection.execute(
            """
            SELECT COALESCE(MAX(operation_sequence), 0) AS current_sequence
            FROM control_assurance.deployment_operations
            WHERE tenant_id = %s AND control_id = %s
            """,
            (actor.tenant_id, revision.control_id),
        ).fetchone()
        if sequence_row is None:
            raise ControlPlaneIntegrityError(
                "deployment operation sequence could not be read"
            )
        operation_sequence = cast(int, sequence_row["current_sequence"]) + 1
        operation_id = deployment_operation_identity(
            tenant_id=actor.tenant_id,
            control_id=revision.control_id,
            operation_sequence=operation_sequence,
            kind=kind,
            revision_id=revision.revision_id,
            configuration_digest=revision.configuration_digest,
            predecessor_operation_id=predecessor_operation_id,
            retry_of_operation_id=retry_of_operation_id,
            requested_by=actor.subject,
            requested_at=requested_at,
            requester_session_digest=actor.session_id_digest,
        )
        connection.execute(
            """
            INSERT INTO control_assurance.deployment_operations (
                operation_id, tenant_id, control_id, operation_sequence, kind,
                revision_id, configuration_digest, predecessor_operation_id,
                retry_of_operation_id, requested_by, requested_at,
                requester_session_digest, state, state_version, attempt_count,
                lease_fence
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                'pending', 0, 0, 0
            )
            """,
            (
                operation_id,
                actor.tenant_id,
                revision.control_id,
                operation_sequence,
                kind,
                revision.revision_id,
                revision.configuration_digest,
                predecessor_operation_id,
                retry_of_operation_id,
                actor.subject,
                requested_at,
                actor.session_id_digest,
            ),
        )
        return DeploymentOperation(
            operation_id=operation_id,
            tenant_id=actor.tenant_id,
            control_id=revision.control_id,
            operation_sequence=operation_sequence,
            kind=kind,
            revision_id=revision.revision_id,
            configuration_digest=revision.configuration_digest,
            predecessor_operation_id=predecessor_operation_id,
            retry_of_operation_id=retry_of_operation_id,
            requested_by=actor.subject,
            requested_at=requested_at,
            requester_session_digest=actor.session_id_digest,
            state="pending",
            state_version=0,
            attempt_count=0,
            lease_fence=0,
        )

    def activate_with_operation(
        self,
        *,
        actor: Actor,
        revision_id: str,
        expected_deployment_version: int | None,
        activated_at: datetime,
    ) -> tuple[ActiveDeployment, DeploymentOperation]:
        activated_at = _utc_second(activated_at, label="revision activation time")
        deployment: ActiveDeployment | None = None
        operation: DeploymentOperation | None = None
        with self._transaction(tenant_id=actor.tenant_id) as connection:
            self._lock_audit_head(connection, actor.tenant_id)
            revision = self._locked_revision(
                connection,
                tenant_id=actor.tenant_id,
                revision_id=revision_id,
            )
            if revision.state != "approved":
                raise ControlPlaneConflict("only an approved revision can be activated")
            existing_row = connection.execute(
                """
                SELECT *
                FROM control_assurance.active_deployments
                WHERE tenant_id = %s AND control_id = %s
                FOR UPDATE
                """,
                (actor.tenant_id, revision.control_id),
            ).fetchone()
            if existing_row is None:
                if expected_deployment_version is not None:
                    raise ControlPlaneConflict("deployment pointer changed concurrently")
                deployment_version = 1
                previous_revision_id = None
                connection.execute(
                    """
                    INSERT INTO control_assurance.active_deployments (
                        tenant_id, control_id, revision_id, configuration_digest,
                        activated_by, activated_at, deployment_version
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        actor.tenant_id,
                        revision.control_id,
                        revision.revision_id,
                        revision.configuration_digest,
                        actor.subject,
                        activated_at,
                        deployment_version,
                    ),
                )
            else:
                existing = self._deployment(existing_row)
                if expected_deployment_version != existing.deployment_version:
                    raise ControlPlaneConflict("deployment pointer changed concurrently")
                if existing.revision_id == revision.revision_id:
                    raise ControlPlaneConflict("revision is already active")
                deployment_version = existing.deployment_version + 1
                cursor = connection.execute(
                    """
                    UPDATE control_assurance.active_deployments
                    SET revision_id = %s, configuration_digest = %s, activated_by = %s,
                        activated_at = %s, deployment_version = %s
                    WHERE tenant_id = %s AND control_id = %s
                      AND deployment_version = %s
                    """,
                    (
                        revision.revision_id,
                        revision.configuration_digest,
                        actor.subject,
                        activated_at,
                        deployment_version,
                        actor.tenant_id,
                        revision.control_id,
                        existing.deployment_version,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ControlPlaneConflict("deployment pointer changed concurrently")
                retired = connection.execute(
                    """
                    UPDATE control_assurance.control_revisions
                    SET state = 'retired', state_version = state_version + 1
                    WHERE tenant_id = %s AND revision_id = %s AND state = 'approved'
                    """,
                    (actor.tenant_id, existing.revision_id),
                )
                if retired.rowcount != 1:
                    raise ControlPlaneIntegrityError(
                        "active deployment did not reference an approved revision"
                    )
                previous_revision_id = existing.revision_id
            operation = self._create_deployment_operation(
                connection,
                actor=actor,
                revision=revision,
                kind="apply",
                requested_at=activated_at,
            )
            deployment = ActiveDeployment(
                tenant_id=actor.tenant_id,
                control_id=revision.control_id,
                revision_id=revision.revision_id,
                configuration_digest=revision.configuration_digest,
                activated_by=actor.subject,
                activated_at=activated_at,
                deployment_version=deployment_version,
            )
            self._append_audit(
                connection,
                actor=actor,
                action="revision-activated",
                object_id=revision.revision_id,
                occurred_at=activated_at,
                details={
                    "configuration_digest": revision.configuration_digest,
                    "control_id": revision.control_id,
                    "deployment_version": deployment_version,
                    "operation_id": operation.operation_id,
                    "operation_sequence": operation.operation_sequence,
                    "previous_revision_id": previous_revision_id,
                },
            )
        if deployment is None or operation is None:  # pragma: no cover
            raise ControlPlaneIntegrityError(
                "deployment pointer and operation were not persisted"
            )
        return deployment, operation

    def activate(
        self,
        *,
        actor: Actor,
        revision_id: str,
        expected_deployment_version: int | None,
        activated_at: datetime,
    ) -> ActiveDeployment:
        """Compatibility wrapper returning only the desired-selection pointer."""

        deployment, _operation = self.activate_with_operation(
            actor=actor,
            revision_id=revision_id,
            expected_deployment_version=expected_deployment_version,
            activated_at=activated_at,
        )
        return deployment

    def get_active_deployment(
        self,
        *,
        tenant_id: str,
        control_id: str,
    ) -> ActiveDeployment:
        with self._transaction(tenant_id=tenant_id) as connection:
            row = connection.execute(
                """
                SELECT
                    deployment.*,
                    revision.configuration_digest AS revision_configuration_digest,
                    revision.tenant_id AS revision_tenant_id,
                    revision.control_id AS revision_control_id,
                    revision.state AS revision_state
                FROM control_assurance.active_deployments AS deployment
                JOIN control_assurance.control_revisions AS revision
                  ON revision.revision_id = deployment.revision_id
                WHERE deployment.tenant_id = %s AND deployment.control_id = %s
                """,
                (tenant_id, control_id),
            ).fetchone()
        if row is None:
            raise ControlPlaneNotFound("active deployment was not found")
        deployment = self._deployment(row)
        if (
            row["revision_configuration_digest"] != deployment.configuration_digest
            or row["revision_tenant_id"] != deployment.tenant_id
            or row["revision_control_id"] != deployment.control_id
            or row["revision_state"] != "approved"
        ):
            raise ControlPlaneIntegrityError(
                "active deployment pointer differs from its approved revision"
            )
        return deployment

    def request_rollback(
        self,
        *,
        actor: Actor,
        revision_id: str,
        expected_predecessor_operation_id: str,
        requested_at: datetime,
    ) -> DeploymentOperation:
        requested_at = _utc_second(requested_at, label="rollback request time")
        _require_digest(
            expected_predecessor_operation_id,
            label="expected predecessor operation id",
        )
        operation: DeploymentOperation | None = None
        with self._transaction(tenant_id=actor.tenant_id) as connection:
            self._lock_audit_head(connection, actor.tenant_id)
            revision = self._locked_revision(
                connection,
                tenant_id=actor.tenant_id,
                revision_id=revision_id,
            )
            if revision.state != "retired":
                raise ControlPlaneConflict(
                    "rollback target must be a previously retired revision"
                )
            approved = connection.execute(
                """
                SELECT 1
                FROM control_assurance.approval_decisions
                WHERE tenant_id = %s AND revision_id = %s
                  AND decision = 'approved'
                """,
                (actor.tenant_id, revision_id),
            ).fetchone()
            if approved is None:
                raise ControlPlaneIntegrityError(
                    "rollback target lacks its immutable approval"
                )
            if revision.created_by == actor.subject:
                raise ControlPlaneConflict(
                    "revision maker cannot request its rollback deployment"
                )
            current_row = connection.execute(
                """
                SELECT *
                FROM control_assurance.deployment_operations
                WHERE tenant_id = %s AND control_id = %s AND state = 'applied'
                ORDER BY operation_sequence DESC
                LIMIT 1
                """,
                (actor.tenant_id, revision.control_id),
            ).fetchone()
            if current_row is None:
                raise ControlPlaneConflict(
                    "rollback requires a previously applied deployment operation"
                )
            current = self._operation(current_row)
            if current.operation_id != expected_predecessor_operation_id:
                raise ControlPlaneConflict(
                    "applied deployment operation changed concurrently"
                )
            if current.revision_id == revision.revision_id:
                raise ControlPlaneConflict(
                    "rollback target is already the applied configuration"
                )
            operation = self._create_deployment_operation(
                connection,
                actor=actor,
                revision=revision,
                kind="rollback",
                requested_at=requested_at,
                expected_predecessor_operation_id=expected_predecessor_operation_id,
                enforce_predecessor=True,
            )
            self._append_audit(
                connection,
                actor=actor,
                action="deployment-rollback-requested",
                object_id=operation.operation_id,
                occurred_at=requested_at,
                details={
                    "configuration_digest": operation.configuration_digest,
                    "control_id": operation.control_id,
                    "operation_sequence": operation.operation_sequence,
                    "predecessor_operation_id": operation.predecessor_operation_id,
                    "revision_id": operation.revision_id,
                },
            )
        if operation is None:  # pragma: no cover - transaction cannot skip assignment
            raise ControlPlaneIntegrityError("rollback operation was not persisted")
        return operation

    def request_deployment_retry(
        self,
        *,
        actor: Actor,
        failed_operation_id: str,
        requested_at: datetime,
    ) -> DeploymentOperation:
        requested_at = _utc_second(
            requested_at,
            label="deployment retry request time",
        )
        _require_digest(failed_operation_id, label="failed deployment operation id")
        operation: DeploymentOperation | None = None
        with self._transaction(tenant_id=actor.tenant_id) as connection:
            self._lock_audit_head(connection, actor.tenant_id)
            failed_row = connection.execute(
                """
                SELECT *
                FROM control_assurance.deployment_operations
                WHERE tenant_id = %s AND operation_id = %s
                """,
                (actor.tenant_id, failed_operation_id),
            ).fetchone()
            if failed_row is None:
                raise ControlPlaneNotFound(
                    "failed deployment operation was not found"
                )
            failed = self._operation(failed_row)
            self._lock_control(
                connection,
                failed.tenant_id,
                failed.control_id,
            )
            if failed.state != "failed" or failed.retry_at is not None:
                raise ControlPlaneConflict(
                    "only a terminal deployment failure can be retried manually"
                )
            latest_row = connection.execute(
                """
                SELECT operation_id
                FROM control_assurance.deployment_operations
                WHERE tenant_id = %s AND control_id = %s
                ORDER BY operation_sequence DESC
                LIMIT 1
                """,
                (actor.tenant_id, failed.control_id),
            ).fetchone()
            if (
                latest_row is None
                or latest_row["operation_id"] != failed.operation_id
            ):
                raise ControlPlaneConflict(
                    "failed operation is no longer the control's latest intent"
                )
            revision_row = connection.execute(
                """
                SELECT *
                FROM control_assurance.control_revisions
                WHERE tenant_id = %s AND revision_id = %s
                FOR UPDATE
                """,
                (actor.tenant_id, failed.revision_id),
            ).fetchone()
            if revision_row is None:
                raise ControlPlaneIntegrityError(
                    "failed operation target revision disappeared"
                )
            revision = self._revision(revision_row)
            if revision.state != "approved":
                raise ControlPlaneConflict(
                    "failed operation target is no longer approved"
                )
            if revision.created_by == actor.subject:
                raise ControlPlaneConflict(
                    "revision maker cannot request its deployment retry"
                )
            selection_row = connection.execute(
                """
                SELECT *
                FROM control_assurance.active_deployments
                WHERE tenant_id = %s AND control_id = %s
                FOR UPDATE
                """,
                (actor.tenant_id, failed.control_id),
            ).fetchone()
            if selection_row is None:
                raise ControlPlaneIntegrityError(
                    "failed operation has no desired selection"
                )
            selection = self._deployment(selection_row)
            if (
                selection.revision_id != revision.revision_id
                or selection.configuration_digest != revision.configuration_digest
            ):
                raise ControlPlaneConflict(
                    "failed operation is no longer the desired selection"
                )
            operation = self._create_deployment_operation(
                connection,
                actor=actor,
                revision=revision,
                kind="apply",
                requested_at=requested_at,
                retry_of_operation_id=failed.operation_id,
            )
            self._append_audit(
                connection,
                actor=actor,
                action="deployment-retry-requested",
                object_id=operation.operation_id,
                occurred_at=requested_at,
                details={
                    "configuration_digest": operation.configuration_digest,
                    "control_id": operation.control_id,
                    "operation_sequence": operation.operation_sequence,
                    "retry_of_operation_id": failed.operation_id,
                    "revision_id": operation.revision_id,
                },
            )
        if operation is None:  # pragma: no cover - transaction cannot skip assignment
            raise ControlPlaneIntegrityError("deployment retry was not persisted")
        return operation

    def get_deployment_operation(
        self,
        *,
        tenant_id: str,
        operation_id: str,
    ) -> DeploymentOperation:
        with self._transaction(tenant_id=tenant_id) as connection:
            row = connection.execute(
                """
                SELECT *
                FROM control_assurance.deployment_operations
                WHERE tenant_id = %s AND operation_id = %s
                """,
                (tenant_id, operation_id),
            ).fetchone()
        if row is None:
            raise ControlPlaneNotFound("deployment operation was not found")
        return self._operation(row)

    def list_deployment_operations(
        self,
        *,
        tenant_id: str,
        control_id: str,
        limit: int = 100,
    ) -> tuple[DeploymentOperation, ...]:
        if type(limit) is not int or limit < 1 or limit > 1_000:
            raise ValueError("deployment operation limit is outside the supported range")
        with self._transaction(tenant_id=tenant_id) as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM control_assurance.deployment_operations
                WHERE tenant_id = %s AND control_id = %s
                ORDER BY operation_sequence DESC
                LIMIT %s
                """,
                (tenant_id, control_id, limit),
            ).fetchall()
        return tuple(self._operation(row) for row in rows)

    def latest_applied_operation(
        self,
        *,
        tenant_id: str,
        control_id: str,
    ) -> DeploymentOperation:
        with self._transaction(tenant_id=tenant_id) as connection:
            row = connection.execute(
                """
                SELECT *
                FROM control_assurance.deployment_operations
                WHERE tenant_id = %s AND control_id = %s AND state = 'applied'
                ORDER BY operation_sequence DESC
                LIMIT 1
                """,
                (tenant_id, control_id),
            ).fetchone()
        if row is None:
            raise ControlPlaneNotFound("applied deployment operation was not found")
        return self._operation(row)

    def lease_next_deployment_operation(
        self,
        *,
        worker: DeploymentWorkerIdentity,
        lease_token_digest: str,
        leased_at: datetime,
        lease_ttl_seconds: int,
    ) -> DeploymentOperation | None:
        lease_token_digest = _require_digest(
            lease_token_digest,
            label="lease token digest",
        )
        leased_at = _utc_second(leased_at, label="deployment lease time")
        if (
            type(lease_ttl_seconds) is not int
            or lease_ttl_seconds < 15
            or lease_ttl_seconds > 3_600
        ):
            raise ValueError("deployment lease TTL is outside the supported range")
        lease_expires_at = leased_at + timedelta(seconds=lease_ttl_seconds)
        operation: DeploymentOperation | None = None
        with self._transaction(tenant_id=worker.tenant_id) as connection:
            self._lock_audit_head(connection, worker.tenant_id)
            row = connection.execute(
                """
                SELECT *
                FROM control_assurance.deployment_operations
                WHERE tenant_id = %s
                  AND (
                        (state = 'pending' AND requested_at <= %s)
                        OR (
                            state = 'failed'
                            AND retry_at IS NOT NULL
                            AND retry_at <= %s
                        )
                        OR (
                            state = 'leased'
                            AND lease_expires_at <= %s
                        )
                  )
                ORDER BY requested_at, control_id, operation_sequence
                LIMIT 1
                FOR UPDATE SKIP LOCKED
                """,
                (worker.tenant_id, leased_at, leased_at, leased_at),
            ).fetchone()
            if row is None:
                return None
            current = self._operation(row)
            self._lock_control(
                connection,
                current.tenant_id,
                current.control_id,
            )
            next_attempt = current.attempt_count + 1
            cursor = connection.execute(
                """
                UPDATE control_assurance.deployment_operations
                SET state = 'leased',
                    state_version = state_version + 1,
                    attempt_count = %s,
                    lease_fence = %s,
                    lease_owner = %s,
                    lease_token_digest = %s,
                    leased_at = %s,
                    lease_expires_at = %s,
                    retry_at = NULL,
                    failed_at = NULL,
                    failure_digest = NULL
                WHERE tenant_id = %s AND operation_id = %s
                  AND state_version = %s
                  AND (
                        (state = 'pending' AND requested_at <= %s)
                        OR (
                            state = 'failed'
                            AND retry_at IS NOT NULL
                            AND retry_at <= %s
                        )
                        OR (
                            state = 'leased'
                            AND lease_expires_at <= %s
                        )
                  )
                """,
                (
                    next_attempt,
                    next_attempt,
                    worker.worker_id,
                    lease_token_digest,
                    leased_at,
                    lease_expires_at,
                    worker.tenant_id,
                    current.operation_id,
                    current.state_version,
                    leased_at,
                    leased_at,
                    leased_at,
                ),
            )
            if cursor.rowcount != 1:
                raise ControlPlaneConflict(
                    "deployment operation lease changed concurrently"
                )
            self._append_audit(
                connection,
                actor=worker,
                action="deployment-leased",
                object_id=current.operation_id,
                occurred_at=leased_at,
                details={
                    "attempt_count": next_attempt,
                    "control_id": current.control_id,
                    "lease_expires_at": lease_expires_at.strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                    "lease_fence": next_attempt,
                    "recovered_from_state": current.state,
                    "worker_id": worker.worker_id,
                },
            )
            updated = connection.execute(
                """
                SELECT *
                FROM control_assurance.deployment_operations
                WHERE tenant_id = %s AND operation_id = %s
                """,
                (worker.tenant_id, current.operation_id),
            ).fetchone()
            if updated is None:
                raise ControlPlaneIntegrityError(
                    "leased deployment operation disappeared"
                )
            operation = self._operation(updated)
        return operation

    def acknowledge_deployment_applied(
        self,
        *,
        worker: DeploymentWorkerIdentity,
        operation_id: str,
        lease_token_digest: str,
        lease_fence: int,
        applied_configuration_digest: str,
        target_receipt_digest: str,
        applied_at: datetime,
    ) -> DeploymentOperation:
        lease_token_digest = _require_digest(
            lease_token_digest,
            label="lease token digest",
        )
        applied_configuration_digest = _require_digest(
            applied_configuration_digest,
            label="applied configuration digest",
        )
        target_receipt_digest = _require_digest(
            target_receipt_digest,
            label="target receipt digest",
        )
        if type(lease_fence) is not int or lease_fence < 1:
            raise ValueError("deployment lease fence is invalid")
        applied_at = _utc_second(applied_at, label="deployment application time")
        operation: DeploymentOperation | None = None
        with self._transaction(tenant_id=worker.tenant_id) as connection:
            self._lock_audit_head(connection, worker.tenant_id)
            row = connection.execute(
                """
                SELECT *
                FROM control_assurance.deployment_operations
                WHERE tenant_id = %s AND operation_id = %s
                FOR UPDATE
                """,
                (worker.tenant_id, operation_id),
            ).fetchone()
            if row is None:
                raise ControlPlaneNotFound("deployment operation was not found")
            current = self._operation(row)
            self._lock_control(
                connection,
                current.tenant_id,
                current.control_id,
            )
            if applied_configuration_digest != current.configuration_digest:
                raise ControlPlaneIntegrityError(
                    "target acknowledged a different configuration digest"
                )
            if (
                current.state != "leased"
                or current.lease_owner != worker.worker_id
                or current.lease_token_digest != lease_token_digest
                or current.lease_fence != lease_fence
                or current.lease_expires_at is None
                or applied_at >= current.lease_expires_at
            ):
                raise ControlPlaneConflict(
                    "deployment lease is stale or belongs to another worker"
                )
            cursor = connection.execute(
                """
                UPDATE control_assurance.deployment_operations
                SET state = 'applied',
                    state_version = state_version + 1,
                    lease_owner = NULL,
                    lease_token_digest = NULL,
                    leased_at = NULL,
                    lease_expires_at = NULL,
                    applied_at = %s,
                    applied_configuration_digest = %s,
                    target_receipt_digest = %s
                WHERE tenant_id = %s AND operation_id = %s
                  AND state = 'leased' AND state_version = %s
                  AND lease_owner = %s AND lease_token_digest = %s
                  AND lease_fence = %s AND lease_expires_at > %s
                """,
                (
                    applied_at,
                    applied_configuration_digest,
                    target_receipt_digest,
                    worker.tenant_id,
                    operation_id,
                    current.state_version,
                    worker.worker_id,
                    lease_token_digest,
                    lease_fence,
                    applied_at,
                ),
            )
            if cursor.rowcount != 1:
                raise ControlPlaneConflict(
                    "deployment lease is stale or belongs to another worker"
                )
            self._append_audit(
                connection,
                actor=worker,
                action="deployment-applied",
                object_id=operation_id,
                occurred_at=applied_at,
                details={
                    "applied_configuration_digest": (
                        applied_configuration_digest
                    ),
                    "control_id": current.control_id,
                    "lease_fence": lease_fence,
                    "target_receipt_digest": target_receipt_digest,
                    "worker_id": worker.worker_id,
                },
            )
            updated = connection.execute(
                """
                SELECT *
                FROM control_assurance.deployment_operations
                WHERE tenant_id = %s AND operation_id = %s
                """,
                (worker.tenant_id, operation_id),
            ).fetchone()
            if updated is None:
                raise ControlPlaneIntegrityError(
                    "applied deployment operation disappeared"
                )
            operation = self._operation(updated)
        if operation is None:  # pragma: no cover - transaction cannot skip assignment
            raise ControlPlaneIntegrityError("deployment receipt was not persisted")
        return operation

    def fail_deployment_operation(
        self,
        *,
        worker: DeploymentWorkerIdentity,
        operation_id: str,
        lease_token_digest: str,
        lease_fence: int,
        failure_digest: str,
        failed_at: datetime,
        retry_at: datetime | None,
    ) -> DeploymentOperation:
        lease_token_digest = _require_digest(
            lease_token_digest,
            label="lease token digest",
        )
        failure_digest = _require_digest(failure_digest, label="failure digest")
        if type(lease_fence) is not int or lease_fence < 1:
            raise ValueError("deployment lease fence is invalid")
        failed_at = _utc_second(failed_at, label="deployment failure time")
        if retry_at is not None:
            retry_at = _utc_second(retry_at, label="deployment retry time")
            if retry_at <= failed_at or retry_at > failed_at + timedelta(hours=24):
                raise ValueError("deployment retry time is outside the supported range")
        operation: DeploymentOperation | None = None
        with self._transaction(tenant_id=worker.tenant_id) as connection:
            self._lock_audit_head(connection, worker.tenant_id)
            row = connection.execute(
                """
                SELECT *
                FROM control_assurance.deployment_operations
                WHERE tenant_id = %s AND operation_id = %s
                FOR UPDATE
                """,
                (worker.tenant_id, operation_id),
            ).fetchone()
            if row is None:
                raise ControlPlaneNotFound("deployment operation was not found")
            current = self._operation(row)
            self._lock_control(
                connection,
                current.tenant_id,
                current.control_id,
            )
            if (
                current.state != "leased"
                or current.lease_owner != worker.worker_id
                or current.lease_token_digest != lease_token_digest
                or current.lease_fence != lease_fence
                or current.lease_expires_at is None
                or failed_at >= current.lease_expires_at
            ):
                raise ControlPlaneConflict(
                    "deployment lease is stale or belongs to another worker"
                )
            cursor = connection.execute(
                """
                UPDATE control_assurance.deployment_operations
                SET state = 'failed',
                    state_version = state_version + 1,
                    lease_owner = NULL,
                    lease_token_digest = NULL,
                    leased_at = NULL,
                    lease_expires_at = NULL,
                    retry_at = %s,
                    failed_at = %s,
                    failure_digest = %s
                WHERE tenant_id = %s AND operation_id = %s
                  AND state = 'leased' AND state_version = %s
                  AND lease_owner = %s AND lease_token_digest = %s
                  AND lease_fence = %s AND lease_expires_at > %s
                """,
                (
                    retry_at,
                    failed_at,
                    failure_digest,
                    worker.tenant_id,
                    operation_id,
                    current.state_version,
                    worker.worker_id,
                    lease_token_digest,
                    lease_fence,
                    failed_at,
                ),
            )
            if cursor.rowcount != 1:
                raise ControlPlaneConflict(
                    "deployment lease is stale or belongs to another worker"
                )
            self._append_audit(
                connection,
                actor=worker,
                action="deployment-failed",
                object_id=operation_id,
                occurred_at=failed_at,
                details={
                    "control_id": current.control_id,
                    "failure_digest": failure_digest,
                    "lease_fence": lease_fence,
                    "retry_at": (
                        None
                        if retry_at is None
                        else retry_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                    ),
                    "worker_id": worker.worker_id,
                },
            )
            updated = connection.execute(
                """
                SELECT *
                FROM control_assurance.deployment_operations
                WHERE tenant_id = %s AND operation_id = %s
                """,
                (worker.tenant_id, operation_id),
            ).fetchone()
            if updated is None:
                raise ControlPlaneIntegrityError(
                    "failed deployment operation disappeared"
                )
            operation = self._operation(updated)
        if operation is None:  # pragma: no cover - transaction cannot skip assignment
            raise ControlPlaneIntegrityError("deployment failure was not persisted")
        return operation

    @staticmethod
    def _audit_events_on(
        connection: Connection,
        *,
        tenant_id: str,
        after_sequence: int,
        limit: int,
    ) -> tuple[AuditEvent, ...]:
        rows = connection.execute(
            """
            SELECT *
            FROM control_assurance.control_audit_events
            WHERE tenant_id = %s AND sequence > %s
            ORDER BY sequence
            LIMIT %s
            """,
            (tenant_id, after_sequence, limit),
        ).fetchall()
        return tuple(PostgresControlPlaneStore._audit(row) for row in rows)

    def audit_events(
        self,
        *,
        tenant_id: str,
        after_sequence: int = 0,
        limit: int = 1_000,
    ) -> tuple[AuditEvent, ...]:
        if type(after_sequence) is not int or after_sequence < 0:
            raise ValueError("audit cursor is invalid")
        if type(limit) is not int or limit < 1 or limit > 10_000:
            raise ValueError("audit limit is outside the supported range")
        with self._transaction(tenant_id=tenant_id) as connection:
            return self._audit_events_on(
                connection,
                tenant_id=tenant_id,
                after_sequence=after_sequence,
                limit=limit,
            )

    def verify_audit_chain(self, *, tenant_id: str) -> tuple[int, str]:
        previous = _GENESIS_DIGEST
        sequence = 0
        with self._transaction(
            tenant_id=tenant_id,
            isolation="REPEATABLE READ",
        ) as connection:
            while True:
                events = self._audit_events_on(
                    connection,
                    tenant_id=tenant_id,
                    after_sequence=sequence,
                    limit=1_000,
                )
                if not events:
                    break
                for event in events:
                    sequence += 1
                    if (
                        event.sequence != sequence
                        or event.previous_event_digest != previous
                        or _sha256(event.event_bytes) != event.event_digest
                    ):
                        raise ControlPlaneIntegrityError("audit hash chain is broken")
                    try:
                        details = strict_json_loads(
                            event.details_bytes,
                            limits=_DETAIL_LIMITS,
                        )
                        if (
                            canonical_json_bytes(details, limits=_DETAIL_LIMITS)
                            != event.details_bytes
                        ):
                            raise ControlPlaneIntegrityError(
                                "audit details are not canonical"
                            )
                    except StrictJSONError as exc:
                        raise ControlPlaneIntegrityError(
                            "audit details are invalid"
                        ) from exc
                    previous = event.event_digest
                if len(events) < 1_000:
                    break
        return sequence, previous
