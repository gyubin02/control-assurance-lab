"""Append-only SQLite reference store for control-plane state.

This store is intentionally single-node.  It gives local evaluation and
recovery drills the same immutable revision and audit semantics as the
PostgreSQL HA store, but it is not presented as an HA deployment.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, cast

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
from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)

_SCHEMA_VERSION: Final = 3
_BUSY_TIMEOUT_MILLISECONDS: Final = 15_000
_GENESIS_DIGEST: Final = f"sha256:{'0' * 64}"
_DETAIL_LIMITS = JSONLimits(
    max_bytes=64 * 1024,
    max_line_bytes=64 * 1024,
    max_depth=16,
    max_collection_items=1_024,
    max_string_length=8_192,
)


class ControlPlaneStoreError(RuntimeError):
    pass


class ControlPlaneNotFound(ControlPlaneStoreError):
    pass


class ControlPlaneConflict(ControlPlaneStoreError):
    pass


class ControlPlaneIntegrityError(ControlPlaneStoreError):
    pass


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ControlPlaneIntegrityError("stored timestamp is invalid") from exc
    return parsed


def _utc_second(value: datetime, *, label: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
    converted = value.astimezone(UTC)
    if converted.microsecond != 0:
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


class SQLiteControlPlaneStore:
    """Durable local state with immutable rows and a per-tenant hash chain."""

    __slots__ = ("_path",)

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path):
            raise TypeError("control-plane database path must be a pathlib.Path")
        self._path = path
        self._prepare_file()
        self._initialize()

    def _prepare_file(self) -> None:
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            current = self._path.lstat()
        except FileNotFoundError:
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self._path, flags, 0o600)
            os.close(descriptor)
            current = self._path.lstat()
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or current.st_uid != os.geteuid()
            or stat.S_IMODE(current.st_mode) & 0o077
        ):
            raise ControlPlaneStoreError(
                "control-plane database must be an owner-only, single-link regular file"
            )

    def _connect(self) -> sqlite3.Connection:
        self._prepare_file()
        connection = sqlite3.connect(
            self._path,
            isolation_level=None,
            timeout=_BUSY_TIMEOUT_MILLISECONDS / 1_000,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MILLISECONDS}")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA journal_mode=DELETE")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            version = cast(int, connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in {0, 1, 2, _SCHEMA_VERSION}:
                raise ControlPlaneStoreError("control-plane database schema is unsupported")
            retry_lineage_migration = (
                """
                ALTER TABLE deployment_operations
                    ADD COLUMN retry_of_operation_id TEXT
                    REFERENCES deployment_operations(operation_id);
                DROP TRIGGER IF EXISTS deployment_operations_insert_guard;
                DROP TRIGGER IF EXISTS deployment_operations_immutable_request;
                """
                if version == 2
                else ""
            )
            try:
                connection.executescript(
                    f"""
                    BEGIN IMMEDIATE;

                    {retry_lineage_migration}

                    CREATE TABLE IF NOT EXISTS control_revisions (
                        revision_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        control_id TEXT NOT NULL,
                        generation INTEGER NOT NULL CHECK (generation >= 1),
                        parent_revision_id TEXT,
                        configuration_digest TEXT NOT NULL,
                        configuration_bytes BLOB NOT NULL,
                        state TEXT NOT NULL CHECK (
                            state IN ('draft', 'submitted', 'approved', 'rejected', 'retired')
                        ),
                        state_version INTEGER NOT NULL DEFAULT 0,
                        created_by TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        submitted_at TEXT,
                        decided_at TEXT,
                        UNIQUE (tenant_id, control_id, generation),
                        FOREIGN KEY (parent_revision_id)
                            REFERENCES control_revisions(revision_id)
                    );

                    CREATE INDEX IF NOT EXISTS control_revisions_lineage
                        ON control_revisions (tenant_id, control_id, generation DESC);

                    CREATE TABLE IF NOT EXISTS approval_decisions (
                        decision_id TEXT PRIMARY KEY,
                        revision_id TEXT NOT NULL UNIQUE,
                        tenant_id TEXT NOT NULL,
                        decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
                        decided_by TEXT NOT NULL,
                        decided_at TEXT NOT NULL,
                        comment TEXT NOT NULL,
                        actor_session_digest TEXT NOT NULL,
                        FOREIGN KEY (revision_id)
                            REFERENCES control_revisions(revision_id)
                    );

                    CREATE TABLE IF NOT EXISTS active_deployments (
                        tenant_id TEXT NOT NULL,
                        control_id TEXT NOT NULL,
                        revision_id TEXT NOT NULL,
                        configuration_digest TEXT NOT NULL,
                        activated_by TEXT NOT NULL,
                        activated_at TEXT NOT NULL,
                        deployment_version INTEGER NOT NULL CHECK (deployment_version >= 1),
                        PRIMARY KEY (tenant_id, control_id),
                        FOREIGN KEY (revision_id)
                            REFERENCES control_revisions(revision_id)
                    );

                    CREATE TABLE IF NOT EXISTS deployment_operations (
                        operation_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        control_id TEXT NOT NULL,
                        operation_sequence INTEGER NOT NULL
                            CHECK (operation_sequence >= 1),
                        kind TEXT NOT NULL CHECK (kind IN ('apply', 'rollback')),
                        revision_id TEXT NOT NULL,
                        configuration_digest TEXT NOT NULL,
                        predecessor_operation_id TEXT,
                        retry_of_operation_id TEXT,
                        requested_by TEXT NOT NULL,
                        requested_at TEXT NOT NULL,
                        requester_session_digest TEXT NOT NULL,
                        state TEXT NOT NULL
                            CHECK (state IN ('pending', 'leased', 'applied', 'failed')),
                        state_version INTEGER NOT NULL DEFAULT 0
                            CHECK (state_version >= 0),
                        attempt_count INTEGER NOT NULL DEFAULT 0
                            CHECK (attempt_count >= 0),
                        lease_fence INTEGER NOT NULL DEFAULT 0
                            CHECK (lease_fence >= 0),
                        lease_owner TEXT,
                        lease_token_digest TEXT,
                        leased_at TEXT,
                        lease_expires_at TEXT,
                        retry_at TEXT,
                        applied_at TEXT,
                        applied_configuration_digest TEXT,
                        target_receipt_digest TEXT,
                        failed_at TEXT,
                        failure_digest TEXT,
                        UNIQUE (tenant_id, control_id, operation_sequence),
                        FOREIGN KEY (revision_id)
                            REFERENCES control_revisions(revision_id),
                        FOREIGN KEY (predecessor_operation_id)
                            REFERENCES deployment_operations(operation_id),
                        FOREIGN KEY (retry_of_operation_id)
                            REFERENCES deployment_operations(operation_id),
                        CHECK (
                            (
                                state = 'pending'
                                AND state_version = 0
                                AND attempt_count = 0
                                AND lease_fence = 0
                                AND lease_owner IS NULL
                                AND lease_token_digest IS NULL
                                AND leased_at IS NULL
                                AND lease_expires_at IS NULL
                                AND retry_at IS NULL
                                AND applied_at IS NULL
                                AND applied_configuration_digest IS NULL
                                AND target_receipt_digest IS NULL
                                AND failed_at IS NULL
                                AND failure_digest IS NULL
                            )
                            OR (
                                state = 'leased'
                                AND attempt_count >= 1
                                AND lease_fence = attempt_count
                                AND lease_owner IS NOT NULL
                                AND lease_token_digest IS NOT NULL
                                AND leased_at IS NOT NULL
                                AND leased_at >= requested_at
                                AND lease_expires_at > leased_at
                                AND retry_at IS NULL
                                AND applied_at IS NULL
                                AND applied_configuration_digest IS NULL
                                AND target_receipt_digest IS NULL
                                AND failed_at IS NULL
                                AND failure_digest IS NULL
                            )
                            OR (
                                state = 'applied'
                                AND attempt_count >= 1
                                AND lease_fence = attempt_count
                                AND lease_owner IS NULL
                                AND lease_token_digest IS NULL
                                AND leased_at IS NULL
                                AND lease_expires_at IS NULL
                                AND retry_at IS NULL
                                AND applied_at IS NOT NULL
                                AND applied_at >= requested_at
                                AND applied_configuration_digest = configuration_digest
                                AND target_receipt_digest IS NOT NULL
                                AND failed_at IS NULL
                                AND failure_digest IS NULL
                            )
                            OR (
                                state = 'failed'
                                AND attempt_count >= 1
                                AND lease_fence = attempt_count
                                AND lease_owner IS NULL
                                AND lease_token_digest IS NULL
                                AND leased_at IS NULL
                                AND lease_expires_at IS NULL
                                AND applied_at IS NULL
                                AND applied_configuration_digest IS NULL
                                AND target_receipt_digest IS NULL
                                AND failed_at IS NOT NULL
                                AND failed_at >= requested_at
                                AND failure_digest IS NOT NULL
                                AND (
                                    retry_at IS NULL
                                    OR (
                                        retry_at > failed_at
                                        AND julianday(retry_at)
                                            <= julianday(failed_at) + 1
                                    )
                                )
                            )
                        )
                    );

                    CREATE INDEX IF NOT EXISTS deployment_operations_poll
                        ON deployment_operations (
                            tenant_id, state, retry_at, requested_at, operation_sequence
                        );

                    CREATE UNIQUE INDEX IF NOT EXISTS
                        deployment_operations_one_unresolved
                        ON deployment_operations (tenant_id, control_id)
                        WHERE state IN ('pending', 'leased')
                           OR (state = 'failed' AND retry_at IS NOT NULL);

                    CREATE TABLE IF NOT EXISTS control_audit_events (
                        tenant_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL CHECK (sequence >= 1),
                        previous_event_digest TEXT NOT NULL,
                        event_digest TEXT NOT NULL UNIQUE,
                        action TEXT NOT NULL,
                        object_id TEXT NOT NULL,
                        actor_subject TEXT NOT NULL,
                        actor_session_digest TEXT NOT NULL,
                        occurred_at TEXT NOT NULL,
                        details_digest TEXT NOT NULL,
                        details_bytes BLOB NOT NULL,
                        event_bytes BLOB NOT NULL,
                        PRIMARY KEY (tenant_id, sequence)
                    );

                    CREATE TRIGGER IF NOT EXISTS revisions_no_delete
                    BEFORE DELETE ON control_revisions
                    BEGIN
                        SELECT RAISE(ABORT, 'control revisions are append-only');
                    END;

                    CREATE TRIGGER IF NOT EXISTS revisions_immutable_content
                    BEFORE UPDATE OF
                        revision_id, tenant_id, control_id, generation,
                        parent_revision_id, configuration_digest, configuration_bytes,
                        created_by, created_at
                    ON control_revisions
                    BEGIN
                        SELECT RAISE(ABORT, 'revision content is immutable');
                    END;

                    CREATE TRIGGER IF NOT EXISTS decisions_no_update
                    BEFORE UPDATE ON approval_decisions
                    BEGIN
                        SELECT RAISE(ABORT, 'approval decisions are immutable');
                    END;

                    CREATE TRIGGER IF NOT EXISTS decisions_no_delete
                    BEFORE DELETE ON approval_decisions
                    BEGIN
                        SELECT RAISE(ABORT, 'approval decisions are append-only');
                    END;

                    CREATE TRIGGER IF NOT EXISTS deployment_operations_no_delete
                    BEFORE DELETE ON deployment_operations
                    BEGIN
                        SELECT RAISE(
                            ABORT,
                            'deployment operations are append-only'
                        );
                    END;

                    CREATE TRIGGER IF NOT EXISTS deployment_operations_insert_guard
                    BEFORE INSERT ON deployment_operations
                    WHEN
                        NOT EXISTS (
                            SELECT 1
                            FROM control_revisions AS revision
                            WHERE revision.tenant_id = NEW.tenant_id
                              AND revision.control_id = NEW.control_id
                              AND revision.revision_id = NEW.revision_id
                              AND revision.configuration_digest
                                  = NEW.configuration_digest
                              AND revision.created_by <> NEW.requested_by
                              AND (
                                    (
                                        NEW.kind = 'apply'
                                        AND revision.state = 'approved'
                                    )
                                    OR (
                                        NEW.kind = 'rollback'
                                        AND revision.state = 'retired'
                                        AND EXISTS (
                                            SELECT 1
                                            FROM approval_decisions AS decision
                                            WHERE decision.tenant_id = NEW.tenant_id
                                              AND decision.revision_id
                                                  = NEW.revision_id
                                              AND decision.decision = 'approved'
                                        )
                                    )
                              )
                        )
                        OR NEW.operation_sequence <> (
                            SELECT COALESCE(MAX(current.operation_sequence), 0) + 1
                            FROM deployment_operations AS current
                            WHERE current.tenant_id = NEW.tenant_id
                              AND current.control_id = NEW.control_id
                        )
                        OR NEW.predecessor_operation_id IS NOT (
                            SELECT current.operation_id
                            FROM deployment_operations AS current
                            WHERE current.tenant_id = NEW.tenant_id
                              AND current.control_id = NEW.control_id
                              AND current.state = 'applied'
                            ORDER BY current.operation_sequence DESC
                            LIMIT 1
                        )
                        OR (
                            NEW.kind = 'rollback'
                            AND NEW.predecessor_operation_id IS NULL
                        )
                        OR (
                            NEW.retry_of_operation_id IS NOT NULL
                            AND (
                                NEW.kind <> 'apply'
                                OR NOT EXISTS (
                                    SELECT 1
                                    FROM deployment_operations AS failed
                                    WHERE failed.operation_id
                                        = NEW.retry_of_operation_id
                                      AND failed.tenant_id = NEW.tenant_id
                                      AND failed.control_id = NEW.control_id
                                      AND failed.revision_id = NEW.revision_id
                                      AND failed.configuration_digest
                                          = NEW.configuration_digest
                                      AND failed.state = 'failed'
                                      AND failed.retry_at IS NULL
                                      AND failed.operation_sequence
                                          = NEW.operation_sequence - 1
                                )
                            )
                        )
                    BEGIN
                        SELECT RAISE(
                            ABORT,
                            'deployment operation violates request invariants'
                        );
                    END;

                    CREATE TRIGGER IF NOT EXISTS deployment_operations_immutable_request
                    BEFORE UPDATE OF
                        operation_id, tenant_id, control_id, operation_sequence,
                        kind, revision_id, configuration_digest,
                        predecessor_operation_id, retry_of_operation_id,
                        requested_by, requested_at, requester_session_digest
                    ON deployment_operations
                    BEGIN
                        SELECT RAISE(
                            ABORT,
                            'deployment operation request is immutable'
                        );
                    END;

                    CREATE TRIGGER IF NOT EXISTS deployment_operations_transition_guard
                    BEFORE UPDATE ON deployment_operations
                    WHEN NOT (
                        NEW.state_version = OLD.state_version + 1
                        AND (
                            (
                                OLD.state = 'pending'
                                AND NEW.state = 'leased'
                            )
                            OR (
                                OLD.state = 'failed'
                                AND OLD.retry_at IS NOT NULL
                                AND NEW.leased_at >= OLD.retry_at
                                AND NEW.state = 'leased'
                            )
                            OR (
                                OLD.state = 'leased'
                                AND NEW.state = 'leased'
                                AND NEW.leased_at >= OLD.lease_expires_at
                                AND NEW.lease_fence = OLD.lease_fence + 1
                            )
                            OR (
                                OLD.state = 'leased'
                                AND NEW.state IN ('applied', 'failed')
                            )
                        )
                    )
                    BEGIN
                        SELECT RAISE(
                            ABORT,
                            'invalid deployment operation transition'
                        );
                    END;

                    CREATE TRIGGER IF NOT EXISTS audit_no_update
                    BEFORE UPDATE ON control_audit_events
                    BEGIN
                        SELECT RAISE(ABORT, 'audit events are immutable');
                    END;

                    CREATE TRIGGER IF NOT EXISTS audit_no_delete
                    BEFORE DELETE ON control_audit_events
                    BEGIN
                        SELECT RAISE(ABORT, 'audit events are append-only');
                    END;

                    PRAGMA user_version={_SCHEMA_VERSION};
                    COMMIT;
                    """
                )
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        finally:
            connection.close()

    @staticmethod
    def _revision(row: sqlite3.Row) -> ConfigurationRevision:
        try:
            return ConfigurationRevision(
                revision_id=cast(str, row["revision_id"]),
                tenant_id=cast(str, row["tenant_id"]),
                control_id=cast(str, row["control_id"]),
                generation=cast(int, row["generation"]),
                parent_revision_id=cast(str | None, row["parent_revision_id"]),
                configuration_digest=cast(str, row["configuration_digest"]),
                configuration_bytes=cast(bytes, row["configuration_bytes"]),
                state=cast(RevisionState, row["state"]),
                state_version=cast(int, row["state_version"]),
                created_by=cast(str, row["created_by"]),
                created_at=_parse_timestamp(cast(str, row["created_at"])),
                submitted_at=(
                    None
                    if row["submitted_at"] is None
                    else _parse_timestamp(cast(str, row["submitted_at"]))
                ),
                decided_at=(
                    None
                    if row["decided_at"] is None
                    else _parse_timestamp(cast(str, row["decided_at"]))
                ),
            )
        except ValueError as exc:
            raise ControlPlaneIntegrityError("stored revision failed validation") from exc

    @staticmethod
    def _deployment(row: sqlite3.Row | Mapping[str, Any]) -> ActiveDeployment:
        try:
            return ActiveDeployment(
                tenant_id=cast(str, row["tenant_id"]),
                control_id=cast(str, row["control_id"]),
                revision_id=cast(str, row["revision_id"]),
                configuration_digest=cast(str, row["configuration_digest"]),
                activated_by=cast(str, row["activated_by"]),
                activated_at=_parse_timestamp(cast(str, row["activated_at"])),
                deployment_version=cast(int, row["deployment_version"]),
            )
        except ValueError as exc:
            raise ControlPlaneIntegrityError("stored deployment failed validation") from exc

    @staticmethod
    def _operation(row: sqlite3.Row | Mapping[str, Any]) -> DeploymentOperation:
        def optional_time(name: str) -> datetime | None:
            value = row[name]
            return None if value is None else _parse_timestamp(cast(str, value))

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
                requested_at=_parse_timestamp(cast(str, row["requested_at"])),
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
    def _audit(row: sqlite3.Row) -> AuditEvent:
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
                occurred_at=_parse_timestamp(cast(str, row["occurred_at"])),
                details_digest=cast(str, row["details_digest"]),
                details_bytes=cast(bytes, row["details_bytes"]),
                event_bytes=cast(bytes, row["event_bytes"]),
            )
        except ValueError as exc:
            raise ControlPlaneIntegrityError("stored audit event failed validation") from exc

    def _append_audit(
        self,
        connection: sqlite3.Connection,
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
            raise ControlPlaneStoreError("audit details exceed their canonical profile") from exc
        last = connection.execute(
            """
            SELECT sequence, event_digest
            FROM control_audit_events
            WHERE tenant_id = ?
            ORDER BY sequence DESC
            LIMIT 1
            """,
            (actor.tenant_id,),
        ).fetchone()
        sequence = 1 if last is None else cast(int, last["sequence"]) + 1
        previous = _GENESIS_DIGEST if last is None else cast(str, last["event_digest"])
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
            INSERT INTO control_audit_events (
                tenant_id, sequence, previous_event_digest, event_digest, action,
                object_id, actor_subject, actor_session_digest, occurred_at,
                details_digest, details_bytes, event_bytes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                _timestamp(event.occurred_at),
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
        configuration_bytes = configuration.canonical_bytes()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                latest_row = connection.execute(
                    """
                    SELECT * FROM control_revisions
                    WHERE tenant_id = ? AND control_id = ?
                    ORDER BY generation DESC
                    LIMIT 1
                    """,
                    (configuration.tenant_id, configuration.control_id),
                ).fetchone()
                if latest_row is None:
                    if expected_parent_revision_id is not None:
                        raise ControlPlaneConflict(
                            "first revision cannot declare a parent"
                        )
                    generation = 1
                    parent_revision_id = None
                else:
                    latest = self._revision(latest_row)
                    if latest.state in {"draft", "submitted"}:
                        raise ControlPlaneConflict(
                            "another revision is still in flight"
                        )
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
                    INSERT INTO control_revisions (
                        revision_id, tenant_id, control_id, generation,
                        parent_revision_id, configuration_digest, configuration_bytes,
                        state, state_version, created_by, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'draft', 0, ?, ?)
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
                        _timestamp(created_at),
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
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        except sqlite3.IntegrityError as exc:
            raise ControlPlaneConflict("revision identity already exists") from exc
        finally:
            connection.close()
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
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT * FROM control_revisions
                WHERE tenant_id = ? AND revision_id = ?
                """,
                (tenant_id, revision_id),
            ).fetchone()
        finally:
            connection.close()
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
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT * FROM control_revisions
                WHERE tenant_id = ? AND control_id = ?
                ORDER BY generation DESC
                LIMIT ?
                """,
                (tenant_id, control_id, limit),
            ).fetchall()
        finally:
            connection.close()
        return tuple(self._revision(row) for row in rows)

    def list_controls(
        self,
        *,
        tenant_id: str,
        limit: int = 100,
    ) -> tuple[ControlSummary, ...]:
        """List each control's latest generation and verified active pointer."""

        if type(limit) is not int or limit < 1 or limit > 1_000:
            raise ValueError("control list limit is outside the supported range")
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                WITH latest AS (
                    SELECT revision.*
                    FROM control_revisions AS revision
                    WHERE revision.tenant_id = ?
                      AND revision.generation = (
                          SELECT MAX(candidate.generation)
                          FROM control_revisions AS candidate
                          WHERE candidate.tenant_id = revision.tenant_id
                            AND candidate.control_id = revision.control_id
                      )
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
                LEFT JOIN active_deployments AS deployment
                  ON deployment.tenant_id = latest.tenant_id
                 AND deployment.control_id = latest.control_id
                LEFT JOIN control_revisions AS active_revision
                  ON active_revision.revision_id = deployment.revision_id
                ORDER BY latest.control_id
                LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
        finally:
            connection.close()
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

    def submit(
        self,
        *,
        actor: Actor,
        revision_id: str,
        expected_state_version: int,
        submitted_at: datetime,
    ) -> ConfigurationRevision:
        return self._transition(
            actor=actor,
            revision_id=revision_id,
            expected_state="draft",
            next_state="submitted",
            expected_state_version=expected_state_version,
            occurred_at=submitted_at,
            action="revision-submitted",
        )

    def _transition(
        self,
        *,
        actor: Actor,
        revision_id: str,
        expected_state: RevisionState,
        next_state: RevisionState,
        expected_state_version: int,
        occurred_at: datetime,
        action: AuditAction,
    ) -> ConfigurationRevision:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                current_row = connection.execute(
                    """
                    SELECT * FROM control_revisions
                    WHERE tenant_id = ? AND revision_id = ?
                    """,
                    (actor.tenant_id, revision_id),
                ).fetchone()
                if current_row is None:
                    raise ControlPlaneNotFound("configuration revision was not found")
                current = self._revision(current_row)
                if (
                    current.state != expected_state
                    or current.state_version != expected_state_version
                ):
                    raise ControlPlaneConflict("revision state changed concurrently")
                submitted_at = (
                    _timestamp(occurred_at)
                    if next_state == "submitted"
                    else (
                        None
                        if current.submitted_at is None
                        else _timestamp(current.submitted_at)
                    )
                )
                decided_at = (
                    _timestamp(occurred_at)
                    if next_state in {"approved", "rejected"}
                    else (
                        None
                        if current.decided_at is None
                        else _timestamp(current.decided_at)
                    )
                )
                cursor = connection.execute(
                    """
                    UPDATE control_revisions
                    SET state = ?, state_version = state_version + 1,
                        submitted_at = ?, decided_at = ?
                    WHERE tenant_id = ? AND revision_id = ?
                      AND state = ? AND state_version = ?
                    """,
                    (
                        next_state,
                        submitted_at,
                        decided_at,
                        actor.tenant_id,
                        revision_id,
                        expected_state,
                        expected_state_version,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ControlPlaneConflict("revision state changed concurrently")
                self._append_audit(
                    connection,
                    actor=actor,
                    action=action,
                    object_id=revision_id,
                    occurred_at=occurred_at,
                    details={
                        "control_id": current.control_id,
                        "from_state": expected_state,
                        "generation": current.generation,
                        "to_state": next_state,
                    },
                )
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        finally:
            connection.close()
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
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    """
                    SELECT * FROM control_revisions
                    WHERE tenant_id = ? AND revision_id = ?
                    """,
                    (actor.tenant_id, revision_id),
                ).fetchone()
                if row is None:
                    raise ControlPlaneNotFound("configuration revision was not found")
                current = self._revision(row)
                if current.state != "submitted" or current.state_version != expected_state_version:
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
                    INSERT INTO approval_decisions (
                        decision_id, revision_id, tenant_id, decision, decided_by,
                        decided_at, comment, actor_session_digest
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        approval.decision_id,
                        approval.revision_id,
                        approval.tenant_id,
                        approval.decision,
                        approval.decided_by,
                        _timestamp(approval.decided_at),
                        approval.comment,
                        approval.actor_session_digest,
                    ),
                )
                cursor = connection.execute(
                    """
                    UPDATE control_revisions
                    SET state = ?, state_version = state_version + 1, decided_at = ?
                    WHERE tenant_id = ? AND revision_id = ?
                      AND state = 'submitted' AND state_version = ?
                    """,
                    (
                        decision,
                        _timestamp(decided_at),
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
                        "comment_digest": _sha256(comment.encode("utf-8")),
                        "control_id": current.control_id,
                        "decision_id": approval.decision_id,
                        "generation": current.generation,
                    },
                )
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        except sqlite3.IntegrityError as exc:
            raise ControlPlaneConflict("revision already has an approval decision") from exc
        finally:
            connection.close()
        return (
            self.get_revision(tenant_id=actor.tenant_id, revision_id=revision_id),
            approval,
        )

    def _create_deployment_operation(
        self,
        connection: sqlite3.Connection,
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
            FROM deployment_operations
            WHERE tenant_id = ? AND control_id = ?
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
            FROM deployment_operations
            WHERE tenant_id = ? AND control_id = ? AND state = 'applied'
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
            FROM deployment_operations
            WHERE tenant_id = ? AND control_id = ?
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
            INSERT INTO deployment_operations (
                operation_id, tenant_id, control_id, operation_sequence, kind,
                revision_id, configuration_digest, predecessor_operation_id,
                retry_of_operation_id, requested_by, requested_at,
                requester_session_digest, state, state_version, attempt_count,
                lease_fence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, 0, 0)
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
                _timestamp(requested_at),
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
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    """
                    SELECT * FROM control_revisions
                    WHERE tenant_id = ? AND revision_id = ?
                    """,
                    (actor.tenant_id, revision_id),
                ).fetchone()
                if row is None:
                    raise ControlPlaneNotFound("configuration revision was not found")
                revision = self._revision(row)
                if revision.state != "approved":
                    raise ControlPlaneConflict("only an approved revision can be activated")
                existing_row = connection.execute(
                    """
                    SELECT * FROM active_deployments
                    WHERE tenant_id = ? AND control_id = ?
                    """,
                    (actor.tenant_id, revision.control_id),
                ).fetchone()
                if existing_row is None:
                    if expected_deployment_version is not None:
                        raise ControlPlaneConflict("deployment pointer changed concurrently")
                    deployment_version = 1
                    connection.execute(
                        """
                        INSERT INTO active_deployments (
                            tenant_id, control_id, revision_id, configuration_digest,
                            activated_by, activated_at, deployment_version
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            actor.tenant_id,
                            revision.control_id,
                            revision.revision_id,
                            revision.configuration_digest,
                            actor.subject,
                            _timestamp(activated_at),
                            deployment_version,
                        ),
                    )
                    previous_revision_id = None
                else:
                    existing = self._deployment(existing_row)
                    if expected_deployment_version != existing.deployment_version:
                        raise ControlPlaneConflict("deployment pointer changed concurrently")
                    if existing.revision_id == revision.revision_id:
                        raise ControlPlaneConflict("revision is already active")
                    deployment_version = existing.deployment_version + 1
                    cursor = connection.execute(
                        """
                        UPDATE active_deployments
                        SET revision_id = ?, configuration_digest = ?, activated_by = ?,
                            activated_at = ?, deployment_version = ?
                        WHERE tenant_id = ? AND control_id = ?
                          AND deployment_version = ?
                        """,
                        (
                            revision.revision_id,
                            revision.configuration_digest,
                            actor.subject,
                            _timestamp(activated_at),
                            deployment_version,
                            actor.tenant_id,
                            revision.control_id,
                            existing.deployment_version,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise ControlPlaneConflict("deployment pointer changed concurrently")
                    connection.execute(
                        """
                        UPDATE control_revisions
                        SET state = 'retired', state_version = state_version + 1
                        WHERE tenant_id = ? AND revision_id = ? AND state = 'approved'
                        """,
                        (actor.tenant_id, existing.revision_id),
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
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        except sqlite3.IntegrityError as exc:
            raise ControlPlaneConflict(
                "deployment activation changed concurrently"
            ) from exc
        finally:
            connection.close()
        if operation is None:  # pragma: no cover - transaction cannot skip assignment
            raise ControlPlaneIntegrityError("deployment operation was not persisted")
        if deployment is None:  # pragma: no cover - transaction cannot skip assignment
            raise ControlPlaneIntegrityError("deployment pointer was not persisted")
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
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT
                    deployment.*,
                    revision.configuration_digest AS revision_configuration_digest,
                    revision.tenant_id AS revision_tenant_id,
                    revision.control_id AS revision_control_id,
                    revision.state AS revision_state
                FROM active_deployments AS deployment
                JOIN control_revisions AS revision
                  ON revision.revision_id = deployment.revision_id
                WHERE deployment.tenant_id = ? AND deployment.control_id = ?
                """,
                (tenant_id, control_id),
            ).fetchone()
        finally:
            connection.close()
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
        """Append a rollback request; never rewrite a prior operation or receipt."""

        requested_at = _utc_second(requested_at, label="rollback request time")
        _require_digest(
            expected_predecessor_operation_id,
            label="expected predecessor operation id",
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    """
                    SELECT *
                    FROM control_revisions
                    WHERE tenant_id = ? AND revision_id = ?
                    """,
                    (actor.tenant_id, revision_id),
                ).fetchone()
                if row is None:
                    raise ControlPlaneNotFound("rollback revision was not found")
                revision = self._revision(row)
                if revision.state != "retired":
                    raise ControlPlaneConflict(
                        "rollback target must be a previously retired revision"
                    )
                approved = connection.execute(
                    """
                    SELECT 1
                    FROM approval_decisions
                    WHERE tenant_id = ? AND revision_id = ?
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
                    FROM deployment_operations
                    WHERE tenant_id = ? AND control_id = ? AND state = 'applied'
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
                    expected_predecessor_operation_id=(
                        expected_predecessor_operation_id
                    ),
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
                        "predecessor_operation_id": (
                            operation.predecessor_operation_id
                        ),
                        "revision_id": operation.revision_id,
                    },
                )
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        except sqlite3.IntegrityError as exc:
            raise ControlPlaneConflict(
                "rollback operation changed concurrently"
            ) from exc
        finally:
            connection.close()
        return operation

    def request_deployment_retry(
        self,
        *,
        actor: Actor,
        failed_operation_id: str,
        requested_at: datetime,
    ) -> DeploymentOperation:
        """Create fresh intent after a terminal failure; never reopen old state."""

        requested_at = _utc_second(requested_at, label="deployment retry request time")
        _require_digest(failed_operation_id, label="failed deployment operation id")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                failed_row = connection.execute(
                    """
                    SELECT *
                    FROM deployment_operations
                    WHERE tenant_id = ? AND operation_id = ?
                    """,
                    (actor.tenant_id, failed_operation_id),
                ).fetchone()
                if failed_row is None:
                    raise ControlPlaneNotFound(
                        "failed deployment operation was not found"
                    )
                failed = self._operation(failed_row)
                if failed.state != "failed" or failed.retry_at is not None:
                    raise ControlPlaneConflict(
                        "only a terminal deployment failure can be retried manually"
                    )
                latest_row = connection.execute(
                    """
                    SELECT operation_id
                    FROM deployment_operations
                    WHERE tenant_id = ? AND control_id = ?
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
                    FROM control_revisions
                    WHERE tenant_id = ? AND revision_id = ?
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
                    FROM active_deployments
                    WHERE tenant_id = ? AND control_id = ?
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
                    or selection.configuration_digest
                    != revision.configuration_digest
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
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        except sqlite3.IntegrityError as exc:
            raise ControlPlaneConflict(
                "deployment retry request changed concurrently"
            ) from exc
        finally:
            connection.close()
        return operation

    def get_deployment_operation(
        self,
        *,
        tenant_id: str,
        operation_id: str,
    ) -> DeploymentOperation:
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT *
                FROM deployment_operations
                WHERE tenant_id = ? AND operation_id = ?
                """,
                (tenant_id, operation_id),
            ).fetchone()
        finally:
            connection.close()
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
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT *
                FROM deployment_operations
                WHERE tenant_id = ? AND control_id = ?
                ORDER BY operation_sequence DESC
                LIMIT ?
                """,
                (tenant_id, control_id, limit),
            ).fetchall()
        finally:
            connection.close()
        return tuple(self._operation(row) for row in rows)

    def latest_applied_operation(
        self,
        *,
        tenant_id: str,
        control_id: str,
    ) -> DeploymentOperation:
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT *
                FROM deployment_operations
                WHERE tenant_id = ? AND control_id = ? AND state = 'applied'
                ORDER BY operation_sequence DESC
                LIMIT 1
                """,
                (tenant_id, control_id),
            ).fetchone()
        finally:
            connection.close()
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
        """Claim one eligible operation with an expiring, monotonically fenced lease."""

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
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    """
                    SELECT *
                    FROM deployment_operations
                    WHERE tenant_id = ?
                      AND (
                            (state = 'pending' AND requested_at <= ?)
                            OR (
                                state = 'failed'
                                AND retry_at IS NOT NULL
                                AND retry_at <= ?
                            )
                            OR (
                                state = 'leased'
                                AND lease_expires_at <= ?
                            )
                      )
                    ORDER BY requested_at, control_id, operation_sequence
                    LIMIT 1
                    """,
                    (
                        worker.tenant_id,
                        _timestamp(leased_at),
                        _timestamp(leased_at),
                        _timestamp(leased_at),
                    ),
                ).fetchone()
                if row is None:
                    connection.execute("COMMIT")
                    return None
                current = self._operation(row)
                next_attempt = current.attempt_count + 1
                cursor = connection.execute(
                    """
                    UPDATE deployment_operations
                    SET state = 'leased',
                        state_version = state_version + 1,
                        attempt_count = ?,
                        lease_fence = ?,
                        lease_owner = ?,
                        lease_token_digest = ?,
                        leased_at = ?,
                        lease_expires_at = ?,
                        retry_at = NULL,
                        failed_at = NULL,
                        failure_digest = NULL
                    WHERE tenant_id = ? AND operation_id = ?
                      AND state_version = ?
                      AND (
                            (state = 'pending' AND requested_at <= ?)
                            OR (
                                state = 'failed'
                                AND retry_at IS NOT NULL
                                AND retry_at <= ?
                            )
                            OR (
                                state = 'leased'
                                AND lease_expires_at <= ?
                            )
                      )
                    """,
                    (
                        next_attempt,
                        next_attempt,
                        worker.worker_id,
                        lease_token_digest,
                        _timestamp(leased_at),
                        _timestamp(lease_expires_at),
                        worker.tenant_id,
                        current.operation_id,
                        current.state_version,
                        _timestamp(leased_at),
                        _timestamp(leased_at),
                        _timestamp(leased_at),
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
                        "lease_expires_at": _timestamp(lease_expires_at),
                        "lease_fence": next_attempt,
                        "recovered_from_state": current.state,
                        "worker_id": worker.worker_id,
                    },
                )
                updated = connection.execute(
                    """
                    SELECT *
                    FROM deployment_operations
                    WHERE tenant_id = ? AND operation_id = ?
                    """,
                    (worker.tenant_id, current.operation_id),
                ).fetchone()
                if updated is None:
                    raise ControlPlaneIntegrityError(
                        "leased deployment operation disappeared"
                    )
                operation = self._operation(updated)
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        except sqlite3.IntegrityError as exc:
            raise ControlPlaneConflict(
                "deployment operation lease changed concurrently"
            ) from exc
        finally:
            connection.close()
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
        """Close a live lease only after an exact target acknowledgement."""

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
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    """
                    SELECT *
                    FROM deployment_operations
                    WHERE tenant_id = ? AND operation_id = ?
                    """,
                    (worker.tenant_id, operation_id),
                ).fetchone()
                if row is None:
                    raise ControlPlaneNotFound("deployment operation was not found")
                current = self._operation(row)
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
                    UPDATE deployment_operations
                    SET state = 'applied',
                        state_version = state_version + 1,
                        lease_owner = NULL,
                        lease_token_digest = NULL,
                        leased_at = NULL,
                        lease_expires_at = NULL,
                        applied_at = ?,
                        applied_configuration_digest = ?,
                        target_receipt_digest = ?
                    WHERE tenant_id = ? AND operation_id = ?
                      AND state = 'leased' AND state_version = ?
                      AND lease_owner = ? AND lease_token_digest = ?
                      AND lease_fence = ? AND lease_expires_at > ?
                    """,
                    (
                        _timestamp(applied_at),
                        applied_configuration_digest,
                        target_receipt_digest,
                        worker.tenant_id,
                        operation_id,
                        current.state_version,
                        worker.worker_id,
                        lease_token_digest,
                        lease_fence,
                        _timestamp(applied_at),
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
                    FROM deployment_operations
                    WHERE tenant_id = ? AND operation_id = ?
                    """,
                    (worker.tenant_id, operation_id),
                ).fetchone()
                if updated is None:
                    raise ControlPlaneIntegrityError(
                        "applied deployment operation disappeared"
                    )
                operation = self._operation(updated)
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        finally:
            connection.close()
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
        """Record a secret-free failure digest and optional bounded retry time."""

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
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    """
                    SELECT *
                    FROM deployment_operations
                    WHERE tenant_id = ? AND operation_id = ?
                    """,
                    (worker.tenant_id, operation_id),
                ).fetchone()
                if row is None:
                    raise ControlPlaneNotFound("deployment operation was not found")
                current = self._operation(row)
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
                    UPDATE deployment_operations
                    SET state = 'failed',
                        state_version = state_version + 1,
                        lease_owner = NULL,
                        lease_token_digest = NULL,
                        leased_at = NULL,
                        lease_expires_at = NULL,
                        retry_at = ?,
                        failed_at = ?,
                        failure_digest = ?
                    WHERE tenant_id = ? AND operation_id = ?
                      AND state = 'leased' AND state_version = ?
                      AND lease_owner = ? AND lease_token_digest = ?
                      AND lease_fence = ? AND lease_expires_at > ?
                    """,
                    (
                        None if retry_at is None else _timestamp(retry_at),
                        _timestamp(failed_at),
                        failure_digest,
                        worker.tenant_id,
                        operation_id,
                        current.state_version,
                        worker.worker_id,
                        lease_token_digest,
                        lease_fence,
                        _timestamp(failed_at),
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
                            None if retry_at is None else _timestamp(retry_at)
                        ),
                        "worker_id": worker.worker_id,
                    },
                )
                updated = connection.execute(
                    """
                    SELECT *
                    FROM deployment_operations
                    WHERE tenant_id = ? AND operation_id = ?
                    """,
                    (worker.tenant_id, operation_id),
                ).fetchone()
                if updated is None:
                    raise ControlPlaneIntegrityError(
                        "failed deployment operation disappeared"
                    )
                operation = self._operation(updated)
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        finally:
            connection.close()
        return operation

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
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT * FROM control_audit_events
                WHERE tenant_id = ? AND sequence > ?
                ORDER BY sequence
                LIMIT ?
                """,
                (tenant_id, after_sequence, limit),
            ).fetchall()
        finally:
            connection.close()
        return tuple(self._audit(row) for row in rows)

    def verify_audit_chain(self, *, tenant_id: str) -> tuple[int, str]:
        previous = _GENESIS_DIGEST
        sequence = 0
        while True:
            events = self.audit_events(
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
                    raise ControlPlaneIntegrityError("audit details are invalid") from exc
                previous = event.event_digest
            if len(events) < 1_000:
                break
        return sequence, previous
