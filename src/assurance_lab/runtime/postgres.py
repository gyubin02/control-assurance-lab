"""PostgreSQL deployment target and HA-safe control-run repository.

The database schema is installed separately from
``deploy/postgres/runtime-schema.sql``.  This module deliberately imports
psycopg only in :meth:`PostgresRuntimeCatalog.from_dsn`, so the core package
remains usable without the control-plane extra.
"""

from __future__ import annotations

import importlib
from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from datetime import datetime, timedelta
from itertools import pairwise
from typing import Any, Final, Protocol, cast

from assurance_lab.control_plane.deployment import (
    DeploymentApplyError,
    DeploymentApplyRequest,
    DeploymentOutcomeUnknown,
    DeploymentTargetAcknowledgement,
)
from assurance_lab.control_plane.models import ControlConfiguration
from assurance_lab.evidence.canonical import (
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)
from assurance_lab.runtime.models import (
    ControlRun,
    ControlRunClosure,
    ControlRunExecutionResult,
    ControlRunOutcomeUnknown,
    ControlRunRequest,
    DeployedControl,
    RegisteredControlProfile,
    RuntimeDeploymentReceipt,
    RuntimeWorkerIdentity,
    sha256_digest,
    utc_second,
)
from assurance_lab.runtime.scheduling import due_window_ends

_DEFAULT_STATEMENT_TIMEOUT_MS: Final = 15_000
_DEFAULT_LOCK_TIMEOUT_MS: Final = 5_000
_DEFAULT_MAX_RUN_ATTEMPTS: Final = 8
_CONFLICT_SQLSTATES = frozenset(
    {
        "23503",  # foreign_key_violation
        "23505",  # unique_violation
        "23514",  # check_violation
        "40001",  # serialization_failure
        "40P01",  # deadlock_detected
        "55P03",  # lock_not_available
    }
)


class Cursor(Protocol):
    rowcount: int

    def fetchone(self) -> Mapping[str, Any] | None: ...

    def fetchall(self) -> Sequence[Mapping[str, Any]]: ...


class Connection(Protocol):
    def execute(
        self,
        query: str,
        params: Sequence[object] = (),
    ) -> Cursor: ...

    def transaction(self) -> AbstractContextManager[object]: ...


class ConnectionPool(Protocol):
    def connection(self) -> AbstractContextManager[Connection]: ...


class RuntimeCatalogError(RuntimeError):
    """Base runtime persistence error with no secret-bearing message."""


class RuntimeCatalogConflict(RuntimeCatalogError):
    """A stale fence, lease, or immutable identity was rejected."""


class RuntimeCatalogNotFound(RuntimeCatalogError):
    """A tenant-scoped runtime object does not exist."""


class RuntimeCatalogIntegrityError(RuntimeCatalogError):
    """Persisted state failed independent model or digest validation."""


class RuntimeCatalogOutcomeUnknown(RuntimeCatalogError):
    """A catalog write may have committed and must be retried by identity."""


def _stored_time(value: object) -> datetime:
    if isinstance(value, datetime):
        return utc_second(value, label="stored runtime timestamp")
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise RuntimeCatalogIntegrityError("stored runtime timestamp is invalid") from exc
        return utc_second(parsed, label="stored runtime timestamp")
    raise RuntimeCatalogIntegrityError("stored runtime timestamp is invalid")


def _stored_bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray | memoryview):
        return bytes(value)
    raise RuntimeCatalogIntegrityError("stored runtime binary value is invalid")


def _stored_int(value: object) -> int:
    if type(value) is int:
        return value
    raise RuntimeCatalogIntegrityError("stored runtime integer value is invalid")


def _sqlstate(exc: BaseException) -> str | None:
    state = getattr(exc, "sqlstate", None)
    return state if isinstance(state, str) else None


def _configuration(request: DeploymentApplyRequest) -> ControlConfiguration:
    try:
        configuration = ControlConfiguration.model_validate_json(
            request.configuration_bytes
        )
    except ValueError as exc:
        raise DeploymentApplyError(
            "runtime-configuration-invalid",
            retryable=False,
        ) from exc
    if (
        configuration.canonical_bytes() != request.configuration_bytes
        or configuration.digest != request.configuration_digest
        or configuration.tenant_id != request.tenant_id
        or configuration.control_id != request.control_id
    ):
        raise DeploymentApplyError(
            "runtime-configuration-not-canonical",
            retryable=False,
        )
    return configuration


def _validate_receipt(row: Mapping[str, object]) -> RuntimeDeploymentReceipt:
    receipt_bytes = _stored_bytes(row["receipt_bytes"])
    receipt_digest = str(row["receipt_digest"])
    if sha256_digest(receipt_bytes) != receipt_digest:
        raise RuntimeCatalogIntegrityError("stored deployment receipt digest differs")
    try:
        parsed = strict_json_loads(receipt_bytes)
        if canonical_json_bytes(parsed) != receipt_bytes:
            raise RuntimeCatalogIntegrityError(
                "stored deployment receipt is not canonical JSON"
            )
        receipt = RuntimeDeploymentReceipt.model_validate_json(receipt_bytes)
    except (StrictJSONError, ValueError) as exc:
        raise RuntimeCatalogIntegrityError(
            "stored deployment receipt is invalid"
        ) from exc
    if receipt.digest != receipt_digest:
        raise RuntimeCatalogIntegrityError("stored deployment receipt identity differs")
    bindings = (
        ("tenant_id", receipt.tenant_id),
        ("control_id", receipt.control_id),
        ("operation_id", receipt.operation_id),
        ("revision_id", receipt.revision_id),
        ("configuration_digest", receipt.configuration_digest),
        ("control_profile_id", receipt.control_profile_id),
        ("control_profile_digest", receipt.control_profile_digest),
    )
    if any(key in row and str(row[key]) != value for key, value in bindings):
        raise RuntimeCatalogIntegrityError(
            "stored deployment receipt differs from its catalog row"
        )
    return receipt


def _profile_from_row(row: Mapping[str, object]) -> RegisteredControlProfile:
    try:
        return RegisteredControlProfile(
            tenant_id=str(row["tenant_id"]),
            profile_id=str(row["profile_id"]),
            profile_digest=str(row["profile_digest"]),
            media_type=str(row["media_type"]),
            profile_bytes=_stored_bytes(row["profile_bytes"]),
            registered_at=_stored_time(row["registered_at"]),
            registered_by=str(row["registered_by"]),
        )
    except (ValueError, KeyError, TypeError) as exc:
        raise RuntimeCatalogIntegrityError(
            "stored control profile is invalid"
        ) from exc


def _run_from_row(row: Mapping[str, object]) -> ControlRun:
    request_bytes = _stored_bytes(row["request_bytes"])
    if sha256_digest(request_bytes) != str(row["run_id"]):
        raise RuntimeCatalogIntegrityError("stored control run request digest differs")
    try:
        parsed = strict_json_loads(request_bytes)
        if canonical_json_bytes(parsed) != request_bytes:
            raise RuntimeCatalogIntegrityError(
                "stored control run request is not canonical JSON"
            )
        request = ControlRunRequest.model_validate_json(request_bytes)
        return ControlRun(
            run_id=str(row["run_id"]),
            request=request,
            state=cast(Any, str(row["state"])),
            state_version=_stored_int(row["state_version"]),
            attempt_count=_stored_int(row["attempt_count"]),
            lease_fence=_stored_int(row["lease_fence"]),
            lease_owner=(
                None if row["lease_owner"] is None else str(row["lease_owner"])
            ),
            lease_token_digest=(
                None
                if row["lease_token_digest"] is None
                else str(row["lease_token_digest"])
            ),
            leased_at=(
                None if row["leased_at"] is None else _stored_time(row["leased_at"])
            ),
            lease_expires_at=(
                None
                if row["lease_expires_at"] is None
                else _stored_time(row["lease_expires_at"])
            ),
            retry_at=(
                None if row["retry_at"] is None else _stored_time(row["retry_at"])
            ),
            completed_at=(
                None
                if row["completed_at"] is None
                else _stored_time(row["completed_at"])
            ),
            evidence_digest=(
                None
                if row["evidence_digest"] is None
                else str(row["evidence_digest"])
            ),
            executor_receipt_digest=(
                None
                if row["executor_receipt_digest"] is None
                else str(row["executor_receipt_digest"])
            ),
            closure_digest=(
                None
                if row["closure_digest"] is None
                else str(row["closure_digest"])
            ),
            failed_at=(
                None if row["failed_at"] is None else _stored_time(row["failed_at"])
            ),
            failure_digest=(
                None
                if row["failure_digest"] is None
                else str(row["failure_digest"])
            ),
        )
    except (StrictJSONError, ValueError, KeyError, TypeError) as exc:
        raise RuntimeCatalogIntegrityError("stored control run is invalid") from exc


class PostgresRuntimeCatalog:
    """Real PostgreSQL target catalog and SKIP-LOCKED scheduler store."""

    __slots__ = (
        "_lock_timeout_ms",
        "_max_run_attempts",
        "_owns_pool",
        "_pool",
        "_statement_timeout_ms",
    )

    def __init__(
        self,
        pool: ConnectionPool,
        *,
        statement_timeout_ms: int = _DEFAULT_STATEMENT_TIMEOUT_MS,
        lock_timeout_ms: int = _DEFAULT_LOCK_TIMEOUT_MS,
        max_run_attempts: int = _DEFAULT_MAX_RUN_ATTEMPTS,
        owns_pool: bool = False,
    ) -> None:
        if not callable(getattr(pool, "connection", None)):
            raise TypeError("PostgreSQL pool must provide connection()")
        for label, value in (
            ("statement timeout", statement_timeout_ms),
            ("lock timeout", lock_timeout_ms),
        ):
            if type(value) is not int or value < 100 or value > 120_000:
                raise ValueError(f"{label} is outside the supported range")
        if lock_timeout_ms > statement_timeout_ms:
            raise ValueError("lock timeout cannot exceed statement timeout")
        if (
            type(max_run_attempts) is not int
            or max_run_attempts < 1
            or max_run_attempts > 32
        ):
            raise ValueError("runtime run attempt limit is outside the supported range")
        self._pool = pool
        self._statement_timeout_ms = statement_timeout_ms
        self._lock_timeout_ms = lock_timeout_ms
        self._max_run_attempts = max_run_attempts
        self._owns_pool = owns_pool

    @classmethod
    def from_dsn(
        cls,
        dsn: str,
        *,
        min_size: int = 2,
        max_size: int = 16,
        connect_timeout_seconds: int = 10,
        statement_timeout_ms: int = _DEFAULT_STATEMENT_TIMEOUT_MS,
        lock_timeout_ms: int = _DEFAULT_LOCK_TIMEOUT_MS,
        max_run_attempts: int = _DEFAULT_MAX_RUN_ATTEMPTS,
    ) -> PostgresRuntimeCatalog:
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
            raise RuntimeCatalogError(
                "PostgreSQL support requires the control-plane optional dependency"
            ) from exc
        pool_class = pool_module.ConnectionPool
        pool = pool_class(
            conninfo=dsn,
            min_size=min_size,
            max_size=max_size,
            kwargs={
                "autocommit": False,
                "connect_timeout": connect_timeout_seconds,
                "row_factory": rows_module.dict_row,
            },
            open=True,
        )
        return cls(
            cast(ConnectionPool, pool),
            statement_timeout_ms=statement_timeout_ms,
            lock_timeout_ms=lock_timeout_ms,
            max_run_attempts=max_run_attempts,
            owns_pool=True,
        )

    @property
    def max_run_attempts(self) -> int:
        return self._max_run_attempts

    def close(self) -> None:
        if self._owns_pool:
            close = getattr(self._pool, "close", None)
            if callable(close):
                close()
            self._owns_pool = False

    def register_control_profile(
        self,
        profile: RegisteredControlProfile,
    ) -> RegisteredControlProfile:
        """Append one immutable profile version or reopen its exact identity.

        The content digest is the idempotency identity.  Re-registering the
        same bytes under the same profile id returns the original audit row;
        a digest alias or media-type collision is rejected rather than
        rewriting history.
        """

        if not isinstance(profile, RegisteredControlProfile):
            raise TypeError("runtime profile registration requires a profile")
        try:
            validated = RegisteredControlProfile.model_validate(
                profile.model_dump(mode="python")
            )
        except ValueError as exc:
            raise RuntimeCatalogIntegrityError(
                "control profile registration is invalid"
            ) from exc
        try:
            with self._pool.connection() as connection, connection.transaction():
                self._prepare(connection, validated.tenant_id)
                connection.execute(
                    """
                    SELECT pg_advisory_xact_lock(
                        hashtextextended(
                            'control-assurance:runtime-profile-registry:'
                                || %s,
                            0
                        )
                    )
                    """,
                    (validated.tenant_id,),
                )
                existing_row = connection.execute(
                    """
                    SELECT *
                    FROM control_assurance_runtime.control_profiles
                    WHERE tenant_id = %s AND profile_digest = %s
                    """,
                    (validated.tenant_id, validated.profile_digest),
                ).fetchone()
                if existing_row is not None:
                    existing = _profile_from_row(existing_row)
                    if (
                        existing.profile_id != validated.profile_id
                        or existing.media_type != validated.media_type
                        or existing.profile_bytes != validated.profile_bytes
                    ):
                        raise RuntimeCatalogConflict(
                            "control profile content identity collides"
                        )
                    return existing
                inserted = connection.execute(
                    """
                    INSERT INTO control_assurance_runtime.control_profiles (
                        tenant_id,
                        profile_id,
                        profile_digest,
                        media_type,
                        profile_bytes,
                        registered_at,
                        registered_by
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING *
                    """,
                    (
                        validated.tenant_id,
                        validated.profile_id,
                        validated.profile_digest,
                        validated.media_type,
                        validated.profile_bytes,
                        validated.registered_at,
                        validated.registered_by,
                    ),
                ).fetchone()
                if inserted is None:
                    raise RuntimeCatalogIntegrityError(
                        "database did not return registered control profile"
                    )
                stored = _profile_from_row(inserted)
            return stored
        except RuntimeCatalogError:
            raise
        except Exception as exc:
            if _sqlstate(exc) in _CONFLICT_SQLSTATES:
                raise RuntimeCatalogConflict(
                    "control profile registration was rejected"
                ) from exc
            raise RuntimeCatalogOutcomeUnknown(
                "control profile registration outcome is unknown"
            ) from exc

    def control_profile(
        self,
        *,
        tenant_id: str,
        profile_digest: str,
    ) -> RegisteredControlProfile:
        """Reopen and independently verify one content-addressed profile."""

        try:
            with self._pool.connection() as connection, connection.transaction():
                self._prepare(connection, tenant_id)
                row = connection.execute(
                    """
                    SELECT *
                    FROM control_assurance_runtime.control_profiles
                    WHERE tenant_id = %s AND profile_digest = %s
                    """,
                    (tenant_id, profile_digest),
                ).fetchone()
            if row is None:
                raise RuntimeCatalogNotFound("runtime control profile not found")
            profile = _profile_from_row(row)
            if profile.tenant_id != tenant_id:
                raise RuntimeCatalogIntegrityError(
                    "stored control profile crosses its tenant boundary"
                )
            return profile
        except RuntimeCatalogError:
            raise
        except Exception as exc:
            raise RuntimeCatalogError("runtime control profile read failed") from exc

    def profile_bytes(
        self,
        *,
        tenant_id: str,
        profile_digest: str,
    ) -> bytes:
        """Return the exact canonical bytes addressed by a profile digest."""

        return self.control_profile(
            tenant_id=tenant_id,
            profile_digest=profile_digest,
        ).profile_bytes

    def _prepare(self, connection: Connection, tenant_id: str) -> None:
        connection.execute(
            """
            SELECT control_assurance_runtime.assert_session_principal(
                %s,
                current_user::text,
                control_assurance_runtime.session_principal_kind(),
                current_user::text,
                session_user::text
            )
            """,
            (tenant_id,),
        )
        connection.execute(
            "SELECT set_config('statement_timeout', %s, true)",
            (f"{self._statement_timeout_ms}ms",),
        )
        connection.execute(
            "SELECT set_config('lock_timeout', %s, true)",
            (f"{self._lock_timeout_ms}ms",),
        )

    @staticmethod
    def _control_lock(
        connection: Connection,
        tenant_id: str,
        control_id: str,
    ) -> None:
        connection.execute(
            """
            SELECT pg_advisory_xact_lock(
                hashtextextended(
                    'control-assurance:runtime-control:' || %s || ':' || %s,
                    0
                )
            )
            """,
            (tenant_id, control_id),
        )

    @staticmethod
    def _assert_existing_deployment(
        row: Mapping[str, object],
        request: DeploymentApplyRequest,
        configuration: ControlConfiguration,
    ) -> None:
        exact = (
            str(row["tenant_id"]) == request.tenant_id
            and str(row["control_id"]) == request.control_id
            and _stored_int(row["operation_sequence"]) == request.operation_sequence
            and str(row["revision_id"]) == request.revision_id
            and str(row["configuration_digest"]) == request.configuration_digest
            and _stored_bytes(row["configuration_bytes"])
            == request.configuration_bytes
            and str(row["control_profile_id"])
            == configuration.control_profile_id
            and str(row["control_profile_digest"])
            == configuration.control_profile_digest
        )
        if not exact:
            raise DeploymentApplyError(
                "runtime-operation-id-collision",
                retryable=False,
            )

    def ensure_applied(
        self,
        request: DeploymentApplyRequest,
    ) -> DeploymentTargetAcknowledgement:
        """Idempotently make one exact canonical configuration current.

        Any unclassified database exception is reported as outcome-unknown.
        Returning success after a possibly failed COMMIT is forbidden.
        """

        if not isinstance(request, DeploymentApplyRequest):
            raise TypeError("runtime target requires DeploymentApplyRequest")
        configuration = _configuration(request)
        try:
            with self._pool.connection() as connection, connection.transaction():
                self._prepare(connection, request.tenant_id)
                self._control_lock(
                    connection,
                    request.tenant_id,
                    request.control_id,
                )
                profile_row = connection.execute(
                    """
                    SELECT *
                    FROM control_assurance_runtime.control_profiles
                    WHERE tenant_id = %s
                      AND profile_id = %s
                      AND profile_digest = %s
                    """,
                    (
                        request.tenant_id,
                        configuration.control_profile_id,
                        configuration.control_profile_digest,
                    ),
                ).fetchone()
                if profile_row is None:
                    raise DeploymentApplyError(
                        "runtime-control-profile-not-found",
                        retryable=False,
                    )
                profile = _profile_from_row(profile_row)
                if (
                    profile.tenant_id != request.tenant_id
                    or profile.profile_id
                    != configuration.control_profile_id
                    or profile.profile_digest
                    != configuration.control_profile_digest
                ):
                    raise RuntimeCatalogIntegrityError(
                        "control profile differs from deployment configuration"
                    )
                existing = connection.execute(
                    """
                        SELECT history.*, fence.highest_lease_fence_seen
                        FROM control_assurance_runtime.deployment_history AS history
                        JOIN control_assurance_runtime.deployment_operation_fences
                            AS fence
                          ON fence.operation_id = history.operation_id
                        WHERE history.tenant_id = %s
                          AND history.operation_id = %s
                        """,
                    (request.tenant_id, request.operation_id),
                ).fetchone()
                current = connection.execute(
                    """
                        SELECT *
                        FROM control_assurance_runtime.current_deployed_controls
                        WHERE tenant_id = %s AND control_id = %s
                        FOR UPDATE
                        """,
                    (request.tenant_id, request.control_id),
                ).fetchone()
                if existing is not None:
                    self._assert_existing_deployment(
                        existing,
                        request,
                        configuration,
                    )
                    if (
                        current is None
                        or str(current["operation_id"]) != request.operation_id
                    ):
                        raise DeploymentApplyError(
                            "runtime-deployment-superseded",
                            retryable=False,
                        )
                    highest = int(existing["highest_lease_fence_seen"])
                    if request.lease_fence < highest:
                        raise DeploymentApplyError(
                            "runtime-stale-deployment-fence",
                            retryable=False,
                        )
                    if request.lease_fence > highest:
                        connection.execute(
                            """
                                UPDATE control_assurance_runtime
                                    .deployment_operation_fences
                                SET highest_lease_fence_seen = %s
                                WHERE tenant_id = %s AND operation_id = %s
                                """,
                            (
                                request.lease_fence,
                                request.tenant_id,
                                request.operation_id,
                            ),
                        )
                    receipt = _validate_receipt(existing)
                    return DeploymentTargetAcknowledgement(
                        operation_id=request.operation_id,
                        lease_fence=request.lease_fence,
                        applied_configuration_digest=request.configuration_digest,
                        target_receipt_digest=receipt.digest,
                    )
                if current is not None:
                    current_sequence = int(current["operation_sequence"])
                    if request.operation_sequence <= current_sequence:
                        raise DeploymentApplyError(
                            "runtime-stale-deployment-sequence",
                            retryable=False,
                        )
                applied_row = connection.execute(
                    """
                        SELECT date_trunc(
                            'second',
                            transaction_timestamp()
                        ) AS applied_at
                        """
                ).fetchone()
                if applied_row is None:
                    raise RuntimeCatalogIntegrityError(
                        "database did not return deployment time"
                    )
                applied_at = _stored_time(applied_row["applied_at"])
                if (
                    current is not None
                    and applied_at <= _stored_time(current["applied_at"])
                ):
                    # Runtime records use whole UTC seconds. Two legitimate
                    # deployments may commit within one wall-clock second, so
                    # advance the logical application time to preserve a
                    # non-empty, deterministic validity interval.
                    applied_at = _stored_time(current["applied_at"]) + timedelta(
                        seconds=1
                    )
                previous_operation_id = (
                    None if current is None else str(current["operation_id"])
                )
                previous_receipt_digest = (
                    None
                    if current is None
                    else str(current["deployment_receipt_digest"])
                )
                receipt = RuntimeDeploymentReceipt(
                    tenant_id=request.tenant_id,
                    control_id=request.control_id,
                    operation_id=request.operation_id,
                    operation_sequence=request.operation_sequence,
                    lease_fence_at_commit=request.lease_fence,
                    revision_id=request.revision_id,
                    configuration_digest=request.configuration_digest,
                    control_profile_id=configuration.control_profile_id,
                    control_profile_digest=configuration.control_profile_digest,
                    previous_operation_id=previous_operation_id,
                    previous_receipt_digest=previous_receipt_digest,
                    applied_at=applied_at,
                )
                receipt_bytes = receipt.canonical_bytes()
                schedule = configuration.schedule
                connection.execute(
                    """
                        INSERT INTO
                            control_assurance_runtime.deployment_history (
                                operation_id,
                                tenant_id,
                                control_id,
                                operation_sequence,
                                revision_id,
                                configuration_digest,
                                configuration_bytes,
                                control_profile_id,
                                control_profile_digest,
                                enabled,
                                interval_seconds,
                                collection_lag_seconds,
                                window_seconds,
                                lease_fence_at_commit,
                                previous_operation_id,
                                previous_receipt_digest,
                                receipt_digest,
                                receipt_bytes,
                                applied_at
                            )
                        VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s
                        )
                        """,
                    (
                        request.operation_id,
                        request.tenant_id,
                        request.control_id,
                        request.operation_sequence,
                        request.revision_id,
                        request.configuration_digest,
                        request.configuration_bytes,
                        configuration.control_profile_id,
                        configuration.control_profile_digest,
                        configuration.enabled,
                        schedule.interval_seconds,
                        schedule.collection_lag_seconds,
                        schedule.window_seconds,
                        request.lease_fence,
                        previous_operation_id,
                        previous_receipt_digest,
                        receipt.digest,
                        receipt_bytes,
                        applied_at,
                    ),
                )
                connection.execute(
                    """
                        INSERT INTO control_assurance_runtime
                            .deployment_operation_fences (
                                operation_id,
                                tenant_id,
                                control_id,
                                highest_lease_fence_seen
                            )
                        VALUES (%s, %s, %s, %s)
                        """,
                    (
                        request.operation_id,
                        request.tenant_id,
                        request.control_id,
                        request.lease_fence,
                    ),
                )
                current_values = (
                    request.operation_id,
                    request.operation_sequence,
                    request.revision_id,
                    request.configuration_digest,
                    request.configuration_bytes,
                    configuration.control_profile_id,
                    configuration.control_profile_digest,
                    configuration.enabled,
                    schedule.interval_seconds,
                    schedule.collection_lag_seconds,
                    schedule.window_seconds,
                    receipt.digest,
                    request.lease_fence,
                    applied_at,
                    request.tenant_id,
                    request.control_id,
                )
                if current is None:
                    connection.execute(
                        """
                            INSERT INTO control_assurance_runtime
                                .current_deployed_controls (
                                    operation_id,
                                    operation_sequence,
                                    revision_id,
                                    configuration_digest,
                                    configuration_bytes,
                                    control_profile_id,
                                    control_profile_digest,
                                    enabled,
                                    interval_seconds,
                                    collection_lag_seconds,
                                    window_seconds,
                                    deployment_receipt_digest,
                                    lease_fence_at_commit,
                                    applied_at,
                                    tenant_id,
                                    control_id
                                )
                            VALUES (
                                %s, %s, %s, %s, %s, %s, %s,
                                %s, %s, %s, %s, %s, %s, %s,
                                %s, %s
                            )
                            """,
                        current_values,
                    )
                else:
                    connection.execute(
                        """
                            UPDATE control_assurance_runtime
                                .current_deployed_controls
                            SET operation_id = %s,
                                operation_sequence = %s,
                                revision_id = %s,
                                configuration_digest = %s,
                                configuration_bytes = %s,
                                control_profile_id = %s,
                                control_profile_digest = %s,
                                enabled = %s,
                                interval_seconds = %s,
                                collection_lag_seconds = %s,
                                window_seconds = %s,
                                deployment_receipt_digest = %s,
                                lease_fence_at_commit = %s,
                                applied_at = %s
                            WHERE tenant_id = %s AND control_id = %s
                            """,
                        current_values,
                    )
            return DeploymentTargetAcknowledgement(
                operation_id=request.operation_id,
                lease_fence=request.lease_fence,
                applied_configuration_digest=request.configuration_digest,
                target_receipt_digest=receipt.digest,
            )
        except DeploymentApplyError:
            raise
        except RuntimeCatalogIntegrityError as exc:
            raise DeploymentApplyError(
                "runtime-catalog-integrity",
                retryable=False,
            ) from exc
        except Exception as exc:
            if _sqlstate(exc) in _CONFLICT_SQLSTATES:
                raise DeploymentApplyError(
                    "runtime-deployment-conflict",
                    retryable=False,
                ) from exc
            raise DeploymentOutcomeUnknown(
                "runtime-deployment-outcome-unknown"
            ) from exc

    def deployment_receipt(
        self,
        *,
        tenant_id: str,
        operation_id: str,
    ) -> RuntimeDeploymentReceipt:
        try:
            with self._pool.connection() as connection, connection.transaction():
                self._prepare(connection, tenant_id)
                row = connection.execute(
                    """
                        SELECT *
                        FROM control_assurance_runtime.deployment_history
                        WHERE tenant_id = %s AND operation_id = %s
                        """,
                    (tenant_id, operation_id),
                ).fetchone()
            if row is None:
                raise RuntimeCatalogNotFound("runtime deployment receipt not found")
            return _validate_receipt(row)
        except RuntimeCatalogError:
            raise
        except Exception as exc:
            raise RuntimeCatalogError("runtime deployment receipt read failed") from exc

    def current_deployed_control(
        self,
        *,
        tenant_id: str,
        control_id: str,
    ) -> DeployedControl:
        try:
            with self._pool.connection() as connection, connection.transaction():
                self._prepare(connection, tenant_id)
                row = connection.execute(
                    """
                        SELECT current.*, fence.highest_lease_fence_seen
                        FROM control_assurance_runtime.current_deployed_controls
                            AS current
                        JOIN control_assurance_runtime.deployment_operation_fences
                            AS fence
                          ON fence.operation_id = current.operation_id
                        WHERE current.tenant_id = %s
                          AND current.control_id = %s
                        """,
                    (tenant_id, control_id),
                ).fetchone()
            if row is None:
                raise RuntimeCatalogNotFound("deployed control not found")
            return DeployedControl(
                tenant_id=str(row["tenant_id"]),
                control_id=str(row["control_id"]),
                operation_id=str(row["operation_id"]),
                operation_sequence=int(row["operation_sequence"]),
                revision_id=str(row["revision_id"]),
                configuration_digest=str(row["configuration_digest"]),
                configuration_bytes=_stored_bytes(row["configuration_bytes"]),
                control_profile_id=str(row["control_profile_id"]),
                control_profile_digest=str(row["control_profile_digest"]),
                deployment_receipt_digest=str(
                    row["deployment_receipt_digest"]
                ),
                lease_fence_at_commit=int(row["lease_fence_at_commit"]),
                highest_lease_fence_seen=int(row["highest_lease_fence_seen"]),
                applied_at=_stored_time(row["applied_at"]),
            )
        except RuntimeCatalogError:
            raise
        except (ValueError, KeyError, TypeError) as exc:
            raise RuntimeCatalogIntegrityError(
                "stored deployed control is invalid"
            ) from exc
        except Exception as exc:
            raise RuntimeCatalogError("deployed control read failed") from exc

    def deployment_history_for_control(
        self,
        *,
        tenant_id: str,
        control_id: str,
    ) -> tuple[DeployedControl, ...]:
        """Read and independently validate immutable deployment history."""

        try:
            with self._pool.connection() as connection, connection.transaction():
                self._prepare(connection, tenant_id)
                rows = connection.execute(
                    """
                        SELECT history.*,
                               history.receipt_digest
                                    AS deployment_receipt_digest,
                               fence.highest_lease_fence_seen
                        FROM control_assurance_runtime.deployment_history
                            AS history
                        JOIN control_assurance_runtime
                            .deployment_operation_fences AS fence
                          ON fence.operation_id = history.operation_id
                        WHERE history.tenant_id = %s
                          AND history.control_id = %s
                        ORDER BY history.operation_sequence
                        """,
                    (tenant_id, control_id),
                ).fetchall()
            result = tuple(
                DeployedControl(
                    tenant_id=str(row["tenant_id"]),
                    control_id=str(row["control_id"]),
                    operation_id=str(row["operation_id"]),
                    operation_sequence=_stored_int(row["operation_sequence"]),
                    revision_id=str(row["revision_id"]),
                    configuration_digest=str(row["configuration_digest"]),
                    configuration_bytes=_stored_bytes(row["configuration_bytes"]),
                    control_profile_id=str(row["control_profile_id"]),
                    control_profile_digest=str(row["control_profile_digest"]),
                    deployment_receipt_digest=str(
                        row["deployment_receipt_digest"]
                    ),
                    lease_fence_at_commit=_stored_int(
                        row["lease_fence_at_commit"]
                    ),
                    highest_lease_fence_seen=_stored_int(
                        row["highest_lease_fence_seen"]
                    ),
                    applied_at=_stored_time(row["applied_at"]),
                )
                for row in rows
            )
            if any(
                later.operation_sequence <= earlier.operation_sequence
                or later.applied_at <= earlier.applied_at
                for earlier, later in pairwise(result)
            ):
                raise RuntimeCatalogIntegrityError(
                    "runtime deployment history is not strictly ordered"
                )
            return result
        except RuntimeCatalogError:
            raise
        except (ValueError, KeyError, TypeError) as exc:
            raise RuntimeCatalogIntegrityError(
                "stored runtime deployment history is invalid"
            ) from exc
        except Exception as exc:
            raise RuntimeCatalogError("runtime deployment history read failed") from exc

    def materialize_due_runs(
        self,
        *,
        tenant_id: str,
        through: datetime | None = None,
        max_deployments: int = 10_000,
        max_windows_per_deployment: int = 10_000,
        max_new_runs: int = 10_000,
    ) -> int:
        """Idempotently append all bounded due runs for deployment intervals.

        ``None`` uses PostgreSQL's transaction clock as the horizon.  Long-lived
        workers should prefer that mode so a host clock a fraction ahead of the
        database cannot manufacture future work or turn harmless clock skew
        into an availability failure.  An explicit past horizon remains useful
        for bounded operator backfills and deterministic tests.
        """

        horizon = (
            None
            if through is None
            else utc_second(through, label="materialization horizon")
        )
        for label, value, maximum in (
            ("deployment scan", max_deployments, 100_000),
            ("window scan", max_windows_per_deployment, 100_000),
            ("new run limit", max_new_runs, 100_000),
        ):
            if type(value) is not int or value < 1 or value > maximum:
                raise ValueError(f"{label} is outside the supported range")
        try:
            with self._pool.connection() as connection, connection.transaction():
                self._prepare(connection, tenant_id)
                timestamp_row = connection.execute(
                    """
                        SELECT date_trunc(
                            'second',
                            transaction_timestamp()
                        ) AS materialized_at
                        """
                ).fetchone()
                if timestamp_row is None:
                    raise RuntimeCatalogIntegrityError(
                        "database did not return materialization time"
                    )
                materialized_at = _stored_time(
                    timestamp_row["materialized_at"]
                )
                if horizon is None:
                    horizon = materialized_at
                elif horizon > materialized_at:
                    raise RuntimeCatalogConflict(
                        "materialization horizon cannot be in the future"
                    )
                rows = connection.execute(
                    """
                        SELECT *
                        FROM (
                            SELECT history.*,
                                lead(history.applied_at) OVER (
                                    PARTITION BY
                                        history.tenant_id,
                                        history.control_id
                                    ORDER BY
                                        history.operation_sequence
                                ) AS superseded_at
                            FROM control_assurance_runtime.deployment_history
                                AS history
                            WHERE history.tenant_id = %s
                        ) AS deployments
                        ORDER BY
                            control_id,
                            operation_sequence
                        LIMIT %s
                        """,
                    (tenant_id, max_deployments + 1),
                ).fetchall()
                if len(rows) > max_deployments:
                    raise RuntimeCatalogConflict(
                        "runtime deployment scan exceeds its bounded limit"
                    )
                created = 0
                for row in rows:
                    configuration_bytes = _stored_bytes(
                        row["configuration_bytes"]
                    )
                    configuration = ControlConfiguration.model_validate_json(
                        configuration_bytes
                    )
                    if (
                        configuration.canonical_bytes()
                        != configuration_bytes
                        or configuration.digest
                        != str(row["configuration_digest"])
                        or configuration.tenant_id != tenant_id
                        or configuration.control_id
                        != str(row["control_id"])
                        or configuration.control_profile_id
                        != str(row["control_profile_id"])
                        or configuration.control_profile_digest
                        != str(row["control_profile_digest"])
                    ):
                        raise RuntimeCatalogIntegrityError(
                            "deployment history configuration is invalid"
                        )
                    superseded_at = (
                        None
                        if row["superseded_at"] is None
                        else _stored_time(row["superseded_at"])
                    )
                    window_ends = due_window_ends(
                        configuration,
                        applied_at=_stored_time(row["applied_at"]),
                        superseded_at=superseded_at,
                        through=horizon,
                        limit=max_windows_per_deployment,
                    )
                    for window_end in window_ends:
                        request = ControlRunRequest(
                            tenant_id=tenant_id,
                            control_id=configuration.control_id,
                            deployment_operation_id=str(row["operation_id"]),
                            deployment_operation_sequence=int(
                                row["operation_sequence"]
                            ),
                            deployment_receipt_digest=str(
                                row["receipt_digest"]
                            ),
                            control_profile_id=(
                                configuration.control_profile_id
                            ),
                            control_profile_digest=(
                                configuration.control_profile_digest
                            ),
                            revision_id=str(row["revision_id"]),
                            configuration_digest=configuration.digest,
                            window_start=window_end
                            - timedelta(
                                seconds=configuration.schedule.window_seconds
                            ),
                            window_end=window_end,
                            due_at=window_end
                            + timedelta(
                                seconds=(
                                    configuration.schedule
                                    .collection_lag_seconds
                                )
                            ),
                        )
                        inserted = connection.execute(
                            """
                                INSERT INTO
                                    control_assurance_runtime.control_runs (
                                        run_id,
                                        tenant_id,
                                        control_id,
                                        deployment_operation_id,
                                        deployment_operation_sequence,
                                        deployment_receipt_digest,
                                        revision_id,
                                        configuration_digest,
                                        control_profile_id,
                                        control_profile_digest,
                                        request_bytes,
                                        window_start,
                                        window_end,
                                        due_at,
                                        materialized_at,
                                        state
                                    )
                                VALUES (
                                    %s, %s, %s, %s, %s, %s, %s,
                                    %s, %s, %s, %s, %s, %s, %s,
                                    %s, 'pending'
                                )
                                ON CONFLICT (run_id) DO NOTHING
                                """,
                            (
                                request.run_id,
                                request.tenant_id,
                                request.control_id,
                                request.deployment_operation_id,
                                request.deployment_operation_sequence,
                                request.deployment_receipt_digest,
                                request.revision_id,
                                request.configuration_digest,
                                request.control_profile_id,
                                request.control_profile_digest,
                                request.canonical_bytes(),
                                request.window_start,
                                request.window_end,
                                request.due_at,
                                materialized_at,
                            ),
                        )
                        created += inserted.rowcount
                        if created > max_new_runs:
                            raise RuntimeCatalogConflict(
                                "new control runs exceed the bounded limit"
                            )
            return created
        except RuntimeCatalogError:
            raise
        except (ValueError, KeyError, TypeError) as exc:
            raise RuntimeCatalogIntegrityError(
                "runtime materialization input or state is invalid"
            ) from exc
        except Exception as exc:
            raise RuntimeCatalogError("runtime materialization failed") from exc

    def _terminalize_exhausted_lease(
        self,
        connection: Connection,
        *,
        tenant_id: str,
        failed_at: datetime,
    ) -> None:
        row = connection.execute(
            """
            SELECT *
            FROM control_assurance_runtime.control_runs
            WHERE tenant_id = %s
              AND state = 'leased'
              AND lease_expires_at <= %s
              AND attempt_count >= %s
            ORDER BY due_at, run_id
            FOR UPDATE SKIP LOCKED
            LIMIT 1
            """,
            (tenant_id, failed_at, self._max_run_attempts),
        ).fetchone()
        if row is None:
            return
        failure_digest = sha256_digest(
            canonical_json_bytes(
                {
                    "attempt_count": int(row["attempt_count"]),
                    "code": "lease-expired-attempt-limit",
                    "lease_fence": int(row["lease_fence"]),
                    "retryable": False,
                    "run_id": str(row["run_id"]),
                }
            )
        )
        connection.execute(
            """
            INSERT INTO control_assurance_runtime.control_run_outcomes (
                tenant_id,
                run_id,
                lease_fence,
                outcome,
                recorded_at,
                failure_digest
            )
            VALUES (%s, %s, %s, 'failed', %s, %s)
            """,
            (
                tenant_id,
                str(row["run_id"]),
                int(row["lease_fence"]),
                failed_at,
                failure_digest,
            ),
        )
        connection.execute(
            """
            UPDATE control_assurance_runtime.control_runs
            SET state = 'failed',
                state_version = state_version + 1,
                lease_owner = NULL,
                lease_token_digest = NULL,
                leased_at = NULL,
                lease_expires_at = NULL,
                retry_at = NULL,
                failed_at = %s,
                failure_digest = %s
            WHERE tenant_id = %s
              AND run_id = %s
              AND state = 'leased'
              AND lease_fence = %s
            """,
            (
                failed_at,
                failure_digest,
                tenant_id,
                str(row["run_id"]),
                int(row["lease_fence"]),
            ),
        )

    def claim_next_run(
        self,
        *,
        worker: RuntimeWorkerIdentity,
        lease_token_digest: str,
        leased_at: datetime,
        lease_ttl_seconds: int,
    ) -> ControlRun | None:
        if not isinstance(worker, RuntimeWorkerIdentity):
            raise TypeError("runtime worker identity is required")
        claimed_at = utc_second(leased_at, label="run lease time")
        if (
            type(lease_ttl_seconds) is not int
            or lease_ttl_seconds < 15
            or lease_ttl_seconds > 3_600
        ):
            raise ValueError("run lease TTL is outside the supported range")
        if (
            type(lease_token_digest) is not str
            or len(lease_token_digest) != 71
            or not lease_token_digest.startswith("sha256:")
        ):
            raise ValueError("run lease token digest is invalid")
        expires_at = claimed_at + timedelta(seconds=lease_ttl_seconds)
        try:
            with self._pool.connection() as connection, connection.transaction():
                self._prepare(connection, worker.tenant_id)
                self._terminalize_exhausted_lease(
                    connection,
                    tenant_id=worker.tenant_id,
                    failed_at=claimed_at,
                )
                row = connection.execute(
                    """
                        SELECT *
                        FROM control_assurance_runtime.control_runs
                        WHERE tenant_id = %s
                          AND due_at <= %s
                          AND attempt_count < %s
                          AND (
                              state = 'pending'
                              OR (
                                  state = 'leased'
                                  AND lease_expires_at <= %s
                              )
                              OR (
                                  state = 'failed'
                                  AND retry_at IS NOT NULL
                                  AND retry_at <= %s
                              )
                          )
                        ORDER BY due_at, run_id
                        FOR UPDATE SKIP LOCKED
                        LIMIT 1
                        """,
                    (
                        worker.tenant_id,
                        claimed_at,
                        self._max_run_attempts,
                        claimed_at,
                        claimed_at,
                    ),
                ).fetchone()
                if row is None:
                    return None
                new_fence = int(row["lease_fence"]) + 1
                new_attempt = int(row["attempt_count"]) + 1
                updated = connection.execute(
                    """
                        UPDATE control_assurance_runtime.control_runs
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
                        WHERE tenant_id = %s AND run_id = %s
                        RETURNING *
                        """,
                    (
                        new_attempt,
                        new_fence,
                        worker.worker_id,
                        lease_token_digest,
                        claimed_at,
                        expires_at,
                        worker.tenant_id,
                        str(row["run_id"]),
                    ),
                ).fetchone()
                if updated is None:
                    raise RuntimeCatalogConflict("control run lease was lost")
                connection.execute(
                    """
                        INSERT INTO
                            control_assurance_runtime.control_run_claims (
                                tenant_id,
                                run_id,
                                lease_fence,
                                attempt_count,
                                worker_id,
                                worker_credential_digest,
                                lease_token_digest,
                                leased_at,
                                lease_expires_at
                            )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                    (
                        worker.tenant_id,
                        str(row["run_id"]),
                        new_fence,
                        new_attempt,
                        worker.worker_id,
                        worker.credential_digest,
                        lease_token_digest,
                        claimed_at,
                        expires_at,
                    ),
                )
            return _run_from_row(updated)
        except RuntimeCatalogError:
            raise
        except Exception as exc:
            raise RuntimeCatalogError("control run claim failed") from exc

    def configuration_bytes_for_run(
        self,
        *,
        tenant_id: str,
        run_id: str,
    ) -> bytes:
        try:
            with self._pool.connection() as connection, connection.transaction():
                self._prepare(connection, tenant_id)
                row = connection.execute(
                    """
                        SELECT history.configuration_bytes,
                               history.configuration_digest,
                               history.control_profile_id,
                               history.control_profile_digest
                        FROM control_assurance_runtime.control_runs AS run
                        JOIN control_assurance_runtime.deployment_history AS history
                          ON history.operation_id =
                                run.deployment_operation_id
                        WHERE run.tenant_id = %s AND run.run_id = %s
                          AND history.tenant_id = run.tenant_id
                          AND history.control_id = run.control_id
                          AND history.configuration_digest =
                                run.configuration_digest
                          AND history.control_profile_id =
                                run.control_profile_id
                          AND history.control_profile_digest =
                                run.control_profile_digest
                        """,
                    (tenant_id, run_id),
                ).fetchone()
            if row is None:
                raise RuntimeCatalogNotFound("control run configuration not found")
            value = _stored_bytes(row["configuration_bytes"])
            configuration = ControlConfiguration.model_validate_json(value)
            if (
                configuration.canonical_bytes() != value
                or configuration.digest != str(row["configuration_digest"])
                or configuration.control_profile_id
                != str(row["control_profile_id"])
                or configuration.control_profile_digest
                != str(row["control_profile_digest"])
            ):
                raise RuntimeCatalogIntegrityError(
                    "control run configuration is invalid"
                )
            return value
        except RuntimeCatalogError:
            raise
        except (ValueError, KeyError, TypeError) as exc:
            raise RuntimeCatalogIntegrityError(
                "control run configuration is invalid"
            ) from exc
        except Exception as exc:
            raise RuntimeCatalogError("control run configuration read failed") from exc

    @staticmethod
    def _require_current_lease(
        row: Mapping[str, object],
        *,
        worker: RuntimeWorkerIdentity,
        lease_token_digest: str,
        lease_fence: int,
        at: datetime,
    ) -> None:
        if (
            str(row["state"]) != "leased"
            or str(row["lease_owner"]) != worker.worker_id
            or str(row["lease_token_digest"]) != lease_token_digest
            or _stored_int(row["lease_fence"]) != lease_fence
            or _stored_time(row["lease_expires_at"]) <= at
        ):
            raise RuntimeCatalogConflict("control run lease is stale")

    def complete_run(
        self,
        *,
        worker: RuntimeWorkerIdentity,
        run_id: str,
        lease_token_digest: str,
        lease_fence: int,
        result: ControlRunExecutionResult,
        completed_at: datetime,
    ) -> ControlRun:
        completed = utc_second(completed_at, label="run completion time")
        if (
            not isinstance(result, ControlRunExecutionResult)
            or result.run_id != run_id
            or result.lease_fence != lease_fence
        ):
            raise RuntimeCatalogConflict("executor result does not match the run lease")
        try:
            with self._pool.connection() as connection, connection.transaction():
                self._prepare(connection, worker.tenant_id)
                row = connection.execute(
                    """
                        SELECT *
                        FROM control_assurance_runtime.control_runs
                        WHERE tenant_id = %s AND run_id = %s
                        FOR UPDATE
                        """,
                    (worker.tenant_id, run_id),
                ).fetchone()
                if row is None:
                    raise RuntimeCatalogNotFound("control run not found")
                if str(row["state"]) == "succeeded":
                    if (
                        int(row["lease_fence"]) != lease_fence
                        or str(row["evidence_digest"])
                        != result.evidence_digest
                        or str(row["executor_receipt_digest"])
                        != result.executor_receipt_digest
                    ):
                        raise RuntimeCatalogConflict(
                            "completed run differs from executor result"
                        )
                    claim = connection.execute(
                        """
                            SELECT *
                            FROM control_assurance_runtime.control_run_claims
                            WHERE tenant_id = %s
                              AND run_id = %s
                              AND lease_fence = %s
                            """,
                        (worker.tenant_id, run_id, lease_fence),
                    ).fetchone()
                    if (
                        claim is None
                        or str(claim["worker_id"]) != worker.worker_id
                        or str(claim["lease_token_digest"])
                        != lease_token_digest
                    ):
                        raise RuntimeCatalogConflict(
                            "completed run claim identity differs"
                        )
                    return _run_from_row(row)
                self._require_current_lease(
                    row,
                    worker=worker,
                    lease_token_digest=lease_token_digest,
                    lease_fence=lease_fence,
                    at=completed,
                )
                request = ControlRunRequest.model_validate_json(
                    _stored_bytes(row["request_bytes"])
                )
                closure = ControlRunClosure(
                    run_id=run_id,
                    tenant_id=request.tenant_id,
                    control_id=request.control_id,
                    deployment_operation_id=request.deployment_operation_id,
                    deployment_receipt_digest=(
                        request.deployment_receipt_digest
                    ),
                    configuration_digest=request.configuration_digest,
                    control_profile_id=request.control_profile_id,
                    control_profile_digest=request.control_profile_digest,
                    window_start=request.window_start,
                    window_end=request.window_end,
                    attempt_count=int(row["attempt_count"]),
                    lease_fence=lease_fence,
                    evidence_digest=result.evidence_digest,
                    executor_receipt_digest=(
                        result.executor_receipt_digest
                    ),
                    completed_at=completed,
                )
                connection.execute(
                    """
                        INSERT INTO
                            control_assurance_runtime.control_run_outcomes (
                                tenant_id,
                                run_id,
                                lease_fence,
                                outcome,
                                recorded_at,
                                evidence_digest,
                                executor_receipt_digest,
                                closure_digest,
                                closure_bytes
                            )
                        VALUES (
                            %s, %s, %s, 'succeeded', %s,
                            %s, %s, %s, %s
                        )
                        """,
                    (
                        worker.tenant_id,
                        run_id,
                        lease_fence,
                        completed,
                        result.evidence_digest,
                        result.executor_receipt_digest,
                        closure.digest,
                        closure.canonical_bytes(),
                    ),
                )
                updated = connection.execute(
                    """
                        UPDATE control_assurance_runtime.control_runs
                        SET state = 'succeeded',
                            state_version = state_version + 1,
                            lease_owner = NULL,
                            lease_token_digest = NULL,
                            leased_at = NULL,
                            lease_expires_at = NULL,
                            completed_at = %s,
                            evidence_digest = %s,
                            executor_receipt_digest = %s,
                            closure_digest = %s
                        WHERE tenant_id = %s
                          AND run_id = %s
                          AND state = 'leased'
                          AND lease_fence = %s
                        RETURNING *
                        """,
                    (
                        completed,
                        result.evidence_digest,
                        result.executor_receipt_digest,
                        closure.digest,
                        worker.tenant_id,
                        run_id,
                        lease_fence,
                    ),
                ).fetchone()
                if updated is None:
                    raise RuntimeCatalogConflict(
                        "control run completion compare-and-swap failed"
                    )
            return _run_from_row(updated)
        except RuntimeCatalogError:
            raise
        except Exception as exc:
            if _sqlstate(exc) in _CONFLICT_SQLSTATES:
                raise RuntimeCatalogConflict(
                    "control run completion was rejected"
                ) from exc
            raise ControlRunOutcomeUnknown(
                "run-completion-outcome-unknown"
            ) from exc

    def fail_run(
        self,
        *,
        worker: RuntimeWorkerIdentity,
        run_id: str,
        lease_token_digest: str,
        lease_fence: int,
        failure_digest: str,
        failed_at: datetime,
        retry_at: datetime | None,
    ) -> ControlRun:
        failed = utc_second(failed_at, label="run failure time")
        retry = (
            None
            if retry_at is None
            else utc_second(retry_at, label="run retry time")
        )
        if retry is not None and retry <= failed:
            raise ValueError("run retry must be later than failure")
        try:
            with self._pool.connection() as connection, connection.transaction():
                self._prepare(connection, worker.tenant_id)
                row = connection.execute(
                    """
                        SELECT *
                        FROM control_assurance_runtime.control_runs
                        WHERE tenant_id = %s AND run_id = %s
                        FOR UPDATE
                        """,
                    (worker.tenant_id, run_id),
                ).fetchone()
                if row is None:
                    raise RuntimeCatalogNotFound("control run not found")
                if str(row["state"]) == "failed":
                    expected_retry = retry
                    if (
                        _stored_int(row["attempt_count"])
                        >= self._max_run_attempts
                    ):
                        expected_retry = None
                    if (
                        int(row["lease_fence"]) != lease_fence
                        or str(row["failure_digest"]) != failure_digest
                        or (
                            None
                            if row["retry_at"] is None
                            else _stored_time(row["retry_at"])
                        )
                        != expected_retry
                    ):
                        raise RuntimeCatalogConflict(
                            "failed run differs from requested failure"
                        )
                    claim = connection.execute(
                        """
                            SELECT *
                            FROM control_assurance_runtime.control_run_claims
                            WHERE tenant_id = %s
                              AND run_id = %s
                              AND lease_fence = %s
                            """,
                        (worker.tenant_id, run_id, lease_fence),
                    ).fetchone()
                    if (
                        claim is None
                        or str(claim["worker_id"]) != worker.worker_id
                        or str(claim["lease_token_digest"])
                        != lease_token_digest
                    ):
                        raise RuntimeCatalogConflict(
                            "failed run claim identity differs"
                        )
                    return _run_from_row(row)
                self._require_current_lease(
                    row,
                    worker=worker,
                    lease_token_digest=lease_token_digest,
                    lease_fence=lease_fence,
                    at=failed,
                )
                if int(row["attempt_count"]) >= self._max_run_attempts:
                    retry = None
                connection.execute(
                    """
                        INSERT INTO
                            control_assurance_runtime.control_run_outcomes (
                                tenant_id,
                                run_id,
                                lease_fence,
                                outcome,
                                recorded_at,
                                failure_digest,
                                retry_at
                            )
                        VALUES (%s, %s, %s, 'failed', %s, %s, %s)
                        """,
                    (
                        worker.tenant_id,
                        run_id,
                        lease_fence,
                        failed,
                        failure_digest,
                        retry,
                    ),
                )
                updated = connection.execute(
                    """
                        UPDATE control_assurance_runtime.control_runs
                        SET state = 'failed',
                            state_version = state_version + 1,
                            lease_owner = NULL,
                            lease_token_digest = NULL,
                            leased_at = NULL,
                            lease_expires_at = NULL,
                            retry_at = %s,
                            failed_at = %s,
                            failure_digest = %s
                        WHERE tenant_id = %s
                          AND run_id = %s
                          AND state = 'leased'
                          AND lease_fence = %s
                        RETURNING *
                        """,
                    (
                        retry,
                        failed,
                        failure_digest,
                        worker.tenant_id,
                        run_id,
                        lease_fence,
                    ),
                ).fetchone()
                if updated is None:
                    raise RuntimeCatalogConflict(
                        "control run failure compare-and-swap failed"
                    )
            return _run_from_row(updated)
        except RuntimeCatalogError:
            raise
        except Exception as exc:
            if _sqlstate(exc) in _CONFLICT_SQLSTATES:
                raise RuntimeCatalogConflict(
                    "control run failure was rejected"
                ) from exc
            raise ControlRunOutcomeUnknown("run-failure-outcome-unknown") from exc

    def get_run(self, *, tenant_id: str, run_id: str) -> ControlRun:
        try:
            with self._pool.connection() as connection, connection.transaction():
                self._prepare(connection, tenant_id)
                row = connection.execute(
                    """
                        SELECT *
                        FROM control_assurance_runtime.control_runs
                        WHERE tenant_id = %s AND run_id = %s
                        """,
                    (tenant_id, run_id),
                ).fetchone()
            if row is None:
                raise RuntimeCatalogNotFound("control run not found")
            return _run_from_row(row)
        except RuntimeCatalogError:
            raise
        except Exception as exc:
            raise RuntimeCatalogError("control run read failed") from exc

    def run_closure(
        self,
        *,
        tenant_id: str,
        run_id: str,
    ) -> ControlRunClosure:
        """Reopen and verify the exact canonical closure of a successful run."""

        try:
            with self._pool.connection() as connection, connection.transaction():
                self._prepare(connection, tenant_id)
                row = connection.execute(
                    """
                        SELECT outcome.closure_digest, outcome.closure_bytes
                        FROM control_assurance_runtime.control_run_outcomes
                            AS outcome
                        WHERE outcome.tenant_id = %s
                          AND outcome.run_id = %s
                          AND outcome.outcome = 'succeeded'
                        """,
                    (tenant_id, run_id),
                ).fetchone()
            if row is None:
                raise RuntimeCatalogNotFound("successful control run closure not found")
            closure_bytes = _stored_bytes(row["closure_bytes"])
            closure_digest = str(row["closure_digest"])
            parsed = strict_json_loads(closure_bytes)
            if (
                canonical_json_bytes(parsed) != closure_bytes
                or sha256_digest(closure_bytes) != closure_digest
            ):
                raise RuntimeCatalogIntegrityError(
                    "stored control run closure digest differs"
                )
            closure = ControlRunClosure.model_validate_json(closure_bytes)
            if closure.run_id != run_id or closure.digest != closure_digest:
                raise RuntimeCatalogIntegrityError(
                    "stored control run closure identity differs"
                )
            return closure
        except RuntimeCatalogError:
            raise
        except (StrictJSONError, ValueError, KeyError, TypeError) as exc:
            raise RuntimeCatalogIntegrityError(
                "stored control run closure is invalid"
            ) from exc
        except Exception as exc:
            raise RuntimeCatalogError("control run closure read failed") from exc
