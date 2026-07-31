"""PostgreSQL HA journal for one externally visible control execution.

The journal is the write-ahead boundary between a leased scheduler run and
connector, PAM, signing, and custody side effects.  An operator installs
``deploy/postgres/execution-journal-schema.sql``; this module never performs
DDL.

One logical run has one immutable scheduler request and one immutable
execution plan.  Attempts are fenced independently.  A higher fence may
recover unfinished work, but it must reuse the exact plan (including capture
nonce and connector request) already stored for the run.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager
from datetime import UTC, datetime
from typing import Any, Final, Literal, Protocol, Self, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from assurance_lab.control_plane.models import Digest
from assurance_lab.evidence.admission import LeaseAuthorityVerifier
from assurance_lab.evidence.canonical import (
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)
from assurance_lab.runtime.execution_identity import (
    ExecutionEnvironmentIdentity,
    ExecutionEnvironmentIdentityError,
    parse_execution_environment_identity,
)
from assurance_lab.runtime.execution_plan import (
    ControlRunExecutionPlanError,
    verify_control_run_execution_plan,
)
from assurance_lab.runtime.execution_recovery import (
    PublishingRecoveryError,
    PublishingRecoveryJournalExpectation,
    PublishingRecoveryUseClaim,
    RecoveryActorVerificationPolicy,
    SignedPublishingRecoveryAuthorization,
    verify_publishing_recovery_authorization,
)
from assurance_lab.runtime.models import (
    ControlRunExecutionRequest,
    ControlRunExecutionResult,
    ControlRunRequest,
    PortableId,
    sha256_digest,
    utc_second,
    utc_text,
)

ExecutionAttemptState = Literal[
    "prepared",
    "publishing",
    "completed",
    "failed",
    "uncertain",
]

_SCHEMA_VERSION: Final = 6
_DEFAULT_STATEMENT_TIMEOUT_MS: Final = 15_000
_DEFAULT_LOCK_TIMEOUT_MS: Final = 5_000
_MAX_POOL_SIZE: Final = 256
_MAX_PLAN_BYTES: Final = 2 * 1024 * 1024
_MAX_EXECUTION_IDENTITY_BYTES: Final = 512 * 1024
_MAX_EXECUTOR_RECEIPT_BYTES: Final = 1024 * 1024
_STABLE_REQUEST_MEDIA_TYPE: Final = (
    "application/vnd.control-assurance.execution-request-identity.v1+json"
)
_PORTABLE_ID_RE: Final = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_DIGEST_RE: Final = re.compile(r"^sha256:[a-f0-9]{64}$")
_ERROR_CODE_RE: Final = re.compile(r"^[a-z][a-z0-9.-]{0,63}$")
_CONFLICT_SQLSTATES: Final = frozenset(
    {
        "23000",
        "23503",
        "23505",
        "23514",
        "40001",
        "40P01",
        "55P03",
        "57014",
    }
)

_CONSUME_PUBLISHING_RECOVERY = """
    SELECT control_assurance_execution.consume_publishing_recovery_authorization(
        %s, %s, %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s, %s
    ) AS consumed
"""


class Cursor(Protocol):
    def fetchone(self) -> Mapping[str, Any] | None: ...

    def fetchall(self) -> Sequence[Mapping[str, Any]]: ...


class Connection(Protocol):
    def execute(
        self,
        query: str,
        params: Sequence[object] = (),
    ) -> Cursor: ...

    def transaction(self) -> AbstractContextManager[object]: ...


class ExecutionJournalConnectionPool(Protocol):
    """Minimal psycopg-pool surface used by the journal."""

    def connection(self) -> AbstractContextManager[Connection]: ...


class _TransactionPublishingRecoveryRegistry:
    """Consume one signed authorization through the recovery-only SQL routine.

    ``verify_publishing_recovery_authorization`` calls this object only after
    all five pinned signatures, validity windows, and the exact journal
    expectation have passed.  The SQL routine both records the canonical
    authorization set and performs the old-attempt/new-attempt transition.
    Because this adapter uses the caller's open transaction, a later exception
    rolls the consumption record and the transition back together.
    """

    __slots__ = ("_connection", "_signed_authorization_bytes")

    def __init__(
        self,
        connection: Connection,
        *,
        signed_authorization_bytes: bytes,
    ) -> None:
        self._connection = connection
        self._signed_authorization_bytes = signed_authorization_bytes

    def consume_once(self, claim: PublishingRecoveryUseClaim) -> bool:
        if type(claim) is not PublishingRecoveryUseClaim:
            raise TypeError("publishing recovery use claim must be exact")
        envelope = SignedPublishingRecoveryAuthorization.model_validate_json(
            self._signed_authorization_bytes,
            strict=True,
        )
        authorization = envelope.authorization
        recovery_request = authorization.recovery_request
        signed_maker_action = recovery_request.signed_maker_action
        signed_checker_action = authorization.signed_checker_action
        signed_fence = authorization.signed_compute_fence_attestation
        signed_drain = authorization.signed_credential_drain_attestation
        row = self._connection.execute(
            _CONSUME_PUBLISHING_RECOVERY,
            (
                self._signed_authorization_bytes,
                authorization.canonical_bytes(),
                recovery_request.canonical_bytes(),
                recovery_request.intent.canonical_bytes(),
                signed_maker_action.canonical_bytes(),
                signed_maker_action.actor_action.canonical_bytes(),
                signed_checker_action.canonical_bytes(),
                signed_checker_action.actor_action.canonical_bytes(),
                signed_fence.canonical_bytes(),
                signed_fence.attestation.canonical_bytes(),
                signed_drain.canonical_bytes(),
                signed_drain.attestation.canonical_bytes(),
                claim.canonical_bytes(),
            ),
        ).fetchone()
        if row is None or type(row.get("consumed")) is not bool:
            raise RuntimeError("publishing recovery routine returned invalid state")
        return cast(bool, row["consumed"])


class ExecutionJournalError(RuntimeError):
    """Secret-free base error for durable execution state."""


class ExecutionJournalConflict(ExecutionJournalError):
    """An immutable identity, CAS revision, or lease fence was rejected."""


class ExecutionJournalNotFound(ExecutionJournalError):
    """The tenant-scoped logical execution does not exist."""


class ExecutionJournalIntegrityError(ExecutionJournalError):
    """Persisted bytes or state failed independent verification."""


class ExecutionJournalUnavailable(ExecutionJournalError):
    """A read-only journal operation could not reach durable state."""


class ExecutionJournalOutcomeUnknown(ExecutionJournalError):
    """A write may have committed and must be reread by tenant and run id."""


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class ExecutionJournalRecord(_FrozenModel):
    """Verified current or historical attempt joined to its immutable run."""

    request: ControlRunExecutionRequest
    stable_request_digest: Digest
    stable_request_bytes: bytes = Field(min_length=2, max_length=65536)
    execution_plan_digest: Digest
    execution_plan_bytes: bytes = Field(min_length=2, max_length=_MAX_PLAN_BYTES)
    execution_identity_digest: Digest | None = None
    execution_identity_bytes: bytes | None = Field(
        default=None,
        min_length=2,
        max_length=_MAX_EXECUTION_IDENTITY_BYTES,
    )
    state: ExecutionAttemptState
    revision: int = Field(ge=0, le=2**63 - 1)
    highest_lease_fence: int = Field(ge=1, le=2**63 - 1)
    worker_id: PortableId
    lease_token_digest: Digest
    prepared_at: datetime
    publishing_at: datetime | None = None
    finished_at: datetime | None = None
    error_code: str | None = Field(default=None, max_length=64)
    completion_lease_fence: int | None = Field(
        default=None,
        ge=1,
        le=2**63 - 1,
    )
    evidence_digest: Digest | None = None
    executor_receipt_digest: Digest | None = None
    executor_receipt_bytes: bytes | None = Field(
        default=None,
        min_length=2,
        max_length=_MAX_EXECUTOR_RECEIPT_BYTES,
    )

    @field_validator("prepared_at", "publishing_at", "finished_at")
    @classmethod
    def validate_times(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return utc_second(value, label="execution journal time")

    @field_validator("error_code")
    @classmethod
    def validate_error_code(cls, value: str | None) -> str | None:
        if value is not None and _ERROR_CODE_RE.fullmatch(value) is None:
            raise ValueError("execution error code is not bounded")
        return value

    @model_validator(mode="after")
    def validate_state_shape(self) -> ExecutionJournalRecord:
        if self.highest_lease_fence < self.request.lease_fence:
            raise ValueError("execution journal fence moved backwards")
        if (self.execution_identity_digest is None) != (self.execution_identity_bytes is None):
            raise ValueError("execution environment identity is partially bound")
        if self.execution_identity_bytes is not None:
            assert self.execution_identity_digest is not None
            identity = _validate_execution_identity_bytes(
                self.execution_identity_bytes,
                expected_digest=self.execution_identity_digest,
            )
            _validate_execution_identity_binding(
                identity,
                request=self.request,
                execution_plan_bytes=self.execution_plan_bytes,
                execution_plan_digest=self.execution_plan_digest,
            )
        completion = (
            self.completion_lease_fence,
            self.evidence_digest,
            self.executor_receipt_digest,
            self.executor_receipt_bytes,
        )
        if any(value is None for value in completion) != all(value is None for value in completion):
            raise ValueError("execution journal completion is partially bound")
        if self.state == "prepared":
            if (
                self.revision != 0
                or self.publishing_at is not None
                or self.finished_at is not None
                or self.error_code is not None
            ):
                raise ValueError("prepared execution attempt has outcome state")
        elif self.state == "publishing":
            if (
                self.revision != 1
                or self.publishing_at is None
                or self.finished_at is not None
                or self.error_code is not None
            ):
                raise ValueError("publishing execution attempt is invalid")
        elif self.state == "completed":
            if (
                self.revision != 2
                or self.publishing_at is None
                or self.finished_at is None
                or self.error_code is not None
                or self.completion_lease_fence != self.request.lease_fence
                or self.execution_identity_bytes is None
            ):
                raise ValueError("completed execution attempt is invalid")
            assert self.executor_receipt_bytes is not None
            assert self.executor_receipt_digest is not None
            _validate_executor_receipt_bytes(
                self.executor_receipt_bytes,
                expected_digest=self.executor_receipt_digest,
            )
        elif self.revision < 1 or self.finished_at is None or self.error_code is None:
            raise ValueError("failed or uncertain execution attempt is invalid")
        return self

    @property
    def terminal(self) -> bool:
        return self.state in {"completed", "failed", "uncertain"}

    @property
    def result(self) -> ControlRunExecutionResult | None:
        if (
            self.completion_lease_fence is None
            or self.evidence_digest is None
            or self.executor_receipt_digest is None
        ):
            return None
        return ControlRunExecutionResult(
            run_id=self.request.run_id,
            lease_fence=self.completion_lease_fence,
            evidence_digest=self.evidence_digest,
            executor_receipt_digest=self.executor_receipt_digest,
        )


def _sqlstate(exc: BaseException) -> str | None:
    value = getattr(exc, "sqlstate", None)
    return value if isinstance(value, str) else None


def _require_digest(value: str, *, label: str) -> str:
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be one canonical SHA-256 digest")
    return value


def _require_portable_id(value: str, *, label: str) -> str:
    if type(value) is not str or _PORTABLE_ID_RE.fullmatch(value) is None:
        raise ValueError(f"{label} is not a portable identifier")
    return value


def _validate_executor_receipt_bytes(
    value: bytes,
    *,
    expected_digest: str,
) -> bytes:
    if type(value) is not bytes or not 2 <= len(value) <= _MAX_EXECUTOR_RECEIPT_BYTES:
        raise ValueError("executor receipt bytes are outside the supported range")
    if sha256_digest(value) != expected_digest:
        raise ValueError("executor receipt digest differs from its exact bytes")
    try:
        parsed = strict_json_loads(value)
    except StrictJSONError as exc:
        raise ValueError("executor receipt is not strict JSON") from exc
    if not isinstance(parsed, dict) or canonical_json_bytes(parsed) != value:
        raise ValueError("executor receipt is not one canonical JSON object")
    return value


def _validate_execution_identity_bytes(
    value: bytes,
    *,
    expected_digest: str,
) -> ExecutionEnvironmentIdentity:
    if type(value) is not bytes or not 2 <= len(value) <= _MAX_EXECUTION_IDENTITY_BYTES:
        raise ValueError("execution environment identity bytes are outside the supported range")
    if sha256_digest(value) != expected_digest:
        raise ValueError("execution environment identity digest differs from its exact bytes")
    try:
        return parse_execution_environment_identity(value)
    except ExecutionEnvironmentIdentityError as exc:
        raise ValueError(
            "execution environment identity is not an exact canonical identity"
        ) from exc


def _validate_execution_identity_binding(
    identity: ExecutionEnvironmentIdentity,
    *,
    request: ControlRunExecutionRequest,
    execution_plan_bytes: bytes,
    execution_plan_digest: str,
) -> None:
    try:
        plan, _ = verify_control_run_execution_plan(
            execution_plan_bytes,
            expected_request=request,
        )
    except ControlRunExecutionPlanError as exc:
        raise ValueError("execution plan is invalid") from exc
    if (
        execution_plan_digest != plan.digest
        or identity.run_id != request.run_id
        or identity.tenant_id != request.tenant_id
        or identity.control_id != request.control_id
        or identity.configuration_digest != request.configuration_digest
        or identity.execution_plan_digest != execution_plan_digest
        or identity.source_revision != plan.source_revision
        or identity.source_kind != plan.source_kind
    ):
        raise ValueError("execution environment identity crosses its journaled execution")


def _validate_request(request: ControlRunExecutionRequest) -> ControlRunExecutionRequest:
    if type(request) is not ControlRunExecutionRequest:
        raise TypeError("execution request must be an exact ControlRunExecutionRequest")
    try:
        return ControlRunExecutionRequest.model_validate(request.model_dump(mode="python"))
    except ValueError as exc:
        raise ValueError("execution request failed independent validation") from exc


def stable_execution_request_bytes(request: ControlRunExecutionRequest) -> bytes:
    """Return the canonical attempt-independent identity stored by the journal."""

    validated = _validate_request(request)
    run_request = ControlRunRequest.model_validate_json(validated.run_request_bytes)
    return canonical_json_bytes(
        {
            "configuration_digest": validated.configuration_digest,
            "control_id": validated.control_id,
            "control_profile_digest": validated.control_profile_digest,
            "control_profile_id": validated.control_profile_id,
            "control_profile_media_type": validated.control_profile_media_type,
            "deployment_operation_id": validated.deployment_operation_id,
            "deployment_operation_sequence": (run_request.deployment_operation_sequence),
            "deployment_receipt_digest": validated.deployment_receipt_digest,
            "media_type": _STABLE_REQUEST_MEDIA_TYPE,
            "run_id": validated.run_id,
            "run_request_digest": sha256_digest(validated.run_request_bytes),
            "revision_id": run_request.revision_id,
            "schema_version": "1.0.0",
            "tenant_id": validated.tenant_id,
            "window_end": utc_text(validated.window_end),
            "window_start": utc_text(validated.window_start),
        }
    )


def _same_stable_request(
    first: ControlRunExecutionRequest,
    second: ControlRunExecutionRequest,
) -> bool:
    return (
        first.run_id,
        first.run_request_bytes,
        first.tenant_id,
        first.control_id,
        first.deployment_operation_id,
        first.deployment_receipt_digest,
        first.configuration_digest,
        first.configuration_bytes,
        first.control_profile_id,
        first.control_profile_digest,
        first.control_profile_media_type,
        first.control_profile_bytes,
        first.window_start,
        first.window_end,
    ) == (
        second.run_id,
        second.run_request_bytes,
        second.tenant_id,
        second.control_id,
        second.deployment_operation_id,
        second.deployment_receipt_digest,
        second.configuration_digest,
        second.configuration_bytes,
        second.control_profile_id,
        second.control_profile_digest,
        second.control_profile_media_type,
        second.control_profile_bytes,
        second.window_start,
        second.window_end,
    )


def _stored_bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray | memoryview):
        return bytes(value)
    raise ExecutionJournalIntegrityError("stored execution binary value is invalid")


def _stored_int(value: object) -> int:
    if type(value) is not int:
        raise ExecutionJournalIntegrityError("stored execution integer is invalid")
    return value


def _stored_time(value: object) -> datetime:
    if isinstance(value, datetime):
        return utc_second(value, label="stored execution time")
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ExecutionJournalIntegrityError("stored execution time is invalid") from exc
        return utc_second(parsed.astimezone(UTC), label="stored execution time")
    raise ExecutionJournalIntegrityError("stored execution time is invalid")


_SELECT_CURRENT = """
    SELECT execution.*,
           attempt.attempt_count AS attempt_count,
           attempt.worker_id AS attempt_worker_id,
           attempt.lease_token_digest AS attempt_lease_token_digest,
           attempt.state AS attempt_state,
           attempt.revision AS attempt_revision,
           attempt.prepared_at AS attempt_prepared_at,
           attempt.publishing_at AS attempt_publishing_at,
           attempt.finished_at AS attempt_finished_at,
           attempt.error_code AS attempt_error_code
    FROM control_assurance_execution.executions AS execution
    JOIN control_assurance_execution.execution_attempts AS attempt
      ON attempt.tenant_id = execution.tenant_id
     AND attempt.run_id = execution.run_id
     AND attempt.lease_fence = execution.highest_lease_fence
    WHERE execution.tenant_id = %s AND execution.run_id = %s
"""


def _record_from_row(row: Mapping[str, object]) -> ExecutionJournalRecord:
    try:
        request = ControlRunExecutionRequest(
            run_id=str(row["run_id"]),
            run_request_bytes=_stored_bytes(row["run_request_bytes"]),
            tenant_id=str(row["tenant_id"]),
            control_id=str(row["control_id"]),
            deployment_operation_id=str(row["deployment_operation_id"]),
            deployment_receipt_digest=str(row["deployment_receipt_digest"]),
            configuration_digest=str(row["configuration_digest"]),
            configuration_bytes=_stored_bytes(row["configuration_bytes"]),
            control_profile_id=str(row["control_profile_id"]),
            control_profile_digest=str(row["control_profile_digest"]),
            control_profile_media_type=str(row["control_profile_media_type"]),
            control_profile_bytes=_stored_bytes(row["control_profile_bytes"]),
            window_start=_stored_time(row["window_start"]),
            window_end=_stored_time(row["window_end"]),
            attempt_count=_stored_int(row["attempt_count"]),
            lease_fence=_stored_int(row["highest_lease_fence"]),
        )
        run_request = ControlRunRequest.model_validate_json(request.run_request_bytes)
        if run_request.deployment_operation_sequence != _stored_int(
            row["deployment_operation_sequence"]
        ) or run_request.revision_id != str(row["revision_id"]):
            raise ExecutionJournalIntegrityError("stored source deployment anchors differ")
        stable_bytes = _stored_bytes(row["stable_request_bytes"])
        stable_digest = str(row["stable_request_digest"])
        expected_stable = stable_execution_request_bytes(request)
        if stable_bytes != expected_stable or stable_digest != sha256_digest(stable_bytes):
            raise ExecutionJournalIntegrityError("stored stable execution request differs")
        plan_bytes = _stored_bytes(row["execution_plan_bytes"])
        plan_digest = str(row["execution_plan_digest"])
        if plan_digest != sha256_digest(plan_bytes):
            raise ExecutionJournalIntegrityError("stored execution plan digest differs")
        verify_control_run_execution_plan(
            plan_bytes,
            expected_request=request,
        )
        completion_fence = (
            None
            if row["completion_lease_fence"] is None
            else _stored_int(row["completion_lease_fence"])
        )
        return ExecutionJournalRecord(
            request=request,
            stable_request_digest=stable_digest,
            stable_request_bytes=stable_bytes,
            execution_plan_digest=plan_digest,
            execution_plan_bytes=plan_bytes,
            execution_identity_digest=(
                None
                if row["execution_identity_digest"] is None
                else str(row["execution_identity_digest"])
            ),
            execution_identity_bytes=(
                None
                if row["execution_identity_bytes"] is None
                else _stored_bytes(row["execution_identity_bytes"])
            ),
            state=cast(ExecutionAttemptState, str(row["attempt_state"])),
            revision=_stored_int(row["attempt_revision"]),
            highest_lease_fence=_stored_int(row["highest_lease_fence"]),
            worker_id=str(row["attempt_worker_id"]),
            lease_token_digest=str(row["attempt_lease_token_digest"]),
            prepared_at=_stored_time(row["attempt_prepared_at"]),
            publishing_at=(
                None
                if row["attempt_publishing_at"] is None
                else _stored_time(row["attempt_publishing_at"])
            ),
            finished_at=(
                None
                if row["attempt_finished_at"] is None
                else _stored_time(row["attempt_finished_at"])
            ),
            error_code=(
                None if row["attempt_error_code"] is None else str(row["attempt_error_code"])
            ),
            completion_lease_fence=completion_fence,
            evidence_digest=(
                None if row["evidence_digest"] is None else str(row["evidence_digest"])
            ),
            executor_receipt_digest=(
                None
                if row["executor_receipt_digest"] is None
                else str(row["executor_receipt_digest"])
            ),
            executor_receipt_bytes=(
                None
                if row["executor_receipt_bytes"] is None
                else _stored_bytes(row["executor_receipt_bytes"])
            ),
        )
    except ExecutionJournalIntegrityError:
        raise
    except (ControlRunExecutionPlanError, KeyError, TypeError, ValueError) as exc:
        raise ExecutionJournalIntegrityError("stored execution journal row is invalid") from exc


class PostgresExecutionJournal:
    """Tenant-isolated, fenced execution journal with immutable completion."""

    __slots__ = (
        "_lock_timeout_ms",
        "_owns_pool",
        "_pool",
        "_statement_timeout_ms",
    )

    def __init__(
        self,
        pool: ExecutionJournalConnectionPool,
        *,
        statement_timeout_ms: int = _DEFAULT_STATEMENT_TIMEOUT_MS,
        lock_timeout_ms: int = _DEFAULT_LOCK_TIMEOUT_MS,
        owns_pool: bool = False,
    ) -> None:
        if not callable(getattr(pool, "connection", None)):
            raise TypeError("PostgreSQL execution pool must provide connection()")
        for label, value in (
            ("statement timeout", statement_timeout_ms),
            ("lock timeout", lock_timeout_ms),
        ):
            if type(value) is not int or not 100 <= value <= 120_000:
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
        min_size: int = 1,
        max_size: int = 8,
        connect_timeout_seconds: int = 10,
        statement_timeout_ms: int = _DEFAULT_STATEMENT_TIMEOUT_MS,
        lock_timeout_ms: int = _DEFAULT_LOCK_TIMEOUT_MS,
    ) -> Self:
        if type(dsn) is not str or not dsn:
            raise ValueError("PostgreSQL DSN is required")
        if (
            type(min_size) is not int
            or type(max_size) is not int
            or min_size < 1
            or max_size < min_size
            or max_size > _MAX_POOL_SIZE
        ):
            raise ValueError("PostgreSQL execution pool size is invalid")
        if type(connect_timeout_seconds) is not int or not 1 <= connect_timeout_seconds <= 60:
            raise ValueError("PostgreSQL connect timeout is invalid")
        try:
            pool_module = importlib.import_module("psycopg_pool")
            rows_module = importlib.import_module("psycopg.rows")
        except ImportError as exc:
            raise RuntimeError(
                "PostgreSQL execution journal requires the control-plane extra"
            ) from exc
        pool = pool_module.ConnectionPool(
            conninfo=dsn,
            min_size=min_size,
            max_size=max_size,
            timeout=float(connect_timeout_seconds),
            kwargs={
                "autocommit": True,
                "connect_timeout": connect_timeout_seconds,
                "row_factory": rows_module.dict_row,
            },
            open=True,
        )
        return cls(
            cast(ExecutionJournalConnectionPool, pool),
            statement_timeout_ms=statement_timeout_ms,
            lock_timeout_ms=lock_timeout_ms,
            owns_pool=True,
        )

    def close_pool(self) -> None:
        """Close only a pool created by :meth:`from_dsn`."""

        if not self._owns_pool:
            return
        close = getattr(self._pool, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                raise ExecutionJournalUnavailable(
                    "PostgreSQL execution pool could not close cleanly"
                ) from None

    @contextmanager
    def _transaction(
        self,
        tenant_id: str,
        *,
        principal_kind: Literal["worker", "recovery"] = "worker",
    ) -> Iterator[Connection]:
        _require_portable_id(tenant_id, label="tenant id")
        with self._pool.connection() as connection, connection.transaction():
            connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            connection.execute(
                """
                SELECT control_assurance_execution.assert_session_principal(
                    %s,
                    current_user::text,
                    %s,
                    current_user::text,
                    session_user::text
                )
                """,
                (tenant_id, principal_kind),
            )
            connection.execute(
                "SELECT set_config('statement_timeout', %s, true)",
                (f"{self._statement_timeout_ms}ms",),
            )
            connection.execute(
                "SELECT set_config('lock_timeout', %s, true)",
                (f"{self._lock_timeout_ms}ms",),
            )
            migration = connection.execute(
                """
                SELECT array_agg(version ORDER BY version) AS versions
                FROM control_assurance_execution.schema_migrations
                """
            ).fetchone()
            versions = None if migration is None else migration.get("versions")
            if not isinstance(versions, (list, tuple)) or tuple(versions) != tuple(
                range(1, _SCHEMA_VERSION + 1)
            ):
                raise ExecutionJournalIntegrityError(
                    "PostgreSQL execution journal schema version is unsupported"
                )
            yield connection

    @staticmethod
    def _select_current(
        connection: Connection,
        *,
        tenant_id: str,
        run_id: str,
        for_update: bool,
    ) -> Mapping[str, Any] | None:
        query = _SELECT_CURRENT + (" FOR UPDATE OF execution, attempt" if for_update else "")
        return connection.execute(query, (tenant_id, run_id)).fetchone()

    @staticmethod
    def _assert_same_identity(
        record: ExecutionJournalRecord,
        request: ControlRunExecutionRequest,
        *,
        execution_plan_bytes: bytes | None,
    ) -> None:
        if not _same_stable_request(record.request, request):
            raise ExecutionJournalConflict(
                "execution request differs from immutable journal identity"
            )
        if execution_plan_bytes is not None and execution_plan_bytes != record.execution_plan_bytes:
            raise ExecutionJournalConflict("execution plan differs from immutable journal identity")

    @staticmethod
    def _assert_attempt_identity(
        record: ExecutionJournalRecord,
        *,
        request: ControlRunExecutionRequest,
        worker_id: str,
        lease_token_digest: str,
    ) -> None:
        if (
            record.request.lease_fence != request.lease_fence
            or record.request.attempt_count != request.attempt_count
            or record.worker_id != worker_id
            or record.lease_token_digest != lease_token_digest
        ):
            raise ExecutionJournalConflict("execution attempt identity differs from its lease")

    @staticmethod
    def _assert_publishing_recovery_expectation(
        record: ExecutionJournalRecord,
        expectation: PublishingRecoveryJournalExpectation,
    ) -> None:
        """Compare every recovery field the current journal can attest.

        Worker credential digests and scheduler lease start/expiry timestamps
        are intentionally absent: the current scheduler journal schema never
        persisted them.  They remain signed recovery-authority facts and are
        retained in the recovery record, but are not misrepresented as
        database-observed state.
        """

        observed = (
            record.request.tenant_id,
            record.request.run_id,
            record.request.control_id,
            record.request.configuration_digest,
            record.execution_plan_digest,
            record.execution_identity_digest,
            record.request.lease_fence,
            record.request.attempt_count,
            record.revision,
            record.worker_id,
            record.lease_token_digest,
            record.publishing_at,
            record.state,
            record.completion_lease_fence,
        )
        expected = (
            expectation.tenant_id,
            expectation.run_id,
            expectation.control_id,
            expectation.configuration_digest,
            expectation.execution_plan_digest,
            expectation.execution_identity_digest,
            expectation.abandoned_lease_fence,
            expectation.abandoned_attempt_count,
            expectation.abandoned_attempt_revision,
            expectation.abandoned_worker_id,
            expectation.abandoned_lease_token_digest,
            expectation.abandoned_publishing_at,
            "publishing",
            None,
        )
        if observed != expected or record.execution_identity_bytes is None:
            raise ExecutionJournalConflict(
                "publishing recovery expectation differs from current durable state"
            )

    def recover_identity_bound_publication(
        self,
        signed_authorization_bytes: bytes,
        *,
        journal_expectation: PublishingRecoveryJournalExpectation,
        verifier: LeaseAuthorityVerifier,
        fence_verifier: LeaseAuthorityVerifier,
        drain_verifier: LeaseAuthorityVerifier,
        maker_verifier: LeaseAuthorityVerifier,
        checker_verifier: LeaseAuthorityVerifier,
        actor_policy: RecoveryActorVerificationPolicy,
    ) -> ExecutionJournalRecord:
        """Atomically adopt one externally fenced identity-bound publication.

        The transaction first reads and compares the exact old journal tuple.
        Verification then uses the database transaction itself as the
        single-use registry.  Its recovery-only SQL routine locks and
        independently rechecks that tuple, appends all canonical signed
        records, supersedes the old publishing attempt, and inserts the exact
        successor directly in ``publishing`` state.  No ordinary higher-fence
        ``prepare`` path is opened.  This method must be invoked through a
        journal instance whose pool authenticates as the dedicated recovery
        service role; the ordinary worker role is not granted EXECUTE on the
        SQL routine.

        PostgreSQL intentionally does not implement Ed25519 verification.  The
        five pinned-key checks occur immediately before ``consume_once`` in
        this process, which makes the narrowly held recovery-service database
        credential part of the trusted computing base.  Maker and checker
        actions must carry independent IdP signatures, bind the exact request
        and approval intents, and satisfy the pinned actor policy.
        """

        if type(journal_expectation) is not PublishingRecoveryJournalExpectation:
            raise TypeError("publishing recovery journal expectation must be exact")
        if type(actor_policy) is not RecoveryActorVerificationPolicy:
            raise TypeError("recovery actor verification policy must be exact")
        if type(signed_authorization_bytes) is not bytes:
            raise TypeError("signed publishing recovery authorization must be bytes")
        try:
            with self._transaction(
                journal_expectation.tenant_id,
                principal_kind="recovery",
            ) as connection:
                row = self._select_current(
                    connection,
                    tenant_id=journal_expectation.tenant_id,
                    run_id=journal_expectation.run_id,
                    for_update=False,
                )
                if row is None:
                    raise ExecutionJournalNotFound("execution journal record not found")
                current = _record_from_row(row)
                self._assert_publishing_recovery_expectation(
                    current,
                    journal_expectation,
                )
                clock = connection.execute(
                    """
                    SELECT date_trunc(
                        'second',
                        clock_timestamp()
                    ) AS recovery_now
                    """
                ).fetchone()
                if clock is None or "recovery_now" not in clock:
                    raise ExecutionJournalIntegrityError(
                        "publishing recovery database clock is unavailable"
                    )
                recovery_now = _stored_time(clock["recovery_now"])
                registry = _TransactionPublishingRecoveryRegistry(
                    connection,
                    signed_authorization_bytes=signed_authorization_bytes,
                )
                verify_publishing_recovery_authorization(
                    signed_authorization_bytes,
                    verifier=verifier,
                    fence_verifier=fence_verifier,
                    drain_verifier=drain_verifier,
                    maker_verifier=maker_verifier,
                    checker_verifier=checker_verifier,
                    actor_policy=actor_policy,
                    now=recovery_now,
                    journal_expectation=journal_expectation,
                    use_registry=registry,
                )
                recovered = self._select_current(
                    connection,
                    tenant_id=journal_expectation.tenant_id,
                    run_id=journal_expectation.run_id,
                    for_update=False,
                )
                if recovered is None:
                    raise ExecutionJournalIntegrityError("recovered execution could not be reread")
                result = _record_from_row(recovered)
                successor = (
                    journal_expectation.successor_lease_fence,
                    journal_expectation.successor_attempt_count,
                    journal_expectation.successor_worker_id,
                    journal_expectation.successor_lease_token_digest,
                    "publishing",
                    1,
                    journal_expectation.execution_plan_digest,
                    journal_expectation.execution_identity_digest,
                )
                observed_successor = (
                    result.request.lease_fence,
                    result.request.attempt_count,
                    result.worker_id,
                    result.lease_token_digest,
                    result.state,
                    result.revision,
                    result.execution_plan_digest,
                    result.execution_identity_digest,
                )
                if observed_successor != successor:
                    raise ExecutionJournalIntegrityError(
                        "publishing recovery routine returned a substituted successor"
                    )
                return result
        except ExecutionJournalError:
            raise
        except PublishingRecoveryError as exc:
            if exc.code == "consumption-unavailable":
                raise ExecutionJournalOutcomeUnknown(
                    "publishing recovery transaction outcome is unknown"
                ) from None
            raise ExecutionJournalConflict(
                f"publishing recovery authorization was rejected: {exc.code}"
            ) from None
        except Exception as exc:
            if _sqlstate(exc) in _CONFLICT_SQLSTATES:
                raise ExecutionJournalConflict(
                    "publishing recovery transaction was rejected"
                ) from None
            raise ExecutionJournalOutcomeUnknown(
                "publishing recovery transaction outcome is unknown"
            ) from None

    def prepare(
        self,
        request: ControlRunExecutionRequest,
        *,
        worker_id: str,
        lease_token_digest: str,
        execution_plan_bytes: bytes | None,
    ) -> ExecutionJournalRecord:
        """Persist or recover the sole plan before any external side effect.

        ``execution_plan_bytes`` is mandatory for a new logical run.  A caller
        recovering an existing run may pass ``None`` to retrieve the already
        frozen plan.  Supplying different plan bytes is always a conflict.
        """

        validated = _validate_request(request)
        worker = _require_portable_id(worker_id, label="worker id")
        token = _require_digest(lease_token_digest, label="lease token digest")
        stable_bytes = stable_execution_request_bytes(validated)
        stable_digest = sha256_digest(stable_bytes)
        run_request = ControlRunRequest.model_validate_json(validated.run_request_bytes)
        if execution_plan_bytes is not None:
            if (
                type(execution_plan_bytes) is not bytes
                or not 2 <= len(execution_plan_bytes) <= _MAX_PLAN_BYTES
            ):
                raise ValueError("execution plan bytes are outside the supported range")
            verify_control_run_execution_plan(
                execution_plan_bytes,
                expected_request=validated,
            )
        try:
            with self._transaction(validated.tenant_id) as connection:
                row = self._select_current(
                    connection,
                    tenant_id=validated.tenant_id,
                    run_id=validated.run_id,
                    for_update=True,
                )
                if row is None:
                    if execution_plan_bytes is None:
                        raise ExecutionJournalNotFound(
                            "new execution requires a frozen execution plan"
                        )
                    inserted = connection.execute(
                        """
                        INSERT INTO control_assurance_execution.executions (
                            tenant_id,
                            run_id,
                            stable_request_digest,
                            stable_request_bytes,
                            run_request_bytes,
                            control_id,
                            deployment_operation_id,
                            deployment_operation_sequence,
                            deployment_receipt_digest,
                            revision_id,
                            configuration_digest,
                            configuration_bytes,
                            control_profile_id,
                            control_profile_digest,
                            control_profile_media_type,
                            control_profile_bytes,
                            window_start,
                            window_end,
                            execution_plan_digest,
                            execution_plan_bytes,
                            highest_lease_fence,
                            highest_attempt_count
                        )
                        VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s
                        )
                        ON CONFLICT (tenant_id, run_id) DO NOTHING
                        RETURNING run_id
                        """,
                        (
                            validated.tenant_id,
                            validated.run_id,
                            stable_digest,
                            stable_bytes,
                            validated.run_request_bytes,
                            validated.control_id,
                            validated.deployment_operation_id,
                            run_request.deployment_operation_sequence,
                            validated.deployment_receipt_digest,
                            run_request.revision_id,
                            validated.configuration_digest,
                            validated.configuration_bytes,
                            validated.control_profile_id,
                            validated.control_profile_digest,
                            validated.control_profile_media_type,
                            validated.control_profile_bytes,
                            validated.window_start,
                            validated.window_end,
                            sha256_digest(execution_plan_bytes),
                            execution_plan_bytes,
                            validated.lease_fence,
                            validated.attempt_count,
                        ),
                    ).fetchone()
                    if inserted is not None:
                        connection.execute(
                            """
                            INSERT INTO
                                control_assurance_execution.execution_attempts (
                                    tenant_id,
                                    run_id,
                                    lease_fence,
                                    attempt_count,
                                    worker_id,
                                    lease_token_digest,
                                    state,
                                    revision
                                )
                            VALUES (%s, %s, %s, %s, %s, %s, 'prepared', 0)
                            """,
                            (
                                validated.tenant_id,
                                validated.run_id,
                                validated.lease_fence,
                                validated.attempt_count,
                                worker,
                                token,
                            ),
                        )
                    row = self._select_current(
                        connection,
                        tenant_id=validated.tenant_id,
                        run_id=validated.run_id,
                        for_update=True,
                    )
                    if row is None:
                        raise ExecutionJournalIntegrityError(
                            "prepared execution could not be reread"
                        )
                current = _record_from_row(row)
                self._assert_same_identity(
                    current,
                    validated,
                    execution_plan_bytes=execution_plan_bytes,
                )
                if validated.lease_fence < current.highest_lease_fence:
                    raise ExecutionJournalConflict("execution lease fence is stale")
                if current.state == "completed":
                    return current
                if validated.lease_fence == current.highest_lease_fence:
                    self._assert_attempt_identity(
                        current,
                        request=validated,
                        worker_id=worker,
                        lease_token_digest=token,
                    )
                    return current
                if validated.attempt_count <= current.request.attempt_count:
                    raise ExecutionJournalConflict("execution attempt count did not advance")
                if current.state == "publishing" and current.execution_identity_bytes is not None:
                    # Once a publishing attempt has durably selected its source,
                    # PAM, signer, and custody identities, the database fence
                    # cannot revoke handles already held by that process.  A
                    # blind higher-fence takeover could therefore let both
                    # workers exercise the same external authority.  Such an
                    # attempt must be reconciled against its deterministic
                    # workspace and immutable custody before ownership changes.
                    raise ExecutionJournalConflict(
                        "identity-bound publishing execution requires reconciliation"
                    )
                if current.state in {"prepared", "publishing"}:
                    superseded = connection.execute(
                        """
                        UPDATE control_assurance_execution.execution_attempts
                        SET state = 'uncertain',
                            revision = revision + 1,
                            finished_at = statement_timestamp(),
                            error_code = 'lease-superseded'
                        WHERE tenant_id = %s
                          AND run_id = %s
                          AND lease_fence = %s
                          AND state = %s
                          AND revision = %s
                        RETURNING lease_fence
                        """,
                        (
                            validated.tenant_id,
                            validated.run_id,
                            current.request.lease_fence,
                            current.state,
                            current.revision,
                        ),
                    ).fetchone()
                    if superseded is None:
                        raise ExecutionJournalConflict("execution recovery compare-and-swap failed")
                advanced = connection.execute(
                    """
                    UPDATE control_assurance_execution.executions
                    SET highest_lease_fence = %s,
                        highest_attempt_count = %s
                    WHERE tenant_id = %s
                      AND run_id = %s
                      AND highest_lease_fence = %s
                      AND highest_attempt_count = %s
                      AND completion_lease_fence IS NULL
                    RETURNING run_id
                    """,
                    (
                        validated.lease_fence,
                        validated.attempt_count,
                        validated.tenant_id,
                        validated.run_id,
                        current.highest_lease_fence,
                        current.request.attempt_count,
                    ),
                ).fetchone()
                if advanced is None:
                    raise ExecutionJournalConflict(
                        "execution fence advance compare-and-swap failed"
                    )
                connection.execute(
                    """
                    INSERT INTO control_assurance_execution.execution_attempts (
                        tenant_id,
                        run_id,
                        lease_fence,
                        attempt_count,
                        worker_id,
                        lease_token_digest,
                        state,
                        revision
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, 'prepared', 0)
                    """,
                    (
                        validated.tenant_id,
                        validated.run_id,
                        validated.lease_fence,
                        validated.attempt_count,
                        worker,
                        token,
                    ),
                )
                recovered = self._select_current(
                    connection,
                    tenant_id=validated.tenant_id,
                    run_id=validated.run_id,
                    for_update=False,
                )
                if recovered is None:
                    raise ExecutionJournalIntegrityError("recovered execution could not be reread")
                return _record_from_row(recovered)
        except ExecutionJournalError:
            raise
        except Exception as exc:
            if _sqlstate(exc) in _CONFLICT_SQLSTATES:
                raise ExecutionJournalConflict("execution preparation was rejected") from None
            raise ExecutionJournalOutcomeUnknown(
                "execution preparation outcome is unknown"
            ) from None

    def get(self, *, tenant_id: str, run_id: str) -> ExecutionJournalRecord:
        _require_portable_id(tenant_id, label="tenant id")
        _require_digest(run_id, label="run id")
        try:
            with self._transaction(tenant_id) as connection:
                row = self._select_current(
                    connection,
                    tenant_id=tenant_id,
                    run_id=run_id,
                    for_update=False,
                )
            if row is None:
                raise ExecutionJournalNotFound("execution journal record not found")
            return _record_from_row(row)
        except ExecutionJournalError:
            raise
        except Exception:
            raise ExecutionJournalUnavailable("execution journal read is unavailable") from None

    def begin_publishing(
        self,
        *,
        tenant_id: str,
        run_id: str,
        lease_fence: int,
        worker_id: str,
        lease_token_digest: str,
        expected_revision: int,
    ) -> ExecutionJournalRecord:
        """CAS ``prepared`` to ``publishing`` before the first network call."""

        return self._transition(
            tenant_id=tenant_id,
            run_id=run_id,
            lease_fence=lease_fence,
            worker_id=worker_id,
            lease_token_digest=lease_token_digest,
            expected_revision=expected_revision,
            target="publishing",
            error_code=None,
        )

    def bind_execution_identity(
        self,
        *,
        tenant_id: str,
        run_id: str,
        lease_fence: int,
        worker_id: str,
        lease_token_digest: str,
        expected_revision: int,
        execution_identity_digest: str,
        execution_identity_bytes: bytes,
    ) -> ExecutionJournalRecord:
        """Bind the exact public connector and custody identity before use.

        The logical run owns this identity, so a higher-fence recovery must
        reuse it.  Binding does not advance the attempt revision: it is an
        idempotent CAS within the current publishing revision.
        """

        _require_portable_id(tenant_id, label="tenant id")
        _require_digest(run_id, label="run id")
        worker = _require_portable_id(worker_id, label="worker id")
        token = _require_digest(lease_token_digest, label="lease token digest")
        identity_digest = _require_digest(
            execution_identity_digest,
            label="execution environment identity digest",
        )
        if (
            type(lease_fence) is not int
            or not 1 <= lease_fence <= 2**63 - 1
            or type(expected_revision) is not int
            or expected_revision < 0
        ):
            raise ValueError("execution identity fence or revision is invalid")
        try:
            identity = _validate_execution_identity_bytes(
                execution_identity_bytes,
                expected_digest=identity_digest,
            )
        except ValueError:
            raise ExecutionJournalConflict(
                "execution environment identity is not exact canonical state"
            ) from None
        try:
            with self._transaction(tenant_id) as connection:
                row = self._select_current(
                    connection,
                    tenant_id=tenant_id,
                    run_id=run_id,
                    for_update=True,
                )
                if row is None:
                    raise ExecutionJournalNotFound("execution journal record not found")
                current = _record_from_row(row)
                if (
                    current.highest_lease_fence != lease_fence
                    or current.request.lease_fence != lease_fence
                    or current.worker_id != worker
                    or current.lease_token_digest != token
                    or current.state != "publishing"
                    or current.revision != expected_revision
                ):
                    raise ExecutionJournalConflict(
                        "execution identity binding used a stale publishing attempt"
                    )
                try:
                    _validate_execution_identity_binding(
                        identity,
                        request=current.request,
                        execution_plan_bytes=current.execution_plan_bytes,
                        execution_plan_digest=current.execution_plan_digest,
                    )
                except ValueError:
                    raise ExecutionJournalConflict(
                        "execution environment identity crosses its journaled execution"
                    ) from None
                if current.execution_identity_bytes is not None:
                    if (
                        current.execution_identity_digest != identity_digest
                        or current.execution_identity_bytes != execution_identity_bytes
                    ):
                        raise ExecutionJournalConflict(
                            "execution environment identity differs from its binding"
                        )
                    return current
                bound = connection.execute(
                    """
                    UPDATE control_assurance_execution.executions
                    SET execution_identity_digest = %s,
                        execution_identity_bytes = %s
                    WHERE tenant_id = %s
                      AND run_id = %s
                      AND highest_lease_fence = %s
                      AND completion_lease_fence IS NULL
                      AND execution_identity_digest IS NULL
                      AND execution_identity_bytes IS NULL
                      AND EXISTS (
                          SELECT 1
                          FROM control_assurance_execution.execution_attempts
                              AS attempt
                          WHERE attempt.tenant_id = %s
                            AND attempt.run_id = %s
                            AND attempt.lease_fence = %s
                            AND attempt.worker_id = %s
                            AND attempt.lease_token_digest = %s
                            AND attempt.state = 'publishing'
                            AND attempt.revision = %s
                      )
                    RETURNING run_id
                    """,
                    (
                        identity_digest,
                        execution_identity_bytes,
                        tenant_id,
                        run_id,
                        lease_fence,
                        tenant_id,
                        run_id,
                        lease_fence,
                        worker,
                        token,
                        expected_revision,
                    ),
                ).fetchone()
                if bound is None:
                    raise ExecutionJournalConflict(
                        "execution identity binding compare-and-swap failed"
                    )
                updated = self._select_current(
                    connection,
                    tenant_id=tenant_id,
                    run_id=run_id,
                    for_update=False,
                )
                if updated is None:
                    raise ExecutionJournalIntegrityError(
                        "bound execution identity could not be reread"
                    )
                return _record_from_row(updated)
        except ExecutionJournalError:
            raise
        except Exception as exc:
            if _sqlstate(exc) in _CONFLICT_SQLSTATES:
                raise ExecutionJournalConflict("execution identity binding was rejected") from None
            raise ExecutionJournalOutcomeUnknown(
                "execution identity binding outcome is unknown"
            ) from None

    def mark_failed(
        self,
        *,
        tenant_id: str,
        run_id: str,
        lease_fence: int,
        worker_id: str,
        lease_token_digest: str,
        expected_revision: int,
        error_code: str,
    ) -> ExecutionJournalRecord:
        """Record a bounded, known failure without storing diagnostics."""

        return self._transition(
            tenant_id=tenant_id,
            run_id=run_id,
            lease_fence=lease_fence,
            worker_id=worker_id,
            lease_token_digest=lease_token_digest,
            expected_revision=expected_revision,
            target="failed",
            error_code=error_code,
        )

    def mark_uncertain(
        self,
        *,
        tenant_id: str,
        run_id: str,
        lease_fence: int,
        worker_id: str,
        lease_token_digest: str,
        expected_revision: int,
        error_code: str,
    ) -> ExecutionJournalRecord:
        """Record that an external effect may have happened."""

        return self._transition(
            tenant_id=tenant_id,
            run_id=run_id,
            lease_fence=lease_fence,
            worker_id=worker_id,
            lease_token_digest=lease_token_digest,
            expected_revision=expected_revision,
            target="uncertain",
            error_code=error_code,
        )

    def _transition(
        self,
        *,
        tenant_id: str,
        run_id: str,
        lease_fence: int,
        worker_id: str,
        lease_token_digest: str,
        expected_revision: int,
        target: Literal["publishing", "failed", "uncertain"],
        error_code: str | None,
    ) -> ExecutionJournalRecord:
        _require_portable_id(tenant_id, label="tenant id")
        _require_digest(run_id, label="run id")
        worker = _require_portable_id(worker_id, label="worker id")
        token = _require_digest(lease_token_digest, label="lease token digest")
        if type(lease_fence) is not int or not 1 <= lease_fence <= 2**63 - 1:
            raise ValueError("lease fence is outside the supported range")
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("expected revision is invalid")
        if target == "publishing":
            if error_code is not None:
                raise ValueError("publishing transition cannot carry an error")
        elif type(error_code) is not str or _ERROR_CODE_RE.fullmatch(error_code) is None:
            raise ValueError("execution error code is invalid")
        try:
            with self._transaction(tenant_id) as connection:
                row = self._select_current(
                    connection,
                    tenant_id=tenant_id,
                    run_id=run_id,
                    for_update=True,
                )
                if row is None:
                    raise ExecutionJournalNotFound("execution journal record not found")
                current = _record_from_row(row)
                if (
                    current.highest_lease_fence != lease_fence
                    or current.request.lease_fence != lease_fence
                    or current.worker_id != worker
                    or current.lease_token_digest != token
                ):
                    raise ExecutionJournalConflict("execution transition used a stale lease")
                if current.state == "completed":
                    return current
                if (
                    current.state == target
                    and current.revision == expected_revision + 1
                    and current.error_code == error_code
                ):
                    return current
                allowed_source = (
                    {"prepared"} if target == "publishing" else {"prepared", "publishing"}
                )
                if current.state not in allowed_source or current.revision != expected_revision:
                    raise ExecutionJournalConflict("execution transition compare-and-swap failed")
                if target == "publishing":
                    transition = """
                        UPDATE control_assurance_execution.execution_attempts
                        SET state = 'publishing',
                            revision = revision + 1,
                            publishing_at = statement_timestamp()
                        WHERE tenant_id = %s
                          AND run_id = %s
                          AND lease_fence = %s
                          AND worker_id = %s
                          AND lease_token_digest = %s
                          AND state = %s
                          AND revision = %s
                        RETURNING lease_fence
                    """
                    params: tuple[object, ...] = (
                        tenant_id,
                        run_id,
                        lease_fence,
                        worker,
                        token,
                        current.state,
                        expected_revision,
                    )
                else:
                    transition = """
                        UPDATE control_assurance_execution.execution_attempts
                        SET state = %s,
                            revision = revision + 1,
                            finished_at = statement_timestamp(),
                            error_code = %s
                        WHERE tenant_id = %s
                          AND run_id = %s
                          AND lease_fence = %s
                          AND worker_id = %s
                          AND lease_token_digest = %s
                          AND state = %s
                          AND revision = %s
                        RETURNING lease_fence
                    """
                    params = (
                        target,
                        error_code,
                        tenant_id,
                        run_id,
                        lease_fence,
                        worker,
                        token,
                        current.state,
                        expected_revision,
                    )
                if connection.execute(transition, params).fetchone() is None:
                    raise ExecutionJournalConflict("execution transition compare-and-swap failed")
                updated = self._select_current(
                    connection,
                    tenant_id=tenant_id,
                    run_id=run_id,
                    for_update=False,
                )
                if updated is None:
                    raise ExecutionJournalIntegrityError(
                        "transitioned execution could not be reread"
                    )
                return _record_from_row(updated)
        except ExecutionJournalError:
            raise
        except Exception as exc:
            if _sqlstate(exc) in _CONFLICT_SQLSTATES:
                raise ExecutionJournalConflict("execution transition was rejected") from None
            raise ExecutionJournalOutcomeUnknown(
                "execution transition outcome is unknown"
            ) from None

    def mark_completed(
        self,
        *,
        tenant_id: str,
        run_id: str,
        lease_fence: int,
        worker_id: str,
        lease_token_digest: str,
        expected_revision: int,
        result: ControlRunExecutionResult,
        executor_receipt_bytes: bytes,
    ) -> ExecutionJournalRecord:
        """Immutably close one publishing attempt.

        Retrying after a lost commit acknowledgement returns the same result.
        A different result for the same logical run is rejected.
        """

        _require_portable_id(tenant_id, label="tenant id")
        _require_digest(run_id, label="run id")
        worker = _require_portable_id(worker_id, label="worker id")
        token = _require_digest(lease_token_digest, label="lease token digest")
        if (
            type(lease_fence) is not int
            or not 1 <= lease_fence <= 2**63 - 1
            or type(expected_revision) is not int
            or expected_revision < 0
        ):
            raise ValueError("completion fence or revision is invalid")
        if (
            type(result) is not ControlRunExecutionResult
            or result.run_id != run_id
            or result.lease_fence != lease_fence
        ):
            raise ExecutionJournalConflict("executor result differs from execution lease")
        if type(executor_receipt_bytes) is not bytes:
            raise ExecutionJournalConflict("executor receipt bytes differ from the result digest")
        try:
            _validate_executor_receipt_bytes(
                executor_receipt_bytes,
                expected_digest=result.executor_receipt_digest,
            )
        except ValueError:
            raise ExecutionJournalConflict(
                "executor receipt bytes differ from the canonical result"
            ) from None
        try:
            with self._transaction(tenant_id) as connection:
                row = self._select_current(
                    connection,
                    tenant_id=tenant_id,
                    run_id=run_id,
                    for_update=True,
                )
                if row is None:
                    raise ExecutionJournalNotFound("execution journal record not found")
                current = _record_from_row(row)
                if current.result is not None:
                    if (
                        current.result != result
                        or current.state != "completed"
                        or current.worker_id != worker
                        or current.lease_token_digest != token
                        or current.executor_receipt_bytes != executor_receipt_bytes
                    ):
                        raise ExecutionJournalConflict(
                            "completed execution differs from requested result"
                        )
                    return current
                if (
                    current.highest_lease_fence != lease_fence
                    or current.request.lease_fence != lease_fence
                    or current.worker_id != worker
                    or current.lease_token_digest != token
                    or current.state != "publishing"
                    or current.revision != expected_revision
                    or current.execution_identity_bytes is None
                ):
                    raise ExecutionJournalConflict("execution completion compare-and-swap failed")
                attempt = connection.execute(
                    """
                    UPDATE control_assurance_execution.execution_attempts
                    SET state = 'completed',
                        revision = revision + 1,
                        finished_at = statement_timestamp(),
                        evidence_digest = %s,
                        executor_receipt_digest = %s,
                        executor_receipt_bytes = %s
                    WHERE tenant_id = %s
                      AND run_id = %s
                      AND lease_fence = %s
                      AND worker_id = %s
                      AND lease_token_digest = %s
                      AND state = 'publishing'
                      AND revision = %s
                    RETURNING lease_fence
                    """,
                    (
                        result.evidence_digest,
                        result.executor_receipt_digest,
                        executor_receipt_bytes,
                        tenant_id,
                        run_id,
                        lease_fence,
                        worker,
                        token,
                        expected_revision,
                    ),
                ).fetchone()
                if attempt is None:
                    raise ExecutionJournalConflict("execution completion compare-and-swap failed")
                execution = connection.execute(
                    """
                    UPDATE control_assurance_execution.executions
                    SET completion_lease_fence = %s,
                        evidence_digest = %s,
                        executor_receipt_digest = %s,
                        executor_receipt_bytes = %s,
                        completed_at = statement_timestamp()
                    WHERE tenant_id = %s
                      AND run_id = %s
                      AND highest_lease_fence = %s
                      AND completion_lease_fence IS NULL
                    RETURNING run_id
                    """,
                    (
                        lease_fence,
                        result.evidence_digest,
                        result.executor_receipt_digest,
                        executor_receipt_bytes,
                        tenant_id,
                        run_id,
                        lease_fence,
                    ),
                ).fetchone()
                if execution is None:
                    raise ExecutionJournalConflict(
                        "logical execution completion was already claimed"
                    )
                completed = self._select_current(
                    connection,
                    tenant_id=tenant_id,
                    run_id=run_id,
                    for_update=False,
                )
                if completed is None:
                    raise ExecutionJournalIntegrityError("completed execution could not be reread")
                return _record_from_row(completed)
        except ExecutionJournalError:
            raise
        except Exception as exc:
            if _sqlstate(exc) in _CONFLICT_SQLSTATES:
                raise ExecutionJournalConflict("execution completion was rejected") from None
            raise ExecutionJournalOutcomeUnknown(
                "execution completion outcome is unknown"
            ) from None


__all__ = [
    "ExecutionAttemptState",
    "ExecutionJournalConflict",
    "ExecutionJournalConnectionPool",
    "ExecutionJournalError",
    "ExecutionJournalIntegrityError",
    "ExecutionJournalNotFound",
    "ExecutionJournalOutcomeUnknown",
    "ExecutionJournalRecord",
    "ExecutionJournalUnavailable",
    "PostgresExecutionJournal",
    "stable_execution_request_bytes",
]
