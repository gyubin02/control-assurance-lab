"""PostgreSQL HA journals for Elastic and Defender PAM lifecycles.

The schema is an operator-installed boundary in
``deploy/postgres/pam-journal-schema.sql``.  This module performs no DDL and
does not retry transactions: every lifecycle mutation is one revision-fenced
``UPDATE ... RETURNING`` or one immutable ``INSERT ... RETURNING``.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, Literal, Protocol, Self, cast

from assurance_lab.connectors.defender_pam import (
    CredentialMode,
    DefenderPamError,
    DefenderTokenRecord,
    TokenClosure,
)
from assurance_lab.connectors.elastic_pam import (
    ElasticLeaseRecord,
    ElasticPamError,
    ElasticPamPolicy,
    LeaseState,
)

if TYPE_CHECKING:
    from assurance_lab.runtime.execution_plan import ControlRunExecutionPlan
    from assurance_lab.runtime.execution_recovery import PAMRecoveryScope

_SCHEMA_VERSION: Final = 3
_DEFAULT_STATEMENT_TIMEOUT_MS: Final = 15_000
_DEFAULT_LOCK_TIMEOUT_MS: Final = 5_000
_MAX_POOL_SIZE: Final = 256
_MAX_SAFE_INTEGER: Final = 2**53 - 1

_HEX_ID_RE: Final = re.compile(r"^[a-f0-9]{64}$")
_DIGEST_RE: Final = re.compile(r"^sha256:[a-f0-9]{64}$")
_KEY_NAME_RE: Final = re.compile(r"^control-assurance-[a-f0-9]{32}$")
_KEY_ID_RE: Final = re.compile(r"^[A-Za-z0-9_-]{1,512}$")
_INDEX_ALIAS_RE: Final = re.compile(r"^[.]alerts-security[.]alerts-[a-z0-9][a-z0-9_-]{0,63}$")
_PORTABLE_ID_RE: Final = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_LIFECYCLE_RECORD_ID_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,255}$")

PAMLifecycleState = Literal[
    "expired",
    "issued",
    "never-issued",
    "prepared",
    "revoked",
    "uncertain",
]
PAMSettledState = Literal["expired", "never-issued", "revoked"]


class PostgresPamRecoveryError(RuntimeError):
    """Bounded rejection at the PostgreSQL PAM recovery boundary."""


@dataclass(frozen=True, slots=True, init=False)
class PAMExecutionBinding:
    """One plan-derived PAM scope bound to one execution lease fence."""

    tenant_id: str
    run_id: str
    execution_plan_digest: str
    execution_identity_digest: str
    lease_fence: int
    lease_expires_at_epoch_millis: int
    pam_scopes: tuple[PAMRecoveryScope, ...]
    pam_scope_digest: str
    execution_binding_digest: str

    def __init__(self) -> None:
        raise TypeError("PAM execution bindings must be created from an exact execution plan")

    def __post_init__(self) -> None:
        from assurance_lab.runtime.execution_recovery import (
            PAMRecoveryScope,
            publishing_recovery_execution_binding_digest,
            publishing_recovery_pam_scope_digest,
        )

        if type(self.tenant_id) is not str or _PORTABLE_ID_RE.fullmatch(self.tenant_id) is None:
            raise ValueError("PAM execution binding tenant is invalid")
        for label, value in (
            ("run", self.run_id),
            ("execution plan", self.execution_plan_digest),
            ("execution identity", self.execution_identity_digest),
            ("PAM scope", self.pam_scope_digest),
            ("execution binding", self.execution_binding_digest),
        ):
            _require_digest(value, label=f"{label} digest")
        if type(self.lease_fence) is not int or not 1 <= self.lease_fence <= _MAX_SAFE_INTEGER:
            raise ValueError("PAM execution lease fence is invalid")
        _require_nonnegative_integer(
            self.lease_expires_at_epoch_millis,
            label="lease expiry",
        )
        if (
            type(self.pam_scopes) is not tuple
            or len(self.pam_scopes) != 3
            or any(type(scope) is not PAMRecoveryScope for scope in self.pam_scopes)
        ):
            raise ValueError("PAM execution binding must contain three exact scopes")
        scope_keys = tuple(scope.sort_key for scope in self.pam_scopes)
        if (
            scope_keys != tuple(sorted(scope_keys))
            or len(set(scope_keys)) != 3
            or {scope.authority_class for scope in self.pam_scopes}
            != {"custody", "signing", "source"}
        ):
            raise ValueError(
                "PAM execution binding requires one source, signing, and custody scope"
            )
        expected_scope_digest = publishing_recovery_pam_scope_digest(self.pam_scopes)
        expected_binding = publishing_recovery_execution_binding_digest(
            tenant_id=self.tenant_id,
            run_id=self.run_id,
            execution_plan_digest=self.execution_plan_digest,
            execution_identity_digest=self.execution_identity_digest,
            abandoned_lease_fence=self.lease_fence,
            pam_scope_digest=expected_scope_digest,
        )
        if (
            self.pam_scope_digest != expected_scope_digest
            or self.execution_binding_digest != expected_binding
        ):
            raise ValueError("PAM execution binding is not content-derived")

    @classmethod
    def from_execution_plan(
        cls,
        plan: ControlRunExecutionPlan,
        *,
        execution_identity_digest: str,
        lease_fence: int,
        lease_expires_at_epoch_millis: int,
    ) -> PAMExecutionBinding:
        """Build an issuance binding only from an independently valid plan."""

        from assurance_lab.runtime.execution_plan import (
            ControlRunExecutionPlan,
            execution_plan_pam_recovery_scopes,
        )
        from assurance_lab.runtime.execution_recovery import (
            publishing_recovery_execution_binding_digest,
            publishing_recovery_pam_scope_digest,
        )

        if cls is not PAMExecutionBinding:
            raise TypeError("PAM execution binding subclasses are unsupported")
        if type(plan) is not ControlRunExecutionPlan:
            raise TypeError("execution plan must be exact")
        scopes = execution_plan_pam_recovery_scopes(plan)
        scope_digest = publishing_recovery_pam_scope_digest(scopes)
        binding_digest = publishing_recovery_execution_binding_digest(
            tenant_id=plan.tenant_id,
            run_id=plan.run_id,
            execution_plan_digest=plan.digest,
            execution_identity_digest=execution_identity_digest,
            abandoned_lease_fence=lease_fence,
            pam_scope_digest=scope_digest,
        )
        binding = object.__new__(PAMExecutionBinding)
        for name, value in (
            ("tenant_id", plan.tenant_id),
            ("run_id", plan.run_id),
            ("execution_plan_digest", plan.digest),
            ("execution_identity_digest", execution_identity_digest),
            ("lease_fence", lease_fence),
            ("lease_expires_at_epoch_millis", lease_expires_at_epoch_millis),
            ("pam_scopes", scopes),
            ("pam_scope_digest", scope_digest),
            ("execution_binding_digest", binding_digest),
        ):
            object.__setattr__(binding, name, value)
        binding.__post_init__()
        return binding

    def scope(
        self,
        *,
        authority_class: Literal["custody", "signing", "source"],
        connector_id: str,
        connector_request_digest: str,
    ) -> PAMRecoveryScope:
        key = (authority_class, connector_id, connector_request_digest)
        for scope in self.pam_scopes:
            if scope.sort_key == key:
                return scope
        raise ValueError("PAM lifecycle scope is outside the frozen execution plan")


@dataclass(frozen=True, slots=True)
class PAMLifecycleRecord:
    lifecycle_sequence: int
    lifecycle_record_id: str
    tenant_id: str
    run_id: str
    execution_plan_digest: str
    execution_identity_digest: str
    lease_fence: int
    pam_scope_digest: str
    execution_binding_digest: str
    authority_class: Literal["custody", "signing", "source"]
    connector_id: str
    connector_request_digest: str
    credential_reference_digest: str | None
    state: PAMLifecycleState
    revision: int
    created_epoch_millis: int
    issued_epoch_millis: int | None
    expires_epoch_millis: int | None
    settled_epoch_millis: int | None
    maximum_residual_exposure_ends_epoch_millis: int

    def __post_init__(self) -> None:
        if (
            type(self.lifecycle_sequence) is not int
            or not 1 <= self.lifecycle_sequence <= _MAX_SAFE_INTEGER
        ):
            raise ValueError("PAM lifecycle sequence is invalid")
        _require_lifecycle_record_id(self.lifecycle_record_id)
        if type(self.tenant_id) is not str or _PORTABLE_ID_RE.fullmatch(self.tenant_id) is None:
            raise ValueError("PAM lifecycle tenant is invalid")
        for label, value in (
            ("run", self.run_id),
            ("execution plan", self.execution_plan_digest),
            ("execution identity", self.execution_identity_digest),
            ("PAM scope", self.pam_scope_digest),
            ("execution binding", self.execution_binding_digest),
            ("connector request", self.connector_request_digest),
        ):
            _require_digest(value, label=f"{label} digest")
        if type(self.lease_fence) is not int or not 1 <= self.lease_fence <= _MAX_SAFE_INTEGER:
            raise ValueError("PAM lifecycle lease fence is invalid")
        if self.authority_class not in {"custody", "signing", "source"}:
            raise ValueError("PAM lifecycle authority class is invalid")
        if (
            type(self.connector_id) is not str
            or _PORTABLE_ID_RE.fullmatch(self.connector_id) is None
        ):
            raise ValueError("PAM lifecycle connector id is invalid")
        _optional_digest(
            self.credential_reference_digest,
            label="credential reference digest",
        )
        if self.state not in {
            "expired",
            "issued",
            "never-issued",
            "prepared",
            "revoked",
            "uncertain",
        }:
            raise ValueError("PAM lifecycle state is invalid")
        _require_nonnegative_integer(self.revision, label="PAM lifecycle revision")
        _require_nonnegative_integer(
            self.created_epoch_millis,
            label="PAM lifecycle creation time",
        )
        for label, timestamp_value in (
            ("issuance", self.issued_epoch_millis),
            ("expiry", self.expires_epoch_millis),
            ("settlement", self.settled_epoch_millis),
        ):
            if timestamp_value is not None:
                _require_nonnegative_integer(
                    timestamp_value,
                    label=f"PAM lifecycle {label} time",
                )
                if timestamp_value < self.created_epoch_millis:
                    raise ValueError(f"PAM lifecycle {label} precedes creation")
        _require_nonnegative_integer(
            self.maximum_residual_exposure_ends_epoch_millis,
            label="PAM lifecycle maximum residual exposure",
        )
        if self.maximum_residual_exposure_ends_epoch_millis < self.created_epoch_millis:
            raise ValueError("PAM lifecycle residual exposure precedes creation")
        if self.expires_epoch_millis is not None and (
            self.issued_epoch_millis is None
            or self.expires_epoch_millis <= self.issued_epoch_millis
            or self.expires_epoch_millis > self.maximum_residual_exposure_ends_epoch_millis
        ):
            raise ValueError("PAM lifecycle expiry is invalid")
        if self.state == "prepared":
            valid = (
                self.revision == 0
                and self.issued_epoch_millis is None
                and self.expires_epoch_millis is None
                and self.settled_epoch_millis is None
            )
        elif self.state == "issued":
            valid = (
                self.revision >= 1
                and self.issued_epoch_millis is not None
                and self.expires_epoch_millis is not None
                and self.settled_epoch_millis is None
            )
        elif self.state == "uncertain":
            valid = self.revision >= 1 and self.settled_epoch_millis is None
        else:
            valid = (
                self.revision >= 1
                and self.settled_epoch_millis is not None
                and self.settled_epoch_millis >= self.maximum_residual_exposure_ends_epoch_millis
            )
        if not valid:
            raise ValueError("PAM lifecycle state shape is invalid")


@dataclass(frozen=True, slots=True)
class PAMIssuanceFence:
    operation_digest: str
    fenced_execution_binding_digest: str
    successor_execution_binding_digest: str
    snapshot_high_watermark: int
    effective_at_epoch_millis: int
    valid_until_epoch_millis: int

    def __post_init__(self) -> None:
        for label, value in (
            ("operation", self.operation_digest),
            ("fenced execution binding", self.fenced_execution_binding_digest),
            ("successor execution binding", self.successor_execution_binding_digest),
        ):
            _require_digest(value, label=f"{label} digest")
        if self.fenced_execution_binding_digest == self.successor_execution_binding_digest:
            raise ValueError("PAM issuance fence cannot reuse an execution binding")
        if (
            type(self.snapshot_high_watermark) is not int
            or not 1 <= self.snapshot_high_watermark <= _MAX_SAFE_INTEGER
        ):
            raise ValueError("PAM issuance fence high-watermark is invalid")
        _require_nonnegative_integer(
            self.effective_at_epoch_millis,
            label="PAM issuance fence effective time",
        )
        _require_nonnegative_integer(
            self.valid_until_epoch_millis,
            label="PAM issuance fence expiry",
        )
        if self.valid_until_epoch_millis <= self.effective_at_epoch_millis:
            raise ValueError("PAM issuance fence interval is empty")


@dataclass(frozen=True, slots=True)
class PAMLifecycleSnapshot:
    execution_binding: PAMExecutionBinding
    fence: PAMIssuanceFence
    scopes: tuple[PAMRecoveryScope, ...]
    snapshot_high_watermark: int
    matching_record_count: int
    records: tuple[PAMLifecycleRecord, ...]

    def __post_init__(self) -> None:
        record_sequences = tuple(record.lifecycle_sequence for record in self.records)
        scope_keys = frozenset(scope.sort_key for scope in self.scopes)
        if (
            self.scopes != self.execution_binding.pam_scopes
            or self.fence.fenced_execution_binding_digest
            != self.execution_binding.execution_binding_digest
            or self.snapshot_high_watermark != self.fence.snapshot_high_watermark
            or self.matching_record_count != len(self.records)
            or record_sequences != tuple(sorted(record_sequences))
            or len(set(record_sequences)) != len(record_sequences)
            or any(
                (
                    record.tenant_id,
                    record.run_id,
                    record.execution_plan_digest,
                    record.execution_identity_digest,
                    record.lease_fence,
                    record.pam_scope_digest,
                    record.execution_binding_digest,
                )
                != (
                    self.execution_binding.tenant_id,
                    self.execution_binding.run_id,
                    self.execution_binding.execution_plan_digest,
                    self.execution_binding.execution_identity_digest,
                    self.execution_binding.lease_fence,
                    self.execution_binding.pam_scope_digest,
                    self.execution_binding.execution_binding_digest,
                )
                or (
                    record.authority_class,
                    record.connector_id,
                    record.connector_request_digest,
                )
                not in scope_keys
                or record.lifecycle_sequence > self.snapshot_high_watermark
                for record in self.records
            )
        ):
            raise ValueError("PAM lifecycle snapshot is inconsistent")

    @property
    def all_matching_records_settled(self) -> bool:
        return all(
            record.state in {"expired", "never-issued", "revoked"} for record in self.records
        )


class _Cursor(Protocol):
    def fetchone(self) -> Mapping[str, Any] | None: ...

    def fetchall(self) -> tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]]: ...


class _Connection(Protocol):
    def execute(
        self,
        query: str,
        params: tuple[object, ...] = (),
    ) -> _Cursor: ...

    def transaction(self) -> AbstractContextManager[object]: ...


class PostgresPamConnectionPool(Protocol):
    """Minimal psycopg-pool surface accepted by both journals."""

    def connection(self) -> AbstractContextManager[_Connection]: ...


def _require_text(
    row: Mapping[str, Any],
    name: str,
    *,
    optional: bool = False,
) -> str | None:
    value = row.get(name)
    if value is None and optional:
        return None
    if type(value) is not str:
        raise ValueError("stored PAM journal text is invalid")
    return value


def _require_integer(
    row: Mapping[str, Any],
    name: str,
    *,
    optional: bool = False,
) -> int | None:
    value = row.get(name)
    if value is None and optional:
        return None
    if type(value) is not int:
        raise ValueError("stored PAM journal integer is invalid")
    return value


def _require_nonnegative_integer(value: int, *, label: str) -> int:
    if type(value) is not int or value < 0 or value > 2**63 - 1:
        raise ValueError(f"{label} is outside the PostgreSQL bigint range")
    return value


def _require_digest(value: str, *, label: str) -> str:
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        raise ValueError(f"{label} is not a canonical SHA-256 digest")
    return value


def _require_lifecycle_record_id(value: str) -> str:
    if type(value) is not str or _LIFECYCLE_RECORD_ID_RE.fullmatch(value) is None:
        raise ValueError("PAM lifecycle record id is invalid")
    return value


def _optional_digest(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    return _require_digest(value, label=label)


def _lifecycle_record(row: Mapping[str, Any]) -> PAMLifecycleRecord:
    state = _require_text(row, "state")
    if state not in {
        "expired",
        "issued",
        "never-issued",
        "prepared",
        "revoked",
        "uncertain",
    }:
        raise ValueError("stored PAM lifecycle state is invalid")
    authority_class = _require_text(row, "authority_class")
    if authority_class not in {"custody", "signing", "source"}:
        raise ValueError("stored PAM authority class is invalid")
    return PAMLifecycleRecord(
        lifecycle_sequence=cast(
            int,
            _require_integer(row, "lifecycle_sequence"),
        ),
        lifecycle_record_id=cast(
            str,
            _require_text(row, "lifecycle_record_id"),
        ),
        tenant_id=cast(str, _require_text(row, "tenant_id")),
        run_id=cast(str, _require_text(row, "run_id")),
        execution_plan_digest=cast(
            str,
            _require_text(row, "execution_plan_digest"),
        ),
        execution_identity_digest=cast(
            str,
            _require_text(row, "execution_identity_digest"),
        ),
        lease_fence=cast(int, _require_integer(row, "lease_fence")),
        pam_scope_digest=cast(str, _require_text(row, "pam_scope_digest")),
        execution_binding_digest=cast(
            str,
            _require_text(row, "execution_binding_digest"),
        ),
        authority_class=cast(
            Literal["custody", "signing", "source"],
            authority_class,
        ),
        connector_id=cast(str, _require_text(row, "connector_id")),
        connector_request_digest=cast(
            str,
            _require_text(row, "connector_request_digest"),
        ),
        credential_reference_digest=_require_text(
            row,
            "credential_reference_digest",
            optional=True,
        ),
        state=cast(PAMLifecycleState, state),
        revision=cast(int, _require_integer(row, "revision")),
        created_epoch_millis=cast(
            int,
            _require_integer(row, "created_epoch_millis"),
        ),
        issued_epoch_millis=_require_integer(
            row,
            "issued_epoch_millis",
            optional=True,
        ),
        expires_epoch_millis=_require_integer(
            row,
            "expires_epoch_millis",
            optional=True,
        ),
        settled_epoch_millis=_require_integer(
            row,
            "settled_epoch_millis",
            optional=True,
        ),
        maximum_residual_exposure_ends_epoch_millis=cast(
            int,
            _require_integer(
                row,
                "maximum_residual_exposure_ends_epoch_millis",
            ),
        ),
    )


def _bound_lifecycle_record(
    row: Mapping[str, Any],
    binding: PAMExecutionBinding,
    *,
    lifecycle_record_id: str,
    expected_state: PAMLifecycleState,
    expected_scope: PAMRecoveryScope | None = None,
) -> PAMLifecycleRecord:
    record = _lifecycle_record(row)
    if (
        record.lifecycle_record_id,
        record.tenant_id,
        record.run_id,
        record.execution_plan_digest,
        record.execution_identity_digest,
        record.lease_fence,
        record.pam_scope_digest,
        record.execution_binding_digest,
        record.state,
    ) != (
        lifecycle_record_id,
        binding.tenant_id,
        binding.run_id,
        binding.execution_plan_digest,
        binding.execution_identity_digest,
        binding.lease_fence,
        binding.pam_scope_digest,
        binding.execution_binding_digest,
        expected_state,
    ) or (
        expected_scope is not None
        and (
            record.authority_class,
            record.connector_id,
            record.connector_request_digest,
        )
        != expected_scope.sort_key
    ):
        raise PostgresPamRecoveryError(
            "stored PAM lifecycle row differs from its execution binding"
        )
    return record


def _normalize_error(value: str | None, *, maximum: int) -> str | None:
    if value is None:
        return None
    if type(value) is not str:
        raise TypeError("journal error must be text or None")
    normalized = " ".join(value.split())
    if not normalized:
        raise ValueError("journal error must contain non-whitespace text")
    return normalized[:maximum]


def _sqlstate(value: BaseException) -> str | None:
    state = getattr(value, "sqlstate", None)
    return state if isinstance(state, str) else None


class _PostgresPamJournal:
    __slots__ = (
        "_execution_binding",
        "_journal_namespace_digest",
        "_lock_timeout_ms",
        "_owns_pool",
        "_pool",
        "_statement_timeout_ms",
    )

    def __init__(
        self,
        pool: PostgresPamConnectionPool,
        *,
        journal_namespace_digest: str,
        statement_timeout_ms: int,
        lock_timeout_ms: int,
        owns_pool: bool,
        execution_binding: PAMExecutionBinding | None = None,
    ) -> None:
        if not callable(getattr(pool, "connection", None)):
            raise TypeError("PostgreSQL PAM pool must provide connection()")
        self._validate_timeouts(
            statement_timeout_ms=statement_timeout_ms,
            lock_timeout_ms=lock_timeout_ms,
        )
        self._journal_namespace_digest = _require_digest(
            journal_namespace_digest,
            label="journal namespace digest",
        )
        if execution_binding is not None and type(execution_binding) is not PAMExecutionBinding:
            raise TypeError("PAM execution binding must be exact")
        self._execution_binding = execution_binding
        self._pool = pool
        self._statement_timeout_ms = statement_timeout_ms
        self._lock_timeout_ms = lock_timeout_ms
        self._owns_pool = owns_pool

    @staticmethod
    def _validate_timeouts(
        *,
        statement_timeout_ms: int,
        lock_timeout_ms: int,
    ) -> None:
        for label, value in (
            ("statement timeout", statement_timeout_ms),
            ("lock timeout", lock_timeout_ms),
        ):
            if type(value) is not int or not 100 <= value <= 120_000:
                raise ValueError(f"{label} is outside the supported range")
        if lock_timeout_ms > statement_timeout_ms:
            raise ValueError("lock timeout cannot exceed statement timeout")

    def _error(self, reason: str) -> RuntimeError:
        raise NotImplementedError

    @staticmethod
    def _validate_pool_configuration(
        dsn: str,
        *,
        min_size: int,
        max_size: int,
        connect_timeout_seconds: int,
    ) -> None:
        if type(dsn) is not str or not dsn:
            raise ValueError("PostgreSQL DSN is required")
        if (
            type(min_size) is not int
            or type(max_size) is not int
            or min_size < 1
            or max_size < min_size
            or max_size > _MAX_POOL_SIZE
        ):
            raise ValueError("PostgreSQL PAM pool size is invalid")
        if type(connect_timeout_seconds) is not int or not 1 <= connect_timeout_seconds <= 60:
            raise ValueError("PostgreSQL connect timeout is invalid")

    @classmethod
    def _owned_pool(
        cls,
        dsn: str,
        *,
        min_size: int,
        max_size: int,
        connect_timeout_seconds: int,
    ) -> PostgresPamConnectionPool:
        cls._validate_pool_configuration(
            dsn,
            min_size=min_size,
            max_size=max_size,
            connect_timeout_seconds=connect_timeout_seconds,
        )
        try:
            pool_module = importlib.import_module("psycopg_pool")
            rows_module = importlib.import_module("psycopg.rows")
        except ImportError as exc:
            raise RuntimeError("PostgreSQL PAM support requires the control-plane extra") from exc
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
        return cast(PostgresPamConnectionPool, pool)

    def close_pool(self) -> None:
        """Close only a pool created by ``from_dsn``."""

        if self._owns_pool:
            close = getattr(self._pool, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    raise self._error("PostgreSQL PAM pool could not be closed cleanly") from None

    @contextmanager
    def _transaction(self) -> Iterator[_Connection]:
        try:
            with self._pool.connection() as connection, connection.transaction():
                connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                connection.execute(
                    """
                    SELECT control_assurance_pam.assert_journal_namespace(
                        %s,
                        current_user::text,
                        session_user::text
                    )
                    """,
                    (self._journal_namespace_digest,),
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
                    SELECT
                        count(*)::integer AS migration_count,
                        min(version)::integer AS minimum_version,
                        max(version)::integer AS maximum_version
                    FROM control_assurance_pam.schema_migrations
                    """
                ).fetchone()
                if (
                    migration is None
                    or migration.get("migration_count") != _SCHEMA_VERSION
                    or migration.get("minimum_version") != 1
                    or migration.get("maximum_version") != _SCHEMA_VERSION
                ):
                    raise self._error("PostgreSQL PAM journal schema version is unsupported")
                yield connection
        except (ElasticPamError, DefenderPamError, PostgresPamRecoveryError):
            raise
        except Exception as exc:
            reason = (
                "PostgreSQL PAM journal write conflicted"
                if _sqlstate(exc) in {"23000", "23505", "40001", "40P01", "55P03", "57014"}
                else "PostgreSQL PAM journal is unavailable"
            )
            raise self._error(reason) from None


class PostgresPamIssuanceJournal(_PostgresPamJournal):
    """Plan-bound lifecycle, issuance-fence, and exact snapshot boundary."""

    def __init__(
        self,
        pool: PostgresPamConnectionPool,
        *,
        journal_namespace_digest: str,
        statement_timeout_ms: int = _DEFAULT_STATEMENT_TIMEOUT_MS,
        lock_timeout_ms: int = _DEFAULT_LOCK_TIMEOUT_MS,
        owns_pool: bool = False,
    ) -> None:
        super().__init__(
            pool,
            journal_namespace_digest=journal_namespace_digest,
            statement_timeout_ms=statement_timeout_ms,
            lock_timeout_ms=lock_timeout_ms,
            owns_pool=owns_pool,
        )

    @classmethod
    def from_dsn(
        cls,
        dsn: str,
        *,
        journal_namespace_digest: str,
        min_size: int = 2,
        max_size: int = 16,
        connect_timeout_seconds: int = 10,
        statement_timeout_ms: int = _DEFAULT_STATEMENT_TIMEOUT_MS,
        lock_timeout_ms: int = _DEFAULT_LOCK_TIMEOUT_MS,
    ) -> Self:
        cls._validate_timeouts(
            statement_timeout_ms=statement_timeout_ms,
            lock_timeout_ms=lock_timeout_ms,
        )
        _require_digest(
            journal_namespace_digest,
            label="journal namespace digest",
        )
        cls._validate_pool_configuration(
            dsn,
            min_size=min_size,
            max_size=max_size,
            connect_timeout_seconds=connect_timeout_seconds,
        )
        try:
            pool = cls._owned_pool(
                dsn,
                min_size=min_size,
                max_size=max_size,
                connect_timeout_seconds=connect_timeout_seconds,
            )
        except Exception:
            raise PostgresPamRecoveryError(
                "PostgreSQL PAM issuance journal is unavailable"
            ) from None
        return cls(
            pool,
            journal_namespace_digest=journal_namespace_digest,
            statement_timeout_ms=statement_timeout_ms,
            lock_timeout_ms=lock_timeout_ms,
            owns_pool=True,
        )

    def _error(self, reason: str) -> PostgresPamRecoveryError:
        return PostgresPamRecoveryError(reason)

    @staticmethod
    def _validate_binding_row(
        row: Mapping[str, Any],
        binding: PAMExecutionBinding,
        *,
        expected_state: Literal["active", "fenced"],
    ) -> None:
        observed = (
            _require_text(row, "tenant_id"),
            _require_text(row, "run_id"),
            _require_text(row, "execution_plan_digest"),
            _require_text(row, "execution_identity_digest"),
            _require_integer(row, "lease_fence"),
            _require_integer(row, "lease_expires_at_epoch_millis"),
            _require_text(row, "pam_scope_digest"),
            _require_text(row, "execution_binding_digest"),
            _require_text(row, "state"),
        )
        expected = (
            binding.tenant_id,
            binding.run_id,
            binding.execution_plan_digest,
            binding.execution_identity_digest,
            binding.lease_fence,
            binding.lease_expires_at_epoch_millis,
            binding.pam_scope_digest,
            binding.execution_binding_digest,
            expected_state,
        )
        if observed != expected:
            raise PostgresPamRecoveryError(
                "stored PAM execution binding differs from the frozen plan"
            )

    def _insert_binding(
        self,
        connection: _Connection,
        binding: PAMExecutionBinding,
        *,
        predecessor_binding_digest: str | None,
        registered_at_epoch_millis: int,
    ) -> None:
        row = connection.execute(
            """
            INSERT INTO control_assurance_pam.execution_bindings (
                journal_namespace_digest, execution_binding_digest,
                tenant_id, run_id, execution_plan_digest,
                execution_identity_digest, lease_fence,
                lease_expires_at_epoch_millis, pam_scope_digest,
                predecessor_binding_digest, state,
                registered_at_epoch_millis
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                'active', %s
            )
            RETURNING *
            """,
            (
                self._journal_namespace_digest,
                binding.execution_binding_digest,
                binding.tenant_id,
                binding.run_id,
                binding.execution_plan_digest,
                binding.execution_identity_digest,
                binding.lease_fence,
                binding.lease_expires_at_epoch_millis,
                binding.pam_scope_digest,
                predecessor_binding_digest,
                registered_at_epoch_millis,
            ),
        ).fetchone()
        if row is None:
            raise PostgresPamRecoveryError(
                "PAM execution binding registration returned no durable row"
            )
        self._validate_binding_row(row, binding, expected_state="active")
        scope_rows = connection.execute(
            """
            INSERT INTO control_assurance_pam.execution_binding_scopes (
                journal_namespace_digest, execution_binding_digest,
                authority_class, connector_id, connector_request_digest
            ) VALUES
                (%s, %s, %s, %s, %s),
                (%s, %s, %s, %s, %s),
                (%s, %s, %s, %s, %s)
            RETURNING authority_class, connector_id, connector_request_digest
            """,
            tuple(
                value
                for scope in binding.pam_scopes
                for value in (
                    self._journal_namespace_digest,
                    binding.execution_binding_digest,
                    scope.authority_class,
                    scope.connector_id,
                    scope.connector_request_digest,
                )
            ),
        ).fetchall()
        observed_scopes = tuple(
            sorted(
                (
                    cast(str, _require_text(scope_row, "authority_class")),
                    cast(str, _require_text(scope_row, "connector_id")),
                    cast(
                        str,
                        _require_text(
                            scope_row,
                            "connector_request_digest",
                        ),
                    ),
                )
                for scope_row in scope_rows
            )
        )
        if observed_scopes != tuple(scope.sort_key for scope in binding.pam_scopes):
            raise PostgresPamRecoveryError(
                "PAM execution binding scope registration was incomplete"
            )

    def register_execution_binding(
        self,
        binding: PAMExecutionBinding,
        *,
        registered_at_epoch_millis: int,
    ) -> PAMExecutionBinding:
        """Register the only active lease-fenced binding for one run."""

        if type(binding) is not PAMExecutionBinding:
            raise TypeError("PAM execution binding must be exact")
        _require_nonnegative_integer(
            registered_at_epoch_millis,
            label="binding registration time",
        )
        if registered_at_epoch_millis >= binding.lease_expires_at_epoch_millis:
            raise ValueError("PAM execution binding registration follows lease expiry")
        with self._transaction() as connection:
            existing = connection.execute(
                """
                SELECT *
                FROM control_assurance_pam.execution_bindings
                WHERE journal_namespace_digest = %s
                  AND execution_binding_digest = %s
                FOR UPDATE
                """,
                (
                    self._journal_namespace_digest,
                    binding.execution_binding_digest,
                ),
            ).fetchone()
            if existing is not None:
                self._validate_binding_row(
                    existing,
                    binding,
                    expected_state="active",
                )
                return binding
            self._insert_binding(
                connection,
                binding,
                predecessor_binding_digest=None,
                registered_at_epoch_millis=registered_at_epoch_millis,
            )
        return binding

    @staticmethod
    def _validate_successor(
        fenced: PAMExecutionBinding,
        successor: PAMExecutionBinding,
    ) -> None:
        if (
            successor.tenant_id != fenced.tenant_id
            or successor.run_id != fenced.run_id
            or successor.execution_plan_digest != fenced.execution_plan_digest
            or successor.execution_identity_digest != fenced.execution_identity_digest
            or successor.pam_scopes != fenced.pam_scopes
            or successor.pam_scope_digest != fenced.pam_scope_digest
            or successor.lease_fence != fenced.lease_fence + 1
            or successor.execution_binding_digest == fenced.execution_binding_digest
        ):
            raise ValueError(
                "successor PAM execution binding does not advance the same frozen plan"
            )

    def install_recovery_issuance_fence(
        self,
        fenced_binding: PAMExecutionBinding,
        successor_binding: PAMExecutionBinding,
        *,
        operation_digest: str,
        effective_at_epoch_millis: int,
        valid_until_epoch_millis: int,
    ) -> PAMIssuanceFence:
        """Atomically retire one binding, register its successor, and seal issuance."""

        if (
            type(fenced_binding) is not PAMExecutionBinding
            or type(successor_binding) is not PAMExecutionBinding
        ):
            raise TypeError("PAM execution bindings must be exact")
        self._validate_successor(fenced_binding, successor_binding)
        _require_digest(operation_digest, label="issuance fence operation digest")
        _require_nonnegative_integer(
            effective_at_epoch_millis,
            label="issuance fence effective time",
        )
        _require_nonnegative_integer(
            valid_until_epoch_millis,
            label="issuance fence expiry",
        )
        if (
            effective_at_epoch_millis >= valid_until_epoch_millis
            or valid_until_epoch_millis < successor_binding.lease_expires_at_epoch_millis
        ):
            raise ValueError("PAM issuance fence does not cover the successor lease")
        with self._transaction() as connection:
            old_row = connection.execute(
                """
                SELECT *
                FROM control_assurance_pam.execution_bindings
                WHERE journal_namespace_digest = %s
                  AND execution_binding_digest = %s
                FOR UPDATE
                """,
                (
                    self._journal_namespace_digest,
                    fenced_binding.execution_binding_digest,
                ),
            ).fetchone()
            if old_row is None:
                raise PostgresPamRecoveryError("fenced PAM execution binding is absent")
            self._validate_binding_row(
                old_row,
                fenced_binding,
                expected_state="active",
            )
            updated = connection.execute(
                """
                UPDATE control_assurance_pam.execution_bindings
                SET state = 'fenced',
                    fenced_at_epoch_millis = %s
                WHERE journal_namespace_digest = %s
                  AND execution_binding_digest = %s
                  AND state = 'active'
                RETURNING *
                """,
                (
                    effective_at_epoch_millis,
                    self._journal_namespace_digest,
                    fenced_binding.execution_binding_digest,
                ),
            ).fetchone()
            if updated is None:
                raise PostgresPamRecoveryError("PAM execution binding fencing lost its transition")
            self._validate_binding_row(
                updated,
                fenced_binding,
                expected_state="fenced",
            )
            self._insert_binding(
                connection,
                successor_binding,
                predecessor_binding_digest=(fenced_binding.execution_binding_digest),
                registered_at_epoch_millis=effective_at_epoch_millis,
            )
            watermark_row = connection.execute(
                """
                SELECT nextval(
                    'control_assurance_pam.lifecycle_sequence'
                )::bigint AS snapshot_high_watermark
                """
            ).fetchone()
            if watermark_row is None:
                raise PostgresPamRecoveryError("PAM issuance fence high-watermark was unavailable")
            high_watermark = cast(
                int,
                _require_integer(
                    watermark_row,
                    "snapshot_high_watermark",
                ),
            )
            fence_row = connection.execute(
                """
                INSERT INTO control_assurance_pam.issuance_fences (
                    journal_namespace_digest, operation_digest,
                    fenced_execution_binding_digest,
                    successor_execution_binding_digest,
                    pam_scope_digest, snapshot_high_watermark,
                    effective_at_epoch_millis, valid_until_epoch_millis
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s
                )
                RETURNING *
                """,
                (
                    self._journal_namespace_digest,
                    operation_digest,
                    fenced_binding.execution_binding_digest,
                    successor_binding.execution_binding_digest,
                    fenced_binding.pam_scope_digest,
                    high_watermark,
                    effective_at_epoch_millis,
                    valid_until_epoch_millis,
                ),
            ).fetchone()
            if fence_row is None:
                raise PostgresPamRecoveryError("PAM issuance fence returned no durable row")
            observed = (
                _require_text(fence_row, "operation_digest"),
                _require_text(
                    fence_row,
                    "fenced_execution_binding_digest",
                ),
                _require_text(
                    fence_row,
                    "successor_execution_binding_digest",
                ),
                _require_integer(
                    fence_row,
                    "snapshot_high_watermark",
                ),
                _require_integer(
                    fence_row,
                    "effective_at_epoch_millis",
                ),
                _require_integer(
                    fence_row,
                    "valid_until_epoch_millis",
                ),
            )
            expected = (
                operation_digest,
                fenced_binding.execution_binding_digest,
                successor_binding.execution_binding_digest,
                high_watermark,
                effective_at_epoch_millis,
                valid_until_epoch_millis,
            )
            if observed != expected:
                raise PostgresPamRecoveryError("stored PAM issuance fence is inconsistent")
        return PAMIssuanceFence(
            operation_digest=operation_digest,
            fenced_execution_binding_digest=(fenced_binding.execution_binding_digest),
            successor_execution_binding_digest=(successor_binding.execution_binding_digest),
            snapshot_high_watermark=high_watermark,
            effective_at_epoch_millis=effective_at_epoch_millis,
            valid_until_epoch_millis=valid_until_epoch_millis,
        )

    def prepare_lifecycle(
        self,
        binding: PAMExecutionBinding,
        scope: PAMRecoveryScope,
        *,
        lifecycle_record_id: str,
        credential_reference_digest: str | None,
        created_epoch_millis: int,
        maximum_residual_exposure_ends_epoch_millis: int,
    ) -> PAMLifecycleRecord:
        """Durably prepare one exact authority request before external issuance."""

        from assurance_lab.runtime.execution_recovery import PAMRecoveryScope

        if type(binding) is not PAMExecutionBinding:
            raise TypeError("PAM execution binding must be exact")
        if type(scope) is not PAMRecoveryScope:
            raise TypeError("PAM recovery scope must be exact")
        binding.scope(
            authority_class=scope.authority_class,
            connector_id=scope.connector_id,
            connector_request_digest=scope.connector_request_digest,
        )
        _require_lifecycle_record_id(lifecycle_record_id)
        _optional_digest(
            credential_reference_digest,
            label="credential reference digest",
        )
        _require_nonnegative_integer(
            created_epoch_millis,
            label="lifecycle creation time",
        )
        _require_nonnegative_integer(
            maximum_residual_exposure_ends_epoch_millis,
            label="maximum residual exposure",
        )
        if maximum_residual_exposure_ends_epoch_millis < created_epoch_millis:
            raise ValueError("PAM residual exposure precedes lifecycle creation")
        with self._transaction() as connection:
            row = connection.execute(
                """
                INSERT INTO control_assurance_pam.lifecycle_records (
                    lifecycle_record_id, journal_namespace_digest,
                    tenant_id, run_id, execution_plan_digest,
                    execution_identity_digest, lease_fence,
                    pam_scope_digest, execution_binding_digest,
                    authority_class, connector_id,
                    connector_request_digest,
                    credential_reference_digest, state, revision,
                    created_epoch_millis, issued_epoch_millis,
                    expires_epoch_millis, settled_epoch_millis,
                    maximum_residual_exposure_ends_epoch_millis
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, 'prepared', 0, %s,
                    NULL, NULL, NULL, %s
                )
                RETURNING *
                """,
                (
                    lifecycle_record_id,
                    self._journal_namespace_digest,
                    binding.tenant_id,
                    binding.run_id,
                    binding.execution_plan_digest,
                    binding.execution_identity_digest,
                    binding.lease_fence,
                    binding.pam_scope_digest,
                    binding.execution_binding_digest,
                    scope.authority_class,
                    scope.connector_id,
                    scope.connector_request_digest,
                    credential_reference_digest,
                    created_epoch_millis,
                    maximum_residual_exposure_ends_epoch_millis,
                ),
            ).fetchone()
            if row is None:
                raise PostgresPamRecoveryError("PAM lifecycle preparation returned no durable row")
            return _bound_lifecycle_record(
                row,
                binding,
                lifecycle_record_id=lifecycle_record_id,
                expected_state="prepared",
                expected_scope=scope,
            )

    def mark_lifecycle_issued(
        self,
        binding: PAMExecutionBinding,
        *,
        lifecycle_record_id: str,
        expected_revision: int,
        issued_epoch_millis: int,
        expires_epoch_millis: int,
        maximum_residual_exposure_ends_epoch_millis: int,
    ) -> PAMLifecycleRecord:
        """Atomically reject issuance when the exact binding has been fenced."""

        if type(binding) is not PAMExecutionBinding:
            raise TypeError("PAM execution binding must be exact")
        _require_lifecycle_record_id(lifecycle_record_id)
        _require_nonnegative_integer(expected_revision, label="expected revision")
        _require_nonnegative_integer(issued_epoch_millis, label="issued time")
        _require_nonnegative_integer(expires_epoch_millis, label="expiry time")
        _require_nonnegative_integer(
            maximum_residual_exposure_ends_epoch_millis,
            label="maximum residual exposure",
        )
        if not (
            issued_epoch_millis
            < expires_epoch_millis
            <= maximum_residual_exposure_ends_epoch_millis
        ):
            raise ValueError("PAM issuance exposure timeline is invalid")
        with self._transaction() as connection:
            row = connection.execute(
                """
                UPDATE control_assurance_pam.lifecycle_records
                SET state = 'issued',
                    issued_epoch_millis = %s,
                    expires_epoch_millis = %s,
                    maximum_residual_exposure_ends_epoch_millis = %s,
                    revision = revision + 1
                WHERE journal_namespace_digest = %s
                  AND execution_binding_digest = %s
                  AND lifecycle_record_id = %s
                  AND revision = %s
                  AND state = 'prepared'
                RETURNING *
                """,
                (
                    issued_epoch_millis,
                    expires_epoch_millis,
                    maximum_residual_exposure_ends_epoch_millis,
                    self._journal_namespace_digest,
                    binding.execution_binding_digest,
                    lifecycle_record_id,
                    expected_revision,
                ),
            ).fetchone()
            if row is None:
                raise PostgresPamRecoveryError("PAM lifecycle issuance lost its transition")
            return _bound_lifecycle_record(
                row,
                binding,
                lifecycle_record_id=lifecycle_record_id,
                expected_state="issued",
            )

    def mark_lifecycle_uncertain(
        self,
        binding: PAMExecutionBinding,
        *,
        lifecycle_record_id: str,
        expected_revision: int,
    ) -> PAMLifecycleRecord:
        """Preserve an ambiguous issuance as unsettled exposure."""

        if type(binding) is not PAMExecutionBinding:
            raise TypeError("PAM execution binding must be exact")
        _require_lifecycle_record_id(lifecycle_record_id)
        _require_nonnegative_integer(expected_revision, label="expected revision")
        with self._transaction() as connection:
            row = connection.execute(
                """
                UPDATE control_assurance_pam.lifecycle_records
                SET state = 'uncertain',
                    revision = revision + 1
                WHERE journal_namespace_digest = %s
                  AND execution_binding_digest = %s
                  AND lifecycle_record_id = %s
                  AND revision = %s
                  AND state = 'prepared'
                RETURNING *
                """,
                (
                    self._journal_namespace_digest,
                    binding.execution_binding_digest,
                    lifecycle_record_id,
                    expected_revision,
                ),
            ).fetchone()
            if row is None:
                raise PostgresPamRecoveryError("PAM uncertain lifecycle transition failed")
            return _bound_lifecycle_record(
                row,
                binding,
                lifecycle_record_id=lifecycle_record_id,
                expected_state="uncertain",
            )

    def settle_lifecycle(
        self,
        binding: PAMExecutionBinding,
        *,
        lifecycle_record_id: str,
        expected_revision: int,
        state: PAMSettledState,
        settled_epoch_millis: int,
    ) -> PAMLifecycleRecord:
        """Settle one prepared/issued/uncertain record without changing identity."""

        if type(binding) is not PAMExecutionBinding:
            raise TypeError("PAM execution binding must be exact")
        _require_lifecycle_record_id(lifecycle_record_id)
        _require_nonnegative_integer(expected_revision, label="expected revision")
        _require_nonnegative_integer(
            settled_epoch_millis,
            label="lifecycle settlement time",
        )
        if state not in {"expired", "never-issued", "revoked"}:
            raise ValueError("PAM lifecycle settlement state is invalid")
        with self._transaction() as connection:
            row = connection.execute(
                """
                UPDATE control_assurance_pam.lifecycle_records
                SET state = %s,
                    settled_epoch_millis = %s,
                    revision = revision + 1
                WHERE journal_namespace_digest = %s
                  AND execution_binding_digest = %s
                  AND lifecycle_record_id = %s
                  AND revision = %s
                  AND state IN ('prepared', 'issued', 'uncertain')
                RETURNING *
                """,
                (
                    state,
                    settled_epoch_millis,
                    self._journal_namespace_digest,
                    binding.execution_binding_digest,
                    lifecycle_record_id,
                    expected_revision,
                ),
            ).fetchone()
            if row is None:
                raise PostgresPamRecoveryError("PAM lifecycle settlement lost its transition")
            return _bound_lifecycle_record(
                row,
                binding,
                lifecycle_record_id=lifecycle_record_id,
                expected_state=state,
            )

    def lifecycle_snapshot(
        self,
        binding: PAMExecutionBinding,
    ) -> PAMLifecycleSnapshot:
        """Return DB-counted exact rows at the installed fence high-watermark."""

        from assurance_lab.runtime.execution_recovery import PAMRecoveryScope

        if type(binding) is not PAMExecutionBinding:
            raise TypeError("PAM execution binding must be exact")
        with self._transaction() as connection:
            binding_row = connection.execute(
                """
                SELECT *
                FROM control_assurance_pam.execution_bindings
                WHERE journal_namespace_digest = %s
                  AND execution_binding_digest = %s
                FOR UPDATE
                """,
                (
                    self._journal_namespace_digest,
                    binding.execution_binding_digest,
                ),
            ).fetchone()
            if binding_row is None:
                raise PostgresPamRecoveryError("PAM snapshot execution binding is absent")
            self._validate_binding_row(
                binding_row,
                binding,
                expected_state="fenced",
            )
            fence_row = connection.execute(
                """
                SELECT *
                FROM control_assurance_pam.issuance_fences
                WHERE journal_namespace_digest = %s
                  AND fenced_execution_binding_digest = %s
                """,
                (
                    self._journal_namespace_digest,
                    binding.execution_binding_digest,
                ),
            ).fetchone()
            if fence_row is None:
                raise PostgresPamRecoveryError("PAM snapshot requires a durable issuance fence")
            fence = PAMIssuanceFence(
                operation_digest=cast(
                    str,
                    _require_text(fence_row, "operation_digest"),
                ),
                fenced_execution_binding_digest=cast(
                    str,
                    _require_text(
                        fence_row,
                        "fenced_execution_binding_digest",
                    ),
                ),
                successor_execution_binding_digest=cast(
                    str,
                    _require_text(
                        fence_row,
                        "successor_execution_binding_digest",
                    ),
                ),
                snapshot_high_watermark=cast(
                    int,
                    _require_integer(
                        fence_row,
                        "snapshot_high_watermark",
                    ),
                ),
                effective_at_epoch_millis=cast(
                    int,
                    _require_integer(
                        fence_row,
                        "effective_at_epoch_millis",
                    ),
                ),
                valid_until_epoch_millis=cast(
                    int,
                    _require_integer(
                        fence_row,
                        "valid_until_epoch_millis",
                    ),
                ),
            )
            scope_rows = connection.execute(
                """
                SELECT authority_class, connector_id,
                       connector_request_digest
                FROM control_assurance_pam.execution_binding_scopes
                WHERE journal_namespace_digest = %s
                  AND execution_binding_digest = %s
                ORDER BY authority_class, connector_id,
                         connector_request_digest
                """,
                (
                    self._journal_namespace_digest,
                    binding.execution_binding_digest,
                ),
            ).fetchall()
            scopes = tuple(
                PAMRecoveryScope(
                    authority_class=cast(
                        Literal["custody", "signing", "source"],
                        _require_text(row, "authority_class"),
                    ),
                    connector_id=cast(
                        str,
                        _require_text(row, "connector_id"),
                    ),
                    connector_request_digest=cast(
                        str,
                        _require_text(
                            row,
                            "connector_request_digest",
                        ),
                    ),
                )
                for row in scope_rows
            )
            if scopes != binding.pam_scopes:
                raise PostgresPamRecoveryError(
                    "stored PAM snapshot scope differs from the frozen plan"
                )
            count_row = connection.execute(
                """
                SELECT
                    count(*) FILTER (
                        WHERE lifecycle_sequence <= %s
                    )::integer AS matching_record_count,
                    count(*) FILTER (
                        WHERE lifecycle_sequence > %s
                    )::integer AS records_after_high_watermark
                FROM control_assurance_pam.lifecycle_records
                WHERE journal_namespace_digest = %s
                  AND execution_binding_digest = %s
                """,
                (
                    fence.snapshot_high_watermark,
                    fence.snapshot_high_watermark,
                    self._journal_namespace_digest,
                    binding.execution_binding_digest,
                ),
            ).fetchone()
            if count_row is None:
                raise PostgresPamRecoveryError("PAM lifecycle snapshot count is unavailable")
            record_count = cast(
                int,
                _require_integer(
                    count_row,
                    "matching_record_count",
                ),
            )
            records_after = cast(
                int,
                _require_integer(
                    count_row,
                    "records_after_high_watermark",
                ),
            )
            if records_after != 0:
                raise PostgresPamRecoveryError(
                    "PAM lifecycle row appeared after the issuance fence"
                )
            rows = connection.execute(
                """
                SELECT *
                FROM control_assurance_pam.lifecycle_records
                WHERE journal_namespace_digest = %s
                  AND execution_binding_digest = %s
                  AND lifecycle_sequence <= %s
                ORDER BY lifecycle_sequence
                """,
                (
                    self._journal_namespace_digest,
                    binding.execution_binding_digest,
                    fence.snapshot_high_watermark,
                ),
            ).fetchall()
            records = tuple(_lifecycle_record(row) for row in rows)
            if len(records) != record_count:
                raise PostgresPamRecoveryError(
                    "PAM lifecycle snapshot rows differ from the DB count"
                )
        return PAMLifecycleSnapshot(
            execution_binding=binding,
            fence=fence,
            scopes=scopes,
            snapshot_high_watermark=fence.snapshot_high_watermark,
            matching_record_count=record_count,
            records=records,
        )


class PostgresElasticLeaseJournal(_PostgresPamJournal):
    """HA-safe Elastic JIT lease journal with revision-fenced transitions.

    Replicas of one broker use the same secret-free namespace digest.  Brokers
    that must not recover each other's leases use different digests.
    """

    def __init__(
        self,
        pool: PostgresPamConnectionPool,
        *,
        journal_namespace_digest: str,
        statement_timeout_ms: int = _DEFAULT_STATEMENT_TIMEOUT_MS,
        lock_timeout_ms: int = _DEFAULT_LOCK_TIMEOUT_MS,
        owns_pool: bool = False,
    ) -> None:
        super().__init__(
            pool,
            journal_namespace_digest=journal_namespace_digest,
            statement_timeout_ms=statement_timeout_ms,
            lock_timeout_ms=lock_timeout_ms,
            owns_pool=owns_pool,
        )

    @classmethod
    def from_dsn(
        cls,
        dsn: str,
        *,
        journal_namespace_digest: str,
        min_size: int = 2,
        max_size: int = 16,
        connect_timeout_seconds: int = 10,
        statement_timeout_ms: int = _DEFAULT_STATEMENT_TIMEOUT_MS,
        lock_timeout_ms: int = _DEFAULT_LOCK_TIMEOUT_MS,
    ) -> Self:
        cls._validate_timeouts(
            statement_timeout_ms=statement_timeout_ms,
            lock_timeout_ms=lock_timeout_ms,
        )
        _require_digest(
            journal_namespace_digest,
            label="journal namespace digest",
        )
        cls._validate_pool_configuration(
            dsn,
            min_size=min_size,
            max_size=max_size,
            connect_timeout_seconds=connect_timeout_seconds,
        )
        try:
            pool = cls._owned_pool(
                dsn,
                min_size=min_size,
                max_size=max_size,
                connect_timeout_seconds=connect_timeout_seconds,
            )
        except Exception:
            raise ElasticPamError(
                "journal",
                "PostgreSQL PAM support is unavailable",
            ) from None
        return cls(
            pool,
            journal_namespace_digest=journal_namespace_digest,
            statement_timeout_ms=statement_timeout_ms,
            lock_timeout_ms=lock_timeout_ms,
            owns_pool=True,
        )

    def _error(self, reason: str) -> ElasticPamError:
        return ElasticPamError("journal", reason)

    @staticmethod
    def _record(row: Mapping[str, Any]) -> ElasticLeaseRecord:
        return ElasticLeaseRecord(
            lease_id=cast(str, _require_text(row, "lease_id")),
            key_name=cast(str, _require_text(row, "key_name")),
            index_alias=cast(str, _require_text(row, "index_alias")),
            request_digest=cast(str, _require_text(row, "request_digest")),
            endpoint_origin_digest=cast(
                str,
                _require_text(row, "endpoint_origin_digest"),
            ),
            role_descriptor_digest=cast(
                str,
                _require_text(row, "role_descriptor_digest"),
            ),
            ttl_seconds=cast(int, _require_integer(row, "ttl_seconds")),
            state=cast(LeaseState, _require_text(row, "state")),
            key_id=_require_text(row, "key_id", optional=True),
            expiration_epoch_millis=_require_integer(
                row,
                "expiration_epoch_millis",
                optional=True,
            ),
            created_epoch_millis=cast(
                int,
                _require_integer(row, "created_epoch_millis"),
            ),
            activated_epoch_millis=_require_integer(
                row,
                "activated_epoch_millis",
                optional=True,
            ),
            revoked_epoch_millis=_require_integer(
                row,
                "revoked_epoch_millis",
                optional=True,
            ),
            revoke_attempts=cast(int, _require_integer(row, "revoke_attempts")),
            revision=cast(int, _require_integer(row, "revision")),
            last_error=_require_text(row, "last_error", optional=True),
        )

    def get(self, lease_id: str) -> ElasticLeaseRecord:
        if type(lease_id) is not str or _HEX_ID_RE.fullmatch(lease_id) is None:
            raise ValueError("lease id is invalid")
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM control_assurance_pam.elastic_jit_leases
                WHERE journal_namespace_digest = %s
                  AND lease_id = %s
                """,
                (self._journal_namespace_digest, lease_id),
            ).fetchone()
            if row is None:
                raise ElasticPamError("journal", "lease does not exist")
            return self._record(row)

    def prepare(
        self,
        *,
        lease_id: str,
        key_name: str,
        policy: ElasticPamPolicy,
        request_digest: str,
        endpoint_origin_digest: str,
        now_epoch_millis: int,
    ) -> ElasticLeaseRecord:
        if (
            type(lease_id) is not str
            or _HEX_ID_RE.fullmatch(lease_id) is None
            or type(key_name) is not str
            or _KEY_NAME_RE.fullmatch(key_name) is None
        ):
            raise ValueError("lease identity is invalid")
        if type(policy) is not ElasticPamPolicy:
            raise TypeError("policy must be an exact ElasticPamPolicy")
        _require_digest(request_digest, label="request digest")
        _require_digest(endpoint_origin_digest, label="endpoint digest")
        _require_nonnegative_integer(now_epoch_millis, label="created time")
        with self._transaction() as connection:
            row = connection.execute(
                """
                INSERT INTO control_assurance_pam.elastic_jit_leases (
                    journal_namespace_digest, lease_id, key_name, index_alias,
                    request_digest, endpoint_origin_digest,
                    role_descriptor_digest, ttl_seconds, state, key_id,
                    expiration_epoch_millis,
                    created_epoch_millis, activated_epoch_millis,
                    revoked_epoch_millis, revoke_attempts, revision, last_error
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s,
                    'prepared', NULL, NULL, %s, NULL, NULL, 0, 0, NULL
                )
                RETURNING *
                """,
                (
                    self._journal_namespace_digest,
                    lease_id,
                    key_name,
                    policy.index_alias,
                    request_digest,
                    endpoint_origin_digest,
                    policy.role_descriptor_digest,
                    policy.ttl_seconds,
                    now_epoch_millis,
                ),
            ).fetchone()
            if row is None:
                raise ElasticPamError(
                    "journal",
                    "lease preparation returned no durable record",
                )
            return self._record(row)

    def activate(
        self,
        *,
        lease_id: str,
        expected_revision: int,
        key_id: str,
        expiration_epoch_millis: int,
        now_epoch_millis: int,
    ) -> ElasticLeaseRecord:
        if type(lease_id) is not str or _HEX_ID_RE.fullmatch(lease_id) is None:
            raise ValueError("lease id is invalid")
        if type(key_id) is not str or _KEY_ID_RE.fullmatch(key_id) is None:
            raise ValueError("key id is invalid")
        _require_nonnegative_integer(expected_revision, label="expected revision")
        _require_nonnegative_integer(expiration_epoch_millis, label="expiration")
        _require_nonnegative_integer(now_epoch_millis, label="activation time")
        if expiration_epoch_millis <= now_epoch_millis:
            raise ValueError("expiration must follow activation")
        with self._transaction() as connection:
            row = connection.execute(
                """
                UPDATE control_assurance_pam.elastic_jit_leases
                SET state = 'active',
                    key_id = %s,
                    expiration_epoch_millis = %s,
                    activated_epoch_millis = %s,
                    revision = revision + 1,
                    last_error = NULL
                WHERE journal_namespace_digest = %s
                  AND lease_id = %s
                  AND revision = %s
                  AND state = 'prepared'
                RETURNING *
                """,
                (
                    key_id,
                    expiration_epoch_millis,
                    now_epoch_millis,
                    self._journal_namespace_digest,
                    lease_id,
                    expected_revision,
                ),
            ).fetchone()
            if row is None:
                raise ElasticPamError(
                    "journal",
                    "lease activation lost its state transition",
                )
            return self._record(row)

    def begin_revocation(
        self,
        *,
        lease_id: str,
        expected_revision: int,
        reason: str | None,
    ) -> ElasticLeaseRecord:
        if type(lease_id) is not str or _HEX_ID_RE.fullmatch(lease_id) is None:
            raise ValueError("lease id is invalid")
        _require_nonnegative_integer(expected_revision, label="expected revision")
        normalized = _normalize_error(reason, maximum=512)
        with self._transaction() as connection:
            row = connection.execute(
                """
                UPDATE control_assurance_pam.elastic_jit_leases
                SET state = 'revoke-pending',
                    revoke_attempts = revoke_attempts + 1,
                    revision = revision + 1,
                    last_error = %s
                WHERE journal_namespace_digest = %s
                  AND lease_id = %s
                  AND revision = %s
                  AND state IN ('prepared', 'active', 'revoke-pending')
                RETURNING *
                """,
                (
                    normalized,
                    self._journal_namespace_digest,
                    lease_id,
                    expected_revision,
                ),
            ).fetchone()
            if row is None:
                raise ElasticPamError(
                    "journal",
                    "lease revocation lost its state transition",
                )
            return self._record(row)

    def mark_revoked(
        self,
        *,
        lease_id: str,
        expected_revision: int,
        now_epoch_millis: int,
    ) -> ElasticLeaseRecord:
        if type(lease_id) is not str or _HEX_ID_RE.fullmatch(lease_id) is None:
            raise ValueError("lease id is invalid")
        _require_nonnegative_integer(expected_revision, label="expected revision")
        _require_nonnegative_integer(now_epoch_millis, label="revocation time")
        with self._transaction() as connection:
            row = connection.execute(
                """
                UPDATE control_assurance_pam.elastic_jit_leases
                SET state = 'revoked',
                    revoked_epoch_millis = %s,
                    revision = revision + 1,
                    last_error = NULL
                WHERE journal_namespace_digest = %s
                  AND lease_id = %s
                  AND revision = %s
                  AND state = 'revoke-pending'
                RETURNING *
                """,
                (
                    now_epoch_millis,
                    self._journal_namespace_digest,
                    lease_id,
                    expected_revision,
                ),
            ).fetchone()
            if row is None:
                raise ElasticPamError(
                    "journal",
                    "lease finalization lost its state transition",
                )
            return self._record(row)

    def unsettled(self, *, limit: int = 1_000) -> tuple[ElasticLeaseRecord, ...]:
        if type(limit) is not int or not 1 <= limit <= 10_000:
            raise ValueError("recovery limit is outside the supported range")
        with self._transaction() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM control_assurance_pam.elastic_jit_leases
                WHERE journal_namespace_digest = %s
                  AND state != 'revoked'
                ORDER BY created_epoch_millis, lease_id
                LIMIT %s
                """,
                (self._journal_namespace_digest, limit),
            ).fetchall()
            return tuple(self._record(row) for row in rows)

    def records_for_request_digest(
        self,
        request_digest: str,
        *,
        unsettled_only: bool = False,
        limit: int = 1_000,
    ) -> tuple[ElasticLeaseRecord, ...]:
        """Read only lifecycle rows belonging to one frozen connector request.

        Recovery controllers use this instead of namespace-wide ``unsettled``:
        revoking another run's JIT key while reconciling this run would cross
        both the execution and PAM authority boundaries.
        """

        request = _require_digest(request_digest, label="request digest")
        if type(unsettled_only) is not bool:
            raise TypeError("unsettled-only selection must be boolean")
        if type(limit) is not int or not 1 <= limit <= 10_000:
            raise ValueError("recovery limit is outside the supported range")
        state_clause = "AND state != 'revoked'" if unsettled_only else ""
        with self._transaction() as connection:
            rows = connection.execute(
                f"""
                SELECT *
                FROM control_assurance_pam.elastic_jit_leases
                WHERE journal_namespace_digest = %s
                  AND request_digest = %s
                  {state_clause}
                ORDER BY created_epoch_millis, lease_id
                LIMIT %s
                """,
                (
                    self._journal_namespace_digest,
                    request,
                    limit,
                ),
            ).fetchall()
            return tuple(self._record(row) for row in rows)


class PostgresDefenderTokenJournal(_PostgresPamJournal):
    """HA-safe Defender workload-token residual-exposure journal.

    Replicas of one broker use the same secret-free namespace digest.  Brokers
    that must not recover each other's token intents use different digests.
    """

    def __init__(
        self,
        pool: PostgresPamConnectionPool,
        *,
        journal_namespace_digest: str,
        statement_timeout_ms: int = _DEFAULT_STATEMENT_TIMEOUT_MS,
        lock_timeout_ms: int = _DEFAULT_LOCK_TIMEOUT_MS,
        owns_pool: bool = False,
    ) -> None:
        super().__init__(
            pool,
            journal_namespace_digest=journal_namespace_digest,
            statement_timeout_ms=statement_timeout_ms,
            lock_timeout_ms=lock_timeout_ms,
            owns_pool=owns_pool,
        )

    @classmethod
    def from_dsn(
        cls,
        dsn: str,
        *,
        journal_namespace_digest: str,
        min_size: int = 2,
        max_size: int = 16,
        connect_timeout_seconds: int = 10,
        statement_timeout_ms: int = _DEFAULT_STATEMENT_TIMEOUT_MS,
        lock_timeout_ms: int = _DEFAULT_LOCK_TIMEOUT_MS,
    ) -> Self:
        cls._validate_timeouts(
            statement_timeout_ms=statement_timeout_ms,
            lock_timeout_ms=lock_timeout_ms,
        )
        _require_digest(
            journal_namespace_digest,
            label="journal namespace digest",
        )
        cls._validate_pool_configuration(
            dsn,
            min_size=min_size,
            max_size=max_size,
            connect_timeout_seconds=connect_timeout_seconds,
        )
        try:
            pool = cls._owned_pool(
                dsn,
                min_size=min_size,
                max_size=max_size,
                connect_timeout_seconds=connect_timeout_seconds,
            )
        except Exception:
            raise DefenderPamError(
                "journal",
                "PostgreSQL PAM support is unavailable",
            ) from None
        return cls(
            pool,
            journal_namespace_digest=journal_namespace_digest,
            statement_timeout_ms=statement_timeout_ms,
            lock_timeout_ms=lock_timeout_ms,
            owns_pool=True,
        )

    def _error(self, reason: str) -> DefenderPamError:
        return DefenderPamError("journal", reason)

    @staticmethod
    def _record(row: Mapping[str, Any]) -> DefenderTokenRecord:
        return DefenderTokenRecord(
            acquisition_id=cast(str, _require_text(row, "acquisition_id")),
            request_digest=cast(str, _require_text(row, "request_digest")),
            token_endpoint_digest=cast(
                str,
                _require_text(row, "token_endpoint_digest"),
            ),
            graph_origin_digest=cast(
                str,
                _require_text(row, "graph_origin_digest"),
            ),
            scope_digest=cast(str, _require_text(row, "scope_digest")),
            credential_mode=cast(
                CredentialMode,
                _require_text(row, "credential_mode"),
            ),
            credential_reference_digest=cast(
                str,
                _require_text(row, "credential_reference_digest"),
            ),
            token_request_profile_digest=cast(
                str,
                _require_text(row, "token_request_profile_digest"),
            ),
            state=cast(
                Literal["prepared", "issued", "closed", "uncertain"],
                _require_text(row, "state"),
            ),
            closure=cast(
                TokenClosure | None,
                _require_text(row, "closure", optional=True),
            ),
            created_epoch_millis=cast(
                int,
                _require_integer(row, "created_epoch_millis"),
            ),
            issued_epoch_millis=_require_integer(
                row,
                "issued_epoch_millis",
                optional=True,
            ),
            closed_epoch_millis=_require_integer(
                row,
                "closed_epoch_millis",
                optional=True,
            ),
            access_token_expires_epoch_millis=_require_integer(
                row,
                "access_token_expires_epoch_millis",
                optional=True,
            ),
            conservative_exposure_end_epoch_millis=cast(
                int,
                _require_integer(
                    row,
                    "conservative_exposure_end_epoch_millis",
                ),
            ),
            assertion_id_digest=_require_text(
                row,
                "assertion_id_digest",
                optional=True,
            ),
            response_request_id_digest=_require_text(
                row,
                "response_request_id_digest",
                optional=True,
            ),
            revision=cast(int, _require_integer(row, "revision")),
            last_error=_require_text(row, "last_error", optional=True),
        )

    def prepare(
        self,
        *,
        acquisition_id: str,
        request_digest: str,
        token_endpoint_digest: str,
        graph_origin_digest: str,
        scope_digest: str,
        credential_mode: CredentialMode,
        credential_reference_digest: str,
        token_request_profile_digest: str,
        now_epoch_millis: int,
        conservative_exposure_end_epoch_millis: int,
    ) -> DefenderTokenRecord:
        if type(acquisition_id) is not str or _HEX_ID_RE.fullmatch(acquisition_id) is None:
            raise ValueError("token acquisition id is invalid")
        for label, value in (
            ("request", request_digest),
            ("token endpoint", token_endpoint_digest),
            ("Graph origin", graph_origin_digest),
            ("scope", scope_digest),
            ("credential reference", credential_reference_digest),
            ("token request profile", token_request_profile_digest),
        ):
            _require_digest(value, label=f"{label} digest")
        if type(credential_mode) is not str or credential_mode not in {
            "certificate-ps256",
            "federated-rs256",
        }:
            raise ValueError("credential mode is invalid")
        _require_nonnegative_integer(now_epoch_millis, label="created time")
        _require_nonnegative_integer(
            conservative_exposure_end_epoch_millis,
            label="conservative exposure end",
        )
        if conservative_exposure_end_epoch_millis < now_epoch_millis:
            raise ValueError("conservative exposure end precedes creation")
        with self._transaction() as connection:
            row = connection.execute(
                """
                INSERT INTO control_assurance_pam.defender_token_lifecycle (
                    journal_namespace_digest, acquisition_id, request_digest,
                    token_endpoint_digest, graph_origin_digest, scope_digest,
                    credential_mode, credential_reference_digest,
                    token_request_profile_digest, state, closure,
                    created_epoch_millis, issued_epoch_millis,
                    closed_epoch_millis, access_token_expires_epoch_millis,
                    conservative_exposure_end_epoch_millis,
                    assertion_id_digest, response_request_id_digest,
                    revision, last_error
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    'prepared', NULL, %s, NULL, NULL, NULL, %s,
                    NULL, NULL, 0, NULL
                )
                RETURNING *
                """,
                (
                    self._journal_namespace_digest,
                    acquisition_id,
                    request_digest,
                    token_endpoint_digest,
                    graph_origin_digest,
                    scope_digest,
                    credential_mode,
                    credential_reference_digest,
                    token_request_profile_digest,
                    now_epoch_millis,
                    conservative_exposure_end_epoch_millis,
                ),
            ).fetchone()
            if row is None:
                raise DefenderPamError(
                    "journal",
                    "token preparation returned no durable record",
                )
            return self._record(row)

    def mark_issued(
        self,
        *,
        acquisition_id: str,
        expected_revision: int,
        now_epoch_millis: int,
        expires_epoch_millis: int,
        assertion_id_digest: str,
        response_request_id_digest: str | None,
    ) -> DefenderTokenRecord:
        if type(acquisition_id) is not str or _HEX_ID_RE.fullmatch(acquisition_id) is None:
            raise ValueError("token acquisition id is invalid")
        _require_nonnegative_integer(expected_revision, label="expected revision")
        _require_nonnegative_integer(now_epoch_millis, label="issued time")
        _require_nonnegative_integer(expires_epoch_millis, label="token expiry")
        if not 60_000 <= expires_epoch_millis - now_epoch_millis <= 3_900_000:
            raise ValueError("access token lifetime is outside policy")
        _require_digest(assertion_id_digest, label="assertion id digest")
        if response_request_id_digest is not None:
            _require_digest(
                response_request_id_digest,
                label="response request id digest",
            )
        with self._transaction() as connection:
            row = connection.execute(
                """
                UPDATE control_assurance_pam.defender_token_lifecycle
                SET state = 'issued',
                    issued_epoch_millis = %s,
                    access_token_expires_epoch_millis = %s,
                    assertion_id_digest = %s,
                    response_request_id_digest = %s,
                    revision = revision + 1
                WHERE journal_namespace_digest = %s
                  AND acquisition_id = %s
                  AND revision = %s
                  AND state = 'prepared'
                RETURNING *
                """,
                (
                    now_epoch_millis,
                    expires_epoch_millis,
                    assertion_id_digest,
                    response_request_id_digest,
                    self._journal_namespace_digest,
                    acquisition_id,
                    expected_revision,
                ),
            ).fetchone()
            if row is None:
                raise DefenderPamError(
                    "journal",
                    "token lifecycle compare-and-swap failed",
                )
            return self._record(row)

    def close(
        self,
        *,
        acquisition_id: str,
        expected_revision: int,
        expected_state: Literal["prepared", "issued"],
        closure: TokenClosure,
        now_epoch_millis: int,
        error: str | None,
    ) -> DefenderTokenRecord:
        if type(acquisition_id) is not str or _HEX_ID_RE.fullmatch(acquisition_id) is None:
            raise ValueError("token acquisition id is invalid")
        _require_nonnegative_integer(expected_revision, label="expected revision")
        _require_nonnegative_integer(now_epoch_millis, label="closure time")
        if expected_state not in {"prepared", "issued"}:
            raise ValueError("expected token state is invalid")
        allowed = {
            "capture-completed-token-release-only",
            "capture-failed-token-release-only",
            "token-request-rejected-no-token",
            "abandoned-after-crash",
        }
        if closure not in allowed:
            raise ValueError("token closure is invalid for a definite close")
        if expected_state == "prepared" and closure != "token-request-rejected-no-token":
            raise ValueError("prepared token intent can only close as rejected")
        if expected_state == "issued" and closure == "token-request-rejected-no-token":
            raise ValueError("issued token cannot close as a rejected request")
        normalized = _normalize_error(error, maximum=384)
        if closure == "capture-completed-token-release-only" and normalized is not None:
            raise ValueError("completed capture cannot retain an error")
        if closure != "capture-completed-token-release-only" and normalized is None:
            raise ValueError("non-success token closure requires an error")
        with self._transaction() as connection:
            row = connection.execute(
                """
                UPDATE control_assurance_pam.defender_token_lifecycle
                SET state = 'closed',
                    closure = %s,
                    closed_epoch_millis = %s,
                    last_error = %s,
                    revision = revision + 1
                WHERE journal_namespace_digest = %s
                  AND acquisition_id = %s
                  AND revision = %s
                  AND state = %s
                RETURNING *
                """,
                (
                    closure,
                    now_epoch_millis,
                    normalized,
                    self._journal_namespace_digest,
                    acquisition_id,
                    expected_revision,
                    expected_state,
                ),
            ).fetchone()
            if row is None:
                raise DefenderPamError(
                    "journal",
                    "token lifecycle compare-and-swap failed",
                )
            return self._record(row)

    def mark_uncertain(
        self,
        *,
        acquisition_id: str,
        expected_revision: int,
        now_epoch_millis: int,
        error: str,
    ) -> DefenderTokenRecord:
        if type(acquisition_id) is not str or _HEX_ID_RE.fullmatch(acquisition_id) is None:
            raise ValueError("token acquisition id is invalid")
        _require_nonnegative_integer(expected_revision, label="expected revision")
        _require_nonnegative_integer(now_epoch_millis, label="uncertain time")
        normalized = _normalize_error(error, maximum=384)
        assert normalized is not None
        with self._transaction() as connection:
            row = connection.execute(
                """
                UPDATE control_assurance_pam.defender_token_lifecycle
                SET state = 'uncertain',
                    closure = 'token-request-ambiguous',
                    closed_epoch_millis = %s,
                    last_error = %s,
                    revision = revision + 1
                WHERE journal_namespace_digest = %s
                  AND acquisition_id = %s
                  AND revision = %s
                  AND state = 'prepared'
                RETURNING *
                """,
                (
                    now_epoch_millis,
                    normalized,
                    self._journal_namespace_digest,
                    acquisition_id,
                    expected_revision,
                ),
            ).fetchone()
            if row is None:
                raise DefenderPamError(
                    "journal",
                    "token lifecycle compare-and-swap failed",
                )
            return self._record(row)

    def get(self, acquisition_id: str) -> DefenderTokenRecord:
        if type(acquisition_id) is not str or _HEX_ID_RE.fullmatch(acquisition_id) is None:
            raise ValueError("token acquisition id is invalid")
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM control_assurance_pam.defender_token_lifecycle
                WHERE journal_namespace_digest = %s
                  AND acquisition_id = %s
                """,
                (self._journal_namespace_digest, acquisition_id),
            ).fetchone()
            if row is None:
                raise DefenderPamError(
                    "journal",
                    "token lifecycle record does not exist",
                )
            return self._record(row)

    def unsettled(self, *, limit: int = 1_000) -> tuple[DefenderTokenRecord, ...]:
        if type(limit) is not int or not 1 <= limit <= 10_000:
            raise ValueError("recovery limit is outside the supported range")
        with self._transaction() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM control_assurance_pam.defender_token_lifecycle
                WHERE journal_namespace_digest = %s
                  AND state IN ('prepared', 'issued')
                ORDER BY created_epoch_millis, acquisition_id
                LIMIT %s
                """,
                (self._journal_namespace_digest, limit),
            ).fetchall()
            return tuple(self._record(row) for row in rows)

    def records_for_request_digest(
        self,
        request_digest: str,
        *,
        unsettled_only: bool = False,
        limit: int = 1_000,
    ) -> tuple[DefenderTokenRecord, ...]:
        """Read only token exposure rows for one frozen Defender request."""

        request = _require_digest(request_digest, label="request digest")
        if type(unsettled_only) is not bool:
            raise TypeError("unsettled-only selection must be boolean")
        if type(limit) is not int or not 1 <= limit <= 10_000:
            raise ValueError("recovery limit is outside the supported range")
        state_clause = "AND state IN ('prepared', 'issued')" if unsettled_only else ""
        with self._transaction() as connection:
            rows = connection.execute(
                f"""
                SELECT *
                FROM control_assurance_pam.defender_token_lifecycle
                WHERE journal_namespace_digest = %s
                  AND request_digest = %s
                  {state_clause}
                ORDER BY created_epoch_millis, acquisition_id
                LIMIT %s
                """,
                (
                    self._journal_namespace_digest,
                    request,
                    limit,
                ),
            ).fetchall()
            return tuple(self._record(row) for row in rows)


__all__ = [
    "PAMExecutionBinding",
    "PAMIssuanceFence",
    "PAMLifecycleRecord",
    "PAMLifecycleSnapshot",
    "PostgresDefenderTokenJournal",
    "PostgresElasticLeaseJournal",
    "PostgresPamConnectionPool",
    "PostgresPamIssuanceJournal",
    "PostgresPamRecoveryError",
]
