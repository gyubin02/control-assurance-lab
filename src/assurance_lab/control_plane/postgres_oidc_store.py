"""Durable PostgreSQL state for the OIDC authorization-code boundary.

Authorization callbacks arrive before a tenant can be trusted, and opaque
session cookies must be resolved before their tenant is known.  Consequently
this store uses the dedicated ``control_assurance_auth`` schema instead of
weakening the tenant RLS policies on ``control_assurance``.

Only SHA-256 digests of browser transaction/session handles reach this API.
Before the PKCE verifier reaches the injected protector, a global and
source-scoped slot is atomically reserved in PostgreSQL.  The remote protector
never runs while a database transaction or row lock is held.  Its result is
then atomically converted to callback-visible ready state; failure cancels the
slot, and an abandoned reservation expires by itself.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import math
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Protocol, cast

from assurance_lab.control_plane.models import Actor
from assurance_lab.control_plane.oidc import (
    AuthorizationTransaction,
    OIDCError,
    OIDCLoginAdmissionPolicy,
    SessionRecord,
)
from assurance_lab.control_plane.postgres_security import (
    RuntimeBoundaryExpectation,
    identity_matches,
    runtime_identity_row,
)
from assurance_lab.control_plane.postgres_store import (
    Connection,
    ConnectionPool,
)
from assurance_lab.evidence.canonical import canonical_json_bytes

_DIGEST_RE: Final = re.compile(r"^sha256:[a-f0-9]{64}$")
_SOURCE_DIGEST_RE: Final = re.compile(r"^hmac-sha256:[a-f0-9]{64}$")
_PKCE_VERIFIER_RE: Final = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
_KEY_REFERENCE_RE: Final = re.compile(r"^[^\x00-\x20\x7f]{1,512}$")
_ALGORITHM_RE: Final = re.compile(r"^[A-Za-z0-9._:/@+-]{1,64}$")
_DEFAULT_STATEMENT_TIMEOUT_MS: Final = 15_000
_DEFAULT_LOCK_TIMEOUT_MS: Final = 5_000
_DEFAULT_CLEANUP_BATCH_SIZE: Final = 512
_DEFAULT_BURN_RETENTION_SECONDS: Final = 3_600
_DEFAULT_BURN_CAPACITY: Final = 4_096
_MAX_TRANSACTION_TTL: Final = timedelta(minutes=15)
_MAX_SESSION_TTL: Final = timedelta(days=1)
_MAX_ACTOR_BYTES: Final = 64 * 1024


def _fail(code: str) -> OIDCError:
    return OIDCError(code)


def _digest(value: object, *, code: str) -> str:
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        raise _fail(code)
    return value


def _utc(value: object, *, code: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None:
        raise _fail(code)
    converted = value.astimezone(UTC)
    if not math.isfinite(converted.timestamp()):
        raise _fail(code)
    return converted


def _bytes(value: object, *, code: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray | memoryview):
        return bytes(value)
    raise _fail(code)


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _stored_time(value: object, *, code: str) -> datetime:
    if isinstance(value, datetime):
        return _utc(value, code=code)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise _fail(code) from None
        return _utc(parsed, code=code)
    raise _fail(code)


@dataclass(frozen=True, slots=True, repr=False)
class ProtectedCodeVerifier:
    """Ciphertext and non-secret routing metadata returned by a KMS adapter."""

    ciphertext: bytes
    key_reference: str
    algorithm: str

    def __post_init__(self) -> None:
        if (
            type(self.ciphertext) is not bytes
            or not 16 <= len(self.ciphertext) <= 16_384
            or type(self.key_reference) is not str
            or _KEY_REFERENCE_RE.fullmatch(self.key_reference) is None
            or type(self.algorithm) is not str
            or _ALGORITHM_RE.fullmatch(self.algorithm) is None
        ):
            raise ValueError("protected PKCE verifier envelope is invalid")

    def __repr__(self) -> str:
        return (
            "ProtectedCodeVerifier(ciphertext=<redacted>, "
            f"key_reference={self.key_reference!r}, algorithm={self.algorithm!r})"
        )


class CodeVerifierProtector(Protocol):
    """KMS/envelope boundary for the only secret persisted by this store."""

    def protect(
        self,
        *,
        code_verifier: str,
        transaction_digest: str,
    ) -> ProtectedCodeVerifier: ...

    def unprotect(
        self,
        *,
        protected: ProtectedCodeVerifier,
        transaction_digest: str,
    ) -> str: ...


class PostgresOIDCStateStore:
    """Production OIDCStateStore backed by narrowly callable SQL routines."""

    __slots__ = (
        "_burn_capacity",
        "_burn_retention_seconds",
        "_cleanup_batch_size",
        "_expectation",
        "_lock_timeout_ms",
        "_owns_pool",
        "_pool",
        "_protector",
        "_statement_timeout_ms",
    )

    def __init__(
        self,
        pool: ConnectionPool,
        *,
        tenant_id: str,
        expected_role: str,
        protector: CodeVerifierProtector,
        cleanup_batch_size: int = _DEFAULT_CLEANUP_BATCH_SIZE,
        burn_retention_seconds: int = _DEFAULT_BURN_RETENTION_SECONDS,
        burn_capacity: int = _DEFAULT_BURN_CAPACITY,
        statement_timeout_ms: int = _DEFAULT_STATEMENT_TIMEOUT_MS,
        lock_timeout_ms: int = _DEFAULT_LOCK_TIMEOUT_MS,
        owns_pool: bool = False,
    ) -> None:
        if not callable(getattr(pool, "connection", None)):
            raise TypeError("PostgreSQL pool must provide connection()")
        self._expectation = RuntimeBoundaryExpectation(
            tenant_id=tenant_id,
            login_role=expected_role,
            role_kind="auth",
        )
        if (
            not callable(getattr(protector, "protect", None))
            or not callable(getattr(protector, "unprotect", None))
        ):
            raise TypeError("PKCE verifier protector does not implement its protocol")
        if (
            type(cleanup_batch_size) is not int
            or cleanup_batch_size < 1
            or cleanup_batch_size > 10_000
        ):
            raise ValueError("OIDC cleanup batch size is invalid")
        if (
            type(burn_retention_seconds) is not int
            or burn_retention_seconds < 60
            or burn_retention_seconds > 86_400
        ):
            raise ValueError("OIDC transaction burn retention is invalid")
        if (
            type(burn_capacity) is not int
            or burn_capacity < 1
            or burn_capacity > 1_000_000
        ):
            raise ValueError("OIDC transaction burn capacity is invalid")
        for label, value in (
            ("statement timeout", statement_timeout_ms),
            ("lock timeout", lock_timeout_ms),
        ):
            if type(value) is not int or value < 100 or value > 120_000:
                raise ValueError(f"{label} is outside the supported range")
        if lock_timeout_ms > statement_timeout_ms:
            raise ValueError("lock timeout cannot exceed statement timeout")
        self._pool = pool
        self._protector = protector
        self._cleanup_batch_size = cleanup_batch_size
        self._burn_retention_seconds = burn_retention_seconds
        self._burn_capacity = burn_capacity
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
        protector: CodeVerifierProtector,
        min_size: int = 2,
        max_size: int = 16,
        connect_timeout_seconds: int = 10,
        cleanup_batch_size: int = _DEFAULT_CLEANUP_BATCH_SIZE,
        burn_retention_seconds: int = _DEFAULT_BURN_RETENTION_SECONDS,
        burn_capacity: int = _DEFAULT_BURN_CAPACITY,
        statement_timeout_ms: int = _DEFAULT_STATEMENT_TIMEOUT_MS,
        lock_timeout_ms: int = _DEFAULT_LOCK_TIMEOUT_MS,
    ) -> PostgresOIDCStateStore:
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
            raise _fail("state_store_unavailable") from exc
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
            cast(ConnectionPool, pool),
            tenant_id=tenant_id,
            expected_role=expected_role,
            protector=protector,
            cleanup_batch_size=cleanup_batch_size,
            burn_retention_seconds=burn_retention_seconds,
            burn_capacity=burn_capacity,
            statement_timeout_ms=statement_timeout_ms,
            lock_timeout_ms=lock_timeout_ms,
            owns_pool=True,
        )

    def close(self) -> None:
        """Close only a pool created by :meth:`from_dsn`."""

        if self._owns_pool:
            close = getattr(self._pool, "close", None)
            if callable(close):
                close()

    @contextmanager
    def _transaction(self) -> Iterator[Connection]:
        try:
            with self._pool.connection() as connection, connection.transaction():
                connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
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
                    raise _fail("state_store_unavailable")
                yield connection
        except OIDCError:
            raise
        except Exception as exc:
            raise _fail("state_store_unavailable") from exc

    @staticmethod
    def _transaction_record(
        transaction: AuthorizationTransaction,
    ) -> tuple[str, str, str, str, datetime, datetime]:
        transaction_digest = _digest(
            transaction.transaction_digest,
            code="invalid_transaction",
        )
        state_digest = _digest(transaction.state_digest, code="invalid_transaction")
        nonce_digest = _digest(transaction.nonce_digest, code="invalid_transaction")
        if (
            type(transaction.code_verifier) is not str
            or _PKCE_VERIFIER_RE.fullmatch(transaction.code_verifier) is None
        ):
            raise _fail("invalid_transaction")
        created_at = _utc(transaction.created_at, code="invalid_transaction")
        expires_at = _utc(transaction.expires_at, code="invalid_transaction")
        lifetime = expires_at - created_at
        if lifetime <= timedelta(0) or lifetime > _MAX_TRANSACTION_TTL:
            raise _fail("invalid_transaction")
        return (
            transaction_digest,
            state_digest,
            nonce_digest,
            transaction.code_verifier,
            created_at,
            expires_at,
        )

    def _cancel_failed_admission(self, transaction_digest: str) -> None:
        """Best-effort removal after a protector/finalization failure.

        Failure here is intentionally suppressed: the reservation has a short
        database-enforced expiry and cannot be consumed before finalization.
        """

        try:
            with self._transaction() as connection:
                connection.execute(
                    """
                    SELECT control_assurance_auth.cancel_login_admission(%s)
                        AS cancelled
                    """,
                    (transaction_digest,),
                ).fetchone()
        except OIDCError:
            pass

    def create_transaction(
        self,
        transaction: AuthorizationTransaction,
        *,
        source_digest: str,
        admission_policy: OIDCLoginAdmissionPolicy,
    ) -> None:
        (
            transaction_digest,
            state_digest,
            nonce_digest,
            code_verifier,
            created_at,
            expires_at,
        ) = self._transaction_record(transaction)
        if (
            type(source_digest) is not str
            or _SOURCE_DIGEST_RE.fullmatch(source_digest) is None
        ):
            raise _fail("invalid_login_source")
        if type(admission_policy) is not OIDCLoginAdmissionPolicy:
            raise _fail("invalid_login_admission")
        if admission_policy.burn_capacity != self._burn_capacity:
            raise _fail("invalid_login_admission")

        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT control_assurance_auth.reserve_login_admission(
                    %s, %s, %s, %s, %s, %s, %s, %s
                ) AS outcome
                """,
                (
                    transaction_digest,
                    source_digest,
                    expires_at,
                    admission_policy.reservation_ttl_seconds,
                    admission_policy.global_active_limit,
                    admission_policy.source_active_limit,
                    admission_policy.burn_capacity,
                    self._cleanup_batch_size,
                ),
            ).fetchone()
        outcome = None if row is None else row.get("outcome")
        if outcome in {"global-limit", "source-limit"}:
            raise _fail("login_admission_limited")
        if outcome == "conflict":
            raise _fail("transaction_conflict")
        if outcome != "reserved":
            raise _fail("state_store_unavailable")

        try:
            protected = self._protector.protect(
                code_verifier=code_verifier,
                transaction_digest=transaction_digest,
            )
        except Exception:
            self._cancel_failed_admission(transaction_digest)
            raise _fail("state_store_protection_failed") from None
        if type(protected) is not ProtectedCodeVerifier:
            self._cancel_failed_admission(transaction_digest)
            raise _fail("state_store_protection_failed")
        try:
            with self._transaction() as connection:
                row = connection.execute(
                    """
                    SELECT control_assurance_auth.finalize_login_admission(
                        %s, %s, %s, %s, %s, %s, %s, %s
                    ) AS finalized
                    """,
                    (
                        transaction_digest,
                        state_digest,
                        nonce_digest,
                        protected.ciphertext,
                        protected.key_reference,
                        protected.algorithm,
                        created_at,
                        expires_at,
                    ),
                ).fetchone()
                finalized = row is not None and row.get("finalized") is True
        except OIDCError:
            self._cancel_failed_admission(transaction_digest)
            raise
        if not finalized:
            self._cancel_failed_admission(transaction_digest)
            raise _fail("state_store_unavailable")

    def consume_transaction(
        self,
        *,
        transaction_digest: str,
        state_digest: str,
        consumed_at: datetime,
    ) -> AuthorizationTransaction:
        transaction_digest = _digest(
            transaction_digest,
            code="invalid_transaction",
        )
        consumed_at = _utc(consumed_at, code="invalid_transaction")
        # A malformed returned state still burns a valid transaction.  It is
        # normalized only for constant-time comparison after the commit.
        state_candidate = (
            state_digest
            if type(state_digest) is str and len(state_digest) <= 128
            else ""
        )
        row: Mapping[str, Any] | None
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM control_assurance_auth.consume_ready_authorization_transaction(
                    %s, %s, %s, %s, %s
                )
                """,
                (
                    transaction_digest,
                    consumed_at,
                    self._burn_retention_seconds,
                    self._cleanup_batch_size,
                    self._burn_capacity,
                ),
            ).fetchone()
        if row is None:
            raise _fail("invalid_transaction")
        try:
            stored_digest = _digest(
                row["transaction_digest"],
                code="state_store_integrity_failure",
            )
            stored_state = _digest(
                row["state_digest"],
                code="state_store_integrity_failure",
            )
            nonce_digest = _digest(
                row["nonce_digest"],
                code="state_store_integrity_failure",
            )
            created_at = _stored_time(
                row["created_at"],
                code="state_store_integrity_failure",
            )
            expires_at = _stored_time(
                row["expires_at"],
                code="state_store_integrity_failure",
            )
            protected = ProtectedCodeVerifier(
                ciphertext=_bytes(
                    row["verifier_ciphertext"],
                    code="state_store_integrity_failure",
                ),
                key_reference=cast(str, row["verifier_key_reference"]),
                algorithm=cast(str, row["verifier_algorithm"]),
            )
        except (KeyError, TypeError, ValueError):
            raise _fail("state_store_integrity_failure") from None
        if (
            stored_digest != transaction_digest
            or consumed_at < created_at
            or consumed_at > expires_at
            or not hmac.compare_digest(stored_state, state_candidate)
        ):
            raise _fail("invalid_transaction")
        try:
            code_verifier = self._protector.unprotect(
                protected=protected,
                transaction_digest=transaction_digest,
            )
        except Exception:
            raise _fail("state_store_protection_failed") from None
        if (
            type(code_verifier) is not str
            or _PKCE_VERIFIER_RE.fullmatch(code_verifier) is None
        ):
            raise _fail("state_store_protection_failed")
        return AuthorizationTransaction(
            transaction_digest=transaction_digest,
            state_digest=stored_state,
            nonce_digest=nonce_digest,
            code_verifier=code_verifier,
            created_at=created_at,
            expires_at=expires_at,
        )

    @staticmethod
    def _session_record(
        session: SessionRecord,
    ) -> tuple[str, str, str, bytes, datetime, datetime]:
        session_digest = _digest(session.session_id_digest, code="invalid_session")
        if type(session.actor) is not Actor:
            raise _fail("invalid_session")
        if session.actor.session_id_digest != session_digest:
            raise _fail("invalid_session")
        issued_at = _utc(session.issued_at, code="invalid_session")
        expires_at = _utc(session.expires_at, code="invalid_session")
        lifetime = expires_at - issued_at
        if lifetime <= timedelta(0) or lifetime > _MAX_SESSION_TTL:
            raise _fail("invalid_session")
        actor_payload = session.actor.model_dump(mode="json")
        actor_payload["roles"] = sorted(session.actor.roles)
        actor_payload["groups"] = list(session.actor.groups)
        actor_bytes = canonical_json_bytes(actor_payload)
        if len(actor_bytes) > _MAX_ACTOR_BYTES:
            raise _fail("invalid_session")
        return (
            session_digest,
            session.actor.tenant_id,
            _sha256(actor_bytes),
            actor_bytes,
            issued_at,
            expires_at,
        )

    def create_session(self, session: SessionRecord) -> None:
        (
            session_digest,
            tenant_id,
            actor_digest,
            actor_bytes,
            issued_at,
            expires_at,
        ) = self._session_record(session)
        if tenant_id != self._expectation.tenant_id:
            raise _fail("invalid_session")
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT control_assurance_auth.create_browser_session(
                    %s, %s, %s, %s, %s, %s, %s
                ) AS created
                """,
                (
                    session_digest,
                    tenant_id,
                    actor_digest,
                    actor_bytes,
                    issued_at,
                    expires_at,
                    self._cleanup_batch_size,
                ),
            ).fetchone()
            created = row is not None and row.get("created") is True
        if not created:
            raise _fail("session_conflict")

    def read_session(
        self,
        *,
        session_id_digest: str,
        read_at: datetime,
    ) -> SessionRecord:
        session_digest = _digest(session_id_digest, code="invalid_session")
        read_at = _utc(read_at, code="invalid_session")
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM control_assurance_auth.read_browser_session(%s, %s)
                """,
                (session_digest, read_at),
            ).fetchone()
        if row is None:
            raise _fail("invalid_session")
        try:
            stored_digest = _digest(
                row["session_id_digest"],
                code="state_store_integrity_failure",
            )
            tenant_id = cast(str, row["tenant_id"])
            actor_digest = _digest(
                row["actor_digest"],
                code="state_store_integrity_failure",
            )
            actor_bytes = _bytes(
                row["actor_bytes"],
                code="state_store_integrity_failure",
            )
            issued_at = _stored_time(
                row["issued_at"],
                code="state_store_integrity_failure",
            )
            expires_at = _stored_time(
                row["expires_at"],
                code="state_store_integrity_failure",
            )
            actor = Actor.model_validate_json(actor_bytes)
        except (KeyError, TypeError, ValueError):
            raise _fail("state_store_integrity_failure") from None
        if (
            stored_digest != session_digest
            or actor_digest != _sha256(actor_bytes)
            or tenant_id != self._expectation.tenant_id
            or actor.tenant_id != tenant_id
            or actor.session_id_digest != session_digest
            or read_at < issued_at
            or read_at >= expires_at
        ):
            raise _fail("state_store_integrity_failure")
        return SessionRecord(
            session_id_digest=session_digest,
            actor=actor,
            issued_at=issued_at,
            expires_at=expires_at,
        )

    def revoke_session(self, *, session_id_digest: str) -> bool:
        try:
            session_digest = _digest(session_id_digest, code="invalid_session")
        except OIDCError:
            return False
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT control_assurance_auth.revoke_browser_session(%s) AS revoked
                """,
                (session_digest,),
            ).fetchone()
            return row is not None and row.get("revoked") is True
