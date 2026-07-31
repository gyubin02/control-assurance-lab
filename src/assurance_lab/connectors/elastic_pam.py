"""Just-in-time Elastic credentials with durable, fail-closed revocation.

The alert connector only needs ``read`` on one Elastic Security alert alias.
This module turns that fact into an operational boundary:

* a durable intent is written before contacting Elasticsearch;
* a short-lived API key is created with no cluster privileges and one exact
  index grant;
* the key is used for exactly one connector capture;
* revocation is confirmed before the capture is returned; and
* a canonical, secret-free lifecycle receipt binds the lease to the capture.

The parent identity must be a Basic or Bearer credential with
``manage_own_api_key`` and the index privilege being delegated.  Elastic does
not permit a privileged child API key to be minted from another API key, so
``ApiKey`` is deliberately not accepted as a parent authentication scheme.

This is a PAM adapter, not a general Elasticsearch security client.  It never
lists, updates, or broadens API keys and never retries an ambiguous mutation.
Recovery invalidates the deterministic, per-intent key name instead.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import os
import re
import sqlite3
import ssl
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal, Protocol, cast, runtime_checkable

from assurance_lab._version import __version__
from assurance_lab.connectors.contract import ConnectorCapture, ConnectorCaptureError
from assurance_lab.connectors.elastic_security import (
    ElasticApiKey,
    ElasticSecurityConnector,
    ElasticSecurityRequest,
    _normalize_endpoint,
    _ssl_context,
)
from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)

ELASTIC_PAM_RECEIPT_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.elastic-pam-lifecycle.v1+json"]
] = "application/vnd.control-assurance.elastic-pam-lifecycle.v1+json"
ELASTIC_PAM_RECEIPT_SCHEMA_VERSION: Final[Literal["1.0.0"]] = "1.0.0"
ELASTIC_PAM_BROKER_ID: Final[Literal["elastic-native-jit-api-key"]] = (
    "elastic-native-jit-api-key"
)

_CREATE_TARGET = "/_security/api_key"
_INVALIDATE_TARGET = "/_security/api_key"
_JSON_HEADERS = (
    ("accept", "application/json"),
    ("accept-encoding", "identity"),
    ("content-type", "application/json"),
)
_RECORDED_RESPONSE_HEADERS = ("content-type", "x-elastic-product")

_LEASE_ID_RE = re.compile(r"^[a-f0-9]{64}$")
_KEY_NAME_RE = re.compile(r"^control-assurance-[a-f0-9]{32}$")
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,512}$")
_KEY_SECRET_RE = re.compile(rb"^[\x21-\x7e]{1,4096}$")
_PARENT_SECRET_RE = re.compile(rb"^[\x21-\x7e]{1,16384}$")
_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_ALERT_ALIAS_RE = re.compile(
    r"^[.]alerts-security[.]alerts-[a-z0-9][a-z0-9_-]{0,63}$"
)

_MIN_TTL_SECONDS = 120
_MAX_TTL_SECONDS = 3_600
_MIN_TIMEOUT_SECONDS = 1
_MAX_TIMEOUT_SECONDS = 120
_MAX_RESPONSE_BYTES = 128 * 1024
_MAX_CLOCK_SKEW_MILLISECONDS = 5 * 60 * 1_000
_MAX_ERROR_LENGTH = 512
_SQLITE_SCHEMA_VERSION = 1
_SQLITE_BUSY_TIMEOUT_MS = 15_000

_RESPONSE_LIMITS = JSONLimits(
    max_bytes=_MAX_RESPONSE_BYTES,
    max_line_bytes=_MAX_RESPONSE_BYTES,
    max_depth=16,
    max_collection_items=10_000,
    max_string_length=16_384,
)
_RECEIPT_LIMITS = JSONLimits(
    max_bytes=64 * 1024,
    max_line_bytes=64 * 1024,
    max_depth=16,
    max_collection_items=512,
    max_string_length=4_096,
)

LeaseState = Literal["prepared", "active", "revoke-pending", "revoked"]
RevocationOutcome = Literal["invalidated", "previously-invalidated", "not-created"]


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _epoch_milliseconds() -> int:
    return time.time_ns() // 1_000_000


def _require_digest(value: str, *, label: str) -> str:
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        raise ValueError(f"{label} is not a canonical SHA-256 digest")
    return value


def _bounded_error(value: BaseException | str) -> str:
    """Return a normalized reason that cannot accidentally retain a secret."""

    if isinstance(value, ElasticPamError):
        reason = value.reason
    elif isinstance(value, ConnectorCaptureError):
        reason = f"{value.stage}: {value.reason}"
    else:
        reason = type(value).__name__
    reason = " ".join(reason.split())
    return (reason or "unspecified failure")[:_MAX_ERROR_LENGTH]


class ElasticPamError(RuntimeError):
    """A JIT credential lifecycle did not complete safely."""

    def __init__(self, stage: str, reason: str) -> None:
        if not stage or len(stage) > 64 or not stage.replace("-", "").isascii():
            raise ValueError("PAM failure stage is invalid")
        normalized = " ".join(reason.split())
        if not normalized or len(normalized) > _MAX_ERROR_LENGTH:
            raise ValueError("PAM failure reason is invalid")
        self.stage = stage
        self.reason = normalized
        super().__init__(f"{stage}: {normalized}")


class ElasticParentCredential:
    """Opaque Basic or Bearer material used only by the JIT broker.

    The value is the bytes after the HTTP authentication scheme.  For Basic
    authentication that means the caller supplies the base64 encoding of
    ``username:password``; the broker never needs either field separately.
    """

    __slots__ = ("__scheme", "__value")

    def __init__(self, scheme: Literal["Basic", "Bearer"], value: bytes) -> None:
        if scheme not in {"Basic", "Bearer"}:
            raise ValueError("parent credential must use Basic or Bearer authentication")
        if (
            type(value) is not bytes
            or _PARENT_SECRET_RE.fullmatch(value) is None
            or any(byte in value for byte in b" \t\r\n")
        ):
            raise ValueError("parent credential must be bounded visible ASCII without whitespace")
        self.__scheme = scheme
        self.__value = value

    @classmethod
    def basic(cls, username: str, password: str) -> ElasticParentCredential:
        """Construct an opaque Basic credential without retaining its inputs."""

        if (
            type(username) is not str
            or not username
            or ":" in username
            or "\r" in username
            or "\n" in username
            or type(password) is not str
            or "\r" in password
            or "\n" in password
        ):
            raise ValueError("Basic username or password is invalid")
        try:
            material = f"{username}:{password}".encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ValueError("Basic username or password is not valid UTF-8") from exc
        if len(material) > 12_000:
            raise ValueError("Basic credential exceeds the broker limit")
        return cls("Basic", base64.b64encode(material))

    def __repr__(self) -> str:
        return f"ElasticParentCredential({self.__scheme}, <redacted>)"

    def __str__(self) -> str:
        return "<redacted>"

    @property
    def scheme(self) -> Literal["Basic", "Bearer"]:
        return self.__scheme

    def _authorization_header(self) -> str:
        return f"{self.__scheme} {self.__value.decode('ascii', errors='strict')}"

    def _appears_in(self, value: bytes) -> bool:
        escaped = self.__value.replace(b"/", b"\\/")
        quoted = urllib.parse.quote_from_bytes(self.__value).encode("ascii")
        return any(candidate in value for candidate in (self.__value, escaped, quoted))


@dataclass(frozen=True, slots=True)
class ElasticPamPolicy:
    """The only authority a child key may receive."""

    index_alias: str
    ttl_seconds: int = 900

    def __post_init__(self) -> None:
        if (
            type(self.index_alias) is not str
            or _ALERT_ALIAS_RE.fullmatch(self.index_alias) is None
        ):
            raise ValueError("PAM policy requires one exact Elastic Security alert alias")
        if (
            type(self.ttl_seconds) is not int
            or self.ttl_seconds < _MIN_TTL_SECONDS
            or self.ttl_seconds > _MAX_TTL_SECONDS
        ):
            raise ValueError("PAM lease lifetime is outside the supported range")

    def role_descriptor(self) -> dict[str, Any]:
        """Return the exact least-privilege descriptor sent to Elasticsearch."""

        space_id = self.index_alias.removeprefix(".alerts-security.alerts-")
        backing_indices = f".internal.alerts-security.alerts-{space_id}-*"
        return {
            "capture": {
                "cluster": [],
                "indices": [
                    {
                        "allow_restricted_indices": True,
                        # PIT authorization is checked again against the hidden
                        # concrete generations.  Limiting this wildcard to the
                        # exact Kibana space survives rollover without granting
                        # access to another space.
                        "names": [self.index_alias, backing_indices],
                        "privileges": ["read"],
                    }
                ],
            }
        }

    @property
    def role_descriptor_digest(self) -> str:
        return _sha256(canonical_json_bytes(self.role_descriptor()))


@dataclass(frozen=True, slots=True)
class ElasticLeaseRecord:
    lease_id: str
    key_name: str
    index_alias: str
    request_digest: str
    endpoint_origin_digest: str
    role_descriptor_digest: str
    ttl_seconds: int
    state: LeaseState
    key_id: str | None
    expiration_epoch_millis: int | None
    created_epoch_millis: int
    activated_epoch_millis: int | None
    revoked_epoch_millis: int | None
    revoke_attempts: int
    revision: int
    last_error: str | None

    def __post_init__(self) -> None:
        if _LEASE_ID_RE.fullmatch(self.lease_id) is None:
            raise ValueError("lease id is invalid")
        if _KEY_NAME_RE.fullmatch(self.key_name) is None:
            raise ValueError("key name is invalid")
        if _ALERT_ALIAS_RE.fullmatch(self.index_alias) is None:
            raise ValueError("lease index alias is invalid")
        _require_digest(self.request_digest, label="request digest")
        _require_digest(self.endpoint_origin_digest, label="endpoint digest")
        _require_digest(self.role_descriptor_digest, label="role descriptor digest")
        if self.state not in {"prepared", "active", "revoke-pending", "revoked"}:
            raise ValueError("lease state is invalid")
        if self.key_id is not None and _KEY_ID_RE.fullmatch(self.key_id) is None:
            raise ValueError("lease key id is invalid")


@runtime_checkable
class ElasticLeaseJournal(Protocol):
    """Durable CAS journal required by :class:`ElasticJitApiKeyBroker`."""

    def get(self, lease_id: str) -> ElasticLeaseRecord: ...

    def prepare(
        self,
        *,
        lease_id: str,
        key_name: str,
        policy: ElasticPamPolicy,
        request_digest: str,
        endpoint_origin_digest: str,
        now_epoch_millis: int,
    ) -> ElasticLeaseRecord: ...

    def activate(
        self,
        *,
        lease_id: str,
        expected_revision: int,
        key_id: str,
        expiration_epoch_millis: int,
        now_epoch_millis: int,
    ) -> ElasticLeaseRecord: ...

    def begin_revocation(
        self,
        *,
        lease_id: str,
        expected_revision: int,
        reason: str | None,
    ) -> ElasticLeaseRecord: ...

    def mark_revoked(
        self,
        *,
        lease_id: str,
        expected_revision: int,
        now_epoch_millis: int,
    ) -> ElasticLeaseRecord: ...

    def unsettled(self, *, limit: int = 1_000) -> tuple[ElasticLeaseRecord, ...]: ...

    def records_for_request_digest(
        self,
        request_digest: str,
        *,
        unsettled_only: bool = False,
        limit: int = 1_000,
    ) -> tuple[ElasticLeaseRecord, ...]: ...


class SQLiteElasticLeaseJournal:
    """Owner-only durable state for ambiguous-create recovery.

    The SQLite reference journal uses short ``BEGIN IMMEDIATE`` transactions;
    no HTTP request is made while a database write lock is held.  PostgreSQL is
    the HA implementation boundary, but both stores implement the same state
    transitions.
    """

    __slots__ = ("_path",)

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path):
            raise TypeError("lease journal path must be a pathlib.Path")
        self._path = path
        self._prepare_file()
        self._initialize()

    def _prepare_file(self) -> None:
        parent = self._path.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            before = self._path.lstat()
        except FileNotFoundError:
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self._path, flags, 0o600)
            os.close(descriptor)
            before = self._path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o077
        ):
            raise ElasticPamError(
                "journal",
                "lease journal must be an owner-only, single-link regular file",
            )

    def _connect(self) -> sqlite3.Connection:
        self._prepare_file()
        connection = sqlite3.connect(
            self._path,
            isolation_level=None,
            timeout=_SQLITE_BUSY_TIMEOUT_MS / 1_000,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout={_SQLITE_BUSY_TIMEOUT_MS}")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA journal_mode=DELETE")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            version = cast(int, connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in {0, _SQLITE_SCHEMA_VERSION}:
                raise ElasticPamError("journal", "lease journal schema version is unsupported")
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS elastic_jit_leases (
                        lease_id TEXT PRIMARY KEY,
                        key_name TEXT NOT NULL UNIQUE,
                        index_alias TEXT NOT NULL,
                        request_digest TEXT NOT NULL,
                        endpoint_origin_digest TEXT NOT NULL,
                        role_descriptor_digest TEXT NOT NULL,
                        ttl_seconds INTEGER NOT NULL,
                        state TEXT NOT NULL CHECK (
                            state IN ('prepared', 'active', 'revoke-pending', 'revoked')
                        ),
                        key_id TEXT,
                        expiration_epoch_millis INTEGER,
                        created_epoch_millis INTEGER NOT NULL,
                        activated_epoch_millis INTEGER,
                        revoked_epoch_millis INTEGER,
                        revoke_attempts INTEGER NOT NULL DEFAULT 0,
                        revision INTEGER NOT NULL DEFAULT 0,
                        last_error TEXT
                    )
                    """
                )
                connection.execute(f"PRAGMA user_version={_SQLITE_SCHEMA_VERSION}")
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        finally:
            connection.close()

    @staticmethod
    def _record(row: sqlite3.Row) -> ElasticLeaseRecord:
        return ElasticLeaseRecord(
            lease_id=cast(str, row["lease_id"]),
            key_name=cast(str, row["key_name"]),
            index_alias=cast(str, row["index_alias"]),
            request_digest=cast(str, row["request_digest"]),
            endpoint_origin_digest=cast(str, row["endpoint_origin_digest"]),
            role_descriptor_digest=cast(str, row["role_descriptor_digest"]),
            ttl_seconds=cast(int, row["ttl_seconds"]),
            state=cast(LeaseState, row["state"]),
            key_id=cast(str | None, row["key_id"]),
            expiration_epoch_millis=cast(int | None, row["expiration_epoch_millis"]),
            created_epoch_millis=cast(int, row["created_epoch_millis"]),
            activated_epoch_millis=cast(int | None, row["activated_epoch_millis"]),
            revoked_epoch_millis=cast(int | None, row["revoked_epoch_millis"]),
            revoke_attempts=cast(int, row["revoke_attempts"]),
            revision=cast(int, row["revision"]),
            last_error=cast(str | None, row["last_error"]),
        )

    def get(self, lease_id: str) -> ElasticLeaseRecord:
        if _LEASE_ID_RE.fullmatch(lease_id) is None:
            raise ValueError("lease id is invalid")
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM elastic_jit_leases WHERE lease_id = ?",
                (lease_id,),
            ).fetchone()
        finally:
            connection.close()
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
        if _LEASE_ID_RE.fullmatch(lease_id) is None or _KEY_NAME_RE.fullmatch(key_name) is None:
            raise ValueError("lease identity is invalid")
        _require_digest(request_digest, label="request digest")
        _require_digest(endpoint_origin_digest, label="endpoint digest")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    """
                    INSERT INTO elastic_jit_leases (
                        lease_id, key_name, index_alias, request_digest,
                        endpoint_origin_digest, role_descriptor_digest, ttl_seconds,
                        state, created_epoch_millis
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'prepared', ?)
                    """,
                    (
                        lease_id,
                        key_name,
                        policy.index_alias,
                        request_digest,
                        endpoint_origin_digest,
                        policy.role_descriptor_digest,
                        policy.ttl_seconds,
                        now_epoch_millis,
                    ),
                )
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        except sqlite3.IntegrityError as exc:
            raise ElasticPamError("journal", "lease identity was already used") from exc
        finally:
            connection.close()
        return self.get(lease_id)

    def activate(
        self,
        *,
        lease_id: str,
        expected_revision: int,
        key_id: str,
        expiration_epoch_millis: int,
        now_epoch_millis: int,
    ) -> ElasticLeaseRecord:
        if _KEY_ID_RE.fullmatch(key_id) is None:
            raise ValueError("key id is invalid")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = connection.execute(
                    """
                    UPDATE elastic_jit_leases
                    SET state = 'active', key_id = ?, expiration_epoch_millis = ?,
                        activated_epoch_millis = ?, revision = revision + 1,
                        last_error = NULL
                    WHERE lease_id = ? AND revision = ? AND state = 'prepared'
                    """,
                    (
                        key_id,
                        expiration_epoch_millis,
                        now_epoch_millis,
                        lease_id,
                        expected_revision,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ElasticPamError(
                        "journal",
                        "lease activation lost its state transition",
                    )
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        finally:
            connection.close()
        return self.get(lease_id)

    def begin_revocation(
        self,
        *,
        lease_id: str,
        expected_revision: int,
        reason: str | None,
    ) -> ElasticLeaseRecord:
        normalized = None if reason is None else " ".join(reason.split())[:_MAX_ERROR_LENGTH]
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = connection.execute(
                    """
                    UPDATE elastic_jit_leases
                    SET state = 'revoke-pending', revoke_attempts = revoke_attempts + 1,
                        revision = revision + 1, last_error = ?
                    WHERE lease_id = ? AND revision = ?
                      AND state IN ('prepared', 'active', 'revoke-pending')
                    """,
                    (normalized, lease_id, expected_revision),
                )
                if cursor.rowcount != 1:
                    raise ElasticPamError(
                        "journal",
                        "lease revocation lost its state transition",
                    )
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        finally:
            connection.close()
        return self.get(lease_id)

    def mark_revoked(
        self,
        *,
        lease_id: str,
        expected_revision: int,
        now_epoch_millis: int,
    ) -> ElasticLeaseRecord:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = connection.execute(
                    """
                    UPDATE elastic_jit_leases
                    SET state = 'revoked', revoked_epoch_millis = ?,
                        revision = revision + 1, last_error = NULL
                    WHERE lease_id = ? AND revision = ? AND state = 'revoke-pending'
                    """,
                    (now_epoch_millis, lease_id, expected_revision),
                )
                if cursor.rowcount != 1:
                    raise ElasticPamError(
                        "journal",
                        "lease finalization lost its state transition",
                    )
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        finally:
            connection.close()
        return self.get(lease_id)

    def unsettled(self, *, limit: int = 1_000) -> tuple[ElasticLeaseRecord, ...]:
        if type(limit) is not int or limit < 1 or limit > 10_000:
            raise ValueError("recovery limit is outside the supported range")
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT * FROM elastic_jit_leases
                WHERE state != 'revoked'
                ORDER BY created_epoch_millis, lease_id
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        finally:
            connection.close()
        return tuple(self._record(row) for row in rows)

    def records_for_request_digest(
        self,
        request_digest: str,
        *,
        unsettled_only: bool = False,
        limit: int = 1_000,
    ) -> tuple[ElasticLeaseRecord, ...]:
        request = _require_digest(request_digest, label="request digest")
        if type(unsettled_only) is not bool:
            raise TypeError("unsettled-only selection must be boolean")
        if type(limit) is not int or not 1 <= limit <= 10_000:
            raise ValueError("recovery limit is outside the supported range")
        state_clause = "AND state != 'revoked'" if unsettled_only else ""
        connection = self._connect()
        try:
            rows = connection.execute(
                f"""
                SELECT * FROM elastic_jit_leases
                WHERE request_digest = ?
                {state_clause}
                ORDER BY created_epoch_millis, lease_id
                LIMIT ?
                """,
                (request, limit),
            ).fetchall()
        finally:
            connection.close()
        return tuple(self._record(row) for row in rows)


@dataclass(frozen=True, slots=True)
class _PamHTTPResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


class _PamHTTPTransport(Protocol):
    def request(
        self,
        *,
        method: str,
        target: str,
        body: bytes,
        headers: tuple[tuple[str, str], ...],
        deadline: float,
    ) -> _PamHTTPResponse: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


class _UrllibPamTransport:
    __slots__ = ("_credential", "_endpoint", "_opener", "_timeout_seconds")

    def __init__(
        self,
        *,
        endpoint: str,
        credential: ElasticParentCredential,
        timeout_seconds: int,
        ssl_context: ssl.SSLContext | None,
    ) -> None:
        handlers: list[Any] = [urllib.request.ProxyHandler({}), _NoRedirect()]
        if ssl_context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=ssl_context))
        self._opener = urllib.request.build_opener(*handlers)
        self._endpoint = endpoint
        self._credential = credential
        self._timeout_seconds = timeout_seconds

    def request(
        self,
        *,
        method: str,
        target: str,
        body: bytes,
        headers: tuple[tuple[str, str], ...],
        deadline: float,
    ) -> _PamHTTPResponse:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ElasticPamError("deadline", "PAM request deadline expired")
        request_headers = {name: value for name, value in headers}
        request_headers["authorization"] = self._credential._authorization_header()
        request = urllib.request.Request(
            f"{self._endpoint}{target}",
            data=body,
            headers=request_headers,
            method=method,
        )
        response: Any
        try:
            response = self._opener.open(
                request,
                timeout=min(float(self._timeout_seconds), remaining),
            )
        except urllib.error.HTTPError as exc:
            response = exc
        except TimeoutError as exc:
            raise ElasticPamError("transport", "Elasticsearch PAM request timed out") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise ElasticPamError(
                "transport",
                "Elasticsearch PAM request could not be completed",
            ) from exc
        try:
            content = bytearray()
            reader = getattr(response, "read1", response.read)
            while True:
                if time.monotonic() >= deadline:
                    raise ElasticPamError("deadline", "PAM request deadline expired")
                chunk = reader(min(64 * 1024, _MAX_RESPONSE_BYTES + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > _MAX_RESPONSE_BYTES:
                    raise ElasticPamError(
                        "transport",
                        "Elasticsearch PAM response exceeds the byte limit",
                    )
            selected: list[tuple[str, str]] = []
            for name in _RECORDED_RESPONSE_HEADERS:
                values = response.headers.get_all(name, [])
                if len(values) > 1:
                    raise ElasticPamError(
                        "transport",
                        f"Elasticsearch returned duplicate {name} headers",
                    )
                if values:
                    selected.append((name, values[0]))
            return _PamHTTPResponse(
                status=int(response.status),
                headers=tuple(selected),
                body=bytes(content),
            )
        except (OSError, http.client.HTTPException) as exc:
            raise ElasticPamError(
                "transport",
                "Elasticsearch PAM response could not be read completely",
            ) from exc
        finally:
            response.close()


@dataclass(frozen=True, slots=True)
class _IssuedLease:
    record: ElasticLeaseRecord
    api_key: ElasticApiKey
    create_body_digest: str

    def __repr__(self) -> str:
        return (
            f"_IssuedLease(lease_id={self.record.lease_id!r}, "
            "api_key=<redacted>, create_body_digest="
            f"{self.create_body_digest!r})"
        )


@dataclass(frozen=True, slots=True)
class ElasticPamRecoveryResult:
    lease_id: str
    final_state: LeaseState
    revocation_outcome: RevocationOutcome


@dataclass(frozen=True, slots=True)
class VerifiedElasticPamReceipt:
    lease_id: str
    request_digest: str
    endpoint_origin_digest: str
    role_descriptor_digest: str
    capture_receipt_digest: str
    capture_records_digest: str
    receipt_digest: str


@dataclass(frozen=True, slots=True)
class ManagedElasticCapture:
    capture: ConnectorCapture
    pam_receipt_bytes: bytes
    pam_receipt_digest: str

    def __post_init__(self) -> None:
        if type(self.capture) is not ConnectorCapture:
            raise TypeError("managed capture must contain an exact ConnectorCapture")
        if type(self.pam_receipt_bytes) is not bytes or not self.pam_receipt_bytes:
            raise ValueError("PAM receipt must be non-empty immutable bytes")
        _require_digest(self.pam_receipt_digest, label="PAM receipt digest")
        if _sha256(self.pam_receipt_bytes) != self.pam_receipt_digest:
            raise ValueError("PAM receipt digest does not match its bytes")


class _CaptureConnector(Protocol):
    def capture(self, request: object) -> ConnectorCapture: ...


ConnectorFactory = Callable[[ElasticApiKey], _CaptureConnector]


class ElasticJitApiKeyBroker:
    """Run one Elastic capture under a durable, least-privilege JIT lease."""

    __slots__ = (
        "_connector_factory",
        "_credential",
        "_endpoint",
        "_endpoint_digest",
        "_journal",
        "_nonce",
        "_now",
        "_timeout_seconds",
        "_transport",
    )

    def __init__(
        self,
        endpoint: str,
        credential: ElasticParentCredential,
        journal: ElasticLeaseJournal,
        *,
        ca_file: Path | None = None,
        allow_insecure_loopback: bool = False,
        timeout_seconds: int = 15,
        _transport: _PamHTTPTransport | None = None,
        _connector_factory: ConnectorFactory | None = None,
        _nonce: Callable[[], str] | None = None,
        _now: Callable[[], int] | None = None,
    ) -> None:
        if type(credential) is not ElasticParentCredential:
            raise TypeError("parent credential must be an exact ElasticParentCredential")
        if not isinstance(journal, ElasticLeaseJournal):
            raise TypeError("journal does not implement the Elastic lease protocol")
        if (
            type(timeout_seconds) is not int
            or timeout_seconds < _MIN_TIMEOUT_SECONDS
            or timeout_seconds > _MAX_TIMEOUT_SECONDS
        ):
            raise ValueError("PAM request timeout is outside the supported range")
        normalized, tls = _normalize_endpoint(
            endpoint,
            allow_insecure_loopback=allow_insecure_loopback,
        )
        context = _ssl_context(ca_file) if tls else None
        self._credential = credential
        self._endpoint = normalized
        self._endpoint_digest = _sha256(normalized.encode("utf-8"))
        self._journal = journal
        self._timeout_seconds = timeout_seconds
        self._transport = _transport or _UrllibPamTransport(
            endpoint=normalized,
            credential=credential,
            timeout_seconds=timeout_seconds,
            ssl_context=context,
        )
        self._connector_factory = _connector_factory or (
            lambda key: ElasticSecurityConnector(
                normalized,
                key,
                ca_file=ca_file,
                allow_insecure_loopback=allow_insecure_loopback,
                timeout_seconds=timeout_seconds,
            )
        )
        self._nonce = _nonce or (lambda: os.urandom(32).hex())
        self._now = _now or _epoch_milliseconds

    @property
    def endpoint_origin_digest(self) -> str:
        return self._endpoint_digest

    def _request(
        self,
        *,
        method: str,
        body: bytes,
        stage: str,
    ) -> _PamHTTPResponse:
        response = self._transport.request(
            method=method,
            target=_CREATE_TARGET if method == "POST" else _INVALIDATE_TARGET,
            body=body,
            headers=_JSON_HEADERS,
            deadline=time.monotonic() + self._timeout_seconds,
        )
        if type(response) is not _PamHTTPResponse:
            raise ElasticPamError(stage, "PAM transport returned an invalid response")
        reflected = response.body + b"\x00" + b"\x00".join(
            f"{name}:{value}".encode("utf-8", errors="replace")
            for name, value in response.headers
        )
        if self._credential._appears_in(reflected):
            raise ElasticPamError(stage, "Elasticsearch response reflected parent credentials")
        return response

    @staticmethod
    def _response_json(response: _PamHTTPResponse, *, stage: str) -> dict[str, Any]:
        headers = dict(response.headers)
        if headers.get("x-elastic-product") != "Elasticsearch":
            raise ElasticPamError(stage, "response lacks the Elasticsearch product marker")
        content_type = headers.get("content-type", "")
        if content_type.split(";", 1)[0].strip().lower() != "application/json":
            raise ElasticPamError(stage, "response is not application/json")
        if response.status != 200:
            raise ElasticPamError(stage, f"Elasticsearch returned HTTP {response.status}")
        try:
            parsed = strict_json_loads(response.body, limits=_RESPONSE_LIMITS)
        except StrictJSONError as exc:
            raise ElasticPamError(stage, "response is not strict bounded JSON") from exc
        if not isinstance(parsed, dict):
            raise ElasticPamError(stage, "response JSON is not an object")
        return cast(dict[str, Any], parsed)

    def _create_body(
        self,
        *,
        record: ElasticLeaseRecord,
        policy: ElasticPamPolicy,
    ) -> bytes:
        return canonical_json_bytes(
            {
                "expiration": f"{policy.ttl_seconds}s",
                "metadata": {
                    "application": "control-assurance-lab",
                    "lease_id": record.lease_id,
                    "request_digest": record.request_digest,
                },
                "name": record.key_name,
                "role_descriptors": policy.role_descriptor(),
            },
            limits=_RESPONSE_LIMITS,
        )

    def _issue(
        self,
        *,
        record: ElasticLeaseRecord,
        policy: ElasticPamPolicy,
    ) -> _IssuedLease:
        body = self._create_body(record=record, policy=policy)
        sent_at = self._now()
        response = self._request(method="POST", body=body, stage="create-key")
        parsed = self._response_json(response, stage="create-key")
        if frozenset(parsed) != frozenset({"api_key", "encoded", "expiration", "id", "name"}):
            raise ElasticPamError("create-key", "response has missing or unexpected members")
        key_id = parsed["id"]
        key_name = parsed["name"]
        raw_key = parsed["api_key"]
        encoded = parsed["encoded"]
        expiration = parsed["expiration"]
        if type(key_id) is not str or _KEY_ID_RE.fullmatch(key_id) is None:
            raise ElasticPamError("create-key", "response key id is invalid")
        if key_name != record.key_name:
            raise ElasticPamError("create-key", "response names a different lease")
        if (
            type(raw_key) is not str
            or type(encoded) is not str
            or _KEY_SECRET_RE.fullmatch(raw_key.encode("ascii", errors="ignore")) is None
        ):
            raise ElasticPamError("create-key", "response key material is invalid")
        try:
            encoded_bytes = encoded.encode("ascii", errors="strict")
            decoded = base64.b64decode(encoded_bytes, validate=True)
        except (UnicodeEncodeError, ValueError) as exc:
            raise ElasticPamError("create-key", "response encoded key is invalid") from exc
        expected = f"{key_id}:{raw_key}".encode("ascii", errors="strict")
        if decoded != expected or base64.b64encode(decoded) != encoded_bytes:
            raise ElasticPamError("create-key", "response key encodings do not agree")
        if type(expiration) is not int:
            raise ElasticPamError("create-key", "response expiration is invalid")
        expected_expiration = sent_at + (policy.ttl_seconds * 1_000)
        if abs(expiration - expected_expiration) > _MAX_CLOCK_SKEW_MILLISECONDS:
            raise ElasticPamError("create-key", "response expiration is outside the lease window")
        activated_at = self._now()
        try:
            active = self._journal.activate(
                lease_id=record.lease_id,
                expected_revision=record.revision,
                key_id=key_id,
                expiration_epoch_millis=expiration,
                now_epoch_millis=activated_at,
            )
        except BaseException:
            # The prepared intent remains recoverable by its unique key name.
            raise
        return _IssuedLease(
            record=active,
            api_key=ElasticApiKey(encoded_bytes),
            create_body_digest=_sha256(body),
        )

    def _revoke(
        self,
        record: ElasticLeaseRecord,
        *,
        reason: str | None,
    ) -> tuple[ElasticLeaseRecord, RevocationOutcome, str]:
        pending = self._journal.begin_revocation(
            lease_id=record.lease_id,
            expected_revision=record.revision,
            reason=reason,
        )
        if pending.key_id is None:
            request_object: dict[str, Any] = {
                "name": pending.key_name,
                "owner": True,
            }
        else:
            request_object = {"ids": [pending.key_id]}
        body = canonical_json_bytes(request_object, limits=_RESPONSE_LIMITS)
        response = self._request(method="DELETE", body=body, stage="revoke-key")
        parsed = self._response_json(response, stage="revoke-key")
        required = frozenset(
            {"error_count", "invalidated_api_keys", "previously_invalidated_api_keys"}
        )
        if not required <= frozenset(parsed) or not frozenset(parsed) <= (
            required | frozenset({"error_details"})
        ):
            raise ElasticPamError("revoke-key", "response has missing or unexpected members")
        invalidated = parsed["invalidated_api_keys"]
        previous = parsed["previously_invalidated_api_keys"]
        error_count = parsed["error_count"]
        if (
            not isinstance(invalidated, list)
            or not isinstance(previous, list)
            or any(type(value) is not str for value in (*invalidated, *previous))
            or type(error_count) is not int
            or error_count != 0
            or "error_details" in parsed
        ):
            raise ElasticPamError("revoke-key", "Elasticsearch did not confirm clean revocation")
        if pending.key_id is None:
            outcome: RevocationOutcome = (
                "invalidated" if invalidated or previous else "not-created"
            )
        elif pending.key_id in invalidated:
            outcome = "invalidated"
        elif pending.key_id in previous:
            outcome = "previously-invalidated"
        else:
            raise ElasticPamError("revoke-key", "response did not account for the exact key id")
        revoked = self._journal.mark_revoked(
            lease_id=pending.lease_id,
            expected_revision=pending.revision,
            now_epoch_millis=self._now(),
        )
        return revoked, outcome, _sha256(body)

    def recover_unsettled(self, *, limit: int = 1_000) -> tuple[ElasticPamRecoveryResult, ...]:
        """Revoke every prepared or active intent without reissuing a key."""

        return self._recover_records(self._journal.unsettled(limit=limit))

    def recover_request_digest(
        self,
        request_digest: str,
        *,
        limit: int = 1_000,
    ) -> tuple[ElasticPamRecoveryResult, ...]:
        """Revoke unsettled JIT keys for one exact connector request only."""

        records = self._journal.records_for_request_digest(
            request_digest,
            unsettled_only=True,
            limit=limit,
        )
        return self._recover_records(records)

    def _recover_records(
        self,
        records: tuple[ElasticLeaseRecord, ...],
    ) -> tuple[ElasticPamRecoveryResult, ...]:
        results: list[ElasticPamRecoveryResult] = []
        for record in records:
            latest = record
            if latest.state == "revoke-pending":
                # A prior invalidation response may have been lost.  The API is
                # idempotent and explicitly reports already-invalidated ids.
                latest = self._journal.get(latest.lease_id)
            try:
                revoked, outcome, _ = self._revoke(latest, reason="recovery")
            except ElasticPamError:
                raise
            results.append(
                ElasticPamRecoveryResult(
                    lease_id=revoked.lease_id,
                    final_state=revoked.state,
                    revocation_outcome=outcome,
                )
            )
        return tuple(results)

    def capture(
        self,
        request: ElasticSecurityRequest,
        *,
        ttl_seconds: int = 900,
    ) -> ManagedElasticCapture:
        """Capture under one JIT key and return only after confirmed revocation."""

        if type(request) is not ElasticSecurityRequest:
            raise TypeError("request must be an exact ElasticSecurityRequest")
        policy = ElasticPamPolicy(index_alias=request.index_alias, ttl_seconds=ttl_seconds)
        request_bytes = canonical_json_bytes(request.as_json())
        request_digest = _sha256(request_bytes)
        lease_id = self._nonce()
        if type(lease_id) is not str or _LEASE_ID_RE.fullmatch(lease_id) is None:
            raise ElasticPamError("lease", "nonce source returned an invalid lease id")
        key_name = f"control-assurance-{lease_id[:32]}"
        prepared = self._journal.prepare(
            lease_id=lease_id,
            key_name=key_name,
            policy=policy,
            request_digest=request_digest,
            endpoint_origin_digest=self._endpoint_digest,
            now_epoch_millis=self._now(),
        )

        issued: _IssuedLease | None = None
        capture: ConnectorCapture | None = None
        operation_error: BaseException | None = None
        try:
            issued = self._issue(record=prepared, policy=policy)
            connector = self._connector_factory(issued.api_key)
            capture = connector.capture(request)
            if type(capture) is not ConnectorCapture:
                raise ElasticPamError(
                    "capture",
                    "connector returned an unsupported capture object",
                )
        except BaseException as exc:
            operation_error = exc

        latest = self._journal.get(lease_id)
        try:
            revoked, outcome, invalidate_body_digest = self._revoke(
                latest,
                reason=None if operation_error is None else _bounded_error(operation_error),
            )
        except BaseException as cleanup_error:
            raise ElasticPamError(
                "revoke-key",
                "capture is withheld because lease revocation was not confirmed",
            ) from cleanup_error

        if operation_error is not None:
            if isinstance(operation_error, (ElasticPamError, ConnectorCaptureError)):
                raise operation_error
            raise ElasticPamError(
                "capture",
                "connector capture failed before evidence could be returned",
            ) from operation_error
        assert issued is not None and capture is not None
        receipt = {
            "broker": {
                "id": ELASTIC_PAM_BROKER_ID,
                "version": __version__,
            },
            "capture": {
                "records_digest": capture.records_digest,
                "receipt_digest": capture.receipt_digest,
            },
            "lease": {
                "activated_epoch_millis": revoked.activated_epoch_millis,
                "created_epoch_millis": revoked.created_epoch_millis,
                "endpoint_origin_digest": revoked.endpoint_origin_digest,
                "expiration_epoch_millis": revoked.expiration_epoch_millis,
                "index_alias": revoked.index_alias,
                "key_id_digest": _sha256(cast(str, revoked.key_id).encode("utf-8")),
                "key_name_digest": _sha256(revoked.key_name.encode("utf-8")),
                "lease_id": revoked.lease_id,
                "request_digest": revoked.request_digest,
                "revoked_epoch_millis": revoked.revoked_epoch_millis,
                "role_descriptor_digest": revoked.role_descriptor_digest,
                "ttl_seconds": revoked.ttl_seconds,
            },
            "media_type": ELASTIC_PAM_RECEIPT_MEDIA_TYPE,
            "mutations": {
                "create_body_digest": issued.create_body_digest,
                "invalidate_body_digest": invalidate_body_digest,
                "revocation_outcome": outcome,
            },
            "schema_version": ELASTIC_PAM_RECEIPT_SCHEMA_VERSION,
        }
        try:
            receipt_bytes = canonical_json_bytes(receipt, limits=_RECEIPT_LIMITS)
        except StrictJSONError as exc:
            raise ElasticPamError("receipt", "PAM receipt exceeds its canonical profile") from exc
        verified = verify_elastic_pam_receipt(
            receipt_bytes,
            expected_request_digest=request_digest,
            expected_endpoint_origin_digest=self._endpoint_digest,
            expected_role_descriptor_digest=policy.role_descriptor_digest,
            expected_capture_receipt_digest=capture.receipt_digest,
            expected_capture_records_digest=capture.records_digest,
        )
        return ManagedElasticCapture(
            capture=capture,
            pam_receipt_bytes=receipt_bytes,
            pam_receipt_digest=verified.receipt_digest,
        )


def verify_elastic_pam_receipt(
    receipt_bytes: bytes,
    *,
    expected_request_digest: str,
    expected_endpoint_origin_digest: str,
    expected_role_descriptor_digest: str,
    expected_capture_receipt_digest: str,
    expected_capture_records_digest: str,
) -> VerifiedElasticPamReceipt:
    """Verify lifecycle closure using only public, externally anchored values."""

    for label, value in (
        ("request digest", expected_request_digest),
        ("endpoint digest", expected_endpoint_origin_digest),
        ("role descriptor digest", expected_role_descriptor_digest),
        ("capture receipt digest", expected_capture_receipt_digest),
        ("capture records digest", expected_capture_records_digest),
    ):
        _require_digest(value, label=label)
    if type(receipt_bytes) is not bytes or not receipt_bytes:
        raise ElasticPamError("verify", "PAM receipt must be non-empty immutable bytes")
    try:
        parsed = strict_json_loads(receipt_bytes, limits=_RECEIPT_LIMITS)
        canonical = canonical_json_bytes(parsed, limits=_RECEIPT_LIMITS)
    except StrictJSONError as exc:
        raise ElasticPamError("verify", "PAM receipt is not strict bounded JSON") from exc
    if canonical != receipt_bytes or not isinstance(parsed, dict):
        raise ElasticPamError("verify", "PAM receipt is not a canonical JSON object")
    if frozenset(parsed) != frozenset(
        {"broker", "capture", "lease", "media_type", "mutations", "schema_version"}
    ):
        raise ElasticPamError("verify", "PAM receipt has missing or unexpected members")
    if (
        parsed["media_type"] != ELASTIC_PAM_RECEIPT_MEDIA_TYPE
        or parsed["schema_version"] != ELASTIC_PAM_RECEIPT_SCHEMA_VERSION
    ):
        raise ElasticPamError("verify", "PAM receipt has the wrong profile identity")

    broker = parsed["broker"]
    capture = parsed["capture"]
    lease = parsed["lease"]
    mutations = parsed["mutations"]
    if (
        not isinstance(broker, dict)
        or frozenset(broker) != frozenset({"id", "version"})
        or broker["id"] != ELASTIC_PAM_BROKER_ID
        or type(broker["version"]) is not str
        or not isinstance(capture, dict)
        or frozenset(capture) != frozenset({"records_digest", "receipt_digest"})
        or not isinstance(lease, dict)
        or not isinstance(mutations, dict)
    ):
        raise ElasticPamError("verify", "PAM receipt structure is invalid")
    expected_lease_keys = frozenset(
        {
            "activated_epoch_millis",
            "created_epoch_millis",
            "endpoint_origin_digest",
            "expiration_epoch_millis",
            "index_alias",
            "key_id_digest",
            "key_name_digest",
            "lease_id",
            "request_digest",
            "revoked_epoch_millis",
            "role_descriptor_digest",
            "ttl_seconds",
        }
    )
    if frozenset(lease) != expected_lease_keys or frozenset(mutations) != frozenset(
        {"create_body_digest", "invalidate_body_digest", "revocation_outcome"}
    ):
        raise ElasticPamError("verify", "PAM receipt lifecycle fields are incomplete")
    digest_fields = (
        capture["records_digest"],
        capture["receipt_digest"],
        lease["endpoint_origin_digest"],
        lease["key_id_digest"],
        lease["key_name_digest"],
        lease["request_digest"],
        lease["role_descriptor_digest"],
        mutations["create_body_digest"],
        mutations["invalidate_body_digest"],
    )
    if any(
        type(value) is not str or _DIGEST_RE.fullmatch(value) is None
        for value in digest_fields
    ):
        raise ElasticPamError("verify", "PAM receipt contains an invalid digest")
    if (
        capture["receipt_digest"] != expected_capture_receipt_digest
        or capture["records_digest"] != expected_capture_records_digest
        or lease["request_digest"] != expected_request_digest
        or lease["endpoint_origin_digest"] != expected_endpoint_origin_digest
        or lease["role_descriptor_digest"] != expected_role_descriptor_digest
    ):
        raise ElasticPamError("verify", "PAM receipt differs from an external anchor")
    if (
        type(lease["lease_id"]) is not str
        or _LEASE_ID_RE.fullmatch(lease["lease_id"]) is None
        or type(lease["index_alias"]) is not str
        or _ALERT_ALIAS_RE.fullmatch(lease["index_alias"]) is None
        or type(lease["ttl_seconds"]) is not int
        or not _MIN_TTL_SECONDS <= lease["ttl_seconds"] <= _MAX_TTL_SECONDS
    ):
        raise ElasticPamError("verify", "PAM lease identity or scope is invalid")
    times = (
        lease["created_epoch_millis"],
        lease["activated_epoch_millis"],
        lease["revoked_epoch_millis"],
        lease["expiration_epoch_millis"],
    )
    if any(type(value) is not int or value < 0 for value in times):
        raise ElasticPamError("verify", "PAM lifecycle time is invalid")
    created, activated, revoked, expiration = cast(tuple[int, int, int, int], times)
    if not created <= activated <= revoked < expiration:
        raise ElasticPamError("verify", "PAM lifecycle is not closed before expiration")
    if mutations["revocation_outcome"] not in {
        "invalidated",
        "previously-invalidated",
    }:
        raise ElasticPamError("verify", "PAM receipt does not prove an issued key was revoked")
    return VerifiedElasticPamReceipt(
        lease_id=lease["lease_id"],
        request_digest=cast(str, lease["request_digest"]),
        endpoint_origin_digest=cast(str, lease["endpoint_origin_digest"]),
        role_descriptor_digest=cast(str, lease["role_descriptor_digest"]),
        capture_receipt_digest=cast(str, capture["receipt_digest"]),
        capture_records_digest=cast(str, capture["records_digest"]),
        receipt_digest=_sha256(receipt_bytes),
    )
