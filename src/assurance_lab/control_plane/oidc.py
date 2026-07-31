"""Fail-closed OpenID Connect authorization-code authentication core.

The module deliberately owns the security-sensitive protocol state while
leaving HTTP transport to narrow injected interfaces.  A production transport
must disable redirects, environment proxies, and response decompression as
requested by the immutable request objects below.  A production store must
implement the same atomic consume/create operations in durable storage.

Only opaque, high-entropy transaction and session handles cross the browser
cookie boundary.  State, nonce, and the PKCE verifier remain server side.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import threading
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Final, Literal, Protocol, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256

from assurance_lab.control_plane.models import Actor, Role
from assurance_lab.evidence.canonical import JSONLimits, StrictJSONError, strict_json_loads

_B64URL_RE: Final = re.compile(r"^[A-Za-z0-9_-]+$")
_CLIENT_ID_RE: Final = re.compile(r"^[\x21-\x7e]{1,255}$")
_CLAIM_TEXT_RE: Final = re.compile(r"^[^\x00-\x1f\x7f]{1,255}$")
_GROUP_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}$")
_SCOPE_RE: Final = re.compile(r"^[A-Za-z0-9._:/-]{1,64}$")
_SOURCE_DIGEST_RE: Final = re.compile(r"^hmac-sha256:[a-f0-9]{64}$")
_OPAQUE_BYTES: Final = 32
_JWT_LIMITS: Final = JSONLimits(
    max_bytes=64 * 1024,
    max_line_bytes=64 * 1024,
    max_depth=12,
    max_collection_items=512,
    max_string_length=8_192,
)
_JWKS_LIMITS: Final = JSONLimits(
    max_bytes=1 * 1024 * 1024,
    max_line_bytes=1 * 1024 * 1024,
    max_depth=12,
    max_collection_items=1_024,
    max_string_length=16_384,
)
_ALLOWED_ALGORITHMS: Final = frozenset({"RS256", "ES256"})
_ROLE_VALUES: Final = frozenset(
    {"viewer", "editor", "approver", "deployer", "auditor", "administrator"}
)
_ALLOWED_HEADER_KEYS: Final = frozenset({"alg", "kid", "typ"})
_PRIVATE_JWK_FIELDS: Final = frozenset(
    {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
)


class OIDCError(RuntimeError):
    """A deliberately non-oracular, secret-redacted authentication failure."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"OIDC authentication failed ({code})")

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r})"


def _fail(code: str) -> OIDCError:
    return OIDCError(code)


def _now_utc(value: datetime) -> datetime:
    if type(value) is not datetime or value.tzinfo is None:
        raise TypeError("OIDC clock must return a timezone-aware datetime")
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> int:
    return int(_now_utc(value).timestamp())


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_b64url(value: str, *, maximum: int, code: str) -> bytes:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum * 2
        or _B64URL_RE.fullmatch(value) is None
    ):
        raise _fail(code)
    try:
        decoded = base64.b64decode(
            value + ("=" * ((-len(value)) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError):
        raise _fail(code) from None
    if len(decoded) > maximum or _b64url(decoded) != value:
        raise _fail(code)
    return decoded


def _https_url(
    value: str,
    *,
    label: str,
    allow_path: bool = True,
) -> str:
    if type(value) is not str or not value or len(value) > 2_048:
        raise ValueError(f"{label} is absent or too long")
    parsed = urllib.parse.urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{label} has an invalid port") from exc
    path = parsed.path or ""
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port == 0
        or (not allow_path and path not in {"", "/"})
        or "\\" in path
        or "%" in path
        or "//" in path
        or any(segment in {".", ".."} for segment in path.split("/"))
        or any(character.isspace() for character in value)
    ):
        raise ValueError(f"{label} must be a credential-free HTTPS URL")
    host = parsed.hostname.lower()
    rendered_host = f"[{host}]" if ":" in host else host
    authority = rendered_host if port in {None, 443} else f"{rendered_host}:{port}"
    return urllib.parse.urlunsplit(("https", authority, path, "", ""))


def _claim_text(value: object, *, code: str, maximum: int = 255) -> str:
    if (
        type(value) is not str
        or len(value) > maximum
        or _CLAIM_TEXT_RE.fullmatch(value) is None
    ):
        raise _fail(code)
    return value


def _numeric_date(value: object, *, code: str) -> int:
    if type(value) is not int or value < 0 or value > 253_402_300_799:
        raise _fail(code)
    return value


@dataclass(frozen=True, slots=True)
class GroupEntitlement:
    """Exact IdP group claim to one local tenant and a bounded role set."""

    group: str
    tenant_id: str
    roles: frozenset[Role]

    def __post_init__(self) -> None:
        if type(self.group) is not str or _GROUP_RE.fullmatch(self.group) is None:
            raise ValueError("entitlement group is invalid")
        if (
            type(self.tenant_id) is not str
            or not self.tenant_id
            or len(self.tenant_id) > 128
            or re.fullmatch(r"^[a-z][a-z0-9._-]{0,127}$", self.tenant_id) is None
        ):
            raise ValueError("entitlement tenant id is invalid")
        if (
            type(self.roles) is not frozenset
            or not self.roles
            or len(self.roles) > 6
            or not self.roles.issubset(_ROLE_VALUES)
        ):
            raise ValueError("entitlement must grant a bounded non-empty role set")


@dataclass(frozen=True, slots=True)
class MFAPolicy:
    """Required OIDC authentication evidence.

    When ``required`` is true, every configured evidence family is required:
    ``acr`` must be one of ``accepted_acr`` when that set is non-empty, and all
    values in ``required_amr`` must appear in the token's ``amr`` array.

    The default is deliberately provider-neutral and fail closed.  It does
    not assert that every Microsoft Entra v2 tenant emits ``amr=["mfa"]``;
    deployments must pin this contract to claims observed under their own
    Conditional Access policy before enabling live authentication.
    """

    required: bool = True
    accepted_acr: frozenset[str] = frozenset()
    required_amr: frozenset[str] = frozenset({"mfa"})
    maximum_authentication_age_seconds: int = 3_600

    def __post_init__(self) -> None:
        if (
            type(self.maximum_authentication_age_seconds) is not int
            or not 60 <= self.maximum_authentication_age_seconds <= 86_400
        ):
            raise ValueError("maximum authentication age must be between 60 and 86400 seconds")
        if (
            type(self.required) is not bool
            or type(self.accepted_acr) is not frozenset
            or type(self.required_amr) is not frozenset
        ):
            raise ValueError("MFA policy fields have invalid types")
        for value in self.accepted_acr | self.required_amr:
            if (
                type(value) is not str
                or not value
                or len(value) > 128
                or _CLAIM_TEXT_RE.fullmatch(value) is None
            ):
                raise ValueError("MFA evidence values are invalid")
        if self.required and not self.accepted_acr and not self.required_amr:
            raise ValueError("required MFA policy must name at least one evidence condition")


@dataclass(frozen=True, slots=True)
class OIDCLoginAdmissionPolicy:
    """Durable bounds applied before protecting a PKCE verifier.

    Active reservations and ready authorization transactions consume the same
    global/source capacity.  Burn records are separately capped so replay
    protection cannot become attacker-controlled unbounded durable state.
    """

    global_active_limit: int = 512
    source_active_limit: int = 4
    reservation_ttl_seconds: int = 30
    burn_capacity: int = 4_096

    def __post_init__(self) -> None:
        if (
            type(self.global_active_limit) is not int
            or not 1 <= self.global_active_limit <= 100_000
        ):
            raise ValueError("OIDC global active login limit is invalid")
        if (
            type(self.source_active_limit) is not int
            or not 1 <= self.source_active_limit <= self.global_active_limit
        ):
            raise ValueError("OIDC source active login limit is invalid")
        if (
            type(self.reservation_ttl_seconds) is not int
            or not 5 <= self.reservation_ttl_seconds <= 120
        ):
            raise ValueError("OIDC login reservation TTL is invalid")
        if (
            type(self.burn_capacity) is not int
            or not self.global_active_limit <= self.burn_capacity <= 1_000_000
        ):
            raise ValueError("OIDC transaction burn capacity is invalid")


@dataclass(frozen=True, slots=True)
class OIDCConfiguration:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    client_id: str
    redirect_uri: str
    entitlements: tuple[GroupEntitlement, ...]
    mfa_policy: MFAPolicy = field(default_factory=MFAPolicy)
    login_admission_policy: OIDCLoginAdmissionPolicy = field(
        default_factory=OIDCLoginAdmissionPolicy
    )
    # ``groups`` is an ID-token claim configured at the identity provider, not
    # an OAuth scope in Microsoft Entra.  Keep the portable OIDC defaults here.
    scopes: tuple[str, ...] = ("openid", "profile")
    transaction_ttl_seconds: int = 300
    session_ttl_seconds: int = 28_800
    clock_skew_seconds: int = 60
    maximum_id_token_age_seconds: int = 300
    maximum_id_token_lifetime_seconds: int = 3_600

    def __post_init__(self) -> None:
        if type(self.mfa_policy) is not MFAPolicy:
            raise ValueError("OIDC MFA policy is invalid")
        if type(self.login_admission_policy) is not OIDCLoginAdmissionPolicy:
            raise ValueError("OIDC login admission policy is invalid")
        if (
            type(self.entitlements) is not tuple
            or any(type(item) is not GroupEntitlement for item in self.entitlements)
        ):
            raise ValueError("OIDC entitlements are invalid")
        if type(self.scopes) is not tuple:
            raise ValueError("OIDC scopes are invalid")
        object.__setattr__(self, "issuer", _https_url(self.issuer, label="OIDC issuer"))
        object.__setattr__(
            self,
            "authorization_endpoint",
            _https_url(self.authorization_endpoint, label="OIDC authorization endpoint"),
        )
        object.__setattr__(
            self,
            "token_endpoint",
            _https_url(self.token_endpoint, label="OIDC token endpoint"),
        )
        object.__setattr__(self, "jwks_uri", _https_url(self.jwks_uri, label="OIDC JWKS URI"))
        object.__setattr__(
            self,
            "redirect_uri",
            _https_url(self.redirect_uri, label="OIDC redirect URI"),
        )
        if type(self.client_id) is not str or _CLIENT_ID_RE.fullmatch(self.client_id) is None:
            raise ValueError("OIDC client id is invalid")
        if not self.entitlements or len(self.entitlements) > 512:
            raise ValueError("OIDC entitlements must be bounded and non-empty")
        groups = [item.group for item in self.entitlements]
        if len(groups) != len(set(groups)):
            raise ValueError("OIDC entitlement groups must be unique")
        if (
            not self.scopes
            or len(self.scopes) > 16
            or "openid" not in self.scopes
            or len(self.scopes) != len(set(self.scopes))
            or any(_SCOPE_RE.fullmatch(scope) is None for scope in self.scopes)
        ):
            raise ValueError("OIDC scopes are invalid")
        if (
            type(self.transaction_ttl_seconds) is not int
            or not 60 <= self.transaction_ttl_seconds <= 900
        ):
            raise ValueError("OIDC transaction TTL must be between 60 and 900 seconds")
        if (
            type(self.session_ttl_seconds) is not int
            or not 300 <= self.session_ttl_seconds <= 86_400
        ):
            raise ValueError("OIDC session TTL must be between 300 and 86400 seconds")
        if (
            type(self.clock_skew_seconds) is not int
            or not 0 <= self.clock_skew_seconds <= 300
        ):
            raise ValueError("OIDC clock skew must be between 0 and 300 seconds")
        if (
            type(self.maximum_id_token_age_seconds) is not int
            or not 30 <= self.maximum_id_token_age_seconds <= 900
        ):
            raise ValueError("OIDC ID token age must be between 30 and 900 seconds")
        if (
            type(self.maximum_id_token_lifetime_seconds) is not int
            or not 60 <= self.maximum_id_token_lifetime_seconds <= 86_400
        ):
            raise ValueError("OIDC ID token lifetime must be between 60 and 86400 seconds")


@dataclass(frozen=True, slots=True, repr=False)
class AuthorizationTransaction:
    transaction_digest: str
    state_digest: str
    nonce_digest: str
    code_verifier: str
    created_at: datetime
    expires_at: datetime

    def __repr__(self) -> str:
        return (
            "AuthorizationTransaction("
            f"transaction_digest={self.transaction_digest!r}, "
            f"created_at={self.created_at!r}, expires_at={self.expires_at!r}, "
            "state_digest=<redacted>, nonce_digest=<redacted>, code_verifier=<redacted>)"
        )


@dataclass(frozen=True, slots=True)
class SessionRecord:
    session_id_digest: str
    actor: Actor
    issued_at: datetime
    expires_at: datetime


class OIDCStateStore(Protocol):
    """Atomic protocol for a durable transaction and session store.

    Implementations must atomically consume an authorization transaction.
    They must not invoke caller code or remote services while holding a store
    lock.  Raw browser handles are never supplied; only their SHA-256 digests
    reach the store.
    """

    def create_transaction(
        self,
        transaction: AuthorizationTransaction,
        *,
        source_digest: str,
        admission_policy: OIDCLoginAdmissionPolicy,
    ) -> None: ...

    def consume_transaction(
        self,
        *,
        transaction_digest: str,
        state_digest: str,
        consumed_at: datetime,
    ) -> AuthorizationTransaction: ...

    def create_session(self, session: SessionRecord) -> None: ...

    def read_session(
        self,
        *,
        session_id_digest: str,
        read_at: datetime,
    ) -> SessionRecord: ...

    def revoke_session(self, *, session_id_digest: str) -> bool: ...


class InMemoryOIDCStateStore:
    """Thread-safe test/reference store; not a durable production store."""

    __slots__ = (
        "_burn_capacities",
        "_lock",
        "_sessions",
        "_transaction_sources",
        "_transactions",
        "_used_transactions",
    )

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._transactions: dict[str, AuthorizationTransaction] = {}
        self._transaction_sources: dict[str, str] = {}
        self._burn_capacities: dict[str, int] = {}
        self._used_transactions: dict[str, datetime] = {}
        self._sessions: dict[str, SessionRecord] = {}

    @property
    def locked(self) -> bool:
        """Expose lock state solely for transport-boundary tests."""

        return self._lock.locked()

    def create_transaction(
        self,
        transaction: AuthorizationTransaction,
        *,
        source_digest: str,
        admission_policy: OIDCLoginAdmissionPolicy,
    ) -> None:
        if (
            type(source_digest) is not str
            or _SOURCE_DIGEST_RE.fullmatch(source_digest) is None
        ):
            raise _fail("invalid_login_source")
        if type(admission_policy) is not OIDCLoginAdmissionPolicy:
            raise _fail("invalid_login_admission")
        with self._lock:
            self._used_transactions = {
                digest: expires_at
                for digest, expires_at in self._used_transactions.items()
                if expires_at > transaction.created_at
            }
            expired = tuple(
                digest
                for digest, current in self._transactions.items()
                if current.expires_at <= transaction.created_at
            )
            for digest in expired:
                self._transactions.pop(digest, None)
                self._transaction_sources.pop(digest, None)
                self._burn_capacities.pop(digest, None)
            if len(self._used_transactions) >= admission_policy.burn_capacity:
                raise _fail("state_store_unavailable")
            if len(self._transactions) >= admission_policy.global_active_limit:
                raise _fail("login_admission_limited")
            source_active = sum(
                current == source_digest
                for current in self._transaction_sources.values()
            )
            if source_active >= admission_policy.source_active_limit:
                raise _fail("login_admission_limited")
            if (
                transaction.transaction_digest in self._transactions
                or transaction.transaction_digest in self._used_transactions
            ):
                raise _fail("transaction_conflict")
            self._transactions[transaction.transaction_digest] = transaction
            self._transaction_sources[transaction.transaction_digest] = source_digest
            self._burn_capacities[transaction.transaction_digest] = (
                admission_policy.burn_capacity
            )

    def consume_transaction(
        self,
        *,
        transaction_digest: str,
        state_digest: str,
        consumed_at: datetime,
    ) -> AuthorizationTransaction:
        consumed_at = _now_utc(consumed_at)
        with self._lock:
            transaction = self._transactions.get(transaction_digest)
            if transaction is None:
                raise _fail("invalid_transaction")
            self._used_transactions = {
                digest: expires_at
                for digest, expires_at in self._used_transactions.items()
                if expires_at > consumed_at
            }
            burn_capacity = self._burn_capacities[transaction_digest]
            if len(self._used_transactions) >= burn_capacity:
                raise _fail("state_store_unavailable")
            self._transactions.pop(transaction_digest)
            self._transaction_sources.pop(transaction_digest, None)
            self._burn_capacities.pop(transaction_digest, None)
            self._used_transactions[transaction_digest] = transaction.expires_at
            if (
                consumed_at < transaction.created_at
                or consumed_at > transaction.expires_at
                or not hmac.compare_digest(transaction.state_digest, state_digest)
            ):
                raise _fail("invalid_transaction")
            return transaction

    def create_session(self, session: SessionRecord) -> None:
        with self._lock:
            self._sessions = {
                digest: current
                for digest, current in self._sessions.items()
                if current.expires_at > session.issued_at
            }
            if session.session_id_digest in self._sessions:
                raise _fail("session_conflict")
            self._sessions[session.session_id_digest] = session

    def read_session(
        self,
        *,
        session_id_digest: str,
        read_at: datetime,
    ) -> SessionRecord:
        read_at = _now_utc(read_at)
        with self._lock:
            session = self._sessions.get(session_id_digest)
            if session is None or read_at < session.issued_at or read_at >= session.expires_at:
                if session is not None:
                    self._sessions.pop(session_id_digest, None)
                raise _fail("invalid_session")
            return session

    def revoke_session(self, *, session_id_digest: str) -> bool:
        with self._lock:
            return self._sessions.pop(session_id_digest, None) is not None


@dataclass(frozen=True, slots=True, repr=False)
class AuthorizationRequest:
    """Browser redirect plus the only opaque value that belongs in a cookie."""

    redirect_url: str
    transaction_cookie: str
    expires_at: datetime

    def __repr__(self) -> str:
        return (
            "AuthorizationRequest(redirect_url=<redacted>, "
            "transaction_cookie=<redacted>, "
            f"expires_at={self.expires_at!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class TokenExchangeRequest:
    endpoint: str
    client_id: str
    redirect_uri: str
    code: str
    code_verifier: str
    grant_type: Literal["authorization_code"] = "authorization_code"
    allow_redirects: Literal[False] = False
    use_environment_proxy: Literal[False] = False
    allow_response_compression: Literal[False] = False
    maximum_response_bytes: int = 64 * 1024

    def __repr__(self) -> str:
        return (
            "TokenExchangeRequest("
            f"endpoint={self.endpoint!r}, client_id={self.client_id!r}, "
            f"redirect_uri={self.redirect_uri!r}, grant_type={self.grant_type!r}, "
            "code=<redacted>, code_verifier=<redacted>, allow_redirects=False, "
            "use_environment_proxy=False, allow_response_compression=False)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class TokenExchangeResult:
    id_token: str
    effective_endpoint: str

    def __repr__(self) -> str:
        return (
            "TokenExchangeResult(id_token=<redacted>, "
            f"effective_endpoint={self.effective_endpoint!r})"
        )


class AuthorizationCodeRedeemer(Protocol):
    """Secret-owning token transport supplied by the deployment."""

    def redeem(self, request: TokenExchangeRequest) -> TokenExchangeResult: ...


@dataclass(frozen=True, slots=True)
class JWKSFetchRequest:
    uri: str
    expected_issuer: str
    force_refresh: bool = False
    missing_kid: str | None = None
    observed_generation_digest: str | None = None
    allow_redirects: Literal[False] = False
    use_environment_proxy: Literal[False] = False
    allow_response_compression: Literal[False] = False
    maximum_response_bytes: int = 1 * 1024 * 1024


@dataclass(frozen=True, slots=True, repr=False)
class JWKSFetchResult:
    payload: bytes
    effective_uri: str

    def __repr__(self) -> str:
        return (
            f"JWKSFetchResult(payload=<{len(self.payload)} bytes>, "
            f"effective_uri={self.effective_uri!r})"
        )


class JWKSFetcher(Protocol):
    """Pinned JWKS transport supplied by the deployment.

    Implementations are responsible for TLS trust, deadlines, DNS controls,
    and honoring the explicit no-redirect/no-proxy/no-compression request.
    """

    def fetch(self, request: JWKSFetchRequest) -> JWKSFetchResult: ...


@dataclass(frozen=True, slots=True)
class VerifiedIdentity:
    subject: str
    display_name: str
    groups: tuple[str, ...]
    acr: str | None
    amr: tuple[str, ...]
    authenticated_at: datetime
    expires_at: datetime
    mfa: bool


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticationResult:
    actor: Actor
    session_cookie: str
    expires_at: datetime

    def __repr__(self) -> str:
        return (
            f"AuthenticationResult(actor={self.actor!r}, "
            "session_cookie=<redacted>, "
            f"expires_at={self.expires_at!r})"
        )


def _string_array(
    value: object,
    *,
    code: str,
    maximum_items: int,
    pattern: re.Pattern[str] | None = None,
) -> tuple[str, ...]:
    if type(value) is not list or len(value) > maximum_items:
        raise _fail(code)
    result: list[str] = []
    for item in value:
        text = _claim_text(item, code=code)
        if pattern is not None and pattern.fullmatch(text) is None:
            raise _fail(code)
        result.append(text)
    if len(result) != len(set(result)):
        raise _fail(code)
    return tuple(sorted(result))


def _jwt_parts(token: str) -> tuple[str, str, bytes, Mapping[str, object], Mapping[str, object]]:
    if type(token) is not str or not token or len(token) > 64 * 1024:
        raise _fail("invalid_token")
    parts = token.split(".")
    if len(parts) != 3:
        raise _fail("invalid_token")
    encoded_header, encoded_payload, encoded_signature = parts
    header_bytes = _decode_b64url(encoded_header, maximum=16 * 1024, code="invalid_token")
    payload_bytes = _decode_b64url(encoded_payload, maximum=48 * 1024, code="invalid_token")
    signature = _decode_b64url(encoded_signature, maximum=2 * 1024, code="invalid_token")
    try:
        header_value = strict_json_loads(header_bytes, limits=_JWT_LIMITS)
        payload_value = strict_json_loads(payload_bytes, limits=_JWT_LIMITS)
    except StrictJSONError:
        raise _fail("invalid_token") from None
    if type(header_value) is not dict or type(payload_value) is not dict:
        raise _fail("invalid_token")
    header = cast(Mapping[str, object], header_value)
    payload = cast(Mapping[str, object], payload_value)
    return encoded_header, encoded_payload, signature, header, payload


def _select_jwk(
    payload: bytes,
    *,
    kid: str,
    algorithm: str,
) -> Mapping[str, object]:
    try:
        value = strict_json_loads(payload, limits=_JWKS_LIMITS)
    except StrictJSONError:
        raise _fail("invalid_jwks") from None
    if type(value) is not dict:
        raise _fail("invalid_jwks")
    keys = value.get("keys")
    if type(keys) is not list or not keys or len(keys) > 512:
        raise _fail("invalid_jwks")
    matching: list[Mapping[str, object]] = []
    for key in keys:
        if type(key) is not dict:
            raise _fail("invalid_jwks")
        if key.get("kid") == kid:
            matching.append(cast(Mapping[str, object], key))
    if not matching:
        raise _fail("unknown_signing_key")
    if len(matching) != 1:
        raise _fail("invalid_jwks")
    key = matching[0]
    if any(name in key for name in _PRIVATE_JWK_FIELDS):
        raise _fail("invalid_jwks")
    # RFC 7517 permits ``alg`` to be absent.  When present it is pinned;
    # otherwise the mandatory kty/curve checks in _verify_signature bind the
    # key to the header algorithm without inventing an algorithm default.
    if "alg" in key and key.get("alg") != algorithm:
        raise _fail("invalid_jwks")
    if "use" in key and key.get("use") != "sig":
        raise _fail("invalid_jwks")
    if "key_ops" in key:
        operations = key["key_ops"]
        if (
            type(operations) is not list
            or not operations
            or len(operations) > 8
            or any(type(item) is not str for item in operations)
            or len(operations) != len(set(cast(list[str], operations)))
            or "verify" not in operations
        ):
            raise _fail("invalid_jwks")
    return key


def _verify_signature(
    *,
    algorithm: str,
    key: Mapping[str, object],
    signing_input: bytes,
    signature: bytes,
) -> None:
    try:
        if algorithm == "RS256":
            if key.get("kty") != "RSA":
                raise _fail("invalid_jwks")
            modulus_bytes = _decode_b64url(
                cast(str, key.get("n")),
                maximum=1_024,
                code="invalid_jwks",
            )
            exponent_bytes = _decode_b64url(
                cast(str, key.get("e")),
                maximum=8,
                code="invalid_jwks",
            )
            if (
                not modulus_bytes
                or modulus_bytes[0] == 0
                or not exponent_bytes
                or exponent_bytes[0] == 0
            ):
                raise _fail("invalid_jwks")
            modulus = int.from_bytes(modulus_bytes, "big")
            exponent = int.from_bytes(exponent_bytes, "big")
            if not 2_048 <= modulus.bit_length() <= 8_192 or exponent < 3 or exponent % 2 == 0:
                raise _fail("invalid_jwks")
            rsa_public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
            rsa_public_key.verify(signature, signing_input, padding.PKCS1v15(), SHA256())
            return
        if algorithm == "ES256":
            if key.get("kty") != "EC" or key.get("crv") != "P-256":
                raise _fail("invalid_jwks")
            x_bytes = _decode_b64url(cast(str, key.get("x")), maximum=32, code="invalid_jwks")
            y_bytes = _decode_b64url(cast(str, key.get("y")), maximum=32, code="invalid_jwks")
            if len(x_bytes) != 32 or len(y_bytes) != 32 or len(signature) != 64:
                raise _fail("invalid_jwks")
            ec_public_key = ec.EllipticCurvePublicNumbers(
                int.from_bytes(x_bytes, "big"),
                int.from_bytes(y_bytes, "big"),
                ec.SECP256R1(),
            ).public_key()
            r_value = int.from_bytes(signature[:32], "big")
            s_value = int.from_bytes(signature[32:], "big")
            ec_public_key.verify(
                encode_dss_signature(r_value, s_value),
                signing_input,
                ec.ECDSA(SHA256()),
            )
            return
        raise _fail("invalid_algorithm")
    except InvalidSignature:
        raise _fail("invalid_signature") from None
    except OIDCError:
        raise
    except (TypeError, ValueError, OverflowError):
        raise _fail("invalid_jwks") from None


def verify_id_token(
    token: str,
    *,
    jwks: bytes,
    configuration: OIDCConfiguration,
    expected_nonce_digest: str,
    now: datetime,
) -> VerifiedIdentity:
    """Verify one ID token against pinned transaction and deployment inputs."""

    now = _now_utc(now)
    now_seconds = _timestamp(now)
    encoded_header, encoded_payload, signature, header, claims = _jwt_parts(token)
    if set(header) - _ALLOWED_HEADER_KEYS:
        raise _fail("invalid_token")
    algorithm = header.get("alg")
    if type(algorithm) is not str or algorithm not in _ALLOWED_ALGORITHMS:
        raise _fail("invalid_algorithm")
    kid = _claim_text(header.get("kid"), code="invalid_token")
    token_type = header.get("typ")
    if token_type is not None and token_type != "JWT":
        raise _fail("invalid_token")
    key = _select_jwk(jwks, kid=kid, algorithm=algorithm)
    _verify_signature(
        algorithm=algorithm,
        key=key,
        signing_input=f"{encoded_header}.{encoded_payload}".encode("ascii"),
        signature=signature,
    )

    issuer = _claim_text(claims.get("iss"), code="invalid_claims", maximum=2_048)
    if not hmac.compare_digest(issuer, configuration.issuer):
        raise _fail("invalid_claims")

    audience_value = claims.get("aud")
    audiences: tuple[str, ...]
    if type(audience_value) is str:
        audiences = (_claim_text(audience_value, code="invalid_claims"),)
    else:
        audiences = _string_array(
            audience_value,
            code="invalid_claims",
            maximum_items=16,
        )
    if configuration.client_id not in audiences:
        raise _fail("invalid_claims")
    authorized_party = claims.get("azp")
    if len(audiences) > 1:
        if authorized_party != configuration.client_id:
            raise _fail("invalid_claims")
    elif authorized_party is not None and authorized_party != configuration.client_id:
        raise _fail("invalid_claims")

    issued_at = _numeric_date(claims.get("iat"), code="invalid_claims")
    expires_at = _numeric_date(claims.get("exp"), code="invalid_claims")
    auth_time = _numeric_date(claims.get("auth_time"), code="invalid_claims")
    skew = configuration.clock_skew_seconds
    if (
        expires_at <= issued_at
        or expires_at - issued_at > configuration.maximum_id_token_lifetime_seconds
        or now_seconds > expires_at + skew
        or issued_at > now_seconds + skew
        or now_seconds - issued_at > configuration.maximum_id_token_age_seconds + skew
        or auth_time > issued_at + skew
        or auth_time > now_seconds + skew
        or now_seconds - auth_time
        > configuration.mfa_policy.maximum_authentication_age_seconds + skew
    ):
        raise _fail("stale_authentication")

    nonce = claims.get("nonce")
    if (
        type(nonce) is not str
        or len(nonce) != 43
        or _B64URL_RE.fullmatch(nonce) is None
        or not hmac.compare_digest(
            _sha256(nonce.encode("ascii")),
            expected_nonce_digest,
        )
    ):
        raise _fail("invalid_claims")
    subject = _claim_text(claims.get("sub"), code="invalid_claims", maximum=250)
    display = claims.get("name", subject)
    display_name = _claim_text(display, code="invalid_claims")

    acr_value = claims.get("acr")
    acr = None if acr_value is None else _claim_text(acr_value, code="invalid_claims", maximum=128)
    amr_value = claims.get("amr", [])
    amr = _string_array(amr_value, code="invalid_claims", maximum_items=16)
    groups = _string_array(
        claims.get("groups", []),
        code="invalid_claims",
        maximum_items=128,
        pattern=_GROUP_RE,
    )

    policy = configuration.mfa_policy
    acr_ok = not policy.accepted_acr or acr in policy.accepted_acr
    amr_ok = policy.required_amr.issubset(amr)
    evidence_configured = bool(policy.accepted_acr or policy.required_amr)
    mfa = evidence_configured and acr_ok and amr_ok
    if policy.required and not mfa:
        raise _fail("mfa_required")

    return VerifiedIdentity(
        subject=subject,
        display_name=display_name,
        groups=groups,
        acr=acr,
        amr=amr,
        authenticated_at=datetime.fromtimestamp(auth_time, tz=UTC),
        expires_at=datetime.fromtimestamp(expires_at, tz=UTC),
        mfa=mfa,
    )


def _map_actor(
    identity: VerifiedIdentity,
    *,
    configuration: OIDCConfiguration,
    session_id_digest: str,
) -> Actor:
    by_group = {entitlement.group: entitlement for entitlement in configuration.entitlements}
    matched = [by_group[group] for group in identity.groups if group in by_group]
    if not matched:
        raise _fail("not_entitled")
    tenants = {item.tenant_id for item in matched}
    if len(tenants) != 1:
        raise _fail("ambiguous_tenant")
    roles: set[Role] = set()
    for entitlement in matched:
        roles.update(entitlement.roles)
    return Actor(
        tenant_id=next(iter(tenants)),
        subject=f"oidc:{identity.subject}",
        display_name=identity.display_name,
        roles=frozenset(roles),
        groups=identity.groups,
        authenticated_at=identity.authenticated_at,
        session_id_digest=session_id_digest,
        mfa=identity.mfa,
    )


class OIDCAuthenticator:
    """Authorization-code coordinator with replay-safe server-side state."""

    __slots__ = (
        "_clock",
        "_configuration",
        "_jwks_fetcher",
        "_random_bytes",
        "_redeemer",
        "_store",
    )

    def __init__(
        self,
        configuration: OIDCConfiguration,
        store: OIDCStateStore,
        redeemer: AuthorizationCodeRedeemer,
        jwks_fetcher: JWKSFetcher,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        self._configuration = configuration
        self._store = store
        self._redeemer = redeemer
        self._jwks_fetcher = jwks_fetcher
        self._clock = clock
        self._random_bytes = random_bytes

    @property
    def issuer(self) -> str:
        """Return the pinned public issuer used for front-channel mix-up checks."""

        return self._configuration.issuer

    @property
    def redirect_uri(self) -> str:
        """Return the exact callback URI registered for this deployment."""

        return self._configuration.redirect_uri

    def _opaque(self) -> str:
        try:
            value = self._random_bytes(_OPAQUE_BYTES)
        except Exception:
            raise _fail("random_source_failure") from None
        if type(value) is not bytes or len(value) != _OPAQUE_BYTES:
            raise _fail("random_source_failure")
        return _b64url(value)

    def begin(self, *, source_digest: str) -> AuthorizationRequest:
        now = _now_utc(self._clock())
        transaction_handle = self._opaque()
        state = self._opaque()
        nonce = self._opaque()
        code_verifier = self._opaque()
        code_challenge = _b64url(hashlib.sha256(code_verifier.encode("ascii")).digest())
        expires_at = now + timedelta(seconds=self._configuration.transaction_ttl_seconds)
        self._store.create_transaction(
            AuthorizationTransaction(
                transaction_digest=_sha256(transaction_handle.encode("ascii")),
                state_digest=_sha256(state.encode("ascii")),
                nonce_digest=_sha256(nonce.encode("ascii")),
                code_verifier=code_verifier,
                created_at=now,
                expires_at=expires_at,
            ),
            source_digest=source_digest,
            admission_policy=self._configuration.login_admission_policy,
        )
        query = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": self._configuration.client_id,
                "redirect_uri": self._configuration.redirect_uri,
                "scope": " ".join(self._configuration.scopes),
                "state": state,
                "nonce": nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "max_age": str(
                    self._configuration.mfa_policy.maximum_authentication_age_seconds
                ),
            },
            quote_via=urllib.parse.quote,
        )
        return AuthorizationRequest(
            redirect_url=f"{self._configuration.authorization_endpoint}?{query}",
            transaction_cookie=transaction_handle,
            expires_at=expires_at,
        )

    def _fetch_jwks(
        self,
        *,
        force_refresh: bool,
        missing_kid: str | None = None,
        observed_generation_digest: str | None = None,
    ) -> bytes:
        try:
            result = self._jwks_fetcher.fetch(
                JWKSFetchRequest(
                    uri=self._configuration.jwks_uri,
                    expected_issuer=self._configuration.issuer,
                    force_refresh=force_refresh,
                    missing_kid=missing_kid,
                    observed_generation_digest=observed_generation_digest,
                )
            )
        except OIDCError:
            raise _fail("jwks_fetch_failed") from None
        except Exception:
            raise _fail("jwks_fetch_failed") from None
        if (
            type(result) is not JWKSFetchResult
            or result.effective_uri != self._configuration.jwks_uri
            or type(result.payload) is not bytes
            or not result.payload
            or len(result.payload) > _JWKS_LIMITS.max_bytes
        ):
            raise _fail("jwks_fetch_failed")
        return result.payload

    def complete(
        self,
        *,
        transaction_cookie: str,
        returned_state: str,
        authorization_code: str,
    ) -> AuthenticationResult:
        if (
            type(transaction_cookie) is not str
            or len(transaction_cookie) != 43
            or _B64URL_RE.fullmatch(transaction_cookie) is None
            or type(returned_state) is not str
            or len(returned_state) != 43
            or _B64URL_RE.fullmatch(returned_state) is None
            or type(authorization_code) is not str
            or not authorization_code
            or len(authorization_code) > 4_096
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in authorization_code
            )
        ):
            raise _fail("invalid_callback")
        now = _now_utc(self._clock())
        transaction = self._store.consume_transaction(
            transaction_digest=_sha256(transaction_cookie.encode("ascii")),
            state_digest=_sha256(returned_state.encode("ascii")),
            consumed_at=now,
        )

        # Both remote calls occur after the atomic transaction consume returned;
        # no store method holds a lock across either network boundary.
        try:
            token_result = self._redeemer.redeem(
                TokenExchangeRequest(
                    endpoint=self._configuration.token_endpoint,
                    client_id=self._configuration.client_id,
                    redirect_uri=self._configuration.redirect_uri,
                    code=authorization_code,
                    code_verifier=transaction.code_verifier,
                )
            )
        except OIDCError:
            raise _fail("token_exchange_failed") from None
        except Exception:
            raise _fail("token_exchange_failed") from None
        if (
            type(token_result) is not TokenExchangeResult
            or token_result.effective_endpoint != self._configuration.token_endpoint
        ):
            raise _fail("token_exchange_failed")

        jwks = self._fetch_jwks(force_refresh=False)
        try:
            identity = verify_id_token(
                token_result.id_token,
                jwks=jwks,
                configuration=self._configuration,
                expected_nonce_digest=transaction.nonce_digest,
                now=now,
            )
        except OIDCError as error:
            if error.code != "unknown_signing_key":
                raise
            _, _, _, header, _ = _jwt_parts(token_result.id_token)
            missing_kid = _claim_text(
                header.get("kid"),
                code="invalid_token",
            )
            # A new ``kid`` is the one safe reason to bypass the local cache.
            # Perform one fresh GET and one final verification attempt.  A
            # failed refresh never falls back to the cached key set.
            fresh_jwks = self._fetch_jwks(
                force_refresh=True,
                missing_kid=missing_kid,
                observed_generation_digest=_sha256(jwks),
            )
            identity = verify_id_token(
                token_result.id_token,
                jwks=fresh_jwks,
                configuration=self._configuration,
                expected_nonce_digest=transaction.nonce_digest,
                now=now,
            )
        session_handle = self._opaque()
        session_digest = _sha256(session_handle.encode("ascii"))
        actor = _map_actor(
            identity,
            configuration=self._configuration,
            session_id_digest=session_digest,
        )
        expires_at = min(
            identity.expires_at,
            now + timedelta(seconds=self._configuration.session_ttl_seconds),
        )
        if expires_at <= now:
            raise _fail("stale_authentication")
        self._store.create_session(
            SessionRecord(
                session_id_digest=session_digest,
                actor=actor,
                issued_at=now,
                expires_at=expires_at,
            )
        )
        return AuthenticationResult(
            actor=actor,
            session_cookie=session_handle,
            expires_at=expires_at,
        )

    def authenticate_session(self, session_cookie: str) -> Actor:
        if (
            type(session_cookie) is not str
            or len(session_cookie) != 43
            or _B64URL_RE.fullmatch(session_cookie) is None
        ):
            raise _fail("invalid_session")
        session = self._store.read_session(
            session_id_digest=_sha256(session_cookie.encode("ascii")),
            read_at=_now_utc(self._clock()),
        )
        return session.actor

    def logout(self, session_cookie: str) -> bool:
        if (
            type(session_cookie) is not str
            or len(session_cookie) != 43
            or _B64URL_RE.fullmatch(session_cookie) is None
        ):
            return False
        return self._store.revoke_session(
            session_id_digest=_sha256(session_cookie.encode("ascii"))
        )
