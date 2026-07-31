"""Workload-identity boundary for Microsoft Defender XDR captures.

This module deliberately does not accept a client secret.  It exchanges either
an externally issued workload assertion or a PS256 assertion signed by an
injected KMS/Vault-backed signer for one Microsoft Graph access token.  The
token is handed to the existing :class:`DefenderXDRConnector` through its
``DefenderBearerTokenProvider`` protocol and is never persisted.

Microsoft Entra access tokens do not have an API-key-like, per-token
invalidation operation.  Closing a capture therefore means releasing the
process reference, *not* revoking the token.  The canonical lifecycle receipt
records that residual exposure explicitly and anchors it to the token expiry.
Ambiguous token requests are not retried; their conservative exposure window is
left in the durable journal for recovery and operations.
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
import uuid
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, Literal, Protocol, cast, runtime_checkable

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from assurance_lab._version import __version__
from assurance_lab.connectors.contract import ConnectorCapture, ConnectorCaptureError
from assurance_lab.connectors.defender_xdr import (
    DEFENDER_XDR_REQUIRED_PERMISSION,
    DefenderBearerToken,
    DefenderBearerTokenProvider,
    DefenderXDRConnector,
    DefenderXDRRequest,
)
from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)

DEFENDER_PAM_RECEIPT_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.defender-workload-token-lifecycle.v1+json"]
] = "application/vnd.control-assurance.defender-workload-token-lifecycle.v1+json"
DEFENDER_PAM_RECEIPT_SCHEMA_VERSION: Final[Literal["1.0.0"]] = "1.0.0"
DEFENDER_PAM_BROKER_ID: Final[Literal["entra-workload-identity-token-broker"]] = (
    "entra-workload-identity-token-broker"
)
CLIENT_ASSERTION_TYPE: Final = (
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)
FEDERATED_ASSERTION_AUDIENCE: Final = "api://AzureADTokenExchange"

CloudName = Literal["global", "us-government-l4", "us-government-l5"]
CredentialMode = Literal["certificate-ps256", "federated-rs256"]
TokenState = Literal["prepared", "issued", "closed", "uncertain"]
TokenClosure = Literal[
    "capture-completed-token-release-only",
    "capture-failed-token-release-only",
    "token-request-rejected-no-token",
    "token-request-ambiguous",
    "abandoned-after-crash",
]

_TOKEN_TARGET_SUFFIX = "/oauth2/v2.0/token"
_FORM_HEADERS = (
    ("accept", "application/json"),
    ("accept-encoding", "identity"),
    ("content-type", "application/x-www-form-urlencoded"),
)
_RECORDED_RESPONSE_HEADERS = (
    "client-request-id",
    "content-encoding",
    "content-type",
    "request-id",
)
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_ACQUISITION_ID_RE = re.compile(r"^[a-f0-9]{64}$")
_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:/._@#+=-]{0,511}$")
_JWT_RE = re.compile(rb"^[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+[.][A-Za-z0-9_-]+$")
_VISIBLE_TOKEN_RE = re.compile(rb"^[A-Za-z0-9\-._~+/]+=*$")

_MIN_TIMEOUT_SECONDS = 1
_MAX_TIMEOUT_SECONDS = 120
_MIN_ACCESS_TOKEN_TTL_SECONDS = 60
_MAX_ACCESS_TOKEN_TTL_SECONDS = 3_900
_ASSERTION_TTL_SECONDS = 300
_MAX_ASSERTION_TTL_SECONDS = 600
_MAX_ASSERTION_AGE_SECONDS = 300
_MAX_CLOCK_SKEW_SECONDS = 60
_MAX_ASSERTION_BYTES = 128 * 1024
_MAX_TOKEN_BYTES = 32 * 1024
_MAX_FORM_BYTES = 192 * 1024
_MAX_RESPONSE_BYTES = 256 * 1024
_MAX_ERROR_LENGTH = 384
_SQLITE_SCHEMA_VERSION = 1
_SQLITE_BUSY_TIMEOUT_MS = 15_000

_RESPONSE_LIMITS = JSONLimits(
    max_bytes=_MAX_RESPONSE_BYTES,
    max_line_bytes=_MAX_RESPONSE_BYTES,
    max_depth=12,
    max_collection_items=128,
    max_string_length=128 * 1024,
)
_JWT_LIMITS = JSONLimits(
    max_bytes=64 * 1024,
    max_line_bytes=64 * 1024,
    max_depth=8,
    max_collection_items=64,
    max_string_length=8 * 1024,
)
_RECEIPT_LIMITS = JSONLimits(
    max_bytes=64 * 1024,
    max_line_bytes=64 * 1024,
    max_depth=16,
    max_collection_items=256,
    max_string_length=4_096,
)


@dataclass(frozen=True, slots=True)
class DefenderEntraCloud:
    name: CloudName
    authority_origin: str
    graph_origin: str

    @property
    def scope(self) -> str:
        return f"{self.graph_origin}/.default"

    @property
    def authority_origin_digest(self) -> str:
        return _sha256(self.authority_origin.encode("ascii"))

    @property
    def graph_origin_digest(self) -> str:
        return _sha256(self.graph_origin.encode("ascii"))

    @property
    def scope_digest(self) -> str:
        return _sha256(self.scope.encode("ascii"))


_CLOUDS: Final[Mapping[CloudName, DefenderEntraCloud]] = MappingProxyType(
    {
        "global": DefenderEntraCloud(
            name="global",
            authority_origin="https://login.microsoftonline.com",
            graph_origin="https://graph.microsoft.com",
        ),
        "us-government-l4": DefenderEntraCloud(
            name="us-government-l4",
            authority_origin="https://login.microsoftonline.us",
            graph_origin="https://graph.microsoft.us",
        ),
        "us-government-l5": DefenderEntraCloud(
            name="us-government-l5",
            authority_origin="https://login.microsoftonline.us",
            graph_origin="https://dod-graph.microsoft.us",
        ),
    }
)


def defender_entra_cloud(name: CloudName) -> DefenderEntraCloud:
    """Return one immutable, supported authority/Graph pairing."""

    if name not in _CLOUDS:
        raise ValueError("unsupported Microsoft Entra cloud")
    return _CLOUDS[name]


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _epoch_milliseconds() -> int:
    return time.time_ns() // 1_000_000


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_b64url(value: bytes, *, label: str, maximum: int) -> bytes:
    if not value or len(value) > 4 * ((maximum + 2) // 3):
        raise DefenderPamError("assertion", f"{label} is absent or exceeds its limit")
    if b"=" in value or re.fullmatch(rb"[A-Za-z0-9_-]+", value) is None:
        raise DefenderPamError("assertion", f"{label} is not canonical base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + (b"=" * (-len(value) % 4)))
    except ValueError as exc:
        raise DefenderPamError("assertion", f"{label} is not canonical base64url") from exc
    if len(decoded) > maximum or _b64url(decoded).encode("ascii") != value:
        raise DefenderPamError("assertion", f"{label} is not canonical base64url")
    return decoded


def _require_uuid(value: str, *, label: str) -> str:
    if type(value) is not str or _UUID_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a canonical lowercase UUID")
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError
    except ValueError as exc:
        raise ValueError(f"{label} must be a canonical lowercase UUID") from exc
    return value


def _require_digest(value: str, *, label: str) -> str:
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        raise ValueError(f"{label} is not a canonical SHA-256 digest")
    return value


def _require_reference(value: str, *, label: str) -> str:
    if type(value) is not str or _REFERENCE_RE.fullmatch(value) is None:
        raise ValueError(f"{label} is not a bounded portable reference")
    return value


def _safe_reason(value: BaseException) -> str:
    if isinstance(value, DefenderPamError):
        reason = value.reason
    elif isinstance(value, ConnectorCaptureError):
        # Connector messages are outside this module's secret-handling
        # boundary.  Persist only their controlled stage, never their text.
        reason = f"connector-{value.stage}-failure"
    else:
        reason = type(value).__name__
    normalized = " ".join(reason.split())
    return (normalized or "unspecified failure")[:_MAX_ERROR_LENGTH]


class DefenderPamError(RuntimeError):
    """A workload-token lifecycle failed without exposing secret material."""

    def __init__(self, stage: str, reason: str) -> None:
        if (
            type(stage) is not str
            or not stage
            or len(stage) > 64
            or re.fullmatch(r"[a-z][a-z0-9-]*", stage) is None
        ):
            raise ValueError("PAM failure stage is invalid")
        normalized = " ".join(reason.split())
        if not normalized or len(normalized) > _MAX_ERROR_LENGTH:
            raise ValueError("PAM failure reason is invalid")
        self.stage = stage
        self.reason = normalized
        super().__init__(f"{stage}: {normalized}")


class DefenderPamAmbiguousRequest(DefenderPamError):
    """The token endpoint may have issued a token, but closure is unknown."""


@runtime_checkable
class PS256AssertionSigner(Protocol):
    """KMS/Vault-backed RSA-PSS signing boundary.

    ``key_reference`` is an operator-visible identifier, not private material.
    The implementation receives only the JWS signing input and must return a
    raw RSA-PSS/SHA-256 signature.
    """

    @property
    def key_reference(self) -> str: ...

    def sign_ps256(self, signing_input: bytes, *, deadline: float) -> bytes: ...


class FederatedClientAssertion:
    """Opaque external-IdP JWT with redacted representations."""

    __slots__ = ("__value",)

    def __init__(self, value: bytes) -> None:
        if (
            type(value) is not bytes
            or not value
            or len(value) > _MAX_ASSERTION_BYTES
            or _JWT_RE.fullmatch(value) is None
        ):
            raise ValueError("federated assertion must be one bounded compact JWT")
        self.__value = value

    def __repr__(self) -> str:
        return "FederatedClientAssertion(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"

    def _bytes(self) -> bytes:
        return self.__value

    def _appears_in(self, value: bytes) -> bool:
        quoted = urllib.parse.quote_from_bytes(self.__value).encode("ascii")
        return self.__value in value or quoted in value


@runtime_checkable
class FederatedAssertionSource(Protocol):
    """Obtain one external-IdP assertion for the requested exact audience."""

    @property
    def source_reference(self) -> str: ...

    def get_assertion(
        self,
        *,
        audience: str,
        deadline: float,
    ) -> FederatedClientAssertion: ...


@dataclass(frozen=True, slots=True)
class _IssuedAssertion:
    value: bytes
    mode: CredentialMode
    reference_digest: str
    assertion_id_digest: str
    expires_epoch_seconds: int

    def __repr__(self) -> str:
        return (
            f"_IssuedAssertion(mode={self.mode!r}, reference_digest="
            f"{self.reference_digest!r}, value=<redacted>)"
        )

    def appears_in(self, content: bytes) -> bool:
        quoted = urllib.parse.quote_from_bytes(self.value).encode("ascii")
        return self.value in content or quoted in content


class _AssertionCredential(Protocol):
    @property
    def mode(self) -> CredentialMode: ...

    @property
    def reference_digest(self) -> str: ...

    def issue(
        self,
        *,
        client_id: str,
        token_endpoint: str,
        now_epoch_seconds: int,
        deadline: float,
    ) -> _IssuedAssertion: ...


class CertificateAssertionCredential:
    """Create PS256 assertions while private-key operations stay in KMS/Vault."""

    __slots__ = ("_certificate", "_jti", "_reference_digest", "_signer")

    def __init__(
        self,
        certificate_der: bytes,
        signer: PS256AssertionSigner,
        *,
        _jti: Callable[[], str] | None = None,
    ) -> None:
        if type(certificate_der) is not bytes or not certificate_der:
            raise TypeError("certificate DER must be non-empty immutable bytes")
        if not isinstance(signer, PS256AssertionSigner):
            raise TypeError("signer must implement PS256AssertionSigner")
        reference = _require_reference(signer.key_reference, label="signer key reference")
        try:
            certificate = x509.load_der_x509_certificate(certificate_der)
        except ValueError as exc:
            raise ValueError("certificate DER is not a valid X.509 certificate") from exc
        public_key = certificate.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 2048:
            raise ValueError("certificate must contain an RSA public key of at least 2048 bits")
        self._certificate = certificate
        self._signer = signer
        self._jti = _jti or (lambda: str(uuid.uuid4()))
        self._reference_digest = _sha256(reference.encode("utf-8"))

    @property
    def mode(self) -> CredentialMode:
        return "certificate-ps256"

    @property
    def reference_digest(self) -> str:
        return self._reference_digest

    def issue(
        self,
        *,
        client_id: str,
        token_endpoint: str,
        now_epoch_seconds: int,
        deadline: float,
    ) -> _IssuedAssertion:
        if time.monotonic() >= deadline:
            raise DefenderPamError("deadline", "client assertion deadline expired")
        now = now_epoch_seconds
        if not (
            int(self._certificate.not_valid_before_utc.timestamp())
            <= now
            < int(self._certificate.not_valid_after_utc.timestamp())
        ):
            raise DefenderPamError("assertion", "registered certificate is not currently valid")
        jti_failed = False
        jti: object = None
        try:
            jti = self._jti()
        except Exception:
            jti_failed = True
        if jti_failed or type(jti) is not str:
            raise DefenderPamError("assertion", "assertion id generation failed")
        try:
            _require_uuid(jti, label="assertion jti")
        except ValueError as exc:
            raise DefenderPamError(
                "assertion",
                "assertion id source returned an invalid UUID",
            ) from exc
        header = {
            "alg": "PS256",
            "typ": "JWT",
            "x5t#S256": _b64url(self._certificate.fingerprint(hashes.SHA256())),
        }
        claims = {
            "aud": token_endpoint,
            "exp": now + _ASSERTION_TTL_SECONDS,
            "iat": now,
            "iss": client_id,
            "jti": jti,
            "nbf": now,
            "sub": client_id,
        }
        signing_input = (
            f"{_b64url(canonical_json_bytes(header))}."
            f"{_b64url(canonical_json_bytes(claims))}"
        ).encode("ascii")
        signing_failed = False
        signature: object = None
        try:
            signature = self._signer.sign_ps256(signing_input, deadline=deadline)
        except Exception:
            signing_failed = True
        if signing_failed:
            raise DefenderPamError("assertion", "remote PS256 signing failed")
        if (
            type(signature) is not bytes
            or not signature
            or len(signature) > 2_048
            or time.monotonic() >= deadline
        ):
            raise DefenderPamError("assertion", "remote signer returned an invalid signature")
        public_key = self._certificate.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        try:
            public_key.verify(
                signature,
                signing_input,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256(),
            )
        except InvalidSignature as exc:
            raise DefenderPamError(
                "assertion",
                "remote signer output does not verify under the registered certificate",
            ) from exc
        encoded = signing_input + b"." + _b64url(signature).encode("ascii")
        if len(encoded) > _MAX_ASSERTION_BYTES:
            raise DefenderPamError("assertion", "client assertion exceeds its byte limit")
        return _IssuedAssertion(
            value=encoded,
            mode=self.mode,
            reference_digest=self.reference_digest,
            assertion_id_digest=_sha256(jti.encode("ascii")),
            expires_epoch_seconds=now + _ASSERTION_TTL_SECONDS,
        )


class FederatedAssertionCredential:
    """Validate a workload-federation assertion before token exchange."""

    __slots__ = (
        "_expected_issuer",
        "_expected_subject",
        "_reference_digest",
        "_source",
    )

    def __init__(
        self,
        source: FederatedAssertionSource,
        *,
        expected_issuer: str,
        expected_subject: str,
    ) -> None:
        if not isinstance(source, FederatedAssertionSource):
            raise TypeError("source must implement FederatedAssertionSource")
        reference = _require_reference(source.source_reference, label="federation source reference")
        parsed = urllib.parse.urlsplit(expected_issuer)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or len(expected_issuer) > 600
        ):
            raise ValueError("federated issuer must be one bounded HTTPS issuer URL")
        if (
            type(expected_subject) is not str
            or not expected_subject
            or len(expected_subject) > 600
            or any(character in expected_subject for character in "\r\n")
        ):
            raise ValueError("federated subject is invalid")
        self._source = source
        self._expected_issuer = expected_issuer
        self._expected_subject = expected_subject
        self._reference_digest = _sha256(reference.encode("utf-8"))

    @property
    def mode(self) -> CredentialMode:
        return "federated-rs256"

    @property
    def reference_digest(self) -> str:
        return self._reference_digest

    def issue(
        self,
        *,
        client_id: str,
        token_endpoint: str,
        now_epoch_seconds: int,
        deadline: float,
    ) -> _IssuedAssertion:
        del client_id, token_endpoint
        if time.monotonic() >= deadline:
            raise DefenderPamError("deadline", "federated assertion deadline expired")
        source_failed = False
        assertion: object = None
        try:
            assertion = self._source.get_assertion(
                audience=FEDERATED_ASSERTION_AUDIENCE,
                deadline=deadline,
            )
        except Exception:
            source_failed = True
        if source_failed:
            raise DefenderPamError("assertion", "federated assertion acquisition failed")
        if type(assertion) is not FederatedClientAssertion:
            raise DefenderPamError("assertion", "source returned an invalid assertion object")
        raw = assertion._bytes()
        header_segment, payload_segment, _ = raw.split(b".", 2)
        header_bytes = _decode_b64url(header_segment, label="JWT header", maximum=16 * 1024)
        payload_bytes = _decode_b64url(payload_segment, label="JWT claims", maximum=48 * 1024)
        try:
            header = strict_json_loads(header_bytes, limits=_JWT_LIMITS)
            claims = strict_json_loads(payload_bytes, limits=_JWT_LIMITS)
        except StrictJSONError as exc:
            raise DefenderPamError("assertion", "federated JWT is not strict bounded JSON") from exc
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise DefenderPamError("assertion", "federated JWT header or claims are not objects")
        if header.get("alg") != "RS256" or header.get("typ", "JWT") != "JWT":
            raise DefenderPamError("assertion", "federated JWT must use RS256 and JWT type")
        if frozenset(header) - frozenset({"alg", "kid", "typ", "x5t"}):
            raise DefenderPamError("assertion", "federated JWT header has unsupported members")
        if "kid" in header and (
            type(header["kid"]) is not str
            or not header["kid"]
            or len(header["kid"]) > 512
        ):
            raise DefenderPamError("assertion", "federated JWT key id is invalid")
        required = frozenset({"aud", "exp", "iat", "iss", "jti", "nbf", "sub"})
        if not required <= frozenset(claims):
            raise DefenderPamError("assertion", "federated JWT lacks required claims")
        if (
            claims["aud"] != FEDERATED_ASSERTION_AUDIENCE
            or claims["iss"] != self._expected_issuer
            or claims["sub"] != self._expected_subject
        ):
            raise DefenderPamError("assertion", "federated JWT identity binding is wrong")
        if (
            type(claims["jti"]) is not str
            or not claims["jti"]
            or len(claims["jti"]) > 512
            or any(character in claims["jti"] for character in "\r\n")
        ):
            raise DefenderPamError("assertion", "federated JWT identifier is invalid")
        if any(type(claims[name]) is not int for name in ("exp", "iat", "nbf")):
            raise DefenderPamError("assertion", "federated JWT times are invalid")
        issued = cast(int, claims["iat"])
        not_before = cast(int, claims["nbf"])
        expires = cast(int, claims["exp"])
        now = now_epoch_seconds
        if (
            not_before > now + _MAX_CLOCK_SKEW_SECONDS
            or issued > now + _MAX_CLOCK_SKEW_SECONDS
            or issued < now - _MAX_ASSERTION_AGE_SECONDS
            or expires <= now
            or expires - max(issued, not_before) > _MAX_ASSERTION_TTL_SECONDS
        ):
            raise DefenderPamError("assertion", "federated JWT is outside the freshness window")
        return _IssuedAssertion(
            value=raw,
            mode=self.mode,
            reference_digest=self.reference_digest,
            assertion_id_digest=_sha256(claims["jti"].encode("utf-8")),
            expires_epoch_seconds=expires,
        )


@dataclass(frozen=True, slots=True)
class DefenderTokenRecord:
    acquisition_id: str
    request_digest: str
    token_endpoint_digest: str
    graph_origin_digest: str
    scope_digest: str
    credential_mode: CredentialMode
    credential_reference_digest: str
    token_request_profile_digest: str
    state: TokenState
    closure: TokenClosure | None
    created_epoch_millis: int
    issued_epoch_millis: int | None
    closed_epoch_millis: int | None
    access_token_expires_epoch_millis: int | None
    conservative_exposure_end_epoch_millis: int
    assertion_id_digest: str | None
    response_request_id_digest: str | None
    revision: int
    last_error: str | None

    def __post_init__(self) -> None:
        if _ACQUISITION_ID_RE.fullmatch(self.acquisition_id) is None:
            raise ValueError("token acquisition id is invalid")
        for label, value in (
            ("request", self.request_digest),
            ("token endpoint", self.token_endpoint_digest),
            ("Graph origin", self.graph_origin_digest),
            ("scope", self.scope_digest),
            ("credential reference", self.credential_reference_digest),
            ("token request profile", self.token_request_profile_digest),
        ):
            _require_digest(value, label=f"{label} digest")
        if self.assertion_id_digest is not None:
            _require_digest(self.assertion_id_digest, label="assertion id digest")
        if self.response_request_id_digest is not None:
            _require_digest(self.response_request_id_digest, label="response request id digest")
        if self.state not in {"prepared", "issued", "closed", "uncertain"}:
            raise ValueError("token lifecycle state is invalid")


@runtime_checkable
class DefenderTokenJournal(Protocol):
    """Durable CAS journal required by :class:`DefenderWorkloadIdentityBroker`."""

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
    ) -> DefenderTokenRecord: ...

    def mark_issued(
        self,
        *,
        acquisition_id: str,
        expected_revision: int,
        now_epoch_millis: int,
        expires_epoch_millis: int,
        assertion_id_digest: str,
        response_request_id_digest: str | None,
    ) -> DefenderTokenRecord: ...

    def close(
        self,
        *,
        acquisition_id: str,
        expected_revision: int,
        expected_state: Literal["prepared", "issued"],
        closure: TokenClosure,
        now_epoch_millis: int,
        error: str | None,
    ) -> DefenderTokenRecord: ...

    def mark_uncertain(
        self,
        *,
        acquisition_id: str,
        expected_revision: int,
        now_epoch_millis: int,
        error: str,
    ) -> DefenderTokenRecord: ...

    def get(self, acquisition_id: str) -> DefenderTokenRecord: ...

    def unsettled(self, *, limit: int = 1_000) -> tuple[DefenderTokenRecord, ...]: ...

    def records_for_request_digest(
        self,
        request_digest: str,
        *,
        unsettled_only: bool = False,
        limit: int = 1_000,
    ) -> tuple[DefenderTokenRecord, ...]: ...


class SQLiteDefenderTokenJournal:
    """Owner-only durable token intent and residual-exposure ledger."""

    __slots__ = ("_path",)

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path):
            raise TypeError("token journal path must be a pathlib.Path")
        self._path = path
        self._prepare_file()
        self._initialize()

    def _prepare_file(self) -> None:
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            metadata = self._path.lstat()
        except FileNotFoundError:
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self._path, flags, 0o600)
            os.close(descriptor)
            metadata = self._path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise DefenderPamError(
                "journal",
                "token journal must be an owner-only single-link regular file",
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
                raise DefenderPamError("journal", "unsupported token journal schema")
            if version == 0:
                connection.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE token_lifecycle (
                        acquisition_id TEXT PRIMARY KEY,
                        request_digest TEXT NOT NULL,
                        token_endpoint_digest TEXT NOT NULL,
                        graph_origin_digest TEXT NOT NULL,
                        scope_digest TEXT NOT NULL,
                        credential_mode TEXT NOT NULL,
                        credential_reference_digest TEXT NOT NULL,
                        token_request_profile_digest TEXT NOT NULL,
                        state TEXT NOT NULL,
                        closure TEXT,
                        created_epoch_millis INTEGER NOT NULL,
                        issued_epoch_millis INTEGER,
                        closed_epoch_millis INTEGER,
                        access_token_expires_epoch_millis INTEGER,
                        conservative_exposure_end_epoch_millis INTEGER NOT NULL,
                        assertion_id_digest TEXT,
                        response_request_id_digest TEXT,
                        revision INTEGER NOT NULL,
                        last_error TEXT
                    ) STRICT;
                    CREATE TRIGGER token_identity_immutable
                    BEFORE UPDATE ON token_lifecycle
                    WHEN NEW.acquisition_id != OLD.acquisition_id
                      OR NEW.request_digest != OLD.request_digest
                      OR NEW.token_endpoint_digest != OLD.token_endpoint_digest
                      OR NEW.graph_origin_digest != OLD.graph_origin_digest
                      OR NEW.scope_digest != OLD.scope_digest
                      OR NEW.credential_mode != OLD.credential_mode
                      OR NEW.credential_reference_digest != OLD.credential_reference_digest
                      OR NEW.token_request_profile_digest != OLD.token_request_profile_digest
                      OR NEW.created_epoch_millis != OLD.created_epoch_millis
                      OR NEW.conservative_exposure_end_epoch_millis
                         != OLD.conservative_exposure_end_epoch_millis
                    BEGIN SELECT RAISE(ABORT, 'immutable token identity'); END;
                    PRAGMA user_version=1;
                    COMMIT;
                    """
                )
        finally:
            connection.close()

    @staticmethod
    def _record(row: sqlite3.Row) -> DefenderTokenRecord:
        return DefenderTokenRecord(
            acquisition_id=cast(str, row["acquisition_id"]),
            request_digest=cast(str, row["request_digest"]),
            token_endpoint_digest=cast(str, row["token_endpoint_digest"]),
            graph_origin_digest=cast(str, row["graph_origin_digest"]),
            scope_digest=cast(str, row["scope_digest"]),
            credential_mode=cast(CredentialMode, row["credential_mode"]),
            credential_reference_digest=cast(str, row["credential_reference_digest"]),
            token_request_profile_digest=cast(str, row["token_request_profile_digest"]),
            state=cast(TokenState, row["state"]),
            closure=cast(TokenClosure | None, row["closure"]),
            created_epoch_millis=cast(int, row["created_epoch_millis"]),
            issued_epoch_millis=cast(int | None, row["issued_epoch_millis"]),
            closed_epoch_millis=cast(int | None, row["closed_epoch_millis"]),
            access_token_expires_epoch_millis=cast(
                int | None,
                row["access_token_expires_epoch_millis"],
            ),
            conservative_exposure_end_epoch_millis=cast(
                int,
                row["conservative_exposure_end_epoch_millis"],
            ),
            assertion_id_digest=cast(str | None, row["assertion_id_digest"]),
            response_request_id_digest=cast(str | None, row["response_request_id_digest"]),
            revision=cast(int, row["revision"]),
            last_error=cast(str | None, row["last_error"]),
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
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO token_lifecycle (
                    acquisition_id, request_digest, token_endpoint_digest,
                    graph_origin_digest, scope_digest, credential_mode,
                    credential_reference_digest, token_request_profile_digest,
                    state, closure, created_epoch_millis, issued_epoch_millis,
                    closed_epoch_millis, access_token_expires_epoch_millis,
                    conservative_exposure_end_epoch_millis, assertion_id_digest,
                    response_request_id_digest, revision, last_error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'prepared', NULL, ?, NULL,
                          NULL, NULL, ?, NULL, NULL, 0, NULL)
                """,
                (
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
            )
            row = connection.execute(
                "SELECT * FROM token_lifecycle WHERE acquisition_id=?",
                (acquisition_id,),
            ).fetchone()
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        assert row is not None
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
        return self._transition(
            acquisition_id=acquisition_id,
            expected_revision=expected_revision,
            expected_state="prepared",
            assignments=(
                "state='issued', issued_epoch_millis=?, "
                "access_token_expires_epoch_millis=?, assertion_id_digest=?, "
                "response_request_id_digest=?, revision=revision+1"
            ),
            values=(
                now_epoch_millis,
                expires_epoch_millis,
                assertion_id_digest,
                response_request_id_digest,
            ),
        )

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
        return self._transition(
            acquisition_id=acquisition_id,
            expected_revision=expected_revision,
            expected_state=expected_state,
            assignments=(
                "state='closed', closure=?, closed_epoch_millis=?, "
                "last_error=?, revision=revision+1"
            ),
            values=(closure, now_epoch_millis, error),
        )

    def mark_uncertain(
        self,
        *,
        acquisition_id: str,
        expected_revision: int,
        now_epoch_millis: int,
        error: str,
    ) -> DefenderTokenRecord:
        return self._transition(
            acquisition_id=acquisition_id,
            expected_revision=expected_revision,
            expected_state="prepared",
            assignments=(
                "state='uncertain', closure='token-request-ambiguous', "
                "closed_epoch_millis=?, last_error=?, revision=revision+1"
            ),
            values=(now_epoch_millis, error),
        )

    def _transition(
        self,
        *,
        acquisition_id: str,
        expected_revision: int,
        expected_state: TokenState,
        assignments: str,
        values: tuple[object, ...],
    ) -> DefenderTokenRecord:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                f"""
                UPDATE token_lifecycle SET {assignments}
                WHERE acquisition_id=? AND revision=? AND state=?
                """,
                (*values, acquisition_id, expected_revision, expected_state),
            )
            if cursor.rowcount != 1:
                raise DefenderPamError("journal", "token lifecycle compare-and-swap failed")
            row = connection.execute(
                "SELECT * FROM token_lifecycle WHERE acquisition_id=?",
                (acquisition_id,),
            ).fetchone()
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        assert row is not None
        return self._record(row)

    def get(self, acquisition_id: str) -> DefenderTokenRecord:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM token_lifecycle WHERE acquisition_id=?",
                (acquisition_id,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise DefenderPamError("journal", "token lifecycle record does not exist")
        return self._record(row)

    def unsettled(self, *, limit: int = 1_000) -> tuple[DefenderTokenRecord, ...]:
        if type(limit) is not int or not 1 <= limit <= 10_000:
            raise ValueError("recovery limit is outside the supported range")
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT * FROM token_lifecycle
                WHERE state IN ('prepared', 'issued')
                ORDER BY created_epoch_millis, acquisition_id LIMIT ?
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
    ) -> tuple[DefenderTokenRecord, ...]:
        request = _require_digest(request_digest, label="request digest")
        if type(unsettled_only) is not bool:
            raise TypeError("unsettled-only selection must be boolean")
        if type(limit) is not int or not 1 <= limit <= 10_000:
            raise ValueError("recovery limit is outside the supported range")
        state_clause = (
            "AND state IN ('prepared', 'issued')"
            if unsettled_only
            else ""
        )
        connection = self._connect()
        try:
            rows = connection.execute(
                f"""
                SELECT * FROM token_lifecycle
                WHERE request_digest = ?
                {state_clause}
                ORDER BY created_epoch_millis, acquisition_id
                LIMIT ?
                """,
                (request, limit),
            ).fetchall()
        finally:
            connection.close()
        return tuple(self._record(row) for row in rows)


@dataclass(frozen=True, slots=True)
class _TokenHTTPResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


class _TokenHTTPTransport(Protocol):
    def request(
        self,
        *,
        target: str,
        body: bytes,
        headers: tuple[tuple[str, str], ...],
        deadline: float,
    ) -> _TokenHTTPResponse: ...


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
        del req, fp, code, msg, headers, newurl
        return None


class _UrllibTokenTransport:
    __slots__ = ("_authority_origin", "_opener", "_timeout_seconds")

    def __init__(
        self,
        *,
        authority_origin: str,
        timeout_seconds: int,
        ssl_context: ssl.SSLContext,
    ) -> None:
        self._authority_origin = authority_origin
        self._timeout_seconds = timeout_seconds
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl_context),
        )

    def request(
        self,
        *,
        target: str,
        body: bytes,
        headers: tuple[tuple[str, str], ...],
        deadline: float,
    ) -> _TokenHTTPResponse:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DefenderPamError("deadline", "token request deadline expired")
        request = urllib.request.Request(
            f"{self._authority_origin}{target}",
            data=body,
            headers=dict(headers),
            method="POST",
        )
        response: Any
        try:
            response = self._opener.open(
                request,
                timeout=min(float(self._timeout_seconds), remaining),
            )
        except urllib.error.HTTPError as exc:
            response = exc
        except (TimeoutError, urllib.error.URLError, OSError) as exc:
            raise DefenderPamAmbiguousRequest(
                "token-transport",
                "token request outcome is ambiguous",
            ) from exc
        try:
            content = bytearray()
            reader = getattr(response, "read1", response.read)
            while True:
                if time.monotonic() >= deadline:
                    raise DefenderPamAmbiguousRequest(
                        "token-transport",
                        "token response completion is ambiguous",
                    )
                chunk = reader(min(64 * 1024, _MAX_RESPONSE_BYTES + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > _MAX_RESPONSE_BYTES:
                    raise DefenderPamAmbiguousRequest(
                        "token-transport",
                        "token response exceeds the byte limit",
                    )
            selected: list[tuple[str, str]] = []
            for name in _RECORDED_RESPONSE_HEADERS:
                values = response.headers.get_all(name, [])
                if len(values) > 1:
                    raise DefenderPamAmbiguousRequest(
                        "token-transport",
                        f"token response has duplicate {name} headers",
                    )
                if values:
                    selected.append((name, values[0]))
            return _TokenHTTPResponse(
                status=int(response.status),
                headers=tuple(selected),
                body=bytes(content),
            )
        except (OSError, http.client.HTTPException) as exc:
            raise DefenderPamAmbiguousRequest(
                "token-transport",
                "token response could not be read completely",
            ) from exc
        finally:
            response.close()


def _ssl_context(ca_file: Path | None) -> ssl.SSLContext:
    if ca_file is None:
        return ssl.create_default_context()
    if not isinstance(ca_file, Path):
        raise TypeError("CA file must be a pathlib.Path")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(ca_file, flags)
    content = bytearray()
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > 8 * 1024 * 1024
        ):
            raise ValueError("CA file must be a bounded single-link regular file")
        while len(content) <= 8 * 1024 * 1024:
            chunk = os.read(descriptor, min(64 * 1024, 8 * 1024 * 1024 + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if (
            len(content) > 8 * 1024 * 1024
            or len(content) != after.st_size
            or identity_before != identity_after
        ):
            raise ValueError("CA file changed while it was read")
    finally:
        os.close(descriptor)
    context = ssl.create_default_context()
    context.load_verify_locations(cadata=bytes(content).decode("ascii", errors="strict"))
    return context


@dataclass(frozen=True, slots=True)
class _IssuedToken:
    token: DefenderBearerToken
    record: DefenderTokenRecord

    def __repr__(self) -> str:
        return f"_IssuedToken(acquisition_id={self.record.acquisition_id!r}, token=<redacted>)"


class _SingleUseTokenProvider:
    __slots__ = ("_token", "_used")

    def __init__(self, token: DefenderBearerToken) -> None:
        self._token = token
        self._used = False

    def get_token(self, *, deadline: float) -> DefenderBearerToken:
        if self._used:
            raise DefenderPamError("token-use", "managed token was requested more than once")
        if time.monotonic() >= deadline:
            raise DefenderPamError("deadline", "managed token use deadline expired")
        self._used = True
        return self._token


class _CaptureConnector(Protocol):
    def capture(self, request: object) -> ConnectorCapture: ...


ConnectorFactory = Callable[[DefenderBearerTokenProvider], _CaptureConnector]


@dataclass(frozen=True, slots=True)
class ManagedDefenderCapture:
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


@dataclass(frozen=True, slots=True)
class VerifiedDefenderPamReceipt:
    acquisition_id: str
    request_digest: str
    token_endpoint_digest: str
    graph_origin_digest: str
    scope_digest: str
    credential_reference_digest: str
    capture_receipt_digest: str
    capture_records_digest: str
    residual_exposure_end_epoch_millis: int
    receipt_digest: str


class DefenderWorkloadIdentityBroker:
    """Run one Defender capture with a secretless workload identity exchange."""

    __slots__ = (
        "_client_id",
        "_cloud",
        "_connector_factory",
        "_credential",
        "_journal",
        "_nonce",
        "_now",
        "_tenant_id",
        "_timeout_seconds",
        "_token_endpoint",
        "_token_endpoint_digest",
        "_transport",
    )

    def __init__(
        self,
        *,
        tenant_id: str,
        client_id: str,
        cloud: CloudName,
        credential: CertificateAssertionCredential | FederatedAssertionCredential,
        journal: DefenderTokenJournal,
        ca_file: Path | None = None,
        timeout_seconds: int = 30,
        _transport: _TokenHTTPTransport | None = None,
        _connector_factory: ConnectorFactory | None = None,
        _nonce: Callable[[], str] | None = None,
        _now: Callable[[], int] | None = None,
    ) -> None:
        self._tenant_id = _require_uuid(tenant_id, label="tenant id")
        self._client_id = _require_uuid(client_id, label="client id")
        if type(credential) not in {
            CertificateAssertionCredential,
            FederatedAssertionCredential,
        }:
            raise TypeError("credential must be an exact supported assertion credential")
        if not isinstance(journal, DefenderTokenJournal):
            raise TypeError("journal does not implement the Defender token protocol")
        if (
            type(timeout_seconds) is not int
            or not _MIN_TIMEOUT_SECONDS <= timeout_seconds <= _MAX_TIMEOUT_SECONDS
        ):
            raise ValueError("token request timeout is outside the supported range")
        self._cloud = defender_entra_cloud(cloud)
        self._credential = credential
        self._journal = journal
        self._timeout_seconds = timeout_seconds
        self._token_endpoint = (
            f"{self._cloud.authority_origin}/{self._tenant_id}{_TOKEN_TARGET_SUFFIX}"
        )
        self._token_endpoint_digest = _sha256(self._token_endpoint.encode("ascii"))
        self._transport = _transport or _UrllibTokenTransport(
            authority_origin=self._cloud.authority_origin,
            timeout_seconds=timeout_seconds,
            ssl_context=_ssl_context(ca_file),
        )
        self._connector_factory = _connector_factory or (
            lambda provider: DefenderXDRConnector(
                provider,
                endpoint=self._cloud.graph_origin,
                ca_file=ca_file,
                timeout_seconds=timeout_seconds,
            )
        )
        self._nonce = _nonce or (lambda: os.urandom(32).hex())
        self._now = _now or _epoch_milliseconds

    @property
    def token_endpoint_digest(self) -> str:
        return self._token_endpoint_digest

    @property
    def graph_origin_digest(self) -> str:
        return self._cloud.graph_origin_digest

    @property
    def scope_digest(self) -> str:
        return self._cloud.scope_digest

    @property
    def credential_reference_digest(self) -> str:
        return self._credential.reference_digest

    def _profile_digest(self) -> str:
        return _sha256(
            canonical_json_bytes(
                {
                    "client_id": self._client_id,
                    "client_assertion_type": CLIENT_ASSERTION_TYPE,
                    "grant_type": "client_credentials",
                    "scope": self._cloud.scope,
                }
            )
        )

    def _prepare(self, *, request_digest: str) -> DefenderTokenRecord:
        acquisition_id = self._nonce()
        if type(acquisition_id) is not str or _ACQUISITION_ID_RE.fullmatch(acquisition_id) is None:
            raise DefenderPamError("lifecycle", "nonce source returned an invalid id")
        now = self._now()
        if type(now) is not int or now < 0:
            raise DefenderPamError("clock", "wall clock source returned an invalid value")
        conservative_end = now + (
            (_MAX_ACCESS_TOKEN_TTL_SECONDS + _MAX_CLOCK_SKEW_SECONDS) * 1_000
        )
        return self._journal.prepare(
            acquisition_id=acquisition_id,
            request_digest=request_digest,
            token_endpoint_digest=self._token_endpoint_digest,
            graph_origin_digest=self._cloud.graph_origin_digest,
            scope_digest=self._cloud.scope_digest,
            credential_mode=self._credential.mode,
            credential_reference_digest=self._credential.reference_digest,
            token_request_profile_digest=self._profile_digest(),
            now_epoch_millis=now,
            conservative_exposure_end_epoch_millis=conservative_end,
        )

    def _form(self, assertion: _IssuedAssertion) -> bytes:
        fields = (
            ("client_id", self._client_id),
            ("client_assertion_type", CLIENT_ASSERTION_TYPE),
            ("client_assertion", assertion.value.decode("ascii", errors="strict")),
            ("grant_type", "client_credentials"),
            ("scope", self._cloud.scope),
        )
        body = urllib.parse.urlencode(fields, quote_via=urllib.parse.quote).encode("ascii")
        if len(body) > _MAX_FORM_BYTES:
            raise DefenderPamError("token-request", "token request form exceeds its byte limit")
        return body

    def _issue(self, prepared: DefenderTokenRecord) -> _IssuedToken:
        deadline = time.monotonic() + self._timeout_seconds
        assertion = self._credential.issue(
            client_id=self._client_id,
            token_endpoint=self._token_endpoint,
            now_epoch_seconds=self._now() // 1_000,
            deadline=deadline,
        )
        if (
            assertion.mode != prepared.credential_mode
            or assertion.reference_digest != prepared.credential_reference_digest
        ):
            raise DefenderPamError("assertion", "credential identity changed during acquisition")
        body = self._form(assertion)
        try:
            response = self._transport.request(
                target=f"/{self._tenant_id}{_TOKEN_TARGET_SUFFIX}",
                body=body,
                headers=_FORM_HEADERS,
                deadline=deadline,
            )
        except DefenderPamAmbiguousRequest as exc:
            self._journal.mark_uncertain(
                acquisition_id=prepared.acquisition_id,
                expected_revision=prepared.revision,
                now_epoch_millis=self._now(),
                error=_safe_reason(exc),
            )
            raise
        except BaseException as exc:
            # A transport implementation that fails after sending has an
            # ambiguous outcome unless it returned an HTTP response.
            self._journal.mark_uncertain(
                acquisition_id=prepared.acquisition_id,
                expected_revision=prepared.revision,
                now_epoch_millis=self._now(),
                error=type(exc).__name__,
            )
            raise DefenderPamAmbiguousRequest(
                "token-transport",
                "token request outcome is ambiguous",
            ) from None
        if type(response) is not _TokenHTTPResponse:
            self._journal.mark_uncertain(
                acquisition_id=prepared.acquisition_id,
                expected_revision=prepared.revision,
                now_epoch_millis=self._now(),
                error="invalid transport response",
            )
            raise DefenderPamAmbiguousRequest(
                "token-transport",
                "token transport returned an invalid response",
            )
        if (
            type(response.status) is not int
            or not 100 <= response.status <= 599
            or type(response.headers) is not tuple
            or type(response.body) is not bytes
            or len(response.body) > _MAX_RESPONSE_BYTES
        ):
            self._journal.mark_uncertain(
                acquisition_id=prepared.acquisition_id,
                expected_revision=prepared.revision,
                now_epoch_millis=self._now(),
                error="malformed transport response fields",
            )
            raise DefenderPamAmbiguousRequest(
                "token-transport",
                "token transport returned malformed response fields",
            )
        reflected = response.body + b"\x00" + b"\x00".join(
            f"{name}:{value}".encode("utf-8", errors="replace")
            for name, value in response.headers
        )
        if assertion.appears_in(reflected):
            self._journal.mark_uncertain(
                acquisition_id=prepared.acquisition_id,
                expected_revision=prepared.revision,
                now_epoch_millis=self._now(),
                error="assertion reflection",
            )
            raise DefenderPamAmbiguousRequest(
                "token-response",
                "token endpoint reflected client assertion material",
            )
        if response.status != 200:
            self._journal.close(
                acquisition_id=prepared.acquisition_id,
                expected_revision=prepared.revision,
                expected_state="prepared",
                closure="token-request-rejected-no-token",
                now_epoch_millis=self._now(),
                error=f"HTTP {response.status}",
            )
            raise DefenderPamError(
                "token-response",
                f"Microsoft Entra returned HTTP {response.status}",
            )
        try:
            parsed = self._parse_success(response)
        except DefenderPamError as exc:
            self._journal.mark_uncertain(
                acquisition_id=prepared.acquisition_id,
                expected_revision=prepared.revision,
                now_epoch_millis=self._now(),
                error=_safe_reason(exc),
            )
            raise DefenderPamAmbiguousRequest(
                "token-response",
                "HTTP 200 token response could not be safely consumed",
            ) from None
        token_bytes, expires_in, request_id_digest = parsed
        try:
            token = DefenderBearerToken(token_bytes)
        except ValueError:
            self._journal.mark_uncertain(
                acquisition_id=prepared.acquisition_id,
                expected_revision=prepared.revision,
                now_epoch_millis=self._now(),
                error="invalid access token material",
            )
            raise DefenderPamAmbiguousRequest(
                "token-response",
                "HTTP 200 contained invalid access token material",
            ) from None
        issued_at = self._now()
        expires_at = issued_at + (expires_in * 1_000)
        try:
            issued = self._journal.mark_issued(
                acquisition_id=prepared.acquisition_id,
                expected_revision=prepared.revision,
                now_epoch_millis=issued_at,
                expires_epoch_millis=expires_at,
                assertion_id_digest=assertion.assertion_id_digest,
                response_request_id_digest=request_id_digest,
            )
        except BaseException:
            # HTTP 200 contained a usable token.  If durable activation fails,
            # never relabel the prepared intent as a definite no-token result.
            with suppress(BaseException):
                self._journal.mark_uncertain(
                    acquisition_id=prepared.acquisition_id,
                    expected_revision=prepared.revision,
                    now_epoch_millis=self._now(),
                    error="issued token could not be durably activated",
                )
            raise DefenderPamAmbiguousRequest(
                "journal",
                "issued token could not be durably recorded",
            ) from None
        return _IssuedToken(token=token, record=issued)

    @staticmethod
    def _parse_success(
        response: _TokenHTTPResponse,
    ) -> tuple[bytes, int, str | None]:
        headers: dict[str, str] = {}
        previous = ""
        for name, value in response.headers:
            if (
                type(name) is not str
                or type(value) is not str
                or name != name.lower()
                or name <= previous
                or "\r" in value
                or "\n" in value
                or len(value) > 4_096
            ):
                raise DefenderPamError("token-response", "response headers are not canonical")
            headers[name] = value
            previous = name
        content_type = headers.get("content-type", "")
        if content_type.split(";", 1)[0].strip().lower() != "application/json":
            raise DefenderPamError("token-response", "token response is not application/json")
        if headers.get("content-encoding", "identity").lower() != "identity":
            raise DefenderPamError("token-response", "compressed token responses are forbidden")
        try:
            parsed = strict_json_loads(response.body, limits=_RESPONSE_LIMITS)
        except StrictJSONError as exc:
            raise DefenderPamError("token-response", "token response is not strict JSON") from exc
        if not isinstance(parsed, dict):
            raise DefenderPamError("token-response", "token response JSON is not an object")
        required = frozenset({"access_token", "expires_in", "token_type"})
        allowed = required | frozenset({"ext_expires_in"})
        if not required <= frozenset(parsed) or not frozenset(parsed) <= allowed:
            raise DefenderPamError("token-response", "response has missing or unexpected members")
        if parsed["token_type"] != "Bearer":
            raise DefenderPamError("token-response", "token type is not Bearer")
        expires = parsed["expires_in"]
        if (
            type(expires) is not int
            or not _MIN_ACCESS_TOKEN_TTL_SECONDS <= expires <= _MAX_ACCESS_TOKEN_TTL_SECONDS
        ):
            raise DefenderPamError("token-response", "access token lifetime is outside policy")
        if "ext_expires_in" in parsed and (
            type(parsed["ext_expires_in"]) is not int
            or parsed["ext_expires_in"] < expires
            or parsed["ext_expires_in"] > 86_400
        ):
            raise DefenderPamError("token-response", "extended token lifetime is invalid")
        access_token = parsed["access_token"]
        if type(access_token) is not str:
            raise DefenderPamError("token-response", "access token is not text")
        try:
            token_bytes = access_token.encode("ascii", errors="strict")
        except UnicodeEncodeError as exc:
            raise DefenderPamError("token-response", "access token is not ASCII") from exc
        if (
            not token_bytes
            or len(token_bytes) > _MAX_TOKEN_BYTES
            or _VISIBLE_TOKEN_RE.fullmatch(token_bytes) is None
        ):
            raise DefenderPamError("token-response", "access token has invalid syntax")
        request_id = headers.get("request-id")
        request_id_digest = (
            None if request_id is None else _sha256(request_id.encode("utf-8"))
        )
        return token_bytes, expires, request_id_digest

    def recover_unsettled(self, *, limit: int = 1_000) -> tuple[DefenderTokenRecord, ...]:
        """Close crashed intents without pretending their tokens were revoked."""

        return self._recover_records(self._journal.unsettled(limit=limit))

    def recover_request_digest(
        self,
        request_digest: str,
        *,
        limit: int = 1_000,
    ) -> tuple[DefenderTokenRecord, ...]:
        """Close crashed token intents for one exact connector request."""

        records = self._journal.records_for_request_digest(
            request_digest,
            unsettled_only=True,
            limit=limit,
        )
        return self._recover_records(records)

    def _recover_records(
        self,
        records: tuple[DefenderTokenRecord, ...],
    ) -> tuple[DefenderTokenRecord, ...]:
        recovered: list[DefenderTokenRecord] = []
        for record in records:
            if record.state == "prepared":
                recovered.append(
                    self._journal.mark_uncertain(
                        acquisition_id=record.acquisition_id,
                        expected_revision=record.revision,
                        now_epoch_millis=self._now(),
                        error="recovered prepared token request",
                    )
                )
            else:
                recovered.append(
                    self._journal.close(
                        acquisition_id=record.acquisition_id,
                        expected_revision=record.revision,
                        expected_state="issued",
                        closure="abandoned-after-crash",
                        now_epoch_millis=self._now(),
                        error="issued token was abandoned after process recovery",
                    )
                )
        return tuple(recovered)

    def capture(self, request: DefenderXDRRequest) -> ManagedDefenderCapture:
        """Acquire one token, perform one capture, and record expiry-only closure."""

        if type(request) is not DefenderXDRRequest:
            raise TypeError("request must be an exact DefenderXDRRequest")
        request_digest = _sha256(canonical_json_bytes(request.as_json()))
        prepared = self._prepare(request_digest=request_digest)
        try:
            issued = self._issue(prepared)
        except DefenderPamError as exc:
            latest = self._journal.get(prepared.acquisition_id)
            if latest.state == "prepared" and not isinstance(
                exc,
                DefenderPamAmbiguousRequest,
            ):
                self._journal.close(
                    acquisition_id=latest.acquisition_id,
                    expected_revision=latest.revision,
                    expected_state="prepared",
                    closure="token-request-rejected-no-token",
                    now_epoch_millis=self._now(),
                    error="assertion or local token request construction failed",
                )
            raise

        capture: ConnectorCapture | None = None
        operation_error: BaseException | None = None
        try:
            provider = _SingleUseTokenProvider(issued.token)
            if not isinstance(provider, DefenderBearerTokenProvider):
                raise DefenderPamError("token-use", "provider protocol integration failed")
            connector = self._connector_factory(provider)
            capture = connector.capture(request)
            if type(capture) is not ConnectorCapture:
                raise DefenderPamError("capture", "connector returned an invalid capture object")
        except BaseException as exc:
            operation_error = exc

        closure: TokenClosure = (
            "capture-completed-token-release-only"
            if operation_error is None
            else "capture-failed-token-release-only"
        )
        try:
            closed = self._journal.close(
                acquisition_id=issued.record.acquisition_id,
                expected_revision=issued.record.revision,
                expected_state="issued",
                closure=closure,
                now_epoch_millis=self._now(),
                error=None if operation_error is None else _safe_reason(operation_error),
            )
        except BaseException as exc:
            raise DefenderPamError(
                "journal",
                "capture is withheld because token lifecycle closure was not durable",
            ) from exc
        if operation_error is not None:
            if isinstance(operation_error, (DefenderPamError, ConnectorCaptureError)):
                raise operation_error
            raise DefenderPamError(
                "capture",
                "connector capture failed before evidence could be returned",
            )
        assert capture is not None
        receipt = self._receipt(closed=closed, capture=capture)
        verified = verify_defender_pam_receipt(
            receipt,
            expected_request_digest=request_digest,
            expected_token_endpoint_digest=self._token_endpoint_digest,
            expected_graph_origin_digest=self._cloud.graph_origin_digest,
            expected_scope_digest=self._cloud.scope_digest,
            expected_credential_reference_digest=self._credential.reference_digest,
            expected_capture_receipt_digest=capture.receipt_digest,
            expected_capture_records_digest=capture.records_digest,
        )
        return ManagedDefenderCapture(
            capture=capture,
            pam_receipt_bytes=receipt,
            pam_receipt_digest=verified.receipt_digest,
        )

    def _receipt(self, *, closed: DefenderTokenRecord, capture: ConnectorCapture) -> bytes:
        if (
            closed.state != "closed"
            or closed.closure != "capture-completed-token-release-only"
            or closed.issued_epoch_millis is None
            or closed.closed_epoch_millis is None
            or closed.access_token_expires_epoch_millis is None
            or closed.assertion_id_digest is None
        ):
            raise DefenderPamError("receipt", "token lifecycle is not a completed capture")
        value = {
            "authorization": {
                "dedicated_app_registration_required": True,
                "required_application_permission": DEFENDER_XDR_REQUIRED_PERMISSION,
                "requested_scope_mode": "resource-default-static-grants",
                "runtime_permission_attenuation_supported": False,
            },
            "broker": {"id": DEFENDER_PAM_BROKER_ID, "version": __version__},
            "capture": {
                "records_digest": capture.records_digest,
                "receipt_digest": capture.receipt_digest,
            },
            "identity": {
                "client_id_digest": _sha256(self._client_id.encode("ascii")),
                "cloud": self._cloud.name,
                "credential_mode": closed.credential_mode,
                "credential_reference_digest": closed.credential_reference_digest,
                "graph_origin_digest": closed.graph_origin_digest,
                "scope_digest": closed.scope_digest,
                "tenant_id_digest": _sha256(self._tenant_id.encode("ascii")),
                "token_endpoint_digest": closed.token_endpoint_digest,
            },
            "lifecycle": {
                "access_token_expires_epoch_millis": (
                    closed.access_token_expires_epoch_millis
                ),
                "access_token_lifetime_control": (
                    "issuer-determined-bounded-at-consumption"
                ),
                "access_token_max_accepted_ttl_seconds": (
                    _MAX_ACCESS_TOKEN_TTL_SECONDS
                ),
                "access_token_persisted": False,
                "access_token_revocation_supported": False,
                "acquisition_id": closed.acquisition_id,
                "assertion_id_digest": closed.assertion_id_digest,
                "closed_epoch_millis": closed.closed_epoch_millis,
                "closure": closed.closure,
                "created_epoch_millis": closed.created_epoch_millis,
                "issued_epoch_millis": closed.issued_epoch_millis,
                "refresh_token_requested": False,
                "refresh_token_received": False,
                "residual_exposure_end_epoch_millis": (
                    closed.access_token_expires_epoch_millis
                ),
                "revocation_boundary": "expiry-only-no-individual-token-revocation",
            },
            "media_type": DEFENDER_PAM_RECEIPT_MEDIA_TYPE,
            "request": {
                "request_digest": closed.request_digest,
                "token_request_profile_digest": closed.token_request_profile_digest,
            },
            "response": {
                "request_id_digest": closed.response_request_id_digest,
            },
            "schema_version": DEFENDER_PAM_RECEIPT_SCHEMA_VERSION,
        }
        try:
            return canonical_json_bytes(value, limits=_RECEIPT_LIMITS)
        except StrictJSONError as exc:
            raise DefenderPamError("receipt", "PAM receipt exceeds its canonical profile") from exc


def verify_defender_pam_receipt(
    receipt_bytes: bytes,
    *,
    expected_request_digest: str,
    expected_token_endpoint_digest: str,
    expected_graph_origin_digest: str,
    expected_scope_digest: str,
    expected_credential_reference_digest: str,
    expected_capture_receipt_digest: str,
    expected_capture_records_digest: str,
) -> VerifiedDefenderPamReceipt:
    """Verify a secret-free, expiry-only Defender token lifecycle receipt."""

    for label, value in (
        ("request", expected_request_digest),
        ("token endpoint", expected_token_endpoint_digest),
        ("Graph origin", expected_graph_origin_digest),
        ("scope", expected_scope_digest),
        ("credential reference", expected_credential_reference_digest),
        ("capture receipt", expected_capture_receipt_digest),
        ("capture records", expected_capture_records_digest),
    ):
        _require_digest(value, label=f"{label} digest")
    if type(receipt_bytes) is not bytes or not receipt_bytes:
        raise DefenderPamError("verify", "PAM receipt must be non-empty immutable bytes")
    try:
        parsed = strict_json_loads(receipt_bytes, limits=_RECEIPT_LIMITS)
        canonical = canonical_json_bytes(parsed, limits=_RECEIPT_LIMITS)
    except StrictJSONError as exc:
        raise DefenderPamError("verify", "PAM receipt is not strict bounded JSON") from exc
    if canonical != receipt_bytes or not isinstance(parsed, dict):
        raise DefenderPamError("verify", "PAM receipt is not a canonical JSON object")
    if frozenset(parsed) != frozenset(
        {
            "authorization",
            "broker",
            "capture",
            "identity",
            "lifecycle",
            "media_type",
            "request",
            "response",
            "schema_version",
        }
    ):
        raise DefenderPamError("verify", "PAM receipt has missing or unexpected members")
    if (
        parsed["media_type"] != DEFENDER_PAM_RECEIPT_MEDIA_TYPE
        or parsed["schema_version"] != DEFENDER_PAM_RECEIPT_SCHEMA_VERSION
    ):
        raise DefenderPamError("verify", "PAM receipt has the wrong profile identity")
    authorization = parsed["authorization"]
    broker = parsed["broker"]
    capture = parsed["capture"]
    identity = parsed["identity"]
    lifecycle = parsed["lifecycle"]
    request = parsed["request"]
    response = parsed["response"]
    if (
        not isinstance(authorization, dict)
        or frozenset(authorization)
        != frozenset(
            {
                "dedicated_app_registration_required",
                "required_application_permission",
                "requested_scope_mode",
                "runtime_permission_attenuation_supported",
            }
        )
        or authorization["dedicated_app_registration_required"] is not True
        or authorization["required_application_permission"]
        != DEFENDER_XDR_REQUIRED_PERMISSION
        or authorization["requested_scope_mode"] != "resource-default-static-grants"
        or authorization["runtime_permission_attenuation_supported"] is not False
        or not isinstance(broker, dict)
        or frozenset(broker) != frozenset({"id", "version"})
        or broker["id"] != DEFENDER_PAM_BROKER_ID
        or type(broker["version"]) is not str
        or not isinstance(capture, dict)
        or frozenset(capture) != frozenset({"records_digest", "receipt_digest"})
        or not isinstance(identity, dict)
        or not isinstance(lifecycle, dict)
        or not isinstance(request, dict)
        or not isinstance(response, dict)
    ):
        raise DefenderPamError("verify", "PAM receipt structure is invalid")
    if frozenset(identity) != frozenset(
        {
            "client_id_digest",
            "cloud",
            "credential_mode",
            "credential_reference_digest",
            "graph_origin_digest",
            "scope_digest",
            "tenant_id_digest",
            "token_endpoint_digest",
        }
    ) or frozenset(request) != frozenset(
        {"request_digest", "token_request_profile_digest"}
    ):
        raise DefenderPamError("verify", "PAM receipt identity fields are incomplete")
    if frozenset(lifecycle) != frozenset(
        {
            "access_token_expires_epoch_millis",
            "access_token_lifetime_control",
            "access_token_max_accepted_ttl_seconds",
            "access_token_persisted",
            "access_token_revocation_supported",
            "acquisition_id",
            "assertion_id_digest",
            "closed_epoch_millis",
            "closure",
            "created_epoch_millis",
            "issued_epoch_millis",
            "refresh_token_requested",
            "refresh_token_received",
            "residual_exposure_end_epoch_millis",
            "revocation_boundary",
        }
    ) or frozenset(response) != frozenset({"request_id_digest"}):
        raise DefenderPamError("verify", "PAM receipt lifecycle fields are incomplete")
    digests = (
        capture["records_digest"],
        capture["receipt_digest"],
        identity["client_id_digest"],
        identity["credential_reference_digest"],
        identity["graph_origin_digest"],
        identity["scope_digest"],
        identity["tenant_id_digest"],
        identity["token_endpoint_digest"],
        lifecycle["assertion_id_digest"],
        request["request_digest"],
        request["token_request_profile_digest"],
    )
    if any(type(value) is not str or _DIGEST_RE.fullmatch(value) is None for value in digests):
        raise DefenderPamError("verify", "PAM receipt contains an invalid digest")
    request_id_digest = response["request_id_digest"]
    if request_id_digest is not None and (
        type(request_id_digest) is not str
        or _DIGEST_RE.fullmatch(request_id_digest) is None
    ):
        raise DefenderPamError("verify", "PAM response request id digest is invalid")
    if (
        capture["receipt_digest"] != expected_capture_receipt_digest
        or capture["records_digest"] != expected_capture_records_digest
        or request["request_digest"] != expected_request_digest
        or identity["token_endpoint_digest"] != expected_token_endpoint_digest
        or identity["graph_origin_digest"] != expected_graph_origin_digest
        or identity["scope_digest"] != expected_scope_digest
        or identity["credential_reference_digest"]
        != expected_credential_reference_digest
    ):
        raise DefenderPamError("verify", "PAM receipt differs from an external anchor")
    cloud_name = identity["cloud"]
    credential_mode = identity["credential_mode"]
    if (
        type(cloud_name) is not str
        or cloud_name not in _CLOUDS
        or type(credential_mode) is not str
        or credential_mode not in {"certificate-ps256", "federated-rs256"}
        or type(lifecycle["acquisition_id"]) is not str
        or _ACQUISITION_ID_RE.fullmatch(lifecycle["acquisition_id"]) is None
    ):
        raise DefenderPamError("verify", "PAM identity or acquisition id is invalid")
    cloud_profile = _CLOUDS[cast(CloudName, cloud_name)]
    if (
        identity["graph_origin_digest"] != cloud_profile.graph_origin_digest
        or identity["scope_digest"] != cloud_profile.scope_digest
    ):
        raise DefenderPamError("verify", "PAM cloud binding is internally inconsistent")
    times = (
        lifecycle["created_epoch_millis"],
        lifecycle["issued_epoch_millis"],
        lifecycle["closed_epoch_millis"],
        lifecycle["access_token_expires_epoch_millis"],
        lifecycle["residual_exposure_end_epoch_millis"],
    )
    if any(type(value) is not int or value < 0 for value in times):
        raise DefenderPamError("verify", "PAM lifecycle time is invalid")
    created, issued, closed, expires, residual = cast(
        tuple[int, int, int, int, int],
        times,
    )
    if (
        not created <= issued <= closed < expires
        or residual != expires
        or not (
            _MIN_ACCESS_TOKEN_TTL_SECONDS * 1_000
            <= expires - issued
            <= _MAX_ACCESS_TOKEN_TTL_SECONDS * 1_000
        )
    ):
        raise DefenderPamError("verify", "PAM lifecycle timing is invalid")
    if (
        lifecycle["closure"] != "capture-completed-token-release-only"
        or lifecycle["access_token_lifetime_control"]
        != "issuer-determined-bounded-at-consumption"
        or lifecycle["access_token_max_accepted_ttl_seconds"]
        != _MAX_ACCESS_TOKEN_TTL_SECONDS
        or lifecycle["revocation_boundary"]
        != "expiry-only-no-individual-token-revocation"
        or lifecycle["access_token_revocation_supported"] is not False
        or lifecycle["access_token_persisted"] is not False
        or lifecycle["refresh_token_requested"] is not False
        or lifecycle["refresh_token_received"] is not False
    ):
        raise DefenderPamError("verify", "PAM receipt overstates token lifecycle closure")
    return VerifiedDefenderPamReceipt(
        acquisition_id=lifecycle["acquisition_id"],
        request_digest=cast(str, request["request_digest"]),
        token_endpoint_digest=cast(str, identity["token_endpoint_digest"]),
        graph_origin_digest=cast(str, identity["graph_origin_digest"]),
        scope_digest=cast(str, identity["scope_digest"]),
        credential_reference_digest=cast(str, identity["credential_reference_digest"]),
        capture_receipt_digest=cast(str, capture["receipt_digest"]),
        capture_records_digest=cast(str, capture["records_digest"]),
        residual_exposure_end_epoch_millis=residual,
        receipt_digest=_sha256(receipt_bytes),
    )


__all__ = [
    "CLIENT_ASSERTION_TYPE",
    "DEFENDER_PAM_BROKER_ID",
    "DEFENDER_PAM_RECEIPT_MEDIA_TYPE",
    "DEFENDER_PAM_RECEIPT_SCHEMA_VERSION",
    "FEDERATED_ASSERTION_AUDIENCE",
    "CertificateAssertionCredential",
    "DefenderEntraCloud",
    "DefenderPamAmbiguousRequest",
    "DefenderPamError",
    "DefenderTokenJournal",
    "DefenderTokenRecord",
    "DefenderWorkloadIdentityBroker",
    "FederatedAssertionCredential",
    "FederatedAssertionSource",
    "FederatedClientAssertion",
    "ManagedDefenderCapture",
    "PS256AssertionSigner",
    "SQLiteDefenderTokenJournal",
    "VerifiedDefenderPamReceipt",
    "defender_entra_cloud",
    "verify_defender_pam_receipt",
]
