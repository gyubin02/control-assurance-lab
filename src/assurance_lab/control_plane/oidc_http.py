"""Pinned HTTP and ``private_key_jwt`` boundary for the OIDC control plane.

The OIDC coordinator in :mod:`assurance_lab.control_plane.oidc` owns browser
state, PKCE, nonce validation, ID-token verification, entitlement mapping, and
session issuance.  This module closes the two network interfaces that the
coordinator intentionally leaves injectable:

* authorization-code redemption at one exact token endpoint; and
* JWKS retrieval from one exact URI.

Client authentication uses a short-lived PS256 assertion signed through the
same KMS/Vault protocol used by the Defender connector.  No client-secret
configuration exists.  The default transport disables environment proxies,
redirect following, response compression, and retries.  It accepts one
bounded response from the pinned HTTPS URL and never returns access or refresh
tokens to the application.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import math
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Protocol, cast, runtime_checkable

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from assurance_lab.connectors.defender_pam import PS256AssertionSigner
from assurance_lab.control_plane.oidc import (
    AuthorizationCodeRedeemer,
    JWKSFetcher,
    JWKSFetchRequest,
    JWKSFetchResult,
    OIDCConfiguration,
    TokenExchangeRequest,
    TokenExchangeResult,
)
from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)

PRIVATE_KEY_JWT_ASSERTION_TYPE: Final = (
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

_ASSERTION_TTL_SECONDS: Final = 300
_MAX_ASSERTION_BYTES: Final = 128 * 1024
_MAX_TOKEN_RESPONSE_BYTES: Final = 64 * 1024
_MAX_JWKS_RESPONSE_BYTES: Final = 1 * 1024 * 1024
_MAX_HEADER_COUNT: Final = 64
_MAX_HEADER_NAME_BYTES: Final = 128
_MAX_HEADER_VALUE_BYTES: Final = 8 * 1024
_MAX_ACCESS_TOKEN_BYTES: Final = 32 * 1024
_MAX_ID_TOKEN_BYTES: Final = 64 * 1024
_MAX_OPERATION_SECONDS: Final = 120
_MAX_JWKS_CACHE_SECONDS: Final = 300
_MAX_JWKS_NEGATIVE_CACHE_SECONDS: Final = 30
_MAX_JWKS_NEGATIVE_ENTRIES: Final = 128
_MAX_JWKS_GENERATION_BOUNDS: Final = 16

_CLIENT_ID_RE = re.compile(r"^[\x21-\x7e]{1,255}$")
_KID_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,255}$")
_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_COMPACT_JWT_RE = re.compile(r"^[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+[.][A-Za-z0-9_-]+$")
# RFC 6749 Appendix A permits VSCHAR in opaque access/refresh token strings.
# They are validated and discarded here, never interpreted as HTTP credentials.
_TOKEN_RE = re.compile(r"^[\x20-\x7e]+$")
_OAUTH_SCOPE_TOKEN_RE = re.compile(r'^[\x21\x23-\x5b\x5d-\x7e]{1,256}$')
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_SINGLETON_RESPONSE_HEADERS = frozenset(
    {
        "content-encoding",
        "content-length",
        "content-type",
        "location",
        "transfer-encoding",
    }
)

_TOKEN_RESPONSE_LIMITS = JSONLimits(
    max_bytes=_MAX_TOKEN_RESPONSE_BYTES,
    max_line_bytes=_MAX_TOKEN_RESPONSE_BYTES,
    max_depth=8,
    max_collection_items=64,
    max_string_length=_MAX_ID_TOKEN_BYTES,
)
_JWKS_RESPONSE_LIMITS = JSONLimits(
    max_bytes=_MAX_JWKS_RESPONSE_BYTES,
    max_line_bytes=_MAX_JWKS_RESPONSE_BYTES,
    max_depth=12,
    max_collection_items=1_024,
    max_string_length=16 * 1024,
)


class OIDCHTTPError(RuntimeError):
    """Stable, credential-free failure from the OIDC network boundary."""

    __slots__ = ("stage",)

    def __init__(self, stage: str) -> None:
        if (
            type(stage) is not str
            or not stage
            or len(stage) > 64
            or re.fullmatch(r"[a-z][a-z0-9-]*", stage) is None
        ):
            raise ValueError("OIDC HTTP failure stage is invalid")
        self.stage = stage
        super().__init__(f"OIDC network operation failed ({stage})")

    def __repr__(self) -> str:
        return f"{type(self).__name__}(stage={self.stage!r})"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _https_url(value: str, *, label: str) -> str:
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
        or "\\" in path
        or "%" in path
        or "//" in path
        or any(segment in {".", ".."} for segment in path.split("/"))
        or any(character.isspace() for character in value)
    ):
        raise ValueError(f"{label} must be one credential-free HTTPS URL")
    host = parsed.hostname.lower()
    rendered_host = f"[{host}]" if ":" in host else host
    authority = rendered_host if port in {None, 443} else f"{rendered_host}:{port}"
    return urllib.parse.urlunsplit(("https", authority, path, "", ""))


def _ssl_context(ca_file: Path | None) -> ssl.SSLContext:
    if ca_file is not None and not isinstance(ca_file, Path):
        raise TypeError("OIDC CA file must be a pathlib.Path")
    try:
        context = ssl.create_default_context(
            cafile=None if ca_file is None else str(ca_file)
        )
    except (OSError, ssl.SSLError):
        raise ValueError("OIDC CA trust configuration is invalid") from None
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class ClientAssertion:
    """One opaque compact assertion whose representations are always redacted."""

    __slots__ = ("__value", "expires_epoch_seconds", "identifier_digest")

    def __init__(
        self,
        value: bytes,
        *,
        expires_epoch_seconds: int,
        identifier_digest: str,
    ) -> None:
        try:
            text = value.decode("ascii", errors="strict")
        except (AttributeError, UnicodeDecodeError):
            text = ""
        if (
            type(value) is not bytes
            or not value
            or len(value) > _MAX_ASSERTION_BYTES
            or _COMPACT_JWT_RE.fullmatch(text) is None
        ):
            raise ValueError("client assertion is invalid")
        if type(expires_epoch_seconds) is not int or expires_epoch_seconds <= 0:
            raise ValueError("client assertion expiry is invalid")
        if (
            type(identifier_digest) is not str
            or re.fullmatch(r"sha256:[a-f0-9]{64}", identifier_digest) is None
        ):
            raise ValueError("client assertion identifier digest is invalid")
        self.__value = value
        self.expires_epoch_seconds = expires_epoch_seconds
        self.identifier_digest = identifier_digest

    def __repr__(self) -> str:
        return (
            "ClientAssertion(value=<redacted>, "
            f"expires_epoch_seconds={self.expires_epoch_seconds!r}, "
            f"identifier_digest={self.identifier_digest!r})"
        )

    def __str__(self) -> str:
        return "<redacted>"

    def _form_value(self) -> str:
        return self.__value.decode("ascii", errors="strict")

    def _appears_in(self, content: bytes) -> bool:
        quoted = urllib.parse.quote_from_bytes(self.__value).encode("ascii")
        return self.__value in content or quoted in content


@runtime_checkable
class ClientAssertionProvider(Protocol):
    """Issue one client assertion bound to an exact client and endpoint."""

    @property
    def client_id(self) -> str: ...

    @property
    def token_endpoint(self) -> str: ...

    def issue(self, *, deadline: float) -> ClientAssertion: ...


class CertificatePrivateKeyJWT:
    """PS256 ``private_key_jwt`` authentication with a remote private key.

    The remote signer receives only the compact JWS signing input.  The
    resulting signature is verified locally under the exact registered
    certificate before the assertion can cross the token boundary.
    """

    __slots__ = (
        "_certificate",
        "_client_id",
        "_jti",
        "_now",
        "_signer",
        "_token_endpoint",
    )

    def __init__(
        self,
        *,
        client_id: str,
        token_endpoint: str,
        certificate_der: bytes,
        signer: PS256AssertionSigner,
        _now: Callable[[], int] | None = None,
        _jti: Callable[[], str] | None = None,
    ) -> None:
        if type(client_id) is not str or _CLIENT_ID_RE.fullmatch(client_id) is None:
            raise ValueError("OIDC client id is invalid")
        endpoint = _https_url(token_endpoint, label="OIDC token endpoint")
        if type(certificate_der) is not bytes or not certificate_der:
            raise TypeError("certificate DER must be non-empty immutable bytes")
        if not isinstance(signer, PS256AssertionSigner):
            raise TypeError("signer must implement PS256AssertionSigner")
        key_reference = signer.key_reference
        if (
            type(key_reference) is not str
            or not key_reference
            or len(key_reference) > 512
            or any(character in key_reference for character in "\x00\r\n")
        ):
            raise ValueError("signer key reference is invalid")
        try:
            certificate = x509.load_der_x509_certificate(certificate_der)
        except ValueError:
            raise ValueError("certificate DER is not a valid X.509 certificate") from None
        public_key = certificate.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 2_048:
            raise ValueError("certificate must contain an RSA public key of at least 2048 bits")
        self._client_id = client_id
        self._token_endpoint = endpoint
        self._certificate = certificate
        self._signer = signer
        self._now = _now or (lambda: time.time_ns() // 1_000_000_000)
        self._jti = _jti or (lambda: str(uuid.uuid4()))

    @property
    def client_id(self) -> str:
        return self._client_id

    @property
    def token_endpoint(self) -> str:
        return self._token_endpoint

    @property
    def key_reference_digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            self._signer.key_reference.encode("utf-8")
        ).hexdigest()

    def issue(self, *, deadline: float) -> ClientAssertion:
        if type(deadline) is not float or not math.isfinite(deadline):
            raise TypeError("client assertion deadline must be a finite float")
        if time.monotonic() >= deadline:
            raise OIDCHTTPError("assertion-deadline")
        now = self._now()
        if type(now) is not int or now < 0:
            raise OIDCHTTPError("assertion-clock")
        if not (
            int(self._certificate.not_valid_before_utc.timestamp())
            <= now
            < int(self._certificate.not_valid_after_utc.timestamp())
        ):
            raise OIDCHTTPError("assertion-certificate")
        try:
            jti = self._jti()
        except Exception:
            raise OIDCHTTPError("assertion-identifier") from None
        if type(jti) is not str or _UUID_RE.fullmatch(jti) is None:
            raise OIDCHTTPError("assertion-identifier")
        try:
            if str(uuid.UUID(jti)) != jti:
                raise ValueError
        except ValueError:
            raise OIDCHTTPError("assertion-identifier") from None

        header = {
            "alg": "PS256",
            "typ": "JWT",
            "x5t#S256": _b64url(self._certificate.fingerprint(hashes.SHA256())),
        }
        claims = {
            "aud": self._token_endpoint,
            "exp": now + _ASSERTION_TTL_SECONDS,
            "iat": now,
            "iss": self._client_id,
            "jti": jti,
            "nbf": now,
            "sub": self._client_id,
        }
        signing_input = (
            f"{_b64url(canonical_json_bytes(header))}."
            f"{_b64url(canonical_json_bytes(claims))}"
        ).encode("ascii")
        try:
            signature = self._signer.sign_ps256(signing_input, deadline=deadline)
        except Exception:
            raise OIDCHTTPError("assertion-signing") from None
        if (
            type(signature) is not bytes
            or not signature
            or len(signature) > 2_048
            or time.monotonic() >= deadline
        ):
            raise OIDCHTTPError("assertion-signature")
        public_key = self._certificate.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        try:
            public_key.verify(
                signature,
                signing_input,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256(),
            )
        except InvalidSignature:
            raise OIDCHTTPError("assertion-signature") from None
        value = signing_input + b"." + _b64url(signature).encode("ascii")
        return ClientAssertion(
            value,
            expires_epoch_seconds=now + _ASSERTION_TTL_SECONDS,
            identifier_digest="sha256:" + hashlib.sha256(jti.encode("ascii")).hexdigest(),
        )


@dataclass(frozen=True, slots=True)
class _HTTPResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


@dataclass(slots=True)
class _JWKSFlight:
    """One network retrieval shared by callers without sharing exceptions."""

    forced: bool
    leader_missing_kid: str | None
    event: threading.Event = field(default_factory=threading.Event)
    payload: bytes | None = None
    kids: frozenset[str] = frozenset()
    generation_digest: str | None = None
    error_stage: str | None = None


class _HTTPTransport(Protocol):
    def request(
        self,
        *,
        method: str,
        url: str,
        body: bytes | None,
        headers: tuple[tuple[str, str], ...],
        maximum_response_bytes: int,
        deadline: float,
    ) -> _HTTPResponse: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: http.client.HTTPMessage,
        new_url: str,
    ) -> None:
        del request, file_pointer, code, message, headers, new_url
        return None


class _UrllibHTTPTransport:
    __slots__ = ("_opener", "_timeout_seconds")

    def __init__(
        self,
        *,
        ssl_context: ssl.SSLContext,
        timeout_seconds: int,
    ) -> None:
        self._timeout_seconds = timeout_seconds
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl_context),
        )

    def request(
        self,
        *,
        method: str,
        url: str,
        body: bytes | None,
        headers: tuple[tuple[str, str], ...],
        maximum_response_bytes: int,
        deadline: float,
    ) -> _HTTPResponse:
        if method not in {"GET", "POST"}:
            raise OIDCHTTPError("transport-profile")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise OIDCHTTPError("transport-deadline")
        request = urllib.request.Request(
            url,
            data=body,
            headers=dict(headers),
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
        except (
            TimeoutError,
            urllib.error.URLError,
            http.client.HTTPException,
            OSError,
        ):
            raise OIDCHTTPError("transport") from None
        try:
            content = bytearray()
            reader = getattr(response, "read1", response.read)
            while True:
                if time.monotonic() >= deadline:
                    raise OIDCHTTPError("transport-deadline")
                chunk = reader(min(64 * 1024, maximum_response_bytes + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > maximum_response_bytes:
                    raise OIDCHTTPError("response-size")
            raw_items = getattr(response.headers, "raw_items", response.headers.items)()
            response_headers = tuple(
                (str(name), str(value))
                for name, value in raw_items
            )
            return _HTTPResponse(
                status=int(response.status),
                headers=response_headers,
                body=bytes(content),
            )
        except (OSError, http.client.HTTPException):
            raise OIDCHTTPError("transport") from None
        finally:
            response.close()


def _canonical_headers(
    headers: tuple[tuple[str, str], ...],
    *,
    body_length: int,
) -> dict[str, str]:
    if type(body_length) is not int or body_length < 0:
        raise OIDCHTTPError("response-headers")
    if type(headers) is not tuple or len(headers) > _MAX_HEADER_COUNT:
        raise OIDCHTTPError("response-headers")
    canonical: dict[str, str] = {}
    for item in headers:
        if (
            type(item) is not tuple
            or len(item) != 2
            or type(item[0]) is not str
            or type(item[1]) is not str
        ):
            raise OIDCHTTPError("response-headers")
        name, value = item
        if (
            not name
            or len(name.encode("ascii", errors="ignore")) > _MAX_HEADER_NAME_BYTES
            or _HEADER_NAME_RE.fullmatch(name) is None
            or len(value.encode("utf-8")) > _MAX_HEADER_VALUE_BYTES
            or any(character in value for character in "\x00\r\n")
        ):
            raise OIDCHTTPError("response-headers")
        lowered = name.lower()
        if lowered in canonical and lowered in _SINGLETON_RESPONSE_HEADERS:
            raise OIDCHTTPError("response-headers")
        canonical.setdefault(lowered, value)
    content_length = canonical.get("content-length")
    transfer_encoding = canonical.get("transfer-encoding")
    if content_length is not None and transfer_encoding is not None:
        raise OIDCHTTPError("response-headers")
    if (
        content_length is not None
        and (
            re.fullmatch(r"[0-9]{1,20}", content_length) is None
            or int(content_length) != body_length
        )
    ):
        raise OIDCHTTPError("response-headers")
    if (
        transfer_encoding is not None
        and transfer_encoding.strip().lower() != "chunked"
    ):
        raise OIDCHTTPError("response-headers")
    return canonical


def _is_json_content_type(value: str, *, jwks: bool) -> bool:
    media_type = value.split(";", 1)[0].strip().lower()
    allowed = {"application/json"}
    if jwks:
        allowed.add("application/jwk-set+json")
    return media_type in allowed


def _secret_variants(value: str) -> tuple[bytes, ...]:
    raw = value.encode("utf-8")
    return (
        raw,
        urllib.parse.quote(value, safe="").encode("ascii"),
        urllib.parse.quote_plus(value, safe="").encode("ascii"),
    )


def _headers_bytes(headers: tuple[tuple[str, str], ...]) -> bytes:
    return b"\x00".join(
        name.encode("ascii", errors="ignore")
        + b":"
        + value.encode("utf-8", errors="replace")
        for name, value in headers
    )


class PinnedOIDCHTTPClient(AuthorizationCodeRedeemer, JWKSFetcher):
    """Production transport for one immutable OIDC deployment profile."""

    __slots__ = (
        "_assertions",
        "_client_id",
        "_issuer",
        "_jwks_cache_generation_digest",
        "_jwks_cache_kids",
        "_jwks_cache_lock",
        "_jwks_cache_payload",
        "_jwks_cache_seconds",
        "_jwks_cache_until",
        "_jwks_failure_stage",
        "_jwks_failure_until",
        "_jwks_flight",
        "_jwks_generation_refresh_not_before",
        "_jwks_negative_cache",
        "_jwks_negative_cache_seconds",
        "_jwks_uri",
        "_redirect_uri",
        "_timeout_seconds",
        "_token_endpoint",
        "_transport",
    )

    def __init__(
        self,
        configuration: OIDCConfiguration,
        assertions: ClientAssertionProvider,
        *,
        ca_file: Path | None = None,
        timeout_seconds: int = 15,
        jwks_cache_seconds: int = 60,
        jwks_negative_cache_seconds: int = 5,
        _transport: _HTTPTransport | None = None,
    ) -> None:
        if type(configuration) is not OIDCConfiguration:
            raise TypeError("configuration must be an exact OIDCConfiguration")
        if not isinstance(assertions, ClientAssertionProvider):
            raise TypeError("assertions must implement ClientAssertionProvider")
        if (
            assertions.client_id != configuration.client_id
            or assertions.token_endpoint != configuration.token_endpoint
        ):
            raise ValueError("client assertion identity is not bound to this OIDC profile")
        if (
            type(timeout_seconds) is not int
            or not 1 <= timeout_seconds <= _MAX_OPERATION_SECONDS
        ):
            raise ValueError("OIDC timeout is outside the supported range")
        if (
            type(jwks_cache_seconds) is not int
            or not 0 <= jwks_cache_seconds <= _MAX_JWKS_CACHE_SECONDS
        ):
            raise ValueError("JWKS cache TTL is outside the supported range")
        if (
            type(jwks_negative_cache_seconds) is not int
            or not 1
            <= jwks_negative_cache_seconds
            <= _MAX_JWKS_NEGATIVE_CACHE_SECONDS
        ):
            raise ValueError("JWKS negative cache TTL is outside the supported range")
        self._issuer = configuration.issuer
        self._token_endpoint = configuration.token_endpoint
        self._jwks_uri = configuration.jwks_uri
        self._client_id = configuration.client_id
        self._redirect_uri = configuration.redirect_uri
        self._assertions = assertions
        self._timeout_seconds = timeout_seconds
        self._jwks_cache_seconds = jwks_cache_seconds
        self._jwks_negative_cache_seconds = jwks_negative_cache_seconds
        self._jwks_cache_lock = threading.Lock()
        self._jwks_cache_payload: bytes | None = None
        self._jwks_cache_kids: frozenset[str] = frozenset()
        self._jwks_cache_generation_digest: str | None = None
        self._jwks_cache_until = 0.0
        self._jwks_flight: _JWKSFlight | None = None
        self._jwks_negative_cache: OrderedDict[tuple[str, str], float] = OrderedDict()
        self._jwks_generation_refresh_not_before: OrderedDict[str, float] = (
            OrderedDict()
        )
        self._jwks_failure_until = 0.0
        self._jwks_failure_stage: str | None = None
        self._transport = _transport or _UrllibHTTPTransport(
            ssl_context=_ssl_context(ca_file),
            timeout_seconds=timeout_seconds,
        )

    def _deadline(self) -> float:
        return time.monotonic() + float(self._timeout_seconds)

    def redeem(self, request: TokenExchangeRequest) -> TokenExchangeResult:
        if (
            type(request) is not TokenExchangeRequest
            or request.endpoint != self._token_endpoint
            or request.client_id != self._client_id
            or request.redirect_uri != self._redirect_uri
            or request.grant_type != "authorization_code"
            or request.allow_redirects is not False
            or request.use_environment_proxy is not False
            or request.allow_response_compression is not False
            or request.maximum_response_bytes != _MAX_TOKEN_RESPONSE_BYTES
        ):
            raise OIDCHTTPError("token-request-profile")
        deadline = self._deadline()
        try:
            assertion = self._assertions.issue(deadline=deadline)
        except OIDCHTTPError:
            raise
        except Exception:
            raise OIDCHTTPError("assertion") from None
        if type(assertion) is not ClientAssertion:
            raise OIDCHTTPError("assertion")
        fields = (
            ("client_id", self._client_id),
            ("client_assertion_type", PRIVATE_KEY_JWT_ASSERTION_TYPE),
            ("client_assertion", assertion._form_value()),
            ("code", request.code),
            ("code_verifier", request.code_verifier),
            ("grant_type", "authorization_code"),
            ("redirect_uri", self._redirect_uri),
        )
        body = urllib.parse.urlencode(
            fields,
            quote_via=urllib.parse.quote,
            safe="",
        ).encode("ascii")
        if len(body) > 192 * 1024:
            raise OIDCHTTPError("token-request-size")
        try:
            response = self._transport.request(
                method="POST",
                url=self._token_endpoint,
                body=body,
                headers=(
                    ("Accept", "application/json"),
                    ("Accept-Encoding", "identity"),
                    ("Content-Type", "application/x-www-form-urlencoded"),
                ),
                maximum_response_bytes=_MAX_TOKEN_RESPONSE_BYTES,
                deadline=deadline,
            )
        except OIDCHTTPError:
            raise
        except Exception:
            # The code is single-use and the transport may have sent the
            # request before failing.  Never retry or expose the underlying
            # exception as if the outcome were known.
            raise OIDCHTTPError("token-transport-ambiguous") from None
        if (
            type(response) is not _HTTPResponse
            or type(response.status) is not int
            or type(response.body) is not bytes
            or len(response.body) > _MAX_TOKEN_RESPONSE_BYTES
        ):
            raise OIDCHTTPError("token-response")
        headers = _canonical_headers(response.headers, body_length=len(response.body))
        reflected = response.body + b"\x00" + _headers_bytes(response.headers)
        if assertion._appears_in(reflected) or any(
            variant in reflected
            for secret in (request.code, request.code_verifier)
            for variant in _secret_variants(secret)
        ):
            raise OIDCHTTPError("token-response-reflection")
        if (
            response.status != 200
            or not _is_json_content_type(headers.get("content-type", ""), jwks=False)
            or headers.get("content-encoding", "identity").lower() != "identity"
        ):
            raise OIDCHTTPError("token-response")
        try:
            parsed = strict_json_loads(response.body, limits=_TOKEN_RESPONSE_LIMITS)
        except StrictJSONError:
            raise OIDCHTTPError("token-response") from None
        if type(parsed) is not dict:
            raise OIDCHTTPError("token-response")
        values = cast(dict[str, object], parsed)
        required = frozenset({"access_token", "id_token", "token_type"})
        if not required <= frozenset(values):
            raise OIDCHTTPError("token-response")
        token_type = values["token_type"]
        if (
            type(token_type) is not str
            or len(token_type) > 64
            or token_type.casefold() != "bearer"
        ):
            raise OIDCHTTPError("token-response")
        if "expires_in" in values:
            expires_in = values["expires_in"]
            if type(expires_in) is not int or not 1 <= expires_in <= 86_400:
                raise OIDCHTTPError("token-response")
        access_token = values["access_token"]
        id_token = values["id_token"]
        if (
            type(access_token) is not str
            or not access_token
            or len(access_token.encode("utf-8")) > _MAX_ACCESS_TOKEN_BYTES
            or _TOKEN_RE.fullmatch(access_token) is None
            or type(id_token) is not str
            or len(id_token.encode("ascii", errors="ignore")) > _MAX_ID_TOKEN_BYTES
            or _COMPACT_JWT_RE.fullmatch(id_token) is None
        ):
            raise OIDCHTTPError("token-response")
        # RFC 6749 allows a refresh token and extension response members.
        # This component has no refresh-token flow: validate the optional
        # secret under the same bound, then drop both bearer credentials
        # immediately.  Only the ID token crosses this adapter boundary.
        refresh_token = values.get("refresh_token")
        if (
            "refresh_token" in values
            and (
                type(refresh_token) is not str
                or not refresh_token
                or len(refresh_token.encode("utf-8")) > _MAX_ACCESS_TOKEN_BYTES
                or _TOKEN_RE.fullmatch(refresh_token) is None
            )
        ):
            raise OIDCHTTPError("token-response")
        values.pop("access_token")
        values.pop("refresh_token", None)
        del access_token, refresh_token
        if "scope" in values:
            scope = values["scope"]
            if type(scope) is not str or len(scope) > 4_096:
                raise OIDCHTTPError("token-response")
            returned_scopes = scope.split(" ")
            if (
                not returned_scopes
                or "" in returned_scopes
                or len(returned_scopes) > 64
                or len(returned_scopes) != len(set(returned_scopes))
                or any(
                    _OAUTH_SCOPE_TOKEN_RE.fullmatch(item) is None
                    for item in returned_scopes
                )
            ):
                raise OIDCHTTPError("token-response")
        return TokenExchangeResult(
            id_token=id_token,
            effective_endpoint=self._token_endpoint,
        )

    @staticmethod
    def _jwks_generation(payload: bytes) -> str:
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    def _admit_jwks_response(
        self,
        response: _HTTPResponse,
    ) -> tuple[bytes, frozenset[str], str]:
        headers = _canonical_headers(response.headers, body_length=len(response.body))
        if (
            type(response.status) is not int
            or response.status != 200
            or type(response.body) is not bytes
            or not response.body
            or len(response.body) > _MAX_JWKS_RESPONSE_BYTES
            or not _is_json_content_type(headers.get("content-type", ""), jwks=True)
            or headers.get("content-encoding", "identity").lower() != "identity"
        ):
            raise OIDCHTTPError("jwks-response")
        try:
            parsed = strict_json_loads(response.body, limits=_JWKS_RESPONSE_LIMITS)
        except StrictJSONError:
            raise OIDCHTTPError("jwks-response") from None
        if type(parsed) is not dict or type(parsed.get("keys")) is not list:
            raise OIDCHTTPError("jwks-response")
        keys = cast(list[object], parsed["keys"])
        if not keys or len(keys) > 512 or any(type(item) is not dict for item in keys):
            raise OIDCHTTPError("jwks-response")
        kids: set[str] = set()
        for raw_key in keys:
            key = cast(dict[str, object], raw_key)
            kid = key.get("kid")
            if kid is None:
                continue
            if type(kid) is not str or _KID_RE.fullmatch(kid) is None:
                raise OIDCHTTPError("jwks-response")
            kids.add(kid)
        payload = bytes(response.body)
        return payload, frozenset(kids), self._jwks_generation(payload)

    def _retrieve_jwks(
        self,
        *,
        deadline: float,
    ) -> tuple[bytes, frozenset[str], str]:
        try:
            response = self._transport.request(
                method="GET",
                url=self._jwks_uri,
                body=None,
                headers=(
                    ("Accept", "application/jwk-set+json, application/json"),
                    ("Accept-Encoding", "identity"),
                ),
                maximum_response_bytes=_MAX_JWKS_RESPONSE_BYTES,
                deadline=deadline,
            )
        except Exception:
            raise OIDCHTTPError("jwks-transport") from None
        if type(response) is not _HTTPResponse:
            raise OIDCHTTPError("jwks-response")
        return self._admit_jwks_response(response)

    def _prune_jwks_bounds_locked(self, *, now: float) -> None:
        for key, expires_at in tuple(self._jwks_negative_cache.items()):
            if expires_at <= now:
                self._jwks_negative_cache.pop(key, None)
        while len(self._jwks_negative_cache) > _MAX_JWKS_NEGATIVE_ENTRIES:
            self._jwks_negative_cache.popitem(last=False)

        for generation, expires_at in tuple(
            self._jwks_generation_refresh_not_before.items()
        ):
            if expires_at <= now:
                self._jwks_generation_refresh_not_before.pop(generation, None)
        while (
            len(self._jwks_generation_refresh_not_before)
            > _MAX_JWKS_GENERATION_BOUNDS
        ):
            self._jwks_generation_refresh_not_before.popitem(last=False)

    def _record_negative_locked(
        self,
        *,
        generation_digest: str,
        missing_kid: str,
        expires_at: float,
    ) -> None:
        key = (generation_digest, missing_kid)
        self._jwks_negative_cache.pop(key, None)
        self._jwks_negative_cache[key] = expires_at
        while len(self._jwks_negative_cache) > _MAX_JWKS_NEGATIVE_ENTRIES:
            self._jwks_negative_cache.popitem(last=False)

    def _joined_jwks_result(
        self,
        *,
        flight: _JWKSFlight,
        deadline: float,
        missing_kid: str | None,
    ) -> JWKSFetchResult:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not flight.event.wait(timeout=remaining):
            raise OIDCHTTPError("jwks-wait-timeout")
        if flight.error_stage is not None:
            raise OIDCHTTPError(flight.error_stage)
        if (
            flight.payload is None
            or flight.generation_digest is None
            or not _DIGEST_RE.fullmatch(flight.generation_digest)
        ):
            raise OIDCHTTPError("jwks-response")
        if missing_kid is not None and missing_kid not in flight.kids:
            with self._jwks_cache_lock:
                self._record_negative_locked(
                    generation_digest=flight.generation_digest,
                    missing_kid=missing_kid,
                    expires_at=(
                        time.monotonic() + self._jwks_negative_cache_seconds
                    ),
                )
        return JWKSFetchResult(
            payload=flight.payload,
            effective_uri=self._jwks_uri,
        )

    def fetch(self, request: JWKSFetchRequest) -> JWKSFetchResult:
        if (
            type(request) is not JWKSFetchRequest
            or request.uri != self._jwks_uri
            or request.expected_issuer != self._issuer
            or type(request.force_refresh) is not bool
            or (
                request.force_refresh
                and (
                    type(request.missing_kid) is not str
                    or _KID_RE.fullmatch(request.missing_kid) is None
                    or type(request.observed_generation_digest) is not str
                    or _DIGEST_RE.fullmatch(request.observed_generation_digest)
                    is None
                )
            )
            or (
                not request.force_refresh
                and (
                    request.missing_kid is not None
                    or request.observed_generation_digest is not None
                )
            )
            or request.allow_redirects is not False
            or request.use_environment_proxy is not False
            or request.allow_response_compression is not False
            or request.maximum_response_bytes != _MAX_JWKS_RESPONSE_BYTES
        ):
            raise OIDCHTTPError("jwks-request-profile")
        deadline = self._deadline()
        leader = False
        with self._jwks_cache_lock:
            now = time.monotonic()
            self._prune_jwks_bounds_locked(now=now)
            cache_is_fresh = (
                self._jwks_cache_payload is not None
                and self._jwks_cache_generation_digest is not None
                and now < self._jwks_cache_until
            )
            if (
                not request.force_refresh
                and cache_is_fresh
            ):
                assert self._jwks_cache_payload is not None
                return JWKSFetchResult(
                    payload=self._jwks_cache_payload,
                    effective_uri=self._jwks_uri,
                )
            if request.force_refresh and cache_is_fresh:
                assert request.missing_kid is not None
                assert request.observed_generation_digest is not None
                assert self._jwks_cache_generation_digest is not None
                assert self._jwks_cache_payload is not None
                generation = self._jwks_cache_generation_digest
                if generation != request.observed_generation_digest:
                    return JWKSFetchResult(
                        payload=self._jwks_cache_payload,
                        effective_uri=self._jwks_uri,
                    )
                negative_until = self._jwks_negative_cache.get(
                    (generation, request.missing_kid),
                    0.0,
                )
                refresh_not_before = self._jwks_generation_refresh_not_before.get(
                    generation,
                    0.0,
                )
                if now < negative_until or now < refresh_not_before:
                    if request.missing_kid not in self._jwks_cache_kids:
                        self._record_negative_locked(
                            generation_digest=generation,
                            missing_kid=request.missing_kid,
                            expires_at=max(negative_until, refresh_not_before),
                        )
                    return JWKSFetchResult(
                        payload=self._jwks_cache_payload,
                        effective_uri=self._jwks_uri,
                    )
            flight = self._jwks_flight
            if flight is None and now < self._jwks_failure_until:
                raise OIDCHTTPError(self._jwks_failure_stage or "jwks-transport")
            if flight is None:
                flight = _JWKSFlight(
                    forced=request.force_refresh,
                    leader_missing_kid=request.missing_kid,
                )
                self._jwks_flight = flight
                leader = True
            elif request.force_refresh:
                # A forced waiter promotes an already-running ordinary cache
                # fill so its resulting generation receives the same rate
                # bound as a forced leader.
                flight.forced = True
                if flight.leader_missing_kid is None:
                    flight.leader_missing_kid = request.missing_kid
            if leader and request.force_refresh:
                # A forced rotation check makes the observed set ineligible as
                # fallback before I/O.  Waiters retain only the flight handle.
                self._jwks_cache_payload = None
                self._jwks_cache_kids = frozenset()
                self._jwks_cache_generation_digest = None
                self._jwks_cache_until = 0.0

        if not leader:
            return self._joined_jwks_result(
                flight=flight,
                deadline=deadline,
                missing_kid=request.missing_kid,
            )

        try:
            payload, kids, generation_digest = self._retrieve_jwks(
                deadline=deadline
            )
        except OIDCHTTPError as error:
            with self._jwks_cache_lock:
                self._jwks_cache_payload = None
                self._jwks_cache_kids = frozenset()
                self._jwks_cache_generation_digest = None
                self._jwks_cache_until = 0.0
                self._jwks_failure_stage = error.stage
                self._jwks_failure_until = (
                    time.monotonic() + self._jwks_negative_cache_seconds
                )
                flight.error_stage = error.stage
                if self._jwks_flight is flight:
                    self._jwks_flight = None
                flight.event.set()
            raise OIDCHTTPError(error.stage) from None

        completed_at = time.monotonic()
        with self._jwks_cache_lock:
            self._jwks_cache_payload = payload
            self._jwks_cache_kids = kids
            self._jwks_cache_generation_digest = generation_digest
            self._jwks_cache_until = completed_at + self._jwks_cache_seconds
            self._jwks_failure_stage = None
            self._jwks_failure_until = 0.0
            if flight.forced:
                refresh_bound = (
                    completed_at + self._jwks_negative_cache_seconds
                )
                self._jwks_generation_refresh_not_before.pop(
                    generation_digest,
                    None,
                )
                self._jwks_generation_refresh_not_before[generation_digest] = (
                    refresh_bound
                )
                if (
                    flight.leader_missing_kid is not None
                    and flight.leader_missing_kid not in kids
                ):
                    self._record_negative_locked(
                        generation_digest=generation_digest,
                        missing_kid=flight.leader_missing_kid,
                        expires_at=refresh_bound,
                    )
            self._prune_jwks_bounds_locked(now=completed_at)
            flight.payload = payload
            flight.kids = kids
            flight.generation_digest = generation_digest
            if self._jwks_flight is flight:
                self._jwks_flight = None
            flight.event.set()
        return JWKSFetchResult(payload=payload, effective_uri=self._jwks_uri)


__all__ = [
    "PRIVATE_KEY_JWT_ASSERTION_TYPE",
    "CertificatePrivateKeyJWT",
    "ClientAssertion",
    "ClientAssertionProvider",
    "OIDCHTTPError",
    "PinnedOIDCHTTPClient",
]
