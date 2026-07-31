"""Pinned Azure Key Vault operations for workload signing and PKCE custody.

Two deliberately narrow production boundaries live here:

* :class:`AzureKeyVaultPS256Signer` implements the Defender workload-identity
  signer without exporting an RSA private key; and
* :class:`AzureKeyVaultEnvelopeProtector` protects the OIDC PKCE verifier with
  AES-256-GCM while Azure Key Vault wraps the ephemeral data-encryption key.

The adapter accepts no client secret and implements no credential discovery.
An injected token provider must return a short-lived token for the exact Key
Vault scope.  Requests use one pinned public-cloud vault origin, one immutable
key version, no environment proxy, no redirect, no compression, and no retry.

This is an application-layer fail-closed boundary, not proof that the Azure
tenant, managed identity, RBAC assignment, private endpoint, or HSM tier was
configured correctly.  Those controls remain deployment and conformance
responsibilities.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import math
import os
import re
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, cast, runtime_checkable

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from assurance_lab.control_plane.postgres_oidc_store import ProtectedCodeVerifier
from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)

AZURE_KEY_VAULT_SCOPE: Final = "https://vault.azure.net/.default"
AZURE_KEY_VAULT_API_VERSION: Final = "2025-07-01"
AZURE_KEY_VAULT_ENVELOPE_MEDIA_TYPE: Final = (
    "application/vnd.control-assurance.azure-key-vault-envelope.v1+json"
)
AZURE_KEY_VAULT_ENVELOPE_SCHEMA_VERSION: Final = "1.0.0"

_MAX_TOKEN_BYTES: Final = 64 * 1024
_MAX_RESPONSE_BYTES: Final = 128 * 1024
_MAX_OPERATION_SECONDS: Final = 120
_MAX_WRAPPED_KEY_BYTES: Final = 16 * 1024
_MAX_ENVELOPE_BYTES: Final = 32 * 1024
_AES_KEY_BYTES: Final = 32
_AES_NONCE_BYTES: Final = 12
_AES_TAG_BYTES: Final = 16
_CONTENT_ALGORITHM: Final = "A256GCM"
_WRAP_ALGORITHM: Final = "RSA-OAEP-256"
_PROTECTED_ALGORITHM: Final = "A256GCM+RSA-OAEP-256"
_AAD_PREFIX: Final = b"control-assurance:oidc-pkce:v1\x00"

_VAULT_NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,22}[a-z0-9])$")
_KEY_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,127}$")
_KEY_VERSION_RE = re.compile(r"^[a-f0-9]{32}$")
_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_PKCE_RE = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
_TOKEN_RE = re.compile(rb"^[\x21-\x7e]{1,65536}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_DOCUMENT_LIMITS = JSONLimits(
    max_bytes=_MAX_ENVELOPE_BYTES,
    max_line_bytes=_MAX_ENVELOPE_BYTES,
    max_depth=5,
    max_collection_items=32,
    max_string_length=24 * 1024,
)
_RESPONSE_LIMITS = JSONLimits(
    max_bytes=_MAX_RESPONSE_BYTES,
    max_line_bytes=_MAX_RESPONSE_BYTES,
    max_depth=5,
    max_collection_items=32,
    max_string_length=_MAX_RESPONSE_BYTES,
)


class AzureKeyVaultError(RuntimeError):
    """Stable credential-free error from the Key Vault boundary."""

    __slots__ = ("stage",)

    def __init__(self, stage: str, detail: str) -> None:
        self.stage = stage
        super().__init__(detail)


class AzureKeyVaultBearerToken:
    """Opaque short-lived Key Vault token with redacted representations."""

    __slots__ = ("__token", "valid_until_monotonic")

    def __init__(self, token: bytes, *, valid_until_monotonic: float) -> None:
        if (
            type(token) is not bytes
            or len(token) > _MAX_TOKEN_BYTES
            or _TOKEN_RE.fullmatch(token) is None
            or b" " in token
        ):
            raise ValueError("Key Vault bearer token is invalid")
        if (
            type(valid_until_monotonic) is not float
            or not math.isfinite(valid_until_monotonic)
            or valid_until_monotonic <= 0
        ):
            raise ValueError("Key Vault bearer token expiry is invalid")
        self.__token = token
        self.valid_until_monotonic = valid_until_monotonic

    def __repr__(self) -> str:
        return "AzureKeyVaultBearerToken(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"

    def _authorization_header(self) -> str:
        return "Bearer " + self.__token.decode("ascii", errors="strict")

    def _appears_in(self, payload: bytes) -> bool:
        return self.__token in payload


@runtime_checkable
class AzureKeyVaultTokenProvider(Protocol):
    """Return one token for the exact Key Vault data-plane scope."""

    def get_token(
        self,
        *,
        scope: str,
        deadline: float,
    ) -> AzureKeyVaultBearerToken: ...


@dataclass(frozen=True, slots=True)
class _HTTPResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


class _HTTPTransport(Protocol):
    def post(
        self,
        *,
        target: str,
        body: bytes,
        token: AzureKeyVaultBearerToken,
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


class _UrllibTransport:
    __slots__ = ("_opener", "_origin", "_timeout_seconds")

    def __init__(
        self,
        *,
        origin: str,
        ssl_context: ssl.SSLContext,
        timeout_seconds: int,
    ) -> None:
        self._origin = origin
        self._timeout_seconds = timeout_seconds
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl_context),
        )

    def post(
        self,
        *,
        target: str,
        body: bytes,
        token: AzureKeyVaultBearerToken,
        deadline: float,
    ) -> _HTTPResponse:
        if (
            not target.startswith("/")
            or target.startswith("//")
            or "\r" in target
            or "\n" in target
        ):
            raise AzureKeyVaultError("transport", "Key Vault target is invalid")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AzureKeyVaultError("deadline", "Key Vault operation deadline expired")
        request = urllib.request.Request(
            self._origin + target,
            data=body,
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Authorization": token._authorization_header(),
                "Content-Type": "application/json",
            },
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
        except (
            TimeoutError,
            urllib.error.URLError,
            http.client.HTTPException,
            OSError,
        ):
            raise AzureKeyVaultError(
                "transport",
                "Key Vault request failed at the pinned origin",
            ) from None
        try:
            length = response.headers.get("Content-Length")
            if length is not None:
                try:
                    declared = int(length)
                except ValueError:
                    raise AzureKeyVaultError(
                        "response",
                        "Key Vault response length is invalid",
                    ) from None
                if declared < 0 or declared > _MAX_RESPONSE_BYTES:
                    raise AzureKeyVaultError(
                        "response",
                        "Key Vault response exceeds its byte limit",
                    )
            payload = response.read(_MAX_RESPONSE_BYTES + 1)
            if len(payload) > _MAX_RESPONSE_BYTES:
                raise AzureKeyVaultError(
                    "response",
                    "Key Vault response exceeds its byte limit",
                )
            raw_headers = tuple(
                (str(name).lower(), str(value))
                for name, value in response.headers.items()
            )
            return _HTTPResponse(
                status=int(response.status),
                headers=raw_headers,
                body=payload,
            )
        finally:
            response.close()


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_b64url(value: str, *, maximum: int, label: str) -> bytes:
    if (
        type(value) is not str
        or not value
        or len(value) > 4 * ((maximum + 2) // 3)
        or "=" in value
        or _B64URL_RE.fullmatch(value) is None
    ):
        raise AzureKeyVaultError("response", f"{label} is not canonical base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))
    except (ValueError, UnicodeEncodeError):
        raise AzureKeyVaultError(
            "response",
            f"{label} is not canonical base64url",
        ) from None
    if len(decoded) > maximum or _b64url(decoded) != value:
        raise AzureKeyVaultError("response", f"{label} is not canonical base64url")
    return decoded


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _unique_header(response: _HTTPResponse, name: str) -> str | None:
    values = tuple(value for key, value in response.headers if key == name)
    if len(values) > 1:
        raise AzureKeyVaultError("response", f"duplicate Key Vault {name} header")
    return values[0] if values else None


def _ssl_context(ca_file: Path | None) -> ssl.SSLContext:
    if ca_file is not None and (
        not isinstance(ca_file, Path) or not ca_file.is_absolute()
    ):
        raise ValueError("Key Vault CA file must be one absolute path")
    context = ssl.create_default_context(
        cafile=None if ca_file is None else os.fspath(ca_file)
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


class AzureKeyVaultCryptoClient:
    """Exact-version Key Vault cryptographic client with no retry."""

    __slots__ = (
        "_key_reference",
        "_key_uri",
        "_operation_timeout_seconds",
        "_token_provider",
        "_transport",
    )

    def __init__(
        self,
        token_provider: AzureKeyVaultTokenProvider,
        *,
        vault_name: str,
        key_name: str,
        key_version: str,
        ca_file: Path | None = None,
        request_timeout_seconds: int = 30,
        operation_timeout_seconds: int = 60,
        _transport: _HTTPTransport | None = None,
    ) -> None:
        if not isinstance(token_provider, AzureKeyVaultTokenProvider):
            raise TypeError("token provider does not implement the Key Vault protocol")
        if type(vault_name) is not str or _VAULT_NAME_RE.fullmatch(vault_name) is None:
            raise ValueError("Azure Key Vault name is invalid")
        if type(key_name) is not str or _KEY_NAME_RE.fullmatch(key_name) is None:
            raise ValueError("Azure Key Vault key name is invalid")
        if (
            type(key_version) is not str
            or _KEY_VERSION_RE.fullmatch(key_version) is None
        ):
            raise ValueError("Azure Key Vault key version must be 32 lowercase hex")
        for label, value in (
            ("request timeout", request_timeout_seconds),
            ("operation timeout", operation_timeout_seconds),
        ):
            if type(value) is not int or not 1 <= value <= _MAX_OPERATION_SECONDS:
                raise ValueError(f"{label} is outside the supported range")
        origin = f"https://{vault_name}.vault.azure.net"
        self._key_uri = f"{origin}/keys/{key_name}/{key_version}"
        self._key_reference = self._key_uri
        self._token_provider = token_provider
        self._operation_timeout_seconds = operation_timeout_seconds
        self._transport = _transport or _UrllibTransport(
            origin=origin,
            ssl_context=_ssl_context(ca_file),
            timeout_seconds=request_timeout_seconds,
        )

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(key_uri_digest={self.key_uri_digest!r}, "
            f"api_version={AZURE_KEY_VAULT_API_VERSION!r})"
        )

    @property
    def key_reference(self) -> str:
        return self._key_reference

    @property
    def key_uri_digest(self) -> str:
        return _sha256(self._key_uri.encode("ascii"))

    @property
    def operation_timeout_seconds(self) -> int:
        return self._operation_timeout_seconds

    def _operation(
        self,
        operation: str,
        *,
        algorithm: str,
        value: bytes,
        deadline: float,
        maximum_result: int,
    ) -> bytes:
        if operation not in {"sign", "wrapkey", "unwrapkey"}:
            raise ValueError("unsupported Key Vault operation")
        if time.monotonic() >= deadline:
            raise AzureKeyVaultError("deadline", "Key Vault operation deadline expired")
        try:
            token = self._token_provider.get_token(
                scope=AZURE_KEY_VAULT_SCOPE,
                deadline=deadline,
            )
        except Exception:
            raise AzureKeyVaultError(
                "authentication",
                "Key Vault token acquisition failed",
            ) from None
        now = time.monotonic()
        if (
            type(token) is not AzureKeyVaultBearerToken
            or token.valid_until_monotonic <= now
            or now >= deadline
        ):
            raise AzureKeyVaultError(
                "authentication",
                "Key Vault token provider returned no currently valid token",
            )
        request_body = canonical_json_bytes(
            {"alg": algorithm, "value": _b64url(value)},
            limits=_RESPONSE_LIMITS,
        )
        target = (
            f"{self._key_uri.removeprefix('https://').split('/', 1)[1]}/"
            f"{operation}?api-version={AZURE_KEY_VAULT_API_VERSION}"
        )
        target = "/" + target
        try:
            response = self._transport.post(
                target=target,
                body=request_body,
                token=token,
                deadline=min(deadline, token.valid_until_monotonic),
            )
        except AzureKeyVaultError:
            raise
        except Exception:
            raise AzureKeyVaultError(
                "transport",
                "Key Vault request failed at the pinned origin",
            ) from None
        if token._appears_in(response.body):
            raise AzureKeyVaultError(
                "response",
                "Key Vault response reflected credential material",
            )
        if response.status != 200:
            raise AzureKeyVaultError(
                "remote",
                "Key Vault rejected the cryptographic operation",
            )
        encoding = _unique_header(response, "content-encoding")
        content_type = _unique_header(response, "content-type")
        if encoding not in {None, "", "identity"}:
            raise AzureKeyVaultError(
                "response",
                "Key Vault response used unsupported content encoding",
            )
        if (
            content_type is None
            or content_type.split(";", 1)[0].strip().lower() != "application/json"
        ):
            raise AzureKeyVaultError(
                "response",
                "Key Vault response is not application/json",
            )
        try:
            document = strict_json_loads(response.body, limits=_RESPONSE_LIMITS)
        except StrictJSONError:
            raise AzureKeyVaultError(
                "response",
                "Key Vault response is not strict bounded JSON",
            ) from None
        if (
            type(document) is not dict
            or set(document) != {"kid", "value"}
            or document.get("kid") != self._key_uri
            or type(document.get("value")) is not str
        ):
            raise AzureKeyVaultError(
                "response",
                "Key Vault response did not bind the pinned key version",
            )
        result = _decode_b64url(
            cast(str, document["value"]),
            maximum=maximum_result,
            label="Key Vault operation result",
        )
        if time.monotonic() >= deadline:
            raise AzureKeyVaultError("deadline", "Key Vault operation deadline expired")
        return result

    def sign_ps256_digest(self, digest: bytes, *, deadline: float) -> bytes:
        if type(digest) is not bytes or len(digest) != 32:
            raise TypeError("PS256 input must be one SHA-256 digest")
        return self._operation(
            "sign",
            algorithm="PS256",
            value=digest,
            deadline=deadline,
            maximum_result=2_048,
        )

    def wrap_key(self, key: bytes, *, deadline: float) -> bytes:
        if type(key) is not bytes or len(key) != _AES_KEY_BYTES:
            raise TypeError("data-encryption key must be exactly 32 bytes")
        wrapped = self._operation(
            "wrapkey",
            algorithm=_WRAP_ALGORITHM,
            value=key,
            deadline=deadline,
            maximum_result=_MAX_WRAPPED_KEY_BYTES,
        )
        if len(wrapped) <= len(key) or wrapped == key:
            raise AzureKeyVaultError(
                "response",
                "Key Vault did not return a wrapped data-encryption key",
            )
        return wrapped

    def unwrap_key(self, wrapped: bytes, *, deadline: float) -> bytes:
        if (
            type(wrapped) is not bytes
            or len(wrapped) <= _AES_KEY_BYTES
            or len(wrapped) > _MAX_WRAPPED_KEY_BYTES
        ):
            raise TypeError("wrapped data-encryption key is invalid")
        key = self._operation(
            "unwrapkey",
            algorithm=_WRAP_ALGORITHM,
            value=wrapped,
            deadline=deadline,
            maximum_result=_AES_KEY_BYTES,
        )
        if len(key) != _AES_KEY_BYTES:
            raise AzureKeyVaultError(
                "response",
                "Key Vault returned the wrong data-encryption key size",
            )
        return key


class AzureKeyVaultPS256Signer:
    """Defender ``PS256AssertionSigner`` backed by one pinned Key Vault key."""

    __slots__ = ("_client", "_public_key")

    def __init__(
        self,
        client: AzureKeyVaultCryptoClient,
        *,
        certificate_der: bytes,
    ) -> None:
        if type(client) is not AzureKeyVaultCryptoClient:
            raise TypeError("client must be an exact AzureKeyVaultCryptoClient")
        if type(certificate_der) is not bytes or not certificate_der:
            raise TypeError("certificate DER must be non-empty immutable bytes")
        try:
            certificate = x509.load_der_x509_certificate(certificate_der)
        except ValueError:
            raise ValueError("certificate DER is not a valid X.509 certificate") from None
        public_key = certificate.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 2048:
            raise ValueError("certificate must contain an RSA key of at least 2048 bits")
        self._client = client
        self._public_key = public_key

    @property
    def key_reference(self) -> str:
        return self._client.key_reference

    def sign_ps256(self, signing_input: bytes, *, deadline: float) -> bytes:
        if type(signing_input) is not bytes or not signing_input:
            raise TypeError("PS256 signing input must be non-empty immutable bytes")
        digest = hashlib.sha256(signing_input).digest()
        signature = self._client.sign_ps256_digest(digest, deadline=deadline)
        try:
            self._public_key.verify(
                signature,
                signing_input,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256(),
            )
        except InvalidSignature:
            raise AzureKeyVaultError(
                "verification",
                "Key Vault signature does not match the registered certificate",
            ) from None
        return signature


class _Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    media_type: str
    schema_version: str
    content_encryption_algorithm: str
    key_uri_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    key_wrap_algorithm: str
    transaction_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    nonce: str
    wrapped_key: str
    ciphertext: str

    @field_validator("nonce", "wrapped_key", "ciphertext")
    @classmethod
    def base64url_is_canonical(cls, value: str) -> str:
        if type(value) is not str or _B64URL_RE.fullmatch(value) is None:
            raise ValueError("envelope binary field is not canonical base64url")
        return value

    @model_validator(mode="after")
    def profile_is_exact(self) -> _Envelope:
        if (
            self.media_type != AZURE_KEY_VAULT_ENVELOPE_MEDIA_TYPE
            or self.schema_version != AZURE_KEY_VAULT_ENVELOPE_SCHEMA_VERSION
            or self.content_encryption_algorithm != _CONTENT_ALGORITHM
            or self.key_wrap_algorithm != _WRAP_ALGORITHM
        ):
            raise ValueError("unsupported Key Vault envelope profile")
        _decode_b64url(self.nonce, maximum=_AES_NONCE_BYTES, label="nonce")
        wrapped = _decode_b64url(
            self.wrapped_key,
            maximum=_MAX_WRAPPED_KEY_BYTES,
            label="wrapped key",
        )
        encrypted = _decode_b64url(
            self.ciphertext,
            maximum=512,
            label="ciphertext",
        )
        if (
            len(_decode_b64url(self.nonce, maximum=_AES_NONCE_BYTES, label="nonce"))
            != _AES_NONCE_BYTES
            or len(wrapped) <= _AES_KEY_BYTES
            or len(encrypted) < 43 + _AES_TAG_BYTES
        ):
            raise ValueError("Key Vault envelope binary sizes are invalid")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"), limits=_DOCUMENT_LIMITS)


class AzureKeyVaultEnvelopeProtector:
    """AES-GCM envelope implementation of ``CodeVerifierProtector``."""

    __slots__ = ("_client", "_random")

    def __init__(
        self,
        client: AzureKeyVaultCryptoClient,
        *,
        _random: Callable[[int], bytes] | None = None,
    ) -> None:
        if type(client) is not AzureKeyVaultCryptoClient:
            raise TypeError("client must be an exact AzureKeyVaultCryptoClient")
        self._client = client
        self._random = _random or os.urandom

    @staticmethod
    def _transaction_digest(value: str) -> str:
        if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
            raise ValueError("OIDC transaction digest is invalid")
        return value

    @staticmethod
    def _aad(transaction_digest: str) -> bytes:
        return _AAD_PREFIX + transaction_digest.encode("ascii")

    def protect(
        self,
        *,
        code_verifier: str,
        transaction_digest: str,
    ) -> ProtectedCodeVerifier:
        if type(code_verifier) is not str or _PKCE_RE.fullmatch(code_verifier) is None:
            raise ValueError("OIDC PKCE verifier is invalid")
        transaction_digest = self._transaction_digest(transaction_digest)
        data_key = self._random(_AES_KEY_BYTES)
        nonce = self._random(_AES_NONCE_BYTES)
        if (
            type(data_key) is not bytes
            or len(data_key) != _AES_KEY_BYTES
            or type(nonce) is not bytes
            or len(nonce) != _AES_NONCE_BYTES
        ):
            raise AzureKeyVaultError(
                "randomness",
                "envelope randomness source returned invalid material",
            )
        deadline = time.monotonic() + self._client.operation_timeout_seconds
        wrapped = self._client.wrap_key(data_key, deadline=deadline)
        encrypted = AESGCM(data_key).encrypt(
            nonce,
            code_verifier.encode("ascii"),
            self._aad(transaction_digest),
        )
        envelope = _Envelope(
            media_type=AZURE_KEY_VAULT_ENVELOPE_MEDIA_TYPE,
            schema_version=AZURE_KEY_VAULT_ENVELOPE_SCHEMA_VERSION,
            content_encryption_algorithm=_CONTENT_ALGORITHM,
            key_uri_digest=self._client.key_uri_digest,
            key_wrap_algorithm=_WRAP_ALGORITHM,
            transaction_digest=transaction_digest,
            nonce=_b64url(nonce),
            wrapped_key=_b64url(wrapped),
            ciphertext=_b64url(encrypted),
        )
        return ProtectedCodeVerifier(
            ciphertext=envelope.canonical_bytes(),
            key_reference=self._client.key_reference,
            algorithm=_PROTECTED_ALGORITHM,
        )

    def unprotect(
        self,
        *,
        protected: ProtectedCodeVerifier,
        transaction_digest: str,
    ) -> str:
        if type(protected) is not ProtectedCodeVerifier:
            raise TypeError("protected verifier must be an exact envelope")
        transaction_digest = self._transaction_digest(transaction_digest)
        if (
            protected.key_reference != self._client.key_reference
            or protected.algorithm != _PROTECTED_ALGORITHM
        ):
            raise AzureKeyVaultError(
                "envelope",
                "protected verifier uses a different key or algorithm",
            )
        try:
            document = strict_json_loads(
                protected.ciphertext,
                limits=_DOCUMENT_LIMITS,
            )
            envelope = _Envelope.model_validate(document)
        except (StrictJSONError, TypeError, ValueError):
            raise AzureKeyVaultError(
                "envelope",
                "protected verifier envelope is invalid",
            ) from None
        if (
            envelope.canonical_bytes() != protected.ciphertext
            or envelope.transaction_digest != transaction_digest
            or envelope.key_uri_digest != self._client.key_uri_digest
        ):
            raise AzureKeyVaultError(
                "envelope",
                "protected verifier envelope binding is invalid",
            )
        nonce = _decode_b64url(
            envelope.nonce,
            maximum=_AES_NONCE_BYTES,
            label="nonce",
        )
        wrapped = _decode_b64url(
            envelope.wrapped_key,
            maximum=_MAX_WRAPPED_KEY_BYTES,
            label="wrapped key",
        )
        encrypted = _decode_b64url(
            envelope.ciphertext,
            maximum=512,
            label="ciphertext",
        )
        deadline = time.monotonic() + self._client.operation_timeout_seconds
        data_key = self._client.unwrap_key(wrapped, deadline=deadline)
        try:
            plaintext = AESGCM(data_key).decrypt(
                nonce,
                encrypted,
                self._aad(transaction_digest),
            )
            code_verifier = plaintext.decode("ascii", errors="strict")
        except (InvalidTag, UnicodeDecodeError):
            raise AzureKeyVaultError(
                "envelope",
                "protected verifier authentication failed",
            ) from None
        if _PKCE_RE.fullmatch(code_verifier) is None:
            raise AzureKeyVaultError(
                "envelope",
                "protected verifier plaintext is invalid",
            )
        return code_verifier


__all__ = [
    "AZURE_KEY_VAULT_API_VERSION",
    "AZURE_KEY_VAULT_ENVELOPE_MEDIA_TYPE",
    "AZURE_KEY_VAULT_ENVELOPE_SCHEMA_VERSION",
    "AZURE_KEY_VAULT_SCOPE",
    "AzureKeyVaultBearerToken",
    "AzureKeyVaultCryptoClient",
    "AzureKeyVaultEnvelopeProtector",
    "AzureKeyVaultError",
    "AzureKeyVaultPS256Signer",
    "AzureKeyVaultTokenProvider",
]
