"""Version-pinned Azure Key Vault secret retrieval.

The control-plane configuration stores references, never secret values.  This
module is the narrow data-plane boundary that resolves one immutable
``azure-keyvault://`` reference under an injected workload identity.

There is deliberately no ambient credential discovery, redirect, proxy,
compression, retry, or "latest" version lookup.  A successful read is bound to
the exact vault, secret name, and 32-hex version present in the approved
configuration.  The returned value has redacted representations and can only
be handed to a caller-supplied decoder; Python cannot guarantee zeroization of
immutable bytes, so process isolation remains a deployment responsibility.
"""

from __future__ import annotations

import hashlib
import http.client
import math
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Protocol, TypeVar, cast

from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    strict_json_loads,
)
from assurance_lab.key_management.azure_key_vault import (
    AZURE_KEY_VAULT_API_VERSION,
    AZURE_KEY_VAULT_SCOPE,
    AzureKeyVaultBearerToken,
    AzureKeyVaultTokenProvider,
)

_VAULT_NAME_RE: Final = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,22}[a-z0-9])$")
_SECRET_NAME_RE: Final = re.compile(r"^[A-Za-z0-9-]{1,127}$")
_SECRET_VERSION_RE: Final = re.compile(r"^[a-f0-9]{32}$")
_CONTENT_TYPE_RE: Final = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+(?:[+]json)?$")

_MAX_RESPONSE_BYTES: Final = 256 * 1024
_MAX_SECRET_BYTES: Final = 128 * 1024
_MAX_TIMEOUT_SECONDS: Final = 120
_RESPONSE_LIMITS = JSONLimits(
    max_bytes=_MAX_RESPONSE_BYTES,
    max_line_bytes=_MAX_RESPONSE_BYTES,
    max_depth=8,
    max_collection_items=256,
    max_string_length=_MAX_SECRET_BYTES,
)

_T = TypeVar("_T")


class AzureKeyVaultSecretError(RuntimeError):
    """Stable, credential-free failure at the Key Vault secret boundary."""

    __slots__ = ("stage",)

    def __init__(self, stage: str, detail: str) -> None:
        if (
            type(stage) is not str
            or not stage
            or len(stage) > 64
            or re.fullmatch(r"[a-z][a-z0-9-]*", stage) is None
        ):
            raise ValueError("secret failure stage is invalid")
        if type(detail) is not str or not detail or len(detail) > 256:
            raise ValueError("secret failure detail is invalid")
        self.stage = stage
        super().__init__(detail)


@dataclass(frozen=True, slots=True)
class AzureKeyVaultSecretReference:
    """One canonical, immutable Key Vault secret identity."""

    vault_name: str
    secret_name: str
    secret_version: str

    def __post_init__(self) -> None:
        if type(self.vault_name) is not str or _VAULT_NAME_RE.fullmatch(self.vault_name) is None:
            raise ValueError("Azure Key Vault name is invalid")
        if type(self.secret_name) is not str or _SECRET_NAME_RE.fullmatch(self.secret_name) is None:
            raise ValueError("Azure Key Vault secret name is invalid")
        if (
            type(self.secret_version) is not str
            or _SECRET_VERSION_RE.fullmatch(self.secret_version) is None
        ):
            raise ValueError("Azure Key Vault secret version must be 32 lowercase hex")

    @property
    def origin(self) -> str:
        return f"https://{self.vault_name}.vault.azure.net"

    @property
    def secret_uri(self) -> str:
        return f"{self.origin}/secrets/{self.secret_name}/{self.secret_version}"

    @property
    def configuration_reference(self) -> str:
        return (
            f"azure-keyvault://{self.vault_name}/secrets/{self.secret_name}/{self.secret_version}"
        )

    @property
    def reference_digest(self) -> str:
        return f"sha256:{hashlib.sha256(self.secret_uri.encode('ascii')).hexdigest()}"

    @classmethod
    def parse(cls, value: str) -> AzureKeyVaultSecretReference:
        if type(value) is not str or not value or len(value) > 2_048:
            raise ValueError("Azure Key Vault secret reference is absent or too long")
        parsed = urllib.parse.urlsplit(value)
        if (
            parsed.scheme != "azure-keyvault"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.query
            or parsed.fragment
            or not parsed.hostname
            or parsed.hostname != parsed.netloc
            or "\\" in value
            or any(character.isspace() for character in value)
        ):
            raise ValueError("Azure Key Vault secret reference is not canonical")
        segments = parsed.path.split("/")
        if len(segments) != 4 or segments[0] != "" or segments[1] != "secrets":
            raise ValueError("Azure Key Vault secret reference path is invalid")
        reference = cls(
            vault_name=parsed.hostname,
            secret_name=segments[2],
            secret_version=segments[3],
        )
        if reference.configuration_reference != value:
            raise ValueError("Azure Key Vault secret reference is not canonical")
        return reference


class AzureKeyVaultSecretValue:
    """Opaque secret bytes plus non-secret, version-pinned metadata."""

    __slots__ = (
        "__value",
        "_content_type",
        "_reference",
        "_retrieved_at",
    )

    def __init__(
        self,
        value: bytes,
        *,
        reference: AzureKeyVaultSecretReference,
        content_type: str | None,
        retrieved_at: datetime,
    ) -> None:
        if type(value) is not bytes or not value or len(value) > _MAX_SECRET_BYTES:
            raise ValueError("Key Vault secret value is absent or exceeds its limit")
        if type(reference) is not AzureKeyVaultSecretReference:
            raise TypeError("secret reference must be exact")
        if content_type is not None and (
            type(content_type) is not str
            or len(content_type) > 128
            or _CONTENT_TYPE_RE.fullmatch(content_type) is None
        ):
            raise ValueError("Key Vault secret content type is invalid")
        if (
            type(retrieved_at) is not datetime
            or retrieved_at.tzinfo is None
            or retrieved_at.microsecond != 0
        ):
            raise ValueError("secret retrieval time must use whole UTC seconds")
        self.__value = value
        self._reference = reference
        self._content_type = content_type
        self._retrieved_at = retrieved_at.astimezone(UTC)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(reference_digest={self.reference_digest!r}, value=<redacted>)"
        )

    def __str__(self) -> str:
        return "<redacted>"

    @property
    def reference_digest(self) -> str:
        return self._reference.reference_digest

    @property
    def content_type(self) -> str | None:
        return self._content_type

    @property
    def retrieved_at(self) -> datetime:
        return self._retrieved_at

    def consume(
        self,
        decoder: Callable[[bytes], _T],
        *,
        expected_content_type: str | None = None,
    ) -> _T:
        """Hand the value to a narrow decoder without exposing it in repr.

        The object intentionally does not offer a plaintext property.  This is
        an API guardrail, not a memory-zeroization claim.
        """

        if not callable(decoder):
            raise TypeError("secret decoder must be callable")
        if expected_content_type is not None and (
            type(expected_content_type) is not str
            or _CONTENT_TYPE_RE.fullmatch(expected_content_type) is None
        ):
            raise ValueError("expected secret content type is invalid")
        if expected_content_type is not None and self._content_type != expected_content_type:
            raise AzureKeyVaultSecretError(
                "content-type",
                "Key Vault secret content type does not match the decoder profile",
            )
        try:
            return decoder(self.__value)
        except AzureKeyVaultSecretError:
            raise
        except Exception:
            raise AzureKeyVaultSecretError(
                "decode",
                "Key Vault secret could not be decoded by the selected profile",
            ) from None

    def _appears_in(self, payload: bytes) -> bool:
        return self.__value in payload


@dataclass(frozen=True, slots=True)
class _SecretHTTPResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


class _SecretHTTPTransport(Protocol):
    def get(
        self,
        *,
        target: str,
        token: AzureKeyVaultBearerToken,
        deadline: float,
    ) -> _SecretHTTPResponse: ...


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


class _UrllibSecretTransport:
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

    def get(
        self,
        *,
        target: str,
        token: AzureKeyVaultBearerToken,
        deadline: float,
    ) -> _SecretHTTPResponse:
        if (
            not target.startswith("/")
            or target.startswith("//")
            or "\r" in target
            or "\n" in target
        ):
            raise AzureKeyVaultSecretError("transport", "Key Vault target is invalid")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AzureKeyVaultSecretError(
                "deadline",
                "Key Vault secret read deadline expired",
            )
        request = urllib.request.Request(
            self._origin + target,
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Authorization": token._authorization_header(),
            },
            method="GET",
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
            raise AzureKeyVaultSecretError(
                "transport",
                "Key Vault secret request failed at the pinned origin",
            ) from None
        try:
            lengths = response.headers.get_all("Content-Length", [])
            transfers = response.headers.get_all("Transfer-Encoding", [])
            if len(lengths) > 1 or len(transfers) > 1 or (lengths and transfers):
                raise AzureKeyVaultSecretError(
                    "response",
                    "Key Vault response has ambiguous message framing",
                )
            if transfers and transfers[0].strip().lower() != "chunked":
                raise AzureKeyVaultSecretError(
                    "response",
                    "Key Vault response transfer encoding is unsupported",
                )
            if lengths:
                try:
                    declared = int(lengths[0])
                except (TypeError, ValueError):
                    raise AzureKeyVaultSecretError(
                        "response",
                        "Key Vault response length is invalid",
                    ) from None
                if declared < 0 or declared > _MAX_RESPONSE_BYTES:
                    raise AzureKeyVaultSecretError(
                        "response",
                        "Key Vault response exceeds its byte limit",
                    )
            content = bytearray()
            reader = getattr(response, "read1", response.read)
            while True:
                if time.monotonic() >= deadline:
                    raise AzureKeyVaultSecretError(
                        "deadline",
                        "Key Vault secret response deadline expired",
                    )
                chunk = reader(min(64 * 1024, _MAX_RESPONSE_BYTES + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > _MAX_RESPONSE_BYTES:
                    raise AzureKeyVaultSecretError(
                        "response",
                        "Key Vault response exceeds its byte limit",
                    )
            selected: list[tuple[str, str]] = []
            for name in ("content-encoding", "content-type", "request-id"):
                values = response.headers.get_all(name, [])
                if len(values) > 1:
                    raise AzureKeyVaultSecretError(
                        "response",
                        "Key Vault response contains duplicate security headers",
                    )
                if values:
                    selected.append((name, str(values[0])))
            return _SecretHTTPResponse(
                status=int(response.status),
                headers=tuple(selected),
                body=bytes(content),
            )
        except (OSError, http.client.HTTPException):
            raise AzureKeyVaultSecretError(
                "response",
                "Key Vault secret response could not be read completely",
            ) from None
        finally:
            response.close()


def _ssl_context(ca_file: Path | None) -> ssl.SSLContext:
    if ca_file is not None and (not isinstance(ca_file, Path) or not ca_file.is_absolute()):
        raise ValueError("Key Vault CA file must be one absolute path")
    context = ssl.create_default_context(cafile=None if ca_file is None else os.fspath(ca_file))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def _header(response: _SecretHTTPResponse, name: str) -> str | None:
    values = tuple(value for key, value in response.headers if key == name)
    if len(values) > 1:
        raise AzureKeyVaultSecretError(
            "response",
            "Key Vault response contains duplicate security headers",
        )
    return values[0] if values else None


class AzureKeyVaultSecretClient:
    """Read exact-version secrets through one pinned public-cloud vault."""

    __slots__ = (
        "_monotonic",
        "_now",
        "_operation_timeout_seconds",
        "_reference",
        "_token_provider",
        "_transport",
    )

    def __init__(
        self,
        token_provider: AzureKeyVaultTokenProvider,
        reference: AzureKeyVaultSecretReference,
        *,
        ca_file: Path | None = None,
        request_timeout_seconds: int = 30,
        operation_timeout_seconds: int = 60,
        _transport: _SecretHTTPTransport | None = None,
        _monotonic: Callable[[], float] = time.monotonic,
        _now: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(token_provider, AzureKeyVaultTokenProvider):
            raise TypeError("token provider does not implement the Key Vault protocol")
        if type(reference) is not AzureKeyVaultSecretReference:
            raise TypeError("secret reference must be exact")
        for label, value in (
            ("request timeout", request_timeout_seconds),
            ("operation timeout", operation_timeout_seconds),
        ):
            if type(value) is not int or not 1 <= value <= _MAX_TIMEOUT_SECONDS:
                raise ValueError(f"{label} is outside the supported range")
        if not callable(_monotonic) or (_now is not None and not callable(_now)):
            raise TypeError("secret clocks must be callable")
        self._reference = reference
        self._token_provider = token_provider
        self._operation_timeout_seconds = operation_timeout_seconds
        self._transport = _transport or _UrllibSecretTransport(
            origin=reference.origin,
            ssl_context=_ssl_context(ca_file),
            timeout_seconds=request_timeout_seconds,
        )
        self._monotonic = _monotonic
        self._now = _now or (lambda: datetime.now(UTC).replace(microsecond=0))

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(reference_digest="
            f"{self._reference.reference_digest!r}, "
            f"api_version={AZURE_KEY_VAULT_API_VERSION!r})"
        )

    @property
    def reference_digest(self) -> str:
        return self._reference.reference_digest

    def _monotonic_time(self) -> float:
        try:
            value = self._monotonic()
        except Exception:
            raise AzureKeyVaultSecretError(
                "clock",
                "secret monotonic clock failed",
            ) from None
        if (
            type(value) not in {float, int}
            or isinstance(value, bool)
            or not math.isfinite(float(value))
            or float(value) < 0
        ):
            raise AzureKeyVaultSecretError(
                "clock",
                "secret monotonic clock returned an invalid value",
            )
        return float(value)

    def _wall_time(self) -> datetime:
        try:
            value = self._now()
        except Exception:
            raise AzureKeyVaultSecretError(
                "clock",
                "secret wall clock failed",
            ) from None
        if type(value) is not datetime or value.tzinfo is None:
            raise AzureKeyVaultSecretError(
                "clock",
                "secret wall clock returned an invalid instant",
            )
        try:
            return value.astimezone(UTC)
        except (OverflowError, ValueError):
            raise AzureKeyVaultSecretError(
                "clock",
                "secret wall clock returned an invalid instant",
            ) from None

    def get(self) -> AzureKeyVaultSecretValue:
        deadline = self._monotonic_time() + self._operation_timeout_seconds
        try:
            token = self._token_provider.get_token(
                scope=AZURE_KEY_VAULT_SCOPE,
                deadline=deadline,
            )
        except Exception:
            raise AzureKeyVaultSecretError(
                "authentication",
                "Key Vault token acquisition failed",
            ) from None
        now_monotonic = self._monotonic_time()
        if (
            type(token) is not AzureKeyVaultBearerToken
            or token.valid_until_monotonic <= now_monotonic
            or now_monotonic >= deadline
        ):
            raise AzureKeyVaultSecretError(
                "authentication",
                "Key Vault token provider returned no currently valid token",
            )
        target = (
            f"/secrets/{self._reference.secret_name}/"
            f"{self._reference.secret_version}"
            f"?api-version={AZURE_KEY_VAULT_API_VERSION}"
        )
        try:
            response = self._transport.get(
                target=target,
                token=token,
                deadline=min(deadline, token.valid_until_monotonic),
            )
        except AzureKeyVaultSecretError:
            raise
        except Exception:
            raise AzureKeyVaultSecretError(
                "transport",
                "Key Vault secret request failed at the pinned origin",
            ) from None
        reflected = (
            response.body
            + b"\x00"
            + b"\x00".join(
                f"{name}:{value}".encode("utf-8", errors="replace")
                for name, value in response.headers
            )
        )
        if token._appears_in(reflected):
            raise AzureKeyVaultSecretError(
                "response",
                "Key Vault response reflected credential material",
            )
        encoding = _header(response, "content-encoding")
        content_type = _header(response, "content-type")
        if encoding not in {None, "", "identity"}:
            raise AzureKeyVaultSecretError(
                "response",
                "Key Vault response used unsupported content encoding",
            )
        if (
            content_type is None
            or content_type.split(";", 1)[0].strip().lower() != "application/json"
        ):
            raise AzureKeyVaultSecretError(
                "response",
                "Key Vault response is not application/json",
            )
        if response.status != 200:
            raise AzureKeyVaultSecretError(
                "remote",
                "Key Vault rejected the exact-version secret read",
            )
        try:
            document = strict_json_loads(response.body, limits=_RESPONSE_LIMITS)
        except StrictJSONError:
            raise AzureKeyVaultSecretError(
                "response",
                "Key Vault response is not strict bounded JSON",
            ) from None
        if not isinstance(document, dict):
            raise AzureKeyVaultSecretError(
                "response",
                "Key Vault secret response is not an object",
            )
        allowed = {
            "attributes",
            "contentType",
            "id",
            "kid",
            "managed",
            "previousVersion",
            "tags",
            "value",
        }
        if (
            not {"attributes", "id", "value"} <= set(document)
            or not set(document) <= allowed
            or document.get("id") != self._reference.secret_uri
            or type(document.get("value")) is not str
        ):
            raise AzureKeyVaultSecretError(
                "response",
                "Key Vault response did not bind the pinned secret version",
            )
        attributes = document["attributes"]
        if not isinstance(attributes, dict) or attributes.get("enabled") is not True:
            raise AzureKeyVaultSecretError(
                "policy",
                "Key Vault secret is not explicitly enabled",
            )
        wall_now = self._wall_time()
        epoch_now = int(wall_now.timestamp())
        for name in ("nbf", "exp"):
            value = attributes.get(name)
            if value is not None and (type(value) is not int or value < 0):
                raise AzureKeyVaultSecretError(
                    "response",
                    "Key Vault secret validity attributes are invalid",
                )
        not_before = attributes.get("nbf")
        expires = attributes.get("exp")
        if type(not_before) is int and epoch_now < not_before:
            raise AzureKeyVaultSecretError(
                "policy",
                "Key Vault secret is not yet valid",
            )
        if type(expires) is int and epoch_now >= expires:
            raise AzureKeyVaultSecretError(
                "policy",
                "Key Vault secret is expired",
            )
        raw_value = cast(str, document["value"])
        try:
            value_bytes = raw_value.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise AzureKeyVaultSecretError(
                "response",
                "Key Vault secret value is not valid UTF-8",
            ) from None
        if not value_bytes or len(value_bytes) > _MAX_SECRET_BYTES:
            raise AzureKeyVaultSecretError(
                "response",
                "Key Vault secret value is absent or exceeds its limit",
            )
        secret_content_type = document.get("contentType")
        if secret_content_type is not None and type(secret_content_type) is not str:
            raise AzureKeyVaultSecretError(
                "response",
                "Key Vault secret content type is invalid",
            )
        retrieved_at = wall_now.replace(microsecond=0)
        if self._monotonic_time() >= deadline:
            raise AzureKeyVaultSecretError(
                "deadline",
                "Key Vault secret read deadline expired",
            )
        try:
            return AzureKeyVaultSecretValue(
                value_bytes,
                reference=self._reference,
                content_type=secret_content_type,
                retrieved_at=retrieved_at,
            )
        except (TypeError, ValueError):
            raise AzureKeyVaultSecretError(
                "response",
                "Key Vault secret response is outside the supported profile",
            ) from None


__all__ = [
    "AzureKeyVaultSecretClient",
    "AzureKeyVaultSecretError",
    "AzureKeyVaultSecretReference",
    "AzureKeyVaultSecretValue",
]
