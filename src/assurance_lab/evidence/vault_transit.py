"""A fail-closed HashiCorp Vault Transit Ed25519 receipt signer.

The private key never enters this process.  Construction reads one Transit key,
pins its exact current version and Ed25519 public key, and every later signing
request names that version explicitly.  A returned ``vault:vN:...`` signature
must name the same version and verify locally before it can become a
``DetachedSignature``.

The adapter deliberately does not authenticate to Vault itself, follow
redirects, use ambient proxies, retry signing requests, discover alternate
Vault origins, or use Vault's remote verification endpoint.  Token acquisition
is delegated to a bounded opaque provider and verification remains available
from the pinned public key when Vault is unavailable.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import http.client
import ipaddress
import math
import os
import re
import ssl
import stat
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from assurance_lab.evidence.admission import DetachedSignature
from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)

MAX_VAULT_TOKEN_BYTES: Final = 32 * 1024
MAX_VAULT_RESPONSE_BYTES: Final = 256 * 1024
MAX_SIGNING_MESSAGE_BYTES: Final = 4 * 1024 * 1024
MAX_CA_BUNDLE_BYTES: Final = 8 * 1024 * 1024
MAX_PUBLIC_KEY_PEM_BYTES: Final = 64 * 1024
MIN_TIMEOUT_SECONDS: Final = 1
MAX_REQUEST_TIMEOUT_SECONDS: Final = 120
MAX_OPERATION_TIMEOUT_SECONDS: Final = 300

_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,255}$")
_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_TOKEN_RE = re.compile(rb"^[A-Za-z0-9!#$%&'*+\-.^_`|~=/]{8,32768}$")
_VAULT_SIGNATURE_RE = re.compile(
    r"^vault:v([1-9][0-9]{0,9}):([A-Za-z0-9+/]{86}==)$"
)
_PUBLIC_KEY_PEM_HEADER = b"-----BEGIN PUBLIC KEY-----\n"
_PUBLIC_KEY_PEM_FOOTER = b"-----END PUBLIC KEY-----\n"
_JSON_LIMITS = JSONLimits(
    max_bytes=MAX_VAULT_RESPONSE_BYTES,
    max_line_bytes=MAX_VAULT_RESPONSE_BYTES,
    max_depth=8,
    max_collection_items=512,
    max_string_length=MAX_PUBLIC_KEY_PEM_BYTES,
)
_REQUEST_JSON_LIMITS = JSONLimits(
    max_bytes=6 * 1024 * 1024,
    max_line_bytes=6 * 1024 * 1024,
    max_depth=3,
    max_collection_items=4,
    max_string_length=6 * 1024 * 1024,
)
_BASE_REQUEST_HEADERS = (
    ("accept", "application/json"),
    ("content-type", "application/json"),
    ("x-vault-request", "true"),
)
_RESPONSE_HEADER_NAMES = frozenset({"content-encoding", "content-type"})
_ABSENT_NAMESPACE_DIGEST_INPUT = b"control-assurance:vault-namespace:v1:absent"


class VaultTransitError(RuntimeError):
    """A stable, credential-free failure at the Vault Transit boundary."""

    __slots__ = ("stage",)

    def __init__(self, stage: str, detail: str) -> None:
        super().__init__(detail)
        self.stage = stage


class VaultToken:
    """Opaque, explicitly expiring Vault token bytes.

    ``valid_until_monotonic`` is a local safety horizon supplied by the token
    provider.  It is not a substitute for Vault lease validation.
    """

    __slots__ = ("__valid_until_monotonic", "__value")

    def __init__(self, value: bytes, *, valid_until_monotonic: float) -> None:
        if type(value) is not bytes or _TOKEN_RE.fullmatch(value) is None:
            raise ValueError("Vault token must be bounded opaque HTTP header bytes")
        if (
            type(valid_until_monotonic) is not float
            or not math.isfinite(valid_until_monotonic)
            or valid_until_monotonic <= 0
        ):
            raise ValueError("Vault token validity horizon must be finite monotonic time")
        self.__value = value
        self.__valid_until_monotonic = valid_until_monotonic

    def __repr__(self) -> str:
        return "VaultToken(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"

    @property
    def valid_until_monotonic(self) -> float:
        return self.__valid_until_monotonic

    def _header_value(self) -> str:
        return self.__value.decode("ascii", errors="strict")

    def _appears_in(self, value: bytes) -> bool:
        escaped_slash = self.__value.replace(b"/", b"\\/")
        quoted = urllib.parse.quote_from_bytes(self.__value, safe="").encode("ascii")
        quoted_lower_escapes = re.sub(
            rb"%([0-9A-F]{2})",
            lambda match: b"%" + match.group(1).lower(),
            quoted,
        )
        return any(
            candidate in value
            for candidate in (
                self.__value,
                escaped_slash,
                quoted,
                quoted_lower_escapes,
            )
        )


@runtime_checkable
class VaultTokenProvider(Protocol):
    """Thread-safe acquisition of a short-lived token before ``deadline``."""

    def get_token(self, *, deadline: float) -> VaultToken:
        """Return a token authorized only for this Transit read/sign role."""


@dataclass(frozen=True, slots=True)
class _HTTPResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


class _HTTPTransport(Protocol):
    def request(
        self,
        *,
        method: str,
        target: str,
        body: bytes,
        headers: tuple[tuple[str, str], ...],
        token: VaultToken,
        deadline: float,
    ) -> _HTTPResponse: ...


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


class _UrllibTransport:
    """One-origin urllib transport with no redirect or proxy inheritance."""

    __slots__ = ("_endpoint", "_request_timeout_seconds", "_ssl_context")

    def __init__(
        self,
        *,
        endpoint: str,
        request_timeout_seconds: int,
        ssl_context: ssl.SSLContext | None,
    ) -> None:
        self._endpoint = endpoint
        self._request_timeout_seconds = request_timeout_seconds
        self._ssl_context = ssl_context

    def _opener(self) -> urllib.request.OpenerDirector:
        handlers: list[Any] = [urllib.request.ProxyHandler({}), _NoRedirect()]
        if self._ssl_context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=self._ssl_context))
        return urllib.request.build_opener(*handlers)

    def request(
        self,
        *,
        method: str,
        target: str,
        body: bytes,
        headers: tuple[tuple[str, str], ...],
        token: VaultToken,
        deadline: float,
    ) -> _HTTPResponse:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise VaultTransitError("deadline", "Vault operation deadline expired")
        request_headers = {name: value for name, value in headers}
        request_headers["x-vault-token"] = token._header_value()
        request = urllib.request.Request(
            f"{self._endpoint}{target}",
            data=body if method == "POST" else None,
            headers=request_headers,
            method=method,
        )

        response: Any = None
        transport_failed = False
        try:
            response = self._opener().open(
                request,
                timeout=min(float(self._request_timeout_seconds), remaining),
            )
        except urllib.error.HTTPError as exc:
            response = exc
        except (TimeoutError, urllib.error.URLError, OSError, http.client.HTTPException):
            transport_failed = True
        if transport_failed:
            raise VaultTransitError(
                "transport",
                "Vault request could not be completed",
            )
        if response is None:
            raise VaultTransitError(
                "transport",
                "Vault request returned no response",
            )

        read_failed = False
        payload = b""
        selected_headers: tuple[tuple[str, str], ...] = ()
        try:
            content = bytearray()
            reader = getattr(response, "read1", response.read)
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError
                chunk = reader(
                    min(
                        64 * 1024,
                        MAX_VAULT_RESPONSE_BYTES + 1 - len(content),
                    )
                )
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > MAX_VAULT_RESPONSE_BYTES:
                    raise ValueError
            payload = bytes(content)

            reflected_parts = [payload]
            selected: list[tuple[str, str]] = []
            for raw_name, raw_value in response.headers.items():
                name = str(raw_name).lower()
                value = str(raw_value)
                reflected_parts.append(
                    f"{name}:{value}".encode("utf-8", errors="replace")
                )
                if name in _RESPONSE_HEADER_NAMES:
                    selected.append((name, value))
            if token._appears_in(b"\x00".join(reflected_parts)):
                raise VaultTransitError(
                    "transport",
                    "Vault response reflected credential material",
                )
            selected_headers = tuple(sorted(selected))
        except VaultTransitError:
            raise
        except (TimeoutError, ValueError, OSError, http.client.HTTPException):
            read_failed = True
        finally:
            response.close()
        if read_failed:
            raise VaultTransitError(
                "transport",
                "Vault response could not be read within its byte and time limits",
            )
        return _HTTPResponse(
            status=int(response.status),
            headers=selected_headers,
            body=payload,
        )


def _canonical_endpoint(
    endpoint: str,
    *,
    allow_insecure_loopback: bool,
) -> tuple[str, bool]:
    if type(endpoint) is not str or not endpoint or len(endpoint) > 2_048:
        raise ValueError("Vault endpoint must be a bounded canonical origin")
    try:
        endpoint.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        raise ValueError("Vault endpoint must be an ASCII origin") from None
    parsed = urllib.parse.urlsplit(endpoint)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path
    ):
        raise ValueError("Vault endpoint must be an origin without credentials or path")
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("Vault endpoint port is invalid") from None
    host = parsed.hostname
    if host != host.lower():
        raise ValueError("Vault endpoint hostname must be lowercase")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
        labels = host.split(".")
        if (
            not labels
            or any(
                not label
                or len(label) > 63
                or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
                is None
                for label in labels
            )
        ):
            raise ValueError("Vault endpoint hostname is not canonical") from None
    rendered_host = f"[{host}]" if address is not None and address.version == 6 else host
    if parsed.scheme == "http":
        if (
            not allow_insecure_loopback
            or address is None
            or not address.is_loopback
        ):
            raise ValueError("plain HTTP requires explicit literal-loopback lab mode")
        authority = rendered_host if port in {None, 80} else f"{rendered_host}:{port}"
        canonical = f"http://{authority}"
        tls = False
    else:
        authority = rendered_host if port in {None, 443} else f"{rendered_host}:{port}"
        canonical = f"https://{authority}"
        tls = True
    if endpoint != canonical:
        raise ValueError("Vault endpoint must use its exact canonical origin form")
    return canonical, tls


def vault_endpoint_origin_digest(
    endpoint: str,
    *,
    allow_insecure_loopback: bool = False,
) -> str:
    """Return the exact configured Vault origin's SHA-256 anchor."""

    canonical, _ = _canonical_endpoint(
        endpoint,
        allow_insecure_loopback=allow_insecure_loopback,
    )
    return f"sha256:{hashlib.sha256(canonical.encode('ascii')).hexdigest()}"


def _locator_digest(domain: bytes, value: str) -> str:
    encoded = value.encode("utf-8")
    framed = domain + b"\x00" + len(encoded).to_bytes(4, "big") + encoded
    return f"sha256:{hashlib.sha256(framed).hexdigest()}"


def _validate_mount_path(mount_path: str) -> str:
    if type(mount_path) is not str or not mount_path or len(mount_path) > 512:
        raise ValueError("Vault Transit mount path is absent or too long")
    segments = mount_path.split("/")
    if len(segments) > 8 or any(
        _PATH_SEGMENT_RE.fullmatch(segment) is None or segment.endswith(".")
        for segment in segments
    ):
        raise ValueError("Vault Transit mount path is not canonical")
    return mount_path


def _validate_key_name(key_name: str) -> str:
    if (
        type(key_name) is not str
        or _PATH_SEGMENT_RE.fullmatch(key_name) is None
        or key_name.endswith(".")
    ):
        raise ValueError("Vault Transit key name must be one canonical path segment")
    return key_name


def _request_headers(namespace: str | None) -> tuple[tuple[str, str], ...]:
    if namespace is None:
        return _BASE_REQUEST_HEADERS
    canonical_namespace = _validate_mount_path(namespace)
    return tuple(
        sorted(
            (
                *_BASE_REQUEST_HEADERS,
                ("x-vault-namespace", canonical_namespace),
            )
        )
    )


def _ssl_context(ca_file: Path | None) -> ssl.SSLContext:
    if ca_file is None:
        context = ssl.create_default_context()
    else:
        if not isinstance(ca_file, Path):
            raise TypeError("CA file must be a pathlib.Path")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = -1
        content = bytearray()
        try:
            descriptor = os.open(ca_file, flags)
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size > MAX_CA_BUNDLE_BYTES
            ):
                raise ValueError(
                    "CA file must be a bounded single-link regular file"
                )
            while len(content) <= MAX_CA_BUNDLE_BYTES:
                chunk = os.read(
                    descriptor,
                    min(
                        64 * 1024,
                        MAX_CA_BUNDLE_BYTES + 1 - len(content),
                    ),
                )
                if not chunk:
                    break
                content.extend(chunk)
            after = os.fstat(descriptor)
            before_identity = (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_nlink,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            after_identity = (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_nlink,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            if (
                len(content) > MAX_CA_BUNDLE_BYTES
                or len(content) != after.st_size
                or before_identity != after_identity
            ):
                raise ValueError("CA file changed while it was read")
        except OSError:
            raise ValueError("CA file cannot be read safely") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        try:
            pem = bytes(content).decode("ascii", errors="strict")
            if "-----BEGIN CERTIFICATE-----" not in pem:
                raise ValueError("CA file is not a PEM certificate bundle")
            context = ssl.create_default_context()
            context.load_verify_locations(cadata=pem)
        except (UnicodeDecodeError, OSError, ssl.SSLError):
            raise ValueError(
                "CA file could not establish a TLS trust context"
            ) from None
    if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
        raise ValueError("TLS context must verify the Vault certificate hostname")
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _timeout(value: int, *, label: str, maximum: int) -> int:
    if type(value) is not int or value < MIN_TIMEOUT_SECONDS or value > maximum:
        raise ValueError(f"{label} is outside the supported range")
    return value


def _canonical_base64_decode(
    value: str,
    *,
    expected_length: int,
) -> bytes:
    try:
        encoded = value.encode("ascii", errors="strict")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise ValueError("value is not canonical RFC 4648 base64") from None
    if len(decoded) != expected_length or base64.b64encode(decoded) != encoded:
        raise ValueError("value is not canonical RFC 4648 base64")
    return decoded


def _parse_public_key(public_key_value: object) -> tuple[Ed25519PublicKey, bytes]:
    if type(public_key_value) is not str:
        raise ValueError("Vault key response has no public key")
    try:
        encoded = public_key_value.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        raise ValueError("Vault public key is not ASCII") from None
    loaded: object
    if encoded.startswith(b"-----"):
        if (
            not encoded.startswith(_PUBLIC_KEY_PEM_HEADER)
            or not encoded.endswith(_PUBLIC_KEY_PEM_FOOTER)
            or len(encoded) > MAX_PUBLIC_KEY_PEM_BYTES
            or encoded.count(b"-----BEGIN PUBLIC KEY-----") != 1
            or encoded.count(b"-----END PUBLIC KEY-----") != 1
        ):
            raise ValueError("Vault public key is not one exact SPKI PEM block")
        try:
            loaded = serialization.load_pem_public_key(encoded)
        except (TypeError, ValueError):
            raise ValueError("Vault public key PEM could not be decoded") from None
        if (
            not isinstance(loaded, Ed25519PublicKey)
            or loaded.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            != encoded
        ):
            raise ValueError("Vault public key PEM is not canonical Ed25519 SPKI")
    else:
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError(
                "Vault Ed25519 public key is not canonical base64"
            ) from None
        if base64.b64encode(decoded) != encoded:
            raise ValueError("Vault Ed25519 public key is not canonical base64")
        try:
            if len(decoded) == 32:
                loaded = Ed25519PublicKey.from_public_bytes(decoded)
            else:
                loaded = serialization.load_der_public_key(decoded)
        except (TypeError, ValueError):
            raise ValueError("Vault public key bytes could not be decoded") from None
        if (
            not isinstance(loaded, Ed25519PublicKey)
            or (
                len(decoded) != 32
                and loaded.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                != decoded
            )
        ):
            raise ValueError("Vault public key is not canonical Ed25519 raw/SPKI")
    if not isinstance(loaded, Ed25519PublicKey):
        raise ValueError("Vault Transit public key is not Ed25519")
    der = loaded.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    try:
        reparsed = serialization.load_der_public_key(der)
    except (TypeError, ValueError):
        raise ValueError("Vault public key DER could not be decoded") from None
    if (
        not isinstance(reparsed, Ed25519PublicKey)
        or reparsed.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        != der
    ):
        raise ValueError("Vault public key PEM/DER encoding is not canonical")
    raw = loaded.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if len(raw) != 32:
        raise ValueError("Vault Ed25519 public key is not exactly 32 bytes")
    return loaded, raw


def _validated_response(response: object, *, token: VaultToken) -> _HTTPResponse:
    if type(response) is not _HTTPResponse:
        raise VaultTransitError("transport", "Vault transport returned an invalid response")
    if (
        type(response.status) is not int
        or response.status < 100
        or response.status > 599
        or type(response.body) is not bytes
        or len(response.body) > MAX_VAULT_RESPONSE_BYTES
        or type(response.headers) is not tuple
        or len(response.headers) > 16
    ):
        raise VaultTransitError("transport", "Vault transport returned an invalid response")
    previous = ""
    reflected_parts = [response.body]
    for pair in response.headers:
        if (
            type(pair) is not tuple
            or len(pair) != 2
            or type(pair[0]) is not str
            or type(pair[1]) is not str
        ):
            raise VaultTransitError(
                "transport",
                "Vault transport returned invalid response headers",
            )
        name, value = pair
        if (
            name not in _RESPONSE_HEADER_NAMES
            or name <= previous
            or "\r" in value
            or "\n" in value
            or len(value) > 512
        ):
            raise VaultTransitError(
                "transport",
                "Vault transport returned invalid response headers",
            )
        previous = name
        reflected_parts.append(f"{name}:{value}".encode("utf-8", errors="replace"))
    if token._appears_in(b"\x00".join(reflected_parts)):
        raise VaultTransitError(
            "transport",
            "Vault response reflected credential material",
        )
    return response


def _json_response(response: _HTTPResponse, *, operation: str) -> dict[str, Any]:
    if response.status != 200:
        raise VaultTransitError(
            operation,
            f"Vault returned HTTP {response.status}",
        )
    headers = dict(response.headers)
    content_encoding = headers.get("content-encoding", "").strip().lower()
    if content_encoding not in {"", "identity"}:
        raise VaultTransitError(
            operation,
            "Vault response used an unrequested content encoding",
        )
    media_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        raise VaultTransitError(
            operation,
            "Vault response is not application/json",
        )
    parse_failed = False
    document: object = None
    try:
        document = strict_json_loads(response.body, limits=_JSON_LIMITS)
    except StrictJSONError:
        parse_failed = True
    if parse_failed or type(document) is not dict:
        raise VaultTransitError(
            operation,
            "Vault response is not bounded strict JSON",
        )
    return document


def _pinned_key_from_response(
    response: _HTTPResponse,
    *,
    expected_name: str,
) -> tuple[int, Ed25519PublicKey, bytes]:
    document = _json_response(response, operation="initialize")
    data = document.get("data")
    if type(data) is not dict:
        raise VaultTransitError("initialize", "Vault key response has no data object")
    latest_version = data.get("latest_version")
    keys = data.get("keys")
    min_signing_version = data.get("min_encryption_version")
    if (
        data.get("name") != expected_name
        or data.get("type") != "ed25519"
        or data.get("derived") is not False
        or data.get("supports_signing") is not True
        or type(latest_version) is not int
        or latest_version < 1
        or latest_version > 2**31 - 1
        or type(min_signing_version) is not int
        or min_signing_version < 0
        or min_signing_version > latest_version
        or type(keys) is not dict
        or not keys
        or len(keys) > 256
    ):
        raise VaultTransitError(
            "initialize",
            "Vault key metadata is incompatible with the Ed25519 signer profile",
        )
    for version_text, entry in keys.items():
        if (
            type(version_text) is not str
            or re.fullmatch(r"[1-9][0-9]{0,9}", version_text) is None
            or int(version_text) > latest_version
            or type(entry) is not dict
        ):
            raise VaultTransitError(
                "initialize",
                "Vault key version map is malformed",
            )
    latest_entry = keys.get(str(latest_version))
    if type(latest_entry) is not dict:
        raise VaultTransitError(
            "initialize",
            "Vault key response omits the latest key version",
        )
    key_parse_failed = False
    parsed: tuple[Ed25519PublicKey, bytes] | None = None
    try:
        parsed = _parse_public_key(latest_entry.get("public_key"))
    except ValueError:
        key_parse_failed = True
    if key_parse_failed or parsed is None:
        raise VaultTransitError(
            "initialize",
            "Vault latest public key is not canonical Ed25519 raw/SPKI",
        )
    public_key, raw = parsed
    return latest_version, public_key, raw


def _signature_from_response(
    response: _HTTPResponse,
    *,
    expected_version: int,
    public_key: Ed25519PublicKey,
    message: bytes,
) -> bytes:
    document = _json_response(response, operation="sign")
    data = document.get("data")
    signature_value = data.get("signature") if type(data) is dict else None
    if type(signature_value) is not str:
        raise VaultTransitError("sign", "Vault sign response has no signature")
    matched = _VAULT_SIGNATURE_RE.fullmatch(signature_value)
    if matched is None:
        raise VaultTransitError(
            "sign",
            "Vault returned a malformed Ed25519 signature",
        )
    if int(matched.group(1)) != expected_version:
        raise VaultTransitError(
            "sign",
            "Vault signature key version does not match the pinned version",
        )
    decode_failed = False
    decoded = b""
    try:
        decoded = _canonical_base64_decode(matched.group(2), expected_length=64)
    except ValueError:
        decode_failed = True
    if decode_failed:
        raise VaultTransitError(
            "sign",
            "Vault returned a malformed Ed25519 signature",
        )
    signature_invalid = False
    try:
        public_key.verify(decoded, message)
    except InvalidSignature:
        signature_invalid = True
    if signature_invalid:
        raise VaultTransitError(
            "sign",
            "Vault signature failed local Ed25519 verification",
        )
    return decoded


class VaultTransitEd25519ReceiptSigner:
    """A version-pinned Vault Transit implementation of ``ReceiptSigner``."""

    __slots__ = (
        "_endpoint_origin_digest",
        "_initialization_timeout_seconds",
        "_key_id",
        "_key_id_digest",
        "_key_name",
        "_key_name_digest",
        "_key_version",
        "_mount_path",
        "_mount_path_digest",
        "_namespace_digest",
        "_provider_lock",
        "_public_key",
        "_public_key_bytes",
        "_request_headers",
        "_sign_timeout_seconds",
        "_token_provider",
        "_transport",
    )

    def __init__(
        self,
        token_provider: VaultTokenProvider,
        *,
        endpoint: str,
        mount_path: str,
        key_name: str,
        key_id: str,
        namespace: str | None = None,
        ca_file: Path | None = None,
        allow_insecure_loopback: bool = False,
        request_timeout_seconds: int = 10,
        initialization_timeout_seconds: int = 30,
        sign_timeout_seconds: int = 30,
        _transport: _HTTPTransport | None = None,
    ) -> None:
        if not isinstance(token_provider, VaultTokenProvider):
            raise TypeError("token provider must implement VaultTokenProvider")
        if type(key_id) is not str or _KEY_ID_RE.fullmatch(key_id) is None:
            raise ValueError("key id is not portable or exceeds 256 characters")
        normalized_endpoint, tls = _canonical_endpoint(
            endpoint,
            allow_insecure_loopback=allow_insecure_loopback,
        )
        if not tls and ca_file is not None:
            raise ValueError("CA file is only valid for an HTTPS Vault endpoint")
        context = _ssl_context(ca_file) if tls else None
        self._mount_path = _validate_mount_path(mount_path)
        self._mount_path_digest = _locator_digest(
            b"control-assurance:vault-transit-mount:v1",
            self._mount_path,
        )
        self._key_name = _validate_key_name(key_name)
        self._key_name_digest = _locator_digest(
            b"control-assurance:vault-transit-key:v1",
            self._key_name,
        )
        self._key_id = key_id
        self._key_id_digest = _locator_digest(
            b"control-assurance:vault-key-id:v1",
            self._key_id,
        )
        self._request_headers = _request_headers(namespace)
        self._namespace_digest = (
            f"sha256:{hashlib.sha256(_ABSENT_NAMESPACE_DIGEST_INPUT).hexdigest()}"
            if namespace is None
            else _locator_digest(
                b"control-assurance:vault-namespace:v1",
                namespace,
            )
        )
        request_timeout_seconds = _timeout(
            request_timeout_seconds,
            label="request timeout",
            maximum=MAX_REQUEST_TIMEOUT_SECONDS,
        )
        self._initialization_timeout_seconds = _timeout(
            initialization_timeout_seconds,
            label="initialization timeout",
            maximum=MAX_OPERATION_TIMEOUT_SECONDS,
        )
        self._sign_timeout_seconds = _timeout(
            sign_timeout_seconds,
            label="sign timeout",
            maximum=MAX_OPERATION_TIMEOUT_SECONDS,
        )
        self._endpoint_origin_digest = (
            f"sha256:{hashlib.sha256(normalized_endpoint.encode('ascii')).hexdigest()}"
        )
        self._token_provider = token_provider
        self._provider_lock = threading.Lock()
        self._transport = _transport or _UrllibTransport(
            endpoint=normalized_endpoint,
            request_timeout_seconds=request_timeout_seconds,
            ssl_context=context,
        )
        deadline = time.monotonic() + self._initialization_timeout_seconds
        token = self._acquire_token(deadline=deadline)
        response = self._request(
            method="GET",
            target=self._key_target,
            body=b"",
            token=token,
            deadline=min(deadline, token.valid_until_monotonic),
        )
        key_version, public_key, public_key_bytes = _pinned_key_from_response(
            response,
            expected_name=self._key_name,
        )
        self._key_version = key_version
        self._public_key = public_key
        self._public_key_bytes = public_key_bytes

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(key_id_digest={self._key_id_digest!r}, "
            f"key_version={self._key_version}, "
            f"endpoint_origin_digest={self._endpoint_origin_digest!r}, "
            f"public_key_fingerprint={self.public_key_fingerprint!r})"
        )

    @property
    def _key_target(self) -> str:
        return f"/v1/{self._mount_path}/keys/{self._key_name}"

    @property
    def _sign_target(self) -> str:
        return f"/v1/{self._mount_path}/sign/{self._key_name}"

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def key_id_digest(self) -> str:
        """Return a non-reversible anchor for the public verifier key ID."""

        return self._key_id_digest

    @property
    def key_version(self) -> int:
        return self._key_version

    @property
    def endpoint_origin_digest(self) -> str:
        return self._endpoint_origin_digest

    @property
    def namespace_digest(self) -> str:
        """Return a non-reversible anchor for the exact Vault namespace."""

        return self._namespace_digest

    @property
    def mount_path_digest(self) -> str:
        """Return a non-reversible anchor for the exact Transit mount."""

        return self._mount_path_digest

    @property
    def key_name_digest(self) -> str:
        """Return a non-reversible anchor for the exact Transit key path segment."""

        return self._key_name_digest

    @property
    def public_key_bytes(self) -> bytes:
        return self._public_key_bytes

    @property
    def public_key_fingerprint(self) -> str:
        return f"sha256:{hashlib.sha256(self._public_key_bytes).hexdigest()}"

    def _acquire_token(self, *, deadline: float) -> VaultToken:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not self._provider_lock.acquire(timeout=remaining):
            raise VaultTransitError("deadline", "Vault operation deadline expired")
        acquisition_failed = False
        token: object = None
        try:
            try:
                token = self._token_provider.get_token(deadline=deadline)
            except Exception:
                acquisition_failed = True
        finally:
            self._provider_lock.release()
        if acquisition_failed:
            raise VaultTransitError(
                "authentication",
                "Vault token acquisition failed",
            )
        now = time.monotonic()
        if (
            type(token) is not VaultToken
            or token.valid_until_monotonic <= now
            or now >= deadline
        ):
            raise VaultTransitError(
                "authentication",
                "Vault token provider returned no currently valid token",
            )
        return token

    def _request(
        self,
        *,
        method: str,
        target: str,
        body: bytes,
        token: VaultToken,
        deadline: float,
    ) -> _HTTPResponse:
        if time.monotonic() >= deadline:
            raise VaultTransitError("deadline", "Vault operation deadline expired")
        transport_failed = False
        response: object = None
        try:
            response = self._transport.request(
                method=method,
                target=target,
                body=body,
                headers=self._request_headers,
                token=token,
                deadline=deadline,
            )
        except Exception:
            transport_failed = True
        if transport_failed:
            raise VaultTransitError(
                "transport",
                "Vault request failed at the configured origin",
            )
        if time.monotonic() >= deadline:
            raise VaultTransitError("deadline", "Vault operation deadline expired")
        return _validated_response(response, token=token)

    def sign(self, message: bytes) -> DetachedSignature:
        if type(message) is not bytes:
            raise TypeError("message must be immutable bytes")
        if len(message) > MAX_SIGNING_MESSAGE_BYTES:
            raise VaultTransitError(
                "sign",
                "message exceeds the Vault signing request profile",
            )
        deadline = time.monotonic() + self._sign_timeout_seconds
        token = self._acquire_token(deadline=deadline)
        try:
            body = canonical_json_bytes(
                {
                    "input": base64.b64encode(message).decode("ascii"),
                    "key_version": self._key_version,
                },
                limits=_REQUEST_JSON_LIMITS,
            )
        except StrictJSONError:
            raise VaultTransitError(
                "sign",
                "message exceeds the Vault signing request profile",
            ) from None
        response = self._request(
            method="POST",
            target=self._sign_target,
            body=body,
            token=token,
            deadline=min(deadline, token.valid_until_monotonic),
        )
        raw_signature = _signature_from_response(
            response,
            expected_version=self._key_version,
            public_key=self._public_key,
            message=message,
        )
        return DetachedSignature(
            key_id=self._key_id,
            algorithm="ed25519",
            signature=base64.b64encode(raw_signature).decode("ascii"),
        )

    def verify(self, message: bytes, signature: DetachedSignature) -> bool:
        if (
            type(message) is not bytes
            or not isinstance(signature, DetachedSignature)
            or signature.key_id != self._key_id
            or signature.algorithm != "ed25519"
        ):
            return False
        try:
            decoded = _canonical_base64_decode(
                signature.signature,
                expected_length=64,
            )
            self._public_key.verify(decoded, message)
        except (InvalidSignature, ValueError):
            return False
        return True


__all__ = [
    "VaultToken",
    "VaultTokenProvider",
    "VaultTransitEd25519ReceiptSigner",
    "VaultTransitError",
    "vault_endpoint_origin_digest",
]
