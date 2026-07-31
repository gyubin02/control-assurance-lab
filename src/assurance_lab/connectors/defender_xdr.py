"""Fail-closed capture of Microsoft Defender XDR AlertInfo evidence.

This connector calls the Microsoft Graph v1.0 ``security/runHuntingQuery``
action with the least-privileged ``ThreatHunting.Read.All`` permission.  It
does not accept caller-supplied KQL.  Instead, one fixed query:

* bounds ``AlertInfo`` to the requested half-open UTC interval;
* projects only the documented AlertInfo columns;
* emits one control row containing the exact server-side count;
* sorts every result deterministically; and
* asks for one row beyond the caller's safety limit.

Microsoft Graph does not paginate advanced-hunting results.  The service limits
each query to 100,000 rows and 64 MB, so a syntactically successful response can
never be treated as complete merely because it returned HTTP 200.  The verifier
requires the control row, exact schema, exact count closure, deterministic row
order, and the externally supplied request/source/version anchors.  Saturated
or size-truncated responses therefore fail closed instead of becoming evidence.

The OAuth bearer token is acquired through an opaque provider and is omitted
from request receipts, exceptions, and object representations.  This module
does not acquire Entra credentials, change alerts, isolate devices, retry
ambiguous requests, or claim that Microsoft cryptographically attested to the
captured bytes.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import os
import re
import secrets
import ssl
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, Literal, Protocol, cast, runtime_checkable

from assurance_lab._version import __version__
from assurance_lab.connectors.contract import (
    ConnectorCapture,
    ConnectorCaptureError,
    ConnectorDescriptor,
    ConnectorWindow,
    VerifiedConnectorCapture,
    canonical_timestamp,
)
from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    canonical_jsonl_bytes,
    strict_json_loads,
)

DEFENDER_XDR_CAPTURE_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.defender-xdr-capture.v1+json"]
] = "application/vnd.control-assurance.defender-xdr-capture.v1+json"
DEFENDER_XDR_CAPTURE_SCHEMA_VERSION: Final[Literal["1.0.0"]] = "1.0.0"
DEFENDER_XDR_CONNECTOR_ID: Final[Literal["microsoft-defender-xdr-readonly"]] = (
    "microsoft-defender-xdr-readonly"
)
DEFENDER_XDR_REQUEST_PROFILE: Final[Literal["microsoft-graph-v1.0-alertinfo-exact-count-v1"]] = (
    "microsoft-graph-v1.0-alertinfo-exact-count-v1"
)
DEFENDER_XDR_REQUIRED_PERMISSION: Final[Literal["ThreatHunting.Read.All"]] = (
    "ThreatHunting.Read.All"
)

DEFAULT_GRAPH_ENDPOINT = "https://graph.microsoft.com"
_OFFICIAL_GRAPH_ENDPOINTS = frozenset(
    {
        "https://dod-graph.microsoft.us",
        "https://graph.microsoft.com",
        "https://graph.microsoft.us",
    }
)
_ALLOWED_ODATA_CONTEXTS = frozenset(
    f"{endpoint}/v1.0/$metadata#microsoft.graph.security.huntingQueryResults"
    for endpoint in _OFFICIAL_GRAPH_ENDPOINTS
)
_HUNTING_TARGET = "/v1.0/security/runHuntingQuery"

MAX_BEARER_TOKEN_BYTES = 32 * 1024
MAX_RESPONSE_BYTES = 65 * 1024 * 1024
MAX_RECEIPT_BYTES = 90 * 1024 * 1024
MAX_RECORD_BYTES = 64 * 1024 * 1024
MAX_FIELD_VALUE_BYTES = 256 * 1024
MAX_SERVICE_ROWS = 100_000
# One exact-count control row and one saturation-probe row must fit inside the
# documented 100,000-row service limit.
MAX_HITS = MAX_SERVICE_ROWS - 2
MAX_WINDOW_SECONDS = 30 * 24 * 60 * 60
MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 620
MIN_CAPTURE_TIMEOUT_SECONDS = 5
MAX_CAPTURE_TIMEOUT_SECONDS = 900
MAX_TIMING_MICROSECONDS = MAX_CAPTURE_TIMEOUT_SECONDS * 1_000_000

_CAPTURE_ID_RE = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_CAPTURE_NONCE_RE = re.compile(r"^[a-f0-9]{64}$")
_BEARER_TOKEN_RE = re.compile(rb"^[A-Za-z0-9\-._~+/]+=*$")
_SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_CAPTURE_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{6}Z$"
)
_ALERT_TIMESTAMP_RE = re.compile(
    r"^(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})T"
    r"(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"[.](?P<fraction>[0-9]{7})Z$"
)
_EXACT_TOTAL_RE = re.compile(r"^(?:0|[1-9][0-9]{0,18})$")
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

_REQUEST_HEADERS = (
    ("accept", "application/json"),
    ("accept-encoding", "identity"),
    ("content-type", "application/json"),
)
_RECORDED_RESPONSE_HEADERS = (
    "content-encoding",
    "content-type",
    "request-id",
)
_RESULT_COLUMNS = (
    "ControlAssuranceKind",
    "ControlAssuranceTotal",
    "Timestamp",
    "AlertId",
    "Title",
    "Category",
    "Severity",
    "ServiceSource",
    "DetectionSource",
    "AttackTechniques",
)
_ALERT_COLUMNS = _RESULT_COLUMNS[2:]
_RESULT_KEYS = frozenset(_RESULT_COLUMNS)
_CONTROL_EMPTY_COLUMNS = _RESULT_COLUMNS[2:]

_RESPONSE_LIMITS = JSONLimits(
    max_bytes=MAX_RESPONSE_BYTES,
    max_line_bytes=MAX_RESPONSE_BYTES,
    max_depth=16,
    max_collection_items=MAX_SERVICE_ROWS + 32,
    max_string_length=MAX_FIELD_VALUE_BYTES,
)
_RECEIPT_LIMITS = JSONLimits(
    max_bytes=MAX_RECEIPT_BYTES,
    max_line_bytes=MAX_RECEIPT_BYTES,
    max_depth=32,
    max_collection_items=MAX_SERVICE_ROWS + 128,
    max_string_length=MAX_RESPONSE_BYTES * 2,
)
_RECORD_LIMITS = JSONLimits(
    max_bytes=MAX_RECORD_BYTES,
    max_line_bytes=2 * 1024 * 1024,
    max_depth=16,
    max_collection_items=MAX_SERVICE_ROWS,
    max_string_length=MAX_FIELD_VALUE_BYTES,
)


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def new_defender_capture_nonce() -> str:
    """Return a fresh 256-bit replay-binding nonce for one Defender request."""

    return secrets.token_hex(32)


def _capture_timestamp(value: datetime) -> str:
    if type(value) is not datetime or value.tzinfo is None:
        raise ValueError("capture timestamp must be timezone-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _base64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_base64(value: object, *, label: str, maximum: int) -> bytes:
    if type(value) is not str or len(value) > 4 * ((maximum + 2) // 3):
        raise ConnectorCaptureError("verify", f"{label} is absent or exceeds its limit")
    try:
        encoded = value.encode("ascii", errors="strict")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise ConnectorCaptureError("verify", f"{label} is not canonical base64") from exc
    if len(decoded) > maximum or base64.b64encode(decoded) != encoded:
        raise ConnectorCaptureError("verify", f"{label} is not canonical base64")
    return decoded


def _exact_dict(
    value: object,
    *,
    label: str,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConnectorCaptureError("verify", f"{label} is not an object")
    keys = frozenset(value)
    if not required <= keys or not keys <= (required | optional):
        raise ConnectorCaptureError("verify", f"{label} has missing or unexpected members")
    return cast(dict[str, Any], value)


def _exact_array(value: object, *, label: str, maximum: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ConnectorCaptureError("verify", f"{label} is not a bounded array")
    return value


def _exact_int(value: object, *, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise ConnectorCaptureError("verify", f"{label} is outside its integer range")
    return value


def _exact_text(
    value: object,
    *,
    label: str,
    maximum: int,
    allow_empty: bool = False,
) -> str:
    if type(value) is not str or (not value and not allow_empty) or len(value) > maximum:
        raise ConnectorCaptureError("verify", f"{label} is absent or too long")
    return value


def _validate_digest(value: object, *, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ConnectorCaptureError("verify", f"{label} is not a canonical SHA-256 digest")
    return value


def _canonical_headers(value: object, *, label: str) -> tuple[tuple[str, str], ...]:
    array = _exact_array(value, label=label, maximum=8)
    headers: list[tuple[str, str]] = []
    previous = ""
    for index, raw in enumerate(array):
        pair = _exact_array(raw, label=f"{label}[{index}]", maximum=2)
        if len(pair) != 2 or type(pair[0]) is not str or type(pair[1]) is not str:
            raise ConnectorCaptureError("verify", f"{label}[{index}] is not a text pair")
        name, content = pair
        if name != name.lower() or not name or name <= previous:
            raise ConnectorCaptureError("verify", f"{label} is not strictly ordered")
        if "\r" in content or "\n" in content or len(content) > 512:
            raise ConnectorCaptureError("verify", f"{label}[{index}] is unsafe")
        headers.append((name, content))
        previous = name
    return tuple(headers)


@dataclass(frozen=True, slots=True)
class DefenderXDRRequest:
    """One bounded, fixed-profile AlertInfo collection request."""

    capture_id: str
    window: ConnectorWindow
    capture_nonce: str
    max_hits: int = 10_000

    def __post_init__(self) -> None:
        if type(self.capture_id) is not str or _CAPTURE_ID_RE.fullmatch(self.capture_id) is None:
            raise ValueError("capture id is not a portable identifier")
        if type(self.window) is not ConnectorWindow:
            raise TypeError("window must be an exact ConnectorWindow")
        if (
            type(self.capture_nonce) is not str
            or _CAPTURE_NONCE_RE.fullmatch(self.capture_nonce) is None
        ):
            raise ValueError("capture nonce must be exactly 256 bits of lowercase hex")
        if self.window.end - self.window.start > timedelta(seconds=MAX_WINDOW_SECONDS):
            raise ValueError("Defender XDR windows cannot exceed 30 days")
        if type(self.max_hits) is not int or self.max_hits < 1 or self.max_hits > MAX_HITS:
            raise ValueError("max hits is outside the Defender XDR connector profile")

    def as_json(self) -> dict[str, Any]:
        return {
            "capture_id": self.capture_id,
            "capture_nonce": self.capture_nonce,
            "max_hits": self.max_hits,
            "profile": DEFENDER_XDR_REQUEST_PROFILE,
            "window": self.window.as_json(),
        }


class DefenderBearerToken:
    """Opaque OAuth bearer-token bytes with redacted representations.

    Python cannot guarantee that immutable secret bytes are zeroized.  This
    wrapper keeps the value out of connector receipts, normalized failures,
    and ordinary ``repr``/``str`` output; secret lifetime remains a provider
    and process-isolation responsibility.
    """

    __slots__ = ("__value",)

    def __init__(self, value: bytes) -> None:
        if (
            type(value) is not bytes
            or not value
            or len(value) > MAX_BEARER_TOKEN_BYTES
            or _BEARER_TOKEN_RE.fullmatch(value) is None
        ):
            raise ValueError("Defender bearer token must be bounded RFC 6750 token bytes")
        self.__value = value

    def __repr__(self) -> str:
        return "DefenderBearerToken(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"

    def _authorization_header(self) -> str:
        return f"Bearer {self.__value.decode('ascii', errors='strict')}"

    def _appears_in(self, value: bytes) -> bool:
        escaped = self.__value.replace(b"/", b"\\/")
        quoted = urllib.parse.quote_from_bytes(self.__value).encode("ascii")
        return any(candidate in value for candidate in (self.__value, escaped, quoted))

    def _appears_in_json(self, value: bytes) -> bool:
        """Detect reflected material even when JSON uses Unicode escapes."""

        try:
            parsed = strict_json_loads(value, limits=_RESPONSE_LIMITS)
        except StrictJSONError:
            return False
        needle = self.__value.decode("ascii", errors="strict")
        pending: list[Any] = [parsed]
        while pending:
            member = pending.pop()
            if isinstance(member, str):
                if needle in member:
                    return True
            elif isinstance(member, list):
                pending.extend(member)
            elif isinstance(member, dict):
                pending.extend(member)
                pending.extend(member.values())
        return False


@runtime_checkable
class DefenderBearerTokenProvider(Protocol):
    """Acquire one opaque Graph token before the caller-supplied deadline."""

    def get_token(self, *, deadline: float) -> DefenderBearerToken:
        """Return a token authorized with ``ThreatHunting.Read.All``."""


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
        bearer_token: DefenderBearerToken,
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
    __slots__ = ("_endpoint", "_opener", "_timeout_seconds")

    def __init__(
        self,
        *,
        endpoint: str,
        timeout_seconds: int,
        ssl_context: ssl.SSLContext | None,
    ) -> None:
        handlers: list[Any] = [
            urllib.request.ProxyHandler({}),
            _NoRedirect(),
        ]
        if ssl_context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=ssl_context))
        self._opener = urllib.request.build_opener(*handlers)
        self._endpoint = endpoint
        self._timeout_seconds = timeout_seconds

    def request(
        self,
        *,
        method: str,
        target: str,
        body: bytes,
        headers: tuple[tuple[str, str], ...],
        bearer_token: DefenderBearerToken,
        deadline: float,
    ) -> _HTTPResponse:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ConnectorCaptureError("deadline", "capture deadline expired")
        request_headers = {name: value for name, value in headers}
        request_headers["authorization"] = bearer_token._authorization_header()
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
            raise ConnectorCaptureError("transport", "Microsoft Graph request timed out") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise ConnectorCaptureError(
                "transport",
                "Microsoft Graph request could not be completed",
            ) from exc
        try:
            content = bytearray()
            reader = getattr(response, "read1", response.read)
            while True:
                if time.monotonic() >= deadline:
                    raise ConnectorCaptureError("deadline", "capture deadline expired")
                chunk = reader(min(64 * 1024, MAX_RESPONSE_BYTES + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > MAX_RESPONSE_BYTES:
                    raise ConnectorCaptureError(
                        "transport",
                        "Microsoft Graph response exceeds the connector byte limit",
                    )
            payload = bytes(content)
            selected: list[tuple[str, str]] = []
            for name in _RECORDED_RESPONSE_HEADERS:
                values = response.headers.get_all(name, [])
                if len(values) > 1:
                    raise ConnectorCaptureError(
                        "transport",
                        f"Microsoft Graph returned duplicate {name} headers",
                    )
                if values:
                    selected.append((name, values[0]))
            reflected = (
                payload
                + b"\x00"
                + b"\x00".join(
                    f"{name}:{value}".encode("utf-8", errors="replace") for name, value in selected
                )
            )
            if bearer_token._appears_in(reflected) or bearer_token._appears_in_json(payload):
                raise ConnectorCaptureError(
                    "transport",
                    "Microsoft Graph response reflected credential material",
                )
            return _HTTPResponse(
                status=int(response.status),
                headers=tuple(selected),
                body=payload,
            )
        except (OSError, http.client.HTTPException) as exc:
            raise ConnectorCaptureError(
                "transport",
                "Microsoft Graph response could not be read completely",
            ) from exc
        finally:
            response.close()


def _normalize_endpoint(
    endpoint: str,
    *,
    allow_insecure_loopback: bool,
) -> tuple[str, bool]:
    if type(endpoint) is not str or len(endpoint) > 2_048:
        raise ValueError("Microsoft Graph endpoint is absent or too long")
    parsed = urllib.parse.urlsplit(endpoint)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("Microsoft Graph endpoint must be an origin without credentials or path")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Microsoft Graph endpoint port is invalid") from exc
    host = parsed.hostname.lower()
    if parsed.scheme == "http":
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError("plain HTTP is restricted to a literal loopback address") from exc
        if not allow_insecure_loopback or not address.is_loopback:
            raise ValueError("plain HTTP requires explicit loopback lab mode")
        rendered_host = f"[{host}]" if ":" in host else host
        authority = rendered_host if port in {None, 80} else f"{rendered_host}:{port}"
        return f"http://{authority}", False
    normalized = f"https://{host}"
    if port not in {None, 443} or normalized not in _OFFICIAL_GRAPH_ENDPOINTS:
        raise ValueError("HTTPS endpoint is not an approved Microsoft Graph cloud origin")
    return normalized, True


def defender_xdr_endpoint_origin_digest(
    endpoint: str = DEFAULT_GRAPH_ENDPOINT,
    *,
    allow_insecure_loopback: bool = False,
) -> str:
    """Return the privacy-preserving Microsoft Graph origin anchor."""

    normalized, _ = _normalize_endpoint(
        endpoint,
        allow_insecure_loopback=allow_insecure_loopback,
    )
    return _sha256(normalized.encode("utf-8"))


def _ssl_context(ca_file: Path | None) -> ssl.SSLContext:
    if ca_file is None:
        return ssl.create_default_context()
    if type(ca_file) is not Path:
        raise TypeError("CA file must be a pathlib.Path")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    content = bytearray()
    try:
        descriptor = os.open(ca_file, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > (8 * 1024 * 1024)
        ):
            raise ValueError("CA file must be a bounded single-link regular file")
        while len(content) <= (8 * 1024 * 1024):
            chunk = os.read(
                descriptor,
                min(64 * 1024, (8 * 1024 * 1024) + 1 - len(content)),
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
            len(content) > (8 * 1024 * 1024)
            or len(content) != after.st_size
            or before_identity != after_identity
        ):
            raise ValueError("CA file changed while it was read")
    except OSError as exc:
        raise ValueError("CA file cannot be read safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        pem = bytes(content).decode("ascii", errors="strict")
        if "-----BEGIN CERTIFICATE-----" not in pem:
            raise ValueError("CA file is not a PEM certificate bundle")
        context = ssl.create_default_context()
        context.load_verify_locations(cadata=pem)
        return context
    except (UnicodeDecodeError, OSError, ssl.SSLError) as exc:
        raise ValueError("CA file could not establish a TLS trust context") from exc


def _query_text(request: DefenderXDRRequest) -> str:
    """Generate the only KQL profile accepted by this connector."""

    start = canonical_timestamp(request.window.start)
    end = canonical_timestamp(request.window.end)
    take = request.max_hits + 2
    return (
        "let _ca_rows = materialize(\n"
        "    AlertInfo\n"
        f"    | where Timestamp >= datetime({start}) and Timestamp < datetime({end})\n"
        '    | project ControlAssuranceKind = "record", '
        'ControlAssuranceTotal = "", '
        "Timestamp = strcat("
        'format_datetime(Timestamp, "yyyy-MM-dd"), "T", '
        'format_datetime(Timestamp, "HH:mm:ss.fffffff"), "Z"), '
        "AlertId = tostring(AlertId), "
        "Title = tostring(Title), "
        "Category = tostring(Category), "
        "Severity = tostring(Severity), "
        "ServiceSource = tostring(ServiceSource), "
        "DetectionSource = tostring(DetectionSource), "
        "AttackTechniques = tostring(AttackTechniques)\n"
        ");\n"
        "let _ca_total = toscalar(_ca_rows | count);\n"
        "union _ca_rows,\n"
        '    (print ControlAssuranceKind = "control", '
        "ControlAssuranceTotal = tostring(_ca_total), "
        'Timestamp = "", AlertId = "", Title = "", Category = "", '
        'Severity = "", ServiceSource = "", DetectionSource = "", '
        'AttackTechniques = "")\n'
        "| order by ControlAssuranceKind asc, Timestamp asc, AlertId asc, "
        "Title asc, Category asc, Severity asc, ServiceSource asc, "
        "DetectionSource asc, AttackTechniques asc\n"
        f"| take {take}"
    )


def _request_body(request: DefenderXDRRequest) -> bytes:
    return canonical_json_bytes(
        {
            "Query": _query_text(request),
            "Timespan": (
                f"{canonical_timestamp(request.window.start)}/"
                f"{canonical_timestamp(request.window.end)}"
            ),
        },
        limits=_RESPONSE_LIMITS,
    )


def _exchange(
    *,
    request_body: bytes,
    response: _HTTPResponse,
) -> dict[str, Any]:
    return {
        "operation": "run-hunting-query",
        "request": {
            "body_base64": _base64(request_body),
            "body_digest": _sha256(request_body),
            "headers": [list(pair) for pair in _REQUEST_HEADERS],
            "method": "POST",
            "target": _HUNTING_TARGET,
        },
        "response": {
            "body_base64": _base64(response.body),
            "body_digest": _sha256(response.body),
            "headers": [list(pair) for pair in response.headers],
            "status": response.status,
        },
        "sequence": 0,
    }


class DefenderXDRConnector:
    """Capture one complete Microsoft Defender XDR AlertInfo window."""

    __slots__ = (
        "_capture_timeout_seconds",
        "_descriptor",
        "_endpoint_digest",
        "_token_provider",
        "_transport",
    )

    def __init__(
        self,
        token_provider: DefenderBearerTokenProvider,
        *,
        endpoint: str = DEFAULT_GRAPH_ENDPOINT,
        ca_file: Path | None = None,
        allow_insecure_loopback: bool = False,
        timeout_seconds: int = 120,
        capture_timeout_seconds: int = 660,
        _transport: _HTTPTransport | None = None,
    ) -> None:
        if not isinstance(token_provider, DefenderBearerTokenProvider):
            raise TypeError("token provider must implement DefenderBearerTokenProvider")
        if (
            type(timeout_seconds) is not int
            or timeout_seconds < MIN_TIMEOUT_SECONDS
            or timeout_seconds > MAX_TIMEOUT_SECONDS
        ):
            raise ValueError("request timeout is outside the connector profile")
        if (
            type(capture_timeout_seconds) is not int
            or capture_timeout_seconds < MIN_CAPTURE_TIMEOUT_SECONDS
            or capture_timeout_seconds > MAX_CAPTURE_TIMEOUT_SECONDS
        ):
            raise ValueError("capture timeout is outside the connector profile")
        normalized, tls = _normalize_endpoint(
            endpoint,
            allow_insecure_loopback=allow_insecure_loopback,
        )
        context = _ssl_context(ca_file) if tls else None
        self._descriptor = ConnectorDescriptor(
            connector_id=DEFENDER_XDR_CONNECTOR_ID,
            connector_version=__version__,
            capture_media_type=DEFENDER_XDR_CAPTURE_MEDIA_TYPE,
        )
        self._endpoint_digest = _sha256(normalized.encode("utf-8"))
        self._token_provider = token_provider
        self._capture_timeout_seconds = capture_timeout_seconds
        self._transport = _transport or _UrllibTransport(
            endpoint=normalized,
            timeout_seconds=timeout_seconds,
            ssl_context=context,
        )

    @property
    def descriptor(self) -> ConnectorDescriptor:
        return self._descriptor

    def _acquire_token(self, *, deadline: float) -> DefenderBearerToken:
        if time.monotonic() >= deadline:
            raise ConnectorCaptureError("deadline", "capture deadline expired")
        acquisition_failed = False
        token: object = None
        try:
            token = self._token_provider.get_token(deadline=deadline)
        except Exception:
            # Provider errors can contain raw OAuth responses or token values.
            # Exit the exception handler before raising so neither ``__cause__``
            # nor ``__context__`` retains the provider exception.
            acquisition_failed = True
        if acquisition_failed:
            raise ConnectorCaptureError(
                "authentication",
                "bearer token acquisition failed",
            )
        if type(token) is not DefenderBearerToken:
            raise ConnectorCaptureError(
                "authentication",
                "token provider returned an invalid token object",
            )
        if time.monotonic() >= deadline:
            raise ConnectorCaptureError("deadline", "capture deadline expired")
        return token

    def _request(
        self,
        *,
        body: bytes,
        bearer_token: DefenderBearerToken,
        deadline: float,
    ) -> _HTTPResponse:
        if time.monotonic() >= deadline:
            raise ConnectorCaptureError("deadline", "capture deadline expired")
        response = self._transport.request(
            method="POST",
            target=_HUNTING_TARGET,
            body=body,
            headers=_REQUEST_HEADERS,
            bearer_token=bearer_token,
            deadline=deadline,
        )
        if type(response) is not _HTTPResponse:
            raise ConnectorCaptureError(
                "query",
                "transport returned an invalid response object",
            )
        if response.status != 200:
            raise ConnectorCaptureError(
                "query",
                f"Microsoft Graph returned HTTP {response.status}",
            )
        return response

    def capture(self, request: object) -> ConnectorCapture:
        if type(request) is not DefenderXDRRequest:
            raise TypeError("request must be an exact DefenderXDRRequest")
        started_at = datetime.now(UTC)
        started_monotonic = time.monotonic()
        deadline = started_monotonic + self._capture_timeout_seconds
        body = _request_body(request)
        token = self._acquire_token(deadline=deadline)
        response = self._request(
            body=body,
            bearer_token=token,
            deadline=deadline,
        )
        elapsed_microseconds = round((time.monotonic() - started_monotonic) * 1_000_000)
        if elapsed_microseconds < 0 or elapsed_microseconds > MAX_TIMING_MICROSECONDS:
            raise ConnectorCaptureError("timing", "capture elapsed time is outside the profile")
        finished_at = started_at + timedelta(microseconds=elapsed_microseconds)
        receipt = {
            "connector": {
                "id": self._descriptor.connector_id,
                "version": self._descriptor.connector_version,
            },
            "endpoint_origin_digest": self._endpoint_digest,
            "exchanges": [_exchange(request_body=body, response=response)],
            "media_type": DEFENDER_XDR_CAPTURE_MEDIA_TYPE,
            "request": request.as_json(),
            "schema_version": DEFENDER_XDR_CAPTURE_SCHEMA_VERSION,
            "source_profile": {
                "api": "Microsoft Graph v1.0",
                "permission": DEFENDER_XDR_REQUIRED_PERMISSION,
                "table": "AlertInfo",
            },
            "timing": {
                "elapsed_microseconds": elapsed_microseconds,
                "finished_at": _capture_timestamp(finished_at),
                "started_at": _capture_timestamp(started_at),
            },
        }
        try:
            receipt_bytes = canonical_json_bytes(receipt, limits=_RECEIPT_LIMITS)
        except StrictJSONError as exc:
            raise ConnectorCaptureError(
                "receipt",
                "capture receipt exceeds the canonical evidence profile",
            ) from exc
        verified = verify_defender_xdr_capture(
            receipt_bytes,
            expected_endpoint_origin_digest=self._endpoint_digest,
            expected_request=request,
            expected_connector_version=self._descriptor.connector_version,
        )
        return ConnectorCapture(
            descriptor=self._descriptor,
            receipt_bytes=receipt_bytes,
            receipt_digest=verified.receipt_digest,
            records_jsonl=verified.records_jsonl,
            records_digest=verified.records_digest,
            record_count=verified.record_count,
        )


def _require_json_response(response: _HTTPResponse) -> dict[str, Any]:
    headers = dict(response.headers)
    content_encoding = headers.get("content-encoding", "").strip().lower()
    if content_encoding not in {"", "identity"}:
        raise ConnectorCaptureError("verify", "response used an unrequested content encoding")
    content_type = headers.get("content-type", "")
    if content_type.split(";", 1)[0].strip().lower() != "application/json":
        raise ConnectorCaptureError("verify", "response is not application/json")
    if response.status != 200:
        raise ConnectorCaptureError(
            "verify",
            f"Microsoft Graph returned HTTP {response.status}",
        )
    try:
        parsed = strict_json_loads(response.body, limits=_RESPONSE_LIMITS)
    except StrictJSONError as exc:
        raise ConnectorCaptureError("verify", "response is not strict bounded JSON") from exc
    if not isinstance(parsed, dict):
        raise ConnectorCaptureError("verify", "response JSON is not an object")
    return cast(dict[str, Any], parsed)


def _response_from_exchange(value: object, *, label: str) -> _HTTPResponse:
    response = _exact_dict(
        value,
        label=f"{label} response",
        required=frozenset({"body_base64", "body_digest", "headers", "status"}),
    )
    body = _decode_base64(
        response["body_base64"],
        label=f"{label} response body",
        maximum=MAX_RESPONSE_BYTES,
    )
    digest = _validate_digest(
        response["body_digest"],
        label=f"{label} response body digest",
    )
    if _sha256(body) != digest:
        raise ConnectorCaptureError("verify", f"{label} response body digest is false")
    status = _exact_int(
        response["status"],
        label=f"{label} response status",
        minimum=100,
        maximum=599,
    )
    headers = _canonical_headers(response["headers"], label=f"{label} response headers")
    if any(name not in _RECORDED_RESPONSE_HEADERS for name, _ in headers):
        raise ConnectorCaptureError("verify", f"{label} response retained an unsafe header")
    return _HTTPResponse(status=status, headers=headers, body=body)


def _request_from_exchange(
    value: object,
    *,
    label: str,
) -> tuple[str, str, tuple[tuple[str, str], ...], bytes]:
    request = _exact_dict(
        value,
        label=f"{label} request",
        required=frozenset({"body_base64", "body_digest", "headers", "method", "target"}),
    )
    body = _decode_base64(
        request["body_base64"],
        label=f"{label} request body",
        maximum=64 * 1024,
    )
    digest = _validate_digest(
        request["body_digest"],
        label=f"{label} request body digest",
    )
    if _sha256(body) != digest:
        raise ConnectorCaptureError("verify", f"{label} request body digest is false")
    method = _exact_text(request["method"], label=f"{label} method", maximum=16)
    target = _exact_text(request["target"], label=f"{label} target", maximum=2_048)
    headers = _canonical_headers(request["headers"], label=f"{label} request headers")
    if any(name == "authorization" for name, _ in headers):
        raise ConnectorCaptureError("verify", "receipt contains an authorization header")
    return method, target, headers, body


def _parse_window(value: object) -> ConnectorWindow:
    window = _exact_dict(
        value,
        label="request window",
        required=frozenset({"end_exclusive", "start_inclusive"}),
    )

    def parse(name: str) -> datetime:
        text = _exact_text(window[name], label=f"request {name}", maximum=32)
        try:
            parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        except ValueError as exc:
            raise ConnectorCaptureError(
                "verify",
                f"request {name} is not canonical whole-second UTC",
            ) from exc
        if canonical_timestamp(parsed) != text:
            raise ConnectorCaptureError(
                "verify",
                f"request {name} is not canonical whole-second UTC",
            )
        return parsed

    try:
        return ConnectorWindow(
            start=parse("start_inclusive"),
            end=parse("end_exclusive"),
        )
    except (TypeError, ValueError) as exc:
        raise ConnectorCaptureError("verify", "request window is invalid") from exc


def _parse_request(value: object) -> DefenderXDRRequest:
    request = _exact_dict(
        value,
        label="Defender XDR request",
        required=frozenset(
            {
                "capture_id",
                "capture_nonce",
                "max_hits",
                "profile",
                "window",
            }
        ),
    )
    if request["profile"] != DEFENDER_XDR_REQUEST_PROFILE:
        raise ConnectorCaptureError("verify", "request uses a different fixed query profile")
    capture_id = _exact_text(request["capture_id"], label="capture id", maximum=128)
    capture_nonce = _exact_text(
        request["capture_nonce"],
        label="capture nonce",
        maximum=64,
    )
    max_hits = _exact_int(
        request["max_hits"],
        label="request max hits",
        minimum=1,
        maximum=MAX_HITS,
    )
    try:
        return DefenderXDRRequest(
            capture_id=capture_id,
            window=_parse_window(request["window"]),
            capture_nonce=capture_nonce,
            max_hits=max_hits,
        )
    except (TypeError, ValueError) as exc:
        raise ConnectorCaptureError("verify", "receipt request is invalid") from exc


def _parse_capture_timing(value: object) -> None:
    timing = _exact_dict(
        value,
        label="capture timing",
        required=frozenset({"elapsed_microseconds", "finished_at", "started_at"}),
    )
    started_text = _exact_text(
        timing["started_at"],
        label="capture start",
        maximum=32,
    )
    finished_text = _exact_text(
        timing["finished_at"],
        label="capture finish",
        maximum=32,
    )
    if (
        _CAPTURE_TIMESTAMP_RE.fullmatch(started_text) is None
        or _CAPTURE_TIMESTAMP_RE.fullmatch(finished_text) is None
    ):
        raise ConnectorCaptureError(
            "verify",
            "capture timing is not canonical microsecond UTC",
        )
    try:
        started = datetime.strptime(
            started_text,
            "%Y-%m-%dT%H:%M:%S.%fZ",
        ).replace(tzinfo=UTC)
        finished = datetime.strptime(
            finished_text,
            "%Y-%m-%dT%H:%M:%S.%fZ",
        ).replace(tzinfo=UTC)
    except ValueError as exc:
        raise ConnectorCaptureError("verify", "capture timing is not a real instant") from exc
    elapsed = _exact_int(
        timing["elapsed_microseconds"],
        label="capture elapsed microseconds",
        minimum=0,
        maximum=MAX_TIMING_MICROSECONDS,
    )
    delta = finished - started
    actual = (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds
    if actual != elapsed:
        raise ConnectorCaptureError(
            "verify",
            "capture timing does not close over its monotonic elapsed time",
        )


def _parse_alert_timestamp(value: object, *, label: str) -> tuple[int, str]:
    text = _exact_text(value, label=label, maximum=40)
    match = _ALERT_TIMESTAMP_RE.fullmatch(text)
    if match is None:
        raise ConnectorCaptureError(
            "verify",
            f"{label} is not canonical seven-digit UTC",
        )
    try:
        whole = datetime.strptime(
            f"{match.group('date')}T{match.group('time')}Z",
            "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=UTC)
    except ValueError as exc:
        raise ConnectorCaptureError("verify", f"{label} is not a real UTC instant") from exc
    delta = whole - _UNIX_EPOCH
    seconds = (delta.days * 86_400) + delta.seconds
    return (seconds * 10_000_000) + int(match.group("fraction")), text


def _window_ticks(value: datetime) -> int:
    delta = value - _UNIX_EPOCH
    seconds = (delta.days * 86_400) + delta.seconds
    return (seconds * 10_000_000) + (delta.microseconds * 10)


def _parse_schema(value: object) -> None:
    schema = _exact_array(value, label="hunting response schema", maximum=len(_RESULT_COLUMNS))
    if len(schema) != len(_RESULT_COLUMNS):
        raise ConnectorCaptureError("verify", "hunting response schema is incomplete")
    seen: set[str] = set()
    for index, raw in enumerate(schema):
        member = _exact_dict(
            raw,
            label=f"schema member {index}",
            required=frozenset({"name", "type"}),
            optional=frozenset({"@odata.type"}),
        )
        name = _exact_text(member["name"], label=f"schema member {index} name", maximum=64)
        kind = _exact_text(member["type"], label=f"schema member {index} type", maximum=32)
        if name not in _RESULT_KEYS or name in seen or kind != "String":
            raise ConnectorCaptureError("verify", "hunting response schema was substituted")
        odata_type = member.get("@odata.type")
        if odata_type is not None and odata_type != (
            "#microsoft.graph.security.singlePropertySchema"
        ):
            raise ConnectorCaptureError("verify", "schema member has an unexpected OData type")
        seen.add(name)
    if seen != _RESULT_KEYS:
        raise ConnectorCaptureError("verify", "hunting response schema is incomplete")


def _parse_hunting_results(
    response: _HTTPResponse,
    *,
    request: DefenderXDRRequest,
) -> list[dict[str, Any]]:
    parsed = _require_json_response(response)
    root = _exact_dict(
        parsed,
        label="hunting response",
        required=frozenset({"results", "schema"}),
        optional=frozenset({"@odata.context"}),
    )
    context = root.get("@odata.context")
    if context is not None and context not in _ALLOWED_ODATA_CONTEXTS:
        raise ConnectorCaptureError("verify", "hunting response has an unexpected OData context")
    _parse_schema(root["schema"])
    results = _exact_array(
        root["results"],
        label="hunting results",
        maximum=MAX_SERVICE_ROWS,
    )
    if not results:
        raise ConnectorCaptureError("verify", "hunting response lacks its exact-count control row")

    control = _exact_dict(
        results[0],
        label="exact-count control row",
        required=_RESULT_KEYS,
    )
    if control["ControlAssuranceKind"] != "control":
        raise ConnectorCaptureError("verify", "exact-count control row is absent or out of order")
    total_text = _exact_text(
        control["ControlAssuranceTotal"],
        label="exact-count value",
        maximum=19,
        allow_empty=False,
    )
    if _EXACT_TOTAL_RE.fullmatch(total_text) is None:
        raise ConnectorCaptureError("verify", "exact-count value is not canonical")
    exact_total = int(total_text)
    for name in _CONTROL_EMPTY_COLUMNS:
        if control[name] != "":
            raise ConnectorCaptureError("verify", "exact-count control row contains source data")
    if exact_total > request.max_hits:
        raise ConnectorCaptureError(
            "verify",
            "exact alert count exceeds the request safety limit",
        )
    if len(results) != exact_total + 1:
        raise ConnectorCaptureError(
            "verify",
            "response does not close over its exact server-side count",
        )

    start_ticks = _window_ticks(request.window.start)
    end_ticks = _window_ticks(request.window.end)
    records: list[dict[str, Any]] = []
    previous_key: tuple[str, ...] | None = None
    for index, raw in enumerate(results[1:]):
        row = _exact_dict(
            raw,
            label=f"alert row {index}",
            required=_RESULT_KEYS,
        )
        if row["ControlAssuranceKind"] != "record" or row["ControlAssuranceTotal"] != "":
            raise ConnectorCaptureError("verify", "alert row has invalid control fields")
        values: dict[str, str] = {}
        for name in _ALERT_COLUMNS:
            values[name] = _exact_text(
                row[name],
                label=f"alert row {index} {name}",
                maximum=MAX_FIELD_VALUE_BYTES,
                allow_empty=name != "AlertId" and name != "Timestamp",
            )
        timestamp_ticks, timestamp_text = _parse_alert_timestamp(
            values["Timestamp"],
            label=f"alert row {index} Timestamp",
        )
        if timestamp_ticks < start_ticks or timestamp_ticks >= end_ticks:
            raise ConnectorCaptureError(
                "verify",
                "alert timestamp falls outside the requested half-open window",
            )
        values["Timestamp"] = timestamp_text
        order_key = tuple(values[name] for name in _ALERT_COLUMNS)
        if previous_key is not None and order_key < previous_key:
            raise ConnectorCaptureError(
                "verify",
                "alert rows are not in the query's deterministic order",
            )
        previous_key = order_key
        records.append(
            {
                "fields": values,
                "id": f"defender-xdr-alert:{index:012d}",
            }
        )
    return records


def verify_defender_xdr_capture(
    receipt_bytes: bytes,
    *,
    expected_endpoint_origin_digest: str,
    expected_request: DefenderXDRRequest,
    expected_connector_version: str = __version__,
) -> VerifiedConnectorCapture:
    """Rebuild canonical AlertInfo records from one exact Graph exchange.

    The verifier does not consume a collector-supplied verdict or count.  It
    reconstructs the fixed KQL and Timespan body, checks all external anchors,
    and requires the server-side control count to close exactly over the
    returned records.  This establishes receipt-internal consistency, not
    source authenticity.
    """

    if type(receipt_bytes) is not bytes or not receipt_bytes:
        raise ConnectorCaptureError("verify", "receipt must be non-empty immutable bytes")
    expected_origin = _validate_digest(
        expected_endpoint_origin_digest,
        label="expected endpoint origin digest",
    )
    if type(expected_request) is not DefenderXDRRequest:
        raise TypeError("expected request must be an exact DefenderXDRRequest")
    if (
        type(expected_connector_version) is not str
        or not expected_connector_version
        or len(expected_connector_version) > 64
        or not expected_connector_version.isascii()
    ):
        raise ValueError("expected connector version must be bounded non-empty ASCII")
    try:
        parsed = strict_json_loads(receipt_bytes, limits=_RECEIPT_LIMITS)
    except StrictJSONError as exc:
        raise ConnectorCaptureError("verify", "receipt is not strict bounded JSON") from exc
    try:
        canonical = canonical_json_bytes(parsed, limits=_RECEIPT_LIMITS)
    except StrictJSONError as exc:
        raise ConnectorCaptureError(
            "verify",
            "receipt exceeds the canonical evidence profile",
        ) from exc
    if canonical != receipt_bytes:
        raise ConnectorCaptureError("verify", "receipt is not canonical JSON")
    root = _exact_dict(
        parsed,
        label="Defender XDR capture",
        required=frozenset(
            {
                "connector",
                "endpoint_origin_digest",
                "exchanges",
                "media_type",
                "request",
                "schema_version",
                "source_profile",
                "timing",
            }
        ),
    )
    if (
        root["media_type"] != DEFENDER_XDR_CAPTURE_MEDIA_TYPE
        or root["schema_version"] != DEFENDER_XDR_CAPTURE_SCHEMA_VERSION
    ):
        raise ConnectorCaptureError("verify", "receipt has the wrong profile identity")
    observed_origin = _validate_digest(
        root["endpoint_origin_digest"],
        label="endpoint origin digest",
    )
    if observed_origin != expected_origin:
        raise ConnectorCaptureError("verify", "receipt came from a different source origin")
    connector = _exact_dict(
        root["connector"],
        label="connector identity",
        required=frozenset({"id", "version"}),
    )
    if connector["id"] != DEFENDER_XDR_CONNECTOR_ID:
        raise ConnectorCaptureError("verify", "receipt names a different connector")
    connector_version = _exact_text(
        connector["version"],
        label="connector version",
        maximum=64,
    )
    if connector_version != expected_connector_version:
        raise ConnectorCaptureError(
            "verify",
            "connector version is not the expected implementation",
        )
    source_profile = _exact_dict(
        root["source_profile"],
        label="source profile",
        required=frozenset({"api", "permission", "table"}),
    )
    if source_profile != {
        "api": "Microsoft Graph v1.0",
        "permission": DEFENDER_XDR_REQUIRED_PERMISSION,
        "table": "AlertInfo",
    }:
        raise ConnectorCaptureError("verify", "receipt source profile was substituted")
    request = _parse_request(root["request"])
    if request.as_json() != expected_request.as_json():
        raise ConnectorCaptureError("verify", "receipt request is not the externally expected job")
    _parse_capture_timing(root["timing"])
    exchanges = _exact_array(root["exchanges"], label="Graph exchanges", maximum=1)
    if len(exchanges) != 1:
        raise ConnectorCaptureError("verify", "receipt must contain exactly one Graph exchange")
    exchange = _exact_dict(
        exchanges[0],
        label="Graph exchange",
        required=frozenset({"operation", "request", "response", "sequence"}),
    )
    if exchange["operation"] != "run-hunting-query" or exchange["sequence"] != 0:
        raise ConnectorCaptureError("verify", "Graph exchange lifecycle was substituted")
    method, target, headers, body = _request_from_exchange(
        exchange["request"],
        label="Graph exchange",
    )
    if (
        method != "POST"
        or target != _HUNTING_TARGET
        or headers != _REQUEST_HEADERS
        or body != _request_body(request)
    ):
        raise ConnectorCaptureError("verify", "Graph hunting request was substituted")
    response = _response_from_exchange(
        exchange["response"],
        label="Graph exchange",
    )
    records = _parse_hunting_results(response, request=request)
    try:
        records_jsonl = canonical_jsonl_bytes(records, limits=_RECORD_LIMITS)
    except StrictJSONError as exc:
        raise ConnectorCaptureError(
            "verify",
            "derived records exceed the canonical evidence profile",
        ) from exc
    descriptor = ConnectorDescriptor(
        connector_id=DEFENDER_XDR_CONNECTOR_ID,
        connector_version=connector_version,
        capture_media_type=DEFENDER_XDR_CAPTURE_MEDIA_TYPE,
    )
    return VerifiedConnectorCapture(
        descriptor=descriptor,
        receipt_digest=_sha256(receipt_bytes),
        records_jsonl=records_jsonl,
        records_digest=_sha256(records_jsonl),
        record_count=len(records),
        source_locator_digest=observed_origin,
        source_product="Microsoft Defender XDR",
        source_version=None,
    )
