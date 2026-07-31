"""Fail-closed, read-only capture of Elastic Security alert evidence.

The connector deliberately uses the Elasticsearch REST API directly so the
receipt can retain the exact JSON request and response bytes.  It opens one
point-in-time (PIT), walks it with ``search_after``, requires exact total-hit
counts, and closes the latest PIT before returning.  Search responses are
server-filtered to the explicitly selected fields; document ids and the
Authorization header never enter the receipt.

This is a bounded reference connector.  It does not change alert state, create
rules, isolate endpoints, retry ambiguous requests, or claim that Elasticsearch
cryptographically attested to the returned bytes.
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
from typing import Any, Final, Literal, Protocol, cast

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

ELASTIC_SECURITY_CAPTURE_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.elastic-security-capture.v1+json"]
] = "application/vnd.control-assurance.elastic-security-capture.v1+json"
ELASTIC_SECURITY_CAPTURE_SCHEMA_VERSION: Final[Literal["1.0.0"]] = "1.0.0"
ELASTIC_SECURITY_CONNECTOR_ID: Final[Literal["elastic-security-readonly"]] = (
    "elastic-security-readonly"
)

DEFAULT_ALERT_INDEX = ".alerts-security.alerts-default"
DEFAULT_FIELDS = (
    "@timestamp",
    "kibana.alert.risk_score",
    "kibana.alert.rule.name",
    "kibana.alert.rule.uuid",
    "kibana.alert.severity",
    "kibana.alert.status",
    "kibana.alert.workflow_status",
)

MAX_API_KEY_BYTES = 4_096
MAX_FIELDS = 32
MAX_FILTER_VALUES = 256
MAX_PAGE_SIZE = 1_000
MAX_HITS = 100_000
MAX_PAGES = 10_001
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_RECEIPT_BYTES = 96 * 1024 * 1024
MAX_RECORD_BYTES = 64 * 1024 * 1024
MAX_FIELD_VALUE_BYTES = 1024 * 1024
MIN_KEEP_ALIVE_SECONDS = 15
MAX_KEEP_ALIVE_SECONDS = 300
MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 120
MIN_CAPTURE_TIMEOUT_SECONDS = 5
MAX_CAPTURE_TIMEOUT_SECONDS = 3_600
MAX_CLEANUP_SECONDS = 15
MAX_TIMING_MICROSECONDS = (MAX_CAPTURE_TIMEOUT_SECONDS + MAX_CLEANUP_SECONDS) * 1_000_000

_ALERT_INDEX_RE = re.compile(r"^[.]alerts-security[.]alerts-[a-z0-9][a-z0-9_-]{0,63}$")
_FIELD_RE = re.compile(r"^(?:@timestamp|[A-Za-z][A-Za-z0-9_.]{0,127})$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_CAPTURE_ID_RE = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_CAPTURE_NONCE_RE = re.compile(r"^[a-f0-9]{64}$")
_API_KEY_RE = re.compile(rb"^[A-Za-z0-9_+/=-]+$")
_UTC_NANOS_RE = re.compile(
    r"^(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})T"
    r"(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?P<fraction>[.][0-9]{1,9})?Z$"
)
_WORKFLOW_STATUSES = frozenset({"acknowledged", "closed", "open"})
_ALERT_STATUSES = frozenset({"active", "recovered"})
_SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_CAPTURE_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{6}Z$"
)

_RESPONSE_LIMITS = JSONLimits(
    max_bytes=MAX_RESPONSE_BYTES,
    max_line_bytes=MAX_RESPONSE_BYTES,
    max_depth=16,
    max_collection_items=100_000,
    max_string_length=MAX_FIELD_VALUE_BYTES,
)
_RECEIPT_LIMITS = JSONLimits(
    max_bytes=MAX_RECEIPT_BYTES,
    max_line_bytes=MAX_RECEIPT_BYTES,
    max_depth=32,
    max_collection_items=200_000,
    max_string_length=MAX_RESPONSE_BYTES * 2,
)
_RECORD_LIMITS = JSONLimits(
    max_bytes=MAX_RECORD_BYTES,
    max_line_bytes=2 * 1024 * 1024,
    max_depth=16,
    max_collection_items=200_000,
    max_string_length=MAX_FIELD_VALUE_BYTES,
)

_SEARCH_TARGET = (
    "/_search?filter_path="
    "pit_id%2Ctimed_out%2C_shards%2Chits.total%2Chits.hits.sort%2Chits.hits.fields"
)
_CLOSE_TARGET = "/_pit?filter_path=succeeded%2Cnum_freed"
_JSON_HEADERS = (
    ("accept", "application/json"),
    ("accept-encoding", "identity"),
    ("content-type", "application/json"),
)
_RECORDED_RESPONSE_HEADERS = ("content-type", "x-elastic-product")


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def new_capture_nonce() -> str:
    """Return a fresh 256-bit replay-binding nonce for one connector request."""

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


def _exact_text(value: object, *, label: str, maximum: int) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        raise ConnectorCaptureError("verify", f"{label} is absent or too long")
    return value


def _parse_timestamp(value: object, *, label: str) -> tuple[int, str]:
    text = _exact_text(value, label=label, maximum=40)
    match = _UTC_NANOS_RE.fullmatch(text)
    if match is None:
        raise ConnectorCaptureError("verify", f"{label} is not canonical UTC date_nanos")
    try:
        whole = datetime.strptime(
            f"{match.group('date')}T{match.group('time')}Z",
            "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=UTC)
    except ValueError as exc:
        raise ConnectorCaptureError("verify", f"{label} is not a real UTC instant") from exc
    fraction = (match.group("fraction") or ".0")[1:].ljust(9, "0")
    seconds = int(whole.timestamp())
    return (seconds * 1_000_000_000) + int(fraction), text


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


def _validate_digest(value: object, *, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ConnectorCaptureError("verify", f"{label} is not a canonical SHA-256 digest")
    return value


@dataclass(frozen=True, slots=True)
class ElasticSecurityRequest:
    """One bounded, half-open alert collection request."""

    capture_id: str
    window: ConnectorWindow
    capture_nonce: str
    index_alias: str = DEFAULT_ALERT_INDEX
    fields: tuple[str, ...] = DEFAULT_FIELDS
    rule_uuids: tuple[str, ...] = ()
    workflow_statuses: tuple[str, ...] = ()
    alert_statuses: tuple[str, ...] = ()
    page_size: int = 500
    max_hits: int = 10_000
    keep_alive_seconds: int = 60

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
        if type(self.index_alias) is not str or _ALERT_INDEX_RE.fullmatch(self.index_alias) is None:
            raise ValueError("index alias is not an exact Elastic Security alert alias")
        fields = _sorted_unique_text(
            self.fields,
            label="fields",
            maximum=MAX_FIELDS,
            pattern=_FIELD_RE,
        )
        if "@timestamp" not in fields:
            raise ValueError("selected fields must include @timestamp")
        object.__setattr__(self, "fields", fields)
        object.__setattr__(
            self,
            "rule_uuids",
            _sorted_unique_text(
                self.rule_uuids,
                label="rule UUIDs",
                maximum=MAX_FILTER_VALUES,
                pattern=_UUID_RE,
            ),
        )
        object.__setattr__(
            self,
            "workflow_statuses",
            _sorted_enum_values(
                self.workflow_statuses,
                label="workflow statuses",
                allowed=_WORKFLOW_STATUSES,
            ),
        )
        object.__setattr__(
            self,
            "alert_statuses",
            _sorted_enum_values(
                self.alert_statuses,
                label="alert statuses",
                allowed=_ALERT_STATUSES,
            ),
        )
        if type(self.page_size) is not int or self.page_size < 1 or self.page_size > MAX_PAGE_SIZE:
            raise ValueError("page size is outside the connector profile")
        if (
            type(self.max_hits) is not int
            or self.max_hits < self.page_size
            or self.max_hits > MAX_HITS
        ):
            raise ValueError("max hits is outside the connector profile")
        if (
            type(self.keep_alive_seconds) is not int
            or self.keep_alive_seconds < MIN_KEEP_ALIVE_SECONDS
            or self.keep_alive_seconds > MAX_KEEP_ALIVE_SECONDS
        ):
            raise ValueError("PIT keep-alive is outside the connector profile")

    def as_json(self) -> dict[str, Any]:
        return {
            "alert_statuses": list(self.alert_statuses),
            "capture_id": self.capture_id,
            "capture_nonce": self.capture_nonce,
            "fields": list(self.fields),
            "index_alias": self.index_alias,
            "keep_alive_seconds": self.keep_alive_seconds,
            "max_hits": self.max_hits,
            "page_size": self.page_size,
            "rule_uuids": list(self.rule_uuids),
            "window": self.window.as_json(),
            "workflow_statuses": list(self.workflow_statuses),
        }


def _sorted_unique_text(
    values: object,
    *,
    label: str,
    maximum: int,
    pattern: re.Pattern[str],
) -> tuple[str, ...]:
    if type(values) is not tuple or len(values) > maximum:
        raise ValueError(f"{label} must be a tuple with at most {maximum} values")
    if any(type(value) is not str or pattern.fullmatch(value) is None for value in values):
        raise ValueError(f"{label} contains an invalid value")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} contains duplicate values")
    return tuple(sorted(values))


def _sorted_enum_values(
    values: object,
    *,
    label: str,
    allowed: frozenset[str],
) -> tuple[str, ...]:
    if type(values) is not tuple or len(values) > len(allowed):
        raise ValueError(f"{label} must be a bounded tuple")
    if any(type(value) is not str or value not in allowed for value in values):
        raise ValueError(f"{label} contains an unsupported value")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} contains duplicates")
    return tuple(sorted(values))


class ElasticApiKey:
    """Opaque API-key bytes whose representations are always redacted.

    Python cannot guarantee that immutable secret bytes are zeroized.  The
    object merely keeps the key out of connector receipts, logs, exceptions,
    equality output, and ``repr``/``str``.
    """

    __slots__ = ("__value",)

    def __init__(self, value: bytes) -> None:
        if (
            type(value) is not bytes
            or not value
            or len(value) > MAX_API_KEY_BYTES
            or _API_KEY_RE.fullmatch(value) is None
        ):
            raise ValueError("Elastic API key must be bounded base64-like ASCII bytes")
        self.__value = value

    def __repr__(self) -> str:
        return "ElasticApiKey(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"

    def _authorization_header(self) -> str:
        return f"ApiKey {self.__value.decode('ascii', errors='strict')}"

    def _appears_in(self, value: bytes) -> bool:
        escaped = self.__value.replace(b"/", b"\\/")
        quoted = urllib.parse.quote_from_bytes(self.__value).encode("ascii")
        return any(candidate in value for candidate in (self.__value, escaped, quoted))


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
        return None


class _UrllibTransport:
    __slots__ = ("_api_key", "_endpoint", "_opener", "_timeout_seconds")

    def __init__(
        self,
        *,
        endpoint: str,
        api_key: ElasticApiKey,
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
        self._api_key = api_key
        self._timeout_seconds = timeout_seconds

    def request(
        self,
        *,
        method: str,
        target: str,
        body: bytes,
        headers: tuple[tuple[str, str], ...],
        deadline: float,
    ) -> _HTTPResponse:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ConnectorCaptureError("deadline", "capture deadline expired")
        request_headers = {name: value for name, value in headers}
        request_headers["authorization"] = self._api_key._authorization_header()
        request = urllib.request.Request(
            f"{self._endpoint}{target}",
            data=body if body else None,
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
            raise ConnectorCaptureError("transport", "Elasticsearch request timed out") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise ConnectorCaptureError(
                "transport",
                "Elasticsearch request could not be completed",
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
                        "Elasticsearch response exceeds the connector byte limit",
                    )
            payload = bytes(content)
            selected: list[tuple[str, str]] = []
            for name in _RECORDED_RESPONSE_HEADERS:
                values = response.headers.get_all(name, [])
                if len(values) > 1:
                    raise ConnectorCaptureError(
                        "transport",
                        f"Elasticsearch returned duplicate {name} headers",
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
            if self._api_key._appears_in(reflected):
                raise ConnectorCaptureError(
                    "transport",
                    "Elasticsearch response reflected credential material",
                )
            return _HTTPResponse(
                status=int(response.status),
                headers=tuple(selected),
                body=payload,
            )
        except (OSError, http.client.HTTPException) as exc:
            raise ConnectorCaptureError(
                "transport",
                "Elasticsearch response could not be read completely",
            ) from exc
        finally:
            response.close()


def _normalize_endpoint(
    endpoint: str,
    *,
    allow_insecure_loopback: bool,
) -> tuple[str, bool]:
    if type(endpoint) is not str or len(endpoint) > 2_048:
        raise ValueError("Elasticsearch endpoint is absent or too long")
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
        raise ValueError("Elasticsearch endpoint must be an origin without credentials or path")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Elasticsearch endpoint port is invalid") from exc
    if parsed.scheme == "http":
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError as exc:
            raise ValueError("plain HTTP is restricted to a literal loopback address") from exc
        if not allow_insecure_loopback or not address.is_loopback:
            raise ValueError("plain HTTP requires explicit loopback lab mode")
    host = parsed.hostname.lower()
    rendered_host = f"[{host}]" if ":" in host else host
    default_port = 443 if parsed.scheme == "https" else 80
    authority = rendered_host if port in {None, default_port} else f"{rendered_host}:{port}"
    return f"{parsed.scheme}://{authority}", parsed.scheme == "https"


def elastic_endpoint_origin_digest(
    endpoint: str,
    *,
    allow_insecure_loopback: bool = False,
) -> str:
    """Return the privacy-preserving source locator expected by a verifier."""

    normalized, _ = _normalize_endpoint(
        endpoint,
        allow_insecure_loopback=allow_insecure_loopback,
    )
    return _sha256(normalized.encode("utf-8"))


def _ssl_context(ca_file: Path | None) -> ssl.SSLContext:
    if ca_file is None:
        return ssl.create_default_context()
    if not isinstance(ca_file, Path):
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
        if (
            len(content) > (8 * 1024 * 1024)
            or len(content) != after.st_size
            or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_nlink,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_nlink,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
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


def _open_target(request: ElasticSecurityRequest) -> str:
    encoded_index = urllib.parse.quote(request.index_alias, safe=".-_")
    query = urllib.parse.urlencode(
        (
            ("allow_partial_search_results", "false"),
            ("filter_path", "id,_shards"),
            ("keep_alive", f"{request.keep_alive_seconds}s"),
        )
    )
    return f"/{encoded_index}/_pit?{query}"


def _query_json(request: ElasticSecurityRequest) -> dict[str, Any]:
    filters: list[dict[str, Any]] = [
        {
            "range": {
                "@timestamp": {
                    "format": "strict_date_optional_time",
                    "gte": canonical_timestamp(request.window.start),
                    "lt": canonical_timestamp(request.window.end),
                }
            }
        }
    ]
    if request.rule_uuids:
        filters.append({"terms": {"kibana.alert.rule.uuid": list(request.rule_uuids)}})
    if request.workflow_statuses:
        filters.append({"terms": {"kibana.alert.workflow_status": list(request.workflow_statuses)}})
    if request.alert_statuses:
        filters.append({"terms": {"kibana.alert.status": list(request.alert_statuses)}})
    return {"bool": {"filter": filters}}


def _search_body(
    request: ElasticSecurityRequest,
    *,
    pit_id: str,
    search_after: list[Any] | None,
) -> bytes:
    body: dict[str, Any] = {
        "_source": False,
        "fields": list(request.fields),
        "pit": {
            "id": pit_id,
            "keep_alive": f"{request.keep_alive_seconds}s",
        },
        "query": _query_json(request),
        "size": request.page_size,
        "sort": [
            {
                "@timestamp": {
                    "format": "strict_date_optional_time_nanos",
                    "numeric_type": "date_nanos",
                    "order": "asc",
                }
            },
            {"_shard_doc": "asc"},
        ],
        "track_total_hits": True,
    }
    if search_after is not None:
        body["search_after"] = search_after
    return canonical_json_bytes(body, limits=_RESPONSE_LIMITS)


def _exchange(
    *,
    sequence: int,
    operation: str,
    method: str,
    target: str,
    request_headers: tuple[tuple[str, str], ...],
    request_body: bytes,
    response: _HTTPResponse,
) -> dict[str, Any]:
    return {
        "operation": operation,
        "request": {
            "body_base64": _base64(request_body),
            "body_digest": _sha256(request_body),
            "headers": [list(pair) for pair in request_headers],
            "method": method,
            "target": target,
        },
        "response": {
            "body_base64": _base64(response.body),
            "body_digest": _sha256(response.body),
            "headers": [list(pair) for pair in response.headers],
            "status": response.status,
        },
        "sequence": sequence,
    }


class ElasticSecurityConnector:
    """Capture an exact Elastic Security alert window without mutating it."""

    __slots__ = (
        "_capture_timeout_seconds",
        "_descriptor",
        "_endpoint_digest",
        "_request_timeout_seconds",
        "_transport",
    )

    def __init__(
        self,
        endpoint: str,
        api_key: ElasticApiKey,
        *,
        ca_file: Path | None = None,
        allow_insecure_loopback: bool = False,
        timeout_seconds: int = 15,
        capture_timeout_seconds: int = 300,
        _transport: _HTTPTransport | None = None,
    ) -> None:
        if type(api_key) is not ElasticApiKey:
            raise TypeError("api key must be an exact ElasticApiKey")
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
            connector_id=ELASTIC_SECURITY_CONNECTOR_ID,
            connector_version=__version__,
            capture_media_type=ELASTIC_SECURITY_CAPTURE_MEDIA_TYPE,
        )
        self._endpoint_digest = _sha256(normalized.encode("utf-8"))
        self._request_timeout_seconds = timeout_seconds
        self._capture_timeout_seconds = capture_timeout_seconds
        self._transport = _transport or _UrllibTransport(
            endpoint=normalized,
            api_key=api_key,
            timeout_seconds=timeout_seconds,
            ssl_context=context,
        )

    @property
    def descriptor(self) -> ConnectorDescriptor:
        return self._descriptor

    def _request(
        self,
        *,
        method: str,
        target: str,
        body: bytes,
        headers: tuple[tuple[str, str], ...],
        stage: str,
        deadline: float,
    ) -> _HTTPResponse:
        if time.monotonic() >= deadline:
            raise ConnectorCaptureError("deadline", "capture deadline expired")
        response = self._transport.request(
            method=method,
            target=target,
            body=body,
            headers=headers,
            deadline=deadline,
        )
        if type(response) is not _HTTPResponse:
            raise ConnectorCaptureError(stage, "transport returned an invalid response object")
        if response.status != 200:
            raise ConnectorCaptureError(stage, f"Elasticsearch returned HTTP {response.status}")
        return response

    def capture(self, request: object) -> ConnectorCapture:
        if type(request) is not ElasticSecurityRequest:
            raise TypeError("request must be an exact ElasticSecurityRequest")
        started_at = datetime.now(UTC)
        started_monotonic = time.monotonic()
        deadline = started_monotonic + self._capture_timeout_seconds
        exchanges: list[dict[str, Any]] = []
        total_response_bytes = 0
        collection_error: ConnectorCaptureError | None = None
        cleanup_error: ConnectorCaptureError | None = None
        close_response: _HTTPResponse | None = None
        pit_id: str | None = None

        open_target = _open_target(request)
        try:
            opened = self._request(
                method="POST",
                target=open_target,
                body=b"",
                headers=_JSON_HEADERS,
                stage="open-pit",
                deadline=deadline,
            )
            total_response_bytes += len(opened.body)
            exchanges.append(
                _exchange(
                    sequence=0,
                    operation="open-pit",
                    method="POST",
                    target=open_target,
                    request_headers=_JSON_HEADERS,
                    request_body=b"",
                    response=opened,
                )
            )
            # Claim cleanup ownership before validating product markers, shard
            # accounting, or the remainder of the open response.
            pit_id = _extract_pit_id(opened, member="id")
            opened_json = _parse_open_response(opened, stage="open-pit")
            pit_id = cast(str, opened_json["id"])
            search_after: list[Any] | None = None
            expected_total: int | None = None
            observed = 0
            page_number = 0
            while True:
                if page_number >= MAX_PAGES:
                    raise ConnectorCaptureError("search", "page count exceeds the connector limit")
                assert pit_id is not None
                body = _search_body(request, pit_id=pit_id, search_after=search_after)
                response = self._request(
                    method="POST",
                    target=_SEARCH_TARGET,
                    body=body,
                    headers=_JSON_HEADERS,
                    stage="search",
                    deadline=deadline,
                )
                total_response_bytes += len(response.body)
                if total_response_bytes > MAX_TOTAL_RESPONSE_BYTES:
                    raise ConnectorCaptureError(
                        "search",
                        "combined Elasticsearch responses exceed the capture limit",
                    )
                exchanges.append(
                    _exchange(
                        sequence=len(exchanges),
                        operation="search-page",
                        method="POST",
                        target=_SEARCH_TARGET,
                        request_headers=_JSON_HEADERS,
                        request_body=body,
                        response=response,
                    )
                )
                # Elasticsearch can rotate the PIT id even on a response whose
                # search result must later be rejected.  Close the newest id.
                next_pit = _extract_pit_id(response, member="pit_id")
                if next_pit is not None:
                    pit_id = next_pit
                parsed, next_pit, next_cursor, hit_count, page_total = _parse_search_response(
                    response,
                    request=request,
                )
                del parsed
                pit_id = next_pit or pit_id
                if expected_total is None:
                    expected_total = page_total
                    if expected_total > request.max_hits:
                        raise ConnectorCaptureError(
                            "search",
                            "exact hit count exceeds the requested safety limit",
                        )
                elif page_total != expected_total:
                    raise ConnectorCaptureError("search", "exact hit count changed inside the PIT")
                if hit_count == 0:
                    if observed != expected_total:
                        raise ConnectorCaptureError(
                            "search",
                            "search ended before the exact total was observed",
                        )
                    break
                if next_cursor is None:
                    raise ConnectorCaptureError(
                        "search",
                        "non-empty page has no continuation cursor",
                    )
                observed += hit_count
                if observed > expected_total:
                    raise ConnectorCaptureError(
                        "search",
                        "search returned more than its exact total",
                    )
                search_after = next_cursor
                page_number += 1
        except ConnectorCaptureError as exc:
            collection_error = exc
        except (StrictJSONError, OverflowError, TypeError, ValueError) as exc:
            collection_error = ConnectorCaptureError(
                "capture",
                "connector data could not be represented safely",
            )
            collection_error.__cause__ = exc
        finally:
            if pit_id is not None:
                try:
                    close_body = canonical_json_bytes(
                        {"id": pit_id},
                        limits=_RESPONSE_LIMITS,
                    )
                    cleanup_deadline = time.monotonic() + min(
                        self._request_timeout_seconds,
                        MAX_CLEANUP_SECONDS,
                    )
                    close_response = self._request(
                        method="DELETE",
                        target=_CLOSE_TARGET,
                        body=close_body,
                        headers=_JSON_HEADERS,
                        stage="close-pit",
                        deadline=cleanup_deadline,
                    )
                    total_response_bytes += len(close_response.body)
                    if total_response_bytes > MAX_TOTAL_RESPONSE_BYTES:
                        raise ConnectorCaptureError(
                            "close-pit",
                            "combined Elasticsearch responses exceed the capture limit",
                        )
                    exchanges.append(
                        _exchange(
                            sequence=len(exchanges),
                            operation="close-pit",
                            method="DELETE",
                            target=_CLOSE_TARGET,
                            request_headers=_JSON_HEADERS,
                            request_body=close_body,
                            response=close_response,
                        )
                    )
                    _parse_close_response(close_response)
                except ConnectorCaptureError as exc:
                    cleanup_error = exc
                except (StrictJSONError, OverflowError, TypeError, ValueError) as exc:
                    cleanup_error = ConnectorCaptureError(
                        "cleanup",
                        "PIT cleanup could not be represented or confirmed safely",
                    )
                    cleanup_error.__cause__ = exc

        if collection_error is not None and cleanup_error is not None:
            raise ConnectorCaptureError(
                "cleanup",
                "collection failed and the latest PIT could not be confirmed closed",
            ) from cleanup_error
        if cleanup_error is not None:
            raise cleanup_error
        if collection_error is not None:
            raise collection_error
        assert close_response is not None

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
            "exchanges": exchanges,
            "media_type": ELASTIC_SECURITY_CAPTURE_MEDIA_TYPE,
            "request": request.as_json(),
            "schema_version": ELASTIC_SECURITY_CAPTURE_SCHEMA_VERSION,
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
        verified = verify_elastic_security_capture(
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


def _require_json_response(
    response: _HTTPResponse,
    *,
    stage: str,
) -> dict[str, Any]:
    headers = dict(response.headers)
    if headers.get("x-elastic-product") != "Elasticsearch":
        raise ConnectorCaptureError(stage, "response lacks the Elasticsearch product marker")
    content_type = headers.get("content-type", "")
    if content_type.split(";", 1)[0].strip().lower() != "application/json":
        raise ConnectorCaptureError(stage, "response is not application/json")
    if response.status != 200:
        raise ConnectorCaptureError(stage, f"Elasticsearch returned HTTP {response.status}")
    try:
        parsed = strict_json_loads(response.body, limits=_RESPONSE_LIMITS)
    except StrictJSONError as exc:
        raise ConnectorCaptureError(stage, "response is not strict bounded JSON") from exc
    if not isinstance(parsed, dict):
        raise ConnectorCaptureError(stage, "response JSON is not an object")
    return cast(dict[str, Any], parsed)


def _parse_shards(value: object, *, stage: str) -> None:
    shards = _exact_dict(
        value,
        label=f"{stage} shards",
        required=frozenset({"failed", "successful", "total"}),
        optional=frozenset({"failures", "skipped"}),
    )
    total = _exact_int(shards["total"], label=f"{stage} total shards", minimum=0, maximum=10**9)
    successful = _exact_int(
        shards["successful"],
        label=f"{stage} successful shards",
        minimum=0,
        maximum=total,
    )
    failed = _exact_int(
        shards["failed"],
        label=f"{stage} failed shards",
        minimum=0,
        maximum=total,
    )
    skipped = _exact_int(
        shards.get("skipped", 0),
        label=f"{stage} skipped shards",
        minimum=0,
        maximum=total,
    )
    if failed != 0 or "failures" in shards:
        raise ConnectorCaptureError(stage, "Elasticsearch reported a shard failure")
    if successful + skipped != total:
        raise ConnectorCaptureError(stage, "shard accounting is incomplete")


def _parse_open_response(response: _HTTPResponse, *, stage: str) -> dict[str, Any]:
    parsed = _require_json_response(response, stage=stage)
    result = _exact_dict(
        parsed,
        label="open PIT response",
        required=frozenset({"_shards", "id"}),
    )
    _exact_text(result["id"], label="PIT id", maximum=16_384)
    _parse_shards(result["_shards"], stage=stage)
    return result


def _extract_pit_id(response: _HTTPResponse, *, member: str) -> str | None:
    """Best-effort extraction used only to acquire cleanup ownership.

    The caller must still run the full response parser.  This intentionally
    ignores HTTP metadata so a product-marker or shard-accounting failure
    cannot leak a PIT that Elasticsearch already created or rotated.
    """

    if member not in {"id", "pit_id"}:
        raise ValueError("unsupported PIT response member")
    try:
        parsed = strict_json_loads(response.body, limits=_RESPONSE_LIMITS)
    except StrictJSONError:
        return None
    if not isinstance(parsed, dict):
        return None
    value = parsed.get(member)
    if type(value) is not str or not value or len(value) > 16_384:
        return None
    return value


def _parse_search_response(
    response: _HTTPResponse,
    *,
    request: ElasticSecurityRequest,
) -> tuple[dict[str, Any], str | None, list[Any] | None, int, int]:
    parsed = _require_json_response(response, stage="search")
    root = _exact_dict(
        parsed,
        label="search response",
        required=frozenset({"_shards", "hits", "timed_out"}),
        optional=frozenset({"pit_id"}),
    )
    if type(root["timed_out"]) is not bool or root["timed_out"]:
        raise ConnectorCaptureError("search", "Elasticsearch search timed out")
    _parse_shards(root["_shards"], stage="search")
    hits_root = _exact_dict(
        root["hits"],
        label="search hits",
        required=frozenset({"total"}),
        optional=frozenset({"hits"}),
    )
    total = _exact_dict(
        hits_root["total"],
        label="search total",
        required=frozenset({"relation", "value"}),
    )
    if total["relation"] != "eq":
        raise ConnectorCaptureError("search", "Elasticsearch did not return an exact hit count")
    total_value = _exact_int(
        total["value"],
        label="exact hit count",
        minimum=0,
        maximum=MAX_HITS + 1,
    )
    hits = _exact_array(
        hits_root.get("hits", []),
        label="search page",
        maximum=request.page_size,
    )
    start_ns, _ = _parse_timestamp(
        canonical_timestamp(request.window.start),
        label="request window start",
    )
    end_ns, _ = _parse_timestamp(
        canonical_timestamp(request.window.end),
        label="request window end",
    )
    previous: tuple[int, int] | None = None
    last_cursor: list[Any] | None = None
    for index, raw_hit in enumerate(hits):
        hit = _exact_dict(
            raw_hit,
            label=f"search hit {index}",
            required=frozenset({"sort"}),
            optional=frozenset({"fields"}),
        )
        sort_values = _exact_array(hit["sort"], label=f"search hit {index} sort", maximum=2)
        if len(sort_values) != 2:
            raise ConnectorCaptureError("search", "search cursor does not have two values")
        timestamp_ns, timestamp_text = _parse_timestamp(
            sort_values[0],
            label=f"search hit {index} timestamp cursor",
        )
        if timestamp_ns < start_ns or timestamp_ns >= end_ns:
            raise ConnectorCaptureError(
                "search",
                "search hit timestamp is outside the requested half-open window",
            )
        shard_doc = _exact_int(
            sort_values[1],
            label=f"search hit {index} shard cursor",
            minimum=0,
            maximum=(2**53) - 1,
        )
        cursor = (timestamp_ns, shard_doc)
        if previous is not None and cursor <= previous:
            raise ConnectorCaptureError("search", "search cursors are not strictly increasing")
        previous = cursor
        last_cursor = [sort_values[0], sort_values[1]]
        fields = hit.get("fields", {})
        if not isinstance(fields, dict):
            raise ConnectorCaptureError("search", "search hit fields are not an object")
        if any(type(name) is not str or name not in request.fields for name in fields):
            raise ConnectorCaptureError("search", "search returned a field outside the allowlist")
        timestamp_field = fields.get("@timestamp")
        if (
            not isinstance(timestamp_field, list)
            or len(timestamp_field) != 1
            or timestamp_field[0] != timestamp_text
        ):
            raise ConnectorCaptureError(
                "search",
                "search hit @timestamp does not match its sort cursor",
            )
        # Re-encoding enforces bounded field trees and portable JSON values.
        try:
            canonical_json_bytes(fields, limits=_RESPONSE_LIMITS)
        except StrictJSONError as exc:
            raise ConnectorCaptureError(
                "search",
                "search hit fields exceed the canonical evidence profile",
            ) from exc
    pit_id: str | None = None
    if "pit_id" in root:
        pit_id = _exact_text(root["pit_id"], label="search PIT id", maximum=16_384)
    return root, pit_id, last_cursor, len(hits), total_value


def _parse_close_response(response: _HTTPResponse) -> dict[str, Any]:
    parsed = _require_json_response(response, stage="close-pit")
    result = _exact_dict(
        parsed,
        label="close PIT response",
        required=frozenset({"num_freed", "succeeded"}),
    )
    if type(result["succeeded"]) is not bool or not result["succeeded"]:
        raise ConnectorCaptureError("close-pit", "Elasticsearch did not confirm PIT closure")
    _exact_int(
        result["num_freed"],
        label="freed PIT contexts",
        minimum=0,
        maximum=10**9,
    )
    return result


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
    digest = _validate_digest(response["body_digest"], label=f"{label} response digest")
    if _sha256(body) != digest:
        raise ConnectorCaptureError("verify", f"{label} response digest does not match")
    status = _exact_int(
        response["status"],
        label=f"{label} response status",
        minimum=100,
        maximum=599,
    )
    headers = _canonical_headers(response["headers"], label=f"{label} response headers")
    if any(name not in _RECORDED_RESPONSE_HEADERS for name, _ in headers):
        raise ConnectorCaptureError("verify", f"{label} retained an unapproved response header")
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
        maximum=MAX_RESPONSE_BYTES,
    )
    digest = _validate_digest(request["body_digest"], label=f"{label} request digest")
    if _sha256(body) != digest:
        raise ConnectorCaptureError("verify", f"{label} request digest does not match")
    method = _exact_text(request["method"], label=f"{label} request method", maximum=16)
    target = _exact_text(request["target"], label=f"{label} request target", maximum=32_768)
    headers = _canonical_headers(request["headers"], label=f"{label} request headers")
    if any(name == "authorization" for name, _ in headers):
        raise ConnectorCaptureError("verify", "Authorization entered the connector receipt")
    return method, target, headers, body


def _parse_request(value: object) -> ElasticSecurityRequest:
    request = _exact_dict(
        value,
        label="connector request",
        required=frozenset(
            {
                "alert_statuses",
                "capture_id",
                "capture_nonce",
                "fields",
                "index_alias",
                "keep_alive_seconds",
                "max_hits",
                "page_size",
                "rule_uuids",
                "window",
                "workflow_statuses",
            }
        ),
    )
    window = _exact_dict(
        request["window"],
        label="connector window",
        required=frozenset({"end_exclusive", "start_inclusive"}),
    )
    start_text = _exact_text(
        window["start_inclusive"],
        label="window start",
        maximum=32,
    )
    end_text = _exact_text(window["end_exclusive"], label="window end", maximum=32)
    try:
        start = datetime.strptime(start_text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        end = datetime.strptime(end_text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ConnectorCaptureError("verify", "connector window is not whole-second UTC") from exc

    def text_tuple(name: str, maximum: int) -> tuple[str, ...]:
        values = _exact_array(request[name], label=name, maximum=maximum)
        if any(type(item) is not str for item in values):
            raise ConnectorCaptureError("verify", f"{name} is not a text array")
        return tuple(cast(list[str], values))

    try:
        return ElasticSecurityRequest(
            capture_id=cast(str, request["capture_id"]),
            window=ConnectorWindow(start=start, end=end),
            capture_nonce=cast(str, request["capture_nonce"]),
            index_alias=cast(str, request["index_alias"]),
            fields=text_tuple("fields", MAX_FIELDS),
            rule_uuids=text_tuple("rule_uuids", MAX_FILTER_VALUES),
            workflow_statuses=text_tuple("workflow_statuses", len(_WORKFLOW_STATUSES)),
            alert_statuses=text_tuple("alert_statuses", len(_ALERT_STATUSES)),
            page_size=cast(int, request["page_size"]),
            max_hits=cast(int, request["max_hits"]),
            keep_alive_seconds=cast(int, request["keep_alive_seconds"]),
        )
    except (TypeError, ValueError) as exc:
        raise ConnectorCaptureError("verify", "connector request is outside the profile") from exc


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


def verify_elastic_security_capture(
    receipt_bytes: bytes,
    *,
    expected_endpoint_origin_digest: str,
    expected_request: ElasticSecurityRequest,
    expected_connector_version: str = __version__,
) -> VerifiedConnectorCapture:
    """Rebuild the record stream from exact REST exchanges.

    No collector verdict or supplied record count is consumed.  The verifier
    reconstructs every request body, follows PIT-id and cursor lineage, checks
    exact shard/total accounting, and requires one final empty page followed by
    closure of the latest PIT.
    """

    if type(receipt_bytes) is not bytes or not receipt_bytes:
        raise ConnectorCaptureError("verify", "receipt must be non-empty immutable bytes")
    expected_origin = _validate_digest(
        expected_endpoint_origin_digest,
        label="expected endpoint origin digest",
    )
    if type(expected_request) is not ElasticSecurityRequest:
        raise TypeError("expected request must be an exact ElasticSecurityRequest")
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
        label="Elastic capture",
        required=frozenset(
            {
                "connector",
                "endpoint_origin_digest",
                "exchanges",
                "media_type",
                "request",
                "schema_version",
                "timing",
            }
        ),
    )
    if (
        root["media_type"] != ELASTIC_SECURITY_CAPTURE_MEDIA_TYPE
        or root["schema_version"] != ELASTIC_SECURITY_CAPTURE_SCHEMA_VERSION
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
    if connector["id"] != ELASTIC_SECURITY_CONNECTOR_ID:
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
    request = _parse_request(root["request"])
    if request.as_json() != expected_request.as_json():
        raise ConnectorCaptureError("verify", "receipt request is not the externally expected job")
    _parse_capture_timing(root["timing"])
    exchanges = _exact_array(root["exchanges"], label="REST exchanges", maximum=MAX_PAGES + 3)
    if len(exchanges) < 3:
        raise ConnectorCaptureError("verify", "receipt is missing lifecycle exchanges")

    records: list[dict[str, Any]] = []
    current_pit = ""
    previous_cursor: list[Any] | None = None
    previous_cursor_key: tuple[int, int] | None = None
    exact_total: int | None = None
    found_empty_page = False
    total_response_bytes = 0

    for sequence, raw_exchange in enumerate(exchanges):
        exchange = _exact_dict(
            raw_exchange,
            label=f"exchange {sequence}",
            required=frozenset({"operation", "request", "response", "sequence"}),
        )
        if exchange["sequence"] != sequence:
            raise ConnectorCaptureError("verify", "exchange sequence is not contiguous")
        operation = _exact_text(
            exchange["operation"],
            label=f"exchange {sequence} operation",
            maximum=32,
        )
        method, target, headers, body = _request_from_exchange(
            exchange["request"],
            label=f"exchange {sequence}",
        )
        response = _response_from_exchange(
            exchange["response"],
            label=f"exchange {sequence}",
        )
        total_response_bytes += len(response.body)
        if total_response_bytes > MAX_TOTAL_RESPONSE_BYTES:
            raise ConnectorCaptureError("verify", "receipt responses exceed the profile limit")

        if sequence == 0:
            if (
                operation != "open-pit"
                or method != "POST"
                or target != _open_target(request)
                or headers != _JSON_HEADERS
                or body
            ):
                raise ConnectorCaptureError("verify", "open-PIT request was substituted")
            opened = _parse_open_response(response, stage="verify")
            current_pit = cast(str, opened["id"])
            continue

        is_last = sequence == len(exchanges) - 1
        if is_last:
            if operation != "close-pit" or method != "DELETE" or target != _CLOSE_TARGET:
                raise ConnectorCaptureError("verify", "receipt does not end with PIT closure")
            if headers != _JSON_HEADERS:
                raise ConnectorCaptureError("verify", "PIT closure headers were substituted")
            expected_close = canonical_json_bytes({"id": current_pit}, limits=_RESPONSE_LIMITS)
            if body != expected_close:
                raise ConnectorCaptureError("verify", "PIT closure did not use the latest PIT id")
            _parse_close_response(response)
            if not found_empty_page:
                raise ConnectorCaptureError("verify", "receipt lacks a final empty search page")
            continue

        if found_empty_page:
            raise ConnectorCaptureError("verify", "search continued after its empty closure page")
        if (
            operation != "search-page"
            or method != "POST"
            or target != _SEARCH_TARGET
            or headers != _JSON_HEADERS
        ):
            raise ConnectorCaptureError("verify", "search request was substituted")
        expected_body = _search_body(
            request,
            pit_id=current_pit,
            search_after=previous_cursor,
        )
        if body != expected_body:
            raise ConnectorCaptureError("verify", "search body breaks query or cursor lineage")
        root_response, next_pit, next_cursor, hit_count, page_total = _parse_search_response(
            response,
            request=request,
        )
        if exact_total is None:
            exact_total = page_total
            if exact_total > request.max_hits:
                raise ConnectorCaptureError(
                    "verify",
                    "exact total exceeds the request safety limit",
                )
        elif page_total != exact_total:
            raise ConnectorCaptureError("verify", "exact total changed inside the PIT")
        if next_pit is not None:
            current_pit = next_pit
        hits_root = cast(dict[str, Any], root_response["hits"])
        hits = cast(list[Any], hits_root.get("hits", []))
        if hit_count == 0:
            if len(records) != exact_total:
                raise ConnectorCaptureError("verify", "empty page precedes the exact total")
            found_empty_page = True
            previous_cursor = None
            continue
        if next_cursor is None:
            raise ConnectorCaptureError("verify", "non-empty search page lacks a cursor")
        for raw_hit in hits:
            hit = cast(dict[str, Any], raw_hit)
            cursor = cast(list[Any], hit["sort"])
            timestamp_ns, timestamp_text = _parse_timestamp(
                cursor[0],
                label="record cursor timestamp",
            )
            shard_doc = cast(int, cursor[1])
            cursor_key = (timestamp_ns, shard_doc)
            if previous_cursor_key is not None and cursor_key <= previous_cursor_key:
                raise ConnectorCaptureError("verify", "cursor repeated or moved backwards")
            previous_cursor_key = cursor_key
            fields = cast(dict[str, Any], hit.get("fields", {}))
            records.append(
                {
                    "cursor": [timestamp_text, shard_doc],
                    "fields": fields,
                    "id": f"elastic-alert:{len(records):012d}",
                }
            )
            if len(records) > request.max_hits:
                raise ConnectorCaptureError("verify", "derived records exceed the request limit")
        previous_cursor = next_cursor

    if exact_total is None or len(records) != exact_total:
        raise ConnectorCaptureError("verify", "receipt does not close over its exact record total")
    try:
        records_jsonl = canonical_jsonl_bytes(records, limits=_RECORD_LIMITS)
    except StrictJSONError as exc:
        raise ConnectorCaptureError(
            "verify",
            "derived records exceed the canonical evidence profile",
        ) from exc
    descriptor = ConnectorDescriptor(
        connector_id=ELASTIC_SECURITY_CONNECTOR_ID,
        connector_version=connector_version,
        capture_media_type=ELASTIC_SECURITY_CAPTURE_MEDIA_TYPE,
    )
    return VerifiedConnectorCapture(
        descriptor=descriptor,
        receipt_digest=_sha256(receipt_bytes),
        records_jsonl=records_jsonl,
        records_digest=_sha256(records_jsonl),
        record_count=len(records),
        source_locator_digest=observed_origin,
        source_product="Elasticsearch",
        source_version=None,
    )
