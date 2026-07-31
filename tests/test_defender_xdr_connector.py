from __future__ import annotations

import base64
import hashlib
import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Any, ClassVar

import pytest

from assurance_lab.connectors.contract import (
    ConnectorCaptureError,
    ConnectorWindow,
    VerifiedConnectorCapture,
)
from assurance_lab.connectors.defender_xdr import (
    DefenderBearerToken,
    DefenderXDRConnector,
    DefenderXDRRequest,
    _HTTPResponse,
    defender_xdr_endpoint_origin_digest,
    verify_defender_xdr_capture,
)
from assurance_lab.evidence.canonical import (
    canonical_json_bytes,
    strict_json_loads,
    strict_jsonl_loads,
)

_ENDPOINT = "http://127.0.0.1:8787"
_ENDPOINT_DIGEST = defender_xdr_endpoint_origin_digest(
    _ENDPOINT,
    allow_insecure_loopback=True,
)
_NONCE = "a" * 64
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
_SCHEMA = [{"name": name, "type": "String"} for name in _RESULT_COLUMNS]
_HEADERS = (("content-type", "application/json"),)


def _request(**changes: Any) -> DefenderXDRRequest:
    values: dict[str, Any] = {
        "capture_id": "defender-xdr-test",
        "capture_nonce": _NONCE,
        "window": ConnectorWindow(
            start=datetime(2026, 7, 29, 0, 0, tzinfo=UTC),
            end=datetime(2026, 7, 30, 0, 0, tzinfo=UTC),
        ),
        "max_hits": 10,
    }
    values.update(changes)
    return DefenderXDRRequest(**values)


def _control(total: int) -> dict[str, str]:
    return {
        "AlertId": "",
        "AttackTechniques": "",
        "Category": "",
        "ControlAssuranceKind": "control",
        "ControlAssuranceTotal": str(total),
        "DetectionSource": "",
        "ServiceSource": "",
        "Severity": "",
        "Timestamp": "",
        "Title": "",
    }


def _alert(
    second: int,
    alert_id: str,
    *,
    title: str,
    severity: str,
) -> dict[str, str]:
    return {
        "AlertId": alert_id,
        "AttackTechniques": "T1059",
        "Category": "Execution",
        "ControlAssuranceKind": "record",
        "ControlAssuranceTotal": "",
        "DetectionSource": "Microsoft Defender for Endpoint",
        "ServiceSource": "Microsoft Defender for Endpoint",
        "Severity": severity,
        "Timestamp": f"2026-07-29T00:00:{second:02d}.0000000Z",
        "Title": title,
    }


def _response(
    results: list[dict[str, str]] | None = None,
    *,
    status: int = 200,
    headers: tuple[tuple[str, str], ...] = _HEADERS,
    schema: list[dict[str, str]] | None = None,
) -> _HTTPResponse:
    if results is None:
        results = [
            _control(2),
            _alert(1, "alert-a", title="Credential access signal", severity="High"),
            _alert(2, "alert-b", title="Suspicious process", severity="Medium"),
        ]
    return _HTTPResponse(
        status=status,
        headers=headers,
        body=canonical_json_bytes(
            {
                "@odata.context": (
                    "https://graph.microsoft.com/v1.0/$metadata"
                    "#microsoft.graph.security.huntingQueryResults"
                ),
                "results": results,
                "schema": schema if schema is not None else _SCHEMA,
            }
        ),
    )


@dataclass
class _TokenProvider:
    token: DefenderBearerToken

    def __post_init__(self) -> None:
        self.deadlines: list[float] = []

    def get_token(self, *, deadline: float) -> DefenderBearerToken:
        self.deadlines.append(deadline)
        return self.token


class _FailingTokenProvider:
    def __init__(self, secret: str) -> None:
        self.secret = secret

    def get_token(self, *, deadline: float) -> DefenderBearerToken:
        del deadline
        raise RuntimeError(self.secret)


@dataclass
class _QueuedTransport:
    responses: list[_HTTPResponse]

    def __post_init__(self) -> None:
        self.calls: list[
            tuple[
                str,
                str,
                bytes,
                tuple[tuple[str, str], ...],
                DefenderBearerToken,
            ]
        ] = []

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
        assert deadline > 0
        self.calls.append((method, target, body, headers, bearer_token))
        if not self.responses:
            raise AssertionError("connector made an unexpected request")
        return self.responses.pop(0)


def _connector(
    transport: _QueuedTransport,
    *,
    provider: _TokenProvider | _FailingTokenProvider | None = None,
) -> DefenderXDRConnector:
    actual_provider = provider or _TokenProvider(
        DefenderBearerToken(b"eyJhbGciOiJub25lIn0.lab-signature"),
    )
    return DefenderXDRConnector(
        actual_provider,
        endpoint=_ENDPOINT,
        allow_insecure_loopback=True,
        _transport=transport,
    )


def _verify(
    receipt_bytes: bytes,
    *,
    request: DefenderXDRRequest | None = None,
) -> VerifiedConnectorCapture:
    return verify_defender_xdr_capture(
        receipt_bytes,
        expected_endpoint_origin_digest=_ENDPOINT_DIGEST,
        expected_request=request or _request(),
    )


def test_complete_capture_rebuilds_fixed_alertinfo_result() -> None:
    transport = _QueuedTransport([_response()])
    provider = _TokenProvider(DefenderBearerToken(b"opaque-token.for-test"))
    request = _request()
    capture = _connector(transport, provider=provider).capture(request)
    verified = _verify(capture.receipt_bytes, request=request)

    assert capture.record_count == verified.record_count == 2
    assert capture.records_digest == verified.records_digest
    assert capture.receipt_digest == verified.receipt_digest
    assert strict_jsonl_loads(capture.records_jsonl, require_sorted_ids=True) == [
        {
            "fields": {
                "AlertId": "alert-a",
                "AttackTechniques": "T1059",
                "Category": "Execution",
                "DetectionSource": "Microsoft Defender for Endpoint",
                "ServiceSource": "Microsoft Defender for Endpoint",
                "Severity": "High",
                "Timestamp": "2026-07-29T00:00:01.0000000Z",
                "Title": "Credential access signal",
            },
            "id": "defender-xdr-alert:000000000000",
        },
        {
            "fields": {
                "AlertId": "alert-b",
                "AttackTechniques": "T1059",
                "Category": "Execution",
                "DetectionSource": "Microsoft Defender for Endpoint",
                "ServiceSource": "Microsoft Defender for Endpoint",
                "Severity": "Medium",
                "Timestamp": "2026-07-29T00:00:02.0000000Z",
                "Title": "Suspicious process",
            },
            "id": "defender-xdr-alert:000000000001",
        },
    ]
    assert len(provider.deadlines) == 1
    assert len(transport.calls) == 1
    method, target, body, headers, _ = transport.calls[0]
    assert method == "POST"
    assert target == "/v1.0/security/runHuntingQuery"
    assert headers == (
        ("accept", "application/json"),
        ("accept-encoding", "identity"),
        ("content-type", "application/json"),
    )
    request_json = strict_json_loads(body)
    assert isinstance(request_json, dict)
    assert request_json["Timespan"] == ("2026-07-29T00:00:00Z/2026-07-30T00:00:00Z")
    query = request_json["Query"]
    assert isinstance(query, str)
    assert query.startswith("let _ca_rows = materialize(\n    AlertInfo\n")
    assert "| take 12" in query
    assert "exact_total" not in capture.receipt_bytes.decode("utf-8")


def test_token_never_enters_receipt_or_representation() -> None:
    secret = b"secret-token.that-must-never-appear"
    token = DefenderBearerToken(secret)
    capture = _connector(
        _QueuedTransport([_response()]),
        provider=_TokenProvider(token),
    ).capture(_request())

    assert secret not in capture.receipt_bytes
    assert secret.decode() not in repr(token)
    assert secret.decode() not in str(token)
    assert b"authorization" not in capture.receipt_bytes.lower()


def test_token_provider_failure_is_normalized_without_exception_retention() -> None:
    secret = "provider-secret-must-not-escape"
    connector = _connector(
        _QueuedTransport([]),
        provider=_FailingTokenProvider(secret),
    )

    with pytest.raises(ConnectorCaptureError) as failure:
        connector.capture(_request())

    assert failure.value.stage == "authentication"
    assert secret not in str(failure.value)
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None


@pytest.mark.parametrize(
    ("endpoint", "lab_mode"),
    (
        ("http://graph.microsoft.com", True),
        ("http://127.0.0.1:9200", False),
        ("https://graph.microsoft.com:8443", False),
        ("https://user:secret@graph.microsoft.com", False),
        ("https://graph.microsoft.com/v1.0", False),
        ("https://graph.example", False),
        ("https://microsoftgraph.chinacloudapi.cn", False),
    ),
)
def test_endpoint_rejects_non_graph_origins_and_unsafe_http(
    endpoint: str,
    lab_mode: bool,
) -> None:
    with pytest.raises(ValueError):
        DefenderXDRConnector(
            _TokenProvider(DefenderBearerToken(b"test-token")),
            endpoint=endpoint,
            allow_insecure_loopback=lab_mode,
            _transport=_QueuedTransport([]),
        )


def test_supported_graph_cloud_origins_have_distinct_external_anchors() -> None:
    digests = {
        defender_xdr_endpoint_origin_digest(endpoint)
        for endpoint in (
            "https://graph.microsoft.com",
            "https://graph.microsoft.us",
            "https://dod-graph.microsoft.us",
        )
    }
    assert len(digests) == 3


def test_request_profile_rejects_long_window_saturation_and_bad_nonce() -> None:
    start = datetime(2026, 6, 1, tzinfo=UTC)
    with pytest.raises(ValueError, match="30 days"):
        _request(
            window=ConnectorWindow(
                start=start,
                end=start + timedelta(days=30, seconds=1),
            )
        )
    with pytest.raises(ValueError, match="max hits"):
        _request(max_hits=99_999)
    with pytest.raises(ValueError, match="nonce"):
        _request(capture_nonce="A" * 64)
    with pytest.raises(TypeError):
        DefenderXDRRequest(
            capture_id="no-arbitrary-kql",
            capture_nonce=_NONCE,
            window=_request().window,
            max_hits=10,
            query="AlertInfo | take 1",  # type: ignore[call-arg]
        )


def _mutated_receipt(
    receipt_bytes: bytes,
    mutate: Callable[[dict[str, Any]], None],
) -> bytes:
    parsed = strict_json_loads(receipt_bytes)
    assert isinstance(parsed, dict)
    mutate(parsed)
    return canonical_json_bytes(parsed)


def _replace_response_body(
    receipt: dict[str, Any],
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    response = receipt["exchanges"][0]["response"]
    body = base64.b64decode(response["body_base64"], validate=True)
    parsed = strict_json_loads(body)
    assert isinstance(parsed, dict)
    mutate(parsed)
    changed = canonical_json_bytes(parsed)
    response["body_base64"] = base64.b64encode(changed).decode()
    response["body_digest"] = f"sha256:{hashlib.sha256(changed).hexdigest()}"


@pytest.mark.parametrize(
    "mutate",
    (
        lambda receipt: receipt["exchanges"][0]["request"].__setitem__(
            "target",
            "/beta/security/runHuntingQuery",
        ),
        lambda receipt: receipt["exchanges"][0]["request"].__setitem__(
            "body_digest",
            f"sha256:{'0' * 64}",
        ),
        lambda receipt: receipt["exchanges"][0]["request"]["headers"].append(
            ["authorization", "Bearer stolen"],
        ),
        lambda receipt: _replace_response_body(
            receipt,
            lambda body: body["results"].pop(0),
        ),
        lambda receipt: _replace_response_body(
            receipt,
            lambda body: body["results"][0].__setitem__(
                "ControlAssuranceTotal",
                "1",
            ),
        ),
        lambda receipt: _replace_response_body(
            receipt,
            lambda body: body["results"].reverse(),
        ),
        lambda receipt: _replace_response_body(
            receipt,
            lambda body: body["schema"].pop(),
        ),
        lambda receipt: _replace_response_body(
            receipt,
            lambda body: body.__setitem__(
                "@odata.context",
                "https://attacker.invalid/v1.0/$metadata"
                "#microsoft.graph.security.huntingQueryResults",
            ),
        ),
        lambda receipt: _replace_response_body(
            receipt,
            lambda body: body["results"][1].__setitem__(
                "Timestamp",
                "2026-07-30T00:00:00.0000000Z",
            ),
        ),
        lambda receipt: receipt["source_profile"].__setitem__(
            "permission",
            "SecurityEvents.Read.All",
        ),
    ),
    ids=(
        "beta-target",
        "false-request-digest",
        "authorization-in-receipt",
        "missing-control",
        "truncated-count",
        "wrong-order",
        "schema-truncated",
        "foreign-odata-context",
        "end-boundary-included",
        "permission-substitution",
    ),
)
def test_verifier_rejects_hostile_receipt_mutations(
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    capture = _connector(_QueuedTransport([_response()])).capture(_request())
    corrupted = _mutated_receipt(capture.receipt_bytes, mutate)

    with pytest.raises(ConnectorCaptureError):
        _verify(corrupted)


def test_saturated_result_fails_instead_of_returning_partial_evidence() -> None:
    response = _response(
        [
            _control(11),
            *[
                _alert(
                    second,
                    f"alert-{second:02d}",
                    title=f"Alert {second:02d}",
                    severity="Medium",
                )
                for second in range(1, 12)
            ],
        ]
    )
    with pytest.raises(ConnectorCaptureError, match="safety limit"):
        _connector(_QueuedTransport([response])).capture(_request(max_hits=10))


def test_short_result_with_forged_smaller_count_still_fails_count_closure() -> None:
    response = _response(
        [
            _control(2),
            _alert(1, "alert-a", title="Only one returned", severity="High"),
        ]
    )
    with pytest.raises(ConnectorCaptureError, match="close over"):
        _connector(_QueuedTransport([response])).capture(_request())


@pytest.mark.parametrize(
    "headers",
    (
        (("content-type", "text/html"),),
        (
            ("content-encoding", "gzip"),
            ("content-type", "application/json"),
        ),
    ),
    ids=("wrong-media-type", "unrequested-compression"),
)
def test_response_media_metadata_fails_closed(
    headers: tuple[tuple[str, str], ...],
) -> None:
    with pytest.raises(ConnectorCaptureError):
        _connector(_QueuedTransport([_response(headers=headers)])).capture(_request())


def test_verifier_requires_external_origin_request_and_version_anchors() -> None:
    request = _request()
    capture = _connector(_QueuedTransport([_response()])).capture(request)

    with pytest.raises(ConnectorCaptureError, match="different source origin"):
        verify_defender_xdr_capture(
            capture.receipt_bytes,
            expected_endpoint_origin_digest=f"sha256:{'0' * 64}",
            expected_request=request,
        )
    with pytest.raises(ConnectorCaptureError, match="externally expected job"):
        verify_defender_xdr_capture(
            capture.receipt_bytes,
            expected_endpoint_origin_digest=_ENDPOINT_DIGEST,
            expected_request=_request(capture_nonce="b" * 64),
        )
    with pytest.raises(ConnectorCaptureError, match="expected implementation"):
        verify_defender_xdr_capture(
            capture.receipt_bytes,
            expected_endpoint_origin_digest=_ENDPOINT_DIGEST,
            expected_request=request,
            expected_connector_version="forged-version",
        )


@pytest.mark.parametrize(
    "mutate",
    (
        lambda receipt: receipt["timing"].__setitem__(
            "elapsed_microseconds",
            receipt["timing"]["elapsed_microseconds"] + 1,
        ),
        lambda receipt: receipt["timing"].__setitem__(
            "finished_at",
            receipt["timing"]["started_at"],
        ),
    ),
    ids=("elapsed-forgery", "finished-at-forgery"),
)
def test_verifier_rejects_capture_timing_forgery(
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    capture = _connector(_QueuedTransport([_response()])).capture(_request())
    corrupted = _mutated_receipt(capture.receipt_bytes, mutate)

    with pytest.raises(ConnectorCaptureError, match="timing"):
        _verify(corrupted)


class _CredentialReflectionHandler(BaseHTTPRequestHandler):
    secret = ""
    unicode_escape = False
    authorization_headers: ClassVar[list[str]] = []

    def do_POST(self) -> None:
        self.authorization_headers.append(self.headers.get("Authorization", ""))
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        if self.unicode_escape:
            escaped = "".join(f"\\u{ord(character):04x}" for character in self.secret)
            body = f'{{"reflected":"{escaped}"}}'.encode()
        else:
            body = canonical_json_bytes(
                {
                    "results": [_control(0)],
                    "schema": _SCHEMA,
                    "reflected": self.secret,
                }
            )
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


class _RedirectHandler(BaseHTTPRequestHandler):
    paths: ClassVar[list[str]] = []

    def do_POST(self) -> None:
        self.paths.append(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        self.send_response(302)
        self.send_header("Location", "/credential-sink")
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, format: str, *args: object) -> None:
        del format, args


def _start_http_server(
    handler: type[BaseHTTPRequestHandler],
) -> tuple[ThreadingHTTPServer, Thread]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


@pytest.mark.parametrize("unicode_escape", (False, True))
def test_real_transport_sends_bearer_but_rejects_reflection_without_leak(
    unicode_escape: bool,
) -> None:
    secret = "transport-reflection.secret-token"
    _CredentialReflectionHandler.secret = secret
    _CredentialReflectionHandler.unicode_escape = unicode_escape
    _CredentialReflectionHandler.authorization_headers = []
    server, thread = _start_http_server(_CredentialReflectionHandler)
    connector = DefenderXDRConnector(
        _TokenProvider(DefenderBearerToken(secret.encode())),
        endpoint=f"http://127.0.0.1:{server.server_port}",
        allow_insecure_loopback=True,
    )
    try:
        with pytest.raises(ConnectorCaptureError) as failure:
            connector.capture(_request())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert _CredentialReflectionHandler.authorization_headers == [f"Bearer {secret}"]
    assert secret not in str(failure.value)


def test_real_transport_does_not_follow_redirects_with_bearer() -> None:
    _RedirectHandler.paths = []
    server, thread = _start_http_server(_RedirectHandler)
    connector = DefenderXDRConnector(
        _TokenProvider(DefenderBearerToken(b"redirect-never-follow")),
        endpoint=f"http://127.0.0.1:{server.server_port}",
        allow_insecure_loopback=True,
    )
    try:
        with pytest.raises(ConnectorCaptureError, match="HTTP 302"):
            connector.capture(_request())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert _RedirectHandler.paths == ["/v1.0/security/runHuntingQuery"]


def test_proxy_environment_is_not_used_by_real_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A syntactically valid but unreachable proxy would break this request if
    # urllib inherited proxy configuration instead of using ProxyHandler({}).
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")

    class _SuccessHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(_response(results=[_control(0)]).body)

        def log_message(self, format: str, *args: object) -> None:
            del format, args

    server, thread = _start_http_server(_SuccessHandler)
    connector = DefenderXDRConnector(
        _TokenProvider(DefenderBearerToken(b"proxy-test-token")),
        endpoint=f"http://127.0.0.1:{server.server_port}",
        allow_insecure_loopback=True,
    )
    try:
        capture = connector.capture(_request())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert capture.record_count == 0
    assert os.environ["HTTP_PROXY"] == "http://127.0.0.1:1"
