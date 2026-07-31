from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Any, ClassVar

import pytest

from assurance_lab.connectors.contract import (
    ConnectorCaptureError,
    ConnectorWindow,
    VerifiedConnectorCapture,
)
from assurance_lab.connectors.elastic_security import (
    ElasticApiKey,
    ElasticSecurityConnector,
    ElasticSecurityRequest,
    _HTTPResponse,
    elastic_endpoint_origin_digest,
    verify_elastic_security_capture,
)
from assurance_lab.evidence.canonical import (
    canonical_json_bytes,
    strict_json_loads,
    strict_jsonl_loads,
)

_HEADERS = (
    ("content-type", "application/json"),
    ("x-elastic-product", "Elasticsearch"),
)
_SHARDS = {"failed": 0, "skipped": 0, "successful": 1, "total": 1}
_ENDPOINT = "http://127.0.0.1:9200"
_ENDPOINT_DIGEST = elastic_endpoint_origin_digest(
    _ENDPOINT,
    allow_insecure_loopback=True,
)
_NONCE = "a" * 64


def _json_response(value: dict[str, Any], *, status: int = 200) -> _HTTPResponse:
    return _HTTPResponse(
        status=status,
        headers=_HEADERS,
        body=canonical_json_bytes(value),
    )


def _hit(second: int, shard_doc: int, *, severity: str) -> dict[str, Any]:
    timestamp = f"2026-07-29T00:00:{second:02d}.000000000Z"
    return {
        "fields": {
            "@timestamp": [timestamp],
            "kibana.alert.severity": [severity],
        },
        "sort": [timestamp, shard_doc],
    }


def _search(
    *,
    pit_id: str,
    total: int,
    hits: list[dict[str, Any]],
    timed_out: bool = False,
    shards: dict[str, Any] | None = None,
    relation: str = "eq",
) -> _HTTPResponse:
    return _json_response(
        {
            "_shards": shards or _SHARDS,
            "hits": {
                "hits": hits,
                "total": {"relation": relation, "value": total},
            },
            "pit_id": pit_id,
            "timed_out": timed_out,
        }
    )


def _responses() -> list[_HTTPResponse]:
    return [
        _json_response({"_shards": _SHARDS, "id": "pit-0"}),
        _search(
            pit_id="pit-1",
            total=3,
            hits=[
                _hit(1, 10, severity="high"),
                _hit(2, 11, severity="medium"),
            ],
        ),
        _search(
            pit_id="pit-2",
            total=3,
            hits=[_hit(3, 12, severity="critical")],
        ),
        _json_response(
            {
                "_shards": _SHARDS,
                "hits": {"total": {"relation": "eq", "value": 3}},
                "pit_id": "pit-3",
                "timed_out": False,
            }
        ),
        _json_response({"num_freed": 1, "succeeded": True}),
    ]


@dataclass
class _QueuedTransport:
    responses: list[_HTTPResponse]

    def __post_init__(self) -> None:
        self.calls: list[tuple[str, str, bytes, tuple[tuple[str, str], ...]]] = []

    def request(
        self,
        *,
        method: str,
        target: str,
        body: bytes,
        headers: tuple[tuple[str, str], ...],
        deadline: float,
    ) -> _HTTPResponse:
        assert deadline > 0
        self.calls.append((method, target, body, headers))
        if not self.responses:
            raise AssertionError("connector made an unexpected request")
        return self.responses.pop(0)


def _request(**changes: Any) -> ElasticSecurityRequest:
    values: dict[str, Any] = {
        "capture_id": "elastic-live-test",
        "capture_nonce": _NONCE,
        "window": ConnectorWindow(
            start=datetime(2026, 7, 29, 0, 0, tzinfo=UTC),
            end=datetime(2026, 7, 30, 0, 0, tzinfo=UTC),
        ),
        "fields": ("@timestamp", "kibana.alert.severity"),
        "page_size": 2,
        "max_hits": 10,
    }
    values.update(changes)
    return ElasticSecurityRequest(**values)


def _connector(transport: _QueuedTransport) -> ElasticSecurityConnector:
    return ElasticSecurityConnector(
        _ENDPOINT,
        ElasticApiKey(b"bGFiLW9ubHk6bm90LWEtc2VjcmV0"),
        allow_insecure_loopback=True,
        _transport=transport,
    )


def _verify(
    receipt_bytes: bytes,
    *,
    request: ElasticSecurityRequest | None = None,
) -> VerifiedConnectorCapture:
    return verify_elastic_security_capture(
        receipt_bytes,
        expected_endpoint_origin_digest=_ENDPOINT_DIGEST,
        expected_request=request or _request(),
    )


def test_complete_capture_is_recomputed_from_exact_rest_exchanges() -> None:
    transport = _QueuedTransport(_responses())
    request = _request()
    capture = _connector(transport).capture(request)
    verified = _verify(capture.receipt_bytes, request=request)

    assert capture.record_count == verified.record_count == 3
    assert capture.records_digest == verified.records_digest
    assert capture.receipt_digest == verified.receipt_digest
    assert strict_jsonl_loads(capture.records_jsonl, require_sorted_ids=True) == [
        {
            "cursor": ["2026-07-29T00:00:01.000000000Z", 10],
            "fields": {
                "@timestamp": ["2026-07-29T00:00:01.000000000Z"],
                "kibana.alert.severity": ["high"],
            },
            "id": "elastic-alert:000000000000",
        },
        {
            "cursor": ["2026-07-29T00:00:02.000000000Z", 11],
            "fields": {
                "@timestamp": ["2026-07-29T00:00:02.000000000Z"],
                "kibana.alert.severity": ["medium"],
            },
            "id": "elastic-alert:000000000001",
        },
        {
            "cursor": ["2026-07-29T00:00:03.000000000Z", 12],
            "fields": {
                "@timestamp": ["2026-07-29T00:00:03.000000000Z"],
                "kibana.alert.severity": ["critical"],
            },
            "id": "elastic-alert:000000000002",
        },
    ]
    assert [call[0] for call in transport.calls] == [
        "POST",
        "POST",
        "POST",
        "POST",
        "DELETE",
    ]
    receipt = strict_json_loads(capture.receipt_bytes)
    assert isinstance(receipt, dict)
    assert receipt["endpoint_origin_digest"].startswith("sha256:")
    assert "127.0.0.1" not in capture.receipt_bytes.decode()


def test_api_key_never_enters_receipt_or_object_representation() -> None:
    secret = b"dGhpcy1tdXN0LW5ldmVyLWxlYXZl"
    key = ElasticApiKey(secret)
    transport = _QueuedTransport(_responses())
    connector = ElasticSecurityConnector(
        "http://127.0.0.1:9200",
        key,
        allow_insecure_loopback=True,
        _transport=transport,
    )

    capture = connector.capture(_request())

    assert secret not in capture.receipt_bytes
    assert secret.decode() not in repr(key)
    assert secret.decode() not in str(key)
    assert b"authorization" not in capture.receipt_bytes.lower()


@pytest.mark.parametrize(
    ("endpoint", "lab_mode"),
    (
        ("http://elastic.example:9200", True),
        ("http://127.0.0.1:9200", False),
        ("https://user:password@elastic.example", False),
        ("https://elastic.example/base", False),
        ("https://elastic.example?token=secret", False),
    ),
)
def test_endpoint_rejects_plain_remote_http_and_embedded_credentials(
    endpoint: str,
    lab_mode: bool,
) -> None:
    with pytest.raises(ValueError):
        ElasticSecurityConnector(
            endpoint,
            ElasticApiKey(b"bGFiLW9ubHk"),
            allow_insecure_loopback=lab_mode,
            _transport=_QueuedTransport([]),
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
    exchange_index: int,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    exchange = receipt["exchanges"][exchange_index]
    response = exchange["response"]
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
        lambda receipt: _replace_response_body(
            receipt,
            1,
            lambda body: body.__setitem__("timed_out", True),
        ),
        lambda receipt: _replace_response_body(
            receipt,
            1,
            lambda body: body["_shards"].__setitem__("failed", 1),
        ),
        lambda receipt: _replace_response_body(
            receipt,
            1,
            lambda body: body["hits"]["total"].__setitem__("relation", "gte"),
        ),
        lambda receipt: receipt["exchanges"][2]["request"].__setitem__(
            "body_base64",
            receipt["exchanges"][1]["request"]["body_base64"],
        ),
        lambda receipt: receipt["exchanges"].pop(3),
        lambda receipt: receipt["exchanges"][-1]["request"].__setitem__(
            "body_digest",
            f"sha256:{'0' * 64}",
        ),
    ),
    ids=(
        "timed-out",
        "failed-shard",
        "inexact-total",
        "reused-page-request",
        "missing-empty-page",
        "wrong-close-digest",
    ),
)
def test_independent_verifier_rejects_hostile_capture_mutations(
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    capture = _connector(_QueuedTransport(_responses())).capture(_request())
    corrupted = _mutated_receipt(capture.receipt_bytes, mutate)

    with pytest.raises(ConnectorCaptureError):
        _verify(corrupted)


def test_search_failure_still_closes_latest_pit() -> None:
    responses = _responses()
    responses[1] = _search(pit_id="pit-1", total=3, hits=[], timed_out=True)
    # The connector should stop after the failed page and consume the close response next.
    responses = [*responses[:2], responses[-1]]
    transport = _QueuedTransport(responses)

    with pytest.raises(ConnectorCaptureError, match="timed out"):
        _connector(transport).capture(_request())

    assert transport.calls[-1][0] == "DELETE"
    close_body = strict_json_loads(transport.calls[-1][2])
    assert close_body == {"id": "pit-1"}


def test_exact_total_over_safety_limit_returns_no_partial_capture() -> None:
    responses = _responses()
    responses[1] = _search(
        pit_id="pit-1",
        total=11,
        hits=[_hit(1, 10, severity="high")],
    )
    responses = [*responses[:2], responses[-1]]
    transport = _QueuedTransport(responses)

    with pytest.raises(ConnectorCaptureError, match="safety limit"):
        _connector(transport).capture(_request(max_hits=10))

    assert transport.calls[-1][0] == "DELETE"


def test_fields_are_sorted_and_sensitive_identity_fields_are_opt_in() -> None:
    request = _request(
        fields=(
            "user.name",
            "@timestamp",
            "host.name",
        )
    )

    assert request.fields == ("@timestamp", "host.name", "user.name")
    assert (
        "host.name"
        not in ElasticSecurityRequest(
            capture_id="minimal",
            window=request.window,
            capture_nonce=_NONCE,
        ).fields
    )
    assert (
        "user.name"
        not in ElasticSecurityRequest(
            capture_id="minimal",
            window=request.window,
            capture_nonce=_NONCE,
        ).fields
    )


@pytest.mark.parametrize(
    "opened",
    (
        _HTTPResponse(
            status=200,
            headers=(("content-type", "application/json"),),
            body=canonical_json_bytes({"_shards": _SHARDS, "id": "pit-owned"}),
        ),
        _json_response(
            {
                "_shards": {
                    "failed": 1,
                    "skipped": 0,
                    "successful": 0,
                    "total": 1,
                },
                "id": "pit-owned",
            }
        ),
    ),
    ids=("missing-product-marker", "failed-open-shard"),
)
def test_open_validation_failure_still_closes_extracted_pit(
    opened: _HTTPResponse,
) -> None:
    transport = _QueuedTransport(
        [
            opened,
            _json_response({"num_freed": 1, "succeeded": True}),
        ]
    )

    with pytest.raises(ConnectorCaptureError):
        _connector(transport).capture(_request())

    assert [call[0] for call in transport.calls] == ["POST", "DELETE"]
    assert strict_json_loads(transport.calls[-1][2]) == {"id": "pit-owned"}


@pytest.mark.parametrize(
    "mutate",
    (
        lambda body: body["hits"]["hits"][0]["fields"].pop("@timestamp"),
        lambda body: body["hits"]["hits"][0]["fields"].__setitem__(
            "@timestamp",
            ["2026-07-29T00:00:09.000000000Z"],
        ),
        lambda body: (
            body["hits"]["hits"][0].__setitem__(
                "sort",
                ["2026-07-30T00:00:00.000000000Z", 10],
            ),
            body["hits"]["hits"][0]["fields"].__setitem__(
                "@timestamp",
                ["2026-07-30T00:00:00.000000000Z"],
            ),
        ),
    ),
    ids=("missing-timestamp-field", "cursor-field-mismatch", "outside-half-open-window"),
)
def test_search_rejects_timestamp_lineage_violations(
    mutate: Callable[[dict[str, Any]], object],
) -> None:
    response = _search(
        pit_id="pit-1",
        total=1,
        hits=[_hit(1, 10, severity="high")],
    )
    parsed = strict_json_loads(response.body)
    assert isinstance(parsed, dict)
    mutate(parsed)
    responses = [
        _json_response({"_shards": _SHARDS, "id": "pit-0"}),
        _json_response(parsed),
        _json_response({"num_freed": 1, "succeeded": True}),
    ]
    transport = _QueuedTransport(responses)

    with pytest.raises(ConnectorCaptureError):
        _connector(transport).capture(_request())

    assert strict_json_loads(transport.calls[-1][2]) == {"id": "pit-1"}


def test_verifier_requires_external_source_request_and_version_bindings() -> None:
    request = _request()
    capture = _connector(_QueuedTransport(_responses())).capture(request)

    with pytest.raises(ConnectorCaptureError, match="different source origin"):
        verify_elastic_security_capture(
            capture.receipt_bytes,
            expected_endpoint_origin_digest=f"sha256:{'0' * 64}",
            expected_request=request,
        )
    with pytest.raises(ConnectorCaptureError, match="externally expected job"):
        verify_elastic_security_capture(
            capture.receipt_bytes,
            expected_endpoint_origin_digest=_ENDPOINT_DIGEST,
            expected_request=_request(capture_nonce="b" * 64),
        )
    with pytest.raises(ConnectorCaptureError, match="expected implementation"):
        verify_elastic_security_capture(
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
    capture = _connector(_QueuedTransport(_responses())).capture(_request())
    corrupted = _mutated_receipt(capture.receipt_bytes, mutate)

    with pytest.raises(ConnectorCaptureError, match="timing"):
        _verify(corrupted)


class _CredentialReflectionHandler(BaseHTTPRequestHandler):
    secret = ""
    authorization_headers: ClassVar[list[str]] = []

    def do_POST(self) -> None:
        self.authorization_headers.append(self.headers.get("Authorization", ""))
        body = canonical_json_bytes({"id": self.secret, "_shards": _SHARDS})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Elastic-Product", "Elasticsearch")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


class _RedirectHandler(BaseHTTPRequestHandler):
    paths: ClassVar[list[str]] = []

    def do_POST(self) -> None:
        self.paths.append(self.path)
        self.send_response(302)
        self.send_header("Location", "/credential-sink")
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Elastic-Product", "Elasticsearch")
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


def test_real_transport_sends_auth_but_rejects_reflection_without_leaking_it() -> None:
    secret = "dHJhbnNwb3J0LXJlZmxlY3Rpb24tc2VjcmV0"
    _CredentialReflectionHandler.secret = secret
    _CredentialReflectionHandler.authorization_headers = []
    server, thread = _start_http_server(_CredentialReflectionHandler)
    endpoint = f"http://127.0.0.1:{server.server_port}"
    connector = ElasticSecurityConnector(
        endpoint,
        ElasticApiKey(secret.encode()),
        allow_insecure_loopback=True,
    )
    try:
        with pytest.raises(ConnectorCaptureError) as failure:
            connector.capture(_request())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert _CredentialReflectionHandler.authorization_headers == [f"ApiKey {secret}"]
    assert secret not in str(failure.value)


def test_real_transport_does_not_follow_redirects_with_authorization() -> None:
    _RedirectHandler.paths = []
    server, thread = _start_http_server(_RedirectHandler)
    connector = ElasticSecurityConnector(
        f"http://127.0.0.1:{server.server_port}",
        ElasticApiKey(b"cmVkaXJlY3QtbmV2ZXItZm9sbG93"),
        allow_insecure_loopback=True,
    )
    try:
        with pytest.raises(ConnectorCaptureError, match="HTTP 302"):
            connector.capture(_request())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert len(_RedirectHandler.paths) == 1
    assert _RedirectHandler.paths[0].endswith(
        "/_pit?allow_partial_search_results=false&filter_path=id%2C_shards&keep_alive=60s"
    )
