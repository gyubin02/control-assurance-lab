"""Opt-in conformance test against a real Elasticsearch Security alert alias."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from assurance_lab.connectors import (
    ConnectorWindow,
    ElasticApiKey,
    ElasticSecurityConnector,
    ElasticSecurityRequest,
    VerifiedConnectorCapture,
    elastic_endpoint_origin_digest,
    new_capture_nonce,
)
from assurance_lab.connectors.elastic_pam import (
    ElasticJitApiKeyBroker,
    ElasticPamPolicy,
    ElasticParentCredential,
    SQLiteElasticLeaseJournal,
    verify_elastic_pam_receipt,
)
from assurance_lab.connectors.elastic_security import verify_elastic_security_capture
from assurance_lab.connectors.evidence import (
    connector_request_bytes,
    create_connector_evidence_job,
    verify_connector_evidence_bundle,
    write_connector_evidence_bundle,
)
from assurance_lab.evidence.canonical import (
    canonical_json_bytes,
    strict_json_loads,
    strict_jsonl_loads,
)


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if value is None:
        pytest.skip(f"{name} is required for the live Elastic conformance test")
    return value


def _read_api_key_file() -> str:
    """Read the ephemeral key without putting its value in the process environment."""

    path = Path(_required_environment("CONTROL_ASSURANCE_ELASTIC_API_KEY_FILE"))
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if not hasattr(os, "O_NOFOLLOW"):
        raise AssertionError("O_NOFOLLOW is required by the live conformance profile")
    flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > 16_384
            or before.st_mode & 0o077
        ):
            raise AssertionError("API key file is not a bounded owner-only regular file")
        chunks: list[bytes] = []
        remaining = before.st_size + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(content) != before.st_size
            or (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
        ):
            raise AssertionError("API key file changed while it was read")
    finally:
        os.close(descriptor)
    try:
        value = content.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise AssertionError("API key file is not ASCII") from exc
    if (
        not value
        or len(value) > 8_192
        or any(
            character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_+/=-"
            for character in value
        )
    ):
        raise AssertionError("API key file is not a bounded encoded API key")
    return value


def _read_parent_password_file() -> str:
    """Read the bootstrap password through the same owner-only file boundary."""

    path = Path(_required_environment("CONTROL_ASSURANCE_ELASTIC_PARENT_SECRET_FILE"))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise AssertionError("O_NOFOLLOW is required by the live conformance profile")
    descriptor = os.open(path, flags | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 1 <= before.st_size <= 16_384
            or before.st_mode & 0o077
        ):
            raise AssertionError("parent secret is not a bounded owner-only regular file")
        content = os.read(descriptor, before.st_size + 1)
        after = os.fstat(descriptor)
        if len(content) != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise AssertionError("parent secret changed while it was read")
    finally:
        os.close(descriptor)
    try:
        password = content.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise AssertionError("parent secret is not ASCII") from exc
    if not password or any(character.isspace() for character in password):
        raise AssertionError("parent secret is empty or contains whitespace")
    return password


def test_real_elasticsearch_capture_cross_verifies_in_node(tmp_path: Path) -> None:
    endpoint = _required_environment("CONTROL_ASSURANCE_ELASTIC_URL")
    api_key = _read_api_key_file()
    expected_count = int(os.environ.get("CONTROL_ASSURANCE_ELASTIC_EXPECTED_COUNT", "4"))
    request = ElasticSecurityRequest(
        capture_id="elastic-live-conformance",
        capture_nonce=new_capture_nonce(),
        window=ConnectorWindow(
            start=datetime(2026, 7, 29, 0, 0, tzinfo=UTC),
            end=datetime(2026, 7, 30, 0, 0, tzinfo=UTC),
        ),
        fields=(
            "@timestamp",
            "kibana.alert.rule.name",
            "kibana.alert.severity",
        ),
        page_size=2,
        max_hits=100,
    )
    connector = ElasticSecurityConnector(
        endpoint,
        ElasticApiKey(api_key.encode("ascii", errors="strict")),
        allow_insecure_loopback=endpoint.startswith(("http://127.0.0.1:", "http://[::1]:")),
    )

    capture = connector.capture(request)

    records = strict_jsonl_loads(
        capture.records_jsonl,
        require_sorted_ids=True,
    )
    expected_records = [
        (
            "2026-07-29T00:00:00.000Z",
            "Boundary-open",
            "low",
        ),
        (
            "2026-07-29T08:15:30.123456789Z",
            "Credential access signal",
            "medium",
        ),
        (
            "2026-07-29T16:45:00.000Z",
            "Endpoint isolation lag",
            "high",
        ),
        (
            "2026-07-29T23:59:59.999999999Z",
            "Recovery validation",
            "critical",
        ),
    ]
    assert capture.record_count == expected_count
    assert len(records) == expected_count
    assert [
        (
            record["cursor"][0],
            record["fields"]["kibana.alert.rule.name"][0],
            record["fields"]["kibana.alert.severity"][0],
        )
        for record in records
    ] == expected_records
    assert all(
        set(record["fields"])
        == {"@timestamp", "kibana.alert.rule.name", "kibana.alert.severity"}
        for record in records
    )
    assert all(record["fields"]["@timestamp"] == [record["cursor"][0]] for record in records)
    assert not any(
        record["fields"]["kibana.alert.rule.name"] == ["End boundary must be excluded"]
        for record in records
    )
    assert b"authorization" not in capture.receipt_bytes.lower()

    receipt = strict_json_loads(capture.receipt_bytes)
    assert isinstance(receipt, dict)
    exchanges = receipt["exchanges"]
    assert [exchange["operation"] for exchange in exchanges] == [
        "open-pit",
        "search-page",
        "search-page",
        "search-page",
        "close-pit",
    ]
    assert [exchange["sequence"] for exchange in exchanges] == list(range(5))
    open_response = strict_json_loads(
        base64.b64decode(exchanges[0]["response"]["body_base64"], validate=True)
    )
    assert open_response["_shards"] == {
        "failed": 0,
        "skipped": 0,
        "successful": 2,
        "total": 2,
    }

    receipt_path = tmp_path / "elastic-receipt.json"
    request_path = tmp_path / "expected-request.json"
    records_path = tmp_path / "node-records.jsonl"
    receipt_path.write_bytes(capture.receipt_bytes)
    request_path.write_bytes(canonical_json_bytes(request.as_json()))
    repository = Path(__file__).resolve().parents[2]
    completed = subprocess.run(
        [
            "node",
            str(repository / "verifier-js" / "src" / "elastic-security-cli.js"),
            "--receipt",
            str(receipt_path),
            "--expected-request",
            str(request_path),
            "--expected-endpoint-origin-digest",
            elastic_endpoint_origin_digest(
                endpoint,
                allow_insecure_loopback=endpoint.startswith(("http://127.0.0.1:", "http://[::1]:")),
            ),
            "--expected-connector-version",
            capture.descriptor.connector_version,
            "--records-output",
            str(records_path),
        ],
        check=False,
        capture_output=True,
        env={"PATH": os.environ["PATH"]},
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr.decode(
        "utf-8",
        errors="replace",
    )
    summary = json.loads(completed.stdout)
    assert summary["status"] == "verified"
    assert summary["claim_scope"] == "receipt-internal-consistency"
    assert summary["source_authenticity"] == "not-established"
    assert summary["record_count"] == expected_count
    assert summary["records_digest"] == capture.records_digest
    assert summary["receipt_digest"] == capture.receipt_digest
    assert records_path.read_bytes() == capture.records_jsonl

    request_bytes = connector_request_bytes(request.as_json())
    endpoint_digest = elastic_endpoint_origin_digest(
        endpoint,
        allow_insecure_loopback=endpoint.startswith(
            ("http://127.0.0.1:", "http://[::1]:")
        ),
    )
    evidence_job = create_connector_evidence_job(
        job_id="elastic-live-conformance",
        descriptor=capture.descriptor,
        source_locator_digest=endpoint_digest,
        request_media_type="application/vnd.control-assurance.elastic-security-request.v1+json",
        request_bytes=request_bytes,
    )

    def verify_receipt(receipt: bytes) -> VerifiedConnectorCapture:
        return verify_elastic_security_capture(
            receipt,
            expected_endpoint_origin_digest=endpoint_digest,
            expected_request=request,
            expected_connector_version=capture.descriptor.connector_version,
        )

    evidence_root = tmp_path / "elastic-live.cab"
    evidence = write_connector_evidence_bundle(
        evidence_root,
        job=evidence_job,
        request_bytes=request_bytes,
        capture=capture,
        receipt_verifier=verify_receipt,
        receipt_verifier_id="control-assurance-lab/python-elastic-security-verifier-v1",
        created_at=datetime(2026, 7, 30, 0, 0, 1, tzinfo=UTC),
        as_of=datetime(2026, 7, 30, 0, 0, 0, tzinfo=UTC),
        source_revision="elastic-live-conformance",
    )
    reopened_evidence = verify_connector_evidence_bundle(
        evidence_root,
        expected_job=evidence_job,
        expected_request_bytes=request_bytes,
        receipt_verifier=verify_receipt,
        receipt_verifier_id="control-assurance-lab/python-elastic-security-verifier-v1",
        expected_source_revision="elastic-live-conformance",
    )
    assert reopened_evidence.cab_id == evidence.cab_id
    assert reopened_evidence.receipt_digest == capture.receipt_digest
    assert reopened_evidence.records_digest == capture.records_digest


def test_real_elasticsearch_jit_key_is_scoped_used_and_revoked(tmp_path: Path) -> None:
    endpoint = _required_environment("CONTROL_ASSURANCE_ELASTIC_URL")
    request = ElasticSecurityRequest(
        capture_id="elastic-live-jit-pam",
        capture_nonce=new_capture_nonce(),
        window=ConnectorWindow(
            start=datetime(2026, 7, 29, 0, 0, tzinfo=UTC),
            end=datetime(2026, 7, 30, 0, 0, tzinfo=UTC),
        ),
        fields=(
            "@timestamp",
            "kibana.alert.rule.name",
            "kibana.alert.severity",
        ),
        page_size=2,
        max_hits=100,
    )
    journal = SQLiteElasticLeaseJournal(tmp_path / "elastic-pam.sqlite3")
    parent_password = _read_parent_password_file()
    broker = ElasticJitApiKeyBroker(
        endpoint,
        ElasticParentCredential.basic("elastic", parent_password),
        journal,
        allow_insecure_loopback=endpoint.startswith(
            ("http://127.0.0.1:", "http://[::1]:")
        ),
    )

    managed = broker.capture(request)

    assert managed.capture.record_count == 4
    assert journal.unsettled() == ()
    receipt = strict_json_loads(managed.pam_receipt_bytes)
    assert receipt["mutations"]["revocation_outcome"] == "invalidated"
    assert receipt["lease"]["index_alias"] == ".alerts-security.alerts-default"
    assert receipt["lease"]["ttl_seconds"] == 900
    assert parent_password.encode() not in managed.pam_receipt_bytes
    assert (
        base64.b64encode(f"elastic:{parent_password}".encode())
        not in managed.pam_receipt_bytes
    )
    request_digest = f"sha256:{hashlib.sha256(canonical_json_bytes(request.as_json())).hexdigest()}"
    verified = verify_elastic_pam_receipt(
        managed.pam_receipt_bytes,
        expected_request_digest=request_digest,
        expected_endpoint_origin_digest=broker.endpoint_origin_digest,
        expected_role_descriptor_digest=ElasticPamPolicy(
            request.index_alias
        ).role_descriptor_digest,
        expected_capture_receipt_digest=managed.capture.receipt_digest,
        expected_capture_records_digest=managed.capture.records_digest,
    )
    assert verified.receipt_digest == managed.pam_receipt_digest
