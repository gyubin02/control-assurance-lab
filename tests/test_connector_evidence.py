from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from assurance_lab.connectors import evidence as connector_evidence_module
from assurance_lab.connectors.contract import (
    ConnectorCapture,
    ConnectorDescriptor,
    VerifiedConnectorCapture,
)
from assurance_lab.connectors.evidence import (
    MAX_CONNECTOR_EVIDENCE_RECEIPT_BYTES,
    MAX_CONNECTOR_EVIDENCE_RECORD_BYTES,
    ConnectorEvidenceError,
    ConnectorEvidenceJob,
    connector_request_bytes,
    create_connector_evidence_job,
    verify_connector_evidence_bundle,
    verify_streamed_connector_evidence_bundle,
    write_connector_evidence_bundle,
)
from assurance_lab.evidence.canonical import (
    JSONLimits,
    canonical_json_bytes,
    canonical_jsonl_bytes,
)
from assurance_lab.evidence.snapshot import CABSnapshotError, capture_cab_snapshot

_DESCRIPTOR = ConnectorDescriptor(
    connector_id="test-readonly",
    connector_version="1.2.3",
    capture_media_type="application/vnd.example.capture.v1+json",
)
_SOURCE_DIGEST = f"sha256:{'a' * 64}"
_RECEIPT = canonical_json_bytes(
    {
        "connector": {"id": "test-readonly", "version": "1.2.3"},
        "nonce": "b" * 64,
        "source_locator_digest": _SOURCE_DIGEST,
    }
)
_RECORDS = canonical_jsonl_bytes(
    [
        {"id": "record:2", "severity": "high"},
        {"id": "record:1", "severity": "low"},
    ]
)
_REQUEST = connector_request_bytes(
    {
        "capture_id": "capture-001",
        "capture_nonce": "b" * 64,
        "window": {
            "end_exclusive": "2026-07-30T00:00:00Z",
            "start_inclusive": "2026-07-29T00:00:00Z",
        },
    }
)


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _capture(*, records: bytes = _RECORDS) -> ConnectorCapture:
    return ConnectorCapture(
        descriptor=_DESCRIPTOR,
        receipt_bytes=_RECEIPT,
        receipt_digest=_digest(_RECEIPT),
        records_jsonl=records,
        records_digest=_digest(records),
        record_count=2,
    )


def _verified(
    receipt: bytes,
    *,
    source_digest: str = _SOURCE_DIGEST,
    records: bytes = _RECORDS,
) -> VerifiedConnectorCapture:
    if receipt != _RECEIPT:
        raise ValueError("unexpected receipt")
    return VerifiedConnectorCapture(
        descriptor=_DESCRIPTOR,
        receipt_digest=_digest(receipt),
        records_jsonl=records,
        records_digest=_digest(records),
        record_count=2,
        source_locator_digest=source_digest,
        source_product="Test EDR",
        source_version=None,
    )


def _job() -> ConnectorEvidenceJob:
    return create_connector_evidence_job(
        job_id="connector-capture-001",
        descriptor=_DESCRIPTOR,
        source_locator_digest=_SOURCE_DIGEST,
        request_media_type="application/vnd.example.request.v1+json",
        request_bytes=_REQUEST,
    )


def test_verified_capture_enters_a_reopenable_cab(tmp_path: Path) -> None:
    job = _job()
    destination = tmp_path / "capture.cab"

    written = write_connector_evidence_bundle(
        destination,
        job=job,
        request_bytes=_REQUEST,
        capture=_capture(),
        receipt_verifier=_verified,
        receipt_verifier_id="test/independent-verifier-v1",
        created_at=datetime(2026, 7, 29, 12, 0, 1, tzinfo=UTC),
        as_of=datetime(2026, 7, 29, 12, 0, 0, tzinfo=UTC),
        source_revision="test-revision",
    )
    reopened = verify_connector_evidence_bundle(
        destination,
        expected_job=job,
        expected_request_bytes=_REQUEST,
        receipt_verifier=_verified,
        receipt_verifier_id="test/independent-verifier-v1",
        expected_source_revision="test-revision",
    )

    assert reopened.cab_id == written.cab_id
    assert reopened.receipt_digest == written.receipt_digest == _digest(_RECEIPT)
    assert reopened.records_digest == written.records_digest == _digest(_RECORDS)
    assert reopened.record_count == written.record_count == 2
    assert capture_cab_snapshot(destination).cab_id == written.cab_id
    assert written.stream_snapshot_root.is_dir()
    streamed = verify_streamed_connector_evidence_bundle(
        written.stream_snapshot_root,
        expected_snapshot_digest=written.snapshot_digest,
        expected_job=job,
        expected_request_bytes=_REQUEST,
        receipt_verifier=_verified,
        receipt_verifier_id="test/independent-verifier-v1",
        expected_source_revision="test-revision",
    )
    assert streamed.cab_id == written.cab_id


def test_writer_rejects_collector_records_that_differ_from_receipt_recomputation(
    tmp_path: Path,
) -> None:
    foreign = canonical_jsonl_bytes(
        [
            {"id": "record:1", "severity": "low"},
            {"id": "record:2", "severity": "critical"},
        ]
    )

    with pytest.raises(ConnectorEvidenceError, match="differs"):
        write_connector_evidence_bundle(
            tmp_path / "capture.cab",
            job=_job(),
            request_bytes=_REQUEST,
            capture=_capture(records=foreign),
            receipt_verifier=_verified,
            receipt_verifier_id="test/independent-verifier-v1",
            created_at=datetime(2026, 7, 29, 12, 0, 1, tzinfo=UTC),
            as_of=datetime(2026, 7, 29, 12, 0, 0, tzinfo=UTC),
            source_revision="test-revision",
        )


def test_writer_rejects_a_receipt_verified_for_another_source(tmp_path: Path) -> None:
    def foreign_source(receipt: bytes) -> VerifiedConnectorCapture:
        return _verified(receipt, source_digest=f"sha256:{'f' * 64}")

    with pytest.raises(ConnectorEvidenceError, match="source"):
        write_connector_evidence_bundle(
            tmp_path / "capture.cab",
            job=_job(),
            request_bytes=_REQUEST,
            capture=_capture(),
            receipt_verifier=foreign_source,
            receipt_verifier_id="test/independent-verifier-v1",
            created_at=datetime(2026, 7, 29, 12, 0, 1, tzinfo=UTC),
            as_of=datetime(2026, 7, 29, 12, 0, 0, tzinfo=UTC),
            source_revision="test-revision",
        )


def test_reader_requires_the_out_of_band_job_and_request(tmp_path: Path) -> None:
    job = _job()
    destination = tmp_path / "capture.cab"
    write_connector_evidence_bundle(
        destination,
        job=job,
        request_bytes=_REQUEST,
        capture=_capture(),
        receipt_verifier=_verified,
        receipt_verifier_id="test/independent-verifier-v1",
        created_at=datetime(2026, 7, 29, 12, 0, 1, tzinfo=UTC),
        as_of=datetime(2026, 7, 29, 12, 0, 0, tzinfo=UTC),
        source_revision="test-revision",
    )
    other_request = connector_request_bytes(
        {
            "capture_id": "capture-002",
            "capture_nonce": "c" * 64,
            "window": {
                "end_exclusive": "2026-07-30T00:00:00Z",
                "start_inclusive": "2026-07-29T00:00:00Z",
            },
        }
    )
    other_job = create_connector_evidence_job(
        job_id="connector-capture-002",
        descriptor=_DESCRIPTOR,
        source_locator_digest=_SOURCE_DIGEST,
        request_media_type="application/vnd.example.request.v1+json",
        request_bytes=other_request,
    )

    with pytest.raises(ConnectorEvidenceError, match="differs"):
        verify_connector_evidence_bundle(
            destination,
            expected_job=other_job,
            expected_request_bytes=other_request,
            receipt_verifier=_verified,
            receipt_verifier_id="test/independent-verifier-v1",
            expected_source_revision="test-revision",
        )


def test_reader_detects_payload_change_even_if_the_source_directory_survives(
    tmp_path: Path,
) -> None:
    job = _job()
    destination = tmp_path / "capture.cab"
    write_connector_evidence_bundle(
        destination,
        job=job,
        request_bytes=_REQUEST,
        capture=_capture(),
        receipt_verifier=_verified,
        receipt_verifier_id="test/independent-verifier-v1",
        created_at=datetime(2026, 7, 29, 12, 0, 1, tzinfo=UTC),
        as_of=datetime(2026, 7, 29, 12, 0, 0, tzinfo=UTC),
        source_revision="test-revision",
    )
    (destination / "records/source-records.jsonl").write_bytes(
        b'{"id":"record:1","severity":"tampered"}\n'
    )

    with pytest.raises(ConnectorEvidenceError, match="safely sealed"):
        verify_connector_evidence_bundle(
            destination,
            expected_job=job,
            expected_request_bytes=_REQUEST,
            receipt_verifier=_verified,
            receipt_verifier_id="test/independent-verifier-v1",
            expected_source_revision="test-revision",
        )


def test_request_must_be_canonical_and_job_digest_must_close() -> None:
    with pytest.raises(ConnectorEvidenceError, match="canonical"):
        create_connector_evidence_job(
            job_id="connector-capture-001",
            descriptor=_DESCRIPTOR,
            source_locator_digest=_SOURCE_DIGEST,
            request_media_type="application/json",
            request_bytes=b'{ "capture_id": "not-canonical" }',
        )


def test_v2_reopens_a_connector_cab_larger_than_the_v1_inline_limit(
    tmp_path: Path,
) -> None:
    padding = "x" * (4 * 1024 * 1024)
    receipt = canonical_json_bytes(
        {
            "connector": {"id": "test-readonly", "version": "1.2.3"},
            "nonce": "b" * 64,
            "padding": padding,
            "source_locator_digest": _SOURCE_DIGEST,
        },
        limits=JSONLimits(
            max_bytes=6 * 1024 * 1024,
            max_line_bytes=6 * 1024 * 1024,
            max_depth=8,
            max_collection_items=32,
            max_string_length=5 * 1024 * 1024,
        ),
    )
    capture = ConnectorCapture(
        descriptor=_DESCRIPTOR,
        receipt_bytes=receipt,
        receipt_digest=_digest(receipt),
        records_jsonl=_RECORDS,
        records_digest=_digest(_RECORDS),
        record_count=2,
    )

    def verify_large(observed: bytes) -> VerifiedConnectorCapture:
        if observed != receipt:
            raise ValueError("unexpected receipt")
        return VerifiedConnectorCapture(
            descriptor=_DESCRIPTOR,
            receipt_digest=_digest(observed),
            records_jsonl=_RECORDS,
            records_digest=_digest(_RECORDS),
            record_count=2,
            source_locator_digest=_SOURCE_DIGEST,
            source_product="Test EDR",
            source_version=None,
        )

    destination = tmp_path / "large.cab"
    written = write_connector_evidence_bundle(
        destination,
        job=_job(),
        request_bytes=_REQUEST,
        capture=capture,
        receipt_verifier=verify_large,
        receipt_verifier_id="test/large-verifier-v1",
        created_at=datetime(2026, 7, 29, 12, 0, 1, tzinfo=UTC),
        as_of=datetime(2026, 7, 29, 12, 0, 0, tzinfo=UTC),
        source_revision="test-revision",
    )

    with pytest.raises(CABSnapshotError, match="limit"):
        capture_cab_snapshot(destination)
    reopened = verify_streamed_connector_evidence_bundle(
        written.stream_snapshot_root,
        expected_snapshot_digest=written.snapshot_digest,
        expected_job=_job(),
        expected_request_bytes=_REQUEST,
        receipt_verifier=verify_large,
        receipt_verifier_id="test/large-verifier-v1",
        expected_source_revision="test-revision",
    )
    assert reopened.cab_id == written.cab_id
    assert reopened.receipt_digest == _digest(receipt)


def test_connector_evidence_rejects_inputs_over_its_explicit_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert MAX_CONNECTOR_EVIDENCE_RECEIPT_BYTES == 96 * 1024 * 1024
    assert MAX_CONNECTOR_EVIDENCE_RECORD_BYTES == 64 * 1024 * 1024
    monkeypatch.setattr(
        connector_evidence_module,
        "MAX_CONNECTOR_EVIDENCE_RECEIPT_BYTES",
        len(_RECEIPT) - 1,
    )

    with pytest.raises(ConnectorEvidenceError, match="receipt exceeds"):
        write_connector_evidence_bundle(
            tmp_path / "capture.cab",
            job=_job(),
            request_bytes=_REQUEST,
            capture=_capture(),
            receipt_verifier=_verified,
            receipt_verifier_id="test/independent-verifier-v1",
            created_at=datetime(2026, 7, 29, 12, 0, 1, tzinfo=UTC),
            as_of=datetime(2026, 7, 29, 12, 0, 0, tzinfo=UTC),
            source_revision="test-revision",
        )
    monkeypatch.setattr(
        connector_evidence_module,
        "MAX_CONNECTOR_EVIDENCE_RECEIPT_BYTES",
        MAX_CONNECTOR_EVIDENCE_RECEIPT_BYTES,
    )
    monkeypatch.setattr(
        connector_evidence_module,
        "MAX_CONNECTOR_EVIDENCE_RECORD_BYTES",
        len(_RECORDS) - 1,
    )
    with pytest.raises(ConnectorEvidenceError, match="records exceed"):
        write_connector_evidence_bundle(
            tmp_path / "records.cab",
            job=_job(),
            request_bytes=_REQUEST,
            capture=_capture(),
            receipt_verifier=_verified,
            receipt_verifier_id="test/independent-verifier-v1",
            created_at=datetime(2026, 7, 29, 12, 0, 1, tzinfo=UTC),
            as_of=datetime(2026, 7, 29, 12, 0, 0, tzinfo=UTC),
            source_revision="test-revision",
        )


def test_streamed_reopen_rejects_blob_tampering(tmp_path: Path) -> None:
    job = _job()
    written = write_connector_evidence_bundle(
        tmp_path / "capture.cab",
        job=job,
        request_bytes=_REQUEST,
        capture=_capture(),
        receipt_verifier=_verified,
        receipt_verifier_id="test/independent-verifier-v1",
        created_at=datetime(2026, 7, 29, 12, 0, 1, tzinfo=UTC),
        as_of=datetime(2026, 7, 29, 12, 0, 0, tzinfo=UTC),
        source_revision="test-revision",
    )
    descriptor = json.loads(
        (written.stream_snapshot_root / "snapshot.json").read_bytes()
    )
    receipt_digest = next(
        entry["digest"]
        for entry in descriptor["entries"]
        if entry["path"] == "artifacts/source-receipt.json"
    )
    blob = written.stream_snapshot_root / "blobs" / receipt_digest.removeprefix("sha256:")
    blob.write_bytes(b"tampered")

    with pytest.raises(ConnectorEvidenceError, match="safely reopened"):
        verify_streamed_connector_evidence_bundle(
            written.stream_snapshot_root,
            expected_snapshot_digest=written.snapshot_digest,
            expected_job=job,
            expected_request_bytes=_REQUEST,
            receipt_verifier=_verified,
            receipt_verifier_id="test/independent-verifier-v1",
            expected_source_revision="test-revision",
        )


def test_streamed_reopen_detects_tampering_during_receipt_recomputation(
    tmp_path: Path,
) -> None:
    job = _job()
    written = write_connector_evidence_bundle(
        tmp_path / "capture.cab",
        job=job,
        request_bytes=_REQUEST,
        capture=_capture(),
        receipt_verifier=_verified,
        receipt_verifier_id="test/independent-verifier-v1",
        created_at=datetime(2026, 7, 29, 12, 0, 1, tzinfo=UTC),
        as_of=datetime(2026, 7, 29, 12, 0, 0, tzinfo=UTC),
        source_revision="test-revision",
    )
    descriptor = json.loads(
        (written.stream_snapshot_root / "snapshot.json").read_bytes()
    )
    records_digest = next(
        entry["digest"]
        for entry in descriptor["entries"]
        if entry["path"] == "records/source-records.jsonl"
    )
    records_blob = (
        written.stream_snapshot_root
        / "blobs"
        / records_digest.removeprefix("sha256:")
    )

    def tamper_while_verifying(receipt: bytes) -> VerifiedConnectorCapture:
        verified = _verified(receipt)
        records_blob.write_bytes(b"tampered-during-verification")
        return verified

    with pytest.raises(ConnectorEvidenceError, match="changed during semantic"):
        verify_streamed_connector_evidence_bundle(
            written.stream_snapshot_root,
            expected_snapshot_digest=written.snapshot_digest,
            expected_job=job,
            expected_request_bytes=_REQUEST,
            receipt_verifier=tamper_while_verifying,
            receipt_verifier_id="test/independent-verifier-v1",
            expected_source_revision="test-revision",
        )
