from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from assurance_lab.evidence.bundle import (
    BundleStatus,
    EvaluationRef,
    EvaluatorRef,
    ExperimentRef,
    Sensitivity,
)
from assurance_lab.evidence.canonical import canonical_json_bytes, canonical_jsonl_bytes
from assurance_lab.evidence.writer import (
    BundleMetadata,
    BundleWriteError,
    PayloadFile,
    write_bundle,
)


def _metadata() -> BundleMetadata:
    as_of = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)
    return BundleMetadata(
        created_at=as_of + timedelta(seconds=1),
        as_of=as_of,
        experiment=ExperimentRef(
            id="financial-support-export",
            spec_version="3.0.0",
            spec_digest="sha256:" + "1" * 64,
        ),
        evaluation=EvaluationRef(
            policy_id="integrity-only-v1",
            policy_digest="sha256:" + "2" * 64,
            evaluator=EvaluatorRef(
                name="assurance-lab",
                version="0.0.1",
                source_revision="working-tree",
                image_digest=None,
            ),
        ),
    )


def _payloads() -> tuple[PayloadFile, ...]:
    return (
        PayloadFile(
            path="spec/experiment.json",
            content=canonical_json_bytes({"id": "financial-support-export"}),
            media_type="application/json",
            role="compiled experiment",
            sensitivity=Sensitivity.SYNTHETIC,
            required_for=("design",),
        ),
        PayloadFile(
            path="records/events.jsonl",
            content=canonical_jsonl_bytes(
                (
                    {"id": "event-2", "state": "allow"},
                    {"id": "event-1", "state": "deny"},
                )
            ),
            media_type="application/x-ndjson",
            role="raw runtime events",
            sensitivity=Sensitivity.LAB_INTERNAL,
            required_for=("target-local", "path"),
        ),
    )


def test_writer_produces_a_bundle_accepted_by_the_independent_verifier(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "evidence"

    result = write_bundle(
        destination,
        metadata=_metadata(),
        payloads=_payloads(),
    )

    assert result.status == BundleStatus.INTEGRITY_VERIFIED
    assert result.bundle_id is not None
    assert (destination / "bundle.json").is_file()


def test_writer_never_overwrites_an_existing_destination(tmp_path: Path) -> None:
    destination = tmp_path / "evidence"
    destination.mkdir()

    with pytest.raises(BundleWriteError, match="already exists"):
        write_bundle(
            destination,
            metadata=_metadata(),
            payloads=_payloads(),
        )


def test_writer_removes_a_bundle_that_fails_canonical_verification(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "evidence"
    invalid = (
        PayloadFile(
            path="records/events.jsonl",
            content=b'{"id":"event-1", "state":"deny"}\n',
            media_type="application/x-ndjson",
            role="raw runtime events",
            sensitivity=Sensitivity.LAB_INTERNAL,
            required_for=("target-local",),
        ),
    )

    with pytest.raises(BundleWriteError, match="failed verification"):
        write_bundle(
            destination,
            metadata=_metadata(),
            payloads=invalid,
        )
    assert not destination.exists()
