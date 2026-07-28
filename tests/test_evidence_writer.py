from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from assurance_lab.evidence import writer as writer_module
from assurance_lab.evidence.bundle import (
    BundleStatus,
    EvaluationRef,
    EvaluatorRef,
    ExperimentRef,
    Sensitivity,
    verify_bundle,
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


def test_writer_rejects_destination_root_swap_to_foreign_valid_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "evidence"
    displaced = tmp_path / "displaced"
    foreign = tmp_path / "foreign"
    foreign_result = write_bundle(
        foreign,
        metadata=_metadata(),
        payloads=_payloads(),
    )
    real_verify = writer_module.verify_bundle

    def swap_then_verify(path: Path):
        path.rename(displaced)
        foreign.rename(path)
        return real_verify(path)

    monkeypatch.setattr(writer_module, "verify_bundle", swap_then_verify)

    with pytest.raises(BundleWriteError, match="destination root changed"):
        write_bundle(
            destination,
            metadata=_metadata(),
            payloads=_payloads(),
        )

    assert verify_bundle(destination).bundle_id == foreign_result.bundle_id
    assert verify_bundle(displaced).status == BundleStatus.INTEGRITY_VERIFIED


def test_writer_requires_the_exact_manifest_and_bundle_id_it_constructed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    foreign = tmp_path / "foreign"
    foreign_result = write_bundle(
        foreign,
        metadata=replace(
            _metadata(),
            parent_bundles=(f"cab:sha256:{'f' * 64}",),
        ),
        payloads=_payloads(),
    )
    monkeypatch.setattr(
        writer_module,
        "verify_bundle",
        lambda _path: foreign_result,
    )
    destination = tmp_path / "evidence"

    with pytest.raises(BundleWriteError, match="different manifest or bundle id"):
        write_bundle(
            destination,
            metadata=_metadata(),
            payloads=_payloads(),
        )

    assert not destination.exists()
