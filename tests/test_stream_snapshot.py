from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from assurance_lab.evidence import stream_snapshot as stream_snapshot_module
from assurance_lab.evidence.bundle import (
    EvaluationRef,
    EvaluatorRef,
    ExperimentRef,
    Sensitivity,
)
from assurance_lab.evidence.stream_snapshot import (
    StreamSnapshotError,
    StreamSnapshotLimits,
    capture_streamed_cab_snapshot,
    read_streamed_cab_snapshot_entries,
    verify_streamed_cab_snapshot,
)
from assurance_lab.evidence.writer import BundleMetadata, PayloadFile, write_bundle


def _write_cab(
    destination: Path,
    payloads: tuple[tuple[str, bytes], ...] = (
        ("records/events.bin", b"event-one"),
        ("artifacts/receipt.bin", b"receipt-one"),
    ),
) -> None:
    metadata = BundleMetadata(
        created_at=datetime(2026, 7, 29, 12, 0, 1, tzinfo=UTC),
        as_of=datetime(2026, 7, 29, 12, 0, 0, tzinfo=UTC),
        experiment=ExperimentRef(
            id="stream-snapshot-test",
            spec_version="1.0.0",
            spec_digest=f"sha256:{'a' * 64}",
        ),
        evaluation=EvaluationRef(
            policy_id="policy:stream-snapshot-test",
            policy_digest=f"sha256:{'b' * 64}",
            evaluator=EvaluatorRef(
                name="stream-snapshot-test",
                version="1.0.0",
                source_revision="test",
                image_digest=None,
            ),
        ),
    )
    result = write_bundle(
        destination,
        metadata=metadata,
        payloads=tuple(
            PayloadFile(
                path=path,
                content=content,
                media_type="application/octet-stream",
                role="test-evidence",
                sensitivity=Sensitivity.SYNTHETIC,
                required_for=("stream-snapshot-test",),
            )
            for path, content in payloads
        ),
    )
    assert result.bundle_id is not None


def test_large_profile_snapshot_is_content_addressed_and_reopenable(
    tmp_path: Path,
) -> None:
    source = tmp_path / "cab"
    snapshot = tmp_path / "snapshot"
    _write_cab(source)

    captured = capture_streamed_cab_snapshot(source, snapshot)
    reopened = verify_streamed_cab_snapshot(
        snapshot,
        expected_snapshot_digest=captured.snapshot_digest,
    )

    assert reopened.cab_id == captured.cab_id
    assert reopened.descriptor_bytes == captured.descriptor_bytes
    assert reopened.file_count == 3
    assert reopened.total_bytes == sum(entry.size for entry in reopened.descriptor.entries)
    assert sorted(path.name for path in (snapshot / "blobs").iterdir()) == sorted(
        {entry.digest.removeprefix("sha256:") for entry in reopened.descriptor.entries}
    )


def test_duplicate_payload_bytes_share_one_blob_without_losing_paths(
    tmp_path: Path,
) -> None:
    source = tmp_path / "cab"
    snapshot = tmp_path / "snapshot"
    _write_cab(
        source,
        (
            ("records/first.bin", b"same-content"),
            ("artifacts/second.bin", b"same-content"),
        ),
    )

    captured = capture_streamed_cab_snapshot(source, snapshot)

    assert captured.file_count == 3
    assert len(tuple((snapshot / "blobs").iterdir())) == 2
    assert captured.descriptor.entries[1].digest == captured.descriptor.entries[2].digest


def test_exact_per_file_boundary_is_accepted_and_plus_one_is_rejected(
    tmp_path: Path,
) -> None:
    limits = StreamSnapshotLimits(
        max_manifest_bytes=4_096,
        max_file_bytes=4_096,
        max_total_bytes=8_192,
        max_files=8,
    )
    exact = tmp_path / "exact"
    _write_cab(exact, (("records/boundary.bin", b"x" * 4_096),))
    accepted = capture_streamed_cab_snapshot(
        exact,
        tmp_path / "exact-snapshot",
        limits=limits,
    )
    assert accepted.descriptor.entries[1].size == 4_096

    over = tmp_path / "over"
    _write_cab(over, (("records/boundary.bin", b"x" * 4_097),))
    with pytest.raises(StreamSnapshotError, match="not integrity verified"):
        capture_streamed_cab_snapshot(
            over,
            tmp_path / "over-snapshot",
            limits=limits,
        )


def test_corrupt_blob_and_unexpected_blob_are_rejected(tmp_path: Path) -> None:
    source = tmp_path / "cab"
    snapshot = tmp_path / "snapshot"
    _write_cab(source)
    captured = capture_streamed_cab_snapshot(source, snapshot)
    payload_entry = captured.descriptor.entries[1]
    blob = snapshot / "blobs" / payload_entry.digest.removeprefix("sha256:")
    blob.write_bytes(b"forged")

    with pytest.raises(StreamSnapshotError, match=r"wrong size|differs"):
        verify_streamed_cab_snapshot(snapshot)

    source_two = tmp_path / "cab-two"
    snapshot_two = tmp_path / "snapshot-two"
    _write_cab(source_two)
    capture_streamed_cab_snapshot(source_two, snapshot_two)
    (snapshot_two / "blobs" / ("f" * 64)).write_bytes(b"orphan")
    with pytest.raises(StreamSnapshotError, match="does not close"):
        verify_streamed_cab_snapshot(snapshot_two)


def test_descriptor_is_canonical_and_externally_anchored(tmp_path: Path) -> None:
    source = tmp_path / "cab"
    snapshot = tmp_path / "snapshot"
    _write_cab(source)
    capture_streamed_cab_snapshot(source, snapshot)

    with pytest.raises(StreamSnapshotError, match="external digest"):
        verify_streamed_cab_snapshot(
            snapshot,
            expected_snapshot_digest=f"sha256:{'0' * 64}",
        )

    descriptor_path = snapshot / "snapshot.json"
    document = json.loads(descriptor_path.read_bytes())
    descriptor_path.write_text(
        json.dumps(document, indent=2),
        encoding="utf-8",
    )
    with pytest.raises(StreamSnapshotError, match="canonical"):
        verify_streamed_cab_snapshot(snapshot)


def test_source_hardlinks_and_snapshot_symlinks_fail_closed(tmp_path: Path) -> None:
    source = tmp_path / "cab"
    _write_cab(source)
    os.link(source / "records/events.bin", source / "records/alias.bin")
    with pytest.raises(StreamSnapshotError, match="not integrity verified"):
        capture_streamed_cab_snapshot(source, tmp_path / "hardlink-snapshot")

    clean = tmp_path / "clean"
    snapshot = tmp_path / "snapshot"
    _write_cab(clean)
    captured = capture_streamed_cab_snapshot(clean, snapshot)
    entry = captured.descriptor.entries[1]
    blob = snapshot / "blobs" / entry.digest.removeprefix("sha256:")
    replacement = tmp_path / "replacement"
    replacement.write_bytes(blob.read_bytes())
    blob.unlink()
    blob.symlink_to(replacement)
    with pytest.raises(StreamSnapshotError, match=r"unsafe|verify"):
        verify_streamed_cab_snapshot(snapshot)


def test_selected_entries_are_read_during_the_anchored_verification_pass(
    tmp_path: Path,
) -> None:
    source = tmp_path / "cab"
    snapshot = tmp_path / "snapshot"
    _write_cab(source)
    captured = capture_streamed_cab_snapshot(source, snapshot)

    reopened, entries = read_streamed_cab_snapshot_entries(
        snapshot,
        expected_snapshot_digest=captured.snapshot_digest,
        entry_limits={"records/events.bin": len(b"event-one")},
    )

    assert reopened.snapshot_digest == captured.snapshot_digest
    assert entries == (("records/events.bin", b"event-one"),)


def test_ancestor_symlink_is_rejected_even_when_it_resolves_to_a_valid_cab(
    tmp_path: Path,
) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    source = real_parent / "cab"
    _write_cab(source)
    alias = tmp_path / "alias"
    alias.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(StreamSnapshotError, match=r"component|pin"):
        capture_streamed_cab_snapshot(
            alias / "cab",
            tmp_path / "snapshot",
        )


def test_failed_capture_does_not_delete_an_attacker_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "cab"
    snapshot = tmp_path / "snapshot"
    displaced = tmp_path / "displaced"
    _write_cab(source)
    real_stream = stream_snapshot_module._stream_source
    attacked = False

    def replace_destination(*args: object, **kwargs: object) -> tuple[str, int]:
        nonlocal attacked
        if not attacked:
            attacked = True
            snapshot.rename(displaced)
            snapshot.mkdir()
            (snapshot / "attacker-owned").write_bytes(b"do-not-delete")
            raise StreamSnapshotError("injected capture failure")
        return real_stream(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(stream_snapshot_module, "_stream_source", replace_destination)

    with pytest.raises(StreamSnapshotError, match="injected"):
        capture_streamed_cab_snapshot(source, snapshot)

    assert (snapshot / "attacker-owned").read_bytes() == b"do-not-delete"
    assert displaced.is_dir()


@pytest.mark.skipif(
    os.environ.get("CONTROL_ASSURANCE_RUN_LARGE_TESTS") != "1",
    reason="set CONTROL_ASSURANCE_RUN_LARGE_TESTS=1 for the real 64 MiB boundary",
)
def test_real_64_mib_file_boundary_streams_without_an_inline_snapshot(
    tmp_path: Path,
) -> None:
    boundary = 64 * 1024 * 1024
    source = tmp_path / "cab"
    snapshot = tmp_path / "snapshot"
    _write_cab(source, (("records/boundary.bin", b"x" * boundary),))
    limits = StreamSnapshotLimits(
        max_manifest_bytes=4_096,
        max_file_bytes=boundary,
        max_total_bytes=boundary + 4_096,
        max_files=2,
    )

    captured = capture_streamed_cab_snapshot(
        source,
        snapshot,
        limits=limits,
    )

    assert captured.descriptor.entries[1].size == boundary
    assert captured.total_bytes <= boundary + 4_096
