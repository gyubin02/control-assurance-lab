from __future__ import annotations

import hashlib
import os
import struct
from collections.abc import Callable
from pathlib import Path

import pytest

from assurance_lab.evidence.bundle import (
    PROFILE,
    ROOT_MEDIA_TYPE,
    SCHEMA_VERSION,
    BundleFile,
    BundleManifest,
    EvaluationRef,
    EvaluatorRef,
    ExperimentRef,
    Sensitivity,
)
from assurance_lab.evidence.snapshot import (
    CABSnapshotError,
    capture_cab_snapshot,
    verify_cab_snapshot,
)

_MAGIC = b"CONTROL-ASSURANCE-CAB-SNAPSHOT\x00\x01"


def _manifest(files: dict[str, bytes]) -> BundleManifest:
    return BundleManifest(
        media_type=ROOT_MEDIA_TYPE,
        schema_version=SCHEMA_VERSION,
        profile=PROFILE,
        created_at="2026-07-29T11:55:00.000000Z",
        as_of="2026-07-29T11:54:00.000000Z",
        experiment=ExperimentRef(
            id="snapshot-test",
            spec_version="1.0.0",
            spec_digest=f"sha256:{'7' * 64}",
        ),
        evaluation=EvaluationRef(
            policy_id="policy:snapshot-test:v1",
            policy_digest=f"sha256:{'8' * 64}",
            evaluator=EvaluatorRef(
                name="assurance-lab",
                version="0.1.0",
                source_revision="snapshot-test",
                image_digest=None,
            ),
        ),
        parent_bundles=[],
        files=[
            BundleFile(
                path=path,
                sha256=hashlib.sha256(content).hexdigest(),
                size=len(content),
                media_type="application/x-ndjson",
                role="control-observation",
                sensitivity=Sensitivity.SYNTHETIC,
                required_for=["admission"],
            )
            for path, content in sorted(files.items())
        ],
    )


def _write_cab(root: Path, files: dict[str, bytes]) -> BundleManifest:
    manifest = _manifest(files)
    for relative_path, content in files.items():
        target = root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    (root / "bundle.json").write_bytes(manifest.canonical_bytes())
    return manifest


def _wire(entries: tuple[tuple[str, bytes], ...]) -> bytes:
    value = bytearray(_MAGIC)
    value.extend(struct.pack(">I", len(entries)))
    for path, content in entries:
        encoded_path = path.encode("ascii")
        value.extend(struct.pack(">H", len(encoded_path)))
        value.extend(encoded_path)
        value.extend(struct.pack(">Q", len(content)))
        value.extend(content)
    return bytes(value)


def test_snapshot_is_deterministic_across_source_copies(tmp_path: Path) -> None:
    files = {
        "artifacts/attestation.jsonl": b'{"id":"attestation"}\n',
        "records/a.jsonl": b'{"id":"a"}\n',
        "records/b.jsonl": b'{"id":"b"}\n',
    }
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    manifest = _write_cab(first_root, files)
    _write_cab(second_root, files)
    os.utime(second_root / "records/a.jsonl", (1_000_000, 1_000_000))

    first = capture_cab_snapshot(first_root)
    second = capture_cab_snapshot(second_root)

    assert first.snapshot_bytes == second.snapshot_bytes
    assert first.snapshot_digest == second.snapshot_digest
    assert first.cab_id == second.cab_id == manifest.bundle_id()
    assert first.file_count == 4


def test_sealed_bytes_survive_source_mutation_and_a_new_manifest_changes_identity(
    tmp_path: Path,
) -> None:
    root = tmp_path / "cab"
    original = {"records/events.jsonl": b'{"approved":true,"id":"event:1"}\n'}
    manifest = _write_cab(root, original)
    sealed = capture_cab_snapshot(root)

    changed = {"records/events.jsonl": b'{"approved":false,"id":"event:1"}\n'}
    _write_cab(root, changed)
    replacement = capture_cab_snapshot(root)

    assert verify_cab_snapshot(sealed.snapshot_bytes).cab_id == manifest.bundle_id()
    assert replacement.snapshot_digest != sealed.snapshot_digest
    assert replacement.cab_id != sealed.cab_id


@pytest.mark.parametrize(
    "corrupt",
    (
        lambda value: value[:-1],
        lambda value: value + b"\x00",
        lambda value: value[:-1] + bytes([value[-1] ^ 1]),
    ),
    ids=("truncated", "trailing-byte", "content-tamper"),
)
def test_snapshot_corruption_is_rejected(
    tmp_path: Path,
    corrupt: Callable[[bytes], bytes],
) -> None:
    root = tmp_path / "cab"
    _write_cab(root, {"records/events.jsonl": b'{"approved":true,"id":"event:1"}\n'})
    snapshot = capture_cab_snapshot(root).snapshot_bytes

    with pytest.raises(CABSnapshotError):
        verify_cab_snapshot(corrupt(snapshot))


def test_duplicate_and_out_of_order_paths_are_rejected(tmp_path: Path) -> None:
    root = tmp_path / "cab"
    files = {
        "records/aa.jsonl": b'{"id":"a"}\n',
        "records/bb.jsonl": b'{"id":"b"}\n',
    }
    manifest = _write_cab(root, files)
    manifest_bytes = manifest.canonical_bytes()
    duplicate = _wire(
        (
            ("bundle.json", manifest_bytes),
            ("records/aa.jsonl", files["records/aa.jsonl"]),
            ("records/aa.jsonl", files["records/bb.jsonl"]),
        )
    )
    out_of_order = _wire(
        (
            ("bundle.json", manifest_bytes),
            ("records/bb.jsonl", files["records/bb.jsonl"]),
            ("records/aa.jsonl", files["records/aa.jsonl"]),
        )
    )

    with pytest.raises(CABSnapshotError, match="strictly sorted"):
        verify_cab_snapshot(duplicate)
    with pytest.raises(CABSnapshotError, match="strictly sorted"):
        verify_cab_snapshot(out_of_order)


def test_bundle_manifest_must_be_the_only_first_snapshot_entry(tmp_path: Path) -> None:
    root = tmp_path / "cab"
    files = {"artifacts/events.jsonl": b'{"id":"event:1"}\n'}
    manifest = _write_cab(root, files)
    manifest_bytes = manifest.canonical_bytes()
    payload = files["artifacts/events.jsonl"]
    misplaced = _wire(
        (
            ("artifacts/events.jsonl", payload),
            ("bundle.json", manifest_bytes),
        )
    )
    duplicated = _wire(
        (
            ("bundle.json", manifest_bytes),
            ("bundle.json", manifest_bytes),
            ("artifacts/events.jsonl", payload),
        )
    )

    with pytest.raises(CABSnapshotError, match=r"begin with bundle[.]json"):
        verify_cab_snapshot(misplaced)
    with pytest.raises(CABSnapshotError, match=r"only one leading bundle[.]json"):
        verify_cab_snapshot(duplicated)


@pytest.mark.parametrize(
    "path",
    ("records/\x00hidden.jsonl", "records/../escape.jsonl", "/records/root.jsonl"),
)
def test_unsafe_wire_paths_raise_snapshot_errors(path: str) -> None:
    malformed = _wire(
        (
            ("bundle.json", b"{}"),
            (path, b'{"id":"event:1"}\n'),
        )
    )

    with pytest.raises(CABSnapshotError, match="CAB-safe"):
        verify_cab_snapshot(malformed)


def test_snapshot_size_limit_applies_to_the_exact_encoded_object(tmp_path: Path) -> None:
    root = tmp_path / "cab"
    content = b'{"data":"' + (b"x" * 2048) + b'","id":"event:1"}\n'
    _write_cab(root, {"records/events.jsonl": content})
    snapshot = capture_cab_snapshot(root).snapshot_bytes

    with pytest.raises(CABSnapshotError, match="byte limit"):
        verify_cab_snapshot(snapshot, maximum=len(snapshot) - 1)


@pytest.mark.parametrize("hazard", ("unlisted", "symlink", "hardlink"))
def test_unsafe_source_entries_are_never_sealed(tmp_path: Path, hazard: str) -> None:
    root = tmp_path / hazard
    _write_cab(root, {"records/events.jsonl": b'{"approved":true,"id":"event:1"}\n'})
    if hazard == "unlisted":
        (root / "records/unlisted.jsonl").write_text('{"surprise":true}\n')
    elif hazard == "symlink":
        (root / "records/link").symlink_to(root / "bundle.json")
    else:
        os.link(
            root / "records/events.jsonl",
            root / "records/events-hardlink.jsonl",
        )

    with pytest.raises(CABSnapshotError):
        capture_cab_snapshot(root)
