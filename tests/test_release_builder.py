from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

import pytest

import assurance_lab.benchmark.release_builder as release_builder
from assurance_lab.benchmark.cab import raw_sha256
from assurance_lab.benchmark.models import BenchmarkSemanticResult, canonical_digest
from assurance_lab.benchmark.release_builder import (
    PublicReleaseError,
    PublicReleaseSummary,
    PublishedBenchmarkRelease,
    build_public_release,
    verify_public_release,
)
from assurance_lab.evidence.canonical import canonical_json_bytes, strict_json_loads


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


@pytest.fixture(scope="module")
def repeated_releases(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[PublishedBenchmarkRelease, PublishedBenchmarkRelease]:
    parent = tmp_path_factory.mktemp("public-release")
    os.chmod(parent, 0o700)
    return (
        build_public_release(parent / "first"),
        build_public_release(parent / "second"),
    )


def test_release_is_exactly_reproducible_and_reopens(
    repeated_releases: tuple[
        PublishedBenchmarkRelease,
        PublishedBenchmarkRelease,
    ],
) -> None:
    first, second = repeated_releases

    assert _tree_bytes(first.root) == _tree_bytes(second.root)
    assert first.release_digest == second.release_digest
    assert first.release_manifest_digest == second.release_manifest_digest
    assert first.index_digest == second.index_digest
    assert first.corpus_digest == second.corpus_digest
    assert first.semantic_verification_receipt_digest == second.semantic_verification_receipt_digest
    assert (
        first.rejected_count,
        first.indeterminate_count,
        first.conflicting_count,
    ) == (15, 4, 1)
    reopened = verify_public_release(first.root)
    assert reopened.release_digest == first.release_digest
    assert reopened.release_manifest_digest == first.release_manifest_digest


def test_release_summary_is_derived_from_the_typed_semantic_corpus(
    repeated_releases: tuple[
        PublishedBenchmarkRelease,
        PublishedBenchmarkRelease,
    ],
) -> None:
    summary = PublicReleaseSummary.model_validate_json(
        (repeated_releases[0].root / "summary.json").read_bytes(),
        strict=True,
    )

    assert summary.total_cells == 48
    assert summary.agreed_cells == 48
    assert summary.total_trials == 144
    assert summary.seeded_masked_target_failure_cells == 8
    assert summary.baseline_pass_target_refuted_masking_cells == 8
    assert summary.false_supported_target_cells == 0
    assert summary.semantic_issue_count == 0
    assert len(summary.rejected) == 15
    assert summary.indeterminate == ("C07", "C08", "C09", "C11")
    assert summary.conflicting == ("C13",)


def test_release_pins_primary_evaluator_attribution(
    repeated_releases: tuple[
        PublishedBenchmarkRelease,
        PublishedBenchmarkRelease,
    ],
) -> None:
    root = repeated_releases[0].root
    semantic = BenchmarkSemanticResult.model_validate_json(
        (root / "semantic" / "primary.json").read_bytes(),
        strict=True,
    )
    source_identity = (root / "semantic" / "primary-source-identity.json").read_bytes()
    release_builder._verify_primary_evaluator_identity(semantic, source_identity)

    hostile = semantic.model_copy(update={"evaluator_id": "coherent-but-foreign-evaluator"})
    with pytest.raises(PublicReleaseError, match="foreign evaluator identity"):
        release_builder._verify_primary_evaluator_identity(hostile, source_identity)


def test_release_is_no_replace(
    repeated_releases: tuple[
        PublishedBenchmarkRelease,
        PublishedBenchmarkRelease,
    ],
) -> None:
    existing = repeated_releases[0].root
    before = _tree_bytes(existing)

    with pytest.raises(FileExistsError, match="already exists"):
        build_public_release(existing)

    assert _tree_bytes(existing) == before


def test_interrupted_build_leaves_no_staging_or_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    os.chmod(tmp_path, 0o700)
    destination = tmp_path / "interrupted"
    before = tuple(tmp_path.iterdir())

    def interrupt(_root: Path) -> Any:
        raise KeyboardInterrupt

    monkeypatch.setattr(
        release_builder,
        "build_public_benchmark",
        interrupt,
    )
    with pytest.raises(KeyboardInterrupt):
        build_public_release(destination)

    assert not destination.exists()
    assert tuple(tmp_path.iterdir()) == before


def test_atomic_publish_removes_destination_after_post_rename_interrupt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    os.chmod(tmp_path, 0o700)
    staging = tmp_path / ".release.staging"
    destination = tmp_path / "release"
    staging.mkdir(mode=0o700)
    (staging / "proof.json").write_bytes(b'{"verified":true}')
    pinned_parent = os.lstat(tmp_path)
    pinned_staging = os.lstat(staging)
    real_rename = release_builder._rename_noreplace

    def rename_then_interrupt(
        source: Path,
        target: Path,
        *,
        pinned_parent: os.stat_result,
    ) -> None:
        real_rename(
            source,
            target,
            pinned_parent=pinned_parent,
        )
        raise KeyboardInterrupt

    monkeypatch.setattr(
        release_builder,
        "_rename_noreplace",
        rename_then_interrupt,
    )
    with pytest.raises(KeyboardInterrupt):
        release_builder._publish_verified_staging(
            staging,
            destination,
            pinned_parent=pinned_parent,
            pinned_staging=pinned_staging,
        )

    assert not staging.exists()
    assert not destination.exists()
    assert tuple(tmp_path.iterdir()) == ()


def test_outer_manifest_rejects_one_byte_tampering(
    repeated_releases: tuple[
        PublishedBenchmarkRelease,
        PublishedBenchmarkRelease,
    ],
    tmp_path: Path,
) -> None:
    copy = tmp_path / "tampered"
    shutil.copytree(repeated_releases[0].root, copy)
    target = copy / "summary.json"
    changed = bytearray(target.read_bytes())
    changed[-1] ^= 1
    target.write_bytes(changed)

    with pytest.raises(PublicReleaseError, match="outer manifest does not bind"):
        verify_public_release(copy)


def test_release_rejects_a_coherently_manifested_extra_file(
    repeated_releases: tuple[
        PublishedBenchmarkRelease,
        PublishedBenchmarkRelease,
    ],
    tmp_path: Path,
) -> None:
    copy = tmp_path / "coherent-extra"
    shutil.copytree(repeated_releases[0].root, copy)
    extra = b"described but outside the frozen release profile"
    (copy / "extra.bin").write_bytes(extra)
    manifest_path = copy / "release-manifest.json"
    manifest = strict_json_loads(manifest_path.read_bytes())
    assert isinstance(manifest, dict)
    files = manifest["files"]
    assert isinstance(files, list)
    files.append(
        {
            "path": "extra.bin",
            "sha256": raw_sha256(extra),
            "size": len(extra),
        }
    )
    files.sort(key=lambda item: item["path"])
    manifest["file_count"] = len(files)
    manifest.pop("release_digest")
    manifest["release_digest"] = canonical_digest(manifest)
    manifest_path.write_bytes(canonical_json_bytes(manifest))

    with pytest.raises(PublicReleaseError, match="exact v1 profile"):
        verify_public_release(copy)


def test_release_rejects_an_extra_empty_directory(
    repeated_releases: tuple[
        PublishedBenchmarkRelease,
        PublishedBenchmarkRelease,
    ],
    tmp_path: Path,
) -> None:
    copy = tmp_path / "empty-directory"
    shutil.copytree(repeated_releases[0].root, copy)
    (copy / "evil").mkdir()

    with pytest.raises(PublicReleaseError, match="directory topology"):
        verify_public_release(copy)


def test_safe_tree_detects_in_place_change_after_a_file_was_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "tree"
    nested = root / "a"
    nested.mkdir(parents=True)
    early = nested / "early.json"
    early.write_bytes(b'{"ok":true}')
    late = root / "z-large.bin"
    late.write_bytes(b"x" * (2 * 1024 * 1024))
    real_read = os.read
    changed = False

    def racing_read(descriptor: int, count: int) -> bytes:
        nonlocal changed
        payload = real_read(descriptor, count)
        if not changed and os.fstat(descriptor).st_size == late.stat().st_size:
            changed = True
            early.write_bytes(b'{"ok":false,"changed":true}')
        return payload

    monkeypatch.setattr(os, "read", racing_read)
    with pytest.raises(PublicReleaseError, match="whole-tree"):
        release_builder._safe_release_tree(root)


def test_safe_tree_rejects_deep_and_directory_bomb_inputs(tmp_path: Path) -> None:
    deep = tmp_path / "deep"
    (deep / "one" / "two" / "three").mkdir(parents=True)
    with pytest.raises(PublicReleaseError, match="depth bound"):
        release_builder._safe_release_tree(deep)

    wide = tmp_path / "wide"
    wide.mkdir()
    for index in range(release_builder._MAX_RELEASE_DIRECTORIES):
        (wide / f"d{index:02d}").mkdir()
    with pytest.raises(PublicReleaseError, match="directory bounds"):
        release_builder._safe_release_tree(wide)


def test_node_source_identity_detects_a_late_in_place_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "verifier-js"
    source = package / "src"
    source.mkdir(parents=True)
    (package / "package.json").write_bytes(b'{"name":"cab-integrity-verifier","version":"0.2.0"}')
    first = source / "a.js"
    first.write_bytes(b"export const a = 1;\n")
    (source / "b.js").write_bytes(b"export const b = 2;\n")
    real_read = release_builder._read_file_at

    def racing_read(*args: Any, **kwargs: Any) -> Any:
        result = real_read(*args, **kwargs)
        if kwargs["relative_path"] == "src/b.js":
            first.write_bytes(b"export const a = 999;\n")
        return result

    monkeypatch.setattr(release_builder, "_read_file_at", racing_read)
    with pytest.raises(PublicReleaseError, match="changed during"):
        release_builder._derive_node_source_identity(tmp_path)


def test_node_source_identity_rejects_an_unaddressed_foreign_member(
    tmp_path: Path,
) -> None:
    package = tmp_path / "verifier-js"
    source = package / "src"
    source.mkdir(parents=True)
    (package / "package.json").write_bytes(b'{"name":"cab-integrity-verifier","version":"0.2.0"}')
    (source / "verifier.js").write_bytes(b"export const verified = true;\n")
    (source / "mutable-loader.mjs").write_bytes(b"export default false;\n")

    with pytest.raises(PublicReleaseError, match="foreign member"):
        release_builder._derive_node_source_identity(tmp_path)


def test_node_source_identity_rejects_a_source_file_bomb(tmp_path: Path) -> None:
    package = tmp_path / "verifier-js"
    source = package / "src"
    source.mkdir(parents=True)
    (package / "package.json").write_bytes(b'{"name":"cab-integrity-verifier","version":"0.2.0"}')
    for index in range(release_builder._MAX_NODE_SOURCE_FILES + 1):
        (source / f"f{index:02d}.js").write_bytes(b"export {};\n")

    with pytest.raises(PublicReleaseError, match="file bound"):
        release_builder._derive_node_source_identity(tmp_path)


def test_frozen_profile_file_is_human_readable_canonical_json(
    repeated_releases: tuple[
        PublishedBenchmarkRelease,
        PublishedBenchmarkRelease,
    ],
) -> None:
    document = strict_json_loads(
        (repeated_releases[0].root / "corruptions" / "specifications.json").read_bytes()
    )

    assert document["wire_schema"] == ("assurance-lab.benchmark.frozen-corruption-profile/v1")
    assert [item["corruption_id"] for item in document["corruptions"]] == [
        f"C{number:02d}" for number in range(1, 21)
    ]
