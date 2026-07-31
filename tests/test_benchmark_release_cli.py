from __future__ import annotations

from pathlib import Path

import pytest

import assurance_lab.benchmark as benchmark_api
import assurance_lab.benchmark.release_builder as release_builder
import assurance_lab.benchmark_cli as benchmark_cli
from assurance_lab.benchmark.release_builder import (
    PublishedBenchmarkRelease,
    VerifiedPublicRelease,
)
from assurance_lab.cli import main
from assurance_lab.evidence.canonical import canonical_json_bytes, strict_json_loads


def _verified(root: Path) -> VerifiedPublicRelease:
    return VerifiedPublicRelease(
        root=root,
        release_digest="sha256:" + ("1" * 64),
        release_manifest_digest="sha256:" + ("2" * 64),
        index_digest="sha256:" + ("3" * 64),
        corpus_digest="sha256:" + ("4" * 64),
        semantic_verification_receipt_digest="sha256:" + ("5" * 64),
        rejected_count=15,
        indeterminate_count=4,
        conflicting_count=1,
    )


def _published(root: Path) -> PublishedBenchmarkRelease:
    verified = _verified(root)
    return PublishedBenchmarkRelease(
        root=verified.root,
        release_digest=verified.release_digest,
        release_manifest_digest=verified.release_manifest_digest,
        index_digest=verified.index_digest,
        corpus_digest=verified.corpus_digest,
        semantic_verification_receipt_digest=(verified.semantic_verification_receipt_digest),
        rejected_count=verified.rejected_count,
        indeterminate_count=verified.indeterminate_count,
        conflicting_count=verified.conflicting_count,
    )


def test_benchmark_package_exports_the_public_release_api() -> None:
    assert benchmark_api.build_public_release is release_builder.build_public_release
    assert benchmark_api.verify_public_release is release_builder.verify_public_release


def test_release_build_cli_delegates_once_and_emits_canonical_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "public-release"
    observed: list[Path] = []

    def build(path: Path) -> PublishedBenchmarkRelease:
        observed.append(path)
        return _published(path.absolute())

    monkeypatch.setattr(benchmark_cli, "build_public_release", build)

    assert (
        main(
            [
                "benchmark",
                "release",
                "build",
                str(destination),
                "--json",
            ]
        )
        == 0
    )

    captured = capsys.readouterr()
    assert captured.err == ""
    assert observed == [destination]
    payload = captured.out.encode("utf-8")
    assert canonical_json_bytes(strict_json_loads(payload)) == payload
    assert strict_json_loads(payload) == {
        "schema": "assurance-lab.benchmark.release-cli-result/v1",
        "operation": "build",
        "status": "verified",
        "release_digest": "sha256:" + ("1" * 64),
        "release_manifest_digest": "sha256:" + ("2" * 64),
        "index_digest": "sha256:" + ("3" * 64),
        "corpus_digest": "sha256:" + ("4" * 64),
        "semantic_verification_receipt_digest": "sha256:" + ("5" * 64),
        "corruptions": {
            "rejected": 15,
            "indeterminate": 4,
            "conflicting": 1,
        },
    }


def test_release_verify_cli_is_read_only_and_prints_the_verified_location(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    release = tmp_path / "public-release"
    release.mkdir()
    sentinel = release / "sentinel"
    sentinel.write_bytes(b"unchanged")
    observed: list[Path] = []

    def verify(path: Path) -> VerifiedPublicRelease:
        observed.append(path)
        return _verified(path)

    monkeypatch.setattr(benchmark_cli, "verify_public_release", verify)

    assert main(["benchmark", "release", "verify", str(release)]) == 0

    captured = capsys.readouterr()
    assert captured.err == ""
    assert observed == [release]
    assert "Benchmark release  VERIFIED" in captured.out
    assert f"Directory          {release}" in captured.out
    assert sentinel.read_bytes() == b"unchanged"


def test_release_build_cli_reports_failure_without_success_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "already-present"
    destination.mkdir()

    def reject(_path: Path) -> PublishedBenchmarkRelease:
        raise FileExistsError("release destination already exists")

    monkeypatch.setattr(benchmark_cli, "build_public_release", reject)

    assert main(["benchmark", "release", "build", str(destination)]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: release destination already exists\n"
