from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from assurance_lab.source_identity import (
    package_source_digest,
    package_source_manifest,
)


def test_installed_source_identity_covers_the_benchmark_evaluator() -> None:
    manifest = package_source_manifest()
    files = cast(list[dict[str, object]], manifest["files"])
    paths = {cast(str, entry["path"]) for entry in files}

    assert manifest["schema"] == "assurance-lab.python-source-set/v1"
    assert "benchmark/generator.py" in paths
    assert "scenarios/financial_detection_runtime.py" in paths
    assert "scenarios/financial_response_runtime.py" in paths
    assert "scenarios/financial_recovery_runtime.py" in paths
    assert package_source_digest().startswith("sha256:")


def test_source_identity_is_path_independent_and_changes_with_bytes(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    for root in (first, second):
        (root / "__init__.py").write_text('VALUE = "one"\n', encoding="utf-8")
        (root / "py.typed").write_bytes(b"")

    assert package_source_digest(first) == package_source_digest(second)

    (second / "__init__.py").write_text('VALUE = "two"\n', encoding="utf-8")
    assert package_source_digest(first) != package_source_digest(second)


def test_source_identity_rejects_a_symlinked_source_entry(tmp_path: Path) -> None:
    root = tmp_path / "package"
    root.mkdir()
    target = tmp_path / "outside.py"
    target.write_text("VALUE = 1\n", encoding="utf-8")
    (root / "linked.py").symlink_to(target)

    with pytest.raises(ValueError, match="must not contain symbolic links"):
        package_source_manifest(root)


def test_source_identity_rejects_a_symlinked_source_directory(
    tmp_path: Path,
) -> None:
    root = tmp_path / "package"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    (outside / "hidden.py").write_text("VALUE = 2\n", encoding="utf-8")
    (root / "linked").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="must not contain symbolic links"):
        package_source_manifest(root)
