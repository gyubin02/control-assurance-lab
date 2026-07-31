from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_CANONICALIZER = _ROOT / "scripts" / "canonicalize-buildkit-layout.py"


def _run(layout: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_CANONICALIZER), str(layout)],
        check=False,
        capture_output=True,
        text=True,
    )


def test_removes_only_an_empty_buildkit_ingest_workspace(tmp_path: Path) -> None:
    layout = tmp_path / "layout"
    ingest = layout / "ingest"
    ingest.mkdir(parents=True)
    (layout / "index.json").write_text("{}\n", encoding="utf-8")

    result = _run(layout)

    assert result.returncode == 0
    assert not ingest.exists()
    assert (layout / "index.json").read_text(encoding="utf-8") == "{}\n"


@pytest.mark.parametrize("condition", ["missing", "nonempty", "symlink"])
def test_rejects_any_noncanonical_ingest_state_without_deleting_it(
    tmp_path: Path, condition: str
) -> None:
    layout = tmp_path / "layout"
    layout.mkdir()
    ingest = layout / "ingest"

    if condition == "nonempty":
        ingest.mkdir()
        (ingest / "active").write_text("incomplete\n", encoding="utf-8")
    elif condition == "symlink":
        target = tmp_path / "target"
        target.mkdir()
        ingest.symlink_to(target, target_is_directory=True)

    result = _run(layout)

    assert result.returncode == 1
    assert result.stderr.startswith("layout canonicalization rejected:")
    if condition == "nonempty":
        assert (ingest / "active").read_text(encoding="utf-8") == "incomplete\n"
    elif condition == "symlink":
        assert ingest.is_symlink()
    else:
        assert not ingest.exists()
