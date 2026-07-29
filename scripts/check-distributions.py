#!/usr/bin/env python3
"""Fail closed when release archives omit the public package contract."""

from __future__ import annotations

import argparse
import email.parser
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

PROJECT = "control_assurance_lab"
VERSION = "0.1.0"
WHEEL_REQUIRED = {
    "assurance_lab/py.typed",
    f"{PROJECT}-{VERSION}.dist-info/entry_points.txt",
    f"{PROJECT}-{VERSION}.dist-info/licenses/LICENSE",
    f"{PROJECT}-{VERSION}.dist-info/METADATA",
}
SDIST_REQUIRED = {
    "LICENSE",
    "README.md",
    "pyproject.toml",
    "src/assurance_lab/py.typed",
}


def _one(directory: Path, pattern: str) -> Path:
    matches = sorted(directory.glob(pattern))
    if len(matches) != 1:
        raise ValueError(f"expected one {pattern!r} in {directory}, found {len(matches)}")
    return matches[0]


def _safe_archive_name(name: str) -> bool:
    path = PurePosixPath(name)
    return not path.is_absolute() and ".." not in path.parts and "\\" not in name


def _check_wheel(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        if any(not _safe_archive_name(name) for name in names):
            raise ValueError("wheel contains an unsafe member path")
        missing = WHEEL_REQUIRED - names
        if missing:
            raise ValueError(f"wheel is missing required members: {sorted(missing)!r}")
        metadata_path = f"{PROJECT}-{VERSION}.dist-info/METADATA"
        metadata = email.parser.BytesParser().parsebytes(archive.read(metadata_path))
        expected = {
            "Name": "control-assurance-lab",
            "Version": VERSION,
            "License-Expression": "Apache-2.0",
            "Requires-Python": ">=3.12",
        }
        observed = {field: metadata.get(field) for field in expected}
        if observed != expected:
            raise ValueError(f"wheel metadata differs: {observed!r}")
        entry_points = archive.read(
            f"{PROJECT}-{VERSION}.dist-info/entry_points.txt"
        ).decode("utf-8")
        if "assurance-lab = assurance_lab.cli:main" not in entry_points:
            raise ValueError("wheel does not expose the assurance-lab command")


def _check_sdist(path: Path) -> None:
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        if any(not _safe_archive_name(member.name) for member in members):
            raise ValueError("sdist contains an unsafe member path")
        roots = {PurePosixPath(member.name).parts[0] for member in members}
        if len(roots) != 1:
            raise ValueError("sdist must contain exactly one top-level directory")
        root = next(iter(roots))
        relative = {
            PurePosixPath(member.name).relative_to(root).as_posix()
            for member in members
            if PurePosixPath(member.name).parts
        }
        missing = SDIST_REQUIRED - relative
        if missing:
            raise ValueError(f"sdist is missing required members: {sorted(missing)!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    arguments = parser.parse_args()
    wheel = _one(arguments.directory, f"{PROJECT}-{VERSION}-*.whl")
    sdist = _one(arguments.directory, f"control_assurance_lab-{VERSION}.tar.gz")
    _check_wheel(wheel)
    _check_sdist(sdist)
    print(f"release archives verified: {wheel.name}, {sdist.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
