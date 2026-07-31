#!/usr/bin/env python3
"""Fail closed when release archives omit the public package contract."""

from __future__ import annotations

import argparse
import email.parser
import tarfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath

from packaging.specifiers import SpecifierSet

PROJECT = "control_assurance_lab"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
with (REPOSITORY_ROOT / "pyproject.toml").open("rb") as _project_stream:
    _PROJECT_METADATA = tomllib.load(_project_stream)["project"]
VERSION = str(_PROJECT_METADATA["version"])
REQUIRES_PYTHON = str(
    SpecifierSet(str(_PROJECT_METADATA["requires-python"]))
)
VERIFIER_SOURCES = {
    "benchmark-cli.js",
    "benchmark-verifier.js",
    "cli.js",
    "defender-xdr-cli.js",
    "defender-xdr-verifier.js",
    "elastic-security-cli.js",
    "elastic-security-verifier.js",
    "source-identity.js",
    "strict-json.js",
    "verifier.js",
}
WHEEL_REQUIRED = {
    "assurance_lab/_release_assets/verifier-js/package.json",
    "assurance_lab/py.typed",
    f"{PROJECT}-{VERSION}.dist-info/entry_points.txt",
    f"{PROJECT}-{VERSION}.dist-info/licenses/LICENSE",
    f"{PROJECT}-{VERSION}.dist-info/METADATA",
    *{f"assurance_lab/_release_assets/verifier-js/src/{name}" for name in VERIFIER_SOURCES},
}
SDIST_REQUIRED = {
    "LICENSE",
    "README.md",
    "pyproject.toml",
    "src/assurance_lab/py.typed",
    "verifier-js/package.json",
    *{f"verifier-js/src/{name}" for name in VERIFIER_SOURCES},
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
        source_prefix = "assurance_lab/_release_assets/verifier-js/src/"
        observed_sources = {
            name.removeprefix(source_prefix)
            for name in names
            if name.startswith(source_prefix) and not name.endswith("/")
        }
        if observed_sources != VERIFIER_SOURCES:
            raise ValueError(
                "wheel verifier source set differs: "
                f"expected={sorted(VERIFIER_SOURCES)!r}, "
                f"observed={sorted(observed_sources)!r}"
            )
        metadata_path = f"{PROJECT}-{VERSION}.dist-info/METADATA"
        metadata = email.parser.BytesParser().parsebytes(archive.read(metadata_path))
        expected = {
            "Name": "control-assurance-lab",
            "Version": VERSION,
            "License-Expression": "Apache-2.0",
            "Requires-Python": REQUIRES_PYTHON,
        }
        observed = {field: metadata.get(field) for field in expected}
        if observed != expected:
            raise ValueError(f"wheel metadata differs: {observed!r}")
        entry_points = archive.read(f"{PROJECT}-{VERSION}.dist-info/entry_points.txt").decode(
            "utf-8"
        )
        required_commands = {
            "assurance-lab = assurance_lab.cli:main",
            (
                "assurance-control-plane = "
                "assurance_lab.control_plane.service_cli:main"
            ),
            (
                "assurance-deployment-reconciler = "
                "assurance_lab.control_plane.reconciler_cli:main"
            ),
            (
                "assurance-runtime-worker = "
                "assurance_lab.runtime.service_cli:main"
            ),
        }
        missing_commands = {
            command for command in required_commands if command not in entry_points
        }
        if missing_commands:
            raise ValueError(
                "wheel is missing required commands: "
                f"{sorted(missing_commands)!r}"
            )


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
        source_prefix = "verifier-js/src/"
        observed_sources = {
            name.removeprefix(source_prefix)
            for name in relative
            if name.startswith(source_prefix) and not name.endswith("/")
        }
        if observed_sources != VERIFIER_SOURCES:
            raise ValueError(
                "sdist verifier source set differs: "
                f"expected={sorted(VERIFIER_SOURCES)!r}, "
                f"observed={sorted(observed_sources)!r}"
            )


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
