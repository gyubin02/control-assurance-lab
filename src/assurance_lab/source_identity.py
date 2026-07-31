"""Content identity for the reviewed local Python implementation.

The digest produced here covers the complete shipped ``assurance_lab`` source
tree.  It identifies bytes; it does not authenticate an author, interpreter,
third-party dependency, build environment, or installation path.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from assurance_lab.evidence.canonical import canonical_json_bytes

_READ_CHUNK_BYTES: Final = 64 * 1024
_MAX_SOURCE_BYTES: Final = 16 * 1024 * 1024
_NO_FOLLOW: Final = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY: Final = getattr(os, "O_DIRECTORY", 0)
_FILE_FLAGS: Final = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | _NO_FOLLOW
)
_DIRECTORY_FLAGS: Final = _FILE_FLAGS | _DIRECTORY


@dataclass(frozen=True, slots=True)
class _OpenDirectory:
    descriptor: int
    parent_descriptor: int | None
    name: str | None
    opened: os.stat_result
    entries: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _OpenSource:
    descriptor: int
    parent_descriptor: int
    name: str
    relative_path: str
    opened: os.stat_result
    payload: bytes


def package_source_manifest(root: Path | None = None) -> dict[str, object]:
    """Describe every shipped Python/typing source file by relative path and bytes."""

    if _NO_FOLLOW == 0 or _DIRECTORY == 0:
        raise ValueError("secure source identity requires O_NOFOLLOW and O_DIRECTORY")
    package_root = Path(__file__).parent if root is None else root
    directories: list[_OpenDirectory] = []
    sources: list[_OpenSource] = []
    root_descriptor = -1
    try:
        root_descriptor = os.open(package_root, _DIRECTORY_FLAGS)
        _collect_sources(
            descriptor=root_descriptor,
            parent_descriptor=None,
            name=None,
            relative_prefix="",
            directories=directories,
            sources=sources,
        )
        if not sources:
            raise ValueError("package source root contains no shipped source files")
        _assert_source_tree_stable(directories=directories, sources=sources)
        files = [
            {
                "path": source.relative_path,
                "size": len(source.payload),
                "sha256": "sha256:" + hashlib.sha256(source.payload).hexdigest(),
            }
            for source in sorted(sources, key=lambda item: item.relative_path)
        ]
    except OSError as exc:
        raise ValueError("cannot securely traverse the package source tree") from exc
    finally:
        for source in reversed(sources):
            os.close(source.descriptor)
        for directory in reversed(directories):
            os.close(directory.descriptor)
        if root_descriptor >= 0 and not any(
            directory.descriptor == root_descriptor for directory in directories
        ):
            os.close(root_descriptor)
    return {
        "schema": "assurance-lab.python-source-set/v1",
        "claim_boundary": (
            "identifies the shipped assurance_lab source bytes; does not "
            "authenticate origin, Python, the standard library, or dependencies"
        ),
        "files": files,
    }


def package_source_digest(root: Path | None = None) -> str:
    """Content-address the complete local package source manifest."""

    manifest = package_source_manifest(root)
    return "sha256:" + hashlib.sha256(canonical_json_bytes(manifest)).hexdigest()


def _collect_sources(
    *,
    descriptor: int,
    parent_descriptor: int | None,
    name: str | None,
    relative_prefix: str,
    directories: list[_OpenDirectory],
    sources: list[_OpenSource],
) -> None:
    opened = os.fstat(descriptor)
    if not stat.S_ISDIR(opened.st_mode):
        raise ValueError("package source entry must be a real directory")
    entries = tuple(sorted(os.listdir(descriptor)))
    if any(
        not entry or entry in {".", ".."} or "/" in entry or "\x00" in entry
        for entry in entries
    ):
        raise ValueError("package source directory contains an unsafe entry name")
    directories.append(
        _OpenDirectory(
            descriptor=descriptor,
            parent_descriptor=parent_descriptor,
            name=name,
            opened=opened,
            entries=entries,
        )
    )
    for entry_name in entries:
        entry = os.stat(entry_name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISLNK(entry.st_mode):
            raise ValueError("package source tree must not contain symbolic links")
        relative_path = (
            entry_name
            if not relative_prefix
            else f"{relative_prefix}/{entry_name}"
        )
        if stat.S_ISDIR(entry.st_mode):
            if entry_name == "__pycache__":
                continue
            child = os.open(entry_name, _DIRECTORY_FLAGS, dir_fd=descriptor)
            child_opened = os.fstat(child)
            if _stable_identity(entry) != _stable_identity(child_opened):
                os.close(child)
                raise ValueError("package source directory changed while it was opened")
            try:
                _collect_sources(
                    descriptor=child,
                    parent_descriptor=descriptor,
                    name=entry_name,
                    relative_prefix=relative_path,
                    directories=directories,
                    sources=sources,
                )
            except BaseException:
                if not any(directory.descriptor == child for directory in directories):
                    os.close(child)
                raise
        elif stat.S_ISREG(entry.st_mode):
            if entry_name == "py.typed" or entry_name.endswith(".py"):
                sources.append(
                    _read_source_file(
                        parent_descriptor=descriptor,
                        name=entry_name,
                        relative_path=relative_path,
                        directory_entry=entry,
                    )
                )
        else:
            raise ValueError("package source tree contains a special filesystem entry")


def _read_source_file(
    *,
    parent_descriptor: int,
    name: str,
    relative_path: str,
    directory_entry: os.stat_result,
) -> _OpenSource:
    descriptor = -1
    try:
        descriptor = os.open(name, _FILE_FLAGS, dir_fd=parent_descriptor)
        opened = os.fstat(descriptor)
        if (
            _stable_identity(directory_entry) != _stable_identity(opened)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size > _MAX_SOURCE_BYTES
        ):
            raise ValueError("package source entry must be one regular, unlinked file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, _READ_CHUNK_BYTES)
            if not chunk:
                break
            chunks.append(chunk)
        after_read = os.fstat(descriptor)
        payload = b"".join(chunks)
        if (
            _stable_identity(opened) != _stable_identity(after_read)
            or len(payload) != after_read.st_size
        ):
            raise ValueError("package source entry changed while it was read")
        return _OpenSource(
            descriptor=descriptor,
            parent_descriptor=parent_descriptor,
            name=name,
            relative_path=relative_path,
            opened=opened,
            payload=payload,
        )
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _assert_source_tree_stable(
    *,
    directories: list[_OpenDirectory],
    sources: list[_OpenSource],
) -> None:
    for source in sources:
        opened_now = os.fstat(source.descriptor)
        named_now = os.stat(
            source.name,
            dir_fd=source.parent_descriptor,
            follow_symlinks=False,
        )
        if (
            _stable_identity(source.opened) != _stable_identity(opened_now)
            or _stable_identity(source.opened) != _stable_identity(named_now)
            or not stat.S_ISREG(named_now.st_mode)
            or named_now.st_nlink != 1
        ):
            raise ValueError("package source entry changed during source-set identity")
    for directory in reversed(directories):
        opened_now = os.fstat(directory.descriptor)
        if (
            _stable_identity(directory.opened) != _stable_identity(opened_now)
            or directory.entries != tuple(sorted(os.listdir(directory.descriptor)))
        ):
            raise ValueError("package source directory changed during source-set identity")
        if directory.parent_descriptor is not None and directory.name is not None:
            named_now = os.stat(
                directory.name,
                dir_fd=directory.parent_descriptor,
                follow_symlinks=False,
            )
            if (
                _stable_identity(directory.opened) != _stable_identity(named_now)
                or not stat.S_ISDIR(named_now.st_mode)
            ):
                raise ValueError(
                    "package source directory was replaced during source-set identity"
                )


def _stable_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


__all__ = ["package_source_digest", "package_source_manifest"]
