"""Streaming, content-addressed snapshots for large verified CABs.

The original snapshot profile intentionally embeds every CAB byte in one
small value.  That is useful for unit-sized evidence, but it is the wrong
shape for EDR and SIEM captures: copying a large receipt into Python, SQLite,
and custody multiplies memory, database, and lock pressure.

This v2 profile separates identity from content:

* ``snapshot.json`` is a small canonical descriptor of ordered
  ``(path, size, sha256)`` entries;
* exact file bytes live once under ``blobs/<sha256>``;
* the snapshot identity is the SHA-256 digest of ``snapshot.json``; and
* capture and verification stream every blob through bounded buffers.

The descriptor is not a promise that a storage service is immutable.  A
custody adapter still has to publish the descriptor and blobs with
write-once/object-lock semantics and return a durable acknowledgement.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from assurance_lab.evidence.bundle import (
    MAX_MANIFEST_FILES,
    BundleLimits,
    BundleManifest,
    BundleStatus,
    validate_payload_path,
    verify_bundle,
)
from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)

STREAM_SNAPSHOT_MEDIA_TYPE: Literal[
    "application/vnd.control-assurance.cab-stream-snapshot.v2+json"
] = "application/vnd.control-assurance.cab-stream-snapshot.v2+json"
STREAM_SNAPSHOT_SCHEMA_VERSION: Literal["2.0.0"] = "2.0.0"

# Connector receipts can approach 96 MiB after base64 framing while canonical
# records can approach 64 MiB.  The total ceiling leaves bounded room for the
# manifest and small profile documents without silently accepting arbitrary
# multi-gigabyte evidence.
MAX_STREAM_SNAPSHOT_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_STREAM_SNAPSHOT_FILE_BYTES = 96 * 1024 * 1024
MAX_STREAM_SNAPSHOT_TOTAL_BYTES = 192 * 1024 * 1024
MAX_STREAM_SNAPSHOT_FILES = min(MAX_MANIFEST_FILES + 1, 4_096)

_DESCRIPTOR_NAME = "snapshot.json"
_BLOBS_NAME = "blobs"
_CHUNK_SIZE = 1024 * 1024
_DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_DOCUMENT_LIMITS = JSONLimits(
    max_bytes=MAX_STREAM_SNAPSHOT_MANIFEST_BYTES,
    max_line_bytes=MAX_STREAM_SNAPSHOT_MANIFEST_BYTES,
    max_depth=12,
    max_collection_items=MAX_STREAM_SNAPSHOT_FILES * 8,
    max_string_length=4_096,
)


class StreamSnapshotError(ValueError):
    """A v2 CAB snapshot was unsafe, incomplete, corrupt, or outside limits."""


@dataclass(frozen=True, slots=True)
class StreamSnapshotLimits:
    """Explicit resource contract for one v2 capture or verification."""

    max_manifest_bytes: int = MAX_STREAM_SNAPSHOT_MANIFEST_BYTES
    max_file_bytes: int = MAX_STREAM_SNAPSHOT_FILE_BYTES
    max_total_bytes: int = MAX_STREAM_SNAPSHOT_TOTAL_BYTES
    max_files: int = MAX_STREAM_SNAPSHOT_FILES

    def __post_init__(self) -> None:
        values = (
            self.max_manifest_bytes,
            self.max_file_bytes,
            self.max_total_bytes,
            self.max_files,
        )
        if any(type(value) is not int or value <= 0 for value in values):
            raise ValueError("stream snapshot limits must be positive integers")
        if self.max_manifest_bytes > MAX_STREAM_SNAPSHOT_MANIFEST_BYTES:
            raise ValueError("manifest limit exceeds the v2 profile")
        if self.max_file_bytes > MAX_STREAM_SNAPSHOT_FILE_BYTES:
            raise ValueError("per-file limit exceeds the v2 profile")
        if self.max_total_bytes > MAX_STREAM_SNAPSHOT_TOTAL_BYTES:
            raise ValueError("total limit exceeds the v2 profile")
        if self.max_files > MAX_STREAM_SNAPSHOT_FILES:
            raise ValueError("file-count limit exceeds the v2 profile")
        if self.max_manifest_bytes > self.max_file_bytes:
            raise ValueError("manifest limit cannot exceed the per-file limit")
        if self.max_file_bytes > self.max_total_bytes:
            raise ValueError("per-file limit cannot exceed the total limit")

    def bundle_limits(self) -> BundleLimits:
        return BundleLimits(
            max_manifest_bytes=self.max_manifest_bytes,
            max_files=self.max_files,
            max_file_bytes=self.max_file_bytes,
            max_total_bytes=self.max_total_bytes,
            json_limits=JSONLimits(
                max_bytes=self.max_file_bytes,
                max_line_bytes=self.max_file_bytes,
                max_depth=64,
                max_collection_items=1_000_000,
                max_string_length=self.max_file_bytes,
            ),
        )


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class StreamSnapshotEntry(_StrictFrozenModel):
    path: str = Field(min_length=1, max_length=1024)
    size: int = Field(ge=0)
    digest: str = Field(pattern=_DIGEST_PATTERN)

    @model_validator(mode="after")
    def path_is_portable(self) -> StreamSnapshotEntry:
        if self.path != "bundle.json":
            validate_payload_path(self.path)
        return self


class StreamSnapshotDescriptor(_StrictFrozenModel):
    media_type: Literal[
        "application/vnd.control-assurance.cab-stream-snapshot.v2+json"
    ] = STREAM_SNAPSHOT_MEDIA_TYPE
    schema_version: Literal["2.0.0"] = STREAM_SNAPSHOT_SCHEMA_VERSION
    digest_algorithm: Literal["sha256"] = "sha256"
    blob_layout: Literal["blobs/<sha256-hex>"] = "blobs/<sha256-hex>"
    cab_id: str = Field(pattern=r"^cab:sha256:[a-f0-9]{64}$")
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    file_count: int = Field(ge=1, le=MAX_STREAM_SNAPSHOT_FILES)
    total_bytes: int = Field(ge=1, le=MAX_STREAM_SNAPSHOT_TOTAL_BYTES)
    entries: tuple[StreamSnapshotEntry, ...] = Field(
        min_length=1,
        max_length=MAX_STREAM_SNAPSHOT_FILES,
    )

    @field_validator("entries", mode="before")
    @classmethod
    def entries_are_a_json_array(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value

    @model_validator(mode="after")
    def descriptor_is_closed(self) -> StreamSnapshotDescriptor:
        if self.cab_id.removeprefix("cab:") != self.manifest_digest:
            raise ValueError("CAB id must identify the exact manifest digest")
        if self.file_count != len(self.entries):
            raise ValueError("file count does not close over snapshot entries")
        if self.total_bytes != sum(entry.size for entry in self.entries):
            raise ValueError("total bytes do not close over snapshot entries")
        paths = tuple(entry.path for entry in self.entries)
        if paths[0] != "bundle.json" or paths.count("bundle.json") != 1:
            raise ValueError("snapshot entries must begin with one bundle.json")
        if paths[1:] != tuple(sorted(paths[1:])) or len(paths) != len(set(paths)):
            raise ValueError("snapshot payload paths must be unique and sorted")
        manifest_entry = self.entries[0]
        if manifest_entry.digest != self.manifest_digest:
            raise ValueError("bundle.json entry must match the manifest digest")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            self.model_dump(mode="json"),
            limits=_DOCUMENT_LIMITS,
        )

    def snapshot_digest(self) -> str:
        return _sha256(self.canonical_bytes())


@dataclass(frozen=True, slots=True)
class StreamedCABSnapshot:
    """A verified on-disk v2 snapshot ready for immutable custody."""

    root: Path
    descriptor: StreamSnapshotDescriptor
    descriptor_bytes: bytes
    snapshot_digest: str
    cab_id: str
    manifest_digest: str
    file_count: int
    total_bytes: int


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _same_object(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        stat.S_IFMT(left.st_mode),
    ) == (
        right.st_dev,
        right.st_ino,
        stat.S_IFMT(right.st_mode),
    )


def _stable_file(left: os.stat_result, right: os.stat_result) -> bool:
    return _same_object(left, right) and (
        left.st_size,
        left.st_nlink,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_size,
        right.st_nlink,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _pin_directory_path(
    path: Path,
) -> tuple[int, os.stat_result, int | None, str | None]:
    """Open every path component without following a symbolic link.

    The returned optional parent descriptor and leaf name let callers prove
    that the pathname still names the directory they pinned.  ``.`` and ``/``
    have no separate leaf, so only their live descriptor can be checked.
    """

    if not isinstance(path, Path):
        raise TypeError("directory path must be a pathlib.Path")
    absolute = path.is_absolute()
    components = path.parts[1:] if absolute else path.parts
    components = tuple(component for component in components if component != ".")
    if any(component in {"", ".."} for component in components):
        raise StreamSnapshotError("directory path contains an unsafe component")
    try:
        current = os.open("/" if absolute else ".", _DIRECTORY_FLAGS)
    except OSError as exc:
        raise StreamSnapshotError(f"cannot pin directory path root: {exc}") from exc
    if not components:
        opened = os.fstat(current)
        return current, opened, None, None

    parent_descriptor: int | None = None
    try:
        for index, component in enumerate(components):
            listed = os.stat(component, dir_fd=current, follow_symlinks=False)
            if not stat.S_ISDIR(listed.st_mode):
                raise StreamSnapshotError(
                    f"directory path component {component!r} is not a directory"
                )
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
            opened = os.fstat(child)
            if not _stable_file(listed, opened):
                os.close(child)
                raise StreamSnapshotError(
                    f"directory path component {component!r} changed while opened"
                )
            if index == len(components) - 1:
                parent_descriptor = current
                current = child
            else:
                os.close(current)
                current = child
    except OSError as exc:
        os.close(current)
        raise StreamSnapshotError(f"cannot safely pin directory path: {exc}") from exc
    except Exception:
        os.close(current)
        raise
    return current, opened, parent_descriptor, components[-1]


def _close_pinned_directory(
    descriptor: int,
    parent_descriptor: int | None,
) -> None:
    os.close(descriptor)
    if parent_descriptor is not None:
        os.close(parent_descriptor)


def _require_pinned_directory_path(
    descriptor: int,
    initial: os.stat_result,
    *,
    parent_descriptor: int | None,
    leaf_name: str | None,
    label: str,
) -> None:
    if not _stable_file(initial, os.fstat(descriptor)):
        raise StreamSnapshotError(f"{label} changed while it was in use")
    if parent_descriptor is None or leaf_name is None:
        return
    try:
        current = os.stat(
            leaf_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise StreamSnapshotError(f"{label} pathname disappeared") from exc
    if not _stable_file(initial, current):
        raise StreamSnapshotError(f"{label} pathname changed while it was in use")


def _require_directory_path_reopens(
    path: Path,
    initial: os.stat_result,
    *,
    label: str,
) -> None:
    """Close the gap where an ancestor above the retained parent was replaced."""

    descriptor, reopened, parent_descriptor, _leaf_name = _pin_directory_path(path)
    try:
        if not _stable_file(initial, reopened):
            raise StreamSnapshotError(f"{label} no longer resolves to the pinned directory")
    finally:
        _close_pinned_directory(descriptor, parent_descriptor)


def _create_pinned_directory(
    destination: Path,
) -> tuple[int, os.stat_result, int, str]:
    leaf_name = destination.name
    if leaf_name in {"", ".", ".."}:
        raise StreamSnapshotError("stream snapshot destination has no safe leaf name")
    parent, _parent_stat, parent_parent, _parent_leaf = _pin_directory_path(
        destination.parent
    )
    if parent_parent is not None:
        os.close(parent_parent)
    try:
        try:
            os.stat(leaf_name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise StreamSnapshotError("stream snapshot destination already exists")
        os.mkdir(leaf_name, 0o700, dir_fd=parent)
        listed = os.stat(leaf_name, dir_fd=parent, follow_symlinks=False)
        descriptor = os.open(leaf_name, _DIRECTORY_FLAGS, dir_fd=parent)
        opened = os.fstat(descriptor)
        if not _stable_file(listed, opened):
            os.close(descriptor)
            raise StreamSnapshotError("snapshot destination changed after creation")
    except OSError as exc:
        os.close(parent)
        raise StreamSnapshotError(f"cannot create snapshot destination: {exc}") from exc
    except Exception:
        os.close(parent)
        raise
    return descriptor, opened, parent, leaf_name


def _open_source_file(root_descriptor: int, relative_path: str) -> tuple[int, os.stat_result]:
    components = relative_path.split("/")
    current = os.dup(root_descriptor)
    try:
        for component in components[:-1]:
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
            os.close(current)
            current = child
        listed = os.stat(components[-1], dir_fd=current, follow_symlinks=False)
        if not stat.S_ISREG(listed.st_mode) or listed.st_nlink != 1:
            raise StreamSnapshotError(
                f"{relative_path!r} is not a single-link regular file"
            )
        descriptor = os.open(components[-1], _FILE_FLAGS, dir_fd=current)
    except OSError as exc:
        raise StreamSnapshotError(f"cannot safely open {relative_path!r}: {exc}") from exc
    finally:
        os.close(current)
    opened = os.fstat(descriptor)
    if not _stable_file(listed, opened):
        os.close(descriptor)
        raise StreamSnapshotError(f"{relative_path!r} changed before it was opened")
    return descriptor, opened


def _stream_source(
    source_descriptor: int,
    source_stat: os.stat_result,
    *,
    destination_descriptor: int | None,
    maximum: int,
) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        while size <= maximum:
            chunk = os.read(
                source_descriptor,
                min(_CHUNK_SIZE, maximum + 1 - size),
            )
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
            if destination_descriptor is not None:
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_descriptor, view)
                    if written <= 0:
                        raise OSError("snapshot blob write made no progress")
                    view = view[written:]
        if size > maximum:
            raise StreamSnapshotError("source file exceeds the configured per-file limit")
        after = os.fstat(source_descriptor)
        if not _stable_file(source_stat, after) or size != after.st_size:
            raise StreamSnapshotError("source file changed while it was streamed")
        if destination_descriptor is not None:
            os.fsync(destination_descriptor)
            destination_stat = os.fstat(destination_descriptor)
            if not stat.S_ISREG(destination_stat.st_mode) or destination_stat.st_nlink != 1:
                raise StreamSnapshotError("staged blob is not a single-link regular file")
            if destination_stat.st_size != size:
                raise StreamSnapshotError("staged blob size differs from the source")
    except OSError as exc:
        raise StreamSnapshotError(f"cannot stream source file: {exc}") from exc
    return f"sha256:{digest.hexdigest()}", size


def _write_exact_at(directory_descriptor: int, name: str, content: bytes) -> os.stat_result:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(name, flags, 0o600, dir_fd=directory_descriptor)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("snapshot descriptor write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        result = os.fstat(descriptor)
        if not stat.S_ISREG(result.st_mode) or result.st_nlink != 1:
            raise StreamSnapshotError("new snapshot file is not a single-link regular file")
        return result
    finally:
        os.close(descriptor)


def _read_exact_at(
    directory_descriptor: int,
    name: str,
    *,
    maximum: int,
) -> tuple[bytes, os.stat_result]:
    listed = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    if (
        not stat.S_ISREG(listed.st_mode)
        or listed.st_nlink != 1
        or listed.st_size > maximum
    ):
        raise StreamSnapshotError(f"{name!r} is not a bounded single-link regular file")
    descriptor = os.open(name, _FILE_FLAGS, dir_fd=directory_descriptor)
    try:
        opened = os.fstat(descriptor)
        if not _stable_file(listed, opened):
            raise StreamSnapshotError(f"{name!r} changed before it was opened")
        content = bytearray()
        while len(content) <= maximum:
            chunk = os.read(
                descriptor,
                min(_CHUNK_SIZE, maximum + 1 - len(content)),
            )
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        if len(content) > maximum:
            raise StreamSnapshotError(f"{name!r} exceeds its configured limit")
        if not _stable_file(opened, after) or len(content) != after.st_size:
            raise StreamSnapshotError(f"{name!r} changed while it was read")
        return bytes(content), opened
    finally:
        os.close(descriptor)


def _parse_descriptor(
    descriptor_bytes: bytes,
    *,
    limits: StreamSnapshotLimits,
) -> StreamSnapshotDescriptor:
    try:
        parsed = strict_json_loads(descriptor_bytes, limits=_DOCUMENT_LIMITS)
        descriptor = StreamSnapshotDescriptor.model_validate(parsed)
    except (StrictJSONError, TypeError, ValueError) as exc:
        raise StreamSnapshotError("snapshot descriptor is invalid") from exc
    if descriptor.canonical_bytes() != descriptor_bytes:
        raise StreamSnapshotError("snapshot descriptor is not canonical JSON")
    if descriptor.file_count > limits.max_files:
        raise StreamSnapshotError("snapshot file count exceeds the configured limit")
    if descriptor.total_bytes > limits.max_total_bytes:
        raise StreamSnapshotError("snapshot total bytes exceed the configured limit")
    if any(entry.size > limits.max_file_bytes for entry in descriptor.entries):
        raise StreamSnapshotError("snapshot entry exceeds the configured per-file limit")
    if descriptor.entries[0].size > limits.max_manifest_bytes:
        raise StreamSnapshotError("snapshot CAB manifest exceeds the configured limit")
    return descriptor


def _require_snapshot_digest(value: str) -> str:
    if type(value) is not str or re.fullmatch(_DIGEST_PATTERN, value) is None:
        raise StreamSnapshotError("external snapshot digest is not lowercase sha256")
    return value


def _expected_entries(
    manifest_bytes: bytes,
    manifest: BundleManifest,
) -> tuple[StreamSnapshotEntry, ...]:
    return (
        StreamSnapshotEntry(
            path="bundle.json",
            size=len(manifest_bytes),
            digest=_sha256(manifest_bytes),
        ),
        *(
            StreamSnapshotEntry(
                path=file.path,
                size=file.size,
                digest=f"sha256:{file.sha256}",
            )
            for file in manifest.files
        ),
    )


_DEFAULT_LIMITS = StreamSnapshotLimits()


def capture_streamed_cab_snapshot(
    source: Path,
    destination: Path,
    *,
    limits: StreamSnapshotLimits = _DEFAULT_LIMITS,
) -> StreamedCABSnapshot:
    """Copy one verified CAB into a bounded content-addressed staging snapshot."""

    if not isinstance(source, Path) or not isinstance(destination, Path):
        raise TypeError("source and destination must be pathlib.Path values")
    first = verify_bundle(source, limits=limits.bundle_limits())
    if (
        first.status != BundleStatus.INTEGRITY_VERIFIED
        or first.manifest is None
        or first.bundle_id is None
    ):
        details = "; ".join(issue.code for issue in first.issues[:8])
        raise StreamSnapshotError(f"CAB source is not integrity verified: {details}")
    (
        source_descriptor,
        source_stat,
        source_parent_descriptor,
        source_leaf_name,
    ) = _pin_directory_path(source)

    root_descriptor = -1
    root_stat: os.stat_result | None = None
    destination_parent_descriptor = -1
    destination_leaf_name = ""
    blobs_descriptor = -1
    try:
        (
            root_descriptor,
            root_stat,
            destination_parent_descriptor,
            destination_leaf_name,
        ) = _create_pinned_directory(destination)
        os.mkdir(_BLOBS_NAME, 0o700, dir_fd=root_descriptor)
        blobs_descriptor = os.open(_BLOBS_NAME, _DIRECTORY_FLAGS, dir_fd=root_descriptor)

        manifest_bytes, _manifest_stat = _read_exact_at(
            source_descriptor,
            "bundle.json",
            maximum=limits.max_manifest_bytes,
        )
        if _sha256(manifest_bytes) != first.bundle_id.removeprefix("cab:"):
            raise StreamSnapshotError("CAB manifest identity changed before streaming")
        entries = _expected_entries(manifest_bytes, first.manifest)
        total_bytes = sum(entry.size for entry in entries)
        if len(entries) > limits.max_files or total_bytes > limits.max_total_bytes:
            raise StreamSnapshotError("CAB exceeds the configured snapshot limits")

        written_blobs: set[str] = set()
        for entry in entries:
            source_file, source_file_stat = _open_source_file(
                source_descriptor,
                entry.path,
            )
            blob_name = entry.digest.removeprefix("sha256:")
            blob_descriptor: int | None = None
            try:
                if entry.digest not in written_blobs:
                    blob_descriptor = os.open(
                        blob_name,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                        dir_fd=blobs_descriptor,
                    )
                observed_digest, observed_size = _stream_source(
                    source_file,
                    source_file_stat,
                    destination_descriptor=blob_descriptor,
                    maximum=limits.max_file_bytes,
                )
            finally:
                if blob_descriptor is not None:
                    os.close(blob_descriptor)
                os.close(source_file)
            if observed_digest != entry.digest or observed_size != entry.size:
                raise StreamSnapshotError(
                    f"{entry.path!r} differs from the verified CAB manifest"
                )
            written_blobs.add(entry.digest)

        descriptor = StreamSnapshotDescriptor(
            cab_id=first.bundle_id,
            manifest_digest=_sha256(manifest_bytes),
            file_count=len(entries),
            total_bytes=total_bytes,
            entries=entries,
        )
        descriptor_bytes = descriptor.canonical_bytes()
        _write_exact_at(root_descriptor, _DESCRIPTOR_NAME, descriptor_bytes)
        os.fsync(blobs_descriptor)
        os.fsync(root_descriptor)
        root_stat = os.fstat(root_descriptor)
        _require_pinned_directory_path(
            root_descriptor,
            root_stat,
            parent_descriptor=destination_parent_descriptor,
            leaf_name=destination_leaf_name,
            label="snapshot destination",
        )
        _require_directory_path_reopens(
            destination,
            root_stat,
            label="snapshot destination",
        )
        _require_pinned_directory_path(
            source_descriptor,
            source_stat,
            parent_descriptor=source_parent_descriptor,
            leaf_name=source_leaf_name,
            label="CAB source",
        )
        _require_directory_path_reopens(
            source,
            source_stat,
            label="CAB source",
        )
    except Exception:
        # Never remove a pathname after failure.  Even deleting an apparently
        # empty directory can remove an attacker replacement after a rename
        # race.  A partial snapshot is deliberately left for inspection or
        # out-of-band cleanup.
        raise
    finally:
        if blobs_descriptor >= 0:
            os.close(blobs_descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)
        if destination_parent_descriptor >= 0:
            os.close(destination_parent_descriptor)
        _close_pinned_directory(source_descriptor, source_parent_descriptor)

    closing = verify_bundle(source, limits=limits.bundle_limits())
    if closing.status != BundleStatus.INTEGRITY_VERIFIED or closing.bundle_id != first.bundle_id:
        raise StreamSnapshotError("CAB source changed before snapshot capture completed")
    sealed = verify_streamed_cab_snapshot(destination, limits=limits)
    if sealed.cab_id != first.bundle_id:
        raise StreamSnapshotError("streamed snapshot reopened with a different CAB identity")
    return sealed


def _normalized_entry_limits(
    entry_limits: Mapping[str, int] | None,
    *,
    limits: StreamSnapshotLimits,
) -> dict[str, int]:
    if entry_limits is None:
        return {}
    if type(entry_limits) is not dict or not entry_limits:
        raise TypeError("entry limits must be one non-empty exact dict")
    normalized: dict[str, int] = {}
    for path, maximum in entry_limits.items():
        if type(path) is not str or type(maximum) is not int or maximum < 0:
            raise TypeError("entry limits require text paths and non-negative integers")
        if path != "bundle.json":
            try:
                validate_payload_path(path)
            except ValueError as exc:
                raise StreamSnapshotError("requested snapshot path is not CAB-safe") from exc
        profile_maximum = (
            limits.max_manifest_bytes if path == "bundle.json" else limits.max_file_bytes
        )
        if maximum > profile_maximum:
            raise StreamSnapshotError("requested entry limit exceeds the snapshot profile")
        normalized[path] = maximum
    return normalized


def _verify_and_read_streamed_snapshot(
    root: Path,
    *,
    expected_snapshot_digest: str | None,
    limits: StreamSnapshotLimits,
    entry_limits: Mapping[str, int] | None,
) -> tuple[StreamedCABSnapshot, tuple[tuple[str, bytes], ...]]:
    if not isinstance(root, Path):
        raise TypeError("snapshot root must be a pathlib.Path")
    if expected_snapshot_digest is not None:
        expected_snapshot_digest = _require_snapshot_digest(expected_snapshot_digest)
    requested = _normalized_entry_limits(entry_limits, limits=limits)
    (
        root_descriptor,
        root_stat,
        root_parent_descriptor,
        root_leaf_name,
    ) = _pin_directory_path(root)
    blobs_descriptor = -1
    try:
        root_names = sorted(entry.name for entry in os.scandir(root_descriptor))
        if root_names != [_BLOBS_NAME, _DESCRIPTOR_NAME]:
            raise StreamSnapshotError("snapshot root contains an unexpected entry")
        blobs_listed = os.stat(
            _BLOBS_NAME,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        if not stat.S_ISDIR(blobs_listed.st_mode):
            raise StreamSnapshotError("snapshot blobs entry is not a directory")
        blobs_descriptor = os.open(
            _BLOBS_NAME,
            _DIRECTORY_FLAGS,
            dir_fd=root_descriptor,
        )
        opened_blobs = os.fstat(blobs_descriptor)
        if not _stable_file(blobs_listed, opened_blobs):
            raise StreamSnapshotError("snapshot blobs directory changed before it was opened")
        descriptor_bytes, descriptor_stat = _read_exact_at(
            root_descriptor,
            _DESCRIPTOR_NAME,
            maximum=limits.max_manifest_bytes,
        )
        descriptor = _parse_descriptor(descriptor_bytes, limits=limits)
        snapshot_digest = _sha256(descriptor_bytes)
        if (
            expected_snapshot_digest is not None
            and snapshot_digest != expected_snapshot_digest
        ):
            raise StreamSnapshotError("snapshot descriptor differs from the external digest")

        entries_by_path = {entry.path: entry for entry in descriptor.entries}
        missing_requested = set(requested) - set(entries_by_path)
        if missing_requested:
            raise StreamSnapshotError("requested entry is absent from the snapshot")
        for path, maximum in requested.items():
            if entries_by_path[path].size > maximum:
                raise StreamSnapshotError(
                    f"snapshot entry {path!r} exceeds its caller-declared limit"
                )
        requested_by_digest: dict[str, list[str]] = {}
        for path in requested:
            requested_by_digest.setdefault(entries_by_path[path].digest, []).append(path)

        expected_blob_names = sorted(
            {entry.digest.removeprefix("sha256:") for entry in descriptor.entries}
        )
        observed_blob_names = sorted(entry.name for entry in os.scandir(blobs_descriptor))
        if observed_blob_names != expected_blob_names:
            raise StreamSnapshotError("snapshot blob set does not close over its descriptor")

        blob_stats: dict[str, os.stat_result] = {}
        captured_by_path: dict[str, bytes] = {}
        manifest_bytes = b""
        for entry in descriptor.entries:
            blob_name = entry.digest.removeprefix("sha256:")
            previous_stat = blob_stats.get(blob_name)
            if previous_stat is not None:
                if previous_stat.st_size != entry.size:
                    raise StreamSnapshotError("shared snapshot digest has conflicting sizes")
                continue
            listed = os.stat(blob_name, dir_fd=blobs_descriptor, follow_symlinks=False)
            if (
                not stat.S_ISREG(listed.st_mode)
                or listed.st_nlink != 1
                or listed.st_size != entry.size
            ):
                raise StreamSnapshotError("snapshot blob is unsafe or has the wrong size")
            blob = os.open(blob_name, _FILE_FLAGS, dir_fd=blobs_descriptor)
            try:
                opened = os.fstat(blob)
                if not _stable_file(listed, opened):
                    raise StreamSnapshotError("snapshot blob changed before it was opened")
                digest = hashlib.sha256()
                size = 0
                capture_blob = (
                    entry.path == "bundle.json"
                    or entry.digest in requested_by_digest
                )
                captured = bytearray() if capture_blob else None
                while size <= limits.max_file_bytes:
                    chunk = os.read(
                        blob,
                        min(_CHUNK_SIZE, limits.max_file_bytes + 1 - size),
                    )
                    if not chunk:
                        break
                    size += len(chunk)
                    digest.update(chunk)
                    if captured is not None:
                        captured.extend(chunk)
                after = os.fstat(blob)
                if size > limits.max_file_bytes:
                    raise StreamSnapshotError("snapshot blob exceeds the configured limit")
                if not _stable_file(opened, after) or size != after.st_size:
                    raise StreamSnapshotError("snapshot blob changed while it was verified")
                if f"sha256:{digest.hexdigest()}" != entry.digest or size != entry.size:
                    raise StreamSnapshotError("snapshot blob differs from its descriptor")
                if captured is not None:
                    captured_bytes = bytes(captured)
                    if entry.path == "bundle.json":
                        manifest_bytes = captured_bytes
                    for requested_path in requested_by_digest.get(entry.digest, ()):
                        captured_by_path[requested_path] = captured_bytes
                blob_stats[blob_name] = after
            finally:
                os.close(blob)

        try:
            strict_json_loads(
                manifest_bytes,
                limits=limits.bundle_limits().json_limits,
            )
            manifest = BundleManifest.model_validate_json(manifest_bytes)
        except (StrictJSONError, TypeError, ValueError) as exc:
            raise StreamSnapshotError("snapshot CAB manifest is invalid") from exc
        if manifest.canonical_bytes() != manifest_bytes:
            raise StreamSnapshotError("snapshot CAB manifest is not canonical JSON")
        expected_entries = _expected_entries(manifest_bytes, manifest)
        if descriptor.entries != expected_entries:
            raise StreamSnapshotError("snapshot descriptor differs from its CAB manifest")
        if manifest.bundle_id() != descriptor.cab_id:
            raise StreamSnapshotError("snapshot CAB identity differs from its manifest")
        if set(captured_by_path) != set(requested):
            raise StreamSnapshotError("requested snapshot entries were not captured exactly")

        # Closing pass: a same-user attacker must not be able to change an
        # already hashed blob, descriptor, directory, or rooted pathname before
        # verification and selected-entry consumption complete.
        for blob_name, before in blob_stats.items():
            after = os.stat(blob_name, dir_fd=blobs_descriptor, follow_symlinks=False)
            if not _stable_file(before, after):
                raise StreamSnapshotError("snapshot blob changed after it was verified")
        descriptor_after = os.stat(
            _DESCRIPTOR_NAME,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        if not _stable_file(descriptor_stat, descriptor_after):
            raise StreamSnapshotError("snapshot descriptor changed during verification")
        if not _stable_file(opened_blobs, os.fstat(blobs_descriptor)):
            raise StreamSnapshotError("snapshot blobs directory changed during verification")
        _require_pinned_directory_path(
            root_descriptor,
            root_stat,
            parent_descriptor=root_parent_descriptor,
            leaf_name=root_leaf_name,
            label="snapshot root",
        )
        _require_directory_path_reopens(
            root,
            root_stat,
            label="snapshot root",
        )
    except OSError as exc:
        raise StreamSnapshotError(f"cannot safely verify stream snapshot: {exc}") from exc
    finally:
        if blobs_descriptor >= 0:
            os.close(blobs_descriptor)
        _close_pinned_directory(root_descriptor, root_parent_descriptor)

    snapshot = StreamedCABSnapshot(
        root=root,
        descriptor=descriptor,
        descriptor_bytes=descriptor_bytes,
        snapshot_digest=snapshot_digest,
        cab_id=descriptor.cab_id,
        manifest_digest=descriptor.manifest_digest,
        file_count=descriptor.file_count,
        total_bytes=descriptor.total_bytes,
    )
    return snapshot, tuple(
        (path, captured_by_path[path])
        for path in sorted(captured_by_path)
    )


def verify_streamed_cab_snapshot(
    root: Path,
    *,
    expected_snapshot_digest: str | None = None,
    limits: StreamSnapshotLimits = _DEFAULT_LIMITS,
) -> StreamedCABSnapshot:
    """Independently stream-verify one staged or durably stored v2 snapshot."""

    snapshot, _entries = _verify_and_read_streamed_snapshot(
        root,
        expected_snapshot_digest=expected_snapshot_digest,
        limits=limits,
        entry_limits=None,
    )
    return snapshot


def read_streamed_cab_snapshot_entries(
    root: Path,
    *,
    expected_snapshot_digest: str,
    entry_limits: dict[str, int],
    limits: StreamSnapshotLimits = _DEFAULT_LIMITS,
) -> tuple[StreamedCABSnapshot, tuple[tuple[str, bytes], ...]]:
    """Verify all blobs and return only explicitly bounded CAB members.

    Hashing and selected-entry capture happen in one pass over pinned file
    descriptors.  This avoids the verify-then-reopen race and avoids building a
    second, whole-CAB in-memory container.
    """

    return _verify_and_read_streamed_snapshot(
        root,
        expected_snapshot_digest=expected_snapshot_digest,
        limits=limits,
        entry_limits=entry_limits,
    )


__all__ = [
    "MAX_STREAM_SNAPSHOT_FILES",
    "MAX_STREAM_SNAPSHOT_FILE_BYTES",
    "MAX_STREAM_SNAPSHOT_MANIFEST_BYTES",
    "MAX_STREAM_SNAPSHOT_TOTAL_BYTES",
    "STREAM_SNAPSHOT_MEDIA_TYPE",
    "STREAM_SNAPSHOT_SCHEMA_VERSION",
    "StreamSnapshotDescriptor",
    "StreamSnapshotEntry",
    "StreamSnapshotError",
    "StreamSnapshotLimits",
    "StreamedCABSnapshot",
    "capture_streamed_cab_snapshot",
    "read_streamed_cab_snapshot_entries",
    "verify_streamed_cab_snapshot",
]
