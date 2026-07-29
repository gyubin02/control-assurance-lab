"""Deterministic, bounded snapshots of verified CAB directories.

The bundle verifier deliberately verifies a directory *as observed during one
call*.  Admission needs a stronger hand-off: the exact bytes verified before a
database commit must be the bytes later written to custody.  This module
captures those bytes into a small, deterministic binary container and verifies
the container itself before returning it.

The format is intentionally boring and non-extensible:

``magic | file-count:u32 | repeated(path-len:u16 | path | size:u64 | bytes)``

``bundle.json`` is always first; the remaining entries are strictly sorted
portable ASCII payload paths.  There are no timestamps, owners, compression
codecs, links, or optional headers whose interpretation could vary between
readers.
"""

from __future__ import annotations

import hashlib
import os
import stat
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from assurance_lab.evidence.bundle import (
    BundleLimits,
    BundleStatus,
    validate_payload_path,
    verify_bundle,
)

SNAPSHOT_MEDIA_TYPE: Literal["application/vnd.control-assurance.cab-snapshot.v1"] = (
    "application/vnd.control-assurance.cab-snapshot.v1"
)
SNAPSHOT_SCHEMA_VERSION: Literal["1.0.0"] = "1.0.0"
MAX_CAB_SNAPSHOT_BYTES = 4 * 1024 * 1024
MAX_CAB_SNAPSHOT_FILES = 4_096

_MAGIC = b"CONTROL-ASSURANCE-CAB-SNAPSHOT\x00\x01"
_HEADER = struct.Struct(">I")
_PATH_LENGTH = struct.Struct(">H")
_CONTENT_LENGTH = struct.Struct(">Q")
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_CHUNK_SIZE = 1024 * 1024


class CABSnapshotError(ValueError):
    """The source or encoded snapshot is not a safe, verified CAB snapshot."""


@dataclass(frozen=True, slots=True)
class SealedCABSnapshot:
    """Exact, content-addressed CAB bytes ready for transaction and custody."""

    snapshot_bytes: bytes
    snapshot_digest: str
    cab_id: str
    manifest_digest: str
    file_count: int


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


def _read_exact_source_file(root_descriptor: int, relative_path: str, maximum: int) -> bytes:
    components = relative_path.split("/")
    try:
        current = os.dup(root_descriptor)
    except OSError as exc:
        raise CABSnapshotError(f"cannot pin the CAB root: {exc}") from exc
    descriptor = -1
    try:
        for component in components[:-1]:
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
            os.close(current)
            current = child
        listed = os.stat(components[-1], dir_fd=current, follow_symlinks=False)
        if not stat.S_ISREG(listed.st_mode) or listed.st_nlink != 1:
            raise CABSnapshotError(f"{relative_path!r} is not a single-link regular file")
        if listed.st_size > maximum:
            raise CABSnapshotError(f"{relative_path!r} exceeds the snapshot byte limit")
        descriptor = os.open(components[-1], _FILE_FLAGS, dir_fd=current)
        opened = os.fstat(descriptor)
        if not _stable_file(listed, opened):
            raise CABSnapshotError(f"{relative_path!r} changed before it was opened")
        chunks = bytearray()
        while len(chunks) <= maximum:
            chunk = os.read(descriptor, min(_CHUNK_SIZE, maximum + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(descriptor)
        if len(chunks) > maximum:
            raise CABSnapshotError(f"{relative_path!r} exceeds the snapshot byte limit")
        if not _stable_file(opened, after) or len(chunks) != after.st_size:
            raise CABSnapshotError(f"{relative_path!r} changed while it was read")
        return bytes(chunks)
    except OSError as exc:
        raise CABSnapshotError(f"cannot safely read {relative_path!r}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(current)


def _validate_snapshot_path(path: str) -> None:
    if path == "bundle.json":
        return
    try:
        validate_payload_path(path)
    except ValueError as exc:
        raise CABSnapshotError(f"snapshot path {path!r} is not CAB-safe") from exc


def _encode(entries: tuple[tuple[str, bytes], ...], *, maximum: int) -> bytes:
    if type(entries) is not tuple or not entries or len(entries) > MAX_CAB_SNAPSHOT_FILES:
        raise CABSnapshotError("snapshot file count is outside the supported range")
    output = bytearray(_MAGIC)
    output.extend(_HEADER.pack(len(entries)))
    previous_payload_path = ""
    for index, entry in enumerate(entries):
        if type(entry) is not tuple or len(entry) != 2:
            raise CABSnapshotError("snapshot entries must be exact path/content pairs")
        path, content = entry
        if type(path) is not str or type(content) is not bytes:
            raise CABSnapshotError("snapshot entries require text paths and immutable bytes")
        _validate_snapshot_path(path)
        if index == 0:
            if path != "bundle.json":
                raise CABSnapshotError("CAB snapshot must begin with bundle.json")
        elif path == "bundle.json":
            raise CABSnapshotError("CAB snapshot can contain only one leading bundle.json")
        elif path <= previous_payload_path:
            raise CABSnapshotError("snapshot paths must be strictly sorted")
        if index > 0:
            previous_payload_path = path
        try:
            encoded_path = path.encode("ascii", errors="strict")
        except UnicodeEncodeError as exc:
            raise CABSnapshotError("snapshot paths must use portable ASCII") from exc
        if not encoded_path or len(encoded_path) > 1024:
            raise CABSnapshotError("snapshot path length is outside the supported range")
        output.extend(_PATH_LENGTH.pack(len(encoded_path)))
        output.extend(encoded_path)
        output.extend(_CONTENT_LENGTH.pack(len(content)))
        output.extend(content)
        if len(output) > maximum:
            raise CABSnapshotError("CAB snapshot exceeds the configured byte limit")
    return bytes(output)


def _decode(snapshot_bytes: bytes, *, maximum: int) -> tuple[tuple[str, bytes], ...]:
    if type(snapshot_bytes) is not bytes:
        raise CABSnapshotError("CAB snapshot must be bytes")
    if len(snapshot_bytes) > maximum:
        raise CABSnapshotError("CAB snapshot exceeds the configured byte limit")
    if not snapshot_bytes.startswith(_MAGIC):
        raise CABSnapshotError("CAB snapshot has the wrong format marker")
    offset = len(_MAGIC)
    if len(snapshot_bytes) < offset + _HEADER.size:
        raise CABSnapshotError("CAB snapshot header is truncated")
    count = _HEADER.unpack_from(snapshot_bytes, offset)[0]
    offset += _HEADER.size
    if count < 1 or count > MAX_CAB_SNAPSHOT_FILES:
        raise CABSnapshotError("CAB snapshot file count is outside the supported range")
    entries: list[tuple[str, bytes]] = []
    previous_payload_path = ""
    for index in range(count):
        if len(snapshot_bytes) < offset + _PATH_LENGTH.size:
            raise CABSnapshotError("CAB snapshot path length is truncated")
        path_length = _PATH_LENGTH.unpack_from(snapshot_bytes, offset)[0]
        offset += _PATH_LENGTH.size
        if path_length < 1 or path_length > 1024:
            raise CABSnapshotError("CAB snapshot path length is outside the supported range")
        if len(snapshot_bytes) < offset + path_length + _CONTENT_LENGTH.size:
            raise CABSnapshotError("CAB snapshot entry header is truncated")
        encoded_path = snapshot_bytes[offset : offset + path_length]
        offset += path_length
        try:
            path = encoded_path.decode("ascii", errors="strict")
        except UnicodeDecodeError as exc:
            raise CABSnapshotError("CAB snapshot path is not portable ASCII") from exc
        _validate_snapshot_path(path)
        if index == 0:
            if path != "bundle.json":
                raise CABSnapshotError("CAB snapshot must begin with bundle.json")
        elif path == "bundle.json":
            raise CABSnapshotError("CAB snapshot can contain only one leading bundle.json")
        elif path <= previous_payload_path:
            raise CABSnapshotError("CAB snapshot paths are not strictly sorted")
        if index > 0:
            previous_payload_path = path
        content_length = _CONTENT_LENGTH.unpack_from(snapshot_bytes, offset)[0]
        offset += _CONTENT_LENGTH.size
        end = offset + content_length
        if end > len(snapshot_bytes):
            raise CABSnapshotError("CAB snapshot content is truncated")
        entries.append((path, snapshot_bytes[offset:end]))
        offset = end
    if offset != len(snapshot_bytes):
        raise CABSnapshotError("CAB snapshot has trailing bytes")
    return tuple(entries)


def encode_cab_snapshot_entries(
    entries: tuple[tuple[str, bytes], ...],
    *,
    maximum: int = MAX_CAB_SNAPSHOT_BYTES,
) -> bytes:
    """Encode exact CAB members using the one canonical snapshot wire codec."""

    if type(maximum) is not int or maximum < 1024 or maximum > MAX_CAB_SNAPSHOT_BYTES:
        raise CABSnapshotError("CAB snapshot limit is outside the supported profile")
    return _encode(entries, maximum=maximum)


def decode_cab_snapshot_entries(
    snapshot_bytes: bytes,
    *,
    maximum: int = MAX_CAB_SNAPSHOT_BYTES,
) -> tuple[tuple[str, bytes], ...]:
    """Decode exact CAB members using the one canonical snapshot wire codec."""

    if type(maximum) is not int or maximum < 1024 or maximum > MAX_CAB_SNAPSHOT_BYTES:
        raise CABSnapshotError("CAB snapshot limit is outside the supported profile")
    return _decode(snapshot_bytes, maximum=maximum)


def _write_snapshot_tree(root: Path, entries: tuple[tuple[str, bytes], ...]) -> None:
    for relative_path, content in entries:
        components = relative_path.split("/")
        if any(component in {"", ".", ".."} for component in components):
            raise CABSnapshotError("CAB snapshot contains an unsafe path")
        target = root.joinpath(*components)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise CABSnapshotError("short write while verifying CAB snapshot")
                view = view[written:]
        finally:
            os.close(descriptor)


def verify_cab_snapshot(
    snapshot_bytes: bytes,
    *,
    maximum: int = MAX_CAB_SNAPSHOT_BYTES,
) -> SealedCABSnapshot:
    """Parse and independently verify one deterministic CAB snapshot."""

    if type(maximum) is not int or maximum < 1024 or maximum > MAX_CAB_SNAPSHOT_BYTES:
        raise CABSnapshotError("CAB snapshot limit is outside the supported profile")
    entries = decode_cab_snapshot_entries(snapshot_bytes, maximum=maximum)
    paths = [path for path, _content in entries]
    if not paths or paths[0] != "bundle.json" or paths.count("bundle.json") != 1:
        raise CABSnapshotError("CAB snapshot must contain one leading bundle.json")
    with tempfile.TemporaryDirectory(prefix="assurance-cab-snapshot-") as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        _write_snapshot_tree(root, entries)
        verification = verify_bundle(
            root,
            limits=BundleLimits(
                max_manifest_bytes=maximum,
                max_files=MAX_CAB_SNAPSHOT_FILES,
                max_file_bytes=maximum,
                max_total_bytes=maximum,
            ),
        )
    if (
        verification.status != BundleStatus.INTEGRITY_VERIFIED
        or verification.manifest is None
        or verification.bundle_id is None
    ):
        details = "; ".join(issue.code for issue in verification.issues[:8])
        raise CABSnapshotError(f"captured CAB is not integrity verified: {details}")
    manifest_bytes = dict(entries)["bundle.json"]
    manifest_digest = _sha256(manifest_bytes)
    if verification.bundle_id != f"cab:{manifest_digest}":
        raise CABSnapshotError("CAB id does not match the exact captured manifest")
    return SealedCABSnapshot(
        snapshot_bytes=snapshot_bytes,
        snapshot_digest=_sha256(snapshot_bytes),
        cab_id=verification.bundle_id,
        manifest_digest=manifest_digest,
        file_count=len(entries),
    )


def capture_cab_snapshot(
    root: Path,
    *,
    maximum: int = MAX_CAB_SNAPSHOT_BYTES,
) -> SealedCABSnapshot:
    """Capture and verify exact CAB bytes before an admission transaction."""

    if not isinstance(root, Path):
        raise CABSnapshotError("CAB source must be a pathlib.Path")
    if type(maximum) is not int or maximum < 1024 or maximum > MAX_CAB_SNAPSHOT_BYTES:
        raise CABSnapshotError("CAB snapshot limit is outside the supported profile")
    first = verify_bundle(
        root,
        limits=BundleLimits(
            max_manifest_bytes=maximum,
            max_files=MAX_CAB_SNAPSHOT_FILES,
            max_file_bytes=maximum,
            max_total_bytes=maximum,
        ),
    )
    if (
        first.status != BundleStatus.INTEGRITY_VERIFIED
        or first.manifest is None
        or first.bundle_id is None
    ):
        details = "; ".join(issue.code for issue in first.issues[:8])
        raise CABSnapshotError(f"CAB source is not integrity verified: {details}")
    try:
        root_stat = os.lstat(root)
    except OSError as exc:
        raise CABSnapshotError(f"cannot inspect CAB root: {exc}") from exc
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise CABSnapshotError("CAB root must be a real directory")
    try:
        root_descriptor = os.open(root, _DIRECTORY_FLAGS)
    except OSError as exc:
        raise CABSnapshotError(f"cannot safely open CAB root: {exc}") from exc
    try:
        if not _same_object(root_stat, os.fstat(root_descriptor)):
            raise CABSnapshotError("CAB root changed before snapshot capture")
        expected_paths = (
            "bundle.json",
            *(sorted(descriptor.path for descriptor in first.manifest.files)),
        )
        if len(expected_paths) > MAX_CAB_SNAPSHOT_FILES:
            raise CABSnapshotError("CAB snapshot file count exceeds the profile limit")
        entries: list[tuple[str, bytes]] = []
        remaining = maximum
        for relative_path in expected_paths:
            content = _read_exact_source_file(root_descriptor, relative_path, remaining)
            entries.append((relative_path, content))
            remaining -= len(content)
            if remaining < 0:
                raise CABSnapshotError("CAB snapshot exceeds the configured byte limit")
    finally:
        os.close(root_descriptor)
    encoded = encode_cab_snapshot_entries(tuple(entries), maximum=maximum)
    sealed = verify_cab_snapshot(encoded, maximum=maximum)
    if sealed.cab_id != first.bundle_id:
        raise CABSnapshotError("CAB identity changed while the snapshot was captured")
    closing = verify_bundle(
        root,
        limits=BundleLimits(
            max_manifest_bytes=maximum,
            max_files=MAX_CAB_SNAPSHOT_FILES,
            max_file_bytes=maximum,
            max_total_bytes=maximum,
        ),
    )
    if closing.status != BundleStatus.INTEGRITY_VERIFIED or closing.bundle_id != sealed.cab_id:
        raise CABSnapshotError("CAB source changed before snapshot sealing completed")
    return sealed


__all__ = [
    "MAX_CAB_SNAPSHOT_BYTES",
    "SNAPSHOT_MEDIA_TYPE",
    "SNAPSHOT_SCHEMA_VERSION",
    "CABSnapshotError",
    "SealedCABSnapshot",
    "capture_cab_snapshot",
    "decode_cab_snapshot_entries",
    "encode_cab_snapshot_entries",
    "verify_cab_snapshot",
]
