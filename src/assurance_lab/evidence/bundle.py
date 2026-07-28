"""Integrity-only verification for canonical evidence bundle directories."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
    strict_jsonl_loads,
)

ROOT_MEDIA_TYPE: Literal["application/vnd.control-assurance.bundle.v1+json"] = (
    "application/vnd.control-assurance.bundle.v1+json"
)
SCHEMA_VERSION: Literal["1.0.0"] = "1.0.0"
PROFILE: Literal["integrity-only"] = "integrity-only"
PAYLOAD_PREFIXES = frozenset({"spec", "records", "artifacts", "derived"})
JSONL_MEDIA_TYPES = frozenset({"application/x-ndjson", "application/jsonl"})
MAX_PATH_BYTES = 1024
MAX_COMPONENT_BYTES = 255
MAX_MANIFEST_FILES = 10_000
_TIMESTAMP_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$"
)
_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_BIDI_CLASSES = frozenset(
    {"R", "AL", "AN", "RLE", "RLO", "LRE", "LRO", "PDF", "LRI", "RLI", "FSI", "PDI"}
)
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True, slots=True)
class BundleLimits:
    """Hard bounds applied before directory traversal or payload reads."""

    max_manifest_bytes: int = 2 * 1024 * 1024
    max_files: int = MAX_MANIFEST_FILES + 1
    max_directories: int = 2_048
    max_depth: int = 32
    max_file_bytes: int = 1024 * 1024 * 1024
    max_total_bytes: int = 8 * 1024 * 1024 * 1024
    max_component_bytes: int = MAX_COMPONENT_BYTES
    max_path_bytes: int = MAX_PATH_BYTES
    json_limits: JSONLimits = field(default_factory=JSONLimits)

    def __post_init__(self) -> None:
        positive = (
            self.max_manifest_bytes,
            self.max_files,
            self.max_directories,
            self.max_file_bytes,
            self.max_total_bytes,
            self.max_component_bytes,
            self.max_path_bytes,
        )
        if any(type(value) is not int or value <= 0 for value in positive):
            raise ValueError("bundle resource limits must be positive integers")
        if type(self.max_depth) is not int or self.max_depth < 1:
            raise ValueError("bundle maximum depth must be a positive integer")


class BundleStatus(StrEnum):
    INTEGRITY_VERIFIED = "integrity_verified"
    CORRUPT = "corrupt"
    UNSUPPORTED = "unsupported"


class Sensitivity(StrEnum):
    SYNTHETIC = "synthetic"
    LAB_INTERNAL = "lab-internal"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def _safe_display_text(value: str) -> str:
    if any(
        unicodedata.category(character) in {"Cc", "Cf", "Cs"}
        or unicodedata.bidirectional(character) in _BIDI_CLASSES
        for character in value
    ):
        raise ValueError("display text contains a control or bidirectional character")
    return value


_SafeText = Annotated[str, AfterValidator(_safe_display_text)]


class BundleFile(_StrictModel):
    path: str = Field(min_length=1, max_length=MAX_PATH_BYTES)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size: int = Field(ge=0)
    media_type: str = Field(min_length=1, max_length=255)
    role: _SafeText = Field(min_length=1, max_length=128)
    sensitivity: Sensitivity
    required_for: list[_SafeText] = Field(max_length=128)

    @model_validator(mode="after")
    def safe_payload_path(self) -> BundleFile:
        validate_payload_path(self.path)
        if len(set(self.required_for)) != len(self.required_for):
            raise ValueError("required_for entries must be unique")
        return self


class ExperimentRef(_StrictModel):
    id: _SafeText = Field(min_length=1, max_length=256)
    spec_version: _SafeText = Field(min_length=1, max_length=64)
    spec_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")


class EvaluatorRef(_StrictModel):
    name: _SafeText = Field(min_length=1, max_length=128)
    version: _SafeText = Field(min_length=1, max_length=64)
    source_revision: _SafeText = Field(min_length=1, max_length=256)
    image_digest: str | None = Field(pattern=r"^sha256:[a-f0-9]{64}$")


class EvaluationRef(_StrictModel):
    policy_id: _SafeText = Field(min_length=1, max_length=256)
    policy_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    evaluator: EvaluatorRef


class BundleManifest(_StrictModel):
    media_type: Literal["application/vnd.control-assurance.bundle.v1+json"]
    schema_version: Literal["1.0.0"]
    profile: Literal["integrity-only"]
    created_at: str
    as_of: str
    experiment: ExperimentRef
    evaluation: EvaluationRef
    parent_bundles: list[_SafeText] = Field(max_length=1_000)
    files: list[BundleFile] = Field(max_length=MAX_MANIFEST_FILES)

    @field_validator("created_at", "as_of")
    @classmethod
    def canonical_timestamp(cls, value: str) -> str:
        if _TIMESTAMP_PATTERN.fullmatch(value) is None:
            raise ValueError("timestamp must use YYYY-MM-DDTHH:MM:SS.ffffffZ")
        try:
            datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError as exc:
            raise ValueError("timestamp is not a valid UTC date and time") from exc
        return value

    @model_validator(mode="after")
    def coherent_manifest(self) -> BundleManifest:
        if self.created_at < self.as_of:
            raise ValueError("bundle cannot be created before its evaluation time")
        paths = [descriptor.path for descriptor in self.files]
        if paths != sorted(paths):
            raise ValueError("bundle file descriptors must be sorted by path")
        if len(set(paths)) != len(paths):
            raise ValueError("bundle file paths must be unique")
        folded = [path.lower() for path in paths]
        if len(set(folded)) != len(folded):
            raise ValueError("bundle paths collide after ASCII case folding")
        if len(set(self.parent_bundles)) != len(self.parent_bundles):
            raise ValueError("parent bundle identifiers must be unique")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"))

    def bundle_id(self) -> str:
        return _bundle_id(self.canonical_bytes())


class VerificationIssue(_StrictModel):
    code: str
    detail: str
    path: str | None = None


class BundleVerification(_StrictModel):
    status: BundleStatus
    bundle_id: str | None
    manifest: BundleManifest | None
    issues: list[VerificationIssue]


@dataclass(frozen=True, slots=True)
class _Entry:
    path: str
    parts: tuple[str, ...]
    stat: os.stat_result


@dataclass(slots=True)
class _Tree:
    files: dict[str, _Entry] = field(default_factory=dict)
    directories: dict[str, _Entry] = field(default_factory=dict)
    issues: list[VerificationIssue] = field(default_factory=list)
    entry_count: int = 0
    file_count: int = 0
    directory_count: int = 0
    total_bytes: int = 0
    complete: bool = True


class _TraversalLimit(Exception):
    pass


class _UnsafeFile(OSError):
    pass


def validate_payload_path(
    path: str,
    *,
    max_path_bytes: int = MAX_PATH_BYTES,
    max_component_bytes: int = MAX_COMPONENT_BYTES,
) -> None:
    if not path or path.startswith("/") or "\\" in path:
        raise ValueError("bundle path must be a relative POSIX path")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in path):
        raise ValueError("bundle path contains an ASCII control character")
    if any(unicodedata.bidirectional(character) in _BIDI_CLASSES for character in path):
        raise ValueError("bundle path contains a bidirectional control character")
    if not path.isascii():
        raise ValueError("bundle paths must use portable ASCII characters")
    encoded = path.encode("ascii")
    if len(encoded) > max_path_bytes:
        raise ValueError("bundle path exceeds the configured byte limit")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("bundle path contains traversal or an empty component")
    if parts[0] not in PAYLOAD_PREFIXES:
        raise ValueError("bundle payload path uses an unsupported root")
    for part in parts:
        if len(part.encode("ascii")) > max_component_bytes:
            raise ValueError("bundle path component exceeds the configured byte limit")
        if part.startswith("."):
            raise ValueError("bundle path sidecar components are forbidden")
        if _SAFE_COMPONENT.fullmatch(part) is None:
            raise ValueError("bundle path contains a non-portable component")


def _bundle_id(raw_manifest: bytes) -> str:
    return f"cab:sha256:{hashlib.sha256(raw_manifest).hexdigest()}"


def _issue(code: str, detail: str, path: str | None = None) -> VerificationIssue:
    return VerificationIssue(code=code, detail=detail, path=path)


def _result(
    status: BundleStatus,
    *,
    bundle_id: str | None = None,
    manifest: BundleManifest | None = None,
    issues: list[VerificationIssue],
) -> BundleVerification:
    return BundleVerification(
        status=status,
        bundle_id=bundle_id,
        manifest=manifest,
        issues=issues,
    )


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


def _read_bounded(file_descriptor: int, maximum: int) -> bytes:
    chunks = bytearray()
    while len(chunks) <= maximum:
        chunk = os.read(file_descriptor, min(_CHUNK_SIZE, maximum + 1 - len(chunks)))
        if not chunk:
            break
        chunks.extend(chunk)
    if len(chunks) > maximum:
        raise _UnsafeFile("file exceeds the configured byte limit")
    return bytes(chunks)


def _read_root_manifest(
    root_descriptor: int,
    limits: BundleLimits,
) -> tuple[bytes | None, os.stat_result | None, VerificationIssue | None]:
    try:
        listed = os.stat("bundle.json", dir_fd=root_descriptor, follow_symlinks=False)
    except OSError as exc:
        return None, None, _issue("missing-root-manifest", str(exc), "bundle.json")
    if not stat.S_ISREG(listed.st_mode):
        return (
            None,
            None,
            _issue(
                "missing-root-manifest",
                "bundle.json must be a regular file",
                "bundle.json",
            ),
        )
    if listed.st_nlink != 1:
        return (
            None,
            None,
            _issue(
                "unsafe-hardlink",
                "bundle.json must have exactly one hard link",
                "bundle.json",
            ),
        )
    if listed.st_size > limits.max_manifest_bytes:
        return (
            None,
            None,
            _issue(
                "resource-limit",
                "bundle.json exceeds the manifest byte limit",
                "bundle.json",
            ),
        )
    try:
        descriptor = os.open("bundle.json", _FILE_FLAGS, dir_fd=root_descriptor)
    except OSError as exc:
        return None, None, _issue("unreadable-root-manifest", str(exc), "bundle.json")
    try:
        opened = os.fstat(descriptor)
        if not _stable_file(listed, opened) or opened.st_nlink != 1:
            raise _UnsafeFile("bundle.json changed between directory lookup and open")
        raw = _read_bounded(descriptor, limits.max_manifest_bytes)
        after = os.fstat(descriptor)
        if not _stable_file(opened, after) or len(raw) != after.st_size:
            raise _UnsafeFile("bundle.json changed while it was read")
    except OSError as exc:
        return None, None, _issue("unreadable-root-manifest", str(exc), "bundle.json")
    finally:
        os.close(descriptor)
    return raw, opened, None


def _portable_tree_path(path: str, limits: BundleLimits) -> str | None:
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in path):
        return "filesystem path contains an ASCII control character"
    if any(unicodedata.bidirectional(character) in _BIDI_CLASSES for character in path):
        return "filesystem path contains a bidirectional control character"
    if not path.isascii():
        return "filesystem path is not portable ASCII"
    if len(path.encode("ascii")) > limits.max_path_bytes:
        return "filesystem path exceeds the configured byte limit"
    for part in path.split("/"):
        if (
            not part
            or part.startswith(".")
            or len(part.encode("ascii")) > limits.max_component_bytes
            or _SAFE_COMPONENT.fullmatch(part) is None
        ):
            return "filesystem path contains a non-portable or sidecar component"
    return None


def _scan_tree(root_descriptor: int, limits: BundleLimits) -> _Tree:
    tree = _Tree()
    folded_paths: dict[str, str] = {}

    def scan(directory_descriptor: int, parent: tuple[str, ...]) -> None:
        try:
            iterator = os.scandir(directory_descriptor)
        except OSError as exc:
            tree.complete = False
            tree.issues.append(
                _issue(
                    "unreadable-subtree",
                    str(exc),
                    "/".join(parent) if parent else None,
                )
            )
            return
        try:
            with iterator:
                for directory_entry in iterator:
                    name = directory_entry.name
                    parts = (*parent, name)
                    relative = "/".join(parts)
                    tree.entry_count += 1
                    if tree.entry_count > limits.max_files + limits.max_directories:
                        raise _TraversalLimit(
                            "directory entry count exceeds the configured limit"
                        )
                    try:
                        entry_stat = os.stat(
                            name,
                            dir_fd=directory_descriptor,
                            follow_symlinks=False,
                        )
                    except OSError as exc:
                        tree.complete = False
                        tree.issues.append(_issue("unreadable-entry", str(exc), relative))
                        continue

                    path_problem = _portable_tree_path(relative, limits)
                    if path_problem is not None:
                        tree.issues.append(_issue("unsafe-path", path_problem, relative))
                    folded = relative.lower()
                    previous = folded_paths.setdefault(folded, relative)
                    if previous != relative:
                        tree.issues.append(
                            _issue(
                                "path-collision",
                                f"path collides with {previous!r} after ASCII case folding",
                                relative,
                            )
                        )

                    if stat.S_ISDIR(entry_stat.st_mode):
                        tree.directory_count += 1
                        if tree.directory_count > limits.max_directories:
                            raise _TraversalLimit("directory count exceeds the configured limit")
                        entry = _Entry(relative, parts, entry_stat)
                        tree.directories[relative] = entry
                        if len(parts) >= limits.max_depth:
                            tree.complete = False
                            tree.issues.append(
                                _issue(
                                    "resource-limit",
                                    "directory depth exceeds the configured limit",
                                    relative,
                                )
                            )
                            continue
                        try:
                            child_descriptor = os.open(
                                name,
                                _DIRECTORY_FLAGS,
                                dir_fd=directory_descriptor,
                            )
                        except OSError as exc:
                            tree.complete = False
                            tree.issues.append(_issue("unreadable-subtree", str(exc), relative))
                            continue
                        try:
                            opened = os.fstat(child_descriptor)
                            if not _same_object(entry_stat, opened):
                                raise _UnsafeFile("directory changed between lookup and open")
                            scan(child_descriptor, parts)
                        except OSError as exc:
                            tree.complete = False
                            tree.issues.append(_issue("unreadable-subtree", str(exc), relative))
                        finally:
                            os.close(child_descriptor)
                        continue

                    tree.file_count += 1
                    if tree.file_count > limits.max_files:
                        raise _TraversalLimit("file count exceeds the configured limit")
                    if stat.S_ISLNK(entry_stat.st_mode):
                        tree.issues.append(
                            _issue(
                                "unsafe-symlink",
                                "bundle trees cannot contain symbolic links",
                                relative,
                            )
                        )
                        continue
                    if not stat.S_ISREG(entry_stat.st_mode):
                        tree.issues.append(
                            _issue(
                                "unsafe-entry",
                                "bundle trees may contain only directories and regular files",
                                relative,
                            )
                        )
                        continue
                    tree.files[relative] = _Entry(relative, parts, entry_stat)
                    if entry_stat.st_nlink != 1:
                        tree.issues.append(
                            _issue(
                                "unsafe-hardlink",
                                "bundle files must have exactly one hard link",
                                relative,
                            )
                        )
                    if entry_stat.st_size > limits.max_file_bytes:
                        tree.issues.append(
                            _issue(
                                "resource-limit",
                                "file exceeds the configured per-file byte limit",
                                relative,
                            )
                        )
                    tree.total_bytes += entry_stat.st_size
                    if tree.total_bytes > limits.max_total_bytes:
                        raise _TraversalLimit("total bundle bytes exceed the configured limit")
        except OSError as exc:
            tree.complete = False
            tree.issues.append(
                _issue(
                    "unreadable-subtree",
                    str(exc),
                    "/".join(parent) if parent else None,
                )
            )

    try:
        scan(root_descriptor, ())
    except _TraversalLimit as exc:
        tree.complete = False
        tree.issues.append(_issue("resource-limit", str(exc)))
    return tree


def _tree_snapshot_issues(
    before: _Tree,
    after: _Tree,
) -> list[VerificationIssue]:
    issues = list(after.issues)
    if not after.complete and not issues:
        issues.append(
            _issue(
                "tree-changed",
                "final bundle tree scan did not complete",
            )
        )

    for kind, before_entries, after_entries in (
        ("file", before.files, after.files),
        ("directory", before.directories, after.directories),
    ):
        before_paths = set(before_entries)
        after_paths = set(after_entries)
        for path in sorted(before_paths - after_paths):
            issues.append(
                _issue(
                    "tree-changed",
                    f"{kind} disappeared after payload verification",
                    path,
                )
            )
        for path in sorted(after_paths - before_paths):
            issues.append(
                _issue(
                    "tree-changed",
                    f"{kind} appeared after payload verification",
                    path,
                )
            )
        for path in sorted(before_paths & after_paths):
            if not _stable_file(
                before_entries[path].stat,
                after_entries[path].stat,
            ):
                issues.append(
                    _issue(
                        "entry-changed",
                        f"{kind} changed after payload verification",
                        path,
                    )
                )
    return issues


def _open_scanned_file(
    root_descriptor: int,
    entry: _Entry,
    directories: dict[str, _Entry],
) -> int:
    current = os.dup(root_descriptor)
    try:
        traversed: list[str] = []
        for component in entry.parts[:-1]:
            traversed.append(component)
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
            os.close(current)
            current = child
            scanned = directories.get("/".join(traversed))
            if scanned is None or not _stable_file(scanned.stat, os.fstat(current)):
                raise _UnsafeFile(
                    "payload directory changed between scan and open"
                )
        descriptor = os.open(entry.parts[-1], _FILE_FLAGS, dir_fd=current)
    finally:
        os.close(current)
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or not _stable_file(entry.stat, opened)
    ):
        os.close(descriptor)
        raise _UnsafeFile("payload changed between directory scan and open")
    return descriptor


def _media_kind(media_type: str) -> Literal["json", "jsonl"] | None:
    if media_type in JSONL_MEDIA_TYPES:
        return "jsonl"
    if media_type == "application/json" or (
        media_type.startswith("application/") and media_type.endswith("+json")
    ):
        return "json"
    return None


def _hash_payload(
    root_descriptor: int,
    entry: _Entry,
    directories: dict[str, _Entry],
    *,
    capture: bool,
    limits: BundleLimits,
) -> tuple[str, int, bytes | None]:
    descriptor = _open_scanned_file(root_descriptor, entry, directories)
    digest = hashlib.sha256()
    size = 0
    content = bytearray() if capture else None
    read_limit = (
        min(limits.max_file_bytes, limits.json_limits.max_bytes)
        if capture
        else limits.max_file_bytes
    )
    opened = os.fstat(descriptor)
    try:
        while size <= read_limit:
            chunk = os.read(
                descriptor,
                min(_CHUNK_SIZE, read_limit + 1 - size),
            )
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
            if content is not None:
                content.extend(chunk)
        if size > read_limit:
            raise _UnsafeFile("payload exceeds its configured read limit")
        after = os.fstat(descriptor)
        if not _stable_file(opened, after) or size != after.st_size:
            raise _UnsafeFile("payload changed while it was read")
    finally:
        os.close(descriptor)
    return digest.hexdigest(), size, bytes(content) if content is not None else None


def _final_payload_issues(
    root_descriptor: int,
    manifest: BundleManifest,
    tree: _Tree,
    limits: BundleLimits,
) -> list[VerificationIssue]:
    issues: list[VerificationIssue] = []
    for descriptor in manifest.files:
        entry = tree.files.get(descriptor.path)
        if entry is None:
            continue
        try:
            digest, size, _ = _hash_payload(
                root_descriptor,
                entry,
                tree.directories,
                capture=False,
                limits=limits,
            )
        except OSError as error:
            issues.append(
                _issue(
                    "unreadable-payload",
                    f"payload changed during final verification: {error}",
                    descriptor.path,
                )
            )
            continue
        if size != descriptor.size:
            issues.append(
                _issue(
                    "size-mismatch",
                    f"manifest={descriptor.size}; final={size}",
                    descriptor.path,
                )
            )
        if digest != descriptor.sha256:
            issues.append(
                _issue(
                    "digest-mismatch",
                    f"manifest={descriptor.sha256}; final={digest}",
                    descriptor.path,
                )
            )
    return issues


def _canonical_artifact_issue(
    descriptor: BundleFile,
    content: bytes,
    limits: BundleLimits,
) -> VerificationIssue | None:
    try:
        if _media_kind(descriptor.media_type) == "json":
            value = strict_json_loads(content, limits=limits.json_limits)
            if canonical_json_bytes(value, limits=limits.json_limits) != content:
                raise StrictJSONError("JSON artifact is not exact RFC 8785 bytes")
        else:
            strict_jsonl_loads(
                content,
                limits=limits.json_limits,
                require_sorted_ids=True,
            )
    except StrictJSONError as exc:
        return _issue(
            "invalid-canonical-artifact",
            str(exc),
            descriptor.path,
        )
    return None


def verify_bundle(
    root: Path,
    *,
    limits: BundleLimits | None = None,
) -> BundleVerification:
    """Verify the directory snapshot observed during this call.

    The result does not make the pathname immutable.  A caller that permits
    concurrent writers must consume a pinned snapshot or reverify before
    reopening payloads.
    """

    if limits is None:
        limits = BundleLimits()
    try:
        root_stat = os.lstat(root)
    except OSError as exc:
        return _result(
            BundleStatus.CORRUPT,
            issues=[_issue("unsafe-root", str(exc))],
        )
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        return _result(
            BundleStatus.CORRUPT,
            issues=[_issue("unsafe-root", "bundle root must be a real directory")],
        )
    try:
        root_descriptor = os.open(root, _DIRECTORY_FLAGS)
    except OSError as exc:
        return _result(
            BundleStatus.CORRUPT,
            issues=[_issue("unsafe-root", str(exc))],
        )
    try:
        opened_root = os.fstat(root_descriptor)
        if not _same_object(root_stat, opened_root):
            return _result(
                BundleStatus.CORRUPT,
                issues=[_issue("unsafe-root", "bundle root changed between lookup and open")],
            )

        raw_manifest, manifest_stat, manifest_issue = _read_root_manifest(
            root_descriptor,
            limits,
        )
        if manifest_issue is not None or raw_manifest is None or manifest_stat is None:
            return _result(
                BundleStatus.CORRUPT,
                issues=[manifest_issue or _issue("invalid-root-manifest", "unknown error")],
            )
        try:
            parsed = strict_json_loads(raw_manifest, limits=limits.json_limits)
            if not isinstance(parsed, dict):
                raise StrictJSONError("bundle root must be a JSON object")
            if canonical_json_bytes(parsed, limits=limits.json_limits) != raw_manifest:
                return _result(
                    BundleStatus.CORRUPT,
                    issues=[
                        _issue(
                            "noncanonical-root-manifest",
                            "bundle.json must be exact RFC 8785 bytes",
                            "bundle.json",
                        )
                    ],
                )
        except StrictJSONError as exc:
            return _result(
                BundleStatus.CORRUPT,
                issues=[_issue("invalid-root-manifest", str(exc), "bundle.json")],
            )

        semantic_id = _bundle_id(raw_manifest)
        unsupported: list[VerificationIssue] = []
        expected_root_values = {
            "media_type": ROOT_MEDIA_TYPE,
            "schema_version": SCHEMA_VERSION,
            "profile": PROFILE,
        }
        for key, expected in expected_root_values.items():
            value = parsed.get(key)
            if isinstance(value, str) and value != expected:
                unsupported.append(
                    _issue(
                        f"unsupported-{key.replace('_', '-')}",
                        f"supported value is {expected!r}; received {value!r}",
                        "bundle.json",
                    )
                )
        if unsupported:
            return _result(
                BundleStatus.UNSUPPORTED,
                bundle_id=semantic_id,
                issues=unsupported,
            )
        try:
            manifest = BundleManifest.model_validate_json(raw_manifest)
            for descriptor in manifest.files:
                validate_payload_path(
                    descriptor.path,
                    max_path_bytes=limits.max_path_bytes,
                    max_component_bytes=limits.max_component_bytes,
                )
        except ValueError as exc:
            return _result(
                BundleStatus.CORRUPT,
                bundle_id=semantic_id,
                issues=[_issue("invalid-root-manifest", str(exc), "bundle.json")],
            )

        tree = _scan_tree(root_descriptor, limits)
        issues = tree.issues
        scanned_manifest = tree.files.get("bundle.json")
        if scanned_manifest is None or not _stable_file(
            manifest_stat,
            scanned_manifest.stat,
        ):
            issues.append(
                _issue(
                    "root-manifest-changed",
                    "bundle.json changed during verification",
                    "bundle.json",
                )
            )
        if not tree.complete and any(issue.code == "resource-limit" for issue in issues):
            return _result(
                BundleStatus.CORRUPT,
                bundle_id=semantic_id,
                manifest=manifest,
                issues=issues,
            )

        expected_paths = {descriptor.path for descriptor in manifest.files}
        expected_directories = {
            "/".join(descriptor.path.split("/")[:index])
            for descriptor in manifest.files
            for index in range(1, len(descriptor.path.split("/")))
        }
        actual_paths = set(tree.files) - {"bundle.json"}
        for path in sorted(actual_paths - expected_paths):
            issues.append(_issue("unlisted-file", "file is not declared by bundle.json", path))
        for path in sorted(expected_paths - actual_paths):
            issues.append(_issue("missing-file", "manifested payload is absent", path))
        for path in sorted(set(tree.directories) - expected_directories):
            issues.append(
                _issue(
                    "unlisted-directory",
                    "directory is not required by a manifested payload",
                    path,
                )
            )

        for descriptor in manifest.files:
            entry = tree.files.get(descriptor.path)
            if (
                entry is None
                or entry.stat.st_nlink != 1
                or entry.stat.st_size > limits.max_file_bytes
            ):
                continue
            kind = _media_kind(descriptor.media_type)
            capture = kind is not None and entry.stat.st_size <= limits.json_limits.max_bytes
            if kind is not None and not capture:
                issues.append(
                    _issue(
                        "resource-limit",
                        "canonical JSON artifact exceeds the JSON byte limit",
                        descriptor.path,
                    )
                )
            try:
                digest, size, content = _hash_payload(
                    root_descriptor,
                    entry,
                    tree.directories,
                    capture=capture,
                    limits=limits,
                )
            except OSError as exc:
                issues.append(_issue("unreadable-payload", str(exc), descriptor.path))
                continue
            if size != descriptor.size:
                issues.append(
                    _issue(
                        "size-mismatch",
                        f"manifest={descriptor.size}; actual={size}",
                        descriptor.path,
                    )
                )
            if digest != descriptor.sha256:
                issues.append(
                    _issue(
                        "digest-mismatch",
                        f"manifest={descriptor.sha256}; actual={digest}",
                        descriptor.path,
                    )
                )
            if kind is not None and content is not None:
                artifact_issue = _canonical_artifact_issue(
                    descriptor,
                    content,
                    limits,
                )
                if artifact_issue is not None:
                    issues.append(artifact_issue)

        if not issues:
            final_tree = _scan_tree(root_descriptor, limits)
            issues.extend(_tree_snapshot_issues(tree, final_tree))
            if not issues:
                issues.extend(
                    _final_payload_issues(
                        root_descriptor,
                        manifest,
                        final_tree,
                        limits,
                    )
                )
                final_manifest, final_manifest_stat, final_manifest_issue = (
                    _read_root_manifest(root_descriptor, limits)
                )
                if (
                    final_manifest_issue is not None
                    or final_manifest is None
                    or final_manifest_stat is None
                    or final_manifest != raw_manifest
                    or not _stable_file(manifest_stat, final_manifest_stat)
                ):
                    issues.append(
                        _issue(
                            "root-manifest-changed",
                            "bundle.json changed after payload verification",
                            "bundle.json",
                        )
                    )
                closing_tree = _scan_tree(root_descriptor, limits)
                issues.extend(_tree_snapshot_issues(final_tree, closing_tree))
        if not _stable_file(opened_root, os.fstat(root_descriptor)):
            issues.append(
                _issue(
                    "root-changed",
                    "bundle root changed during verification",
                )
            )
        return _result(
            BundleStatus.CORRUPT if issues else BundleStatus.INTEGRITY_VERIFIED,
            bundle_id=semantic_id,
            manifest=manifest,
            issues=issues,
        )
    finally:
        os.close(root_descriptor)
