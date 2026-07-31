"""Small, non-overwriting writer for canonical evidence bundle directories."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from assurance_lab.evidence.bundle import (
    PROFILE,
    ROOT_MEDIA_TYPE,
    SCHEMA_VERSION,
    BundleFile,
    BundleLimits,
    BundleManifest,
    BundleStatus,
    BundleVerification,
    EvaluationRef,
    ExperimentRef,
    Sensitivity,
    verify_bundle,
)


@dataclass(frozen=True, slots=True)
class PayloadFile:
    path: str
    content: bytes
    media_type: str
    role: str
    sensitivity: Sensitivity
    required_for: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BundleMetadata:
    created_at: datetime
    as_of: datetime
    experiment: ExperimentRef
    evaluation: EvaluationRef
    parent_bundles: tuple[str, ...] = ()


class BundleWriteError(ValueError):
    """The requested output was unsafe or failed its own integrity check."""


def write_bundle(
    destination: Path,
    *,
    metadata: BundleMetadata,
    payloads: tuple[PayloadFile, ...],
    limits: BundleLimits | None = None,
) -> BundleVerification:
    """Write once, then accept the result only if the independent verifier does.

    ``None`` preserves the verifier's default resource profile.  Callers with
    an explicitly versioned evidence profile may supply its matching limits;
    the writer never derives or widens limits implicitly from payload sizes.
    """

    if destination.exists() or destination.is_symlink():
        raise BundleWriteError(f"destination already exists: {destination}")
    descriptors = tuple(
        sorted(
            (
                BundleFile(
                    path=payload.path,
                    sha256=hashlib.sha256(payload.content).hexdigest(),
                    size=len(payload.content),
                    media_type=payload.media_type,
                    role=payload.role,
                    sensitivity=payload.sensitivity,
                    required_for=list(payload.required_for),
                )
                for payload in payloads
            ),
            key=lambda descriptor: descriptor.path,
        )
    )
    manifest = BundleManifest(
        media_type=ROOT_MEDIA_TYPE,
        schema_version=SCHEMA_VERSION,
        profile=PROFILE,
        created_at=_timestamp(metadata.created_at),
        as_of=_timestamp(metadata.as_of),
        experiment=metadata.experiment,
        evaluation=metadata.evaluation,
        parent_bundles=list(metadata.parent_bundles),
        files=list(descriptors),
    )
    payload_by_path = {payload.path: payload for payload in payloads}
    if len(payload_by_path) != len(payloads):
        raise BundleWriteError("payload paths must be unique")
    manifest_bytes = manifest.canonical_bytes()
    expected_bundle_id = manifest.bundle_id()

    created = False
    pinned_root: os.stat_result | None = None
    try:
        destination.mkdir(parents=False, mode=0o700)
        created = True
        pinned_root = _pin_destination_root(destination)
        for descriptor in descriptors:
            payload = payload_by_path[descriptor.path]
            target = destination.joinpath(*descriptor.path.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            _write_new(target, payload.content)
        _write_new(destination / "bundle.json", manifest_bytes)
        _require_pinned_root(destination, pinned_root)
        result = (
            verify_bundle(destination)
            if limits is None
            else verify_bundle(destination, limits=limits)
        )
        _require_pinned_root(destination, pinned_root)
        if result.status != BundleStatus.INTEGRITY_VERIFIED:
            details = "; ".join(f"{issue.code}: {issue.detail}" for issue in result.issues)
            raise BundleWriteError(f"written bundle failed verification: {details}")
        if result.bundle_id != expected_bundle_id or result.manifest != manifest:
            raise BundleWriteError(
                "written bundle verification returned a different manifest or bundle id"
            )
        return result
    except Exception:
        if (
            created
            and pinned_root is not None
            and _is_pinned_root(destination, pinned_root)
        ):
            shutil.rmtree(destination)
        raise


def _write_new(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written == 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _pin_destination_root(destination: Path) -> os.stat_result:
    try:
        root = os.lstat(destination)
    except OSError as error:
        raise BundleWriteError(f"cannot pin destination root: {error}") from error
    if stat.S_ISLNK(root.st_mode) or not stat.S_ISDIR(root.st_mode):
        raise BundleWriteError("created destination root is not a real directory")
    return root


def _is_pinned_root(
    destination: Path,
    pinned: os.stat_result,
) -> bool:
    try:
        current = os.lstat(destination)
    except OSError:
        return False
    return (
        stat.S_ISDIR(current.st_mode)
        and not stat.S_ISLNK(current.st_mode)
        and (current.st_dev, current.st_ino)
        == (pinned.st_dev, pinned.st_ino)
    )


def _require_pinned_root(
    destination: Path,
    pinned: os.stat_result,
) -> None:
    if not _is_pinned_root(destination, pinned):
        raise BundleWriteError("destination root changed while the bundle was written")


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise BundleWriteError("bundle timestamps must be timezone-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
