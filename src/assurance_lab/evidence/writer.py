"""Small, non-overwriting writer for canonical evidence bundle directories."""

from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from assurance_lab.evidence.bundle import (
    PROFILE,
    ROOT_MEDIA_TYPE,
    SCHEMA_VERSION,
    BundleFile,
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
) -> BundleVerification:
    """Write once, then accept the result only if the independent verifier does."""

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

    created = False
    try:
        destination.mkdir(parents=False, mode=0o700)
        created = True
        for descriptor in descriptors:
            payload = payload_by_path[descriptor.path]
            target = destination.joinpath(*descriptor.path.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            _write_new(target, payload.content)
        _write_new(destination / "bundle.json", manifest.canonical_bytes())
        result = verify_bundle(destination)
        if result.status != BundleStatus.INTEGRITY_VERIFIED:
            details = "; ".join(f"{issue.code}: {issue.detail}" for issue in result.issues)
            raise BundleWriteError(f"written bundle failed verification: {details}")
        return result
    except Exception:
        if created:
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


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise BundleWriteError("bundle timestamps must be timezone-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
