"""Concrete, bounded CAB snapshot profile used by benchmark release admission.

The general CAB verifier works on directories.  Benchmark publication needs a
stable byte object that can be resolved by digest, replayed, and compared without
relying on a mutable filesystem.  The evidence snapshot format already provides
that object.  This module implements the small public subset needed by the
benchmark:

* decode the documented deterministic snapshot container;
* run the ordinary CAB integrity verifier over the decoded bytes;
* expose exact manifested members for membership checks; and
* deterministically re-encode a mutation, optionally rebuilding ``bundle.json``.

This is intentionally one concrete profile, not a generic archive abstraction.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final

from pydantic import ValidationError

from assurance_lab.evidence.bundle import BundleManifest
from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.evidence.snapshot import (
    MAX_CAB_SNAPSHOT_BYTES,
    CABSnapshotError,
    decode_cab_snapshot_entries,
    encode_cab_snapshot_entries,
    verify_cab_snapshot,
)

BENCHMARK_SPEC_PATH: Final = "spec/benchmark-compiled-spec.json"
BENCHMARK_PLAN_PATH: Final = "records/benchmark-frozen-plan.json"
BENCHMARK_RAW_PATH: Final = "records/benchmark-raw-trial-set.json"

class BenchmarkCABError(ValueError):
    """A resolved benchmark CAB is malformed, unbounded, or not integrity verified."""


@dataclass(frozen=True, slots=True)
class VerifiedBenchmarkCAB:
    """Exact verified source CAB bytes and their immutable members."""

    snapshot_bytes: bytes
    snapshot_digest: str
    cab_id: str
    manifest_digest: str
    manifest: BundleManifest
    entries: tuple[tuple[str, bytes], ...]

    def member(self, path: str) -> bytes:
        for candidate, payload in self.entries:
            if candidate == path:
                return payload
        raise BenchmarkCABError(f"benchmark CAB is missing required member {path!r}")

    def content_by_digest(self) -> dict[str, bytes]:
        result: dict[str, bytes] = {}
        for path, payload in self.entries:
            if path == "bundle.json":
                continue
            digest = raw_sha256(payload)
            previous = result.get(digest)
            if previous is not None and previous != payload:
                raise BenchmarkCABError("CAB contains a content-address collision")
            result[digest] = payload
        return result


def raw_sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def decode_snapshot_entries(
    snapshot_bytes: bytes,
    *,
    maximum: int = MAX_CAB_SNAPSHOT_BYTES,
) -> tuple[tuple[str, bytes], ...]:
    """Decode entries through the evidence snapshot's canonical wire codec."""

    try:
        return decode_cab_snapshot_entries(snapshot_bytes, maximum=maximum)
    except CABSnapshotError as exc:
        raise BenchmarkCABError("CAB snapshot violates the evidence snapshot profile") from exc


def encode_snapshot_entries(
    entries: tuple[tuple[str, bytes], ...],
    *,
    maximum: int = MAX_CAB_SNAPSHOT_BYTES,
) -> bytes:
    """Encode entries through the evidence snapshot's canonical wire codec."""

    try:
        return encode_cab_snapshot_entries(entries, maximum=maximum)
    except CABSnapshotError as exc:
        raise BenchmarkCABError("CAB entries violate the evidence snapshot profile") from exc


def verify_benchmark_cab(
    snapshot_bytes: bytes,
    *,
    expected_snapshot_digest: str,
) -> VerifiedBenchmarkCAB:
    """Verify one content-addressed source CAB and return its exact members."""

    if type(snapshot_bytes) is not bytes:
        raise BenchmarkCABError("resolved source CAB must be immutable bytes")
    if len(snapshot_bytes) > MAX_CAB_SNAPSHOT_BYTES:
        raise BenchmarkCABError("resolved source CAB exceeds the CAB snapshot byte limit")
    if raw_sha256(snapshot_bytes) != expected_snapshot_digest:
        raise BenchmarkCABError("resolved source CAB bytes do not match the index digest")
    try:
        sealed = verify_cab_snapshot(snapshot_bytes)
        entries = decode_snapshot_entries(snapshot_bytes)
        manifest = BundleManifest.model_validate_json(dict(entries)["bundle.json"])
    except (CABSnapshotError, ValidationError, ValueError, KeyError) as exc:
        raise BenchmarkCABError("resolved source CAB is not a verified canonical CAB") from exc
    if sealed.snapshot_digest != expected_snapshot_digest:
        raise BenchmarkCABError("CAB verifier returned a different snapshot digest")
    return VerifiedBenchmarkCAB(
        snapshot_bytes=snapshot_bytes,
        snapshot_digest=sealed.snapshot_digest,
        cab_id=sealed.cab_id,
        manifest_digest=sealed.manifest_digest,
        manifest=manifest,
        entries=entries,
    )


def rebuild_manifest(
    entries: tuple[tuple[str, bytes], ...],
    *,
    changed_paths: frozenset[str],
) -> tuple[tuple[str, bytes], ...]:
    """Rebuild exact CAB descriptors for changed members and no others."""

    stored = dict(entries)
    try:
        manifest = BundleManifest.model_validate_json(stored["bundle.json"])
    except (ValidationError, ValueError, KeyError) as exc:
        raise BenchmarkCABError("cannot rebuild an invalid CAB manifest") from exc
    descriptors = []
    observed: set[str] = set()
    for descriptor in manifest.files:
        if descriptor.path in changed_paths:
            payload = stored.get(descriptor.path)
            if payload is None:
                raise BenchmarkCABError("cannot rebuild a manifest for a missing target")
            document = descriptor.model_dump(mode="python")
            document["sha256"] = hashlib.sha256(payload).hexdigest()
            document["size"] = len(payload)
            descriptors.append(type(descriptor).model_validate(document))
            observed.add(descriptor.path)
        else:
            descriptors.append(descriptor)
    if observed != set(changed_paths):
        raise BenchmarkCABError("manifest rebuild target is not a manifested CAB member")
    document = manifest.model_dump(mode="python")
    document["files"] = descriptors
    rebuilt = BundleManifest.model_validate(document)
    stored["bundle.json"] = canonical_json_bytes(rebuilt.model_dump(mode="json"))
    return (
        ("bundle.json", stored["bundle.json"]),
        *tuple(
            sorted(
                (path, payload)
                for path, payload in stored.items()
                if path != "bundle.json"
            )
        ),
    )


__all__ = [
    "BENCHMARK_PLAN_PATH",
    "BENCHMARK_RAW_PATH",
    "BENCHMARK_SPEC_PATH",
    "BenchmarkCABError",
    "VerifiedBenchmarkCAB",
    "decode_snapshot_entries",
    "encode_snapshot_entries",
    "raw_sha256",
    "rebuild_manifest",
    "verify_benchmark_cab",
]
