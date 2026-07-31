"""Small offline command handlers for signed evidence and sealed CAB bytes."""

from __future__ import annotations

import os
import re
import stat
import sys
from contextlib import suppress
from datetime import datetime
from pathlib import Path

from assurance_lab.evidence.attestation import (
    MAX_DECODED_PAYLOAD_BYTES,
    MAX_ENVELOPE_BYTES,
    MAX_TRUST_POLICY_BYTES,
    AttestationVerification,
    parse_trust_policy,
    verify_dsse_attestation,
)
from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.evidence.snapshot import (
    MAX_CAB_SNAPSHOT_BYTES,
    SealedCABSnapshot,
    capture_cab_snapshot,
    verify_cab_snapshot,
)

_RFC3339_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?"
    r"(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)


def run_dsse_verify(
    *,
    envelope_path: Path,
    policy_path: Path,
    payload_path: Path,
    payload_type: str,
    admission_time: str,
    json_output: bool,
) -> int:
    """Verify one exact envelope against independently supplied expectations."""

    trusted_time = _parse_rfc3339(admission_time)
    envelope_bytes = _read_bounded(
        envelope_path,
        maximum=MAX_ENVELOPE_BYTES,
        subject="DSSE envelope",
    )
    policy_bytes = _read_bounded(
        policy_path,
        maximum=MAX_TRUST_POLICY_BYTES,
        subject="trust policy",
    )
    expected_payload = _read_bounded(
        payload_path,
        maximum=MAX_DECODED_PAYLOAD_BYTES,
        subject="expected payload",
    )
    policy = parse_trust_policy(policy_bytes)
    decision = verify_dsse_attestation(
        envelope_bytes,
        policy=policy,
        expected_payload_type=payload_type,
        expected_payload=expected_payload,
        admission_time=trusted_time,
    )
    if json_output:
        sys.stdout.write(decision.canonical_bytes().decode("utf-8"))
    else:
        _print_dsse_decision(decision)
    return 0 if decision.verified else 1


def run_cab_snapshot_create(
    *,
    source: Path,
    output: Path,
) -> int:
    """Capture, self-verify, and write one new deterministic CAB snapshot."""

    sealed = capture_cab_snapshot(source)
    verified = verify_cab_snapshot(sealed.snapshot_bytes)
    if verified != sealed:
        raise ValueError("CAB snapshot self-verification returned a different result")
    _write_new_file(output, sealed.snapshot_bytes)
    _print_snapshot(verified, output=output)
    return 0


def run_cab_snapshot_verify(
    *,
    snapshot_path: Path,
    json_output: bool,
) -> int:
    """Verify one existing deterministic CAB snapshot."""

    snapshot_bytes = _read_bounded(
        snapshot_path,
        maximum=MAX_CAB_SNAPSHOT_BYTES,
        subject="CAB snapshot",
    )
    sealed = verify_cab_snapshot(snapshot_bytes)
    if json_output:
        sys.stdout.write(canonical_json_bytes(_snapshot_summary(sealed)).decode("utf-8"))
    else:
        _print_snapshot(sealed)
    return 0


def _parse_rfc3339(value: str) -> datetime:
    if _RFC3339_PATTERN.fullmatch(value) is None or value.endswith("-00:00"):
        raise ValueError(
            "admission time must be RFC 3339 with a known offset and "
            "at most six fractional digits"
        )
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
        offset = parsed.utcoffset()
    except (OverflowError, ValueError) as exc:
        raise ValueError("admission time is not a valid RFC 3339 instant") from exc
    if parsed.tzinfo is None or offset is None:
        raise ValueError("admission time must include a known UTC offset")
    return parsed


def _read_bounded(path: Path, *, maximum: int, subject: str) -> bytes:
    try:
        with path.open("rb") as source:
            opened = os.fstat(source.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise ValueError(f"{subject} must be a regular file")
            if opened.st_size > maximum:
                raise ValueError(f"{subject} exceeds the supported byte limit")
            payload = source.read(maximum + 1)
            closing = os.fstat(source.fileno())
    except OSError as exc:
        raise OSError(f"cannot read {subject} {str(path)!r}: {exc}") from exc
    if len(payload) > maximum:
        raise ValueError(f"{subject} exceeds the supported byte limit")
    opened_identity = (
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
        opened.st_mtime_ns,
        opened.st_ctime_ns,
    )
    closing_identity = (
        closing.st_dev,
        closing.st_ino,
        closing.st_size,
        closing.st_mtime_ns,
        closing.st_ctime_ns,
    )
    if opened_identity != closing_identity or len(payload) != closing.st_size:
        raise ValueError(f"{subject} changed while it was read")
    return payload


def _write_new_file(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = -1
    created = False
    try:
        descriptor = os.open(path, flags, 0o600)
        created = True
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while saving CAB snapshot")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
            descriptor = -1
        if created:
            with suppress(OSError):
                path.unlink()
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _snapshot_summary(sealed: SealedCABSnapshot) -> dict[str, str | int]:
    return {
        "cab_id": sealed.cab_id,
        "file_count": sealed.file_count,
        "manifest_digest": sealed.manifest_digest,
        "snapshot_digest": sealed.snapshot_digest,
    }


def _print_dsse_decision(decision: AttestationVerification) -> None:
    status = "VERIFIED" if decision.verified else "REJECTED"
    print(f"DSSE             {status}")
    print(f"Reason           {decision.reason_code.value}")
    if decision.policy_id is not None:
        print(f"Policy           {decision.policy_id}")
    if decision.admission_time is not None:
        print(f"Admission time   {decision.admission_time}")
    if decision.raw_envelope_sha256 is not None:
        print(f"Envelope         sha256:{decision.raw_envelope_sha256}")
    if decision.expected_payload_sha256 is not None:
        print(f"Expected payload sha256:{decision.expected_payload_sha256}")
    if decision.accepted_identities:
        print(f"Signers          {', '.join(decision.accepted_identities)}")


def _print_snapshot(
    sealed: SealedCABSnapshot,
    *,
    output: Path | None = None,
) -> None:
    print("CAB snapshot     VERIFIED")
    print(f"Snapshot         {sealed.snapshot_digest}")
    print(f"CAB              {sealed.cab_id}")
    print(f"Manifest         {sealed.manifest_digest}")
    print(f"Files            {sealed.file_count}")
    if output is not None:
        print(f"Written          {output}")


__all__ = [
    "run_cab_snapshot_create",
    "run_cab_snapshot_verify",
    "run_dsse_verify",
]
