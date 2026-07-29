from __future__ import annotations

import stat
from pathlib import Path

import pytest

from assurance_lab.cli import main
from assurance_lab.evidence.attestation import (
    AttestationReason,
    AttestationVerification,
)
from assurance_lab.evidence.canonical import canonical_json_bytes, strict_json_loads
from assurance_lab.evidence.snapshot import verify_cab_snapshot

REPOSITORY_ROOT = Path(__file__).parents[1]
DSSE_FIXTURE = REPOSITORY_ROOT / "examples" / "dsse-v1"
EXAMPLE_CAB = REPOSITORY_ROOT / "examples" / "masked-export.cab"
DSSE_ARGUMENTS = [
    "dsse",
    "verify",
    "--envelope",
    str(DSSE_FIXTURE / "envelope.json"),
    "--policy",
    str(DSSE_FIXTURE / "trust-policy.json"),
    "--payload",
    str(DSSE_FIXTURE / "payload.json"),
    "--payload-type",
    "application/json",
    "--at",
    "2026-07-29T12:00:00Z",
    "--json",
]


def test_dsse_cli_verifies_the_complete_checked_in_fixture(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(DSSE_ARGUMENTS) == 0
    captured = capsys.readouterr()
    expected = (DSSE_FIXTURE / "expected-verification.json").read_bytes()

    assert captured.err == ""
    assert captured.out.encode("utf-8") == expected
    decision = AttestationVerification.model_validate_json(expected, strict=True)
    assert decision.verified
    assert decision.reason_code is AttestationReason.VERIFIED
    assert decision.accepted_identities == ("collector:synthetic-example",)

    offset_arguments = list(DSSE_ARGUMENTS)
    offset_arguments[offset_arguments.index("2026-07-29T12:00:00Z")] = (
        "2026-07-29T21:00:00+09:00"
    )
    assert main(offset_arguments) == 0
    assert capsys.readouterr().out.encode("utf-8") == expected


def test_dsse_cli_returns_a_negative_decision_for_different_exact_payload_bytes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    changed_payload = tmp_path / "payload.json"
    changed_payload.write_bytes((DSSE_FIXTURE / "payload.json").read_bytes() + b" ")
    arguments = list(DSSE_ARGUMENTS)
    arguments[arguments.index(str(DSSE_FIXTURE / "payload.json"))] = str(changed_payload)

    assert main(arguments) == 1
    captured = capsys.readouterr()
    decision = AttestationVerification.model_validate_json(
        captured.out.encode("utf-8"),
        strict=True,
    )
    assert captured.err == ""
    assert not decision.verified
    assert decision.reason_code is AttestationReason.PAYLOAD_MISMATCH


def test_dsse_cli_rejects_a_time_without_an_rfc3339_offset(
    capsys: pytest.CaptureFixture[str],
) -> None:
    arguments = list(DSSE_ARGUMENTS)
    arguments[arguments.index("2026-07-29T12:00:00Z")] = "2026-07-29T12:00:00"

    assert main(arguments) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "admission time must be RFC 3339" in captured.err


def test_cab_snapshot_cli_creates_then_verifies_exact_bytes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    snapshot = tmp_path / "masked-export.cabsnap"

    assert (
        main(
            [
                "cab",
                "snapshot",
                "create",
                str(EXAMPLE_CAB),
                "--out",
                str(snapshot),
            ]
        )
        == 0
    )
    create_output = capsys.readouterr()
    assert create_output.err == ""
    assert "CAB snapshot     VERIFIED" in create_output.out
    assert f"Written          {snapshot}" in create_output.out
    assert stat.S_IMODE(snapshot.stat().st_mode) == 0o600

    sealed = verify_cab_snapshot(snapshot.read_bytes())
    assert (
        main(
            [
                "cab",
                "snapshot",
                "verify",
                str(snapshot),
                "--json",
            ]
        )
        == 0
    )
    verify_output = capsys.readouterr()
    expected = {
        "cab_id": sealed.cab_id,
        "file_count": sealed.file_count,
        "manifest_digest": sealed.manifest_digest,
        "snapshot_digest": sealed.snapshot_digest,
    }
    assert verify_output.err == ""
    assert verify_output.out.encode("utf-8") == canonical_json_bytes(expected)
    assert strict_json_loads(verify_output.out.encode("utf-8")) == expected


def test_cab_snapshot_cli_fails_closed_without_clobbering_an_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "existing.cabsnap"
    output.write_bytes(b"keep this file")

    assert (
        main(
            [
                "cab",
                "snapshot",
                "create",
                str(EXAMPLE_CAB),
                "--out",
                str(output),
            ]
        )
        == 2
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "File exists" in captured.err
    assert output.read_bytes() == b"keep this file"


def test_cab_snapshot_cli_rejects_corrupted_snapshot_bytes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    valid = tmp_path / "valid.cabsnap"
    assert (
        main(
            [
                "cab",
                "snapshot",
                "create",
                str(EXAMPLE_CAB),
                "--out",
                str(valid),
            ]
        )
        == 0
    )
    capsys.readouterr()
    payload = bytearray(valid.read_bytes())
    payload[-1] ^= 1
    corrupted = tmp_path / "corrupted.cabsnap"
    corrupted.write_bytes(payload)

    assert (
        main(
            [
                "cab",
                "snapshot",
                "verify",
                str(corrupted),
                "--json",
            ]
        )
        == 2
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "captured CAB is not integrity verified" in captured.err
