"""Opt-in Microsoft Graph conformance test for a real Defender XDR tenant.

This test is intentionally skipped unless an operator supplies a bounded
AlertInfo window, expected count, and owner-only bearer-token file.  Repository
CI does not possess tenant credentials, so the presence of this test is not a
claim that the connector has been exercised against a live tenant.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

from assurance_lab.connectors.contract import ConnectorWindow
from assurance_lab.connectors.defender_xdr import (
    DEFAULT_GRAPH_ENDPOINT,
    DefenderBearerToken,
    DefenderXDRConnector,
    DefenderXDRRequest,
    defender_xdr_endpoint_origin_digest,
    new_defender_capture_nonce,
    verify_defender_xdr_capture,
)
from assurance_lab.evidence.canonical import strict_jsonl_loads


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if value is None:
        pytest.skip(f"{name} is required for the live Defender XDR conformance test")
    return value


def _parse_utc(name: str) -> datetime:
    text = _required_environment(name)
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise AssertionError(f"{name} must be whole-second UTC") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != text:
        raise AssertionError(f"{name} must be canonical whole-second UTC")
    return parsed


def _read_token_file() -> bytes:
    path = Path(_required_environment("CONTROL_ASSURANCE_DEFENDER_XDR_TOKEN_FILE"))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > 32 * 1024
            or before.st_mode & 0o077
        ):
            raise AssertionError("token file must be a bounded owner-only regular file")
        content = os.read(descriptor, before.st_size + 1)
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if len(content) != before.st_size or before_identity != after_identity:
            raise AssertionError("token file changed while it was read")
    finally:
        os.close(descriptor)
    return content


@dataclass(frozen=True, slots=True)
class _OneShotTokenProvider:
    token: DefenderBearerToken

    def get_token(self, *, deadline: float) -> DefenderBearerToken:
        if deadline <= 0:
            raise RuntimeError("invalid token acquisition deadline")
        return self.token


def _parse_alert_timestamp(value: str) -> datetime:
    if len(value) != 28 or value[-1] != "Z" or value[-9] != ".":
        raise AssertionError("connector returned a non-canonical AlertInfo timestamp")
    # Python datetime is microsecond-precision; discard only the seventh
    # fractional digit for this half-open whole-second boundary assertion.
    return datetime.strptime(f"{value[:-2]}Z", "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


def test_opt_in_real_defender_xdr_alertinfo_capture() -> None:
    endpoint = os.environ.get(
        "CONTROL_ASSURANCE_DEFENDER_XDR_ENDPOINT",
        DEFAULT_GRAPH_ENDPOINT,
    )
    expected_count = int(_required_environment("CONTROL_ASSURANCE_DEFENDER_XDR_EXPECTED_COUNT"))
    max_hits = int(
        os.environ.get(
            "CONTROL_ASSURANCE_DEFENDER_XDR_MAX_HITS",
            str(max(expected_count, 1)),
        )
    )
    request = DefenderXDRRequest(
        capture_id="defender-xdr-live-conformance",
        capture_nonce=new_defender_capture_nonce(),
        window=ConnectorWindow(
            start=_parse_utc("CONTROL_ASSURANCE_DEFENDER_XDR_START"),
            end=_parse_utc("CONTROL_ASSURANCE_DEFENDER_XDR_END"),
        ),
        max_hits=max_hits,
    )
    connector = DefenderXDRConnector(
        _OneShotTokenProvider(DefenderBearerToken(_read_token_file())),
        endpoint=endpoint,
    )

    capture = connector.capture(request)
    verified = verify_defender_xdr_capture(
        capture.receipt_bytes,
        expected_endpoint_origin_digest=defender_xdr_endpoint_origin_digest(endpoint),
        expected_request=request,
        expected_connector_version=capture.descriptor.connector_version,
    )
    records = strict_jsonl_loads(capture.records_jsonl, require_sorted_ids=True)

    assert capture.record_count == verified.record_count == expected_count
    assert capture.records_digest == verified.records_digest
    assert capture.receipt_digest == verified.receipt_digest
    assert len(records) == expected_count
    assert all(record["fields"]["AlertId"] for record in records)
    assert all(
        request.window.start
        <= _parse_alert_timestamp(record["fields"]["Timestamp"])
        < request.window.end
        for record in records
    )
