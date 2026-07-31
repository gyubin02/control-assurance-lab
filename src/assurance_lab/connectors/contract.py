"""Small vendor-neutral contract for read-only evidence connectors.

A connector is not allowed to return an optimistic partial result.  A returned
capture is complete for its declared query and window, or the connector raises
``ConnectorCaptureError``.  Vendor-specific verifiers turn the opaque receipt
back into the same canonical record stream without trusting the collector's
derived output.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_jsonl_loads,
)

_ID_RE = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_MEDIA_TYPE_RE = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
_CONNECTOR_RECORD_LIMITS = JSONLimits(
    max_bytes=64 * 1024 * 1024,
    max_line_bytes=2 * 1024 * 1024,
    max_depth=16,
    max_collection_items=200_000,
    max_string_length=1024 * 1024,
)


class ConnectorCaptureError(RuntimeError):
    """A source could not be captured completely and safely."""

    def __init__(self, stage: str, reason: str) -> None:
        if _ID_RE.fullmatch(stage) is None:
            raise ValueError("connector failure stage is not a portable identifier")
        if not reason or len(reason) > 512:
            raise ValueError("connector failure reason is empty or too long")
        self.stage = stage
        self.reason = reason
        super().__init__(f"{stage}: {reason}")


def _require_identifier(value: str, *, label: str) -> str:
    if type(value) is not str or _ID_RE.fullmatch(value) is None:
        raise ValueError(f"{label} is not a portable identifier")
    return value


def _require_digest(value: str, *, label: str) -> str:
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be lowercase sha256:<64 hex>")
    return value


def _canonical_utc(value: datetime, *, label: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
    try:
        converted = value.astimezone(UTC)
    except (OverflowError, ValueError) as exc:
        raise ValueError(f"{label} is outside the supported UTC range") from exc
    if converted.microsecond != 0:
        raise ValueError(f"{label} must use whole seconds")
    return converted


def canonical_timestamp(value: datetime) -> str:
    """Encode one already-validated UTC instant without locale ambiguity."""

    converted = _canonical_utc(value, label="timestamp")
    return converted.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True, slots=True)
class ConnectorDescriptor:
    """Stable identity and output type of one connector implementation."""

    connector_id: str
    connector_version: str
    capture_media_type: str

    def __post_init__(self) -> None:
        _require_identifier(self.connector_id, label="connector id")
        if (
            type(self.connector_version) is not str
            or not self.connector_version
            or len(self.connector_version) > 64
            or not self.connector_version.isascii()
        ):
            raise ValueError("connector version must be non-empty ASCII")
        if (
            type(self.capture_media_type) is not str
            or len(self.capture_media_type) > 128
            or _MEDIA_TYPE_RE.fullmatch(self.capture_media_type) is None
        ):
            raise ValueError("capture media type is invalid")


@dataclass(frozen=True, slots=True)
class ConnectorWindow:
    """Half-open source interval: ``start <= event time < end``."""

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        start = _canonical_utc(self.start, label="window start")
        end = _canonical_utc(self.end, label="window end")
        if start >= end:
            raise ValueError("connector window must have positive duration")
        object.__setattr__(self, "start", start)
        object.__setattr__(self, "end", end)

    def as_json(self) -> dict[str, str]:
        return {
            "end_exclusive": canonical_timestamp(self.end),
            "start_inclusive": canonical_timestamp(self.start),
        }


@dataclass(frozen=True, slots=True)
class ConnectorCapture:
    """Exact vendor receipt plus the canonical records derived from it."""

    descriptor: ConnectorDescriptor
    receipt_bytes: bytes
    receipt_digest: str
    records_jsonl: bytes
    records_digest: str
    record_count: int

    def __post_init__(self) -> None:
        if type(self.receipt_bytes) is not bytes or not self.receipt_bytes:
            raise ValueError("connector receipt must be non-empty immutable bytes")
        if type(self.records_jsonl) is not bytes:
            raise ValueError("connector records must be immutable bytes")
        _require_digest(self.receipt_digest, label="receipt digest")
        _require_digest(self.records_digest, label="records digest")
        if type(self.record_count) is not int or self.record_count < 0:
            raise ValueError("record count must be a non-negative integer")
        if f"sha256:{hashlib.sha256(self.receipt_bytes).hexdigest()}" != self.receipt_digest:
            raise ValueError("receipt digest does not match the exact receipt bytes")
        if f"sha256:{hashlib.sha256(self.records_jsonl).hexdigest()}" != self.records_digest:
            raise ValueError("records digest does not match the exact JSONL bytes")
        try:
            records = strict_jsonl_loads(
                self.records_jsonl,
                limits=_CONNECTOR_RECORD_LIMITS,
                require_sorted_ids=True,
            )
        except StrictJSONError as exc:
            raise ValueError("connector records are not canonical sorted JSONL") from exc
        if len(records) != self.record_count:
            raise ValueError("record count does not match the canonical JSONL stream")


@dataclass(frozen=True, slots=True)
class VerifiedConnectorCapture:
    """A verifier-derived view of a complete connector capture."""

    descriptor: ConnectorDescriptor
    receipt_digest: str
    records_jsonl: bytes
    records_digest: str
    record_count: int
    source_locator_digest: str
    source_product: str
    source_version: str | None

    def __post_init__(self) -> None:
        _require_digest(self.receipt_digest, label="receipt digest")
        _require_digest(self.records_digest, label="records digest")
        _require_digest(self.source_locator_digest, label="source locator digest")
        if type(self.records_jsonl) is not bytes:
            raise ValueError("verified records must be immutable bytes")
        if type(self.record_count) is not int or self.record_count < 0:
            raise ValueError("verified record count must be non-negative")
        if f"sha256:{hashlib.sha256(self.records_jsonl).hexdigest()}" != self.records_digest:
            raise ValueError("verified records digest does not match the JSONL bytes")
        try:
            records = strict_jsonl_loads(
                self.records_jsonl,
                limits=_CONNECTOR_RECORD_LIMITS,
                require_sorted_ids=True,
            )
        except StrictJSONError as exc:
            raise ValueError("verified records are not canonical sorted JSONL") from exc
        if len(records) != self.record_count:
            raise ValueError("verified record count does not match the JSONL stream")
        if (
            type(self.source_product) is not str
            or not self.source_product
            or len(self.source_product) > 128
        ):
            raise ValueError("source product is empty or too long")
        if self.source_version is not None and (
            type(self.source_version) is not str
            or not self.source_version
            or len(self.source_version) > 128
        ):
            raise ValueError("source version must be non-empty text or None")

    def canonical_summary(self) -> bytes:
        return canonical_json_bytes(
            {
                "connector_id": self.descriptor.connector_id,
                "connector_version": self.descriptor.connector_version,
                "record_count": self.record_count,
                "records_digest": self.records_digest,
                "receipt_digest": self.receipt_digest,
                "source_locator_digest": self.source_locator_digest,
                "source_product": self.source_product,
                "source_version": self.source_version,
            }
        )


@runtime_checkable
class ReadOnlySnapshotConnector(Protocol):
    """The minimum surface required by the evidence plane."""

    @property
    def descriptor(self) -> ConnectorDescriptor:
        """Return stable implementation and media-type identity."""

    def capture(self, request: object) -> ConnectorCapture:
        """Return one complete capture or raise ``ConnectorCaptureError``."""
