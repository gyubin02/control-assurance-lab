"""Fail-closed admission of signed evidence into durable custody.

The public boundary accepts only raw inputs.  It does not accept a caller's
claim that a signature, policy, CAB, signer identity, or timestamp was already
verified.  ``AdmissionService`` reads its clock once, resolves policy through a
configured authority, verifies the DSSE payload and exact CAB snapshot, and
then asks the private SQLite ledger to reserve and finalize one state
transition.

SQLite remains the R1 single-node reference.  WAL + FULL synchronous commits
and explicit crash recovery are useful, but they are not HA, an external
transparency log, a privileged-operator rollback anchor, or WORM custody.  The
receipt signer is called only after a durable preparation commits and before a
compare-and-finalize transaction begins. A slow or unavailable remote signer
therefore leaves retryable state without holding the SQLite writer lock.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import secrets
import sqlite3
import stat
import threading
import unicodedata
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Literal, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from assurance_lab.evidence.attestation import (
    ATTESTATION_VERIFIER_ID,
    MAX_ENVELOPE_BYTES,
    MAX_TRUST_POLICY_BYTES,
    TRUST_POLICY_SCHEMA_VERSION,
    AttestationReason,
    AttestationVerification,
    TrustPolicy,
    parse_dsse_envelope,
    parse_trust_policy,
    verify_dsse_attestation,
)
from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)
from assurance_lab.evidence.snapshot import (
    MAX_CAB_SNAPSHOT_BYTES,
    SNAPSHOT_MEDIA_TYPE,
    CABSnapshotError,
    SealedCABSnapshot,
    capture_cab_snapshot,
    verify_cab_snapshot,
)

LEASE_MEDIA_TYPE: Literal["application/vnd.control-assurance.job-lease.v2+json"] = (
    "application/vnd.control-assurance.job-lease.v2+json"
)
LEASE_GRANT_MEDIA_TYPE: Literal["application/vnd.control-assurance.signed-job-lease.v2+json"] = (
    "application/vnd.control-assurance.signed-job-lease.v2+json"
)
COLLECTION_STATEMENT_MEDIA_TYPE: Literal[
    "application/vnd.control-assurance.collection-statement.v2+json"
] = "application/vnd.control-assurance.collection-statement.v2+json"
RECEIPT_MEDIA_TYPE: Literal["application/vnd.control-assurance.admission-receipt.v2+json"] = (
    "application/vnd.control-assurance.admission-receipt.v2+json"
)
CUSTODY_ACK_MEDIA_TYPE: Literal["application/vnd.control-assurance.custody-ack.v1+json"] = (
    "application/vnd.control-assurance.custody-ack.v1+json"
)
ADMISSION_SCHEMA_VERSION: Literal["2.0.0"] = "2.0.0"
CUSTODY_ACK_SCHEMA_VERSION: Literal["1.0.0"] = "1.0.0"
_LEDGER_SCHEMA_VERSION: Literal["3.0.0"] = "3.0.0"
MINIMUM_NONCE_BYTES = 32

_TIMESTAMP_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$"
)
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,255}$")
_BIDI_CLASSES = frozenset(
    {"R", "AL", "AN", "RLE", "RLO", "LRE", "LRO", "PDF", "LRI", "RLI", "FSI", "PDI"}
)
_DOCUMENT_LIMITS = JSONLimits(
    max_bytes=1024 * 1024,
    max_line_bytes=1024 * 1024,
    max_depth=8,
    max_collection_items=512,
    max_string_length=4096,
)


class _FrozenStrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        revalidate_instances="always",
        strict=True,
    )


def _tuple_from_array(value: object) -> object:
    if isinstance(value, tuple):
        return value
    if isinstance(value, list):
        return tuple(value)
    raise ValueError("value must be an array")


def _canonical_timestamp(value: datetime) -> str:
    if type(value) is not datetime or value.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    try:
        offset = value.utcoffset()
    except Exception as exc:
        raise ValueError("timestamp has an invalid UTC offset") from exc
    if offset is None:
        raise ValueError("timestamp must be timezone-aware")
    try:
        normalized = value.astimezone(UTC)
    except Exception as exc:
        raise ValueError("timestamp cannot be normalized to UTC") from exc
    return (
        f"{normalized.year:04d}-{normalized.month:02d}-{normalized.day:02d}T"
        f"{normalized.hour:02d}:{normalized.minute:02d}:"
        f"{normalized.second:02d}.{normalized.microsecond:06d}Z"
    )


def _parse_timestamp(value: str) -> datetime:
    if _TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise ValueError("timestamp must use YYYY-MM-DDTHH:MM:SS.ffffffZ")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ValueError("timestamp is not a valid UTC date and time") from exc


def _safe_identifier(value: str) -> str:
    if _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError("identifier is not portable or exceeds 256 characters")
    if any(
        unicodedata.category(character) in {"Cc", "Cf", "Cs"}
        or unicodedata.bidirectional(character) in _BIDI_CLASSES
        for character in value
    ):
        raise ValueError("identifier contains a control or bidirectional character")
    return value


def _safe_reference(value: str) -> str:
    if not value or len(value) > 1024:
        raise ValueError("custody reference is empty or exceeds 1024 characters")
    if any(
        ord(character) < 0x21
        or ord(character) > 0x7E
        or unicodedata.bidirectional(character) in _BIDI_CLASSES
        for character in value
    ):
        raise ValueError("custody reference must use visible ASCII")
    return value


def _canonical_b64(value: str, *, decoded_bytes: int) -> str:
    try:
        encoded = value.encode("ascii", errors="strict")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ValueError("signature is not canonical RFC 4648 base64") from exc
    if len(decoded) != decoded_bytes or base64.b64encode(decoded) != encoded:
        raise ValueError(f"signature must be canonical base64 for exactly {decoded_bytes} bytes")
    return value


def _digest(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _canonical_model_bytes(model: BaseModel) -> bytes:
    return canonical_json_bytes(model.model_dump(mode="json"), limits=_DOCUMENT_LIMITS)


def _parse_canonical_model(
    document_bytes: bytes,
    model_type: type[_FrozenStrictModel],
) -> _FrozenStrictModel:
    document = strict_json_loads(document_bytes, limits=_DOCUMENT_LIMITS)
    if not isinstance(document, dict):
        raise ValueError("document root must be an object")
    model = model_type.model_validate(document)
    if _canonical_model_bytes(model) != document_bytes:
        raise ValueError("document must use exact RFC 8785 canonical JSON")
    return model


class DetachedSignature(_FrozenStrictModel):
    key_id: str = Field(min_length=1, max_length=256)
    algorithm: Literal["ed25519"]
    signature: str = Field(min_length=88, max_length=88)

    _key_id_is_safe = field_validator("key_id")(_safe_identifier)

    @field_validator("signature")
    @classmethod
    def signature_is_exact_ed25519(cls, value: str) -> str:
        return _canonical_b64(value, decoded_bytes=64)


class JobLease(_FrozenStrictModel):
    """One signed authorization to submit one exact CAB in one sequence."""

    media_type: Literal["application/vnd.control-assurance.job-lease.v2+json"]
    schema_version: Literal["2.0.0"]
    tenant_id: str = Field(min_length=1, max_length=256)
    collector_id: str = Field(min_length=1, max_length=256)
    audience: str = Field(min_length=1, max_length=256)
    job_id: str = Field(min_length=1, max_length=256)
    capability_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    policy_id: str = Field(min_length=1, max_length=256)
    policy_revision: int = Field(ge=1)
    policy_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    lease_authority_key_fingerprint: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    epoch: int = Field(ge=1)
    sequence: int = Field(ge=1)
    previous_epoch: int | None = Field(default=None, ge=1)
    previous_epoch_final_sequence: int | None = Field(default=None, ge=1)
    previous_epoch_final_receipt_digest: str | None = Field(
        default=None,
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    cab_id: str = Field(pattern=r"^cab:sha256:[a-f0-9]{64}$")
    manifest_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    job_nonce: str = Field(pattern=r"^[a-f0-9]{64}$")
    issued_at: str
    expires_at: str

    _tenant_is_safe = field_validator("tenant_id")(_safe_identifier)
    _collector_is_safe = field_validator("collector_id")(_safe_identifier)
    _audience_is_safe = field_validator("audience")(_safe_identifier)
    _job_is_safe = field_validator("job_id")(_safe_identifier)
    _policy_is_safe = field_validator("policy_id")(_safe_identifier)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def timestamp_is_canonical(cls, value: str) -> str:
        _parse_timestamp(value)
        return value

    @model_validator(mode="after")
    def lease_is_coherent(self) -> JobLease:
        if _parse_timestamp(self.expires_at) <= _parse_timestamp(self.issued_at):
            raise ValueError("lease expiry must be later than issuance")
        transition = (
            self.previous_epoch,
            self.previous_epoch_final_sequence,
            self.previous_epoch_final_receipt_digest,
        )
        if self.epoch == 1 or self.sequence != 1:
            if any(value is not None for value in transition):
                raise ValueError("only sequence one of a later epoch may bind a predecessor")
        else:
            if any(value is None for value in transition):
                raise ValueError("a later epoch must bind the preceding collector head")
            if self.previous_epoch != self.epoch - 1:
                raise ValueError("previous_epoch must be exactly epoch minus one")
        if self.cab_id.removeprefix("cab:") != self.manifest_digest:
            raise ValueError("CAB id must identify the exact manifest digest")
        return self

    def canonical_bytes(self) -> bytes:
        return _canonical_model_bytes(self)

    def lease_digest(self) -> str:
        return _digest(self.canonical_bytes())

    def nonce_digest(self) -> str:
        return _digest(bytes.fromhex(self.job_nonce))


class SignedJobLease(_FrozenStrictModel):
    media_type: Literal["application/vnd.control-assurance.signed-job-lease.v2+json"]
    schema_version: Literal["2.0.0"]
    lease: JobLease
    authority_signature: DetachedSignature

    def canonical_bytes(self) -> bytes:
        return _canonical_model_bytes(self)


class CollectionStatement(_FrozenStrictModel):
    """Collector-signed binding from one lease to one exact CAB manifest."""

    media_type: Literal["application/vnd.control-assurance.collection-statement.v2+json"]
    schema_version: Literal["2.0.0"]
    lease_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    tenant_id: str = Field(min_length=1, max_length=256)
    collector_id: str = Field(min_length=1, max_length=256)
    audience: str = Field(min_length=1, max_length=256)
    job_id: str = Field(min_length=1, max_length=256)
    capability_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    policy_id: str = Field(min_length=1, max_length=256)
    policy_revision: int = Field(ge=1)
    policy_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    epoch: int = Field(ge=1)
    sequence: int = Field(ge=1)
    previous_epoch: int | None = Field(default=None, ge=1)
    previous_epoch_final_sequence: int | None = Field(default=None, ge=1)
    previous_epoch_final_receipt_digest: str | None = Field(
        default=None,
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    cab_id: str = Field(pattern=r"^cab:sha256:[a-f0-9]{64}$")
    manifest_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    job_nonce: str = Field(pattern=r"^[a-f0-9]{64}$")
    collected_at: str

    _tenant_is_safe = field_validator("tenant_id")(_safe_identifier)
    _collector_is_safe = field_validator("collector_id")(_safe_identifier)
    _audience_is_safe = field_validator("audience")(_safe_identifier)
    _job_is_safe = field_validator("job_id")(_safe_identifier)
    _policy_is_safe = field_validator("policy_id")(_safe_identifier)

    @field_validator("collected_at")
    @classmethod
    def timestamp_is_canonical(cls, value: str) -> str:
        _parse_timestamp(value)
        return value

    @model_validator(mode="after")
    def statement_is_coherent(self) -> CollectionStatement:
        if self.cab_id.removeprefix("cab:") != self.manifest_digest:
            raise ValueError("CAB id must identify the exact manifest digest")
        return self

    def canonical_bytes(self) -> bytes:
        return _canonical_model_bytes(self)

    def nonce_digest(self) -> str:
        return _digest(bytes.fromhex(self.job_nonce))

    def matches(self, lease: JobLease) -> bool:
        return (
            self.lease_digest == lease.lease_digest()
            and self.tenant_id == lease.tenant_id
            and self.collector_id == lease.collector_id
            and self.audience == lease.audience
            and self.job_id == lease.job_id
            and self.capability_digest == lease.capability_digest
            and self.policy_id == lease.policy_id
            and self.policy_revision == lease.policy_revision
            and self.policy_digest == lease.policy_digest
            and self.epoch == lease.epoch
            and self.sequence == lease.sequence
            and self.previous_epoch == lease.previous_epoch
            and self.previous_epoch_final_sequence == lease.previous_epoch_final_sequence
            and self.previous_epoch_final_receipt_digest
            == lease.previous_epoch_final_receipt_digest
            and self.cab_id == lease.cab_id
            and self.manifest_digest == lease.manifest_digest
            and self.job_nonce == lease.job_nonce
        )


class AdmissionReceiptBody(_FrozenStrictModel):
    media_type: Literal["application/vnd.control-assurance.admission-receipt.v2+json"]
    schema_version: Literal["2.0.0"]
    receipt_sequence: int = Field(ge=1)
    admitted_at: str
    tenant_id: str = Field(min_length=1, max_length=256)
    collector_id: str = Field(min_length=1, max_length=256)
    audience: str = Field(min_length=1, max_length=256)
    job_id: str = Field(min_length=1, max_length=256)
    capability_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    epoch: int = Field(ge=1)
    sequence: int = Field(ge=1)
    previous_epoch: int | None = Field(default=None, ge=1)
    previous_epoch_final_sequence: int | None = Field(default=None, ge=1)
    previous_epoch_final_receipt_digest: str | None = Field(
        default=None,
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    lease_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    nonce_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    cab_id: str = Field(pattern=r"^cab:sha256:[a-f0-9]{64}$")
    manifest_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    cab_snapshot_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    cab_snapshot_media_type: Literal["application/vnd.control-assurance.cab-snapshot.v1"]
    envelope_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    payload_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    payload_type: Literal["application/vnd.control-assurance.collection-statement.v2+json"]
    trust_policy_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    trust_policy_id: str = Field(min_length=1, max_length=256)
    trust_policy_revision: int = Field(ge=1)
    trust_policy_schema_version: Literal["1.0.0"]
    lease_authority_key_fingerprint: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    receipt_signer_key_fingerprint: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    attestation_verifier_id: Literal["control-assurance-lab/python-attestation-v1"]
    attestation_verification_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    accepted_key_ids: tuple[str, ...] = Field(min_length=1, max_length=64)
    accepted_identities: tuple[str, ...] = Field(min_length=1, max_length=64)
    admission_request_fingerprint: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    previous_receipt_digest: str | None = Field(
        default=None,
        pattern=r"^sha256:[a-f0-9]{64}$",
    )
    custody_object_id: str = Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")
    custody_reference: str = Field(min_length=1, max_length=1024)

    _tenant_is_safe = field_validator("tenant_id")(_safe_identifier)
    _collector_is_safe = field_validator("collector_id")(_safe_identifier)
    _audience_is_safe = field_validator("audience")(_safe_identifier)
    _job_is_safe = field_validator("job_id")(_safe_identifier)
    _policy_is_safe = field_validator("trust_policy_id")(_safe_identifier)
    _custody_reference_is_safe = field_validator("custody_reference")(_safe_reference)
    _key_ids_are_immutable = field_validator(
        "accepted_key_ids",
        mode="before",
    )(_tuple_from_array)
    _identities_are_immutable = field_validator(
        "accepted_identities",
        mode="before",
    )(_tuple_from_array)

    @field_validator("admitted_at")
    @classmethod
    def timestamp_is_canonical(cls, value: str) -> str:
        _parse_timestamp(value)
        return value

    @field_validator("accepted_key_ids", "accepted_identities")
    @classmethod
    def signer_sets_are_canonical(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if values != tuple(sorted(values)) or len(set(values)) != len(values):
            raise ValueError("accepted signer fields must be sorted and unique")
        for value in values:
            _safe_identifier(value)
        return values

    @model_validator(mode="after")
    def transition_is_coherent(self) -> AdmissionReceiptBody:
        if self.lease_authority_key_fingerprint == self.receipt_signer_key_fingerprint:
            raise ValueError("lease and receipt roles require distinct public-key material")
        transition = (
            self.previous_epoch,
            self.previous_epoch_final_sequence,
            self.previous_epoch_final_receipt_digest,
        )
        if self.epoch == 1 or self.sequence != 1:
            if any(value is not None for value in transition):
                raise ValueError("only sequence one of a later epoch may bind a predecessor")
        else:
            if any(value is None for value in transition):
                raise ValueError("a later epoch must bind the preceding collector head")
            if self.previous_epoch != self.epoch - 1:
                raise ValueError("previous_epoch must be exactly epoch minus one")
        return self

    def canonical_bytes(self) -> bytes:
        return _canonical_model_bytes(self)


class AdmissionReceipt(_FrozenStrictModel):
    body: AdmissionReceiptBody
    service_signature: DetachedSignature

    def canonical_bytes(self) -> bytes:
        return _canonical_model_bytes(self)

    def receipt_digest(self) -> str:
        return _digest(self.canonical_bytes())


class CustodyAcknowledgementBody(_FrozenStrictModel):
    media_type: Literal["application/vnd.control-assurance.custody-ack.v1+json"]
    schema_version: Literal["1.0.0"]
    receipt_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    custody_object_id: str = Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")
    custody_reference: str = Field(min_length=1, max_length=1024)
    envelope_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    cab_snapshot_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    trust_policy_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    receipt_signer_key_fingerprint: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")

    _custody_reference_is_safe = field_validator("custody_reference")(_safe_reference)

    def canonical_bytes(self) -> bytes:
        return _canonical_model_bytes(self)


class CustodyAcknowledgement(_FrozenStrictModel):
    body: CustodyAcknowledgementBody
    service_signature: DetachedSignature

    def canonical_bytes(self) -> bytes:
        return _canonical_model_bytes(self)

    def acknowledgement_digest(self) -> str:
        return _digest(self.canonical_bytes())


class AdmissionDisposition(StrEnum):
    ADMITTED = "admitted"
    EXACT_RETRY = "exact-retry"


class AdmissionOutcome(_FrozenStrictModel):
    disposition: AdmissionDisposition
    receipt: AdmissionReceipt
    custody_acknowledgement: CustodyAcknowledgement

    @property
    def custody_reference(self) -> str:
        return self.custody_acknowledgement.body.custody_reference


class AdmissionRejectReason(StrEnum):
    MALFORMED_LEASE = "malformed-lease"
    INVALID_LEASE_SIGNATURE = "invalid-lease-signature"
    DUPLICATE_JOB = "duplicate-job"
    DUPLICATE_NONCE = "duplicate-nonce"
    DUPLICATE_SEQUENCE = "duplicate-sequence"
    UNKNOWN_LEASE = "unknown-lease"
    LEASE_EXPIRED = "lease-expired"
    LEASE_MISMATCH = "lease-mismatch"
    OUT_OF_SEQUENCE = "out-of-sequence"
    EPOCH_MISMATCH = "epoch-mismatch"
    REPLAY_CONFLICT = "replay-conflict"
    RETRY_MISMATCH = "retry-mismatch"
    MALFORMED_ENVELOPE = "malformed-envelope"
    POLICY_UNAVAILABLE = "policy-unavailable"
    POLICY_ROLLBACK = "policy-rollback"
    POLICY_FORK = "policy-fork"
    ATTESTATION_REJECTED = "attestation-rejected"
    CAB_REJECTED = "cab-rejected"
    CONFIGURATION_MISMATCH = "configuration-mismatch"
    CLOCK_ROLLBACK = "clock-rollback"
    RESOURCE_LIMIT_EXCEEDED = "resource-limit-exceeded"
    QUOTA_EXCEEDED = "quota-exceeded"
    SIGNER_UNAVAILABLE = "signer-unavailable"
    INVALID_RECEIPT_SIGNATURE = "invalid-receipt-signature"
    CUSTODY_UNAVAILABLE = "custody-unavailable"
    INTERNAL_INTEGRITY_ERROR = "internal-integrity-error"
    STORAGE_UNAVAILABLE = "storage-unavailable"


class AdmissionRejected(ValueError):
    """A stable fail-closed rejection suitable for an external reason code."""

    def __init__(self, reason: AdmissionRejectReason, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


class LeaseAuthorityVerifier(Protocol):
    @property
    def key_id(self) -> str:
        """Stable key label bound to every detached signature."""
        ...

    @property
    def public_key_bytes(self) -> bytes:
        """Immutable canonical 32-byte raw Ed25519 public key."""
        ...


class ReceiptSigner(LeaseAuthorityVerifier, Protocol):
    """Concurrent signer boundary; implementations must be thread-safe."""

    def sign(self, message: bytes) -> DetachedSignature: ...


def _signer_fingerprint(signer: LeaseAuthorityVerifier) -> str:
    """Derive one representation-independent signer identity from raw key material."""

    try:
        public_key = signer.public_key_bytes
    except Exception as exc:
        raise ValueError("signer public-key material is unavailable") from exc
    if type(public_key) is not bytes or len(public_key) != 32:
        raise ValueError("signer must expose one canonical raw Ed25519 public key")
    return _digest(public_key)


def _verify_signer_signature(
    signer: LeaseAuthorityVerifier,
    message: bytes,
    signature: DetachedSignature,
    *,
    expected_fingerprint: str,
) -> bool:
    """Verify locally with immutable key material; never call a remote adapter."""

    try:
        public_key = signer.public_key_bytes
        key_id = signer.key_id
        if (
            type(message) is not bytes
            or not isinstance(signature, DetachedSignature)
            or type(key_id) is not str
            or signature.key_id != key_id
            or signature.algorithm != "ed25519"
            or type(public_key) is not bytes
            or len(public_key) != 32
            or _digest(public_key) != expected_fingerprint
        ):
            return False
        encoded = signature.signature.encode("ascii", errors="strict")
        decoded = base64.b64decode(encoded, validate=True)
        if len(decoded) != 64 or base64.b64encode(decoded) != encoded:
            return False
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            decoded,
            message,
        )
    except (
        AttributeError,
        InvalidSignature,
        UnicodeEncodeError,
        ValueError,
        TypeError,
        binascii.Error,
    ):
        return False
    return True


class TrustPolicyResolver(Protocol):
    """Configured policy authority; callers cannot inject policy claims."""

    def resolve(
        self,
        policy_id: str,
        policy_revision: int,
        policy_digest: str,
    ) -> bytes: ...


class CustodyStore(Protocol):
    """Deterministic, idempotent durable custody keyed by object id."""

    def reference_for(self, custody_object_id: str) -> str: ...

    def persist(
        self,
        *,
        custody_object_id: str,
        custody_reference: str,
        receipt_bytes: bytes,
        envelope_bytes: bytes,
        cab_snapshot_bytes: bytes,
        trust_policy_bytes: bytes,
        expected_envelope_digest: str,
        expected_cab_snapshot_digest: str,
        expected_trust_policy_digest: str,
        expected_receipt_digest: str,
    ) -> str: ...

    def verify(
        self,
        *,
        custody_object_id: str,
        custody_reference: str,
        receipt_digest: str,
        envelope_digest: str,
        cab_snapshot_digest: str,
        trust_policy_digest: str,
    ) -> bool: ...


class Clock(Protocol):
    def now(self) -> datetime: ...


class FaultPoint(StrEnum):
    AFTER_PREPARE_BEFORE_RECEIPT_SIGN = "after-prepare-before-receipt-sign"
    AFTER_RECEIPT_SIGN_BEFORE_FINALIZE = "after-receipt-sign-before-finalize"
    BEFORE_COMMIT = "before-commit"
    AFTER_COMMIT_BEFORE_CUSTODY = "after-commit-before-custody"
    AFTER_CUSTODY_BEFORE_ACK = "after-custody-before-ack"
    AFTER_ACK_PREPARE_BEFORE_SIGN = "after-ack-prepare-before-sign"
    AFTER_ACK_SIGN_BEFORE_FINALIZE = "after-ack-sign-before-finalize"


class FaultInjector(Protocol):
    def __call__(self, point: FaultPoint) -> None: ...


class _SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class AdmissionLimits:
    max_envelope_bytes: int = MAX_ENVELOPE_BYTES
    max_policy_bytes: int = MAX_TRUST_POLICY_BYTES
    max_cab_snapshot_bytes: int = MAX_CAB_SNAPSHOT_BYTES
    max_admissions_per_tenant: int = 100_000
    max_registered_leases_per_tenant: int = 200_000
    max_database_bytes: int = 1024 * 1024 * 1024

    def __post_init__(self) -> None:
        values = (
            self.max_envelope_bytes,
            self.max_policy_bytes,
            self.max_cab_snapshot_bytes,
            self.max_admissions_per_tenant,
            self.max_registered_leases_per_tenant,
            self.max_database_bytes,
        )
        if any(type(value) is not int or value <= 0 for value in values):
            raise ValueError("admission limits must be positive integers")
        if self.max_envelope_bytes > MAX_ENVELOPE_BYTES:
            raise ValueError("envelope limit exceeds the DSSE profile")
        if self.max_policy_bytes > MAX_TRUST_POLICY_BYTES:
            raise ValueError("policy limit exceeds the trust-policy profile")
        if self.max_cab_snapshot_bytes > MAX_CAB_SNAPSHOT_BYTES:
            raise ValueError("CAB snapshot limit exceeds the snapshot profile")


def parse_job_lease(payload: bytes) -> JobLease:
    try:
        parsed = _parse_canonical_model(payload, JobLease)
    except (StrictJSONError, ValueError, TypeError) as exc:
        raise ValueError("invalid canonical job lease") from exc
    assert isinstance(parsed, JobLease)
    return parsed


def parse_signed_job_lease(payload: bytes) -> SignedJobLease:
    try:
        parsed = _parse_canonical_model(payload, SignedJobLease)
    except (StrictJSONError, ValueError, TypeError) as exc:
        raise ValueError("invalid canonical signed job lease") from exc
    assert isinstance(parsed, SignedJobLease)
    return parsed


def parse_collection_statement(payload: bytes) -> CollectionStatement:
    try:
        parsed = _parse_canonical_model(payload, CollectionStatement)
    except (StrictJSONError, ValueError, TypeError) as exc:
        raise ValueError("invalid canonical collection statement") from exc
    assert isinstance(parsed, CollectionStatement)
    return parsed


def _parse_receipt(payload: bytes) -> AdmissionReceipt:
    parsed = _parse_canonical_model(payload, AdmissionReceipt)
    assert isinstance(parsed, AdmissionReceipt)
    return parsed


def _parse_custody_ack(payload: bytes) -> CustodyAcknowledgement:
    parsed = _parse_canonical_model(payload, CustodyAcknowledgement)
    assert isinstance(parsed, CustodyAcknowledgement)
    return parsed


def issue_signed_job_lease(
    *,
    signer: ReceiptSigner,
    tenant_id: str,
    collector_id: str,
    audience: str,
    job_id: str,
    capability_digest: str,
    policy_id: str,
    policy_revision: int,
    policy_digest: str,
    epoch: int,
    sequence: int,
    cab_id: str,
    manifest_digest: str,
    issued_at: datetime,
    expires_at: datetime,
    previous_epoch: int | None = None,
    previous_epoch_final_sequence: int | None = None,
    previous_epoch_final_receipt_digest: str | None = None,
    nonce_factory: Callable[[int], bytes] = secrets.token_bytes,
) -> SignedJobLease:
    """Issue and self-check one canonical, signed control-plane grant."""

    nonce = nonce_factory(MINIMUM_NONCE_BYTES)
    if type(nonce) is not bytes or len(nonce) != MINIMUM_NONCE_BYTES:
        raise ValueError("nonce factory must return exactly 32 bytes")
    authority_fingerprint = _signer_fingerprint(signer)
    lease = JobLease(
        media_type=LEASE_MEDIA_TYPE,
        schema_version=ADMISSION_SCHEMA_VERSION,
        tenant_id=tenant_id,
        collector_id=collector_id,
        audience=audience,
        job_id=job_id,
        capability_digest=capability_digest,
        policy_id=policy_id,
        policy_revision=policy_revision,
        policy_digest=policy_digest,
        lease_authority_key_fingerprint=authority_fingerprint,
        epoch=epoch,
        sequence=sequence,
        previous_epoch=previous_epoch,
        previous_epoch_final_sequence=previous_epoch_final_sequence,
        previous_epoch_final_receipt_digest=previous_epoch_final_receipt_digest,
        cab_id=cab_id,
        manifest_digest=manifest_digest,
        job_nonce=nonce.hex(),
        issued_at=_canonical_timestamp(issued_at),
        expires_at=_canonical_timestamp(expires_at),
    )
    signature = signer.sign(lease.canonical_bytes())
    if _signer_fingerprint(signer) != authority_fingerprint or not _verify_signer_signature(
        signer,
        lease.canonical_bytes(),
        signature,
        expected_fingerprint=authority_fingerprint,
    ):
        raise AdmissionRejected(
            AdmissionRejectReason.INVALID_LEASE_SIGNATURE,
            "lease authority did not verify its returned signature",
        )
    return SignedJobLease(
        media_type=LEASE_GRANT_MEDIA_TYPE,
        schema_version=ADMISSION_SCHEMA_VERSION,
        lease=lease,
        authority_signature=signature,
    )


def _attestation_bytes(verification: AttestationVerification) -> bytes:
    return verification.canonical_bytes()


def _admission_request_fingerprint(
    *,
    statement_digest: str,
    envelope_digest: str,
    snapshot_digest: str,
    policy_digest: str,
    policy_revision: int,
    attestation_bytes: bytes,
    audience: str,
    capability_digest: str,
    accepted_key_ids: tuple[str, ...],
    accepted_identities: tuple[str, ...],
    custody_object_id: str,
    custody_reference: str,
    lease_authority_key_fingerprint: str,
    receipt_signer_key_fingerprint: str,
) -> str:
    return _digest(
        canonical_json_bytes(
            {
                "accepted_identities": list(accepted_identities),
                "accepted_key_ids": list(accepted_key_ids),
                "attestation_verification_digest": _digest(attestation_bytes),
                "audience": audience,
                "cab_snapshot_digest": snapshot_digest,
                "capability_digest": capability_digest,
                "custody_object_id": custody_object_id,
                "custody_reference": custody_reference,
                "envelope_digest": envelope_digest,
                "lease_authority_key_fingerprint": lease_authority_key_fingerprint,
                "profile": "control-assurance-admission-request-v2",
                "receipt_signer_key_fingerprint": receipt_signer_key_fingerprint,
                "statement_digest": statement_digest,
                "trust_policy_digest": policy_digest,
                "trust_policy_revision": policy_revision,
            }
        )
    )


def _custody_object_id(
    *,
    tenant_id: str,
    job_id: str,
    envelope_digest: str,
    snapshot_digest: str,
) -> str:
    return hashlib.sha256(
        b"\x00".join(
            (
                tenant_id.encode("ascii"),
                job_id.encode("ascii"),
                envelope_digest.encode("ascii"),
                snapshot_digest.encode("ascii"),
            )
        )
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class _VerifiedAdmission:
    statement: CollectionStatement
    envelope_bytes: bytes
    envelope_digest: str
    snapshot: SealedCABSnapshot
    policy_bytes: bytes
    policy_digest: str
    attestation: AttestationVerification
    attestation_bytes: bytes
    request_fingerprint: str
    admitted_at: str
    current_time: str
    custody_object_id: str
    custody_reference: str


@dataclass(frozen=True, slots=True)
class _StoredAdmission:
    disposition: AdmissionDisposition
    receipt: AdmissionReceipt
    envelope_bytes: bytes
    cab_snapshot_bytes: bytes
    trust_policy_bytes: bytes
    custody_reference: str
    custody_acknowledgement: CustodyAcknowledgement | None


@dataclass(frozen=True, slots=True)
class _PreparedAdmission:
    """Durable unsigned receipt body and the exact bytes it will authorize."""

    receipt_body_digest: str
    body: AdmissionReceiptBody
    envelope_bytes: bytes
    cab_snapshot_bytes: bytes
    trust_policy_bytes: bytes
    attestation_bytes: bytes


@dataclass(frozen=True, slots=True)
class _PreparedCustodyAcknowledgement:
    """Durable unsigned acknowledgement body for one persisted custody object."""

    acknowledgement_body_digest: str
    body: CustodyAcknowledgementBody


_SCHEMA_SCRIPT = """
CREATE TABLE admission_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version TEXT NOT NULL,
    schema_fingerprint TEXT NOT NULL,
    lease_authority_key_fingerprint TEXT NOT NULL,
    receipt_signer_key_fingerprint TEXT NOT NULL,
    last_admitted_at TEXT
) STRICT;

CREATE TABLE job_leases (
    lease_digest TEXT PRIMARY KEY,
    nonce_digest TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    audience TEXT NOT NULL,
    job_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_revision INTEGER NOT NULL CHECK (policy_revision >= 1),
    policy_digest TEXT NOT NULL,
    epoch INTEGER NOT NULL CHECK (epoch >= 1),
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    expires_at TEXT NOT NULL,
    grant_bytes BLOB NOT NULL,
    consumed_envelope_digest TEXT,
    consumed_receipt_digest TEXT,
    UNIQUE (tenant_id, job_id),
    UNIQUE (tenant_id, collector_id, epoch, sequence)
) STRICT;

CREATE TABLE policy_versions (
    policy_id TEXT NOT NULL,
    policy_revision INTEGER NOT NULL CHECK (policy_revision >= 1),
    policy_digest TEXT NOT NULL,
    PRIMARY KEY (policy_id, policy_revision),
    UNIQUE (policy_id, policy_revision, policy_digest)
) STRICT;

CREATE TABLE policy_heads (
    policy_id TEXT PRIMARY KEY,
    current_revision INTEGER NOT NULL CHECK (current_revision >= 1),
    current_policy_digest TEXT NOT NULL,
    FOREIGN KEY (policy_id, current_revision, current_policy_digest)
        REFERENCES policy_versions (policy_id, policy_revision, policy_digest)
) STRICT;

CREATE TABLE collector_heads (
    tenant_id TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    current_epoch INTEGER NOT NULL CHECK (current_epoch >= 1),
    last_sequence INTEGER NOT NULL CHECK (last_sequence >= 1),
    last_receipt_digest TEXT NOT NULL,
    PRIMARY KEY (tenant_id, collector_id)
) STRICT;

CREATE TABLE tenant_heads (
    tenant_id TEXT PRIMARY KEY,
    last_receipt_sequence INTEGER NOT NULL CHECK (last_receipt_sequence >= 1),
    last_receipt_digest TEXT NOT NULL
) STRICT;

CREATE TABLE admissions (
    receipt_digest TEXT PRIMARY KEY,
    receipt_sequence INTEGER NOT NULL CHECK (receipt_sequence >= 1),
    lease_digest TEXT NOT NULL UNIQUE REFERENCES job_leases(lease_digest),
    tenant_id TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    epoch INTEGER NOT NULL CHECK (epoch >= 1),
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    envelope_digest TEXT NOT NULL UNIQUE,
    statement_digest TEXT NOT NULL,
    cab_snapshot_digest TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_revision INTEGER NOT NULL CHECK (policy_revision >= 1),
    policy_digest TEXT NOT NULL,
    attestation_digest TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    receipt_bytes BLOB NOT NULL,
    envelope_bytes BLOB NOT NULL,
    cab_snapshot_bytes BLOB NOT NULL,
    policy_bytes BLOB NOT NULL,
    attestation_bytes BLOB NOT NULL,
    custody_object_id TEXT NOT NULL UNIQUE,
    custody_reference TEXT NOT NULL,
    custody_state TEXT NOT NULL CHECK (custody_state IN ('pending', 'durable')),
    custody_ack_digest TEXT,
    custody_ack_bytes BLOB,
    FOREIGN KEY (policy_id, policy_revision, policy_digest)
        REFERENCES policy_versions (policy_id, policy_revision, policy_digest),
    UNIQUE (tenant_id, receipt_sequence),
    UNIQUE (tenant_id, collector_id, epoch, sequence)
) STRICT;

CREATE TABLE admission_preparations (
    receipt_body_digest TEXT PRIMARY KEY,
    lease_digest TEXT NOT NULL UNIQUE REFERENCES job_leases(lease_digest),
    tenant_id TEXT NOT NULL UNIQUE,
    collector_id TEXT NOT NULL,
    epoch INTEGER NOT NULL CHECK (epoch >= 1),
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    receipt_sequence INTEGER NOT NULL CHECK (receipt_sequence >= 1),
    envelope_digest TEXT NOT NULL UNIQUE,
    policy_id TEXT NOT NULL,
    policy_revision INTEGER NOT NULL CHECK (policy_revision >= 1),
    policy_digest TEXT NOT NULL,
    receipt_body_bytes BLOB NOT NULL,
    envelope_bytes BLOB NOT NULL,
    cab_snapshot_bytes BLOB NOT NULL,
    policy_bytes BLOB NOT NULL,
    attestation_bytes BLOB NOT NULL,
    custody_object_id TEXT NOT NULL UNIQUE,
    custody_reference TEXT NOT NULL,
    FOREIGN KEY (policy_id, policy_revision, policy_digest)
        REFERENCES policy_versions (policy_id, policy_revision, policy_digest),
    UNIQUE (tenant_id, collector_id, epoch, sequence)
) STRICT;

CREATE TABLE custody_ack_preparations (
    receipt_digest TEXT PRIMARY KEY REFERENCES admissions(receipt_digest),
    acknowledgement_body_digest TEXT NOT NULL UNIQUE,
    acknowledgement_body_bytes BLOB NOT NULL
) STRICT;
"""


def _schema_fingerprint(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        """
        SELECT type, name, tbl_name, sql
        FROM sqlite_master
        WHERE name NOT LIKE 'sqlite_%'
        ORDER BY type, name
        """
    ).fetchall()
    document = [
        {
            "name": str(row["name"]),
            "sql": None if row["sql"] is None else str(row["sql"]),
            "table": str(row["tbl_name"]),
            "type": str(row["type"]),
        }
        for row in rows
    ]
    return _digest(canonical_json_bytes(document))


@lru_cache(maxsize=1)
def _expected_schema_fingerprint() -> str:
    with closing(sqlite3.connect(":memory:", isolation_level=None)) as connection:
        connection.row_factory = sqlite3.Row
        connection.executescript(_SCHEMA_SCRIPT)
        return _schema_fingerprint(connection)


class _SQLiteAdmissionLedger:
    """Private single-node ledger.  Callers enter through ``AdmissionService``."""

    def __init__(
        self,
        path: Path,
        *,
        lease_authority: LeaseAuthorityVerifier,
        receipt_signer: ReceiptSigner,
        clock: Clock,
        limits: AdmissionLimits,
        fault_injector: FaultInjector,
    ) -> None:
        self._path = Path(os.path.abspath(os.fspath(path)))
        if self._path.name in {"", ".", ".."}:
            raise RuntimeError("admission database path must name one file")
        if (
            not hasattr(os, "O_NOFOLLOW")
            or not hasattr(os, "O_DIRECTORY")
            or not Path("/proc/self/fd").is_dir()
        ):
            raise RuntimeError(
                "private admission storage requires Linux no-follow openat semantics"
            )
        self._lease_authority = lease_authority
        self._receipt_signer = receipt_signer
        self._lease_authority_fingerprint = _signer_fingerprint(lease_authority)
        self._receipt_signer_fingerprint = _signer_fingerprint(receipt_signer)
        if self._lease_authority_fingerprint == self._receipt_signer_fingerprint:
            raise RuntimeError("lease authority and receipt signer must use distinct key material")
        self._limits = limits
        self._clock = clock
        self._fault_injector = fault_injector
        self._parent_fd = -1
        self._database_fd = -1
        self._parent_identity = (-1, -1)
        self._database_identity = (-1, -1)
        self._connection: sqlite3.Connection | None = None
        self._connection_lock = threading.RLock()
        self._observed_data_version = -1
        self._validated_tenant_heads: dict[str, tuple[int, str]] = {}
        try:
            new_database = self._prepare_storage()
            self._connection = self._open_connection()
            self._initialize(new_database=new_database)
        except Exception:
            self._close_storage()
            raise

    @property
    def lease_authority_fingerprint(self) -> str:
        return self._lease_authority_fingerprint

    @property
    def receipt_signer_fingerprint(self) -> str:
        return self._receipt_signer_fingerprint

    def _assert_configured_signer_material(self) -> None:
        try:
            authority = _signer_fingerprint(self._lease_authority)
            receipt = _signer_fingerprint(self._receipt_signer)
        except ValueError as exc:
            raise AdmissionRejected(
                AdmissionRejectReason.CONFIGURATION_MISMATCH,
                "configured signer material identity is unavailable",
            ) from exc
        if (
            authority != self._lease_authority_fingerprint
            or receipt != self._receipt_signer_fingerprint
            or authority == receipt
        ):
            raise AdmissionRejected(
                AdmissionRejectReason.CONFIGURATION_MISMATCH,
                "configured signer key material changed or is not role-separated",
            )

    def __del__(self) -> None:
        self._close_storage()

    def _close_storage(self) -> None:
        connection = getattr(self, "_connection", None)
        if connection is not None:
            with suppress(sqlite3.Error):
                connection.close()
            self._connection = None
        for attribute in ("_database_fd", "_parent_fd"):
            descriptor = getattr(self, attribute, -1)
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
                setattr(self, attribute, -1)

    def _open_parent_directory(self, *, create: bool) -> int:
        """Walk every component without following links and return the parent fd."""

        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open("/", flags)
        try:
            for component in self._path.parent.parts[1:]:
                try:
                    child = os.open(component, flags, dir_fd=descriptor)
                except FileNotFoundError:
                    if not create:
                        raise
                    os.mkdir(component, mode=0o700, dir_fd=descriptor)
                    child = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            selected = os.fstat(descriptor)
            if not stat.S_ISDIR(selected.st_mode):
                raise RuntimeError("admission database ancestry contains a non-directory")
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    def _assert_pinned_parent(self) -> None:
        try:
            descriptor = self._open_parent_directory(create=False)
        except (OSError, RuntimeError) as exc:
            raise RuntimeError(
                "admission database ancestry changed or contains a symbolic link"
            ) from exc
        try:
            selected = os.fstat(descriptor)
            if (selected.st_dev, selected.st_ino) != self._parent_identity:
                raise RuntimeError("admission database parent identity changed")
        finally:
            os.close(descriptor)

    def _prepare_storage(self) -> bool:
        try:
            self._parent_fd = self._open_parent_directory(create=True)
            parent_stat = os.fstat(self._parent_fd)
        except (OSError, RuntimeError) as exc:
            raise RuntimeError(
                "cannot prepare admission directory with symbolic link ancestry"
            ) from exc
        if (
            not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != os.geteuid()
            or stat.S_IMODE(parent_stat.st_mode) & 0o077
        ):
            raise RuntimeError(
                "admission directory must be owned by the service and mode 0700 or stricter"
            )
        self._parent_identity = (parent_stat.st_dev, parent_stat.st_ino)
        flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        new_database = False
        try:
            descriptor = os.open(
                self._path.name,
                flags,
                dir_fd=self._parent_fd,
            )
        except FileNotFoundError:
            try:
                descriptor = os.open(
                    self._path.name,
                    flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=self._parent_fd,
                )
            except OSError as exc:
                raise RuntimeError("cannot create the admission database safely") from exc
            new_database = True
        except OSError as exc:
            raise RuntimeError("cannot open the admission database safely") from exc
        try:
            if new_database:
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
                os.fsync(self._parent_fd)
            selected = os.fstat(descriptor)
            self._validate_private_file(selected)
        except Exception:
            os.close(descriptor)
            raise
        self._database_fd = descriptor
        self._database_identity = (selected.st_dev, selected.st_ino)
        return new_database

    @staticmethod
    def _validate_private_file(selected: os.stat_result) -> None:
        if (
            stat.S_ISLNK(selected.st_mode)
            or not stat.S_ISREG(selected.st_mode)
            or selected.st_nlink != 1
            or selected.st_uid != os.geteuid()
            or stat.S_IMODE(selected.st_mode) & 0o077
        ):
            raise RuntimeError(
                "admission database files must be single-link regular files owned "
                "by the service and mode 0600 or stricter"
            )

    def _database_stat(self) -> os.stat_result:
        pinned = os.fstat(self._database_fd)
        self._validate_private_file(pinned)
        if (pinned.st_dev, pinned.st_ino) != self._database_identity:
            raise RuntimeError("pinned admission database identity changed")
        published = os.stat(
            self._path.name,
            dir_fd=self._parent_fd,
            follow_symlinks=False,
        )
        self._validate_private_file(published)
        if (published.st_dev, published.st_ino) != self._database_identity:
            raise RuntimeError("admission database identity changed")
        return pinned

    def _validate_sidecars(self) -> None:
        for suffix in ("-wal", "-shm"):
            try:
                selected = os.stat(
                    f"{self._path.name}{suffix}",
                    dir_fd=self._parent_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                continue
            self._validate_private_file(selected)

    def _verify_open_database_identity(self, connection: sqlite3.Connection) -> None:
        rows = connection.execute("PRAGMA database_list").fetchall()
        main = [row for row in rows if str(row["name"]) == "main"]
        if len(main) != 1 or not str(main[0]["file"]):
            raise RuntimeError("SQLite did not report one concrete main database")
        opened = os.stat(str(main[0]["file"]), follow_symlinks=False)
        self._validate_private_file(opened)
        pinned = self._database_stat()
        expected = self._database_identity
        if (opened.st_dev, opened.st_ino) != expected or (pinned.st_dev, pinned.st_ino) != expected:
            raise RuntimeError("SQLite opened a different admission database inode")

    def _open_connection(self) -> sqlite3.Connection:
        self._assert_pinned_parent()
        self._database_stat()
        # Existing sidecars must be rejected before SQLite has an opportunity
        # to open or write through them.
        self._validate_sidecars()
        connection: sqlite3.Connection | None = None
        try:
            pinned_path = f"/proc/self/fd/{self._database_fd}"
            connection = sqlite3.connect(
                pinned_path,
                isolation_level=None,
                timeout=30,
                check_same_thread=False,
            )
            connection.row_factory = sqlite3.Row
            self._verify_open_database_identity(connection)
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA busy_timeout = 30000")
            self._assert_pinned_parent()
            self._verify_open_database_identity(connection)
            self._validate_sidecars()
            return connection
        except (OSError, sqlite3.Error) as exc:
            if connection is not None:
                connection.close()
            raise RuntimeError("cannot open the private admission database") from exc
        except RuntimeError:
            if connection is not None:
                connection.close()
            raise

    def _initialize(self, *, new_database: bool) -> None:
        connection = self._connection
        if connection is None:
            raise RuntimeError("admission database connection is unavailable")
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            self._validate_sidecars()
            quick = connection.execute("PRAGMA quick_check").fetchone()
            if quick is None or str(quick[0]) != "ok":
                raise RuntimeError("admission database quick_check failed")
            expected = _expected_schema_fingerprint()
            if new_database:
                connection.executescript(_SCHEMA_SCRIPT)
                live = _schema_fingerprint(connection)
                if live != expected:
                    raise RuntimeError("new admission schema does not match its profile")
                connection.execute(
                    """
                    INSERT INTO admission_meta (
                        singleton, schema_version, schema_fingerprint,
                        lease_authority_key_fingerprint,
                        receipt_signer_key_fingerprint,
                        last_admitted_at
                    ) VALUES (1, ?, ?, ?, ?, NULL)
                    """,
                    (
                        _LEDGER_SCHEMA_VERSION,
                        expected,
                        self._lease_authority_fingerprint,
                        self._receipt_signer_fingerprint,
                    ),
                )
            else:
                meta = connection.execute(
                    """
                    SELECT schema_version, schema_fingerprint,
                           lease_authority_key_fingerprint,
                           receipt_signer_key_fingerprint
                    FROM admission_meta WHERE singleton = 1
                    """
                ).fetchone()
                if (
                    meta is None
                    or meta["schema_version"] != _LEDGER_SCHEMA_VERSION
                    or meta["schema_fingerprint"] != expected
                    or meta["lease_authority_key_fingerprint"] != self._lease_authority_fingerprint
                    or meta["receipt_signer_key_fingerprint"] != self._receipt_signer_fingerprint
                    or _schema_fingerprint(connection) != expected
                ):
                    raise RuntimeError("unsupported or malformed admission ledger schema")
            page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
            page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
            if page_count * page_size > self._limits.max_database_bytes:
                raise RuntimeError("admission database exceeds its configured byte quota")
            self._validate_complete_ledger(connection)
            self._observed_data_version = int(
                connection.execute("PRAGMA data_version").fetchone()[0]
            )
        except AdmissionRejected as exc:
            raise RuntimeError("admission ledger history validation failed") from exc
        except sqlite3.Error as exc:
            raise RuntimeError("admission database initialization failed") from exc
        os.fsync(self._parent_fd)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """Serialize access and revalidate history after any outside SQLite commit."""

        with self._connection_lock:
            connection = self._connection
            if connection is None:
                raise RuntimeError("admission database connection is unavailable")
            self._assert_pinned_parent()
            self._database_stat()
            self._verify_open_database_identity(connection)
            self._validate_sidecars()
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._assert_pinned_parent()
                self._database_stat()
                self._verify_open_database_identity(connection)
                self._validate_sidecars()
                data_version = int(connection.execute("PRAGMA data_version").fetchone()[0])
                if data_version != self._observed_data_version:
                    quick = connection.execute("PRAGMA quick_check").fetchone()
                    if quick is None or str(quick[0]) != "ok":
                        raise RuntimeError("admission database quick_check failed")
                    if _schema_fingerprint(connection) != _expected_schema_fingerprint():
                        raise RuntimeError("admission database schema changed")
                    self._validate_complete_ledger(connection)
                    self._observed_data_version = data_version
                yield connection
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                if connection.in_transaction:
                    connection.rollback()

    @staticmethod
    def _storage_rejected(exc: Exception) -> AdmissionRejected:
        return AdmissionRejected(
            AdmissionRejectReason.STORAGE_UNAVAILABLE,
            "admission storage is unavailable or corrupt",
        )

    def _verify_grant_row(self, row: sqlite3.Row) -> SignedJobLease:
        self._assert_configured_signer_material()
        try:
            grant = parse_signed_job_lease(bytes(row["grant_bytes"]))
        except (ValueError, TypeError) as exc:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "stored lease is not canonical",
            ) from exc
        lease = grant.lease
        if (
            not _verify_signer_signature(
                self._lease_authority,
                lease.canonical_bytes(),
                grant.authority_signature,
                expected_fingerprint=self._lease_authority_fingerprint,
            )
            or lease.lease_authority_key_fingerprint != self._lease_authority_fingerprint
        ):
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "stored lease authority signature or key binding is invalid",
            )
        expected = (
            lease.lease_digest(),
            lease.nonce_digest(),
            lease.tenant_id,
            lease.collector_id,
            lease.audience,
            lease.job_id,
            lease.policy_id,
            lease.policy_revision,
            lease.policy_digest,
            lease.epoch,
            lease.sequence,
            lease.expires_at,
        )
        observed = tuple(
            row[name]
            for name in (
                "lease_digest",
                "nonce_digest",
                "tenant_id",
                "collector_id",
                "audience",
                "job_id",
                "policy_id",
                "policy_revision",
                "policy_digest",
                "epoch",
                "sequence",
                "expires_at",
            )
        )
        if observed != expected:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "stored lease columns do not match the authority-signed grant",
            )
        return grant

    def _lease_by_nonce(
        self,
        connection: sqlite3.Connection,
        nonce_digest: str,
    ) -> tuple[sqlite3.Row, SignedJobLease]:
        row = connection.execute(
            "SELECT * FROM job_leases WHERE nonce_digest = ?",
            (nonce_digest,),
        ).fetchone()
        if row is None:
            raise AdmissionRejected(
                AdmissionRejectReason.UNKNOWN_LEASE,
                "no issued lease matches the statement nonce",
            )
        return row, self._verify_grant_row(row)

    def _verify_attestation_bytes(self, payload: bytes) -> AttestationVerification:
        try:
            document = strict_json_loads(payload, limits=_DOCUMENT_LIMITS)
            if not isinstance(document, dict):
                raise ValueError("attestation root is not an object")
            result = AttestationVerification.model_validate(document, strict=True)
            if result.canonical_bytes() != payload or not result.verified:
                raise ValueError("attestation result is not canonical and verified")
        except Exception as exc:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "stored attestation verification is invalid",
            ) from exc
        return result

    def _verify_receipt_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> AdmissionReceipt:
        self._assert_configured_signer_material()
        try:
            receipt = _parse_receipt(bytes(row["receipt_bytes"]))
        except (StrictJSONError, ValueError, TypeError) as exc:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "stored receipt is not canonical",
            ) from exc
        body = receipt.body
        if not _verify_signer_signature(
            self._receipt_signer,
            body.canonical_bytes(),
            receipt.service_signature,
            expected_fingerprint=self._receipt_signer_fingerprint,
        ):
            raise AdmissionRejected(
                AdmissionRejectReason.INVALID_RECEIPT_SIGNATURE,
                "stored receipt service signature is invalid",
            )
        if receipt.receipt_digest() != row["receipt_digest"]:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "stored receipt digest does not match its bytes",
            )
        envelope_bytes = bytes(row["envelope_bytes"])
        snapshot_bytes = bytes(row["cab_snapshot_bytes"])
        policy_bytes = bytes(row["policy_bytes"])
        attestation_bytes = bytes(row["attestation_bytes"])
        scalar_pairs = (
            (body.receipt_sequence, row["receipt_sequence"]),
            (body.lease_digest, row["lease_digest"]),
            (body.tenant_id, row["tenant_id"]),
            (body.collector_id, row["collector_id"]),
            (body.epoch, row["epoch"]),
            (body.sequence, row["sequence"]),
            (body.envelope_digest, row["envelope_digest"]),
            (body.payload_digest, row["statement_digest"]),
            (body.cab_snapshot_digest, row["cab_snapshot_digest"]),
            (body.trust_policy_id, row["policy_id"]),
            (body.trust_policy_revision, row["policy_revision"]),
            (body.trust_policy_digest, row["policy_digest"]),
            (body.attestation_verification_digest, row["attestation_digest"]),
            (body.admission_request_fingerprint, row["request_fingerprint"]),
            (body.custody_object_id, row["custody_object_id"]),
            (body.custody_reference, row["custody_reference"]),
            (_digest(envelope_bytes), row["envelope_digest"]),
            (_digest(snapshot_bytes), row["cab_snapshot_digest"]),
            (_digest(policy_bytes), row["policy_digest"]),
            (_digest(attestation_bytes), row["attestation_digest"]),
        )
        if any(left != right for left, right in scalar_pairs):
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "stored admission columns do not match the signed receipt",
            )
        try:
            envelope = parse_dsse_envelope(envelope_bytes)
            statement = parse_collection_statement(envelope.payload_bytes())
            policy = parse_trust_policy(policy_bytes)
        except Exception as exc:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "stored envelope or trust policy is invalid",
            ) from exc
        attestation = self._verify_attestation_bytes(attestation_bytes)
        reverified_attestation = verify_dsse_attestation(
            envelope_bytes,
            policy=policy,
            expected_payload_type=COLLECTION_STATEMENT_MEDIA_TYPE,
            expected_payload=statement.canonical_bytes(),
            admission_time=_parse_timestamp(body.admitted_at),
        )
        grant_row = connection.execute(
            "SELECT * FROM job_leases WHERE lease_digest = ?",
            (row["lease_digest"],),
        ).fetchone()
        if grant_row is None:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "admission references a missing lease",
            )
        grant = self._verify_grant_row(grant_row)
        lease = grant.lease
        policy_version = connection.execute(
            """
            SELECT policy_digest FROM policy_versions
            WHERE policy_id = ? AND policy_revision = ?
            """,
            (body.trust_policy_id, body.trust_policy_revision),
        ).fetchone()
        if (
            policy_version is None
            or str(policy_version["policy_digest"]) != body.trust_policy_digest
        ):
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "stored receipt references an unknown or forked trust-policy revision",
            )
        policy_head = self._verify_policy_head(connection, body.trust_policy_id)
        if policy_head is None or body.trust_policy_revision > policy_head[0]:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "stored receipt is ahead of the durable trust-policy revision head",
            )
        admitted_at = _parse_timestamp(body.admitted_at)
        collected_at = _parse_timestamp(statement.collected_at)
        expected_custody_object_id = _custody_object_id(
            tenant_id=statement.tenant_id,
            job_id=statement.job_id,
            envelope_digest=body.envelope_digest,
            snapshot_digest=body.cab_snapshot_digest,
        )
        if (
            not statement.matches(lease)
            or statement.canonical_bytes() != envelope.payload_bytes()
            or body.lease_authority_key_fingerprint != self._lease_authority_fingerprint
            or body.lease_authority_key_fingerprint != lease.lease_authority_key_fingerprint
            or body.receipt_signer_key_fingerprint != self._receipt_signer_fingerprint
            or body.lease_authority_key_fingerprint == body.receipt_signer_key_fingerprint
            or grant_row["consumed_envelope_digest"] != body.envelope_digest
            or grant_row["consumed_receipt_digest"] != receipt.receipt_digest()
            or body.lease_digest != lease.lease_digest()
            or body.nonce_digest != statement.nonce_digest()
            or body.tenant_id != statement.tenant_id
            or body.collector_id != statement.collector_id
            or body.audience != statement.audience
            or body.job_id != statement.job_id
            or body.capability_digest != statement.capability_digest
            or body.epoch != statement.epoch
            or body.sequence != statement.sequence
            or body.previous_epoch != statement.previous_epoch
            or body.previous_epoch_final_sequence != statement.previous_epoch_final_sequence
            or body.previous_epoch_final_receipt_digest
            != statement.previous_epoch_final_receipt_digest
            or body.cab_id != statement.cab_id
            or body.manifest_digest != statement.manifest_digest
            or body.custody_object_id != expected_custody_object_id
            or body.payload_digest != _digest(statement.canonical_bytes())
            or body.trust_policy_id != statement.policy_id
            or body.trust_policy_revision != statement.policy_revision
            or body.trust_policy_digest != statement.policy_digest
            or body.trust_policy_id != attestation.policy_id
            or policy.policy_id != body.trust_policy_id
            or body.attestation_verifier_id != attestation.verifier_id
            or body.accepted_key_ids != attestation.accepted_key_ids
            or body.accepted_identities != attestation.accepted_identities
            or f"sha256:{attestation.raw_envelope_sha256}" != body.envelope_digest
            or f"sha256:{attestation.expected_payload_sha256}" != body.payload_digest
            or f"sha256:{attestation.trust_policy_sha256}" != body.trust_policy_digest
            or attestation.admission_time != body.admitted_at
            or reverified_attestation.canonical_bytes() != attestation_bytes
            or admitted_at < _parse_timestamp(lease.issued_at)
            or admitted_at >= _parse_timestamp(lease.expires_at)
            or collected_at < _parse_timestamp(lease.issued_at)
            or collected_at >= _parse_timestamp(lease.expires_at)
            or admitted_at < collected_at
        ):
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "stored admission bindings are incoherent",
            )
        fingerprint = _admission_request_fingerprint(
            statement_digest=body.payload_digest,
            envelope_digest=body.envelope_digest,
            snapshot_digest=body.cab_snapshot_digest,
            policy_digest=body.trust_policy_digest,
            policy_revision=body.trust_policy_revision,
            attestation_bytes=attestation_bytes,
            audience=body.audience,
            capability_digest=body.capability_digest,
            accepted_key_ids=body.accepted_key_ids,
            accepted_identities=body.accepted_identities,
            custody_object_id=body.custody_object_id,
            custody_reference=body.custody_reference,
            lease_authority_key_fingerprint=body.lease_authority_key_fingerprint,
            receipt_signer_key_fingerprint=body.receipt_signer_key_fingerprint,
        )
        if fingerprint != body.admission_request_fingerprint:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "stored admission request fingerprint is invalid",
            )
        return receipt

    def _receipt_body(
        self,
        candidate: _VerifiedAdmission,
        *,
        receipt_sequence: int,
        previous_receipt_digest: str | None,
    ) -> AdmissionReceiptBody:
        statement = candidate.statement
        return AdmissionReceiptBody(
            media_type=RECEIPT_MEDIA_TYPE,
            schema_version=ADMISSION_SCHEMA_VERSION,
            receipt_sequence=receipt_sequence,
            admitted_at=candidate.admitted_at,
            tenant_id=statement.tenant_id,
            collector_id=statement.collector_id,
            audience=statement.audience,
            job_id=statement.job_id,
            capability_digest=statement.capability_digest,
            epoch=statement.epoch,
            sequence=statement.sequence,
            previous_epoch=statement.previous_epoch,
            previous_epoch_final_sequence=statement.previous_epoch_final_sequence,
            previous_epoch_final_receipt_digest=(statement.previous_epoch_final_receipt_digest),
            lease_digest=statement.lease_digest,
            nonce_digest=statement.nonce_digest(),
            cab_id=statement.cab_id,
            manifest_digest=statement.manifest_digest,
            cab_snapshot_digest=candidate.snapshot.snapshot_digest,
            cab_snapshot_media_type=SNAPSHOT_MEDIA_TYPE,
            envelope_digest=candidate.envelope_digest,
            payload_digest=_digest(statement.canonical_bytes()),
            payload_type=COLLECTION_STATEMENT_MEDIA_TYPE,
            trust_policy_digest=candidate.policy_digest,
            trust_policy_id=statement.policy_id,
            trust_policy_revision=statement.policy_revision,
            trust_policy_schema_version=TRUST_POLICY_SCHEMA_VERSION,
            lease_authority_key_fingerprint=self._lease_authority_fingerprint,
            receipt_signer_key_fingerprint=self._receipt_signer_fingerprint,
            attestation_verifier_id=ATTESTATION_VERIFIER_ID,
            attestation_verification_digest=_digest(candidate.attestation_bytes),
            accepted_key_ids=candidate.attestation.accepted_key_ids,
            accepted_identities=candidate.attestation.accepted_identities,
            admission_request_fingerprint=candidate.request_fingerprint,
            previous_receipt_digest=previous_receipt_digest,
            custody_object_id=candidate.custody_object_id,
            custody_reference=candidate.custody_reference,
        )

    def _prepared_admission_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> _PreparedAdmission:
        """Re-establish every unsigned preparation binding from durable bytes."""

        try:
            parsed = _parse_canonical_model(
                bytes(row["receipt_body_bytes"]),
                AdmissionReceiptBody,
            )
            assert isinstance(parsed, AdmissionReceiptBody)
            body = parsed
            envelope_bytes = bytes(row["envelope_bytes"])
            snapshot_bytes = bytes(row["cab_snapshot_bytes"])
            policy_bytes = bytes(row["policy_bytes"])
            attestation_bytes = bytes(row["attestation_bytes"])
            envelope = parse_dsse_envelope(envelope_bytes)
            statement = parse_collection_statement(envelope.payload_bytes())
            policy = parse_trust_policy(policy_bytes)
            attestation = self._verify_attestation_bytes(attestation_bytes)
            snapshot = verify_cab_snapshot(
                snapshot_bytes,
                maximum=self._limits.max_cab_snapshot_bytes,
            )
        except Exception as exc:
            if isinstance(exc, AdmissionRejected):
                raise
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "stored admission preparation is not canonical and verified",
            ) from exc
        body_bytes = body.canonical_bytes()
        body_digest = _digest(body_bytes)
        lease_row = connection.execute(
            "SELECT * FROM job_leases WHERE lease_digest = ?",
            (body.lease_digest,),
        ).fetchone()
        if lease_row is None:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "admission preparation references a missing lease",
            )
        grant = self._verify_grant_row(lease_row)
        lease = grant.lease
        consumed = lease_row["consumed_envelope_digest"]
        consumed_receipt = lease_row["consumed_receipt_digest"]
        policy_version = connection.execute(
            """
            SELECT policy_digest FROM policy_versions
            WHERE policy_id = ? AND policy_revision = ?
            """,
            (body.trust_policy_id, body.trust_policy_revision),
        ).fetchone()
        reverified_attestation = verify_dsse_attestation(
            envelope_bytes,
            policy=policy,
            expected_payload_type=COLLECTION_STATEMENT_MEDIA_TYPE,
            expected_payload=statement.canonical_bytes(),
            admission_time=_parse_timestamp(body.admitted_at),
        )
        fingerprint = _admission_request_fingerprint(
            statement_digest=body.payload_digest,
            envelope_digest=body.envelope_digest,
            snapshot_digest=body.cab_snapshot_digest,
            policy_digest=body.trust_policy_digest,
            policy_revision=body.trust_policy_revision,
            attestation_bytes=attestation_bytes,
            audience=body.audience,
            capability_digest=body.capability_digest,
            accepted_key_ids=body.accepted_key_ids,
            accepted_identities=body.accepted_identities,
            custody_object_id=body.custody_object_id,
            custody_reference=body.custody_reference,
            lease_authority_key_fingerprint=body.lease_authority_key_fingerprint,
            receipt_signer_key_fingerprint=body.receipt_signer_key_fingerprint,
        )
        expected_object_id = _custody_object_id(
            tenant_id=statement.tenant_id,
            job_id=statement.job_id,
            envelope_digest=body.envelope_digest,
            snapshot_digest=body.cab_snapshot_digest,
        )
        admitted_at = _parse_timestamp(body.admitted_at)
        collected_at = _parse_timestamp(statement.collected_at)
        scalar_pairs = (
            (body_digest, row["receipt_body_digest"]),
            (body.lease_digest, row["lease_digest"]),
            (body.tenant_id, row["tenant_id"]),
            (body.collector_id, row["collector_id"]),
            (body.epoch, row["epoch"]),
            (body.sequence, row["sequence"]),
            (body.receipt_sequence, row["receipt_sequence"]),
            (body.envelope_digest, row["envelope_digest"]),
            (body.trust_policy_id, row["policy_id"]),
            (body.trust_policy_revision, row["policy_revision"]),
            (body.trust_policy_digest, row["policy_digest"]),
            (body.custody_object_id, row["custody_object_id"]),
            (body.custody_reference, row["custody_reference"]),
            (_digest(envelope_bytes), body.envelope_digest),
            (_digest(snapshot_bytes), body.cab_snapshot_digest),
            (_digest(policy_bytes), body.trust_policy_digest),
            (_digest(attestation_bytes), body.attestation_verification_digest),
        )
        if (
            any(left != right for left, right in scalar_pairs)
            or consumed is not None
            or consumed_receipt is not None
            or policy_version is None
            or str(policy_version["policy_digest"]) != body.trust_policy_digest
            or not statement.matches(lease)
            or statement.canonical_bytes() != envelope.payload_bytes()
            or body.lease_digest != lease.lease_digest()
            or body.nonce_digest != statement.nonce_digest()
            or body.tenant_id != statement.tenant_id
            or body.collector_id != statement.collector_id
            or body.audience != statement.audience
            or body.job_id != statement.job_id
            or body.capability_digest != statement.capability_digest
            or body.epoch != statement.epoch
            or body.sequence != statement.sequence
            or body.previous_epoch != statement.previous_epoch
            or body.previous_epoch_final_sequence != statement.previous_epoch_final_sequence
            or body.previous_epoch_final_receipt_digest
            != statement.previous_epoch_final_receipt_digest
            or body.cab_id != statement.cab_id
            or body.manifest_digest != statement.manifest_digest
            or body.payload_digest != _digest(statement.canonical_bytes())
            or body.trust_policy_id != statement.policy_id
            or body.trust_policy_revision != statement.policy_revision
            or body.trust_policy_digest != statement.policy_digest
            or policy.policy_id != body.trust_policy_id
            or snapshot.cab_id != body.cab_id
            or snapshot.manifest_digest != body.manifest_digest
            or body.custody_object_id != expected_object_id
            or body.lease_authority_key_fingerprint != self._lease_authority_fingerprint
            or body.lease_authority_key_fingerprint != lease.lease_authority_key_fingerprint
            or body.receipt_signer_key_fingerprint != self._receipt_signer_fingerprint
            or body.lease_authority_key_fingerprint == body.receipt_signer_key_fingerprint
            or body.attestation_verifier_id != attestation.verifier_id
            or body.accepted_key_ids != attestation.accepted_key_ids
            or body.accepted_identities != attestation.accepted_identities
            or f"sha256:{attestation.raw_envelope_sha256}" != body.envelope_digest
            or f"sha256:{attestation.expected_payload_sha256}" != body.payload_digest
            or f"sha256:{attestation.trust_policy_sha256}" != body.trust_policy_digest
            or attestation.admission_time != body.admitted_at
            or reverified_attestation.canonical_bytes() != attestation_bytes
            or fingerprint != body.admission_request_fingerprint
            or admitted_at < _parse_timestamp(lease.issued_at)
            or admitted_at >= _parse_timestamp(lease.expires_at)
            or collected_at < _parse_timestamp(lease.issued_at)
            or collected_at >= _parse_timestamp(lease.expires_at)
            or admitted_at < collected_at
        ):
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "stored admission preparation bindings are incoherent",
            )
        return _PreparedAdmission(
            receipt_body_digest=body_digest,
            body=body,
            envelope_bytes=envelope_bytes,
            cab_snapshot_bytes=snapshot_bytes,
            trust_policy_bytes=policy_bytes,
            attestation_bytes=attestation_bytes,
        )

    def _validate_complete_ledger(self, connection: sqlite3.Connection) -> None:
        """Verify every signed tenant/collector link after startup or outside writes.

        Normal appends need only verify the cached head and its immediate signed
        predecessor.  A different SQLite connection changes ``data_version``;
        at that boundary this bounded walk re-establishes closure from sequence
        one through every tenant head.  Count/min/max reject cheap gaps before
        any receipt parsing, while the signed walk defeats a gap hidden by a
        forged replacement row.
        """

        summaries = connection.execute(
            """
            SELECT tenant_id, count(*) AS receipt_count,
                   min(receipt_sequence) AS first_sequence,
                   max(receipt_sequence) AS last_sequence
            FROM admissions
            GROUP BY tenant_id
            ORDER BY tenant_id
            """
        ).fetchall()
        tenant_heads = {
            str(row["tenant_id"]): (
                int(row["last_receipt_sequence"]),
                str(row["last_receipt_digest"]),
            )
            for row in connection.execute(
                """
                SELECT tenant_id, last_receipt_sequence, last_receipt_digest
                FROM tenant_heads
                """
            ).fetchall()
        }
        summary_tenants = {str(row["tenant_id"]) for row in summaries}
        if summary_tenants != set(tenant_heads):
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "tenant receipt heads do not exactly cover durable admissions",
            )

        collector_heads = {
            (str(row["tenant_id"]), str(row["collector_id"])): (
                int(row["current_epoch"]),
                int(row["last_sequence"]),
                str(row["last_receipt_digest"]),
            )
            for row in connection.execute(
                """
                SELECT tenant_id, collector_id, current_epoch,
                       last_sequence, last_receipt_digest
                FROM collector_heads
                """
            ).fetchall()
        }
        expected_collector_heads: dict[tuple[str, str], tuple[int, int, str]] = {}
        validated_tenant_heads: dict[str, tuple[int, str]] = {}
        durable_admission_times: list[str] = []

        for summary in summaries:
            tenant_id = str(summary["tenant_id"])
            receipt_count = int(summary["receipt_count"])
            first_sequence = int(summary["first_sequence"])
            last_sequence = int(summary["last_sequence"])
            if (
                receipt_count < 1
                or receipt_count > self._limits.max_admissions_per_tenant
                or first_sequence != 1
                or last_sequence != receipt_count
            ):
                raise AdmissionRejected(
                    AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                    "tenant receipt history is not one bounded contiguous sequence",
                )

            previous_digest: str | None = None
            collector_state: dict[str, tuple[int, int, str]] = {}
            pending_seen = False
            rows = connection.execute(
                """
                SELECT * FROM admissions
                WHERE tenant_id = ?
                ORDER BY receipt_sequence
                """,
                (tenant_id,),
            )
            for expected_sequence, row in enumerate(rows, start=1):
                receipt = self._verify_receipt_row(connection, row)
                body = receipt.body
                durable_admission_times.append(body.admitted_at)
                receipt_digest = receipt.receipt_digest()
                if (
                    body.tenant_id != tenant_id
                    or body.receipt_sequence != expected_sequence
                    or body.previous_receipt_digest != previous_digest
                ):
                    raise AdmissionRejected(
                        AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                        "tenant receipt chain is not closed over signed predecessor digests",
                    )
                if pending_seen:
                    raise AdmissionRejected(
                        AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                        "a tenant receipt exists beyond an unconfirmed custody predecessor",
                    )

                prior_collector = collector_state.get(body.collector_id)
                if prior_collector is None:
                    if body.epoch != 1 or body.sequence != 1:
                        raise AdmissionRejected(
                            AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                            "collector history does not begin at epoch 1 sequence 1",
                        )
                elif body.epoch == prior_collector[0]:
                    if body.sequence != prior_collector[1] + 1:
                        raise AdmissionRejected(
                            AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                            "collector history contains a sequence gap",
                        )
                elif body.epoch == prior_collector[0] + 1:
                    transition = (
                        body.previous_epoch,
                        body.previous_epoch_final_sequence,
                        body.previous_epoch_final_receipt_digest,
                    )
                    if body.sequence != 1 or transition != prior_collector:
                        raise AdmissionRejected(
                            AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                            "collector epoch transition does not bind its signed predecessor",
                        )
                else:
                    raise AdmissionRejected(
                        AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                        "collector history skips or rolls back an epoch",
                    )

                collector_state[body.collector_id] = (
                    body.epoch,
                    body.sequence,
                    receipt_digest,
                )
                previous_digest = receipt_digest
                pending_seen = self._stored_ack(row) is None

            if previous_digest is None:
                raise AdmissionRejected(
                    AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                    "tenant receipt summary names an empty history",
                )
            expected_head = (last_sequence, previous_digest)
            if tenant_heads[tenant_id] != expected_head:
                raise AdmissionRejected(
                    AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                    "tenant head does not match the complete signed receipt chain",
                )
            validated_tenant_heads[tenant_id] = expected_head
            expected_collector_heads.update(
                {
                    (tenant_id, collector_id): state
                    for collector_id, state in collector_state.items()
                }
            )

        if collector_heads != expected_collector_heads:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "collector heads do not match complete signed collector histories",
            )
        self._validated_tenant_heads = validated_tenant_heads
        prepared_times: list[str] = []
        for row in connection.execute(
            "SELECT * FROM admission_preparations ORDER BY tenant_id"
        ).fetchall():
            prepared = self._prepared_admission_from_row(connection, row)
            body = prepared.body
            tenant_head = self._verify_tenant_head(connection, body.tenant_id)
            expected_sequence = 1 if tenant_head is None else tenant_head[0] + 1
            expected_previous = None if tenant_head is None else tenant_head[1]
            collector_head = self._verify_collector_head(
                connection,
                body.tenant_id,
                body.collector_id,
            )
            if collector_head is None:
                collector_valid = body.epoch == 1 and body.sequence == 1
            elif body.epoch == collector_head[0]:
                collector_valid = body.sequence == collector_head[1] + 1
            elif body.epoch == collector_head[0] + 1:
                collector_valid = (
                    body.sequence == 1
                    and (
                        body.previous_epoch,
                        body.previous_epoch_final_sequence,
                        body.previous_epoch_final_receipt_digest,
                    )
                    == collector_head
                )
            else:
                collector_valid = False
            pending_predecessor = connection.execute(
                """
                SELECT 1 FROM admissions
                WHERE tenant_id = ? AND custody_state = 'pending'
                LIMIT 1
                """,
                (body.tenant_id,),
            ).fetchone()
            policy_head = self._verify_policy_head(
                connection,
                body.trust_policy_id,
            )
            if (
                body.receipt_sequence != expected_sequence
                or body.previous_receipt_digest != expected_previous
                or not collector_valid
                or pending_predecessor is not None
                or policy_head is None
                or body.trust_policy_revision > policy_head[0]
            ):
                raise AdmissionRejected(
                    AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                    "admission preparation no longer reserves the next valid chain position",
                )
            prepared_times.append(body.admitted_at)
        for row in connection.execute(
            "SELECT * FROM custody_ack_preparations ORDER BY receipt_digest"
        ).fetchall():
            self._prepared_acknowledgement_from_row(connection, row)
        meta = connection.execute(
            "SELECT last_admitted_at FROM admission_meta WHERE singleton = 1"
        ).fetchone()
        expected_floor = max(
            (*durable_admission_times, *prepared_times),
            default=None,
        )
        if meta is None or meta["last_admitted_at"] != expected_floor:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "durable admission clock floor does not match receipts and reservations",
            )

    def _verify_tenant_head(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
    ) -> tuple[int, str] | None:
        head = connection.execute(
            "SELECT * FROM tenant_heads WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        latest = connection.execute(
            """
            SELECT * FROM admissions
            WHERE tenant_id = ?
            ORDER BY receipt_sequence DESC LIMIT 1
            """,
            (tenant_id,),
        ).fetchone()
        if head is None and latest is None:
            if tenant_id in self._validated_tenant_heads:
                raise AdmissionRejected(
                    AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                    "empty tenant receipt history disagrees with its validated state",
                )
            return None
        if head is None or latest is None:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "tenant receipt head is missing or orphaned",
            )
        receipt = self._verify_receipt_row(connection, latest)
        if (
            head["last_receipt_sequence"] != receipt.body.receipt_sequence
            or head["last_receipt_digest"] != receipt.receipt_digest()
        ):
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "tenant receipt head does not match the latest signed receipt",
            )
        expected_head = (receipt.body.receipt_sequence, receipt.receipt_digest())
        if self._validated_tenant_heads.get(tenant_id) != expected_head:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "tenant receipt history is not closed through its validated head",
            )
        if receipt.body.receipt_sequence == 1:
            if receipt.body.previous_receipt_digest is not None:
                raise AdmissionRejected(
                    AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                    "first tenant receipt has a predecessor",
                )
        else:
            predecessor = connection.execute(
                """
                SELECT * FROM admissions
                WHERE tenant_id = ? AND receipt_sequence = ?
                """,
                (tenant_id, receipt.body.receipt_sequence - 1),
            ).fetchone()
            if predecessor is None:
                raise AdmissionRejected(
                    AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                    "latest tenant receipt predecessor is missing",
                )
            previous_receipt = self._verify_receipt_row(connection, predecessor)
            if receipt.body.previous_receipt_digest != previous_receipt.receipt_digest():
                raise AdmissionRejected(
                    AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                    "latest tenant receipt predecessor binding is invalid",
                )
        return expected_head

    def _verify_collector_head(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        collector_id: str,
    ) -> tuple[int, int, str] | None:
        head = connection.execute(
            """
            SELECT * FROM collector_heads
            WHERE tenant_id = ? AND collector_id = ?
            """,
            (tenant_id, collector_id),
        ).fetchone()
        latest = connection.execute(
            """
            SELECT * FROM admissions
            WHERE tenant_id = ? AND collector_id = ?
            ORDER BY receipt_sequence DESC LIMIT 1
            """,
            (tenant_id, collector_id),
        ).fetchone()
        if head is None and latest is None:
            return None
        if head is None or latest is None:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "collector sequence head is missing or orphaned",
            )
        receipt = self._verify_receipt_row(connection, latest)
        expected = (
            receipt.body.epoch,
            receipt.body.sequence,
            receipt.receipt_digest(),
        )
        observed = (
            head["current_epoch"],
            head["last_sequence"],
            head["last_receipt_digest"],
        )
        if expected != observed:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "collector head does not match the latest signed receipt",
            )
        return expected

    def _verify_policy_head(
        self,
        connection: sqlite3.Connection,
        policy_id: str,
    ) -> tuple[int, str] | None:
        head = connection.execute(
            "SELECT * FROM policy_heads WHERE policy_id = ?",
            (policy_id,),
        ).fetchone()
        latest = connection.execute(
            """
            SELECT policy_revision, policy_digest
            FROM policy_versions
            WHERE policy_id = ?
            ORDER BY policy_revision DESC
            LIMIT 1
            """,
            (policy_id,),
        ).fetchone()
        latest_admission = connection.execute(
            """
            SELECT policy_revision, policy_digest FROM (
                SELECT policy_revision, policy_digest
                FROM admissions WHERE policy_id = ?
                UNION ALL
                SELECT policy_revision, policy_digest
                FROM admission_preparations WHERE policy_id = ?
            )
            ORDER BY policy_revision DESC
            LIMIT 1
            """,
            (policy_id, policy_id),
        ).fetchone()
        if head is None and latest is None and latest_admission is None:
            return None
        if head is None or latest is None or latest_admission is None:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "trust-policy revision head is missing or orphaned",
            )
        expected = (int(latest["policy_revision"]), str(latest["policy_digest"]))
        admitted = (
            int(latest_admission["policy_revision"]),
            str(latest_admission["policy_digest"]),
        )
        observed = (
            int(head["current_revision"]),
            str(head["current_policy_digest"]),
        )
        if observed != expected or admitted != expected:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "trust-policy head does not match admitted or reserved revision history",
            )
        return expected

    def _advance_policy_head(
        self,
        connection: sqlite3.Connection,
        *,
        policy_id: str,
        policy_revision: int,
        policy_digest: str,
    ) -> None:
        head = self._verify_policy_head(connection, policy_id)
        if head is not None:
            if policy_revision < head[0]:
                raise AdmissionRejected(
                    AdmissionRejectReason.POLICY_ROLLBACK,
                    "signed trust-policy revision is older than the durable high-water mark",
                )
            if policy_revision == head[0]:
                if policy_digest != head[1]:
                    raise AdmissionRejected(
                        AdmissionRejectReason.POLICY_FORK,
                        "one trust-policy revision cannot identify two byte snapshots",
                    )
                return
        try:
            connection.execute(
                """
                INSERT INTO policy_versions (
                    policy_id, policy_revision, policy_digest
                ) VALUES (?, ?, ?)
                """,
                (policy_id, policy_revision, policy_digest),
            )
        except sqlite3.IntegrityError as exc:
            raise AdmissionRejected(
                AdmissionRejectReason.POLICY_FORK,
                "trust-policy revision conflicts with immutable ledger history",
            ) from exc
        connection.execute(
            """
            INSERT INTO policy_heads (
                policy_id, current_revision, current_policy_digest
            ) VALUES (?, ?, ?)
            ON CONFLICT (policy_id) DO UPDATE SET
                current_revision = excluded.current_revision,
                current_policy_digest = excluded.current_policy_digest
            """,
            (policy_id, policy_revision, policy_digest),
        )

    def _verify_receipt_chain_neighborhood(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        receipt: AdmissionReceipt,
    ) -> None:
        sequence = receipt.body.receipt_sequence
        tenant_id = receipt.body.tenant_id
        predecessor = (
            None
            if sequence == 1
            else connection.execute(
                """
                SELECT * FROM admissions
                WHERE tenant_id = ? AND receipt_sequence = ?
                """,
                (tenant_id, sequence - 1),
            ).fetchone()
        )
        if sequence == 1:
            if receipt.body.previous_receipt_digest is not None:
                raise AdmissionRejected(
                    AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                    "first receipt has a predecessor",
                )
        elif predecessor is None:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "receipt predecessor is missing",
            )
        else:
            prior = self._verify_receipt_row(connection, predecessor)
            if receipt.body.previous_receipt_digest != prior.receipt_digest():
                raise AdmissionRejected(
                    AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                    "receipt predecessor digest is invalid",
                )
        successor = connection.execute(
            """
            SELECT * FROM admissions
            WHERE tenant_id = ? AND receipt_sequence = ?
            """,
            (tenant_id, sequence + 1),
        ).fetchone()
        if successor is not None:
            following = self._verify_receipt_row(connection, successor)
            if following.body.previous_receipt_digest != receipt.receipt_digest():
                raise AdmissionRejected(
                    AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                    "receipt successor digest is invalid",
                )
        self._verify_tenant_head(connection, tenant_id)
        self._verify_collector_head(connection, tenant_id, receipt.body.collector_id)

    def _clock_floor(
        self,
        connection: sqlite3.Connection,
        current_time: str,
    ) -> str | None:
        row = connection.execute(
            "SELECT last_admitted_at FROM admission_meta WHERE singleton = 1"
        ).fetchone()
        if row is None:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "admission metadata is missing",
            )
        floor = row["last_admitted_at"]
        if floor is not None and _parse_timestamp(current_time) < _parse_timestamp(str(floor)):
            raise AdmissionRejected(
                AdmissionRejectReason.CLOCK_ROLLBACK,
                "service clock is earlier than the durable admission high-water mark",
            )
        return None if floor is None else str(floor)

    def _trusted_current_time(self) -> str:
        try:
            return _canonical_timestamp(self._clock.now())
        except (ValueError, TypeError) as exc:
            raise AdmissionRejected(
                AdmissionRejectReason.CLOCK_ROLLBACK,
                "service clock did not return a valid trusted instant",
            ) from exc

    def register_lease(self, grant_bytes: bytes) -> SignedJobLease:
        self._assert_configured_signer_material()
        try:
            grant = parse_signed_job_lease(grant_bytes)
        except ValueError as exc:
            raise AdmissionRejected(
                AdmissionRejectReason.MALFORMED_LEASE,
                "signed lease is not the canonical supported schema",
            ) from exc
        lease = grant.lease
        if (
            not _verify_signer_signature(
                self._lease_authority,
                lease.canonical_bytes(),
                grant.authority_signature,
                expected_fingerprint=self._lease_authority_fingerprint,
            )
            or lease.lease_authority_key_fingerprint != self._lease_authority_fingerprint
        ):
            raise AdmissionRejected(
                AdmissionRejectReason.INVALID_LEASE_SIGNATURE,
                "signed lease did not bind and verify under the configured authority key",
            )
        try:
            with self._transaction() as connection:
                exact = connection.execute(
                    "SELECT * FROM job_leases WHERE lease_digest = ?",
                    (lease.lease_digest(),),
                ).fetchone()
                if exact is not None:
                    existing = self._verify_grant_row(exact)
                    if existing.canonical_bytes() == grant_bytes:
                        connection.rollback()
                        return existing
                conflicts = (
                    (
                        AdmissionRejectReason.DUPLICATE_NONCE,
                        connection.execute(
                            "SELECT 1 FROM job_leases WHERE nonce_digest = ?",
                            (lease.nonce_digest(),),
                        ).fetchone(),
                    ),
                    (
                        AdmissionRejectReason.DUPLICATE_JOB,
                        connection.execute(
                            """
                            SELECT 1 FROM job_leases
                            WHERE tenant_id = ? AND job_id = ?
                            """,
                            (lease.tenant_id, lease.job_id),
                        ).fetchone(),
                    ),
                    (
                        AdmissionRejectReason.DUPLICATE_SEQUENCE,
                        connection.execute(
                            """
                            SELECT 1 FROM job_leases
                            WHERE tenant_id = ? AND collector_id = ?
                              AND epoch = ? AND sequence = ?
                            """,
                            (
                                lease.tenant_id,
                                lease.collector_id,
                                lease.epoch,
                                lease.sequence,
                            ),
                        ).fetchone(),
                    ),
                )
                for reason, conflict in conflicts:
                    if conflict is not None:
                        raise AdmissionRejected(reason, "lease coordinate already exists")
                lease_count = int(
                    connection.execute(
                        "SELECT count(*) FROM job_leases WHERE tenant_id = ?",
                        (lease.tenant_id,),
                    ).fetchone()[0]
                )
                if lease_count >= self._limits.max_registered_leases_per_tenant:
                    raise AdmissionRejected(
                        AdmissionRejectReason.QUOTA_EXCEEDED,
                        "tenant registered-lease quota is exhausted",
                    )
                if lease.epoch > 1 and lease.sequence == 1:
                    collector_head = self._verify_collector_head(
                        connection,
                        lease.tenant_id,
                        lease.collector_id,
                    )
                    expected = (
                        lease.previous_epoch,
                        lease.previous_epoch_final_sequence,
                        lease.previous_epoch_final_receipt_digest,
                    )
                    if collector_head is None or expected != collector_head:
                        raise AdmissionRejected(
                            AdmissionRejectReason.EPOCH_MISMATCH,
                            "new epoch lease does not bind the durable collector head",
                        )
                self._check_database_capacity(
                    connection,
                    incoming_bytes=len(grant_bytes) + 4096,
                )
                connection.execute(
                    """
                    INSERT INTO job_leases (
                        lease_digest, nonce_digest, tenant_id, collector_id,
                        audience, job_id, policy_id, policy_revision, policy_digest,
                        epoch, sequence, expires_at, grant_bytes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        lease.lease_digest(),
                        lease.nonce_digest(),
                        lease.tenant_id,
                        lease.collector_id,
                        lease.audience,
                        lease.job_id,
                        lease.policy_id,
                        lease.policy_revision,
                        lease.policy_digest,
                        lease.epoch,
                        lease.sequence,
                        lease.expires_at,
                        grant_bytes,
                    ),
                )
                self._check_database_quota_after_write(connection)
                connection.commit()
        except AdmissionRejected:
            raise
        except (sqlite3.Error, OSError, RuntimeError) as exc:
            raise self._storage_rejected(exc) from exc
        return grant

    def retry_admitted_at(
        self,
        *,
        statement: CollectionStatement,
        envelope_digest: str,
    ) -> str | None:
        try:
            with self._transaction() as connection:
                lease_row, grant = self._lease_by_nonce(
                    connection,
                    statement.nonce_digest(),
                )
                if not statement.matches(grant.lease):
                    raise AdmissionRejected(
                        AdmissionRejectReason.LEASE_MISMATCH,
                        "signed statement does not exactly match its issued lease",
                    )
                consumed = lease_row["consumed_envelope_digest"]
                consumed_receipt = lease_row["consumed_receipt_digest"]
                if (consumed is None) != (consumed_receipt is None):
                    raise AdmissionRejected(
                        AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                        "stored lease consumption markers are incomplete",
                    )
                if consumed is None:
                    prepared_row = connection.execute(
                        "SELECT * FROM admission_preparations WHERE lease_digest = ?",
                        (grant.lease.lease_digest(),),
                    ).fetchone()
                    if prepared_row is not None:
                        prepared = self._prepared_admission_from_row(
                            connection,
                            prepared_row,
                        )
                        if prepared.body.envelope_digest != envelope_digest:
                            raise AdmissionRejected(
                                AdmissionRejectReason.REPLAY_CONFLICT,
                                "one-time lease is reserved by a different envelope",
                            )
                        self._clock_floor(
                            connection,
                            self._trusted_current_time(),
                        )
                        connection.rollback()
                        return prepared.body.admitted_at
                    connection.rollback()
                    return None
                if consumed != envelope_digest:
                    raise AdmissionRejected(
                        AdmissionRejectReason.REPLAY_CONFLICT,
                        "one-time lease was consumed by a different envelope",
                    )
                self._clock_floor(connection, self._trusted_current_time())
                row = connection.execute(
                    "SELECT * FROM admissions WHERE lease_digest = ?",
                    (grant.lease.lease_digest(),),
                ).fetchone()
                if row is None:
                    raise AdmissionRejected(
                        AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                        "consumed lease has no admission record",
                    )
                receipt = self._verify_receipt_row(connection, row)
                self._verify_receipt_chain_neighborhood(connection, row, receipt)
                connection.rollback()
                return receipt.body.admitted_at
        except AdmissionRejected:
            raise
        except (sqlite3.Error, OSError, RuntimeError) as exc:
            raise self._storage_rejected(exc) from exc

    def _check_quota(
        self,
        connection: sqlite3.Connection,
        *,
        tenant_id: str,
        incoming_bytes: int,
    ) -> None:
        tenant_count = connection.execute(
            """
            SELECT (
                (SELECT count(*) FROM admissions WHERE tenant_id = ?)
                +
                (SELECT count(*) FROM admission_preparations WHERE tenant_id = ?)
            )
            """,
            (tenant_id, tenant_id),
        ).fetchone()[0]
        if int(tenant_count) >= self._limits.max_admissions_per_tenant:
            raise AdmissionRejected(
                AdmissionRejectReason.QUOTA_EXCEEDED,
                "tenant admission quota is exhausted",
            )
        self._check_database_capacity(
            connection,
            incoming_bytes=incoming_bytes,
        )

    def _check_database_capacity(
        self,
        connection: sqlite3.Connection,
        *,
        incoming_bytes: int,
    ) -> None:
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        try:
            wal_stat = os.stat(
                f"{self._path.name}-wal",
                dir_fd=self._parent_fd,
                follow_symlinks=False,
            )
            self._validate_private_file(wal_stat)
            wal_size = wal_stat.st_size
        except FileNotFoundError:
            wal_size = 0
        if page_count * page_size + wal_size + incoming_bytes > self._limits.max_database_bytes:
            raise AdmissionRejected(
                AdmissionRejectReason.QUOTA_EXCEEDED,
                "admission database byte quota would be exceeded",
            )

    def _check_database_quota_after_write(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        """Reject the still-rollbackable transaction if its logical DB is too large."""

        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        if page_count * page_size > self._limits.max_database_bytes:
            raise AdmissionRejected(
                AdmissionRejectReason.QUOTA_EXCEEDED,
                "admission database byte quota was exceeded by the transaction",
            )

    def append(
        self,
        *,
        statement: CollectionStatement,
        envelope_digest: str,
        original_admitted_at: str | None,
        candidate_factory: Callable[[str], _VerifiedAdmission],
    ) -> _StoredAdmission:
        """Reserve, sign without a DB lock, then compare-and-finalize."""

        statement = CollectionStatement.model_validate(
            statement.model_dump(mode="json"),
            strict=True,
        )
        prepared_or_stored = self._prepare_admission(
            statement=statement,
            envelope_digest=envelope_digest,
            original_admitted_at=original_admitted_at,
            candidate_factory=candidate_factory,
        )
        if isinstance(prepared_or_stored, _StoredAdmission):
            return prepared_or_stored
        return self._complete_prepared_admission(prepared_or_stored)

    def _complete_prepared_admission(
        self,
        prepared: _PreparedAdmission,
    ) -> _StoredAdmission:
        self._fault_injector(FaultPoint.AFTER_PREPARE_BEFORE_RECEIPT_SIGN)
        receipt = self._sign_prepared_admission(prepared)
        self._fault_injector(FaultPoint.AFTER_RECEIPT_SIGN_BEFORE_FINALIZE)
        return self._finalize_admission(prepared, receipt)

    def _prepare_admission(
        self,
        *,
        statement: CollectionStatement,
        envelope_digest: str,
        original_admitted_at: str | None,
        candidate_factory: Callable[[str], _VerifiedAdmission],
    ) -> _PreparedAdmission | _StoredAdmission:
        try:
            with self._transaction() as connection:
                lease_row, grant = self._lease_by_nonce(
                    connection,
                    statement.nonce_digest(),
                )
                lease = grant.lease
                if not statement.matches(lease):
                    raise AdmissionRejected(
                        AdmissionRejectReason.LEASE_MISMATCH,
                        "signed statement does not exactly match its issued lease",
                    )
                consumed = lease_row["consumed_envelope_digest"]
                consumed_receipt = lease_row["consumed_receipt_digest"]
                if (consumed is None) != (consumed_receipt is None):
                    raise AdmissionRejected(
                        AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                        "stored lease consumption markers are incomplete",
                    )
                if consumed is not None:
                    if consumed != envelope_digest:
                        raise AdmissionRejected(
                            AdmissionRejectReason.REPLAY_CONFLICT,
                            "one-time lease was consumed by a different envelope",
                        )
                    row = connection.execute(
                        "SELECT * FROM admissions WHERE lease_digest = ?",
                        (lease.lease_digest(),),
                    ).fetchone()
                    if row is None:
                        raise AdmissionRejected(
                            AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                            "consumed lease has no admission record",
                        )
                    receipt = self._verify_receipt_row(connection, row)
                    self._verify_receipt_chain_neighborhood(connection, row, receipt)
                    if original_admitted_at is None:
                        self._clock_floor(
                            connection,
                            self._trusted_current_time(),
                        )
                    elif original_admitted_at != receipt.body.admitted_at:
                        raise AdmissionRejected(
                            AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                            "retry probe and durable receipt disagree on admission time",
                        )
                    candidate = candidate_factory(receipt.body.admitted_at)
                    if (
                        candidate.statement != statement
                        or candidate.envelope_digest != envelope_digest
                    ):
                        raise AdmissionRejected(
                            AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                            "verified retry candidate changed its immutable request identity",
                        )
                    if row["request_fingerprint"] != candidate.request_fingerprint:
                        raise AdmissionRejected(
                            AdmissionRejectReason.RETRY_MISMATCH,
                            "retry inputs differ from the original admission request",
                        )
                    stored = _StoredAdmission(
                        disposition=AdmissionDisposition.EXACT_RETRY,
                        receipt=receipt,
                        envelope_bytes=bytes(row["envelope_bytes"]),
                        cab_snapshot_bytes=bytes(row["cab_snapshot_bytes"]),
                        trust_policy_bytes=bytes(row["policy_bytes"]),
                        custody_reference=str(row["custody_reference"]),
                        custody_acknowledgement=self._stored_ack(row),
                    )
                    connection.rollback()
                    return stored

                prepared_row = connection.execute(
                    "SELECT * FROM admission_preparations WHERE lease_digest = ?",
                    (lease.lease_digest(),),
                ).fetchone()
                if prepared_row is not None:
                    prepared = self._prepared_admission_from_row(
                        connection,
                        prepared_row,
                    )
                    if prepared.body.envelope_digest != envelope_digest:
                        raise AdmissionRejected(
                            AdmissionRejectReason.REPLAY_CONFLICT,
                            "one-time lease is reserved by a different envelope",
                        )
                    if original_admitted_at is None:
                        self._clock_floor(
                            connection,
                            self._trusted_current_time(),
                        )
                    elif original_admitted_at != prepared.body.admitted_at:
                        raise AdmissionRejected(
                            AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                            "retry probe and durable preparation disagree on admission time",
                        )
                    candidate = candidate_factory(prepared.body.admitted_at)
                    expected_body = self._receipt_body(
                        candidate,
                        receipt_sequence=prepared.body.receipt_sequence,
                        previous_receipt_digest=(prepared.body.previous_receipt_digest),
                    )
                    if (
                        candidate.statement != statement
                        or candidate.envelope_digest != envelope_digest
                        or expected_body != prepared.body
                        or candidate.envelope_bytes != prepared.envelope_bytes
                        or candidate.snapshot.snapshot_bytes != prepared.cab_snapshot_bytes
                        or candidate.policy_bytes != prepared.trust_policy_bytes
                        or candidate.attestation_bytes != prepared.attestation_bytes
                    ):
                        raise AdmissionRejected(
                            AdmissionRejectReason.RETRY_MISMATCH,
                            "retry inputs differ from the durable signing preparation",
                        )
                    connection.rollback()
                    return prepared

                tenant_preparation = connection.execute(
                    """
                    SELECT lease_digest FROM admission_preparations
                    WHERE tenant_id = ?
                    """,
                    (statement.tenant_id,),
                ).fetchone()
                if tenant_preparation is not None:
                    raise AdmissionRejected(
                        AdmissionRejectReason.CUSTODY_UNAVAILABLE,
                        "tenant has an earlier receipt awaiting signature; retry it first",
                    )
                current_time = self._trusted_current_time()
                self._clock_floor(connection, current_time)
                candidate = candidate_factory(current_time)
                if candidate.statement != statement or candidate.envelope_digest != envelope_digest:
                    raise AdmissionRejected(
                        AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                        "verified admission candidate changed its immutable request identity",
                    )
                if candidate.admitted_at != candidate.current_time:
                    raise AdmissionRejected(
                        AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                        "new admissions must use the service clock instant",
                    )
                if (
                    candidate.policy_digest != statement.policy_digest
                    or candidate.policy_digest != lease.policy_digest
                ):
                    raise AdmissionRejected(
                        AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                        "verified policy bytes do not match the signed policy digest",
                    )
                admitted_at = _parse_timestamp(candidate.admitted_at)
                if admitted_at >= _parse_timestamp(lease.expires_at):
                    raise AdmissionRejected(
                        AdmissionRejectReason.LEASE_EXPIRED,
                        "lease expired before trusted admission time",
                    )
                if admitted_at < _parse_timestamp(lease.issued_at):
                    raise AdmissionRejected(
                        AdmissionRejectReason.LEASE_MISMATCH,
                        "trusted admission time predates lease issuance",
                    )
                collected_at = _parse_timestamp(statement.collected_at)
                if (
                    collected_at < _parse_timestamp(lease.issued_at)
                    or collected_at >= _parse_timestamp(lease.expires_at)
                    or admitted_at < collected_at
                ):
                    raise AdmissionRejected(
                        AdmissionRejectReason.LEASE_MISMATCH,
                        "collection time is outside the trusted lease/admission window",
                    )
                collector_head = self._verify_collector_head(
                    connection,
                    statement.tenant_id,
                    statement.collector_id,
                )
                if collector_head is None:
                    if statement.epoch != 1 or statement.sequence != 1:
                        raise AdmissionRejected(
                            AdmissionRejectReason.EPOCH_MISMATCH,
                            "the first collector admission must be epoch 1 sequence 1",
                        )
                elif statement.epoch == collector_head[0]:
                    if statement.sequence != collector_head[1] + 1:
                        raise AdmissionRejected(
                            AdmissionRejectReason.OUT_OF_SEQUENCE,
                            f"expected collector sequence {collector_head[1] + 1}",
                        )
                elif statement.epoch == collector_head[0] + 1:
                    transition = (
                        statement.previous_epoch,
                        statement.previous_epoch_final_sequence,
                        statement.previous_epoch_final_receipt_digest,
                    )
                    if statement.sequence != 1 or transition != collector_head:
                        raise AdmissionRejected(
                            AdmissionRejectReason.EPOCH_MISMATCH,
                            "new epoch does not bind the preceding collector head",
                        )
                else:
                    raise AdmissionRejected(
                        AdmissionRejectReason.EPOCH_MISMATCH,
                        "collector epoch is stale or skips a durable epoch",
                    )
                tenant_head = self._verify_tenant_head(
                    connection,
                    statement.tenant_id,
                )
                pending_predecessor = connection.execute(
                    """
                    SELECT receipt_sequence FROM admissions
                    WHERE tenant_id = ? AND custody_state = 'pending'
                    ORDER BY receipt_sequence LIMIT 1
                    """,
                    (statement.tenant_id,),
                ).fetchone()
                if pending_predecessor is not None:
                    raise AdmissionRejected(
                        AdmissionRejectReason.CUSTODY_UNAVAILABLE,
                        "tenant has an earlier receipt awaiting durable custody; "
                        "reconcile it before admitting a successor",
                    )
                duplicate_envelope = connection.execute(
                    """
                    SELECT 1 FROM admissions WHERE envelope_digest = ?
                    UNION ALL
                    SELECT 1 FROM admission_preparations WHERE envelope_digest = ?
                    LIMIT 1
                    """,
                    (candidate.envelope_digest, candidate.envelope_digest),
                ).fetchone()
                if duplicate_envelope is not None:
                    raise AdmissionRejected(
                        AdmissionRejectReason.REPLAY_CONFLICT,
                        "envelope was already admitted or reserved under another lease",
                    )
                self._advance_policy_head(
                    connection,
                    policy_id=statement.policy_id,
                    policy_revision=statement.policy_revision,
                    policy_digest=candidate.policy_digest,
                )
                receipt_sequence = 1 if tenant_head is None else tenant_head[0] + 1
                previous_digest = None if tenant_head is None else tenant_head[1]
                body = self._receipt_body(
                    candidate,
                    receipt_sequence=receipt_sequence,
                    previous_receipt_digest=previous_digest,
                )
                body_bytes = body.canonical_bytes()
                prepared = _PreparedAdmission(
                    receipt_body_digest=_digest(body_bytes),
                    body=body,
                    envelope_bytes=candidate.envelope_bytes,
                    cab_snapshot_bytes=candidate.snapshot.snapshot_bytes,
                    trust_policy_bytes=candidate.policy_bytes,
                    attestation_bytes=candidate.attestation_bytes,
                )
                incoming_bytes = (
                    len(body_bytes)
                    + len(prepared.envelope_bytes)
                    + len(prepared.cab_snapshot_bytes)
                    + len(prepared.trust_policy_bytes)
                    + len(prepared.attestation_bytes)
                    + 16 * 1024
                )
                self._check_quota(
                    connection,
                    tenant_id=statement.tenant_id,
                    incoming_bytes=incoming_bytes,
                )
                connection.execute(
                    """
                    INSERT INTO admission_preparations (
                        receipt_body_digest, lease_digest, tenant_id,
                        collector_id, epoch, sequence, receipt_sequence,
                        envelope_digest, policy_id, policy_revision,
                        policy_digest, receipt_body_bytes, envelope_bytes,
                        cab_snapshot_bytes, policy_bytes, attestation_bytes,
                        custody_object_id, custody_reference
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        prepared.receipt_body_digest,
                        body.lease_digest,
                        body.tenant_id,
                        body.collector_id,
                        body.epoch,
                        body.sequence,
                        body.receipt_sequence,
                        body.envelope_digest,
                        body.trust_policy_id,
                        body.trust_policy_revision,
                        body.trust_policy_digest,
                        body_bytes,
                        prepared.envelope_bytes,
                        prepared.cab_snapshot_bytes,
                        prepared.trust_policy_bytes,
                        prepared.attestation_bytes,
                        body.custody_object_id,
                        body.custody_reference,
                    ),
                )
                connection.execute(
                    """
                    UPDATE admission_meta SET last_admitted_at = ?
                    WHERE singleton = 1
                    """,
                    (candidate.current_time,),
                )
                self._check_database_quota_after_write(connection)
                connection.commit()
                return prepared
        except AdmissionRejected:
            raise
        except (sqlite3.Error, OSError, RuntimeError) as exc:
            raise self._storage_rejected(exc) from exc

    def _sign_prepared_admission(
        self,
        prepared: _PreparedAdmission,
    ) -> AdmissionReceipt:
        body_bytes = prepared.body.canonical_bytes()
        if _digest(body_bytes) != prepared.receipt_body_digest:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "in-memory receipt preparation changed before signing",
            )
        self._assert_configured_signer_material()
        try:
            signature = self._receipt_signer.sign(body_bytes)
        except Exception as exc:
            raise AdmissionRejected(
                AdmissionRejectReason.SIGNER_UNAVAILABLE,
                "receipt signer is unavailable; retry the exact request",
            ) from exc
        self._assert_configured_signer_material()
        if not _verify_signer_signature(
            self._receipt_signer,
            body_bytes,
            signature,
            expected_fingerprint=self._receipt_signer_fingerprint,
        ):
            raise AdmissionRejected(
                AdmissionRejectReason.INVALID_RECEIPT_SIGNATURE,
                "receipt signer returned an invalid or substituted signature",
            )
        return AdmissionReceipt(
            body=prepared.body,
            service_signature=signature,
        )

    def _finalize_admission(
        self,
        expected: _PreparedAdmission,
        receipt: AdmissionReceipt,
    ) -> _StoredAdmission:
        try:
            with self._transaction() as connection:
                existing_row = connection.execute(
                    "SELECT * FROM admissions WHERE lease_digest = ?",
                    (expected.body.lease_digest,),
                ).fetchone()
                if existing_row is not None:
                    existing = self._verify_receipt_row(connection, existing_row)
                    self._verify_receipt_chain_neighborhood(
                        connection,
                        existing_row,
                        existing,
                    )
                    if existing.body != expected.body or receipt.body != expected.body:
                        raise AdmissionRejected(
                            AdmissionRejectReason.RETRY_MISMATCH,
                            "finalized receipt differs from the durable preparation",
                        )
                    stored = _StoredAdmission(
                        disposition=AdmissionDisposition.EXACT_RETRY,
                        receipt=existing,
                        envelope_bytes=bytes(existing_row["envelope_bytes"]),
                        cab_snapshot_bytes=bytes(existing_row["cab_snapshot_bytes"]),
                        trust_policy_bytes=bytes(existing_row["policy_bytes"]),
                        custody_reference=str(existing_row["custody_reference"]),
                        custody_acknowledgement=self._stored_ack(existing_row),
                    )
                    connection.rollback()
                    return stored
                row = connection.execute(
                    "SELECT * FROM admission_preparations WHERE lease_digest = ?",
                    (expected.body.lease_digest,),
                ).fetchone()
                if row is None:
                    raise AdmissionRejected(
                        AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                        "durable receipt preparation disappeared before finalization",
                    )
                prepared = self._prepared_admission_from_row(connection, row)
                if prepared != expected or receipt.body != prepared.body:
                    raise AdmissionRejected(
                        AdmissionRejectReason.RETRY_MISMATCH,
                        "signed receipt does not match the durable preparation",
                    )
                if not _verify_signer_signature(
                    self._receipt_signer,
                    receipt.body.canonical_bytes(),
                    receipt.service_signature,
                    expected_fingerprint=self._receipt_signer_fingerprint,
                ):
                    raise AdmissionRejected(
                        AdmissionRejectReason.INVALID_RECEIPT_SIGNATURE,
                        "signed receipt changed before finalization",
                    )
                tenant_head = self._verify_tenant_head(
                    connection,
                    prepared.body.tenant_id,
                )
                expected_sequence = 1 if tenant_head is None else tenant_head[0] + 1
                expected_previous = None if tenant_head is None else tenant_head[1]
                collector_head = self._verify_collector_head(
                    connection,
                    prepared.body.tenant_id,
                    prepared.body.collector_id,
                )
                if collector_head is None:
                    collector_valid = prepared.body.epoch == 1 and prepared.body.sequence == 1
                elif prepared.body.epoch == collector_head[0]:
                    collector_valid = prepared.body.sequence == collector_head[1] + 1
                elif prepared.body.epoch == collector_head[0] + 1:
                    collector_valid = (
                        prepared.body.sequence == 1
                        and (
                            prepared.body.previous_epoch,
                            prepared.body.previous_epoch_final_sequence,
                            prepared.body.previous_epoch_final_receipt_digest,
                        )
                        == collector_head
                    )
                else:
                    collector_valid = False
                pending_predecessor = connection.execute(
                    """
                    SELECT 1 FROM admissions
                    WHERE tenant_id = ? AND custody_state = 'pending'
                    LIMIT 1
                    """,
                    (prepared.body.tenant_id,),
                ).fetchone()
                if (
                    prepared.body.receipt_sequence != expected_sequence
                    or prepared.body.previous_receipt_digest != expected_previous
                    or not collector_valid
                    or pending_predecessor is not None
                ):
                    raise AdmissionRejected(
                        AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                        "reserved tenant or collector chain position changed",
                    )
                receipt_digest = receipt.receipt_digest()
                # This replaces a bounded preparation. The rollbackable
                # post-write check below measures logical pages without
                # double-counting the preparation's already-committed WAL.
                deleted = connection.execute(
                    """
                    DELETE FROM admission_preparations
                    WHERE receipt_body_digest = ? AND lease_digest = ?
                    """,
                    (
                        prepared.receipt_body_digest,
                        prepared.body.lease_digest,
                    ),
                )
                if deleted.rowcount != 1:
                    raise AdmissionRejected(
                        AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                        "receipt preparation compare-and-delete failed",
                    )
                connection.execute(
                    """
                    INSERT INTO admissions (
                        receipt_digest, receipt_sequence, lease_digest,
                        tenant_id, collector_id, epoch, sequence,
                        envelope_digest, statement_digest, cab_snapshot_digest,
                        policy_id, policy_revision, policy_digest,
                        attestation_digest, request_fingerprint,
                        receipt_bytes, envelope_bytes, cab_snapshot_bytes,
                        policy_bytes, attestation_bytes,
                        custody_object_id, custody_reference,
                        custody_state
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending'
                    )
                    """,
                    (
                        receipt_digest,
                        prepared.body.receipt_sequence,
                        prepared.body.lease_digest,
                        prepared.body.tenant_id,
                        prepared.body.collector_id,
                        prepared.body.epoch,
                        prepared.body.sequence,
                        prepared.body.envelope_digest,
                        prepared.body.payload_digest,
                        prepared.body.cab_snapshot_digest,
                        prepared.body.trust_policy_id,
                        prepared.body.trust_policy_revision,
                        prepared.body.trust_policy_digest,
                        prepared.body.attestation_verification_digest,
                        prepared.body.admission_request_fingerprint,
                        receipt.canonical_bytes(),
                        prepared.envelope_bytes,
                        prepared.cab_snapshot_bytes,
                        prepared.trust_policy_bytes,
                        prepared.attestation_bytes,
                        prepared.body.custody_object_id,
                        prepared.body.custody_reference,
                    ),
                )
                updated = connection.execute(
                    """
                    UPDATE job_leases
                    SET consumed_envelope_digest = ?, consumed_receipt_digest = ?
                    WHERE lease_digest = ?
                      AND consumed_envelope_digest IS NULL
                      AND consumed_receipt_digest IS NULL
                    """,
                    (
                        prepared.body.envelope_digest,
                        receipt_digest,
                        prepared.body.lease_digest,
                    ),
                )
                if updated.rowcount != 1:
                    raise AdmissionRejected(
                        AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                        "lease consumption was not atomic",
                    )
                connection.execute(
                    """
                    INSERT INTO collector_heads (
                        tenant_id, collector_id, current_epoch,
                        last_sequence, last_receipt_digest
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT (tenant_id, collector_id) DO UPDATE SET
                        current_epoch = excluded.current_epoch,
                        last_sequence = excluded.last_sequence,
                        last_receipt_digest = excluded.last_receipt_digest
                    """,
                    (
                        prepared.body.tenant_id,
                        prepared.body.collector_id,
                        prepared.body.epoch,
                        prepared.body.sequence,
                        receipt_digest,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO tenant_heads (
                        tenant_id, last_receipt_sequence, last_receipt_digest
                    ) VALUES (?, ?, ?)
                    ON CONFLICT (tenant_id) DO UPDATE SET
                        last_receipt_sequence = excluded.last_receipt_sequence,
                        last_receipt_digest = excluded.last_receipt_digest
                    """,
                    (
                        prepared.body.tenant_id,
                        prepared.body.receipt_sequence,
                        receipt_digest,
                    ),
                )
                self._check_database_quota_after_write(connection)
                self._fault_injector(FaultPoint.BEFORE_COMMIT)
                connection.commit()
                self._validated_tenant_heads[prepared.body.tenant_id] = (
                    prepared.body.receipt_sequence,
                    receipt_digest,
                )
                return _StoredAdmission(
                    disposition=AdmissionDisposition.ADMITTED,
                    receipt=receipt,
                    envelope_bytes=prepared.envelope_bytes,
                    cab_snapshot_bytes=prepared.cab_snapshot_bytes,
                    trust_policy_bytes=prepared.trust_policy_bytes,
                    custody_reference=prepared.body.custody_reference,
                    custody_acknowledgement=None,
                )
        except AdmissionRejected:
            raise
        except (sqlite3.Error, OSError, RuntimeError) as exc:
            raise self._storage_rejected(exc) from exc

    def _stored_ack(self, row: sqlite3.Row) -> CustodyAcknowledgement | None:
        state = row["custody_state"]
        ack_bytes = row["custody_ack_bytes"]
        ack_digest = row["custody_ack_digest"]
        if state == "pending":
            if ack_bytes is not None or ack_digest is not None:
                raise AdmissionRejected(
                    AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                    "pending custody row already contains an acknowledgement",
                )
            return None
        if ack_bytes is None or ack_digest is None:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "durable custody row is missing its acknowledgement",
            )
        try:
            acknowledgement = _parse_custody_ack(bytes(ack_bytes))
        except (StrictJSONError, ValueError, TypeError) as exc:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "stored custody acknowledgement is not canonical",
            ) from exc
        if (
            acknowledgement.acknowledgement_digest() != ack_digest
            or not _verify_signer_signature(
                self._receipt_signer,
                acknowledgement.body.canonical_bytes(),
                acknowledgement.service_signature,
                expected_fingerprint=self._receipt_signer_fingerprint,
            )
            or acknowledgement.body.receipt_digest != row["receipt_digest"]
            or acknowledgement.body.custody_object_id != row["custody_object_id"]
            or acknowledgement.body.custody_reference != row["custody_reference"]
            or acknowledgement.body.envelope_digest != row["envelope_digest"]
            or acknowledgement.body.cab_snapshot_digest != row["cab_snapshot_digest"]
            or acknowledgement.body.trust_policy_digest != row["policy_digest"]
            or acknowledgement.body.receipt_signer_key_fingerprint
            != self._receipt_signer_fingerprint
        ):
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "stored custody acknowledgement binding is invalid",
            )
        return acknowledgement

    def _prepared_acknowledgement_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> _PreparedCustodyAcknowledgement:
        try:
            parsed = _parse_canonical_model(
                bytes(row["acknowledgement_body_bytes"]),
                CustodyAcknowledgementBody,
            )
            assert isinstance(parsed, CustodyAcknowledgementBody)
            body = parsed
        except Exception as exc:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "stored custody acknowledgement preparation is not canonical",
            ) from exc
        body_digest = _digest(body.canonical_bytes())
        admission_row = connection.execute(
            "SELECT * FROM admissions WHERE receipt_digest = ?",
            (body.receipt_digest,),
        ).fetchone()
        if admission_row is None:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "custody acknowledgement preparation references a missing receipt",
            )
        receipt = self._verify_receipt_row(connection, admission_row)
        if (
            body.receipt_digest != row["receipt_digest"]
            or body_digest != row["acknowledgement_body_digest"]
            or admission_row["custody_state"] != "pending"
            or admission_row["custody_ack_digest"] is not None
            or admission_row["custody_ack_bytes"] is not None
            or body.receipt_digest != receipt.receipt_digest()
            or body.custody_object_id != receipt.body.custody_object_id
            or body.custody_reference != receipt.body.custody_reference
            or body.envelope_digest != receipt.body.envelope_digest
            or body.cab_snapshot_digest != receipt.body.cab_snapshot_digest
            or body.trust_policy_digest != receipt.body.trust_policy_digest
            or body.receipt_signer_key_fingerprint != self._receipt_signer_fingerprint
        ):
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "stored custody acknowledgement preparation bindings are incoherent",
            )
        pending_predecessor = connection.execute(
            """
            SELECT 1 FROM admissions
            WHERE tenant_id = ? AND receipt_sequence < ?
              AND custody_state != 'durable'
            ORDER BY receipt_sequence LIMIT 1
            """,
            (
                admission_row["tenant_id"],
                admission_row["receipt_sequence"],
            ),
        ).fetchone()
        if pending_predecessor is not None:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "custody acknowledgement preparation bypasses a pending predecessor",
            )
        return _PreparedCustodyAcknowledgement(
            acknowledgement_body_digest=body_digest,
            body=body,
        )

    def mark_custody_durable(
        self,
        *,
        receipt_digest: str,
        custody_reference: str,
    ) -> CustodyAcknowledgement:
        prepared_or_existing = self._prepare_custody_acknowledgement(
            receipt_digest=receipt_digest,
            custody_reference=custody_reference,
        )
        if isinstance(prepared_or_existing, CustodyAcknowledgement):
            return prepared_or_existing
        self._fault_injector(FaultPoint.AFTER_ACK_PREPARE_BEFORE_SIGN)
        acknowledgement = self._sign_prepared_acknowledgement(prepared_or_existing)
        self._fault_injector(FaultPoint.AFTER_ACK_SIGN_BEFORE_FINALIZE)
        return self._finalize_custody_acknowledgement(
            prepared_or_existing,
            acknowledgement,
        )

    def _prepare_custody_acknowledgement(
        self,
        *,
        receipt_digest: str,
        custody_reference: str,
    ) -> _PreparedCustodyAcknowledgement | CustodyAcknowledgement:
        try:
            with self._transaction() as connection:
                row = connection.execute(
                    "SELECT * FROM admissions WHERE receipt_digest = ?",
                    (receipt_digest,),
                ).fetchone()
                if row is None:
                    raise AdmissionRejected(
                        AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                        "receipt disappeared before custody acknowledgement",
                    )
                receipt = self._verify_receipt_row(connection, row)
                if custody_reference != row["custody_reference"]:
                    raise AdmissionRejected(
                        AdmissionRejectReason.CUSTODY_UNAVAILABLE,
                        "custody returned a non-idempotent reference",
                    )
                existing = self._stored_ack(row)
                if existing is not None:
                    connection.rollback()
                    return existing
                prepared_row = connection.execute(
                    """
                    SELECT * FROM custody_ack_preparations
                    WHERE receipt_digest = ?
                    """,
                    (receipt_digest,),
                ).fetchone()
                if prepared_row is not None:
                    prepared = self._prepared_acknowledgement_from_row(
                        connection,
                        prepared_row,
                    )
                    if prepared.body.custody_reference != custody_reference:
                        raise AdmissionRejected(
                            AdmissionRejectReason.CUSTODY_UNAVAILABLE,
                            "custody acknowledgement retry changed its reference",
                        )
                    connection.rollback()
                    return prepared
                pending_predecessor = connection.execute(
                    """
                    SELECT receipt_sequence FROM admissions
                    WHERE tenant_id = ? AND receipt_sequence < ?
                      AND custody_state != 'durable'
                    ORDER BY receipt_sequence LIMIT 1
                    """,
                    (row["tenant_id"], row["receipt_sequence"]),
                ).fetchone()
                if pending_predecessor is not None:
                    raise AdmissionRejected(
                        AdmissionRejectReason.CUSTODY_UNAVAILABLE,
                        "an earlier tenant receipt must reach durable custody first",
                    )
                body = CustodyAcknowledgementBody(
                    media_type=CUSTODY_ACK_MEDIA_TYPE,
                    schema_version=CUSTODY_ACK_SCHEMA_VERSION,
                    receipt_digest=receipt.receipt_digest(),
                    custody_object_id=receipt.body.custody_object_id,
                    custody_reference=custody_reference,
                    envelope_digest=receipt.body.envelope_digest,
                    cab_snapshot_digest=receipt.body.cab_snapshot_digest,
                    trust_policy_digest=receipt.body.trust_policy_digest,
                    receipt_signer_key_fingerprint=self._receipt_signer_fingerprint,
                )
                prepared = _PreparedCustodyAcknowledgement(
                    acknowledgement_body_digest=_digest(body.canonical_bytes()),
                    body=body,
                )
                # The body is schema-bounded. Let the rollbackable post-write
                # quota check decide rather than pessimistically counting the
                # receipt transaction's committed WAL a second time.
                connection.execute(
                    """
                    INSERT INTO custody_ack_preparations (
                        receipt_digest, acknowledgement_body_digest,
                        acknowledgement_body_bytes
                    ) VALUES (?, ?, ?)
                    """,
                    (
                        receipt_digest,
                        prepared.acknowledgement_body_digest,
                        body.canonical_bytes(),
                    ),
                )
                self._check_database_quota_after_write(connection)
                connection.commit()
                return prepared
        except AdmissionRejected:
            raise
        except (sqlite3.Error, OSError, RuntimeError) as exc:
            raise self._storage_rejected(exc) from exc

    def _sign_prepared_acknowledgement(
        self,
        prepared: _PreparedCustodyAcknowledgement,
    ) -> CustodyAcknowledgement:
        body_bytes = prepared.body.canonical_bytes()
        if _digest(body_bytes) != prepared.acknowledgement_body_digest:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "in-memory custody acknowledgement preparation changed",
            )
        self._assert_configured_signer_material()
        try:
            signature = self._receipt_signer.sign(body_bytes)
        except Exception as exc:
            raise AdmissionRejected(
                AdmissionRejectReason.SIGNER_UNAVAILABLE,
                "custody acknowledgement signer is unavailable; retry reconciliation",
            ) from exc
        self._assert_configured_signer_material()
        if not _verify_signer_signature(
            self._receipt_signer,
            body_bytes,
            signature,
            expected_fingerprint=self._receipt_signer_fingerprint,
        ):
            raise AdmissionRejected(
                AdmissionRejectReason.INVALID_RECEIPT_SIGNATURE,
                "custody acknowledgement signer returned a substituted signature",
            )
        return CustodyAcknowledgement(
            body=prepared.body,
            service_signature=signature,
        )

    def _finalize_custody_acknowledgement(
        self,
        expected: _PreparedCustodyAcknowledgement,
        acknowledgement: CustodyAcknowledgement,
    ) -> CustodyAcknowledgement:
        try:
            with self._transaction() as connection:
                admission_row = connection.execute(
                    "SELECT * FROM admissions WHERE receipt_digest = ?",
                    (expected.body.receipt_digest,),
                ).fetchone()
                if admission_row is None:
                    raise AdmissionRejected(
                        AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                        "receipt disappeared before custody acknowledgement finalization",
                    )
                existing = self._stored_ack(admission_row)
                if existing is not None:
                    if existing.body != expected.body or acknowledgement.body != expected.body:
                        raise AdmissionRejected(
                            AdmissionRejectReason.RETRY_MISMATCH,
                            "final custody acknowledgement differs from its preparation",
                        )
                    connection.rollback()
                    return existing
                prepared_row = connection.execute(
                    """
                    SELECT * FROM custody_ack_preparations
                    WHERE receipt_digest = ?
                    """,
                    (expected.body.receipt_digest,),
                ).fetchone()
                if prepared_row is None:
                    raise AdmissionRejected(
                        AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                        "custody acknowledgement preparation disappeared",
                    )
                prepared = self._prepared_acknowledgement_from_row(
                    connection,
                    prepared_row,
                )
                if (
                    prepared != expected
                    or acknowledgement.body != prepared.body
                    or not _verify_signer_signature(
                        self._receipt_signer,
                        acknowledgement.body.canonical_bytes(),
                        acknowledgement.service_signature,
                        expected_fingerprint=self._receipt_signer_fingerprint,
                    )
                ):
                    raise AdmissionRejected(
                        AdmissionRejectReason.INVALID_RECEIPT_SIGNATURE,
                        "custody acknowledgement changed before finalization",
                    )
                pending_predecessor = connection.execute(
                    """
                    SELECT 1 FROM admissions
                    WHERE tenant_id = ? AND receipt_sequence < ?
                      AND custody_state != 'durable'
                    ORDER BY receipt_sequence LIMIT 1
                    """,
                    (
                        admission_row["tenant_id"],
                        admission_row["receipt_sequence"],
                    ),
                ).fetchone()
                if pending_predecessor is not None:
                    raise AdmissionRejected(
                        AdmissionRejectReason.CUSTODY_UNAVAILABLE,
                        "an earlier tenant receipt must reach durable custody first",
                    )
                # Like receipt finalization, this replaces a bounded
                # preparation and is guarded by the post-write logical quota.
                deleted = connection.execute(
                    """
                    DELETE FROM custody_ack_preparations
                    WHERE receipt_digest = ?
                      AND acknowledgement_body_digest = ?
                    """,
                    (
                        expected.body.receipt_digest,
                        expected.acknowledgement_body_digest,
                    ),
                )
                if deleted.rowcount != 1:
                    raise AdmissionRejected(
                        AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                        "custody acknowledgement compare-and-delete failed",
                    )
                updated = connection.execute(
                    """
                    UPDATE admissions
                    SET custody_state = 'durable',
                        custody_ack_digest = ?,
                        custody_ack_bytes = ?
                    WHERE receipt_digest = ? AND custody_state = 'pending'
                    """,
                    (
                        acknowledgement.acknowledgement_digest(),
                        acknowledgement.canonical_bytes(),
                        expected.body.receipt_digest,
                    ),
                )
                if updated.rowcount != 1:
                    raise AdmissionRejected(
                        AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                        "custody acknowledgement transition was not atomic",
                    )
                self._check_database_quota_after_write(connection)
                connection.commit()
                return acknowledgement
        except AdmissionRejected:
            raise
        except (sqlite3.Error, OSError, RuntimeError) as exc:
            raise self._storage_rejected(exc) from exc

    def reconcile_prepared(
        self,
        *,
        limit: int = 100,
    ) -> Iterator[_StoredAdmission]:
        """Sign and finalize durable preparations without reopening source inputs."""

        if type(limit) is not int or limit < 1 or limit > 1000:
            raise ValueError("prepared reconciliation limit must be between 1 and 1000")
        try:
            with self._transaction() as connection:
                body_digests = tuple(
                    str(row["receipt_body_digest"])
                    for row in connection.execute(
                        """
                        SELECT receipt_body_digest
                        FROM admission_preparations
                        ORDER BY receipt_body_digest
                        LIMIT ?
                        """,
                        (limit,),
                    ).fetchall()
                )
                connection.rollback()
        except AdmissionRejected:
            raise
        except (sqlite3.Error, OSError, RuntimeError) as exc:
            raise self._storage_rejected(exc) from exc
        for body_digest in body_digests:
            try:
                with self._transaction() as connection:
                    row = connection.execute(
                        """
                        SELECT * FROM admission_preparations
                        WHERE receipt_body_digest = ?
                        """,
                        (body_digest,),
                    ).fetchone()
                    if row is None:
                        connection.rollback()
                        continue
                    prepared = self._prepared_admission_from_row(connection, row)
                    connection.rollback()
            except AdmissionRejected:
                raise
            except (sqlite3.Error, OSError, RuntimeError) as exc:
                raise self._storage_rejected(exc) from exc
            yield self._complete_prepared_admission(prepared)

    def pending(self, *, limit: int = 100) -> tuple[_StoredAdmission, ...]:
        if type(limit) is not int or limit < 1 or limit > 1000:
            raise ValueError("pending reconciliation limit must be between 1 and 1000")
        try:
            with self._transaction() as connection:
                rows = connection.execute(
                    """
                    SELECT * FROM admissions
                    WHERE custody_state = 'pending'
                    ORDER BY receipt_sequence LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
                pending: list[_StoredAdmission] = []
                for row in rows:
                    receipt = self._verify_receipt_row(connection, row)
                    self._verify_receipt_chain_neighborhood(connection, row, receipt)
                    pending.append(
                        _StoredAdmission(
                            disposition=AdmissionDisposition.EXACT_RETRY,
                            receipt=receipt,
                            envelope_bytes=bytes(row["envelope_bytes"]),
                            cab_snapshot_bytes=bytes(row["cab_snapshot_bytes"]),
                            trust_policy_bytes=bytes(row["policy_bytes"]),
                            custody_reference=str(row["custody_reference"]),
                            custody_acknowledgement=None,
                        )
                    )
                return tuple(pending)
        except AdmissionRejected:
            raise
        except (sqlite3.Error, OSError, RuntimeError) as exc:
            raise self._storage_rejected(exc) from exc


class AdmissionService:
    """The sole public trust boundary for evidence admission."""

    def __init__(
        self,
        path: Path,
        *,
        lease_authority: LeaseAuthorityVerifier,
        receipt_signer: ReceiptSigner,
        policy_resolver: TrustPolicyResolver,
        custody: CustodyStore,
        expected_audience: str,
        expected_capability_digest: str,
        clock: Clock | None = None,
        limits: AdmissionLimits | None = None,
        fault_injector: FaultInjector | None = None,
    ) -> None:
        self._expected_audience = _safe_identifier(expected_audience)
        if re.fullmatch(r"sha256:[a-f0-9]{64}", expected_capability_digest) is None:
            raise ValueError("expected capability digest must be lowercase SHA-256")
        self._expected_capability_digest = expected_capability_digest
        self._policy_resolver = policy_resolver
        self._custody = custody
        self._clock = clock or _SystemClock()
        self._limits = limits or AdmissionLimits()
        self._fault_injector = fault_injector or (lambda _point: None)
        self._ledger = _SQLiteAdmissionLedger(
            path,
            lease_authority=lease_authority,
            receipt_signer=receipt_signer,
            clock=self._clock,
            limits=self._limits,
            fault_injector=self._fault_injector,
        )

    def register_lease(self, grant_bytes: bytes) -> SignedJobLease:
        """Control-plane operation: verify and durably register an exact lease."""

        if type(grant_bytes) is not bytes:
            raise AdmissionRejected(
                AdmissionRejectReason.MALFORMED_LEASE,
                "signed lease must be bytes",
            )
        return self._ledger.register_lease(grant_bytes)

    def _resolve_policy(
        self,
        *,
        policy_id: str,
        policy_revision: int,
        policy_digest: str,
        exact_retry: bool,
    ) -> tuple[bytes, TrustPolicy]:
        try:
            policy_bytes = self._policy_resolver.resolve(
                policy_id,
                policy_revision,
                policy_digest,
            )
        except Exception as exc:
            raise AdmissionRejected(
                AdmissionRejectReason.POLICY_UNAVAILABLE,
                "authoritative trust policy could not be resolved",
            ) from exc
        if type(policy_bytes) is not bytes or len(policy_bytes) > self._limits.max_policy_bytes:
            raise AdmissionRejected(
                AdmissionRejectReason.RESOURCE_LIMIT_EXCEEDED,
                "resolved trust policy is not bounded canonical bytes",
            )
        try:
            policy = parse_trust_policy(policy_bytes)
        except Exception as exc:
            raise AdmissionRejected(
                AdmissionRejectReason.POLICY_UNAVAILABLE,
                "authoritative trust policy is malformed",
            ) from exc
        if policy.policy_id != policy_id:
            raise AdmissionRejected(
                AdmissionRejectReason.POLICY_UNAVAILABLE,
                "resolved trust policy id does not match the signed statement",
            )
        if _digest(policy_bytes) != policy_digest:
            raise AdmissionRejected(
                (
                    AdmissionRejectReason.RETRY_MISMATCH
                    if exact_retry
                    else AdmissionRejectReason.POLICY_UNAVAILABLE
                ),
                "resolved trust policy bytes do not match the signed immutable revision",
            )
        return policy_bytes, policy

    def admit(
        self,
        *,
        envelope_bytes: bytes,
        cab_source: Path,
    ) -> AdmissionOutcome:
        """Verify raw envelope, authoritative policy, and exact CAB, then admit."""

        if type(envelope_bytes) is not bytes:
            raise AdmissionRejected(
                AdmissionRejectReason.MALFORMED_ENVELOPE,
                "DSSE envelope must be bytes",
            )
        if len(envelope_bytes) > self._limits.max_envelope_bytes:
            raise AdmissionRejected(
                AdmissionRejectReason.RESOURCE_LIMIT_EXCEEDED,
                "DSSE envelope exceeds the configured byte limit",
            )
        try:
            envelope = parse_dsse_envelope(envelope_bytes)
            payload_bytes = envelope.payload_bytes()
            statement = parse_collection_statement(payload_bytes)
        except Exception as exc:
            raise AdmissionRejected(
                AdmissionRejectReason.MALFORMED_ENVELOPE,
                "envelope does not carry one canonical collection statement",
            ) from exc
        if (
            statement.audience != self._expected_audience
            or statement.capability_digest != self._expected_capability_digest
        ):
            raise AdmissionRejected(
                AdmissionRejectReason.CONFIGURATION_MISMATCH,
                "statement audience or capability is not configured for this service",
            )
        envelope_digest = _digest(envelope_bytes)
        original_time = self._ledger.retry_admitted_at(
            statement=statement,
            envelope_digest=envelope_digest,
        )
        policy_bytes, policy = self._resolve_policy(
            policy_id=statement.policy_id,
            policy_revision=statement.policy_revision,
            policy_digest=statement.policy_digest,
            exact_retry=original_time is not None,
        )
        policy_digest = _digest(policy_bytes)
        try:
            snapshot = capture_cab_snapshot(
                cab_source,
                maximum=self._limits.max_cab_snapshot_bytes,
            )
        except CABSnapshotError as exc:
            raise AdmissionRejected(
                AdmissionRejectReason.CAB_REJECTED,
                "CAB source could not be sealed as an integrity-verified snapshot",
            ) from exc
        if (
            snapshot.cab_id != statement.cab_id
            or snapshot.manifest_digest != statement.manifest_digest
        ):
            raise AdmissionRejected(
                AdmissionRejectReason.CAB_REJECTED,
                "sealed CAB identity does not match the signed collection statement",
            )
        object_id = _custody_object_id(
            tenant_id=statement.tenant_id,
            job_id=statement.job_id,
            envelope_digest=envelope_digest,
            snapshot_digest=snapshot.snapshot_digest,
        )
        try:
            expected_reference = _safe_reference(self._custody.reference_for(object_id))
        except Exception as exc:
            raise AdmissionRejected(
                AdmissionRejectReason.CUSTODY_UNAVAILABLE,
                "custody could not derive a deterministic object reference",
            ) from exc

        def candidate_for(admission_time: str) -> _VerifiedAdmission:
            verification_time = _parse_timestamp(admission_time)
            verification = verify_dsse_attestation(
                envelope_bytes,
                policy=policy,
                expected_payload_type=COLLECTION_STATEMENT_MEDIA_TYPE,
                expected_payload=statement.canonical_bytes(),
                admission_time=verification_time,
            )
            if not verification.verified or verification.reason_code != AttestationReason.VERIFIED:
                raise AdmissionRejected(
                    AdmissionRejectReason.ATTESTATION_REJECTED,
                    f"DSSE attestation rejected: {verification.reason_code}",
                )
            if (
                policy_digest != statement.policy_digest
                or verification.raw_envelope_sha256 != envelope_digest.removeprefix("sha256:")
                or verification.expected_payload_sha256
                != _digest(statement.canonical_bytes()).removeprefix("sha256:")
                or verification.expected_payload_type != COLLECTION_STATEMENT_MEDIA_TYPE
                or verification.trust_policy_sha256 != policy_digest.removeprefix("sha256:")
                or verification.policy_id != statement.policy_id
                or verification.admission_time != admission_time
            ):
                raise AdmissionRejected(
                    AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                    "attestation verifier returned incoherent provenance",
                )
            attestation_bytes = _attestation_bytes(verification)
            request_fingerprint = _admission_request_fingerprint(
                statement_digest=_digest(statement.canonical_bytes()),
                envelope_digest=envelope_digest,
                snapshot_digest=snapshot.snapshot_digest,
                policy_digest=policy_digest,
                policy_revision=statement.policy_revision,
                attestation_bytes=attestation_bytes,
                audience=statement.audience,
                capability_digest=statement.capability_digest,
                accepted_key_ids=verification.accepted_key_ids,
                accepted_identities=verification.accepted_identities,
                custody_object_id=object_id,
                custody_reference=expected_reference,
                lease_authority_key_fingerprint=(self._ledger.lease_authority_fingerprint),
                receipt_signer_key_fingerprint=(self._ledger.receipt_signer_fingerprint),
            )
            return _VerifiedAdmission(
                statement=statement,
                envelope_bytes=envelope_bytes,
                envelope_digest=envelope_digest,
                snapshot=snapshot,
                policy_bytes=policy_bytes,
                policy_digest=policy_digest,
                attestation=verification,
                attestation_bytes=attestation_bytes,
                request_fingerprint=request_fingerprint,
                admitted_at=admission_time,
                current_time=admission_time,
                custody_object_id=object_id,
                custody_reference=expected_reference,
            )

        stored = self._ledger.append(
            statement=statement,
            envelope_digest=envelope_digest,
            original_admitted_at=original_time,
            candidate_factory=candidate_for,
        )
        self._fault_injector(FaultPoint.AFTER_COMMIT_BEFORE_CUSTODY)
        acknowledgement = self._establish_custody(stored)
        return AdmissionOutcome(
            disposition=stored.disposition,
            receipt=stored.receipt,
            custody_acknowledgement=acknowledgement,
        )

    def _establish_custody(
        self,
        stored: _StoredAdmission,
    ) -> CustodyAcknowledgement:
        receipt = stored.receipt
        if stored.custody_acknowledgement is not None:
            acknowledgement = stored.custody_acknowledgement
        else:
            acknowledgement = None
        try:
            returned_reference = self._custody.persist(
                custody_object_id=receipt.body.custody_object_id,
                custody_reference=stored.custody_reference,
                receipt_bytes=receipt.canonical_bytes(),
                envelope_bytes=stored.envelope_bytes,
                cab_snapshot_bytes=stored.cab_snapshot_bytes,
                trust_policy_bytes=stored.trust_policy_bytes,
                expected_envelope_digest=receipt.body.envelope_digest,
                expected_cab_snapshot_digest=receipt.body.cab_snapshot_digest,
                expected_trust_policy_digest=receipt.body.trust_policy_digest,
                expected_receipt_digest=receipt.receipt_digest(),
            )
            if returned_reference != stored.custody_reference or not self._custody.verify(
                custody_object_id=receipt.body.custody_object_id,
                custody_reference=stored.custody_reference,
                receipt_digest=receipt.receipt_digest(),
                envelope_digest=receipt.body.envelope_digest,
                cab_snapshot_digest=receipt.body.cab_snapshot_digest,
                trust_policy_digest=receipt.body.trust_policy_digest,
            ):
                raise ValueError("custody did not verify the exact deterministic object")
        except Exception as exc:
            raise AdmissionRejected(
                AdmissionRejectReason.CUSTODY_UNAVAILABLE,
                "lease is consumed but exact durable custody is not confirmed; "
                "retry or reconciliation is required",
            ) from exc
        self._fault_injector(FaultPoint.AFTER_CUSTODY_BEFORE_ACK)
        marked = self._ledger.mark_custody_durable(
            receipt_digest=receipt.receipt_digest(),
            custody_reference=stored.custody_reference,
        )
        if acknowledgement is not None and acknowledgement != marked:
            raise AdmissionRejected(
                AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR,
                "durable custody acknowledgement changed during retry",
            )
        return marked

    def reconcile_pending(self, *, limit: int = 100) -> int:
        """Finish prepared receipts and custody after a process or network crash."""

        completed = 0
        for stored in self._ledger.reconcile_prepared(limit=limit):
            self._establish_custody(stored)
            completed += 1
        remaining = limit - completed
        if remaining < 1:
            return completed
        for stored in self._ledger.pending(limit=remaining):
            self._establish_custody(stored)
            completed += 1
        return completed


__all__ = [
    "ADMISSION_SCHEMA_VERSION",
    "COLLECTION_STATEMENT_MEDIA_TYPE",
    "CUSTODY_ACK_MEDIA_TYPE",
    "CUSTODY_ACK_SCHEMA_VERSION",
    "LEASE_GRANT_MEDIA_TYPE",
    "LEASE_MEDIA_TYPE",
    "RECEIPT_MEDIA_TYPE",
    "AdmissionDisposition",
    "AdmissionLimits",
    "AdmissionOutcome",
    "AdmissionReceipt",
    "AdmissionReceiptBody",
    "AdmissionRejectReason",
    "AdmissionRejected",
    "AdmissionService",
    "Clock",
    "CollectionStatement",
    "CustodyAcknowledgement",
    "CustodyAcknowledgementBody",
    "CustodyStore",
    "DetachedSignature",
    "FaultInjector",
    "FaultPoint",
    "JobLease",
    "LeaseAuthorityVerifier",
    "ReceiptSigner",
    "SignedJobLease",
    "TrustPolicyResolver",
    "issue_signed_job_lease",
    "parse_collection_statement",
    "parse_job_lease",
    "parse_signed_job_lease",
]
