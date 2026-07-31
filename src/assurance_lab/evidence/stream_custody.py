"""Signed, exact-set S3 Object Lock closure for streamed CAB snapshots.

The v2 stream snapshot profile keeps a small canonical descriptor beside
content-addressed blobs.  This module closes the gap between that local shape
and durable custody:

* the descriptor and every unique blob are independently written with
  conditional S3 Object Lock custody;
* the local snapshot is verified again after all component writes;
* one canonical receipt closes over the exact descriptor-derived object set,
  each exact S3 VersionId acknowledgement, byte size, KMS pin, scope, and
  retention instant;
* a ``ReceiptSigner`` signs a domain-separated digest of that receipt; and
* the signed closure itself is conditionally written and reopened under the
  same Object Lock scope.

An S3 custody acknowledgement is a client-produced record of checks performed
against one exact S3 version.  It is not an AWS signature.  The Ed25519
signature authenticates the closed receipt; optional online verification then
reopens every acknowledged VersionId and hashes every byte again.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from assurance_lab.evidence.admission import (
    DetachedSignature,
    LeaseAuthorityVerifier,
    ReceiptSigner,
)
from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)
from assurance_lab.evidence.s3_object_lock import (
    S3CustodyAcknowledgement,
    S3ObjectLockError,
)
from assurance_lab.evidence.stream_snapshot import (
    MAX_STREAM_SNAPSHOT_FILES,
    MAX_STREAM_SNAPSHOT_MANIFEST_BYTES,
    MAX_STREAM_SNAPSHOT_TOTAL_BYTES,
    STREAM_SNAPSHOT_MEDIA_TYPE,
    STREAM_SNAPSHOT_SCHEMA_VERSION,
    StreamedCABSnapshot,
    StreamSnapshotDescriptor,
    StreamSnapshotError,
    StreamSnapshotLimits,
    verify_streamed_cab_snapshot,
)

STREAM_CUSTODY_RECEIPT_MEDIA_TYPE: Literal[
    "application/vnd.control-assurance.stream-custody-receipt.v1+json"
] = "application/vnd.control-assurance.stream-custody-receipt.v1+json"
SIGNED_STREAM_CUSTODY_MEDIA_TYPE: Literal[
    "application/vnd.control-assurance.signed-stream-custody.v1+json"
] = "application/vnd.control-assurance.signed-stream-custody.v1+json"
STREAM_CUSTODY_SCHEMA_VERSION: Literal["1.0.0"] = "1.0.0"
STREAM_CUSTODY_SIGNATURE_DOMAIN: Literal[
    "control-assurance:stream-custody-receipt:v1"
] = "control-assurance:stream-custody-receipt:v1"

MAX_STREAM_CUSTODY_DOCUMENT_BYTES = 8 * 1024 * 1024
_MAX_CUSTODY_OBJECTS = MAX_STREAM_SNAPSHOT_FILES + 1
_DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
_TIMESTAMP_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
_SIGNATURE_PREFIX = STREAM_CUSTODY_SIGNATURE_DOMAIN.encode("ascii") + b"\x00"
_DEFAULT_LIMITS = StreamSnapshotLimits()
_DOCUMENT_LIMITS = JSONLimits(
    max_bytes=MAX_STREAM_CUSTODY_DOCUMENT_BYTES,
    max_line_bytes=MAX_STREAM_CUSTODY_DOCUMENT_BYTES,
    max_depth=16,
    max_collection_items=100_000,
    max_string_length=8_192,
)
_DESCRIPTOR_LIMITS = JSONLimits(
    max_bytes=MAX_STREAM_SNAPSHOT_MANIFEST_BYTES,
    max_line_bytes=MAX_STREAM_SNAPSHOT_MANIFEST_BYTES,
    max_depth=12,
    max_collection_items=40_000,
    max_string_length=4_096,
)


class StreamCustodyError(RuntimeError):
    """Stable failure at the signed stream-custody boundary."""

    __slots__ = ("stage",)

    def __init__(self, stage: str, detail: str) -> None:
        super().__init__(detail)
        self.stage = stage


class StreamCustodyAdapter(Protocol):
    """The narrow local/online surface required from Object Lock custody."""

    def put_file(
        self,
        source: Path,
        *,
        tenant_id: str,
        cab_id: str,
        retain_until: datetime,
        expected_object_digest: str | None = None,
    ) -> S3CustodyAcknowledgement: ...

    def put_bytes(
        self,
        payload: bytes,
        *,
        tenant_id: str,
        cab_id: str,
        retain_until: datetime,
        expected_object_digest: str | None = None,
    ) -> S3CustodyAcknowledgement: ...

    def verify_acknowledgement_scope(
        self,
        acknowledgement: S3CustodyAcknowledgement,
        *,
        tenant_id: str,
        cab_id: str,
    ) -> bool: ...

    def reverify_acknowledgement(
        self,
        acknowledgement: S3CustodyAcknowledgement,
        *,
        tenant_id: str,
        cab_id: str,
        expected_size: int,
    ) -> S3CustodyAcknowledgement: ...


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        revalidate_instances="always",
        strict=True,
    )


def _tuple_from_json_array(value: object) -> object:
    if isinstance(value, list):
        return tuple(value)
    return value


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _parse_utc_second(value: str) -> datetime:
    if type(value) is not str or _TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise ValueError("retention timestamp must use canonical UTC seconds")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ValueError("retention timestamp is not a real UTC instant") from exc


class CustodyAcknowledgementRecord(_StrictFrozenModel):
    """Strict JSON form of :class:`S3CustodyAcknowledgement`."""

    bucket_arn_digest: str = Field(pattern=_DIGEST_PATTERN)
    cab_scope_digest: str = Field(pattern=_DIGEST_PATTERN)
    checksum_sha256: str
    encryption: Literal["aws:kms", "aws:kms:dsse"]
    kms_key_arn_digest: str = Field(pattern=_DIGEST_PATTERN)
    media_type: Literal[
        "application/vnd.control-assurance.s3-object-lock-custody.v1+json"
    ]
    object_digest: str = Field(pattern=_DIGEST_PATTERN)
    object_key_digest: str = Field(pattern=_DIGEST_PATTERN)
    retain_until: str
    retention_mode: Literal["COMPLIANCE"]
    schema_version: Literal["1.0.0"]
    tenant_scope_digest: str = Field(pattern=_DIGEST_PATTERN)
    version_id: str

    @model_validator(mode="after")
    def acknowledgement_is_valid(self) -> CustodyAcknowledgementRecord:
        self.as_acknowledgement()
        return self

    def as_acknowledgement(self) -> S3CustodyAcknowledgement:
        try:
            return S3CustodyAcknowledgement(
                **self.model_dump(mode="python", warnings="error")
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("S3 custody acknowledgement is invalid") from exc

    @classmethod
    def from_acknowledgement(
        cls,
        acknowledgement: S3CustodyAcknowledgement,
    ) -> CustodyAcknowledgementRecord:
        if not isinstance(acknowledgement, S3CustodyAcknowledgement):
            raise TypeError("acknowledgement must be S3CustodyAcknowledgement")
        return cls.model_validate(acknowledgement.to_document(), strict=True)


class StreamCustodyScope(_StrictFrozenModel):
    bucket_arn_digest: str = Field(pattern=_DIGEST_PATTERN)
    cab_scope_digest: str = Field(pattern=_DIGEST_PATTERN)
    encryption: Literal["aws:kms", "aws:kms:dsse"]
    kms_key_arn_digest: str = Field(pattern=_DIGEST_PATTERN)
    retain_until: str
    retention_mode: Literal["COMPLIANCE"]
    tenant_scope_digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("retain_until")
    @classmethod
    def retention_is_canonical(cls, value: str) -> str:
        _parse_utc_second(value)
        return value

    @classmethod
    def from_acknowledgement(
        cls,
        acknowledgement: S3CustodyAcknowledgement,
    ) -> StreamCustodyScope:
        return cls(
            bucket_arn_digest=acknowledgement.bucket_arn_digest,
            cab_scope_digest=acknowledgement.cab_scope_digest,
            encryption=cast(
                Literal["aws:kms", "aws:kms:dsse"],
                acknowledgement.encryption,
            ),
            kms_key_arn_digest=acknowledgement.kms_key_arn_digest,
            retain_until=acknowledgement.retain_until,
            retention_mode="COMPLIANCE",
            tenant_scope_digest=acknowledgement.tenant_scope_digest,
        )


class StreamCustodyObject(_StrictFrozenModel):
    role: Literal["snapshot-descriptor", "cab-blob"]
    digest: str = Field(pattern=_DIGEST_PATTERN)
    size: int = Field(ge=0)
    paths: tuple[str, ...] = Field(
        min_length=1,
        max_length=MAX_STREAM_SNAPSHOT_FILES,
    )
    acknowledgement: CustodyAcknowledgementRecord

    _paths_are_immutable = field_validator("paths", mode="before")(
        _tuple_from_json_array
    )

    @field_validator("paths")
    @classmethod
    def paths_are_sorted_and_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(value)) or len(value) != len(set(value)):
            raise ValueError("custodied object paths must be sorted and unique")
        if any(
            type(path) is not str
            or not path
            or len(path) > 1_024
            or any(ord(character) < 0x20 for character in path)
            for path in value
        ):
            raise ValueError("custodied object path is invalid")
        return value

    @model_validator(mode="after")
    def object_matches_acknowledgement(self) -> StreamCustodyObject:
        if self.acknowledgement.object_digest != self.digest:
            raise ValueError("custodied object digest does not match its acknowledgement")
        if self.role == "snapshot-descriptor":
            if self.paths != ("snapshot.json",):
                raise ValueError("snapshot descriptor must have its exact logical path")
        elif "snapshot.json" in self.paths:
            raise ValueError("CAB blob cannot claim the snapshot descriptor path")
        return self


class StreamCustodyReceipt(_StrictFrozenModel):
    media_type: Literal[
        "application/vnd.control-assurance.stream-custody-receipt.v1+json"
    ] = STREAM_CUSTODY_RECEIPT_MEDIA_TYPE
    schema_version: Literal["1.0.0"] = STREAM_CUSTODY_SCHEMA_VERSION
    snapshot_media_type: Literal[
        "application/vnd.control-assurance.cab-stream-snapshot.v2+json"
    ] = STREAM_SNAPSHOT_MEDIA_TYPE
    snapshot_schema_version: Literal["2.0.0"] = STREAM_SNAPSHOT_SCHEMA_VERSION
    snapshot_digest: str = Field(pattern=_DIGEST_PATTERN)
    cab_id: str = Field(pattern=r"^cab:sha256:[a-f0-9]{64}$")
    manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    descriptor_size: int = Field(ge=1, le=MAX_STREAM_SNAPSHOT_MANIFEST_BYTES)
    file_count: int = Field(ge=1, le=MAX_STREAM_SNAPSHOT_FILES)
    total_bytes: int = Field(ge=1, le=MAX_STREAM_SNAPSHOT_TOTAL_BYTES)
    object_count: int = Field(ge=2, le=_MAX_CUSTODY_OBJECTS)
    custody: StreamCustodyScope
    objects: tuple[StreamCustodyObject, ...] = Field(
        min_length=2,
        max_length=_MAX_CUSTODY_OBJECTS,
    )

    _objects_are_immutable = field_validator("objects", mode="before")(
        _tuple_from_json_array
    )

    @model_validator(mode="after")
    def receipt_is_closed(self) -> StreamCustodyReceipt:
        if self.object_count != len(self.objects):
            raise ValueError("object count does not close over custody objects")
        descriptor = self.objects[0]
        blobs = self.objects[1:]
        if (
            descriptor.role != "snapshot-descriptor"
            or descriptor.digest != self.snapshot_digest
            or descriptor.size != self.descriptor_size
        ):
            raise ValueError("first custody object must be the exact descriptor")
        if any(item.role != "cab-blob" for item in blobs):
            raise ValueError("all remaining custody objects must be CAB blobs")
        blob_digests = tuple(item.digest for item in blobs)
        if blob_digests != tuple(sorted(blob_digests)):
            raise ValueError("CAB custody objects must be sorted by digest")
        all_digests = tuple(item.digest for item in self.objects)
        if len(all_digests) != len(set(all_digests)):
            raise ValueError("custody object digests must be unique")
        for item in self.objects:
            acknowledgement = item.acknowledgement
            if (
                acknowledgement.bucket_arn_digest != self.custody.bucket_arn_digest
                or acknowledgement.cab_scope_digest != self.custody.cab_scope_digest
                or acknowledgement.encryption != self.custody.encryption
                or acknowledgement.kms_key_arn_digest
                != self.custody.kms_key_arn_digest
                or acknowledgement.retain_until != self.custody.retain_until
                or acknowledgement.retention_mode
                != self.custody.retention_mode
                or acknowledgement.tenant_scope_digest
                != self.custody.tenant_scope_digest
            ):
                raise ValueError("custody acknowledgements do not share one exact scope")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            self.model_dump(mode="json", warnings="error"),
            limits=_DOCUMENT_LIMITS,
        )

    def receipt_digest(self) -> str:
        return _sha256(self.canonical_bytes())


class SignedStreamCustodyClosure(_StrictFrozenModel):
    media_type: Literal[
        "application/vnd.control-assurance.signed-stream-custody.v1+json"
    ] = SIGNED_STREAM_CUSTODY_MEDIA_TYPE
    schema_version: Literal["1.0.0"] = STREAM_CUSTODY_SCHEMA_VERSION
    signature_domain: Literal[
        "control-assurance:stream-custody-receipt:v1"
    ] = STREAM_CUSTODY_SIGNATURE_DOMAIN
    receipt_digest: str = Field(pattern=_DIGEST_PATTERN)
    signer_public_key_fingerprint: str = Field(pattern=_DIGEST_PATTERN)
    receipt: StreamCustodyReceipt
    signature: DetachedSignature

    @model_validator(mode="after")
    def digest_closes_over_receipt(self) -> SignedStreamCustodyClosure:
        if self.receipt.receipt_digest() != self.receipt_digest:
            raise ValueError("signed closure digest does not match its receipt")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            self.model_dump(mode="json", warnings="error"),
            limits=_DOCUMENT_LIMITS,
        )

    def closure_digest(self) -> str:
        return _sha256(self.canonical_bytes())


@dataclass(frozen=True, slots=True)
class StreamCustodySeal:
    """A locally verified signed closure and its exact S3 version anchor."""

    closure: SignedStreamCustodyClosure
    closure_bytes: bytes
    closure_digest: str
    closure_acknowledgement: S3CustodyAcknowledgement


@dataclass(frozen=True, slots=True)
class StreamCustodyVerification:
    closure: SignedStreamCustodyClosure
    closure_digest: str
    snapshot_digest: str
    object_count: int
    exact_versions_reverified: bool


def _signing_message(receipt_digest: str) -> bytes:
    if re.fullmatch(_DIGEST_PATTERN, receipt_digest) is None:
        raise ValueError("receipt digest is not canonical SHA-256")
    digest_bytes = bytes.fromhex(receipt_digest.removeprefix("sha256:"))
    return _SIGNATURE_PREFIX + len(digest_bytes).to_bytes(2, "big") + digest_bytes


def _signer_material(
    signer: LeaseAuthorityVerifier,
) -> tuple[str, bytes, str]:
    try:
        key_id = signer.key_id
        public_key_bytes = signer.public_key_bytes
    except Exception:
        raise StreamCustodyError(
            "signer",
            "receipt signer key material is unavailable",
        ) from None
    if (
        type(key_id) is not str
        or not key_id
        or len(key_id) > 256
        or type(public_key_bytes) is not bytes
        or len(public_key_bytes) != 32
    ):
        raise StreamCustodyError(
            "signer",
            "receipt signer does not expose a pinned Ed25519 identity",
        )
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes)
    except ValueError:
        raise StreamCustodyError(
            "signer",
            "receipt signer public key is not Ed25519",
        ) from None
    return key_id, public_key_bytes, _sha256(public_key_bytes)


def _verify_signature(
    closure: SignedStreamCustodyClosure,
    *,
    signer_key_id: str,
    signer_public_key_bytes: bytes,
    signer_fingerprint: str,
) -> None:
    if (
        closure.signer_public_key_fingerprint != signer_fingerprint
        or closure.signature.key_id != signer_key_id
        or closure.signature.algorithm != "ed25519"
    ):
        raise StreamCustodyError(
            "signature",
            "signed closure does not match the pinned signer identity",
        )
    try:
        encoded = closure.signature.signature.encode("ascii", errors="strict")
        signature = base64.b64decode(encoded, validate=True)
        if len(signature) != 64 or base64.b64encode(signature) != encoded:
            raise ValueError
        Ed25519PublicKey.from_public_bytes(signer_public_key_bytes).verify(
            signature,
            _signing_message(closure.receipt_digest),
        )
    except (
        InvalidSignature,
        UnicodeEncodeError,
        ValueError,
        binascii.Error,
    ):
        raise StreamCustodyError(
            "signature",
            "signed closure failed local Ed25519 verification",
        ) from None


def _parse_descriptor(
    descriptor_bytes: bytes,
    *,
    expected_snapshot_digest: str,
    limits: StreamSnapshotLimits,
) -> StreamSnapshotDescriptor:
    if type(descriptor_bytes) is not bytes:
        raise TypeError("snapshot descriptor must be immutable bytes")
    if not isinstance(limits, StreamSnapshotLimits):
        raise TypeError("limits must be StreamSnapshotLimits")
    if len(descriptor_bytes) > limits.max_manifest_bytes:
        raise StreamCustodyError(
            "descriptor",
            "snapshot descriptor exceeds the configured limit",
        )
    try:
        document = strict_json_loads(descriptor_bytes, limits=_DESCRIPTOR_LIMITS)
        descriptor = StreamSnapshotDescriptor.model_validate(document, strict=True)
    except (StrictJSONError, TypeError, ValueError):
        raise StreamCustodyError(
            "descriptor",
            "snapshot descriptor is invalid",
        ) from None
    if (
        descriptor.canonical_bytes() != descriptor_bytes
        or descriptor.snapshot_digest() != expected_snapshot_digest
        or descriptor.file_count > limits.max_files
        or descriptor.total_bytes > limits.max_total_bytes
        or descriptor.entries[0].size > limits.max_manifest_bytes
        or any(entry.size > limits.max_file_bytes for entry in descriptor.entries)
    ):
        raise StreamCustodyError(
            "descriptor",
            "snapshot descriptor is noncanonical, unbounded, or has the wrong digest",
        )
    return descriptor


def _blob_set(
    descriptor: StreamSnapshotDescriptor,
) -> tuple[tuple[str, int, tuple[str, ...]], ...]:
    grouped: dict[str, tuple[int, list[str]]] = {}
    for entry in descriptor.entries:
        existing = grouped.get(entry.digest)
        if existing is None:
            grouped[entry.digest] = (entry.size, [entry.path])
        else:
            size, paths = existing
            if size != entry.size:
                raise StreamCustodyError(
                    "descriptor",
                    "shared descriptor digest has conflicting sizes",
                )
            paths.append(entry.path)
    return tuple(
        (digest, size, tuple(sorted(paths)))
        for digest, (size, paths) in sorted(grouped.items())
    )


def _ack_matches_scope(
    acknowledgement: S3CustodyAcknowledgement,
    scope: StreamCustodyScope,
) -> bool:
    return (
        acknowledgement.bucket_arn_digest == scope.bucket_arn_digest
        and acknowledgement.cab_scope_digest == scope.cab_scope_digest
        and acknowledgement.encryption == scope.encryption
        and acknowledgement.kms_key_arn_digest == scope.kms_key_arn_digest
        and acknowledgement.retain_until == scope.retain_until
        and acknowledgement.retention_mode == scope.retention_mode
        and acknowledgement.tenant_scope_digest == scope.tenant_scope_digest
    )


def _parse_closure(payload: bytes) -> SignedStreamCustodyClosure:
    if type(payload) is not bytes:
        raise TypeError("signed closure must be immutable bytes")
    try:
        document = strict_json_loads(payload, limits=_DOCUMENT_LIMITS)
        closure = SignedStreamCustodyClosure.model_validate(document, strict=True)
    except (StrictJSONError, TypeError, ValueError):
        raise StreamCustodyError(
            "closure",
            "signed stream-custody closure is invalid",
        ) from None
    if closure.canonical_bytes() != payload:
        raise StreamCustodyError(
            "closure",
            "signed stream-custody closure is not canonical JSON",
        )
    return closure


def _object_claims(
    receipt: StreamCustodyReceipt,
) -> tuple[tuple[str, str, int, tuple[str, ...]], ...]:
    return tuple(
        (item.role, item.digest, item.size, item.paths)
        for item in receipt.objects
    )


def verify_stream_custody_closure(
    closure_bytes: bytes,
    closure_acknowledgement: S3CustodyAcknowledgement,
    descriptor_bytes: bytes,
    *,
    expected_snapshot_digest: str,
    tenant_id: str,
    custody: StreamCustodyAdapter,
    receipt_signer: LeaseAuthorityVerifier,
    online_reverify: bool = False,
    limits: StreamSnapshotLimits = _DEFAULT_LIMITS,
) -> StreamCustodyVerification:
    """Verify exact-set closure offline, with optional exact-version S3 reads.

    The default path uses only pinned public-key material and the custody
    adapter's local scope calculation.  It does not call the signer or S3.
    ``online_reverify=True`` additionally reopens every component and the
    closure by their acknowledged VersionIds.
    """

    if type(online_reverify) is not bool:
        raise TypeError("online_reverify must be a boolean")
    closure = _parse_closure(closure_bytes)
    descriptor = _parse_descriptor(
        descriptor_bytes,
        expected_snapshot_digest=expected_snapshot_digest,
        limits=limits,
    )
    receipt = closure.receipt
    if (
        receipt.snapshot_digest != expected_snapshot_digest
        or receipt.cab_id != descriptor.cab_id
        or receipt.manifest_digest != descriptor.manifest_digest
        or receipt.descriptor_size != len(descriptor_bytes)
        or receipt.file_count != descriptor.file_count
        or receipt.total_bytes != descriptor.total_bytes
    ):
        raise StreamCustodyError(
            "closure",
            "signed receipt does not identify the supplied snapshot descriptor",
        )

    expected_blobs = _blob_set(descriptor)
    if expected_snapshot_digest in {digest for digest, _size, _paths in expected_blobs}:
        raise StreamCustodyError(
            "descriptor",
            "descriptor digest overlaps a CAB blob digest",
        )
    expected_claims = (
        (
            "snapshot-descriptor",
            expected_snapshot_digest,
            len(descriptor_bytes),
            ("snapshot.json",),
        ),
        *(
            ("cab-blob", digest, size, paths)
            for digest, size, paths in expected_blobs
        ),
    )
    if _object_claims(receipt) != expected_claims:
        raise StreamCustodyError(
            "closure",
            "signed receipt does not close over the exact descriptor object set",
        )

    signer_key_id, signer_public_key_bytes, signer_fingerprint = _signer_material(
        receipt_signer
    )
    _verify_signature(
        closure,
        signer_key_id=signer_key_id,
        signer_public_key_bytes=signer_public_key_bytes,
        signer_fingerprint=signer_fingerprint,
    )

    if not isinstance(closure_acknowledgement, S3CustodyAcknowledgement):
        raise TypeError("closure acknowledgement must be S3CustodyAcknowledgement")
    closure_digest = _sha256(closure_bytes)
    if (
        closure_acknowledgement.object_digest != closure_digest
        or not _ack_matches_scope(closure_acknowledgement, receipt.custody)
    ):
        raise StreamCustodyError(
            "custody",
            "signed closure acknowledgement does not share the receipt custody scope",
        )

    component_acks: list[tuple[S3CustodyAcknowledgement, int]] = []
    try:
        for item in receipt.objects:
            acknowledgement = item.acknowledgement.as_acknowledgement()
            if (
                not _ack_matches_scope(acknowledgement, receipt.custody)
                or not custody.verify_acknowledgement_scope(
                    acknowledgement,
                    tenant_id=tenant_id,
                    cab_id=descriptor.cab_id,
                )
            ):
                raise StreamCustodyError(
                    "custody",
                    "component acknowledgement is outside the pinned custody scope",
                )
            component_acks.append((acknowledgement, item.size))
        if not custody.verify_acknowledgement_scope(
            closure_acknowledgement,
            tenant_id=tenant_id,
            cab_id=descriptor.cab_id,
        ):
            raise StreamCustodyError(
                "custody",
                "closure acknowledgement is outside the pinned custody scope",
            )
    except StreamCustodyError:
        raise
    except Exception:
        raise StreamCustodyError(
            "custody",
            "custody scope verification failed",
        ) from None

    if online_reverify:
        try:
            for acknowledgement, size in component_acks:
                observed = custody.reverify_acknowledgement(
                    acknowledgement,
                    tenant_id=tenant_id,
                    cab_id=descriptor.cab_id,
                    expected_size=size,
                )
                if (
                    observed.to_canonical_bytes()
                    != acknowledgement.to_canonical_bytes()
                ):
                    raise StreamCustodyError(
                        "remote_reverify",
                        "remote component acknowledgement changed",
                    )
            observed_closure = custody.reverify_acknowledgement(
                closure_acknowledgement,
                tenant_id=tenant_id,
                cab_id=descriptor.cab_id,
                expected_size=len(closure_bytes),
            )
            if (
                observed_closure.to_canonical_bytes()
                != closure_acknowledgement.to_canonical_bytes()
            ):
                raise StreamCustodyError(
                    "remote_reverify",
                    "remote closure acknowledgement changed",
                )
        except StreamCustodyError:
            raise
        except Exception:
            raise StreamCustodyError(
                "remote_reverify",
                "exact S3 version re-verification failed",
            ) from None

    return StreamCustodyVerification(
        closure=closure,
        closure_digest=closure_digest,
        snapshot_digest=expected_snapshot_digest,
        object_count=receipt.object_count,
        exact_versions_reverified=online_reverify,
    )


def _put_bytes(
    custody: StreamCustodyAdapter,
    payload: bytes,
    *,
    tenant_id: str,
    cab_id: str,
    retain_until: datetime,
    expected_object_digest: str,
) -> S3CustodyAcknowledgement:
    try:
        acknowledgement = custody.put_bytes(
            payload,
            tenant_id=tenant_id,
            cab_id=cab_id,
            retain_until=retain_until,
            expected_object_digest=expected_object_digest,
        )
        if not isinstance(acknowledgement, S3CustodyAcknowledgement):
            raise TypeError
        return acknowledgement
    except S3ObjectLockError as exc:
        raise StreamCustodyError(
            f"custody:{exc.stage}",
            "S3 Object Lock custody operation failed",
        ) from None
    except Exception:
        raise StreamCustodyError(
            "custody",
            "stream custody operation failed",
        ) from None


def _put_file(
    custody: StreamCustodyAdapter,
    source: Path,
    *,
    tenant_id: str,
    cab_id: str,
    retain_until: datetime,
    expected_object_digest: str,
) -> S3CustodyAcknowledgement:
    try:
        acknowledgement = custody.put_file(
            source,
            tenant_id=tenant_id,
            cab_id=cab_id,
            retain_until=retain_until,
            expected_object_digest=expected_object_digest,
        )
        if not isinstance(acknowledgement, S3CustodyAcknowledgement):
            raise TypeError
        return acknowledgement
    except S3ObjectLockError as exc:
        raise StreamCustodyError(
            f"custody:{exc.stage}",
            "S3 Object Lock custody operation failed",
        ) from None
    except Exception:
        raise StreamCustodyError(
            "custody",
            "stream custody operation failed",
        ) from None


def _require_local_scope(
    custody: StreamCustodyAdapter,
    acknowledgement: S3CustodyAcknowledgement,
    *,
    tenant_id: str,
    cab_id: str,
) -> None:
    try:
        matches = custody.verify_acknowledgement_scope(
            acknowledgement,
            tenant_id=tenant_id,
            cab_id=cab_id,
        )
    except Exception:
        matches = False
    if matches is not True:
        raise StreamCustodyError(
            "custody",
            "custody acknowledgement is outside the pinned local scope",
        )


def seal_streamed_cab_snapshot(
    snapshot_root: Path,
    *,
    expected_snapshot_digest: str,
    tenant_id: str,
    retain_until: datetime,
    custody: StreamCustodyAdapter,
    receipt_signer: ReceiptSigner,
    limits: StreamSnapshotLimits = _DEFAULT_LIMITS,
) -> StreamCustodySeal:
    """Close, sign, and Object-Lock one already captured v2 CAB snapshot.

    All writes are content-addressed and conditional.  A crash after any
    successful PutObject is therefore retried by reopening and reconciling the
    same exact object version; a conflicting retention, scope, KMS pin, or byte
    sequence fails closed instead of creating a second logical result.
    """

    try:
        snapshot = verify_streamed_cab_snapshot(
            snapshot_root,
            expected_snapshot_digest=expected_snapshot_digest,
            limits=limits,
        )
    except StreamSnapshotError:
        raise StreamCustodyError(
            "snapshot",
            "stream snapshot failed pre-custody verification",
        ) from None
    blobs = _blob_set(snapshot.descriptor)
    if expected_snapshot_digest in {digest for digest, _size, _paths in blobs}:
        raise StreamCustodyError(
            "snapshot",
            "descriptor digest overlaps a CAB blob digest",
        )

    descriptor_ack = _put_bytes(
        custody,
        snapshot.descriptor_bytes,
        tenant_id=tenant_id,
        cab_id=snapshot.cab_id,
        retain_until=retain_until,
        expected_object_digest=snapshot.snapshot_digest,
    )
    _require_local_scope(
        custody,
        descriptor_ack,
        tenant_id=tenant_id,
        cab_id=snapshot.cab_id,
    )
    try:
        objects: list[StreamCustodyObject] = [
            StreamCustodyObject(
                role="snapshot-descriptor",
                digest=snapshot.snapshot_digest,
                size=len(snapshot.descriptor_bytes),
                paths=("snapshot.json",),
                acknowledgement=CustodyAcknowledgementRecord.from_acknowledgement(
                    descriptor_ack
                ),
            )
        ]
    except (TypeError, ValueError):
        raise StreamCustodyError(
            "custody",
            "descriptor custody acknowledgement is invalid",
        ) from None
    for digest, size, paths in blobs:
        acknowledgement = _put_file(
            custody,
            snapshot.root / "blobs" / digest.removeprefix("sha256:"),
            tenant_id=tenant_id,
            cab_id=snapshot.cab_id,
            retain_until=retain_until,
            expected_object_digest=digest,
        )
        _require_local_scope(
            custody,
            acknowledgement,
            tenant_id=tenant_id,
            cab_id=snapshot.cab_id,
        )
        try:
            objects.append(
                StreamCustodyObject(
                    role="cab-blob",
                    digest=digest,
                    size=size,
                    paths=paths,
                    acknowledgement=CustodyAcknowledgementRecord.from_acknowledgement(
                        acknowledgement
                    ),
                )
            )
        except (TypeError, ValueError):
            raise StreamCustodyError(
                "custody",
                "CAB blob custody acknowledgement is invalid",
            ) from None

    try:
        closed_snapshot = verify_streamed_cab_snapshot(
            snapshot_root,
            expected_snapshot_digest=expected_snapshot_digest,
            limits=limits,
        )
    except StreamSnapshotError:
        raise StreamCustodyError(
            "snapshot",
            "stream snapshot changed during component custody",
        ) from None
    if (
        closed_snapshot.descriptor_bytes != snapshot.descriptor_bytes
        or closed_snapshot.descriptor != snapshot.descriptor
    ):
        raise StreamCustodyError(
            "snapshot",
            "stream snapshot identity changed during component custody",
        )

    try:
        receipt = StreamCustodyReceipt(
            snapshot_digest=snapshot.snapshot_digest,
            cab_id=snapshot.cab_id,
            manifest_digest=snapshot.manifest_digest,
            descriptor_size=len(snapshot.descriptor_bytes),
            file_count=snapshot.file_count,
            total_bytes=snapshot.total_bytes,
            object_count=len(objects),
            custody=StreamCustodyScope.from_acknowledgement(descriptor_ack),
            objects=tuple(objects),
        )
    except (TypeError, ValueError):
        raise StreamCustodyError(
            "custody",
            "component acknowledgements do not form one closed custody receipt",
        ) from None
    receipt_digest = receipt.receipt_digest()
    signer_key_id, signer_public_key_bytes, signer_fingerprint = _signer_material(
        receipt_signer
    )
    try:
        signature = receipt_signer.sign(_signing_message(receipt_digest))
    except Exception:
        raise StreamCustodyError(
            "signer",
            "receipt signer could not sign the stream-custody receipt",
        ) from None
    if not isinstance(signature, DetachedSignature):
        raise StreamCustodyError(
            "signer",
            "receipt signer returned no valid detached signature",
        )
    if _signer_material(receipt_signer) != (
        signer_key_id,
        signer_public_key_bytes,
        signer_fingerprint,
    ):
        raise StreamCustodyError(
            "signer",
            "receipt signer identity changed during signing",
        )
    try:
        closure = SignedStreamCustodyClosure(
            receipt_digest=receipt_digest,
            signer_public_key_fingerprint=signer_fingerprint,
            receipt=receipt,
            signature=signature,
        )
    except (TypeError, ValueError):
        raise StreamCustodyError(
            "signer",
            "receipt signer returned an invalid detached signature",
        ) from None
    _verify_signature(
        closure,
        signer_key_id=signer_key_id,
        signer_public_key_bytes=signer_public_key_bytes,
        signer_fingerprint=signer_fingerprint,
    )
    closure_bytes = closure.canonical_bytes()
    closure_digest = _sha256(closure_bytes)
    closure_acknowledgement = _put_bytes(
        custody,
        closure_bytes,
        tenant_id=tenant_id,
        cab_id=snapshot.cab_id,
        retain_until=retain_until,
        expected_object_digest=closure_digest,
    )
    _require_local_scope(
        custody,
        closure_acknowledgement,
        tenant_id=tenant_id,
        cab_id=snapshot.cab_id,
    )
    verify_stream_custody_closure(
        closure_bytes,
        closure_acknowledgement,
        snapshot.descriptor_bytes,
        expected_snapshot_digest=expected_snapshot_digest,
        tenant_id=tenant_id,
        custody=custody,
        receipt_signer=receipt_signer,
        online_reverify=False,
        limits=limits,
    )
    return StreamCustodySeal(
        closure=closure,
        closure_bytes=closure_bytes,
        closure_digest=closure_digest,
        closure_acknowledgement=closure_acknowledgement,
    )


def describe_custody_objects(
    snapshot: StreamedCABSnapshot,
) -> Mapping[str, tuple[str, ...]]:
    """Return the deterministic digest-to-path closure used by operators."""

    if not isinstance(snapshot, StreamedCABSnapshot):
        raise TypeError("snapshot must be a verified StreamedCABSnapshot")
    return {
        digest: paths
        for digest, _size, paths in _blob_set(snapshot.descriptor)
    }


__all__ = [
    "MAX_STREAM_CUSTODY_DOCUMENT_BYTES",
    "SIGNED_STREAM_CUSTODY_MEDIA_TYPE",
    "STREAM_CUSTODY_RECEIPT_MEDIA_TYPE",
    "STREAM_CUSTODY_SCHEMA_VERSION",
    "STREAM_CUSTODY_SIGNATURE_DOMAIN",
    "CustodyAcknowledgementRecord",
    "SignedStreamCustodyClosure",
    "StreamCustodyAdapter",
    "StreamCustodyError",
    "StreamCustodyObject",
    "StreamCustodyReceipt",
    "StreamCustodyScope",
    "StreamCustodySeal",
    "StreamCustodyVerification",
    "describe_custody_objects",
    "seal_streamed_cab_snapshot",
    "verify_stream_custody_closure",
]
