"""S3 Object Lock custody for content-addressed evidence.

The adapter writes one regular file to one pinned, versioned S3 bucket with an
explicit COMPLIANCE retention date and a pinned KMS key.  A successful
``PutObject`` response is not treated as custody proof: the exact returned
version is checked with both ``HeadObject`` and ``GetObject``, and the retrieved
bytes are hashed again through a bounded reader.

The S3 client is injected behind a deliberately small protocol.  Boto3 is an
optional deployment dependency and is imported only by
``create_boto3_s3_client``.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import importlib
import io
import math
import os
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, Protocol, cast, runtime_checkable

from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)

S3_OBJECT_LOCK_CUSTODY_MEDIA_TYPE: Final = (
    "application/vnd.control-assurance.s3-object-lock-custody.v1+json"
)
S3_OBJECT_LOCK_CUSTODY_SCHEMA_VERSION: Final = "1.0.0"

DEFAULT_MAX_OBJECT_BYTES: Final = 256 * 1024 * 1024
MAX_SINGLE_PUT_BYTES: Final = 5 * 1024 * 1024 * 1024
MIN_RETENTION_SECONDS: Final = 60
MAX_RETENTION_SECONDS: Final = 100 * 366 * 24 * 60 * 60
_CHUNK_BYTES: Final = 1024 * 1024
_ACK_LIMITS = JSONLimits(
    max_bytes=32 * 1024,
    max_line_bytes=32 * 1024,
    max_depth=4,
    max_collection_items=32,
    max_string_length=2 * 1024,
)

_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_CHECKSUM_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_IDENTITY_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,1024}$")
_BUCKET_NAME_RE = re.compile(
    r"^(?!xn--)(?!.*\.\.)(?!.*-\.)"
    r"[a-z0-9](?:[a-z0-9.-]{1,61}[a-z0-9])$"
)
_BUCKET_ARN_RE = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):s3:::"
    r"([a-z0-9](?:[a-z0-9.-]{1,61}[a-z0-9]))$"
)
_KMS_KEY_ARN_RE = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):kms:"
    r"([a-z0-9-]{3,32}):([0-9]{12}):"
    r"key/("
    r"(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
    r"|(?:mrk-[0-9a-fA-F]{32})"
    r")$"
)
_OWNER_RE = re.compile(r"^[0-9]{12}$")
_OBJECT_KEY_PREFIX: Final = "control-assurance/custody/v1"
_SOURCE_FLAGS = (
    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
)
_REQUIRED_METADATA_KEYS = frozenset(
    {
        "cab-scope-sha256",
        "custody-profile",
        "object-sha256",
        "tenant-scope-sha256",
    }
)


class S3ObjectLockError(RuntimeError):
    """Stable, endpoint-free, credential-free failure at the custody boundary."""

    __slots__ = ("stage",)

    def __init__(self, stage: str, detail: str) -> None:
        super().__init__(detail)
        self.stage = stage


@runtime_checkable
class S3ObjectLockClient(Protocol):
    """Only the five read/write calls the custody adapter is allowed to make."""

    def get_bucket_versioning(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def get_object_lock_configuration(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def put_object(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def head_object(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def get_object(self, **kwargs: Any) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class S3RetentionPolicy:
    """Local bounds that must also be enforced by the S3 bucket policy."""

    minimum_seconds: int
    maximum_seconds: int
    max_object_bytes: int = DEFAULT_MAX_OBJECT_BYTES

    def __post_init__(self) -> None:
        if (
            type(self.minimum_seconds) is not int
            or not MIN_RETENTION_SECONDS
            <= self.minimum_seconds
            <= MAX_RETENTION_SECONDS
        ):
            raise ValueError("minimum retention is outside the supported range")
        if (
            type(self.maximum_seconds) is not int
            or self.maximum_seconds < self.minimum_seconds
            or self.maximum_seconds > MAX_RETENTION_SECONDS
        ):
            raise ValueError("maximum retention is outside the supported range")
        if (
            type(self.max_object_bytes) is not int
            or self.max_object_bytes < 1
            or self.max_object_bytes > MAX_SINGLE_PUT_BYTES
        ):
            raise ValueError("maximum object size is outside the PutObject range")


@dataclass(frozen=True, slots=True)
class S3CustodyAcknowledgement:
    """Canonical, non-secret proof of the exact S3 version checked by the client."""

    bucket_arn_digest: str
    cab_scope_digest: str
    checksum_sha256: str
    encryption: str
    kms_key_arn_digest: str
    object_digest: str
    object_key_digest: str
    retain_until: str
    tenant_scope_digest: str
    version_id: str
    media_type: str = S3_OBJECT_LOCK_CUSTODY_MEDIA_TYPE
    retention_mode: str = "COMPLIANCE"
    schema_version: str = S3_OBJECT_LOCK_CUSTODY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in (
            "bucket_arn_digest",
            "cab_scope_digest",
            "kms_key_arn_digest",
            "object_digest",
            "object_key_digest",
            "tenant_scope_digest",
        ):
            if _DIGEST_RE.fullmatch(cast(str, getattr(self, name))) is None:
                raise ValueError(f"{name} is not a canonical SHA-256 digest")
        _decode_checksum(self.checksum_sha256)
        if self.checksum_sha256 != _checksum_for_digest(self.object_digest):
            raise ValueError("S3 checksum and object digest do not match")
        if self.encryption not in {"aws:kms", "aws:kms:dsse"}:
            raise ValueError("unsupported custody encryption algorithm")
        if self.media_type != S3_OBJECT_LOCK_CUSTODY_MEDIA_TYPE:
            raise ValueError("unexpected custody acknowledgement media type")
        if self.retention_mode != "COMPLIANCE":
            raise ValueError("custody acknowledgement is not COMPLIANCE locked")
        if self.schema_version != S3_OBJECT_LOCK_CUSTODY_SCHEMA_VERSION:
            raise ValueError("unsupported custody acknowledgement version")
        _parse_utc_second(self.retain_until)
        if not _valid_version_id(self.version_id):
            raise ValueError("invalid S3 version ID")

    def to_document(self) -> dict[str, str]:
        return {
            "bucket_arn_digest": self.bucket_arn_digest,
            "cab_scope_digest": self.cab_scope_digest,
            "checksum_sha256": self.checksum_sha256,
            "encryption": self.encryption,
            "kms_key_arn_digest": self.kms_key_arn_digest,
            "media_type": self.media_type,
            "object_digest": self.object_digest,
            "object_key_digest": self.object_key_digest,
            "retain_until": self.retain_until,
            "retention_mode": self.retention_mode,
            "schema_version": self.schema_version,
            "tenant_scope_digest": self.tenant_scope_digest,
            "version_id": self.version_id,
        }

    def to_canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_document(), limits=_ACK_LIMITS)

    @property
    def acknowledgement_digest(self) -> str:
        return _sha256_digest(self.to_canonical_bytes())

    @classmethod
    def from_canonical_bytes(cls, payload: bytes) -> S3CustodyAcknowledgement:
        try:
            document = strict_json_loads(payload, limits=_ACK_LIMITS)
        except StrictJSONError as exc:
            raise S3ObjectLockError(
                "acknowledgement",
                "custody acknowledgement is not strict JSON",
            ) from exc
        if not isinstance(document, dict) or set(document) != {
            "bucket_arn_digest",
            "cab_scope_digest",
            "checksum_sha256",
            "encryption",
            "kms_key_arn_digest",
            "media_type",
            "object_digest",
            "object_key_digest",
            "retain_until",
            "retention_mode",
            "schema_version",
            "tenant_scope_digest",
            "version_id",
        }:
            raise S3ObjectLockError(
                "acknowledgement",
                "custody acknowledgement has the wrong members",
            )
        if not all(type(value) is str for value in document.values()):
            raise S3ObjectLockError(
                "acknowledgement",
                "custody acknowledgement members must be strings",
            )
        try:
            acknowledgement = cls(**cast(dict[str, str], document))
        except (TypeError, ValueError) as exc:
            raise S3ObjectLockError(
                "acknowledgement",
                "custody acknowledgement is invalid",
            ) from exc
        if acknowledgement.to_canonical_bytes() != payload:
            raise S3ObjectLockError(
                "acknowledgement",
                "custody acknowledgement is not canonical",
            )
        return acknowledgement


@dataclass(frozen=True, slots=True)
class _SourceIdentity:
    device: int
    inode: int
    mode: int
    links: int
    size: int
    mtime_ns: int
    ctime_ns: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> _SourceIdentity:
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            mode=value.st_mode,
            links=value.st_nlink,
            size=value.st_size,
            mtime_ns=value.st_mtime_ns,
            ctime_ns=value.st_ctime_ns,
        )


@dataclass(frozen=True, slots=True)
class _ExpectedObject:
    cab_scope_digest: str
    checksum_sha256: str
    kms_key_arn: str
    metadata: dict[str, str]
    object_digest: str
    object_key: str
    retain_until: datetime
    size: int
    tenant_scope_digest: str


def _sha256_digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _scope_digest(label: bytes, value: str) -> str:
    encoded = value.encode("utf-8", errors="strict")
    framed = label + b"\x00" + len(encoded).to_bytes(4, "big") + encoded
    return _sha256_digest(framed)


def _object_key(
    *,
    tenant_scope_digest: str,
    cab_scope_digest: str,
    object_digest: str,
) -> str:
    return (
        f"{_OBJECT_KEY_PREFIX}/tenants/"
        f"{tenant_scope_digest.removeprefix('sha256:')}/cabs/"
        f"{cab_scope_digest.removeprefix('sha256:')}/objects/sha256/"
        f"{object_digest.removeprefix('sha256:')}"
    )


def _utc_second(value: datetime) -> datetime:
    normalized = _aware_utc(value)
    if normalized.microsecond != 0:
        raise ValueError("retention date must have whole-second precision")
    return normalized


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("retention date must be timezone-aware")
    return value.astimezone(UTC)


def _format_utc_second(value: datetime) -> str:
    return _utc_second(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_utc_second(value: str) -> datetime:
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value):
        raise ValueError("timestamp must be canonical UTC seconds")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError("timestamp is not a real UTC instant") from exc
    return parsed.replace(tzinfo=UTC)


def _decode_checksum(value: str) -> bytes:
    if type(value) is not str or _CHECKSUM_RE.fullmatch(value) is None:
        raise ValueError("checksum is not canonical SHA-256 base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("checksum is not canonical SHA-256 base64") from exc
    if len(decoded) != hashlib.sha256().digest_size:
        raise ValueError("checksum is not 32 bytes")
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("checksum base64 is not canonical")
    return decoded


def _checksum_for_digest(value: str) -> str:
    if _DIGEST_RE.fullmatch(value) is None:
        raise ValueError("object digest is not canonical SHA-256")
    return base64.b64encode(bytes.fromhex(value.removeprefix("sha256:"))).decode("ascii")


def _safe_identity(value: str, *, label: str) -> str:
    if type(value) is not str or _IDENTITY_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a bounded non-control string")
    value.encode("utf-8", errors="strict")
    return value


def _valid_bucket_name(value: str) -> bool:
    if _BUCKET_NAME_RE.fullmatch(value) is None:
        return False
    if re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", value):
        return False
    if value.startswith(("sthree-", "amzn-s3-demo-")):
        return False
    return not value.endswith(
        ("-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3")
    )


def _valid_version_id(value: object) -> bool:
    if type(value) is not str or not value or value == "null":
        return False
    if any(
        ord(character) < 0x20
        or ord(character) == 0x7F
        or 0xD800 <= ord(character) <= 0xDFFF
        for character in value
    ):
        return False
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return False
    return len(encoded) <= 1024


def _response_mapping(value: object, *, stage: str) -> Mapping[str, Any]:
    if type(value) is not dict:
        raise S3ObjectLockError(stage, "S3 returned a malformed response")
    return cast(Mapping[str, Any], value)


def _exception_code(exc: BaseException) -> tuple[str | None, int | None]:
    try:
        response = getattr(exc, "response", None)
        if not isinstance(response, Mapping):
            return None, None
        error = response.get("Error")
        metadata = response.get("ResponseMetadata")
        code: str | None = None
        status: int | None = None
        if isinstance(error, Mapping) and type(error.get("Code")) is str:
            code = cast(str, error["Code"])
        if isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int:
            status = cast(int, metadata["HTTPStatusCode"])
        return code, status
    except Exception:
        return None, None


def _is_not_found(exc: BaseException) -> bool:
    code, status = _exception_code(exc)
    return code in {"404", "NoSuchKey", "NotFound", "NoSuchVersion"} or status == 404


def _is_conditional_conflict(exc: BaseException) -> bool:
    code, status = _exception_code(exc)
    return code in {
        "409",
        "412",
        "ConditionalRequestConflict",
        "PreconditionFailed",
    } or status in {409, 412}


def _close_body(body: object) -> None:
    close = getattr(body, "close", None)
    if callable(close):
        with contextlib.suppress(Exception):
            close()


def _stat_unchanged(file_descriptor: int, expected: _SourceIdentity) -> None:
    try:
        observed = _SourceIdentity.from_stat(os.fstat(file_descriptor))
    except OSError:
        raise S3ObjectLockError("source", "source file could not be restated") from None
    if observed != expected:
        raise S3ObjectLockError("source", "source file changed during custody upload")


class S3ObjectLockCustody:
    """Fail-closed, single-object S3 COMPLIANCE custody adapter."""

    __slots__ = (
        "_bucket_arn",
        "_bucket_arn_digest",
        "_bucket_name",
        "_client",
        "_encryption",
        "_expected_bucket_owner",
        "_kms_key_arn",
        "_kms_key_arn_digest",
        "_now",
        "_policy",
    )

    def __init__(
        self,
        client: S3ObjectLockClient,
        *,
        bucket_name: str,
        bucket_arn: str,
        expected_bucket_owner: str,
        kms_key_arn: str,
        retention_policy: S3RetentionPolicy,
        encryption: str = "aws:kms",
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(client, S3ObjectLockClient):
            raise TypeError("client does not implement the S3 custody protocol")
        if type(bucket_name) is not str or not _valid_bucket_name(bucket_name):
            raise ValueError("bucket name is not a canonical general-purpose name")
        arn_match = _BUCKET_ARN_RE.fullmatch(bucket_arn)
        if (
            arn_match is None
            or arn_match.group(2) != bucket_name
            or not _valid_bucket_name(arn_match.group(2))
        ):
            raise ValueError("bucket ARN does not exactly name the configured bucket")
        kms_match = _KMS_KEY_ARN_RE.fullmatch(kms_key_arn)
        if kms_match is None:
            raise ValueError("KMS key must be a pinned customer-managed key ARN")
        if kms_match.group(1) != arn_match.group(1):
            raise ValueError("bucket and KMS key must use the same AWS partition")
        if _OWNER_RE.fullmatch(expected_bucket_owner) is None:
            raise ValueError("expected bucket owner must be a 12-digit account ID")
        if kms_match.group(3) != expected_bucket_owner:
            raise ValueError("KMS key account must match the expected bucket owner")
        if encryption not in {"aws:kms", "aws:kms:dsse"}:
            raise ValueError("encryption must be SSE-KMS or DSSE-KMS")
        if not isinstance(retention_policy, S3RetentionPolicy):
            raise TypeError("retention_policy must be S3RetentionPolicy")
        self._client = client
        self._bucket_name = bucket_name
        self._bucket_arn = bucket_arn
        self._bucket_arn_digest = _sha256_digest(bucket_arn.encode("ascii"))
        self._expected_bucket_owner = expected_bucket_owner
        self._kms_key_arn = kms_key_arn
        self._kms_key_arn_digest = _sha256_digest(kms_key_arn.encode("ascii"))
        self._encryption = encryption
        self._policy = retention_policy
        self._now = now if now is not None else lambda: datetime.now(UTC)
        self._assert_bucket_ready()

    def __repr__(self) -> str:
        return (
            "S3ObjectLockCustody("
            f"bucket_arn_digest={self._bucket_arn_digest!r}, "
            f"kms_key_arn_digest={self._kms_key_arn_digest!r}, "
            f"encryption={self._encryption!r})"
        )

    @property
    def bucket_arn_digest(self) -> str:
        return self._bucket_arn_digest

    @property
    def kms_key_arn_digest(self) -> str:
        return self._kms_key_arn_digest

    @property
    def bucket_name(self) -> str:
        """Return the exact non-secret bucket name pinned at construction."""

        return self._bucket_name

    @property
    def bucket_arn(self) -> str:
        """Return the exact non-secret bucket ARN pinned at construction."""

        return self._bucket_arn

    @property
    def expected_bucket_owner(self) -> str:
        """Return the AWS account that every request names explicitly."""

        return self._expected_bucket_owner

    @property
    def kms_key_arn(self) -> str:
        """Return the exact customer-managed KMS key ARN."""

        return self._kms_key_arn

    @property
    def encryption(self) -> str:
        """Return the pinned S3 server-side encryption algorithm."""

        return self._encryption

    @property
    def retention_policy(self) -> S3RetentionPolicy:
        """Return the immutable local retention and object-size bounds."""

        return self._policy

    def _assert_bucket_ready(self) -> None:
        try:
            versioning_raw = self._client.get_bucket_versioning(
                Bucket=self._bucket_name,
                ExpectedBucketOwner=self._expected_bucket_owner,
            )
            lock_raw = self._client.get_object_lock_configuration(
                Bucket=self._bucket_name,
                ExpectedBucketOwner=self._expected_bucket_owner,
            )
        except Exception:
            raise S3ObjectLockError(
                "bucket_configuration",
                "S3 bucket custody configuration could not be read",
            ) from None
        versioning = _response_mapping(
            versioning_raw,
            stage="bucket_configuration",
        )
        lock_response = _response_mapping(
            lock_raw,
            stage="bucket_configuration",
        )
        lock_configuration = lock_response.get("ObjectLockConfiguration")
        if (
            versioning.get("Status") != "Enabled"
            or type(lock_configuration) is not dict
            or lock_configuration.get("ObjectLockEnabled") != "Enabled"
        ):
            raise S3ObjectLockError(
                "bucket_configuration",
                "S3 bucket is not versioned with Object Lock enabled",
            )

    def _retention_date(self, value: datetime) -> datetime:
        retain_until = _utc_second(value)
        try:
            now = _aware_utc(self._now())
        except ValueError:
            raise S3ObjectLockError(
                "clock",
                "custody clock did not return a valid UTC instant",
            ) from None
        remaining = (retain_until - now).total_seconds()
        if (
            not math.isfinite(remaining)
            or remaining < self._policy.minimum_seconds
            or remaining > self._policy.maximum_seconds
        ):
            raise S3ObjectLockError(
                "retention",
                "retention date is outside the configured policy bounds",
            )
        return retain_until

    def _open_and_hash(
        self,
        source: Path,
    ) -> tuple[int, _SourceIdentity, str]:
        if not isinstance(source, Path):
            raise TypeError("source must be a pathlib.Path")
        try:
            descriptor = os.open(source, _SOURCE_FLAGS)
        except OSError:
            raise S3ObjectLockError(
                "source",
                "source must be an accessible non-symlink regular file",
            ) from None
        try:
            identity = _SourceIdentity.from_stat(os.fstat(descriptor))
            if (
                not stat.S_ISREG(identity.mode)
                or identity.links != 1
                or identity.size < 0
                or identity.size > self._policy.max_object_bytes
            ):
                raise S3ObjectLockError(
                    "source",
                    "source is not an owner-unique bounded regular file",
                )
            digest = hashlib.sha256()
            remaining = identity.size
            while remaining:
                chunk = os.read(descriptor, min(_CHUNK_BYTES, remaining))
                if not chunk:
                    raise S3ObjectLockError(
                        "source",
                        "source ended before its stated size",
                    )
                digest.update(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise S3ObjectLockError(
                    "source",
                    "source exceeds its stated size",
                )
            _stat_unchanged(descriptor, identity)
            os.lseek(descriptor, 0, os.SEEK_SET)
            return descriptor, identity, f"sha256:{digest.hexdigest()}"
        except BaseException:
            os.close(descriptor)
            raise

    def _expected_object(
        self,
        *,
        tenant_id: str,
        cab_id: str,
        object_digest: str,
        size: int,
        retain_until: datetime,
    ) -> _ExpectedObject:
        tenant_scope_digest = _scope_digest(
            b"control-assurance:s3-custody:tenant:v1",
            _safe_identity(tenant_id, label="tenant ID"),
        )
        cab_scope_digest = _scope_digest(
            b"control-assurance:s3-custody:cab:v1",
            _safe_identity(cab_id, label="CAB ID"),
        )
        key = _object_key(
            tenant_scope_digest=tenant_scope_digest,
            cab_scope_digest=cab_scope_digest,
            object_digest=object_digest,
        )
        metadata = {
            "cab-scope-sha256": cab_scope_digest.removeprefix("sha256:"),
            "custody-profile": "s3-object-lock-v1",
            "object-sha256": object_digest.removeprefix("sha256:"),
            "tenant-scope-sha256": tenant_scope_digest.removeprefix("sha256:"),
        }
        return _ExpectedObject(
            cab_scope_digest=cab_scope_digest,
            checksum_sha256=_checksum_for_digest(object_digest),
            kms_key_arn=self._kms_key_arn,
            metadata=metadata,
            object_digest=object_digest,
            object_key=key,
            retain_until=retain_until,
            size=size,
            tenant_scope_digest=tenant_scope_digest,
        )

    def put_file(
        self,
        source: Path,
        *,
        tenant_id: str,
        cab_id: str,
        retain_until: datetime,
        expected_object_digest: str | None = None,
    ) -> S3CustodyAcknowledgement:
        """Write and independently reopen one exact content-addressed object."""

        retention = self._retention_date(retain_until)
        _safe_identity(tenant_id, label="tenant ID")
        _safe_identity(cab_id, label="CAB ID")
        descriptor, source_identity, observed_digest = self._open_and_hash(source)
        if (
            expected_object_digest is not None
            and expected_object_digest != observed_digest
        ):
            os.close(descriptor)
            raise S3ObjectLockError(
                "source",
                "source digest does not match the external object digest",
            )
        expected = self._expected_object(
            tenant_id=tenant_id,
            cab_id=cab_id,
            object_digest=observed_digest,
            size=source_identity.size,
            retain_until=retention,
        )
        try:
            with os.fdopen(descriptor, "rb", closefd=True) as source_stream:
                self._assert_bucket_ready()
                try:
                    put_raw = self._client.put_object(
                        Body=source_stream,
                        Bucket=self._bucket_name,
                        ChecksumAlgorithm="SHA256",
                        ChecksumSHA256=expected.checksum_sha256,
                        ContentLength=expected.size,
                        ContentType="application/octet-stream",
                        ExpectedBucketOwner=self._expected_bucket_owner,
                        IfNoneMatch="*",
                        Key=expected.object_key,
                        Metadata=expected.metadata,
                        ObjectLockMode="COMPLIANCE",
                        ObjectLockRetainUntilDate=expected.retain_until,
                        SSEKMSKeyId=self._kms_key_arn,
                        ServerSideEncryption=self._encryption,
                    )
                except Exception as put_error:
                    acknowledgement = self._reconcile_after_put_failure(
                        put_error,
                        expected=expected,
                    )
                    _stat_unchanged(source_stream.fileno(), source_identity)
                    self._assert_bucket_ready()
                    return acknowledgement
                put_response = _response_mapping(put_raw, stage="put")
                version_id = self._validate_put_response(put_response, expected)
                acknowledgement = self._verify_version(
                    expected=expected,
                    version_id=version_id,
                )
                _stat_unchanged(source_stream.fileno(), source_identity)
            self._assert_bucket_ready()
            return acknowledgement
        except S3ObjectLockError:
            raise
        except Exception:
            raise S3ObjectLockError(
                "custody",
                "S3 custody operation failed",
            ) from None

    def put_bytes(
        self,
        payload: bytes,
        *,
        tenant_id: str,
        cab_id: str,
        retain_until: datetime,
        expected_object_digest: str | None = None,
    ) -> S3CustodyAcknowledgement:
        """Write immutable bytes and independently reopen their exact S3 version.

        This is intentionally not a general object-upload API.  It has the same
        content-addressed key, conditional create, retention, encryption, and
        read-after-write closure as :meth:`put_file`; it only avoids writing
        small canonical receipts to an intermediate local file.
        """

        if type(payload) is not bytes:
            raise TypeError("payload must be immutable bytes")
        if len(payload) > self._policy.max_object_bytes:
            raise S3ObjectLockError(
                "source",
                "payload exceeds the configured custody object limit",
            )
        retention = self._retention_date(retain_until)
        _safe_identity(tenant_id, label="tenant ID")
        _safe_identity(cab_id, label="CAB ID")
        observed_digest = _sha256_digest(payload)
        if (
            expected_object_digest is not None
            and expected_object_digest != observed_digest
        ):
            raise S3ObjectLockError(
                "source",
                "payload digest does not match the external object digest",
            )
        expected = self._expected_object(
            tenant_id=tenant_id,
            cab_id=cab_id,
            object_digest=observed_digest,
            size=len(payload),
            retain_until=retention,
        )
        try:
            with io.BytesIO(payload) as source_stream:
                self._assert_bucket_ready()
                try:
                    put_raw = self._client.put_object(
                        Body=source_stream,
                        Bucket=self._bucket_name,
                        ChecksumAlgorithm="SHA256",
                        ChecksumSHA256=expected.checksum_sha256,
                        ContentLength=expected.size,
                        ContentType="application/octet-stream",
                        ExpectedBucketOwner=self._expected_bucket_owner,
                        IfNoneMatch="*",
                        Key=expected.object_key,
                        Metadata=expected.metadata,
                        ObjectLockMode="COMPLIANCE",
                        ObjectLockRetainUntilDate=expected.retain_until,
                        SSEKMSKeyId=self._kms_key_arn,
                        ServerSideEncryption=self._encryption,
                    )
                except Exception as put_error:
                    acknowledgement = self._reconcile_after_put_failure(
                        put_error,
                        expected=expected,
                    )
                    self._assert_bucket_ready()
                    return acknowledgement
                put_response = _response_mapping(put_raw, stage="put")
                version_id = self._validate_put_response(put_response, expected)
                acknowledgement = self._verify_version(
                    expected=expected,
                    version_id=version_id,
                )
            self._assert_bucket_ready()
            return acknowledgement
        except S3ObjectLockError:
            raise
        except Exception:
            raise S3ObjectLockError(
                "custody",
                "S3 custody operation failed",
            ) from None

    def _validate_put_response(
        self,
        response: Mapping[str, Any],
        expected: _ExpectedObject,
    ) -> str:
        version_id = response.get("VersionId")
        if not _valid_version_id(version_id):
            raise S3ObjectLockError(
                "put",
                "S3 PutObject returned an invalid version ID",
            )
        assert isinstance(version_id, str)
        if response.get("ChecksumSHA256") != expected.checksum_sha256:
            raise S3ObjectLockError(
                "put",
                "S3 PutObject did not return the expected SHA-256 checksum",
            )
        if (
            response.get("ServerSideEncryption") != self._encryption
            or response.get("SSEKMSKeyId") != self._kms_key_arn
        ):
            raise S3ObjectLockError(
                "put",
                "S3 PutObject did not confirm the pinned KMS encryption",
            )
        return version_id

    def _reconcile_after_put_failure(
        self,
        put_error: BaseException,
        *,
        expected: _ExpectedObject,
    ) -> S3CustodyAcknowledgement:
        code, status = _exception_code(put_error)
        conditional = _is_conditional_conflict(put_error)
        precondition_failed = code in {"412", "PreconditionFailed"} or status == 412
        if status is not None and not conditional:
            raise S3ObjectLockError(
                "put",
                "S3 rejected the custody PutObject request",
            ) from None
        try:
            head_raw = self._client.head_object(
                Bucket=self._bucket_name,
                ChecksumMode="ENABLED",
                ExpectedBucketOwner=self._expected_bucket_owner,
                Key=expected.object_key,
            )
        except Exception as head_error:
            missing = _is_not_found(head_error)
            if precondition_failed and missing:
                raise S3ObjectLockError(
                    "collision",
                    "conditional S3 write conflicted but no current object can be reconciled",
                ) from None
            raise S3ObjectLockError(
                "ambiguous_put",
                "S3 PutObject outcome could not be reconciled",
            ) from None
        head = _response_mapping(head_raw, stage="reconcile")
        version_id = head.get("VersionId")
        if not _valid_version_id(version_id):
            raise S3ObjectLockError(
                "reconcile",
                "current S3 object has no valid version ID",
            )
        assert isinstance(version_id, str)
        try:
            return self._verify_version(
                expected=expected,
                version_id=version_id,
                prefetched_head=head,
            )
        except S3ObjectLockError:
            if conditional:
                raise S3ObjectLockError(
                    "collision",
                    "content-addressed S3 key is occupied by a non-identical object",
                ) from None
            raise S3ObjectLockError(
                "ambiguous_put",
                "ambiguous S3 PutObject resolved to a non-identical object",
            ) from None

    def _verify_version(
        self,
        *,
        expected: _ExpectedObject,
        version_id: str,
        prefetched_head: Mapping[str, Any] | None = None,
    ) -> S3CustodyAcknowledgement:
        if prefetched_head is None:
            try:
                head_raw = self._client.head_object(
                    Bucket=self._bucket_name,
                    ChecksumMode="ENABLED",
                    ExpectedBucketOwner=self._expected_bucket_owner,
                    Key=expected.object_key,
                    VersionId=version_id,
                )
            except Exception:
                raise S3ObjectLockError(
                    "head",
                    "stored S3 version could not be inspected",
                ) from None
            head = _response_mapping(head_raw, stage="head")
        else:
            head = prefetched_head
        self._validate_remote_metadata(
            head,
            expected=expected,
            version_id=version_id,
            stage="head",
        )
        try:
            get_raw = self._client.get_object(
                Bucket=self._bucket_name,
                ChecksumMode="ENABLED",
                ExpectedBucketOwner=self._expected_bucket_owner,
                Key=expected.object_key,
                VersionId=version_id,
            )
        except Exception:
            raise S3ObjectLockError(
                "get",
                "stored S3 version could not be reopened",
            ) from None
        get_response = _response_mapping(get_raw, stage="get")
        self._validate_remote_metadata(
            get_response,
            expected=expected,
            version_id=version_id,
            stage="get",
        )
        body = get_response.get("Body")
        if body is None or not callable(getattr(body, "read", None)):
            raise S3ObjectLockError("get", "S3 GetObject returned no streaming body")
        digest = hashlib.sha256()
        total = 0
        read_failed = False
        try:
            while total <= expected.size:
                chunk = body.read(min(_CHUNK_BYTES, expected.size + 1 - total))
                if not chunk:
                    break
                if type(chunk) is not bytes:
                    raise TypeError
                total += len(chunk)
                if total > expected.size:
                    raise ValueError
                digest.update(chunk)
        except Exception:
            read_failed = True
        finally:
            _close_body(body)
        if read_failed:
            raise S3ObjectLockError(
                "get",
                "S3 object body could not be read exactly",
            )
        retrieved_digest = f"sha256:{digest.hexdigest()}"
        if total != expected.size or retrieved_digest != expected.object_digest:
            raise S3ObjectLockError(
                "collision",
                "stored S3 bytes do not match their content-addressed key",
            )
        return S3CustodyAcknowledgement(
            bucket_arn_digest=self._bucket_arn_digest,
            cab_scope_digest=expected.cab_scope_digest,
            checksum_sha256=expected.checksum_sha256,
            encryption=self._encryption,
            kms_key_arn_digest=self._kms_key_arn_digest,
            object_digest=expected.object_digest,
            object_key_digest=_sha256_digest(expected.object_key.encode("utf-8")),
            retain_until=_format_utc_second(expected.retain_until),
            tenant_scope_digest=expected.tenant_scope_digest,
            version_id=version_id,
        )

    def _validate_remote_metadata(
        self,
        response: Mapping[str, Any],
        *,
        expected: _ExpectedObject,
        version_id: str,
        stage: str,
    ) -> None:
        content_length = response.get("ContentLength")
        if response.get("VersionId") != version_id:
            raise S3ObjectLockError(stage, "S3 response substituted the object version")
        if (
            response.get("DeleteMarker") not in {None, False}
            or type(content_length) is not int
            or content_length != expected.size
            or response.get("ChecksumSHA256") != expected.checksum_sha256
        ):
            raise S3ObjectLockError(stage, "S3 object size or checksum does not close")
        if (
            response.get("ServerSideEncryption") != self._encryption
            or response.get("SSEKMSKeyId") != expected.kms_key_arn
        ):
            raise S3ObjectLockError(
                stage,
                "S3 object is not encrypted by the pinned KMS key",
            )
        if (
            response.get("ObjectLockMode") != "COMPLIANCE"
            or response.get("ObjectLockRetainUntilDate") != expected.retain_until
        ):
            raise S3ObjectLockError(
                stage,
                "S3 object retention does not match the COMPLIANCE policy",
            )
        metadata = response.get("Metadata")
        if (
            type(metadata) is not dict
            or set(metadata) != _REQUIRED_METADATA_KEYS
            or any(
                type(key) is not str or type(value) is not str
                for key, value in metadata.items()
            )
            or dict(metadata) != expected.metadata
        ):
            raise S3ObjectLockError(
                stage,
                "S3 object custody metadata does not match its scope",
            )

    def verify_acknowledgement_scope(
        self,
        acknowledgement: S3CustodyAcknowledgement,
        *,
        tenant_id: str,
        cab_id: str,
    ) -> bool:
        """Check that an acknowledgement belongs to this pinned custody scope."""

        if not isinstance(acknowledgement, S3CustodyAcknowledgement):
            return False
        expected = self._expected_object(
            tenant_id=tenant_id,
            cab_id=cab_id,
            object_digest=acknowledgement.object_digest,
            size=0,
            retain_until=_parse_utc_second(acknowledgement.retain_until),
        )
        return (
            acknowledgement.bucket_arn_digest == self._bucket_arn_digest
            and acknowledgement.kms_key_arn_digest == self._kms_key_arn_digest
            and acknowledgement.encryption == self._encryption
            and acknowledgement.tenant_scope_digest == expected.tenant_scope_digest
            and acknowledgement.cab_scope_digest == expected.cab_scope_digest
            and acknowledgement.object_key_digest
            == _sha256_digest(expected.object_key.encode("utf-8"))
            and acknowledgement.checksum_sha256
            == _checksum_for_digest(acknowledgement.object_digest)
        )

    def reverify_acknowledgement(
        self,
        acknowledgement: S3CustodyAcknowledgement,
        *,
        tenant_id: str,
        cab_id: str,
        expected_size: int,
    ) -> S3CustodyAcknowledgement:
        """Reopen the exact acknowledged version and reproduce its acknowledgement.

        No "latest" lookup is allowed here.  The acknowledgement's VersionId is
        sent to both HeadObject and GetObject, and every byte, retention field,
        scope marker, checksum, and KMS pin must still reproduce the original
        canonical acknowledgement.
        """

        if (
            type(expected_size) is not int
            or expected_size < 0
            or expected_size > self._policy.max_object_bytes
        ):
            raise ValueError("expected object size is outside the custody profile")
        if not self.verify_acknowledgement_scope(
            acknowledgement,
            tenant_id=tenant_id,
            cab_id=cab_id,
        ):
            raise S3ObjectLockError(
                "acknowledgement",
                "custody acknowledgement is outside the pinned scope",
            )
        expected = self._expected_object(
            tenant_id=tenant_id,
            cab_id=cab_id,
            object_digest=acknowledgement.object_digest,
            size=expected_size,
            retain_until=_parse_utc_second(acknowledgement.retain_until),
        )
        self._assert_bucket_ready()
        observed = self._verify_version(
            expected=expected,
            version_id=acknowledgement.version_id,
        )
        self._assert_bucket_ready()
        if observed.to_canonical_bytes() != acknowledgement.to_canonical_bytes():
            raise S3ObjectLockError(
                "acknowledgement",
                "exact S3 version no longer reproduces its acknowledgement",
            )
        return observed


def create_boto3_s3_client(
    *,
    region_name: str,
    connect_timeout_seconds: int = 5,
    read_timeout_seconds: int = 60,
) -> S3ObjectLockClient:
    """Construct a no-retry AWS S3 client when the optional SDK is installed.

    Credentials remain the responsibility of the normal AWS SDK provider
    chain.  No endpoint override is accepted; production calls go to the AWS
    regional S3 endpoint selected by botocore.
    """

    if (
        type(region_name) is not str
        or re.fullmatch(r"^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]$", region_name) is None
    ):
        raise ValueError("region name is not canonical")
    if (
        type(connect_timeout_seconds) is not int
        or not 1 <= connect_timeout_seconds <= 60
        or type(read_timeout_seconds) is not int
        or not 1 <= read_timeout_seconds <= 300
    ):
        raise ValueError("S3 client timeouts are outside the supported range")
    try:
        boto3 = importlib.import_module("boto3")
        config_class = importlib.import_module("botocore.config").Config
    except (ImportError, AttributeError):
        raise S3ObjectLockError(
            "dependency",
            "boto3 is required to construct an AWS S3 custody client",
        ) from None
    try:
        config = config_class(
            connect_timeout=connect_timeout_seconds,
            proxies={},
            read_timeout=read_timeout_seconds,
            retries={"max_attempts": 0, "mode": "standard"},
            signature_version="s3v4",
            s3={"addressing_style": "virtual"},
        )
        return cast(
            S3ObjectLockClient,
            boto3.client("s3", region_name=region_name, config=config),
        )
    except Exception:
        raise S3ObjectLockError(
            "client",
            "AWS S3 custody client could not be constructed",
        ) from None


def retention_date_from_now(
    *,
    now: datetime,
    retention_seconds: int,
) -> datetime:
    """Create a whole-second retention instant without hiding policy choice."""

    if type(retention_seconds) is not int or retention_seconds < 1:
        raise ValueError("retention_seconds must be a positive integer")
    normalized = _aware_utc(now)
    if normalized.microsecond:
        normalized = normalized.replace(microsecond=0) + timedelta(seconds=1)
    return normalized + timedelta(seconds=retention_seconds)
