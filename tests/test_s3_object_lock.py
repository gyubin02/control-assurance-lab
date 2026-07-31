from __future__ import annotations

import base64
import hashlib
import importlib
import io
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from assurance_lab.evidence.s3_object_lock import (
    S3CustodyAcknowledgement,
    S3ObjectLockCustody,
    S3ObjectLockError,
    S3RetentionPolicy,
    create_boto3_s3_client,
    retention_date_from_now,
)

_NOW = datetime(2026, 7, 29, 3, 0, 0, tzinfo=UTC)
_OWNER = "123456789012"
_BUCKET = "control-assurance-prod"
_BUCKET_ARN = f"arn:aws:s3:::{_BUCKET}"
_KMS_ARN = (
    f"arn:aws:kms:ap-northeast-2:{_OWNER}:"
    "key/11111111-2222-3333-4444-555555555555"
)


class _ClientError(RuntimeError):
    def __init__(self, code: str, status: int, message: str = "client error") -> None:
        super().__init__(message)
        self.response = {
            "Error": {"Code": code, "Message": message},
            "ResponseMetadata": {"HTTPStatusCode": status},
        }


@dataclass(slots=True)
class _StoredVersion:
    body: bytes
    checksum: str
    encryption: str
    kms_key: str
    metadata: dict[str, str]
    retain_until: datetime
    version_id: str


class _FakeS3:
    def __init__(self) -> None:
        self.versioning = "Enabled"
        self.object_lock = "Enabled"
        self.objects: dict[str, list[_StoredVersion]] = {}
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.put_response_overrides: dict[str, Any] = {}
        self.head_overrides: dict[str, Any] = {}
        self.get_overrides: dict[str, Any] = {}
        self.get_body_override: bytes | None = None
        self.fail_put_before_store: BaseException | None = None
        self.fail_put_after_store: BaseException | None = None
        self.fail_configuration: BaseException | None = None
        self.drift_after_get = False
        self._next_version = 1
        self._lock = threading.Lock()

    def get_bucket_versioning(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("get_bucket_versioning", dict(kwargs)))
        if self.fail_configuration is not None:
            raise self.fail_configuration
        return {"Status": self.versioning}

    def get_object_lock_configuration(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("get_object_lock_configuration", dict(kwargs)))
        if self.fail_configuration is not None:
            raise self.fail_configuration
        return {
            "ObjectLockConfiguration": {
                "ObjectLockEnabled": self.object_lock,
            }
        }

    def put_object(self, **kwargs: Any) -> dict[str, Any]:
        recorded = {key: value for key, value in kwargs.items() if key != "Body"}
        recorded["BodyWasStreaming"] = callable(getattr(kwargs["Body"], "read", None))
        self.calls.append(("put_object", recorded))
        with self._lock:
            if self.fail_put_before_store is not None:
                error = self.fail_put_before_store
                self.fail_put_before_store = None
                raise error
            key = kwargs["Key"]
            if kwargs.get("IfNoneMatch") == "*" and self.objects.get(key):
                raise _ClientError("PreconditionFailed", 412)
            body = kwargs["Body"].read()
            checksum = base64.b64encode(hashlib.sha256(body).digest()).decode()
            if checksum != kwargs["ChecksumSHA256"]:
                raise _ClientError("BadDigest", 400)
            version_id = f"version-{self._next_version}"
            self._next_version += 1
            version = _StoredVersion(
                body=body,
                checksum=checksum,
                encryption=kwargs["ServerSideEncryption"],
                kms_key=kwargs["SSEKMSKeyId"],
                metadata=dict(kwargs["Metadata"]),
                retain_until=kwargs["ObjectLockRetainUntilDate"],
                version_id=version_id,
            )
            self.objects.setdefault(key, []).append(version)
            if self.fail_put_after_store is not None:
                error = self.fail_put_after_store
                self.fail_put_after_store = None
                raise error
            response = {
                "ChecksumSHA256": checksum,
                "ServerSideEncryption": version.encryption,
                "SSEKMSKeyId": version.kms_key,
                "VersionId": version_id,
            }
            response.update(self.put_response_overrides)
            return response

    def _version(self, key: str, version_id: str | None) -> _StoredVersion:
        versions = self.objects.get(key)
        if not versions:
            raise _ClientError("NoSuchKey", 404)
        if version_id is None:
            return versions[-1]
        for version in versions:
            if version.version_id == version_id:
                return version
        raise _ClientError("NoSuchVersion", 404)

    @staticmethod
    def _metadata(version: _StoredVersion) -> dict[str, Any]:
        return {
            "ChecksumSHA256": version.checksum,
            "ContentLength": len(version.body),
            "Metadata": dict(version.metadata),
            "ObjectLockMode": "COMPLIANCE",
            "ObjectLockRetainUntilDate": version.retain_until,
            "SSEKMSKeyId": version.kms_key,
            "ServerSideEncryption": version.encryption,
            "VersionId": version.version_id,
        }

    def head_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("head_object", dict(kwargs)))
        with self._lock:
            version = self._version(kwargs["Key"], kwargs.get("VersionId"))
            response = self._metadata(version)
            response.update(self.head_overrides)
            return response

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("get_object", dict(kwargs)))
        with self._lock:
            version = self._version(kwargs["Key"], kwargs.get("VersionId"))
            response = self._metadata(version)
            response["Body"] = io.BytesIO(
                version.body
                if self.get_body_override is None
                else self.get_body_override
            )
            response.update(self.get_overrides)
            if self.drift_after_get:
                self.versioning = "Suspended"
            return response


def _custody(
    client: _FakeS3,
    *,
    encryption: str = "aws:kms",
) -> S3ObjectLockCustody:
    return S3ObjectLockCustody(
        client,
        bucket_name=_BUCKET,
        bucket_arn=_BUCKET_ARN,
        expected_bucket_owner=_OWNER,
        kms_key_arn=_KMS_ARN,
        retention_policy=S3RetentionPolicy(
            minimum_seconds=60,
            maximum_seconds=2 * 24 * 60 * 60,
            max_object_bytes=1024 * 1024,
        ),
        encryption=encryption,
        now=lambda: _NOW,
    )


def _source(tmp_path: Path, value: bytes = b"exact custody bytes") -> Path:
    path = tmp_path / "object.bin"
    path.write_bytes(value)
    return path


def _put(
    custody: S3ObjectLockCustody,
    source: Path,
    *,
    tenant_id: str = "tenant:bank-a",
    cab_id: str = "cab:2026-07-29:0001",
) -> S3CustodyAcknowledgement:
    return custody.put_file(
        source,
        tenant_id=tenant_id,
        cab_id=cab_id,
        retain_until=_NOW + timedelta(days=1),
    )


def test_put_is_conditional_compliance_locked_kms_encrypted_and_reopened(
    tmp_path: Path,
) -> None:
    client = _FakeS3()
    custody = _custody(client)

    acknowledgement = _put(custody, _source(tmp_path))

    put = next(kwargs for name, kwargs in client.calls if name == "put_object")
    assert put["IfNoneMatch"] == "*"
    assert put["ChecksumAlgorithm"] == "SHA256"
    assert put["ChecksumSHA256"] == acknowledgement.checksum_sha256
    assert put["ObjectLockMode"] == "COMPLIANCE"
    assert put["ObjectLockRetainUntilDate"] == _NOW + timedelta(days=1)
    assert put["ServerSideEncryption"] == "aws:kms"
    assert put["SSEKMSKeyId"] == _KMS_ARN
    assert put["ExpectedBucketOwner"] == _OWNER
    assert put["BodyWasStreaming"] is True
    assert "ACL" not in put
    assert "BypassGovernanceRetention" not in put
    assert "/tenants/" in put["Key"] and "/cabs/" in put["Key"]
    assert "tenant:bank-a" not in put["Key"]
    assert "cab:2026" not in put["Key"]
    assert any(name == "head_object" for name, _ in client.calls)
    assert any(name == "get_object" for name, _ in client.calls)
    assert acknowledgement.retention_mode == "COMPLIANCE"
    assert custody.verify_acknowledgement_scope(
        acknowledgement,
        tenant_id="tenant:bank-a",
        cab_id="cab:2026-07-29:0001",
    )


def test_dsse_kms_is_explicit_and_pinned(tmp_path: Path) -> None:
    client = _FakeS3()
    acknowledgement = _put(
        _custody(client, encryption="aws:kms:dsse"),
        _source(tmp_path),
    )
    put = next(kwargs for name, kwargs in client.calls if name == "put_object")
    assert put["ServerSideEncryption"] == "aws:kms:dsse"
    assert put["SSEKMSKeyId"] == _KMS_ARN
    assert acknowledgement.encryption == "aws:kms:dsse"


@pytest.mark.parametrize(
    ("versioning", "object_lock"),
    [
        ("Suspended", "Enabled"),
        (None, "Enabled"),
        ("Enabled", "Disabled"),
        ("Enabled", None),
    ],
)
def test_initialization_requires_versioning_and_object_lock(
    versioning: str | None,
    object_lock: str | None,
) -> None:
    client = _FakeS3()
    client.versioning = versioning  # type: ignore[assignment]
    client.object_lock = object_lock  # type: ignore[assignment]
    with pytest.raises(S3ObjectLockError, match="not versioned") as raised:
        _custody(client)
    assert raised.value.stage == "bucket_configuration"


def test_configuration_error_never_reflects_credentials() -> None:
    client = _FakeS3()
    secret = "AKIA-DO-NOT-REFLECT"
    client.fail_configuration = RuntimeError(secret)
    with pytest.raises(S3ObjectLockError) as raised:
        _custody(client)
    assert secret not in str(raised.value)
    assert raised.value.__cause__ is None


@pytest.mark.parametrize("seconds", [59, (2 * 24 * 60 * 60) + 1])
def test_explicit_retention_must_be_within_policy(
    tmp_path: Path,
    seconds: int,
) -> None:
    client = _FakeS3()
    custody = _custody(client)
    with pytest.raises(S3ObjectLockError, match="outside") as raised:
        custody.put_file(
            _source(tmp_path),
            tenant_id="tenant",
            cab_id="cab",
            retain_until=_NOW + timedelta(seconds=seconds),
        )
    assert raised.value.stage == "retention"
    assert not any(name == "put_object" for name, _ in client.calls)


def test_fractional_clock_cannot_shorten_minimum_retention(
    tmp_path: Path,
) -> None:
    client = _FakeS3()
    custody = S3ObjectLockCustody(
        client,
        bucket_name=_BUCKET,
        bucket_arn=_BUCKET_ARN,
        expected_bucket_owner=_OWNER,
        kms_key_arn=_KMS_ARN,
        retention_policy=S3RetentionPolicy(
            minimum_seconds=60,
            maximum_seconds=3600,
        ),
        now=lambda: _NOW + timedelta(microseconds=500_000),
    )
    with pytest.raises(S3ObjectLockError, match="outside"):
        custody.put_file(
            _source(tmp_path),
            tenant_id="tenant",
            cab_id="cab",
            retain_until=_NOW + timedelta(seconds=60),
        )
    assert retention_date_from_now(
        now=_NOW + timedelta(microseconds=500_000),
        retention_seconds=60,
    ) == _NOW + timedelta(seconds=61)


def test_external_digest_mismatch_fails_before_s3_write(tmp_path: Path) -> None:
    client = _FakeS3()
    with pytest.raises(S3ObjectLockError, match="external") as raised:
        _custody(client).put_file(
            _source(tmp_path),
            tenant_id="tenant",
            cab_id="cab",
            retain_until=_NOW + timedelta(days=1),
            expected_object_digest=f"sha256:{'0' * 64}",
        )
    assert raised.value.stage == "source"
    assert not any(name == "put_object" for name, _ in client.calls)


def test_exact_retry_reuses_locked_version_without_creating_another(
    tmp_path: Path,
) -> None:
    client = _FakeS3()
    custody = _custody(client)
    source = _source(tmp_path)

    first = _put(custody, source)
    second = _put(custody, source)

    assert second == first
    key = next(kwargs["Key"] for name, kwargs in client.calls if name == "put_object")
    assert len(client.objects[key]) == 1
    assert len([name for name, _ in client.calls if name == "put_object"]) == 2


def test_timeout_after_server_commit_is_reconciled_to_the_exact_version(
    tmp_path: Path,
) -> None:
    client = _FakeS3()
    secret = "session-token-must-not-escape"
    client.fail_put_after_store = TimeoutError(secret)

    acknowledgement = _put(_custody(client), _source(tmp_path))

    assert acknowledgement.version_id == "version-1"
    assert secret not in repr(acknowledgement)


def test_timeout_before_server_commit_is_an_opaque_ambiguous_failure(
    tmp_path: Path,
) -> None:
    client = _FakeS3()
    secret = "https://secret-endpoint.example/?token=top-secret"
    client.fail_put_before_store = TimeoutError(secret)

    with pytest.raises(S3ObjectLockError) as raised:
        _put(_custody(client), _source(tmp_path))

    assert raised.value.stage == "ambiguous_put"
    assert secret not in str(raised.value)
    assert raised.value.__cause__ is None


def test_409_without_visible_version_remains_retryable_ambiguous(
    tmp_path: Path,
) -> None:
    client = _FakeS3()
    client.fail_put_before_store = _ClientError(
        "ConditionalRequestConflict",
        409,
        "do-not-reflect-request-id",
    )
    with pytest.raises(S3ObjectLockError) as raised:
        _put(_custody(client), _source(tmp_path))
    assert raised.value.stage == "ambiguous_put"
    assert "do-not-reflect" not in str(raised.value)


def test_definitive_s3_rejection_is_normalized_without_reconciliation(
    tmp_path: Path,
) -> None:
    client = _FakeS3()
    secret = "session-token-in-upstream-error"
    client.fail_put_before_store = _ClientError("AccessDenied", 403, secret)
    with pytest.raises(S3ObjectLockError) as raised:
        _put(_custody(client), _source(tmp_path))
    assert raised.value.stage == "put"
    assert secret not in str(raised.value)
    assert not any(name == "head_object" for name, _ in client.calls)


def test_content_address_collision_is_fail_closed(tmp_path: Path) -> None:
    client = _FakeS3()
    custody = _custody(client)
    source = _source(tmp_path, b"good-data")
    _put(custody, source)
    key = next(iter(client.objects))
    client.objects[key][0].body = b"evil-data"

    with pytest.raises(S3ObjectLockError, match="occupied") as raised:
        _put(custody, source)
    assert raised.value.stage == "collision"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("VersionId", "bad\nversion", "version ID"),
        ("ChecksumSHA256", base64.b64encode(b"x" * 32).decode(), "checksum"),
        ("ServerSideEncryption", "AES256", "KMS"),
        (
            "SSEKMSKeyId",
            f"arn:aws:kms:ap-northeast-2:{_OWNER}:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "KMS",
        ),
    ],
)
def test_malicious_put_response_is_never_accepted(
    tmp_path: Path,
    field: str,
    value: str,
    message: str,
) -> None:
    client = _FakeS3()
    client.put_response_overrides[field] = value
    with pytest.raises(S3ObjectLockError, match=message) as raised:
        _put(_custody(client), _source(tmp_path))
    assert raised.value.stage == "put"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"ObjectLockMode": "GOVERNANCE"}, "retention"),
        ({"ObjectLockRetainUntilDate": _NOW + timedelta(hours=23)}, "retention"),
        ({"ServerSideEncryption": "AES256"}, "encrypted"),
        ({"ContentLength": 1}, "size or checksum"),
        ({"Metadata": {"object-sha256": "0" * 64}}, "metadata"),
        ({"VersionId": "other-version"}, "substituted"),
    ],
)
def test_head_response_must_close_every_custody_dimension(
    tmp_path: Path,
    overrides: dict[str, Any],
    message: str,
) -> None:
    client = _FakeS3()
    client.head_overrides = overrides
    with pytest.raises(S3ObjectLockError, match=message) as raised:
        _put(_custody(client), _source(tmp_path))
    assert raised.value.stage == "head"


def test_get_body_is_hashed_instead_of_trusting_remote_metadata(
    tmp_path: Path,
) -> None:
    client = _FakeS3()
    client.get_body_override = b"x" * len(b"exact custody bytes")
    with pytest.raises(S3ObjectLockError, match="content-addressed") as raised:
        _put(_custody(client), _source(tmp_path))
    assert raised.value.stage == "collision"


def test_get_metadata_is_checked_independently_of_head(tmp_path: Path) -> None:
    client = _FakeS3()
    client.get_overrides = {"ObjectLockMode": "GOVERNANCE"}
    with pytest.raises(S3ObjectLockError, match="retention") as raised:
        _put(_custody(client), _source(tmp_path))
    assert raised.value.stage == "get"


def test_acknowledgement_is_canonical_secret_free_and_scope_bound(
    tmp_path: Path,
) -> None:
    endpoint = "https://s3.ap-northeast-2.amazonaws.com"
    client = _FakeS3()
    custody = _custody(client)
    acknowledgement = _put(custody, _source(tmp_path))

    payload = acknowledgement.to_canonical_bytes()
    reopened = S3CustodyAcknowledgement.from_canonical_bytes(payload)

    assert reopened == acknowledgement
    assert payload == json.dumps(
        acknowledgement.to_document(),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    assert _BUCKET.encode() not in payload
    assert _BUCKET_ARN.encode() not in payload
    assert _KMS_ARN.encode() not in payload
    assert endpoint.encode() not in payload
    assert b"tenant:bank-a" not in payload
    assert b"cab:2026" not in payload
    assert not custody.verify_acknowledgement_scope(
        acknowledgement,
        tenant_id="tenant:bank-b",
        cab_id="cab:2026-07-29:0001",
    )
    assert not custody.verify_acknowledgement_scope(
        acknowledgement,
        tenant_id="tenant:bank-a",
        cab_id="cab:substituted",
    )


def test_noncanonical_acknowledgement_is_rejected(tmp_path: Path) -> None:
    acknowledgement = _put(_custody(_FakeS3()), _source(tmp_path))
    pretty = json.dumps(acknowledgement.to_document(), indent=2).encode()
    with pytest.raises(S3ObjectLockError, match="not canonical"):
        S3CustodyAcknowledgement.from_canonical_bytes(pretty)


def test_bucket_configuration_drift_during_write_blocks_acknowledgement(
    tmp_path: Path,
) -> None:
    client = _FakeS3()
    client.drift_after_get = True
    with pytest.raises(S3ObjectLockError, match="not versioned") as raised:
        _put(_custody(client), _source(tmp_path))
    assert raised.value.stage == "bucket_configuration"
    assert len(client.objects) == 1


def test_concurrent_exact_writers_converge_on_one_locked_version(
    tmp_path: Path,
) -> None:
    client = _FakeS3()
    custody = _custody(client)
    source = _source(tmp_path)

    with ThreadPoolExecutor(max_workers=8) as executor:
        acknowledgements = list(
            executor.map(lambda _: _put(custody, source), range(16))
        )

    assert len({item.to_canonical_bytes() for item in acknowledgements}) == 1
    assert len(client.objects) == 1
    assert len(next(iter(client.objects.values()))) == 1


def test_put_bytes_has_the_same_conditional_exact_version_closure() -> None:
    client = _FakeS3()
    custody = _custody(client)
    payload = b'{"canonical":"receipt"}'
    digest = f"sha256:{hashlib.sha256(payload).hexdigest()}"

    first = custody.put_bytes(
        payload,
        tenant_id="tenant:bank-a",
        cab_id="cab:2026-07-29:0001",
        retain_until=_NOW + timedelta(days=1),
        expected_object_digest=digest,
    )
    retried = custody.put_bytes(
        payload,
        tenant_id="tenant:bank-a",
        cab_id="cab:2026-07-29:0001",
        retain_until=_NOW + timedelta(days=1),
        expected_object_digest=digest,
    )

    assert first.to_canonical_bytes() == retried.to_canonical_bytes()
    assert first.object_digest == digest
    assert len(client.objects) == 1
    assert len(next(iter(client.objects.values()))) == 1


def test_put_bytes_recovers_an_ambiguous_post_commit_response() -> None:
    client = _FakeS3()
    client.fail_put_after_store = TimeoutError("must-not-be-reflected")
    custody = _custody(client)
    payload = b"signed closure bytes"

    acknowledgement = custody.put_bytes(
        payload,
        tenant_id="tenant",
        cab_id="cab",
        retain_until=_NOW + timedelta(days=1),
    )

    assert acknowledgement.object_digest == (
        f"sha256:{hashlib.sha256(payload).hexdigest()}"
    )
    assert len(client.objects) == 1
    assert len(next(iter(client.objects.values()))) == 1


def test_put_bytes_rejects_mutable_or_mismatched_input_before_write() -> None:
    client = _FakeS3()
    custody = _custody(client)
    with pytest.raises(TypeError, match="immutable"):
        custody.put_bytes(
            bytearray(b"mutable"),  # type: ignore[arg-type]
            tenant_id="tenant",
            cab_id="cab",
            retain_until=_NOW + timedelta(days=1),
        )
    with pytest.raises(S3ObjectLockError, match="external") as raised:
        custody.put_bytes(
            b"receipt",
            tenant_id="tenant",
            cab_id="cab",
            retain_until=_NOW + timedelta(days=1),
            expected_object_digest=f"sha256:{'0' * 64}",
        )
    assert raised.value.stage == "source"
    assert not any(name == "put_object" for name, _ in client.calls)


def test_acknowledgement_reverification_uses_only_the_exact_version() -> None:
    client = _FakeS3()
    custody = _custody(client)
    payload = b"version-pinned custody"
    acknowledgement = custody.put_bytes(
        payload,
        tenant_id="tenant",
        cab_id="cab",
        retain_until=_NOW + timedelta(days=1),
    )
    client.calls.clear()

    observed = custody.reverify_acknowledgement(
        acknowledgement,
        tenant_id="tenant",
        cab_id="cab",
        expected_size=len(payload),
    )

    assert observed == acknowledgement
    exact_reads = [
        kwargs
        for name, kwargs in client.calls
        if name in {"head_object", "get_object"}
    ]
    assert len(exact_reads) == 2
    assert all(kwargs["VersionId"] == acknowledgement.version_id for kwargs in exact_reads)


def test_acknowledgement_reverification_detects_remote_byte_tamper() -> None:
    client = _FakeS3()
    custody = _custody(client)
    payload = b"locked-object"
    acknowledgement = custody.put_bytes(
        payload,
        tenant_id="tenant",
        cab_id="cab",
        retain_until=_NOW + timedelta(days=1),
    )
    key = next(iter(client.objects))
    client.objects[key][0].body = b"remote-tamper"

    with pytest.raises(S3ObjectLockError, match="content-addressed") as raised:
        custody.reverify_acknowledgement(
            acknowledgement,
            tenant_id="tenant",
            cab_id="cab",
            expected_size=len(payload),
        )
    assert raised.value.stage == "collision"


def test_symlink_and_hardlink_sources_are_rejected(tmp_path: Path) -> None:
    client = _FakeS3()
    custody = _custody(client)
    source = _source(tmp_path)
    symlink = tmp_path / "source-link"
    symlink.symlink_to(source)
    with pytest.raises(S3ObjectLockError, match="non-symlink"):
        _put(custody, symlink)

    hardlink = tmp_path / "source-hardlink"
    hardlink.hardlink_to(source)
    with pytest.raises(S3ObjectLockError, match="owner-unique"):
        _put(custody, source)


def test_optional_boto3_dependency_is_guarded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_import = importlib.import_module

    def guarded_import(name: str) -> Any:
        if name == "boto3":
            raise ImportError
        return real_import(name)

    monkeypatch.setattr(
        importlib,
        "import_module",
        guarded_import,
    )
    with pytest.raises(S3ObjectLockError) as raised:
        create_boto3_s3_client(region_name="ap-northeast-2")
    assert raised.value.stage == "dependency"
