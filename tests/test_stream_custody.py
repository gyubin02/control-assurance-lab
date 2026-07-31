from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from assurance_lab.evidence.admission import DetachedSignature
from assurance_lab.evidence.bundle import (
    EvaluationRef,
    EvaluatorRef,
    ExperimentRef,
    Sensitivity,
)
from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.evidence.s3_object_lock import S3CustodyAcknowledgement
from assurance_lab.evidence.stream_custody import (
    STREAM_CUSTODY_SIGNATURE_DOMAIN,
    StreamCustodyError,
    seal_streamed_cab_snapshot,
    verify_stream_custody_closure,
)
from assurance_lab.evidence.stream_snapshot import (
    StreamedCABSnapshot,
    capture_streamed_cab_snapshot,
)
from assurance_lab.evidence.writer import BundleMetadata, PayloadFile, write_bundle

_NOW = datetime(2026, 7, 29, 12, 0, 0, tzinfo=UTC)
_RETAIN_UNTIL = _NOW + timedelta(days=30)
_TENANT = "tenant:bank-a"
_PIN = f"sha256:{'a' * 64}"
_KMS_PIN = f"sha256:{'b' * 64}"
_SIGNATURE_PREFIX = STREAM_CUSTODY_SIGNATURE_DOMAIN.encode("ascii") + b"\x00"


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _scope(label: bytes, value: str) -> str:
    encoded = value.encode()
    return _sha256(label + b"\x00" + len(encoded).to_bytes(4, "big") + encoded)


def _checksum(digest: str) -> str:
    return base64.b64encode(bytes.fromhex(digest.removeprefix("sha256:"))).decode()


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _signing_message(receipt_digest: str) -> bytes:
    raw = bytes.fromhex(receipt_digest.removeprefix("sha256:"))
    return _SIGNATURE_PREFIX + len(raw).to_bytes(2, "big") + raw


class _Signer:
    def __init__(
        self,
        *,
        key_id: str = "stream-custody-test-key",
        private_key: Ed25519PrivateKey | None = None,
    ) -> None:
        self._key_id = key_id
        self._private_key = private_key or Ed25519PrivateKey.generate()
        self._public_key_bytes = self._private_key.public_key().public_bytes_raw()

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_key_bytes(self) -> bytes:
        return self._public_key_bytes

    @property
    def private_key(self) -> Ed25519PrivateKey:
        return self._private_key

    def sign(self, message: bytes) -> DetachedSignature:
        return DetachedSignature(
            key_id=self._key_id,
            algorithm="ed25519",
            signature=base64.b64encode(self._private_key.sign(message)).decode(),
        )


class _FakeCustody:
    """Content-addressed test double for closure logic, not an S3 emulator."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.acknowledgements: dict[str, S3CustodyAcknowledgement] = {}
        self.versions: dict[str, str] = {}
        self.put_calls = 0
        self.online_reads: list[str] = []
        self.fail_after_store_calls: set[int] = set()
        self.after_store: Callable[[int], None] | None = None

    def _put(
        self,
        payload: bytes,
        *,
        tenant_id: str,
        cab_id: str,
        retain_until: datetime,
        expected_object_digest: str | None,
    ) -> S3CustodyAcknowledgement:
        self.put_calls += 1
        digest = _sha256(payload)
        if expected_object_digest is not None and digest != expected_object_digest:
            raise RuntimeError("external digest mismatch")
        tenant_scope = _scope(b"tenant", tenant_id)
        cab_scope = _scope(b"cab", cab_id)
        existing = self.objects.get(digest)
        if existing is not None:
            acknowledgement = self.acknowledgements[digest]
            if (
                existing != payload
                or acknowledgement.tenant_scope_digest != tenant_scope
                or acknowledgement.cab_scope_digest != cab_scope
                or acknowledgement.retain_until != _timestamp(retain_until)
            ):
                raise RuntimeError("content-addressed collision")
            return acknowledgement
        version_id = f"version-{len(self.objects) + 1}"
        acknowledgement = S3CustodyAcknowledgement(
            bucket_arn_digest=_PIN,
            cab_scope_digest=cab_scope,
            checksum_sha256=_checksum(digest),
            encryption="aws:kms:dsse",
            kms_key_arn_digest=_KMS_PIN,
            object_digest=digest,
            object_key_digest=_sha256(
                f"test-key:{tenant_scope}:{cab_scope}:{digest}".encode()
            ),
            retain_until=_timestamp(retain_until),
            tenant_scope_digest=tenant_scope,
            version_id=version_id,
        )
        self.objects[digest] = payload
        self.acknowledgements[digest] = acknowledgement
        self.versions[version_id] = digest
        if self.after_store is not None:
            self.after_store(self.put_calls)
        if self.put_calls in self.fail_after_store_calls:
            self.fail_after_store_calls.remove(self.put_calls)
            raise RuntimeError("ambiguous post-store failure")
        return acknowledgement

    def put_file(
        self,
        source: Path,
        *,
        tenant_id: str,
        cab_id: str,
        retain_until: datetime,
        expected_object_digest: str | None = None,
    ) -> S3CustodyAcknowledgement:
        return self._put(
            source.read_bytes(),
            tenant_id=tenant_id,
            cab_id=cab_id,
            retain_until=retain_until,
            expected_object_digest=expected_object_digest,
        )

    def put_bytes(
        self,
        payload: bytes,
        *,
        tenant_id: str,
        cab_id: str,
        retain_until: datetime,
        expected_object_digest: str | None = None,
    ) -> S3CustodyAcknowledgement:
        return self._put(
            payload,
            tenant_id=tenant_id,
            cab_id=cab_id,
            retain_until=retain_until,
            expected_object_digest=expected_object_digest,
        )

    def verify_acknowledgement_scope(
        self,
        acknowledgement: S3CustodyAcknowledgement,
        *,
        tenant_id: str,
        cab_id: str,
    ) -> bool:
        return (
            acknowledgement.bucket_arn_digest == _PIN
            and acknowledgement.kms_key_arn_digest == _KMS_PIN
            and acknowledgement.encryption == "aws:kms:dsse"
            and acknowledgement.tenant_scope_digest == _scope(b"tenant", tenant_id)
            and acknowledgement.cab_scope_digest == _scope(b"cab", cab_id)
        )

    def reverify_acknowledgement(
        self,
        acknowledgement: S3CustodyAcknowledgement,
        *,
        tenant_id: str,
        cab_id: str,
        expected_size: int,
    ) -> S3CustodyAcknowledgement:
        self.online_reads.append(acknowledgement.version_id)
        digest = self.versions.get(acknowledgement.version_id)
        if (
            digest is None
            or not self.verify_acknowledgement_scope(
                acknowledgement,
                tenant_id=tenant_id,
                cab_id=cab_id,
            )
            or self.acknowledgements.get(digest) != acknowledgement
        ):
            raise RuntimeError("version substitution")
        body = self.objects[digest]
        if len(body) != expected_size or _sha256(body) != acknowledgement.object_digest:
            raise RuntimeError("remote object corruption")
        return acknowledgement


def _write_cab(
    destination: Path,
    payloads: tuple[tuple[str, bytes], ...] = (
        ("records/events.bin", b"same-event"),
        ("artifacts/copy.bin", b"same-event"),
    ),
) -> None:
    metadata = BundleMetadata(
        created_at=_NOW + timedelta(seconds=1),
        as_of=_NOW,
        experiment=ExperimentRef(
            id="stream-custody-test",
            spec_version="1.0.0",
            spec_digest=f"sha256:{'c' * 64}",
        ),
        evaluation=EvaluationRef(
            policy_id="policy:stream-custody-test",
            policy_digest=f"sha256:{'d' * 64}",
            evaluator=EvaluatorRef(
                name="stream-custody-test",
                version="1.0.0",
                source_revision="test",
                image_digest=None,
            ),
        ),
    )
    result = write_bundle(
        destination,
        metadata=metadata,
        payloads=tuple(
            PayloadFile(
                path=path,
                content=content,
                media_type="application/octet-stream",
                role="test-evidence",
                sensitivity=Sensitivity.SYNTHETIC,
                required_for=("stream-custody-test",),
            )
            for path, content in payloads
        ),
    )
    assert result.bundle_id is not None


def _snapshot(tmp_path: Path) -> StreamedCABSnapshot:
    cab = tmp_path / "cab"
    root = tmp_path / "snapshot"
    _write_cab(cab)
    return capture_streamed_cab_snapshot(cab, root)


def _seal(
    tmp_path: Path,
    *,
    custody: _FakeCustody | None = None,
    signer: _Signer | None = None,
) -> tuple[StreamedCABSnapshot, _FakeCustody, _Signer, Any]:
    snapshot = _snapshot(tmp_path)
    custody = custody or _FakeCustody()
    signer = signer or _Signer()
    seal = seal_streamed_cab_snapshot(
        snapshot.root,
        expected_snapshot_digest=snapshot.snapshot_digest,
        tenant_id=_TENANT,
        retain_until=_RETAIN_UNTIL,
        custody=custody,
        receipt_signer=signer,
    )
    return snapshot, custody, signer, seal


def _resigned_attack(
    seal: Any,
    *,
    signer: _Signer,
    custody: _FakeCustody,
    mutate: Callable[[dict[str, Any]], None],
) -> tuple[bytes, S3CustodyAcknowledgement]:
    document = json.loads(seal.closure_bytes)
    mutate(document)
    receipt_bytes = canonical_json_bytes(document["receipt"])
    receipt_digest = _sha256(receipt_bytes)
    document["receipt_digest"] = receipt_digest
    document["signature"] = signer.sign(
        _signing_message(receipt_digest)
    ).model_dump(mode="json")
    closure_bytes = canonical_json_bytes(document)
    cab_id = document["receipt"]["cab_id"]
    acknowledgement = custody.put_bytes(
        closure_bytes,
        tenant_id=_TENANT,
        cab_id=cab_id,
        retain_until=_RETAIN_UNTIL,
        expected_object_digest=_sha256(closure_bytes),
    )
    return closure_bytes, acknowledgement


def test_seal_closes_unique_blob_set_and_supports_offline_and_online_verify(
    tmp_path: Path,
) -> None:
    snapshot, custody, signer, seal = _seal(tmp_path)

    # bundle.json plus two identical payload files become two unique blobs.
    assert snapshot.file_count == 3
    assert seal.closure.receipt.object_count == 3
    assert len(custody.objects) == 4  # descriptor + two blobs + signed closure
    assert custody.online_reads == []

    offline = verify_stream_custody_closure(
        seal.closure_bytes,
        seal.closure_acknowledgement,
        snapshot.descriptor_bytes,
        expected_snapshot_digest=snapshot.snapshot_digest,
        tenant_id=_TENANT,
        custody=custody,
        receipt_signer=signer,
    )
    assert offline.exact_versions_reverified is False
    assert custody.online_reads == []

    online = verify_stream_custody_closure(
        seal.closure_bytes,
        seal.closure_acknowledgement,
        snapshot.descriptor_bytes,
        expected_snapshot_digest=snapshot.snapshot_digest,
        tenant_id=_TENANT,
        custody=custody,
        receipt_signer=signer,
        online_reverify=True,
    )
    assert online.exact_versions_reverified is True
    assert len(custody.online_reads) == seal.closure.receipt.object_count + 1


def test_partial_component_write_is_retryable_and_final_result_is_deterministic(
    tmp_path: Path,
) -> None:
    snapshot = _snapshot(tmp_path)
    custody = _FakeCustody()
    signer = _Signer()
    custody.fail_after_store_calls.add(2)

    with pytest.raises(StreamCustodyError) as raised:
        seal_streamed_cab_snapshot(
            snapshot.root,
            expected_snapshot_digest=snapshot.snapshot_digest,
            tenant_id=_TENANT,
            retain_until=_RETAIN_UNTIL,
            custody=custody,
            receipt_signer=signer,
        )
    assert raised.value.stage == "custody"
    assert len(custody.objects) == 2

    recovered = seal_streamed_cab_snapshot(
        snapshot.root,
        expected_snapshot_digest=snapshot.snapshot_digest,
        tenant_id=_TENANT,
        retain_until=_RETAIN_UNTIL,
        custody=custody,
        receipt_signer=signer,
    )
    retried = seal_streamed_cab_snapshot(
        snapshot.root,
        expected_snapshot_digest=snapshot.snapshot_digest,
        tenant_id=_TENANT,
        retain_until=_RETAIN_UNTIL,
        custody=custody,
        receipt_signer=signer,
    )

    assert recovered.closure_bytes == retried.closure_bytes
    assert (
        recovered.closure_acknowledgement.to_canonical_bytes()
        == retried.closure_acknowledgement.to_canonical_bytes()
    )
    assert len(custody.objects) == recovered.closure.receipt.object_count + 1


def test_ambiguous_final_closure_write_recovers_without_resigning_identity(
    tmp_path: Path,
) -> None:
    snapshot = _snapshot(tmp_path)
    custody = _FakeCustody()
    signer = _Signer()
    # descriptor + two unique CAB blobs + final signed closure
    custody.fail_after_store_calls.add(4)

    with pytest.raises(StreamCustodyError):
        seal_streamed_cab_snapshot(
            snapshot.root,
            expected_snapshot_digest=snapshot.snapshot_digest,
            tenant_id=_TENANT,
            retain_until=_RETAIN_UNTIL,
            custody=custody,
            receipt_signer=signer,
        )
    assert len(custody.objects) == 4
    locked_closure = next(
        payload
        for payload in custody.objects.values()
        if b"application/vnd.control-assurance.signed-stream-custody" in payload
    )

    recovered = seal_streamed_cab_snapshot(
        snapshot.root,
        expected_snapshot_digest=snapshot.snapshot_digest,
        tenant_id=_TENANT,
        retain_until=_RETAIN_UNTIL,
        custody=custody,
        receipt_signer=signer,
    )

    assert recovered.closure_bytes == locked_closure
    assert len(custody.objects) == 4


def test_local_snapshot_mutation_during_upload_blocks_signed_closure(
    tmp_path: Path,
) -> None:
    snapshot = _snapshot(tmp_path)
    custody = _FakeCustody()

    def mutate_after_last_component(call: int) -> None:
        if call == 3:
            snapshot_file = snapshot.root / "snapshot.json"
            snapshot_file.write_bytes(snapshot_file.read_bytes() + b" ")

    custody.after_store = mutate_after_last_component
    with pytest.raises(StreamCustodyError, match="changed") as raised:
        seal_streamed_cab_snapshot(
            snapshot.root,
            expected_snapshot_digest=snapshot.snapshot_digest,
            tenant_id=_TENANT,
            retain_until=_RETAIN_UNTIL,
            custody=custody,
            receipt_signer=_Signer(),
        )
    assert raised.value.stage == "snapshot"
    assert len(custody.objects) == 3


@pytest.mark.parametrize(
    "mutate",
    [
        lambda document: (
            document["receipt"]["objects"].pop(),
            document["receipt"].update(
                object_count=len(document["receipt"]["objects"])
            ),
        ),
        lambda document: (
            document["receipt"]["objects"].append(
                dict(document["receipt"]["objects"][-1])
            ),
            document["receipt"].update(
                object_count=len(document["receipt"]["objects"])
            ),
        ),
        lambda document: document["receipt"]["objects"][1].update(
            acknowledgement=document["receipt"]["objects"][2]["acknowledgement"]
        ),
        lambda document: document["receipt"]["objects"][1].update(
            size=document["receipt"]["objects"][1]["size"] + 1
        ),
    ],
    ids=("omitted-blob", "duplicate-blob", "substituted-ack", "wrong-size"),
)
def test_resigned_omission_duplicate_substitution_and_size_attacks_fail(
    tmp_path: Path,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    snapshot, custody, signer, seal = _seal(tmp_path)
    closure_bytes, acknowledgement = _resigned_attack(
        seal,
        signer=signer,
        custody=custody,
        mutate=mutate,
    )

    with pytest.raises(StreamCustodyError):
        verify_stream_custody_closure(
            closure_bytes,
            acknowledgement,
            snapshot.descriptor_bytes,
            expected_snapshot_digest=snapshot.snapshot_digest,
            tenant_id=_TENANT,
            custody=custody,
            receipt_signer=signer,
        )


def test_signer_key_and_key_id_mismatch_are_rejected(tmp_path: Path) -> None:
    snapshot, custody, signer, seal = _seal(tmp_path)
    wrong_key = _Signer()
    alias = _Signer(key_id="wrong-key-id", private_key=signer.private_key)

    for verifier in (wrong_key, alias):
        with pytest.raises(StreamCustodyError, match="signer identity") as raised:
            verify_stream_custody_closure(
                seal.closure_bytes,
                seal.closure_acknowledgement,
                snapshot.descriptor_bytes,
                expected_snapshot_digest=snapshot.snapshot_digest,
                tenant_id=_TENANT,
                custody=custody,
                receipt_signer=verifier,
            )
        assert raised.value.stage == "signature"


def test_corrupt_signature_is_rejected_even_with_a_matching_closure_ack(
    tmp_path: Path,
) -> None:
    snapshot, custody, signer, seal = _seal(tmp_path)
    document = json.loads(seal.closure_bytes)
    signature = document["signature"]["signature"]
    document["signature"]["signature"] = (
        ("A" if signature[0] != "A" else "B") + signature[1:]
    )
    corrupt = canonical_json_bytes(document)
    acknowledgement = custody.put_bytes(
        corrupt,
        tenant_id=_TENANT,
        cab_id=snapshot.cab_id,
        retain_until=_RETAIN_UNTIL,
        expected_object_digest=_sha256(corrupt),
    )

    with pytest.raises(StreamCustodyError, match="Ed25519") as raised:
        verify_stream_custody_closure(
            corrupt,
            acknowledgement,
            snapshot.descriptor_bytes,
            expected_snapshot_digest=snapshot.snapshot_digest,
            tenant_id=_TENANT,
            custody=custody,
            receipt_signer=signer,
        )
    assert raised.value.stage == "signature"


def test_closure_ack_cannot_be_replaced_by_a_component_ack(tmp_path: Path) -> None:
    snapshot, custody, signer, seal = _seal(tmp_path)
    component_ack = (
        seal.closure.receipt.objects[0].acknowledgement.as_acknowledgement()
    )

    with pytest.raises(StreamCustodyError, match="closure acknowledgement") as raised:
        verify_stream_custody_closure(
            seal.closure_bytes,
            component_ack,
            snapshot.descriptor_bytes,
            expected_snapshot_digest=snapshot.snapshot_digest,
            tenant_id=_TENANT,
            custody=custody,
            receipt_signer=signer,
        )
    assert raised.value.stage == "custody"


def test_remote_tamper_is_visible_only_when_exact_versions_are_reopened(
    tmp_path: Path,
) -> None:
    snapshot, custody, signer, seal = _seal(tmp_path)
    component = seal.closure.receipt.objects[1]
    custody.objects[component.digest] = b"x" * component.size

    # The signed offline closure remains cryptographically valid.
    verify_stream_custody_closure(
        seal.closure_bytes,
        seal.closure_acknowledgement,
        snapshot.descriptor_bytes,
        expected_snapshot_digest=snapshot.snapshot_digest,
        tenant_id=_TENANT,
        custody=custody,
        receipt_signer=signer,
    )
    with pytest.raises(StreamCustodyError, match="re-verification") as raised:
        verify_stream_custody_closure(
            seal.closure_bytes,
            seal.closure_acknowledgement,
            snapshot.descriptor_bytes,
            expected_snapshot_digest=snapshot.snapshot_digest,
            tenant_id=_TENANT,
            custody=custody,
            receipt_signer=signer,
            online_reverify=True,
        )
    assert raised.value.stage == "remote_reverify"


def test_noncanonical_and_descriptor_substitution_are_rejected(
    tmp_path: Path,
) -> None:
    snapshot, custody, signer, seal = _seal(tmp_path)
    pretty = json.dumps(json.loads(seal.closure_bytes), indent=2).encode()
    with pytest.raises(StreamCustodyError, match="not canonical"):
        verify_stream_custody_closure(
            pretty,
            seal.closure_acknowledgement,
            snapshot.descriptor_bytes,
            expected_snapshot_digest=snapshot.snapshot_digest,
            tenant_id=_TENANT,
            custody=custody,
            receipt_signer=signer,
        )
    with pytest.raises(StreamCustodyError, match="descriptor"):
        verify_stream_custody_closure(
            seal.closure_bytes,
            seal.closure_acknowledgement,
            snapshot.descriptor_bytes + b" ",
            expected_snapshot_digest=snapshot.snapshot_digest,
            tenant_id=_TENANT,
            custody=custody,
            receipt_signer=signer,
        )
