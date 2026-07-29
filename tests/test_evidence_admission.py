from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import stat
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from assurance_lab.evidence.admission import (
    ADMISSION_SCHEMA_VERSION,
    COLLECTION_STATEMENT_MEDIA_TYPE,
    AdmissionDisposition,
    AdmissionLimits,
    AdmissionRejected,
    AdmissionRejectReason,
    AdmissionService,
    CollectionStatement,
    DetachedSignature,
    FaultPoint,
    SignedJobLease,
    issue_signed_job_lease,
)
from assurance_lab.evidence.attestation import (
    TRUST_POLICY_MEDIA_TYPE,
    TRUST_POLICY_SCHEMA_VERSION,
    KeyStatus,
    TrustedKey,
    TrustPolicy,
    dsse_pae,
)
from assurance_lab.evidence.bundle import (
    PROFILE,
    ROOT_MEDIA_TYPE,
    SCHEMA_VERSION,
    BundleFile,
    BundleManifest,
    EvaluationRef,
    EvaluatorRef,
    ExperimentRef,
    Sensitivity,
)
from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.evidence.snapshot import verify_cab_snapshot

NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
CAPABILITY_DIGEST = f"sha256:{'1' * 64}"
AUDIENCE = "admission:prod-kr"
POLICY_ID = "policy:collector"
POLICY_REVISION = 1


class _Ed25519Signer:
    def __init__(self, seed: int, key_id: str) -> None:
        self._private_key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
        self._public_key: Ed25519PublicKey = self._private_key.public_key()
        self._key_id = key_id

    @property
    def public_key_bytes(self) -> bytes:
        return self._public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    @property
    def key_fingerprint(self) -> str:
        return _digest(self.public_key_bytes)

    def sign(self, message: bytes) -> DetachedSignature:
        return DetachedSignature(
            key_id=self._key_id,
            algorithm="ed25519",
            signature=base64.b64encode(self._private_key.sign(message)).decode("ascii"),
        )

    def verify(self, message: bytes, signature: DetachedSignature) -> bool:
        if signature.key_id != self._key_id or signature.algorithm != "ed25519":
            return False
        try:
            self._public_key.verify(
                base64.b64decode(signature.signature, validate=True),
                message,
            )
        except (InvalidSignature, ValueError):
            return False
        return True


class _MisboundEd25519Signer(_Ed25519Signer):
    @property
    def public_key_bytes(self) -> bytes:
        return _Ed25519Signer(99, "key:other-material").public_key_bytes


class _FixedClock:
    def __init__(self, now: datetime = NOW) -> None:
        self.value = now
        self.calls = 0
        self._lock = threading.Lock()

    def now(self) -> datetime:
        with self._lock:
            self.calls += 1
            return self.value


class _PolicyResolver:
    def __init__(self, policy_bytes: bytes) -> None:
        self.policy_bytes = policy_bytes
        self.calls: list[tuple[str, int, str]] = []

    def resolve(
        self,
        policy_id: str,
        policy_revision: int,
        policy_digest: str,
    ) -> bytes:
        self.calls.append((policy_id, policy_revision, policy_digest))
        assert policy_revision >= 1
        assert policy_digest.startswith("sha256:")
        return self.policy_bytes


class _MemoryCustody:
    def __init__(self) -> None:
        self.objects: dict[str, dict[str, bytes | str]] = {}
        self.calls = 0
        self.failures_remaining = 0
        self.return_wrong_reference = False
        self.reference_prefix = "memory-worm"
        self._lock = threading.Lock()

    def reference_for(self, custody_object_id: str) -> str:
        return f"{self.reference_prefix}:{custody_object_id}"

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
    ) -> str:
        with self._lock:
            self.calls += 1
            if self.failures_remaining:
                self.failures_remaining -= 1
                raise OSError("simulated custody outage")
            assert _digest(envelope_bytes) == expected_envelope_digest
            assert _digest(cab_snapshot_bytes) == expected_cab_snapshot_digest
            assert _digest(trust_policy_bytes) == expected_trust_policy_digest
            assert _digest(receipt_bytes) == expected_receipt_digest
            candidate: dict[str, bytes | str] = {
                "reference": custody_reference,
                "receipt": receipt_bytes,
                "envelope": envelope_bytes,
                "snapshot": cab_snapshot_bytes,
                "policy": trust_policy_bytes,
                "receipt_digest": _digest(receipt_bytes),
                "envelope_digest": expected_envelope_digest,
                "snapshot_digest": expected_cab_snapshot_digest,
                "policy_digest": expected_trust_policy_digest,
            }
            previous = self.objects.setdefault(custody_object_id, candidate)
            if previous != candidate:
                raise RuntimeError("custody object id was reused for different bytes")
            if self.return_wrong_reference:
                return f"other:{custody_object_id}"
            return custody_reference

    def verify(
        self,
        *,
        custody_object_id: str,
        custody_reference: str,
        receipt_digest: str,
        envelope_digest: str,
        cab_snapshot_digest: str,
        trust_policy_digest: str,
    ) -> bool:
        with self._lock:
            item = self.objects.get(custody_object_id)
            return item == {
                "reference": custody_reference,
                "receipt": item["receipt"] if item else b"",
                "envelope": item["envelope"] if item else b"",
                "snapshot": item["snapshot"] if item else b"",
                "policy": item["policy"] if item else b"",
                "receipt_digest": receipt_digest,
                "envelope_digest": envelope_digest,
                "snapshot_digest": cab_snapshot_digest,
                "policy_digest": trust_policy_digest,
            }


class _OneShotFault:
    def __init__(self, target: FaultPoint) -> None:
        self._target = target
        self._raised = False

    def __call__(self, point: FaultPoint) -> None:
        if point == self._target and not self._raised:
            self._raised = True
            raise RuntimeError(f"simulated crash at {point}")


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _collector_key(seed: int = 4) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _trusted_key(
    private_key: Ed25519PrivateKey,
    *,
    key_id: str = "key:collector-a",
    identity: str = "collector:seoul-01",
) -> TrustedKey:
    public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return TrustedKey(
        key_id=key_id,
        identity=identity,
        algorithm="ed25519",
        public_key=base64.b64encode(public).decode("ascii"),
        allowed_payload_types=(COLLECTION_STATEMENT_MEDIA_TYPE,),
        valid_from="2026-07-01T00:00:00.000000Z",
        valid_until=None,
        status=KeyStatus.ACTIVE,
        revocation_effective_at=None,
    )


def _policy_bytes(
    collector_key: Ed25519PrivateKey,
    *,
    extra_key: TrustedKey | None = None,
) -> bytes:
    keys = [_trusted_key(collector_key)]
    if extra_key is not None:
        keys.append(extra_key)
    keys.sort(key=lambda key: key.key_id)
    policy = TrustPolicy(
        media_type=TRUST_POLICY_MEDIA_TYPE,
        schema_version=TRUST_POLICY_SCHEMA_VERSION,
        policy_id=POLICY_ID,
        threshold=1,
        trusted_keys=tuple(keys),
    )
    return policy.canonical_bytes()


def _manifest(payload: bytes) -> BundleManifest:
    return BundleManifest(
        media_type=ROOT_MEDIA_TYPE,
        schema_version=SCHEMA_VERSION,
        profile=PROFILE,
        created_at="2026-07-29T11:55:00.000000Z",
        as_of="2026-07-29T11:54:00.000000Z",
        experiment=ExperimentRef(
            id="financial-control-001",
            spec_version="1.0.0",
            spec_digest=f"sha256:{'7' * 64}",
        ),
        evaluation=EvaluationRef(
            policy_id="policy:financial-reference:v1",
            policy_digest=f"sha256:{'8' * 64}",
            evaluator=EvaluatorRef(
                name="assurance-lab",
                version="0.1.0",
                source_revision="test-revision",
                image_digest=None,
            ),
        ),
        parent_bundles=[],
        files=[
            BundleFile(
                path="records/events.jsonl",
                sha256=hashlib.sha256(payload).hexdigest(),
                size=len(payload),
                media_type="application/x-ndjson",
                role="control-observation",
                sensitivity=Sensitivity.SYNTHETIC,
                required_for=["admission"],
            )
        ],
    )


def _write_cab(root: Path, payload: bytes = b'{"id":"event:1","value":true}\n') -> BundleManifest:
    (root / "records").mkdir(parents=True)
    (root / "records/events.jsonl").write_bytes(payload)
    manifest = _manifest(payload)
    (root / "bundle.json").write_bytes(manifest.canonical_bytes())
    return manifest


def _grant(
    manifest: BundleManifest,
    *,
    signer: _Ed25519Signer | None = None,
    tenant_id: str = "tenant:bank-a",
    collector_id: str = "collector:seoul-01",
    audience: str = AUDIENCE,
    capability_digest: str = CAPABILITY_DIGEST,
    policy_revision: int = POLICY_REVISION,
    policy_digest: str | None = None,
    job_id: str = "job:0001",
    epoch: int = 1,
    sequence: int = 1,
    previous_epoch: int | None = None,
    previous_epoch_final_sequence: int | None = None,
    previous_epoch_final_receipt_digest: str | None = None,
    issued_at: datetime = NOW - timedelta(minutes=5),
    expires_at: datetime = NOW + timedelta(minutes=5),
    nonce_byte: int = 9,
) -> SignedJobLease:
    manifest_digest = _digest(manifest.canonical_bytes())
    selected_policy_digest = policy_digest or _digest(_policy_bytes(_collector_key()))
    return issue_signed_job_lease(
        signer=signer or _Ed25519Signer(1, "key:lease-authority"),
        tenant_id=tenant_id,
        collector_id=collector_id,
        audience=audience,
        job_id=job_id,
        capability_digest=capability_digest,
        policy_id=POLICY_ID,
        policy_revision=policy_revision,
        policy_digest=selected_policy_digest,
        epoch=epoch,
        sequence=sequence,
        previous_epoch=previous_epoch,
        previous_epoch_final_sequence=previous_epoch_final_sequence,
        previous_epoch_final_receipt_digest=previous_epoch_final_receipt_digest,
        cab_id=f"cab:{manifest_digest}",
        manifest_digest=manifest_digest,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce_factory=lambda size: bytes([nonce_byte]) * size,
    )


def _next_grant(
    anchor: SignedJobLease,
    *,
    sequence: int,
    nonce_byte: int,
) -> SignedJobLease:
    lease = anchor.lease
    return issue_signed_job_lease(
        signer=_Ed25519Signer(1, "key:lease-authority"),
        tenant_id=lease.tenant_id,
        collector_id=lease.collector_id,
        audience=lease.audience,
        job_id=f"job:{sequence:04d}",
        capability_digest=lease.capability_digest,
        policy_id=lease.policy_id,
        policy_revision=lease.policy_revision,
        policy_digest=lease.policy_digest,
        epoch=lease.epoch,
        sequence=sequence,
        cab_id=lease.cab_id,
        manifest_digest=lease.manifest_digest,
        issued_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(minutes=5),
        nonce_factory=lambda size: bytes([nonce_byte]) * size,
    )


def _statement(
    grant: SignedJobLease,
    *,
    collected_at: datetime = NOW - timedelta(minutes=1),
) -> CollectionStatement:
    lease = grant.lease
    return CollectionStatement(
        media_type=COLLECTION_STATEMENT_MEDIA_TYPE,
        schema_version=ADMISSION_SCHEMA_VERSION,
        lease_digest=lease.lease_digest(),
        tenant_id=lease.tenant_id,
        collector_id=lease.collector_id,
        audience=lease.audience,
        job_id=lease.job_id,
        capability_digest=lease.capability_digest,
        policy_id=lease.policy_id,
        policy_revision=lease.policy_revision,
        policy_digest=lease.policy_digest,
        epoch=lease.epoch,
        sequence=lease.sequence,
        previous_epoch=lease.previous_epoch,
        previous_epoch_final_sequence=lease.previous_epoch_final_sequence,
        previous_epoch_final_receipt_digest=lease.previous_epoch_final_receipt_digest,
        cab_id=lease.cab_id,
        manifest_digest=lease.manifest_digest,
        job_nonce=lease.job_nonce,
        collected_at=collected_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    )


def _envelope(
    statement: CollectionStatement,
    collector_key: Ed25519PrivateKey,
    *,
    pretty: bool = False,
) -> bytes:
    payload = statement.canonical_bytes()
    signature = collector_key.sign(dsse_pae(COLLECTION_STATEMENT_MEDIA_TYPE, payload))
    document = {
        "payload": base64.b64encode(payload).decode("ascii"),
        "payloadType": COLLECTION_STATEMENT_MEDIA_TYPE,
        "signatures": [
            {
                "keyid": "key:collector-a",
                "sig": base64.b64encode(signature).decode("ascii"),
            }
        ],
    }
    if pretty:
        return json.dumps(document, indent=2, sort_keys=True).encode()
    return canonical_json_bytes(document)


def _service(
    root: Path,
    *,
    resolver: _PolicyResolver,
    custody: _MemoryCustody | None = None,
    clock: _FixedClock | None = None,
    fault: _OneShotFault | None = None,
    limits: AdmissionLimits | None = None,
    lease_authority: _Ed25519Signer | None = None,
    receipt_signer: _Ed25519Signer | None = None,
) -> tuple[AdmissionService, _MemoryCustody, _FixedClock]:
    selected_custody = custody or _MemoryCustody()
    selected_clock = clock or _FixedClock()
    service = AdmissionService(
        root / "ledger" / "admission.sqlite3",
        lease_authority=lease_authority or _Ed25519Signer(1, "key:lease-authority"),
        receipt_signer=receipt_signer or _Ed25519Signer(2, "key:receipt-service"),
        policy_resolver=resolver,
        custody=selected_custody,
        expected_audience=AUDIENCE,
        expected_capability_digest=CAPABILITY_DIGEST,
        clock=selected_clock,
        limits=limits,
        fault_injector=fault,
    )
    return service, selected_custody, selected_clock


def _case(
    tmp_path: Path,
    *,
    fault: _OneShotFault | None = None,
    custody: _MemoryCustody | None = None,
    clock: _FixedClock | None = None,
    limits: AdmissionLimits | None = None,
) -> tuple[
    AdmissionService,
    _MemoryCustody,
    _FixedClock,
    _PolicyResolver,
    Ed25519PrivateKey,
    Path,
    SignedJobLease,
    bytes,
]:
    collector = _collector_key()
    resolver = _PolicyResolver(_policy_bytes(collector))
    cab = tmp_path / "cab"
    manifest = _write_cab(cab)
    grant = _grant(manifest)
    service, selected_custody, selected_clock = _service(
        tmp_path,
        resolver=resolver,
        custody=custody,
        clock=clock,
        fault=fault,
        limits=limits,
    )
    service.register_lease(grant.canonical_bytes())
    envelope = _envelope(_statement(grant), collector)
    return (
        service,
        selected_custody,
        selected_clock,
        resolver,
        collector,
        cab,
        grant,
        envelope,
    )


def _reason(call: Callable[[], object]) -> AdmissionRejectReason:
    with pytest.raises(AdmissionRejected) as caught:
        call()
    return caught.value.reason


def _database(root: Path) -> Path:
    return root / "ledger" / "admission.sqlite3"


def test_public_service_verifies_real_dsse_cab_policy_and_custody(
    tmp_path: Path,
) -> None:
    service, custody, clock, resolver, _collector, cab, grant, envelope = _case(tmp_path)

    outcome = service.admit(envelope_bytes=envelope, cab_source=cab)

    assert outcome.disposition == AdmissionDisposition.ADMITTED
    assert clock.calls == 1
    assert resolver.calls == [
        (
            grant.lease.policy_id,
            grant.lease.policy_revision,
            grant.lease.policy_digest,
        )
    ]
    assert outcome.receipt.body.lease_digest == grant.lease.lease_digest()
    assert outcome.receipt.body.cab_id == grant.lease.cab_id
    assert outcome.receipt.body.manifest_digest == grant.lease.manifest_digest
    assert outcome.receipt.body.accepted_key_ids == ("key:collector-a",)
    assert outcome.receipt.body.accepted_identities == ("collector:seoul-01",)
    assert (
        outcome.receipt.body.lease_authority_key_fingerprint
        == _Ed25519Signer(1, "key:lease-authority").key_fingerprint
    )
    assert (
        outcome.receipt.body.receipt_signer_key_fingerprint
        == _Ed25519Signer(2, "key:receipt-service").key_fingerprint
    )
    assert outcome.receipt.body.previous_receipt_digest is None
    assert outcome.custody_reference.startswith("memory-worm:")
    assert outcome.custody_acknowledgement.body.schema_version == "1.0.0"
    assert outcome.custody_acknowledgement.body.receipt_digest == (outcome.receipt.receipt_digest())
    assert (
        outcome.custody_acknowledgement.body.receipt_signer_key_fingerprint
        == outcome.receipt.body.receipt_signer_key_fingerprint
    )
    assert len(custody.objects) == 1
    stored = next(iter(custody.objects.values()))
    sealed = verify_cab_snapshot(stored["snapshot"])  # type: ignore[arg-type]
    assert sealed.cab_id == grant.lease.cab_id
    assert stored["policy"] == resolver.policy_bytes


def test_no_public_preverified_dto_or_mutable_path_seam(tmp_path: Path) -> None:
    collector = _collector_key()
    resolver = _PolicyResolver(_policy_bytes(collector))
    service, _custody, _clock = _service(tmp_path, resolver=resolver)

    assert not hasattr(service, "append_verified")
    assert set(AdmissionService.admit.__annotations__) >= {
        "envelope_bytes",
        "cab_source",
    }
    assert (
        _reason(
            lambda: service.admit(
                envelope_bytes=b"THIS IS NOT A DSSE ENVELOPE",
                cab_source=tmp_path,
            )
        )
        == AdmissionRejectReason.MALFORMED_ENVELOPE
    )


def test_configured_audience_and_capability_fail_before_policy_or_cab(
    tmp_path: Path,
) -> None:
    collector = _collector_key()
    resolver = _PolicyResolver(_policy_bytes(collector))
    cab = tmp_path / "cab"
    manifest = _write_cab(cab)
    wrong = _grant(manifest, audience="admission:development")
    service, _custody, _clock = _service(tmp_path, resolver=resolver)
    service.register_lease(wrong.canonical_bytes())

    reason = _reason(
        lambda: service.admit(
            envelope_bytes=_envelope(_statement(wrong), collector),
            cab_source=cab,
        )
    )

    assert reason == AdmissionRejectReason.CONFIGURATION_MISMATCH
    assert resolver.calls == []


def test_invalid_signature_cannot_supply_fictional_provenance(tmp_path: Path) -> None:
    (
        service,
        _custody,
        _clock,
        _resolver,
        _collector,
        cab,
        grant,
        _envelope_bytes,
    ) = _case(tmp_path)
    outsider = _collector_key(99)

    reason = _reason(
        lambda: service.admit(
            envelope_bytes=_envelope(_statement(grant), outsider),
            cab_source=cab,
        )
    )

    assert reason == AdmissionRejectReason.ATTESTATION_REJECTED


def test_lease_and_receipt_keys_must_be_separate(tmp_path: Path) -> None:
    collector = _collector_key()
    resolver = _PolicyResolver(_policy_bytes(collector))
    lease_signer = _Ed25519Signer(1, "key:lease-label")
    receipt_signer = _Ed25519Signer(1, "key:different-receipt-label")

    assert lease_signer.key_fingerprint == receipt_signer.key_fingerprint
    with pytest.raises(RuntimeError, match="distinct key material"):
        _service(
            tmp_path,
            resolver=resolver,
            lease_authority=lease_signer,
            receipt_signer=receipt_signer,
        )


def test_signer_cannot_claim_a_fingerprint_for_different_key_material(
    tmp_path: Path,
) -> None:
    manifest = _write_cab(tmp_path / "cab")

    reason = _reason(
        lambda: _grant(
            manifest,
            signer=_MisboundEd25519Signer(1, "key:misbound"),
        )
    )

    assert reason == AdmissionRejectReason.INVALID_LEASE_SIGNATURE


def test_ledger_pins_signer_material_across_restart(tmp_path: Path) -> None:
    collector = _collector_key()
    resolver = _PolicyResolver(_policy_bytes(collector))
    _service(tmp_path, resolver=resolver)

    with pytest.raises(RuntimeError, match="malformed admission ledger schema"):
        _service(
            tmp_path,
            resolver=resolver,
            receipt_signer=_Ed25519Signer(8, "key:receipt-service"),
        )


def test_exact_retry_requires_the_original_policy_snapshot(tmp_path: Path) -> None:
    service, custody, clock, resolver, collector, cab, _grant_value, envelope = _case(tmp_path)
    first = service.admit(envelope_bytes=envelope, cab_source=cab)
    extra = _trusted_key(
        _collector_key(44),
        key_id="key:unused-b",
        identity="collector:unused-b",
    )
    resolver.policy_bytes = _policy_bytes(collector, extra_key=extra)
    clock.value += timedelta(seconds=10)

    reason = _reason(lambda: service.admit(envelope_bytes=envelope, cab_source=cab))

    assert first.disposition == AdmissionDisposition.ADMITTED
    assert reason == AdmissionRejectReason.RETRY_MISMATCH
    assert custody.calls == 1


@pytest.mark.parametrize(
    ("first_revision", "second_revision", "expected_reason"),
    [
        (2, 1, AdmissionRejectReason.POLICY_ROLLBACK),
        (1, 1, AdmissionRejectReason.POLICY_FORK),
    ],
)
def test_policy_revision_history_rejects_rollback_and_fork(
    tmp_path: Path,
    first_revision: int,
    second_revision: int,
    expected_reason: AdmissionRejectReason,
) -> None:
    first_collector = _collector_key(4)
    second_collector = _collector_key(5)
    first_policy = _policy_bytes(first_collector)
    second_policy = _policy_bytes(second_collector)
    resolver = _PolicyResolver(first_policy)
    cab = tmp_path / "cab"
    manifest = _write_cab(cab)
    first_grant = _grant(
        manifest,
        policy_revision=first_revision,
        policy_digest=_digest(first_policy),
    )
    service, custody, clock = _service(tmp_path, resolver=resolver)
    service.register_lease(first_grant.canonical_bytes())
    first = service.admit(
        envelope_bytes=_envelope(_statement(first_grant), first_collector),
        cab_source=cab,
    )
    service, _same_custody, _same_clock = _service(
        tmp_path,
        resolver=resolver,
        custody=custody,
        clock=clock,
    )
    second_grant = _grant(
        manifest,
        job_id="job:policy-conflict",
        sequence=2,
        nonce_byte=10,
        policy_revision=second_revision,
        policy_digest=_digest(second_policy),
    )
    service.register_lease(second_grant.canonical_bytes())
    resolver.policy_bytes = second_policy
    clock.value += timedelta(seconds=1)

    reason = _reason(
        lambda: service.admit(
            envelope_bytes=_envelope(_statement(second_grant), second_collector),
            cab_source=cab,
        )
    )

    assert first.receipt.body.trust_policy_revision == first_revision
    assert first.receipt.body.trust_policy_digest == _digest(first_policy)
    assert reason == expected_reason
    with sqlite3.connect(_database(tmp_path)) as connection:
        assert connection.execute("SELECT count(*) FROM admissions").fetchone() == (1,)
        assert connection.execute(
            """
            SELECT current_revision, current_policy_digest
            FROM policy_heads WHERE policy_id = ?
            """,
            (POLICY_ID,),
        ).fetchone() == (first_revision, _digest(first_policy))


def test_resolver_must_return_the_exact_policy_digest_signed_by_the_lease(
    tmp_path: Path,
) -> None:
    signed_collector = _collector_key(4)
    other_policy = _policy_bytes(_collector_key(5))
    signed_policy = _policy_bytes(signed_collector)
    resolver = _PolicyResolver(other_policy)
    cab = tmp_path / "cab"
    manifest = _write_cab(cab)
    grant = _grant(manifest, policy_digest=_digest(signed_policy))
    service, _custody, _clock = _service(tmp_path, resolver=resolver)
    service.register_lease(grant.canonical_bytes())

    reason = _reason(
        lambda: service.admit(
            envelope_bytes=_envelope(_statement(grant), signed_collector),
            cab_source=cab,
        )
    )

    assert reason == AdmissionRejectReason.POLICY_UNAVAILABLE
    with sqlite3.connect(_database(tmp_path)) as connection:
        assert connection.execute("SELECT count(*) FROM admissions").fetchone() == (0,)


def test_higher_policy_revision_advances_with_exact_new_bytes(tmp_path: Path) -> None:
    first_collector = _collector_key(4)
    second_collector = _collector_key(5)
    first_policy = _policy_bytes(first_collector)
    second_policy = _policy_bytes(second_collector)
    resolver = _PolicyResolver(first_policy)
    cab = tmp_path / "cab"
    manifest = _write_cab(cab)
    first_grant = _grant(manifest, policy_digest=_digest(first_policy))
    service, _custody, clock = _service(tmp_path, resolver=resolver)
    service.register_lease(first_grant.canonical_bytes())
    service.admit(
        envelope_bytes=_envelope(_statement(first_grant), first_collector),
        cab_source=cab,
    )
    second_grant = _grant(
        manifest,
        job_id="job:policy-v2",
        sequence=2,
        nonce_byte=10,
        policy_revision=2,
        policy_digest=_digest(second_policy),
    )
    service.register_lease(second_grant.canonical_bytes())
    resolver.policy_bytes = second_policy
    clock.value += timedelta(seconds=1)

    second = service.admit(
        envelope_bytes=_envelope(_statement(second_grant), second_collector),
        cab_source=cab,
    )

    assert second.receipt.body.trust_policy_revision == 2
    assert second.receipt.body.trust_policy_digest == _digest(second_policy)
    with sqlite3.connect(_database(tmp_path)) as connection:
        assert connection.execute(
            """
            SELECT current_revision, current_policy_digest
            FROM policy_heads WHERE policy_id = ?
            """,
            (POLICY_ID,),
        ).fetchone() == (2, _digest(second_policy))


def test_exact_retry_returns_original_receipt_and_uses_stored_snapshot(
    tmp_path: Path,
) -> None:
    service, custody, clock, _resolver, _collector, cab, _grant_value, envelope = _case(tmp_path)
    first = service.admit(envelope_bytes=envelope, cab_source=cab)
    clock.value += timedelta(seconds=10)

    retry = service.admit(envelope_bytes=envelope, cab_source=cab)

    assert retry.disposition == AdmissionDisposition.EXACT_RETRY
    assert retry.receipt == first.receipt
    assert retry.custody_acknowledgement == first.custody_acknowledgement
    assert custody.calls == 2
    with sqlite3.connect(_database(tmp_path)) as connection:
        assert connection.execute("SELECT count(*) FROM admissions").fetchone() == (1,)


def test_exact_retry_binds_the_original_custody_destination(tmp_path: Path) -> None:
    service, custody, clock, _resolver, _collector, cab, _grant_value, envelope = _case(tmp_path)
    service.admit(envelope_bytes=envelope, cab_source=cab)
    custody.reference_prefix = "replacement-store"
    clock.value += timedelta(seconds=1)

    reason = _reason(lambda: service.admit(envelope_bytes=envelope, cab_source=cab))

    assert reason == AdmissionRejectReason.RETRY_MISMATCH
    assert custody.calls == 1


def test_same_signed_payload_with_different_raw_envelope_is_replay_conflict(
    tmp_path: Path,
) -> None:
    service, _custody, _clock, _resolver, collector, cab, grant, envelope = _case(tmp_path)
    service.admit(envelope_bytes=envelope, cab_source=cab)

    reason = _reason(
        lambda: service.admit(
            envelope_bytes=_envelope(_statement(grant), collector, pretty=True),
            cab_source=cab,
        )
    )

    assert reason == AdmissionRejectReason.REPLAY_CONFLICT


def test_mutated_source_after_commit_cannot_change_reconciled_custody(
    tmp_path: Path,
) -> None:
    fault = _OneShotFault(FaultPoint.AFTER_COMMIT_BEFORE_CUSTODY)
    service, custody, _clock, resolver, _collector, cab, _grant_value, envelope = _case(
        tmp_path,
        fault=fault,
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        service.admit(envelope_bytes=envelope, cab_source=cab)
    with sqlite3.connect(_database(tmp_path)) as connection:
        sealed_before = bytes(
            connection.execute("SELECT cab_snapshot_bytes FROM admissions").fetchone()[0]
        )
    (cab / "records/events.jsonl").write_bytes(b'{"id":"event:1","value":false}\n')
    recovered, _same_custody, _same_clock = _service(
        tmp_path,
        resolver=resolver,
        custody=custody,
    )

    assert recovered.reconcile_pending() == 1
    stored = next(iter(custody.objects.values()))
    assert stored["snapshot"] == sealed_before
    assert b"false" not in sealed_before


@pytest.mark.parametrize(
    "point",
    (
        FaultPoint.BEFORE_COMMIT,
        FaultPoint.AFTER_COMMIT_BEFORE_CUSTODY,
        FaultPoint.AFTER_CUSTODY_BEFORE_ACK,
    ),
)
def test_crash_boundaries_recover_one_admission(
    tmp_path: Path,
    point: FaultPoint,
) -> None:
    custody = _MemoryCustody()
    fault = _OneShotFault(point)
    (
        service,
        _selected,
        clock,
        resolver,
        _collector,
        cab,
        grant,
        envelope,
    ) = _case(tmp_path, fault=fault, custody=custody)

    if point == FaultPoint.BEFORE_COMMIT:
        assert (
            _reason(lambda: service.admit(envelope_bytes=envelope, cab_source=cab))
            == AdmissionRejectReason.STORAGE_UNAVAILABLE
        )
    else:
        with pytest.raises(RuntimeError, match="simulated crash"):
            service.admit(envelope_bytes=envelope, cab_source=cab)

    recovered, _custody, _clock = _service(
        tmp_path,
        resolver=resolver,
        custody=custody,
        clock=clock,
    )
    recovered.register_lease(grant.canonical_bytes())
    clock.value += timedelta(seconds=1)
    outcome = recovered.admit(envelope_bytes=envelope, cab_source=cab)
    expected = (
        AdmissionDisposition.ADMITTED
        if point == FaultPoint.BEFORE_COMMIT
        else AdmissionDisposition.EXACT_RETRY
    )
    assert outcome.disposition == expected
    with sqlite3.connect(_database(tmp_path)) as connection:
        assert connection.execute("SELECT count(*) FROM admissions").fetchone() == (1,)
        assert connection.execute("SELECT custody_state FROM admissions").fetchone() == ("durable",)


def test_custody_outage_is_pending_and_reconciled_without_source(
    tmp_path: Path,
) -> None:
    custody = _MemoryCustody()
    custody.failures_remaining = 1
    service, _selected, _clock, resolver, _collector, cab, _grant_value, envelope = _case(
        tmp_path, custody=custody
    )

    assert (
        _reason(lambda: service.admit(envelope_bytes=envelope, cab_source=cab))
        == AdmissionRejectReason.CUSTODY_UNAVAILABLE
    )
    for child in sorted(cab.rglob("*"), reverse=True):
        if child.is_file():
            child.unlink()
        else:
            child.rmdir()
    cab.rmdir()
    recovered, _custody, _clock = _service(
        tmp_path,
        resolver=resolver,
        custody=custody,
    )

    assert recovered.reconcile_pending() == 1
    assert custody.calls == 2


def test_pending_custody_is_a_tenant_tail_barrier_until_reconciled(
    tmp_path: Path,
) -> None:
    custody = _MemoryCustody()
    custody.failures_remaining = 1
    (
        service,
        _selected,
        clock,
        _resolver,
        collector,
        cab,
        first_grant,
        first_envelope,
    ) = _case(tmp_path, custody=custody)
    second_grant = _next_grant(first_grant, sequence=2, nonce_byte=10)
    service.register_lease(second_grant.canonical_bytes())

    assert (
        _reason(
            lambda: service.admit(
                envelope_bytes=first_envelope,
                cab_source=cab,
            )
        )
        == AdmissionRejectReason.CUSTODY_UNAVAILABLE
    )
    clock.value += timedelta(seconds=1)
    second_envelope = _envelope(_statement(second_grant), collector)

    assert (
        _reason(
            lambda: service.admit(
                envelope_bytes=second_envelope,
                cab_source=cab,
            )
        )
        == AdmissionRejectReason.CUSTODY_UNAVAILABLE
    )
    with sqlite3.connect(_database(tmp_path)) as connection:
        assert connection.execute(
            "SELECT receipt_sequence, custody_state FROM admissions"
        ).fetchall() == [(1, "pending")]
        assert connection.execute(
            """
            SELECT consumed_envelope_digest, consumed_receipt_digest
            FROM job_leases WHERE lease_digest = ?
            """,
            (second_grant.lease.lease_digest(),),
        ).fetchone() == (None, None)

    assert service.reconcile_pending() == 1
    second = service.admit(
        envelope_bytes=second_envelope,
        cab_source=cab,
    )

    assert second.disposition == AdmissionDisposition.ADMITTED
    with sqlite3.connect(_database(tmp_path)) as connection:
        assert connection.execute(
            "SELECT receipt_sequence, custody_state FROM admissions ORDER BY receipt_sequence"
        ).fetchall() == [(1, "durable"), (2, "durable")]


def test_acknowledgement_cannot_skip_an_earlier_pending_receipt(
    tmp_path: Path,
) -> None:
    (
        service,
        _custody,
        clock,
        _resolver,
        collector,
        cab,
        first_grant,
        first_envelope,
    ) = _case(tmp_path)
    service.admit(envelope_bytes=first_envelope, cab_source=cab)
    second_grant = _next_grant(first_grant, sequence=2, nonce_byte=10)
    service.register_lease(second_grant.canonical_bytes())
    clock.value += timedelta(seconds=1)
    second = service.admit(
        envelope_bytes=_envelope(_statement(second_grant), collector),
        cab_source=cab,
    )

    # Simulate a legacy/crash-recovered ledger that predates the tail barrier.
    connection = service._ledger._connection
    assert connection is not None
    with service._ledger._connection_lock:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            UPDATE admissions
            SET custody_state = 'pending',
                custody_ack_digest = NULL,
                custody_ack_bytes = NULL
            """
        )
        connection.commit()

    assert (
        _reason(
            lambda: service._ledger.mark_custody_durable(
                receipt_digest=second.receipt.receipt_digest(),
                custody_reference=second.receipt.body.custody_reference,
            )
        )
        == AdmissionRejectReason.CUSTODY_UNAVAILABLE
    )
    assert service.reconcile_pending() == 2
    with sqlite3.connect(_database(tmp_path)) as external:
        assert external.execute(
            "SELECT receipt_sequence, custody_state FROM admissions ORDER BY receipt_sequence"
        ).fetchall() == [(1, "durable"), (2, "durable")]


def test_non_idempotent_custody_reference_is_rejected(tmp_path: Path) -> None:
    custody = _MemoryCustody()
    custody.return_wrong_reference = True
    service, _selected, _clock, _resolver, _collector, cab, _grant_value, envelope = _case(
        tmp_path, custody=custody
    )

    reason = _reason(lambda: service.admit(envelope_bytes=envelope, cab_source=cab))

    assert reason == AdmissionRejectReason.CUSTODY_UNAVAILABLE
    with sqlite3.connect(_database(tmp_path)) as connection:
        assert connection.execute(
            "SELECT custody_state, custody_ack_bytes FROM admissions"
        ).fetchone() == ("pending", None)


def test_clock_is_read_once_and_rollback_fails_closed(tmp_path: Path) -> None:
    service, _custody, clock, _resolver, _collector, cab, _grant_value, envelope = _case(tmp_path)
    service.admit(envelope_bytes=envelope, cab_source=cab)
    assert clock.calls == 1
    clock.value -= timedelta(seconds=1)

    reason = _reason(lambda: service.admit(envelope_bytes=envelope, cab_source=cab))

    assert reason == AdmissionRejectReason.CLOCK_ROLLBACK
    assert clock.calls == 2


def test_expired_lease_cannot_be_backdated_by_the_caller(tmp_path: Path) -> None:
    collector = _collector_key()
    resolver = _PolicyResolver(_policy_bytes(collector))
    cab = tmp_path / "cab"
    manifest = _write_cab(cab)
    grant = _grant(manifest, expires_at=NOW)
    clock = _FixedClock(NOW + timedelta(seconds=1))
    service, _custody, _clock = _service(tmp_path, resolver=resolver, clock=clock)
    service.register_lease(grant.canonical_bytes())

    reason = _reason(
        lambda: service.admit(
            envelope_bytes=_envelope(_statement(grant), collector),
            cab_source=cab,
        )
    )

    assert reason == AdmissionRejectReason.LEASE_EXPIRED
    assert "admitted_at" not in AdmissionService.admit.__annotations__


def test_signed_epoch_transition_retires_the_previous_epoch(tmp_path: Path) -> None:
    (
        service,
        _custody,
        clock,
        _resolver,
        collector,
        cab,
        first_grant,
        first_envelope,
    ) = _case(tmp_path)
    first = service.admit(envelope_bytes=first_envelope, cab_source=cab)
    old_sequence = _grant(
        _manifest(b'{"id":"event:old","value":true}\n'),
        job_id="job:old-sequence",
        epoch=1,
        sequence=2,
        nonce_byte=10,
    )
    # Keep the CAB identity equal to the source used for the actual stale attempt.
    old_sequence = issue_signed_job_lease(
        signer=_Ed25519Signer(1, "key:lease-authority"),
        tenant_id=first_grant.lease.tenant_id,
        collector_id=first_grant.lease.collector_id,
        audience=AUDIENCE,
        job_id="job:old-sequence",
        capability_digest=CAPABILITY_DIGEST,
        policy_id=POLICY_ID,
        policy_revision=first_grant.lease.policy_revision,
        policy_digest=first_grant.lease.policy_digest,
        epoch=1,
        sequence=2,
        cab_id=first_grant.lease.cab_id,
        manifest_digest=first_grant.lease.manifest_digest,
        issued_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(minutes=5),
        nonce_factory=lambda size: bytes([10]) * size,
    )
    service.register_lease(old_sequence.canonical_bytes())
    epoch_two = _grant(
        _manifest(b'{"id":"event:unused","value":true}\n'),
        job_id="job:epoch-two",
        epoch=2,
        sequence=1,
        previous_epoch=1,
        previous_epoch_final_sequence=1,
        previous_epoch_final_receipt_digest=first.receipt.receipt_digest(),
        nonce_byte=11,
    )
    epoch_two = issue_signed_job_lease(
        signer=_Ed25519Signer(1, "key:lease-authority"),
        tenant_id=first_grant.lease.tenant_id,
        collector_id=first_grant.lease.collector_id,
        audience=AUDIENCE,
        job_id="job:epoch-two",
        capability_digest=CAPABILITY_DIGEST,
        policy_id=POLICY_ID,
        policy_revision=first_grant.lease.policy_revision,
        policy_digest=first_grant.lease.policy_digest,
        epoch=2,
        sequence=1,
        previous_epoch=1,
        previous_epoch_final_sequence=1,
        previous_epoch_final_receipt_digest=first.receipt.receipt_digest(),
        cab_id=first_grant.lease.cab_id,
        manifest_digest=first_grant.lease.manifest_digest,
        issued_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(minutes=5),
        nonce_factory=lambda size: bytes([11]) * size,
    )
    service.register_lease(epoch_two.canonical_bytes())
    clock.value += timedelta(seconds=1)
    second = service.admit(
        envelope_bytes=_envelope(_statement(epoch_two), collector),
        cab_source=cab,
    )
    clock.value += timedelta(seconds=1)

    reason = _reason(
        lambda: service.admit(
            envelope_bytes=_envelope(_statement(old_sequence), collector),
            cab_source=cab,
        )
    )

    assert second.receipt.body.epoch == 2
    assert second.receipt.body.previous_epoch == 1
    assert second.receipt.body.previous_epoch_final_sequence == 1
    assert second.receipt.body.previous_epoch_final_receipt_digest == first.receipt.receipt_digest()
    assert reason == AdmissionRejectReason.EPOCH_MISMATCH


def test_epoch_transition_must_bind_the_current_collector_head(tmp_path: Path) -> None:
    service, _custody, _clock, _resolver, _collector, cab, grant, envelope = _case(tmp_path)
    first = service.admit(envelope_bytes=envelope, cab_source=cab)
    wrong_predecessor = _grant(
        _manifest(b'{"id":"unused","value":true}\n'),
        job_id="job:bad-epoch",
        epoch=2,
        sequence=1,
        previous_epoch=1,
        previous_epoch_final_sequence=1,
        previous_epoch_final_receipt_digest=f"sha256:{'f' * 64}",
        nonce_byte=12,
    )

    reason = _reason(lambda: service.register_lease(wrong_predecessor.canonical_bytes()))

    assert first.receipt.body.epoch == grant.lease.epoch
    assert reason == AdmissionRejectReason.EPOCH_MISMATCH


def test_stored_lease_signature_is_reverified_before_admission(tmp_path: Path) -> None:
    service, _custody, _clock, _resolver, _collector, cab, _grant_value, envelope = _case(tmp_path)
    database = _database(tmp_path)
    with sqlite3.connect(database) as connection:
        raw = bytes(connection.execute("SELECT grant_bytes FROM job_leases").fetchone()[0])
        document = json.loads(raw)
        document["authority_signature"]["signature"] = base64.b64encode(bytes(64)).decode("ascii")
        connection.execute(
            "UPDATE job_leases SET grant_bytes = ?",
            (canonical_json_bytes(document),),
        )

    reason = _reason(lambda: service.admit(envelope_bytes=envelope, cab_source=cab))

    assert reason == AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR


def test_stored_receipt_signature_is_reverified_on_retry(tmp_path: Path) -> None:
    fault = _OneShotFault(FaultPoint.AFTER_COMMIT_BEFORE_CUSTODY)
    service, _custody, _clock, _resolver, _collector, cab, _grant_value, envelope = _case(
        tmp_path,
        fault=fault,
    )
    with pytest.raises(RuntimeError):
        service.admit(envelope_bytes=envelope, cab_source=cab)
    database = _database(tmp_path)
    with sqlite3.connect(database) as connection:
        raw = bytes(connection.execute("SELECT receipt_bytes FROM admissions").fetchone()[0])
        document = json.loads(raw)
        document["service_signature"]["signature"] = base64.b64encode(bytes(64)).decode("ascii")
        connection.execute(
            "UPDATE admissions SET receipt_bytes = ?",
            (canonical_json_bytes(document),),
        )

    reason = _reason(lambda: service.admit(envelope_bytes=envelope, cab_source=cab))

    assert reason == AdmissionRejectReason.INVALID_RECEIPT_SIGNATURE


def test_stored_snapshot_digest_is_reverified_on_retry(tmp_path: Path) -> None:
    service, _custody, _clock, _resolver, _collector, cab, _grant_value, envelope = _case(tmp_path)
    service.admit(envelope_bytes=envelope, cab_source=cab)
    with sqlite3.connect(_database(tmp_path)) as connection:
        original = bytes(
            connection.execute("SELECT cab_snapshot_bytes FROM admissions").fetchone()[0]
        )
        connection.execute(
            "UPDATE admissions SET cab_snapshot_bytes = ?",
            (original + b"\x00",),
        )

    reason = _reason(lambda: service.admit(envelope_bytes=envelope, cab_source=cab))

    assert reason == AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR


def test_stored_policy_is_reparsed_and_attestation_is_reverified(
    tmp_path: Path,
) -> None:
    service, _custody, _clock, _resolver, _collector, cab, _grant_value, envelope = _case(tmp_path)
    service.admit(envelope_bytes=envelope, cab_source=cab)
    with sqlite3.connect(_database(tmp_path)) as connection:
        original = bytes(connection.execute("SELECT policy_bytes FROM admissions").fetchone()[0])
        connection.execute(
            "UPDATE admissions SET policy_bytes = ?",
            (original + b"\x00",),
        )

    reason = _reason(lambda: service.admit(envelope_bytes=envelope, cab_source=cab))

    assert reason == AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR


def test_tampered_head_is_not_notarized_into_the_next_receipt(tmp_path: Path) -> None:
    (
        service,
        _custody,
        clock,
        _resolver,
        collector,
        cab,
        first_grant,
        envelope,
    ) = _case(tmp_path)
    service.admit(envelope_bytes=envelope, cab_source=cab)
    second = issue_signed_job_lease(
        signer=_Ed25519Signer(1, "key:lease-authority"),
        tenant_id=first_grant.lease.tenant_id,
        collector_id=first_grant.lease.collector_id,
        audience=AUDIENCE,
        job_id="job:0002",
        capability_digest=CAPABILITY_DIGEST,
        policy_id=POLICY_ID,
        policy_revision=first_grant.lease.policy_revision,
        policy_digest=first_grant.lease.policy_digest,
        epoch=1,
        sequence=2,
        cab_id=first_grant.lease.cab_id,
        manifest_digest=first_grant.lease.manifest_digest,
        issued_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(minutes=5),
        nonce_factory=lambda size: bytes([10]) * size,
    )
    service.register_lease(second.canonical_bytes())
    with sqlite3.connect(_database(tmp_path)) as connection:
        connection.execute(
            """
            UPDATE tenant_heads
            SET last_receipt_sequence = 41,
                last_receipt_digest = ?
            """,
            (f"sha256:{'d' * 64}",),
        )
    clock.value += timedelta(seconds=1)

    reason = _reason(
        lambda: service.admit(
            envelope_bytes=_envelope(_statement(second), collector),
            cab_source=cab,
        )
    )

    assert reason == AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR


@pytest.mark.parametrize(
    ("mutation", "expected_reason"),
    (
        ("delete-sequence-one", AdmissionRejectReason.INTERNAL_INTEGRITY_ERROR),
        ("forge-sequence-one", AdmissionRejectReason.INVALID_RECEIPT_SIGNATURE),
    ),
)
def test_complete_chain_validation_blocks_a_fourth_receipt_after_historical_tamper(
    tmp_path: Path,
    mutation: str,
    expected_reason: AdmissionRejectReason,
) -> None:
    (
        service,
        custody,
        clock,
        resolver,
        collector,
        cab,
        first_grant,
        first_envelope,
    ) = _case(tmp_path)
    grants = [
        first_grant,
        _next_grant(first_grant, sequence=2, nonce_byte=10),
        _next_grant(first_grant, sequence=3, nonce_byte=11),
        _next_grant(first_grant, sequence=4, nonce_byte=12),
    ]
    for grant in grants[1:]:
        service.register_lease(grant.canonical_bytes())
    for index, grant in enumerate(grants[:3]):
        if index:
            clock.value += timedelta(seconds=1)
        service.admit(
            envelope_bytes=(
                first_envelope if index == 0 else _envelope(_statement(grant), collector)
            ),
            cab_source=cab,
        )

    with sqlite3.connect(_database(tmp_path)) as connection:
        if mutation == "delete-sequence-one":
            connection.execute(
                "DELETE FROM admissions WHERE tenant_id = ? AND receipt_sequence = 1",
                (first_grant.lease.tenant_id,),
            )
        else:
            raw = bytes(
                connection.execute(
                    """
                    SELECT receipt_bytes FROM admissions
                    WHERE tenant_id = ? AND receipt_sequence = 1
                    """,
                    (first_grant.lease.tenant_id,),
                ).fetchone()[0]
            )
            forged = json.loads(raw)
            forged["service_signature"]["signature"] = base64.b64encode(bytes(64)).decode("ascii")
            connection.execute(
                """
                UPDATE admissions SET receipt_bytes = ?
                WHERE tenant_id = ? AND receipt_sequence = 1
                """,
                (
                    canonical_json_bytes(forged),
                    first_grant.lease.tenant_id,
                ),
            )

    with pytest.raises(RuntimeError, match="history validation"):
        _service(
            tmp_path,
            resolver=resolver,
            custody=custody,
            clock=clock,
        )
    clock.value += timedelta(seconds=1)
    fourth_envelope = _envelope(_statement(grants[3]), collector)

    assert (
        _reason(
            lambda: service.admit(
                envelope_bytes=fourth_envelope,
                cab_source=cab,
            )
        )
        == expected_reason
    )
    with sqlite3.connect(_database(tmp_path)) as connection:
        assert connection.execute(
            "SELECT count(*) FROM admissions WHERE receipt_sequence = 4"
        ).fetchone() == (0,)
        assert connection.execute(
            """
            SELECT consumed_envelope_digest, consumed_receipt_digest
            FROM job_leases WHERE lease_digest = ?
            """,
            (grants[3].lease.lease_digest(),),
        ).fetchone() == (None, None)


def test_normal_appends_reuse_the_validated_head_without_a_full_history_walk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        service,
        _custody,
        clock,
        _resolver,
        collector,
        cab,
        first_grant,
        first_envelope,
    ) = _case(tmp_path)
    full_walks = 0

    def count_full_walk(_connection: sqlite3.Connection) -> None:
        nonlocal full_walks
        full_walks += 1

    monkeypatch.setattr(service._ledger, "_validate_complete_ledger", count_full_walk)
    service.admit(envelope_bytes=first_envelope, cab_source=cab)
    second_grant = _next_grant(first_grant, sequence=2, nonce_byte=10)
    service.register_lease(second_grant.canonical_bytes())
    clock.value += timedelta(seconds=1)
    service.admit(
        envelope_bytes=_envelope(_statement(second_grant), collector),
        cab_source=cab,
    )

    assert full_walks == 0


def test_concurrent_different_envelopes_consume_one_lease_once(
    tmp_path: Path,
) -> None:
    service, _custody, _clock, _resolver, collector, cab, grant, canonical = _case(tmp_path)
    pretty = _envelope(_statement(grant), collector, pretty=True)
    barrier = threading.Barrier(2)
    results: list[str] = []

    def contender(envelope_bytes: bytes) -> None:
        barrier.wait()
        try:
            outcome = service.admit(envelope_bytes=envelope_bytes, cab_source=cab)
            results.append(outcome.disposition.value)
        except AdmissionRejected as exc:
            results.append(exc.reason.value)

    threads = [
        threading.Thread(target=contender, args=(canonical,)),
        threading.Thread(target=contender, args=(pretty,)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(results) == ["admitted", "replay-conflict"]
    with sqlite3.connect(_database(tmp_path)) as connection:
        assert connection.execute("SELECT count(*) FROM admissions").fetchone() == (1,)


def test_registration_is_idempotent_and_conflicts_are_stable(tmp_path: Path) -> None:
    service, _custody, _clock, _resolver, _collector, _cab, grant, _envelope_bytes = _case(tmp_path)

    assert service.register_lease(grant.canonical_bytes()) == grant
    duplicate = grant.model_copy(
        update={
            "lease": grant.lease.model_copy(
                update={
                    "job_id": "job:other",
                }
            )
        }
    )
    # The copied grant is deliberately invalid under the authority signature.
    assert (
        _reason(lambda: service.register_lease(duplicate.canonical_bytes()))
        == AdmissionRejectReason.INVALID_LEASE_SIGNATURE
    )


def test_resource_limit_fails_before_envelope_parsing(tmp_path: Path) -> None:
    collector = _collector_key()
    resolver = _PolicyResolver(_policy_bytes(collector))
    limits = AdmissionLimits(
        max_envelope_bytes=1024,
        max_policy_bytes=1024 * 1024,
        max_cab_snapshot_bytes=4 * 1024 * 1024,
        max_admissions_per_tenant=1,
        max_database_bytes=64 * 1024 * 1024,
    )
    service, _custody, _clock = _service(tmp_path, resolver=resolver, limits=limits)
    assert (
        _reason(
            lambda: service.admit(
                envelope_bytes=b"x" * 1025,
                cab_source=tmp_path,
            )
        )
        == AdmissionRejectReason.RESOURCE_LIMIT_EXCEEDED
    )


def test_tenant_quota_rolls_back_the_second_admission(tmp_path: Path) -> None:
    limits = AdmissionLimits(max_admissions_per_tenant=1)
    (
        service,
        _custody,
        clock,
        _resolver,
        collector,
        cab,
        first_grant,
        first_envelope,
    ) = _case(tmp_path, limits=limits)
    service.admit(envelope_bytes=first_envelope, cab_source=cab)
    second = issue_signed_job_lease(
        signer=_Ed25519Signer(1, "key:lease-authority"),
        tenant_id=first_grant.lease.tenant_id,
        collector_id=first_grant.lease.collector_id,
        audience=AUDIENCE,
        job_id="job:quota-second",
        capability_digest=CAPABILITY_DIGEST,
        policy_id=POLICY_ID,
        policy_revision=first_grant.lease.policy_revision,
        policy_digest=first_grant.lease.policy_digest,
        epoch=1,
        sequence=2,
        cab_id=first_grant.lease.cab_id,
        manifest_digest=first_grant.lease.manifest_digest,
        issued_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(minutes=5),
        nonce_factory=lambda size: bytes([77]) * size,
    )
    service.register_lease(second.canonical_bytes())
    clock.value += timedelta(seconds=1)

    reason = _reason(
        lambda: service.admit(
            envelope_bytes=_envelope(_statement(second), collector),
            cab_source=cab,
        )
    )

    assert reason == AdmissionRejectReason.QUOTA_EXCEEDED
    with sqlite3.connect(_database(tmp_path)) as connection:
        assert connection.execute("SELECT count(*) FROM admissions").fetchone() == (1,)
        assert connection.execute(
            """
            SELECT consumed_envelope_digest
            FROM job_leases
            WHERE lease_digest = ?
            """,
            (second.lease.lease_digest(),),
        ).fetchone() == (None,)


def test_registered_lease_quota_rejects_before_insertion(tmp_path: Path) -> None:
    limits = AdmissionLimits(max_registered_leases_per_tenant=1)
    service, _custody, _clock, _resolver, _collector, _cab, grant, _envelope_bytes = _case(
        tmp_path, limits=limits
    )
    second = grant.model_copy(
        update={
            "lease": grant.lease.model_copy(
                update={
                    "job_id": "job:lease-quota",
                    "sequence": 2,
                    "job_nonce": "ab" * 32,
                }
            )
        }
    )
    signer = _Ed25519Signer(1, "key:lease-authority")
    second = second.model_copy(
        update={"authority_signature": signer.sign(second.lease.canonical_bytes())}
    )

    reason = _reason(lambda: service.register_lease(second.canonical_bytes()))

    assert reason == AdmissionRejectReason.QUOTA_EXCEEDED
    with sqlite3.connect(_database(tmp_path)) as connection:
        assert connection.execute("SELECT count(*) FROM job_leases").fetchone() == (1,)


def test_private_database_permissions_and_no_mutable_bundle_path(
    tmp_path: Path,
) -> None:
    service, _custody, _clock, _resolver, _collector, cab, _grant_value, envelope = _case(tmp_path)
    service.admit(envelope_bytes=envelope, cab_source=cab)
    database = _database(tmp_path)

    assert stat.S_IMODE(os.stat(database.parent).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(database).st_mode) == 0o600
    with sqlite3.connect(database) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(admissions)")}
    assert "bundle_path" not in columns
    assert {"cab_snapshot_bytes", "cab_snapshot_digest", "policy_bytes"} <= columns


def test_broad_database_mode_and_schema_tamper_are_rejected(tmp_path: Path) -> None:
    collector = _collector_key()
    resolver = _PolicyResolver(_policy_bytes(collector))
    service, _custody, _clock = _service(tmp_path, resolver=resolver)
    database = _database(tmp_path)
    os.chmod(database, 0o644)
    with pytest.raises(RuntimeError, match="mode 0600"):
        _service(tmp_path, resolver=resolver)
    os.chmod(database, 0o600)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE collector_heads")
    with pytest.raises(RuntimeError, match="malformed admission ledger schema"):
        _service(tmp_path, resolver=resolver)
    assert service is not None


def test_database_hardlinks_and_sidecar_symlinks_are_rejected(tmp_path: Path) -> None:
    collector = _collector_key()
    resolver = _PolicyResolver(_policy_bytes(collector))
    _service(tmp_path, resolver=resolver)
    database = _database(tmp_path)
    alias = database.with_name("admission-alias.sqlite3")
    os.link(database, alias)
    with pytest.raises(RuntimeError, match="single-link"):
        _service(tmp_path, resolver=resolver)
    alias.unlink()

    sidecar = Path(f"{database}-wal")
    if sidecar.exists() or sidecar.is_symlink():
        sidecar.unlink()
    target = tmp_path / "must-not-be-opened"
    target.write_bytes(b"sentinel")
    sidecar.symlink_to(target)
    with pytest.raises(RuntimeError, match="single-link regular files"):
        _service(tmp_path, resolver=resolver)
    assert target.read_bytes() == b"sentinel"


def test_symbolic_link_in_database_ancestry_is_rejected(tmp_path: Path) -> None:
    collector = _collector_key()
    resolver = _PolicyResolver(_policy_bytes(collector))
    real_root = tmp_path / "real-root"
    real_root.mkdir(mode=0o700)
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(real_root, target_is_directory=True)

    with pytest.raises(RuntimeError, match="symbolic link"):
        _service(linked_root, resolver=resolver)

    assert not (real_root / "ledger" / "admission.sqlite3").exists()


def test_database_parent_and_inode_are_pinned_for_service_lifetime(
    tmp_path: Path,
) -> None:
    collector = _collector_key()
    resolver = _PolicyResolver(_policy_bytes(collector))
    service, _custody, _clock = _service(tmp_path, resolver=resolver)
    cab = tmp_path / "cab"
    grant = _grant(_write_cab(cab))
    original_parent = _database(tmp_path).parent
    moved_parent = tmp_path / "original-ledger"
    original_parent.rename(moved_parent)
    original_parent.mkdir(mode=0o700)

    reason = _reason(lambda: service.register_lease(grant.canonical_bytes()))

    assert reason == AdmissionRejectReason.STORAGE_UNAVAILABLE
    assert not _database(tmp_path).exists()


def test_sqlite_reported_database_inode_is_verified_after_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collector = _collector_key()
    resolver = _PolicyResolver(_policy_bytes(collector))
    _service(tmp_path / "other", resolver=resolver)
    other_database = _database(tmp_path / "other")
    real_connect = sqlite3.connect

    def redirect_pinned_open(
        database: str | bytes | Path,
        *args: Any,
        **kwargs: Any,
    ) -> sqlite3.Connection:
        if str(database).startswith("/proc/self/fd/"):
            return cast(
                sqlite3.Connection,
                real_connect(other_database, *args, **kwargs),
            )
        return cast(sqlite3.Connection, real_connect(database, *args, **kwargs))

    monkeypatch.setattr(sqlite3, "connect", redirect_pinned_open)

    with pytest.raises(RuntimeError, match="different admission database inode"):
        _service(tmp_path / "primary", resolver=resolver)


def test_rename_swap_during_sqlite_open_cannot_redirect_the_pinned_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collector = _collector_key()
    resolver = _PolicyResolver(_policy_bytes(collector))
    primary, _custody, _clock = _service(tmp_path / "primary", resolver=resolver)
    alternate, _other_custody, _other_clock = _service(
        tmp_path / "alternate",
        resolver=resolver,
    )
    primary_database = _database(tmp_path / "primary")
    alternate_database = _database(tmp_path / "alternate")
    primary_inode = (primary_database.stat().st_dev, primary_database.stat().st_ino)
    alternate_inode = (alternate_database.stat().st_dev, alternate_database.stat().st_ino)
    primary._ledger._close_storage()
    alternate._ledger._close_storage()
    displaced = primary_database.with_name("admission-original.sqlite3")
    opened_inode: tuple[int, int] | None = None
    swapped = False
    real_connect = sqlite3.connect

    def swap_after_pin(
        database: str | bytes | Path,
        *args: Any,
        **kwargs: Any,
    ) -> sqlite3.Connection:
        nonlocal opened_inode, swapped
        if str(database).startswith("/proc/self/fd/") and not swapped:
            swapped = True
            primary_database.rename(displaced)
            alternate_database.replace(primary_database)
            connection = cast(sqlite3.Connection, real_connect(database, *args, **kwargs))
            opened_path = str(connection.execute("PRAGMA database_list").fetchone()[2])
            selected = os.stat(opened_path, follow_symlinks=False)
            opened_inode = (selected.st_dev, selected.st_ino)
            return connection
        return cast(sqlite3.Connection, real_connect(database, *args, **kwargs))

    monkeypatch.setattr(sqlite3, "connect", swap_after_pin)

    with pytest.raises(RuntimeError, match="database identity changed"):
        _service(tmp_path / "primary", resolver=resolver)

    assert swapped
    assert opened_inode == primary_inode
    assert opened_inode != alternate_inode


def test_wal_symlink_injected_during_sqlite_open_is_rejected_without_touching_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collector = _collector_key()
    resolver = _PolicyResolver(_policy_bytes(collector))
    service, _custody, _clock = _service(tmp_path, resolver=resolver)
    database = _database(tmp_path)
    service._ledger._close_storage()
    wal = Path(f"{database}-wal")
    if wal.exists() or wal.is_symlink():
        wal.unlink()
    sentinel = tmp_path / "wal-sentinel"
    sentinel.write_bytes(b"must remain unchanged")
    injected = False
    real_connect = sqlite3.connect

    def inject_sidecar_after_precheck(
        selected_database: str | bytes | Path,
        *args: Any,
        **kwargs: Any,
    ) -> sqlite3.Connection:
        nonlocal injected
        if str(selected_database).startswith("/proc/self/fd/") and not injected:
            injected = True
            wal.symlink_to(sentinel)
        return cast(
            sqlite3.Connection,
            real_connect(selected_database, *args, **kwargs),
        )

    monkeypatch.setattr(sqlite3, "connect", inject_sidecar_after_precheck)

    with pytest.raises(
        RuntimeError,
        match=r"private admission database|single-link regular files",
    ):
        _service(tmp_path, resolver=resolver)

    assert injected
    assert sentinel.read_bytes() == b"must remain unchanged"


def test_database_quota_applies_at_startup(tmp_path: Path) -> None:
    collector = _collector_key()
    resolver = _PolicyResolver(_policy_bytes(collector))
    limits = AdmissionLimits(max_database_bytes=1)

    with pytest.raises(RuntimeError, match="configured byte quota"):
        _service(tmp_path, resolver=resolver, limits=limits)


def test_cab_manifest_identity_must_match_signed_statement(tmp_path: Path) -> None:
    service, _custody, _clock, _resolver, collector, _cab, grant, _envelope_bytes = _case(tmp_path)
    other = tmp_path / "other-cab"
    _write_cab(other, b'{"id":"event:2","value":true}\n')

    reason = _reason(
        lambda: service.admit(
            envelope_bytes=_envelope(_statement(grant), collector),
            cab_source=other,
        )
    )

    assert reason == AdmissionRejectReason.CAB_REJECTED


def test_sequence_two_cannot_arrive_before_sequence_one(tmp_path: Path) -> None:
    collector = _collector_key()
    resolver = _PolicyResolver(_policy_bytes(collector))
    cab = tmp_path / "cab"
    manifest = _write_cab(cab)
    second = _grant(
        manifest,
        job_id="job:0002",
        sequence=2,
        nonce_byte=10,
    )
    service, _custody, _clock = _service(tmp_path, resolver=resolver)
    service.register_lease(second.canonical_bytes())

    reason = _reason(
        lambda: service.admit(
            envelope_bytes=_envelope(_statement(second), collector),
            cab_source=cab,
        )
    )

    assert reason == AdmissionRejectReason.EPOCH_MISMATCH


def test_model_construct_cannot_cross_the_raw_public_boundary(tmp_path: Path) -> None:
    service, _custody, _clock, _resolver, _collector, cab, grant, _envelope_bytes = _case(tmp_path)
    primitive: dict[str, Any] = _statement(grant).model_dump(mode="json")
    primitive["sequence"] = "1"
    forged = CollectionStatement.model_construct(**primitive)

    assert forged.model_dump(mode="python", warnings=False)["sequence"] == "1"
    assert (
        _reason(
            lambda: service.admit(
                envelope_bytes=canonical_json_bytes(
                    {
                        "payload": base64.b64encode(
                            forged.model_dump_json(warnings=False).encode()
                        ).decode(),
                        "payloadType": COLLECTION_STATEMENT_MEDIA_TYPE,
                        "signatures": [],
                    }
                ),
                cab_source=cab,
            )
        )
        == AdmissionRejectReason.MALFORMED_ENVELOPE
    )
