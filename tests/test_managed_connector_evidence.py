from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from assurance_lab.connectors import managed_evidence as managed_module
from assurance_lab.connectors.contract import (
    ConnectorCapture,
    ConnectorDescriptor,
    ConnectorWindow,
    VerifiedConnectorCapture,
)
from assurance_lab.connectors.managed_evidence import (
    ManagedAuthorizationProfile,
    ManagedConnectorEvidenceBundle,
    ManagedConnectorEvidenceError,
    ManagedConnectorEvidenceJob,
    PamReceiptVerificationContext,
    PamReceiptVerifier,
    VerifiedManagedConnectorEvidenceBundle,
    VerifiedPamLifecycleReceipt,
    create_managed_connector_evidence_job,
    managed_connector_request_bytes,
    verify_streamed_managed_connector_evidence_bundle,
    write_managed_connector_evidence_bundle,
)
from assurance_lab.controls.alert_window import (
    AlertWindowProfile,
    Criterion,
    DefenderAlertSource,
    EqualsPredicate,
    MatchingRecordCount,
)
from assurance_lab.evidence.canonical import (
    canonical_json_bytes,
    canonical_jsonl_bytes,
    strict_json_loads,
)

_DESCRIPTOR = ConnectorDescriptor(
    connector_id="test-managed-readonly",
    connector_version="2.0.0",
    capture_media_type="application/vnd.example.managed-capture.v1+json",
)
_RUN_ID = f"sha256:{'1' * 64}"
_CONFIGURATION_DIGEST = f"sha256:{'2' * 64}"
_DEPLOYMENT_RECEIPT_DIGEST = f"sha256:{'3' * 64}"
_SOURCE_LOCATOR_DIGEST = f"sha256:{'4' * 64}"
_AUTHORIZATION_BINDING_DIGEST = f"sha256:{'5' * 64}"
_LIFECYCLE_REFERENCE_DIGEST = f"sha256:{'6' * 64}"
_RESIDUAL_EXPOSURE_END_EPOCH_MILLIS = int(
    datetime(2026, 7, 29, 2, tzinfo=UTC).timestamp() * 1_000
)
_CONNECTOR_VERIFIER_ID = "test/managed-connector-verifier-v2"
_PAM_VERIFIER_ID = "test/managed-pam-verifier-v1"
_AUTHORIZATION_PROFILE = ManagedAuthorizationProfile(
    profile_id="alerts-read-jit-v1",
    provider_id="test-pam",
    authorization_binding_digest=_AUTHORIZATION_BINDING_DIGEST,
    credential_reference_digest=f"sha256:{'7' * 64}",
    permission_ids=("alerts.read",),
    resource_scope_digests=(f"sha256:{'8' * 64}",),
)
_AUTHORIZATION_PROFILE_BYTES = _AUTHORIZATION_PROFILE.canonical_bytes()
_CONTROL_PROFILE = AlertWindowProfile(
    profile_id="high-severity-alert-window",
    profile_version="1.0.0",
    title="High severity alert window",
    source=DefenderAlertSource(),
    criteria=(
        Criterion(
            criterion_id="high-severity-observed",
            description="At least one high severity alert was observed.",
            metric=MatchingRecordCount(
                all=(EqualsPredicate(field="Severity", value="High"),)
            ),
            comparison="ge",
            expected_count=1,
        ),
    ),
)
_CONTROL_PROFILE_BYTES = _CONTROL_PROFILE.canonical_bytes()
_REQUEST = managed_connector_request_bytes(
    {
        "capture_id": "capture-20260729-0001",
        "window": {
            "end_exclusive": "2026-07-29T01:00:00Z",
            "start_inclusive": "2026-07-29T00:00:00Z",
        },
    }
)
_SOURCE_RECEIPT = canonical_json_bytes(
    {
        "connector": {
            "id": _DESCRIPTOR.connector_id,
            "version": _DESCRIPTOR.connector_version,
        },
        "source_locator_digest": _SOURCE_LOCATOR_DIGEST,
    }
)
_RECORDS = canonical_jsonl_bytes(
    [
        {
            "fields": {"Severity": "Low"},
            "id": "defender-xdr-alert:000000000002",
        },
        {
            "fields": {"Severity": "High"},
            "id": "defender-xdr-alert:000000000001",
        },
    ]
)


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _window(*, offset_hours: int = 0) -> ConnectorWindow:
    start = datetime(2026, 7, 29, tzinfo=UTC) + timedelta(hours=offset_hours)
    return ConnectorWindow(start=start, end=start + timedelta(hours=1))


def _job(
    *,
    run_id: str = _RUN_ID,
    configuration_digest: str = _CONFIGURATION_DIGEST,
    source_locator_digest: str = _SOURCE_LOCATOR_DIGEST,
    window: ConnectorWindow | None = None,
) -> ManagedConnectorEvidenceJob:
    return create_managed_connector_evidence_job(
        run_id=run_id,
        tenant_id="tenant-a",
        control_id="control-a",
        control_profile_id=_CONTROL_PROFILE.profile_id,
        control_profile_digest=_CONTROL_PROFILE.digest,
        control_profile_bytes=_CONTROL_PROFILE_BYTES,
        configuration_digest=configuration_digest,
        deployment_receipt_digest=_DEPLOYMENT_RECEIPT_DIGEST,
        window=window or _window(),
        descriptor=_DESCRIPTOR,
        source_locator_digest=source_locator_digest,
        request_media_type="application/vnd.example.managed-request.v1+json",
        request_bytes=_REQUEST,
        authorization_profile_id=_AUTHORIZATION_PROFILE.profile_id,
        authorization_profile_digest=_AUTHORIZATION_PROFILE.digest,
        authorization_profile_bytes=_AUTHORIZATION_PROFILE_BYTES,
        connector_receipt_verifier_id=_CONNECTOR_VERIFIER_ID,
        pam_receipt_verifier_id=_PAM_VERIFIER_ID,
    )


def _capture() -> ConnectorCapture:
    return ConnectorCapture(
        descriptor=_DESCRIPTOR,
        receipt_bytes=_SOURCE_RECEIPT,
        receipt_digest=_digest(_SOURCE_RECEIPT),
        records_jsonl=_RECORDS,
        records_digest=_digest(_RECORDS),
        record_count=2,
    )


def _verify_source(receipt: bytes) -> VerifiedConnectorCapture:
    if receipt != _SOURCE_RECEIPT:
        raise ValueError("source receipt is not the expected test fixture")
    return VerifiedConnectorCapture(
        descriptor=_DESCRIPTOR,
        receipt_digest=_digest(receipt),
        records_jsonl=_RECORDS,
        records_digest=_digest(_RECORDS),
        record_count=2,
        source_locator_digest=_SOURCE_LOCATOR_DIGEST,
        source_product="Test Managed EDR",
        source_version="2026.7",
    )


def _pam_receipt(
    job: ManagedConnectorEvidenceJob,
    capture: ConnectorCapture,
) -> bytes:
    return canonical_json_bytes(
        {
            "authorization_profile_digest": job.authorization_profile_digest,
            "authorization_profile_id": job.authorization_profile_id,
            "authorization_binding_digest": job.authorization_binding_digest,
            "capture": {
                "records_digest": capture.records_digest,
                "receipt_digest": capture.receipt_digest,
            },
            "closure_state": "closed",
            "credential_exposure_state": "released-awaiting-expiry",
            "job_digest": job.digest,
            "lifecycle_reference_digest": _LIFECYCLE_REFERENCE_DIGEST,
            "request_digest": job.request_digest,
            "residual_exposure_end_epoch_millis": (
                _RESIDUAL_EXPOSURE_END_EPOCH_MILLIS
            ),
            "run_id": job.run_id,
            "source_locator_digest": job.source_locator_digest,
        }
    )


def _verify_pam(
    receipt: bytes,
    context: PamReceiptVerificationContext,
) -> VerifiedPamLifecycleReceipt:
    document = strict_json_loads(receipt)
    if not isinstance(document, dict) or canonical_json_bytes(document) != receipt:
        raise ValueError("PAM fixture is not canonical")
    expected = {
        "authorization_profile_digest": context.authorization_profile_digest,
        "authorization_profile_id": context.authorization_profile_id,
        "authorization_binding_digest": context.authorization_binding_digest,
        "capture": {
            "records_digest": context.capture_records_digest,
            "receipt_digest": context.capture_receipt_digest,
        },
        "closure_state": "closed",
        "credential_exposure_state": "released-awaiting-expiry",
        "job_digest": context.job_digest,
        "lifecycle_reference_digest": _LIFECYCLE_REFERENCE_DIGEST,
        "request_digest": context.request_digest,
        "residual_exposure_end_epoch_millis": (
            _RESIDUAL_EXPOSURE_END_EPOCH_MILLIS
        ),
        "run_id": context.run_id,
        "source_locator_digest": context.source_locator_digest,
    }
    if document != expected:
        raise ValueError("PAM fixture differs from the verifier context")
    return VerifiedPamLifecycleReceipt(
        verifier_id=_PAM_VERIFIER_ID,
        receipt_digest=_digest(receipt),
        job_digest=context.job_digest,
        run_id=context.run_id,
        request_digest=context.request_digest,
        source_locator_digest=context.source_locator_digest,
        capture_receipt_digest=context.capture_receipt_digest,
        capture_records_digest=context.capture_records_digest,
        authorization_profile_id=context.authorization_profile_id,
        authorization_profile_digest=context.authorization_profile_digest,
        authorization_binding_digest=context.authorization_binding_digest,
        lifecycle_reference_digest=_LIFECYCLE_REFERENCE_DIGEST,
        credential_exposure_state="released-awaiting-expiry",
        residual_exposure_end_epoch_millis=(
            _RESIDUAL_EXPOSURE_END_EPOCH_MILLIS
        ),
    )


def _write(
    root: Path,
    *,
    pam_verifier: PamReceiptVerifier = _verify_pam,
) -> tuple[ManagedConnectorEvidenceJob, ManagedConnectorEvidenceBundle]:
    job = _job()
    capture = _capture()
    pam_receipt = _pam_receipt(job, capture)
    return (
        job,
        write_managed_connector_evidence_bundle(
            root / "managed.cab",
            job=job,
            request_bytes=_REQUEST,
            control_profile_bytes=_CONTROL_PROFILE_BYTES,
            authorization_profile_bytes=_AUTHORIZATION_PROFILE_BYTES,
            capture=capture,
            pam_receipt_bytes=pam_receipt,
            pam_receipt_digest=_digest(pam_receipt),
            receipt_verifier=_verify_source,
            connector_receipt_verifier_id=_CONNECTOR_VERIFIER_ID,
            pam_receipt_verifier=pam_verifier,
            pam_receipt_verifier_id=_PAM_VERIFIER_ID,
            created_at=datetime(2026, 7, 29, 1, 0, 1, tzinfo=UTC),
            source_revision="test-managed-revision",
        ),
    )


def _reopen(
    snapshot_root: Path,
    snapshot_digest: str,
    job: ManagedConnectorEvidenceJob,
    *,
    authorization_profile_bytes: bytes = _AUTHORIZATION_PROFILE_BYTES,
    connector_verifier_id: str = _CONNECTOR_VERIFIER_ID,
    pam_verifier_id: str = _PAM_VERIFIER_ID,
) -> VerifiedManagedConnectorEvidenceBundle:
    return verify_streamed_managed_connector_evidence_bundle(
        snapshot_root,
        expected_snapshot_digest=snapshot_digest,
        expected_job=job,
        expected_request_bytes=_REQUEST,
        expected_control_profile_bytes=_CONTROL_PROFILE_BYTES,
        expected_authorization_profile_bytes=authorization_profile_bytes,
        receipt_verifier=_verify_source,
        connector_receipt_verifier_id=connector_verifier_id,
        pam_receipt_verifier=_verify_pam,
        pam_receipt_verifier_id=pam_verifier_id,
        expected_source_revision="test-managed-revision",
    )


def test_managed_capture_writes_snapshots_reopens_and_reverifies(tmp_path: Path) -> None:
    job, written = _write(tmp_path)

    reopened = _reopen(
        written.stream_snapshot_root,
        written.snapshot_digest,
        job,
    )

    assert reopened.cab_id == written.cab_id
    assert (
        tmp_path / "managed.cab" / "spec" / "authorization-profile.json"
    ).read_bytes() == _AUTHORIZATION_PROFILE_BYTES
    assert reopened.job_digest == written.job_digest == job.digest
    assert reopened.source_receipt_digest == _digest(_SOURCE_RECEIPT)
    assert reopened.records_digest == _digest(_RECORDS)
    assert reopened.pam_receipt_digest == written.pam_receipt_digest
    assert reopened.record_count == 2
    assert reopened.pam_verification.closure_state == "closed"
    assert (
        reopened.pam_verification.credential_exposure_state
        == "released-awaiting-expiry"
    )
    assert (
        reopened.pam_verification.residual_exposure_end_epoch_millis
        == _RESIDUAL_EXPOSURE_END_EPOCH_MILLIS
    )
    assert reopened.evaluation.decision == "supported"
    assert reopened.evaluation_digest == written.evaluation_digest


def test_stream_snapshot_tampering_is_rejected_before_semantic_use(
    tmp_path: Path,
) -> None:
    job, written = _write(tmp_path)
    descriptor = json.loads(
        (written.stream_snapshot_root / "snapshot.json").read_bytes()
    )
    pam_digest = next(
        entry["digest"]
        for entry in descriptor["entries"]
        if entry["path"] == "artifacts/pam-lifecycle-receipt.json"
    )
    pam_blob = (
        written.stream_snapshot_root
        / "blobs"
        / pam_digest.removeprefix("sha256:")
    )
    pam_blob.write_bytes(b'{"closure_state":"tampered"}')

    with pytest.raises(ManagedConnectorEvidenceError, match="safely reopened"):
        _reopen(
            written.stream_snapshot_root,
            written.snapshot_digest,
            job,
        )


def test_stored_control_evaluation_cannot_replace_recomputation(
    tmp_path: Path,
) -> None:
    job, written = _write(tmp_path)
    descriptor = json.loads(
        (written.stream_snapshot_root / "snapshot.json").read_bytes()
    )
    evaluation_digest = next(
        entry["digest"]
        for entry in descriptor["entries"]
        if entry["path"] == "derived/control-evaluation.json"
    )
    evaluation_blob = (
        written.stream_snapshot_root
        / "blobs"
        / evaluation_digest.removeprefix("sha256:")
    )
    evaluation_blob.write_bytes(
        canonical_json_bytes(
            {
                "decision": "supported",
                "note": "collector-supplied verdict",
            }
        )
    )

    with pytest.raises(ManagedConnectorEvidenceError, match="safely reopened"):
        _reopen(
            written.stream_snapshot_root,
            written.snapshot_digest,
            job,
        )


@pytest.mark.parametrize(
    "foreign_job",
    [
        _job(run_id=f"sha256:{'a' * 64}"),
        _job(configuration_digest=f"sha256:{'b' * 64}"),
        _job(source_locator_digest=f"sha256:{'c' * 64}"),
        _job(window=_window(offset_hours=1)),
    ],
    ids=("cross-run", "cross-configuration", "cross-source", "cross-window"),
)
def test_external_anchor_cannot_be_substituted(
    tmp_path: Path,
    foreign_job: ManagedConnectorEvidenceJob,
) -> None:
    _job_used, written = _write(tmp_path)

    with pytest.raises(ManagedConnectorEvidenceError, match="job differs"):
        _reopen(
            written.stream_snapshot_root,
            written.snapshot_digest,
            foreign_job,
        )


def test_forged_pam_digest_is_rejected_before_any_cab_is_returned(
    tmp_path: Path,
) -> None:
    job = _job()
    capture = _capture()
    pam_receipt = _pam_receipt(job, capture)

    with pytest.raises(ManagedConnectorEvidenceError, match="claimed PAM"):
        write_managed_connector_evidence_bundle(
            tmp_path / "forged.cab",
            job=job,
            request_bytes=_REQUEST,
            control_profile_bytes=_CONTROL_PROFILE_BYTES,
            authorization_profile_bytes=_AUTHORIZATION_PROFILE_BYTES,
            capture=capture,
            pam_receipt_bytes=pam_receipt,
            pam_receipt_digest=f"sha256:{'f' * 64}",
            receipt_verifier=_verify_source,
            connector_receipt_verifier_id=_CONNECTOR_VERIFIER_ID,
            pam_receipt_verifier=_verify_pam,
            pam_receipt_verifier_id=_PAM_VERIFIER_ID,
            created_at=datetime(2026, 7, 29, 1, 0, 1, tzinfo=UTC),
            source_revision="test-managed-revision",
        )


@pytest.mark.parametrize(
    ("connector_id", "pam_id"),
    [
        ("test/substituted-connector", _PAM_VERIFIER_ID),
        (_CONNECTOR_VERIFIER_ID, "test/substituted-pam"),
    ],
)
def test_verifier_identity_substitution_is_rejected(
    tmp_path: Path,
    connector_id: str,
    pam_id: str,
) -> None:
    job, written = _write(tmp_path)

    with pytest.raises(ManagedConnectorEvidenceError, match="verifier identity"):
        _reopen(
            written.stream_snapshot_root,
            written.snapshot_digest,
            job,
            connector_verifier_id=connector_id,
            pam_verifier_id=pam_id,
        )


def test_noncanonical_request_and_pam_receipt_bytes_are_rejected(
    tmp_path: Path,
) -> None:
    with pytest.raises(ManagedConnectorEvidenceError, match="canonical"):
        create_managed_connector_evidence_job(
            run_id=_RUN_ID,
            tenant_id="tenant-a",
            control_id="control-a",
            control_profile_id=_CONTROL_PROFILE.profile_id,
            control_profile_digest=_CONTROL_PROFILE.digest,
            control_profile_bytes=_CONTROL_PROFILE_BYTES,
            configuration_digest=_CONFIGURATION_DIGEST,
            deployment_receipt_digest=_DEPLOYMENT_RECEIPT_DIGEST,
            window=_window(),
            descriptor=_DESCRIPTOR,
            source_locator_digest=_SOURCE_LOCATOR_DIGEST,
            request_media_type="application/json",
            request_bytes=b'{ "capture_id": "noncanonical" }',
            authorization_profile_id=_AUTHORIZATION_PROFILE.profile_id,
            authorization_profile_digest=_AUTHORIZATION_PROFILE.digest,
            authorization_profile_bytes=_AUTHORIZATION_PROFILE_BYTES,
            connector_receipt_verifier_id=_CONNECTOR_VERIFIER_ID,
            pam_receipt_verifier_id=_PAM_VERIFIER_ID,
        )

    job = _job()
    capture = _capture()
    canonical_pam = _pam_receipt(job, capture)
    noncanonical_pam = b"{ " + canonical_pam[1:]
    with pytest.raises(ManagedConnectorEvidenceError, match="canonical"):
        write_managed_connector_evidence_bundle(
            tmp_path / "noncanonical.cab",
            job=job,
            request_bytes=_REQUEST,
            control_profile_bytes=_CONTROL_PROFILE_BYTES,
            authorization_profile_bytes=_AUTHORIZATION_PROFILE_BYTES,
            capture=capture,
            pam_receipt_bytes=noncanonical_pam,
            pam_receipt_digest=_digest(noncanonical_pam),
            receipt_verifier=_verify_source,
            connector_receipt_verifier_id=_CONNECTOR_VERIFIER_ID,
            pam_receipt_verifier=_verify_pam,
            pam_receipt_verifier_id=_PAM_VERIFIER_ID,
            created_at=datetime(2026, 7, 29, 1, 0, 1, tzinfo=UTC),
            source_revision="test-managed-revision",
        )


def test_oversized_pam_receipt_is_rejected_by_the_frozen_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = _job()
    capture = _capture()
    pam_receipt = _pam_receipt(job, capture)
    monkeypatch.setattr(
        managed_module,
        "MAX_MANAGED_CONNECTOR_PAM_RECEIPT_BYTES",
        len(pam_receipt) - 1,
    )

    with pytest.raises(ManagedConnectorEvidenceError, match="PAM receipt exceeds"):
        write_managed_connector_evidence_bundle(
            tmp_path / "oversized.cab",
            job=job,
            request_bytes=_REQUEST,
            control_profile_bytes=_CONTROL_PROFILE_BYTES,
            authorization_profile_bytes=_AUTHORIZATION_PROFILE_BYTES,
            capture=capture,
            pam_receipt_bytes=pam_receipt,
            pam_receipt_digest=_digest(pam_receipt),
            receipt_verifier=_verify_source,
            connector_receipt_verifier_id=_CONNECTOR_VERIFIER_ID,
            pam_receipt_verifier=_verify_pam,
            pam_receipt_verifier_id=_PAM_VERIFIER_ID,
            created_at=datetime(2026, 7, 29, 1, 0, 1, tzinfo=UTC),
            source_revision="test-managed-revision",
        )


def test_immediate_reopen_mismatch_fails_the_whole_write(tmp_path: Path) -> None:
    invocations = 0

    def changes_after_write(
        receipt: bytes,
        context: PamReceiptVerificationContext,
    ) -> VerifiedPamLifecycleReceipt:
        nonlocal invocations
        invocations += 1
        verified = _verify_pam(receipt, context)
        if invocations == 1:
            return verified
        return verified.model_copy(
            update={"lifecycle_reference_digest": f"sha256:{'d' * 64}"}
        )

    with pytest.raises(
        ManagedConnectorEvidenceError,
        match="PAM verification was not recomputed exactly",
    ):
        _write(tmp_path, pam_verifier=changes_after_write)
    assert invocations == 2


def test_verifier_failures_are_normalized_without_secret_text(tmp_path: Path) -> None:
    secret = "do-not-persist-this-parent-token"

    def leaking_verifier(
        _receipt: bytes,
        _context: PamReceiptVerificationContext,
    ) -> VerifiedPamLifecycleReceipt:
        raise RuntimeError(secret)

    with pytest.raises(ManagedConnectorEvidenceError) as error:
        _write(tmp_path, pam_verifier=leaking_verifier)

    assert secret not in str(error.value)
    assert str(error.value) == "PAM receipt verifier rejected the managed lifecycle"


def test_authorization_profile_substitution_and_noncanonical_bytes_are_rejected(
    tmp_path: Path,
) -> None:
    job, written = _write(tmp_path)
    foreign_profile = _AUTHORIZATION_PROFILE.model_copy(
        update={"provider_id": "substituted-pam"}
    ).canonical_bytes()

    for profile_bytes in (
        foreign_profile,
        b"{ " + _AUTHORIZATION_PROFILE_BYTES[1:],
    ):
        with pytest.raises(
            ManagedConnectorEvidenceError,
            match="authorization profile",
        ):
            _reopen(
                written.stream_snapshot_root,
                written.snapshot_digest,
                job,
                authorization_profile_bytes=profile_bytes,
            )


def test_released_credential_exposure_must_end_after_the_capture_window(
    tmp_path: Path,
) -> None:
    def stale_exposure_bound(
        receipt: bytes,
        context: PamReceiptVerificationContext,
    ) -> VerifiedPamLifecycleReceipt:
        return _verify_pam(receipt, context).model_copy(
            update={
                "residual_exposure_end_epoch_millis": (
                    context.capture_window_end_epoch_millis
                )
            }
        )

    with pytest.raises(
        ManagedConnectorEvidenceError,
        match="residual exposure is not future-bounded",
    ):
        _write(tmp_path, pam_verifier=stale_exposure_bound)


def test_revoked_credentials_cannot_claim_residual_exposure(
    tmp_path: Path,
) -> None:
    def contradictory_exposure(
        receipt: bytes,
        context: PamReceiptVerificationContext,
    ) -> VerifiedPamLifecycleReceipt:
        verified = _verify_pam(receipt, context)
        return VerifiedPamLifecycleReceipt.model_validate(
            {
                **verified.model_dump(mode="json"),
                "credential_exposure_state": "revoked",
            }
        )

    with pytest.raises(
        ManagedConnectorEvidenceError,
        match="PAM receipt verifier rejected",
    ):
        _write(tmp_path, pam_verifier=contradictory_exposure)
