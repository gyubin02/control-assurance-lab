from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from assurance_lab._version import __version__
from assurance_lab.connectors.contract import (
    ConnectorCapture,
    ConnectorDescriptor,
    VerifiedConnectorCapture,
)
from assurance_lab.connectors.defender_xdr import (
    DEFENDER_XDR_CAPTURE_MEDIA_TYPE,
    DEFENDER_XDR_CONNECTOR_ID,
)
from assurance_lab.connectors.managed_evidence import (
    ManagedAuthorizationProfile,
    PamReceiptVerificationContext,
    VerifiedPamLifecycleReceipt,
)
from assurance_lab.control_plane.models import (
    ControlConfiguration,
    DefenderSourceConfiguration,
    EvidenceConfiguration,
    ScheduleConfiguration,
)
from assurance_lab.controls.alert_window import (
    ALERT_WINDOW_PROFILE_MEDIA_TYPE,
    AlertWindowProfile,
    Criterion,
    DefenderAlertSource,
    EqualsPredicate,
    MatchingRecordCount,
)
from assurance_lab.evidence.admission import DetachedSignature
from assurance_lab.evidence.canonical import (
    canonical_json_bytes,
    canonical_jsonl_bytes,
)
from assurance_lab.evidence.s3_object_lock import S3CustodyAcknowledgement
from assurance_lab.runtime.custody_identity import (
    ControlRunCustodyRuntimeIdentity,
    CustodySigningDeploymentProfile,
    S3ObjectLockPublicDeploymentIdentity,
    VaultTransitPublicDeploymentIdentity,
)
from assurance_lab.runtime.evidence_publication import (
    MAX_MANAGED_EXECUTION_RECEIPT_BYTES,
    ManagedEvidencePublication,
    ManagedEvidencePublicationError,
    SignedManagedExecutionReceipt,
    publish_managed_evidence,
    verify_managed_evidence_executor_receipt,
)
from assurance_lab.runtime.execution_identity import (
    ExecutionEnvironmentIdentity,
    parse_execution_environment_identity,
)
from assurance_lab.runtime.execution_plan import (
    ControlRunExecutionPlan,
    create_control_run_execution_plan,
    verify_control_run_execution_plan,
)
from assurance_lab.runtime.managed_source import (
    ManagedSourceCapture,
    PreparedManagedSource,
)
from assurance_lab.runtime.models import (
    ControlRunExecutionRequest,
    ControlRunRequest,
    sha256_digest,
)

_START = datetime(2026, 7, 29, 1, 0, tzinfo=UTC)
_END = _START + timedelta(minutes=5)
_PREPARED = _END + timedelta(minutes=2)
_RETAIN_UNTIL = _PREPARED + timedelta(days=30)
_SOURCE_REVISION = "runtime-build-2026.07.29.1"
_NONCE = "ab" * 32
_OPERATION = f"sha256:{'1' * 64}"
_DEPLOYMENT = f"sha256:{'2' * 64}"
_REVISION = f"sha256:{'3' * 64}"
_BUCKET_ARN = "arn:aws:s3:::control-assurance-test"
_KMS_ARN = (
    "arn:aws:kms:ap-northeast-2:123456789012:key/"
    "11111111-1111-4111-8111-111111111111"
)
_CONNECTOR_VERIFIER_ID = "test/defender-source-receipt-v1"
_PAM_VERIFIER_ID = "test/defender-pam-receipt-v1"
_LIFECYCLE_DIGEST = f"sha256:{'c' * 64}"


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


_BUCKET_PIN = _sha256(_BUCKET_ARN.encode("ascii"))
_KMS_PIN = _sha256(_KMS_ARN.encode("ascii"))


def _scope(label: bytes, value: str) -> str:
    encoded = value.encode()
    return _sha256(label + b"\x00" + len(encoded).to_bytes(4, "big") + encoded)


def _checksum(digest: str) -> str:
    return base64.b64encode(bytes.fromhex(digest.removeprefix("sha256:"))).decode()


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Signer:
    def __init__(self) -> None:
        self._key = Ed25519PrivateKey.generate()
        self.sign_count = 0

    @property
    def key_id(self) -> str:
        return "test-stream-custody-key"

    @property
    def public_key_bytes(self) -> bytes:
        return self._key.public_key().public_bytes_raw()

    @property
    def public_deployment_identity(
        self,
    ) -> VaultTransitPublicDeploymentIdentity:
        return VaultTransitPublicDeploymentIdentity(
            endpoint_origin_digest=sha256_digest(b"vault-origin"),
            namespace_digest=sha256_digest(b"vault-namespace"),
            mount_path_digest=sha256_digest(b"vault-mount"),
            key_name_digest=sha256_digest(b"vault-key"),
            key_id_digest=sha256_digest(self.key_id.encode()),
            key_version=1,
            public_key_fingerprint=sha256_digest(self.public_key_bytes),
        )

    def sign(self, message: bytes) -> DetachedSignature:
        self.sign_count += 1
        return DetachedSignature(
            key_id=self.key_id,
            algorithm="ed25519",
            signature=base64.b64encode(self._key.sign(message)).decode(),
        )


class _Custody:
    """Content-addressed fake that preserves and reverifies exact versions."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.acknowledgements: dict[str, S3CustodyAcknowledgement] = {}
        self.versions: dict[str, str] = {}
        self.put_count = 0
        self.reverify_count = 0
        self.after_put: Callable[[int], None] | None = None
        self.fail_reverify = False
        self.substitute_reverified_ack = False

    @property
    def public_deployment_identity(
        self,
    ) -> S3ObjectLockPublicDeploymentIdentity:
        return S3ObjectLockPublicDeploymentIdentity(
            bucket_name="control-assurance-test",
            bucket_arn=_BUCKET_ARN,
            expected_bucket_owner="123456789012",
            aws_region="ap-northeast-2",
            kms_key_arn=_KMS_ARN,
            encryption="aws:kms:dsse",
            minimum_retention_seconds=24 * 60 * 60,
            maximum_retention_seconds=3650 * 24 * 60 * 60,
            maximum_object_bytes=5 * 1024 * 1024 * 1024,
        )

    def _put(
        self,
        payload: bytes,
        *,
        tenant_id: str,
        cab_id: str,
        retain_until: datetime,
        expected_object_digest: str | None,
    ) -> S3CustodyAcknowledgement:
        self.put_count += 1
        digest = _sha256(payload)
        if expected_object_digest is not None and digest != expected_object_digest:
            raise RuntimeError("digest mismatch")
        tenant_scope = _scope(b"tenant", tenant_id)
        cab_scope = _scope(b"cab", cab_id)
        existing = self.acknowledgements.get(digest)
        if existing is not None:
            if (
                self.objects[digest] != payload
                or existing.tenant_scope_digest != tenant_scope
                or existing.cab_scope_digest != cab_scope
                or existing.retain_until != _timestamp(retain_until)
            ):
                raise RuntimeError("content-addressed conflict")
            if self.after_put is not None:
                self.after_put(self.put_count)
            return existing
        acknowledgement = S3CustodyAcknowledgement(
            bucket_arn_digest=_BUCKET_PIN,
            cab_scope_digest=cab_scope,
            checksum_sha256=_checksum(digest),
            encryption="aws:kms:dsse",
            kms_key_arn_digest=_KMS_PIN,
            object_digest=digest,
            object_key_digest=_sha256(
                f"object:{tenant_scope}:{cab_scope}:{digest}".encode()
            ),
            retain_until=_timestamp(retain_until),
            tenant_scope_digest=tenant_scope,
            version_id=f"version-{len(self.objects) + 1}",
        )
        self.objects[digest] = payload
        self.acknowledgements[digest] = acknowledgement
        self.versions[acknowledgement.version_id] = digest
        if self.after_put is not None:
            self.after_put(self.put_count)
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
            acknowledgement.bucket_arn_digest == _BUCKET_PIN
            and acknowledgement.kms_key_arn_digest == _KMS_PIN
            and acknowledgement.encryption == "aws:kms:dsse"
            and acknowledgement.tenant_scope_digest
            == _scope(b"tenant", tenant_id)
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
        self.reverify_count += 1
        if self.fail_reverify:
            raise RuntimeError("remote read failed")
        digest = self.versions.get(acknowledgement.version_id)
        if (
            digest is None
            or self.acknowledgements.get(digest) != acknowledgement
            or not self.verify_acknowledgement_scope(
                acknowledgement,
                tenant_id=tenant_id,
                cab_id=cab_id,
            )
            or len(self.objects[digest]) != expected_size
            or _sha256(self.objects[digest]) != acknowledgement.object_digest
        ):
            raise RuntimeError("exact version mismatch")
        if self.substitute_reverified_ack:
            document = acknowledgement.to_document()
            document["version_id"] = "substituted-version"
            return S3CustodyAcknowledgement(**document)
        return acknowledgement


class _CustodyPublicIdentityDrift(_Custody):
    @property
    def public_deployment_identity(
        self,
    ) -> S3ObjectLockPublicDeploymentIdentity:
        return S3ObjectLockPublicDeploymentIdentity(
            bucket_name="control-assurance-other",
            bucket_arn="arn:aws:s3:::control-assurance-other",
            expected_bucket_owner="123456789012",
            aws_region="ap-northeast-2",
            kms_key_arn=_KMS_ARN,
            encryption="aws:kms:dsse",
            minimum_retention_seconds=24 * 60 * 60,
            maximum_retention_seconds=3650 * 24 * 60 * 60,
            maximum_object_bytes=5 * 1024 * 1024 * 1024,
        )


class _SignerPublicIdentityDrift(_Signer):
    @property
    def public_deployment_identity(
        self,
    ) -> VaultTransitPublicDeploymentIdentity:
        expected = super().public_deployment_identity
        return VaultTransitPublicDeploymentIdentity(
            **{
                **expected.model_dump(mode="python"),
                "key_version": 2,
            }
        )


def _profile() -> AlertWindowProfile:
    return AlertWindowProfile(
        profile_id="high-defender-alert-window",
        profile_version="1.0.0",
        title="High Defender alert window",
        source=DefenderAlertSource(),
        criteria=(
            Criterion(
                criterion_id="high-alert-observed",
                description="At least one high alert was observed.",
                metric=MatchingRecordCount(
                    all=(EqualsPredicate(field="Severity", value="High"),)
                ),
                comparison="ge",
                expected_count=1,
            ),
        ),
    )


def _request_and_plan(
    *,
    nonce: str = _NONCE,
    source_revision: str = _SOURCE_REVISION,
    deployment_operation_id: str = _OPERATION,
) -> tuple[ControlRunExecutionRequest, ControlRunExecutionPlan]:
    profile = _profile()
    configuration = ControlConfiguration(
        tenant_id="bank-a",
        control_id="high-defender-alert-control",
        display_name="High Defender alert control",
        description="Recomputes one exact Defender alert window.",
        environment="production",
        owner_group="security/detection",
        control_profile_id=profile.profile_id,
        control_profile_digest=profile.digest,
        source=DefenderSourceConfiguration(
            cloud="global",
            tenant_id="11111111-1111-4111-8111-111111111111",
            client_id="22222222-2222-4222-8222-222222222222",
            client_credential_ref=(
                "azure-keyvault://bank-vault/secrets/"
                "defender-profile/0123456789abcdef0123456789abcdef"
            ),
        ),
        schedule=ScheduleConfiguration(
            interval_seconds=300,
            collection_lag_seconds=120,
            window_seconds=300,
        ),
        evidence=EvidenceConfiguration(
            custody_ref="s3-object-lock://evidence/bank-a/high-alerts",
            signing_key_ref="vault-transit://assurance/runtime",
            retention_days=30,
        ),
    )
    run = ControlRunRequest(
        tenant_id=configuration.tenant_id,
        control_id=configuration.control_id,
        deployment_operation_id=deployment_operation_id,
        deployment_operation_sequence=7,
        deployment_receipt_digest=_DEPLOYMENT,
        control_profile_id=profile.profile_id,
        control_profile_digest=profile.digest,
        revision_id=_REVISION,
        configuration_digest=configuration.digest,
        window_start=_START,
        window_end=_END,
        due_at=_PREPARED,
    )
    request = ControlRunExecutionRequest(
        run_id=run.run_id,
        run_request_bytes=run.canonical_bytes(),
        tenant_id=configuration.tenant_id,
        control_id=configuration.control_id,
        deployment_operation_id=run.deployment_operation_id,
        deployment_receipt_digest=run.deployment_receipt_digest,
        configuration_digest=configuration.digest,
        configuration_bytes=configuration.canonical_bytes(),
        control_profile_id=profile.profile_id,
        control_profile_digest=profile.digest,
        control_profile_media_type=ALERT_WINDOW_PROFILE_MEDIA_TYPE,
        control_profile_bytes=profile.canonical_bytes(),
        window_start=_START,
        window_end=_END,
        attempt_count=1,
        lease_fence=5,
    )
    return (
        request,
        create_control_run_execution_plan(
            request,
            capture_nonce=nonce,
            prepared_at=_PREPARED,
            source_revision=source_revision,
        ),
    )


@dataclass(slots=True)
class _CaptureCounter:
    calls: int = 0


def _source(
    request: ControlRunExecutionRequest,
    plan: ControlRunExecutionPlan,
    *,
    counter: _CaptureCounter | None = None,
) -> PreparedManagedSource:
    reopened, connector_request = verify_control_run_execution_plan(
        plan.canonical_bytes(),
        expected_request=request,
    )
    assert reopened == plan
    descriptor = ConnectorDescriptor(
        connector_id=DEFENDER_XDR_CONNECTOR_ID,
        connector_version=__version__,
        capture_media_type=DEFENDER_XDR_CAPTURE_MEDIA_TYPE,
    )
    locator_digest = sha256_digest(b"https://graph.microsoft.com")
    source_receipt = canonical_json_bytes(
        {
            "capture_id": connector_request.capture_id,
            "request_digest": plan.connector_request_digest,
        }
    )
    records = canonical_jsonl_bytes(
        [
            {
                "fields": {
                    "AlertId": "alert-001",
                    "Severity": "High",
                },
                "id": "defender-xdr-alert:alert-001",
            }
        ]
    )
    pam_receipt = canonical_json_bytes(
        {
            "capture_receipt_digest": sha256_digest(source_receipt),
            "closure_state": "closed",
            "request_digest": plan.connector_request_digest,
        }
    )
    capture = ConnectorCapture(
        descriptor=descriptor,
        receipt_bytes=source_receipt,
        receipt_digest=sha256_digest(source_receipt),
        records_jsonl=records,
        records_digest=sha256_digest(records),
        record_count=1,
    )
    authorization = ManagedAuthorizationProfile(
        profile_id="test-defender-auth-v1",
        provider_id="test-entra",
        authorization_binding_digest=sha256_digest(b"authorization-binding"),
        credential_reference_digest=sha256_digest(b"credential-reference"),
        permission_ids=("microsoft-graph:ThreatHunting.Read.All",),
        resource_scope_digests=(locator_digest,),
    )
    observed = counter or _CaptureCounter()

    def capture_source() -> ManagedSourceCapture:
        observed.calls += 1
        return ManagedSourceCapture(
            capture=capture,
            pam_receipt_bytes=pam_receipt,
            pam_receipt_digest=sha256_digest(pam_receipt),
        )

    def verify_source(receipt: bytes) -> VerifiedConnectorCapture:
        if receipt != source_receipt:
            raise ValueError("unexpected source receipt")
        return VerifiedConnectorCapture(
            descriptor=descriptor,
            receipt_digest=sha256_digest(receipt),
            records_jsonl=records,
            records_digest=sha256_digest(records),
            record_count=1,
            source_locator_digest=locator_digest,
            source_product="Microsoft Defender XDR",
            source_version="v1.0",
        )

    def verify_pam(
        receipt: bytes,
        context: PamReceiptVerificationContext,
    ) -> VerifiedPamLifecycleReceipt:
        if receipt != pam_receipt:
            raise ValueError("unexpected PAM receipt")
        return VerifiedPamLifecycleReceipt(
            verifier_id=_PAM_VERIFIER_ID,
            receipt_digest=sha256_digest(receipt),
            job_digest=context.job_digest,
            run_id=context.run_id,
            request_digest=context.request_digest,
            source_locator_digest=context.source_locator_digest,
            capture_receipt_digest=context.capture_receipt_digest,
            capture_records_digest=context.capture_records_digest,
            authorization_profile_id=context.authorization_profile_id,
            authorization_profile_digest=context.authorization_profile_digest,
            authorization_binding_digest=context.authorization_binding_digest,
            lifecycle_reference_digest=_LIFECYCLE_DIGEST,
            credential_exposure_state="revoked",
        )

    prepared = PreparedManagedSource(
        descriptor=descriptor,
        source_locator_digest=locator_digest,
        connector_request=connector_request,
        connector_request_bytes=plan.connector_request_bytes,
        authorization_profile=authorization,
        connector_receipt_verifier_id=_CONNECTOR_VERIFIER_ID,
        pam_receipt_verifier_id=_PAM_VERIFIER_ID,
        _capture=capture_source,
        receipt_verifier=verify_source,
        pam_receipt_verifier=verify_pam,
    )
    source_identity = _source_runtime_identity_bytes(request, prepared)
    return prepared.bind_runtime_identity(
        media_type=(
            "application/vnd.control-assurance."
            "defender-runtime-identity.v1+json"
        ),
        identity_bytes=source_identity,
        identity_digest=sha256_digest(source_identity),
    )


def _source_runtime_identity_bytes(
    request: ControlRunExecutionRequest,
    source: PreparedManagedSource,
) -> bytes:
    configuration = ControlConfiguration.model_validate_json(
        request.configuration_bytes,
        strict=True,
    )
    assert isinstance(configuration.source, DefenderSourceConfiguration)
    source_configuration = configuration.source
    return canonical_json_bytes(
        {
            "client_id": source_configuration.client_id,
            "cloud": source_configuration.cloud,
            "graph_origin_digest": source.source_locator_digest,
            "kind": "defender-runtime-identity",
            "media_type": (
                "application/vnd.control-assurance."
                "defender-runtime-identity.v1+json"
            ),
            "permission": source_configuration.permission,
            "schema_version": "1.0.0",
            "table": source_configuration.table,
            "tenant_id": source_configuration.tenant_id,
        }
    )


def _execution_environment_identity_bytes(
    request: ControlRunExecutionRequest,
    plan: ControlRunExecutionPlan,
    source: PreparedManagedSource,
    signer: _Signer,
    *,
    custody_profile_id: str = "production-object-lock-v1",
) -> bytes:
    configuration = ControlConfiguration.model_validate_json(
        request.configuration_bytes,
        strict=True,
    )
    source_identity = _source_runtime_identity_bytes(request, source)
    profile = CustodySigningDeploymentProfile(
        profile_id=custody_profile_id,
        tenant_id=plan.tenant_id,
        control_id=plan.control_id,
        environment=configuration.environment,
        configuration_digest=plan.configuration_digest,
        custody_ref=configuration.evidence.custody_ref,
        signing_key_ref=configuration.evidence.signing_key_ref,
        configured_retention_days=configuration.evidence.retention_days,
        custody=S3ObjectLockPublicDeploymentIdentity(
            bucket_name="control-assurance-test",
            bucket_arn=_BUCKET_ARN,
            expected_bucket_owner="123456789012",
            aws_region="ap-northeast-2",
            kms_key_arn=_KMS_ARN,
            encryption="aws:kms:dsse",
            minimum_retention_seconds=24 * 60 * 60,
            maximum_retention_seconds=3650 * 24 * 60 * 60,
            maximum_object_bytes=5 * 1024 * 1024 * 1024,
        ),
        signing=VaultTransitPublicDeploymentIdentity(
            endpoint_origin_digest=sha256_digest(b"vault-origin"),
            namespace_digest=sha256_digest(b"vault-namespace"),
            mount_path_digest=sha256_digest(b"vault-mount"),
            key_name_digest=sha256_digest(b"vault-key"),
            key_id_digest=sha256_digest(signer.key_id.encode()),
            key_version=1,
            public_key_fingerprint=sha256_digest(signer.public_key_bytes),
        ),
    )
    custody_identity = ControlRunCustodyRuntimeIdentity(
        run_id=plan.run_id,
        tenant_id=plan.tenant_id,
        control_id=plan.control_id,
        configuration_digest=plan.configuration_digest,
        execution_plan_digest=plan.digest,
        custody_scope_id=plan.custody_scope_id,
        prepared_at=plan.prepared_at,
        custody_retain_until=plan.custody_retain_until,
        custody_ref=configuration.evidence.custody_ref,
        signing_key_ref=configuration.evidence.signing_key_ref,
        deployment_profile_digest=profile.digest,
        deployment_profile=profile,
    )
    return ExecutionEnvironmentIdentity(
        run_id=plan.run_id,
        tenant_id=plan.tenant_id,
        control_id=plan.control_id,
        configuration_digest=plan.configuration_digest,
        execution_plan_digest=plan.digest,
        source_revision=plan.source_revision,
        source_kind=plan.source_kind,
        source_identity_media_type=(
            "application/vnd.control-assurance."
            "defender-runtime-identity.v1+json"
        ),
        source_identity_bytes=source_identity,
        source_identity_digest=sha256_digest(source_identity),
        custody_identity_media_type=custody_identity.media_type,
        custody_identity_bytes=custody_identity.canonical_bytes(),
        custody_identity_digest=custody_identity.digest,
        custody_deployment_profile_digest=profile.digest,
    ).canonical_bytes()


@pytest.fixture
def work_root(tmp_path: Path) -> Path:
    tmp_path.chmod(0o700)
    return tmp_path


def _publish(
    work_root: Path,
    *,
    custody: _Custody | None = None,
    signer: _Signer | None = None,
    counter: _CaptureCounter | None = None,
) -> tuple[
    ManagedEvidencePublication,
    _Custody,
    _Signer,
    _CaptureCounter,
]:
    request, plan = _request_and_plan()
    custody = custody or _Custody()
    signer = signer or _Signer()
    counter = counter or _CaptureCounter()
    source = _source(request, plan, counter=counter)
    publication = publish_managed_evidence(
        request,
        plan,
        source,
        execution_environment_identity_bytes=(
            _execution_environment_identity_bytes(
                request,
                plan,
                source,
                signer,
            )
        ),
        work_root=work_root,
        custody=custody,
        receipt_signer=signer,
        source_revision=_SOURCE_REVISION,
    )
    return publication, custody, signer, counter


@pytest.mark.parametrize(
    "drift",
    ["source-identity", "custody-identity", "signing-identity"],
)
def test_publication_preflight_rejects_runtime_drift_before_side_effects(
    work_root: Path,
    drift: str,
) -> None:
    request, plan = _request_and_plan()
    counter = _CaptureCounter()
    source = _source(request, plan, counter=counter)
    custody: _Custody = (
        _CustodyPublicIdentityDrift()
        if drift == "custody-identity"
        else _Custody()
    )
    signer: _Signer = (
        _SignerPublicIdentityDrift()
        if drift == "signing-identity"
        else _Signer()
    )
    identity_bytes = _execution_environment_identity_bytes(
        request,
        plan,
        source,
        signer,
    )
    if drift == "source-identity":
        identity = parse_execution_environment_identity(identity_bytes)
        source_document = json.loads(identity.source_identity_bytes)
        source_document["credential_mode"] = "substituted"
        substituted_source = canonical_json_bytes(source_document)
        identity_bytes = replace(
            identity,
            source_identity_bytes=substituted_source,
            source_identity_digest=sha256_digest(substituted_source),
        ).canonical_bytes()

    with pytest.raises(ManagedEvidencePublicationError) as raised:
        publish_managed_evidence(
            request,
            plan,
            source,
            execution_environment_identity_bytes=identity_bytes,
            work_root=work_root,
            custody=custody,
            receipt_signer=signer,
            source_revision=_SOURCE_REVISION,
        )

    assert raised.value.stage == "input"
    assert counter.calls == 0
    assert custody.put_count == 0
    assert custody.reverify_count == 0
    assert signer.sign_count == 0
    assert list(work_root.iterdir()) == []


def test_publish_closes_exact_runtime_evidence_and_remote_versions(
    work_root: Path,
) -> None:
    publication, custody, signer, counter = _publish(work_root)
    request, plan = _request_and_plan()
    source = _source(request, plan)
    identity_bytes = _execution_environment_identity_bytes(
        request,
        plan,
        source,
        signer,
    )
    envelope = SignedManagedExecutionReceipt.model_validate_json(
        publication.executor_receipt_bytes,
        strict=True,
    )
    closure = envelope.receipt.custody_closure
    acknowledgement = S3CustodyAcknowledgement.from_canonical_bytes(
        publication.custody_acknowledgement_bytes
    )
    online_reads_after_publish = custody.reverify_count
    offline = verify_managed_evidence_executor_receipt(
        publication.executor_receipt_bytes,
        expected_execution_request=request,
        expected_execution_plan=plan,
        expected_source=source,
        execution_environment_identity_bytes=identity_bytes,
        custody=custody,
        receipt_signer=signer,
    )

    assert counter.calls == 1
    assert publication.exact_versions_reverified is True
    assert publication.executor_receipt_digest == _sha256(
        publication.executor_receipt_bytes
    )
    assert publication.evidence_digest == closure.receipt.snapshot_digest
    assert closure.receipt.custody.retain_until == _timestamp(_RETAIN_UNTIL)
    assert acknowledgement.object_digest == envelope.receipt.custody_closure_digest
    assert publication.executor_receipt_digest != (
        envelope.receipt.custody_closure_digest
    )
    assert len(publication.executor_receipt_bytes) < (
        MAX_MANAGED_EXECUTION_RECEIPT_BYTES
    )
    assert online_reads_after_publish == 2 * (closure.receipt.object_count + 1)
    assert offline.exact_versions_reverified is False
    assert custody.reverify_count == online_reads_after_publish
    assert publication.execution_result(lease_fence=5).model_dump() == {
        "run_id": publication.run_id,
        "lease_fence": 5,
        "evidence_digest": publication.evidence_digest,
        "executor_receipt_digest": publication.executor_receipt_digest,
    }


def test_signed_receipt_binds_exact_public_execution_environment(
    work_root: Path,
) -> None:
    publication, _custody, signer, _counter = _publish(work_root)
    request, plan = _request_and_plan()
    source = _source(request, plan)
    identity_bytes = _execution_environment_identity_bytes(
        request,
        plan,
        source,
        signer,
    )
    envelope = SignedManagedExecutionReceipt.model_validate_json(
        publication.executor_receipt_bytes,
        strict=True,
    )

    assert envelope.receipt.execution_environment_identity_digest == (
        sha256_digest(identity_bytes)
    )
    assert envelope.receipt.custody_deployment_profile_digest == (
        parse_execution_environment_identity(
            identity_bytes
        ).custody_deployment_profile_digest
    )


def test_receipt_verifier_rejects_mutated_environment_identity_bytes(
    work_root: Path,
) -> None:
    publication, custody, signer, _counter = _publish(work_root)
    request, plan = _request_and_plan()
    source = _source(request, plan)
    identity_bytes = _execution_environment_identity_bytes(
        request,
        plan,
        source,
        signer,
    )

    with pytest.raises(ManagedEvidencePublicationError) as raised:
        verify_managed_evidence_executor_receipt(
            publication.executor_receipt_bytes,
            expected_execution_request=request,
            expected_execution_plan=plan,
            expected_source=source,
            execution_environment_identity_bytes=identity_bytes + b" ",
            custody=custody,
            receipt_signer=signer,
        )

    assert raised.value.stage == "input"


def test_receipt_verifier_rejects_cross_run_environment_identity(
    work_root: Path,
) -> None:
    publication, custody, signer, _counter = _publish(work_root)
    request, plan = _request_and_plan()
    source = _source(request, plan)
    other_request, other_plan = _request_and_plan(
        deployment_operation_id=f"sha256:{'9' * 64}",
    )
    other_source = _source(other_request, other_plan)
    other_identity_bytes = _execution_environment_identity_bytes(
        other_request,
        other_plan,
        other_source,
        signer,
    )

    with pytest.raises(ManagedEvidencePublicationError) as raised:
        verify_managed_evidence_executor_receipt(
            publication.executor_receipt_bytes,
            expected_execution_request=request,
            expected_execution_plan=plan,
            expected_source=source,
            execution_environment_identity_bytes=other_identity_bytes,
            custody=custody,
            receipt_signer=signer,
        )

    assert raised.value.stage == "input"


def test_receipt_verifier_rejects_custody_profile_drift(
    work_root: Path,
) -> None:
    publication, custody, signer, _counter = _publish(work_root)
    request, plan = _request_and_plan()
    source = _source(request, plan)
    drifted_identity_bytes = _execution_environment_identity_bytes(
        request,
        plan,
        source,
        signer,
        custody_profile_id="production-object-lock-v2",
    )

    with pytest.raises(ManagedEvidencePublicationError) as raised:
        verify_managed_evidence_executor_receipt(
            publication.executor_receipt_bytes,
            expected_execution_request=request,
            expected_execution_plan=plan,
            expected_source=source,
            execution_environment_identity_bytes=drifted_identity_bytes,
            custody=custody,
            receipt_signer=signer,
        )

    assert raised.value.stage == "executor-receipt-verify"


def test_retry_reuses_semantically_verified_snapshot_without_second_capture(
    work_root: Path,
) -> None:
    custody = _Custody()
    signer = _Signer()
    counter = _CaptureCounter()
    first, _, _, _ = _publish(
        work_root,
        custody=custody,
        signer=signer,
        counter=counter,
    )
    first_reverify_count = custody.reverify_count

    retried, _, _, _ = _publish(
        work_root,
        custody=custody,
        signer=signer,
        counter=counter,
    )

    assert counter.calls == 1
    assert retried == first
    assert custody.reverify_count > first_reverify_count


def test_different_frozen_source_request_is_rejected_before_capture(
    work_root: Path,
) -> None:
    request, plan = _request_and_plan()
    _other_request, other_plan = _request_and_plan(nonce="cd" * 32)
    counter = _CaptureCounter()
    signer = _Signer()
    source = _source(request, other_plan, counter=counter)
    identity_source = _source(request, plan)

    with pytest.raises(ManagedEvidencePublicationError) as raised:
        publish_managed_evidence(
            request,
            plan,
            source,
            execution_environment_identity_bytes=(
                _execution_environment_identity_bytes(
                    request,
                    plan,
                    identity_source,
                    signer,
                )
            ),
            work_root=work_root,
            custody=_Custody(),
            receipt_signer=signer,
            source_revision=_SOURCE_REVISION,
        )

    assert raised.value.stage == "input"
    assert counter.calls == 0


def test_unplanned_source_revision_is_rejected_before_capture(
    work_root: Path,
) -> None:
    request, plan = _request_and_plan()
    counter = _CaptureCounter()
    signer = _Signer()
    source = _source(request, plan, counter=counter)

    with pytest.raises(ManagedEvidencePublicationError) as raised:
        publish_managed_evidence(
            request,
            plan,
            source,
            execution_environment_identity_bytes=(
                _execution_environment_identity_bytes(
                    request,
                    plan,
                    source,
                    signer,
                )
            ),
            work_root=work_root,
            custody=_Custody(),
            receipt_signer=signer,
            source_revision="runtime-build-substituted",
        )

    assert raised.value.stage == "input"
    assert counter.calls == 0


def test_snapshot_mutation_during_component_upload_blocks_publication(
    work_root: Path,
) -> None:
    request, plan = _request_and_plan()
    custody = _Custody()
    signer = _Signer()
    source = _source(request, plan)

    def mutate_after_first_put(call: int) -> None:
        if call != 1:
            return
        snapshot = work_root / (
            f"{plan.artifact_set_id.removeprefix('sha256:')}"
            ".stream-snapshot-v2/snapshot.json"
        )
        snapshot.write_bytes(snapshot.read_bytes() + b" ")

    custody.after_put = mutate_after_first_put
    with pytest.raises(ManagedEvidencePublicationError) as raised:
        publish_managed_evidence(
            request,
            plan,
            source,
            execution_environment_identity_bytes=(
                _execution_environment_identity_bytes(
                    request,
                    plan,
                    source,
                    signer,
                )
            ),
            work_root=work_root,
            custody=custody,
            receipt_signer=signer,
            source_revision=_SOURCE_REVISION,
        )

    assert raised.value.stage == "custody-seal"
    assert not any(
        b"application/vnd.control-assurance.signed-stream-custody" in value
        for value in custody.objects.values()
    )


@pytest.mark.parametrize(
    "mode",
    ["read-failure", "ack-substitution"],
)
def test_exact_version_reverification_failure_withholds_result(
    work_root: Path,
    mode: str,
) -> None:
    custody = _Custody()
    custody.fail_reverify = mode == "read-failure"
    custody.substitute_reverified_ack = mode == "ack-substitution"

    with pytest.raises(ManagedEvidencePublicationError) as raised:
        _publish(work_root, custody=custody)

    assert raised.value.stage == "custody-verify"
    assert custody.reverify_count >= 1


def test_corrupt_existing_snapshot_is_not_overwritten_or_recaptured(
    work_root: Path,
) -> None:
    publication, custody, signer, counter = _publish(work_root)
    snapshot = work_root / (
        f"{publication.artifact_set_id.removeprefix('sha256:')}"
        ".stream-snapshot-v2/snapshot.json"
    )
    snapshot.write_bytes(snapshot.read_bytes() + b" ")

    with pytest.raises(ManagedEvidencePublicationError) as raised:
        _publish(
            work_root,
            custody=custody,
            signer=signer,
            counter=counter,
        )

    assert raised.value.stage == "cab-reopen"
    assert counter.calls == 1


def test_work_root_symlink_is_rejected_before_capture(
    work_root: Path,
    tmp_path: Path,
) -> None:
    request, plan = _request_and_plan()
    counter = _CaptureCounter()
    signer = _Signer()
    source = _source(request, plan, counter=counter)
    target = work_root / "real"
    target.mkdir(mode=0o700)
    linked = work_root / "linked"
    linked.symlink_to(target, target_is_directory=True)

    with pytest.raises(ManagedEvidencePublicationError) as raised:
        publish_managed_evidence(
            request,
            plan,
            source,
            execution_environment_identity_bytes=(
                _execution_environment_identity_bytes(
                    request,
                    plan,
                    source,
                    signer,
                )
            ),
            work_root=linked.absolute(),
            custody=_Custody(),
            receipt_signer=signer,
            source_revision=_SOURCE_REVISION,
        )

    assert raised.value.stage == "workspace"
    assert counter.calls == 0


def test_publication_model_rejects_receipt_byte_mutation(work_root: Path) -> None:
    publication, _custody, _signer, _counter = _publish(work_root)
    document = json.loads(publication.executor_receipt_bytes)
    document["receipt"]["custody_closure"]["receipt"]["total_bytes"] += 1
    mutated = canonical_json_bytes(document)

    with pytest.raises(ValueError, match="executor receipt digest differs"):
        replace(publication, executor_receipt_bytes=mutated)


def test_independent_receipt_reopen_rejects_outer_signature_tamper(
    work_root: Path,
) -> None:
    publication, custody, signer, _counter = _publish(work_root)
    request, plan = _request_and_plan()
    source = _source(request, plan)
    identity_bytes = _execution_environment_identity_bytes(
        request,
        plan,
        source,
        signer,
    )
    document = json.loads(publication.executor_receipt_bytes)
    signature = document["signature"]["signature"]
    document["signature"]["signature"] = (
        ("A" if signature[0] != "A" else "B") + signature[1:]
    )
    tampered = canonical_json_bytes(document)

    with pytest.raises(ManagedEvidencePublicationError) as raised:
        verify_managed_evidence_executor_receipt(
            tampered,
            expected_execution_request=request,
            expected_execution_plan=plan,
            expected_source=source,
            execution_environment_identity_bytes=identity_bytes,
            custody=custody,
            receipt_signer=signer,
        )

    assert raised.value.stage == "executor-receipt-verify"


def test_dr_online_reopen_detects_remote_component_corruption(
    work_root: Path,
) -> None:
    publication, custody, signer, _counter = _publish(work_root)
    request, plan = _request_and_plan()
    source = _source(request, plan)
    identity_bytes = _execution_environment_identity_bytes(
        request,
        plan,
        source,
        signer,
    )
    envelope = SignedManagedExecutionReceipt.model_validate_json(
        publication.executor_receipt_bytes,
        strict=True,
    )
    component = envelope.receipt.custody_closure.receipt.objects[1]
    custody.objects[component.digest] = b"x" * component.size

    offline = verify_managed_evidence_executor_receipt(
        publication.executor_receipt_bytes,
        expected_execution_request=request,
        expected_execution_plan=plan,
        expected_source=source,
        execution_environment_identity_bytes=identity_bytes,
        custody=custody,
        receipt_signer=signer,
    )
    assert offline.exact_versions_reverified is False

    with pytest.raises(ManagedEvidencePublicationError) as raised:
        verify_managed_evidence_executor_receipt(
            publication.executor_receipt_bytes,
            expected_execution_request=request,
            expected_execution_plan=plan,
            expected_source=source,
            execution_environment_identity_bytes=identity_bytes,
            custody=custody,
            receipt_signer=signer,
            online_reverify=True,
        )

    assert raised.value.stage == "executor-receipt-verify"


def test_executor_receipt_cannot_be_replayed_under_another_frozen_plan(
    work_root: Path,
) -> None:
    publication, custody, signer, _counter = _publish(work_root)
    request, _plan = _request_and_plan()
    _other_request, other_plan = _request_and_plan(nonce="cd" * 32)
    other_source = _source(request, other_plan)
    other_identity_bytes = _execution_environment_identity_bytes(
        request,
        other_plan,
        other_source,
        signer,
    )

    with pytest.raises(ManagedEvidencePublicationError) as raised:
        verify_managed_evidence_executor_receipt(
            publication.executor_receipt_bytes,
            expected_execution_request=request,
            expected_execution_plan=other_plan,
            expected_source=other_source,
            execution_environment_identity_bytes=other_identity_bytes,
            custody=custody,
            receipt_signer=signer,
        )

    assert raised.value.stage == "executor-receipt-verify"
