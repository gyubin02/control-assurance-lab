from __future__ import annotations

import base64
import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from assurance_lab.control_plane.models import (
    ControlConfiguration,
    ElasticSourceConfiguration,
    EvidenceConfiguration,
    ScheduleConfiguration,
)
from assurance_lab.controls.alert_window import (
    ALERT_WINDOW_PROFILE_MEDIA_TYPE,
    AlertWindowProfile,
    Criterion,
    ElasticAlertSource,
    EqualsPredicate,
    MatchingRecordCount,
)
from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.evidence.s3_object_lock import (
    S3ObjectLockCustody,
    S3RetentionPolicy,
)
from assurance_lab.evidence.vault_transit import (
    VaultToken,
    VaultTransitEd25519ReceiptSigner,
    _HTTPResponse,
)
from assurance_lab.runtime.custody_identity import (
    CustodyRuntimeIdentityError,
    CustodySigningDeploymentProfile,
    ExactCustodyRuntimeProfileRegistry,
    RegisteredCustodySigningRuntime,
    parse_control_run_custody_runtime_identity,
    parse_custody_signing_deployment_profile,
    prepare_custody_signing_runtime,
)
from assurance_lab.runtime.execution_plan import create_control_run_execution_plan
from assurance_lab.runtime.models import ControlRunExecutionRequest, ControlRunRequest

_START = datetime(2026, 7, 29, 1, 0, tzinfo=UTC)
_END = _START + timedelta(minutes=5)
_PREPARED = _END + timedelta(minutes=2)
_OWNER = "123456789012"
_BUCKET = "control-assurance-prod"
_BUCKET_ARN = f"arn:aws:s3:::{_BUCKET}"
_KMS_ARN = (
    f"arn:aws:kms:ap-northeast-2:{_OWNER}:"
    "key/11111111-2222-3333-4444-555555555555"
)
_OPERATION = f"sha256:{'1' * 64}"
_DEPLOYMENT = f"sha256:{'2' * 64}"
_REVISION = f"sha256:{'3' * 64}"
_NONCE = "ab" * 32
_RULE = "12345678-1234-4234-9234-123456789abc"
_TOKEN = b"hvs.unit-test-secret-token"
_VAULT_ENDPOINT = "https://vault.private.example:8200"
_VAULT_MOUNT = "control/transit"
_VAULT_KEY = "receipt"


class _FakeS3:
    def get_bucket_versioning(self, **kwargs: Any) -> dict[str, object]:
        del kwargs
        return {"Status": "Enabled"}

    def get_object_lock_configuration(self, **kwargs: Any) -> dict[str, object]:
        del kwargs
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}}

    def put_object(self, **kwargs: Any) -> dict[str, object]:
        del kwargs
        raise AssertionError("identity preparation must not write evidence")

    def head_object(self, **kwargs: Any) -> dict[str, object]:
        del kwargs
        raise AssertionError("identity preparation must not read evidence")

    def get_object(self, **kwargs: Any) -> dict[str, object]:
        del kwargs
        raise AssertionError("identity preparation must not read evidence")


class _TokenProvider:
    def get_token(self, *, deadline: float) -> VaultToken:
        return VaultToken(
            _TOKEN,
            valid_until_monotonic=max(deadline, time.monotonic() + 1),
        )


class _VaultTransport:
    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        *,
        key_version: int = 7,
    ) -> None:
        self.private_key = private_key
        self.key_version = key_version

    def request(
        self,
        *,
        method: str,
        target: str,
        body: bytes,
        headers: tuple[tuple[str, str], ...],
        token: VaultToken,
        deadline: float,
    ) -> _HTTPResponse:
        del target, headers, token, deadline
        if method == "GET":
            public_key = self.private_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            document: object = {
                "data": {
                    "derived": False,
                    "keys": {
                        str(self.key_version): {
                            "creation_time": "2026-07-29T00:00:00Z",
                            "name": "Ed25519",
                            "public_key": base64.b64encode(public_key).decode(),
                        }
                    },
                    "latest_version": self.key_version,
                    "min_encryption_version": 0,
                    "name": _VAULT_KEY,
                    "supports_signing": True,
                    "type": "ed25519",
                }
            }
        else:
            request = json.loads(body)
            message = base64.b64decode(request["input"], validate=True)
            signature = base64.b64encode(self.private_key.sign(message)).decode()
            document = {
                "data": {
                    "signature": f"vault:v{self.key_version}:{signature}",
                }
            }
        return _HTTPResponse(
            status=200,
            headers=(("content-type", "application/json"),),
            body=json.dumps(document, separators=(",", ":")).encode(),
        )


def _custody(
    *,
    kms_key_arn: str = _KMS_ARN,
    minimum_seconds: int = 60,
    maximum_seconds: int = 400 * 24 * 60 * 60,
) -> S3ObjectLockCustody:
    return S3ObjectLockCustody(
        _FakeS3(),
        bucket_name=_BUCKET,
        bucket_arn=_BUCKET_ARN,
        expected_bucket_owner=_OWNER,
        kms_key_arn=kms_key_arn,
        retention_policy=S3RetentionPolicy(
            minimum_seconds=minimum_seconds,
            maximum_seconds=maximum_seconds,
            max_object_bytes=8 * 1024 * 1024,
        ),
        now=lambda: _PREPARED,
    )


def _signer(
    private_key: Ed25519PrivateKey | None = None,
    *,
    key_version: int = 7,
) -> VaultTransitEd25519ReceiptSigner:
    selected = private_key or Ed25519PrivateKey.generate()
    return VaultTransitEd25519ReceiptSigner(
        _TokenProvider(),
        endpoint=_VAULT_ENDPOINT,
        namespace="admin/security",
        mount_path=_VAULT_MOUNT,
        key_name=_VAULT_KEY,
        key_id=f"vault:control-assurance:{_VAULT_KEY}:v{key_version}",
        _transport=_VaultTransport(selected, key_version=key_version),
    )


def _control_profile() -> AlertWindowProfile:
    return AlertWindowProfile(
        profile_id="high-alert-window",
        profile_version="1.0.0",
        title="High alert window",
        source=ElasticAlertSource(
            fields=(
                "@timestamp",
                "kibana.alert.rule.uuid",
                "kibana.alert.severity",
            ),
            rule_uuids=(_RULE,),
            workflow_statuses=("open",),
            alert_statuses=("active",),
        ),
        criteria=(
            Criterion(
                criterion_id="high-alert-observed",
                description="At least one high alert was observed.",
                metric=MatchingRecordCount(
                    all=(
                        EqualsPredicate(
                            field="kibana.alert.severity",
                            value="high",
                        ),
                    )
                ),
                comparison="ge",
                expected_count=1,
            ),
        ),
    )


def _configuration(
    *,
    custody_ref: str = "s3-object-lock://evidence/bank-a/high-alerts/v1",
    signing_key_ref: str = "vault-transit://assurance/runtime/v7",
    legal_hold: bool = False,
) -> ControlConfiguration:
    profile = _control_profile()
    return ControlConfiguration(
        tenant_id="bank-a",
        control_id="high-alert-control",
        display_name="High alert control",
        description="Recomputes high-alert evidence for one closed window.",
        environment="production",
        owner_group="security/detection",
        control_profile_id=profile.profile_id,
        control_profile_digest=profile.digest,
        source=ElasticSourceConfiguration(
            endpoint_origin="https://elastic.bank.invalid",
            index_alias=".alerts-security.alerts-payments",
            parent_credential_ref=(
                "azure-keyvault://bank-vault/secrets/"
                "elastic-parent/0123456789abcdef0123456789abcdef"
            ),
            lease_ttl_seconds=900,
        ),
        schedule=ScheduleConfiguration(
            interval_seconds=300,
            collection_lag_seconds=120,
            window_seconds=300,
        ),
        evidence=EvidenceConfiguration(
            custody_ref=custody_ref,
            signing_key_ref=signing_key_ref,
            retention_days=365,
            legal_hold=legal_hold,
        ),
    )


def _request(
    configuration: ControlConfiguration | None = None,
    *,
    attempt_count: int = 1,
) -> ControlRunExecutionRequest:
    selected = configuration or _configuration()
    profile = _control_profile()
    run_request = ControlRunRequest(
        tenant_id=selected.tenant_id,
        control_id=selected.control_id,
        deployment_operation_id=_OPERATION,
        deployment_operation_sequence=7,
        deployment_receipt_digest=_DEPLOYMENT,
        control_profile_id=profile.profile_id,
        control_profile_digest=profile.digest,
        revision_id=_REVISION,
        configuration_digest=selected.digest,
        window_start=_START,
        window_end=_END,
        due_at=_PREPARED,
    )
    return ControlRunExecutionRequest(
        run_id=run_request.run_id,
        run_request_bytes=run_request.canonical_bytes(),
        tenant_id=selected.tenant_id,
        control_id=selected.control_id,
        deployment_operation_id=_OPERATION,
        deployment_receipt_digest=_DEPLOYMENT,
        configuration_digest=selected.digest,
        configuration_bytes=selected.canonical_bytes(),
        control_profile_id=profile.profile_id,
        control_profile_digest=profile.digest,
        control_profile_media_type=ALERT_WINDOW_PROFILE_MEDIA_TYPE,
        control_profile_bytes=profile.canonical_bytes(),
        window_start=_START,
        window_end=_END,
        attempt_count=attempt_count,
        lease_fence=attempt_count,
    )


def _profile_and_registration(
    configuration: ControlConfiguration | None = None,
    *,
    custody: S3ObjectLockCustody | None = None,
    signer: VaultTransitEd25519ReceiptSigner | None = None,
) -> tuple[CustodySigningDeploymentProfile, RegisteredCustodySigningRuntime]:
    selected_configuration = configuration or _configuration()
    selected_custody = custody or _custody()
    selected_signer = signer or _signer()
    profile = CustodySigningDeploymentProfile.from_runtime(
        profile_id="bank-a-custody-v1",
        configuration=selected_configuration,
        custody=selected_custody,
        signer=selected_signer,
    )
    registration = RegisteredCustodySigningRuntime(
        profile_bytes=profile.canonical_bytes(),
        custody=selected_custody,
        signer=selected_signer,
    )
    return profile, registration


def test_preparation_emits_canonical_public_identity_without_vault_locator() -> None:
    configuration = _configuration()
    request = _request(configuration)
    plan = create_control_run_execution_plan(
        request,
        capture_nonce=_NONCE,
        prepared_at=_PREPARED,
        source_revision="git:0123456789abcdef",
    )
    profile, registration = _profile_and_registration(configuration)
    registry = ExactCustodyRuntimeProfileRegistry((registration,))

    prepared = prepare_custody_signing_runtime(
        request,
        plan,
        registry=registry,
    )

    assert prepared.identity.deployment_profile_digest == profile.digest
    assert prepared.deployment_profile_digest == profile.digest
    assert prepared.identity_media_type == (
        "application/vnd.control-assurance.custody-runtime-identity.v1+json"
    )
    assert prepared.identity.execution_plan_digest == plan.digest
    assert prepared.identity.custody_scope_id == plan.custody_scope_id
    assert prepared.identity.custody_retain_until == (
        _PREPARED + timedelta(days=365)
    )
    assert parse_control_run_custody_runtime_identity(
        prepared.identity_bytes
    ) == prepared.identity
    assert parse_custody_signing_deployment_profile(
        profile.canonical_bytes()
    ) == profile
    assert _BUCKET_ARN.encode() in prepared.identity_bytes
    assert _KMS_ARN.encode() in prepared.identity_bytes
    for private_locator in (
        _VAULT_ENDPOINT,
        _VAULT_MOUNT,
        _VAULT_KEY,
        "admin/security",
        _TOKEN.decode(),
    ):
        assert private_locator not in prepared.identity_bytes.decode()
        assert private_locator not in repr(prepared)
        assert private_locator not in repr(registration)


def test_signer_repr_uses_only_digests_for_vault_locator_and_key_id() -> None:
    signer = _signer()

    assert signer.key_id_digest in repr(signer)
    for private_locator in (
        _VAULT_ENDPOINT,
        _VAULT_MOUNT,
        _VAULT_KEY,
        "admin/security",
        signer.key_id,
        _TOKEN.decode(),
    ):
        assert private_locator not in repr(signer)


def test_registered_s3_adapter_substitution_is_rejected() -> None:
    configuration = _configuration()
    custody = _custody()
    signer = _signer()
    profile = CustodySigningDeploymentProfile.from_runtime(
        profile_id="bank-a-custody-v1",
        configuration=configuration,
        custody=custody,
        signer=signer,
    )
    other_kms = (
        f"arn:aws:kms:ap-northeast-2:{_OWNER}:"
        "key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    )

    with pytest.raises(
        CustodyRuntimeIdentityError,
        match="registered-runtime-substitution",
    ):
        RegisteredCustodySigningRuntime(
            profile_bytes=profile.canonical_bytes(),
            custody=_custody(kms_key_arn=other_kms),
            signer=signer,
        )


def test_registered_vault_key_rotation_substitution_is_rejected() -> None:
    configuration = _configuration()
    custody = _custody()
    first = _signer(key_version=7)
    profile = CustodySigningDeploymentProfile.from_runtime(
        profile_id="bank-a-custody-v1",
        configuration=configuration,
        custody=custody,
        signer=first,
    )

    with pytest.raises(
        CustodyRuntimeIdentityError,
        match="registered-runtime-substitution",
    ):
        RegisteredCustodySigningRuntime(
            profile_bytes=profile.canonical_bytes(),
            custody=custody,
            signer=_signer(key_version=8),
        )


def test_retry_rejects_a_new_profile_even_under_the_same_configuration() -> None:
    configuration = _configuration()
    request = _request(configuration)
    plan = create_control_run_execution_plan(
        request,
        capture_nonce=_NONCE,
        prepared_at=_PREPARED,
    )
    _, first_registration = _profile_and_registration(configuration)
    first = prepare_custody_signing_runtime(
        request,
        plan,
        registry=ExactCustodyRuntimeProfileRegistry((first_registration,)),
    )
    _, rotated_registration = _profile_and_registration(
        configuration,
        signer=_signer(key_version=8),
    )

    with pytest.raises(
        CustodyRuntimeIdentityError,
        match="runtime-identity-drift",
    ):
        prepare_custody_signing_runtime(
            request,
            plan,
            registry=ExactCustodyRuntimeProfileRegistry(
                (rotated_registration,)
            ),
            expected_identity_bytes=first.identity_bytes,
        )


def test_recovery_can_prepare_before_the_first_identity_cas_has_committed() -> None:
    configuration = _configuration()
    request = _request(configuration, attempt_count=2)
    plan = create_control_run_execution_plan(
        request,
        capture_nonce=_NONCE,
        prepared_at=_PREPARED,
    )
    _, registration = _profile_and_registration(configuration)

    prepared = prepare_custody_signing_runtime(
        request,
        plan,
        registry=ExactCustodyRuntimeProfileRegistry((registration,)),
    )

    assert prepared.identity.run_id == request.run_id


def test_retry_reopens_the_same_identity_byte_for_byte() -> None:
    configuration = _configuration()
    _, registration = _profile_and_registration(configuration)
    registry = ExactCustodyRuntimeProfileRegistry((registration,))
    first_request = _request(configuration, attempt_count=1)
    first_plan = create_control_run_execution_plan(
        first_request,
        capture_nonce=_NONCE,
        prepared_at=_PREPARED,
    )
    first = prepare_custody_signing_runtime(
        first_request,
        first_plan,
        registry=registry,
    )
    retry_request = _request(configuration, attempt_count=2)
    retry_plan = create_control_run_execution_plan(
        retry_request,
        capture_nonce=_NONCE,
        prepared_at=_PREPARED,
    )

    retried = prepare_custody_signing_runtime(
        retry_request,
        retry_plan,
        registry=registry,
        expected_identity_bytes=first.identity_bytes,
    )

    assert retry_plan == first_plan
    assert retried.identity_bytes == first.identity_bytes
    assert retried.identity_digest == first.identity_digest


def test_reference_change_cannot_fall_through_to_an_existing_registration() -> None:
    original = _configuration()
    _, registration = _profile_and_registration(original)
    changed = _configuration(
        custody_ref="s3-object-lock://evidence/bank-a/high-alerts/v2"
    )
    request = _request(changed)
    plan = create_control_run_execution_plan(
        request,
        capture_nonce=_NONCE,
        prepared_at=_PREPARED,
    )

    with pytest.raises(
        CustodyRuntimeIdentityError,
        match="runtime-profile-not-registered",
    ):
        prepare_custody_signing_runtime(
            request,
            plan,
            registry=ExactCustodyRuntimeProfileRegistry((registration,)),
        )


def test_noncanonical_profile_is_not_accepted_by_the_registry() -> None:
    profile, registration = _profile_and_registration()
    del registration
    noncanonical = json.dumps(
        json.loads(profile.canonical_bytes()),
        indent=2,
    ).encode()

    with pytest.raises(
        CustodyRuntimeIdentityError,
        match="deployment-profile-noncanonical",
    ):
        RegisteredCustodySigningRuntime(
            profile_bytes=noncanonical,
            custody=_custody(),
            signer=_signer(),
        )


def test_retention_policy_must_cover_the_configured_evidence_period() -> None:
    with pytest.raises(
        CustodyRuntimeIdentityError,
        match="deployment-profile-invalid",
    ):
        CustodySigningDeploymentProfile.from_runtime(
            profile_id="bank-a-custody-v1",
            configuration=_configuration(),
            custody=_custody(
                minimum_seconds=366 * 24 * 60 * 60,
                maximum_seconds=400 * 24 * 60 * 60,
            ),
            signer=_signer(),
        )


def test_legal_hold_fails_before_registry_resolution() -> None:
    configuration = _configuration(legal_hold=True)
    request = _request(configuration)
    plan = create_control_run_execution_plan(
        request,
        capture_nonce=_NONCE,
        prepared_at=_PREPARED,
    )
    _, registration = _profile_and_registration(_configuration())

    with pytest.raises(
        CustodyRuntimeIdentityError,
        match="legal-hold-unsupported",
    ):
        prepare_custody_signing_runtime(
            request,
            plan,
            registry=ExactCustodyRuntimeProfileRegistry((registration,)),
        )


def test_registry_exception_text_does_not_escape_the_boundary() -> None:
    configuration = _configuration()
    request = _request(configuration)
    plan = create_control_run_execution_plan(
        request,
        capture_nonce=_NONCE,
        prepared_at=_PREPARED,
    )

    class _FailingRegistry:
        def resolve(self, **kwargs: object) -> RegisteredCustodySigningRuntime:
            del kwargs
            raise RuntimeError(
                f"{_VAULT_ENDPOINT} {_TOKEN.decode()} should remain private"
            )

    with pytest.raises(CustodyRuntimeIdentityError) as caught:
        prepare_custody_signing_runtime(
            request,
            plan,
            registry=_FailingRegistry(),
        )

    assert str(caught.value) == "runtime-profile-registry-failed"
    assert _VAULT_ENDPOINT not in repr(caught.value)
    assert _TOKEN.decode() not in repr(caught.value)


def test_profile_extra_member_is_rejected_even_when_recannonicalized() -> None:
    profile, registration = _profile_and_registration()
    del registration
    document = json.loads(profile.canonical_bytes())
    document["vault_endpoint"] = _VAULT_ENDPOINT

    with pytest.raises(
        CustodyRuntimeIdentityError,
        match="deployment-profile-invalid",
    ):
        parse_custody_signing_deployment_profile(
            canonical_json_bytes(document)
        )
