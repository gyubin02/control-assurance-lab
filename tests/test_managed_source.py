from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from assurance_lab._version import __version__
from assurance_lab.connectors.contract import ConnectorCapture, ConnectorDescriptor
from assurance_lab.connectors.defender_pam import (
    ManagedDefenderCapture,
    VerifiedDefenderPamReceipt,
    defender_entra_cloud,
)
from assurance_lab.connectors.defender_xdr import (
    DEFENDER_XDR_CAPTURE_MEDIA_TYPE,
    DEFENDER_XDR_CONNECTOR_ID,
)
from assurance_lab.connectors.elastic_pam import (
    ManagedElasticCapture,
    VerifiedElasticPamReceipt,
)
from assurance_lab.connectors.elastic_security import (
    ELASTIC_SECURITY_CAPTURE_MEDIA_TYPE,
    ELASTIC_SECURITY_CONNECTOR_ID,
    elastic_endpoint_origin_digest,
)
from assurance_lab.connectors.managed_evidence import (
    PamReceiptVerificationContext,
)
from assurance_lab.control_plane.models import (
    ControlConfiguration,
    DefenderSourceConfiguration,
    ElasticSourceConfiguration,
    EvidenceConfiguration,
    ScheduleConfiguration,
)
from assurance_lab.controls.alert_window import (
    ALERT_WINDOW_PROFILE_MEDIA_TYPE,
    AlertWindowProfile,
    Criterion,
    DefenderAlertSource,
    ElasticAlertSource,
    EqualsPredicate,
    MatchingRecordCount,
)
from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.runtime.execution_plan import (
    ControlRunExecutionPlan,
    create_control_run_execution_plan,
)
from assurance_lab.runtime.managed_source import (
    DEFENDER_AUTHORIZATION_PROFILE_ID,
    DEFENDER_PAM_VERIFIER_ID,
    ELASTIC_AUTHORIZATION_PROFILE_ID,
    ELASTIC_PAM_VERIFIER_ID,
    ManagedSourceError,
    prepare_defender_managed_source,
    prepare_elastic_managed_source,
)
from assurance_lab.runtime.models import (
    ControlRunExecutionRequest,
    ControlRunRequest,
    sha256_digest,
)

_START = datetime(2026, 7, 29, 1, 0, tzinfo=UTC)
_END = _START + timedelta(minutes=5)
_NONCE = "12" * 32
_DIGESTS = tuple(f"sha256:{str(index) * 64}" for index in range(1, 7))


def _profile(kind: str) -> AlertWindowProfile:
    source = (
        ElasticAlertSource(
            fields=("@timestamp", "kibana.alert.severity"),
        )
        if kind == "elastic-security"
        else DefenderAlertSource()
    )
    field = "kibana.alert.severity" if kind == "elastic-security" else "Severity"
    return AlertWindowProfile(
        profile_id="high-alert-window",
        profile_version="1.0.0",
        title="High alert window",
        source=source,
        criteria=(
            Criterion(
                criterion_id="high-alert",
                description="At least one high alert was observed.",
                metric=MatchingRecordCount(
                    all=(EqualsPredicate(field=field, value="High"),)
                ),
                comparison="ge",
                expected_count=1,
            ),
        ),
    )


def _configuration(profile: AlertWindowProfile) -> ControlConfiguration:
    source = (
        ElasticSourceConfiguration(
            endpoint_origin="https://elastic.bank.invalid",
            index_alias=".alerts-security.alerts-payments",
            parent_credential_ref=(
                "azure-keyvault://bank-vault/secrets/"
                "elastic-parent/0123456789abcdef0123456789abcdef"
            ),
            lease_ttl_seconds=1_200,
        )
        if profile.source_kind == "elastic-security"
        else DefenderSourceConfiguration(
            cloud="global",
            tenant_id="11111111-1111-4111-8111-111111111111",
            client_id="22222222-2222-4222-8222-222222222222",
            client_credential_ref=(
                "azure-keyvault://bank-vault/secrets/"
                "defender-profile/0123456789abcdef0123456789abcdef"
            ),
        )
    )
    return ControlConfiguration(
        tenant_id="bank-a",
        control_id="high-alert",
        display_name="High alert",
        description="Collect and re-evaluate one closed alert window.",
        environment="production",
        owner_group="security/detection",
        control_profile_id=profile.profile_id,
        control_profile_digest=profile.digest,
        source=source,
        schedule=ScheduleConfiguration(
            interval_seconds=300,
            collection_lag_seconds=120,
            window_seconds=300,
        ),
        evidence=EvidenceConfiguration(
            custody_ref="s3-object-lock://evidence/bank-a/high-alert",
            signing_key_ref="vault-transit://assurance/runtime",
            retention_days=365,
        ),
    )


def _request(kind: str) -> ControlRunExecutionRequest:
    profile = _profile(kind)
    configuration = _configuration(profile)
    run = ControlRunRequest(
        tenant_id=configuration.tenant_id,
        control_id=configuration.control_id,
        deployment_operation_id=_DIGESTS[0],
        deployment_operation_sequence=1,
        deployment_receipt_digest=_DIGESTS[1],
        control_profile_id=profile.profile_id,
        control_profile_digest=profile.digest,
        revision_id=_DIGESTS[2],
        configuration_digest=configuration.digest,
        window_start=_START,
        window_end=_END,
        due_at=_END + timedelta(minutes=2),
    )
    return ControlRunExecutionRequest(
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
        lease_fence=1,
    )


def _plan(request: ControlRunExecutionRequest) -> ControlRunExecutionPlan:
    return create_control_run_execution_plan(
        request,
        capture_nonce=_NONCE,
        prepared_at=_END + timedelta(minutes=2),
    )


def _capture(descriptor: ConnectorDescriptor) -> ConnectorCapture:
    receipt = canonical_json_bytes({"test": "source"})
    return ConnectorCapture(
        descriptor=descriptor,
        receipt_bytes=receipt,
        receipt_digest=sha256_digest(receipt),
        records_jsonl=b"",
        records_digest=sha256_digest(b""),
        record_count=0,
    )


class _ElasticBroker:
    def __init__(
        self,
        *,
        endpoint_digest: str,
        descriptor: ConnectorDescriptor | None = None,
    ) -> None:
        self.endpoint_origin_digest = endpoint_digest
        self.descriptor = descriptor or ConnectorDescriptor(
            connector_id=ELASTIC_SECURITY_CONNECTOR_ID,
            connector_version=__version__,
            capture_media_type=ELASTIC_SECURITY_CAPTURE_MEDIA_TYPE,
        )
        self.ttl: int | None = None

    def capture(
        self,
        request: Any,
        *,
        ttl_seconds: int = 900,
    ) -> ManagedElasticCapture:
        del request
        self.ttl = ttl_seconds
        pam = canonical_json_bytes({"test": "pam"})
        return ManagedElasticCapture(
            capture=_capture(self.descriptor),
            pam_receipt_bytes=pam,
            pam_receipt_digest=sha256_digest(pam),
        )


class _DefenderBroker:
    def __init__(self, *, wrong_cloud: bool = False) -> None:
        cloud = defender_entra_cloud("global")
        self.token_endpoint_digest = _DIGESTS[3]
        self.graph_origin_digest = (
            _DIGESTS[4] if wrong_cloud else cloud.graph_origin_digest
        )
        self.scope_digest = cloud.scope_digest
        self.credential_reference_digest = _DIGESTS[5]

    def capture(self, request: Any) -> ManagedDefenderCapture:
        del request
        pam = canonical_json_bytes({"test": "pam"})
        return ManagedDefenderCapture(
            capture=_capture(
                ConnectorDescriptor(
                    connector_id=DEFENDER_XDR_CONNECTOR_ID,
                    connector_version=__version__,
                    capture_media_type=DEFENDER_XDR_CAPTURE_MEDIA_TYPE,
                )
            ),
            pam_receipt_bytes=pam,
            pam_receipt_digest=sha256_digest(pam),
        )


def _context(prepared: Any, request_digest: str) -> PamReceiptVerificationContext:
    return PamReceiptVerificationContext(
        job_digest=_DIGESTS[0],
        run_id=_DIGESTS[1],
        request_digest=request_digest,
        source_locator_digest=prepared.source_locator_digest,
        capture_receipt_digest=_DIGESTS[2],
        capture_records_digest=_DIGESTS[3],
        authorization_profile_id=prepared.authorization_profile.profile_id,
        authorization_profile_digest=prepared.authorization_profile.digest,
        authorization_binding_digest=(
            prepared.authorization_profile.authorization_binding_digest
        ),
        capture_window_end_epoch_millis=int(_END.timestamp() * 1_000),
    )


def test_elastic_preparation_binds_endpoint_request_and_public_authority() -> None:
    request = _request("elastic-security")
    plan = _plan(request)
    endpoint_digest = elastic_endpoint_origin_digest(
        "https://elastic.bank.invalid"
    )
    broker = _ElasticBroker(endpoint_digest=endpoint_digest)

    prepared = prepare_elastic_managed_source(
        request,
        plan,
        broker=broker,
    )
    captured = prepared.capture()

    assert prepared.authorization_profile.profile_id == (
        ELASTIC_AUTHORIZATION_PROFILE_ID
    )
    assert prepared.authorization_profile.permission_ids == (
        "elasticsearch:index/read",
    )
    assert prepared.source_locator_digest == endpoint_digest
    assert captured.capture.descriptor == prepared.descriptor
    assert broker.ttl == 1_200


def test_elastic_broker_endpoint_substitution_fails_before_capture() -> None:
    request = _request("elastic-security")
    plan = _plan(request)

    with pytest.raises(ManagedSourceError, match="endpoint differs"):
        prepare_elastic_managed_source(
            request,
            plan,
            broker=_ElasticBroker(endpoint_digest=_DIGESTS[0]),
        )


def test_elastic_capture_with_a_different_descriptor_is_withheld() -> None:
    request = _request("elastic-security")
    plan = _plan(request)
    broker = _ElasticBroker(
        endpoint_digest=elastic_endpoint_origin_digest(
            "https://elastic.bank.invalid"
        ),
        descriptor=ConnectorDescriptor(
            connector_id="another-elastic-collector",
            connector_version=__version__,
            capture_media_type=ELASTIC_SECURITY_CAPTURE_MEDIA_TYPE,
        ),
    )
    prepared = prepare_elastic_managed_source(request, plan, broker=broker)

    with pytest.raises(ManagedSourceError, match="different connector"):
        prepared.capture()


def test_defender_preparation_binds_cloud_permission_and_credential() -> None:
    request = _request("defender-xdr")
    plan = _plan(request)
    broker = _DefenderBroker()

    prepared = prepare_defender_managed_source(
        request,
        plan,
        broker=broker,
    )

    assert prepared.authorization_profile.profile_id == (
        DEFENDER_AUTHORIZATION_PROFILE_ID
    )
    assert prepared.authorization_profile.permission_ids == (
        "microsoft-graph:ThreatHunting.Read.All",
    )
    assert prepared.authorization_profile.credential_reference_digest == (
        sha256_digest(
            b"azure-keyvault://bank-vault/secrets/"
            b"defender-profile/0123456789abcdef0123456789abcdef"
        )
    )
    assert broker.graph_origin_digest in (
        prepared.authorization_profile.resource_scope_digests
    )


def test_defender_cloud_substitution_fails_before_capture() -> None:
    request = _request("defender-xdr")
    plan = _plan(request)

    with pytest.raises(ManagedSourceError, match="cloud differs"):
        prepare_defender_managed_source(
            request,
            plan,
            broker=_DefenderBroker(wrong_cloud=True),
        )


def test_elastic_pam_projection_requires_exact_ttl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request("elastic-security")
    plan = _plan(request)
    prepared = prepare_elastic_managed_source(
        request,
        plan,
        broker=_ElasticBroker(
            endpoint_digest=elastic_endpoint_origin_digest(
                "https://elastic.bank.invalid"
            )
        ),
    )
    receipt = canonical_json_bytes(
        {
            "lease": {
                "index_alias": ".alerts-security.alerts-payments",
                "ttl_seconds": 1_200,
            }
        }
    )
    context = _context(prepared, plan.connector_request_digest)

    def native(*args: Any, **kwargs: Any) -> VerifiedElasticPamReceipt:
        del args, kwargs
        return VerifiedElasticPamReceipt(
            lease_id="a" * 64,
            request_digest=context.request_digest,
            endpoint_origin_digest=context.source_locator_digest,
            role_descriptor_digest=(
                prepared.authorization_profile.authorization_binding_digest
            ),
            capture_receipt_digest=context.capture_receipt_digest,
            capture_records_digest=context.capture_records_digest,
            receipt_digest=sha256_digest(receipt),
        )

    monkeypatch.setattr(
        "assurance_lab.runtime.managed_source.verify_elastic_pam_receipt",
        native,
    )
    verified = prepared.pam_receipt_verifier(receipt, context)

    assert verified.verifier_id == ELASTIC_PAM_VERIFIER_ID
    assert verified.credential_exposure_state == "revoked"
    assert verified.residual_exposure_end_epoch_millis is None

    tampered = canonical_json_bytes(
        {
            "lease": {
                "index_alias": ".alerts-security.alerts-payments",
                "ttl_seconds": 3_600,
            }
        }
    )
    with pytest.raises(ManagedSourceError, match="lease policy"):
        prepared.pam_receipt_verifier(tampered, context)


def test_defender_pam_projection_preserves_residual_exposure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request("defender-xdr")
    plan = _plan(request)
    broker = _DefenderBroker()
    prepared = prepare_defender_managed_source(
        request,
        plan,
        broker=broker,
    )
    receipt = canonical_json_bytes(
        {
            "authorization": {
                "required_application_permission": "ThreatHunting.Read.All"
            },
            "identity": {
                "client_id_digest": sha256_digest(
                    b"22222222-2222-4222-8222-222222222222"
                ),
                "cloud": "global",
                "tenant_id_digest": sha256_digest(
                    b"11111111-1111-4111-8111-111111111111"
                ),
            },
        }
    )
    context = _context(prepared, plan.connector_request_digest)
    residual = 1_785_300_000_000

    def native(*args: Any, **kwargs: Any) -> VerifiedDefenderPamReceipt:
        del args, kwargs
        return VerifiedDefenderPamReceipt(
            acquisition_id="b" * 64,
            request_digest=context.request_digest,
            token_endpoint_digest=broker.token_endpoint_digest,
            graph_origin_digest=broker.graph_origin_digest,
            scope_digest=broker.scope_digest,
            credential_reference_digest=broker.credential_reference_digest,
            capture_receipt_digest=context.capture_receipt_digest,
            capture_records_digest=context.capture_records_digest,
            residual_exposure_end_epoch_millis=residual,
            receipt_digest=sha256_digest(receipt),
        )

    monkeypatch.setattr(
        "assurance_lab.runtime.managed_source.verify_defender_pam_receipt",
        native,
    )
    verified = prepared.pam_receipt_verifier(receipt, context)

    assert verified.verifier_id == DEFENDER_PAM_VERIFIER_ID
    assert verified.credential_exposure_state == "released-awaiting-expiry"
    assert verified.residual_exposure_end_epoch_millis == residual


def test_pam_projection_rejects_authorization_profile_substitution() -> None:
    request = _request("defender-xdr")
    plan = _plan(request)
    prepared = prepare_defender_managed_source(
        request,
        plan,
        broker=_DefenderBroker(),
    )
    context = _context(prepared, plan.connector_request_digest).model_copy(
        update={"authorization_profile_digest": _DIGESTS[0]}
    )

    with pytest.raises(ManagedSourceError, match="authorization profile differs"):
        prepared.pam_receipt_verifier(b"{}", context)
