"""Runtime adapters joining frozen plans to managed SIEM/EDR connectors.

These adapters contain no secret lookup logic.  They receive already
constructed brokers whose credentials were resolved by a separate,
version-pinned boundary.  Their job is to prove that the broker, deployed
configuration, connector request, native PAM receipt, and public authorization
profile all describe the same operation.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any, Final, Protocol, cast, runtime_checkable

from assurance_lab._version import __version__
from assurance_lab.connectors.contract import (
    ConnectorCapture,
    ConnectorDescriptor,
    VerifiedConnectorCapture,
)
from assurance_lab.connectors.defender_pam import (
    ManagedDefenderCapture,
    VerifiedDefenderPamReceipt,
    defender_entra_cloud,
    verify_defender_pam_receipt,
)
from assurance_lab.connectors.defender_xdr import (
    DEFENDER_XDR_CAPTURE_MEDIA_TYPE,
    DEFENDER_XDR_CONNECTOR_ID,
    DEFENDER_XDR_REQUIRED_PERMISSION,
    DefenderXDRRequest,
    verify_defender_xdr_capture,
)
from assurance_lab.connectors.elastic_pam import (
    ElasticPamPolicy,
    ManagedElasticCapture,
    VerifiedElasticPamReceipt,
    verify_elastic_pam_receipt,
)
from assurance_lab.connectors.elastic_security import (
    ELASTIC_SECURITY_CAPTURE_MEDIA_TYPE,
    ELASTIC_SECURITY_CONNECTOR_ID,
    ElasticSecurityRequest,
    elastic_endpoint_origin_digest,
    verify_elastic_security_capture,
)
from assurance_lab.connectors.managed_evidence import (
    ManagedAuthorizationProfile,
    PamReceiptVerificationContext,
    PamReceiptVerifier,
    VerifiedPamLifecycleReceipt,
)
from assurance_lab.control_plane.models import (
    ControlConfiguration,
    DefenderSourceConfiguration,
    ElasticSourceConfiguration,
)
from assurance_lab.controls.alert_window import (
    AlertWindowProfile,
    DefenderAlertSource,
    ElasticAlertSource,
    parse_alert_window_profile,
)
from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)
from assurance_lab.runtime.execution_plan import (
    ControlRunExecutionPlan,
    verify_control_run_execution_plan,
)
from assurance_lab.runtime.models import ControlRunExecutionRequest, sha256_digest

ELASTIC_AUTHORIZATION_PROFILE_ID: Final = "elastic-jit-alert-read-v1"
DEFENDER_AUTHORIZATION_PROFILE_ID: Final = "defender-workload-alert-read-v1"
ELASTIC_RECEIPT_VERIFIER_ID: Final = "python/elastic-security-receipt-v1"
ELASTIC_PAM_VERIFIER_ID: Final = "python/elastic-jit-pam-receipt-v1"
DEFENDER_RECEIPT_VERIFIER_ID: Final = "python/defender-xdr-receipt-v1"
DEFENDER_PAM_VERIFIER_ID: Final = "python/defender-workload-pam-receipt-v1"

_PAM_LIMITS = JSONLimits(
    max_bytes=2 * 1024 * 1024,
    max_line_bytes=2 * 1024 * 1024,
    max_depth=24,
    max_collection_items=32_768,
    max_string_length=512 * 1024,
)


class ManagedSourceError(RuntimeError):
    """A configured broker cannot enter the managed evidence boundary."""

    __slots__ = ("stage",)

    def __init__(self, stage: str, detail: str) -> None:
        if (
            type(stage) is not str
            or not stage
            or len(stage) > 64
            or not stage.replace("-", "").isalnum()
        ):
            raise ValueError("managed source error stage is invalid")
        if type(detail) is not str or not detail or len(detail) > 256:
            raise ValueError("managed source error detail is invalid")
        self.stage = stage
        super().__init__(detail)


def _digest_text(value: str) -> str:
    return sha256_digest(value.encode("utf-8"))


def _public_document(value: bytes, *, label: str) -> dict[str, Any]:
    try:
        parsed = strict_json_loads(value, limits=_PAM_LIMITS)
        canonical = canonical_json_bytes(parsed, limits=_PAM_LIMITS)
    except StrictJSONError as exc:
        raise ManagedSourceError("pam-verification", f"{label} is not strict JSON") from exc
    if not isinstance(parsed, dict) or canonical != value:
        raise ManagedSourceError(
            "pam-verification",
            f"{label} is not one canonical JSON object",
        )
    return cast(dict[str, Any], parsed)


@runtime_checkable
class ElasticManagedBroker(Protocol):
    @property
    def endpoint_origin_digest(self) -> str: ...

    def capture(
        self,
        request: ElasticSecurityRequest,
        *,
        ttl_seconds: int = 900,
    ) -> ManagedElasticCapture: ...


@runtime_checkable
class DefenderManagedBroker(Protocol):
    @property
    def token_endpoint_digest(self) -> str: ...

    @property
    def graph_origin_digest(self) -> str: ...

    @property
    def scope_digest(self) -> str: ...

    @property
    def credential_reference_digest(self) -> str: ...

    def capture(self, request: DefenderXDRRequest) -> ManagedDefenderCapture: ...


@dataclass(frozen=True, slots=True)
class ManagedSourceCapture:
    capture: ConnectorCapture
    pam_receipt_bytes: bytes
    pam_receipt_digest: str

    def __post_init__(self) -> None:
        if type(self.capture) is not ConnectorCapture:
            raise TypeError("managed source capture has an invalid connector capture")
        if type(self.pam_receipt_bytes) is not bytes or not self.pam_receipt_bytes:
            raise TypeError("managed source capture lacks immutable PAM receipt bytes")
        if sha256_digest(self.pam_receipt_bytes) != self.pam_receipt_digest:
            raise ValueError("managed source PAM receipt digest differs from its bytes")


@dataclass(frozen=True, slots=True)
class PreparedManagedSource:
    """Prepared connector operation; publication also requires runtime binding.

    Low-level connector tests may construct an unbound operation.  Production
    composition calls :meth:`bind_runtime_identity` before the operation can
    cross the durable publication boundary.
    """

    descriptor: ConnectorDescriptor
    source_locator_digest: str
    connector_request: ElasticSecurityRequest | DefenderXDRRequest
    connector_request_bytes: bytes
    authorization_profile: ManagedAuthorizationProfile
    connector_receipt_verifier_id: str
    pam_receipt_verifier_id: str
    _capture: Callable[[], ManagedSourceCapture]
    receipt_verifier: Callable[[bytes], VerifiedConnectorCapture]
    pam_receipt_verifier: PamReceiptVerifier
    runtime_identity_media_type: str | None = None
    runtime_identity_bytes: bytes | None = field(default=None, repr=False)
    runtime_identity_digest: str | None = None

    def __post_init__(self) -> None:
        if type(self.descriptor) is not ConnectorDescriptor:
            raise TypeError("managed source descriptor must be exact")
        if type(self.authorization_profile) is not ManagedAuthorizationProfile:
            raise TypeError("managed authorization profile must be exact")
        if (
            type(self.connector_request_bytes) is not bytes
            or canonical_json_bytes(self.connector_request.as_json())
            != self.connector_request_bytes
        ):
            raise ValueError("managed connector request bytes are not exact")
        for verifier in (
            self._capture,
            self.receipt_verifier,
            self.pam_receipt_verifier,
        ):
            if not callable(verifier):
                raise TypeError("managed source operation is not callable")
        identity_fields = (
            self.runtime_identity_media_type,
            self.runtime_identity_bytes,
            self.runtime_identity_digest,
        )
        if any(value is not None for value in identity_fields):
            if (
                type(self.runtime_identity_media_type) is not str
                or not self.runtime_identity_media_type
                or type(self.runtime_identity_bytes) is not bytes
                or not self.runtime_identity_bytes
                or type(self.runtime_identity_digest) is not str
                or sha256_digest(self.runtime_identity_bytes)
                != self.runtime_identity_digest
            ):
                raise ValueError(
                    "managed source runtime identity is not an exact triple"
                )
            try:
                document = strict_json_loads(
                    self.runtime_identity_bytes,
                    limits=_PAM_LIMITS,
                )
            except StrictJSONError as exc:
                raise ValueError(
                    "managed source runtime identity is not strict JSON"
                ) from exc
            if (
                not isinstance(document, dict)
                or canonical_json_bytes(document, limits=_PAM_LIMITS)
                != self.runtime_identity_bytes
                or document.get("media_type")
                != self.runtime_identity_media_type
            ):
                raise ValueError(
                    "managed source runtime identity is not canonical"
                )

    def bind_runtime_identity(
        self,
        *,
        media_type: str,
        identity_bytes: bytes,
        identity_digest: str,
    ) -> PreparedManagedSource:
        """Return this prepared operation bound to its complete public identity."""

        if self.runtime_identity_bytes is not None:
            if (
                self.runtime_identity_media_type != media_type
                or self.runtime_identity_bytes != identity_bytes
                or self.runtime_identity_digest != identity_digest
            ):
                raise ManagedSourceError(
                    "identity-binding",
                    "managed source already uses a different runtime identity",
                )
            return self
        return replace(
            self,
            runtime_identity_media_type=media_type,
            runtime_identity_bytes=identity_bytes,
            runtime_identity_digest=identity_digest,
        )

    def capture(self) -> ManagedSourceCapture:
        result = self._capture()
        if type(result) is not ManagedSourceCapture:
            raise ManagedSourceError(
                "capture",
                "managed broker returned an unsupported capture",
            )
        if result.capture.descriptor != self.descriptor:
            raise ManagedSourceError(
                "capture",
                "managed capture selected a different connector",
            )
        return result


def _validated_inputs(
    execution_request: ControlRunExecutionRequest,
    plan: ControlRunExecutionPlan,
) -> tuple[
    ControlConfiguration,
    AlertWindowProfile,
    ElasticSecurityRequest | DefenderXDRRequest,
]:
    if type(execution_request) is not ControlRunExecutionRequest:
        raise TypeError("execution request must be exact")
    if type(plan) is not ControlRunExecutionPlan:
        raise TypeError("execution plan must be exact")
    try:
        reopened, connector_request = verify_control_run_execution_plan(
            plan.canonical_bytes(),
            expected_request=execution_request,
        )
        configuration = ControlConfiguration.model_validate_json(
            execution_request.configuration_bytes
        )
        profile = parse_alert_window_profile(
            execution_request.control_profile_bytes,
            expected_profile_id=execution_request.control_profile_id,
            expected_profile_digest=execution_request.control_profile_digest,
        )
    except (TypeError, ValueError) as exc:
        raise ManagedSourceError(
            "input",
            "runtime inputs do not rederive the connector operation",
        ) from exc
    if reopened != plan:
        raise ManagedSourceError("input", "execution plan changed while it was reopened")
    return configuration, profile, connector_request


def _elastic_authorization_profile(
    configuration: ElasticSourceConfiguration,
    *,
    source_locator_digest: str,
    policy: ElasticPamPolicy,
) -> ManagedAuthorizationProfile:
    binding = sha256_digest(
        canonical_json_bytes(
            {
                "endpoint_origin_digest": source_locator_digest,
                "index_alias": configuration.index_alias,
                "pam_mode": configuration.pam_mode,
                "role_descriptor_digest": policy.role_descriptor_digest,
                "ttl_seconds": configuration.lease_ttl_seconds,
            }
        )
    )
    return ManagedAuthorizationProfile(
        profile_id=ELASTIC_AUTHORIZATION_PROFILE_ID,
        provider_id="elasticsearch",
        authorization_binding_digest=binding,
        credential_reference_digest=_digest_text(
            configuration.parent_credential_ref
        ),
        permission_ids=("elasticsearch:index/read",),
        resource_scope_digests=tuple(
            sorted(
                {
                    source_locator_digest,
                    _digest_text(configuration.index_alias),
                }
            )
        ),
    )


def prepare_elastic_managed_source(
    execution_request: ControlRunExecutionRequest,
    plan: ControlRunExecutionPlan,
    *,
    broker: ElasticManagedBroker,
) -> PreparedManagedSource:
    """Bind an Elastic JIT broker to one frozen read-only request."""

    if not isinstance(broker, ElasticManagedBroker):
        raise TypeError("broker does not implement the Elastic managed protocol")
    configuration, profile, connector_request = _validated_inputs(
        execution_request,
        plan,
    )
    if (
        not isinstance(configuration.source, ElasticSourceConfiguration)
        or not isinstance(profile.source, ElasticAlertSource)
        or type(connector_request) is not ElasticSecurityRequest
    ):
        raise ManagedSourceError("input", "runtime inputs do not select Elastic")
    source = configuration.source
    request = connector_request
    source_digest = elastic_endpoint_origin_digest(
        source.endpoint_origin
    )
    if broker.endpoint_origin_digest != source_digest:
        raise ManagedSourceError(
            "broker-binding",
            "Elastic broker endpoint differs from deployed configuration",
        )
    policy = ElasticPamPolicy(
        index_alias=source.index_alias,
        ttl_seconds=source.lease_ttl_seconds,
    )
    authorization = _elastic_authorization_profile(
        source,
        source_locator_digest=source_digest,
        policy=policy,
    )

    def capture() -> ManagedSourceCapture:
        managed = broker.capture(
            request,
            ttl_seconds=source.lease_ttl_seconds,
        )
        if type(managed) is not ManagedElasticCapture:
            raise ManagedSourceError(
                "capture",
                "Elastic broker returned an unsupported managed capture",
            )
        return ManagedSourceCapture(
            capture=managed.capture,
            pam_receipt_bytes=managed.pam_receipt_bytes,
            pam_receipt_digest=managed.pam_receipt_digest,
        )

    def verify_source(receipt: bytes) -> VerifiedConnectorCapture:
        return verify_elastic_security_capture(
            receipt,
            expected_endpoint_origin_digest=source_digest,
            expected_request=request,
        )

    def verify_pam(
        receipt: bytes,
        context: PamReceiptVerificationContext,
    ) -> VerifiedPamLifecycleReceipt:
        if (
            context.authorization_profile_id != authorization.profile_id
            or context.authorization_profile_digest != authorization.digest
            or context.authorization_binding_digest
            != authorization.authorization_binding_digest
        ):
            raise ManagedSourceError(
                "pam-verification",
                "Elastic authorization profile differs from managed evidence",
            )
        native: VerifiedElasticPamReceipt = verify_elastic_pam_receipt(
            receipt,
            expected_request_digest=context.request_digest,
            expected_endpoint_origin_digest=source_digest,
            expected_role_descriptor_digest=policy.role_descriptor_digest,
            expected_capture_receipt_digest=context.capture_receipt_digest,
            expected_capture_records_digest=context.capture_records_digest,
        )
        document = _public_document(receipt, label="Elastic PAM receipt")
        lease = document.get("lease")
        if (
            not isinstance(lease, dict)
            or lease.get("index_alias") != source.index_alias
            or lease.get("ttl_seconds") != source.lease_ttl_seconds
        ):
            raise ManagedSourceError(
                "pam-verification",
                "Elastic PAM receipt differs from the deployed lease policy",
            )
        lifecycle_reference = sha256_digest(
            canonical_json_bytes(
                {
                    "lease_id": native.lease_id,
                    "receipt_digest": native.receipt_digest,
                    "revocation_state": "confirmed",
                }
            )
        )
        return VerifiedPamLifecycleReceipt(
            verifier_id=ELASTIC_PAM_VERIFIER_ID,
            receipt_digest=native.receipt_digest,
            job_digest=context.job_digest,
            run_id=context.run_id,
            request_digest=context.request_digest,
            source_locator_digest=context.source_locator_digest,
            capture_receipt_digest=context.capture_receipt_digest,
            capture_records_digest=context.capture_records_digest,
            authorization_profile_id=context.authorization_profile_id,
            authorization_profile_digest=context.authorization_profile_digest,
            authorization_binding_digest=context.authorization_binding_digest,
            lifecycle_reference_digest=lifecycle_reference,
            credential_exposure_state="revoked",
        )

    return PreparedManagedSource(
        descriptor=ConnectorDescriptor(
            connector_id=ELASTIC_SECURITY_CONNECTOR_ID,
            connector_version=__version__,
            capture_media_type=ELASTIC_SECURITY_CAPTURE_MEDIA_TYPE,
        ),
        source_locator_digest=source_digest,
        connector_request=request,
        connector_request_bytes=plan.connector_request_bytes,
        authorization_profile=authorization,
        connector_receipt_verifier_id=ELASTIC_RECEIPT_VERIFIER_ID,
        pam_receipt_verifier_id=ELASTIC_PAM_VERIFIER_ID,
        _capture=capture,
        receipt_verifier=verify_source,
        pam_receipt_verifier=verify_pam,
    )


def _defender_authorization_profile(
    configuration: DefenderSourceConfiguration,
    *,
    broker: DefenderManagedBroker,
) -> ManagedAuthorizationProfile:
    cloud = defender_entra_cloud(configuration.cloud)
    binding = sha256_digest(
        canonical_json_bytes(
            {
                "client_id_digest": _digest_text(configuration.client_id),
                "cloud": configuration.cloud,
                "credential_reference_digest": (
                    broker.credential_reference_digest
                ),
                "graph_origin_digest": broker.graph_origin_digest,
                "permission": configuration.permission,
                "runtime_permission_attenuation_supported": False,
                "scope_digest": broker.scope_digest,
                "tenant_id_digest": _digest_text(configuration.tenant_id),
                "token_endpoint_digest": broker.token_endpoint_digest,
            }
        )
    )
    return ManagedAuthorizationProfile(
        profile_id=DEFENDER_AUTHORIZATION_PROFILE_ID,
        provider_id="microsoft-entra",
        authorization_binding_digest=binding,
        credential_reference_digest=_digest_text(
            configuration.client_credential_ref
        ),
        permission_ids=(
            f"microsoft-graph:{DEFENDER_XDR_REQUIRED_PERMISSION}",
        ),
        resource_scope_digests=tuple(
            sorted(
                {
                    cloud.graph_origin_digest,
                    cloud.scope_digest,
                    _digest_text(configuration.tenant_id),
                }
            )
        ),
    )


def prepare_defender_managed_source(
    execution_request: ControlRunExecutionRequest,
    plan: ControlRunExecutionPlan,
    *,
    broker: DefenderManagedBroker,
) -> PreparedManagedSource:
    """Bind a Defender workload broker to one frozen AlertInfo request."""

    if not isinstance(broker, DefenderManagedBroker):
        raise TypeError("broker does not implement the Defender managed protocol")
    configuration, profile, connector_request = _validated_inputs(
        execution_request,
        plan,
    )
    if (
        not isinstance(configuration.source, DefenderSourceConfiguration)
        or not isinstance(profile.source, DefenderAlertSource)
        or type(connector_request) is not DefenderXDRRequest
    ):
        raise ManagedSourceError("input", "runtime inputs do not select Defender")
    source = configuration.source
    request = connector_request
    cloud = defender_entra_cloud(source.cloud)
    if (
        broker.graph_origin_digest != cloud.graph_origin_digest
        or broker.scope_digest != cloud.scope_digest
    ):
        raise ManagedSourceError(
            "broker-binding",
            "Defender broker cloud differs from deployed configuration",
        )
    authorization = _defender_authorization_profile(
        source,
        broker=broker,
    )

    def capture() -> ManagedSourceCapture:
        managed = broker.capture(request)
        if type(managed) is not ManagedDefenderCapture:
            raise ManagedSourceError(
                "capture",
                "Defender broker returned an unsupported managed capture",
            )
        return ManagedSourceCapture(
            capture=managed.capture,
            pam_receipt_bytes=managed.pam_receipt_bytes,
            pam_receipt_digest=managed.pam_receipt_digest,
        )

    def verify_source(receipt: bytes) -> VerifiedConnectorCapture:
        return verify_defender_xdr_capture(
            receipt,
            expected_endpoint_origin_digest=cloud.graph_origin_digest,
            expected_request=request,
        )

    def verify_pam(
        receipt: bytes,
        context: PamReceiptVerificationContext,
    ) -> VerifiedPamLifecycleReceipt:
        if (
            context.authorization_profile_id != authorization.profile_id
            or context.authorization_profile_digest != authorization.digest
            or context.authorization_binding_digest
            != authorization.authorization_binding_digest
        ):
            raise ManagedSourceError(
                "pam-verification",
                "Defender authorization profile differs from managed evidence",
            )
        native: VerifiedDefenderPamReceipt = verify_defender_pam_receipt(
            receipt,
            expected_request_digest=context.request_digest,
            expected_token_endpoint_digest=broker.token_endpoint_digest,
            expected_graph_origin_digest=cloud.graph_origin_digest,
            expected_scope_digest=cloud.scope_digest,
            expected_credential_reference_digest=(
                broker.credential_reference_digest
            ),
            expected_capture_receipt_digest=context.capture_receipt_digest,
            expected_capture_records_digest=context.capture_records_digest,
        )
        document = _public_document(receipt, label="Defender PAM receipt")
        identity = document.get("identity")
        authorization_document = document.get("authorization")
        if (
            not isinstance(identity, dict)
            or identity.get("tenant_id_digest")
            != _digest_text(source.tenant_id)
            or identity.get("client_id_digest")
            != _digest_text(source.client_id)
            or identity.get("cloud") != source.cloud
            or not isinstance(authorization_document, dict)
            or authorization_document.get("required_application_permission")
            != source.permission
        ):
            raise ManagedSourceError(
                "pam-verification",
                "Defender PAM receipt differs from the deployed identity",
            )
        lifecycle_reference = sha256_digest(
            canonical_json_bytes(
                {
                    "acquisition_id": native.acquisition_id,
                    "receipt_digest": native.receipt_digest,
                    "residual_exposure_end_epoch_millis": (
                        native.residual_exposure_end_epoch_millis
                    ),
                }
            )
        )
        return VerifiedPamLifecycleReceipt(
            verifier_id=DEFENDER_PAM_VERIFIER_ID,
            receipt_digest=native.receipt_digest,
            job_digest=context.job_digest,
            run_id=context.run_id,
            request_digest=context.request_digest,
            source_locator_digest=context.source_locator_digest,
            capture_receipt_digest=context.capture_receipt_digest,
            capture_records_digest=context.capture_records_digest,
            authorization_profile_id=context.authorization_profile_id,
            authorization_profile_digest=context.authorization_profile_digest,
            authorization_binding_digest=context.authorization_binding_digest,
            lifecycle_reference_digest=lifecycle_reference,
            credential_exposure_state="released-awaiting-expiry",
            residual_exposure_end_epoch_millis=(
                native.residual_exposure_end_epoch_millis
            ),
        )

    return PreparedManagedSource(
        descriptor=ConnectorDescriptor(
            connector_id=DEFENDER_XDR_CONNECTOR_ID,
            connector_version=__version__,
            capture_media_type=DEFENDER_XDR_CAPTURE_MEDIA_TYPE,
        ),
        source_locator_digest=cloud.graph_origin_digest,
        connector_request=request,
        connector_request_bytes=plan.connector_request_bytes,
        authorization_profile=authorization,
        connector_receipt_verifier_id=DEFENDER_RECEIPT_VERIFIER_ID,
        pam_receipt_verifier_id=DEFENDER_PAM_VERIFIER_ID,
        _capture=capture,
        receipt_verifier=verify_source,
        pam_receipt_verifier=verify_pam,
    )


__all__ = [
    "DEFENDER_AUTHORIZATION_PROFILE_ID",
    "DEFENDER_PAM_VERIFIER_ID",
    "DEFENDER_RECEIPT_VERIFIER_ID",
    "ELASTIC_AUTHORIZATION_PROFILE_ID",
    "ELASTIC_PAM_VERIFIER_ID",
    "ELASTIC_RECEIPT_VERIFIER_ID",
    "DefenderManagedBroker",
    "ElasticManagedBroker",
    "ManagedSourceCapture",
    "ManagedSourceError",
    "PreparedManagedSource",
    "prepare_defender_managed_source",
    "prepare_elastic_managed_source",
]
