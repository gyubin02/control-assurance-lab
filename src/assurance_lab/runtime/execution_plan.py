"""Frozen connector plans derived from one exact runtime execution request.

The scheduler supplies immutable configuration, profile, and run-request
bytes.  Before a connector is allowed to make a network call, the executor
turns those inputs into one canonical plan containing the exact vendor request
and a 256-bit capture nonce.  A durable execution journal stores these bytes.
Retries therefore replay the same request identity instead of silently
creating a second logical observation.
"""

from __future__ import annotations

import re
import urllib.parse
from datetime import datetime, timedelta
from typing import Any, Final, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from assurance_lab._version import __version__
from assurance_lab.connectors.contract import ConnectorWindow
from assurance_lab.connectors.defender_xdr import DefenderXDRRequest
from assurance_lab.connectors.elastic_security import ElasticSecurityRequest
from assurance_lab.control_plane.models import (
    ControlConfiguration,
    DefenderSourceConfiguration,
    Digest,
    ElasticSourceConfiguration,
)
from assurance_lab.controls.alert_window import (
    ALERT_WINDOW_PROFILE_MEDIA_TYPE,
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
from assurance_lab.runtime.execution_recovery import (
    PAMRecoveryScope,
    publishing_recovery_pam_scope_digest,
)
from assurance_lab.runtime.models import (
    ControlRunExecutionRequest,
    PortableId,
    sha256_digest,
    utc_second,
)

CONTROL_RUN_EXECUTION_PLAN_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.execution-plan.v2+json"]
] = "application/vnd.control-assurance.execution-plan.v2+json"
CONTROL_RUN_EXECUTION_PLAN_SCHEMA_VERSION: Final[Literal["2.0.0"]] = "2.0.0"
EXECUTION_PLAN_PAM_REQUEST_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.execution-plan-pam-request.v1+json"]
] = "application/vnd.control-assurance.execution-plan-pam-request.v1+json"
ELASTIC_REQUEST_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.elastic-security-request.v1+json"]
] = "application/vnd.control-assurance.elastic-security-request.v1+json"
DEFENDER_REQUEST_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.defender-xdr-request.v1+json"]
] = "application/vnd.control-assurance.defender-xdr-request.v1+json"

_CAPTURE_NONCE_RE = re.compile(r"^[a-f0-9]{64}$")
_CAPTURE_ID_RE = re.compile(r"^run-[a-f0-9]{64}$")
_SOURCE_REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+/@:-]{0,255}$")
_SOURCE_CREDENTIAL_REF_SCHEMES = frozenset(
    {
        "aws-secretsmanager",
        "azure-keyvault",
        "gcp-secretmanager",
        "vault",
    }
)
_SIGNING_REF_SCHEMES = frozenset(
    {
        "aws-kms",
        "azure-keyvault",
        "gcp-kms",
        "vault-transit",
    }
)
_CUSTODY_REF_SCHEMES = frozenset({"s3-object-lock"})
_PLAN_LIMITS = JSONLimits(
    max_bytes=2 * 1024 * 1024,
    max_line_bytes=2 * 1024 * 1024,
    max_depth=24,
    max_collection_items=100_000,
    max_string_length=1024 * 1024,
)

ConnectorRequest = ElasticSecurityRequest | DefenderXDRRequest


def _logical_identity(domain: str, *, run_id: str, tenant_id: str) -> str:
    return sha256_digest(
        canonical_json_bytes(
            {
                "domain": domain,
                "run_id": run_id,
                "tenant_id": tenant_id,
            }
        )
    )


def _reference_connector_id(
    value: str,
    *,
    label: str,
    schemes: frozenset[str],
) -> str:
    if type(value) is not str or not value or len(value) > 2_048:
        raise ValueError(f"{label} is absent or too long")
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme not in schemes
        or not parsed.netloc
        or not parsed.path
        or parsed.path == "/"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "\\" in value
        or any(character.isspace() for character in value)
    ):
        raise ValueError(f"{label} is not an approved secret-free reference")
    return parsed.scheme


def _pam_authority_request_digest(
    *,
    authority_class: Literal["custody", "signing"],
    connector_id: str,
    connector_reference: str,
    tenant_id: str,
    run_id: str,
    control_id: str,
    configuration_digest: str,
    target_id: str,
) -> str:
    return sha256_digest(
        canonical_json_bytes(
            {
                "authority_class": authority_class,
                "configuration_digest": configuration_digest,
                "connector_id": connector_id,
                "connector_reference": connector_reference,
                "control_id": control_id,
                "media_type": EXECUTION_PLAN_PAM_REQUEST_MEDIA_TYPE,
                "run_id": run_id,
                "schema_version": "1.0.0",
                "target_id": target_id,
                "tenant_id": tenant_id,
            },
            limits=_PLAN_LIMITS,
        )
    )


def _derived_pam_scopes(
    *,
    tenant_id: str,
    run_id: str,
    control_id: str,
    configuration_digest: str,
    source_kind: Literal["elastic-security", "defender-xdr"],
    connector_request_digest: str,
    signing_key_ref: str,
    custody_ref: str,
    executor_receipt_id: str,
    custody_scope_id: str,
) -> tuple[PAMRecoveryScope, ...]:
    signing_connector_id = _reference_connector_id(
        signing_key_ref,
        label="execution plan signing key reference",
        schemes=_SIGNING_REF_SCHEMES,
    )
    custody_connector_id = _reference_connector_id(
        custody_ref,
        label="execution plan custody reference",
        schemes=_CUSTODY_REF_SCHEMES,
    )
    scopes = (
        PAMRecoveryScope(
            authority_class="custody",
            connector_id=custody_connector_id,
            connector_request_digest=_pam_authority_request_digest(
                authority_class="custody",
                connector_id=custody_connector_id,
                connector_reference=custody_ref,
                tenant_id=tenant_id,
                run_id=run_id,
                control_id=control_id,
                configuration_digest=configuration_digest,
                target_id=custody_scope_id,
            ),
        ),
        PAMRecoveryScope(
            authority_class="signing",
            connector_id=signing_connector_id,
            connector_request_digest=_pam_authority_request_digest(
                authority_class="signing",
                connector_id=signing_connector_id,
                connector_reference=signing_key_ref,
                tenant_id=tenant_id,
                run_id=run_id,
                control_id=control_id,
                configuration_digest=configuration_digest,
                target_id=executor_receipt_id,
            ),
        ),
        PAMRecoveryScope(
            authority_class="source",
            connector_id=source_kind,
            connector_request_digest=connector_request_digest,
        ),
    )
    return tuple(sorted(scopes, key=lambda scope: scope.sort_key))


class ControlRunExecutionPlanError(ValueError):
    """One execution plan failed its immutable pre-network boundary."""


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class ControlRunExecutionPlan(_FrozenModel):
    """Canonical external-call plan stored before connector side effects."""

    media_type: Literal["application/vnd.control-assurance.execution-plan.v2+json"] = (
        CONTROL_RUN_EXECUTION_PLAN_MEDIA_TYPE
    )
    schema_version: Literal["2.0.0"] = CONTROL_RUN_EXECUTION_PLAN_SCHEMA_VERSION
    run_id: Digest
    tenant_id: PortableId
    control_id: PortableId
    deployment_operation_id: Digest
    deployment_receipt_digest: Digest
    configuration_digest: Digest
    control_profile_id: PortableId
    control_profile_digest: Digest
    artifact_set_id: Digest
    custody_scope_id: Digest
    executor_receipt_id: Digest
    window_start: datetime
    window_end: datetime
    prepared_at: datetime
    custody_retain_until: datetime
    source_revision: str = Field(min_length=1, max_length=256)
    source_kind: Literal["elastic-security", "defender-xdr"]
    capture_id: str = Field(pattern=r"^run-[a-f0-9]{64}$")
    capture_nonce: str = Field(pattern=r"^[a-f0-9]{64}$")
    connector_request_media_type: Literal[
        "application/vnd.control-assurance.elastic-security-request.v1+json",
        "application/vnd.control-assurance.defender-xdr-request.v1+json",
    ]
    connector_request_digest: Digest
    connector_request: dict[str, Any]
    source_credential_ref: str = Field(min_length=1, max_length=2_048)
    signing_key_ref: str = Field(min_length=1, max_length=2_048)
    custody_ref: str = Field(min_length=1, max_length=2_048)
    pam_scopes: tuple[PAMRecoveryScope, ...] = Field(min_length=3, max_length=3)
    pam_scope_digest: Digest

    @field_validator(
        "window_start",
        "window_end",
        "prepared_at",
        "custody_retain_until",
    )
    @classmethod
    def validate_times(cls, value: datetime) -> datetime:
        return utc_second(value, label="execution plan time")

    @field_validator("source_revision")
    @classmethod
    def validate_source_revision(cls, value: str) -> str:
        if _SOURCE_REVISION_RE.fullmatch(value) is None:
            raise ValueError("execution plan source revision is invalid")
        return value

    @model_validator(mode="after")
    def validate_plan_shape(self) -> ControlRunExecutionPlan:
        if self.window_end <= self.window_start:
            raise ValueError("execution plan window must be non-empty")
        if self.prepared_at < self.window_end:
            raise ValueError("execution plan cannot predate its closed source window")
        if self.custody_retain_until <= self.prepared_at:
            raise ValueError("execution plan custody retention must be in the future")
        if self.capture_id != f"run-{self.run_id.removeprefix('sha256:')}":
            raise ValueError("capture id does not derive from the stable run id")
        expected_logical_identities = (
            _logical_identity(
                "control-assurance:managed-evidence-artifact-set:v2",
                run_id=self.run_id,
                tenant_id=self.tenant_id,
            ),
            _logical_identity(
                "control-assurance:stream-custody-scope:v1",
                run_id=self.run_id,
                tenant_id=self.tenant_id,
            ),
            _logical_identity(
                "control-assurance:executor-receipt:v1",
                run_id=self.run_id,
                tenant_id=self.tenant_id,
            ),
        )
        if (
            self.artifact_set_id,
            self.custody_scope_id,
            self.executor_receipt_id,
        ) != expected_logical_identities:
            raise ValueError("execution artifact identities do not derive from the stable run")
        expected_media_type = {
            "elastic-security": ELASTIC_REQUEST_MEDIA_TYPE,
            "defender-xdr": DEFENDER_REQUEST_MEDIA_TYPE,
        }[self.source_kind]
        if self.connector_request_media_type != expected_media_type:
            raise ValueError("connector request media type differs from source kind")
        try:
            request_bytes = canonical_json_bytes(
                self.connector_request,
                limits=_PLAN_LIMITS,
            )
        except StrictJSONError as exc:
            raise ValueError("connector request exceeds the execution plan profile") from exc
        if sha256_digest(request_bytes) != self.connector_request_digest:
            raise ValueError("connector request digest differs from its exact JSON")
        _reference_connector_id(
            self.source_credential_ref,
            label="execution plan source credential reference",
            schemes=_SOURCE_CREDENTIAL_REF_SCHEMES,
        )
        expected_scopes = _derived_pam_scopes(
            tenant_id=self.tenant_id,
            run_id=self.run_id,
            control_id=self.control_id,
            configuration_digest=self.configuration_digest,
            source_kind=self.source_kind,
            connector_request_digest=self.connector_request_digest,
            signing_key_ref=self.signing_key_ref,
            custody_ref=self.custody_ref,
            executor_receipt_id=self.executor_receipt_id,
            custody_scope_id=self.custody_scope_id,
        )
        if (
            self.pam_scopes != expected_scopes
            or self.pam_scope_digest != publishing_recovery_pam_scope_digest(expected_scopes)
        ):
            raise ValueError("execution plan PAM recovery scope is not deterministically derived")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            self.model_dump(mode="json"),
            limits=_PLAN_LIMITS,
        )

    @property
    def digest(self) -> str:
        return sha256_digest(self.canonical_bytes())

    @property
    def connector_request_bytes(self) -> bytes:
        return canonical_json_bytes(self.connector_request, limits=_PLAN_LIMITS)


def _runtime_inputs(
    request: ControlRunExecutionRequest,
) -> tuple[ControlConfiguration, AlertWindowProfile]:
    if type(request) is not ControlRunExecutionRequest:
        raise TypeError("request must be an exact ControlRunExecutionRequest")
    try:
        configuration = ControlConfiguration.model_validate_json(request.configuration_bytes)
        profile = parse_alert_window_profile(
            request.control_profile_bytes,
            expected_profile_id=request.control_profile_id,
            expected_profile_digest=request.control_profile_digest,
        )
    except (TypeError, ValueError) as exc:
        raise ControlRunExecutionPlanError(
            "runtime configuration or control profile is invalid"
        ) from exc
    if request.control_profile_media_type != ALERT_WINDOW_PROFILE_MEDIA_TYPE:
        raise ControlRunExecutionPlanError(
            "runtime selected an unsupported control profile media type"
        )
    if configuration.source.kind != profile.source_kind:
        raise ControlRunExecutionPlanError(
            "control profile source differs from deployed source configuration"
        )
    return configuration, profile


def _connector_request(
    *,
    request: ControlRunExecutionRequest,
    configuration: ControlConfiguration,
    profile: AlertWindowProfile,
    capture_nonce: str,
) -> tuple[ConnectorRequest, str]:
    window = ConnectorWindow(start=request.window_start, end=request.window_end)
    capture_id = f"run-{request.run_id.removeprefix('sha256:')}"
    if isinstance(configuration.source, ElasticSourceConfiguration) and isinstance(
        profile.source, ElasticAlertSource
    ):
        return (
            ElasticSecurityRequest(
                capture_id=capture_id,
                window=window,
                capture_nonce=capture_nonce,
                index_alias=configuration.source.index_alias,
                fields=profile.source.fields,
                rule_uuids=profile.source.rule_uuids,
                workflow_statuses=profile.source.workflow_statuses,
                alert_statuses=profile.source.alert_statuses,
            ),
            ELASTIC_REQUEST_MEDIA_TYPE,
        )
    if isinstance(configuration.source, DefenderSourceConfiguration) and isinstance(
        profile.source, DefenderAlertSource
    ):
        return (
            DefenderXDRRequest(
                capture_id=capture_id,
                window=window,
                capture_nonce=capture_nonce,
            ),
            DEFENDER_REQUEST_MEDIA_TYPE,
        )
    raise ControlRunExecutionPlanError(
        "control profile and source configuration select different connectors"
    )


def _source_credential_ref(configuration: ControlConfiguration) -> str:
    if isinstance(configuration.source, ElasticSourceConfiguration):
        return configuration.source.parent_credential_ref
    return configuration.source.client_credential_ref


def execution_plan_pam_recovery_scopes(
    plan: ControlRunExecutionPlan,
) -> tuple[PAMRecoveryScope, ...]:
    """Return the independently revalidated exact PAM tuples frozen in a plan."""

    if type(plan) is not ControlRunExecutionPlan:
        raise TypeError("plan must be an exact ControlRunExecutionPlan")
    try:
        validated = ControlRunExecutionPlan.model_validate(plan.model_dump(mode="python"))
    except ValueError as exc:
        raise ControlRunExecutionPlanError("execution plan PAM recovery scope is invalid") from exc
    return validated.pam_scopes


def create_control_run_execution_plan(
    request: ControlRunExecutionRequest,
    *,
    capture_nonce: str,
    prepared_at: datetime,
    source_revision: str = __version__,
) -> ControlRunExecutionPlan:
    """Derive and freeze the only connector request allowed for one run."""

    if type(capture_nonce) is not str or _CAPTURE_NONCE_RE.fullmatch(capture_nonce) is None:
        raise ControlRunExecutionPlanError(
            "capture nonce must be exactly 256 bits of lowercase hex"
        )
    if type(source_revision) is not str or _SOURCE_REVISION_RE.fullmatch(source_revision) is None:
        raise ControlRunExecutionPlanError(
            "source revision must be one bounded immutable build identity"
        )
    try:
        prepared = utc_second(prepared_at, label="execution plan preparation time")
    except ValueError as exc:
        raise ControlRunExecutionPlanError("execution plan preparation time is invalid") from exc
    configuration, profile = _runtime_inputs(request)
    if prepared < request.window_end:
        raise ControlRunExecutionPlanError(
            "execution plan cannot be prepared before its source window closes"
        )
    retain_until = prepared + timedelta(days=configuration.evidence.retention_days)
    connector_request, request_media_type = _connector_request(
        request=request,
        configuration=configuration,
        profile=profile,
        capture_nonce=capture_nonce,
    )
    request_json = connector_request.as_json()
    try:
        request_bytes = canonical_json_bytes(request_json, limits=_PLAN_LIMITS)
        artifact_set_id = _logical_identity(
            "control-assurance:managed-evidence-artifact-set:v2",
            run_id=request.run_id,
            tenant_id=request.tenant_id,
        )
        custody_scope_id = _logical_identity(
            "control-assurance:stream-custody-scope:v1",
            run_id=request.run_id,
            tenant_id=request.tenant_id,
        )
        executor_receipt_id = _logical_identity(
            "control-assurance:executor-receipt:v1",
            run_id=request.run_id,
            tenant_id=request.tenant_id,
        )
        connector_request_digest = sha256_digest(request_bytes)
        pam_scopes = _derived_pam_scopes(
            tenant_id=request.tenant_id,
            run_id=request.run_id,
            control_id=request.control_id,
            configuration_digest=request.configuration_digest,
            source_kind=configuration.source.kind,
            connector_request_digest=connector_request_digest,
            signing_key_ref=configuration.evidence.signing_key_ref,
            custody_ref=configuration.evidence.custody_ref,
            executor_receipt_id=executor_receipt_id,
            custody_scope_id=custody_scope_id,
        )
        return ControlRunExecutionPlan(
            run_id=request.run_id,
            tenant_id=request.tenant_id,
            control_id=request.control_id,
            deployment_operation_id=request.deployment_operation_id,
            deployment_receipt_digest=request.deployment_receipt_digest,
            configuration_digest=request.configuration_digest,
            control_profile_id=request.control_profile_id,
            control_profile_digest=request.control_profile_digest,
            artifact_set_id=artifact_set_id,
            custody_scope_id=custody_scope_id,
            executor_receipt_id=executor_receipt_id,
            window_start=request.window_start,
            window_end=request.window_end,
            prepared_at=prepared,
            custody_retain_until=retain_until,
            source_revision=source_revision,
            source_kind=configuration.source.kind,
            capture_id=connector_request.capture_id,
            capture_nonce=capture_nonce,
            connector_request_media_type=cast(
                Literal[
                    "application/vnd.control-assurance.elastic-security-request.v1+json",
                    "application/vnd.control-assurance.defender-xdr-request.v1+json",
                ],
                request_media_type,
            ),
            connector_request_digest=connector_request_digest,
            connector_request=request_json,
            source_credential_ref=_source_credential_ref(configuration),
            signing_key_ref=configuration.evidence.signing_key_ref,
            custody_ref=configuration.evidence.custody_ref,
            pam_scopes=pam_scopes,
            pam_scope_digest=publishing_recovery_pam_scope_digest(pam_scopes),
        )
    except (StrictJSONError, TypeError, ValueError) as exc:
        raise ControlRunExecutionPlanError(
            "connector request could not enter the frozen execution plan"
        ) from exc


def verify_control_run_execution_plan(
    value: bytes,
    *,
    expected_request: ControlRunExecutionRequest,
) -> tuple[ControlRunExecutionPlan, ConnectorRequest]:
    """Reopen a journaled plan and independently rebuild its vendor request."""

    if type(value) is not bytes or not value:
        raise ControlRunExecutionPlanError("execution plan bytes are absent")
    if type(expected_request) is not ControlRunExecutionRequest:
        raise TypeError("expected request must be an exact ControlRunExecutionRequest")
    try:
        parsed = strict_json_loads(value, limits=_PLAN_LIMITS)
        plan = ControlRunExecutionPlan.model_validate_json(value)
        canonical = plan.canonical_bytes()
    except (StrictJSONError, TypeError, ValueError) as exc:
        raise ControlRunExecutionPlanError("execution plan is invalid") from exc
    if not isinstance(parsed, dict) or canonical != value:
        raise ControlRunExecutionPlanError("execution plan is not canonical JSON")

    expected_anchors = (
        expected_request.run_id,
        expected_request.tenant_id,
        expected_request.control_id,
        expected_request.deployment_operation_id,
        expected_request.deployment_receipt_digest,
        expected_request.configuration_digest,
        expected_request.control_profile_id,
        expected_request.control_profile_digest,
        expected_request.window_start,
        expected_request.window_end,
    )
    observed_anchors = (
        plan.run_id,
        plan.tenant_id,
        plan.control_id,
        plan.deployment_operation_id,
        plan.deployment_receipt_digest,
        plan.configuration_digest,
        plan.control_profile_id,
        plan.control_profile_digest,
        plan.window_start,
        plan.window_end,
    )
    if observed_anchors != expected_anchors:
        raise ControlRunExecutionPlanError(
            "execution plan differs from the exact scheduler request"
        )

    configuration, profile = _runtime_inputs(expected_request)
    if plan.custody_retain_until != plan.prepared_at + timedelta(
        days=configuration.evidence.retention_days
    ):
        raise ControlRunExecutionPlanError(
            "execution plan retention differs from deployed evidence policy"
        )
    rebuilt, media_type = _connector_request(
        request=expected_request,
        configuration=configuration,
        profile=profile,
        capture_nonce=plan.capture_nonce,
    )
    rebuilt_bytes = canonical_json_bytes(rebuilt.as_json(), limits=_PLAN_LIMITS)
    expected_pam_scopes = _derived_pam_scopes(
        tenant_id=expected_request.tenant_id,
        run_id=expected_request.run_id,
        control_id=expected_request.control_id,
        configuration_digest=expected_request.configuration_digest,
        source_kind=configuration.source.kind,
        connector_request_digest=sha256_digest(rebuilt_bytes),
        signing_key_ref=configuration.evidence.signing_key_ref,
        custody_ref=configuration.evidence.custody_ref,
        executor_receipt_id=plan.executor_receipt_id,
        custody_scope_id=plan.custody_scope_id,
    )
    if (
        plan.source_kind != configuration.source.kind
        or plan.connector_request_media_type != media_type
        or plan.connector_request_bytes != rebuilt_bytes
        or plan.connector_request_digest != sha256_digest(rebuilt_bytes)
        or plan.capture_id != rebuilt.capture_id
        or plan.capture_nonce != rebuilt.capture_nonce
        or plan.source_credential_ref != _source_credential_ref(configuration)
        or plan.signing_key_ref != configuration.evidence.signing_key_ref
        or plan.custody_ref != configuration.evidence.custody_ref
        or plan.pam_scopes != expected_pam_scopes
        or plan.pam_scope_digest != publishing_recovery_pam_scope_digest(expected_pam_scopes)
    ):
        raise ControlRunExecutionPlanError(
            "journaled connector request does not rederive from runtime inputs"
        )
    return plan, rebuilt


__all__ = [
    "CONTROL_RUN_EXECUTION_PLAN_MEDIA_TYPE",
    "CONTROL_RUN_EXECUTION_PLAN_SCHEMA_VERSION",
    "DEFENDER_REQUEST_MEDIA_TYPE",
    "ELASTIC_REQUEST_MEDIA_TYPE",
    "EXECUTION_PLAN_PAM_REQUEST_MEDIA_TYPE",
    "ConnectorRequest",
    "ControlRunExecutionPlan",
    "ControlRunExecutionPlanError",
    "create_control_run_execution_plan",
    "execution_plan_pam_recovery_scopes",
    "verify_control_run_execution_plan",
]
