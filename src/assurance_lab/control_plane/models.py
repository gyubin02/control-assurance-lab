"""Strict, secret-free models for the operational control plane.

Configurations are immutable values.  A change creates a new generation whose
identity is the SHA-256 digest of its canonical JSON representation plus its
lineage.  Secrets are never configuration fields: only references to an
approved secret manager are accepted.
"""

from __future__ import annotations

import hashlib
import re
import urllib.parse
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Final, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from assurance_lab.evidence.canonical import canonical_json_bytes

_PORTABLE_ID_RE: Final = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_GROUP_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}$")
_DIGEST_RE: Final = re.compile(r"^sha256:[a-f0-9]{64}$")
_ALERT_ALIAS_RE: Final = re.compile(
    r"^[.]alerts-security[.]alerts-[a-z0-9][a-z0-9_-]{0,63}$"
)
_UUID_RE: Final = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_SECRET_REF_SCHEMES = frozenset(
    {
        "aws-secretsmanager",
        "azure-keyvault",
        "gcp-secretmanager",
        "vault",
    }
)
_SIGNER_REF_SCHEMES = frozenset(
    {
        "aws-kms",
        "azure-keyvault",
        "gcp-kms",
        "vault-transit",
    }
)
_CUSTODY_REF_SCHEMES = frozenset({"s3-object-lock"})

PortableId = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9._-]{0,127}$",
    ),
]
Digest = Annotated[
    str,
    StringConstraints(
        min_length=71,
        max_length=71,
        pattern=r"^sha256:[a-f0-9]{64}$",
    ),
]
RevisionState = Literal["draft", "submitted", "approved", "rejected", "retired"]
Role = Literal["viewer", "editor", "approver", "deployer", "auditor", "administrator"]
Environment = Literal["development", "test", "staging", "production"]
DeploymentOperationState = Literal["pending", "leased", "applied", "failed"]
DeploymentOperationKind = Literal["apply", "rollback"]
AuditAction = Literal[
    "revision-created",
    "revision-submitted",
    "revision-approved",
    "revision-rejected",
    "revision-activated",
    "deployment-retry-requested",
    "deployment-rollback-requested",
    "deployment-leased",
    "deployment-applied",
    "deployment-failed",
]


def _utc_second(value: datetime, *, label: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
    converted = value.astimezone(UTC)
    if converted.microsecond != 0:
        raise ValueError(f"{label} must use whole UTC seconds")
    return converted


def _origin(value: str, *, label: str) -> str:
    if type(value) is not str or not value or len(value) > 2_048:
        raise ValueError(f"{label} is absent or too long")
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{label} must be a credential-free HTTPS origin")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{label} has an invalid port") from exc
    host = parsed.hostname.lower()
    rendered_host = f"[{host}]" if ":" in host else host
    authority = rendered_host if port in {None, 443} else f"{rendered_host}:{port}"
    return f"https://{authority}"


def _reference(
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
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.path
        or parsed.path == "/"
        or parsed.query
        or parsed.fragment
        or "\\" in value
        or any(character.isspace() for character in value)
    ):
        raise ValueError(f"{label} is not an approved secret-free reference")
    return value


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class Actor(_FrozenModel):
    """One authenticated institutional identity and its effective roles."""

    tenant_id: PortableId
    subject: Annotated[str, StringConstraints(min_length=1, max_length=255)]
    display_name: Annotated[str, StringConstraints(min_length=1, max_length=255)]
    roles: frozenset[Role]
    groups: tuple[str, ...] = ()
    authenticated_at: datetime
    session_id_digest: Digest
    mfa: bool

    @field_validator("authenticated_at")
    @classmethod
    def validate_authenticated_at(cls, value: datetime) -> datetime:
        return _utc_second(value, label="authentication time")

    @field_validator("roles")
    @classmethod
    def validate_roles(cls, value: frozenset[Role]) -> frozenset[Role]:
        if not value or len(value) > 6:
            raise ValueError("actor must have one or more bounded roles")
        return value

    @field_validator("groups")
    @classmethod
    def validate_groups(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > 128 or any(_GROUP_RE.fullmatch(group) is None for group in value):
            raise ValueError("actor groups are invalid or excessive")
        if len(set(value)) != len(value):
            raise ValueError("actor groups contain duplicates")
        return tuple(sorted(value))


class ElasticSourceConfiguration(_FrozenModel):
    kind: Literal["elastic-security"] = "elastic-security"
    endpoint_origin: str
    index_alias: str = ".alerts-security.alerts-default"
    parent_credential_ref: str
    pam_mode: Literal["elastic-jit-api-key"] = "elastic-jit-api-key"
    lease_ttl_seconds: int = Field(default=900, ge=600, le=3_600)
    ca_bundle_ref: str | None = None

    @field_validator("endpoint_origin")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        return _origin(value, label="Elastic endpoint")

    @field_validator("index_alias")
    @classmethod
    def validate_alias(cls, value: str) -> str:
        if _ALERT_ALIAS_RE.fullmatch(value) is None:
            raise ValueError("Elastic source must name one exact Security alert alias")
        return value

    @field_validator("parent_credential_ref")
    @classmethod
    def validate_parent_ref(cls, value: str) -> str:
        return _reference(
            value,
            label="Elastic parent credential reference",
            schemes=_SECRET_REF_SCHEMES,
        )

    @field_validator("ca_bundle_ref")
    @classmethod
    def validate_ca_ref(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _reference(
            value,
            label="Elastic CA bundle reference",
            schemes=_SECRET_REF_SCHEMES,
        )


class DefenderSourceConfiguration(_FrozenModel):
    kind: Literal["defender-xdr"] = "defender-xdr"
    cloud: Literal["global", "us-government-l4", "us-government-l5"] = "global"
    tenant_id: str
    client_id: str
    client_credential_ref: str
    permission: Literal["ThreatHunting.Read.All"] = "ThreatHunting.Read.All"
    table: Literal["AlertInfo"] = "AlertInfo"

    @field_validator("tenant_id", "client_id")
    @classmethod
    def validate_uuid(cls, value: str) -> str:
        lowered = value.lower()
        if _UUID_RE.fullmatch(lowered) is None:
            raise ValueError("Defender tenant and client ids must be canonical UUIDs")
        return lowered

    @field_validator("client_credential_ref")
    @classmethod
    def validate_client_ref(cls, value: str) -> str:
        return _reference(
            value,
            label="Defender client credential reference",
            schemes=_SECRET_REF_SCHEMES,
        )


SourceConfiguration = Annotated[
    ElasticSourceConfiguration | DefenderSourceConfiguration,
    Field(discriminator="kind"),
]


class ScheduleConfiguration(_FrozenModel):
    interval_seconds: int = Field(ge=60, le=86_400)
    collection_lag_seconds: int = Field(default=120, ge=0, le=3_600)
    window_seconds: int = Field(ge=60, le=86_400)
    timezone: Literal["UTC"] = "UTC"

    @model_validator(mode="after")
    def validate_window(self) -> ScheduleConfiguration:
        if self.window_seconds > self.interval_seconds:
            raise ValueError("collection window cannot exceed the schedule interval")
        return self


class EvidenceConfiguration(_FrozenModel):
    custody_ref: str
    signing_key_ref: str
    retention_days: int = Field(ge=30, le=3_650)
    legal_hold: bool = False
    snapshot_format: Literal["cab-stream-v2"] = "cab-stream-v2"

    @field_validator("custody_ref")
    @classmethod
    def validate_custody_ref(cls, value: str) -> str:
        return _reference(
            value,
            label="custody reference",
            schemes=_CUSTODY_REF_SCHEMES,
        )

    @field_validator("signing_key_ref")
    @classmethod
    def validate_signing_ref(cls, value: str) -> str:
        return _reference(
            value,
            label="signing key reference",
            schemes=_SIGNER_REF_SCHEMES,
        )


class ControlConfiguration(_FrozenModel):
    """One deployable, read-only assurance control."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    tenant_id: PortableId
    control_id: PortableId
    display_name: Annotated[str, StringConstraints(min_length=1, max_length=160)]
    description: Annotated[str, StringConstraints(min_length=1, max_length=2_000)]
    environment: Environment
    owner_group: Annotated[
        str,
        StringConstraints(min_length=1, max_length=255),
    ]
    control_profile_id: PortableId
    control_profile_digest: Digest
    source: SourceConfiguration
    schedule: ScheduleConfiguration
    evidence: EvidenceConfiguration
    enabled: bool = True

    @field_validator("owner_group")
    @classmethod
    def validate_owner_group(cls, value: str) -> str:
        if _GROUP_RE.fullmatch(value) is None:
            raise ValueError("owner group is invalid")
        return value

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"))

    @property
    def digest(self) -> str:
        return f"sha256:{hashlib.sha256(self.canonical_bytes()).hexdigest()}"


class ConfigurationRevision(_FrozenModel):
    revision_id: Digest
    tenant_id: PortableId
    control_id: PortableId
    generation: int = Field(ge=1, le=2**63 - 1)
    parent_revision_id: Digest | None
    configuration_digest: Digest
    configuration_bytes: bytes = Field(min_length=2, max_length=1024 * 1024)
    state: RevisionState
    state_version: int = Field(ge=0, le=2**63 - 1)
    created_by: Annotated[str, StringConstraints(min_length=1, max_length=255)]
    created_at: datetime
    submitted_at: datetime | None = None
    decided_at: datetime | None = None

    @field_validator("created_at", "submitted_at", "decided_at")
    @classmethod
    def validate_times(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return _utc_second(value, label="revision time")

    @model_validator(mode="after")
    def validate_revision(self) -> ConfigurationRevision:
        if _sha256_bytes(self.configuration_bytes) != self.configuration_digest:
            raise ValueError("revision configuration digest does not match its bytes")
        try:
            configuration = ControlConfiguration.model_validate_json(self.configuration_bytes)
        except ValueError as exc:
            raise ValueError("revision does not contain a valid configuration") from exc
        if (
            configuration.tenant_id != self.tenant_id
            or configuration.control_id != self.control_id
        ):
            raise ValueError("revision identity differs from its configuration")
        expected = revision_identity(
            tenant_id=self.tenant_id,
            control_id=self.control_id,
            generation=self.generation,
            parent_revision_id=self.parent_revision_id,
            configuration_digest=self.configuration_digest,
        )
        if expected != self.revision_id:
            raise ValueError("revision id does not match its immutable lineage")
        if self.generation == 1 and self.parent_revision_id is not None:
            raise ValueError("first generation cannot have a parent")
        if self.generation > 1 and self.parent_revision_id is None:
            raise ValueError("later generation must name its parent")
        if self.state == "draft" and (self.submitted_at is not None or self.decided_at is not None):
            raise ValueError("draft revision cannot have lifecycle decisions")
        if self.state == "submitted" and (
            self.submitted_at is None or self.decided_at is not None
        ):
            raise ValueError("submitted revision has an invalid lifecycle")
        if self.state in {"approved", "rejected"} and (
            self.submitted_at is None or self.decided_at is None
        ):
            raise ValueError("decided revision lacks lifecycle timestamps")
        return self

    @property
    def configuration(self) -> ControlConfiguration:
        return ControlConfiguration.model_validate_json(self.configuration_bytes)


class ApprovalDecision(_FrozenModel):
    decision_id: Digest
    revision_id: Digest
    tenant_id: PortableId
    decision: Literal["approved", "rejected"]
    decided_by: Annotated[str, StringConstraints(min_length=1, max_length=255)]
    decided_at: datetime
    comment: Annotated[str, StringConstraints(min_length=1, max_length=2_000)]
    actor_session_digest: Digest

    @field_validator("decided_at")
    @classmethod
    def validate_decided_at(cls, value: datetime) -> datetime:
        return _utc_second(value, label="decision time")

    @model_validator(mode="after")
    def validate_decision_id(self) -> ApprovalDecision:
        body = {
            "actor_session_digest": self.actor_session_digest,
            "comment": self.comment,
            "decided_at": self.decided_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "decided_by": self.decided_by,
            "decision": self.decision,
            "revision_id": self.revision_id,
            "tenant_id": self.tenant_id,
        }
        if _sha256_bytes(canonical_json_bytes(body)) != self.decision_id:
            raise ValueError("decision id does not match its canonical content")
        return self


class ActiveDeployment(_FrozenModel):
    """The control-plane desired-selection pointer.

    This record proves that an approved revision was selected by an authorized
    deployer.  It does *not* claim that a runtime accepted the configuration;
    that boundary is represented by an applied :class:`DeploymentOperation`.
    """

    tenant_id: PortableId
    control_id: PortableId
    revision_id: Digest
    configuration_digest: Digest
    activated_by: Annotated[str, StringConstraints(min_length=1, max_length=255)]
    activated_at: datetime
    deployment_version: int = Field(ge=1, le=2**63 - 1)

    @field_validator("activated_at")
    @classmethod
    def validate_activated_at(cls, value: datetime) -> datetime:
        return _utc_second(value, label="activation time")


class DeploymentWorkerIdentity(_FrozenModel):
    """A tenant-scoped workload identity after mTLS/workload-auth verification."""

    tenant_id: PortableId
    worker_id: PortableId
    credential_digest: Digest

    @property
    def subject(self) -> str:
        return f"deployment-worker:{self.worker_id}"

    @property
    def session_id_digest(self) -> str:
        return self.credential_digest


class DeploymentOperation(_FrozenModel):
    """One durable request to make an exact immutable revision effective.

    Request identity and lineage are immutable.  Lease fields are fencing
    metadata, while ``applied_*`` fields are the acknowledgement boundary.
    A desired-selection pointer alone never satisfies this model's applied
    state.
    """

    operation_id: Digest
    tenant_id: PortableId
    control_id: PortableId
    operation_sequence: int = Field(ge=1, le=2**63 - 1)
    kind: DeploymentOperationKind
    revision_id: Digest
    configuration_digest: Digest
    predecessor_operation_id: Digest | None
    retry_of_operation_id: Digest | None
    requested_by: Annotated[str, StringConstraints(min_length=1, max_length=255)]
    requested_at: datetime
    requester_session_digest: Digest
    state: DeploymentOperationState
    state_version: int = Field(ge=0, le=2**63 - 1)
    attempt_count: int = Field(ge=0, le=2**31 - 1)
    lease_fence: int = Field(ge=0, le=2**63 - 1)
    lease_owner: PortableId | None = None
    lease_token_digest: Digest | None = None
    leased_at: datetime | None = None
    lease_expires_at: datetime | None = None
    retry_at: datetime | None = None
    applied_at: datetime | None = None
    applied_configuration_digest: Digest | None = None
    target_receipt_digest: Digest | None = None
    failed_at: datetime | None = None
    failure_digest: Digest | None = None

    @field_validator(
        "requested_at",
        "leased_at",
        "lease_expires_at",
        "retry_at",
        "applied_at",
        "failed_at",
    )
    @classmethod
    def validate_operation_times(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return _utc_second(value, label="deployment operation time")

    @model_validator(mode="after")
    def validate_operation(self) -> DeploymentOperation:
        expected = deployment_operation_identity(
            tenant_id=self.tenant_id,
            control_id=self.control_id,
            operation_sequence=self.operation_sequence,
            kind=self.kind,
            revision_id=self.revision_id,
            configuration_digest=self.configuration_digest,
            predecessor_operation_id=self.predecessor_operation_id,
            retry_of_operation_id=self.retry_of_operation_id,
            requested_by=self.requested_by,
            requested_at=self.requested_at,
            requester_session_digest=self.requester_session_digest,
        )
        if expected != self.operation_id:
            raise ValueError("deployment operation id does not match its request")
        if self.kind == "rollback" and self.retry_of_operation_id is not None:
            raise ValueError("rollback operation cannot be a retry")
        lease_values = (
            self.lease_owner,
            self.lease_token_digest,
            self.leased_at,
            self.lease_expires_at,
        )
        applied_values = (
            self.applied_at,
            self.applied_configuration_digest,
            self.target_receipt_digest,
        )
        failed_values = (self.failed_at, self.failure_digest)
        if self.state == "pending":
            if (
                self.state_version != 0
                or self.attempt_count != 0
                or self.lease_fence != 0
                or any(value is not None for value in lease_values)
                or self.retry_at is not None
                or any(value is not None for value in applied_values)
                or any(value is not None for value in failed_values)
            ):
                raise ValueError("pending deployment operation has mutable outcome state")
        elif self.state == "leased":
            if (
                self.attempt_count < 1
                or self.lease_fence != self.attempt_count
                or any(value is None for value in lease_values)
                or self.retry_at is not None
                or any(value is not None for value in applied_values)
                or any(value is not None for value in failed_values)
            ):
                raise ValueError("leased deployment operation has an invalid lease")
            assert self.leased_at is not None
            assert self.lease_expires_at is not None
            if (
                self.leased_at < self.requested_at
                or self.lease_expires_at <= self.leased_at
            ):
                raise ValueError("deployment lease does not advance time")
        elif self.state == "applied":
            if (
                self.attempt_count < 1
                or self.lease_fence != self.attempt_count
                or any(value is not None for value in lease_values)
                or self.retry_at is not None
                or any(value is None for value in applied_values)
                or any(value is not None for value in failed_values)
                or self.applied_configuration_digest != self.configuration_digest
            ):
                raise ValueError("applied deployment operation lacks an exact acknowledgement")
            assert self.applied_at is not None
            if self.applied_at < self.requested_at:
                raise ValueError("deployment acknowledgement precedes its request")
        elif self.state == "failed":
            if (
                self.attempt_count < 1
                or self.lease_fence != self.attempt_count
                or any(value is not None for value in lease_values)
                or any(value is not None for value in applied_values)
                or any(value is None for value in failed_values)
            ):
                raise ValueError("failed deployment operation has an invalid outcome")
            assert self.failed_at is not None
            if self.failed_at < self.requested_at:
                raise ValueError("deployment failure precedes its request")
            if self.retry_at is not None and (
                self.retry_at <= self.failed_at
                or self.retry_at > self.failed_at + timedelta(hours=24)
            ):
                raise ValueError("deployment retry is outside the supported window")
        return self

    @property
    def retryable(self) -> bool:
        return self.state == "failed" and self.retry_at is not None


class ControlSummary(_FrozenModel):
    """Latest immutable generation and its verified optional active pointer."""

    latest_revision: ConfigurationRevision
    active_deployment: ActiveDeployment | None

    @model_validator(mode="after")
    def validate_summary(self) -> ControlSummary:
        if self.active_deployment is not None and (
            self.active_deployment.tenant_id != self.latest_revision.tenant_id
            or self.active_deployment.control_id != self.latest_revision.control_id
        ):
            raise ValueError("control summary crosses a tenant or control boundary")
        return self


class AuditEvent(_FrozenModel):
    tenant_id: PortableId
    sequence: int = Field(ge=1, le=2**63 - 1)
    previous_event_digest: Digest
    event_digest: Digest
    action: AuditAction
    object_id: Digest
    actor_subject: Annotated[str, StringConstraints(min_length=1, max_length=255)]
    actor_session_digest: Digest
    occurred_at: datetime
    details_digest: Digest
    details_bytes: bytes = Field(min_length=2, max_length=64 * 1024)
    event_bytes: bytes = Field(min_length=2, max_length=64 * 1024)

    @field_validator("occurred_at")
    @classmethod
    def validate_occurred_at(cls, value: datetime) -> datetime:
        return _utc_second(value, label="audit event time")

    @model_validator(mode="after")
    def validate_event(self) -> AuditEvent:
        if _sha256_bytes(self.details_bytes) != self.details_digest:
            raise ValueError("audit details digest does not match its bytes")
        if _sha256_bytes(self.event_bytes) != self.event_digest:
            raise ValueError("audit event digest does not match its bytes")
        expected = audit_event_bytes(
            tenant_id=self.tenant_id,
            sequence=self.sequence,
            previous_event_digest=self.previous_event_digest,
            action=self.action,
            object_id=self.object_id,
            actor_subject=self.actor_subject,
            actor_session_digest=self.actor_session_digest,
            occurred_at=self.occurred_at,
            details_digest=self.details_digest,
        )
        if expected != self.event_bytes:
            raise ValueError("audit event bytes do not match their declared fields")
        return self


def _sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def revision_identity(
    *,
    tenant_id: str,
    control_id: str,
    generation: int,
    parent_revision_id: str | None,
    configuration_digest: str,
) -> str:
    """Compute the immutable identity of one configuration generation."""

    if _PORTABLE_ID_RE.fullmatch(tenant_id) is None:
        raise ValueError("tenant id is invalid")
    if _PORTABLE_ID_RE.fullmatch(control_id) is None:
        raise ValueError("control id is invalid")
    if type(generation) is not int or generation < 1:
        raise ValueError("generation is invalid")
    if parent_revision_id is not None and _DIGEST_RE.fullmatch(parent_revision_id) is None:
        raise ValueError("parent revision id is invalid")
    if _DIGEST_RE.fullmatch(configuration_digest) is None:
        raise ValueError("configuration digest is invalid")
    return _sha256_bytes(
        canonical_json_bytes(
            {
                "configuration_digest": configuration_digest,
                "control_id": control_id,
                "generation": generation,
                "parent_revision_id": parent_revision_id,
                "tenant_id": tenant_id,
            }
        )
    )


def decision_identity(
    *,
    revision_id: str,
    tenant_id: str,
    decision: Literal["approved", "rejected"],
    decided_by: str,
    decided_at: datetime,
    comment: str,
    actor_session_digest: str,
) -> str:
    """Compute the content identity used by :class:`ApprovalDecision`."""

    timestamp = _utc_second(decided_at, label="decision time")
    body: dict[str, Any] = {
        "actor_session_digest": actor_session_digest,
        "comment": comment,
        "decided_at": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "decided_by": decided_by,
        "decision": decision,
        "revision_id": revision_id,
        "tenant_id": tenant_id,
    }
    return _sha256_bytes(canonical_json_bytes(body))


def deployment_operation_identity(
    *,
    tenant_id: str,
    control_id: str,
    operation_sequence: int,
    kind: DeploymentOperationKind,
    revision_id: str,
    configuration_digest: str,
    predecessor_operation_id: str | None,
    retry_of_operation_id: str | None,
    requested_by: str,
    requested_at: datetime,
    requester_session_digest: str,
) -> str:
    """Compute one immutable, tenant-scoped deployment request identity."""

    timestamp = _utc_second(requested_at, label="deployment request time")
    if _PORTABLE_ID_RE.fullmatch(tenant_id) is None:
        raise ValueError("deployment tenant id is invalid")
    if _PORTABLE_ID_RE.fullmatch(control_id) is None:
        raise ValueError("deployment control id is invalid")
    if type(operation_sequence) is not int or operation_sequence < 1:
        raise ValueError("deployment operation sequence is invalid")
    if kind not in {"apply", "rollback"}:
        raise ValueError("deployment operation kind is invalid")
    for label, value in (
        ("revision id", revision_id),
        ("configuration digest", configuration_digest),
        ("requester session digest", requester_session_digest),
    ):
        if _DIGEST_RE.fullmatch(value) is None:
            raise ValueError(f"deployment {label} is invalid")
    if (
        predecessor_operation_id is not None
        and _DIGEST_RE.fullmatch(predecessor_operation_id) is None
    ):
        raise ValueError("deployment predecessor operation id is invalid")
    if (
        retry_of_operation_id is not None
        and _DIGEST_RE.fullmatch(retry_of_operation_id) is None
    ):
        raise ValueError("deployment retry operation id is invalid")
    if kind == "rollback" and retry_of_operation_id is not None:
        raise ValueError("rollback operation cannot be a retry")
    if not requested_by or len(requested_by) > 255:
        raise ValueError("deployment requester is invalid")
    body: dict[str, Any] = {
        "configuration_digest": configuration_digest,
        "control_id": control_id,
        "kind": kind,
        "operation_sequence": operation_sequence,
        "predecessor_operation_id": predecessor_operation_id,
        "requested_at": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "requested_by": requested_by,
        "requester_session_digest": requester_session_digest,
        "revision_id": revision_id,
        "tenant_id": tenant_id,
    }
    # Migration compatibility: operations created before retry lineage existed
    # keep their content identity. A retry includes the non-null lineage field,
    # so changing its parent necessarily changes its operation id.
    if retry_of_operation_id is not None:
        body["retry_of_operation_id"] = retry_of_operation_id
    return _sha256_bytes(canonical_json_bytes(body))


def audit_event_bytes(
    *,
    tenant_id: str,
    sequence: int,
    previous_event_digest: str,
    action: AuditAction,
    object_id: str,
    actor_subject: str,
    actor_session_digest: str,
    occurred_at: datetime,
    details_digest: str,
) -> bytes:
    timestamp = _utc_second(occurred_at, label="audit event time")
    if _PORTABLE_ID_RE.fullmatch(tenant_id) is None:
        raise ValueError("audit tenant id is invalid")
    if type(sequence) is not int or sequence < 1:
        raise ValueError("audit sequence is invalid")
    for label, value in (
        ("previous audit digest", previous_event_digest),
        ("audit object id", object_id),
        ("actor session digest", actor_session_digest),
        ("audit details digest", details_digest),
    ):
        if _DIGEST_RE.fullmatch(value) is None:
            raise ValueError(f"{label} is invalid")
    if action not in {
        "revision-created",
        "revision-submitted",
        "revision-approved",
        "revision-rejected",
        "revision-activated",
        "deployment-retry-requested",
        "deployment-rollback-requested",
        "deployment-leased",
        "deployment-applied",
        "deployment-failed",
    }:
        raise ValueError("audit action is invalid")
    if not actor_subject or len(actor_subject) > 255:
        raise ValueError("audit actor subject is invalid")
    return canonical_json_bytes(
        {
            "action": action,
            "actor_session_digest": actor_session_digest,
            "actor_subject": actor_subject,
            "details_digest": details_digest,
            "object_id": object_id,
            "occurred_at": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "previous_event_digest": previous_event_digest,
            "sequence": sequence,
            "tenant_id": tenant_id,
        }
    )
