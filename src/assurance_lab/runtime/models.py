"""Strict identities and closure records for the assurance runtime.

The runtime keeps three facts separate:

* a deployment operation was durably accepted by the runtime catalog;
* one deterministic collection window became due; and
* an executor returned evidence and receipt digests for that exact run.

None of those facts implies either of the others.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Annotated, Literal, Protocol

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from assurance_lab.control_plane.models import ControlConfiguration, Digest
from assurance_lab.evidence.canonical import (
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)

PortableId = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9._-]{0,127}$",
    ),
]
RunState = Literal["pending", "leased", "succeeded", "failed"]
RunOutcome = Literal["succeeded", "failed"]
_ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9.-]{0,63}$")
_MEDIA_TYPE_RE = re.compile(
    r"^application/(?:json|[a-z0-9!#$&^_.+-]+[+]json)$"
)


def sha256_digest(value: bytes) -> str:
    """Return the one digest representation accepted by runtime records."""

    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def utc_second(value: datetime, *, label: str) -> datetime:
    """Normalize an aware datetime and reject ambiguous sub-second clocks."""

    if type(value) is not datetime or value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
    converted = value.astimezone(UTC)
    if converted.microsecond:
        raise ValueError(f"{label} must use whole UTC seconds")
    return converted


def utc_text(value: datetime) -> str:
    return utc_second(value, label="runtime timestamp").strftime("%Y-%m-%dT%H:%M:%SZ")


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class RuntimeWorkerIdentity(_FrozenModel):
    """Tenant-scoped identity derived from workload authentication."""

    tenant_id: PortableId
    worker_id: PortableId
    credential_digest: Digest


class RegisteredControlProfile(_FrozenModel):
    """One immutable canonical control profile in the runtime registry."""

    tenant_id: PortableId
    profile_id: PortableId
    profile_digest: Digest
    media_type: Annotated[str, StringConstraints(min_length=16, max_length=128)]
    profile_bytes: bytes = Field(min_length=2, max_length=1024 * 1024)
    registered_at: datetime
    registered_by: Annotated[str, StringConstraints(min_length=1, max_length=255)]

    @field_validator("registered_at")
    @classmethod
    def validate_registered_at(cls, value: datetime) -> datetime:
        return utc_second(value, label="control profile registration time")

    @field_validator("media_type")
    @classmethod
    def validate_media_type(cls, value: str) -> str:
        if _MEDIA_TYPE_RE.fullmatch(value) is None:
            raise ValueError("control profile media type must identify JSON")
        return value

    @model_validator(mode="after")
    def validate_profile(self) -> RegisteredControlProfile:
        if sha256_digest(self.profile_bytes) != self.profile_digest:
            raise ValueError("control profile digest differs from its bytes")
        try:
            parsed = strict_json_loads(self.profile_bytes)
        except StrictJSONError as exc:
            raise ValueError("control profile is not bounded strict JSON") from exc
        if not isinstance(parsed, dict):
            raise ValueError("control profile must be one JSON object")
        if canonical_json_bytes(parsed) != self.profile_bytes:
            raise ValueError("control profile is not canonical JSON")
        return self


class RuntimeDeploymentReceipt(_FrozenModel):
    """Content-addressed statement emitted when a configuration is accepted."""

    media_type: Literal[
        "application/vnd.control-assurance.runtime-deployment-receipt.v1+json"
    ] = "application/vnd.control-assurance.runtime-deployment-receipt.v1+json"
    schema_version: Literal["1.0.0"] = "1.0.0"
    tenant_id: PortableId
    control_id: PortableId
    operation_id: Digest
    operation_sequence: int = Field(ge=1, le=2**63 - 1)
    lease_fence_at_commit: int = Field(ge=1, le=2**63 - 1)
    revision_id: Digest
    configuration_digest: Digest
    control_profile_id: PortableId
    control_profile_digest: Digest
    previous_operation_id: Digest | None
    previous_receipt_digest: Digest | None
    applied_at: datetime

    @field_validator("applied_at")
    @classmethod
    def validate_applied_at(cls, value: datetime) -> datetime:
        return utc_second(value, label="deployment receipt time")

    @model_validator(mode="after")
    def validate_previous_pair(self) -> RuntimeDeploymentReceipt:
        if (self.previous_operation_id is None) != (
            self.previous_receipt_digest is None
        ):
            raise ValueError("previous deployment operation and receipt must be paired")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"))

    @property
    def digest(self) -> str:
        return sha256_digest(self.canonical_bytes())


class DeployedControl(_FrozenModel):
    """The runtime's current applied state, not the control-plane desired state."""

    tenant_id: PortableId
    control_id: PortableId
    operation_id: Digest
    operation_sequence: int = Field(ge=1, le=2**63 - 1)
    revision_id: Digest
    configuration_digest: Digest
    configuration_bytes: bytes = Field(min_length=2, max_length=1024 * 1024)
    control_profile_id: PortableId
    control_profile_digest: Digest
    deployment_receipt_digest: Digest
    lease_fence_at_commit: int = Field(ge=1, le=2**63 - 1)
    highest_lease_fence_seen: int = Field(ge=1, le=2**63 - 1)
    applied_at: datetime

    @field_validator("applied_at")
    @classmethod
    def validate_applied_at(cls, value: datetime) -> datetime:
        return utc_second(value, label="deployed control time")

    @model_validator(mode="after")
    def validate_configuration(self) -> DeployedControl:
        if sha256_digest(self.configuration_bytes) != self.configuration_digest:
            raise ValueError("deployed configuration digest differs")
        try:
            configuration = ControlConfiguration.model_validate_json(
                self.configuration_bytes
            )
        except ValueError as exc:
            raise ValueError("deployed configuration is invalid") from exc
        if (
            configuration.canonical_bytes() != self.configuration_bytes
            or configuration.digest != self.configuration_digest
            or configuration.tenant_id != self.tenant_id
            or configuration.control_id != self.control_id
            or configuration.control_profile_id != self.control_profile_id
            or configuration.control_profile_digest
            != self.control_profile_digest
        ):
            raise ValueError("deployed configuration crosses its canonical boundary")
        if self.highest_lease_fence_seen < self.lease_fence_at_commit:
            raise ValueError("deployed control fence moved backwards")
        return self

    @property
    def configuration(self) -> ControlConfiguration:
        return ControlConfiguration.model_validate_json(self.configuration_bytes)


class ControlRunRequest(_FrozenModel):
    """Immutable identity of one half-open collection window."""

    media_type: Literal[
        "application/vnd.control-assurance.control-run-request.v1+json"
    ] = "application/vnd.control-assurance.control-run-request.v1+json"
    schema_version: Literal["1.0.0"] = "1.0.0"
    tenant_id: PortableId
    control_id: PortableId
    deployment_operation_id: Digest
    deployment_operation_sequence: int = Field(ge=1, le=2**63 - 1)
    deployment_receipt_digest: Digest
    control_profile_id: PortableId
    control_profile_digest: Digest
    revision_id: Digest
    configuration_digest: Digest
    window_start: datetime
    window_end: datetime
    due_at: datetime

    @field_validator("window_start", "window_end", "due_at")
    @classmethod
    def validate_times(cls, value: datetime) -> datetime:
        return utc_second(value, label="control run time")

    @model_validator(mode="after")
    def validate_window(self) -> ControlRunRequest:
        if self.window_end <= self.window_start:
            raise ValueError("control run window must be non-empty")
        if self.due_at < self.window_end:
            raise ValueError("control run cannot be due before its window closes")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"))

    @property
    def run_id(self) -> str:
        return sha256_digest(self.canonical_bytes())


class ControlRun(_FrozenModel):
    """One materialized run and its current lease or terminal state."""

    run_id: Digest
    request: ControlRunRequest
    state: RunState
    state_version: int = Field(ge=0, le=2**63 - 1)
    attempt_count: int = Field(ge=0, le=32)
    lease_fence: int = Field(ge=0, le=2**63 - 1)
    lease_owner: PortableId | None = None
    lease_token_digest: Digest | None = None
    leased_at: datetime | None = None
    lease_expires_at: datetime | None = None
    retry_at: datetime | None = None
    completed_at: datetime | None = None
    evidence_digest: Digest | None = None
    executor_receipt_digest: Digest | None = None
    closure_digest: Digest | None = None
    failed_at: datetime | None = None
    failure_digest: Digest | None = None

    @field_validator(
        "leased_at",
        "lease_expires_at",
        "retry_at",
        "completed_at",
        "failed_at",
    )
    @classmethod
    def validate_times(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return utc_second(value, label="control run state time")

    @model_validator(mode="after")
    def validate_state(self) -> ControlRun:
        if self.run_id != self.request.run_id:
            raise ValueError("control run id differs from its canonical request")
        lease = (
            self.lease_owner,
            self.lease_token_digest,
            self.leased_at,
            self.lease_expires_at,
        )
        success = (
            self.completed_at,
            self.evidence_digest,
            self.executor_receipt_digest,
            self.closure_digest,
        )
        failure = (self.failed_at, self.failure_digest)
        if self.state == "pending":
            if (
                self.state_version != 0
                or self.attempt_count != 0
                or self.lease_fence != 0
                or any(value is not None for value in lease + success + failure)
                or self.retry_at is not None
            ):
                raise ValueError("pending run contains mutable outcome state")
        elif self.state == "leased":
            if (
                self.attempt_count < 1
                or self.lease_fence != self.attempt_count
                or any(value is None for value in lease)
                or any(value is not None for value in success + failure)
                or self.retry_at is not None
            ):
                raise ValueError("leased run has an invalid lease")
            assert self.leased_at is not None
            assert self.lease_expires_at is not None
            if (
                self.leased_at < self.request.due_at
                or self.lease_expires_at <= self.leased_at
            ):
                raise ValueError("control run lease does not advance due time")
        elif self.state == "succeeded":
            if (
                self.attempt_count < 1
                or self.lease_fence != self.attempt_count
                or any(value is not None for value in lease + failure)
                or any(value is None for value in success)
                or self.retry_at is not None
            ):
                raise ValueError("succeeded run lacks exact closure")
        elif self.state == "failed" and (
            self.attempt_count < 1
            or self.lease_fence != self.attempt_count
            or any(value is not None for value in lease + success)
            or any(value is None for value in failure)
        ):
            raise ValueError("failed run has an invalid outcome")
        return self

    @property
    def terminal(self) -> bool:
        return self.state == "succeeded" or (
            self.state == "failed" and self.retry_at is None
        )


class ControlRunExecutionRequest(_FrozenModel):
    """Exact, idempotent request handed to the next-layer executor."""

    run_id: Digest
    run_request_bytes: bytes = Field(min_length=2, max_length=65536)
    tenant_id: PortableId
    control_id: PortableId
    deployment_operation_id: Digest
    deployment_receipt_digest: Digest
    configuration_digest: Digest
    configuration_bytes: bytes = Field(min_length=2, max_length=1024 * 1024)
    control_profile_id: PortableId
    control_profile_digest: Digest
    control_profile_media_type: Annotated[
        str,
        StringConstraints(min_length=16, max_length=128),
    ]
    control_profile_bytes: bytes = Field(min_length=2, max_length=1024 * 1024)
    window_start: datetime
    window_end: datetime
    attempt_count: int = Field(ge=1, le=32)
    lease_fence: int = Field(ge=1, le=2**63 - 1)

    @field_validator("window_start", "window_end")
    @classmethod
    def validate_times(cls, value: datetime) -> datetime:
        return utc_second(value, label="executor request time")

    @field_validator("control_profile_media_type")
    @classmethod
    def validate_profile_media_type(cls, value: str) -> str:
        if _MEDIA_TYPE_RE.fullmatch(value) is None:
            raise ValueError("control profile media type must identify JSON")
        return value

    @model_validator(mode="after")
    def validate_configuration(self) -> ControlRunExecutionRequest:
        if self.window_end <= self.window_start:
            raise ValueError("executor request window must be non-empty")
        if sha256_digest(self.run_request_bytes) != self.run_id:
            raise ValueError("executor run request digest differs")
        try:
            parsed_request = strict_json_loads(self.run_request_bytes)
            run_request = ControlRunRequest.model_validate_json(
                self.run_request_bytes
            )
        except (StrictJSONError, ValueError) as exc:
            raise ValueError("executor run request is invalid") from exc
        if (
            canonical_json_bytes(parsed_request) != self.run_request_bytes
            or run_request.canonical_bytes() != self.run_request_bytes
            or run_request.run_id != self.run_id
            or run_request.tenant_id != self.tenant_id
            or run_request.control_id != self.control_id
            or run_request.deployment_operation_id
            != self.deployment_operation_id
            or run_request.deployment_receipt_digest
            != self.deployment_receipt_digest
            or run_request.configuration_digest != self.configuration_digest
            or run_request.control_profile_id != self.control_profile_id
            or run_request.control_profile_digest
            != self.control_profile_digest
            or run_request.window_start != self.window_start
            or run_request.window_end != self.window_end
        ):
            raise ValueError("executor run request crosses its canonical boundary")
        if sha256_digest(self.configuration_bytes) != self.configuration_digest:
            raise ValueError("executor configuration digest differs")
        configuration = ControlConfiguration.model_validate_json(
            self.configuration_bytes
        )
        if (
            configuration.canonical_bytes() != self.configuration_bytes
            or configuration.digest != self.configuration_digest
            or configuration.tenant_id != self.tenant_id
            or configuration.control_id != self.control_id
            or configuration.control_profile_id != self.control_profile_id
            or configuration.control_profile_digest
            != self.control_profile_digest
        ):
            raise ValueError("executor configuration crosses its canonical boundary")
        if sha256_digest(self.control_profile_bytes) != self.control_profile_digest:
            raise ValueError("executor control profile digest differs")
        try:
            profile = strict_json_loads(self.control_profile_bytes)
        except StrictJSONError as exc:
            raise ValueError("executor control profile is invalid") from exc
        if (
            not isinstance(profile, dict)
            or canonical_json_bytes(profile) != self.control_profile_bytes
        ):
            raise ValueError("executor control profile is not one canonical object")
        return self

    @property
    def idempotency_key(self) -> str:
        return self.run_id


class ControlRunExecutionResult(_FrozenModel):
    """Executor observation of immutable evidence already placed in custody."""

    run_id: Digest
    lease_fence: int = Field(ge=1, le=2**63 - 1)
    evidence_digest: Digest
    executor_receipt_digest: Digest


class ControlRunClosure(_FrozenModel):
    """Canonical closure joining request, deployment, evidence, and receipt."""

    media_type: Literal[
        "application/vnd.control-assurance.control-run-closure.v1+json"
    ] = "application/vnd.control-assurance.control-run-closure.v1+json"
    schema_version: Literal["1.0.0"] = "1.0.0"
    run_id: Digest
    tenant_id: PortableId
    control_id: PortableId
    deployment_operation_id: Digest
    deployment_receipt_digest: Digest
    configuration_digest: Digest
    control_profile_id: PortableId
    control_profile_digest: Digest
    window_start: datetime
    window_end: datetime
    attempt_count: int = Field(ge=1, le=32)
    lease_fence: int = Field(ge=1, le=2**63 - 1)
    evidence_digest: Digest
    executor_receipt_digest: Digest
    completed_at: datetime

    @field_validator("window_start", "window_end", "completed_at")
    @classmethod
    def validate_times(cls, value: datetime) -> datetime:
        return utc_second(value, label="run closure time")

    @model_validator(mode="after")
    def validate_window(self) -> ControlRunClosure:
        if self.window_end <= self.window_start:
            raise ValueError("run closure window must be non-empty")
        if self.completed_at < self.window_end:
            raise ValueError("run closure predates its collection window")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"))

    @property
    def digest(self) -> str:
        return sha256_digest(self.canonical_bytes())


class ControlRunExecutionError(RuntimeError):
    """Bounded, secret-free executor error safe for durable classification."""

    def __init__(self, code: str, *, retryable: bool) -> None:
        if type(code) is not str or _ERROR_CODE_RE.fullmatch(code) is None:
            raise ValueError("executor error code is invalid")
        if type(retryable) is not bool:
            raise TypeError("executor retryable flag must be boolean")
        super().__init__(code)
        self.code = code
        self.retryable = retryable


class ControlRunOutcomeUnknown(ControlRunExecutionError):
    """The executor or database may have committed; retry the same run id."""

    def __init__(self, code: str = "run-outcome-unknown") -> None:
        super().__init__(code, retryable=True)


class ControlRunExecutor(Protocol):
    """Vendor-neutral execution seam.

    Implementations key logical work by ``request.run_id``, reject stale lower
    fences, and return the same immutable evidence and receipt digests after an
    ambiguous retry.  The executor, not this scheduler, owns connector, PAM,
    signing, and custody composition.
    """

    def ensure_executed(
        self,
        request: ControlRunExecutionRequest,
    ) -> ControlRunExecutionResult: ...
