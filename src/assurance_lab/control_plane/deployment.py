"""Fenced, idempotent reconciliation boundary for deployment operations.

The control-plane database records intent.  A target adapter is responsible for
making one exact configuration effective and returning a content digest for
its own durable receipt.  Re-invocation uses the same operation id and a higher
lease fence, which is how an adapter resolves the classic "target committed,
worker crashed before acknowledgement" ambiguity without applying a second
logical change.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated, Protocol

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

from assurance_lab.control_plane.models import (
    ConfigurationRevision,
    ControlConfiguration,
    DeploymentOperation,
    DeploymentWorkerIdentity,
    Digest,
)
from assurance_lab.evidence.canonical import canonical_json_bytes

_ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9.-]{0,63}$")


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class DeploymentApplyRequest(_FrozenModel):
    """Exact adapter input; ``operation_id`` is the stable idempotency key."""

    operation_id: Digest
    tenant_id: Annotated[
        str,
        StringConstraints(
            min_length=1,
            max_length=128,
            pattern=r"^[a-z][a-z0-9._-]{0,127}$",
        ),
    ]
    control_id: Annotated[
        str,
        StringConstraints(
            min_length=1,
            max_length=128,
            pattern=r"^[a-z][a-z0-9._-]{0,127}$",
        ),
    ]
    revision_id: Digest
    configuration_digest: Digest
    configuration_bytes: bytes = Field(min_length=2, max_length=1024 * 1024)
    operation_sequence: int = Field(ge=1, le=2**63 - 1)
    lease_fence: int = Field(ge=1, le=2**63 - 1)

    @model_validator(mode="after")
    def validate_request(self) -> DeploymentApplyRequest:
        actual_digest = f"sha256:{hashlib.sha256(self.configuration_bytes).hexdigest()}"
        if actual_digest != self.configuration_digest:
            raise ValueError("deployment request configuration digest differs")
        try:
            configuration = ControlConfiguration.model_validate_json(
                self.configuration_bytes
            )
        except ValueError as exc:
            raise ValueError("deployment request configuration is invalid") from exc
        if (
            configuration.tenant_id != self.tenant_id
            or configuration.control_id != self.control_id
            or configuration.digest != self.configuration_digest
        ):
            raise ValueError("deployment request crosses its configuration boundary")
        return self

    @property
    def idempotency_key(self) -> str:
        return self.operation_id


class DeploymentTargetAcknowledgement(_FrozenModel):
    """Target observation that is necessary, but not sufficient without CAS."""

    operation_id: Digest
    lease_fence: int = Field(ge=1, le=2**63 - 1)
    applied_configuration_digest: Digest
    target_receipt_digest: Digest


class DeploymentApplyError(RuntimeError):
    """Secret-free adapter failure classification."""

    def __init__(self, code: str, *, retryable: bool) -> None:
        if type(code) is not str or _ERROR_CODE_RE.fullmatch(code) is None:
            raise ValueError("deployment error code is invalid")
        if type(retryable) is not bool:
            raise TypeError("deployment retryable flag must be boolean")
        super().__init__(code)
        self.code = code
        self.retryable = retryable


class DeploymentOutcomeUnknown(DeploymentApplyError):
    """The target may have committed, so the same operation must be reconciled."""

    def __init__(self, code: str = "target-outcome-unknown") -> None:
        super().__init__(code, retryable=True)


class DeploymentTarget(Protocol):
    """Adapter contract.

    Implementations must key logical application by ``request.operation_id``,
    reject stale lower fences, and on retries return an observation of the
    already-applied exact digest instead of creating another logical change.
    """

    def ensure_applied(
        self,
        request: DeploymentApplyRequest,
    ) -> DeploymentTargetAcknowledgement: ...


class _DeploymentStore(Protocol):
    def lease_next_deployment_operation(
        self,
        *,
        worker: DeploymentWorkerIdentity,
        lease_token_digest: str,
        leased_at: datetime,
        lease_ttl_seconds: int,
    ) -> DeploymentOperation | None: ...

    def get_revision(
        self,
        *,
        tenant_id: str,
        revision_id: str,
    ) -> ConfigurationRevision: ...

    def acknowledge_deployment_applied(
        self,
        *,
        worker: DeploymentWorkerIdentity,
        operation_id: str,
        lease_token_digest: str,
        lease_fence: int,
        applied_configuration_digest: str,
        target_receipt_digest: str,
        applied_at: datetime,
    ) -> DeploymentOperation: ...

    def fail_deployment_operation(
        self,
        *,
        worker: DeploymentWorkerIdentity,
        operation_id: str,
        lease_token_digest: str,
        lease_fence: int,
        failure_digest: str,
        failed_at: datetime,
        retry_at: datetime | None,
    ) -> DeploymentOperation: ...


def _system_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _failure_digest(
    *,
    operation: DeploymentOperation,
    code: str,
    retryable: bool,
) -> str:
    body = canonical_json_bytes(
        {
            "attempt_count": operation.attempt_count,
            "code": code,
            "lease_fence": operation.lease_fence,
            "operation_id": operation.operation_id,
            "retryable": retryable,
        }
    )
    return f"sha256:{hashlib.sha256(body).hexdigest()}"


class DeploymentReconciler:
    """Lease one request, reconcile it once, and durably close its lease."""

    __slots__ = (
        "_base_retry_seconds",
        "_lease_ttl_seconds",
        "_max_attempts",
        "_max_retry_seconds",
        "_now",
        "_store",
        "_target",
        "_token_bytes",
        "_worker",
    )

    def __init__(
        self,
        store: _DeploymentStore,
        target: DeploymentTarget,
        worker: DeploymentWorkerIdentity,
        *,
        now: Callable[[], datetime] | None = None,
        token_bytes: Callable[[int], bytes] | None = None,
        lease_ttl_seconds: int = 120,
        max_attempts: int = 8,
        base_retry_seconds: int = 30,
        max_retry_seconds: int = 3_600,
    ) -> None:
        required = (
            "acknowledge_deployment_applied",
            "fail_deployment_operation",
            "get_revision",
            "lease_next_deployment_operation",
        )
        if any(not callable(getattr(store, name, None)) for name in required):
            raise TypeError("store does not implement deployment reconciliation")
        if not callable(getattr(target, "ensure_applied", None)):
            raise TypeError("deployment target must implement ensure_applied()")
        if (
            type(lease_ttl_seconds) is not int
            or lease_ttl_seconds < 15
            or lease_ttl_seconds > 3_600
        ):
            raise ValueError("deployment lease TTL is outside the supported range")
        if type(max_attempts) is not int or max_attempts < 1 or max_attempts > 32:
            raise ValueError("deployment attempt limit is outside the supported range")
        if (
            type(base_retry_seconds) is not int
            or type(max_retry_seconds) is not int
            or base_retry_seconds < 1
            or max_retry_seconds < base_retry_seconds
            or max_retry_seconds > 86_400
        ):
            raise ValueError("deployment retry backoff is outside the supported range")
        self._store = store
        self._target = target
        self._worker = worker
        self._now = now or _system_now
        self._token_bytes = token_bytes or secrets.token_bytes
        self._lease_ttl_seconds = lease_ttl_seconds
        self._max_attempts = max_attempts
        self._base_retry_seconds = base_retry_seconds
        self._max_retry_seconds = max_retry_seconds

    def _time(self) -> datetime:
        value = self._now()
        if type(value) is not datetime or value.tzinfo is None:
            raise RuntimeError("deployment clock must return a timezone-aware datetime")
        converted = value.astimezone(UTC)
        if converted.microsecond:
            raise RuntimeError("deployment clock must return whole UTC seconds")
        return converted

    def _lease_token_digest(self) -> str:
        token = self._token_bytes(32)
        if type(token) is not bytes or len(token) < 16:
            raise RuntimeError("deployment lease entropy source returned invalid bytes")
        return f"sha256:{hashlib.sha256(token).hexdigest()}"

    def _failure(
        self,
        *,
        operation: DeploymentOperation,
        lease_token_digest: str,
        code: str,
        retryable: bool,
    ) -> DeploymentOperation:
        failed_at = self._time()
        can_retry = retryable and operation.attempt_count < self._max_attempts
        retry_at: datetime | None = None
        if can_retry:
            exponent = min(operation.attempt_count - 1, 30)
            delay = min(
                self._base_retry_seconds * (2**exponent),
                self._max_retry_seconds,
            )
            retry_at = failed_at + timedelta(seconds=delay)
        return self._store.fail_deployment_operation(
            worker=self._worker,
            operation_id=operation.operation_id,
            lease_token_digest=lease_token_digest,
            lease_fence=operation.lease_fence,
            failure_digest=_failure_digest(
                operation=operation,
                code=code,
                retryable=can_retry,
            ),
            failed_at=failed_at,
            retry_at=retry_at,
        )

    def run_once(self) -> DeploymentOperation | None:
        """Process at most one operation.

        A process crash simply leaves the lease to expire.  If the target may
        already have committed, the next lease uses the same operation id and
        invokes ``ensure_applied`` again with a higher fence.
        """

        lease_token_digest = self._lease_token_digest()
        operation = self._store.lease_next_deployment_operation(
            worker=self._worker,
            lease_token_digest=lease_token_digest,
            leased_at=self._time(),
            lease_ttl_seconds=self._lease_ttl_seconds,
        )
        if operation is None:
            return None
        revision = self._store.get_revision(
            tenant_id=operation.tenant_id,
            revision_id=operation.revision_id,
        )
        if (
            revision.control_id != operation.control_id
            or revision.configuration_digest != operation.configuration_digest
        ):
            return self._failure(
                operation=operation,
                lease_token_digest=lease_token_digest,
                code="revision-integrity-mismatch",
                retryable=False,
            )
        request = DeploymentApplyRequest(
            operation_id=operation.operation_id,
            tenant_id=operation.tenant_id,
            control_id=operation.control_id,
            revision_id=operation.revision_id,
            configuration_digest=operation.configuration_digest,
            configuration_bytes=revision.configuration_bytes,
            operation_sequence=operation.operation_sequence,
            lease_fence=operation.lease_fence,
        )
        try:
            acknowledgement = self._target.ensure_applied(request)
        except DeploymentApplyError as exc:
            return self._failure(
                operation=operation,
                lease_token_digest=lease_token_digest,
                code=exc.code,
                retryable=exc.retryable,
            )
        except Exception:
            # Exception text can contain credentials or target payloads.  Only
            # a stable category enters durable state.
            return self._failure(
                operation=operation,
                lease_token_digest=lease_token_digest,
                code="adapter-unhandled",
                retryable=True,
            )
        if not isinstance(acknowledgement, DeploymentTargetAcknowledgement) or (
            acknowledgement.operation_id != operation.operation_id
            or acknowledgement.lease_fence != operation.lease_fence
            or acknowledgement.applied_configuration_digest
            != operation.configuration_digest
        ):
            return self._failure(
                operation=operation,
                lease_token_digest=lease_token_digest,
                code="target-acknowledgement-mismatch",
                retryable=False,
            )
        return self._store.acknowledge_deployment_applied(
            worker=self._worker,
            operation_id=operation.operation_id,
            lease_token_digest=lease_token_digest,
            lease_fence=operation.lease_fence,
            applied_configuration_digest=(
                acknowledgement.applied_configuration_digest
            ),
            target_receipt_digest=acknowledgement.target_receipt_digest,
            applied_at=self._time(),
        )
