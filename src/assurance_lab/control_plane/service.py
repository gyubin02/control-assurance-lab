"""Authorization and maker-checker rules for configuration lifecycle."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol

from assurance_lab.control_plane.models import (
    ActiveDeployment,
    Actor,
    ApprovalDecision,
    AuditEvent,
    ConfigurationRevision,
    ControlConfiguration,
    ControlSummary,
    DeploymentOperation,
)
from assurance_lab.control_plane.store import SQLiteControlPlaneStore

_PRIVILEGED_SESSION_MAX_AGE = timedelta(hours=1)
_FUTURE_CLOCK_TOLERANCE = timedelta(minutes=5)


class ControlPlaneAuthorizationError(PermissionError):
    pass


class _ControlPlaneStore(Protocol):
    def create_draft(
        self,
        *,
        actor: Actor,
        configuration: ControlConfiguration,
        expected_parent_revision_id: str | None,
        created_at: datetime,
    ) -> ConfigurationRevision: ...

    def get_revision(
        self,
        *,
        tenant_id: str,
        revision_id: str,
    ) -> ConfigurationRevision: ...

    def list_revisions(
        self,
        *,
        tenant_id: str,
        control_id: str,
        limit: int = 100,
    ) -> tuple[ConfigurationRevision, ...]: ...

    def list_controls(
        self,
        *,
        tenant_id: str,
        limit: int = 100,
    ) -> tuple[ControlSummary, ...]: ...

    def submit(
        self,
        *,
        actor: Actor,
        revision_id: str,
        expected_state_version: int,
        submitted_at: datetime,
    ) -> ConfigurationRevision: ...

    def decide(
        self,
        *,
        actor: Actor,
        revision_id: str,
        expected_state_version: int,
        decision: str,
        comment: str,
        decided_at: datetime,
    ) -> tuple[ConfigurationRevision, ApprovalDecision]: ...

    def activate(
        self,
        *,
        actor: Actor,
        revision_id: str,
        expected_deployment_version: int | None,
        activated_at: datetime,
    ) -> ActiveDeployment: ...

    def activate_with_operation(
        self,
        *,
        actor: Actor,
        revision_id: str,
        expected_deployment_version: int | None,
        activated_at: datetime,
    ) -> tuple[ActiveDeployment, DeploymentOperation]: ...

    def get_active_deployment(
        self,
        *,
        tenant_id: str,
        control_id: str,
    ) -> ActiveDeployment: ...

    def request_rollback(
        self,
        *,
        actor: Actor,
        revision_id: str,
        expected_predecessor_operation_id: str,
        requested_at: datetime,
    ) -> DeploymentOperation: ...

    def request_deployment_retry(
        self,
        *,
        actor: Actor,
        failed_operation_id: str,
        requested_at: datetime,
    ) -> DeploymentOperation: ...

    def get_deployment_operation(
        self,
        *,
        tenant_id: str,
        operation_id: str,
    ) -> DeploymentOperation: ...

    def list_deployment_operations(
        self,
        *,
        tenant_id: str,
        control_id: str,
        limit: int = 100,
    ) -> tuple[DeploymentOperation, ...]: ...

    def latest_applied_operation(
        self,
        *,
        tenant_id: str,
        control_id: str,
    ) -> DeploymentOperation: ...

    def audit_events(
        self,
        *,
        tenant_id: str,
        after_sequence: int = 0,
        limit: int = 1_000,
    ) -> tuple[AuditEvent, ...]: ...

    def verify_audit_chain(self, *, tenant_id: str) -> tuple[int, str]: ...


def _system_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


class ControlPlaneService:
    """Tenant isolation, RBAC, MFA freshness, and separation of duties."""

    __slots__ = ("_now", "_store")

    def __init__(
        self,
        store: _ControlPlaneStore,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(store, SQLiteControlPlaneStore):
            # Structural typing is used for the future PostgreSQL backend, but
            # arbitrary objects should not silently become authorization state.
            required = (
                "activate",
                "activate_with_operation",
                "audit_events",
                "create_draft",
                "decide",
                "get_active_deployment",
                "get_deployment_operation",
                "get_revision",
                "latest_applied_operation",
                "list_deployment_operations",
                "list_revisions",
                "list_controls",
                "request_rollback",
                "request_deployment_retry",
                "submit",
                "verify_audit_chain",
            )
            if any(not callable(getattr(store, name, None)) for name in required):
                raise TypeError("store does not implement the control-plane repository")
        self._store = store
        self._now = now or _system_now

    def _time(self) -> datetime:
        value = self._now()
        if type(value) is not datetime or value.tzinfo is None:
            raise RuntimeError("control-plane clock must return a timezone-aware datetime")
        converted = value.astimezone(UTC)
        if converted.microsecond != 0:
            raise RuntimeError("control-plane clock must return whole UTC seconds")
        return converted

    def _authorize(
        self,
        actor: Actor,
        *,
        role: Literal[
            "viewer",
            "editor",
            "approver",
            "deployer",
            "auditor",
        ],
        privileged: bool,
        now: datetime,
    ) -> None:
        if "administrator" not in actor.roles and role not in actor.roles:
            raise ControlPlaneAuthorizationError(f"{role} role is required")
        age = now - actor.authenticated_at
        if age < -_FUTURE_CLOCK_TOLERANCE:
            raise ControlPlaneAuthorizationError("authentication time is in the future")
        if privileged and (
            not actor.mfa
            or age < timedelta(0)
            or age > _PRIVILEGED_SESSION_MAX_AGE
        ):
            raise ControlPlaneAuthorizationError(
                "fresh MFA authentication is required for this action"
            )

    @staticmethod
    def _same_tenant(actor: Actor, tenant_id: str) -> None:
        if actor.tenant_id != tenant_id:
            raise ControlPlaneAuthorizationError("cross-tenant access is denied")

    @staticmethod
    def _owns_control(actor: Actor, configuration: ControlConfiguration) -> None:
        if (
            "administrator" not in actor.roles
            and configuration.owner_group not in actor.groups
        ):
            raise ControlPlaneAuthorizationError(
                "actor is not a member of the control owner group"
            )

    def create_revision(
        self,
        actor: Actor,
        configuration: ControlConfiguration,
        *,
        expected_parent_revision_id: str | None,
    ) -> ConfigurationRevision:
        now = self._time()
        self._authorize(actor, role="editor", privileged=False, now=now)
        self._same_tenant(actor, configuration.tenant_id)
        self._owns_control(actor, configuration)
        return self._store.create_draft(
            actor=actor,
            configuration=configuration,
            expected_parent_revision_id=expected_parent_revision_id,
            created_at=now,
        )

    def submit_revision(
        self,
        actor: Actor,
        revision_id: str,
        *,
        expected_state_version: int,
    ) -> ConfigurationRevision:
        now = self._time()
        self._authorize(actor, role="editor", privileged=False, now=now)
        revision = self._store.get_revision(
            tenant_id=actor.tenant_id,
            revision_id=revision_id,
        )
        if revision.created_by != actor.subject and "administrator" not in actor.roles:
            raise ControlPlaneAuthorizationError(
                "only the revision author may submit it"
            )
        self._owns_control(actor, revision.configuration)
        return self._store.submit(
            actor=actor,
            revision_id=revision_id,
            expected_state_version=expected_state_version,
            submitted_at=now,
        )

    def decide_revision(
        self,
        actor: Actor,
        revision_id: str,
        *,
        expected_state_version: int,
        decision: Literal["approved", "rejected"],
        comment: str,
    ) -> tuple[ConfigurationRevision, ApprovalDecision]:
        now = self._time()
        self._authorize(actor, role="approver", privileged=True, now=now)
        revision = self._store.get_revision(
            tenant_id=actor.tenant_id,
            revision_id=revision_id,
        )
        if revision.created_by == actor.subject:
            raise ControlPlaneAuthorizationError(
                "revision author cannot approve or reject their own change"
            )
        return self._store.decide(
            actor=actor,
            revision_id=revision_id,
            expected_state_version=expected_state_version,
            decision=decision,
            comment=comment,
            decided_at=now,
        )

    def activate_revision(
        self,
        actor: Actor,
        revision_id: str,
        *,
        expected_deployment_version: int | None,
    ) -> ActiveDeployment:
        deployment, _operation = self.activate_revision_with_operation(
            actor,
            revision_id,
            expected_deployment_version=expected_deployment_version,
        )
        return deployment

    def activate_revision_with_operation(
        self,
        actor: Actor,
        revision_id: str,
        *,
        expected_deployment_version: int | None,
    ) -> tuple[ActiveDeployment, DeploymentOperation]:
        now = self._time()
        self._authorize(actor, role="deployer", privileged=True, now=now)
        revision = self._store.get_revision(
            tenant_id=actor.tenant_id,
            revision_id=revision_id,
        )
        if revision.created_by == actor.subject:
            raise ControlPlaneAuthorizationError(
                "revision author cannot activate their own change"
            )
        return self._store.activate_with_operation(
            actor=actor,
            revision_id=revision_id,
            expected_deployment_version=expected_deployment_version,
            activated_at=now,
        )

    def get_revision(
        self,
        actor: Actor,
        revision_id: str,
    ) -> ConfigurationRevision:
        now = self._time()
        self._authorize(actor, role="viewer", privileged=False, now=now)
        return self._store.get_revision(
            tenant_id=actor.tenant_id,
            revision_id=revision_id,
        )

    def list_revisions(
        self,
        actor: Actor,
        control_id: str,
        *,
        limit: int = 100,
    ) -> tuple[ConfigurationRevision, ...]:
        now = self._time()
        self._authorize(actor, role="viewer", privileged=False, now=now)
        return self._store.list_revisions(
            tenant_id=actor.tenant_id,
            control_id=control_id,
            limit=limit,
        )

    def list_controls(
        self,
        actor: Actor,
        *,
        limit: int = 100,
    ) -> tuple[ControlSummary, ...]:
        now = self._time()
        self._authorize(actor, role="viewer", privileged=False, now=now)
        return self._store.list_controls(
            tenant_id=actor.tenant_id,
            limit=limit,
        )

    def active_deployment(
        self,
        actor: Actor,
        control_id: str,
    ) -> ActiveDeployment:
        now = self._time()
        self._authorize(actor, role="viewer", privileged=False, now=now)
        return self._store.get_active_deployment(
            tenant_id=actor.tenant_id,
            control_id=control_id,
        )

    def request_rollback(
        self,
        actor: Actor,
        revision_id: str,
        *,
        expected_predecessor_operation_id: str,
    ) -> DeploymentOperation:
        now = self._time()
        self._authorize(actor, role="deployer", privileged=True, now=now)
        revision = self._store.get_revision(
            tenant_id=actor.tenant_id,
            revision_id=revision_id,
        )
        if revision.created_by == actor.subject:
            raise ControlPlaneAuthorizationError(
                "revision author cannot request their own rollback deployment"
            )
        return self._store.request_rollback(
            actor=actor,
            revision_id=revision_id,
            expected_predecessor_operation_id=(
                expected_predecessor_operation_id
            ),
            requested_at=now,
        )

    def retry_deployment(
        self,
        actor: Actor,
        failed_operation_id: str,
    ) -> DeploymentOperation:
        now = self._time()
        self._authorize(actor, role="deployer", privileged=True, now=now)
        failed = self._store.get_deployment_operation(
            tenant_id=actor.tenant_id,
            operation_id=failed_operation_id,
        )
        revision = self._store.get_revision(
            tenant_id=actor.tenant_id,
            revision_id=failed.revision_id,
        )
        if revision.created_by == actor.subject:
            raise ControlPlaneAuthorizationError(
                "revision author cannot request their own deployment retry"
            )
        return self._store.request_deployment_retry(
            actor=actor,
            failed_operation_id=failed_operation_id,
            requested_at=now,
        )

    def deployment_operation(
        self,
        actor: Actor,
        operation_id: str,
    ) -> DeploymentOperation:
        now = self._time()
        self._authorize(actor, role="viewer", privileged=False, now=now)
        return self._store.get_deployment_operation(
            tenant_id=actor.tenant_id,
            operation_id=operation_id,
        )

    def deployment_operations(
        self,
        actor: Actor,
        control_id: str,
        *,
        limit: int = 100,
    ) -> tuple[DeploymentOperation, ...]:
        now = self._time()
        self._authorize(actor, role="viewer", privileged=False, now=now)
        return self._store.list_deployment_operations(
            tenant_id=actor.tenant_id,
            control_id=control_id,
            limit=limit,
        )

    def applied_deployment_operation(
        self,
        actor: Actor,
        control_id: str,
    ) -> DeploymentOperation:
        now = self._time()
        self._authorize(actor, role="viewer", privileged=False, now=now)
        return self._store.latest_applied_operation(
            tenant_id=actor.tenant_id,
            control_id=control_id,
        )

    def audit_events(
        self,
        actor: Actor,
        *,
        after_sequence: int = 0,
        limit: int = 1_000,
    ) -> tuple[AuditEvent, ...]:
        now = self._time()
        self._authorize(actor, role="auditor", privileged=False, now=now)
        return self._store.audit_events(
            tenant_id=actor.tenant_id,
            after_sequence=after_sequence,
            limit=limit,
        )

    def verify_audit_chain(self, actor: Actor) -> tuple[int, str]:
        now = self._time()
        self._authorize(actor, role="auditor", privileged=False, now=now)
        return self._store.verify_audit_chain(tenant_id=actor.tenant_id)
