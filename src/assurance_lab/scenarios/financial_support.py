"""Pure reference model for the support-export scenario.

The model is an oracle for fixtures and seeded faults. It does not inspect the
implementation under test and must not be used by the runtime services to make
their decisions.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import AwareDatetime, BaseModel, Field, model_validator


class EntitlementMode(StrEnum):
    CASE_SCOPED = "case_scoped"
    WILDCARD_MISGRANT = "wildcard_misgrant"


class ReleaseGuardMode(StrEnum):
    MONITOR_ONLY = "monitor_only"
    ENFORCE = "enforce"


class ActorRole(StrEnum):
    SUPPORT = "support"
    COMPLIANCE = "compliance"


class DataClass(StrEnum):
    CUSTOMER_CONFIDENTIAL = "customer_confidential"


class AuthorizationDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class ReleaseDecision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    NOT_REACHED = "not_reached"


class ReleaseApproval(BaseModel):
    approval_id: str = Field(min_length=1)
    principal_id: str = Field(min_length=1)
    customer_ids: frozenset[str] = Field(min_length=1)
    max_records: int = Field(ge=1)
    valid_from: AwareDatetime
    valid_until: AwareDatetime

    @model_validator(mode="after")
    def coherent_window(self) -> ReleaseApproval:
        if self.valid_until <= self.valid_from:
            raise ValueError("release approval must end after it starts")
        return self

    def permits(
        self,
        *,
        principal_id: str,
        customer_ids: frozenset[str],
        record_count: int,
        as_of: datetime,
    ) -> bool:
        return (
            self.principal_id == principal_id
            and self.valid_from <= as_of <= self.valid_until
            and customer_ids.issubset(self.customer_ids)
            and record_count <= self.max_records
        )


class SupportExportInput(BaseModel):
    trace_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    principal_id: str = Field(min_length=1)
    role: ActorRole
    assigned_customer_ids: frozenset[str] = Field(default_factory=frozenset)
    requested_customer_ids: frozenset[str] = Field(min_length=1)
    records_per_customer: int = Field(ge=1)
    data_class: DataClass = DataClass.CUSTOMER_CONFIDENTIAL
    entitlement_mode: EntitlementMode
    release_guard_mode: ReleaseGuardMode
    bulk_threshold_records: int = Field(ge=1)
    approval: ReleaseApproval | None = None
    as_of: AwareDatetime


class SupportExportOutcome(BaseModel):
    authorization_reached: bool
    authorization_decision: AuthorizationDecision
    out_of_scope_customer_count: int = Field(ge=0)
    out_of_scope_records_selected: int = Field(ge=0)
    selected_record_count: int = Field(ge=0)
    release_guard_reached: bool
    release_guard_decision: ReleaseDecision
    delivered_record_count: int = Field(ge=0)
    final_exfiltration: bool
    approval_valid: bool


def evaluate_support_export(request: SupportExportInput) -> SupportExportOutcome:
    """Calculate the expected result without calling any scenario service."""

    requested = request.requested_customer_ids
    outside_assignment = requested - request.assigned_customer_ids
    selected_records = len(requested) * request.records_per_customer
    outside_records = len(outside_assignment) * request.records_per_customer

    if request.role == ActorRole.SUPPORT:
        allowed = (
            request.entitlement_mode == EntitlementMode.WILDCARD_MISGRANT
            or requested.issubset(request.assigned_customer_ids)
        )
    else:
        allowed = True

    if not allowed:
        return SupportExportOutcome(
            authorization_reached=True,
            authorization_decision=AuthorizationDecision.DENY,
            out_of_scope_customer_count=len(outside_assignment),
            out_of_scope_records_selected=0,
            selected_record_count=0,
            release_guard_reached=False,
            release_guard_decision=ReleaseDecision.NOT_REACHED,
            delivered_record_count=0,
            final_exfiltration=False,
            approval_valid=False,
        )

    approval_valid = bool(
        request.approval
        and request.approval.permits(
            principal_id=request.principal_id,
            customer_ids=request.requested_customer_ids,
            record_count=selected_records,
            as_of=request.as_of,
        )
    )
    unapproved_sensitive_bulk = (
        request.data_class == DataClass.CUSTOMER_CONFIDENTIAL
        and selected_records >= request.bulk_threshold_records
        and not approval_valid
    )
    blocked = request.release_guard_mode == ReleaseGuardMode.ENFORCE and unapproved_sensitive_bulk
    delivered_records = 0 if blocked else selected_records
    return SupportExportOutcome(
        authorization_reached=True,
        authorization_decision=AuthorizationDecision.ALLOW,
        out_of_scope_customer_count=len(outside_assignment),
        out_of_scope_records_selected=outside_records,
        selected_record_count=selected_records,
        release_guard_reached=True,
        release_guard_decision=(ReleaseDecision.BLOCK if blocked else ReleaseDecision.ALLOW),
        delivered_record_count=delivered_records,
        final_exfiltration=delivered_records > 0 and outside_records > 0,
        approval_valid=approval_valid,
    )
