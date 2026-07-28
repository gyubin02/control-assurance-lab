from datetime import UTC, datetime, timedelta

import pytest

from assurance_lab.scenarios.financial_support import (
    ActorRole,
    AuthorizationDecision,
    EntitlementMode,
    ReleaseApproval,
    ReleaseDecision,
    ReleaseGuardMode,
    SupportExportInput,
    evaluate_support_export,
)

NOW = datetime(2026, 7, 29, 1, 0, tzinfo=UTC)
ASSIGNED = frozenset({"SYNTH-CUSTOMER-000017"})
OUTSIDE = frozenset(
    {
        "SYNTH-CUSTOMER-000201",
        "SYNTH-CUSTOMER-000202",
    }
)


def request(
    entitlement: EntitlementMode,
    guard: ReleaseGuardMode,
) -> SupportExportInput:
    return SupportExportInput(
        trace_id="1" * 32,
        principal_id="support-017",
        role=ActorRole.SUPPORT,
        assigned_customer_ids=ASSIGNED,
        requested_customer_ids=OUTSIDE,
        records_per_customer=100,
        entitlement_mode=entitlement,
        release_guard_mode=guard,
        bulk_threshold_records=100,
        as_of=NOW,
    )


@pytest.mark.parametrize(
    ("entitlement", "guard", "selected", "reached", "delivered", "exfiltrated"),
    [
        (
            EntitlementMode.WILDCARD_MISGRANT,
            ReleaseGuardMode.MONITOR_ONLY,
            200,
            True,
            200,
            True,
        ),
        (
            EntitlementMode.WILDCARD_MISGRANT,
            ReleaseGuardMode.ENFORCE,
            200,
            True,
            0,
            False,
        ),
        (
            EntitlementMode.CASE_SCOPED,
            ReleaseGuardMode.MONITOR_ONLY,
            0,
            False,
            0,
            False,
        ),
        (
            EntitlementMode.CASE_SCOPED,
            ReleaseGuardMode.ENFORCE,
            0,
            False,
            0,
            False,
        ),
    ],
)
def test_primary_non_masking_matrix(
    entitlement: EntitlementMode,
    guard: ReleaseGuardMode,
    selected: int,
    reached: bool,
    delivered: int,
    exfiltrated: bool,
) -> None:
    outcome = evaluate_support_export(request(entitlement, guard))

    assert outcome.out_of_scope_records_selected == selected
    assert outcome.release_guard_reached is reached
    assert outcome.delivered_record_count == delivered
    assert outcome.final_exfiltration is exfiltrated


def test_assigned_case_support_lookup_still_works() -> None:
    outcome = evaluate_support_export(
        SupportExportInput(
            trace_id="2" * 32,
            principal_id="support-017",
            role=ActorRole.SUPPORT,
            assigned_customer_ids=ASSIGNED,
            requested_customer_ids=ASSIGNED,
            records_per_customer=1,
            entitlement_mode=EntitlementMode.CASE_SCOPED,
            release_guard_mode=ReleaseGuardMode.ENFORCE,
            bulk_threshold_records=100,
            as_of=NOW,
        )
    )

    assert outcome.authorization_decision == AuthorizationDecision.ALLOW
    assert outcome.release_guard_decision == ReleaseDecision.ALLOW
    assert outcome.delivered_record_count == 1


def test_approved_compliance_bulk_is_not_a_security_success_false_positive() -> None:
    approval = ReleaseApproval(
        approval_id="REL-0001",
        principal_id="compliance-002",
        customer_ids=OUTSIDE,
        max_records=250,
        valid_from=NOW - timedelta(minutes=5),
        valid_until=NOW + timedelta(minutes=5),
    )
    outcome = evaluate_support_export(
        SupportExportInput(
            trace_id="3" * 32,
            principal_id="compliance-002",
            role=ActorRole.COMPLIANCE,
            requested_customer_ids=OUTSIDE,
            records_per_customer=100,
            entitlement_mode=EntitlementMode.CASE_SCOPED,
            release_guard_mode=ReleaseGuardMode.ENFORCE,
            bulk_threshold_records=100,
            approval=approval,
            as_of=NOW,
        )
    )

    assert outcome.approval_valid is True
    assert outcome.release_guard_decision == ReleaseDecision.ALLOW
    assert outcome.delivered_record_count == 200


def test_expired_approval_is_evaluated_at_declared_time() -> None:
    expired = ReleaseApproval(
        approval_id="REL-0002",
        principal_id="compliance-002",
        customer_ids=OUTSIDE,
        max_records=250,
        valid_from=NOW - timedelta(hours=2),
        valid_until=NOW - timedelta(hours=1),
    )
    model_input = SupportExportInput(
        trace_id="4" * 32,
        principal_id="compliance-002",
        role=ActorRole.COMPLIANCE,
        requested_customer_ids=OUTSIDE,
        records_per_customer=100,
        entitlement_mode=EntitlementMode.CASE_SCOPED,
        release_guard_mode=ReleaseGuardMode.ENFORCE,
        bulk_threshold_records=100,
        approval=expired,
        as_of=NOW,
    )

    first = evaluate_support_export(model_input)
    second = evaluate_support_export(model_input)

    assert first == second
    assert first.approval_valid is False
    assert first.release_guard_decision == ReleaseDecision.BLOCK
