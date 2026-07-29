"""Contract for the synthetic entitlement-restore recovery experiment.

The lifecycle verifier owns session cutover.  This experiment receives one
fixed, independently readable cutover state: the compromised old session is
revoked, a distinct replacement is active, and that replacement is bound to
the entitlement-set digest restored in the selected target cell.
"""

from __future__ import annotations

import hashlib
from typing import Any

import rfc8785

from assurance_lab.contract import (
    AllTested,
    BooleanValue,
    CellSelector,
    CompensatorControlAxis,
    ExperimentContract,
    ExperimentScope,
    InputAxis,
    IntegerValue,
    MetricContract,
    MetricRelation,
    MetricValueType,
    Obligation,
    ObligationScope,
    Predicate,
    PredicateOperator,
    PreventiveNonMaskingProfile,
    RelationOperator,
    ShamAxis,
    Stage,
    StringValue,
    Subject,
    TargetControlAxis,
    TrialPlan,
)

SCENARIO_ID = "financial-entitlement-recovery"

ATTACK = StringValue(value="out-of-scope-export-retest")
BENIGN = StringValue(value="assigned-case-export-retest")
TARGET_INEFFECTIVE = StringValue(value="stale-wildcard")
TARGET_EFFECTIVE = StringValue(value="approved-case-scoped")
COMPENSATOR_OFF = StringValue(value="monitor-only")
COMPENSATOR_ON = StringValue(value="enforce")
SHAM_STEADY = StringValue(value="steady")
SHAM_REAPPLY = StringValue(value="snapshot-reapply")

TARGET_COMPONENT = "restored-entitlement-boundary"
COMPENSATOR_COMPONENT = "release-gateway"
OUTCOME_COMPONENT = "recovery-client"

PRINCIPAL_ID = "support-017"
OLD_SESSION_ID = "SYNTH-SESSION-SUPPORT-017-OLD"
# The action is stable across the matched target contrast.  A lifecycle branch
# resolves this role to its own independently produced replacement session.
ACTIVE_REPLACEMENT_SESSION_ROLE = "active-replacement"
REPLACEMENT_SESSION_ID = "SYNTH-SESSION-SUPPORT-017-REPLACEMENT"
COMPARISON_REPLACEMENT_SESSION_ID = (
    "SYNTH-SESSION-SUPPORT-017-REPLACEMENT-COMPARISON"
)
APPROVED_CASE_ID = "CASE-000017"
APPROVED_CUSTOMER_ID = "SYNTH-CUSTOMER-000017"

STALE_SNAPSHOT_ID = "SYNTH-ENTITLEMENT-SNAPSHOT-STALE"
APPROVED_SNAPSHOT_ID = "SYNTH-ENTITLEMENT-SNAPSHOT-APPROVED"
STALE_ENTITLEMENTS = ("customer:*",)
APPROVED_ENTITLEMENTS = (f"customer:{APPROVED_CUSTOMER_ID}",)


def action_descriptor(level: StringValue) -> dict[str, Any]:
    """Return one of the two fixed, entirely synthetic recovery retests."""

    common: dict[str, Any] = {
        "schema": "assurance-lab.recovery-export-action/v1",
        "principal_id": PRINCIPAL_ID,
        "session_role": ACTIVE_REPLACEMENT_SESSION_ROLE,
        "data_class": "synthetic-customer-confidential",
        "purpose": "post-restore-control-retest",
    }
    if level == ATTACK:
        return {
            **common,
            "action": ATTACK.value,
            "request_id": "SYNTH-RECOVERY-RETEST-ATTACK-000001",
            "requested_customer_ids": [
                f"SYNTH-CUSTOMER-{index:06d}" for index in range(21, 31)
            ],
        }
    if level == BENIGN:
        return {
            **common,
            "action": BENIGN.value,
            "request_id": "SYNTH-RECOVERY-RETEST-BENIGN-000001",
            "assigned_case_id": APPROVED_CASE_ID,
            "requested_customer_ids": [APPROVED_CUSTOMER_ID],
        }
    raise ValueError(f"unsupported financial recovery input level: {level.value!r}")


def entitlement_set_descriptor(level: StringValue) -> dict[str, Any]:
    """Return the exact restored entitlement set for one target level."""

    if level == TARGET_INEFFECTIVE:
        entitlements = STALE_ENTITLEMENTS
    elif level == TARGET_EFFECTIVE:
        entitlements = APPROVED_ENTITLEMENTS
    else:
        raise ValueError(
            f"unsupported financial recovery target level: {level.value!r}"
        )
    return {
        "schema": "assurance-lab.recovery-entitlement-set/v1",
        "principal_id": PRINCIPAL_ID,
        "entitlements": list(entitlements),
    }


def snapshot_descriptor(level: StringValue) -> dict[str, Any]:
    """Return the immutable snapshot identity and its restored entitlements."""

    if level == TARGET_INEFFECTIVE:
        snapshot_id = STALE_SNAPSHOT_ID
    elif level == TARGET_EFFECTIVE:
        snapshot_id = APPROVED_SNAPSHOT_ID
    else:
        raise ValueError(
            f"unsupported financial recovery target level: {level.value!r}"
        )
    return {
        "schema": "assurance-lab.recovery-entitlement-snapshot/v1",
        "snapshot_id": snapshot_id,
        "principal_id": PRINCIPAL_ID,
        "restore_operation_id": "SYNTH-RESTORE-OPERATION-000001",
        "entitlement_set": entitlement_set_descriptor(level),
    }


def session_identity_descriptor(session_id: str) -> dict[str, str]:
    """Return the canonical identity bound into lifecycle session digests."""

    if session_id not in {
        OLD_SESSION_ID,
        REPLACEMENT_SESSION_ID,
        COMPARISON_REPLACEMENT_SESSION_ID,
    }:
        raise ValueError("unsupported synthetic recovery session identity")
    return {
        "schema": "assurance-lab.synthetic-session-identity/v1",
        "session_id": session_id,
    }


def _digest(value: dict[str, Any]) -> str:
    return f"sha256:{hashlib.sha256(rfc8785.dumps(value)).hexdigest()}"


ATTACK_ACTION_DIGEST = _digest(action_descriptor(ATTACK))
BENIGN_ACTION_DIGEST = _digest(action_descriptor(BENIGN))
STALE_ENTITLEMENT_SET_DIGEST = _digest(
    entitlement_set_descriptor(TARGET_INEFFECTIVE)
)
APPROVED_ENTITLEMENT_SET_DIGEST = _digest(
    entitlement_set_descriptor(TARGET_EFFECTIVE)
)
STALE_SNAPSHOT_DIGEST = _digest(snapshot_descriptor(TARGET_INEFFECTIVE))
APPROVED_SNAPSHOT_DIGEST = _digest(snapshot_descriptor(TARGET_EFFECTIVE))
OLD_SESSION_DIGEST = _digest(session_identity_descriptor(OLD_SESSION_ID))
REPLACEMENT_SESSION_DIGEST = _digest(
    session_identity_descriptor(REPLACEMENT_SESSION_ID)
)
COMPARISON_REPLACEMENT_SESSION_DIGEST = _digest(
    session_identity_descriptor(COMPARISON_REPLACEMENT_SESSION_ID)
)


def _current_selector() -> CellSelector:
    return CellSelector(
        input=ATTACK,
        target=TARGET_INEFFECTIVE,
        compensator=COMPENSATOR_ON,
        sham=SHAM_STEADY,
    )


def _metric(
    identifier: str,
    *,
    component: str,
    stage: Stage,
    value_type: MetricValueType,
    unit: str | None,
    extractor_id: str,
    evidence_class: str,
) -> MetricContract:
    return MetricContract(
        id=identifier,
        component=component,
        stage=stage,
        value_type=value_type,
        unit=unit,
        extractor_id=extractor_id,
        evidence_class=evidence_class,
    )


def _obligation(
    identifier: str,
    *,
    subject: str,
    component: str,
    scope: ObligationScope,
    selector: CellSelector,
    metric_id: str,
    expected: IntegerValue | BooleanValue,
    min_trials: int,
) -> Obligation:
    return Obligation(
        id=identifier,
        subject=Subject(identifier=subject, component=component),
        scope=scope,
        selector=selector,
        predicate=Predicate(
            metric_id=metric_id,
            operator=PredicateOperator.EQUAL,
            expected=expected,
        ),
        quantifier=AllTested(min_trials=min_trials),
    )


def build_financial_recovery_contract(
    *,
    scope: ExperimentScope,
    plan: TrialPlan,
) -> ExperimentContract:
    """Describe the fixed 2x2x2x2 entitlement-recovery experiment."""

    if scope.scenario_id != SCENARIO_ID:
        raise ValueError(f"scope scenario_id must be {SCENARIO_ID!r}")

    repetitions = len(plan.blocks) * plan.replicates
    target_metric = _metric(
        "out-of-scope-records-selected",
        component=TARGET_COMPONENT,
        stage=Stage.TARGET,
        value_type=MetricValueType.INTEGER,
        unit="records",
        extractor_id="recovery-selection-audit-v1",
        evidence_class="selection-readback",
    )
    snapshot_identity_metric = _metric(
        "snapshot-identity-matches-declared-target",
        component=TARGET_COMPONENT,
        stage=Stage.TARGET,
        value_type=MetricValueType.BOOLEAN,
        unit=None,
        extractor_id="restored-snapshot-digest-readback-v1",
        evidence_class="snapshot-readback",
    )
    guard_metric = _metric(
        "unapproved-release-blocked",
        component=COMPENSATOR_COMPONENT,
        stage=Stage.COMPENSATOR,
        value_type=MetricValueType.BOOLEAN,
        unit=None,
        extractor_id="release-gateway-decision-v1",
        evidence_class="release-gateway-readback",
    )
    outcome_metric = _metric(
        "out-of-scope-records-delivered",
        component=OUTCOME_COMPONENT,
        stage=Stage.OUTCOME,
        value_type=MetricValueType.INTEGER,
        unit="records",
        extractor_id="recovery-client-out-of-scope-receipt-v1",
        evidence_class="client-receipt",
    )
    benign_metric = _metric(
        "assigned-case-records-delivered",
        component=OUTCOME_COMPONENT,
        stage=Stage.OUTCOME,
        value_type=MetricValueType.INTEGER,
        unit="records",
        extractor_id="recovery-client-assigned-case-receipt-v1",
        evidence_class="client-receipt",
    )
    disclosure_unchanged_metric = _metric(
        "prior-disclosure-reference-unchanged",
        component=OUTCOME_COMPONENT,
        stage=Stage.OUTCOME,
        value_type=MetricValueType.BOOLEAN,
        unit=None,
        extractor_id="lifecycle-ledger-reference-identity-v1",
        evidence_class="lifecycle-ledger-reference",
    )
    old_session_metric = _metric(
        "old-session-revoked",
        component=TARGET_COMPONENT,
        stage=Stage.TARGET,
        value_type=MetricValueType.BOOLEAN,
        unit=None,
        extractor_id="recovery-cutover-readback-v1",
        evidence_class="session-store-readback",
    )
    replacement_session_metric = _metric(
        "replacement-session-active",
        component=TARGET_COMPONENT,
        stage=Stage.TARGET,
        value_type=MetricValueType.BOOLEAN,
        unit=None,
        extractor_id="recovery-cutover-readback-v1",
        evidence_class="session-store-readback",
    )
    replacement_binding_metric = _metric(
        "replacement-session-entitlement-digest-bound",
        component=TARGET_COMPONENT,
        stage=Stage.TARGET,
        value_type=MetricValueType.BOOLEAN,
        unit=None,
        extractor_id="recovery-session-entitlement-binding-v1",
        evidence_class="session-store-readback",
    )
    cutover_provenance_metric = _metric(
        "cutover-lifecycle-reference-bound",
        component=TARGET_COMPONENT,
        stage=Stage.TARGET,
        value_type=MetricValueType.BOOLEAN,
        unit=None,
        extractor_id="lifecycle-cutover-reference-readback-v1",
        evidence_class="lifecycle-snapshot-reference",
    )
    sham_receipt_metric = _metric(
        "snapshot-reapply-receipt-valid",
        component=TARGET_COMPONENT,
        stage=Stage.TARGET,
        value_type=MetricValueType.BOOLEAN,
        unit=None,
        extractor_id="snapshot-apply-receipt-readback-v1",
        evidence_class="apply-operation-receipt",
    )
    cleanup_metric = _metric(
        "clone-cleanup-verified",
        component=OUTCOME_COMPONENT,
        stage=Stage.OUTCOME,
        value_type=MetricValueType.BOOLEAN,
        unit=None,
        extractor_id="sqlite-clone-close-attestation-v1",
        evidence_class="cleanup-attestation",
    )

    current = _current_selector()
    obligations = (
        _obligation(
            "current-restored-entitlement-boundary",
            subject=PRINCIPAL_ID,
            component=TARGET_COMPONENT,
            scope=ObligationScope.TARGET_LOCAL,
            selector=current,
            metric_id=target_metric.id,
            expected=IntegerValue(value=0),
            min_trials=repetitions,
        ),
        _obligation(
            "current-release-guard",
            subject="out-of-scope-recovery-export",
            component=COMPENSATOR_COMPONENT,
            scope=ObligationScope.COMPENSATOR_LOCAL,
            selector=current,
            metric_id=guard_metric.id,
            expected=BooleanValue(value=True),
            min_trials=repetitions,
        ),
        _obligation(
            "current-recovery-delivery-path",
            subject=f"{PRINCIPAL_ID}-negative-export-retest",
            component=OUTCOME_COMPONENT,
            scope=ObligationScope.PATH,
            selector=current,
            metric_id=outcome_metric.id,
            expected=IntegerValue(value=0),
            min_trials=repetitions,
        ),
        _obligation(
            "assigned-case-service-envelope",
            subject=f"{PRINCIPAL_ID}-assigned-case-retest",
            component=OUTCOME_COMPONENT,
            scope=ObligationScope.PATH,
            selector=CellSelector(input=BENIGN),
            metric_id=benign_metric.id,
            expected=IntegerValue(value=1),
            min_trials=repetitions * 8,
        ),
        _obligation(
            "restored-snapshot-identity",
            subject="declared-recovery-snapshot",
            component=TARGET_COMPONENT,
            scope=ObligationScope.TARGET_LOCAL,
            selector=CellSelector(),
            metric_id=snapshot_identity_metric.id,
            expected=BooleanValue(value=True),
            min_trials=repetitions * 16,
        ),
        _obligation(
            "lifecycle-disclosure-reference-preserved",
            subject="bound-lifecycle-disclosure-ledger",
            component=OUTCOME_COMPONENT,
            scope=ObligationScope.PATH,
            selector=CellSelector(),
            metric_id=disclosure_unchanged_metric.id,
            expected=BooleanValue(value=True),
            min_trials=repetitions * 16,
        ),
        _obligation(
            "old-session-remains-revoked-at-retest",
            subject=OLD_SESSION_ID,
            component=TARGET_COMPONENT,
            scope=ObligationScope.TARGET_LOCAL,
            selector=CellSelector(),
            metric_id=old_session_metric.id,
            expected=BooleanValue(value=True),
            min_trials=repetitions * 16,
        ),
        _obligation(
            "replacement-session-is-active-at-retest",
            subject=ACTIVE_REPLACEMENT_SESSION_ROLE,
            component=TARGET_COMPONENT,
            scope=ObligationScope.TARGET_LOCAL,
            selector=CellSelector(),
            metric_id=replacement_session_metric.id,
            expected=BooleanValue(value=True),
            min_trials=repetitions * 16,
        ),
        _obligation(
            "replacement-session-binds-restored-entitlements",
            subject=ACTIVE_REPLACEMENT_SESSION_ROLE,
            component=TARGET_COMPONENT,
            scope=ObligationScope.TARGET_LOCAL,
            selector=CellSelector(),
            metric_id=replacement_binding_metric.id,
            expected=BooleanValue(value=True),
            min_trials=repetitions * 16,
        ),
        _obligation(
            "cutover-reference-binds-verified-lifecycle-snapshot",
            subject="lifecycle-owned-cutover-reference",
            component=TARGET_COMPONENT,
            scope=ObligationScope.TARGET_LOCAL,
            selector=CellSelector(),
            metric_id=cutover_provenance_metric.id,
            expected=BooleanValue(value=True),
            min_trials=repetitions * 16,
        ),
        _obligation(
            "sham-application-has-an-exact-operation-receipt",
            subject="snapshot-reapply-operation",
            component=TARGET_COMPONENT,
            scope=ObligationScope.TARGET_LOCAL,
            selector=CellSelector(),
            metric_id=sham_receipt_metric.id,
            expected=BooleanValue(value=True),
            min_trials=repetitions * 16,
        ),
        _obligation(
            "fresh-clone-is-closed-after-each-trial",
            subject="sqlite-recovery-clone",
            component=OUTCOME_COMPONENT,
            scope=ObligationScope.PATH,
            selector=CellSelector(),
            metric_id=cleanup_metric.id,
            expected=BooleanValue(value=True),
            min_trials=repetitions * 16,
        ),
    )

    return ExperimentContract(
        id=SCENARIO_ID,
        version="3.0.0",
        scope=scope,
        metrics=(
            target_metric,
            snapshot_identity_metric,
            guard_metric,
            outcome_metric,
            benign_metric,
            disclosure_unchanged_metric,
            old_session_metric,
            replacement_session_metric,
            replacement_binding_metric,
            cutover_provenance_metric,
            sham_receipt_metric,
            cleanup_metric,
        ),
        obligations=obligations,
        profile=PreventiveNonMaskingProfile(
            input=InputAxis(
                component=OUTCOME_COMPONENT,
                attack=ATTACK,
                benign=BENIGN,
                attack_action_digest=ATTACK_ACTION_DIGEST,
                benign_action_digest=BENIGN_ACTION_DIGEST,
            ),
            target=TargetControlAxis(
                component=TARGET_COMPONENT,
                ineffective=TARGET_INEFFECTIVE,
                effective=TARGET_EFFECTIVE,
                current=TARGET_INEFFECTIVE,
            ),
            compensator=CompensatorControlAxis(
                component=COMPENSATOR_COMPONENT,
                off=COMPENSATOR_OFF,
                on=COMPENSATOR_ON,
                current=COMPENSATOR_ON,
            ),
            sham=ShamAxis(steady=SHAM_STEADY, redeploy=SHAM_REAPPLY),
            outcome_component=OUTCOME_COMPONENT,
            target_metric_id=target_metric.id,
            compensator_metric_id=guard_metric.id,
            outcome_metric_id=outcome_metric.id,
            benign_outcome_metric_id=benign_metric.id,
            target_safe_value=IntegerValue(value=0),
            compensator_safe_value=BooleanValue(value=True),
            outcome_safe_value=IntegerValue(value=0),
            benign_safe_value=IntegerValue(value=1),
            primary_target_obligation_id=obligations[0].id,
            primary_compensator_obligation_id=obligations[1].id,
            primary_path_obligation_id=obligations[2].id,
            primary_benign_obligation_id=obligations[3].id,
            target_attack_relation=MetricRelation(
                operator=RelationOperator.DECREASES
            ),
            target_benign_relation=MetricRelation(operator=RelationOperator.EQUAL),
            sham_relation=MetricRelation(operator=RelationOperator.EQUAL),
            compensator_attack_relation=MetricRelation(
                operator=RelationOperator.DECREASES
            ),
        ),
        plan=plan,
    )
