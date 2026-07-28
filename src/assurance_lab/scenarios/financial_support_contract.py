"""Compiled experiment contract for the financial support-export scenario."""

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

SCENARIO_ID = "financial-support-export"

ATTACK = StringValue(value="out-of-case-bulk-export")
BENIGN = StringValue(value="assigned-case-summary")
TARGET_INEFFECTIVE = StringValue(value="wildcard-misgrant")
TARGET_EFFECTIVE = StringValue(value="case-scoped")
COMPENSATOR_OFF = StringValue(value="monitor-only")
COMPENSATOR_ON = StringValue(value="enforce")
SHAM_STEADY = BooleanValue(value=False)
SHAM_REDEPLOY = BooleanValue(value=True)

TARGET_COMPONENT = "authorization-boundary"
COMPENSATOR_COMPONENT = "release-gateway"
OUTCOME_COMPONENT = "support-client"


def action_descriptor(level: StringValue) -> dict[str, Any]:
    """Return the immutable semantic input whose digest the runner must attest."""

    common: dict[str, Any] = {
        "schema": "assurance-lab.support-action/v1",
        "principal_id": "support-017",
        "role": "support",
        "data_class": "customer_confidential",
    }
    if level == ATTACK:
        return {
            **common,
            "action": ATTACK.value,
            "requested_customer_ids": [
                f"SYNTH-CUSTOMER-{index:06d}" for index in range(21, 31)
            ],
            "records_per_customer": 1,
        }
    if level == BENIGN:
        return {
            **common,
            "action": BENIGN.value,
            "requested_customer_ids": ["SYNTH-CUSTOMER-000017"],
            "records_per_customer": 1,
        }
    raise ValueError(f"unsupported financial support input level: {level.value!r}")


def _action_digest(level: StringValue) -> str:
    return f"sha256:{hashlib.sha256(rfc8785.dumps(action_descriptor(level))).hexdigest()}"


ATTACK_ACTION_DIGEST = _action_digest(ATTACK)
BENIGN_ACTION_DIGEST = _action_digest(BENIGN)


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


def build_financial_support_contract(
    *,
    scope: ExperimentScope,
    plan: TrialPlan,
) -> ExperimentContract:
    """Describe the fixed experiment without supplying any observed result."""

    if scope.scenario_id != SCENARIO_ID:
        raise ValueError(f"scope scenario_id must be {SCENARIO_ID!r}")

    repetitions = len(plan.blocks) * plan.replicates
    target_metric = _metric(
        "out-of-scope-records-selected",
        component=TARGET_COMPONENT,
        stage=Stage.TARGET,
        value_type=MetricValueType.INTEGER,
        unit="records",
        extractor_id="joined-policy-database-audit-v1",
        evidence_class="trace-joined-selection-audit",
    )
    compensator_metric = _metric(
        "unapproved-release-blocked",
        component=COMPENSATOR_COMPONENT,
        stage=Stage.COMPENSATOR,
        value_type=MetricValueType.BOOLEAN,
        unit=None,
        extractor_id="gateway-release-decision-v1",
        evidence_class="gateway-decision",
    )
    outcome_metric = _metric(
        "out-of-scope-records-delivered",
        component=OUTCOME_COMPONENT,
        stage=Stage.OUTCOME,
        value_type=MetricValueType.INTEGER,
        unit="records",
        extractor_id="client-out-of-scope-receipt-v1",
        evidence_class="client-receipt",
    )
    benign_metric = _metric(
        "assigned-case-records-delivered",
        component=OUTCOME_COMPONENT,
        stage=Stage.OUTCOME,
        value_type=MetricValueType.INTEGER,
        unit="records",
        extractor_id="client-assigned-case-receipt-v1",
        evidence_class="client-receipt",
    )

    target_safe = IntegerValue(value=0)
    compensator_safe = BooleanValue(value=True)
    outcome_safe = IntegerValue(value=0)
    benign_safe = IntegerValue(value=1)

    obligations = (
        _obligation(
            "current-selection-boundary",
            subject="support-017",
            component=TARGET_COMPONENT,
            scope=ObligationScope.TARGET_LOCAL,
            selector=_current_selector(),
            metric_id=target_metric.id,
            expected=target_safe,
            min_trials=repetitions,
        ),
        _obligation(
            "current-release-guard",
            subject="unapproved-sensitive-bulk-response",
            component=COMPENSATOR_COMPONENT,
            scope=ObligationScope.COMPENSATOR_LOCAL,
            selector=_current_selector(),
            metric_id=compensator_metric.id,
            expected=compensator_safe,
            min_trials=repetitions,
        ),
        _obligation(
            "current-delivery-path",
            subject="support-017-out-of-case-export",
            component=OUTCOME_COMPONENT,
            scope=ObligationScope.PATH,
            selector=_current_selector(),
            metric_id=outcome_metric.id,
            expected=outcome_safe,
            min_trials=repetitions,
        ),
        _obligation(
            "assigned-case-service-envelope",
            subject="support-017-assigned-case-summary",
            component=OUTCOME_COMPONENT,
            scope=ObligationScope.PATH,
            selector=CellSelector(input=BENIGN),
            metric_id=benign_metric.id,
            expected=benign_safe,
            min_trials=repetitions * 8,
        ),
    )

    return ExperimentContract(
        id=SCENARIO_ID,
        version="3.0.0",
        scope=scope,
        metrics=(
            target_metric,
            compensator_metric,
            outcome_metric,
            benign_metric,
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
            sham=ShamAxis(steady=SHAM_STEADY, redeploy=SHAM_REDEPLOY),
            outcome_component=OUTCOME_COMPONENT,
            target_metric_id=target_metric.id,
            compensator_metric_id=compensator_metric.id,
            outcome_metric_id=outcome_metric.id,
            benign_outcome_metric_id=benign_metric.id,
            target_safe_value=target_safe,
            compensator_safe_value=compensator_safe,
            outcome_safe_value=outcome_safe,
            benign_safe_value=benign_safe,
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
