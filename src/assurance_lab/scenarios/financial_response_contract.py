"""Compiled contract for the financial exact-session response experiment.

The incident-response claim is deliberately narrow: the one compromised
session named by the incident must be revoked.  Quarantining its principal is
a separate, downstream control and cannot stand in for that revocation.
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

SCENARIO_ID = "financial-exact-session-response"

ATTACK = StringValue(value="compromised-old-session-replay")
BENIGN = StringValue(value="unrelated-support-normal-action")
TARGET_INEFFECTIVE = StringValue(value="report-only")
TARGET_EFFECTIVE = StringValue(value="revoke-exact")
COMPENSATOR_OFF = StringValue(value="quarantine-off")
COMPENSATOR_ON = StringValue(value="quarantine-on")
SHAM_STEADY = StringValue(value="steady")
SHAM_RELOAD = StringValue(value="responder-reload")

TARGET_COMPONENT = "session-revoker"
COMPENSATOR_COMPONENT = "principal-quarantine"
OUTCOME_COMPONENT = "identity-gateway"

COMPROMISED_PRINCIPAL_ID = "support-017"
COMPROMISED_SESSION_ID = "SYNTH-SESSION-SUPPORT-017-OLD"
SIBLING_SESSION_ID = "SYNTH-SESSION-SUPPORT-017-CURRENT"
UNRELATED_PRINCIPAL_ID = "support-042"
UNRELATED_SESSION_ID = "SYNTH-SESSION-SUPPORT-042-CURRENT"


def action_descriptor(level: StringValue) -> dict[str, Any]:
    """Return the fixed semantic action whose canonical digest is contracted."""

    common: dict[str, Any] = {
        "schema": "assurance-lab.identity-session-action/v1",
        "data_class": "synthetic-customer-confidential",
    }
    if level == ATTACK:
        return {
            **common,
            "action": ATTACK.value,
            "principal_id": COMPROMISED_PRINCIPAL_ID,
            "session_id": COMPROMISED_SESSION_ID,
            "request_id": "SYNTH-REQUEST-REPLAY-000001",
            "operation": "read-support-workbench",
        }
    if level == BENIGN:
        return {
            **common,
            "action": BENIGN.value,
            "principal_id": UNRELATED_PRINCIPAL_ID,
            "session_id": UNRELATED_SESSION_ID,
            "request_id": "SYNTH-REQUEST-NORMAL-000001",
            "operation": "read-assigned-case-summary",
        }
    raise ValueError(f"unsupported financial response input level: {level.value!r}")


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
    extractor_id: str,
    evidence_class: str,
) -> MetricContract:
    return MetricContract(
        id=identifier,
        component=component,
        stage=stage,
        value_type=MetricValueType.BOOLEAN,
        unit=None,
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
    expected: bool,
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
            expected=BooleanValue(value=expected),
        ),
        quantifier=AllTested(min_trials=min_trials),
    )


def build_financial_response_contract(
    *,
    scope: ExperimentScope,
    plan: TrialPlan,
) -> ExperimentContract:
    """Describe the fixed 2x2x2x2 response experiment."""

    if scope.scenario_id != SCENARIO_ID:
        raise ValueError(f"scope scenario_id must be {SCENARIO_ID!r}")

    repetitions = len(plan.blocks) * plan.replicates
    target_metric = _metric(
        "compromised-session-active",
        component=TARGET_COMPONENT,
        stage=Stage.TARGET,
        extractor_id="exact-session-readback-v1",
        evidence_class="session-store-readback",
    )
    specificity_metric = _metric(
        "non-target-sessions-active",
        component=TARGET_COMPONENT,
        stage=Stage.TARGET,
        extractor_id="exact-session-isolation-readback-v1",
        evidence_class="session-store-readback",
    )
    response_status_metric = _metric(
        "response-action-reported-success",
        component=TARGET_COMPONENT,
        stage=Stage.TARGET,
        extractor_id="responder-status-v1",
        evidence_class="responder-status",
    )
    compensator_metric = _metric(
        "compromised-principal-quarantined",
        component=COMPENSATOR_COMPONENT,
        stage=Stage.COMPENSATOR,
        extractor_id="principal-quarantine-readback-v1",
        evidence_class="identity-store-readback",
    )
    outcome_metric = _metric(
        "compromised-session-replay-denied",
        component=OUTCOME_COMPONENT,
        stage=Stage.OUTCOME,
        extractor_id="identity-gateway-replay-v1",
        evidence_class="gateway-decision",
    )
    benign_metric = _metric(
        "unrelated-support-principal-available",
        component=OUTCOME_COMPONENT,
        stage=Stage.OUTCOME,
        extractor_id="identity-gateway-benign-v1",
        evidence_class="gateway-decision",
    )

    current = _current_selector()
    obligations = (
        _obligation(
            "current-exact-session-revoked",
            subject=COMPROMISED_SESSION_ID,
            component=TARGET_COMPONENT,
            scope=ObligationScope.TARGET_LOCAL,
            selector=current,
            metric_id=target_metric.id,
            expected=False,
            min_trials=repetitions,
        ),
        _obligation(
            "current-principal-quarantined",
            subject=COMPROMISED_PRINCIPAL_ID,
            component=COMPENSATOR_COMPONENT,
            scope=ObligationScope.COMPENSATOR_LOCAL,
            selector=current,
            metric_id=compensator_metric.id,
            expected=True,
            min_trials=repetitions,
        ),
        _obligation(
            "current-replay-denied",
            subject=COMPROMISED_SESSION_ID,
            component=OUTCOME_COMPONENT,
            scope=ObligationScope.PATH,
            selector=current,
            metric_id=outcome_metric.id,
            expected=True,
            min_trials=repetitions,
        ),
        _obligation(
            "unrelated-support-service-envelope",
            subject=UNRELATED_PRINCIPAL_ID,
            component=OUTCOME_COMPONENT,
            scope=ObligationScope.PATH,
            selector=CellSelector(input=BENIGN),
            metric_id=benign_metric.id,
            expected=True,
            min_trials=repetitions * 8,
        ),
        _obligation(
            "revoke-exact-preserves-non-target-sessions",
            subject=f"all-sessions-except-{COMPROMISED_SESSION_ID}",
            component=TARGET_COMPONENT,
            scope=ObligationScope.TARGET_LOCAL,
            selector=CellSelector(
                input=ATTACK,
                target=TARGET_EFFECTIVE,
            ),
            metric_id=specificity_metric.id,
            expected=True,
            min_trials=repetitions * 4,
        ),
    )

    return ExperimentContract(
        id=SCENARIO_ID,
        version="3.0.0",
        scope=scope,
        metrics=(
            target_metric,
            specificity_metric,
            response_status_metric,
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
            sham=ShamAxis(steady=SHAM_STEADY, redeploy=SHAM_RELOAD),
            outcome_component=OUTCOME_COMPONENT,
            target_metric_id=target_metric.id,
            compensator_metric_id=compensator_metric.id,
            outcome_metric_id=outcome_metric.id,
            benign_outcome_metric_id=benign_metric.id,
            target_safe_value=BooleanValue(value=False),
            compensator_safe_value=BooleanValue(value=True),
            outcome_safe_value=BooleanValue(value=True),
            benign_safe_value=BooleanValue(value=True),
            primary_target_obligation_id=obligations[0].id,
            primary_compensator_obligation_id=obligations[1].id,
            primary_path_obligation_id=obligations[2].id,
            primary_benign_obligation_id=obligations[3].id,
            target_attack_relation=MetricRelation(
                operator=RelationOperator.TRUE_TO_FALSE
            ),
            target_benign_relation=MetricRelation(operator=RelationOperator.EQUAL),
            sham_relation=MetricRelation(operator=RelationOperator.EQUAL),
            compensator_attack_relation=MetricRelation(
                operator=RelationOperator.FALSE_TO_TRUE
            ),
        ),
        plan=plan,
    )
