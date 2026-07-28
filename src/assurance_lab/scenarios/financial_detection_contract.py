"""Contract for the synthetic financial exact-correlation experiment.

The shared compiler calls its four-axis profile ``PreventiveNonMaskingProfile``.
Here it is used only as a strict factorial-design compiler: ``target`` is the
named detector and ``compensator`` is an independent fallback telemetry path.
Detection meaning, including when a missing alert may be treated as a real
absence, belongs to :mod:`financial_detection_runtime`; a safe downstream
alert is never treated as evidence that the named detector worked.
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

SCENARIO_ID = "financial-exact-correlation-detection"

ATTACK = StringValue(value="compromised-session-sensitive-replay")
BENIGN = StringValue(value="assigned-case-summary-read")
TARGET_INEFFECTIVE = StringValue(value="exact-rule-inactive")
TARGET_EFFECTIVE = StringValue(value="exact-rule-active")
COMPENSATOR_OFF = StringValue(value="fallback-drop")
COMPENSATOR_ON = StringValue(value="fallback-forward")
SHAM_STEADY = StringValue(value="collector-steady")
SHAM_RELOAD = StringValue(value="collector-reload")

TARGET_COMPONENT = "exact-correlation-detector"
COMPENSATOR_COMPONENT = "fallback-telemetry-path"
OUTCOME_COMPONENT = "detection-observer"

SOURCE_ID = "SYNTH-SOURCE-SUPPORT-GATEWAY-01"
NAMED_RULE_ID = "financial.session-replay.exact-correlation.v1"
FALLBACK_RULE_ID = "financial.support-risk.broad-fallback.v1"
SIMULATED_CLOCK_ID = "financial-detection-clock-v1"
ALERT_SLO_MS = 2_000


def action_descriptor(level: StringValue) -> dict[str, Any]:
    """Return one fixed semantic input, including its expected source sequence."""

    common: dict[str, Any] = {
        "schema": "assurance-lab.financial-detection-action/v1",
        "source_id": SOURCE_ID,
        "data_class": "synthetic-customer-confidential",
    }
    if level == ATTACK:
        return {
            **common,
            "action": ATTACK.value,
            "principal_id": "support-017",
            "session_id": "SYNTH-SESSION-SUPPORT-017-OLD",
            "request_id": "SYNTH-REQUEST-REPLAY-000001",
            "source_event_plan": [
                {
                    "event_id": "SYNTH-SOURCE-REPLAY-01",
                    "sequence": 7_301,
                    "event_type": "session-authenticated",
                },
                {
                    "event_id": "SYNTH-SOURCE-REPLAY-02",
                    "sequence": 7_302,
                    "event_type": "revoked-session-replay-observed",
                },
                {
                    "event_id": "SYNTH-SOURCE-REPLAY-03",
                    "sequence": 7_303,
                    "event_type": "out-of-assignment-sensitive-read",
                },
            ],
        }
    if level == BENIGN:
        return {
            **common,
            "action": BENIGN.value,
            "principal_id": "support-042",
            "session_id": "SYNTH-SESSION-SUPPORT-042-CURRENT",
            "request_id": "SYNTH-REQUEST-ASSIGNED-000001",
            "source_event_plan": [
                {
                    "event_id": "SYNTH-SOURCE-ASSIGNED-01",
                    "sequence": 8_301,
                    "event_type": "session-authenticated",
                },
                {
                    "event_id": "SYNTH-SOURCE-ASSIGNED-02",
                    "sequence": 8_302,
                    "event_type": "assigned-case-opened",
                },
                {
                    "event_id": "SYNTH-SOURCE-ASSIGNED-03",
                    "sequence": 8_303,
                    "event_type": "assigned-case-summary-read",
                },
            ],
        }
    raise ValueError(f"unsupported financial detection input level: {level.value!r}")


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
            expected=BooleanValue(value=True),
        ),
        quantifier=AllTested(min_trials=min_trials),
    )


def build_financial_detection_contract(
    *,
    scope: ExperimentScope,
    plan: TrialPlan,
) -> ExperimentContract:
    """Describe the fixed suspicious/benign x detector x fallback x sham plan."""

    if scope.scenario_id != SCENARIO_ID:
        raise ValueError(f"scope scenario_id must be {SCENARIO_ID!r}")

    repetitions = len(plan.blocks) * plan.replicates
    target_metric = _metric(
        "named-exact-correlation-alert-proven",
        component=TARGET_COMPONENT,
        stage=Stage.TARGET,
        extractor_id="named-alert-correlation-readback-v1",
        evidence_class="alert-correlation-readback",
    )
    named_identity_metric = _metric(
        "named-alert-identity-unique",
        component=TARGET_COMPONENT,
        stage=Stage.TARGET,
        extractor_id="named-alert-identity-readback-v1",
        evidence_class="alert-store-readback",
    )
    named_rule_metric = _metric(
        "named-alert-rule-identity-bound",
        component=TARGET_COMPONENT,
        stage=Stage.TARGET,
        extractor_id="named-rule-binding-readback-v1",
        evidence_class="alert-store-readback",
    )
    named_binding_metric = _metric(
        "named-alert-trace-source-action-bound",
        component=TARGET_COMPONENT,
        stage=Stage.TARGET,
        extractor_id="named-alert-source-binding-v1",
        evidence_class="trace-joined-alert-readback",
    )
    named_correlation_metric = _metric(
        "named-correlation-evidence-valid",
        component=TARGET_COMPONENT,
        stage=Stage.TARGET,
        extractor_id="named-alert-correlation-proof-v1",
        evidence_class="correlation-artifact",
    )
    compensator_metric = _metric(
        "fallback-telemetry-forwarded",
        component=COMPENSATOR_COMPONENT,
        stage=Stage.COMPENSATOR,
        extractor_id="fallback-forwarding-readback-v1",
        evidence_class="telemetry-store-readback",
    )
    fallback_binding_metric = _metric(
        "fallback-alert-binding-valid",
        component=COMPENSATOR_COMPONENT,
        stage=Stage.COMPENSATOR,
        extractor_id="fallback-alert-binding-v1",
        evidence_class="trace-joined-alert-readback",
    )
    outcome_metric = _metric(
        "any-alert-within-slo",
        component=OUTCOME_COMPONENT,
        stage=Stage.OUTCOME,
        extractor_id="alert-existence-window-v1",
        evidence_class="closed-window-alert-readback",
    )
    benign_metric = _metric(
        "tested-benign-action-unalerted",
        component=OUTCOME_COMPONENT,
        stage=Stage.OUTCOME,
        extractor_id="tested-benign-action-readback-v1",
        evidence_class="closed-window-alert-readback",
    )
    source_binding_metric = _metric(
        "source-trace-action-binding-proven",
        component=OUTCOME_COMPONENT,
        stage=Stage.OUTCOME,
        extractor_id="source-trace-action-binding-v1",
        evidence_class="source-event-readback",
    )
    sequence_metric = _metric(
        "source-sequence-coverage-complete",
        component=OUTCOME_COMPONENT,
        stage=Stage.OUTCOME,
        extractor_id="source-sequence-coverage-v1",
        evidence_class="window-closure-artifact",
    )
    source_health_metric = _metric(
        "source-healthy",
        component=OUTCOME_COMPONENT,
        stage=Stage.OUTCOME,
        extractor_id="source-health-readback-v1",
        evidence_class="window-closure-artifact",
    )
    collector_health_metric = _metric(
        "collector-healthy",
        component=OUTCOME_COMPONENT,
        stage=Stage.OUTCOME,
        extractor_id="collector-health-readback-v1",
        evidence_class="window-closure-artifact",
    )
    collector_completion_metric = _metric(
        "collector-completed",
        component=OUTCOME_COMPONENT,
        stage=Stage.OUTCOME,
        extractor_id="collector-completion-readback-v1",
        evidence_class="window-closure-artifact",
    )
    window_metric = _metric(
        "observation-window-closed",
        component=OUTCOME_COMPONENT,
        stage=Stage.OUTCOME,
        extractor_id="observation-window-closure-v1",
        evidence_class="window-closure-artifact",
    )
    clock_metric = _metric(
        "simulated-clock-bound",
        component=OUTCOME_COMPONENT,
        stage=Stage.OUTCOME,
        extractor_id="simulated-clock-binding-v1",
        evidence_class="window-closure-artifact",
    )

    current = _current_selector()
    obligations = [
        _obligation(
            "current-named-exact-correlation",
            subject=NAMED_RULE_ID,
            component=TARGET_COMPONENT,
            scope=ObligationScope.TARGET_LOCAL,
            selector=current,
            metric_id=target_metric.id,
            min_trials=repetitions,
        ),
        _obligation(
            "current-fallback-forwarding",
            subject=SOURCE_ID,
            component=COMPENSATOR_COMPONENT,
            scope=ObligationScope.COMPENSATOR_LOCAL,
            selector=current,
            metric_id=compensator_metric.id,
            min_trials=repetitions,
        ),
        _obligation(
            "current-alert-existence-path",
            subject="suspicious-replay-alert-path",
            component=OUTCOME_COMPONENT,
            scope=ObligationScope.PATH,
            selector=current,
            metric_id=outcome_metric.id,
            min_trials=repetitions,
        ),
        _obligation(
            "tested-benign-action-unalerted",
            subject="assigned-case-summary-read",
            component=OUTCOME_COMPONENT,
            scope=ObligationScope.PATH,
            selector=CellSelector(input=BENIGN),
            metric_id=benign_metric.id,
            min_trials=repetitions * 8,
        ),
        _obligation(
            "active-rule-detects-suspicious-replay",
            subject=NAMED_RULE_ID,
            component=TARGET_COMPONENT,
            scope=ObligationScope.TARGET_LOCAL,
            selector=CellSelector(input=ATTACK, target=TARGET_EFFECTIVE),
            metric_id=target_metric.id,
            min_trials=repetitions * 4,
        ),
    ]
    obligations.append(
        _obligation(
            "current-fallback-alert-binding",
            subject=FALLBACK_RULE_ID,
            component=COMPENSATOR_COMPONENT,
            scope=ObligationScope.COMPENSATOR_LOCAL,
            selector=current,
            metric_id=fallback_binding_metric.id,
            min_trials=repetitions,
        )
    )
    for identifier, metric in (
        ("current-source-binding", source_binding_metric),
        ("current-source-sequence-coverage", sequence_metric),
        ("current-source-health", source_health_metric),
        ("current-collector-health", collector_health_metric),
        ("current-collector-completion", collector_completion_metric),
        ("current-observation-window-closure", window_metric),
        ("current-simulated-clock-binding", clock_metric),
    ):
        obligations.append(
            _obligation(
                identifier,
                subject="closed-detection-observation",
                component=OUTCOME_COMPONENT,
                scope=ObligationScope.PATH,
                selector=current,
                metric_id=metric.id,
                min_trials=repetitions,
            )
        )

    return ExperimentContract(
        id=SCENARIO_ID,
        version="3.0.0",
        scope=scope,
        metrics=(
            target_metric,
            named_identity_metric,
            named_rule_metric,
            named_binding_metric,
            named_correlation_metric,
            compensator_metric,
            fallback_binding_metric,
            outcome_metric,
            benign_metric,
            source_binding_metric,
            sequence_metric,
            source_health_metric,
            collector_health_metric,
            collector_completion_metric,
            window_metric,
            clock_metric,
        ),
        obligations=tuple(obligations),
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
            target_safe_value=BooleanValue(value=True),
            compensator_safe_value=BooleanValue(value=True),
            outcome_safe_value=BooleanValue(value=True),
            benign_safe_value=BooleanValue(value=True),
            primary_target_obligation_id=obligations[0].id,
            primary_compensator_obligation_id=obligations[1].id,
            primary_path_obligation_id=obligations[2].id,
            primary_benign_obligation_id=obligations[3].id,
            target_attack_relation=MetricRelation(
                operator=RelationOperator.FALSE_TO_TRUE
            ),
            target_benign_relation=MetricRelation(operator=RelationOperator.EQUAL),
            sham_relation=MetricRelation(operator=RelationOperator.EQUAL),
            compensator_attack_relation=MetricRelation(
                operator=RelationOperator.FALSE_TO_TRUE
            ),
        ),
        plan=plan,
    )
