from __future__ import annotations

from test_evaluation import (
    current_trial_keys,
    evaluate,
    make_record,
    metric_evidence,
)
from test_financial_support_contract import _compiled

from assurance_lab.baseline import (
    BaselineVerdict,
    MetricObservation,
    compare_final_outcome_only_with_v3,
)
from assurance_lab.contract import BooleanValue, IntegerValue, Stage
from assurance_lab.evaluation import (
    AdmittedMetricEvidence,
    MetricEvidenceResult,
    ResidualClassification,
    TruthValue,
)


def test_outcome_only_baseline_masks_the_refuted_current_target() -> None:
    compiled = _compiled()
    records = [
        make_record(compiled, trial_key)
        for trial_key in current_trial_keys(compiled)
    ]
    profile = compiled.contract.profile
    raw_observations: list[MetricObservation] = []
    metric_overrides: dict[tuple[str, Stage, str], MetricEvidenceResult] = {}

    for record in records:
        values = (
            (
                Stage.TARGET,
                profile.target_metric_id,
                IntegerValue(value=10),
            ),
            (
                Stage.COMPENSATOR,
                profile.compensator_metric_id,
                BooleanValue(value=True),
            ),
            (
                Stage.OUTCOME,
                profile.outcome_metric_id,
                IntegerValue(value=0),
            ),
        )
        for stage, metric_id, value in values:
            coordinate = (record.trial_key, stage, metric_id)
            raw_observations.append(
                MetricObservation(
                    trial_key=record.trial_key,
                    stage=stage,
                    metric_id=metric_id,
                    value=value,
                )
            )
            admitted = metric_evidence(
                compiled,
                record,
                stage,
                metric_id,
                False,
            ).model_copy(update={"value": value})
            assert isinstance(admitted, AdmittedMetricEvidence)
            metric_overrides[coordinate] = admitted

    report = evaluate(
        compiled,
        records,
        {},
        metric_overrides=metric_overrides,
    )
    comparison = compare_final_outcome_only_with_v3(
        compiled,
        raw_observations,
        report,
    )

    assert comparison.baseline.verdict == BaselineVerdict.PASS
    assert comparison.v3.target_truth == TruthValue.REFUTED
    assert (
        comparison.v3.residual_classification
        == ResidualClassification.MASKED_TARGET_FAILURE
    )
    assert comparison.baseline.ignored_observation_count == 4
    assert all(
        observation.value == IntegerValue(value=0)
        for observation in comparison.baseline.evaluated_observations
    )

    machine_readable = comparison.model_dump(mode="json")
    assert machine_readable["baseline"]["baseline"] == "final_outcome_only"
    assert machine_readable["baseline"]["verdict"] == "pass"
    assert machine_readable["v3"] == {
        "evaluator": "preventive_non_masking_v3",
        "target_truth": "refuted",
        "residual_classification": "masked_target_failure",
    }
