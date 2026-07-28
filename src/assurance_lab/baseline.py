"""Explicit outcome-only baseline for comparison with the v3 evaluator."""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel as PydanticBaseModel
from pydantic import ConfigDict, Field

from assurance_lab.contract import (
    DIGEST_PATTERN,
    CompiledExperiment,
    IntegerValue,
    Stage,
    TypedValue,
)
from assurance_lab.evaluation import (
    EvaluationReport,
    ResidualClassification,
    TruthValue,
)

Digest = Annotated[str, Field(pattern=DIGEST_PATTERN)]


class BaseModel(PydanticBaseModel):
    """Strict immutable comparison value object."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        revalidate_instances="always",
    )


class BaselineVerdict(StrEnum):
    PASS = "pass"
    FAIL = "fail"


class MetricObservation(BaseModel):
    """One raw metric value before either evaluator derives a decision."""

    trial_key: Digest
    stage: Stage
    metric_id: str = Field(min_length=1)
    value: TypedValue


class FinalOutcomeOnlyResult(BaseModel):
    baseline: Literal["final_outcome_only"] = "final_outcome_only"
    verdict: BaselineVerdict
    outcome_metric_id: str = Field(min_length=1)
    safe_value: IntegerValue
    evaluated_observations: tuple[MetricObservation, ...] = Field(min_length=1)
    ignored_observation_count: int = Field(ge=0)


class V3ResultSummary(BaseModel):
    evaluator: Literal["preventive_non_masking_v3"] = "preventive_non_masking_v3"
    target_truth: TruthValue
    residual_classification: ResidualClassification


class BaselineComparison(BaseModel):
    """Machine-readable decisions derived from one declared observation set."""

    spec_digest: Digest
    raw_observations: tuple[MetricObservation, ...] = Field(min_length=1)
    baseline: FinalOutcomeOnlyResult
    v3: V3ResultSummary


def evaluate_final_outcome_only(
    compiled: CompiledExperiment,
    observations: Sequence[MetricObservation],
) -> FinalOutcomeOnlyResult:
    """Judge only the current attack cell's final delivered-count metric."""

    profile = compiled.contract.profile
    if compiled.current_selector.input != profile.input.attack:
        raise ValueError("compiled current selector is not the attack input")
    if not isinstance(profile.outcome_safe_value, IntegerValue):
        raise ValueError("final_outcome_only requires an integer outcome safe value")
    if profile.outcome_safe_value.value != 0:
        raise ValueError("final_outcome_only requires safe delivered count 0")

    current_cells = tuple(
        cell for cell in compiled.cells if cell.selector == compiled.current_selector
    )
    if len(current_cells) != 1:
        raise ValueError("compiled experiment must contain exactly one current cell")
    current_cell_key = current_cells[0].key
    expected_trial_keys = tuple(
        trial.key
        for trial in compiled.planned_trials
        if trial.cell_key == current_cell_key
    )

    relevant: dict[str, MetricObservation] = {}
    for observation in observations:
        if (
            observation.trial_key not in expected_trial_keys
            or observation.stage != Stage.OUTCOME
            or observation.metric_id != profile.outcome_metric_id
        ):
            continue
        if observation.trial_key in relevant:
            raise ValueError("duplicate current-cell final outcome observation")
        if not isinstance(observation.value, IntegerValue):
            raise ValueError("final delivered metric observation must be an integer")
        relevant[observation.trial_key] = observation

    missing = tuple(key for key in expected_trial_keys if key not in relevant)
    if missing:
        raise ValueError("missing current-cell final outcome observation")

    evaluated = tuple(relevant[key] for key in expected_trial_keys)
    verdict = (
        BaselineVerdict.PASS
        if all(
            isinstance(observation.value, IntegerValue)
            and observation.value.value == profile.outcome_safe_value.value
            for observation in evaluated
        )
        else BaselineVerdict.FAIL
    )
    return FinalOutcomeOnlyResult(
        verdict=verdict,
        outcome_metric_id=profile.outcome_metric_id,
        safe_value=profile.outcome_safe_value,
        evaluated_observations=evaluated,
        ignored_observation_count=len(observations) - len(evaluated),
    )


def compare_final_outcome_only_with_v3(
    compiled: CompiledExperiment,
    observations: Sequence[MetricObservation],
    v3_report: EvaluationReport,
) -> BaselineComparison:
    """Place the naive baseline and v3 non-masking decision side by side."""

    if v3_report.compiled_experiment.spec_digest != compiled.spec_digest:
        raise ValueError("v3 report does not belong to the compiled experiment")
    target_id = compiled.contract.profile.primary_target_obligation_id
    target = next(
        (
            assessment
            for assessment in v3_report.obligation_assessments
            if assessment.obligation_id == target_id
        ),
        None,
    )
    if target is None:
        raise ValueError("v3 report is missing the primary target assessment")

    raw_observations = tuple(observations)
    return BaselineComparison(
        spec_digest=compiled.spec_digest,
        raw_observations=raw_observations,
        baseline=evaluate_final_outcome_only(compiled, raw_observations),
        v3=V3ResultSummary(
            target_truth=target.truth,
            residual_classification=v3_report.residual_summary.classification,
        ),
    )
