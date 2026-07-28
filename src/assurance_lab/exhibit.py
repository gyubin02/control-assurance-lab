"""Bundle-derived result for the fixed financial-support case."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel as PydanticBaseModel
from pydantic import ConfigDict, Field, model_validator

from assurance_lab.baseline import (
    BaselineComparison,
    BaselineVerdict,
    MetricObservation,
    compare_final_outcome_only_with_v3,
)
from assurance_lab.contract import (
    DIGEST_PATTERN,
    BooleanValue,
    CellSelector,
    IntegerValue,
    Stage,
    StringValue,
)
from assurance_lab.evaluation import (
    EvaluationReport,
    ExecutedStageEvent,
    ExerciseState,
    ExperimentEvaluator,
    ResidualClassification,
    SkippedStageEvent,
    TruthValue,
)
from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.scenarios.financial_support_e2e import (
    FinancialSupportBundleRepository,
    FinancialSupportStageArtifact,
)

Digest = Annotated[str, Field(pattern=DIGEST_PATTERN)]
BundleId = Annotated[str, Field(pattern=r"^cab:sha256:[a-f0-9]{64}$")]
ClaimRole = Literal["target", "guard", "path", "benign"]


class BaseModel(PydanticBaseModel):
    """Strict immutable public case value object."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        revalidate_instances="always",
    )


class CaseLimitation(StrEnum):
    SIMULATED_TIME = "simulated-time"
    INTEGRITY_ONLY = "integrity-only-no-origin-authentication"
    SINGLE_SYNTHETIC_SCENARIO = "single-synthetic-scenario"


class StageArtifactReference(BaseModel):
    trial_key: Digest
    event_id: str = Field(min_length=1)
    stage: Stage
    artifact_digest: Digest


class CurrentCaseObservation(BaseModel):
    trial_key: Digest
    selected_records: int = Field(ge=0)
    guard_blocked: bool
    delivered_records: int = Field(ge=0)


class GuardState(StrEnum):
    EXECUTED_ALLOWED = "executed_allowed"
    EXECUTED_BLOCKED = "executed_blocked"
    SKIPPED_BY_TARGET = "skipped_by_target"


class AttackMatrixCell(BaseModel):
    trial_key: Digest
    target_level: str = Field(min_length=1)
    compensator_level: str = Field(min_length=1)
    selected_records: int = Field(ge=0)
    guard_state: GuardState
    delivered_records: int = Field(ge=0)
    target_artifact_digest: Digest
    compensator_artifact_digest: Digest | None
    outcome_artifact_digest: Digest


class PrimaryClaimSummary(BaseModel):
    role: ClaimRole
    obligation_id: str = Field(min_length=1)
    truth: TruthValue
    exercise: ExerciseState
    evidence_ids: tuple[Digest, ...]


class BenignOutcomeObservation(BaseModel):
    trial_key: Digest
    assigned_records_delivered: int = Field(ge=0)
    artifact_digest: Digest


class MaskingInvariant(BaseModel):
    name: Literal["baseline_pass_vs_refuted_masked_target"] = (
        "baseline_pass_vs_refuted_masked_target"
    )
    holds: bool


class FinancialSupportCaseResult(BaseModel):
    schema_name: Literal["assurance-lab.financial-support-case-result/v1"] = (
        "assurance-lab.financial-support-case-result/v1"
    )
    bundle_id: BundleId
    profile: Literal["integrity-only"]
    time_basis: Literal["simulated"]
    limitations: tuple[CaseLimitation, ...] = Field(min_length=1)
    evaluation: EvaluationReport
    comparison: BaselineComparison
    current: CurrentCaseObservation
    steady_attack_matrix: tuple[AttackMatrixCell, ...] = Field(
        min_length=4,
        max_length=4,
    )
    primary_claims: tuple[PrimaryClaimSummary, ...] = Field(
        min_length=4,
        max_length=4,
    )
    benign_outcomes: tuple[BenignOutcomeObservation, ...] = Field(
        min_length=8,
        max_length=8,
    )
    stage_artifacts: tuple[StageArtifactReference, ...] = Field(min_length=1)
    invariant: MaskingInvariant

    @model_validator(mode="after")
    def one_bundle_one_derivation(self) -> FinancialSupportCaseResult:
        spec_digest = self.evaluation.compiled_experiment.spec_digest
        if self.comparison.spec_digest != spec_digest:
            raise ValueError("baseline and v3 results must share one bundled specification")
        actual_invariant = (
            self.comparison.baseline.verdict == BaselineVerdict.PASS
            and self.comparison.v3.target_truth == TruthValue.REFUTED
            and self.comparison.v3.residual_classification
            == ResidualClassification.MASKED_TARGET_FAILURE
        )
        if self.invariant.holds != actual_invariant:
            raise ValueError("masking invariant status does not match the derived decisions")
        digests = [item.artifact_digest for item in self.stage_artifacts]
        if len(set(digests)) != len(digests):
            raise ValueError("stage artifact digests must be unique")
        benign_keys = [item.trial_key for item in self.benign_outcomes]
        if len(set(benign_keys)) != len(benign_keys):
            raise ValueError("benign outcome trials must be unique")
        profile = self.evaluation.compiled_experiment.contract.profile
        current_target = _string_level(profile.target.current, "current target")
        current_compensator = _string_level(
            profile.compensator.current,
            "current compensator",
        )
        current_cells = tuple(
            item
            for item in self.steady_attack_matrix
            if item.target_level == current_target and item.compensator_level == current_compensator
        )
        if len(current_cells) != 1:
            raise ValueError("steady attack matrix has no unique current cell")
        current_cell = current_cells[0]
        expected_guard_state = (
            GuardState.EXECUTED_BLOCKED
            if self.current.guard_blocked
            else GuardState.EXECUTED_ALLOWED
        )
        if (
            current_cell.trial_key != self.current.trial_key
            or current_cell.selected_records != self.current.selected_records
            or current_cell.delivered_records != self.current.delivered_records
            or current_cell.guard_state != expected_guard_state
        ):
            raise ValueError("current facts disagree with the steady attack matrix")
        expected_claim_ids: dict[ClaimRole, str] = {
            "target": profile.primary_target_obligation_id,
            "guard": profile.primary_compensator_obligation_id,
            "path": profile.primary_path_obligation_id,
            "benign": profile.primary_benign_obligation_id,
        }
        claims: dict[ClaimRole, PrimaryClaimSummary] = {
            item.role: item for item in self.primary_claims
        }
        if set(claims) != set(expected_claim_ids):
            raise ValueError("primary claim roles are incomplete")
        assessments = {item.obligation_id: item for item in self.evaluation.obligation_assessments}
        for role, obligation_id in expected_claim_ids.items():
            claim = claims[role]
            assessment = assessments.get(obligation_id)
            if (
                assessment is None
                or claim.obligation_id != obligation_id
                or claim.truth != assessment.truth
                or claim.exercise != assessment.exercise
                or claim.evidence_ids != assessment.evidence_ids
            ):
                raise ValueError("primary claim summary disagrees with the evaluator report")
        return self


def recompute_case(bundle_root: Path) -> FinancialSupportCaseResult:
    """Recompute both decisions and the displayed facts from one verified bundle."""

    repository = FinancialSupportBundleRepository(bundle_root)
    time_basis = repository.time_basis
    if time_basis != "simulated":
        raise ValueError("case exhibit supports only explicitly simulated evidence")
    compiled = repository.compiled_experiment
    report = ExperimentEvaluator().evaluate(
        compiled,
        repository.trial_records,
        repository,
        repository,
        repository,
    )
    observations, stage_references = _raw_observations(repository)
    comparison = compare_final_outcome_only_with_v3(
        compiled,
        observations,
        report,
    )
    current = _current_observation(repository)
    attack_matrix = _steady_attack_matrix(repository)
    primary_claims = _primary_claims(report)
    benign = _benign_observations(repository)
    invariant_holds = (
        comparison.baseline.verdict == BaselineVerdict.PASS
        and comparison.v3.target_truth == TruthValue.REFUTED
        and comparison.v3.residual_classification == ResidualClassification.MASKED_TARGET_FAILURE
    )
    limitations = (
        CaseLimitation.SIMULATED_TIME,
        CaseLimitation.INTEGRITY_ONLY,
        CaseLimitation.SINGLE_SYNTHETIC_SCENARIO,
    )
    return FinancialSupportCaseResult(
        bundle_id=repository.bundle_id,
        profile=repository.bundle_profile,
        time_basis=time_basis,
        limitations=limitations,
        evaluation=report,
        comparison=comparison,
        current=current,
        steady_attack_matrix=attack_matrix,
        primary_claims=primary_claims,
        benign_outcomes=benign,
        stage_artifacts=stage_references,
        invariant=MaskingInvariant(holds=invariant_holds),
    )


def _raw_observations(
    repository: FinancialSupportBundleRepository,
) -> tuple[tuple[MetricObservation, ...], tuple[StageArtifactReference, ...]]:
    profile = repository.compiled_experiment.contract.profile
    observations: list[MetricObservation] = []
    references: list[StageArtifactReference] = []
    for record in repository.trial_records:
        for stage in Stage:
            try:
                artifact = repository.stage_artifact(record.trial_key, stage)
            except KeyError:
                continue
            digest = _stage_digest(artifact)
            event = record.trace.event_for(stage)
            if not isinstance(event, ExecutedStageEvent) or event.evidence_bundle_digest != digest:
                raise ValueError("raw stage artifact does not match its verified trace event")
            references.append(
                StageArtifactReference(
                    trial_key=record.trial_key,
                    event_id=artifact.event_id,
                    stage=stage,
                    artifact_digest=digest,
                )
            )
            if stage == Stage.TARGET:
                observations.append(
                    MetricObservation(
                        trial_key=record.trial_key,
                        stage=stage,
                        metric_id=profile.target_metric_id,
                        value=IntegerValue(
                            value=_integer_value(
                                artifact,
                                "out_of_scope_records_selected",
                            )
                        ),
                    )
                )
            elif stage == Stage.COMPENSATOR:
                observations.append(
                    MetricObservation(
                        trial_key=record.trial_key,
                        stage=stage,
                        metric_id=profile.compensator_metric_id,
                        value=BooleanValue(
                            value=_boolean_value(
                                artifact,
                                "unapproved_release_blocked",
                            )
                        ),
                    )
                )
            elif stage == Stage.OUTCOME:
                observations.extend(
                    (
                        MetricObservation(
                            trial_key=record.trial_key,
                            stage=stage,
                            metric_id=profile.outcome_metric_id,
                            value=IntegerValue(
                                value=_integer_value(
                                    artifact,
                                    "out_of_scope_records_delivered",
                                )
                            ),
                        ),
                        MetricObservation(
                            trial_key=record.trial_key,
                            stage=stage,
                            metric_id=profile.benign_outcome_metric_id,
                            value=IntegerValue(
                                value=_integer_value(
                                    artifact,
                                    "assigned_case_records_delivered",
                                )
                            ),
                        ),
                    )
                )
    return tuple(observations), tuple(references)


def _current_observation(
    repository: FinancialSupportBundleRepository,
) -> CurrentCaseObservation:
    compiled = repository.compiled_experiment
    current_cells = tuple(
        cell for cell in compiled.cells if cell.selector == compiled.current_selector
    )
    if len(current_cells) != 1:
        raise ValueError("bundled compiler plan has no unique current cell")
    current_trials = tuple(
        trial for trial in compiled.planned_trials if trial.cell_key == current_cells[0].key
    )
    if len(current_trials) != 1:
        raise ValueError("case exhibit requires one current-cell trial")
    trial = current_trials[0]
    target = repository.stage_artifact(trial.key, Stage.TARGET)
    compensator = repository.stage_artifact(trial.key, Stage.COMPENSATOR)
    outcome = repository.stage_artifact(trial.key, Stage.OUTCOME)
    return CurrentCaseObservation(
        trial_key=trial.key,
        selected_records=_integer_value(
            target,
            "out_of_scope_records_selected",
        ),
        guard_blocked=_boolean_value(
            compensator,
            "unapproved_release_blocked",
        ),
        delivered_records=_integer_value(
            outcome,
            "out_of_scope_records_delivered",
        ),
    )


def _benign_observations(
    repository: FinancialSupportBundleRepository,
) -> tuple[BenignOutcomeObservation, ...]:
    compiled = repository.compiled_experiment
    cells = {cell.key: cell.selector for cell in compiled.cells}
    benign_input = compiled.contract.profile.input.benign
    results: list[BenignOutcomeObservation] = []
    for trial in compiled.planned_trials:
        if cells[trial.cell_key].input != benign_input:
            continue
        artifact = repository.stage_artifact(trial.key, Stage.OUTCOME)
        results.append(
            BenignOutcomeObservation(
                trial_key=trial.key,
                assigned_records_delivered=_integer_value(
                    artifact,
                    "assigned_case_records_delivered",
                ),
                artifact_digest=_stage_digest(artifact),
            )
        )
    if len(results) != 8:
        raise ValueError("case exhibit requires eight benign factorial outcomes")
    return tuple(results)


def _steady_attack_matrix(
    repository: FinancialSupportBundleRepository,
) -> tuple[AttackMatrixCell, ...]:
    compiled = repository.compiled_experiment
    profile = compiled.contract.profile
    planned_by_cell = {trial.cell_key: trial for trial in compiled.planned_trials}
    generated_by_selector = {cell.selector.model_dump_json(): cell for cell in compiled.cells}
    results: list[AttackMatrixCell] = []
    for target in (profile.target.ineffective, profile.target.effective):
        for compensator in (profile.compensator.off, profile.compensator.on):
            selector = CellSelector(
                input=profile.input.attack,
                target=target,
                compensator=compensator,
                sham=profile.sham.steady,
            )
            cell = generated_by_selector.get(selector.model_dump_json())
            if cell is None:
                raise ValueError("bundled compiler plan is missing an attack matrix cell")
            trial = planned_by_cell.get(cell.key)
            if trial is None:
                raise ValueError("attack matrix cell has no planned trial")
            record = next(item for item in repository.trial_records if item.trial_key == trial.key)
            target_artifact = repository.stage_artifact(trial.key, Stage.TARGET)
            outcome_artifact = repository.stage_artifact(trial.key, Stage.OUTCOME)
            try:
                compensator_artifact = repository.stage_artifact(
                    trial.key,
                    Stage.COMPENSATOR,
                )
            except KeyError:
                if not isinstance(record.trace.compensator, SkippedStageEvent):
                    raise ValueError("missing guard artifact has no causal skip") from None
                guard_state = GuardState.SKIPPED_BY_TARGET
                compensator_digest = None
            else:
                guard_state = (
                    GuardState.EXECUTED_BLOCKED
                    if _boolean_value(
                        compensator_artifact,
                        "unapproved_release_blocked",
                    )
                    else GuardState.EXECUTED_ALLOWED
                )
                compensator_digest = _stage_digest(compensator_artifact)
            results.append(
                AttackMatrixCell(
                    trial_key=trial.key,
                    target_level=_string_level(target, "target"),
                    compensator_level=_string_level(compensator, "compensator"),
                    selected_records=_integer_value(
                        target_artifact,
                        "out_of_scope_records_selected",
                    ),
                    guard_state=guard_state,
                    delivered_records=_integer_value(
                        outcome_artifact,
                        "out_of_scope_records_delivered",
                    ),
                    target_artifact_digest=_stage_digest(target_artifact),
                    compensator_artifact_digest=compensator_digest,
                    outcome_artifact_digest=_stage_digest(outcome_artifact),
                )
            )
    return tuple(results)


def _primary_claims(
    report: EvaluationReport,
) -> tuple[PrimaryClaimSummary, ...]:
    profile = report.compiled_experiment.contract.profile
    claims: tuple[tuple[ClaimRole, str], ...] = (
        ("target", profile.primary_target_obligation_id),
        ("guard", profile.primary_compensator_obligation_id),
        ("path", profile.primary_path_obligation_id),
        ("benign", profile.primary_benign_obligation_id),
    )
    assessments = {item.obligation_id: item for item in report.obligation_assessments}
    results: list[PrimaryClaimSummary] = []
    for role, obligation_id in claims:
        assessment = assessments.get(obligation_id)
        if assessment is None:
            raise ValueError(f"evaluator report is missing primary {role} claim")
        results.append(
            PrimaryClaimSummary(
                role=role,
                obligation_id=obligation_id,
                truth=assessment.truth,
                exercise=assessment.exercise,
                evidence_ids=assessment.evidence_ids,
            )
        )
    return tuple(results)


def _stage_digest(artifact: FinancialSupportStageArtifact) -> str:
    return (
        "sha256:"
        + hashlib.sha256(canonical_json_bytes(artifact.model_dump(mode="json"))).hexdigest()
    )


def _integer_value(
    artifact: FinancialSupportStageArtifact,
    name: str,
) -> int:
    value = artifact.value(name)
    if type(value) is not int:
        raise ValueError(f"raw stage field {name!r} is not an integer")
    return value


def _boolean_value(
    artifact: FinancialSupportStageArtifact,
    name: str,
) -> bool:
    value = artifact.value(name)
    if type(value) is not bool:
        raise ValueError(f"raw stage field {name!r} is not a boolean")
    return value


def _string_level(value: object, name: str) -> str:
    if not isinstance(value, StringValue):
        raise ValueError(f"{name} level is not a string")
    return value.value
