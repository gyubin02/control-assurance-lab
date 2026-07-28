"""Evidence-admitted inference over a compiled preventive-control experiment.

The compiler owns the design.  This module only admits independently verified
trial state and metric evidence, evaluates the declared obligations, and keeps
design, evidence, and cleanup findings separate from local inference.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Literal, Protocol

from pydantic import (
    AwareDatetime,
    ConfigDict,
    Field,
    PositiveInt,
    TypeAdapter,
    field_serializer,
    model_validator,
)
from pydantic import BaseModel as PydanticBaseModel

from assurance_lab.contract import (
    DIGEST_PATTERN,
    AllTested,
    AtLeastRate,
    CellSelector,
    CompiledExperiment,
    ContrastDefinition,
    Exists,
    ExperimentContract,
    MetricContract,
    MetricValueType,
    Obligation,
    ObligationScope,
    PlannedTrial,
    Predicate,
    PredicateOperator,
    RelationOperator,
    Stage,
    TypedValue,
    compile_experiment,
)

Digest = Annotated[str, Field(pattern=DIGEST_PATTERN)]
ArtifactIds = tuple[Digest, ...]


class BaseModel(PydanticBaseModel):
    """Strict immutable evaluator value object."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        revalidate_instances="always",
    )


class ExecutedStageEvent(BaseModel):
    status: Literal["executed"] = "executed"
    event_id: str = Field(min_length=1)
    evidence_bundle_digest: Digest
    stage: Stage
    started_at: AwareDatetime
    ended_at: AwareDatetime
    blocks_downstream: bool = False

    @model_validator(mode="after")
    def ordered(self) -> ExecutedStageEvent:
        if self.ended_at <= self.started_at:
            raise ValueError("stage event must have positive duration")
        return self


class SkippedStageEvent(BaseModel):
    status: Literal["skipped"] = "skipped"
    event_id: str = Field(min_length=1)
    stage: Stage
    blocked_by_event_id: str = Field(min_length=1)


StageEvent = Annotated[
    ExecutedStageEvent | SkippedStageEvent,
    Field(discriminator="status"),
]


class Trace(BaseModel):
    """The fixed execution lineage; the final outcome is always observed."""

    trace_id: str = Field(min_length=1)
    action_digest: Digest
    input: ExecutedStageEvent
    target: StageEvent
    compensator: StageEvent
    outcome: ExecutedStageEvent

    @model_validator(mode="after")
    def fixed_ordered_lineage(self) -> Trace:
        events: tuple[ExecutedStageEvent | SkippedStageEvent, ...] = (
            self.input,
            self.target,
            self.compensator,
            self.outcome,
        )
        expected_stages = (
            Stage.INPUT,
            Stage.TARGET,
            Stage.COMPENSATOR,
            Stage.OUTCOME,
        )
        for event, expected in zip(events, expected_stages, strict=True):
            if event.stage != expected:
                raise ValueError(f"{expected.value} trace slot has stage {event.stage.value}")

        event_ids = [event.event_id for event in events]
        if len(set(event_ids)) != len(event_ids):
            raise ValueError("trace event ids must be unique")

        prior_executed: dict[str, ExecutedStageEvent] = {}
        previous: ExecutedStageEvent | None = None
        for event in events:
            if isinstance(event, SkippedStageEvent):
                blocker = prior_executed.get(event.blocked_by_event_id)
                if blocker is None:
                    raise ValueError(
                        f"skipped {event.stage.value} blocker is not a prior executed event"
                    )
                if not blocker.blocks_downstream:
                    raise ValueError(
                        f"skipped {event.stage.value} blocker did not block downstream"
                    )
                continue
            if previous is not None and event.started_at < previous.ended_at:
                raise ValueError("executed trace events overlap or run out of order")
            prior_executed[event.event_id] = event
            previous = event

        if self.input.blocks_downstream:
            if not isinstance(self.target, SkippedStageEvent):
                raise ValueError("a blocking input requires a skipped target")
            if self.target.blocked_by_event_id != self.input.event_id:
                raise ValueError("a blocking input must be the target's blocker")
            if not isinstance(self.compensator, SkippedStageEvent):
                raise ValueError("a blocking input requires a skipped compensator")
            if self.compensator.blocked_by_event_id != self.input.event_id:
                raise ValueError("a blocking input must be the compensator's blocker")
        if isinstance(self.target, ExecutedStageEvent) and self.target.blocks_downstream:
            if not isinstance(self.compensator, SkippedStageEvent):
                raise ValueError("a blocking target requires a skipped compensator")
            if self.compensator.blocked_by_event_id != self.target.event_id:
                raise ValueError("a blocking target must be the compensator's blocker")
        return self

    def event_for(self, stage: Stage) -> ExecutedStageEvent | SkippedStageEvent:
        return {
            Stage.INPUT: self.input,
            Stage.TARGET: self.target,
            Stage.COMPENSATOR: self.compensator,
            Stage.OUTCOME: self.outcome,
        }[stage]


class FreshClone(BaseModel):
    unique_instance_id: str = Field(min_length=1)
    base_snapshot_digest: Digest
    covariate_digest: Digest
    attestation_bundle_digest: Digest
    runner_resource_id: str = Field(min_length=1)


class CleanupState(StrEnum):
    VERIFIED = "verified"
    FAILED = "failed"


class CleanupReference(BaseModel):
    """Content-addressed cleanup evidence; no caller-asserted outcome."""

    evidence_bundle_digest: Digest


class CleanupBinding(BaseModel):
    spec_digest: Digest
    trial_key: Digest
    trace_id: str = Field(min_length=1)
    clone_unique_instance_id: str = Field(min_length=1)
    runner_resource_id: str = Field(min_length=1)
    evidence_bundle_digest: Digest
    outcome_ended_at: AwareDatetime


class AdmittedCleanupEvidence(BaseModel):
    status: Literal["admitted"] = "admitted"
    state: CleanupState
    binding: CleanupBinding
    evidence_id: Digest
    observed_at: AwareDatetime
    artifact_ids: ArtifactIds = Field(min_length=1)


class CleanupEvidenceFailure(BaseModel):
    status: Literal["rejected", "conflicting", "missing"]
    reason: str = Field(min_length=1)
    evidence_ids: ArtifactIds = ()
    artifact_ids: ArtifactIds = ()


CleanupVerificationResult = Annotated[
    AdmittedCleanupEvidence | CleanupEvidenceFailure,
    Field(discriminator="status"),
]


class TrialRecord(BaseModel):
    """A planned execution reference.  It deliberately has no metric values."""

    spec_digest: Digest
    trial_key: Digest
    cell_key: str = Field(min_length=1)
    block: str = Field(min_length=1)
    replicate: PositiveInt
    clone: FreshClone
    trace: Trace
    cleanup: CleanupReference


class TrialAttestationBinding(BaseModel):
    spec_digest: Digest
    trial_key: Digest
    cell_key: str = Field(min_length=1)
    block: str = Field(min_length=1)
    replicate: PositiveInt
    ordinal: PositiveInt
    trace_id: str = Field(min_length=1)
    action_digest: Digest
    clone_unique_instance_id: str = Field(min_length=1)
    runner_resource_id: str = Field(min_length=1)
    attestation_bundle_digest: Digest


class AdmittedTrialAttestation(BaseModel):
    status: Literal["admitted"] = "admitted"
    evidence_id: Digest
    binding: TrialAttestationBinding
    observed_build_digest: Digest
    observed_dataset_digest: Digest
    observed_fixture_digest: Digest
    executed_ordinal: PositiveInt
    observed_selector: CellSelector
    base_snapshot_digest: Digest
    covariate_digest: Digest
    intervention_digest: Digest
    artifact_ids: ArtifactIds = Field(min_length=1)
    started_at: AwareDatetime
    ended_at: AwareDatetime

    @model_validator(mode="after")
    def ordered(self) -> AdmittedTrialAttestation:
        if self.ended_at <= self.started_at:
            raise ValueError("trial attestation must have positive duration")
        return self


class TrialAttestationFailure(BaseModel):
    status: Literal["rejected", "conflicting", "missing"]
    reason: str = Field(min_length=1)
    evidence_ids: ArtifactIds = ()
    artifact_ids: ArtifactIds = ()
    observed_selectors: tuple[CellSelector, ...] = ()
    observed_digests: ArtifactIds = ()


TrialAttestationResult = Annotated[
    AdmittedTrialAttestation | TrialAttestationFailure,
    Field(discriminator="status"),
]


class EvidenceBinding(BaseModel):
    spec_digest: Digest
    trial_key: Digest
    trace_id: str = Field(min_length=1)
    event_id: str = Field(min_length=1)
    evidence_bundle_digest: Digest
    stage: Stage
    metric_id: str = Field(min_length=1)


class AdmittedMetricEvidence(BaseModel):
    status: Literal["admitted"] = "admitted"
    evidence_id: Digest
    binding: EvidenceBinding
    value: TypedValue
    observed_at: AwareDatetime
    artifact_ids: ArtifactIds = Field(min_length=1)


class MetricEvidenceFailure(BaseModel):
    status: Literal["rejected", "conflicting", "missing"]
    reason: str = Field(min_length=1)
    evidence_ids: ArtifactIds = ()
    artifact_ids: ArtifactIds = ()
    candidate_values: tuple[TypedValue, ...] = ()


MetricEvidenceResult = Annotated[
    AdmittedMetricEvidence | MetricEvidenceFailure,
    Field(discriminator="status"),
]


class TrialAttestationVerifier(Protocol):
    """Verify observed trial state under the compiled evidence policy."""

    def verify(self, record: TrialRecord, /) -> TrialAttestationResult: ...


class EvidenceVerifier(Protocol):
    """Extract and verify one metric solely from its bound stage event."""

    def verify(self, binding: EvidenceBinding, /) -> MetricEvidenceResult: ...


MetricEvidenceVerifier = EvidenceVerifier


class CleanupVerifier(Protocol):
    """Verify post-outcome cleanup without changing historical inference."""

    def verify(self, binding: CleanupBinding, /) -> CleanupVerificationResult: ...


class EvaluationIssue(BaseModel):
    code: str = Field(min_length=1)
    detail: str = Field(min_length=1)
    affected_trial_keys: tuple[Digest, ...] = ()
    affected_cell_keys: tuple[str, ...] = ()
    evidence_ids: ArtifactIds = ()
    artifact_ids: ArtifactIds = ()
    expected_selector: CellSelector | None = None
    observed_selectors: tuple[CellSelector, ...] = ()
    observed_digests: ArtifactIds = ()
    expected_value_type: MetricValueType | None = None
    candidate_values: tuple[TypedValue, ...] = ()


class DesignCompleteness(BaseModel):
    expected_trial_count: int = Field(ge=0)
    received_record_count: int = Field(ge=0)
    missing_trial_keys: tuple[Digest, ...]
    extra_trial_keys: tuple[Digest, ...]
    duplicate_trial_keys: tuple[Digest, ...]
    missing_cell_keys: tuple[str, ...]
    admissible_trial_count: int = Field(ge=0)
    presence_complete: bool
    evidence_complete: bool
    cleanup_complete: bool
    safety_complete: bool
    protocol_complete: bool
    complete: bool


class TruthValue(StrEnum):
    SUPPORTED = "supported"
    REFUTED = "refuted"
    NEITHER = "neither"


class ExerciseState(StrEnum):
    EXERCISED = "exercised"
    PARTIALLY_EXERCISED = "partially_exercised"
    NOT_EXERCISED = "not_exercised"
    UNKNOWN = "unknown"


class TrialPointState(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    UNRESOLVED = "unresolved"


class TrialPointResult(BaseModel):
    trial_key: Digest
    state: TrialPointState
    exercise: ExerciseState
    observed_value: TypedValue | None = None
    reason: str | None = None
    evidence_ids: ArtifactIds = ()
    artifact_ids: ArtifactIds = ()


class ObligationAssessment(BaseModel):
    obligation_id: str = Field(min_length=1)
    truth: TruthValue
    exercise: ExerciseState
    expected_count: int = Field(ge=1)
    executed_count: int = Field(ge=0)
    admitted_count: int = Field(ge=0)
    pass_count: int = Field(ge=0)
    fail_count: int = Field(ge=0)
    unresolved_count: int = Field(ge=0)
    not_exercised_count: int = Field(ge=0)
    unknown_exercise_count: int = Field(ge=0)
    lower_bound: Decimal
    upper_bound: Decimal
    pass_trial_keys: tuple[Digest, ...]
    fail_trial_keys: tuple[Digest, ...]
    unresolved_trial_keys: tuple[Digest, ...]
    evidence_ids: ArtifactIds
    artifact_ids: ArtifactIds
    trial_results: tuple[TrialPointResult, ...]

    @field_serializer("lower_bound", "upper_bound", when_used="json")
    def decimal_text(self, value: Decimal) -> str:
        text = format(value, "f")
        if "." in text:
            text = text.rstrip("0").rstrip(".")
        return text if text and text != "-0" else "0"


class ContrastPairAssessment(BaseModel):
    reference_trial_key: Digest
    comparison_trial_key: Digest
    block: str = Field(min_length=1)
    replicate: PositiveInt
    truth: TruthValue
    reference_value: TypedValue | None = None
    comparison_value: TypedValue | None = None
    unresolved_reason: str | None = None
    evidence_ids: ArtifactIds = ()
    artifact_ids: ArtifactIds = ()


class ContrastAssessment(BaseModel):
    contrast_id: str = Field(min_length=1)
    metric_id: str = Field(min_length=1)
    truth: TruthValue
    expected_pair_count: int = Field(ge=1)
    supported_pair_count: int = Field(ge=0)
    refuted_pair_count: int = Field(ge=0)
    unresolved_pair_count: int = Field(ge=0)
    pairs: tuple[ContrastPairAssessment, ...]
    evidence_ids: ArtifactIds
    artifact_ids: ArtifactIds


class ResidualClassification(StrEnum):
    MASKED_TARGET_FAILURE = "masked_target_failure"
    EXPOSED_PATH = "exposed_path"
    TARGET_EFFECTIVE = "target_effective"
    UNRESOLVED = "unresolved"


class ResidualSummary(BaseModel):
    classification: ResidualClassification
    target_obligation_id: str
    compensator_obligation_id: str
    path_obligation_id: str
    benign_obligation_id: str
    target_truth: TruthValue
    compensator_truth: TruthValue
    path_truth: TruthValue
    benign_truth: TruthValue
    target_exercise: ExerciseState
    compensator_exercise: ExerciseState
    path_exercise: ExerciseState
    benign_exercise: ExerciseState


class EvaluationReport(BaseModel):
    compiled_experiment: CompiledExperiment
    design_completeness: DesignCompleteness
    design_issues: tuple[EvaluationIssue, ...]
    evidence_issues: tuple[EvaluationIssue, ...]
    safety_issues: tuple[EvaluationIssue, ...]
    obligation_assessments: tuple[ObligationAssessment, ...]
    contrast_assessments: tuple[ContrastAssessment, ...]
    residual_summary: ResidualSummary


class EvaluationBoundaryError(ValueError):
    """A malformed compiled plan or evaluator input crossed the trust boundary."""


_ATTESTATION_ADAPTER: TypeAdapter[TrialAttestationResult] = TypeAdapter(TrialAttestationResult)
_EVIDENCE_ADAPTER: TypeAdapter[MetricEvidenceResult] = TypeAdapter(MetricEvidenceResult)
_CLEANUP_ADAPTER: TypeAdapter[CleanupVerificationResult] = TypeAdapter(CleanupVerificationResult)


@dataclass
class _TrialState:
    record: TrialRecord
    valid: bool = True
    invalid_reasons: list[str] = field(default_factory=list)
    attestation: AdmittedTrialAttestation | None = None


@dataclass
class _Context:
    compiled: CompiledExperiment
    states: list[_TrialState]
    evidence_verifier: EvidenceVerifier
    expected_by_key: dict[str, PlannedTrial]
    cells_by_key: dict[str, CellSelector]
    state_by_key: dict[str, _TrialState]
    evidence_issues: list[EvaluationIssue]
    evidence_cache: dict[tuple[str, str, str], AdmittedMetricEvidence | None] = field(
        default_factory=dict
    )
    evidence_failure_reason: dict[tuple[str, str, str], str] = field(default_factory=dict)


class ExperimentEvaluator:
    """Evaluate a compiled experiment without accepting self-reported facts."""

    def evaluate(
        self,
        compiled: CompiledExperiment,
        records: Sequence[TrialRecord],
        attestation_verifier: TrialAttestationVerifier,
        evidence_verifier: EvidenceVerifier,
        cleanup_verifier: CleanupVerifier,
    ) -> EvaluationReport:
        clean_compiled = _recompile(compiled)
        clean_records = tuple(_revalidate_record(record) for record in records)
        expected_by_key = {trial.key: trial for trial in clean_compiled.planned_trials}
        cells_by_key = {cell.key: cell.selector for cell in clean_compiled.cells}
        states = [_TrialState(record=record) for record in clean_records]
        occurrences: defaultdict[str, list[int]] = defaultdict(list)
        for index, state in enumerate(states):
            occurrences[state.record.trial_key].append(index)

        design_issues: list[EvaluationIssue] = []
        evidence_issues: list[EvaluationIssue] = []
        safety_issues: list[EvaluationIssue] = []

        def issue(
            destination: list[EvaluationIssue],
            code: str,
            detail: str,
            indices: Sequence[int] = (),
            *,
            invalidate: bool = False,
            evidence_ids: ArtifactIds = (),
            artifact_ids: ArtifactIds = (),
            affected_cell_keys: tuple[str, ...] = (),
            expected_selector: CellSelector | None = None,
            observed_selectors: tuple[CellSelector, ...] = (),
            observed_digests: ArtifactIds = (),
            expected_value_type: MetricValueType | None = None,
            candidate_values: tuple[TypedValue, ...] = (),
        ) -> None:
            keys = tuple(sorted({states[index].record.trial_key for index in indices}))
            destination.append(
                EvaluationIssue(
                    code=code,
                    detail=detail,
                    affected_trial_keys=keys,
                    affected_cell_keys=affected_cell_keys,
                    evidence_ids=evidence_ids,
                    artifact_ids=artifact_ids,
                    expected_selector=expected_selector,
                    observed_selectors=observed_selectors,
                    observed_digests=observed_digests,
                    expected_value_type=expected_value_type,
                    candidate_values=candidate_values,
                )
            )
            if invalidate:
                for index in indices:
                    states[index].valid = False
                    if code not in states[index].invalid_reasons:
                        states[index].invalid_reasons.append(code)

        missing = tuple(sorted(key for key in expected_by_key if key not in occurrences))
        extra = tuple(sorted(key for key in occurrences if key not in expected_by_key))
        duplicate = tuple(sorted(key for key, indices in occurrences.items() if len(indices) > 1))
        if missing:
            design_issues.append(
                EvaluationIssue(
                    code="missing-planned-trials",
                    detail="one or more compiler-planned trial keys are absent",
                    affected_trial_keys=missing,
                )
            )
        present_cell_keys = {
            expected_by_key[key].cell_key for key in occurrences if key in expected_by_key
        }
        missing_cell_keys = tuple(sorted(set(cells_by_key).difference(present_cell_keys)))
        if missing_cell_keys:
            design_issues.append(
                EvaluationIssue(
                    code="missing-plan-cells",
                    detail="one or more compiler-generated cells have no trial record",
                    affected_trial_keys=tuple(
                        key for key in missing if expected_by_key[key].cell_key in missing_cell_keys
                    ),
                    affected_cell_keys=missing_cell_keys,
                )
            )
        for key in extra:
            issue(
                design_issues,
                "unknown-trial-key",
                "record has no compiler-planned trial key",
                occurrences[key],
                invalidate=True,
            )
        for key in duplicate:
            issue(
                design_issues,
                "duplicate-trial-key",
                "compiler-planned trial key occurs more than once",
                occurrences[key],
                invalidate=True,
            )

        identity_wrong: set[str] = set()
        for index, state in enumerate(states):
            planned = expected_by_key.get(state.record.trial_key)
            if planned is None:
                continue
            mismatches: list[str] = []
            if state.record.spec_digest != clean_compiled.spec_digest:
                mismatches.append("spec_digest")
            if state.record.cell_key != planned.cell_key:
                mismatches.append("cell_key")
            if state.record.block != planned.block:
                mismatches.append("block")
            if state.record.replicate != planned.replicate:
                mismatches.append("replicate")
            if mismatches:
                identity_wrong.add(state.record.trial_key)
                issue(
                    design_issues,
                    "planned-trial-binding-mismatch",
                    "record disagrees with compiler-owned " + ", ".join(mismatches),
                    (index,),
                    invalidate=True,
                )
            expected_action_digest = _expected_action_digest(
                clean_compiled,
                cells_by_key[planned.cell_key],
            )
            if state.record.trace.action_digest != expected_action_digest:
                issue(
                    design_issues,
                    "action-digest-mismatch",
                    "trace action does not match the compiler-owned input action",
                    (index,),
                    invalidate=True,
                    observed_digests=(state.record.trace.action_digest,),
                )

        _mark_reuse(
            states,
            safety_issues,
            issue,
            lambda state: state.record.clone.unique_instance_id,
            "clone-instance-reuse",
            "fresh-clone instance id is reused",
        )
        _mark_reuse(
            states,
            safety_issues,
            issue,
            lambda state: state.record.clone.attestation_bundle_digest,
            "attestation-bundle-reuse",
            "trial attestation bundle is reused",
        )
        _mark_reuse(
            states,
            safety_issues,
            issue,
            lambda state: state.record.trace.trace_id,
            "trace-id-reuse",
            "trace id is reused across fresh trials",
        )
        _mark_executed_event_reuse(
            states,
            safety_issues,
            issue,
            lambda event: event.event_id,
            "event-id-reuse",
            "executed event id is reused across fresh trials",
        )
        _mark_executed_event_reuse(
            states,
            safety_issues,
            issue,
            lambda event: event.evidence_bundle_digest,
            "stage-evidence-bundle-reuse",
            "executed stage evidence bundle is reused across fresh trials",
        )

        for index, state in enumerate(states):
            if state.record.trial_key not in expected_by_key:
                continue
            result, error = _verify_attestation(attestation_verifier, state.record)
            if error is not None:
                issue(
                    evidence_issues,
                    "invalid-trial-attestation-response",
                    error,
                    (index,),
                    invalidate=True,
                )
                continue
            if isinstance(result, TrialAttestationFailure):
                planned = expected_by_key[state.record.trial_key]
                issue(
                    evidence_issues,
                    f"trial-attestation-{result.status}",
                    result.reason,
                    (index,),
                    invalidate=True,
                    evidence_ids=result.evidence_ids,
                    artifact_ids=result.artifact_ids,
                    expected_selector=cells_by_key[planned.cell_key],
                    observed_selectors=result.observed_selectors,
                    observed_digests=result.observed_digests,
                )
                continue
            assert isinstance(result, AdmittedTrialAttestation)
            state.attestation = result
            planned = expected_by_key[state.record.trial_key]
            expected_selector = cells_by_key[planned.cell_key]
            scope = clean_compiled.contract.scope
            clone = state.record.clone
            expected_binding = TrialAttestationBinding(
                spec_digest=clean_compiled.spec_digest,
                trial_key=planned.key,
                cell_key=planned.cell_key,
                block=planned.block,
                replicate=planned.replicate,
                ordinal=planned.ordinal,
                trace_id=state.record.trace.trace_id,
                action_digest=state.record.trace.action_digest,
                clone_unique_instance_id=clone.unique_instance_id,
                runner_resource_id=clone.runner_resource_id,
                attestation_bundle_digest=clone.attestation_bundle_digest,
            )
            if result.binding != expected_binding:
                issue(
                    evidence_issues,
                    "trial-attestation-binding-mismatch",
                    "trial attestation does not echo the exact planned execution binding",
                    (index,),
                    invalidate=True,
                    evidence_ids=(result.evidence_id,),
                    artifact_ids=result.artifact_ids,
                )
            if (
                result.observed_build_digest != scope.build_digest
                or result.observed_dataset_digest != scope.dataset_digest
                or result.observed_fixture_digest != scope.fixture_digest
            ):
                issue(
                    evidence_issues,
                    "attested-scope-mismatch",
                    "attested build, dataset, or fixture differs from the contract scope",
                    (index,),
                    invalidate=True,
                    evidence_ids=(result.evidence_id,),
                    artifact_ids=result.artifact_ids,
                    observed_digests=(
                        result.observed_build_digest,
                        result.observed_dataset_digest,
                        result.observed_fixture_digest,
                    ),
                )
            if result.executed_ordinal != planned.ordinal:
                issue(
                    design_issues,
                    "attested-order-mismatch",
                    "attested execution ordinal differs from the compiler plan",
                    (index,),
                    invalidate=True,
                    evidence_ids=(result.evidence_id,),
                    artifact_ids=result.artifact_ids,
                )
            if result.observed_selector != expected_selector:
                issue(
                    design_issues,
                    "attested-selector-mismatch",
                    "attested factor state differs from the compiler-planned cell",
                    (index,),
                    invalidate=True,
                    evidence_ids=(result.evidence_id,),
                    artifact_ids=result.artifact_ids,
                    expected_selector=expected_selector,
                    observed_selectors=(result.observed_selector,),
                )
            if (
                result.base_snapshot_digest != clone.base_snapshot_digest
                or result.covariate_digest != clone.covariate_digest
            ):
                issue(
                    evidence_issues,
                    "attested-clone-state-mismatch",
                    "attested base snapshot or covariate differs from the fresh clone",
                    (index,),
                    invalidate=True,
                    evidence_ids=(result.evidence_id,),
                    artifact_ids=result.artifact_ids,
                )
            if clone.attestation_bundle_digest not in result.artifact_ids:
                issue(
                    evidence_issues,
                    "attestation-bundle-unbound",
                    "admission artifacts do not bind the declared attestation bundle",
                    (index,),
                    invalidate=True,
                    evidence_ids=(result.evidence_id,),
                    artifact_ids=result.artifact_ids,
                )
            if not (
                scope.evidence_window.start <= result.started_at
                and result.ended_at <= scope.evidence_window.end
                and result.ended_at <= scope.assessment_as_of
            ):
                issue(
                    evidence_issues,
                    "trial-attestation-outside-window",
                    "attested trial time falls outside the evidence window or as-of",
                    (index,),
                    invalidate=True,
                    evidence_ids=(result.evidence_id,),
                    artifact_ids=result.artifact_ids,
                )
            executed = tuple(
                event
                for event in (
                    state.record.trace.input,
                    state.record.trace.target,
                    state.record.trace.compensator,
                    state.record.trace.outcome,
                )
                if isinstance(event, ExecutedStageEvent)
            )
            if any(
                event.started_at < result.started_at or event.ended_at > result.ended_at
                for event in executed
            ):
                issue(
                    evidence_issues,
                    "trace-outside-attested-time",
                    "an executed stage lies outside the attested trial time",
                    (index,),
                    invalidate=True,
                    evidence_ids=(result.evidence_id,),
                    artifact_ids=result.artifact_ids,
                )

        evidence_owners: defaultdict[str, list[int]] = defaultdict(list)
        for index, state in enumerate(states):
            if state.attestation is not None:
                evidence_owners[state.attestation.evidence_id].append(index)
        for evidence_id, indices in evidence_owners.items():
            if len(indices) > 1:
                issue(
                    safety_issues,
                    "attestation-evidence-reuse",
                    "one attestation evidence id is bound to multiple trials",
                    indices,
                    invalidate=True,
                    evidence_ids=(evidence_id,),
                )

        _mark_runner_overlaps(states, safety_issues, issue)
        cleanup_verified_indices = _admit_cleanups(
            clean_compiled,
            states,
            expected_by_key,
            cleanup_verifier,
            safety_issues,
            issue,
        )

        state_by_key = {
            key: states[indices[0]]
            for key, indices in occurrences.items()
            if key in expected_by_key
            and len(indices) == 1
            and states[indices[0]].valid
            and states[indices[0]].attestation is not None
        }
        probe_state_by_key = {
            key: states[indices[0]]
            for key, indices in occurrences.items()
            if key in expected_by_key
            and len(indices) == 1
            and states[indices[0]].attestation is not None
        }
        context = _Context(
            compiled=clean_compiled,
            states=states,
            evidence_verifier=evidence_verifier,
            expected_by_key=expected_by_key,
            cells_by_key=cells_by_key,
            state_by_key=probe_state_by_key,
            evidence_issues=evidence_issues,
        )

        required_metric_coordinates = _required_metric_coordinates(context)
        _prime_metric_evidence(context, required_metric_coordinates)
        _reject_metric_replays(context)
        context.state_by_key = state_by_key
        evidence_complete = _metric_evidence_complete(
            context,
            required_metric_coordinates,
        )
        presence_complete = not (missing or extra or duplicate or identity_wrong)
        cleanup_complete = presence_complete and all(
            indices[0] in cleanup_verified_indices
            for key, indices in occurrences.items()
            if key in expected_by_key and len(indices) == 1
        )
        cleanup_complete = cleanup_complete and len(cleanup_verified_indices) == len(
            expected_by_key
        )
        safety_complete = not safety_issues
        protocol_complete = (
            presence_complete
            and len(state_by_key) == len(expected_by_key)
            and evidence_complete
            and cleanup_complete
            and safety_complete
        )
        assessments = tuple(
            self._evaluate_obligation(context, obligation)
            for obligation in clean_compiled.contract.obligations
        )
        contrasts = tuple(
            self._evaluate_contrast(context, contrast) for contrast in clean_compiled.contrasts
        )
        residual = _residual_summary(
            clean_compiled,
            assessments,
            contrasts,
            protocol_complete=protocol_complete,
        )
        return EvaluationReport(
            compiled_experiment=clean_compiled,
            design_completeness=DesignCompleteness(
                expected_trial_count=len(expected_by_key),
                received_record_count=len(clean_records),
                missing_trial_keys=missing,
                extra_trial_keys=extra,
                duplicate_trial_keys=duplicate,
                missing_cell_keys=missing_cell_keys,
                admissible_trial_count=len(state_by_key),
                presence_complete=presence_complete,
                evidence_complete=evidence_complete,
                cleanup_complete=cleanup_complete,
                safety_complete=safety_complete,
                protocol_complete=protocol_complete,
                complete=protocol_complete,
            ),
            design_issues=tuple(design_issues),
            evidence_issues=tuple(evidence_issues),
            safety_issues=tuple(safety_issues),
            obligation_assessments=assessments,
            contrast_assessments=contrasts,
            residual_summary=residual,
        )

    def _evaluate_obligation(
        self,
        context: _Context,
        obligation: Obligation,
    ) -> ObligationAssessment:
        coverage = next(
            item
            for item in context.compiled.obligation_coverage
            if item.obligation_id == obligation.id
        )
        metric = _metric_by_id(context.compiled, obligation.predicate.metric_id)
        stage = _stage_for_scope(obligation.scope)
        results: list[TrialPointResult] = []
        for trial_key in coverage.trial_keys:
            state = context.state_by_key.get(trial_key)
            if state is None:
                results.append(
                    TrialPointResult(
                        trial_key=trial_key,
                        state=TrialPointState.UNRESOLVED,
                        exercise=ExerciseState.UNKNOWN,
                        reason=_invalid_reason(context.states, trial_key),
                    )
                )
                continue
            event = state.record.trace.event_for(stage)
            attestation = state.attestation
            assert attestation is not None
            attestation_evidence = (attestation.evidence_id,)
            attestation_artifacts = attestation.artifact_ids
            if isinstance(event, SkippedStageEvent):
                results.append(
                    TrialPointResult(
                        trial_key=trial_key,
                        state=TrialPointState.UNRESOLVED,
                        exercise=ExerciseState.NOT_EXERCISED,
                        reason=(
                            f"{stage.value} stage skipped; blocked by {event.blocked_by_event_id}"
                        ),
                        evidence_ids=attestation_evidence,
                        artifact_ids=attestation_artifacts,
                    )
                )
                continue
            admission = _metric_evidence(context, state, event, metric)
            if admission is None:
                key = (trial_key, event.event_id, metric.id)
                results.append(
                    TrialPointResult(
                        trial_key=trial_key,
                        state=TrialPointState.UNRESOLVED,
                        exercise=ExerciseState.EXERCISED,
                        reason=context.evidence_failure_reason[key],
                        evidence_ids=attestation_evidence,
                        artifact_ids=attestation_artifacts,
                    )
                )
                continue
            did_pass = _predicate_matches(obligation.predicate, admission.value)
            results.append(
                TrialPointResult(
                    trial_key=trial_key,
                    state=(TrialPointState.PASS if did_pass else TrialPointState.FAIL),
                    exercise=ExerciseState.EXERCISED,
                    observed_value=admission.value,
                    evidence_ids=(
                        attestation.evidence_id,
                        admission.evidence_id,
                    ),
                    artifact_ids=_digests((*attestation.artifact_ids, *admission.artifact_ids)),
                )
            )

        expected = len(results)
        pass_results = tuple(result for result in results if result.state == TrialPointState.PASS)
        fail_results = tuple(result for result in results if result.state == TrialPointState.FAIL)
        unresolved_results = tuple(
            result for result in results if result.state == TrialPointState.UNRESOLVED
        )
        executed = sum(result.exercise == ExerciseState.EXERCISED for result in results)
        not_exercised = sum(result.exercise == ExerciseState.NOT_EXERCISED for result in results)
        unknown_exercise = sum(result.exercise == ExerciseState.UNKNOWN for result in results)
        passed = len(pass_results)
        failed = len(fail_results)
        unresolved = len(unresolved_results)
        admitted = passed + failed
        lower = Decimal(passed) / Decimal(expected)
        upper = Decimal(passed + unresolved) / Decimal(expected)
        truth = _quantified_truth(
            obligation,
            passed=passed,
            failed=failed,
            unresolved=unresolved,
            admitted=admitted,
            expected=expected,
            lower=lower,
            upper=upper,
        )
        if unknown_exercise == expected:
            exercise = ExerciseState.UNKNOWN
        elif not_exercised == expected:
            exercise = ExerciseState.NOT_EXERCISED
        elif executed == expected:
            exercise = ExerciseState.EXERCISED
        else:
            exercise = ExerciseState.PARTIALLY_EXERCISED
        return ObligationAssessment(
            obligation_id=obligation.id,
            truth=truth,
            exercise=exercise,
            expected_count=expected,
            executed_count=executed,
            admitted_count=admitted,
            pass_count=passed,
            fail_count=failed,
            unresolved_count=unresolved,
            not_exercised_count=not_exercised,
            unknown_exercise_count=unknown_exercise,
            lower_bound=lower,
            upper_bound=upper,
            pass_trial_keys=tuple(result.trial_key for result in pass_results),
            fail_trial_keys=tuple(result.trial_key for result in fail_results),
            unresolved_trial_keys=tuple(result.trial_key for result in unresolved_results),
            evidence_ids=_digests(
                evidence_id for result in results for evidence_id in result.evidence_ids
            ),
            artifact_ids=_digests(
                artifact_id for result in results for artifact_id in result.artifact_ids
            ),
            trial_results=tuple(results),
        )

    def _evaluate_contrast(
        self,
        context: _Context,
        contrast: ContrastDefinition,
    ) -> ContrastAssessment:
        contrast_id = contrast.id.value
        metric_id = contrast.metric_id
        metric = _metric_by_id(context.compiled, metric_id)
        planned_by_coordinate = {
            (trial.cell_key, trial.block, trial.replicate): trial.key
            for trial in context.compiled.planned_trials
        }
        pair_results: list[ContrastPairAssessment] = []
        for pair in contrast.pairs:
            reference_cell_key = pair.reference_cell_key
            comparison_cell_key = pair.comparison_cell_key
            for block in sorted(context.compiled.contract.plan.blocks):
                for replicate in range(1, context.compiled.contract.plan.replicates + 1):
                    reference_key = planned_by_coordinate[(reference_cell_key, block, replicate)]
                    comparison_key = planned_by_coordinate[(comparison_cell_key, block, replicate)]
                    pair_results.append(
                        _evaluate_contrast_pair(
                            context,
                            reference_key,
                            comparison_key,
                            block,
                            replicate,
                            metric,
                            contrast.relation.operator,
                        )
                    )
        supported = sum(result.truth == TruthValue.SUPPORTED for result in pair_results)
        refuted = sum(result.truth == TruthValue.REFUTED for result in pair_results)
        unresolved = len(pair_results) - supported - refuted
        if refuted:
            truth = TruthValue.REFUTED
        elif unresolved:
            truth = TruthValue.NEITHER
        else:
            truth = TruthValue.SUPPORTED
        return ContrastAssessment(
            contrast_id=contrast_id,
            metric_id=metric_id,
            truth=truth,
            expected_pair_count=len(pair_results),
            supported_pair_count=supported,
            refuted_pair_count=refuted,
            unresolved_pair_count=unresolved,
            pairs=tuple(pair_results),
            evidence_ids=_digests(
                evidence_id for result in pair_results for evidence_id in result.evidence_ids
            ),
            artifact_ids=_digests(
                artifact_id for result in pair_results for artifact_id in result.artifact_ids
            ),
        )


def _recompile(compiled: CompiledExperiment) -> CompiledExperiment:
    try:
        clean_input = CompiledExperiment.model_validate(
            compiled.model_dump(mode="python", round_trip=True),
            strict=True,
        )
        contract = ExperimentContract.model_validate(
            clean_input.contract.model_dump(mode="python", round_trip=True),
            strict=True,
        )
        regenerated = compile_experiment(contract)
    except (AttributeError, TypeError, ValueError) as error:
        raise EvaluationBoundaryError(
            f"compiled experiment revalidation failed: {error}"
        ) from error
    if clean_input.model_dump(mode="json") != regenerated.model_dump(mode="json"):
        raise EvaluationBoundaryError("compiled experiment differs from a fresh compiler result")
    return regenerated


def _revalidate_record(record: TrialRecord) -> TrialRecord:
    try:
        return TrialRecord.model_validate(
            record.model_dump(mode="python", round_trip=True),
            strict=True,
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise EvaluationBoundaryError(f"trial record revalidation failed: {error}") from error


def _verify_attestation(
    verifier: TrialAttestationVerifier,
    record: TrialRecord,
) -> tuple[AdmittedTrialAttestation | TrialAttestationFailure | None, str | None]:
    try:
        raw = verifier.verify(record)
        result = _ATTESTATION_ADAPTER.validate_python(
            raw.model_dump(mode="python", round_trip=True),
            strict=True,
        )
    except Exception as error:  # verifier failures are local missing evidence
        return None, f"trial attestation verifier response failed validation: {error}"
    return result, None


def _verify_metric(
    verifier: EvidenceVerifier,
    binding: EvidenceBinding,
) -> tuple[AdmittedMetricEvidence | MetricEvidenceFailure | None, str | None]:
    try:
        raw = verifier.verify(binding)
        result = _EVIDENCE_ADAPTER.validate_python(
            raw.model_dump(mode="python", round_trip=True),
            strict=True,
        )
    except Exception as error:  # verifier failures are local missing evidence
        return None, f"metric evidence verifier response failed validation: {error}"
    return result, None


def _verify_cleanup(
    verifier: CleanupVerifier,
    binding: CleanupBinding,
) -> tuple[AdmittedCleanupEvidence | CleanupEvidenceFailure | None, str | None]:
    try:
        raw = verifier.verify(binding)
        result = _CLEANUP_ADAPTER.validate_python(
            raw.model_dump(mode="python", round_trip=True),
            strict=True,
        )
    except Exception as error:  # verifier failures are safety findings
        return None, f"cleanup verifier response failed validation: {error}"
    return result, None


def _mark_reuse(
    states: Sequence[_TrialState],
    issues: list[EvaluationIssue],
    issue: Callable[..., None],
    key_for: Callable[[_TrialState], str],
    code: str,
    detail: str,
) -> None:
    groups: defaultdict[str, list[int]] = defaultdict(list)
    for index, state in enumerate(states):
        groups[key_for(state)].append(index)
    for indices in groups.values():
        if len(indices) > 1:
            issue(
                issues,
                code,
                detail,
                indices,
                invalidate=True,
            )


def _executed_events(trace: Trace) -> tuple[ExecutedStageEvent, ...]:
    return tuple(
        event
        for event in (
            trace.input,
            trace.target,
            trace.compensator,
            trace.outcome,
        )
        if isinstance(event, ExecutedStageEvent)
    )


def _mark_executed_event_reuse(
    states: Sequence[_TrialState],
    issues: list[EvaluationIssue],
    issue: Callable[..., None],
    key_for: Callable[[ExecutedStageEvent], str],
    code: str,
    detail: str,
) -> None:
    groups: defaultdict[str, set[int]] = defaultdict(set)
    for index, state in enumerate(states):
        for event in _executed_events(state.record.trace):
            groups[key_for(event)].add(index)
    for key, grouped_indices in groups.items():
        indices = sorted(grouped_indices)
        if len({states[index].record.trial_key for index in indices}) > 1:
            issue(
                issues,
                code,
                detail,
                indices,
                invalidate=True,
                observed_digests=((key,) if key.startswith("sha256:") else ()),
            )


def _mark_runner_overlaps(
    states: Sequence[_TrialState],
    issues: list[EvaluationIssue],
    issue: Callable[..., None],
) -> None:
    groups: defaultdict[str, list[int]] = defaultdict(list)
    for index, state in enumerate(states):
        if state.attestation is not None:
            groups[state.record.clone.runner_resource_id].append(index)
    for runner, indices in groups.items():
        for left_offset, left_index in enumerate(indices):
            left = states[left_index].attestation
            assert left is not None
            for right_index in indices[left_offset + 1 :]:
                right = states[right_index].attestation
                assert right is not None
                if max(left.started_at, right.started_at) < min(left.ended_at, right.ended_at):
                    issue(
                        issues,
                        "runner-resource-overlap",
                        f"trials overlap on runner resource {runner}",
                        (left_index, right_index),
                        invalidate=True,
                    )


def _admit_cleanups(
    compiled: CompiledExperiment,
    states: Sequence[_TrialState],
    expected_by_key: dict[str, PlannedTrial],
    verifier: CleanupVerifier,
    issues: list[EvaluationIssue],
    issue: Callable[..., None],
) -> set[int]:
    bad: set[int] = set()
    admissions: dict[int, AdmittedCleanupEvidence] = {}

    bundle_owners: defaultdict[str, list[int]] = defaultdict(list)
    for index, state in enumerate(states):
        if state.record.trial_key in expected_by_key:
            bundle_owners[state.record.cleanup.evidence_bundle_digest].append(index)
    for bundle_digest, indices in bundle_owners.items():
        if len({states[index].record.trial_key for index in indices}) > 1:
            bad.update(indices)
            issue(
                issues,
                "cleanup-bundle-reuse",
                "cleanup evidence bundle is reused across trials",
                indices,
                artifact_ids=(bundle_digest,),
            )

    scope = compiled.contract.scope
    for index, state in enumerate(states):
        if state.record.trial_key not in expected_by_key:
            continue
        binding = CleanupBinding(
            spec_digest=compiled.spec_digest,
            trial_key=state.record.trial_key,
            trace_id=state.record.trace.trace_id,
            clone_unique_instance_id=state.record.clone.unique_instance_id,
            runner_resource_id=state.record.clone.runner_resource_id,
            evidence_bundle_digest=state.record.cleanup.evidence_bundle_digest,
            outcome_ended_at=state.record.trace.outcome.ended_at,
        )
        result, error = _verify_cleanup(verifier, binding)
        if error is not None:
            bad.add(index)
            issue(
                issues,
                "invalid-cleanup-response",
                error,
                (index,),
            )
            continue
        if isinstance(result, CleanupEvidenceFailure):
            bad.add(index)
            issue(
                issues,
                f"cleanup-{result.status}",
                result.reason,
                (index,),
                evidence_ids=result.evidence_ids,
                artifact_ids=result.artifact_ids,
            )
            continue
        assert isinstance(result, AdmittedCleanupEvidence)
        admissions[index] = result
        if result.binding != binding:
            bad.add(index)
            issue(
                issues,
                "cleanup-binding-mismatch",
                "cleanup admission does not echo the exact cleanup binding",
                (index,),
                evidence_ids=(result.evidence_id,),
                artifact_ids=result.artifact_ids,
            )
        if binding.evidence_bundle_digest not in result.artifact_ids:
            bad.add(index)
            issue(
                issues,
                "cleanup-bundle-unbound",
                "cleanup admission artifacts do not bind the cleanup bundle",
                (index,),
                evidence_ids=(result.evidence_id,),
                artifact_ids=result.artifact_ids,
            )
        if not (
            result.observed_at > binding.outcome_ended_at
            and scope.evidence_window.start <= result.observed_at <= scope.evidence_window.end
            and result.observed_at <= scope.assessment_as_of
        ):
            bad.add(index)
            issue(
                issues,
                "cleanup-time-invalid",
                "cleanup must be observed after outcome and within the window/as-of",
                (index,),
                evidence_ids=(result.evidence_id,),
                artifact_ids=result.artifact_ids,
            )
        if result.state == CleanupState.FAILED:
            bad.add(index)
            issue(
                issues,
                "cleanup-failed",
                "verified cleanup evidence reports failure",
                (index,),
                evidence_ids=(result.evidence_id,),
                artifact_ids=result.artifact_ids,
            )

    evidence_owners: defaultdict[str, list[int]] = defaultdict(list)
    for index, admission in admissions.items():
        evidence_owners[admission.evidence_id].append(index)
    for evidence_id, indices in evidence_owners.items():
        if len({states[index].record.trial_key for index in indices}) > 1:
            bad.update(indices)
            issue(
                issues,
                "cleanup-evidence-reuse",
                "cleanup evidence id is reused across trials",
                indices,
                evidence_ids=(evidence_id,),
            )
    return {
        index
        for index, admission in admissions.items()
        if index not in bad and admission.state == CleanupState.VERIFIED
    }


def _metric_by_id(
    compiled: CompiledExperiment,
    metric_id: str,
) -> MetricContract:
    return next(metric for metric in compiled.contract.metrics if metric.id == metric_id)


def _expected_action_digest(
    compiled: CompiledExperiment,
    selector: CellSelector,
) -> str:
    input_axis = compiled.contract.profile.input
    if selector.input == input_axis.attack:
        return input_axis.attack_action_digest
    if selector.input == input_axis.benign:
        return input_axis.benign_action_digest
    raise EvaluationBoundaryError("compiled cell has no declared input action")


def _stage_for_scope(scope: ObligationScope) -> Stage:
    return {
        ObligationScope.TARGET_LOCAL: Stage.TARGET,
        ObligationScope.COMPENSATOR_LOCAL: Stage.COMPENSATOR,
        ObligationScope.PATH: Stage.OUTCOME,
    }[scope]


MetricCoordinate = tuple[str, Stage, str]


def _required_metric_coordinates(context: _Context) -> set[MetricCoordinate]:
    coverage_by_id = {
        coverage.obligation_id: coverage.trial_keys
        for coverage in context.compiled.obligation_coverage
    }
    required = {
        (trial_key, _stage_for_scope(obligation.scope), obligation.predicate.metric_id)
        for obligation in context.compiled.contract.obligations
        for trial_key in coverage_by_id[obligation.id]
    }
    for contrast in context.compiled.contrasts:
        metric = _metric_by_id(context.compiled, contrast.metric_id)
        cell_keys = {
            cell_key
            for pair in contrast.pairs
            for cell_key in (
                pair.reference_cell_key,
                pair.comparison_cell_key,
            )
        }
        required.update(
            (trial.key, metric.stage, metric.id)
            for trial in context.compiled.planned_trials
            if trial.cell_key in cell_keys
        )
    return required


def _prime_metric_evidence(
    context: _Context,
    required: set[MetricCoordinate],
) -> None:
    for coordinate in sorted(
        required,
        key=lambda item: (item[0], item[1].value, item[2]),
    ):
        trial_key, stage, metric_id = coordinate
        state = context.state_by_key.get(trial_key)
        if state is None:
            continue
        event = state.record.trace.event_for(stage)
        if isinstance(event, SkippedStageEvent):
            continue
        _metric_evidence(
            context,
            state,
            event,
            _metric_by_id(context.compiled, metric_id),
        )


def _reject_metric_replays(context: _Context) -> None:
    admissions = {
        key: admission for key, admission in context.evidence_cache.items() if admission is not None
    }
    evidence_owners: defaultdict[str, list[tuple[tuple[str, str, str], AdmittedMetricEvidence]]] = (
        defaultdict(list)
    )
    bundle_metric_owners: defaultdict[
        tuple[str, str],
        list[tuple[tuple[str, str, str], AdmittedMetricEvidence]],
    ] = defaultdict(list)
    for key, admission in admissions.items():
        evidence_owners[admission.evidence_id].append((key, admission))
        bundle_metric_owners[
            (
                admission.binding.evidence_bundle_digest,
                admission.binding.metric_id,
            )
        ].append((key, admission))

    bad_reasons: defaultdict[tuple[str, str, str], list[str]] = defaultdict(list)
    for evidence_id, owners in evidence_owners.items():
        bindings = {admission.binding.model_dump_json() for _, admission in owners}
        if len(bindings) <= 1:
            continue
        reason = "metric evidence id is rebound across distinct bindings"
        for key, _ in owners:
            bad_reasons[key].append(reason)
        context.evidence_issues.append(
            EvaluationIssue(
                code="metric-evidence-id-reuse",
                detail=reason,
                affected_trial_keys=tuple(sorted({key[0] for key, _ in owners})),
                evidence_ids=(evidence_id,),
                artifact_ids=_digests(
                    artifact_id for _, admission in owners for artifact_id in admission.artifact_ids
                ),
                candidate_values=tuple(admission.value for _, admission in owners),
            )
        )

    for (bundle_digest, metric_id), owners in bundle_metric_owners.items():
        values = {admission.value.model_dump_json() for _, admission in owners}
        if len(values) <= 1:
            continue
        reason = f"bundle {bundle_digest} yields conflicting values for metric {metric_id}"
        for key, _ in owners:
            bad_reasons[key].append(reason)
        context.evidence_issues.append(
            EvaluationIssue(
                code="metric-bundle-value-conflict",
                detail=reason,
                affected_trial_keys=tuple(sorted({key[0] for key, _ in owners})),
                evidence_ids=_digests(admission.evidence_id for _, admission in owners),
                artifact_ids=_digests(
                    artifact_id for _, admission in owners for artifact_id in admission.artifact_ids
                ),
                observed_digests=(bundle_digest,),
                candidate_values=tuple(admission.value for _, admission in owners),
            )
        )

    for key, reasons in bad_reasons.items():
        context.evidence_cache[key] = None
        context.evidence_failure_reason[key] = "; ".join(sorted(set(reasons)))


def _metric_evidence_complete(
    context: _Context,
    required: set[MetricCoordinate],
) -> bool:
    for trial_key, stage, metric_id in required:
        state = context.state_by_key.get(trial_key)
        if state is None:
            return False
        event = state.record.trace.event_for(stage)
        if isinstance(event, SkippedStageEvent):
            continue
        key = (trial_key, event.event_id, metric_id)
        if context.evidence_cache.get(key) is None:
            return False
    return True


def _invalid_reason(states: Sequence[_TrialState], trial_key: str) -> str:
    matching = [state for state in states if state.record.trial_key == trial_key]
    if not matching:
        return "missing planned trial"
    reasons = sorted({reason for state in matching for reason in state.invalid_reasons})
    return ", ".join(reasons) if reasons else "trial is not admissible"


def _metric_evidence(
    context: _Context,
    state: _TrialState,
    event: ExecutedStageEvent,
    metric: MetricContract,
) -> AdmittedMetricEvidence | None:
    key = (state.record.trial_key, event.event_id, metric.id)
    if key in context.evidence_cache:
        return context.evidence_cache[key]
    binding = EvidenceBinding(
        spec_digest=context.compiled.spec_digest,
        trial_key=state.record.trial_key,
        trace_id=state.record.trace.trace_id,
        event_id=event.event_id,
        evidence_bundle_digest=event.evidence_bundle_digest,
        stage=event.stage,
        metric_id=metric.id,
    )
    result, error = _verify_metric(context.evidence_verifier, binding)
    reason: str | None = error
    issue_code = "invalid-metric-evidence-response"
    if isinstance(result, MetricEvidenceFailure):
        reason = f"{result.status}: {result.reason}"
        issue_code = f"metric-evidence-{result.status}"
    elif isinstance(result, AdmittedMetricEvidence):
        if result.binding != binding:
            reason = "metric admission does not echo the exact evidence binding"
            issue_code = "metric-evidence-binding-mismatch"
        elif result.value.type != metric.value_type.value:
            reason = (
                f"admitted value type {result.value.type} does not match {metric.value_type.value}"
            )
            issue_code = "metric-value-type-mismatch"
        else:
            scope = context.compiled.contract.scope
            in_window = (
                scope.evidence_window.start <= result.observed_at <= scope.evidence_window.end
                and result.observed_at <= scope.assessment_as_of
                and event.started_at <= result.observed_at <= event.ended_at
            )
            if not in_window:
                reason = (
                    "metric evidence time falls outside its stage event, evidence window, or as-of"
                )
                issue_code = "metric-evidence-outside-window"
            elif event.evidence_bundle_digest not in result.artifact_ids:
                reason = "metric admission does not bind the stage evidence bundle"
                issue_code = "metric-evidence-bundle-unbound"
            else:
                context.evidence_cache[key] = result
                return result
    if reason is None:
        reason = "metric verifier returned no admissible result"
    context.evidence_cache[key] = None
    context.evidence_failure_reason[key] = reason
    context.evidence_issues.append(
        EvaluationIssue(
            code=issue_code,
            detail=reason,
            affected_trial_keys=(state.record.trial_key,),
            evidence_ids=(
                (result.evidence_id,)
                if isinstance(result, AdmittedMetricEvidence)
                else (result.evidence_ids if isinstance(result, MetricEvidenceFailure) else ())
            ),
            artifact_ids=(
                result.artifact_ids
                if isinstance(result, AdmittedMetricEvidence | MetricEvidenceFailure)
                else ()
            ),
            expected_value_type=metric.value_type,
            candidate_values=(
                result.candidate_values if isinstance(result, MetricEvidenceFailure) else ()
            ),
        )
    )
    return None


def _predicate_matches(predicate: Predicate, actual: TypedValue) -> bool:
    expected = predicate.expected
    if actual.type != expected.type:
        return False
    tolerance = (
        predicate.absolute_tolerance.value
        if predicate.absolute_tolerance is not None
        else Decimal(0)
    )
    operator = predicate.operator
    if actual.type in {"integer", "decimal"}:
        left = _as_decimal(actual)
        right = _as_decimal(expected)
        if operator == PredicateOperator.EQUAL:
            return abs(left - right) <= tolerance
        if operator == PredicateOperator.NOT_EQUAL:
            return abs(left - right) > tolerance
        if operator == PredicateOperator.LESS_OR_EQUAL:
            return left <= right + tolerance
        return left >= right - tolerance
    equal = actual.value == expected.value
    if operator == PredicateOperator.EQUAL:
        return equal
    if operator == PredicateOperator.NOT_EQUAL:
        return not equal
    return False


def _as_decimal(value: TypedValue) -> Decimal:
    if value.type == "integer":
        return Decimal(value.value)
    if value.type == "decimal":
        return value.value
    raise TypeError("non-numeric typed value")


def _quantified_truth(
    obligation: Obligation,
    *,
    passed: int,
    failed: int,
    unresolved: int,
    admitted: int,
    expected: int,
    lower: Decimal,
    upper: Decimal,
) -> TruthValue:
    quantifier = obligation.quantifier
    if isinstance(quantifier, AllTested):
        if failed:
            return TruthValue.REFUTED
        if unresolved == 0 and passed == expected:
            return TruthValue.SUPPORTED
        return TruthValue.NEITHER
    if isinstance(quantifier, AtLeastRate):
        threshold = quantifier.rate.value
        if lower >= threshold and admitted >= quantifier.min_trials:
            return TruthValue.SUPPORTED
        if upper < threshold:
            return TruthValue.REFUTED
        return TruthValue.NEITHER
    assert isinstance(quantifier, Exists)
    if passed and admitted >= quantifier.min_trials:
        return TruthValue.SUPPORTED
    if unresolved == 0 and passed == 0:
        return TruthValue.REFUTED
    return TruthValue.NEITHER


def _evaluate_contrast_pair(
    context: _Context,
    reference_key: str,
    comparison_key: str,
    block: str,
    replicate: int,
    metric: MetricContract,
    operator: RelationOperator,
) -> ContrastPairAssessment:
    reference = context.state_by_key.get(reference_key)
    comparison = context.state_by_key.get(comparison_key)
    if reference is None or comparison is None:
        reasons: list[str] = []
        if reference is None:
            reasons.append(f"reference: {_invalid_reason(context.states, reference_key)}")
        if comparison is None:
            reasons.append(f"comparison: {_invalid_reason(context.states, comparison_key)}")
        return ContrastPairAssessment(
            reference_trial_key=reference_key,
            comparison_trial_key=comparison_key,
            block=block,
            replicate=replicate,
            truth=TruthValue.NEITHER,
            unresolved_reason="; ".join(reasons),
        )
    reference_attestation = reference.attestation
    comparison_attestation = comparison.attestation
    assert reference_attestation is not None
    assert comparison_attestation is not None
    if reference.record.trace.action_digest != comparison.record.trace.action_digest:
        return ContrastPairAssessment(
            reference_trial_key=reference_key,
            comparison_trial_key=comparison_key,
            block=block,
            replicate=replicate,
            truth=TruthValue.NEITHER,
            unresolved_reason="matched trials differ in action digest",
            evidence_ids=(
                reference_attestation.evidence_id,
                comparison_attestation.evidence_id,
            ),
        )
    if (
        reference_attestation.base_snapshot_digest != comparison_attestation.base_snapshot_digest
        or reference_attestation.covariate_digest != comparison_attestation.covariate_digest
    ):
        return ContrastPairAssessment(
            reference_trial_key=reference_key,
            comparison_trial_key=comparison_key,
            block=block,
            replicate=replicate,
            truth=TruthValue.NEITHER,
            unresolved_reason="matched trials differ in base snapshot or covariate",
            evidence_ids=(
                reference_attestation.evidence_id,
                comparison_attestation.evidence_id,
            ),
            artifact_ids=_digests(
                (
                    *reference_attestation.artifact_ids,
                    *comparison_attestation.artifact_ids,
                )
            ),
        )
    if reference_attestation.intervention_digest == comparison_attestation.intervention_digest:
        return ContrastPairAssessment(
            reference_trial_key=reference_key,
            comparison_trial_key=comparison_key,
            block=block,
            replicate=replicate,
            truth=TruthValue.NEITHER,
            unresolved_reason=("attested intervention does not distinguish the matched cells"),
            evidence_ids=(
                reference_attestation.evidence_id,
                comparison_attestation.evidence_id,
            ),
            artifact_ids=_digests(
                (
                    *reference_attestation.artifact_ids,
                    *comparison_attestation.artifact_ids,
                )
            ),
        )
    if reference.record.clone.unique_instance_id == comparison.record.clone.unique_instance_id:
        return ContrastPairAssessment(
            reference_trial_key=reference_key,
            comparison_trial_key=comparison_key,
            block=block,
            replicate=replicate,
            truth=TruthValue.NEITHER,
            unresolved_reason="matched trials do not use distinct fresh clones",
        )
    reference_event = reference.record.trace.event_for(metric.stage)
    comparison_event = comparison.record.trace.event_for(metric.stage)
    if isinstance(reference_event, SkippedStageEvent) or isinstance(
        comparison_event, SkippedStageEvent
    ):
        return ContrastPairAssessment(
            reference_trial_key=reference_key,
            comparison_trial_key=comparison_key,
            block=block,
            replicate=replicate,
            truth=TruthValue.NEITHER,
            unresolved_reason="metric stage was skipped in a matched trial",
        )
    reference_evidence = _metric_evidence(context, reference, reference_event, metric)
    comparison_evidence = _metric_evidence(context, comparison, comparison_event, metric)
    if reference_evidence is None or comparison_evidence is None:
        return ContrastPairAssessment(
            reference_trial_key=reference_key,
            comparison_trial_key=comparison_key,
            block=block,
            replicate=replicate,
            truth=TruthValue.NEITHER,
            unresolved_reason="matched metric evidence is incomplete",
        )
    relation_holds = _relation_matches(
        operator, reference_evidence.value, comparison_evidence.value
    )
    return ContrastPairAssessment(
        reference_trial_key=reference_key,
        comparison_trial_key=comparison_key,
        block=block,
        replicate=replicate,
        truth=(TruthValue.SUPPORTED if relation_holds else TruthValue.REFUTED),
        reference_value=reference_evidence.value,
        comparison_value=comparison_evidence.value,
        evidence_ids=_digests(
            (
                reference_attestation.evidence_id,
                comparison_attestation.evidence_id,
                reference_evidence.evidence_id,
                comparison_evidence.evidence_id,
            )
        ),
        artifact_ids=_digests(
            (
                *reference_attestation.artifact_ids,
                *comparison_attestation.artifact_ids,
                *reference_evidence.artifact_ids,
                *comparison_evidence.artifact_ids,
            )
        ),
    )


def _relation_matches(
    operator: RelationOperator,
    reference: TypedValue,
    comparison: TypedValue,
) -> bool:
    if reference.type != comparison.type:
        return False
    if operator == RelationOperator.TRUE_TO_FALSE:
        return reference.type == "boolean" and reference.value is True and comparison.value is False
    if operator == RelationOperator.FALSE_TO_TRUE:
        return reference.type == "boolean" and reference.value is False and comparison.value is True
    if operator == RelationOperator.EQUAL:
        return reference.value == comparison.value
    if operator == RelationOperator.NOT_EQUAL:
        return reference.value != comparison.value
    if reference.type not in {"integer", "decimal"}:
        return False
    left = _as_decimal(reference)
    right = _as_decimal(comparison)
    if operator == RelationOperator.DECREASES:
        return right < left
    if operator == RelationOperator.INCREASES:
        return right > left
    if operator == RelationOperator.LESS_OR_EQUAL:
        return left <= right
    return left >= right


def _residual_summary(
    compiled: CompiledExperiment,
    assessments: tuple[ObligationAssessment, ...],
    contrasts: tuple[ContrastAssessment, ...],
    *,
    protocol_complete: bool,
) -> ResidualSummary:
    by_id = {assessment.obligation_id: assessment for assessment in assessments}
    profile = compiled.contract.profile
    target = by_id[profile.primary_target_obligation_id]
    compensator = by_id[profile.primary_compensator_obligation_id]
    path = by_id[profile.primary_path_obligation_id]
    benign = by_id[profile.primary_benign_obligation_id]
    contrast_by_id = {contrast.contrast_id: contrast for contrast in contrasts}

    def exercised(item: ObligationAssessment) -> bool:
        return item.exercise in {
            ExerciseState.EXERCISED,
            ExerciseState.PARTIALLY_EXERCISED,
        }

    if (
        target.truth == TruthValue.REFUTED
        and compensator.truth == TruthValue.SUPPORTED
        and path.truth == TruthValue.SUPPORTED
        and exercised(target)
        and exercised(compensator)
        and exercised(path)
    ):
        classification = ResidualClassification.MASKED_TARGET_FAILURE
    elif path.truth == TruthValue.REFUTED and exercised(path):
        classification = ResidualClassification.EXPOSED_PATH
    elif (
        target.truth == TruthValue.SUPPORTED
        and path.truth == TruthValue.SUPPORTED
        and benign.truth == TruthValue.SUPPORTED
        and protocol_complete
        and contrast_by_id["target-attack-effect"].truth == TruthValue.SUPPORTED
        and contrast_by_id["target-benign-invariance"].truth == TruthValue.SUPPORTED
        and contrast_by_id["compensator-benign-invariance"].truth == TruthValue.SUPPORTED
        and contrast_by_id["sham-invariance"].truth == TruthValue.SUPPORTED
        and exercised(target)
        and exercised(path)
        and exercised(benign)
    ):
        classification = ResidualClassification.TARGET_EFFECTIVE
    else:
        classification = ResidualClassification.UNRESOLVED
    return ResidualSummary(
        classification=classification,
        target_obligation_id=target.obligation_id,
        compensator_obligation_id=compensator.obligation_id,
        path_obligation_id=path.obligation_id,
        benign_obligation_id=benign.obligation_id,
        target_truth=target.truth,
        compensator_truth=compensator.truth,
        path_truth=path.truth,
        benign_truth=benign.truth,
        target_exercise=target.exercise,
        compensator_exercise=compensator.exercise,
        path_exercise=path.exercise,
        benign_exercise=benign.exercise,
    )


def _digests(values: Iterable[str]) -> ArtifactIds:
    return tuple(sorted(set(values)))
