"""Version-two experiment protocol with separate estimands and claim results."""

from __future__ import annotations

import hashlib
import math
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    NonNegativeInt,
    model_validator,
)

from assurance_lab.claim_spec import ClaimSpec


class BooleanValue(BaseModel):
    model_config = ConfigDict(strict=True)

    type: Literal["boolean"] = "boolean"
    value: bool


class IntegerValue(BaseModel):
    model_config = ConfigDict(strict=True)

    type: Literal["integer"] = "integer"
    value: int


class NumberValue(BaseModel):
    model_config = ConfigDict(strict=True)

    type: Literal["number"] = "number"
    value: float

    @model_validator(mode="after")
    def finite(self) -> NumberValue:
        if not math.isfinite(self.value):
            raise ValueError("numeric observations must be finite")
        return self


class StringValue(BaseModel):
    model_config = ConfigDict(strict=True)

    type: Literal["string"] = "string"
    value: str


class NullValue(BaseModel):
    model_config = ConfigDict(strict=True)

    type: Literal["null"] = "null"
    value: None = None


TypedValue = Annotated[
    BooleanValue | IntegerValue | NumberValue | StringValue | NullValue,
    Field(discriminator="type"),
]


class FactorRole(StrEnum):
    INPUT = "input"
    TARGET_CONTROL = "target_control"
    COMPENSATING_CONTROL = "compensating_control"
    SHAM = "sham"
    CONTEXT = "context"
    FAULT = "fault"


class ProtocolProfile(StrEnum):
    CUSTOM = "custom"
    PREVENTIVE_INTERVENTIONAL = "preventive_interventional"
    PREVENTIVE_NON_MASKING = "preventive_non_masking"


class OrderingPolicy(StrEnum):
    FIXED = "fixed"
    HASH_RANDOMIZED = "hash_randomized"
    COUNTERBALANCED = "counterbalanced"


class TrialExecution(StrEnum):
    COMPLETED = "completed"
    HARNESS_ERROR = "harness_error"


class CleanupState(StrEnum):
    VERIFIED = "verified"
    FAILED = "failed"
    NOT_RUN = "not_run"


class ObservationSource(StrEnum):
    CONTROL_PLANE = "control_plane"
    RUNTIME_PROBE = "runtime_probe"
    ACTION_MANIFEST = "action_manifest"
    RUNNER_SELF_REPORT = "runner_self_report"


class EvidencePolarity(StrEnum):
    SUPPORTS = "supports"
    REBUTS = "rebuts"


class EffectivenessDimension(StrEnum):
    DESIGN = "design"
    OPERATING = "operating"
    OUTCOME = "outcome"


class ClaimRole(StrEnum):
    TARGET_LOCAL = "target_local"
    COMPENSATOR_LOCAL = "compensator_local"
    PATH = "path"
    OTHER = "other"


class PointKind(StrEnum):
    REACHABILITY = "reachability"
    MECHANISM = "mechanism"
    CURRENT_STATE = "current_state"
    LOCAL_OUTCOME = "local_outcome"
    PATH_OUTCOME = "path_outcome"


class ContrastKind(StrEnum):
    ATTACK_EFFECT = "attack_effect"
    BENIGN_INVARIANCE = "benign_invariance"
    SHAM_INVARIANCE = "sham_invariance"
    CONTROL_INTERACTION = "control_interaction"
    OTHER = "other"


class EstimandKind(StrEnum):
    MECHANISM_EFFECT = "mechanism_effect"
    REMEDIATION_EFFECT = "remediation_effect"
    TEST_SENSITIVITY = "test_sensitivity"


class Comparator(StrEnum):
    EQUAL = "equal"
    NOT_EQUAL = "not_equal"
    TRUE_TO_FALSE = "true_to_false"
    FALSE_TO_TRUE = "false_to_true"
    INCREASES = "increases"
    DECREASES = "decreases"
    LESS_OR_EQUAL = "less_or_equal"
    GREATER_OR_EQUAL = "greater_or_equal"


class Aggregation(StrEnum):
    ALL = "all"
    ANY = "any"


class ProtocolState(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    INCOMPLETE = "incomplete"
    ERROR = "error"


class EffectDirection(StrEnum):
    BENEFICIAL = "beneficial"
    NULL = "null"
    HARMFUL = "harmful"
    HETEROGENEOUS = "heterogeneous"
    UNRESOLVED = "unresolved"


class ExpectationState(StrEnum):
    SATISFIED = "satisfied"
    VIOLATED = "violated"
    HETEROGENEOUS = "heterogeneous"
    UNRESOLVED = "unresolved"


class TruthState(StrEnum):
    NEITHER = "neither"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    CONFLICTING = "conflicting"


class ExerciseState(StrEnum):
    EXERCISED = "exercised"
    PARTIALLY_EXERCISED = "partially_exercised"
    NOT_EXERCISED = "not_exercised"
    UNKNOWN = "unknown"


class CheckCategory(StrEnum):
    DESIGN_COMPLETENESS = "design_completeness"
    ORDERING = "ordering"
    EVIDENCE = "evidence"
    FACTOR_OBSERVATION = "factor_observation"
    RESET = "reset"
    UNDECLARED_DIFF = "undeclared_diff"
    COVARIATE_EQUIVALENCE = "covariate_equivalence"
    ACTION_MATCH = "action_match"
    ASSERTION = "assertion"
    CONTRAST = "contrast"
    CLEANUP = "cleanup"


class FactorSpec(BaseModel):
    name: str = Field(min_length=1)
    role: FactorRole
    levels: list[str] = Field(min_length=2)
    description: str = Field(min_length=1)

    @model_validator(mode="after")
    def unique_nonempty_levels(self) -> FactorSpec:
        if any(not level for level in self.levels):
            raise ValueError(f"factor {self.name!r} has an empty level")
        if len(set(self.levels)) != len(self.levels):
            raise ValueError(f"factor {self.name!r} has duplicate levels")
        return self


class CellSpec(BaseModel):
    id: str = Field(min_length=1)
    factors: dict[str, str]
    tags: set[str] = Field(default_factory=set)


class TrialPlan(BaseModel):
    blocks: list[str] = Field(min_length=1)
    replicates: int = Field(ge=1)
    ordering: OrderingPolicy
    seed: str = Field(min_length=1)

    @model_validator(mode="after")
    def unique_blocks(self) -> TrialPlan:
        if any(not block for block in self.blocks):
            raise ValueError("block ids must be nonempty")
        if len(set(self.blocks)) != len(self.blocks):
            raise ValueError("block ids must be unique")
        return self


class FactorObservation(BaseModel):
    level: str
    source: ObservationSource
    evidence_ids: list[str] = Field(min_length=1)


class Observation(BaseModel):
    value: TypedValue
    source: str = Field(min_length=1)
    evidence_ids: list[str] = Field(min_length=1)
    correlation_id: str | None = None
    unit: str | None = None


class TrialRecord(BaseModel):
    id: str = Field(min_length=1)
    spec_id: str = Field(min_length=1)
    cell_id: str = Field(min_length=1)
    block_id: str = Field(min_length=1)
    replicate: NonNegativeInt
    sequence: NonNegativeInt
    started_at: AwareDatetime
    ended_at: AwareDatetime
    execution: TrialExecution
    action_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    input_seed: str = Field(min_length=1)
    reset_lineage: str = Field(min_length=1)
    reset_epoch: NonNegativeInt
    reset_verified: bool
    reset_evidence_ids: list[str] = Field(min_length=1)
    covariate_snapshot_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    covariate_evidence_ids: list[str] = Field(min_length=1)
    declared_intervention_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    factor_observations: dict[str, FactorObservation]
    undeclared_diff: dict[str, str] = Field(default_factory=dict)
    observations: dict[str, Observation]
    cleanup: CleanupState
    cleanup_evidence_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def coherent_times_and_cleanup(self) -> TrialRecord:
        if self.ended_at < self.started_at:
            raise ValueError("trial ended before it started")
        if self.cleanup != CleanupState.NOT_RUN and not self.cleanup_evidence_ids:
            raise ValueError("a cleanup result requires evidence")
        return self


class CellSelector(BaseModel):
    where: dict[str, str] = Field(default_factory=dict)
    tags: set[str] = Field(default_factory=set)


class PointAssertion(BaseModel):
    id: str = Field(min_length=1)
    claim_id: str = Field(min_length=1)
    claim_role: ClaimRole
    dimension: EffectivenessDimension
    kind: PointKind
    selector: CellSelector
    observation: str = Field(min_length=1)
    comparator: Comparator
    expected: TypedValue
    aggregation: Aggregation
    polarity: EvidencePolarity
    exercise_observation: str | None = None
    purpose: str = Field(min_length=1)

    @model_validator(mode="after")
    def point_comparator_is_unary(self) -> PointAssertion:
        if self.comparator in {
            Comparator.TRUE_TO_FALSE,
            Comparator.FALSE_TO_TRUE,
            Comparator.INCREASES,
            Comparator.DECREASES,
        }:
            raise ValueError("point assertions require a unary comparator")
        return self


class FactorContrast(BaseModel):
    id: str = Field(min_length=1)
    claim_id: str = Field(min_length=1)
    kind: ContrastKind
    estimand: EstimandKind
    factor: str = Field(min_length=1)
    from_level: str = Field(min_length=1)
    to_level: str = Field(min_length=1)
    where: dict[str, str] = Field(default_factory=dict)
    observation: str = Field(min_length=1)
    operator: Comparator
    purpose: str = Field(min_length=1)

    @model_validator(mode="after")
    def contrast_is_binary(self) -> FactorContrast:
        if self.from_level == self.to_level:
            raise ValueError("contrast levels must differ")
        if self.factor in self.where:
            raise ValueError("where cannot constrain the contrasted factor")
        if self.operator in {
            Comparator.LESS_OR_EQUAL,
            Comparator.GREATER_OR_EQUAL,
        }:
            raise ValueError("contrast requires a binary relation operator")
        return self


class ExperimentSpec(BaseModel):
    id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    profile: ProtocolProfile
    factors: list[FactorSpec] = Field(min_length=1)
    cells: list[CellSpec] = Field(min_length=1)
    plan: TrialPlan
    claims: list[ClaimSpec] = Field(min_length=1)
    point_assertions: list[PointAssertion] = Field(default_factory=list)
    contrasts: list[FactorContrast] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_design(self) -> ExperimentSpec:
        factors = {factor.name: factor for factor in self.factors}
        if len(factors) != len(self.factors):
            raise ValueError("factor names must be unique")
        cell_ids = [cell.id for cell in self.cells]
        if len(set(cell_ids)) != len(cell_ids):
            raise ValueError("cell ids must be unique")
        assignments: set[tuple[tuple[str, str], ...]] = set()
        for cell in self.cells:
            if set(cell.factors) != set(factors):
                raise ValueError(f"cell {cell.id!r} does not assign every factor exactly once")
            for name, level in cell.factors.items():
                if level not in factors[name].levels:
                    raise ValueError(
                        f"cell {cell.id!r} uses unknown level {level!r} for {name!r}"
                    )
            assignment = tuple(sorted(cell.factors.items()))
            if assignment in assignments:
                raise ValueError(f"duplicate assignment in cell {cell.id!r}")
            assignments.add(assignment)

        claim_ids = [claim.id for claim in self.claims]
        if len(set(claim_ids)) != len(claim_ids):
            raise ValueError("claim ids must be unique")
        declared_claim_ids = set(claim_ids)
        for assertion in self.point_assertions:
            if assertion.claim_id not in declared_claim_ids:
                raise ValueError(
                    f"assertion {assertion.id!r} references an undeclared claim"
                )
            self._validate_selector(assertion.selector.where, factors)
            if not any(_cell_matches(cell, assertion.selector) for cell in self.cells):
                raise ValueError(f"assertion {assertion.id!r} selects no declared cell")
        for contrast in self.contrasts:
            if contrast.claim_id not in declared_claim_ids:
                raise ValueError(
                    f"contrast {contrast.id!r} references an undeclared claim"
                )
            if contrast.factor not in factors:
                raise ValueError(f"contrast uses unknown factor {contrast.factor!r}")
            factor = factors[contrast.factor]
            if (
                contrast.from_level not in factor.levels
                or contrast.to_level not in factor.levels
            ):
                raise ValueError(f"contrast {contrast.id!r} uses an unknown level")
            self._validate_selector(contrast.where, factors)

        assertion_ids = [assertion.id for assertion in self.point_assertions]
        if len(set(assertion_ids)) != len(assertion_ids):
            raise ValueError("point assertion ids must be unique")
        contrast_ids = [contrast.id for contrast in self.contrasts]
        if len(set(contrast_ids)) != len(contrast_ids):
            raise ValueError("contrast ids must be unique")
        claim_declarations: dict[
            str, tuple[ClaimRole, EffectivenessDimension]
        ] = {}
        for assertion in self.point_assertions:
            declaration = (assertion.claim_role, assertion.dimension)
            previous = claim_declarations.setdefault(assertion.claim_id, declaration)
            if previous != declaration:
                raise ValueError(
                    f"claim {assertion.claim_id!r} has inconsistent role or dimension"
                )

        self._validate_profile()
        return self

    @staticmethod
    def _validate_selector(
        where: dict[str, str],
        factors: dict[str, FactorSpec],
    ) -> None:
        for name, level in where.items():
            if name not in factors:
                raise ValueError(f"selector uses unknown factor {name!r}")
            if level not in factors[name].levels:
                raise ValueError(f"selector uses unknown level {level!r} for {name!r}")

    def _validate_profile(self) -> None:
        if self.profile == ProtocolProfile.CUSTOM:
            return
        roles = {factor.role for factor in self.factors}
        required_roles = {
            FactorRole.INPUT,
            FactorRole.TARGET_CONTROL,
            FactorRole.SHAM,
        }
        if self.profile == ProtocolProfile.PREVENTIVE_NON_MASKING:
            required_roles.add(FactorRole.COMPENSATING_CONTROL)
        missing_roles = required_roles - roles
        if missing_roles:
            raise ValueError(f"profile is missing factor roles: {sorted(missing_roles)}")

        point_kinds = {point.kind for point in self.point_assertions}
        required_points = {PointKind.REACHABILITY, PointKind.MECHANISM}
        if not required_points.issubset(point_kinds):
            raise ValueError("interventional profile requires reachability and mechanism checks")

        contrast_kinds = {contrast.kind for contrast in self.contrasts}
        required_contrasts = {
            ContrastKind.ATTACK_EFFECT,
            ContrastKind.BENIGN_INVARIANCE,
            ContrastKind.SHAM_INVARIANCE,
        }
        if self.profile == ProtocolProfile.PREVENTIVE_NON_MASKING:
            required_contrasts.add(ContrastKind.CONTROL_INTERACTION)
            claim_roles = {point.claim_role for point in self.point_assertions}
            required_claim_roles = {
                ClaimRole.TARGET_LOCAL,
                ClaimRole.COMPENSATOR_LOCAL,
                ClaimRole.PATH,
            }
            if not required_claim_roles.issubset(claim_roles):
                raise ValueError(
                    "non-masking profile requires target, compensator, and path claims"
                )
        if not required_contrasts.issubset(contrast_kinds):
            raise ValueError(
                "interventional profile is missing required contrast categories"
            )


class ProtocolCheck(BaseModel):
    id: str
    category: CheckCategory
    passed: bool
    detail: str
    trial_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class AssertionResult(BaseModel):
    assertion_id: str
    claim_id: str
    polarity: EvidencePolarity
    predicate_met: bool
    exercise: ExerciseState
    complete: bool
    trial_ids: list[str]
    evidence_ids: list[str]
    detail: str


class PointClaimResult(BaseModel):
    claim_id: str
    claim_role: ClaimRole
    dimension: EffectivenessDimension
    admissibility: ProtocolState
    truth: TruthState
    exercise: ExerciseState
    assertion_results: list[AssertionResult]
    support_evidence_ids: list[str]
    rebuttal_evidence_ids: list[str]


class PairResult(BaseModel):
    left_trial_id: str
    right_trial_id: str
    expected_relation: bool | None
    reverse_relation: bool | None
    equal: bool | None
    evidence_ids: list[str]
    detail: str


class ContrastResult(BaseModel):
    contrast_id: str
    claim_id: str
    estimand: EstimandKind
    validity: ProtocolState
    expectation: ExpectationState
    effect_direction: EffectDirection
    pair_results: list[PairResult]
    checks: list[ProtocolCheck]
    evidence_ids: list[str]


class ExperimentReport(BaseModel):
    experiment_id: str
    spec_version: str
    protocol_state: ProtocolState
    protocol_checks: list[ProtocolCheck]
    point_claims: list[PointClaimResult]
    contrasts: list[ContrastResult]
    hygiene_checks: list[ProtocolCheck]


def typed_value(raw: bool | int | float | str | None) -> TypedValue:
    if type(raw) is bool:
        return BooleanValue(value=raw)
    if type(raw) is int:
        return IntegerValue(value=raw)
    if type(raw) is float:
        return NumberValue(value=raw)
    if type(raw) is str:
        return StringValue(value=raw)
    if raw is None:
        return NullValue()
    raise TypeError(f"unsupported value type: {type(raw).__name__}")


def _unwrap(value: TypedValue) -> bool | int | float | str | None:
    return value.value


def _same_typed_value(left: TypedValue, right: TypedValue) -> bool:
    return left.type == right.type and left.value == right.value


def _compare_point(actual: TypedValue, expected: TypedValue, operator: Comparator) -> bool:
    if actual.type != expected.type:
        raise TypeError(
            f"point comparison type mismatch: {actual.type!r} != {expected.type!r}"
        )
    if operator == Comparator.EQUAL:
        return _same_typed_value(actual, expected)
    if operator == Comparator.NOT_EQUAL:
        return not _same_typed_value(actual, expected)
    if operator in {Comparator.LESS_OR_EQUAL, Comparator.GREATER_OR_EQUAL}:
        if actual.type not in {"integer", "number"}:
            raise TypeError("ordered comparisons require equal numeric types")
        actual_number = float(_unwrap(actual))  # type: ignore[arg-type]
        expected_number = float(_unwrap(expected))  # type: ignore[arg-type]
        if operator == Comparator.LESS_OR_EQUAL:
            return actual_number <= expected_number
        return actual_number >= expected_number
    raise TypeError(f"{operator} is not a point comparator")


def _compare_pair(
    left: TypedValue,
    right: TypedValue,
    operator: Comparator,
) -> bool:
    if left.type != right.type:
        raise TypeError(
            f"paired comparison type mismatch: {left.type!r} != {right.type!r}"
        )
    if operator == Comparator.EQUAL:
        return _same_typed_value(left, right)
    if operator == Comparator.NOT_EQUAL:
        return not _same_typed_value(left, right)
    if operator == Comparator.TRUE_TO_FALSE:
        if left.type != "boolean":
            raise TypeError("true_to_false requires boolean observations")
        return left.value is True and right.value is False
    if operator == Comparator.FALSE_TO_TRUE:
        if left.type != "boolean":
            raise TypeError("false_to_true requires boolean observations")
        return left.value is False and right.value is True
    if operator in {Comparator.INCREASES, Comparator.DECREASES}:
        if left.type not in {"integer", "number"}:
            raise TypeError("directional comparisons require equal numeric types")
        left_number = float(_unwrap(left))  # type: ignore[arg-type]
        right_number = float(_unwrap(right))  # type: ignore[arg-type]
        if operator == Comparator.INCREASES:
            return right_number > left_number
        return right_number < left_number
    raise TypeError(f"{operator} is not a pair comparator")


def _reverse_operator(operator: Comparator) -> Comparator:
    return {
        Comparator.TRUE_TO_FALSE: Comparator.FALSE_TO_TRUE,
        Comparator.FALSE_TO_TRUE: Comparator.TRUE_TO_FALSE,
        Comparator.INCREASES: Comparator.DECREASES,
        Comparator.DECREASES: Comparator.INCREASES,
        Comparator.EQUAL: Comparator.NOT_EQUAL,
        Comparator.NOT_EQUAL: Comparator.EQUAL,
    }[operator]


def _cell_matches(cell: CellSpec, selector: CellSelector) -> bool:
    return all(cell.factors.get(name) == value for name, value in selector.where.items()) and (
        not selector.tags or selector.tags.issubset(cell.tags)
    )


def planned_trial_order(spec: ExperimentSpec) -> list[tuple[str, str, int]]:
    result: list[tuple[str, str, int]] = []
    cell_ids = [cell.id for cell in spec.cells]
    for block_index, block in enumerate(spec.plan.blocks):
        for replicate in range(spec.plan.replicates):
            ordered = list(cell_ids)
            if spec.plan.ordering == OrderingPolicy.HASH_RANDOMIZED:
                ordered.sort(
                    key=lambda cell_id: hashlib.sha256(
                        f"{spec.plan.seed}|{block}|{replicate}|{cell_id}".encode()
                    ).hexdigest()
                )
            elif spec.plan.ordering == OrderingPolicy.COUNTERBALANCED:
                offset = (block_index + replicate) % len(ordered)
                ordered = ordered[offset:] + ordered[:offset]
                if (block_index + replicate) % 2:
                    ordered.reverse()
            result.extend((cell_id, block, replicate) for cell_id in ordered)
    return result


class ProtocolEvaluator:
    """Evaluate execution validity, estimands, and point claims independently."""

    def evaluate(
        self,
        spec: ExperimentSpec,
        trials: list[TrialRecord],
    ) -> ExperimentReport:
        checks: list[ProtocolCheck] = []
        hygiene: list[ProtocolCheck] = []
        cell_by_id = {cell.id: cell for cell in spec.cells}
        expected_order = planned_trial_order(spec)
        expected_keys = set(expected_order)

        duplicate_ids = len({trial.id for trial in trials}) != len(trials)
        trial_by_key: dict[tuple[str, str, int], TrialRecord] = {}
        duplicate_keys: list[tuple[str, str, int]] = []
        for trial in trials:
            key = (trial.cell_id, trial.block_id, int(trial.replicate))
            if key in trial_by_key:
                duplicate_keys.append(key)
            trial_by_key[key] = trial

        actual_keys = set(trial_by_key)
        missing = sorted(expected_keys - actual_keys)
        extra = sorted(actual_keys - expected_keys)
        complete = not duplicate_ids and not duplicate_keys and not missing and not extra
        checks.append(
            ProtocolCheck(
                id="design-completeness",
                category=CheckCategory.DESIGN_COMPLETENESS,
                passed=complete,
                detail=(
                    "every declared cell/block/replicate is present exactly once"
                    if complete
                    else (
                        f"duplicate_ids={duplicate_ids}; duplicate_keys={duplicate_keys!r}; "
                        f"missing={missing!r}; extra={extra!r}"
                    )
                ),
                trial_ids=[trial.id for trial in trials],
            )
        )

        ordered_trials = sorted(trials, key=lambda trial: int(trial.sequence))
        sequence_unique = len({int(trial.sequence) for trial in trials}) == len(trials)
        observed_order = [
            (trial.cell_id, trial.block_id, int(trial.replicate))
            for trial in ordered_trials
        ]
        order_ok = (
            complete
            and sequence_unique
            and [int(trial.sequence) for trial in ordered_trials]
            == list(range(len(trials)))
            and observed_order == expected_order
        )
        checks.append(
            ProtocolCheck(
                id="trial-order",
                category=CheckCategory.ORDERING,
                passed=order_ok,
                detail=(
                    "recorded sequence matches the declared ordering policy"
                    if order_ok
                    else "sequence is duplicated, non-contiguous, or differs from the plan"
                ),
                trial_ids=[trial.id for trial in ordered_trials],
            )
        )

        harness_errors = [
            trial for trial in trials if trial.execution == TrialExecution.HARNESS_ERROR
        ]
        checks.append(
            ProtocolCheck(
                id="trial-execution",
                category=CheckCategory.DESIGN_COMPLETENESS,
                passed=not harness_errors,
                detail=(
                    "all planned trials completed"
                    if not harness_errors
                    else "harness errors: " + ", ".join(t.id for t in harness_errors)
                ),
                trial_ids=[trial.id for trial in harness_errors],
            )
        )

        for trial in trials:
            checks.extend(self._validate_trial(spec, trial, cell_by_id.get(trial.cell_id)))
            cleanup_ok = trial.cleanup == CleanupState.VERIFIED
            hygiene.append(
                ProtocolCheck(
                    id=f"cleanup:{trial.id}",
                    category=CheckCategory.CLEANUP,
                    passed=cleanup_ok,
                    detail=(
                        "cleanup verified"
                        if cleanup_ok
                        else f"cleanup state is {trial.cleanup}"
                    ),
                    trial_ids=[trial.id],
                    evidence_ids=trial.cleanup_evidence_ids,
                )
            )

        invalid_trial_ids = {
            trial_id
            for check in checks
            if not check.passed
            for trial_id in check.trial_ids
        }
        point_results = self._evaluate_points(spec, trials, invalid_trial_ids)
        contrast_results = [
            self._evaluate_contrast(spec, contrast, trial_by_key, invalid_trial_ids)
            for contrast in spec.contrasts
        ]

        if harness_errors:
            protocol_state = ProtocolState.ERROR
        elif not complete:
            protocol_state = ProtocolState.INCOMPLETE
        elif all(check.passed for check in checks) and all(
            result.validity == ProtocolState.VALID for result in contrast_results
        ):
            protocol_state = ProtocolState.VALID
        else:
            protocol_state = ProtocolState.INVALID

        return ExperimentReport(
            experiment_id=spec.id,
            spec_version=spec.version,
            protocol_state=protocol_state,
            protocol_checks=checks,
            point_claims=point_results,
            contrasts=contrast_results,
            hygiene_checks=hygiene,
        )

    @staticmethod
    def _validate_trial(
        spec: ExperimentSpec,
        trial: TrialRecord,
        cell: CellSpec | None,
    ) -> list[ProtocolCheck]:
        if cell is None:
            return [
                ProtocolCheck(
                    id=f"cell:{trial.id}",
                    category=CheckCategory.DESIGN_COMPLETENESS,
                    passed=False,
                    detail=f"unknown cell {trial.cell_id!r}",
                    trial_ids=[trial.id],
                )
            ]

        checks: list[ProtocolCheck] = []
        spec_matches = trial.spec_id == spec.id
        checks.append(
            ProtocolCheck(
                id=f"spec:{trial.id}",
                category=CheckCategory.DESIGN_COMPLETENESS,
                passed=spec_matches,
                detail="spec id matches" if spec_matches else "trial references another spec",
                trial_ids=[trial.id],
            )
        )

        factor_names_match = set(trial.factor_observations) == set(cell.factors)
        factor_values_match = factor_names_match and all(
            trial.factor_observations[name].level == level
            for name, level in cell.factors.items()
        )
        factors_by_name = {factor.name: factor for factor in spec.factors}
        independent = factor_names_match and all(
            (
                factors_by_name[name].role
                in {FactorRole.INPUT, FactorRole.CONTEXT}
                or trial.factor_observations[name].source
                in {ObservationSource.CONTROL_PLANE, ObservationSource.RUNTIME_PROBE}
            )
            for name in cell.factors
        )
        factor_evidence = sorted(
            {
                evidence_id
                for observation in trial.factor_observations.values()
                for evidence_id in observation.evidence_ids
            }
        )
        checks.append(
            ProtocolCheck(
                id=f"factors:{trial.id}",
                category=CheckCategory.FACTOR_OBSERVATION,
                passed=factor_values_match and independent and bool(factor_evidence),
                detail=(
                    "declared factor levels are independently observed"
                    if factor_values_match and independent and factor_evidence
                    else (
                        f"names_match={factor_names_match}; values_match={factor_values_match}; "
                        f"independent={independent}; evidence={bool(factor_evidence)}"
                    )
                ),
                trial_ids=[trial.id],
                evidence_ids=factor_evidence,
            )
        )

        checks.append(
            ProtocolCheck(
                id=f"reset:{trial.id}",
                category=CheckCategory.RESET,
                passed=trial.reset_verified and bool(trial.reset_evidence_ids),
                detail=(
                    "reset lineage verified"
                    if trial.reset_verified and trial.reset_evidence_ids
                    else "reset is not independently verified"
                ),
                trial_ids=[trial.id],
                evidence_ids=trial.reset_evidence_ids,
            )
        )
        checks.append(
            ProtocolCheck(
                id=f"undeclared-diff:{trial.id}",
                category=CheckCategory.UNDECLARED_DIFF,
                passed=not trial.undeclared_diff,
                detail=(
                    "no undeclared environment difference"
                    if not trial.undeclared_diff
                    else f"undeclared differences: {trial.undeclared_diff!r}"
                ),
                trial_ids=[trial.id],
                evidence_ids=trial.covariate_evidence_ids,
            )
        )
        observation_evidence = sorted(
            {
                evidence_id
                for observation in trial.observations.values()
                for evidence_id in observation.evidence_ids
            }
        )
        evidence_ok = bool(
            trial.covariate_evidence_ids
            and trial.reset_evidence_ids
            and factor_evidence
            and observation_evidence
        )
        checks.append(
            ProtocolCheck(
                id=f"evidence:{trial.id}",
                category=CheckCategory.EVIDENCE,
                passed=evidence_ok,
                detail=(
                    "trial inputs, factors, reset, and observations have evidence"
                    if evidence_ok
                    else "one or more required evidence classes are empty"
                ),
                trial_ids=[trial.id],
                evidence_ids=sorted(
                    {
                        *trial.covariate_evidence_ids,
                        *trial.reset_evidence_ids,
                        *factor_evidence,
                        *observation_evidence,
                    }
                ),
            )
        )
        return checks

    def _evaluate_points(
        self,
        spec: ExperimentSpec,
        trials: list[TrialRecord],
        invalid_trial_ids: set[str],
    ) -> list[PointClaimResult]:
        assertion_results = [
            self._evaluate_assertion(
                spec,
                assertion,
                trials,
                invalid_trial_ids,
            )
            for assertion in spec.point_assertions
        ]
        claim_ids = list(dict.fromkeys(assertion.claim_id for assertion in spec.point_assertions))
        results: list[PointClaimResult] = []
        for claim_id in claim_ids:
            declarations = [
                assertion
                for assertion in spec.point_assertions
                if assertion.claim_id == claim_id
            ]
            claim_assertions = [
                result for result in assertion_results if result.claim_id == claim_id
            ]
            support_results = [
                result
                for result in claim_assertions
                if result.polarity == EvidencePolarity.SUPPORTS
            ]
            rebuttal_results = [
                result
                for result in claim_assertions
                if result.polarity == EvidencePolarity.REBUTS
            ]
            support = bool(support_results) and all(
                result.predicate_met and result.complete for result in support_results
            )
            rebut = any(
                result.predicate_met and result.complete for result in rebuttal_results
            )
            truth = {
                (False, False): TruthState.NEITHER,
                (True, False): TruthState.SUPPORTED,
                (False, True): TruthState.REFUTED,
                (True, True): TruthState.CONFLICTING,
            }[(support, rebut)]
            exercises = {result.exercise for result in claim_assertions}
            if exercises == {ExerciseState.EXERCISED}:
                exercise = ExerciseState.EXERCISED
            elif exercises == {ExerciseState.NOT_EXERCISED}:
                exercise = ExerciseState.NOT_EXERCISED
            elif ExerciseState.UNKNOWN in exercises or not exercises:
                exercise = ExerciseState.UNKNOWN
            else:
                exercise = ExerciseState.PARTIALLY_EXERCISED
            if all(result.complete for result in claim_assertions):
                admissibility = ProtocolState.VALID
            elif any(not result.trial_ids for result in claim_assertions):
                admissibility = ProtocolState.INCOMPLETE
            else:
                admissibility = ProtocolState.INVALID
            results.append(
                PointClaimResult(
                    claim_id=claim_id,
                    claim_role=declarations[0].claim_role,
                    dimension=declarations[0].dimension,
                    admissibility=admissibility,
                    truth=truth,
                    exercise=exercise,
                    assertion_results=claim_assertions,
                    support_evidence_ids=sorted(
                        {
                            evidence_id
                            for result in support_results
                            if result.predicate_met
                            for evidence_id in result.evidence_ids
                        }
                    ),
                    rebuttal_evidence_ids=sorted(
                        {
                            evidence_id
                            for result in rebuttal_results
                            if result.predicate_met
                            for evidence_id in result.evidence_ids
                        }
                    ),
                )
            )
        return results

    @staticmethod
    def _evaluate_assertion(
        spec: ExperimentSpec,
        assertion: PointAssertion,
        trials: list[TrialRecord],
        invalid_trial_ids: set[str],
    ) -> AssertionResult:
        matched_cell_ids = {
            cell.id
            for cell in spec.cells
            if _cell_matches(cell, assertion.selector)
        }
        expected_keys = {
            (cell_id, block, replicate)
            for cell_id in matched_cell_ids
            for block in spec.plan.blocks
            for replicate in range(spec.plan.replicates)
        }
        selected = [
            trial
            for trial in trials
            if trial.cell_id in matched_cell_ids
            and trial.execution == TrialExecution.COMPLETED
        ]
        actual_keys = {
            (trial.cell_id, trial.block_id, int(trial.replicate))
            for trial in selected
        }
        design_complete = actual_keys == expected_keys
        if not selected or not matched_cell_ids:
            return AssertionResult(
                assertion_id=assertion.id,
                claim_id=assertion.claim_id,
                polarity=assertion.polarity,
                predicate_met=False,
                exercise=ExerciseState.UNKNOWN,
                complete=False,
                trial_ids=[],
                evidence_ids=[],
                detail="selector matched no completed trial",
            )

        exercised: list[TrialRecord] = []
        exercise_unknown = False
        exercise_evidence_ids: set[str] = set()
        for trial in selected:
            if assertion.exercise_observation is None:
                exercised.append(trial)
                continue
            observation = trial.observations.get(assertion.exercise_observation)
            if observation is None or observation.value.type != "boolean":
                exercise_unknown = True
                continue
            exercise_evidence_ids.update(observation.evidence_ids)
            if observation.value.value is True:
                exercised.append(trial)
        if not exercised:
            exercise = (
                ExerciseState.UNKNOWN if exercise_unknown else ExerciseState.NOT_EXERCISED
            )
            return AssertionResult(
                assertion_id=assertion.id,
                claim_id=assertion.claim_id,
                polarity=assertion.polarity,
                predicate_met=False,
                exercise=exercise,
                complete=(
                    design_complete
                    and not exercise_unknown
                    and not any(trial.id in invalid_trial_ids for trial in selected)
                    and bool(exercise_evidence_ids)
                ),
                trial_ids=[trial.id for trial in selected],
                evidence_ids=sorted(exercise_evidence_ids),
                detail="the selected control was not exercised",
            )

        predicates: list[bool] = []
        complete = design_complete and not any(
            trial.id in invalid_trial_ids for trial in selected
        )
        evidence_ids: set[str] = set(exercise_evidence_ids)
        details: list[str] = []
        for trial in exercised:
            observation = trial.observations.get(assertion.observation)
            if observation is None:
                complete = False
                details.append(f"{trial.id}: missing {assertion.observation}")
                continue
            try:
                predicate = _compare_point(
                    observation.value,
                    assertion.expected,
                    assertion.comparator,
                )
            except TypeError as exc:
                complete = False
                details.append(f"{trial.id}: {exc}")
                continue
            predicates.append(predicate)
            evidence_ids.update(observation.evidence_ids)
        if assertion.aggregation == Aggregation.ALL:
            predicate_met = bool(predicates) and all(predicates)
        else:
            predicate_met = any(predicates)
        return AssertionResult(
            assertion_id=assertion.id,
            claim_id=assertion.claim_id,
            polarity=assertion.polarity,
            predicate_met=predicate_met,
            exercise=ExerciseState.EXERCISED,
            complete=complete and bool(evidence_ids),
            trial_ids=[trial.id for trial in exercised],
            evidence_ids=sorted(evidence_ids),
            detail=assertion.purpose if predicate_met and complete else "; ".join(details),
        )

    def _evaluate_contrast(
        self,
        spec: ExperimentSpec,
        contrast: FactorContrast,
        trial_by_key: dict[tuple[str, str, int], TrialRecord],
        invalid_trial_ids: set[str],
    ) -> ContrastResult:
        cell_pairs, unmatched = self._pair_cells(spec.cells, contrast)
        checks: list[ProtocolCheck] = []
        pair_results: list[PairResult] = []
        if unmatched or not cell_pairs:
            checks.append(
                ProtocolCheck(
                    id=f"pairing:{contrast.id}",
                    category=CheckCategory.CONTRAST,
                    passed=False,
                    detail=f"unmatched cells={unmatched!r}; pair_count={len(cell_pairs)}",
                )
            )

        expected_trial_keys = {
            (block, replicate)
            for block in spec.plan.blocks
            for replicate in range(spec.plan.replicates)
        }
        for left_cell, right_cell in cell_pairs:
            for block, replicate in sorted(expected_trial_keys):
                left = trial_by_key.get((left_cell.id, block, replicate))
                right = trial_by_key.get((right_cell.id, block, replicate))
                if left is None or right is None:
                    checks.append(
                        ProtocolCheck(
                            id=(
                                f"pair-missing:{contrast.id}:{left_cell.id}:"
                                f"{right_cell.id}:{block}:{replicate}"
                            ),
                            category=CheckCategory.CONTRAST,
                            passed=False,
                            detail="paired trial is missing",
                            trial_ids=[
                                trial.id for trial in (left, right) if trial is not None
                            ],
                        )
                    )
                    continue
                invalid_pair_trials = sorted(
                    {left.id, right.id}.intersection(invalid_trial_ids)
                )
                if invalid_pair_trials:
                    checks.append(
                        ProtocolCheck(
                            id=f"pair-invalid:{contrast.id}:{left.id}:{right.id}",
                            category=CheckCategory.CONTRAST,
                            passed=False,
                            detail=(
                                "paired trial failed a protocol validity gate: "
                                + ", ".join(invalid_pair_trials)
                            ),
                            trial_ids=[left.id, right.id],
                        )
                    )
                pair_results.append(self._evaluate_pair(contrast, left, right, checks))

        if not pair_results:
            validity = ProtocolState.INCOMPLETE
            expectation = ExpectationState.UNRESOLVED
            direction = EffectDirection.UNRESOLVED
        elif any(not check.passed for check in checks):
            validity = ProtocolState.INVALID
            expectation = ExpectationState.UNRESOLVED
            direction = EffectDirection.UNRESOLVED
        else:
            validity = ProtocolState.VALID
            expectation = self._expectation_state(pair_results)
            direction = self._effect_direction(contrast.operator, pair_results)
        evidence_ids = sorted(
            {
                evidence_id
                for pair in pair_results
                for evidence_id in pair.evidence_ids
            }
        )
        if not evidence_ids:
            validity = ProtocolState.INVALID
            expectation = ExpectationState.UNRESOLVED
            direction = EffectDirection.UNRESOLVED
            checks.append(
                ProtocolCheck(
                    id=f"contrast-evidence:{contrast.id}",
                    category=CheckCategory.EVIDENCE,
                    passed=False,
                    detail="contrast has no evidence",
                )
            )
        return ContrastResult(
            contrast_id=contrast.id,
            claim_id=contrast.claim_id,
            estimand=contrast.estimand,
            validity=validity,
            expectation=expectation,
            effect_direction=direction,
            pair_results=pair_results,
            checks=checks,
            evidence_ids=evidence_ids,
        )

    @staticmethod
    def _pair_cells(
        cells: list[CellSpec],
        contrast: FactorContrast,
    ) -> tuple[list[tuple[CellSpec, CellSpec]], list[str]]:
        candidates = [
            cell
            for cell in cells
            if all(cell.factors.get(name) == level for name, level in contrast.where.items())
        ]
        left = [
            cell
            for cell in candidates
            if cell.factors[contrast.factor] == contrast.from_level
        ]
        right = [
            cell
            for cell in candidates
            if cell.factors[contrast.factor] == contrast.to_level
        ]

        def key(cell: CellSpec) -> tuple[tuple[str, str], ...]:
            return tuple(
                sorted(
                    (name, level)
                    for name, level in cell.factors.items()
                    if name != contrast.factor
                )
            )

        left_by_key = {key(cell): cell for cell in left}
        right_by_key = {key(cell): cell for cell in right}
        common = sorted(set(left_by_key) & set(right_by_key))
        unmatched = sorted(
            [cell.id for k, cell in left_by_key.items() if k not in right_by_key]
            + [cell.id for k, cell in right_by_key.items() if k not in left_by_key]
        )
        return [(left_by_key[k], right_by_key[k]) for k in common], unmatched

    @staticmethod
    def _evaluate_pair(
        contrast: FactorContrast,
        left: TrialRecord,
        right: TrialRecord,
        checks: list[ProtocolCheck],
    ) -> PairResult:
        evidence_ids: set[str] = set()
        covariates_match = (
            left.covariate_snapshot_digest == right.covariate_snapshot_digest
        )
        checks.append(
            ProtocolCheck(
                id=f"covariates:{contrast.id}:{left.id}:{right.id}",
                category=CheckCategory.COVARIATE_EQUIVALENCE,
                passed=covariates_match,
                detail=(
                    "paired covariate snapshots match"
                    if covariates_match
                    else "paired covariate snapshots differ"
                ),
                trial_ids=[left.id, right.id],
                evidence_ids=sorted(
                    {*left.covariate_evidence_ids, *right.covariate_evidence_ids}
                ),
            )
        )
        actions_match = left.action_digest == right.action_digest
        checks.append(
            ProtocolCheck(
                id=f"action:{contrast.id}:{left.id}:{right.id}",
                category=CheckCategory.ACTION_MATCH,
                passed=actions_match,
                detail=(
                    "paired action digests match"
                    if actions_match
                    else "paired actions differ"
                ),
                trial_ids=[left.id, right.id],
            )
        )
        input_seeds_match = left.input_seed == right.input_seed
        checks.append(
            ProtocolCheck(
                id=f"input-seed:{contrast.id}:{left.id}:{right.id}",
                category=CheckCategory.ACTION_MATCH,
                passed=input_seeds_match,
                detail=(
                    "paired input seeds match"
                    if input_seeds_match
                    else "paired input seeds differ"
                ),
                trial_ids=[left.id, right.id],
            )
        )
        reset_lineage_matches = left.reset_lineage == right.reset_lineage
        checks.append(
            ProtocolCheck(
                id=f"reset-lineage:{contrast.id}:{left.id}:{right.id}",
                category=CheckCategory.RESET,
                passed=reset_lineage_matches,
                detail=(
                    "paired trials derive from the same reset lineage"
                    if reset_lineage_matches
                    else "paired trials derive from different reset lineages"
                ),
                trial_ids=[left.id, right.id],
                evidence_ids=sorted(
                    {*left.reset_evidence_ids, *right.reset_evidence_ids}
                ),
            )
        )
        left_observation = left.observations.get(contrast.observation)
        right_observation = right.observations.get(contrast.observation)
        if left_observation is None or right_observation is None:
            checks.append(
                ProtocolCheck(
                    id=f"observation:{contrast.id}:{left.id}:{right.id}",
                    category=CheckCategory.CONTRAST,
                    passed=False,
                    detail=f"missing observation {contrast.observation!r}",
                    trial_ids=[left.id, right.id],
                )
            )
            return PairResult(
                left_trial_id=left.id,
                right_trial_id=right.id,
                expected_relation=None,
                reverse_relation=None,
                equal=None,
                evidence_ids=[],
                detail="missing observation",
            )
        evidence_ids.update(left_observation.evidence_ids)
        evidence_ids.update(right_observation.evidence_ids)
        units_match = left_observation.unit == right_observation.unit
        checks.append(
            ProtocolCheck(
                id=f"unit:{contrast.id}:{left.id}:{right.id}",
                category=CheckCategory.CONTRAST,
                passed=units_match,
                detail=(
                    "paired observation units match"
                    if units_match
                    else "paired observation units differ"
                ),
                trial_ids=[left.id, right.id],
                evidence_ids=sorted(evidence_ids),
            )
        )
        if not units_match:
            return PairResult(
                left_trial_id=left.id,
                right_trial_id=right.id,
                expected_relation=None,
                reverse_relation=None,
                equal=None,
                evidence_ids=sorted(evidence_ids),
                detail="paired observation units differ",
            )
        try:
            expected = _compare_pair(
                left_observation.value,
                right_observation.value,
                contrast.operator,
            )
            reverse = _compare_pair(
                left_observation.value,
                right_observation.value,
                _reverse_operator(contrast.operator),
            )
            equal = _same_typed_value(left_observation.value, right_observation.value)
            detail = f"{_unwrap(left_observation.value)!r} -> {_unwrap(right_observation.value)!r}"
        except (TypeError, KeyError) as exc:
            expected = None
            reverse = None
            equal = None
            detail = str(exc)
            checks.append(
                ProtocolCheck(
                    id=f"type:{contrast.id}:{left.id}:{right.id}",
                    category=CheckCategory.CONTRAST,
                    passed=False,
                    detail=detail,
                    trial_ids=[left.id, right.id],
                    evidence_ids=sorted(evidence_ids),
                )
            )
        return PairResult(
            left_trial_id=left.id,
            right_trial_id=right.id,
            expected_relation=expected,
            reverse_relation=reverse,
            equal=equal,
            evidence_ids=sorted(evidence_ids),
            detail=detail,
        )

    @staticmethod
    def _expectation_state(pairs: list[PairResult]) -> ExpectationState:
        if any(pair.expected_relation is None for pair in pairs):
            return ExpectationState.UNRESOLVED
        if all(pair.expected_relation is True for pair in pairs):
            return ExpectationState.SATISFIED
        if all(pair.reverse_relation is True for pair in pairs):
            return ExpectationState.VIOLATED
        return ExpectationState.HETEROGENEOUS

    @staticmethod
    def _effect_direction(
        operator: Comparator,
        pairs: list[PairResult],
    ) -> EffectDirection:
        if any(pair.expected_relation is None for pair in pairs):
            return EffectDirection.UNRESOLVED
        if operator == Comparator.EQUAL:
            if all(pair.equal is True for pair in pairs):
                return EffectDirection.NULL
            return EffectDirection.HETEROGENEOUS
        if operator == Comparator.NOT_EQUAL:
            if all(pair.equal is True for pair in pairs):
                return EffectDirection.NULL
            return EffectDirection.HETEROGENEOUS
        if all(pair.expected_relation is True for pair in pairs):
            return EffectDirection.BENEFICIAL
        if all(pair.equal is True for pair in pairs):
            return EffectDirection.NULL
        if all(pair.reverse_relation is True for pair in pairs):
            return EffectDirection.HARMFUL
        return EffectDirection.HETEROGENEOUS
