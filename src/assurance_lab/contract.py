"""Declarative experiment contracts and the preventive non-masking compiler.

This module deliberately stops at compilation.  Trial execution, evidence
admission, and inference consume the compiled plan elsewhere; they do not get
to reinterpret its cells, contrasts, or primary claim wiring.
"""

from __future__ import annotations

import hashlib
import itertools
import re
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import Annotated, Literal, Protocol

import rfc8785
from pydantic import (
    AwareDatetime,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)
from pydantic import BaseModel as PydanticBaseModel

ID_PATTERN = r"^[a-z][a-z0-9._-]*$"
DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
_CANONICAL_DECIMAL = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$")
I_JSON_MAX_INTEGER = (2**53) - 1
MAX_ID_LENGTH = 128
MAX_TEXT_LENGTH = 512
MAX_VALUE_LENGTH = 4_096
MAX_DECIMAL_DIGITS = 128
MAX_BLOCKS = 64
MAX_REPLICATES = 1_000
MAX_PLANNED_TRIALS = 100_000
MAX_METRICS = 256
MAX_OBLIGATIONS = 512
Identifier = Annotated[
    str,
    Field(pattern=ID_PATTERN, max_length=MAX_ID_LENGTH),
]
NonEmptyText = Annotated[
    str,
    Field(min_length=1, max_length=MAX_TEXT_LENGTH),
]


class BaseModel(PydanticBaseModel):
    """Strict author-facing value object."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        validate_assignment=True,
        frozen=True,
    )


def _decimal_text(value: Decimal) -> str:
    if not value.is_finite():
        raise ValueError("decimal values must be finite")
    if value.is_zero():
        return "0"
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    if text == "-0":
        return "0"
    return text


class BooleanValue(BaseModel):
    type: Literal["boolean"] = "boolean"
    value: bool


class IntegerValue(BaseModel):
    type: Literal["integer"] = "integer"
    value: int = Field(
        ge=-I_JSON_MAX_INTEGER,
        le=I_JSON_MAX_INTEGER,
    )


class DecimalValue(BaseModel):
    """A finite decimal whose JSON representation has one canonical spelling."""

    type: Literal["decimal"] = "decimal"
    value: Decimal

    @field_validator("value", mode="before")
    @classmethod
    def parse_without_binary_float(cls, value: object) -> Decimal:
        if isinstance(value, float):
            raise ValueError("binary floating-point values are not accepted")
        if isinstance(value, (bool, int)):
            raise ValueError("use the integer value type for integers")
        if isinstance(value, Decimal):
            parsed = value
        elif isinstance(value, str) and _CANONICAL_DECIMAL.fullmatch(value):
            try:
                parsed = Decimal(value)
            except InvalidOperation as error:
                raise ValueError("invalid canonical decimal") from error
        else:
            raise ValueError("decimal value must be a canonical decimal string or Decimal")
        if not parsed.is_finite():
            raise ValueError("decimal values must be finite")
        digits = parsed.as_tuple()
        exponent = digits.exponent
        assert isinstance(exponent, int)
        if len(digits.digits) > MAX_DECIMAL_DIGITS or abs(exponent) > MAX_DECIMAL_DIGITS:
            raise ValueError("decimal value exceeds the configured precision or scale")
        return parsed

    @field_serializer("value", when_used="json")
    def serialize_canonically(self, value: Decimal) -> str:
        return _decimal_text(value)


CanonicalDecimalValue = DecimalValue


class StringValue(BaseModel):
    type: Literal["string"] = "string"
    value: str = Field(max_length=MAX_VALUE_LENGTH)


TypedValue = Annotated[
    BooleanValue | IntegerValue | DecimalValue | StringValue,
    Field(discriminator="type"),
]


class Stage(StrEnum):
    INPUT = "input"
    TARGET = "target"
    COMPENSATOR = "compensator"
    OUTCOME = "outcome"


class MetricValueType(StrEnum):
    BOOLEAN = "boolean"
    INTEGER = "integer"
    DECIMAL = "decimal"
    STRING = "string"


class MetricContract(BaseModel):
    id: Identifier
    component: Identifier
    stage: Stage
    value_type: MetricValueType
    unit: NonEmptyText | None = None
    extractor_id: Identifier
    evidence_class: Identifier

    @model_validator(mode="after")
    def numeric_unit_only(self) -> MetricContract:
        numeric = self.value_type in {
            MetricValueType.INTEGER,
            MetricValueType.DECIMAL,
        }
        if numeric and self.unit is None:
            raise ValueError("numeric metrics require a unit")
        if not numeric and self.unit is not None:
            raise ValueError("non-numeric metrics cannot declare a unit")
        return self


class EvidenceWindow(BaseModel):
    start: AwareDatetime
    end: AwareDatetime

    @model_validator(mode="after")
    def ordered(self) -> EvidenceWindow:
        if self.end < self.start:
            raise ValueError("evidence window ends before it starts")
        return self

    @field_serializer("start", "end", when_used="json")
    def utc_datetime(self, value: datetime) -> str:
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


class EvidencePolicyRef(BaseModel):
    id: Identifier
    version: NonEmptyText
    digest: str = Field(pattern=DIGEST_PATTERN)


class ExperimentScope(BaseModel):
    scenario_id: Identifier
    build_digest: str = Field(pattern=DIGEST_PATTERN)
    dataset_digest: str = Field(pattern=DIGEST_PATTERN)
    fixture_digest: str = Field(pattern=DIGEST_PATTERN)
    assessment_as_of: AwareDatetime
    evidence_window: EvidenceWindow
    evidence_policy: EvidencePolicyRef

    @model_validator(mode="after")
    def assessment_inside_window(self) -> ExperimentScope:
        window = self.evidence_window
        if not window.start <= self.assessment_as_of <= window.end:
            raise ValueError("assessment_as_of must fall inside the evidence window")
        return self

    @field_serializer("assessment_as_of", when_used="json")
    def utc_datetime(self, value: datetime) -> str:
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


class ObligationScope(StrEnum):
    TARGET_LOCAL = "target_local"
    COMPENSATOR_LOCAL = "compensator_local"
    PATH = "path"


class Subject(BaseModel):
    identifier: NonEmptyText
    component: Identifier


class PredicateOperator(StrEnum):
    EQUAL = "eq"
    NOT_EQUAL = "ne"
    LESS_OR_EQUAL = "le"
    GREATER_OR_EQUAL = "ge"


class Predicate(BaseModel):
    metric_id: Identifier
    operator: PredicateOperator
    expected: TypedValue
    absolute_tolerance: DecimalValue | None = None

    @model_validator(mode="after")
    def coherent_operator(self) -> Predicate:
        numeric = self.expected.type in {"integer", "decimal"}
        if (
            self.operator
            in {
                PredicateOperator.LESS_OR_EQUAL,
                PredicateOperator.GREATER_OR_EQUAL,
            }
            and not numeric
        ):
            raise ValueError("ordered predicates require an integer or decimal metric")
        if self.absolute_tolerance is not None:
            if not numeric:
                raise ValueError("absolute tolerance is only valid for numeric predicates")
            if self.absolute_tolerance.value < 0:
                raise ValueError("absolute tolerance cannot be negative")
        return self


class CellSelector(BaseModel):
    input: TypedValue | None = None
    target: TypedValue | None = None
    compensator: TypedValue | None = None
    sham: TypedValue | None = None


class AllTested(BaseModel):
    type: Literal["all_tested"] = "all_tested"
    min_trials: int = Field(ge=1, le=MAX_PLANNED_TRIALS)


class AtLeastRate(BaseModel):
    type: Literal["at_least_rate"] = "at_least_rate"
    rate: DecimalValue
    min_trials: int = Field(ge=1, le=MAX_PLANNED_TRIALS)

    @model_validator(mode="after")
    def unit_interval(self) -> AtLeastRate:
        if not Decimal(0) < self.rate.value <= Decimal(1):
            raise ValueError("rate must be in (0, 1]")
        return self


class Exists(BaseModel):
    type: Literal["exists"] = "exists"
    min_trials: int = Field(ge=1, le=MAX_PLANNED_TRIALS)


Quantifier = Annotated[
    AllTested | AtLeastRate | Exists,
    Field(discriminator="type"),
]


class Obligation(BaseModel):
    id: Identifier
    subject: Subject
    scope: ObligationScope
    selector: CellSelector
    predicate: Predicate
    quantifier: Quantifier


def _same_type(left: TypedValue, right: TypedValue) -> bool:
    return left.type == right.type


def _same_value(left: TypedValue, right: TypedValue) -> bool:
    return left.model_dump(mode="json") == right.model_dump(mode="json")


class InputAxis(BaseModel):
    component: Identifier
    attack: TypedValue
    benign: TypedValue
    attack_action_digest: str = Field(pattern=DIGEST_PATTERN)
    benign_action_digest: str = Field(pattern=DIGEST_PATTERN)

    @model_validator(mode="after")
    def two_levels(self) -> InputAxis:
        _check_axis_levels("input", self.attack, self.benign)
        if self.attack_action_digest == self.benign_action_digest:
            raise ValueError("attack and benign actions must have distinct digests")
        return self


class TargetControlAxis(BaseModel):
    component: Identifier
    ineffective: TypedValue
    effective: TypedValue
    current: TypedValue

    @model_validator(mode="after")
    def two_levels_and_current(self) -> TargetControlAxis:
        _check_axis_levels("target", self.ineffective, self.effective)
        _check_current("target", self.current, self.ineffective, self.effective)
        return self


class CompensatorControlAxis(BaseModel):
    component: Identifier
    off: TypedValue
    on: TypedValue
    current: TypedValue

    @model_validator(mode="after")
    def two_levels_and_current(self) -> CompensatorControlAxis:
        _check_axis_levels("compensator", self.off, self.on)
        _check_current("compensator", self.current, self.off, self.on)
        return self


class ShamAxis(BaseModel):
    steady: TypedValue
    redeploy: TypedValue

    @model_validator(mode="after")
    def two_levels(self) -> ShamAxis:
        _check_axis_levels("sham", self.steady, self.redeploy)
        return self


def _check_axis_levels(name: str, first: TypedValue, second: TypedValue) -> None:
    if not _same_type(first, second):
        raise ValueError(f"{name} axis levels must use the same type")
    if _same_value(first, second):
        raise ValueError(f"{name} axis levels must be distinct")


def _check_current(
    name: str,
    current: TypedValue,
    first: TypedValue,
    second: TypedValue,
) -> None:
    if not _same_type(current, first):
        raise ValueError(f"{name} current level has the wrong type")
    if not (_same_value(current, first) or _same_value(current, second)):
        raise ValueError(f"{name} current level must equal a declared level")


class RelationOperator(StrEnum):
    EQUAL = "eq"
    NOT_EQUAL = "ne"
    LESS_OR_EQUAL = "le"
    GREATER_OR_EQUAL = "ge"
    TRUE_TO_FALSE = "true_to_false"
    FALSE_TO_TRUE = "false_to_true"
    DECREASES = "decreases"
    INCREASES = "increases"


class MetricRelation(BaseModel):
    operator: RelationOperator


class PreventiveNonMaskingProfile(BaseModel):
    input: InputAxis
    target: TargetControlAxis
    compensator: CompensatorControlAxis
    sham: ShamAxis
    outcome_component: Identifier

    target_metric_id: Identifier
    compensator_metric_id: Identifier
    outcome_metric_id: Identifier
    benign_outcome_metric_id: Identifier

    target_safe_value: TypedValue
    compensator_safe_value: TypedValue
    outcome_safe_value: TypedValue
    benign_safe_value: TypedValue

    primary_target_obligation_id: Identifier
    primary_compensator_obligation_id: Identifier
    primary_path_obligation_id: Identifier
    primary_benign_obligation_id: Identifier

    target_attack_relation: MetricRelation
    target_benign_relation: MetricRelation
    sham_relation: MetricRelation
    compensator_attack_relation: MetricRelation

    @model_validator(mode="after")
    def coherent_relation_kinds(self) -> PreventiveNonMaskingProfile:
        directional = {
            RelationOperator.TRUE_TO_FALSE,
            RelationOperator.FALSE_TO_TRUE,
            RelationOperator.DECREASES,
            RelationOperator.INCREASES,
        }
        if self.target_attack_relation.operator not in directional:
            raise ValueError("target attack effect requires a directional relation")
        if self.compensator_attack_relation.operator not in directional:
            raise ValueError("compensator attack effect requires a directional relation")
        if self.target_benign_relation.operator != RelationOperator.EQUAL:
            raise ValueError("target benign invariance must use the equality relation")
        if self.sham_relation.operator != RelationOperator.EQUAL:
            raise ValueError("sham invariance must use the equality relation")
        return self


class TrialPlan(BaseModel):
    blocks: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=MAX_BLOCKS,
    )
    replicates: int = Field(ge=1, le=MAX_REPLICATES)
    order_seed: NonEmptyText

    @model_validator(mode="after")
    def unique_blocks(self) -> TrialPlan:
        if any(not block for block in self.blocks):
            raise ValueError("block identifiers must be nonempty")
        if len(set(self.blocks)) != len(self.blocks):
            raise ValueError("block identifiers must be unique")
        return self


class ExperimentContract(BaseModel):
    id: Identifier
    version: Literal["3.0.0"]
    scope: ExperimentScope
    metrics: tuple[MetricContract, ...] = Field(
        min_length=1,
        max_length=MAX_METRICS,
    )
    obligations: tuple[Obligation, ...] = Field(
        min_length=1,
        max_length=MAX_OBLIGATIONS,
    )
    profile: PreventiveNonMaskingProfile
    plan: TrialPlan

    @model_validator(mode="after")
    def identity_matches_scope(self) -> ExperimentContract:
        if self.id != self.scope.scenario_id:
            raise ValueError("contract id must equal scope scenario_id")
        return self


class ContrastId(StrEnum):
    TARGET_ATTACK_EFFECT = "target-attack-effect"
    TARGET_BENIGN_INVARIANCE = "target-benign-invariance"
    COMPENSATOR_BENIGN_INVARIANCE = "compensator-benign-invariance"
    SHAM_INVARIANCE = "sham-invariance"
    COMPENSATOR_ATTACK_EFFECT = "compensator-attack-effect"


class GeneratedCell(BaseModel):
    key: str = Field(max_length=MAX_TEXT_LENGTH)
    selector: CellSelector


class ContrastPair(BaseModel):
    reference_cell_key: str = Field(max_length=MAX_TEXT_LENGTH)
    comparison_cell_key: str = Field(max_length=MAX_TEXT_LENGTH)


class ContrastDefinition(BaseModel):
    id: ContrastId
    metric_id: Identifier
    relation: MetricRelation
    varied_axis: Literal["target", "compensator", "sham"]
    pairs: tuple[ContrastPair, ...] = Field(min_length=1)


class PlannedTrial(BaseModel):
    key: str = Field(pattern=DIGEST_PATTERN)
    ordinal: int = Field(ge=1, le=MAX_PLANNED_TRIALS)
    cell_key: str = Field(max_length=MAX_TEXT_LENGTH)
    block: Identifier
    replicate: int = Field(ge=1, le=MAX_REPLICATES)


class ObligationCoverage(BaseModel):
    obligation_id: Identifier
    trial_keys: tuple[str, ...] = Field(
        min_length=1,
        max_length=MAX_PLANNED_TRIALS,
    )


class CompiledExperiment(BaseModel):
    contract: ExperimentContract
    canonical_spec: str
    spec_digest: str = Field(pattern=DIGEST_PATTERN)
    cells: tuple[GeneratedCell, ...] = Field(min_length=16, max_length=16)
    current_selector: CellSelector
    contrasts: tuple[ContrastDefinition, ...] = Field(min_length=5, max_length=5)
    planned_trials: tuple[PlannedTrial, ...] = Field(
        min_length=16,
        max_length=MAX_PLANNED_TRIALS,
    )
    obligation_coverage: tuple[ObligationCoverage, ...] = Field(min_length=1)


class ContractCompileError(ValueError):
    """The authored contract cannot produce a semantically sound plan."""


def compile_experiment(contract: ExperimentContract) -> CompiledExperiment:
    """Validate and compile an author contract into an immutable semantic plan."""

    # Revalidation prevents a caller from bypassing assignment checks through
    # ``model_construct`` or from relying on an already-validated instance.
    try:
        clean = ExperimentContract.model_validate(
            contract.model_dump(mode="python"),
            strict=True,
        )
    except ValueError as error:
        raise ContractCompileError(f"contract revalidation failed: {error}") from error

    metrics = _unique_by_id(clean.metrics, "metric")
    obligations = _unique_by_id(clean.obligations, "obligation")
    _validate_plan_size(clean.plan)
    _validate_profile(clean.profile, metrics)

    cells = _generate_cells(clean.profile)
    current = _current_selector(clean.profile)
    _validate_obligations(clean, metrics, obligations, cells, current)

    try:
        canonical = rfc8785.dumps(_semantic_payload(clean)).decode("utf-8")  # type: ignore[arg-type]
    except (rfc8785.CanonicalizationError, UnicodeError, ValueError) as error:
        raise ContractCompileError(f"contract canonicalization failed: {error}") from error
    spec_digest = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    planned = _plan_trials(clean.plan, cells, spec_digest)
    coverage = _coverage(clean.obligations, cells, planned)
    _validate_minimum_trials(clean.obligations, coverage)
    contrasts = _generate_contrasts(clean.profile, cells)

    return CompiledExperiment(
        contract=clean,
        canonical_spec=canonical,
        spec_digest=spec_digest,
        cells=cells,
        current_selector=current,
        contrasts=contrasts,
        planned_trials=planned,
        obligation_coverage=coverage,
    )


compile_contract = compile_experiment


def _validate_plan_size(plan: TrialPlan) -> None:
    planned = 16 * len(plan.blocks) * plan.replicates
    if planned > MAX_PLANNED_TRIALS:
        raise ContractCompileError(
            f"trial plan expands to {planned} trials; maximum is {MAX_PLANNED_TRIALS}"
        )


class _Identified(Protocol):
    id: str


def _unique_by_id[IdentifiedT: _Identified](
    items: tuple[IdentifiedT, ...],
    label: str,
) -> dict[str, IdentifiedT]:
    result: dict[str, IdentifiedT] = {}
    for item in items:
        identifier = item.id
        if identifier in result:
            raise ContractCompileError(f"duplicate {label} id: {identifier}")
        result[identifier] = item
    return result


def _validate_profile(
    profile: PreventiveNonMaskingProfile,
    metrics: dict[str, MetricContract],
) -> None:
    components = {
        profile.target.component,
        profile.compensator.component,
        profile.outcome_component,
    }
    if len(components) != 3:
        raise ContractCompileError("target, compensator, and outcome components must be distinct")
    if profile.outcome_metric_id == profile.benign_outcome_metric_id:
        raise ContractCompileError("security outcome and benign outcome metrics must be distinct")
    bindings = (
        (
            "target",
            profile.target_metric_id,
            Stage.TARGET,
            profile.target.component,
            profile.target_attack_relation,
            profile.target_safe_value,
        ),
        (
            "compensator",
            profile.compensator_metric_id,
            Stage.COMPENSATOR,
            profile.compensator.component,
            None,
            profile.compensator_safe_value,
        ),
        (
            "outcome",
            profile.outcome_metric_id,
            Stage.OUTCOME,
            profile.outcome_component,
            profile.compensator_attack_relation,
            profile.outcome_safe_value,
        ),
        (
            "benign outcome",
            profile.benign_outcome_metric_id,
            Stage.OUTCOME,
            profile.outcome_component,
            None,
            profile.benign_safe_value,
        ),
    )
    for label, metric_id, stage, component, relation, safe_value in bindings:
        metric = metrics.get(metric_id)
        if metric is None:
            raise ContractCompileError(f"{label} metric does not exist: {metric_id}")
        if metric.stage != stage:
            raise ContractCompileError(
                f"{label} metric {metric_id} must belong to stage {stage.value}"
            )
        if metric.component != component:
            raise ContractCompileError(
                f"{label} metric {metric_id} belongs to component {metric.component}, "
                f"not {component}"
            )
        if safe_value.type != metric.value_type.value:
            raise ContractCompileError(f"{label} safe value type does not match metric {metric_id}")
        if relation is not None:
            _validate_effect_relation(relation, metric, label, safe_value)


def _validate_effect_relation(
    relation: MetricRelation,
    metric: MetricContract,
    label: str,
    safe_value: TypedValue,
) -> None:
    boolean_relations = {
        RelationOperator.TRUE_TO_FALSE,
        RelationOperator.FALSE_TO_TRUE,
    }
    numeric_relations = {
        RelationOperator.DECREASES,
        RelationOperator.INCREASES,
    }
    if metric.value_type == MetricValueType.BOOLEAN:
        allowed = boolean_relations
    elif metric.value_type in {
        MetricValueType.INTEGER,
        MetricValueType.DECIMAL,
    }:
        allowed = numeric_relations
    else:
        allowed = set()
    if relation.operator not in allowed:
        raise ContractCompileError(
            f"{label} effect relation is incompatible with "
            f"{metric.value_type.value} metric {metric.id}"
        )
    if metric.value_type == MetricValueType.BOOLEAN:
        safe_terminal = {
            RelationOperator.TRUE_TO_FALSE: False,
            RelationOperator.FALSE_TO_TRUE: True,
        }[relation.operator]
        if safe_value.value is not safe_terminal:
            raise ContractCompileError(
                f"{label} effect relation moves away from its declared safe value"
            )


def _generate_cells(profile: PreventiveNonMaskingProfile) -> tuple[GeneratedCell, ...]:
    levels = (
        (("attack", profile.input.attack), ("benign", profile.input.benign)),
        (
            ("ineffective", profile.target.ineffective),
            ("effective", profile.target.effective),
        ),
        (("off", profile.compensator.off), ("on", profile.compensator.on)),
        (("steady", profile.sham.steady), ("redeploy", profile.sham.redeploy)),
    )
    cells: list[GeneratedCell] = []
    for input_level, target_level, compensator_level, sham_level in itertools.product(*levels):
        labels = (
            f"input={input_level[0]}",
            f"target={target_level[0]}",
            f"compensator={compensator_level[0]}",
            f"sham={sham_level[0]}",
        )
        cells.append(
            GeneratedCell(
                key=";".join(labels),
                selector=CellSelector(
                    input=input_level[1],
                    target=target_level[1],
                    compensator=compensator_level[1],
                    sham=sham_level[1],
                ),
            )
        )
    return tuple(cells)


def _current_selector(profile: PreventiveNonMaskingProfile) -> CellSelector:
    return CellSelector(
        input=profile.input.attack,
        target=profile.target.current,
        compensator=profile.compensator.current,
        sham=profile.sham.steady,
    )


def _benign_envelope_selector(
    profile: PreventiveNonMaskingProfile,
) -> CellSelector:
    return CellSelector(input=profile.input.benign)


def _validate_obligations(
    contract: ExperimentContract,
    metrics: dict[str, MetricContract],
    obligations: dict[str, Obligation],
    cells: tuple[GeneratedCell, ...],
    current: CellSelector,
) -> None:
    profile = contract.profile

    for obligation in contract.obligations:
        metric = metrics.get(obligation.predicate.metric_id)
        if metric is None:
            raise ContractCompileError(
                f"obligation {obligation.id} references unknown metric "
                f"{obligation.predicate.metric_id}"
            )
        required_stage = {
            ObligationScope.TARGET_LOCAL: Stage.TARGET,
            ObligationScope.COMPENSATOR_LOCAL: Stage.COMPENSATOR,
            ObligationScope.PATH: Stage.OUTCOME,
        }[obligation.scope]
        required_component = {
            ObligationScope.TARGET_LOCAL: profile.target.component,
            ObligationScope.COMPENSATOR_LOCAL: profile.compensator.component,
            ObligationScope.PATH: profile.outcome_component,
        }[obligation.scope]
        if metric.stage != required_stage:
            raise ContractCompileError(
                f"{obligation.scope.value} obligation {obligation.id} cannot use "
                f"{metric.stage.value} metric {metric.id}"
            )
        if metric.component != required_component:
            raise ContractCompileError(
                f"{obligation.scope.value} obligation {obligation.id} must use "
                f"component {required_component}"
            )
        if obligation.subject.component != metric.component:
            raise ContractCompileError(
                f"obligation {obligation.id} subject and metric components differ"
            )
        if obligation.predicate.expected.type != metric.value_type.value:
            raise ContractCompileError(
                f"obligation {obligation.id} expected value type does not match metric {metric.id}"
            )
        _validate_selector(obligation.id, obligation.selector, profile)
        if not any(_selector_matches(obligation.selector, cell.selector) for cell in cells):
            raise ContractCompileError(f"obligation {obligation.id} has no planned cell")

    primary = (
        (
            "target",
            profile.primary_target_obligation_id,
            ObligationScope.TARGET_LOCAL,
            profile.target_metric_id,
            profile.target.component,
            current,
            profile.target_safe_value,
        ),
        (
            "compensator",
            profile.primary_compensator_obligation_id,
            ObligationScope.COMPENSATOR_LOCAL,
            profile.compensator_metric_id,
            profile.compensator.component,
            current,
            profile.compensator_safe_value,
        ),
        (
            "path",
            profile.primary_path_obligation_id,
            ObligationScope.PATH,
            profile.outcome_metric_id,
            profile.outcome_component,
            current,
            profile.outcome_safe_value,
        ),
        (
            "benign path",
            profile.primary_benign_obligation_id,
            ObligationScope.PATH,
            profile.benign_outcome_metric_id,
            profile.outcome_component,
            _benign_envelope_selector(profile),
            profile.benign_safe_value,
        ),
    )
    for (
        label,
        obligation_id,
        scope,
        metric_id,
        component,
        selector,
        safe_value,
    ) in primary:
        primary_obligation = obligations.get(obligation_id)
        if primary_obligation is None:
            raise ContractCompileError(
                f"primary {label} obligation does not exist: {obligation_id}"
            )
        if primary_obligation.scope != scope:
            raise ContractCompileError(f"primary {label} obligation must have scope {scope.value}")
        if primary_obligation.predicate.metric_id != metric_id:
            raise ContractCompileError(f"primary {label} obligation must use metric {metric_id}")
        if primary_obligation.subject.component != component:
            raise ContractCompileError(f"primary {label} obligation must use component {component}")
        if primary_obligation.selector != selector:
            raise ContractCompileError(f"primary {label} obligation has the wrong exact selector")
        predicate = primary_obligation.predicate
        if (
            predicate.operator != PredicateOperator.EQUAL
            or predicate.absolute_tolerance is not None
            or not _same_value(predicate.expected, safe_value)
        ):
            raise ContractCompileError(
                f"primary {label} obligation must equal its declared safe value without tolerance"
            )
        if not isinstance(primary_obligation.quantifier, AllTested):
            raise ContractCompileError(f"primary {label} obligation must use all_tested")


def _validate_selector(
    obligation_id: str,
    selector: CellSelector,
    profile: PreventiveNonMaskingProfile,
) -> None:
    allowed = {
        "input": (profile.input.attack, profile.input.benign),
        "target": (profile.target.ineffective, profile.target.effective),
        "compensator": (profile.compensator.off, profile.compensator.on),
        "sham": (profile.sham.steady, profile.sham.redeploy),
    }
    for axis, levels in allowed.items():
        selected = getattr(selector, axis)
        if selected is not None and not any(_same_value(selected, level) for level in levels):
            raise ContractCompileError(
                f"obligation {obligation_id} selector has undeclared {axis} level"
            )


def _selector_matches(narrow: CellSelector, exact: CellSelector) -> bool:
    return all(
        getattr(narrow, axis) is None or _same_value(getattr(narrow, axis), getattr(exact, axis))
        for axis in ("input", "target", "compensator", "sham")
    )


def _semantic_payload(contract: ExperimentContract) -> dict[str, object]:
    payload = contract.model_dump(mode="json")
    payload["metrics"] = sorted(payload["metrics"], key=lambda item: item["id"])
    payload["obligations"] = sorted(payload["obligations"], key=lambda item: item["id"])
    payload["plan"]["blocks"] = sorted(payload["plan"]["blocks"])
    return {
        "contract_schema": "assurance-lab.preventive-non-masking.v3",
        "contract": payload,
    }


def _plan_trials(
    plan: TrialPlan,
    cells: tuple[GeneratedCell, ...],
    spec_digest: str,
) -> tuple[PlannedTrial, ...]:
    raw: list[tuple[str, str, str, int, str]] = []
    for cell, block, replicate in itertools.product(
        cells,
        sorted(plan.blocks),
        range(1, plan.replicates + 1),
    ):
        material = f"{spec_digest}\0{cell.key}\0{block}\0{replicate}".encode()
        trial_key = "sha256:" + hashlib.sha256(material).hexdigest()
        order_material = f"{plan.order_seed}\0{trial_key}".encode()
        order_key = hashlib.sha256(order_material).hexdigest()
        raw.append((order_key, trial_key, cell.key, replicate, block))
    raw.sort(key=lambda item: (item[0], item[1]))
    return tuple(
        PlannedTrial(
            key=trial_key,
            ordinal=ordinal,
            cell_key=cell_key,
            block=block,
            replicate=replicate,
        )
        for ordinal, (_, trial_key, cell_key, replicate, block) in enumerate(raw, start=1)
    )


def _coverage(
    obligations: tuple[Obligation, ...],
    cells: tuple[GeneratedCell, ...],
    trials: tuple[PlannedTrial, ...],
) -> tuple[ObligationCoverage, ...]:
    cells_by_key = {cell.key: cell for cell in cells}
    return tuple(
        ObligationCoverage(
            obligation_id=obligation.id,
            trial_keys=tuple(
                trial.key
                for trial in trials
                if _selector_matches(
                    obligation.selector,
                    cells_by_key[trial.cell_key].selector,
                )
            ),
        )
        for obligation in sorted(obligations, key=lambda item: item.id)
    )


def _validate_minimum_trials(
    obligations: tuple[Obligation, ...],
    coverage: tuple[ObligationCoverage, ...],
) -> None:
    covered = {item.obligation_id: len(item.trial_keys) for item in coverage}
    for obligation in obligations:
        planned = covered.get(obligation.id, 0)
        if planned == 0:
            raise ContractCompileError(f"obligation {obligation.id} is left unassessed")
        if obligation.quantifier.min_trials > planned:
            raise ContractCompileError(
                f"obligation {obligation.id} requires {obligation.quantifier.min_trials} "
                f"trials but the plan contains {planned}"
            )


def _cell_for(cells: tuple[GeneratedCell, ...], selector: CellSelector) -> GeneratedCell:
    matches = [cell for cell in cells if cell.selector == selector]
    if len(matches) != 1:
        raise ContractCompileError("compiler could not resolve a generated contrast cell")
    return matches[0]


def _pair(
    cells: tuple[GeneratedCell, ...],
    reference: CellSelector,
    comparison: CellSelector,
) -> tuple[ContrastPair, ...]:
    return (
        ContrastPair(
            reference_cell_key=_cell_for(cells, reference).key,
            comparison_cell_key=_cell_for(cells, comparison).key,
        ),
    )


def _generate_contrasts(
    profile: PreventiveNonMaskingProfile,
    cells: tuple[GeneratedCell, ...],
) -> tuple[ContrastDefinition, ...]:
    attack = profile.input.attack
    benign = profile.input.benign
    target_off = profile.target.ineffective
    target_on = profile.target.effective
    comp_off = profile.compensator.off
    comp_on = profile.compensator.on
    steady = profile.sham.steady
    redeploy = profile.sham.redeploy
    current_target = profile.target.current
    current_comp = profile.compensator.current

    target_attack = _pair(
        cells,
        CellSelector(input=attack, target=target_off, compensator=comp_off, sham=steady),
        CellSelector(input=attack, target=target_on, compensator=comp_off, sham=steady),
    )
    target_benign = _pair(
        cells,
        CellSelector(input=benign, target=target_off, compensator=comp_off, sham=steady),
        CellSelector(input=benign, target=target_on, compensator=comp_off, sham=steady),
    )
    compensator_benign = _pair(
        cells,
        CellSelector(
            input=benign,
            target=current_target,
            compensator=comp_off,
            sham=steady,
        ),
        CellSelector(
            input=benign,
            target=current_target,
            compensator=comp_on,
            sham=steady,
        ),
    )
    sham = _pair(
        cells,
        CellSelector(
            input=attack,
            target=current_target,
            compensator=current_comp,
            sham=steady,
        ),
        CellSelector(
            input=attack,
            target=current_target,
            compensator=current_comp,
            sham=redeploy,
        ),
    )
    compensator_attack = _pair(
        cells,
        CellSelector(input=attack, target=target_off, compensator=comp_off, sham=steady),
        CellSelector(input=attack, target=target_off, compensator=comp_on, sham=steady),
    )

    return (
        ContrastDefinition(
            id=ContrastId.TARGET_ATTACK_EFFECT,
            metric_id=profile.target_metric_id,
            relation=profile.target_attack_relation,
            varied_axis="target",
            pairs=target_attack,
        ),
        ContrastDefinition(
            id=ContrastId.TARGET_BENIGN_INVARIANCE,
            metric_id=profile.benign_outcome_metric_id,
            relation=profile.target_benign_relation,
            varied_axis="target",
            pairs=target_benign,
        ),
        ContrastDefinition(
            id=ContrastId.COMPENSATOR_BENIGN_INVARIANCE,
            metric_id=profile.benign_outcome_metric_id,
            relation=MetricRelation(operator=RelationOperator.EQUAL),
            varied_axis="compensator",
            pairs=compensator_benign,
        ),
        ContrastDefinition(
            id=ContrastId.SHAM_INVARIANCE,
            metric_id=profile.outcome_metric_id,
            relation=profile.sham_relation,
            varied_axis="sham",
            pairs=sham,
        ),
        ContrastDefinition(
            id=ContrastId.COMPENSATOR_ATTACK_EFFECT,
            metric_id=profile.outcome_metric_id,
            relation=profile.compensator_attack_relation,
            varied_axis="compensator",
            pairs=compensator_attack,
        ),
    )
