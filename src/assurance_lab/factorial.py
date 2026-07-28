"""General factorial experiment model for control interactions."""

from __future__ import annotations

from enum import StrEnum
from itertools import product

from pydantic import BaseModel, Field, model_validator

from assurance_lab.experiments import (
    CheckResult,
    CheckRole,
    RelationOperator,
    RunExecution,
    Scalar,
    WitnessState,
    _relation_holds,
)


class FactorKind(StrEnum):
    INPUT = "input"
    CONTROL = "control"
    CONTEXT = "context"
    FAULT = "fault"


class FactorSpec(BaseModel):
    name: str
    kind: FactorKind
    levels: list[Scalar] = Field(min_length=2)
    description: str

    @model_validator(mode="after")
    def levels_are_unique(self) -> FactorSpec:
        if len({repr(level) for level in self.levels}) != len(self.levels):
            raise ValueError(f"factor {self.name!r} contains duplicate levels")
        return self


class CellSpec(BaseModel):
    id: str
    factors: dict[str, Scalar]


class TrialRecord(BaseModel):
    id: str
    cell_id: str
    block_id: str
    replicate: int = Field(ge=0)
    sequence: int = Field(ge=0)
    execution: RunExecution = RunExecution.COMPLETED
    environment_fingerprint: str
    observed_factors: dict[str, Scalar]
    cleanup_verified: bool
    observations: dict[str, Scalar]
    evidence_ids: list[str] = Field(default_factory=list)


class CellSelector(BaseModel):
    where: dict[str, Scalar] = Field(default_factory=dict)


class PointAssertion(BaseModel):
    id: str
    selector: CellSelector
    observation: str
    expected: Scalar
    check_role: CheckRole
    purpose: str


class FactorContrast(BaseModel):
    id: str
    factor: str
    from_level: Scalar
    to_level: Scalar
    where: dict[str, Scalar] = Field(default_factory=dict)
    observation: str
    operator: RelationOperator
    check_role: CheckRole
    purpose: str

    @model_validator(mode="after")
    def contrast_changes_a_level(self) -> FactorContrast:
        if self.from_level == self.to_level:
            raise ValueError("a contrast must compare two different levels")
        if self.factor in self.where:
            raise ValueError("where must not constrain the contrasted factor")
        return self


class FactorialExperimentSpec(BaseModel):
    id: str
    claim_id: str
    factors: list[FactorSpec]
    cells: list[CellSpec]
    point_assertions: list[PointAssertion] = Field(default_factory=list)
    contrasts: list[FactorContrast] = Field(default_factory=list)
    require_cleanup: bool = True

    @model_validator(mode="after")
    def design_is_closed(self) -> FactorialExperimentSpec:
        factor_by_name = {factor.name: factor for factor in self.factors}
        if len(factor_by_name) != len(self.factors):
            raise ValueError("factor names must be unique")
        cell_ids = [cell.id for cell in self.cells]
        if len(set(cell_ids)) != len(cell_ids):
            raise ValueError("cell ids must be unique")
        expected_names = set(factor_by_name)
        assignments: set[tuple[tuple[str, str], ...]] = set()
        for cell in self.cells:
            if set(cell.factors) != expected_names:
                missing = expected_names - set(cell.factors)
                extra = set(cell.factors) - expected_names
                raise ValueError(
                    f"cell {cell.id!r} has incomplete factors; "
                    f"missing={sorted(missing)!r}, extra={sorted(extra)!r}"
                )
            for name, level in cell.factors.items():
                if level not in factor_by_name[name].levels:
                    raise ValueError(
                        f"cell {cell.id!r} uses unknown level {level!r} for {name!r}"
                    )
            canonical = tuple(sorted((name, repr(value)) for name, value in cell.factors.items()))
            if canonical in assignments:
                raise ValueError(f"duplicate factor assignment in cell {cell.id!r}")
            assignments.add(canonical)

        for assertion in self.point_assertions:
            self._validate_selector(assertion.selector.where, factor_by_name)
        for contrast in self.contrasts:
            if contrast.factor not in factor_by_name:
                raise ValueError(f"contrast uses unknown factor {contrast.factor!r}")
            factor = factor_by_name[contrast.factor]
            if contrast.from_level not in factor.levels or contrast.to_level not in factor.levels:
                raise ValueError(f"contrast {contrast.id!r} uses an unknown factor level")
            self._validate_selector(contrast.where, factor_by_name)
        return self

    @staticmethod
    def _validate_selector(
        where: dict[str, Scalar],
        factors: dict[str, FactorSpec],
    ) -> None:
        for name, value in where.items():
            if name not in factors:
                raise ValueError(f"selector uses unknown factor {name!r}")
            if value not in factors[name].levels:
                raise ValueError(f"selector uses unknown level {value!r} for {name!r}")


class FactorialWitnessResult(BaseModel):
    experiment_id: str
    claim_id: str
    state: WitnessState
    attributable: bool
    checks: list[CheckResult]
    evidence_ids: list[str]
    reasons: list[str]


def expand_full_factorial(factors: list[FactorSpec]) -> list[CellSpec]:
    """Expand a readable full-factorial design in declared level order."""

    names = [factor.name for factor in factors]
    cells: list[CellSpec] = []
    for index, levels in enumerate(product(*(factor.levels for factor in factors)), start=1):
        assignment = dict(zip(names, levels, strict=True))
        cells.append(CellSpec(id=f"cell-{index:03d}", factors=assignment))
    return cells


def cell_matches(cell: CellSpec, selector: dict[str, Scalar]) -> bool:
    return all(cell.factors.get(name) == value for name, value in selector.items())


class FactorialWitnessEvaluator:
    """Evaluate point predicates and controlled factor contrasts."""

    def evaluate(
        self,
        spec: FactorialExperimentSpec,
        trials: list[TrialRecord],
    ) -> FactorialWitnessResult:
        checks: list[CheckResult] = []
        reasons: list[str] = []
        cell_by_id = {cell.id: cell for cell in spec.cells}
        trial_index: dict[tuple[str, str, int], TrialRecord] = {}

        unknown_cells = sorted({trial.cell_id for trial in trials} - set(cell_by_id))
        if unknown_cells:
            reasons.append("trials reference unknown cells: " + ", ".join(unknown_cells))
            return self._result(spec, WitnessState.ERROR, False, checks, trials, reasons)

        duplicate_keys: list[str] = []
        for trial in trials:
            key = (trial.cell_id, trial.block_id, trial.replicate)
            if key in trial_index:
                duplicate_keys.append("/".join(map(str, key)))
            trial_index[key] = trial
        if duplicate_keys:
            reasons.append("duplicate cell/block/replicate trials: " + ", ".join(duplicate_keys))
            return self._result(spec, WitnessState.ERROR, False, checks, trials, reasons)

        completed = [trial for trial in trials if trial.execution == RunExecution.COMPLETED]
        execution_errors = [trial for trial in trials if trial.execution == RunExecution.ERROR]
        checks.append(
            CheckResult(
                id="run-execution",
                passed=not execution_errors and bool(completed),
                detail=(
                    "all trials completed"
                    if not execution_errors and completed
                    else "missing completed trials or harness errors: "
                    + ", ".join(trial.id for trial in execution_errors)
                ),
                run_ids=[trial.id for trial in execution_errors],
            )
        )

        factor_checks = [
            self._check_factor_assignment(cell_by_id[trial.cell_id], trial)
            for trial in completed
        ]
        checks.extend(factor_checks)

        dirty = [trial for trial in completed if not trial.cleanup_verified]
        cleanup_passed = not spec.require_cleanup or not dirty
        checks.append(
            CheckResult(
                id="cleanup",
                passed=cleanup_passed,
                detail=(
                    "cleanup verified"
                    if cleanup_passed
                    else "cleanup failed or unverified: " + ", ".join(t.id for t in dirty)
                ),
                run_ids=[trial.id for trial in dirty],
            )
        )

        assertion_checks = [
            self._evaluate_point_assertion(assertion, spec.cells, completed)
            for assertion in spec.point_assertions
        ]
        contrast_checks: list[CheckResult] = []
        contrast_environment_checks: list[CheckResult] = []
        for contrast in spec.contrasts:
            relation_check, environment_checks = self._evaluate_contrast(
                contrast,
                spec.cells,
                trial_index,
            )
            contrast_checks.append(relation_check)
            contrast_environment_checks.extend(environment_checks)
        checks.extend(assertion_checks)
        checks.extend(contrast_checks)
        checks.extend(contrast_environment_checks)

        general_validity_checks = [
            check
            for check in checks
            if check.id in {"run-execution", "cleanup"}
            or check.id.startswith("factor:")
            or check.id.startswith("environment:")
        ]
        role_checks: list[tuple[CheckRole, CheckResult]] = [
            *(
                (item.check_role, check)
                for item, check in zip(
                    spec.point_assertions,
                    assertion_checks,
                    strict=True,
                )
            ),
            *(
                (item.check_role, check)
                for item, check in zip(
                    spec.contrasts,
                    contrast_checks,
                    strict=True,
                )
            ),
        ]
        declared_validity_checks = [
            check for role, check in role_checks if role == CheckRole.VALIDITY
        ]
        support_checks = [
            check for role, check in role_checks if role == CheckRole.SUPPORT
        ]
        refutation_checks = [
            check for role, check in role_checks if role == CheckRole.REFUTATION
        ]

        validity_holds = all(
            check.passed for check in [*general_validity_checks, *declared_validity_checks]
        )
        if not validity_holds:
            reasons.append(
                "factor manipulation, paired environment, cleanup, or a declared "
                "validity relation failed"
            )
            return self._result(
                spec,
                WitnessState.INCONCLUSIVE,
                False,
                checks,
                trials,
                reasons,
            )

        support_holds = bool(support_checks) and all(check.passed for check in support_checks)
        refutation_holds = bool(refutation_checks) and all(
            check.passed for check in refutation_checks
        )
        if support_holds and refutation_holds:
            reasons.append("supporting and refuting predicates both hold")
            return self._result(
                spec,
                WitnessState.INCONCLUSIVE,
                False,
                checks,
                trials,
                reasons,
            )
        if support_holds:
            reasons.append("the declared controlled contrasts support the scoped claim")
            return self._result(
                spec,
                WitnessState.SUPPORTED,
                True,
                checks,
                trials,
                reasons,
            )
        if refutation_holds:
            reasons.append("the valid experiment satisfies the refutation predicates")
            return self._result(
                spec,
                WitnessState.REFUTED,
                True,
                checks,
                trials,
                reasons,
            )
        reasons.append("valid trials do not satisfy the support or refutation predicates")
        return self._result(
            spec,
            WitnessState.INCONCLUSIVE,
            False,
            checks,
            trials,
            reasons,
        )

    @staticmethod
    def _check_factor_assignment(cell: CellSpec, trial: TrialRecord) -> CheckResult:
        passed = trial.observed_factors == cell.factors
        return CheckResult(
            id=f"factor:{trial.id}",
            passed=passed,
            detail=(
                "observed factors match the declared cell"
                if passed
                else f"declared={cell.factors!r}; observed={trial.observed_factors!r}"
            ),
            run_ids=[trial.id],
        )

    @staticmethod
    def _evaluate_point_assertion(
        assertion: PointAssertion,
        cells: list[CellSpec],
        trials: list[TrialRecord],
    ) -> CheckResult:
        selected_cells = {
            cell.id for cell in cells if cell_matches(cell, assertion.selector.where)
        }
        selected_trials = [trial for trial in trials if trial.cell_id in selected_cells]
        missing = [
            trial.id
            for trial in selected_trials
            if assertion.observation not in trial.observations
        ]
        values = [
            trial.observations[assertion.observation]
            for trial in selected_trials
            if assertion.observation in trial.observations
        ]
        passed = bool(selected_trials) and not missing and all(
            value == assertion.expected for value in values
        )
        return CheckResult(
            id=f"assertion:{assertion.id}",
            passed=passed,
            detail=(
                assertion.purpose
                if passed
                else (
                    f"expected {assertion.observation}={assertion.expected!r}; "
                    f"values={values!r}; missing={missing!r}; "
                    f"matched_cells={sorted(selected_cells)!r}"
                )
            ),
            run_ids=[trial.id for trial in selected_trials],
        )

    @staticmethod
    def _evaluate_contrast(
        contrast: FactorContrast,
        cells: list[CellSpec],
        trial_index: dict[tuple[str, str, int], TrialRecord],
    ) -> tuple[CheckResult, list[CheckResult]]:
        left_cells = [
            cell
            for cell in cells
            if cell.factors[contrast.factor] == contrast.from_level
            and cell_matches(cell, contrast.where)
        ]
        right_lookup = {
            FactorialWitnessEvaluator._other_factor_key(cell, contrast.factor): cell
            for cell in cells
            if cell.factors[contrast.factor] == contrast.to_level
            and cell_matches(cell, contrast.where)
        }
        cell_pairs: list[tuple[CellSpec, CellSpec]] = []
        unmatched_cells: list[str] = []
        for left_cell in left_cells:
            right_cell = right_lookup.get(
                FactorialWitnessEvaluator._other_factor_key(left_cell, contrast.factor)
            )
            if right_cell is None:
                unmatched_cells.append(left_cell.id)
                continue
            cell_pairs.append((left_cell, right_cell))

        failures: list[str] = []
        environment_checks: list[CheckResult] = []
        run_ids: list[str] = []
        compared = 0
        for left_cell, right_cell in cell_pairs:
            left_trials = {
                (block_id, replicate): trial
                for (cell_id, block_id, replicate), trial in trial_index.items()
                if cell_id == left_cell.id
            }
            right_trials = {
                (block_id, replicate): trial
                for (cell_id, block_id, replicate), trial in trial_index.items()
                if cell_id == right_cell.id
            }
            trial_keys = sorted(set(left_trials) | set(right_trials))
            for key in trial_keys:
                left_trial = left_trials.get(key)
                right_trial = right_trials.get(key)
                label = (
                    f"{left_cell.id}->{right_cell.id}/"
                    f"{key[0]}/replicate-{key[1]}"
                )
                if left_trial is None or right_trial is None:
                    failures.append(f"{label}: unpaired trial")
                    continue
                run_ids.extend([left_trial.id, right_trial.id])
                same_environment = (
                    left_trial.environment_fingerprint
                    == right_trial.environment_fingerprint
                )
                environment_checks.append(
                    CheckResult(
                        id=f"environment:{contrast.id}:{label}",
                        passed=same_environment,
                        detail=(
                            "paired environment fingerprints match"
                            if same_environment
                            else "paired environment drift detected"
                        ),
                        run_ids=[left_trial.id, right_trial.id],
                    )
                )
                if (
                    contrast.observation not in left_trial.observations
                    or contrast.observation not in right_trial.observations
                ):
                    failures.append(f"{label}: missing observation")
                    continue
                left_value = left_trial.observations[contrast.observation]
                right_value = right_trial.observations[contrast.observation]
                compared += 1
                if not _relation_holds(left_value, right_value, contrast.operator):
                    failures.append(f"{label}: {left_value!r} -> {right_value!r}")

        if not cell_pairs:
            failures.append("no factor-matched cell pairs")
        if unmatched_cells:
            failures.append("unmatched cells: " + ", ".join(sorted(unmatched_cells)))
        if compared == 0:
            failures.append("no trial pairs compared")

        result = CheckResult(
            id=f"contrast:{contrast.id}",
            passed=not failures,
            detail=contrast.purpose if not failures else "; ".join(failures),
            run_ids=run_ids,
        )
        return result, environment_checks

    @staticmethod
    def _other_factor_key(cell: CellSpec, excluded: str) -> tuple[tuple[str, str], ...]:
        return tuple(
            sorted(
                (name, repr(value))
                for name, value in cell.factors.items()
                if name != excluded
            )
        )

    @staticmethod
    def _result(
        spec: FactorialExperimentSpec,
        state: WitnessState,
        attributable: bool,
        checks: list[CheckResult],
        trials: list[TrialRecord],
        reasons: list[str],
    ) -> FactorialWitnessResult:
        return FactorialWitnessResult(
            experiment_id=spec.id,
            claim_id=spec.claim_id,
            state=state,
            attributable=attributable,
            checks=checks,
            evidence_ids=sorted(
                {evidence_id for trial in trials for evidence_id in trial.evidence_ids}
            ),
            reasons=reasons,
        )
