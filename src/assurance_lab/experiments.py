"""Evaluation of matched security-control interventions."""

from __future__ import annotations

from collections import defaultdict
from enum import StrEnum

from pydantic import BaseModel, Field, model_validator

Scalar = bool | int | float | str | None


class RunRole(StrEnum):
    ATTACK_BASELINE = "attack_baseline"
    ATTACK_TREATMENT = "attack_treatment"
    BENIGN_BASELINE = "benign_baseline"
    BENIGN_TREATMENT = "benign_treatment"
    UNRELATED_INTERVENTION = "unrelated_intervention"


class RunExecution(StrEnum):
    COMPLETED = "completed"
    ERROR = "error"


class RelationOperator(StrEnum):
    EQUAL = "equal"
    NOT_EQUAL = "not_equal"
    FALSE_TO_TRUE = "false_to_true"
    TRUE_TO_FALSE = "true_to_false"
    INCREASES = "increases"
    DECREASES = "decreases"


class CheckRole(StrEnum):
    VALIDITY = "validity"
    SUPPORT = "support"
    REFUTATION = "refutation"


class WitnessState(StrEnum):
    SUPPORTED = "supported"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class RunRecord(BaseModel):
    id: str
    role: RunRole
    pair_id: str
    execution: RunExecution = RunExecution.COMPLETED
    environment_fingerprint: str
    intervention_verified: bool
    cleanup_verified: bool
    observations: dict[str, Scalar]
    evidence_ids: list[str] = Field(default_factory=list)


class Assertion(BaseModel):
    id: str
    role: RunRole
    observation: str
    expected: Scalar
    purpose: str


class Relation(BaseModel):
    id: str
    left_role: RunRole
    right_role: RunRole
    observation: str
    operator: RelationOperator
    check_role: CheckRole = CheckRole.SUPPORT
    purpose: str


class ControlExperimentSpec(BaseModel):
    id: str
    claim_id: str
    required_roles: set[RunRole] = Field(
        default_factory=lambda: {
            RunRole.ATTACK_BASELINE,
            RunRole.ATTACK_TREATMENT,
            RunRole.BENIGN_BASELINE,
            RunRole.BENIGN_TREATMENT,
            RunRole.UNRELATED_INTERVENTION,
        }
    )
    validity_assertions: list[Assertion] = Field(default_factory=list)
    support_assertions: list[Assertion]
    refutation_assertions: list[Assertion] = Field(default_factory=list)
    relations: list[Relation]
    require_environment_equivalence: bool = True
    require_cleanup: bool = True

    @model_validator(mode="after")
    def assertions_target_required_roles(self) -> ControlExperimentSpec:
        referenced = {
            assertion.role
            for assertion in [
                *self.validity_assertions,
                *self.support_assertions,
                *self.refutation_assertions,
            ]
        }
        referenced.update(r.left_role for r in self.relations)
        referenced.update(r.right_role for r in self.relations)
        missing = referenced - self.required_roles
        if missing:
            raise ValueError(f"roles referenced but not required: {sorted(missing)}")
        return self


class CheckResult(BaseModel):
    id: str
    passed: bool
    detail: str
    run_ids: list[str] = Field(default_factory=list)


class WitnessResult(BaseModel):
    experiment_id: str
    claim_id: str
    state: WitnessState
    attributable: bool
    checks: list[CheckResult]
    evidence_ids: list[str]
    reasons: list[str]


def _relation_holds(left: Scalar, right: Scalar, operator: RelationOperator) -> bool:
    if operator == RelationOperator.EQUAL:
        return left == right
    if operator == RelationOperator.NOT_EQUAL:
        return left != right
    if operator == RelationOperator.FALSE_TO_TRUE:
        return left is False and right is True
    if operator == RelationOperator.TRUE_TO_FALSE:
        return left is True and right is False
    if operator in {RelationOperator.INCREASES, RelationOperator.DECREASES}:
        if isinstance(left, bool) or isinstance(right, bool):
            return False
        if not isinstance(left, (int, float)) or not isinstance(right, (int, float)):
            return False
        if operator == RelationOperator.INCREASES:
            return right > left
        return right < left
    raise AssertionError(f"unhandled operator: {operator}")


class InterventionalWitnessEvaluator:
    """Recalculate a control-specific witness from canonical run records."""

    def evaluate(
        self,
        spec: ControlExperimentSpec,
        runs: list[RunRecord],
    ) -> WitnessResult:
        checks: list[CheckResult] = []
        reasons: list[str] = []
        by_pair_role: dict[tuple[str, RunRole], RunRecord] = {}
        roles: defaultdict[RunRole, list[RunRecord]] = defaultdict(list)

        duplicate_keys: list[str] = []
        for run in runs:
            key = (run.pair_id, run.role)
            if key in by_pair_role:
                duplicate_keys.append(f"{run.pair_id}/{run.role}")
            by_pair_role[key] = run
            roles[run.role].append(run)

        if duplicate_keys:
            reasons.append("duplicate pair/role records: " + ", ".join(sorted(duplicate_keys)))
            return self._result(spec, WitnessState.ERROR, False, checks, runs, reasons)

        missing_roles = sorted(
            (role for role in spec.required_roles if not roles[role]),
            key=str,
        )
        checks.append(
            CheckResult(
                id="required-runs",
                passed=not missing_roles,
                detail=(
                    "all required run roles present"
                    if not missing_roles
                    else "missing roles: " + ", ".join(str(role) for role in missing_roles)
                ),
                run_ids=[run.id for run in runs],
            )
        )
        if missing_roles:
            reasons.append("required run family is incomplete")
            return self._result(spec, WitnessState.INCONCLUSIVE, False, checks, runs, reasons)

        errors = [run for run in runs if run.execution == RunExecution.ERROR]
        checks.append(
            CheckResult(
                id="run-execution",
                passed=not errors,
                detail=(
                    "all runs completed"
                    if not errors
                    else "harness errors: " + ", ".join(run.id for run in errors)
                ),
                run_ids=[run.id for run in errors],
            )
        )
        if errors:
            reasons.append("one or more runs ended in a harness error")
            return self._result(spec, WitnessState.ERROR, False, checks, runs, reasons)

        unverified = [run for run in runs if not run.intervention_verified]
        checks.append(
            CheckResult(
                id="manipulation",
                passed=not unverified,
                detail=(
                    "all declared interventions verified"
                    if not unverified
                    else "unverified interventions: " + ", ".join(run.id for run in unverified)
                ),
                run_ids=[run.id for run in unverified],
            )
        )

        dirty = [run for run in runs if not run.cleanup_verified]
        cleanup_passed = not spec.require_cleanup or not dirty
        checks.append(
            CheckResult(
                id="cleanup",
                passed=cleanup_passed,
                detail=(
                    "cleanup verified"
                    if cleanup_passed
                    else "cleanup failed or unverified: " + ", ".join(run.id for run in dirty)
                ),
                run_ids=[run.id for run in dirty],
            )
        )

        equivalence_checks = self._environment_checks(spec, by_pair_role)
        checks.extend(equivalence_checks)

        validity_assertion_checks = [
            self._evaluate_assertion(assertion, roles)
            for assertion in spec.validity_assertions
        ]
        checks.extend(validity_assertion_checks)

        support_assertion_checks = [
            self._evaluate_assertion(assertion, roles) for assertion in spec.support_assertions
        ]
        checks.extend(support_assertion_checks)

        refutation_assertion_checks = [
            self._evaluate_assertion(assertion, roles) for assertion in spec.refutation_assertions
        ]

        all_relation_checks = [
            *(
                self._evaluate_relation(relation, by_pair_role)
                for relation in spec.relations
            )
        ]
        checks.extend(all_relation_checks)

        validity_relation_checks = [
            check
            for relation, check in zip(spec.relations, all_relation_checks, strict=True)
            if relation.check_role == CheckRole.VALIDITY
        ]
        support_relation_checks = [
            check
            for relation, check in zip(spec.relations, all_relation_checks, strict=True)
            if relation.check_role == CheckRole.SUPPORT
        ]
        refutation_relation_checks = [
            check
            for relation, check in zip(spec.relations, all_relation_checks, strict=True)
            if relation.check_role == CheckRole.REFUTATION
        ]

        structural_ids = {"required-runs", "run-execution", "manipulation", "cleanup"}
        structure_checks = [
            check
            for check in checks
            if check.id in structural_ids or check.id.startswith("environment:")
        ]
        validity_checks = [
            *structure_checks,
            *validity_assertion_checks,
            *validity_relation_checks,
        ]
        structurally_valid = all(
            check.passed
            for check in validity_checks
        )
        support_checks = [*support_assertion_checks, *support_relation_checks]
        refutation_checks = [*refutation_assertion_checks, *refutation_relation_checks]
        support_holds = bool(support_checks) and all(check.passed for check in support_checks)
        refutation_holds = bool(refutation_checks) and all(
            check.passed for check in refutation_checks
        )

        if not structurally_valid:
            reasons.append(
                "the observed result is not attributable because intervention, "
                "equivalence, or cleanup checks failed"
            )
            return self._result(spec, WitnessState.INCONCLUSIVE, False, checks, runs, reasons)

        if support_holds and refutation_holds:
            reasons.append("supporting and refuting predicates both hold")
            checks.extend(refutation_assertion_checks)
            return self._result(spec, WitnessState.INCONCLUSIVE, False, checks, runs, reasons)
        if support_holds:
            reasons.append("matched runs satisfy the declared control-specific contrast")
            return self._result(spec, WitnessState.SUPPORTED, True, checks, runs, reasons)
        if refutation_holds:
            checks.extend(refutation_assertion_checks)
            reasons.append("the valid experiment satisfies the declared refutation predicate")
            return self._result(spec, WitnessState.REFUTED, True, checks, runs, reasons)

        reasons.append("the experiment was valid but did not satisfy support or refutation rules")
        return self._result(spec, WitnessState.INCONCLUSIVE, False, checks, runs, reasons)

    @staticmethod
    def _environment_checks(
        spec: ControlExperimentSpec,
        runs: dict[tuple[str, RunRole], RunRecord],
    ) -> list[CheckResult]:
        if not spec.require_environment_equivalence:
            return []
        grouped: defaultdict[str, list[RunRecord]] = defaultdict(list)
        for (pair_id, _), run in runs.items():
            grouped[pair_id].append(run)
        checks: list[CheckResult] = []
        for pair_id, pair_runs in sorted(grouped.items()):
            fingerprints = {run.environment_fingerprint for run in pair_runs}
            checks.append(
                CheckResult(
                    id=f"environment:{pair_id}",
                    passed=len(fingerprints) == 1,
                    detail=(
                        "environment fingerprints match"
                        if len(fingerprints) == 1
                        else "environment drift detected"
                    ),
                    run_ids=[run.id for run in pair_runs],
                )
            )
        return checks

    @staticmethod
    def _evaluate_assertion(
        assertion: Assertion,
        roles: dict[RunRole, list[RunRecord]],
    ) -> CheckResult:
        selected = roles[assertion.role]
        missing = [run.id for run in selected if assertion.observation not in run.observations]
        values = [
            run.observations[assertion.observation]
            for run in selected
            if assertion.observation in run.observations
        ]
        passed = not missing and bool(values) and all(
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
                    f"observed {values!r}; missing in {missing!r}"
                )
            ),
            run_ids=[run.id for run in selected],
        )

    @staticmethod
    def _evaluate_relation(
        relation: Relation,
        runs: dict[tuple[str, RunRole], RunRecord],
    ) -> CheckResult:
        left = {
            pair_id: run
            for (pair_id, role), run in runs.items()
            if role == relation.left_role
        }
        right = {
            pair_id: run
            for (pair_id, role), run in runs.items()
            if role == relation.right_role
        }
        common_pairs = sorted(set(left) & set(right))
        missing_pairs = sorted(set(left) ^ set(right))
        failures: list[str] = []
        run_ids: list[str] = []
        for pair_id in common_pairs:
            left_run = left[pair_id]
            right_run = right[pair_id]
            run_ids.extend([left_run.id, right_run.id])
            if (
                relation.observation not in left_run.observations
                or relation.observation not in right_run.observations
            ):
                failures.append(f"{pair_id}: missing observation")
                continue
            left_value = left_run.observations[relation.observation]
            right_value = right_run.observations[relation.observation]
            if not _relation_holds(left_value, right_value, relation.operator):
                failures.append(f"{pair_id}: {left_value!r} -> {right_value!r}")
        if not common_pairs:
            failures.append("no paired runs")
        if missing_pairs:
            failures.append("unpaired: " + ", ".join(missing_pairs))
        return CheckResult(
            id=f"relation:{relation.id}",
            passed=not failures,
            detail=relation.purpose if not failures else "; ".join(failures),
            run_ids=run_ids,
        )

    @staticmethod
    def _result(
        spec: ControlExperimentSpec,
        state: WitnessState,
        attributable: bool,
        checks: list[CheckResult],
        runs: list[RunRecord],
        reasons: list[str],
    ) -> WitnessResult:
        evidence_ids = sorted({evidence_id for run in runs for evidence_id in run.evidence_ids})
        return WitnessResult(
            experiment_id=spec.id,
            claim_id=spec.claim_id,
            state=state,
            attributable=attributable,
            checks=checks,
            evidence_ids=evidence_ids,
            reasons=reasons,
        )
