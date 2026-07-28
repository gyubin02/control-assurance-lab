from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from itertools import product
from math import inf, nan
from typing import Any

import pytest
from pydantic import ValidationError

from assurance_lab.claim_spec import (
    ClaimPredicate,
    ClaimQuantifier,
    ClaimSpec,
    ClaimSubject,
    EnvironmentScope,
    EvidencePolicyRef,
    ExactTolerance,
    InputDomain,
    QuantifierKind,
    SubjectKind,
    TemporalScope,
)
from assurance_lab.protocol import (
    Aggregation,
    BooleanValue,
    CellSelector,
    CellSpec,
    ClaimRole,
    CleanupState,
    Comparator,
    ContrastKind,
    EffectivenessDimension,
    EstimandKind,
    EvidencePolarity,
    ExerciseState,
    ExpectationState,
    ExperimentReport,
    ExperimentSpec,
    FactorContrast,
    FactorObservation,
    FactorRole,
    FactorSpec,
    IntegerValue,
    Observation,
    ObservationSource,
    OrderingPolicy,
    PointAssertion,
    PointClaimResult,
    PointKind,
    ProtocolEvaluator,
    ProtocolProfile,
    ProtocolState,
    TrialExecution,
    TrialPlan,
    TrialRecord,
    TruthState,
    planned_trial_order,
    typed_value,
)

BASE_TIME = datetime(2026, 7, 29, 9, 0, tzinfo=UTC)
CLAIM_AS_OF = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
FIXTURE_DIGEST = hashlib.sha256(b"finance-export-fixture-v2").hexdigest()
BUILD_DIGEST = hashlib.sha256(b"finance-export-build-v2").hexdigest()
DATASET_DIGEST = hashlib.sha256(b"synthetic-customer-cases-v2").hexdigest()


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _cells() -> list[CellSpec]:
    cells: list[CellSpec] = []
    levels = product(
        ("cross_case_export", "own_case_export"),
        ("wildcard", "case_scoped"),
        ("unguarded", "release_guard"),
        ("steady", "sham_redeploy"),
    )
    for request, row_scope, release_control, deployment in levels:
        cells.append(
            CellSpec(
                id="__".join((request, row_scope, release_control, deployment)),
                factors={
                    "request": request,
                    "row_scope": row_scope,
                    "release_control": release_control,
                    "deployment": deployment,
                },
            )
        )
    return cells


def _claim_spec(
    claim_id: str,
    *,
    subject_kind: SubjectKind,
    identifier: str,
    component: str,
    predicate_name: str,
    statement: str,
) -> ClaimSpec:
    return ClaimSpec(
        id=claim_id,
        subject=ClaimSubject(
            kind=subject_kind,
            identifier=identifier,
            component=component,
        ),
        predicate=ClaimPredicate(
            name=predicate_name,
            statement=statement,
        ),
        input_domain=InputDomain(
            id="finance-export-requests-v2",
            description=(
                "Deterministic own-case and cross-case export requests over the "
                "synthetic customer-case fixture"
            ),
            fixture_digest=FIXTURE_DIGEST,
        ),
        environment=EnvironmentScope(
            scenario_id="finance-export-non-masking",
            scenario_version="2",
            build_digest=BUILD_DIGEST,
            dataset_digest=DATASET_DIGEST,
        ),
        temporal=TemporalScope(as_of=CLAIM_AS_OF),
        quantifier=ClaimQuantifier(
            kind=QuantifierKind.ALL_TESTED,
            minimum_trials=2,
        ),
        tolerance=ExactTolerance(),
        evidence_policy=EvidencePolicyRef(
            id="lab-evidence-policy",
            version="1",
        ),
    )


def _claims() -> list[ClaimSpec]:
    return [
        _claim_spec(
            "baseline-reachability",
            subject_kind=SubjectKind.SERVICE,
            identifier="customer-export-api",
            component="export-query",
            predicate_name="cross_case_fixture_reachable",
            statement="The defective baseline reaches an out-of-scope case row.",
        ),
        _claim_spec(
            "target-mechanism",
            subject_kind=SubjectKind.CONTROL,
            identifier="application-row-scope",
            component="export-query",
            predicate_name="case_scope_denies_cross_case",
            statement="Case-scoped authorization denies the cross-case export upstream.",
        ),
        _claim_spec(
            "target-current",
            subject_kind=SubjectKind.CONTROL,
            identifier="application-row-scope",
            component="current-wildcard-query",
            predicate_name="current_target_prevents_cross_case_selection",
            statement="The current target control prevents selection of another case's rows.",
        ),
        _claim_spec(
            "compensator-current",
            subject_kind=SubjectKind.CONTROL,
            identifier="release-guard",
            component="export-release",
            predicate_name="current_guard_blocks_cross_case_delivery",
            statement="The current release guard blocks delivery of an out-of-scope export.",
        ),
        _claim_spec(
            "path-current",
            subject_kind=SubjectKind.PATH,
            identifier="customer-export-current-path",
            component="query-to-delivery",
            predicate_name="current_path_prevents_cross_case_delivery",
            statement="The tested current path does not deliver another case's export.",
        ),
        _claim_spec(
            "downstream-under-target-block",
            subject_kind=SubjectKind.CONTROL,
            identifier="release-guard",
            component="export-release-after-upstream-denial",
            predicate_name="downstream_guard_operates_after_upstream_denial",
            statement="The downstream release guard operates after the upstream target denies.",
        ),
        _claim_spec(
            "target-mechanism-effect",
            subject_kind=SubjectKind.CONTROL,
            identifier="application-row-scope",
            component="controlled-contrast",
            predicate_name="target_has_beneficial_local_effect",
            statement="Changing wildcard scoping to case scoping has the expected local effect.",
        ),
        _claim_spec(
            "intervention-harness",
            subject_kind=SubjectKind.ENVIRONMENT,
            identifier="experiment-runner",
            component="sham-redeploy",
            predicate_name="sham_leaves_selection_unchanged",
            statement="The sham redeploy leaves export-row selection unchanged.",
        ),
        _claim_spec(
            "compensator-mechanism-effect",
            subject_kind=SubjectKind.CONTROL,
            identifier="release-guard",
            component="controlled-contrast",
            predicate_name="guard_has_beneficial_delivery_effect",
            statement="Enabling the release guard changes final cross-case delivery to blocked.",
        ),
    ]


def protocol_spec() -> ExperimentSpec:
    factors = [
        FactorSpec(
            name="request",
            role=FactorRole.INPUT,
            levels=["cross_case_export", "own_case_export"],
            description="A request for another case or the caller's own case",
        ),
        FactorSpec(
            name="row_scope",
            role=FactorRole.TARGET_CONTROL,
            levels=["wildcard", "case_scoped"],
            description="The application query either ignores or enforces case ownership",
        ),
        FactorSpec(
            name="release_control",
            role=FactorRole.COMPENSATING_CONTROL,
            levels=["unguarded", "release_guard"],
            description="A downstream release guard can stop out-of-scope rows",
        ),
        FactorSpec(
            name="deployment",
            role=FactorRole.SHAM,
            levels=["steady", "sham_redeploy"],
            description="A no-op redeploy exercises the intervention machinery",
        ),
    ]
    current_path = {
        "request": "cross_case_export",
        "row_scope": "wildcard",
        "release_control": "release_guard",
    }
    return ExperimentSpec(
        id="finance-export-non-masking",
        version="2",
        profile=ProtocolProfile.PREVENTIVE_NON_MASKING,
        factors=factors,
        cells=_cells(),
        plan=TrialPlan(
            blocks=["clean-snapshot"],
            replicates=2,
            ordering=OrderingPolicy.HASH_RANDOMIZED,
            seed="published-seed-2026-07-29",
        ),
        claims=_claims(),
        point_assertions=[
            PointAssertion(
                id="broken-baseline-reaches-rows",
                claim_id="baseline-reachability",
                claim_role=ClaimRole.OTHER,
                dimension=EffectivenessDimension.OUTCOME,
                kind=PointKind.REACHABILITY,
                selector=CellSelector(
                    where={
                        "request": "cross_case_export",
                        "row_scope": "wildcard",
                        "release_control": "unguarded",
                    }
                ),
                observation="out_of_scope_rows_selected",
                comparator=Comparator.EQUAL,
                expected=typed_value(True),
                aggregation=Aggregation.ALL,
                polarity=EvidencePolarity.SUPPORTS,
                exercise_observation="target_reached",
                purpose="The defective baseline reaches another customer's rows",
            ),
            PointAssertion(
                id="case-scope-denies-upstream",
                claim_id="target-mechanism",
                claim_role=ClaimRole.TARGET_LOCAL,
                dimension=EffectivenessDimension.OUTCOME,
                kind=PointKind.MECHANISM,
                selector=CellSelector(
                    where={
                        "request": "cross_case_export",
                        "row_scope": "case_scoped",
                    }
                ),
                observation="target_denied",
                comparator=Comparator.EQUAL,
                expected=typed_value(True),
                aggregation=Aggregation.ALL,
                polarity=EvidencePolarity.SUPPORTS,
                exercise_observation="target_reached",
                purpose="The case-scoped query rejects the cross-case request upstream",
            ),
            PointAssertion(
                id="wildcard-selects-out-of-scope",
                claim_id="target-current",
                claim_role=ClaimRole.TARGET_LOCAL,
                dimension=EffectivenessDimension.OPERATING,
                kind=PointKind.CURRENT_STATE,
                selector=CellSelector(where=current_path),
                observation="out_of_scope_rows_selected",
                comparator=Comparator.EQUAL,
                expected=typed_value(True),
                aggregation=Aggregation.ALL,
                polarity=EvidencePolarity.REBUTS,
                exercise_observation="target_reached",
                purpose="The current wildcard target still selects another case's rows",
            ),
            PointAssertion(
                id="release-guard-blocks-delivery",
                claim_id="compensator-current",
                claim_role=ClaimRole.COMPENSATOR_LOCAL,
                dimension=EffectivenessDimension.OPERATING,
                kind=PointKind.CURRENT_STATE,
                selector=CellSelector(where=current_path),
                observation="final_delivery",
                comparator=Comparator.EQUAL,
                expected=typed_value(False),
                aggregation=Aggregation.ALL,
                polarity=EvidencePolarity.SUPPORTS,
                exercise_observation="release_guard_reached",
                purpose="The current release guard blocks the prepared cross-case export",
            ),
            PointAssertion(
                id="current-path-has-no-final-delivery",
                claim_id="path-current",
                claim_role=ClaimRole.PATH,
                dimension=EffectivenessDimension.OUTCOME,
                kind=PointKind.PATH_OUTCOME,
                selector=CellSelector(where=current_path),
                observation="final_delivery",
                comparator=Comparator.EQUAL,
                expected=typed_value(False),
                aggregation=Aggregation.ALL,
                polarity=EvidencePolarity.SUPPORTS,
                exercise_observation="target_reached",
                purpose="The tested current path does not deliver the cross-case export",
            ),
            PointAssertion(
                id="guard-is-not-reached-after-upstream-denial",
                claim_id="downstream-under-target-block",
                claim_role=ClaimRole.COMPENSATOR_LOCAL,
                dimension=EffectivenessDimension.OPERATING,
                kind=PointKind.CURRENT_STATE,
                selector=CellSelector(
                    where={
                        "request": "cross_case_export",
                        "row_scope": "case_scoped",
                        "release_control": "release_guard",
                    }
                ),
                observation="final_delivery",
                comparator=Comparator.EQUAL,
                expected=typed_value(False),
                aggregation=Aggregation.ALL,
                polarity=EvidencePolarity.SUPPORTS,
                exercise_observation="release_guard_reached",
                purpose="An upstream denial gives no evidence that the downstream guard ran",
            ),
        ],
        contrasts=[
            FactorContrast(
                id="target-attack-effect",
                claim_id="target-mechanism-effect",
                kind=ContrastKind.ATTACK_EFFECT,
                estimand=EstimandKind.MECHANISM_EFFECT,
                factor="row_scope",
                from_level="wildcard",
                to_level="case_scoped",
                where={"request": "cross_case_export"},
                observation="out_of_scope_rows_selected",
                operator=Comparator.TRUE_TO_FALSE,
                purpose="Case scoping removes cross-case rows at the application boundary",
            ),
            FactorContrast(
                id="target-benign-invariance",
                claim_id="target-mechanism-effect",
                kind=ContrastKind.BENIGN_INVARIANCE,
                estimand=EstimandKind.MECHANISM_EFFECT,
                factor="row_scope",
                from_level="wildcard",
                to_level="case_scoped",
                where={"request": "own_case_export"},
                observation="legitimate_delivery",
                operator=Comparator.EQUAL,
                purpose="Case scoping preserves the caller's own export",
            ),
            FactorContrast(
                id="sham-does-not-change-selection",
                claim_id="intervention-harness",
                kind=ContrastKind.SHAM_INVARIANCE,
                estimand=EstimandKind.TEST_SENSITIVITY,
                factor="deployment",
                from_level="steady",
                to_level="sham_redeploy",
                where={"request": "cross_case_export"},
                observation="out_of_scope_rows_selected",
                operator=Comparator.EQUAL,
                purpose="A no-op redeploy does not explain the target-control contrast",
            ),
            FactorContrast(
                id="release-guard-masks-final-impact",
                claim_id="compensator-mechanism-effect",
                kind=ContrastKind.CONTROL_INTERACTION,
                estimand=EstimandKind.MECHANISM_EFFECT,
                factor="release_control",
                from_level="unguarded",
                to_level="release_guard",
                where={
                    "request": "cross_case_export",
                    "row_scope": "wildcard",
                },
                observation="final_delivery",
                operator=Comparator.TRUE_TO_FALSE,
                purpose="The release guard blocks delivery after the target already failed",
            ),
        ],
    )


def _observation(
    trial_id: str,
    name: str,
    value: bool,
    *,
    source: str,
) -> Observation:
    return Observation(
        value=typed_value(value),
        source=source,
        evidence_ids=[f"evidence:{trial_id}:{name}"],
        correlation_id=f"correlation:{trial_id}",
        unit="boolean",
    )


def protocol_trials(spec: ExperimentSpec) -> list[TrialRecord]:
    cell_by_id = {cell.id: cell for cell in spec.cells}
    trials: list[TrialRecord] = []
    for sequence, (cell_id, block_id, replicate) in enumerate(planned_trial_order(spec)):
        cell = cell_by_id[cell_id]
        request = cell.factors["request"]
        row_scope = cell.factors["row_scope"]
        release_control = cell.factors["release_control"]
        attack = request == "cross_case_export"
        target_correct = row_scope == "case_scoped"
        guard_on = release_control == "release_guard"

        target_reached = True
        out_of_scope_rows_selected = attack and not target_correct
        target_denied = attack and target_correct
        release_guard_reached = not target_denied
        final_delivery = (not attack) or (out_of_scope_rows_selected and not guard_on)
        legitimate_delivery = not attack and final_delivery
        trial_id = f"trial:{block_id}:{replicate}:{cell_id}"
        started_at = BASE_TIME + timedelta(seconds=sequence * 10)
        factor_observations = {
            "request": FactorObservation(
                level=request,
                source=ObservationSource.ACTION_MANIFEST,
                evidence_ids=[f"evidence:{trial_id}:request"],
            ),
            "row_scope": FactorObservation(
                level=row_scope,
                source=ObservationSource.CONTROL_PLANE,
                evidence_ids=[f"evidence:{trial_id}:row-scope"],
            ),
            "release_control": FactorObservation(
                level=release_control,
                source=ObservationSource.CONTROL_PLANE,
                evidence_ids=[f"evidence:{trial_id}:release-control"],
            ),
            "deployment": FactorObservation(
                level=cell.factors["deployment"],
                source=ObservationSource.CONTROL_PLANE,
                evidence_ids=[f"evidence:{trial_id}:deployment"],
            ),
        }
        observations = {
            "target_reached": _observation(
                trial_id,
                "target-reached",
                target_reached,
                source="application-trace",
            ),
            "out_of_scope_rows_selected": _observation(
                trial_id,
                "out-of-scope-rows",
                out_of_scope_rows_selected,
                source="query-audit",
            ),
            "target_denied": _observation(
                trial_id,
                "target-denied",
                target_denied,
                source="application-policy-log",
            ),
            "release_guard_reached": _observation(
                trial_id,
                "release-guard-reached",
                release_guard_reached,
                source="release-service-trace",
            ),
            "final_delivery": _observation(
                trial_id,
                "final-delivery",
                final_delivery,
                source="delivery-receipt",
            ),
            "legitimate_delivery": _observation(
                trial_id,
                "legitimate-delivery",
                legitimate_delivery,
                source="delivery-receipt",
            ),
        }
        trials.append(
            TrialRecord(
                id=trial_id,
                spec_id=spec.id,
                cell_id=cell_id,
                block_id=block_id,
                replicate=replicate,
                sequence=sequence,
                started_at=started_at,
                ended_at=started_at + timedelta(seconds=2),
                execution=TrialExecution.COMPLETED,
                action_digest=_digest(f"action:{request}"),
                input_seed=f"{block_id}:{replicate}:{request}",
                reset_lineage=f"snapshot:{block_id}:{replicate}",
                reset_epoch=replicate,
                reset_verified=True,
                reset_evidence_ids=[f"evidence:{trial_id}:reset"],
                covariate_snapshot_digest=_digest(f"covariates:{block_id}:{replicate}"),
                covariate_evidence_ids=[f"evidence:{trial_id}:covariates"],
                declared_intervention_digest=_digest(repr(sorted(cell.factors.items()))),
                factor_observations=factor_observations,
                undeclared_diff={},
                observations=observations,
                cleanup=CleanupState.VERIFIED,
                cleanup_evidence_ids=[f"evidence:{trial_id}:cleanup"],
            )
        )
    return trials


def _claim(report: ExperimentReport, claim_id: str) -> PointClaimResult:
    return next(claim for claim in report.point_claims if claim.claim_id == claim_id)


def _contrast(report: ExperimentReport, contrast_id: str):
    return next(contrast for contrast in report.contrasts if contrast.contrast_id == contrast_id)


def _contains_key(value: Any, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(_contains_key(child, key) for child in value.values())
    if isinstance(value, list):
        return any(_contains_key(child, key) for child in value)
    return False


def test_preventive_non_masking_protocol_keeps_three_current_verdicts_separate() -> None:
    spec = protocol_spec()
    report = ProtocolEvaluator().evaluate(spec, protocol_trials(spec))

    assert report.protocol_state == ProtocolState.VALID

    target = _claim(report, "target-current")
    assert target.admissibility == ProtocolState.VALID
    assert target.exercise == ExerciseState.EXERCISED
    assert target.truth == TruthState.REFUTED

    compensator = _claim(report, "compensator-current")
    assert compensator.admissibility == ProtocolState.VALID
    assert compensator.exercise == ExerciseState.EXERCISED
    assert compensator.truth == TruthState.SUPPORTED

    path = _claim(report, "path-current")
    assert path.admissibility == ProtocolState.VALID
    assert path.exercise == ExerciseState.EXERCISED
    assert path.truth == TruthState.SUPPORTED

    downstream = _claim(report, "downstream-under-target-block")
    assert downstream.admissibility == ProtocolState.VALID
    assert downstream.exercise == ExerciseState.NOT_EXERCISED
    assert downstream.truth == TruthState.NEITHER

    assert report.contrasts
    assert all(result.validity == ProtocolState.VALID for result in report.contrasts)
    assert all(result.expectation == ExpectationState.SATISFIED for result in report.contrasts)

    assert not hasattr(report, "attributable")
    assert not _contains_key(report.model_dump(mode="json"), "attributable")


def test_missing_declared_cell_makes_protocol_incomplete_and_removes_current_verdict() -> None:
    spec = protocol_spec()
    trials = protocol_trials(spec)
    missing = next(
        trial
        for trial in trials
        if trial.replicate == 0
        and trial.factor_observations["request"].level == "cross_case_export"
        and trial.factor_observations["row_scope"].level == "wildcard"
        and trial.factor_observations["release_control"].level == "release_guard"
    )
    trials.remove(missing)

    report = ProtocolEvaluator().evaluate(spec, trials)

    assert report.protocol_state == ProtocolState.INCOMPLETE
    assert _claim(report, "target-current").truth == TruthState.NEITHER
    assert _claim(report, "compensator-current").truth == TruthState.NEITHER
    assert _claim(report, "path-current").truth == TruthState.NEITHER


def test_observation_schema_rejects_absent_evidence() -> None:
    with pytest.raises(ValidationError):
        Observation(
            value=typed_value(True),
            source="query-audit",
            evidence_ids=[],
        )


def test_undeclared_drift_invalidates_affected_current_claims() -> None:
    spec = protocol_spec()
    trials = protocol_trials(spec)
    drifted = next(
        trial
        for trial in trials
        if trial.factor_observations["request"].level == "cross_case_export"
        and trial.factor_observations["row_scope"].level == "wildcard"
        and trial.factor_observations["release_control"].level == "release_guard"
    )
    drifted.undeclared_diff = {"feature_flag": "changed outside the intervention"}

    report = ProtocolEvaluator().evaluate(spec, trials)

    assert report.protocol_state == ProtocolState.INVALID
    assert _claim(report, "target-current").truth == TruthState.NEITHER
    assert _claim(report, "compensator-current").truth == TruthState.NEITHER
    assert _claim(report, "path-current").truth == TruthState.NEITHER


def test_control_factor_self_report_is_not_an_independent_manipulation_check() -> None:
    spec = protocol_spec()
    trials = protocol_trials(spec)
    self_reported = trials[0]
    self_reported.factor_observations["row_scope"].source = ObservationSource.RUNNER_SELF_REPORT

    report = ProtocolEvaluator().evaluate(spec, trials)

    assert report.protocol_state == ProtocolState.INVALID
    factor_check = next(
        check for check in report.protocol_checks if check.id == f"factors:{self_reported.id}"
    )
    assert factor_check.passed is False


def test_order_tampering_invalidates_all_inferences_that_used_the_run_ledger() -> None:
    spec = protocol_spec()
    trials = protocol_trials(spec)
    trials[0].sequence, trials[1].sequence = trials[1].sequence, trials[0].sequence

    report = ProtocolEvaluator().evaluate(spec, trials)

    assert report.protocol_state == ProtocolState.INVALID
    assert (
        next(check for check in report.protocol_checks if check.id == "trial-order").passed is False
    )
    assert all(claim.truth == TruthState.NEITHER for claim in report.point_claims)
    assert all(contrast.validity == ProtocolState.INVALID for contrast in report.contrasts)


def test_no_evidence_produces_no_claim_verdict() -> None:
    spec = protocol_spec()
    trials = protocol_trials(spec)
    for trial in trials:
        trial.reset_evidence_ids = []
        trial.covariate_evidence_ids = []
        trial.cleanup_evidence_ids = []
        for factor in trial.factor_observations.values():
            factor.evidence_ids = []
        for observation in trial.observations.values():
            observation.evidence_ids = []

    report = ProtocolEvaluator().evaluate(spec, trials)

    assert report.protocol_state == ProtocolState.INVALID
    assert all(claim.truth == TruthState.NEITHER for claim in report.point_claims)
    assert all(not claim.support_evidence_ids for claim in report.point_claims)
    assert all(not claim.rebuttal_evidence_ids for claim in report.point_claims)
    assert all(contrast.validity == ProtocolState.INVALID for contrast in report.contrasts)


def test_boolean_point_does_not_accept_integer_one() -> None:
    spec = protocol_spec()
    trials = protocol_trials(spec)
    confused = next(
        trial
        for trial in trials
        if trial.factor_observations["request"].level == "cross_case_export"
        and trial.factor_observations["row_scope"].level == "wildcard"
        and trial.factor_observations["release_control"].level == "release_guard"
    )
    confused.observations["out_of_scope_rows_selected"].value = IntegerValue(value=1)

    report = ProtocolEvaluator().evaluate(spec, trials)

    assert _claim(report, "target-current").truth == TruthState.NEITHER


def test_boolean_contrast_with_integer_input_is_invalid_not_heterogeneous() -> None:
    spec = protocol_spec()
    trials = protocol_trials(spec)
    confused = next(
        trial
        for trial in trials
        if trial.replicate == 0
        and trial.factor_observations["request"].level == "cross_case_export"
        and trial.factor_observations["row_scope"].level == "wildcard"
        and trial.factor_observations["release_control"].level == "unguarded"
        and trial.factor_observations["deployment"].level == "steady"
    )
    confused.observations["out_of_scope_rows_selected"].value = IntegerValue(value=1)

    report = ProtocolEvaluator().evaluate(spec, trials)
    target_effect = _contrast(report, "target-attack-effect")

    assert target_effect.validity == ProtocolState.INVALID
    assert target_effect.expectation == ExpectationState.UNRESOLVED


@pytest.mark.parametrize("non_finite", [nan, inf, -inf])
def test_non_finite_numeric_observations_are_rejected(non_finite: float) -> None:
    with pytest.raises(ValidationError):
        typed_value(non_finite)


def test_strict_boolean_value_rejects_integer_one() -> None:
    with pytest.raises(ValidationError):
        BooleanValue(value=1)
