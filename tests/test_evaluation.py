from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from pydantic import ValidationError

from assurance_lab.contract import (
    AllTested,
    AtLeastRate,
    BooleanValue,
    CellSelector,
    CompensatorControlAxis,
    CompiledExperiment,
    DecimalValue,
    EvidencePolicyRef,
    EvidenceWindow,
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
    compile_experiment,
)
from assurance_lab.evaluation import (
    AdmittedCleanupEvidence,
    AdmittedMetricEvidence,
    AdmittedTrialAttestation,
    CleanupBinding,
    CleanupEvidenceFailure,
    CleanupReference,
    CleanupState,
    CleanupVerificationResult,
    EvidenceBinding,
    ExecutedStageEvent,
    ExerciseState,
    ExperimentEvaluator,
    FreshClone,
    MetricEvidenceFailure,
    MetricEvidenceResult,
    ResidualClassification,
    SkippedStageEvent,
    Trace,
    TrialAttestationBinding,
    TrialAttestationFailure,
    TrialAttestationResult,
    TrialRecord,
    TruthValue,
)


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def text(value: str) -> StringValue:
    return StringValue(value=value)


def boolean(value: bool) -> BooleanValue:
    return BooleanValue(value=value)


def current_selector() -> CellSelector:
    return CellSelector(
        input=text("malicious"),
        target=text("wildcard-misgrant"),
        compensator=text("enforce"),
        sham=boolean(False),
    )


def benign_selector() -> CellSelector:
    return CellSelector(input=text("assigned-case"))


def metric(identifier: str, component: str, stage: Stage) -> MetricContract:
    return MetricContract(
        id=identifier,
        component=component,
        stage=stage,
        value_type=MetricValueType.BOOLEAN,
        extractor_id=f"{identifier}.extractor",
        evidence_class="signed-event",
    )


def obligation(
    identifier: str,
    component: str,
    scope: ObligationScope,
    metric_id: str,
    expected: bool,
    *,
    selector: CellSelector,
    quantifier: AllTested | AtLeastRate | None = None,
) -> Obligation:
    return Obligation(
        id=identifier,
        subject=Subject(identifier=component, component=component),
        scope=scope,
        selector=selector,
        predicate=Predicate(
            metric_id=metric_id,
            operator=PredicateOperator.EQUAL,
            expected=boolean(expected),
        ),
        quantifier=quantifier or AllTested(min_trials=2),
    )


def valid_contract() -> ExperimentContract:
    now = datetime(2026, 7, 29, 12, tzinfo=UTC)
    target_metric = metric(
        "out-of-scope-records-selected",
        "authorization-policy",
        Stage.TARGET,
    )
    compensator_metric = metric(
        "unapproved-release-blocked",
        "release-gateway",
        Stage.COMPENSATOR,
    )
    outcome_metric = metric(
        "final-exfiltration",
        "client-receipt",
        Stage.OUTCOME,
    )
    benign_metric = metric(
        "assigned-case-available",
        "client-receipt",
        Stage.OUTCOME,
    )
    return ExperimentContract(
        id="financial-support-export",
        version="3.0.0",
        scope=ExperimentScope(
            scenario_id="financial-support-export",
            build_digest=digest("build"),
            dataset_digest=digest("dataset"),
            fixture_digest=digest("fixture"),
            assessment_as_of=now,
            evidence_window=EvidenceWindow(
                start=now - timedelta(minutes=10),
                end=now + timedelta(minutes=10),
            ),
            evidence_policy=EvidencePolicyRef(
                id="lab-evidence",
                version="1",
                digest=digest("policy"),
            ),
        ),
        metrics=(
            target_metric,
            compensator_metric,
            outcome_metric,
            benign_metric,
        ),
        obligations=(
            obligation(
                "entitlement-current",
                "authorization-policy",
                ObligationScope.TARGET_LOCAL,
                target_metric.id,
                False,
                selector=current_selector(),
            ),
            obligation(
                "release-guard-current",
                "release-gateway",
                ObligationScope.COMPENSATOR_LOCAL,
                compensator_metric.id,
                True,
                selector=current_selector(),
            ),
            obligation(
                "tested-path-current",
                "client-receipt",
                ObligationScope.PATH,
                outcome_metric.id,
                False,
                selector=current_selector(),
            ),
            obligation(
                "benign-path-current",
                "client-receipt",
                ObligationScope.PATH,
                benign_metric.id,
                True,
                selector=benign_selector(),
            ),
        ),
        profile=PreventiveNonMaskingProfile(
            input=InputAxis(
                component="support-client",
                attack=text("malicious"),
                benign=text("assigned-case"),
                attack_action_digest=digest("attack-action"),
                benign_action_digest=digest("benign-action"),
            ),
            target=TargetControlAxis(
                component="authorization-policy",
                ineffective=text("wildcard-misgrant"),
                effective=text("case-scoped"),
                current=text("wildcard-misgrant"),
            ),
            compensator=CompensatorControlAxis(
                component="release-gateway",
                off=text("monitor-only"),
                on=text("enforce"),
                current=text("enforce"),
            ),
            sham=ShamAxis(steady=boolean(False), redeploy=boolean(True)),
            outcome_component="client-receipt",
            target_metric_id=target_metric.id,
            compensator_metric_id=compensator_metric.id,
            outcome_metric_id=outcome_metric.id,
            benign_outcome_metric_id=benign_metric.id,
            target_safe_value=boolean(False),
            compensator_safe_value=boolean(True),
            outcome_safe_value=boolean(False),
            benign_safe_value=boolean(True),
            primary_target_obligation_id="entitlement-current",
            primary_compensator_obligation_id="release-guard-current",
            primary_path_obligation_id="tested-path-current",
            primary_benign_obligation_id="benign-path-current",
            target_attack_relation=MetricRelation(operator=RelationOperator.TRUE_TO_FALSE),
            target_benign_relation=MetricRelation(operator=RelationOperator.EQUAL),
            sham_relation=MetricRelation(operator=RelationOperator.EQUAL),
            compensator_attack_relation=MetricRelation(operator=RelationOperator.TRUE_TO_FALSE),
        ),
        plan=TrialPlan(
            blocks=("fresh-clone-a",),
            replicates=2,
            order_seed="published-seed-2026-07-29",
        ),
    )


def effective_current_contract() -> ExperimentContract:
    contract = valid_contract()
    profile = contract.profile
    target = profile.target.model_copy(update={"current": profile.target.effective})
    updated_profile = profile.model_copy(update={"target": target})
    current = CellSelector(
        input=profile.input.attack,
        target=profile.target.effective,
        compensator=profile.compensator.current,
        sham=profile.sham.steady,
    )
    selectors = {
        profile.primary_target_obligation_id: current,
        profile.primary_compensator_obligation_id: current,
        profile.primary_path_obligation_id: current,
        profile.primary_benign_obligation_id: CellSelector(input=profile.input.benign),
    }
    obligations = tuple(
        obligation_item.model_copy(update={"selector": selectors[obligation_item.id]})
        if obligation_item.id in selectors
        else obligation_item
        for obligation_item in contract.obligations
    )
    return contract.model_copy(
        update={
            "profile": updated_profile,
            "obligations": obligations,
        }
    )


@dataclass
class MemoryAttestationVerifier:
    results: dict[str, TrialAttestationResult]

    def verify(self, record: TrialRecord, /) -> TrialAttestationResult:
        return self.results.get(
            record.trial_key,
            TrialAttestationFailure(status="missing", reason="no attestation"),
        )


@dataclass
class MemoryEvidenceVerifier:
    results: dict[tuple[str, Stage, str], MetricEvidenceResult]

    def verify(self, binding: EvidenceBinding, /) -> MetricEvidenceResult:
        return self.results.get(
            (binding.trial_key, binding.stage, binding.metric_id),
            MetricEvidenceFailure(status="missing", reason="no metric evidence"),
        )


@dataclass
class MemoryCleanupVerifier:
    results: dict[str, CleanupVerificationResult]

    def verify(self, binding: CleanupBinding, /) -> CleanupVerificationResult:
        return self.results.get(
            binding.trial_key,
            CleanupEvidenceFailure(status="missing", reason="no cleanup evidence"),
        )


def current_trial_keys(compiled: CompiledExperiment) -> tuple[str, ...]:
    coverage = {item.obligation_id: item.trial_keys for item in compiled.obligation_coverage}
    return coverage[compiled.contract.profile.primary_target_obligation_id]


def make_record(
    compiled: CompiledExperiment,
    trial_key: str,
    *,
    target_blocks: bool = False,
    action_label: str | None = None,
) -> TrialRecord:
    planned = next(trial for trial in compiled.planned_trials if trial.key == trial_key)
    selector = next(cell.selector for cell in compiled.cells if cell.key == planned.cell_key)
    input_axis = compiled.contract.profile.input
    expected_action = (
        input_axis.attack_action_digest
        if selector.input == input_axis.attack
        else input_axis.benign_action_digest
    )
    start = compiled.contract.scope.evidence_window.start + timedelta(minutes=1)

    def executed(
        stage: Stage,
        offset: int,
        *,
        blocks: bool = False,
    ) -> ExecutedStageEvent:
        return ExecutedStageEvent(
            event_id=f"{stage.value}:{planned.ordinal}",
            evidence_bundle_digest=digest(f"stage-bundle:{trial_key}:{stage.value}"),
            stage=stage,
            started_at=start + timedelta(seconds=offset),
            ended_at=start + timedelta(seconds=offset + 10),
            blocks_downstream=blocks,
        )

    target = executed(Stage.TARGET, 10, blocks=target_blocks)
    compensator: ExecutedStageEvent | SkippedStageEvent
    if target_blocks:
        compensator = SkippedStageEvent(
            event_id=f"compensator-skipped:{planned.ordinal}",
            stage=Stage.COMPENSATOR,
            blocked_by_event_id=target.event_id,
        )
    else:
        compensator = executed(Stage.COMPENSATOR, 20)
    return TrialRecord(
        spec_digest=compiled.spec_digest,
        trial_key=trial_key,
        cell_key=planned.cell_key,
        block=planned.block,
        replicate=planned.replicate,
        clone=FreshClone(
            unique_instance_id=f"clone:{planned.ordinal}",
            base_snapshot_digest=digest("common-base"),
            covariate_digest=digest("common-covariate"),
            attestation_bundle_digest=digest(f"attestation-bundle:{trial_key}"),
            runner_resource_id=f"runner:{planned.ordinal}",
        ),
        trace=Trace(
            trace_id=f"trace:{planned.ordinal}",
            action_digest=(digest(action_label) if action_label is not None else expected_action),
            input=executed(Stage.INPUT, 0),
            target=target,
            compensator=compensator,
            outcome=executed(Stage.OUTCOME, 30),
        ),
        cleanup=CleanupReference(
            evidence_bundle_digest=digest(f"cleanup-bundle:{trial_key}"),
        ),
    )


def attestation_for(
    compiled: CompiledExperiment,
    record: TrialRecord,
) -> AdmittedTrialAttestation:
    selector = next(cell.selector for cell in compiled.cells if cell.key == record.cell_key)
    planned = next(trial for trial in compiled.planned_trials if trial.key == record.trial_key)
    return AdmittedTrialAttestation(
        evidence_id=digest(f"attestation-evidence:{record.trial_key}"),
        binding=TrialAttestationBinding(
            spec_digest=compiled.spec_digest,
            trial_key=record.trial_key,
            cell_key=planned.cell_key,
            block=planned.block,
            replicate=planned.replicate,
            ordinal=planned.ordinal,
            trace_id=record.trace.trace_id,
            action_digest=record.trace.action_digest,
            clone_unique_instance_id=record.clone.unique_instance_id,
            runner_resource_id=record.clone.runner_resource_id,
            attestation_bundle_digest=record.clone.attestation_bundle_digest,
        ),
        observed_build_digest=compiled.contract.scope.build_digest,
        observed_dataset_digest=compiled.contract.scope.dataset_digest,
        observed_fixture_digest=compiled.contract.scope.fixture_digest,
        executed_ordinal=planned.ordinal,
        observed_selector=selector,
        base_snapshot_digest=record.clone.base_snapshot_digest,
        covariate_digest=record.clone.covariate_digest,
        intervention_digest=digest(f"intervention:{record.cell_key}"),
        artifact_ids=(record.clone.attestation_bundle_digest,),
        started_at=record.trace.input.started_at,
        ended_at=record.trace.outcome.ended_at,
    )


def metric_evidence(
    compiled: CompiledExperiment,
    record: TrialRecord,
    stage: Stage,
    metric_id: str,
    value: bool,
    *,
    evidence_id: str | None = None,
) -> AdmittedMetricEvidence:
    event = record.trace.event_for(stage)
    assert isinstance(event, ExecutedStageEvent)
    binding = EvidenceBinding(
        spec_digest=compiled.spec_digest,
        trial_key=record.trial_key,
        trace_id=record.trace.trace_id,
        event_id=event.event_id,
        evidence_bundle_digest=event.evidence_bundle_digest,
        stage=stage,
        metric_id=metric_id,
    )
    return AdmittedMetricEvidence(
        evidence_id=evidence_id
        or digest(f"metric-evidence:{record.trial_key}:{stage.value}:{metric_id}"),
        binding=binding,
        value=BooleanValue(value=value),
        observed_at=event.started_at,
        artifact_ids=(event.evidence_bundle_digest,),
    )


def cleanup_evidence(
    compiled: CompiledExperiment,
    record: TrialRecord,
    *,
    state: CleanupState = CleanupState.VERIFIED,
    evidence_id: str | None = None,
    observed_at=None,
    extra_artifact_ids: tuple[str, ...] = (),
) -> AdmittedCleanupEvidence:
    binding = CleanupBinding(
        spec_digest=compiled.spec_digest,
        trial_key=record.trial_key,
        trace_id=record.trace.trace_id,
        clone_unique_instance_id=record.clone.unique_instance_id,
        runner_resource_id=record.clone.runner_resource_id,
        evidence_bundle_digest=record.cleanup.evidence_bundle_digest,
        outcome_ended_at=record.trace.outcome.ended_at,
    )
    return AdmittedCleanupEvidence(
        state=state,
        binding=binding,
        evidence_id=evidence_id or digest(f"cleanup-evidence:{record.trial_key}"),
        observed_at=observed_at or record.trace.outcome.ended_at + timedelta(seconds=1),
        artifact_ids=(
            record.cleanup.evidence_bundle_digest,
            *extra_artifact_ids,
        ),
    )


def evaluate(
    compiled: CompiledExperiment,
    records: list[TrialRecord],
    values: dict[tuple[str, Stage, str], bool],
    *,
    metric_evidence_ids: dict[tuple[str, Stage, str], str] | None = None,
    metric_overrides: dict[tuple[str, Stage, str], MetricEvidenceResult] | None = None,
    attestation_overrides: dict[str, TrialAttestationResult] | None = None,
    cleanup_overrides: dict[str, CleanupVerificationResult] | None = None,
):
    attestations = {record.trial_key: attestation_for(compiled, record) for record in records}
    attestations.update(attestation_overrides or {})
    metrics: dict[tuple[str, Stage, str], MetricEvidenceResult] = {}
    for key, value in values.items():
        record = next(record for record in records if record.trial_key == key[0])
        if isinstance(record.trace.event_for(key[1]), SkippedStageEvent):
            continue
        metrics[key] = metric_evidence(
            compiled,
            record,
            key[1],
            key[2],
            value,
            evidence_id=(metric_evidence_ids or {}).get(key),
        )
    metrics.update(metric_overrides or {})
    cleanups = {record.trial_key: cleanup_evidence(compiled, record) for record in records}
    cleanups.update(cleanup_overrides or {})
    return ExperimentEvaluator().evaluate(
        compiled,
        records,
        MemoryAttestationVerifier(attestations),
        MemoryEvidenceVerifier(metrics),
        MemoryCleanupVerifier(cleanups),
    )


def full_records_and_values(
    compiled: CompiledExperiment,
    *,
    block_effective_target: bool = False,
) -> tuple[list[TrialRecord], dict[tuple[str, Stage, str], bool]]:
    selectors = {cell.key: cell.selector for cell in compiled.cells}
    records = [
        make_record(
            compiled,
            trial.key,
            target_blocks=(
                block_effective_target
                and selectors[trial.cell_key].target == compiled.contract.profile.target.effective
            ),
        )
        for trial in compiled.planned_trials
    ]
    values: dict[tuple[str, Stage, str], bool] = {}
    coverage = {item.obligation_id: item.trial_keys for item in compiled.obligation_coverage}
    metrics = {metric.id: metric for metric in compiled.contract.metrics}
    for obligation_item in compiled.contract.obligations:
        expected = obligation_item.predicate.expected
        assert isinstance(expected, BooleanValue)
        metric_item = metrics[obligation_item.predicate.metric_id]
        for trial_key in coverage[obligation_item.id]:
            values[(trial_key, metric_item.stage, metric_item.id)] = expected.value

    planned = {
        (trial.cell_key, trial.block, trial.replicate): trial.key
        for trial in compiled.planned_trials
    }
    for contrast in compiled.contrasts:
        metric_item = metrics[contrast.metric_id]
        for pair in contrast.pairs:
            for block in compiled.contract.plan.blocks:
                for replicate in range(1, compiled.contract.plan.replicates + 1):
                    reference_key = planned[(pair.reference_cell_key, block, replicate)]
                    comparison_key = planned[(pair.comparison_cell_key, block, replicate)]
                    if contrast.relation.operator == RelationOperator.TRUE_TO_FALSE:
                        reference_value, comparison_value = True, False
                    elif contrast.relation.operator == RelationOperator.FALSE_TO_TRUE:
                        reference_value, comparison_value = False, True
                    else:
                        invariant = (
                            metric_item.id == compiled.contract.profile.benign_outcome_metric_id
                        )
                        reference_value = comparison_value = invariant
                    values[(reference_key, metric_item.stage, metric_item.id)] = reference_value
                    values[(comparison_key, metric_item.stage, metric_item.id)] = comparison_value
    return records, values


def assessment(report, obligation_id: str):
    return next(
        item for item in report.obligation_assessments if item.obligation_id == obligation_id
    )


def add_target_rate_obligation(
    contract: ExperimentContract,
    quantifier: AtLeastRate,
) -> ExperimentContract:
    target_id = contract.profile.primary_target_obligation_id
    original = next(item for item in contract.obligations if item.id == target_id)
    rate_obligation = original.model_copy(
        update={
            "id": "entitlement-rate",
            "quantifier": quantifier,
        }
    )
    return contract.model_copy(update={"obligations": (*contract.obligations, rate_obligation)})


def test_blocking_target_makes_compensator_not_exercised() -> None:
    compiled = compile_experiment(valid_contract())
    records = [
        make_record(compiled, key, target_blocks=True) for key in current_trial_keys(compiled)
    ]
    profile = compiled.contract.profile
    values = {
        (record.trial_key, Stage.TARGET, profile.target_metric_id): False for record in records
    }
    values.update(
        {(record.trial_key, Stage.OUTCOME, profile.outcome_metric_id): False for record in records}
    )

    report = evaluate(compiled, records, values)
    result = assessment(report, profile.primary_compensator_obligation_id)

    assert result.truth == TruthValue.NEITHER
    assert result.exercise == ExerciseState.NOT_EXERCISED
    assert result.not_exercised_count == 2
    assert result.admitted_count == 0


def test_final_blocked_outcome_does_not_mask_target_counterevidence() -> None:
    compiled = compile_experiment(valid_contract())
    records = [make_record(compiled, key) for key in current_trial_keys(compiled)]
    profile = compiled.contract.profile
    values: dict[tuple[str, Stage, str], bool] = {}
    for record in records:
        values[(record.trial_key, Stage.TARGET, profile.target_metric_id)] = True
        values[
            (
                record.trial_key,
                Stage.COMPENSATOR,
                profile.compensator_metric_id,
            )
        ] = True
        values[(record.trial_key, Stage.OUTCOME, profile.outcome_metric_id)] = False

    report = evaluate(compiled, records, values)

    assert not report.design_completeness.presence_complete
    assert assessment(report, profile.primary_target_obligation_id).truth == TruthValue.REFUTED
    assert (
        assessment(report, profile.primary_compensator_obligation_id).truth == TruthValue.SUPPORTED
    )
    assert assessment(report, profile.primary_path_obligation_id).truth == TruthValue.SUPPORTED
    assert report.residual_summary.classification == ResidualClassification.MASKED_TARGET_FAILURE


def test_target_effective_requires_supported_benign_path() -> None:
    compiled = compile_experiment(valid_contract())
    records = [make_record(compiled, key) for key in current_trial_keys(compiled)]
    profile = compiled.contract.profile
    values: dict[tuple[str, Stage, str], bool] = {}
    for record in records:
        values[(record.trial_key, Stage.TARGET, profile.target_metric_id)] = False
        values[(record.trial_key, Stage.OUTCOME, profile.outcome_metric_id)] = False

    report = evaluate(compiled, records, values)

    assert assessment(report, profile.primary_target_obligation_id).truth == TruthValue.SUPPORTED
    assert assessment(report, profile.primary_path_obligation_id).truth == TruthValue.SUPPORTED
    assert report.residual_summary.benign_truth == TruthValue.NEITHER
    assert report.residual_summary.benign_exercise == ExerciseState.UNKNOWN
    assert report.residual_summary.classification == ResidualClassification.UNRESOLVED


@pytest.mark.parametrize(
    ("observed", "expected_truth"),
    [
        (False, TruthValue.NEITHER),
        (True, TruthValue.REFUTED),
    ],
)
def test_all_tested_needs_all_passes_but_one_counterexample_refutes(
    observed: bool,
    expected_truth: TruthValue,
) -> None:
    compiled = compile_experiment(valid_contract())
    key = current_trial_keys(compiled)[0]
    record = make_record(compiled, key)
    profile = compiled.contract.profile

    report = evaluate(
        compiled,
        [record],
        {(key, Stage.TARGET, profile.target_metric_id): observed},
    )
    result = assessment(report, profile.primary_target_obligation_id)

    assert result.truth == expected_truth
    assert result.unresolved_count == 1


@pytest.mark.parametrize(
    ("rate", "observed", "truth", "lower", "upper"),
    [
        ("0.5", False, TruthValue.SUPPORTED, Decimal("0.5"), Decimal("1")),
        ("0.75", False, TruthValue.NEITHER, Decimal("0.5"), Decimal("1")),
        ("0.75", True, TruthValue.REFUTED, Decimal("0"), Decimal("0.5")),
    ],
)
def test_at_least_rate_uses_exact_incomplete_bounds(
    rate: str,
    observed: bool,
    truth: TruthValue,
    lower: Decimal,
    upper: Decimal,
) -> None:
    contract = add_target_rate_obligation(
        valid_contract(),
        AtLeastRate(
            rate=DecimalValue(value=Decimal(rate)),
            min_trials=1,
        ),
    )
    compiled = compile_experiment(contract)
    key = current_trial_keys(compiled)[0]
    record = make_record(compiled, key)
    profile = compiled.contract.profile

    report = evaluate(
        compiled,
        [record],
        {(key, Stage.TARGET, profile.target_metric_id): observed},
    )
    result = assessment(report, "entitlement-rate")

    assert (result.truth, result.lower_bound, result.upper_bound) == (
        truth,
        lower,
        upper,
    )


def test_old_spec_digest_is_locally_rejected_as_unknown_exercise() -> None:
    compiled = compile_experiment(valid_contract())
    key = current_trial_keys(compiled)[0]
    record = make_record(compiled, key).model_copy(update={"spec_digest": digest("old-spec")})

    report = evaluate(compiled, [record], {})
    result = assessment(report, compiled.contract.profile.primary_target_obligation_id)

    assert result.exercise == ExerciseState.UNKNOWN
    assert result.not_exercised_count == 0
    assert not report.design_completeness.protocol_complete
    assert {issue.code for issue in report.design_issues} >= {"planned-trial-binding-mismatch"}


def test_duplicate_key_and_reused_fresh_clone_are_safety_issues() -> None:
    compiled = compile_experiment(valid_contract())
    first_key, second_key = current_trial_keys(compiled)
    first = make_record(compiled, first_key)
    second = make_record(compiled, second_key).model_copy(
        update={
            "clone": make_record(compiled, second_key).clone.model_copy(
                update={"unique_instance_id": first.clone.unique_instance_id}
            )
        }
    )

    report = evaluate(compiled, [first, first, second], {})

    assert "duplicate-trial-key" in {issue.code for issue in report.design_issues}
    assert "clone-instance-reuse" in {issue.code for issue in report.safety_issues}
    assert not report.design_completeness.protocol_complete


def test_contrast_uses_matched_admissions_and_preserves_pair_values() -> None:
    compiled = compile_experiment(valid_contract())
    contrast = next(item for item in compiled.contrasts if item.id.value == "target-attack-effect")
    pair = contrast.pairs[0]
    planned = {
        (trial.cell_key, trial.block, trial.replicate): trial.key
        for trial in compiled.planned_trials
    }
    records: list[TrialRecord] = []
    values: dict[tuple[str, Stage, str], bool] = {}
    for replicate in range(1, compiled.contract.plan.replicates + 1):
        reference_key = planned[(pair.reference_cell_key, "fresh-clone-a", replicate)]
        comparison_key = planned[(pair.comparison_cell_key, "fresh-clone-a", replicate)]
        reference = make_record(compiled, reference_key)
        comparison = make_record(
            compiled,
            comparison_key,
            action_label=("other-action" if replicate == 2 else None),
        )
        records.extend((reference, comparison))
        values[(reference_key, Stage.TARGET, contrast.metric_id)] = True
        values[(comparison_key, Stage.TARGET, contrast.metric_id)] = False

    report = evaluate(compiled, records, values)
    result = next(
        item for item in report.contrast_assessments if item.contrast_id == contrast.id.value
    )

    assert result.truth == TruthValue.NEITHER
    assert result.supported_pair_count == 1
    assert result.unresolved_pair_count == 1
    assert result.pairs[0].reference_value == boolean(True)
    assert result.pairs[0].comparison_value == boolean(False)
    assert result.pairs[1].unresolved_reason == "comparison: action-digest-mismatch"


def test_rebound_metric_evidence_id_cannot_support_contrast() -> None:
    compiled = compile_experiment(valid_contract())
    contrast = next(item for item in compiled.contrasts if item.id.value == "target-attack-effect")
    cells = {
        contrast.pairs[0].reference_cell_key,
        contrast.pairs[0].comparison_cell_key,
    }
    records = [
        make_record(compiled, trial.key)
        for trial in compiled.planned_trials
        if trial.cell_key in cells
    ]
    values: dict[tuple[str, Stage, str], bool] = {}
    for record in records:
        values[(record.trial_key, Stage.TARGET, contrast.metric_id)] = (
            "target=ineffective" in record.cell_key
        )
    shared_id = digest("rebound-metric-evidence")

    report = evaluate(
        compiled,
        records,
        values,
        metric_evidence_ids={key: shared_id for key in values},
    )
    result = next(
        item for item in report.contrast_assessments if item.contrast_id == contrast.id.value
    )

    assert result.truth != TruthValue.SUPPORTED
    assert result.supported_pair_count == 0
    assert report.residual_summary.classification != (ResidualClassification.TARGET_EFFECTIVE)
    assert "metric-evidence-id-reuse" in {issue.code for issue in report.evidence_issues}


def test_metric_admission_must_echo_exact_binding() -> None:
    compiled = compile_experiment(valid_contract())
    key = current_trial_keys(compiled)[0]
    record = make_record(compiled, key)
    profile = compiled.contract.profile
    coordinate = (key, Stage.TARGET, profile.target_metric_id)
    admission = metric_evidence(
        compiled,
        record,
        Stage.TARGET,
        profile.target_metric_id,
        False,
    )
    admission = admission.model_copy(
        update={"binding": admission.binding.model_copy(update={"event_id": "another-event"})}
    )

    report = evaluate(
        compiled,
        [record],
        {},
        metric_overrides={coordinate: admission},
    )

    assert "metric-evidence-binding-mismatch" in {issue.code for issue in report.evidence_issues}
    assert (
        assessment(
            report,
            profile.primary_target_obligation_id,
        ).truth
        == TruthValue.NEITHER
    )


def test_cross_spec_trial_attestation_replay_is_rejected() -> None:
    compiled = compile_experiment(valid_contract())
    foreign_contract = compiled.contract.model_copy(
        update={
            "obligations": (
                *compiled.contract.obligations,
                compiled.contract.obligations[0].model_copy(update={"id": "historic-target"}),
            )
        }
    )
    foreign = compile_experiment(foreign_contract)
    planned = {
        (trial.cell_key, trial.block, trial.replicate): trial
        for trial in compiled.planned_trials
    }
    foreign_planned = {
        (trial.cell_key, trial.block, trial.replicate): trial
        for trial in foreign.planned_trials
    }
    coordinate = next(
        coordinate
        for coordinate, trial in planned.items()
        if trial.ordinal == foreign_planned[coordinate].ordinal
    )
    trial = planned[coordinate]
    foreign_trial = foreign_planned[coordinate]
    foreign_record = make_record(foreign, foreign_trial.key)
    stale_attestation = attestation_for(foreign, foreign_record)

    records, values = full_records_and_values(compiled)
    record_index = next(
        index for index, record in enumerate(records) if record.trial_key == trial.key
    )
    target_record = records[record_index]
    records[record_index] = target_record.model_copy(
        update={
            "clone": target_record.clone.model_copy(
                update={
                    "attestation_bundle_digest": (
                        foreign_record.clone.attestation_bundle_digest
                    )
                }
            )
        }
    )

    report = evaluate(
        compiled,
        records,
        values,
        attestation_overrides={trial.key: stale_attestation},
    )

    assert "trial-attestation-binding-mismatch" in {
        issue.code for issue in report.evidence_issues
    }
    assert not report.design_completeness.protocol_complete
    assert report.residual_summary.classification != ResidualClassification.TARGET_EFFECTIVE


def test_reused_cross_trial_lineage_cannot_support_contrast() -> None:
    compiled = compile_experiment(valid_contract())
    contrast = next(item for item in compiled.contrasts if item.id.value == "target-attack-effect")
    cells = {
        contrast.pairs[0].reference_cell_key,
        contrast.pairs[0].comparison_cell_key,
    }
    records: list[TrialRecord] = []
    values: dict[tuple[str, Stage, str], bool] = {}
    for planned in compiled.planned_trials:
        if planned.cell_key not in cells:
            continue
        record = make_record(compiled, planned.key)

        def shared_event(
            event: ExecutedStageEvent,
        ) -> ExecutedStageEvent:
            return event.model_copy(
                update={
                    "event_id": f"shared-{event.stage.value}",
                    "evidence_bundle_digest": digest(f"shared-{event.stage.value}-bundle"),
                }
            )

        trace = record.trace.model_copy(
            update={
                "trace_id": "shared-trace",
                "input": shared_event(record.trace.input),
                "target": shared_event(record.trace.target),
                "compensator": shared_event(record.trace.compensator),
                "outcome": shared_event(record.trace.outcome),
            }
        )
        record = record.model_copy(update={"trace": trace})
        records.append(record)
        values[(record.trial_key, Stage.TARGET, contrast.metric_id)] = (
            "target=ineffective" in record.cell_key
        )

    report = evaluate(compiled, records, values)
    result = next(
        item for item in report.contrast_assessments if item.contrast_id == contrast.id.value
    )

    assert result.truth != TruthValue.SUPPORTED
    assert {
        "trace-id-reuse",
        "event-id-reuse",
        "stage-evidence-bundle-reuse",
    }.issubset({issue.code for issue in report.safety_issues})
    assert "metric-bundle-value-conflict" in {issue.code for issue in report.evidence_issues}


def test_target_effective_requires_complete_protocol_and_contrasts() -> None:
    compiled = compile_experiment(valid_contract())
    records, values = full_records_and_values(compiled)

    complete = evaluate(compiled, records, values)

    assert complete.design_completeness.protocol_complete
    assert complete.residual_summary.classification == ResidualClassification.TARGET_EFFECTIVE

    target_contrast = next(
        item for item in compiled.contrasts if item.id.value == "target-attack-effect"
    )
    target_pair = target_contrast.pairs[0]
    planned = {
        (trial.cell_key, trial.block, trial.replicate): trial.key
        for trial in compiled.planned_trials
    }
    replay_coordinates = {
        (
            planned[
                (
                    cell_key,
                    compiled.contract.plan.blocks[0],
                    1,
                )
            ],
            Stage.TARGET,
            target_contrast.metric_id,
        )
        for cell_key in (
            target_pair.reference_cell_key,
            target_pair.comparison_cell_key,
        )
    }
    replayed = evaluate(
        compiled,
        records,
        values,
        metric_evidence_ids={
            coordinate: digest("full-matrix-rebound") for coordinate in replay_coordinates
        },
    )
    assert replayed.residual_summary.classification != ResidualClassification.TARGET_EFFECTIVE
    assert "metric-evidence-id-reuse" in {issue.code for issue in replayed.evidence_issues}

    primary_ids = {
        compiled.contract.profile.primary_target_obligation_id,
        compiled.contract.profile.primary_compensator_obligation_id,
        compiled.contract.profile.primary_path_obligation_id,
        compiled.contract.profile.primary_benign_obligation_id,
    }
    coverage = {item.obligation_id: set(item.trial_keys) for item in compiled.obligation_coverage}
    kept_keys = set().union(*(coverage[item] for item in primary_ids))
    partial_records = [record for record in records if record.trial_key in kept_keys]
    partial_values = {key: value for key, value in values.items() if key[0] in kept_keys}
    incomplete = evaluate(compiled, partial_records, partial_values)

    assert not incomplete.design_completeness.protocol_complete
    assert (
        assessment(
            incomplete,
            compiled.contract.profile.primary_target_obligation_id,
        ).truth
        == TruthValue.SUPPORTED
    )
    assert (
        assessment(
            incomplete,
            compiled.contract.profile.primary_path_obligation_id,
        ).truth
        == TruthValue.SUPPORTED
    )
    assert (
        assessment(
            incomplete,
            compiled.contract.profile.primary_benign_obligation_id,
        ).truth
        == TruthValue.SUPPORTED
    )
    assert incomplete.residual_summary.classification == ResidualClassification.UNRESOLVED


def test_valid_causal_skip_is_complete_exercise_evidence() -> None:
    compiled = compile_experiment(effective_current_contract())
    records, values = full_records_and_values(
        compiled,
        block_effective_target=True,
    )

    report = evaluate(compiled, records, values)
    compensator = assessment(
        report,
        compiled.contract.profile.primary_compensator_obligation_id,
    )

    assert report.design_completeness.evidence_complete
    assert report.design_completeness.protocol_complete
    assert compensator.exercise == ExerciseState.NOT_EXERCISED
    assert compensator.truth == TruthValue.NEITHER
    assert report.residual_summary.classification == ResidualClassification.TARGET_EFFECTIVE


def test_benign_envelope_rejects_equal_but_broken_causal_arms() -> None:
    compiled = compile_experiment(valid_contract())
    records, values = full_records_and_values(compiled)
    target_benign = next(
        item for item in compiled.contrasts if item.id.value == "target-benign-invariance"
    )
    compensator_benign = next(
        item for item in compiled.contrasts if item.id.value == "compensator-benign-invariance"
    )
    planned = {
        (trial.cell_key, trial.block, trial.replicate): trial.key
        for trial in compiled.planned_trials
    }
    broken_cells = {
        cell_key
        for contrast in (target_benign, compensator_benign)
        for pair in contrast.pairs
        for cell_key in (pair.reference_cell_key, pair.comparison_cell_key)
    }
    for cell_key in broken_cells:
        for block in compiled.contract.plan.blocks:
            for replicate in range(1, compiled.contract.plan.replicates + 1):
                values[
                    (
                        planned[(cell_key, block, replicate)],
                        Stage.OUTCOME,
                        target_benign.metric_id,
                    )
                ] = False

    report = evaluate(compiled, records, values)
    contrast_truth = {item.contrast_id: item.truth for item in report.contrast_assessments}

    assert report.design_completeness.protocol_complete
    assert (
        assessment(
            report,
            compiled.contract.profile.primary_benign_obligation_id,
        ).truth
        == TruthValue.REFUTED
    )
    assert contrast_truth["target-benign-invariance"] == TruthValue.SUPPORTED
    assert contrast_truth["compensator-benign-invariance"] == TruthValue.SUPPORTED
    assert report.residual_summary.classification == ResidualClassification.UNRESOLVED


def test_cleanup_failure_does_not_erase_local_point_inference() -> None:
    compiled = compile_experiment(valid_contract())
    records, values = full_records_and_values(compiled)
    cleanup_overrides = {
        record.trial_key: cleanup_evidence(
            compiled,
            record,
            state=CleanupState.FAILED,
        )
        for record in records
    }

    report = evaluate(
        compiled,
        records,
        values,
        cleanup_overrides=cleanup_overrides,
    )

    assert (
        assessment(
            report,
            compiled.contract.profile.primary_target_obligation_id,
        ).truth
        == TruthValue.SUPPORTED
    )
    assert report.design_completeness.evidence_complete
    assert not report.design_completeness.cleanup_complete
    assert not report.design_completeness.protocol_complete
    assert not report.design_completeness.complete


def test_cleanup_reuse_and_pre_outcome_time_are_rejected() -> None:
    compiled = compile_experiment(valid_contract())
    first_key, second_key = current_trial_keys(compiled)
    records = [
        make_record(compiled, first_key),
        make_record(compiled, second_key),
    ]
    records[1] = records[1].model_copy(update={"cleanup": records[0].cleanup})
    shared_evidence_id = digest("shared-cleanup-evidence")
    cleanup_overrides = {
        records[0].trial_key: cleanup_evidence(
            compiled,
            records[0],
            observed_at=records[0].trace.outcome.ended_at,
            evidence_id=shared_evidence_id,
        ),
        records[1].trial_key: cleanup_evidence(
            compiled,
            records[1],
            evidence_id=shared_evidence_id,
        ),
    }
    profile = compiled.contract.profile
    values = {
        (record.trial_key, Stage.TARGET, profile.target_metric_id): False for record in records
    }

    report = evaluate(
        compiled,
        records,
        values,
        cleanup_overrides=cleanup_overrides,
    )

    codes = {issue.code for issue in report.safety_issues}
    assert {
        "cleanup-time-invalid",
        "cleanup-bundle-reuse",
        "cleanup-evidence-reuse",
    } <= codes
    assert not report.design_completeness.cleanup_complete


def test_attested_scope_and_execution_order_are_independent_gates() -> None:
    compiled = compile_experiment(valid_contract())
    key = current_trial_keys(compiled)[0]
    record = make_record(compiled, key)
    admission = attestation_for(compiled, record).model_copy(
        update={
            "observed_build_digest": digest("wrong-build"),
            "executed_ordinal": 1
            if next(trial.ordinal for trial in compiled.planned_trials if trial.key == key) != 1
            else 2,
        }
    )

    report = evaluate(
        compiled,
        [record],
        {},
        attestation_overrides={key: admission},
    )

    codes = {issue.code for issue in (*report.design_issues, *report.evidence_issues)}
    assert {"attested-scope-mismatch", "attested-order-mismatch"} <= codes
    assert (
        assessment(
            report,
            compiled.contract.profile.primary_target_obligation_id,
        ).exercise
        == ExerciseState.UNKNOWN
    )


def test_zero_duration_executed_event_is_rejected() -> None:
    compiled = compile_experiment(valid_contract())
    record = make_record(compiled, current_trial_keys(compiled)[0])
    event = record.trace.input

    with pytest.raises(ValidationError, match="positive duration"):
        ExecutedStageEvent(
            event_id=event.event_id,
            evidence_bundle_digest=event.evidence_bundle_digest,
            stage=event.stage,
            started_at=event.started_at,
            ended_at=event.started_at,
        )


def test_trial_record_cannot_contain_metric_or_cleanup_outcome() -> None:
    compiled = compile_experiment(valid_contract())
    record = make_record(compiled, current_trial_keys(compiled)[0])
    payload = record.model_dump(mode="python")
    payload["metric_value"] = BooleanValue(value=True)

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        TrialRecord.model_validate(payload, strict=True)

    cleanup_payload = record.cleanup.model_dump(mode="python")
    cleanup_payload["state"] = CleanupState.VERIFIED
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        CleanupReference.model_validate(cleanup_payload, strict=True)
