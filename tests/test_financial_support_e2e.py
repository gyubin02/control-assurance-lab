from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pytest import MonkeyPatch

from assurance_lab.contract import (
    EvidencePolicyRef,
    EvidenceWindow,
    ExperimentScope,
    Stage,
    TrialPlan,
    compile_experiment,
)
from assurance_lab.evaluation import (
    EvaluationReport,
    ExperimentEvaluator,
    ObligationAssessment,
    ResidualClassification,
    TruthValue,
)
from assurance_lab.evidence.bundle import (
    BundleStatus,
    ExperimentRef,
    verify_bundle,
)
from assurance_lab.evidence.canonical import (
    canonical_json_bytes,
    canonical_jsonl_bytes,
    strict_json_loads,
    strict_jsonl_loads,
)
from assurance_lab.evidence.writer import (
    BundleMetadata,
    PayloadFile,
    write_bundle,
)
from assurance_lab.scenarios import financial_support
from assurance_lab.scenarios.financial_data import DatasetProfile, generate_dataset
from assurance_lab.scenarios.financial_support_contract import (
    BENIGN,
    SCENARIO_ID,
    build_financial_support_contract,
)
from assurance_lab.scenarios.financial_support_e2e import (
    FinancialSupportBundleError,
    FinancialSupportBundleRepository,
    FinancialSupportExperimentRunner,
)


def _digest(fill: str) -> str:
    return f"sha256:{fill * 64}"


class _StepClock:
    def __init__(self, start: datetime) -> None:
        self._next = start

    def __call__(self) -> datetime:
        result = self._next
        self._next += timedelta(milliseconds=1)
        return result


def _bundle_timestamp(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


def _rewrite_bundle(
    source: Path,
    destination: Path,
    *,
    replacements: dict[str, bytes],
    experiment: ExperimentRef | None = None,
) -> None:
    verified = verify_bundle(source)
    assert verified.status == BundleStatus.INTEGRITY_VERIFIED
    assert verified.manifest is not None
    manifest = verified.manifest
    payloads = tuple(
        PayloadFile(
            path=descriptor.path,
            content=replacements.get(
                descriptor.path,
                source.joinpath(*descriptor.path.split("/")).read_bytes(),
            ),
            media_type=descriptor.media_type,
            role=descriptor.role,
            sensitivity=descriptor.sensitivity,
            required_for=tuple(descriptor.required_for),
        )
        for descriptor in manifest.files
    )
    written = write_bundle(
        destination,
        metadata=BundleMetadata(
            created_at=_bundle_timestamp(manifest.created_at),
            as_of=_bundle_timestamp(manifest.as_of),
            experiment=experiment or manifest.experiment,
            evaluation=manifest.evaluation,
            parent_bundles=tuple(manifest.parent_bundles),
        ),
        payloads=payloads,
    )
    assert written.status == BundleStatus.INTEGRITY_VERIFIED


def _assessment(
    report: EvaluationReport,
    obligation_id: str,
) -> ObligationAssessment:
    return next(
        item for item in report.obligation_assessments if item.obligation_id == obligation_id
    )


def test_sqlite_runner_round_trips_raw_bundle_evidence_into_masked_inference(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    def forbidden_oracle(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("the executable evidence path must not call the pure oracle")

    monkeypatch.setattr(
        financial_support,
        "evaluate_support_export",
        forbidden_oracle,
    )
    dataset = generate_dataset(seed=2907, profile=DatasetProfile.DEFAULT)
    start = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)
    with pytest.raises(ValueError, match="simulated time basis"):
        FinancialSupportExperimentRunner(
            dataset,
            clock=_StepClock(start),
            time_basis="wall-clock-observation",
        )
    with pytest.raises(ValueError, match="simulated time basis"):
        FinancialSupportExperimentRunner(
            dataset,
            time_basis="simulated",
        )
    runner = FinancialSupportExperimentRunner(
        dataset,
        clock=_StepClock(start + timedelta(seconds=1)),
        time_basis="simulated",
    )
    scope = ExperimentScope(
        scenario_id=SCENARIO_ID,
        build_digest=runner.build_digest,
        dataset_digest=runner.dataset_digest,
        fixture_digest=runner.fixture_digest,
        assessment_as_of=start + timedelta(minutes=30),
        evidence_window=EvidenceWindow(
            start=start,
            end=start + timedelta(hours=1),
        ),
        evidence_policy=EvidencePolicyRef(
            id="financial-support-bundle-v1",
            version="1.0.0",
            digest=_digest("7"),
        ),
    )
    compiled = compile_experiment(
        build_financial_support_contract(
            scope=scope,
            plan=TrialPlan(
                blocks=("sqlite-fresh-clone",),
                replicates=1,
                order_seed="financial-support-e2e-seed",
            ),
        )
    )
    bundle_root = tmp_path / "financial-support-evidence"

    written = runner.run(compiled, bundle_root)
    assert written.status == BundleStatus.INTEGRITY_VERIFIED
    assert len(compiled.planned_trials) == 16

    repository = FinancialSupportBundleRepository(bundle_root)
    assert len(repository.trial_records) == 16
    assert repository.time_basis == "simulated"
    assert repository.compiled_experiment.spec_digest == compiled.spec_digest
    assert repository.compiled_experiment.canonical_spec == compiled.canonical_spec
    assert repository.compiled_experiment.planned_trials == compiled.planned_trials
    assert repository.dataset_digest == compiled.contract.scope.dataset_digest
    assert repository.fixture_digest == compiled.contract.scope.fixture_digest
    report = ExperimentEvaluator().evaluate(
        repository.compiled_experiment,
        repository.trial_records,
        repository,
        repository,
        repository,
    )

    profile = compiled.contract.profile
    assert report.design_completeness.protocol_complete
    assert not report.design_issues
    assert not report.evidence_issues
    assert not report.safety_issues
    assert _assessment(report, profile.primary_target_obligation_id).truth == TruthValue.REFUTED
    assert (
        _assessment(report, profile.primary_compensator_obligation_id).truth == TruthValue.SUPPORTED
    )
    assert _assessment(report, profile.primary_path_obligation_id).truth == TruthValue.SUPPORTED
    assert _assessment(report, profile.primary_benign_obligation_id).truth == TruthValue.SUPPORTED
    assert all(contrast.truth == TruthValue.SUPPORTED for contrast in report.contrast_assessments)
    assert report.residual_summary.classification == ResidualClassification.MASKED_TARGET_FAILURE

    selectors = {cell.key: cell.selector for cell in compiled.cells}
    current_trial = next(
        trial
        for trial in compiled.planned_trials
        if selectors[trial.cell_key] == compiled.current_selector
    )
    assert (
        repository.stage_artifact(current_trial.key, Stage.TARGET).value(
            "out_of_scope_records_selected"
        )
        == 10
    )
    assert repository.stage_artifact(current_trial.key, Stage.TARGET).time_basis == "simulated"
    assert (
        repository.stage_artifact(current_trial.key, Stage.OUTCOME).value(
            "out_of_scope_records_delivered"
        )
        == 0
    )
    benign_trials = tuple(
        trial for trial in compiled.planned_trials if selectors[trial.cell_key].input == BENIGN
    )
    assert len(benign_trials) == 8
    assert {
        repository.stage_artifact(trial.key, Stage.OUTCOME).value("assigned_case_records_delivered")
        for trial in benign_trials
    } == {1}

    metric_free_records = (bundle_root / "records" / "trial-records.jsonl").read_bytes()
    assert b"out_of_scope_records_selected" not in metric_free_records
    assert b"out_of_scope_records_delivered" not in metric_free_records
    assert b"assigned_case_records_delivered" not in metric_free_records

    foreign_plan = compiled.contract.plan.model_copy(
        update={"order_seed": "cross-spec-replay-seed"}
    )
    foreign_compiled = compile_experiment(
        compiled.contract.model_copy(update={"plan": foreign_plan})
    )
    cross_spec_root = tmp_path / "cross-spec-replay"
    _rewrite_bundle(
        bundle_root,
        cross_spec_root,
        replacements={"spec/experiment.json": foreign_compiled.canonical_spec.encode("utf-8")},
        experiment=ExperimentRef(
            id=foreign_compiled.contract.id,
            spec_version=foreign_compiled.contract.version,
            spec_digest=foreign_compiled.spec_digest,
        ),
    )
    with pytest.raises(
        FinancialSupportBundleError,
        match="bundled compiler plan",
    ):
        FinancialSupportBundleRepository(cross_spec_root)

    replayed_dataset = generate_dataset(
        seed=2908,
        profile=DatasetProfile.DEFAULT,
    ).manifest()
    fixture_path = bundle_root / "spec" / "fixture-manifest.json"
    fixture_value = strict_json_loads(fixture_path.read_bytes())
    assert isinstance(fixture_value, dict)
    fixture_value["dataset"] = replayed_dataset
    dataset_replay_root = tmp_path / "dataset-replay"
    _rewrite_bundle(
        bundle_root,
        dataset_replay_root,
        replacements={
            "spec/dataset-manifest.json": canonical_json_bytes(replayed_dataset),
            "spec/fixture-manifest.json": canonical_json_bytes(fixture_value),
        },
    )
    with pytest.raises(
        FinancialSupportBundleError,
        match="does not match the bundled contract scope",
    ):
        FinancialSupportBundleRepository(dataset_replay_root)

    stage_path = bundle_root / "records" / "stage-events.jsonl"
    stage_values = strict_jsonl_loads(
        stage_path.read_bytes(),
        require_sorted_ids=True,
    )
    stage_values[0]["time_basis"] = "wall-clock-observation"
    mixed_time_root = tmp_path / "mixed-time-basis"
    _rewrite_bundle(
        bundle_root,
        mixed_time_root,
        replacements={"records/stage-events.jsonl": canonical_jsonl_bytes(stage_values)},
    )
    with pytest.raises(
        FinancialSupportBundleError,
        match="must use one time basis",
    ):
        FinancialSupportBundleRepository(mixed_time_root)
