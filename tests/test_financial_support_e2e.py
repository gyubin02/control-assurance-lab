from __future__ import annotations

import hashlib
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
    EvaluationRef,
    EvaluatorRef,
    ExperimentRef,
    Sensitivity,
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
from assurance_lab.scenarios import (
    financial_support_e2e as financial_support_e2e_module,
)
from assurance_lab.scenarios.financial_data import DatasetProfile, generate_dataset
from assurance_lab.scenarios.financial_support_contract import (
    ATTACK,
    ATTACK_ACTION_DIGEST,
    BENIGN,
    BENIGN_ACTION_DIGEST,
    SCENARIO_ID,
    action_descriptor,
    build_financial_support_contract,
)
from assurance_lab.scenarios.financial_support_e2e import (
    FINANCIAL_SUPPORT_EVIDENCE_POLICY_DIGEST,
    FinancialSupportBundleError,
    FinancialSupportBundleRepository,
    FinancialSupportExperimentRunner,
)
from assurance_lab.scenarios.financial_support_runtime import runtime_dataset_snapshot


def _artifact_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _object(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return value


def _objects(value: object) -> list[dict[str, object]]:
    assert isinstance(value, list)
    assert all(isinstance(item, dict) for item in value)
    return value


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
    evaluation: EvaluationRef | None = None,
    created_at: datetime | None = None,
    as_of: datetime | None = None,
    parent_bundles: tuple[str, ...] | None = None,
    role_overrides: dict[str, str] | None = None,
    required_for_overrides: dict[str, tuple[str, ...]] | None = None,
    sensitivity_overrides: dict[str, Sensitivity] | None = None,
) -> None:
    verified = verify_bundle(source)
    assert verified.status == BundleStatus.INTEGRITY_VERIFIED
    assert verified.manifest is not None
    manifest = verified.manifest
    role_overrides = role_overrides or {}
    required_for_overrides = required_for_overrides or {}
    sensitivity_overrides = sensitivity_overrides or {}
    payloads = tuple(
        PayloadFile(
            path=descriptor.path,
            content=replacements.get(
                descriptor.path,
                source.joinpath(*descriptor.path.split("/")).read_bytes(),
            ),
            media_type=descriptor.media_type,
            role=role_overrides.get(descriptor.path, descriptor.role),
            sensitivity=sensitivity_overrides.get(
                descriptor.path,
                descriptor.sensitivity,
            ),
            required_for=required_for_overrides.get(
                descriptor.path,
                tuple(descriptor.required_for),
            ),
        )
        for descriptor in manifest.files
    )
    written = write_bundle(
        destination,
        metadata=BundleMetadata(
            created_at=created_at or _bundle_timestamp(manifest.created_at),
            as_of=as_of or _bundle_timestamp(manifest.as_of),
            experiment=experiment or manifest.experiment,
            evaluation=evaluation or manifest.evaluation,
            parent_bundles=(
                parent_bundles
                if parent_bundles is not None
                else tuple(manifest.parent_bundles)
            ),
        ),
        payloads=payloads,
    )
    assert written.status == BundleStatus.INTEGRITY_VERIFIED


def _rewrite_coordinated_runtime_claim(
    source: Path,
    destination: Path,
    *,
    tamper: str,
) -> None:
    paths = {
        "runtime": source / "records" / "runtime-observations.jsonl",
        "stages": source / "records" / "stage-events.jsonl",
        "attestations": source / "artifacts" / "trial-attestations.jsonl",
        "cleanups": source / "artifacts" / "cleanup-observations.jsonl",
        "trials": source / "records" / "trial-records.jsonl",
    }
    values = {
        name: strict_jsonl_loads(path.read_bytes(), require_sorted_ids=True)
        for name, path in paths.items()
    }
    runtime_values = _objects(values["runtime"])
    target = runtime_values[0]
    trial_key = target["trial_key"]
    replacement_clone: str | None = None
    if tamper == "principal-role":
        _object(_objects(target["principal_rows"])[0])["role"] = "administrator"
    elif tamper == "clone":
        replacement_clone = "sqlite-clone-coordinated-forgery"
        resource = _object(target["resource_identity"])
        resource["requested_clone_nonce"] = replacement_clone
        resource["observed_clone_nonce"] = replacement_clone
        generation = int(str(resource["observed_generation"]))
        runtime_instance = f"{replacement_clone}:generation-{generation}"
        resource["observed_runtime_instance_id"] = runtime_instance
        redeploy = _object(target["redeploy_operation"])
        redeploy["before_runtime_instance_id"] = f"{replacement_clone}:generation-1"
        redeploy["after_runtime_instance_id"] = runtime_instance
    else:
        raise AssertionError(f"unknown coordinated tamper: {tamper}")

    runtime_digest = _artifact_digest(target)
    stage_digests: dict[str, str] = {}
    for stage in _objects(values["stages"]):
        if stage["trial_key"] == trial_key:
            stage["runtime_observation_digest"] = runtime_digest
            stage_digests[str(stage["event_id"])] = _artifact_digest(stage)

    attestation = next(
        item
        for item in _objects(values["attestations"])
        if item["trial_key"] == trial_key
    )
    attestation["runtime_observation_digest"] = runtime_digest
    if replacement_clone is not None:
        attestation["clone_unique_instance_id"] = replacement_clone
    attestation_digest = _artifact_digest(attestation)

    cleanup = next(
        item
        for item in _objects(values["cleanups"])
        if item["trial_key"] == trial_key
    )
    cleanup["runtime_observation_digest"] = runtime_digest
    if replacement_clone is not None:
        cleanup["clone_unique_instance_id"] = replacement_clone
        cleanup["runtime_instance_id"] = _object(target["resource_identity"])[
            "observed_runtime_instance_id"
        ]
    cleanup_digest = _artifact_digest(cleanup)

    stored = next(
        item
        for item in _objects(values["trials"])
        if _object(item["record"])["trial_key"] == trial_key
    )
    record = _object(stored["record"])
    clone = _object(record["clone"])
    clone["attestation_bundle_digest"] = attestation_digest
    if replacement_clone is not None:
        clone["unique_instance_id"] = replacement_clone
    _object(record["cleanup"])["evidence_bundle_digest"] = cleanup_digest
    trace = _object(record["trace"])
    for stage_name in ("input", "target", "compensator", "outcome"):
        event = _object(trace[stage_name])
        if event.get("status") == "executed":
            event["evidence_bundle_digest"] = stage_digests[str(event["event_id"])]

    _rewrite_bundle(
        source,
        destination,
        replacements={
            "records/runtime-observations.jsonl": canonical_jsonl_bytes(
                runtime_values
            ),
            "records/stage-events.jsonl": canonical_jsonl_bytes(
                _objects(values["stages"])
            ),
            "artifacts/trial-attestations.jsonl": canonical_jsonl_bytes(
                _objects(values["attestations"])
            ),
            "artifacts/cleanup-observations.jsonl": canonical_jsonl_bytes(
                _objects(values["cleanups"])
            ),
            "records/trial-records.jsonl": canonical_jsonl_bytes(
                _objects(values["trials"])
            ),
        },
    )


def _assessment(
    report: EvaluationReport,
    obligation_id: str,
) -> ObligationAssessment:
    return next(
        item for item in report.obligation_assessments if item.obligation_id == obligation_id
    )


@pytest.mark.parametrize(
    "omitted_module",
    (
        "assurance_lab.scenarios.financial_support_runtime",
        "assurance_lab.scenarios.financial_support",
    ),
)
def test_source_allowlist_cannot_omit_a_direct_or_transitive_local_dependency(
    monkeypatch: MonkeyPatch,
    omitted_module: str,
) -> None:
    monkeypatch.setattr(
        financial_support_e2e_module,
        "_SOURCE_SET_MODULES",
        tuple(
            module
            for module in financial_support_e2e_module._SOURCE_SET_MODULES
            if module != omitted_module
        ),
    )

    with pytest.raises(RuntimeError, match="source allowlist") as caught:
        financial_support_e2e_module._source_set_descriptor()
    assert f"missing=['{omitted_module}']" in str(caught.value)


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
            time_basis="wall-clock-observation",  # type: ignore[arg-type]
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
            digest=FINANCIAL_SUPPORT_EVIDENCE_POLICY_DIGEST,
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
    verified = verify_bundle(bundle_root)
    assert verified.manifest is not None
    assert verified.manifest.created_at == "2026-07-28T12:30:00.000000Z"
    assert verified.manifest.as_of == verified.manifest.created_at
    assert not verified.manifest.parent_bundles
    assert {
        descriptor.path for descriptor in verified.manifest.files
    } == {
        "artifacts/cleanup-observations.jsonl",
        "artifacts/trial-attestations.jsonl",
        "records/runtime-observations.jsonl",
        "records/stage-events.jsonl",
        "records/trial-records.jsonl",
        "spec/dataset-manifest.json",
        "spec/experiment.json",
        "spec/fixture-manifest.json",
        "spec/runtime-dataset.json",
        "spec/runtime-source-set.json",
    }

    source_set = strict_json_loads(
        (bundle_root / "spec" / "runtime-source-set.json").read_bytes()
    )
    assert isinstance(source_set, dict)
    assert source_set["claim_boundary"] == (
        "integrity-only: identifies the statically imported local Python "
        "dependency closure; does not authenticate author, origin, the "
        "Python runtime, standard library, or third-party packages"
    )
    assert source_set["dependency_resolver"] == (
        "python-ast-local-import-closure/v1"
    )
    assert source_set["root_modules"] == [
        "assurance_lab.scenarios.financial_support_e2e"
    ]
    source_files = source_set["files"]
    assert isinstance(source_files, list)
    assert len(source_files) == 13
    assert {item["path"] for item in source_files if isinstance(item, dict)} == {
        "assurance_lab/__init__.py",
        "assurance_lab/contract.py",
        "assurance_lab/evaluation.py",
        "assurance_lab/evidence/__init__.py",
        "assurance_lab/evidence/bundle.py",
        "assurance_lab/evidence/canonical.py",
        "assurance_lab/evidence/writer.py",
        "assurance_lab/scenarios/__init__.py",
        "assurance_lab/scenarios/financial_data.py",
        "assurance_lab/scenarios/financial_support.py",
        "assurance_lab/scenarios/financial_support_contract.py",
        "assurance_lab/scenarios/financial_support_e2e.py",
        "assurance_lab/scenarios/financial_support_runtime.py",
    }
    assert {item["module"] for item in source_files if isinstance(item, dict)} == set(
        financial_support_e2e_module._SOURCE_SET_MODULES
    )
    support_source = next(
        item
        for item in source_files
        if isinstance(item, dict)
        and item["module"] == "assurance_lab.scenarios.financial_support"
    )
    assert financial_support.__file__ is not None
    support_source_bytes = Path(financial_support.__file__).read_bytes()
    assert support_source["size"] == len(support_source_bytes)
    assert support_source["sha256"] == (
        "sha256:" + hashlib.sha256(support_source_bytes).hexdigest()
    )
    assert compiled.contract.scope.build_digest == _artifact_digest(source_set)

    runtime_dataset_value = strict_json_loads(
        (bundle_root / "spec" / "runtime-dataset.json").read_bytes()
    )
    assert runtime_dataset_value == runtime_dataset_snapshot(dataset)
    runtime_values = strict_jsonl_loads(
        (bundle_root / "records" / "runtime-observations.jsonl").read_bytes(),
        require_sorted_ids=True,
    )
    assert len(runtime_values) == len(compiled.planned_trials) == 16
    assert len(
        {
            item["resource_identity"]["observed_clone_nonce"]
            for item in runtime_values
        }
    ) == 16
    assert all(
        item["resource_identity"]["requested_clone_nonce"]
        == item["resource_identity"]["observed_clone_nonce"]
        and item["resource_identity"]["requested_runner_resource_id"]
        == item["resource_identity"]["observed_runner_resource_id"]
        for item in runtime_values
    )
    cleanup_values = strict_jsonl_loads(
        (bundle_root / "artifacts" / "cleanup-observations.jsonl").read_bytes(),
        require_sorted_ids=True,
    )
    assert len(cleanup_values) == 16
    runtime_by_trial = {item["trial_key"]: item for item in runtime_values}
    assert all(
        item["probe_operation"] == "select-runtime-identity-after-close"
        and item["probe_error_type"] == "sqlite3.ProgrammingError"
        and item["closed_handle_rejected_operation"] is True
        and item["runtime_instance_id"]
        == runtime_by_trial[item["trial_key"]]["resource_identity"][
            "observed_runtime_instance_id"
        ]
        for item in cleanup_values
    )
    assert repository.attack_action.model_dump(
        mode="json",
        by_alias=True,
    ) == action_descriptor(ATTACK)
    assert repository.benign_action.model_dump(
        mode="json",
        by_alias=True,
    ) == action_descriptor(BENIGN)
    independently_derived_attack_digest = (
        "sha256:"
        + hashlib.sha256(
            canonical_json_bytes(repository.attack_action.model_dump(mode="json", by_alias=True))
        ).hexdigest()
    )
    independently_derived_benign_digest = (
        "sha256:"
        + hashlib.sha256(
            canonical_json_bytes(repository.benign_action.model_dump(mode="json", by_alias=True))
        ).hexdigest()
    )
    assert independently_derived_attack_digest == (
        compiled.contract.profile.input.attack_action_digest
    )
    assert independently_derived_attack_digest == ATTACK_ACTION_DIGEST
    assert independently_derived_benign_digest == (
        compiled.contract.profile.input.benign_action_digest
    )
    assert independently_derived_benign_digest == BENIGN_ACTION_DIGEST
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
    planned_by_key = {trial.key: trial for trial in compiled.planned_trials}
    assert sum(
        bool(item["redeploy_operation"]["performed"])
        for item in runtime_values
    ) == 8
    for item in runtime_values:
        operation = item["redeploy_operation"]
        selector = selectors[planned_by_key[item["trial_key"]].cell_key]
        expected_sham = selector.sham == compiled.contract.profile.sham.redeploy
        assert operation["requested"] is expected_sham
        assert operation["performed"] is expected_sham
        assert operation["previous_handle_closed"] is expected_sham
        assert (
            operation["before_runtime_instance_id"]
            != operation["after_runtime_instance_id"]
        ) is expected_sham
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
        match="compiler plan",
    ):
        FinancialSupportBundleRepository(cross_spec_root)

    replayed_dataset = dict(dataset.manifest())
    replayed_counts = dict(replayed_dataset["counts"])
    replayed_counts["customers"] = int(replayed_counts["customers"]) + 1
    replayed_dataset["counts"] = replayed_counts
    fixture_path = bundle_root / "spec" / "fixture-manifest.json"
    dataset_replay_root = tmp_path / "dataset-replay"
    _rewrite_bundle(
        bundle_root,
        dataset_replay_root,
        replacements={
            "spec/dataset-manifest.json": canonical_json_bytes(replayed_dataset),
        },
    )
    with pytest.raises(
        FinancialSupportBundleError,
        match="deterministic regeneration",
    ):
        FinancialSupportBundleRepository(dataset_replay_root)

    action_fixture_value = strict_json_loads(fixture_path.read_bytes())
    assert isinstance(action_fixture_value, dict)
    attack_action = action_fixture_value["attack_action"]
    assert isinstance(attack_action, dict)
    requested_customer_ids = attack_action["requested_customer_ids"]
    assert isinstance(requested_customer_ids, list)
    requested_customer_ids[0] = "SYNTH-CUSTOMER-000031"
    action_replay_root = tmp_path / "action-replay"
    _rewrite_bundle(
        bundle_root,
        action_replay_root,
        replacements={
            "spec/fixture-manifest.json": canonical_json_bytes(action_fixture_value),
        },
    )
    with pytest.raises(
        FinancialSupportBundleError,
        match="actions or digests do not match",
    ):
        FinancialSupportBundleRepository(action_replay_root)

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
        match="time_basis",
    ):
        FinancialSupportBundleRepository(mixed_time_root)

    source_value = strict_json_loads(
        (bundle_root / "spec" / "runtime-source-set.json").read_bytes()
    )
    assert isinstance(source_value, dict)
    source_value["claim_boundary"] = "forged publisher-authenticated build"
    forged_source_root = tmp_path / "forged-source"
    _rewrite_bundle(
        bundle_root,
        forged_source_root,
        replacements={
            "spec/runtime-source-set.json": canonical_json_bytes(source_value),
        },
    )
    with pytest.raises(
        FinancialSupportBundleError,
        match="current canonical source bytes",
    ):
        FinancialSupportBundleRepository(forged_source_root)

    runtime_dataset_forgery = strict_json_loads(
        (bundle_root / "spec" / "runtime-dataset.json").read_bytes()
    )
    assert isinstance(runtime_dataset_forgery, dict)
    customers = runtime_dataset_forgery["customers"]
    assert isinstance(customers, list)
    assert isinstance(customers[0], dict)
    customers[0]["email"] = "forged@example.invalid"
    forged_rows_root = tmp_path / "forged-runtime-rows"
    _rewrite_bundle(
        bundle_root,
        forged_rows_root,
        replacements={
            "spec/runtime-dataset.json": canonical_json_bytes(
                runtime_dataset_forgery
            ),
        },
    )
    with pytest.raises(
        FinancialSupportBundleError,
        match="deterministic regeneration",
    ):
        FinancialSupportBundleRepository(forged_rows_root)

    evaluator_forgery = EvaluationRef(
        policy_id=verified.manifest.evaluation.policy_id,
        policy_digest=verified.manifest.evaluation.policy_digest,
        evaluator=EvaluatorRef(
            name="assurance-lab",
            version="0.0.1",
            source_revision="forged-evaluator-revision",
            image_digest=None,
        ),
    )
    forged_provenance_root = tmp_path / "forged-provenance"
    _rewrite_bundle(
        bundle_root,
        forged_provenance_root,
        replacements={},
        evaluation=evaluator_forgery,
        created_at=start + timedelta(minutes=31),
        as_of=start + timedelta(minutes=31),
        parent_bundles=("cab:sha256:" + "1" * 64,),
    )
    with pytest.raises(
        FinancialSupportBundleError,
        match="manifest provenance",
    ):
        FinancialSupportBundleRepository(forged_provenance_root)

    forged_descriptor_root = tmp_path / "forged-descriptor"
    _rewrite_bundle(
        bundle_root,
        forged_descriptor_root,
        replacements={},
        role_overrides={
            "records/runtime-observations.jsonl": "trusted runtime truth"
        },
        required_for_overrides={
            "records/runtime-observations.jsonl": ("evaluation",)
        },
        sensitivity_overrides={
            "records/runtime-observations.jsonl": Sensitivity.LAB_INTERNAL
        },
    )
    with pytest.raises(
        FinancialSupportBundleError,
        match="descriptor metadata",
    ):
        FinancialSupportBundleRepository(forged_descriptor_root)

    cleanup_forgery = strict_jsonl_loads(
        (bundle_root / "artifacts" / "cleanup-observations.jsonl").read_bytes(),
        require_sorted_ids=True,
    )
    cleanup_forgery[0]["closed_handle_rejected_operation"] = False
    forged_cleanup_root = tmp_path / "forged-cleanup"
    _rewrite_bundle(
        bundle_root,
        forged_cleanup_root,
        replacements={
            "artifacts/cleanup-observations.jsonl": canonical_jsonl_bytes(
                cleanup_forgery
            ),
        },
    )
    with pytest.raises(
        FinancialSupportBundleError,
        match="closed_handle_rejected_operation",
    ):
        FinancialSupportBundleRepository(forged_cleanup_root)

    coordinated_runtime_root = tmp_path / "coordinated-runtime-rehash"
    _rewrite_coordinated_runtime_claim(
        bundle_root,
        coordinated_runtime_root,
        tamper="principal-role",
    )
    with pytest.raises(
        FinancialSupportBundleError,
        match="principal query rows",
    ):
        FinancialSupportBundleRepository(coordinated_runtime_root)

    coordinated_clone_root = tmp_path / "coordinated-clone-rehash"
    _rewrite_coordinated_runtime_claim(
        bundle_root,
        coordinated_clone_root,
        tamper="clone",
    )
    with pytest.raises(
        FinancialSupportBundleError,
        match="compiler plan",
    ):
        FinancialSupportBundleRepository(coordinated_clone_root)
