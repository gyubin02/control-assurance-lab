from __future__ import annotations

import hashlib
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from assurance_lab.contract import Stage, TrialPlan, compile_experiment
from assurance_lab.evaluation import (
    CleanupBinding,
    EvidenceBinding,
    ResidualClassification,
    TrialRecord,
    TruthValue,
)
from assurance_lab.evidence.bundle import (
    BundleStatus,
    EvaluationRef,
    EvaluatorRef,
    Sensitivity,
    verify_bundle,
)
from assurance_lab.evidence.canonical import (
    canonical_json_bytes,
    canonical_jsonl_bytes,
    strict_json_loads,
    strict_jsonl_loads,
)
from assurance_lab.evidence.writer import BundleMetadata, PayloadFile, write_bundle
from assurance_lab.scenarios.financial_response_contract import (
    ATTACK,
    BENIGN,
    COMPENSATOR_OFF,
    SHAM_RELOAD,
    SHAM_STEADY,
    TARGET_EFFECTIVE,
    build_financial_response_contract,
)
from assurance_lab.scenarios.financial_response_e2e import (
    FinancialResponseBundleError,
    FinancialResponseBundleRepository,
    build_reference_financial_response_experiment,
    evaluate_financial_response_bundle,
    write_reference_financial_response_bundle,
)
from assurance_lab.scenarios.financial_response_runtime import (
    BaselineVerdict,
    ResponderRuntimeReadback,
    ResponseResidualClassification,
    _expected_responder_instance_id,
    _expected_sham_operation_id,
)


def _bundle_timestamp(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


def _rewrite_bundle(
    source: Path,
    destination: Path,
    *,
    replacements: dict[str, bytes],
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
    rewritten = write_bundle(
        destination,
        metadata=BundleMetadata(
            created_at=_bundle_timestamp(manifest.created_at),
            as_of=_bundle_timestamp(manifest.as_of),
            experiment=manifest.experiment,
            evaluation=manifest.evaluation,
            parent_bundles=tuple(manifest.parent_bundles),
        ),
        payloads=payloads,
    )
    assert rewritten.status == BundleStatus.INTEGRITY_VERIFIED


def _payload_index(event: dict[str, Any], name: str) -> int:
    payload = event["payload"]
    assert isinstance(payload, list)
    return next(
        index
        for index, item in enumerate(payload)
        if isinstance(item, dict) and item.get("name") == name
    )


def _set_payload(event: dict[str, Any], name: str, value: object) -> None:
    payload = event["payload"]
    assert isinstance(payload, list)
    item = payload[_payload_index(event, name)]
    assert isinstance(item, dict)
    item["value"] = value


_CHAIN_PATHS = {
    "runtime": "records/runtime-observations.jsonl",
    "stage": "records/stage-events.jsonl",
    "metric": "records/metric-observations.jsonl",
    "attestation": "artifacts/trial-attestations.jsonl",
    "cleanup": "artifacts/cleanup-observations.jsonl",
    "trial": "records/trial-records.jsonl",
}


def _load_trial_chain(source: Path) -> dict[str, list[Any]]:
    return {
        name: strict_jsonl_loads(
            (source / path).read_bytes(),
            require_sorted_ids=True,
        )
        for name, path in _CHAIN_PATHS.items()
    }


def _rewrite_trial_chain(
    source: Path,
    destination: Path,
    values: dict[str, list[Any]],
) -> None:
    _rewrite_bundle(
        source,
        destination,
        replacements={
            _CHAIN_PATHS[name]: canonical_jsonl_bytes(records)
            for name, records in values.items()
        },
    )


def _coherently_rebind_trial_chain(
    values: dict[str, list[Any]],
    *,
    trial_key: str,
) -> None:
    """Rehash every downstream edge after changing one raw observation."""

    runtime = next(
        item for item in values["runtime"] if item["trial_key"] == trial_key
    )
    runtime_digest = (
        f"sha256:{hashlib.sha256(canonical_json_bytes(runtime)).hexdigest()}"
    )
    stage_digests: dict[str, str] = {}
    for stage in values["stage"]:
        if stage["trial_key"] != trial_key:
            continue
        stage["runtime_observation_digest"] = runtime_digest
        stage_digests[str(stage["stage"])] = (
            f"sha256:{hashlib.sha256(canonical_json_bytes(stage)).hexdigest()}"
        )
    for metric in values["metric"]:
        if metric["trial_key"] == trial_key:
            metric["event_digest"] = stage_digests[str(metric["stage"])]

    attestation = next(
        item for item in values["attestation"] if item["trial_key"] == trial_key
    )
    attestation["runtime_observation_digest"] = runtime_digest
    attestation_digest = (
        f"sha256:{hashlib.sha256(canonical_json_bytes(attestation)).hexdigest()}"
    )
    cleanup = next(
        item for item in values["cleanup"] if item["trial_key"] == trial_key
    )
    cleanup["runtime_observation_digest"] = runtime_digest
    cleanup_digest = (
        f"sha256:{hashlib.sha256(canonical_json_bytes(cleanup)).hexdigest()}"
    )
    stored = next(
        item
        for item in values["trial"]
        if item["record"]["trial_key"] == trial_key
    )
    stored["record"]["clone"]["attestation_bundle_digest"] = attestation_digest
    stored["record"]["cleanup"]["evidence_bundle_digest"] = cleanup_digest
    trace = stored["record"]["trace"]
    for stage_name, digest in stage_digests.items():
        trace[stage_name]["evidence_bundle_digest"] = digest


def test_response_bundle_recomputes_masked_revocation_from_raw_evidence(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "response"
    compiled, written = write_reference_financial_response_bundle(bundle)
    assert written.status == BundleStatus.INTEGRITY_VERIFIED
    assert len(compiled.cells) == 16
    assert len(compiled.planned_trials) == 16

    repository = FinancialResponseBundleRepository(bundle)
    assessment = evaluate_financial_response_bundle(repository)
    report = assessment.report
    response = assessment.response_case

    assert len(repository.trial_records) == 16
    assert report.design_completeness.protocol_complete
    assert not report.design_issues
    assert not report.evidence_issues
    assert not report.safety_issues
    assert report.residual_summary.classification == (
        ResidualClassification.MASKED_TARGET_FAILURE
    )
    obligations = {
        item.obligation_id: item.truth for item in report.obligation_assessments
    }
    assert obligations["current-exact-session-revoked"] == TruthValue.REFUTED
    assert obligations["current-principal-quarantined"] == TruthValue.SUPPORTED
    assert obligations["current-replay-denied"] == TruthValue.SUPPORTED
    assert obligations["unrelated-support-service-envelope"] == TruthValue.SUPPORTED
    assert obligations["revoke-exact-preserves-non-target-sessions"] == (
        TruthValue.SUPPORTED
    )
    assert all(
        contrast.truth == TruthValue.SUPPORTED
        for contrast in report.contrast_assessments
    )

    assert response.baseline.verdict == BaselineVerdict.PASS
    assert response.baseline.response_action_reported_success
    assert response.baseline.replay_denied
    assert not response.target_supported
    assert response.compensator_supported
    assert response.path_supported
    assert response.benign_service_supported
    assert response.residual_classification == (
        ResponseResidualClassification.MASKED_REVOCATION_FAILURE
    )

    selectors = {cell.key: cell.selector for cell in compiled.cells}
    current = next(
        trial
        for trial in compiled.planned_trials
        if selectors[trial.cell_key] == compiled.current_selector
    )
    assert repository.metric_value(
        current.key,
        "compromised-session-active",
    )
    assert repository.metric_value(
        current.key,
        "compromised-principal-quarantined",
    )
    assert repository.metric_value(
        current.key,
        "compromised-session-replay-denied",
    )
    target = repository.stage_artifact(current.key, Stage.TARGET)
    assert target.value("response_action_status") == "reported-success"
    assert target.value("target_modified_session_count") == 0

    benign = tuple(
        trial
        for trial in compiled.planned_trials
        if selectors[trial.cell_key].input == BENIGN
    )
    assert len(benign) == 8
    assert all(
        repository.metric_value(
            trial.key,
            "unrelated-support-principal-available",
        )
        for trial in benign
    )
    stage_lines = strict_jsonl_loads(
        (bundle / "records" / "stage-events.jsonl").read_bytes(),
        require_sorted_ids=True,
    )
    metric_lines = strict_jsonl_loads(
        (bundle / "records" / "metric-observations.jsonl").read_bytes(),
        require_sorted_ids=True,
    )
    assert len(stage_lines) == 64
    assert len(metric_lines) == 96
    runtime_lines = strict_jsonl_loads(
        (bundle / "records" / "runtime-observations.jsonl").read_bytes(),
        require_sorted_ids=True,
    )
    cleanup_lines = strict_jsonl_loads(
        (bundle / "artifacts" / "cleanup-observations.jsonl").read_bytes(),
        require_sorted_ids=True,
    )
    assert len(runtime_lines) == 16
    assert len(cleanup_lines) == 16
    assert all(
        item["resource_identity"]["requested_clone_nonce"]
        == item["resource_identity"]["observed_clone_nonce"]
        for item in runtime_lines
    )
    selector_by_trial = {
        trial.key: selectors[trial.cell_key]
        for trial in compiled.planned_trials
    }
    for item in runtime_lines:
        selector = selector_by_trial[item["trial_key"]]
        before = item["responder_before_sham"]
        after = item["responder_after_sham"]
        operation = item["sham_operation"]
        if selector.sham == SHAM_RELOAD:
            assert operation["operation"] == "reload"
            assert operation["rows_affected"] == 1
            assert after["generation"] == before["generation"] + 1
            assert after["instance_id"] != before["instance_id"]
        else:
            assert selector.sham == SHAM_STEADY
            assert operation["operation"] == "steady-observation"
            assert operation["rows_affected"] == 0
            assert after == before
    assert all(
        item["probe_error_type"] == "sqlite3.ProgrammingError"
        and item["closed_handle_rejected_operation"] is True
        for item in cleanup_lines
    )
    source_set_bytes = (bundle / "spec" / "runtime-source-set.json").read_bytes()
    source_set = strict_json_loads(source_set_bytes)
    assert isinstance(source_set, dict)
    assert source_set["schema"] == (
        "assurance-lab.financial-response-source-set/v1"
    )
    assert source_set["dependency_resolver"] == (
        "python-ast-local-import-closure/v1"
    )
    assert len(source_set["files"]) == 11
    assert f"sha256:{hashlib.sha256(source_set_bytes).hexdigest()}" == (
        compiled.contract.scope.build_digest
    )
    trial_bytes = (bundle / "records" / "trial-records.jsonl").read_bytes()
    assert b"compromised_session_active" not in trial_bytes
    assert b"compromised_session_replay_denied" not in trial_bytes


def test_response_runner_allows_repetitions_without_weakening_cell_coverage(
    tmp_path: Path,
) -> None:
    start = datetime(2026, 7, 29, 2, 0, tzinfo=UTC)
    runner, reference = build_reference_financial_response_experiment(start=start)
    repeated = compile_experiment(
        build_financial_response_contract(
            scope=reference.contract.scope,
            plan=TrialPlan(
                blocks=("sqlite-fresh-clone",),
                replicates=2,
                order_seed="financial-response-two-replicates",
            ),
        )
    )
    root = tmp_path / "repeated"
    written = runner.run(repeated, root)
    assert written.status == BundleStatus.INTEGRITY_VERIFIED
    repository = FinancialResponseBundleRepository(root)
    assert len(repeated.cells) == 16
    assert len(repository.trial_records) == 32
    assert evaluate_financial_response_bundle(
        repository
    ).report.design_completeness.protocol_complete


def test_reference_response_bundle_is_byte_deterministic(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    _, first_written = write_reference_financial_response_bundle(first)
    _, second_written = write_reference_financial_response_bundle(second)
    assert first_written.bundle_id == second_written.bundle_id
    first_paths = sorted(path.relative_to(first) for path in first.rglob("*") if path.is_file())
    second_paths = sorted(
        path.relative_to(second) for path in second.rglob("*") if path.is_file()
    )
    assert first_paths == second_paths
    assert all(
        (first / path).read_bytes() == (second / path).read_bytes()
        for path in first_paths
    )


@pytest.mark.parametrize(
    "case",
    (
        "event-metric",
        "metric-observation",
        "selector",
        "action",
        "subject",
        "modified-set",
        "incomplete-stage-coverage",
        "incomplete-metric-coverage",
    ),
)
def test_repository_rejects_semantic_tampering_after_manifest_is_rewritten(
    tmp_path: Path,
    case: str,
) -> None:
    source = tmp_path / "source"
    compiled, _ = write_reference_financial_response_bundle(source)
    stage_path = "records/stage-events.jsonl"
    metric_path = "records/metric-observations.jsonl"
    attestation_path = "artifacts/trial-attestations.jsonl"
    stage_values = strict_jsonl_loads(
        (source / stage_path).read_bytes(),
        require_sorted_ids=True,
    )
    metric_values = strict_jsonl_loads(
        (source / metric_path).read_bytes(),
        require_sorted_ids=True,
    )
    attestation_values = strict_jsonl_loads(
        (source / attestation_path).read_bytes(),
        require_sorted_ids=True,
    )
    replacements: dict[str, bytes]

    if case == "event-metric":
        target = next(item for item in stage_values if item["stage"] == "target")
        current = bool(
            target["payload"][
                _payload_index(target, "compromised_session_active")
            ]["value"]
        )
        _set_payload(target, "compromised_session_active", not current)
        replacements = {stage_path: canonical_jsonl_bytes(stage_values)}
    elif case == "metric-observation":
        observation = metric_values[0]
        value = observation["value"]
        assert isinstance(value, dict)
        value["value"] = not bool(value["value"])
        replacements = {metric_path: canonical_jsonl_bytes(metric_values)}
    elif case == "selector":
        attestation = attestation_values[0]
        selector = attestation["observed_selector"]
        assert isinstance(selector, dict)
        selector["input"] = {
            "kind": "string",
            "value": (
                BENIGN.value
                if selector["input"]["value"] == ATTACK.value
                else ATTACK.value
            ),
        }
        replacements = {
            attestation_path: canonical_jsonl_bytes(attestation_values)
        }
    elif case == "action":
        event = next(item for item in stage_values if item["stage"] == "input")
        action = event_payload(event, "action")
        _set_payload(
            event,
            "action",
            (
                "compromised-old-session-replay"
                if action == "unrelated-support-normal-action"
                else "unrelated-support-normal-action"
            ),
        )
        replacements = {stage_path: canonical_jsonl_bytes(stage_values)}
    elif case == "subject":
        observation = next(
            item
            for item in metric_values
            if item["metric_id"] == "compromised-session-active"
        )
        observation["subject_id"] = "SYNTH-SESSION-SUPPORT-017-CURRENT"
        replacements = {metric_path: canonical_jsonl_bytes(metric_values)}
    elif case == "modified-set":
        event = next(
            item
            for item in stage_values
            if item["stage"] == "target"
            and item["action_digest"]
            == compiled.contract.profile.input.attack_action_digest
            and event_payload(item, "target_mode") == TARGET_EFFECTIVE.value
        )
        replacement_set = {
            "schema": "assurance-lab.modified-session-set/v1",
            "session_ids": ["SYNTH-SESSION-SUPPORT-017-CURRENT"],
        }
        canonical = canonical_json_bytes(replacement_set)
        _set_payload(
            event,
            "target_modified_session_ids_canonical",
            canonical.decode("utf-8"),
        )
        _set_payload(
            event,
            "target_modified_session_ids_digest",
            f"sha256:{hashlib.sha256(canonical).hexdigest()}",
        )
        _set_payload(event, "target_modified_session_count", 1)
        replacements = {stage_path: canonical_jsonl_bytes(stage_values)}
    elif case == "incomplete-stage-coverage":
        replacements = {stage_path: canonical_jsonl_bytes(stage_values[1:])}
    else:
        replacements = {metric_path: canonical_jsonl_bytes(metric_values[1:])}

    rewritten = tmp_path / f"rewritten-{case}"
    _rewrite_bundle(source, rewritten, replacements=replacements)
    with pytest.raises(FinancialResponseBundleError):
        FinancialResponseBundleRepository(rewritten)


def event_payload(event: dict[str, Any], name: str) -> object:
    payload = event["payload"]
    assert isinstance(payload, list)
    item = payload[_payload_index(event, name)]
    assert isinstance(item, dict)
    return item["value"]


def test_provenance_files_cannot_be_rebound_by_rehashing_the_manifest(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    write_reference_financial_response_bundle(source)
    fixture_path = "spec/response-fixture.json"
    fixture = strict_json_loads((source / fixture_path).read_bytes())
    assert isinstance(fixture, dict)
    attack = fixture["attack_action"]
    assert isinstance(attack, dict)
    attack["session_id"] = "SYNTH-SESSION-SUPPORT-017-CURRENT"
    rewritten = tmp_path / "rewritten-fixture"
    _rewrite_bundle(
        source,
        rewritten,
        replacements={fixture_path: canonical_json_bytes(fixture)},
    )
    with pytest.raises(FinancialResponseBundleError):
        FinancialResponseBundleRepository(rewritten)


def test_claimed_source_set_cannot_be_rebound_by_rehashing_the_manifest(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    write_reference_financial_response_bundle(source)
    path = "spec/runtime-source-set.json"
    source_set = strict_json_loads((source / path).read_bytes())
    assert isinstance(source_set, dict)
    files = source_set["files"]
    assert isinstance(files, list)
    first = files[0]
    assert isinstance(first, dict)
    first["sha256"] = f"sha256:{'0' * 64}"
    destination = tmp_path / "rewritten-source-set"
    _rewrite_bundle(
        source,
        destination,
        replacements={path: canonical_json_bytes(source_set)},
    )
    with pytest.raises(
        FinancialResponseBundleError,
        match="source-set descriptor differs",
    ):
        FinancialResponseBundleRepository(destination)


def test_responder_config_descriptor_cannot_be_rebound(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    write_reference_financial_response_bundle(source)
    path = "spec/responder-config.json"
    config = strict_json_loads((source / path).read_bytes())
    assert isinstance(config, dict)
    config["attack_status"] = "not-triggered"
    destination = tmp_path / "rewritten-responder-config"
    _rewrite_bundle(
        source,
        destination,
        replacements={path: canonical_json_bytes(config)},
    )
    with pytest.raises(
        FinancialResponseBundleError,
        match="responder configuration",
    ):
        FinancialResponseBundleRepository(destination)


def test_manifest_provenance_is_not_rebindable(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    write_reference_financial_response_bundle(source)
    verified = verify_bundle(source)
    assert verified.manifest is not None
    manifest = verified.manifest
    payloads = tuple(
        PayloadFile(
            path=descriptor.path,
            content=source.joinpath(*descriptor.path.split("/")).read_bytes(),
            media_type=descriptor.media_type,
            role=descriptor.role,
            sensitivity=descriptor.sensitivity,
            required_for=tuple(descriptor.required_for),
        )
        for descriptor in manifest.files
    )
    destination = tmp_path / "rewritten-manifest"
    rewritten = write_bundle(
        destination,
        metadata=BundleMetadata(
            created_at=datetime(2027, 7, 29, tzinfo=UTC),
            as_of=datetime(2027, 7, 29, tzinfo=UTC),
            experiment=manifest.experiment,
            evaluation=EvaluationRef(
                policy_id=manifest.evaluation.policy_id,
                policy_digest=manifest.evaluation.policy_digest,
                evaluator=EvaluatorRef(
                    name="untrusted-rewriter",
                    version="99",
                    source_revision="not-the-executed-source-set",
                    image_digest=None,
                ),
            ),
            parent_bundles=(f"sha256:{'0' * 64}",),
        ),
        payloads=payloads,
    )
    assert rewritten.status == BundleStatus.INTEGRITY_VERIFIED
    with pytest.raises(FinancialResponseBundleError):
        FinancialResponseBundleRepository(destination)


def test_manifest_descriptor_metadata_is_not_rebindable(tmp_path: Path) -> None:
    source = tmp_path / "source"
    write_reference_financial_response_bundle(source)
    verified = verify_bundle(source)
    assert verified.manifest is not None
    manifest = verified.manifest
    destination = tmp_path / "rewritten-descriptors"
    rewritten = write_bundle(
        destination,
        metadata=BundleMetadata(
            created_at=_bundle_timestamp(manifest.created_at),
            as_of=_bundle_timestamp(manifest.as_of),
            experiment=manifest.experiment,
            evaluation=manifest.evaluation,
        ),
        payloads=tuple(
            PayloadFile(
                path=descriptor.path,
                content=source.joinpath(*descriptor.path.split("/")).read_bytes(),
                media_type=descriptor.media_type,
                role="rewriter-supplied-role",
                sensitivity=Sensitivity.LAB_INTERNAL,
                required_for=(),
            )
            for descriptor in manifest.files
        ),
    )
    assert rewritten.status == BundleStatus.INTEGRITY_VERIFIED
    with pytest.raises(
        FinancialResponseBundleError,
        match="descriptor metadata differs",
    ):
        FinancialResponseBundleRepository(destination)


def test_coordinated_runtime_receipt_rebinding_is_rejected(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    compiled, _ = write_reference_financial_response_bundle(source)
    selectors = {cell.key: cell.selector for cell in compiled.cells}
    current = next(
        trial
        for trial in compiled.planned_trials
        if selectors[trial.cell_key] == compiled.current_selector
    )
    values = _load_trial_chain(source)

    runtime = next(
        item for item in values["runtime"] if item["trial_key"] == current.key
    )
    decision = next(
        item
        for item in runtime["gateway_decisions"]
        if item["query_id"] == "probe-compromised-session-replay"
    )
    decision["session_revoked"] = True
    runtime_digest = f"sha256:{hashlib.sha256(canonical_json_bytes(runtime)).hexdigest()}"

    stages = [
        item for item in values["stage"] if item["trial_key"] == current.key
    ]
    stage_digests: dict[str, str] = {}
    for stage in stages:
        stage["runtime_observation_digest"] = runtime_digest
        stage_digests[str(stage["stage"])] = (
            f"sha256:{hashlib.sha256(canonical_json_bytes(stage)).hexdigest()}"
        )
    for metric in values["metric"]:
        if metric["trial_key"] == current.key:
            metric["event_digest"] = stage_digests[str(metric["stage"])]

    attestation = next(
        item
        for item in values["attestation"]
        if item["trial_key"] == current.key
    )
    attestation["runtime_observation_digest"] = runtime_digest
    attestation_digest = (
        f"sha256:{hashlib.sha256(canonical_json_bytes(attestation)).hexdigest()}"
    )
    cleanup = next(
        item for item in values["cleanup"] if item["trial_key"] == current.key
    )
    cleanup["runtime_observation_digest"] = runtime_digest
    cleanup_digest = (
        f"sha256:{hashlib.sha256(canonical_json_bytes(cleanup)).hexdigest()}"
    )
    stored = next(
        item
        for item in values["trial"]
        if item["record"]["trial_key"] == current.key
    )
    stored["record"]["clone"]["attestation_bundle_digest"] = attestation_digest
    stored["record"]["cleanup"]["evidence_bundle_digest"] = cleanup_digest
    trace = stored["record"]["trace"]
    for stage_name, digest in stage_digests.items():
        trace[stage_name]["evidence_bundle_digest"] = digest

    destination = tmp_path / "coordinated-rebind"
    _rewrite_trial_chain(source, destination, values)
    with pytest.raises(
        FinancialResponseBundleError,
        match="gateway query receipt differs",
    ):
        FinancialResponseBundleRepository(destination)


def test_coherent_response_status_rewrite_is_rejected(
    tmp_path: Path,
) -> None:
    """A rewriter cannot turn the fixed responder's success row into failure."""

    source = tmp_path / "source"
    compiled, _ = write_reference_financial_response_bundle(source)
    selectors = {cell.key: cell.selector for cell in compiled.cells}
    current = next(
        trial
        for trial in compiled.planned_trials
        if selectors[trial.cell_key] == compiled.current_selector
    )
    values = _load_trial_chain(source)
    runtime = next(
        item
        for item in values["runtime"]
        if item["trial_key"] == current.key
    )
    runtime["response_action"]["status"] = "reported-failure"
    target = next(
        item
        for item in values["stage"]
        if item["trial_key"] == current.key and item["stage"] == "target"
    )
    _set_payload(target, "response_action_status", "reported-failure")
    _set_payload(target, "response_action_reported_success", False)
    status_metric = next(
        item
        for item in values["metric"]
        if item["trial_key"] == current.key
        and item["metric_id"] == "response-action-reported-success"
    )
    status_metric["value"]["value"] = False
    _coherently_rebind_trial_chain(values, trial_key=current.key)

    destination = tmp_path / "coherent-status-rewrite"
    _rewrite_trial_chain(source, destination, values)
    with pytest.raises(
        FinancialResponseBundleError,
        match=r"response_action|response status|runtime observation",
    ):
        FinancialResponseBundleRepository(destination)


def test_coherent_raw_rows_and_mutation_receipt_rewrite_is_rejected(
    tmp_path: Path,
) -> None:
    """Rehashing every derived layer cannot invent a failed fixed mutation."""

    source = tmp_path / "source"
    compiled, _ = write_reference_financial_response_bundle(source)
    selectors = {cell.key: cell.selector for cell in compiled.cells}
    trial = next(
        item
        for item in compiled.planned_trials
        if selectors[item.cell_key].input == ATTACK
        and selectors[item.cell_key].target == TARGET_EFFECTIVE
        and selectors[item.cell_key].compensator == COMPENSATOR_OFF
        and selectors[item.cell_key].sham == SHAM_STEADY
    )
    values = _load_trial_chain(source)
    runtime = next(
        item for item in values["runtime"] if item["trial_key"] == trial.key
    )
    for snapshot_name in (
        "sessions_after_target",
        "sessions_after_compensator",
    ):
        compromised = next(
            row
            for row in runtime[snapshot_name]
            if row["session_id"] == "SYNTH-SESSION-SUPPORT-017-OLD"
        )
        compromised["active"] = True
    runtime["target_mutation"]["rows_affected"] = 0
    runtime["response_action"]["rows_affected"] = 0
    replay = next(
        item
        for item in runtime["gateway_decisions"]
        if item["query_id"] == "probe-compromised-session-replay"
    )
    replay["session_revoked"] = False
    replay["principal_quarantined"] = False
    replay["available"] = True

    empty_set = {
        "schema": "assurance-lab.modified-session-set/v1",
        "session_ids": [],
    }
    empty_canonical = canonical_json_bytes(empty_set)
    target = next(
        item
        for item in values["stage"]
        if item["trial_key"] == trial.key and item["stage"] == "target"
    )
    _set_payload(target, "compromised_session_active", True)
    _set_payload(target, "target_modified_session_count", 0)
    _set_payload(
        target,
        "target_modified_session_ids_canonical",
        empty_canonical.decode("utf-8"),
    )
    _set_payload(
        target,
        "target_modified_session_ids_digest",
        f"sha256:{hashlib.sha256(empty_canonical).hexdigest()}",
    )
    outcome = next(
        item
        for item in values["stage"]
        if item["trial_key"] == trial.key and item["stage"] == "outcome"
    )
    _set_payload(outcome, "compromised_session_replay_denied", False)
    for metric_id, value in (
        ("compromised-session-active", True),
        ("compromised-session-replay-denied", False),
    ):
        metric = next(
            item
            for item in values["metric"]
            if item["trial_key"] == trial.key
            and item["metric_id"] == metric_id
        )
        metric["value"]["value"] = value
    _coherently_rebind_trial_chain(values, trial_key=trial.key)

    destination = tmp_path / "coherent-mutation-rewrite"
    _rewrite_trial_chain(source, destination, values)
    with pytest.raises(
        FinancialResponseBundleError,
        match=r"fixed response transitions|mutation row count",
    ):
        FinancialResponseBundleRepository(destination)


def test_coherent_reload_to_steady_receipt_relabel_is_rejected(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    compiled, _ = write_reference_financial_response_bundle(source)
    selectors = {cell.key: cell.selector for cell in compiled.cells}
    trial = next(
        item
        for item in compiled.planned_trials
        if selectors[item.cell_key].sham == SHAM_RELOAD
    )
    values = _load_trial_chain(source)
    runtime = next(
        item for item in values["runtime"] if item["trial_key"] == trial.key
    )
    before = deepcopy(runtime["responder_before_sham"])
    runtime["responder_after_sham"] = deepcopy(before)
    before_readback = ResponderRuntimeReadback(**before)
    runtime["sham_operation"] = {
        "operation_id": _expected_sham_operation_id(
            "steady-observation",
            before_readback,
            before_readback,
        ),
        "operation": "steady-observation",
        "clone_nonce": before["clone_nonce"],
        "before_instance_id": before["instance_id"],
        "after_instance_id": before["instance_id"],
        "before_generation": before["generation"],
        "after_generation": before["generation"],
        "config_digest": before["config_digest"],
        "rows_affected": 0,
    }
    _coherently_rebind_trial_chain(values, trial_key=trial.key)

    destination = tmp_path / "coherent-reload-relabel"
    _rewrite_trial_chain(source, destination, values)
    with pytest.raises(
        FinancialResponseBundleError,
        match="responder configuration",
    ):
        FinancialResponseBundleRepository(destination)


def test_coherent_responder_config_rebinding_is_rejected(
    tmp_path: Path,
) -> None:
    """A stable-looking reload cannot substitute an arbitrary configuration."""

    source = tmp_path / "source"
    compiled, _ = write_reference_financial_response_bundle(source)
    selectors = {cell.key: cell.selector for cell in compiled.cells}
    trial = next(
        item
        for item in compiled.planned_trials
        if selectors[item.cell_key].sham == SHAM_RELOAD
    )
    values = _load_trial_chain(source)
    runtime = next(
        item for item in values["runtime"] if item["trial_key"] == trial.key
    )
    forged_digest = f"sha256:{'a' * 64}"
    runtime["responder_before_sham"]["config_digest"] = forged_digest
    runtime["responder_after_sham"]["config_digest"] = forged_digest
    runtime["sham_operation"]["config_digest"] = forged_digest
    before = ResponderRuntimeReadback(**runtime["responder_before_sham"])
    after = ResponderRuntimeReadback(**runtime["responder_after_sham"])
    runtime["sham_operation"]["operation_id"] = _expected_sham_operation_id(
        "reload",
        before,
        after,
    )
    _coherently_rebind_trial_chain(values, trial_key=trial.key)

    destination = tmp_path / "coherent-config-rebind"
    _rewrite_trial_chain(source, destination, values)
    with pytest.raises(
        FinancialResponseBundleError,
        match="responder configuration",
    ):
        FinancialResponseBundleRepository(destination)


def test_coherent_clone_identity_relabel_is_rejected(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    compiled, _ = write_reference_financial_response_bundle(source)
    selectors = {cell.key: cell.selector for cell in compiled.cells}
    trial = next(
        item
        for item in compiled.planned_trials
        if selectors[item.cell_key].sham == SHAM_STEADY
    )
    values = _load_trial_chain(source)
    new_clone_id = "coherently-relabelled-clone"
    runtime = next(
        item for item in values["runtime"] if item["trial_key"] == trial.key
    )
    resource = runtime["resource_identity"]
    resource["requested_clone_nonce"] = new_clone_id
    resource["observed_clone_nonce"] = new_clone_id
    config_digest = runtime["responder_before_sham"]["config_digest"]
    instance_id = _expected_responder_instance_id(new_clone_id, 0)
    runtime["responder_before_sham"] = {
        "clone_nonce": new_clone_id,
        "instance_id": instance_id,
        "generation": 0,
        "config_digest": config_digest,
    }
    runtime["responder_after_sham"] = deepcopy(
        runtime["responder_before_sham"]
    )
    readback = ResponderRuntimeReadback(
        clone_nonce=new_clone_id,
        instance_id=instance_id,
        generation=0,
        config_digest=config_digest,
    )
    runtime["sham_operation"] = {
        "operation_id": _expected_sham_operation_id(
            "steady-observation",
            readback,
            readback,
        ),
        "operation": "steady-observation",
        "clone_nonce": new_clone_id,
        "before_instance_id": instance_id,
        "after_instance_id": instance_id,
        "before_generation": 0,
        "after_generation": 0,
        "config_digest": config_digest,
        "rows_affected": 0,
    }
    attestation = next(
        item
        for item in values["attestation"]
        if item["trial_key"] == trial.key
    )
    cleanup = next(
        item for item in values["cleanup"] if item["trial_key"] == trial.key
    )
    stored = next(
        item
        for item in values["trial"]
        if item["record"]["trial_key"] == trial.key
    )
    attestation["clone_unique_instance_id"] = new_clone_id
    cleanup["clone_unique_instance_id"] = new_clone_id
    stored["record"]["clone"]["unique_instance_id"] = new_clone_id
    _coherently_rebind_trial_chain(values, trial_key=trial.key)

    destination = tmp_path / "coherent-clone-relabel"
    _rewrite_trial_chain(source, destination, values)
    with pytest.raises(
        FinancialResponseBundleError,
        match="compiler plan",
    ):
        FinancialResponseBundleRepository(destination)


def test_missing_verifier_requests_return_typed_failures(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    write_reference_financial_response_bundle(source)
    repository = FinancialResponseBundleRepository(source)
    record = repository.trial_records[0]
    missing_digest = f"sha256:{'f' * 64}"
    missing_trial_data = record.model_dump(mode="python", round_trip=True)
    missing_trial_data["trial_key"] = missing_digest
    missing_trial = TrialRecord.model_validate(missing_trial_data, strict=True)

    attestation = repository.verify(missing_trial)
    metric = repository.verify(
        EvidenceBinding(
            spec_digest=record.spec_digest,
            trial_key=record.trial_key,
            trace_id=record.trace.trace_id,
            event_id=record.trace.input.event_id,
            evidence_bundle_digest=(
                record.trace.input.evidence_bundle_digest
            ),
            stage=Stage.INPUT,
            metric_id="missing-response-metric",
        )
    )
    cleanup = repository.verify(
        CleanupBinding(
            spec_digest=record.spec_digest,
            trial_key=record.trial_key,
            trace_id=record.trace.trace_id,
            clone_unique_instance_id=record.clone.unique_instance_id,
            runner_resource_id=record.clone.runner_resource_id,
            evidence_bundle_digest=missing_digest,
            outcome_ended_at=record.trace.outcome.ended_at,
        )
    )

    assert attestation.status == "missing"
    assert metric.status == "missing"
    assert cleanup.status == "missing"


@pytest.mark.parametrize("orphan", (False, True))
def test_missing_or_orphan_raw_observation_is_domain_rejected(
    tmp_path: Path,
    orphan: bool,
) -> None:
    source = tmp_path / "source"
    write_reference_financial_response_bundle(source)
    path = "records/runtime-observations.jsonl"
    observations = strict_jsonl_loads(
        (source / path).read_bytes(),
        require_sorted_ids=True,
    )
    if orphan:
        extra = deepcopy(observations[0])
        extra["id"] = "orphan-runtime-observation"
        extra["trial_key"] = f"sha256:{'e' * 64}"
        observations.append(extra)
    else:
        observations.pop()
    destination = tmp_path / ("orphan" if orphan else "missing")
    _rewrite_bundle(
        source,
        destination,
        replacements={path: canonical_jsonl_bytes(observations)},
    )

    with pytest.raises(
        FinancialResponseBundleError,
        match="runtime observations do not exactly cover",
    ):
        FinancialResponseBundleRepository(destination)
