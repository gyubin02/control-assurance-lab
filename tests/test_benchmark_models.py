from __future__ import annotations

import hashlib
import json

import pytest
from pydantic import BaseModel as PydanticBaseModel
from pydantic import JsonValue, ValidationError

from assurance_lab.benchmark import (
    BENCHMARK_SCENARIO_IDS,
    DETECTION_SCENARIO_ID,
    AgreementDisposition,
    BaselineDisposition,
    BenchmarkIndex,
    BenchmarkSemanticResult,
    CellSemanticResult,
    ClaimDisposition,
    CloneReadback,
    CorruptionIndexEntry,
    CorruptionReceipt,
    FrozenActionBinding,
    IndexedCorruptionCorpus,
    IssueDisposition,
    NormalizedIssue,
    OpaqueArtifactReference,
    RawTrialEnvelope,
    RawTrialSet,
    ReplicateAgreement,
    ResidualDisposition,
    ScenarioId,
    ScenarioIndexEntry,
    ScenarioSemanticResult,
    SemanticVector,
    TrialSemanticResult,
    canonical_digest,
    canonical_trial_key,
)
from assurance_lab.benchmark.models import (
    MatchedPairSemanticLineage,
    SingleTrialSemanticLineage,
)


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def clone_readback(
    index: int,
    *,
    clone_id: str | None = None,
    runner_resource_id: str | None = None,
    attestation_bundle_digest: str | None = None,
) -> CloneReadback:
    body: dict[str, str] = {
        "unique_instance_id": clone_id or f"clone-{index:03d}",
        "runner_resource_id": runner_resource_id or f"runner-{index:03d}",
        "base_snapshot_digest": digest("snapshot"),
        "covariate_digest": digest("covariate"),
        "attestation_bundle_digest": attestation_bundle_digest or digest(f"attestation-{index}"),
    }
    addressed_body = {
        "readback_schema": "assurance-lab.clone-readback/v1",
        **body,
    }
    return CloneReadback(
        readback_schema="assurance-lab.clone-readback/v1",
        unique_instance_id=body["unique_instance_id"],
        runner_resource_id=body["runner_resource_id"],
        base_snapshot_digest=body["base_snapshot_digest"],
        covariate_digest=body["covariate_digest"],
        attestation_bundle_digest=body["attestation_bundle_digest"],
        readback_digest=canonical_digest(addressed_body),
    )


def raw_trial(
    ordinal: int,
    *,
    trial_key: str | None = None,
    trace_id: str | None = None,
    clone_id: str | None = None,
    cell_key: str | None = None,
    block: str = "block-1",
    runner_resource_id: str | None = None,
    attestation_bundle_digest: str | None = None,
    runtime_artifact_digest: str | None = None,
) -> RawTrialEnvelope:
    cell_number = (ordinal - 1) // 3 + 1
    replicate = (ordinal - 1) % 3 + 1
    resolved_cell_key = cell_key or f"cell-{cell_number:02d}"
    spec_digest = digest("detection-spec")
    action_artifact = OpaqueArtifactReference(
        schema_name="assurance-lab.action/v1",
        artifact_digest=digest(f"action-{ordinal}"),
    )
    resolved_trial_key = trial_key or canonical_trial_key(
        spec_digest=spec_digest,
        cell_key=resolved_cell_key,
        block=block,
        replicate=replicate,
    )
    binding_body: dict[str, JsonValue] = {
        "binding_schema": "assurance-lab.benchmark.frozen-action-binding/v1",
        "spec_digest": spec_digest,
        "trial_key": resolved_trial_key,
        "artifact": action_artifact.model_dump(mode="json"),
    }
    action = FrozenActionBinding(
        binding_schema="assurance-lab.benchmark.frozen-action-binding/v1",
        spec_digest=spec_digest,
        trial_key=resolved_trial_key,
        artifact=action_artifact,
        binding_digest=canonical_digest(binding_body),
    )
    runtime = OpaqueArtifactReference(
        schema_name="assurance-lab.runtime-observation/v1",
        artifact_digest=runtime_artifact_digest or digest(f"runtime-observation-{ordinal}"),
    )
    return RawTrialEnvelope(
        wire_schema="assurance-lab.benchmark.raw-trial/v1",
        scenario_id=DETECTION_SCENARIO_ID,
        spec_digest=spec_digest,
        trial_key=resolved_trial_key,
        cell_key=resolved_cell_key,
        block=block,
        replicate=replicate,
        ordinal=ordinal,
        trace_id=trace_id or f"trace-{ordinal:03d}",
        action=action,
        clone_readback=clone_readback(
            ordinal,
            clone_id=clone_id,
            runner_resource_id=runner_resource_id,
            attestation_bundle_digest=attestation_bundle_digest,
        ),
        runtime_artifact=runtime,
    )


def raw_trial_set(trials: tuple[RawTrialEnvelope, ...] | None = None) -> RawTrialSet:
    return RawTrialSet(
        wire_schema="assurance-lab.benchmark.raw-trial-set/v1",
        scenario_id=DETECTION_SCENARIO_ID,
        spec_digest=digest("detection-spec"),
        trials=trials or tuple(raw_trial(index) for index in range(1, 49)),
    )


def supported_vector() -> SemanticVector:
    return SemanticVector(
        target=ClaimDisposition.SUPPORTED,
        compensator=ClaimDisposition.NOT_EXERCISED,
        path=ClaimDisposition.SUPPORTED,
        benign=ClaimDisposition.NOT_EXERCISED,
        baseline=BaselineDisposition.PASS,
        residual=ResidualDisposition.TARGET_EFFECTIVE,
    )


def refuted_vector() -> SemanticVector:
    return SemanticVector(
        target=ClaimDisposition.REFUTED,
        compensator=ClaimDisposition.SUPPORTED,
        path=ClaimDisposition.REFUTED,
        benign=ClaimDisposition.NOT_EXERCISED,
        baseline=BaselineDisposition.PASS,
        residual=ResidualDisposition.MASKED_TARGET_FAILURE,
    )


def non_repeatable_vector() -> SemanticVector:
    return SemanticVector(
        target=ClaimDisposition.NON_REPEATABLE,
        compensator=ClaimDisposition.NON_REPEATABLE,
        path=ClaimDisposition.NON_REPEATABLE,
        benign=ClaimDisposition.NON_REPEATABLE,
        baseline=BaselineDisposition.NON_REPEATABLE,
        residual=ResidualDisposition.NON_REPEATABLE,
    )


def unresolved_vector() -> SemanticVector:
    return SemanticVector(
        target=ClaimDisposition.INDETERMINATE,
        compensator=ClaimDisposition.INDETERMINATE,
        path=ClaimDisposition.INDETERMINATE,
        benign=ClaimDisposition.INDETERMINATE,
        baseline=BaselineDisposition.INDETERMINATE,
        residual=ResidualDisposition.UNRESOLVED,
    )


def semantic_trial(
    cell_number: int,
    replicate: int,
    *,
    semantics: SemanticVector | None = None,
    issues: tuple[NormalizedIssue, ...] = (),
) -> TrialSemanticResult:
    ordinal = (cell_number - 1) * 3 + replicate
    spec_digest = digest("detection-spec")
    cell_key = f"cell-{cell_number:02d}"
    trial_key = canonical_trial_key(
        spec_digest=spec_digest,
        cell_key=cell_key,
        block="block-1",
        replicate=replicate,
    )
    action_artifact = OpaqueArtifactReference(
        schema_name="assurance-lab.action/v1",
        artifact_digest=digest(f"semantic-action-{ordinal}"),
    )
    runtime_artifact = OpaqueArtifactReference(
        schema_name="assurance-lab.runtime-observation/v1",
        artifact_digest=digest(f"semantic-runtime-{ordinal}"),
    )
    lineage_body = {
        "mode": "single-trial",
        "lineage_schema": "assurance-lab.benchmark.single-trial-lineage/v1",
        "subject_trial_key": trial_key,
        "action_artifact": action_artifact.model_dump(mode="json"),
        "runtime_artifact": runtime_artifact.model_dump(mode="json"),
    }
    return TrialSemanticResult(
        scenario_id=DETECTION_SCENARIO_ID,
        spec_digest=spec_digest,
        trial_key=trial_key,
        cell_key=cell_key,
        block="block-1",
        replicate=replicate,
        ordinal=ordinal,
        trace_id=f"semantic-trace-{ordinal:03d}",
        clone_unique_instance_id=f"semantic-clone-{ordinal:03d}",
        clone_readback_digest=digest(f"semantic-readback-{ordinal}"),
        attestation_bundle_digest=digest(f"semantic-attestation-{ordinal}"),
        runner_resource_id="shared-sqlite-runner",
        lineage=SingleTrialSemanticLineage.model_validate(
            {
                **lineage_body,
                "lineage_digest": canonical_digest(lineage_body),
            },
            strict=True,
        ),
        semantics=semantics or supported_vector(),
        issues=issues,
    )


def agreement_for(
    trials: tuple[TrialSemanticResult, TrialSemanticResult, TrialSemanticResult],
) -> ReplicateAgreement:
    semantic_digests = tuple(
        sorted({canonical_digest(trial.semantics.model_dump(mode="json")) for trial in trials})
    )
    return ReplicateAgreement(
        disposition=(
            AgreementDisposition.AGREED
            if len(semantic_digests) == 1
            else AgreementDisposition.NON_REPEATABLE
        ),
        semantic_digests=semantic_digests,
        divergent_trial_keys=(
            () if len(semantic_digests) == 1 else tuple(sorted(trial.trial_key for trial in trials))
        ),
    )


def semantic_cell(
    cell_number: int,
    *,
    trial_vectors: tuple[SemanticVector, SemanticVector, SemanticVector] | None = None,
    aggregate: SemanticVector | None = None,
    agreement: ReplicateAgreement | None = None,
) -> CellSemanticResult:
    vectors = trial_vectors or (
        supported_vector(),
        supported_vector(),
        supported_vector(),
    )
    trials = tuple(
        semantic_trial(cell_number, replicate, semantics=vectors[replicate - 1])
        for replicate in range(1, 4)
    )
    typed_trials = (trials[0], trials[1], trials[2])
    return CellSemanticResult(
        scenario_id=DETECTION_SCENARIO_ID,
        spec_digest=digest("detection-spec"),
        cell_key=f"cell-{cell_number:02d}",
        trials=typed_trials,
        agreement=agreement or agreement_for(typed_trials),
        semantics=aggregate or vectors[0],
    )


def scenario_result(
    scenario_id: ScenarioId,
    *,
    raw_trial_set_digest: str | None = None,
) -> ScenarioSemanticResult:
    scenario_spec_digest = digest(f"{scenario_id}-spec")
    cells: list[CellSemanticResult] = []
    for cell_number in range(1, 17):
        stored = semantic_cell(cell_number).model_dump(mode="python")
        stored["scenario_id"] = scenario_id
        stored["spec_digest"] = scenario_spec_digest
        for trial in stored["trials"]:
            ordinal = trial["ordinal"]
            trial["scenario_id"] = scenario_id
            trial["spec_digest"] = scenario_spec_digest
            trial["trial_key"] = canonical_trial_key(
                spec_digest=scenario_spec_digest,
                cell_key=trial["cell_key"],
                block=trial["block"],
                replicate=trial["replicate"],
            )
            trial["trace_id"] = f"{scenario_id}-trace-{ordinal}"
            trial["clone_unique_instance_id"] = f"{scenario_id}-clone-{ordinal}"
            trial["clone_readback_digest"] = digest(f"{scenario_id}-clone-readback-{ordinal}")
            trial["attestation_bundle_digest"] = digest(f"{scenario_id}-attestation-{ordinal}")
            action_artifact = OpaqueArtifactReference(
                schema_name="assurance-lab.action/v1",
                artifact_digest=digest(f"{scenario_id}-action-{ordinal}"),
            )
            runtime_artifact = OpaqueArtifactReference(
                schema_name="assurance-lab.runtime-observation/v1",
                artifact_digest=digest(f"{scenario_id}-runtime-{ordinal}"),
            )
            if scenario_id == BENCHMARK_SCENARIO_IDS[0]:
                cell_number = (ordinal - 1) // 3 + 1
                pair_cell_number = cell_number + 1 if cell_number % 2 == 1 else cell_number - 1
                pair_trial_key = canonical_trial_key(
                    spec_digest=scenario_spec_digest,
                    cell_key=f"cell-{pair_cell_number:02d}",
                    block=trial["block"],
                    replicate=trial["replicate"],
                )
                if cell_number % 2 == 1:
                    attack_trial_key = trial["trial_key"]
                    benign_trial_key = pair_trial_key
                else:
                    attack_trial_key = pair_trial_key
                    benign_trial_key = trial["trial_key"]
                pair_number = (min(cell_number, pair_cell_number) + 1) // 2
                attack_action = OpaqueArtifactReference(
                    schema_name="assurance-lab.recovery-export-action/v1",
                    artifact_digest=digest(
                        f"{scenario_id}-attack-action-{pair_number}"
                    ),
                )
                benign_action = OpaqueArtifactReference(
                    schema_name="assurance-lab.recovery-export-action/v1",
                    artifact_digest=digest(
                        f"{scenario_id}-benign-action-{pair_number}"
                    ),
                )
                attack_runtime = OpaqueArtifactReference(
                    schema_name="assurance-lab.runtime-observation/v1",
                    artifact_digest=digest(f"{scenario_id}-runtime-{attack_trial_key}"),
                )
                benign_runtime = OpaqueArtifactReference(
                    schema_name="assurance-lab.runtime-observation/v1",
                    artifact_digest=digest(f"{scenario_id}-runtime-{benign_trial_key}"),
                )
                lifecycle_proof = OpaqueArtifactReference(
                    schema_name="assurance-lab.recovery-lifecycle-proof/v1",
                    artifact_digest=digest(f"{scenario_id}-lifecycle-proof"),
                )
                lineage_body = {
                    "mode": "matched-pair",
                    "lineage_schema": ("assurance-lab.benchmark.matched-pair-lineage/v1"),
                    "subject_trial_key": trial["trial_key"],
                    "attack_trial_key": attack_trial_key,
                    "benign_trial_key": benign_trial_key,
                    "attack_action_artifact": attack_action.model_dump(mode="json"),
                    "benign_action_artifact": benign_action.model_dump(mode="json"),
                    "attack_runtime_artifact": attack_runtime.model_dump(mode="json"),
                    "benign_runtime_artifact": benign_runtime.model_dump(mode="json"),
                    "shared_lifecycle_proof": lifecycle_proof.model_dump(mode="json"),
                }
                trial["lineage"] = MatchedPairSemanticLineage.model_validate(
                    {
                        **lineage_body,
                        "lineage_digest": canonical_digest(lineage_body),
                    },
                    strict=True,
                )
            else:
                lineage_body = {
                    "mode": "single-trial",
                    "lineage_schema": ("assurance-lab.benchmark.single-trial-lineage/v1"),
                    "subject_trial_key": trial["trial_key"],
                    "action_artifact": action_artifact.model_dump(mode="json"),
                    "runtime_artifact": runtime_artifact.model_dump(mode="json"),
                }
                trial["lineage"] = SingleTrialSemanticLineage.model_validate(
                    {
                        **lineage_body,
                        "lineage_digest": canonical_digest(lineage_body),
                    },
                    strict=True,
                )
        cells.append(CellSemanticResult.model_validate(stored))
    return ScenarioSemanticResult(
        scenario_id=scenario_id,
        spec_digest=scenario_spec_digest,
        raw_trial_set_digest=raw_trial_set_digest or digest(f"{scenario_id}-raw"),
        cells=tuple(cells),
    )


def benchmark_semantic_result(
    scenarios: tuple[ScenarioSemanticResult, ...] | None = None,
    *,
    issues: tuple[NormalizedIssue, ...] = (),
) -> BenchmarkSemanticResult:
    return BenchmarkSemanticResult(
        wire_schema="assurance-lab.benchmark.semantic-result/v1",
        benchmark_id="fixed-lifecycle-v1",
        benchmark_version="1.0.0",
        evaluator_id="reference-evaluator",
        evaluator_digest=digest("reference-evaluator"),
        scenarios=scenarios
        or tuple(scenario_result(scenario_id) for scenario_id in BENCHMARK_SCENARIO_IDS),
        issues=issues,
    )


def corruption_receipt(number: int = 1) -> CorruptionReceipt:
    return CorruptionReceipt(
        wire_schema="assurance-lab.benchmark.corruption-receipt/v1",
        corruption_id=f"C{number:02d}",
        source_bundle_digest=digest(f"source-{number}"),
        corrupted_bundle_digest=digest(f"corrupted-{number}"),
        target_artifact_path="records/runtime.jsonl",
        target_record_key=f"trial-{number:03d}",
        target_field_path="/observed",
        before_digest=digest(f"before-{number}"),
        after_digest=digest(f"after-{number}"),
        manifest_rebuilt=False,
        mutation_spec_digest=digest(f"mutation-spec-{number}"),
        verifier_receipt_digest=digest(f"verifier-receipt-{number}"),
    )


def indexed_corruption_corpus() -> IndexedCorruptionCorpus:
    scenario_entries = tuple(
        ScenarioIndexEntry(
            scenario_id=scenario_id,
            spec_digest=digest(f"{scenario_id}-spec"),
            source_bundle_digest=digest(f"{scenario_id}-bundle"),
            raw_trial_set_digest=digest(f"{scenario_id}-raw"),
            semantic_result_digest=digest(f"{scenario_id}-semantic"),
            cell_count=16,
            trial_count=48,
        )
        for scenario_id in BENCHMARK_SCENARIO_IDS
    )
    source_digest = next(
        entry.source_bundle_digest
        for entry in scenario_entries
        if entry.scenario_id == DETECTION_SCENARIO_ID
    )
    receipts = tuple(
        CorruptionReceipt(
            **{
                **corruption_receipt(number).model_dump(mode="python"),
                "source_bundle_digest": source_digest,
            }
        )
        for number in range(1, 21)
    )
    corruptions = tuple(
        CorruptionIndexEntry(
            corruption_id=receipt.corruption_id,
            source_scenario_id=DETECTION_SCENARIO_ID,
            source_bundle_digest=receipt.source_bundle_digest,
            corrupted_bundle_digest=receipt.corrupted_bundle_digest,
            receipt_digest=canonical_digest(receipt.model_dump(mode="json")),
        )
        for receipt in receipts
    )
    index = BenchmarkIndex(
        wire_schema="assurance-lab.benchmark.index/v1",
        benchmark_id="fixed-lifecycle-v1",
        benchmark_version="1.0.0",
        corpus_digest=digest("corpus"),
        semantic_result_digest=digest("semantic"),
        scenario_count=3,
        cell_count=48,
        trial_count=144,
        replicates_per_cell=3,
        corruption_count=20,
        scenarios=scenario_entries,
        corruptions=corruptions,
    )
    return IndexedCorruptionCorpus(
        wire_schema="assurance-lab.benchmark.indexed-corruption-corpus/v1",
        index=index,
        receipts=receipts,
    )


def _assert_wire_field_is_required(
    model_type: type[PydanticBaseModel],
    instance: PydanticBaseModel,
    field_name: str,
) -> None:
    document = json.loads(instance.model_dump_json())
    del document[field_name]

    with pytest.raises(ValidationError) as caught:
        model_type.model_validate_json(json.dumps(document))

    assert any(
        error["loc"] == (field_name,) and error["type"] == "missing"
        for error in caught.value.errors()
    )


def test_wire_discriminators_are_never_inferred_when_absent() -> None:
    trial = raw_trial(1)
    corpus = indexed_corruption_corpus()
    cases: tuple[tuple[type[PydanticBaseModel], PydanticBaseModel, str], ...] = (
        (CloneReadback, trial.clone_readback, "readback_schema"),
        (FrozenActionBinding, trial.action, "binding_schema"),
        (RawTrialEnvelope, trial, "wire_schema"),
        (RawTrialSet, raw_trial_set(), "wire_schema"),
        (BenchmarkSemanticResult, benchmark_semantic_result(), "wire_schema"),
        (CorruptionReceipt, corpus.receipts[0], "wire_schema"),
        (BenchmarkIndex, corpus.index, "wire_schema"),
        (IndexedCorruptionCorpus, corpus, "wire_schema"),
    )

    for model_type, instance, field_name in cases:
        _assert_wire_field_is_required(model_type, instance, field_name)


def test_positive_recovery_semantics_cannot_claim_one_trial_as_pair_evidence() -> None:
    document = semantic_trial(1, 1).model_dump(mode="python")
    document["scenario_id"] = BENCHMARK_SCENARIO_IDS[0]

    with pytest.raises(ValidationError, match="matched-pair lineage"):
        TrialSemanticResult.model_validate(document, strict=True)


def test_recovery_raw_trial_cannot_omit_its_lifecycle_proof_reference() -> None:
    document = raw_trial(1).model_dump(mode="python")
    document["scenario_id"] = BENCHMARK_SCENARIO_IDS[0]

    with pytest.raises(ValidationError, match="shared lifecycle proof"):
        RawTrialEnvelope.model_validate(document, strict=True)


def test_recovery_lineage_cannot_be_reused_for_another_trial() -> None:
    result = scenario_result(BENCHMARK_SCENARIO_IDS[0])
    first, second = result.cells[0].trials[:2]
    document = second.model_dump(mode="python")
    document["lineage"] = first.lineage.model_dump(mode="python")

    with pytest.raises(ValidationError, match="lineage subject"):
        TrialSemanticResult.model_validate(document, strict=True)


def test_declared_wire_counts_are_never_inferred_when_absent() -> None:
    index = indexed_corruption_corpus().index
    scenario = index.scenarios[0]
    for field_name in ("cell_count", "trial_count"):
        _assert_wire_field_is_required(ScenarioIndexEntry, scenario, field_name)
    for field_name in (
        "scenario_count",
        "cell_count",
        "trial_count",
        "replicates_per_cell",
        "corruption_count",
    ):
        _assert_wire_field_is_required(BenchmarkIndex, index, field_name)


@pytest.mark.parametrize("duplicate", ["trial", "trace", "clone"])
def test_raw_trial_set_rejects_duplicate_lineage_identities(duplicate: str) -> None:
    trials = [raw_trial(index) for index in range(1, 49)]
    if duplicate == "trial":
        trials[1] = trials[0]
    elif duplicate == "trace":
        trials[1] = raw_trial(2, trace_id=trials[0].trace_id)
    else:
        trials[1] = raw_trial(
            2,
            clone_id=trials[0].clone_readback.unique_instance_id,
        )

    expected = "trial keys" if duplicate == "trial" else duplicate
    with pytest.raises(ValidationError, match=expected):
        raw_trial_set(tuple(trials))


def test_trial_key_preserves_compiler_identity_and_rejects_delimiter_injection() -> None:
    spec_digest = digest("compiler-spec")
    expected = (
        "sha256:"
        + hashlib.sha256("\0".join((spec_digest, "cell-01", "block-1", "1")).encode()).hexdigest()
    )
    assert (
        canonical_trial_key(
            spec_digest=spec_digest,
            cell_key="cell-01",
            block="block-1",
            replicate=1,
        )
        == expected
    )

    for coordinates in (
        {
            "spec_digest": f"{spec_digest}\0cell-01",
            "cell_key": "block-1",
            "block": "1",
        },
        {
            "spec_digest": spec_digest,
            "cell_key": "cell-01\0block-1",
            "block": "1",
        },
        {
            "spec_digest": spec_digest,
            "cell_key": "cell-01",
            "block": "block-1\0" + "1",
        },
    ):
        with pytest.raises(ValueError, match="compiler-owned trial coordinates"):
            canonical_trial_key(
                **coordinates,
                replicate=1,
            )


def test_raw_wire_exposes_only_strict_opaque_artifact_references() -> None:
    valid = raw_trial(1).model_dump(mode="python")
    valid["selector"] = {"target": "effective"}
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RawTrialEnvelope.model_validate(valid)

    valid = raw_trial(1).model_dump(mode="python")
    valid["action_payload"] = {"input": "attack", "target": "effective"}
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RawTrialEnvelope.model_validate(valid)

    valid = raw_trial(1).model_dump(mode="python")
    valid["runtime_artifact"]["selector"] = {"target": "effective"}
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RawTrialEnvelope.model_validate(valid)

    valid = raw_trial(1).model_dump(mode="python")
    valid["action"]["artifact"]["producer_factors"] = {
        "input": "attack",
        "target": "effective",
        "compensator": "on",
        "sham": False,
    }
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RawTrialEnvelope.model_validate(valid)


def test_raw_wire_binds_opaque_action_to_frozen_spec_and_trial() -> None:
    valid = raw_trial(1).model_dump(mode="python")
    valid["action"]["binding_digest"] = digest("producer-relabelled-binding")
    with pytest.raises(ValidationError, match="binding_digest"):
        RawTrialEnvelope.model_validate(valid)


def test_raw_trial_set_requires_exactly_sixteen_cells_with_three_replicates() -> None:
    raw_trial_set()

    with pytest.raises(ValidationError):
        raw_trial_set(tuple(raw_trial(index) for index in range(1, 48)))

    trials = [raw_trial(index) for index in range(1, 49)]
    trials[-1] = raw_trial(48, cell_key="cell-01")
    with pytest.raises(ValidationError):
        raw_trial_set(tuple(trials))


def test_raw_trial_set_allows_shared_runner_but_rejects_attestation_reuse() -> None:
    shared_runner_trials = tuple(
        raw_trial(index, runner_resource_id="shared-sqlite-runner") for index in range(1, 49)
    )
    result = raw_trial_set(shared_runner_trials)
    assert {trial.clone_readback.runner_resource_id for trial in result.trials} == {
        "shared-sqlite-runner"
    }

    reused = list(shared_runner_trials)
    reused[1] = raw_trial(
        2,
        runner_resource_id="shared-sqlite-runner",
        attestation_bundle_digest=reused[0].clone_readback.attestation_bundle_digest,
    )
    with pytest.raises(ValidationError, match="attestation"):
        raw_trial_set(tuple(reused))


def test_raw_trial_set_rejects_runtime_artifact_reuse_across_trials() -> None:
    trials = [raw_trial(index) for index in range(1, 49)]
    trials[1] = raw_trial(
        2,
        runtime_artifact_digest=trials[0].runtime_artifact.artifact_digest,
    )

    with pytest.raises(ValidationError, match="runtime artifact digests"):
        raw_trial_set(tuple(trials))


def test_raw_trial_set_rejects_relabelled_trial_key_and_mixed_blocks() -> None:
    with pytest.raises(ValidationError, match="trial_key"):
        raw_trial(1, trial_key=digest("producer-authored-relabel"))

    trials = list(raw_trial(index) for index in range(1, 49))
    trials[1] = raw_trial(2, block="different-runner-block")
    with pytest.raises(ValidationError, match="one declared runner block"):
        raw_trial_set(tuple(trials))


def test_two_matching_replicates_cannot_outvote_one_divergent_replicate() -> None:
    vectors = (supported_vector(), supported_vector(), refuted_vector())
    trials = tuple(
        semantic_trial(1, replicate, semantics=vectors[replicate - 1]) for replicate in range(1, 4)
    )
    typed_trials = (trials[0], trials[1], trials[2])
    digests = tuple(
        sorted(
            {canonical_digest(trial.semantics.model_dump(mode="json")) for trial in typed_trials}
        )
    )

    false_agreement = ReplicateAgreement(
        disposition=AgreementDisposition.NON_REPEATABLE,
        semantic_digests=digests,
        divergent_trial_keys=tuple(sorted(trial.trial_key for trial in typed_trials)),
    )
    with pytest.raises(ValidationError, match="majority-vote"):
        semantic_cell(
            1,
            trial_vectors=vectors,
            agreement=false_agreement,
            aggregate=supported_vector(),
        )

    result = semantic_cell(
        1,
        trial_vectors=vectors,
        agreement=false_agreement,
        aggregate=non_repeatable_vector(),
    )
    assert result.agreement.disposition == AgreementDisposition.NON_REPEATABLE
    assert result.semantics.target == ClaimDisposition.NON_REPEATABLE


def test_negative_trial_and_cell_issues_cannot_coexist_with_positive_semantics() -> None:
    issue = NormalizedIssue(
        code="missing-runtime-readback",
        disposition=IssueDisposition.INDETERMINATE,
        subject_path="/runtime_payload",
    )
    with pytest.raises(ValidationError, match="positive semantics"):
        semantic_trial(1, 1, issues=(issue,))

    trials = tuple(semantic_trial(1, replicate) for replicate in range(1, 4))
    agreement = agreement_for((trials[0], trials[1], trials[2]))
    with pytest.raises(ValidationError, match="positive semantics"):
        CellSemanticResult(
            scenario_id=DETECTION_SCENARIO_ID,
            spec_digest=digest("detection-spec"),
            cell_key="cell-01",
            trials=trials,
            agreement=agreement,
            semantics=supported_vector(),
            issues=(issue,),
        )


def test_scenario_issues_are_bound_to_trials_and_suppress_affected_positive_cell() -> None:
    scenario = scenario_result(DETECTION_SCENARIO_ID)
    trial_key = scenario.cells[0].trials[0].trial_key
    issue = NormalizedIssue(
        code="rejected-runtime-readback",
        disposition=IssueDisposition.REJECTED,
        subject_path="/cells/0/trials/0",
        related_trial_keys=(trial_key,),
    )
    with pytest.raises(ValidationError, match="positive semantics"):
        ScenarioSemanticResult(
            scenario_id=scenario.scenario_id,
            spec_digest=scenario.spec_digest,
            raw_trial_set_digest=scenario.raw_trial_set_digest,
            cells=scenario.cells,
            issues=(issue,),
        )

    unrelated = issue.model_copy(update={"related_trial_keys": (digest("unrelated"),)})
    with pytest.raises(ValidationError, match="outside the scenario"):
        ScenarioSemanticResult(
            scenario_id=scenario.scenario_id,
            spec_digest=scenario.spec_digest,
            raw_trial_set_digest=scenario.raw_trial_set_digest,
            cells=scenario.cells,
            issues=(unrelated,),
        )


def _cell_with_positive_first_trial_and_suppressed_aggregate(
    cell_number: int,
) -> CellSemanticResult:
    vectors = (supported_vector(), unresolved_vector(), unresolved_vector())
    trials = tuple(
        semantic_trial(cell_number, replicate, semantics=vectors[replicate - 1])
        for replicate in range(1, 4)
    )
    typed_trials = (trials[0], trials[1], trials[2])
    return CellSemanticResult(
        scenario_id=DETECTION_SCENARIO_ID,
        spec_digest=digest("detection-spec"),
        cell_key=f"cell-{cell_number:02d}",
        trials=typed_trials,
        agreement=agreement_for(typed_trials),
        semantics=non_repeatable_vector(),
    )


def test_cell_issue_suppresses_the_exact_related_trial_not_only_aggregate() -> None:
    cell = _cell_with_positive_first_trial_and_suppressed_aggregate(1)
    issue = NormalizedIssue(
        code="rejected-runtime-readback",
        disposition=IssueDisposition.REJECTED,
        subject_path="/trials/0",
        related_trial_keys=(cell.trials[0].trial_key,),
    )
    with pytest.raises(ValidationError, match="positive semantics"):
        CellSemanticResult.model_validate(
            {
                **cell.model_dump(mode="python"),
                "issues": (issue,),
            }
        )


def test_scenario_issue_suppresses_the_exact_related_trial_not_only_aggregate() -> None:
    cells = (
        _cell_with_positive_first_trial_and_suppressed_aggregate(1),
        *(semantic_cell(index) for index in range(2, 17)),
    )
    issue = NormalizedIssue(
        code="rejected-runtime-readback",
        disposition=IssueDisposition.REJECTED,
        subject_path="/cells/0/trials/0",
        related_trial_keys=(cells[0].trials[0].trial_key,),
    )
    with pytest.raises(ValidationError, match="positive semantics"):
        ScenarioSemanticResult(
            scenario_id=DETECTION_SCENARIO_ID,
            spec_digest=digest("detection-spec"),
            raw_trial_set_digest=digest("raw-trial-set"),
            cells=cells,
            issues=(issue,),
        )


def _scenario_with_positive_first_trial_and_suppressed_aggregate(
    scenario: ScenarioSemanticResult,
) -> ScenarioSemanticResult:
    stored = scenario.model_dump(mode="python")
    first = stored["cells"][0]
    first["trials"][1]["semantics"] = unresolved_vector().model_dump(mode="python")
    first["trials"][2]["semantics"] = unresolved_vector().model_dump(mode="python")
    typed_trials = tuple(TrialSemanticResult.model_validate(trial) for trial in first["trials"])
    first["agreement"] = agreement_for(
        (typed_trials[0], typed_trials[1], typed_trials[2])
    ).model_dump(mode="python")
    first["semantics"] = non_repeatable_vector().model_dump(mode="python")
    return ScenarioSemanticResult.model_validate(stored)


def test_benchmark_issue_suppresses_the_exact_related_trial_not_only_aggregate() -> None:
    baseline = benchmark_semantic_result()
    first_scenario = _scenario_with_positive_first_trial_and_suppressed_aggregate(
        baseline.scenarios[0]
    )
    issue = NormalizedIssue(
        code="rejected-runtime-readback",
        disposition=IssueDisposition.REJECTED,
        subject_path="/scenarios/0/cells/0/trials/0",
        related_trial_keys=(first_scenario.cells[0].trials[0].trial_key,),
    )
    with pytest.raises(ValidationError, match="positive semantics"):
        benchmark_semantic_result(
            (first_scenario, baseline.scenarios[1], baseline.scenarios[2]),
            issues=(issue,),
        )


def test_scenario_result_requires_sixteen_complete_cells() -> None:
    cells = tuple(semantic_cell(index) for index in range(1, 17))
    result = ScenarioSemanticResult(
        scenario_id=DETECTION_SCENARIO_ID,
        spec_digest=digest("detection-spec"),
        raw_trial_set_digest=digest("raw-trial-set"),
        cells=cells,
    )
    assert len(result.cells) == 16
    assert sum(len(cell.trials) for cell in result.cells) == 48

    with pytest.raises(ValidationError):
        ScenarioSemanticResult(
            scenario_id=DETECTION_SCENARIO_ID,
            spec_digest=digest("detection-spec"),
            raw_trial_set_digest=digest("raw-trial-set"),
            cells=cells[:-1],
        )


def test_issue_order_is_canonical_not_producer_chosen() -> None:
    later = NormalizedIssue(
        code="z-last",
        disposition=IssueDisposition.REJECTED,
        subject_path="/trials/2",
    )
    earlier = NormalizedIssue(
        code="a-first",
        disposition=IssueDisposition.INDETERMINATE,
        subject_path="/trials/1",
    )
    with pytest.raises(ValidationError, match="canonical order"):
        semantic_trial(
            1,
            1,
            semantics=unresolved_vector(),
            issues=(later, earlier),
        )

    ordered = semantic_trial(
        1,
        1,
        semantics=unresolved_vector(),
        issues=(earlier, later),
    )
    assert ordered.issues == (earlier, later)


def test_benchmark_freezes_exact_scenario_set_and_global_lineage() -> None:
    result = benchmark_semantic_result()
    assert tuple(scenario.scenario_id for scenario in result.scenarios) == (BENCHMARK_SCENARIO_IDS)

    arbitrary = tuple(
        scenario.model_copy(update={"scenario_id": replacement})
        for scenario, replacement in zip(
            result.scenarios,
            ("alpha", "beta", "gamma"),
            strict=True,
        )
    )
    with pytest.raises(ValidationError):
        benchmark_semantic_result(arbitrary)

    duplicate_raw_set = result.scenarios[1].model_copy(
        update={"raw_trial_set_digest": result.scenarios[0].raw_trial_set_digest}
    )
    with pytest.raises(ValidationError, match="raw trial sets"):
        benchmark_semantic_result((result.scenarios[0], duplicate_raw_set, result.scenarios[2]))


def test_corruption_index_is_bound_to_one_of_the_indexed_source_bundles() -> None:
    scenario_entries = tuple(
        ScenarioIndexEntry(
            scenario_id=scenario_id,
            spec_digest=digest(f"{scenario_id}-spec"),
            source_bundle_digest=digest(f"{scenario_id}-bundle"),
            raw_trial_set_digest=digest(f"{scenario_id}-raw"),
            semantic_result_digest=digest(f"{scenario_id}-semantic"),
            cell_count=16,
            trial_count=48,
        )
        for scenario_id in BENCHMARK_SCENARIO_IDS
    )
    corruptions = tuple(
        CorruptionIndexEntry(
            corruption_id=f"C{number:02d}",
            source_scenario_id=DETECTION_SCENARIO_ID,
            source_bundle_digest=next(
                entry.source_bundle_digest
                for entry in scenario_entries
                if entry.scenario_id == DETECTION_SCENARIO_ID
            ),
            corrupted_bundle_digest=digest(f"corrupted-{number}"),
            receipt_digest=digest(f"receipt-{number}"),
        )
        for number in range(1, 21)
    )
    BenchmarkIndex(
        wire_schema="assurance-lab.benchmark.index/v1",
        benchmark_id="fixed-lifecycle-v1",
        benchmark_version="1.0.0",
        corpus_digest=digest("corpus"),
        semantic_result_digest=digest("semantic"),
        scenario_count=3,
        cell_count=48,
        trial_count=144,
        replicates_per_cell=3,
        corruption_count=20,
        scenarios=scenario_entries,
        corruptions=corruptions,
    )

    unrelated = list(corruptions)
    unrelated[0] = unrelated[0].model_copy(
        update={"source_bundle_digest": digest("unrelated-source")}
    )
    with pytest.raises(ValidationError, match="indexed scenario bundle"):
        BenchmarkIndex(
            wire_schema="assurance-lab.benchmark.index/v1",
            benchmark_id="fixed-lifecycle-v1",
            benchmark_version="1.0.0",
            corpus_digest=digest("corpus"),
            semantic_result_digest=digest("semantic"),
            scenario_count=3,
            cell_count=48,
            trial_count=144,
            replicates_per_cell=3,
            corruption_count=20,
            scenarios=scenario_entries,
            corruptions=tuple(unrelated),
        )


def test_corrupted_bundle_cannot_equal_any_indexed_source_bundle() -> None:
    scenario_entries = tuple(
        ScenarioIndexEntry(
            scenario_id=scenario_id,
            spec_digest=digest(f"{scenario_id}-spec"),
            source_bundle_digest=digest(f"{scenario_id}-bundle"),
            raw_trial_set_digest=digest(f"{scenario_id}-raw"),
            semantic_result_digest=digest(f"{scenario_id}-semantic"),
            cell_count=16,
            trial_count=48,
        )
        for scenario_id in BENCHMARK_SCENARIO_IDS
    )
    corruptions = tuple(
        CorruptionIndexEntry(
            corruption_id=f"C{number:02d}",
            source_scenario_id=DETECTION_SCENARIO_ID,
            source_bundle_digest=next(
                entry.source_bundle_digest
                for entry in scenario_entries
                if entry.scenario_id == DETECTION_SCENARIO_ID
            ),
            corrupted_bundle_digest=(
                scenario_entries[0].source_bundle_digest
                if number == 1
                else digest(f"corrupted-{number}")
            ),
            receipt_digest=digest(f"receipt-{number}"),
        )
        for number in range(1, 21)
    )
    with pytest.raises(ValidationError, match="must not equal any source"):
        BenchmarkIndex(
            wire_schema="assurance-lab.benchmark.index/v1",
            benchmark_id="fixed-lifecycle-v1",
            benchmark_version="1.0.0",
            corpus_digest=digest("corpus"),
            semantic_result_digest=digest("semantic"),
            scenario_count=3,
            cell_count=48,
            trial_count=144,
            replicates_per_cell=3,
            corruption_count=20,
            scenarios=scenario_entries,
            corruptions=corruptions,
        )


def test_corruption_corpus_cross_binds_every_receipt_to_its_index_entry() -> None:
    scenario_entries = tuple(
        ScenarioIndexEntry(
            scenario_id=scenario_id,
            spec_digest=digest(f"{scenario_id}-spec"),
            source_bundle_digest=digest(f"{scenario_id}-bundle"),
            raw_trial_set_digest=digest(f"{scenario_id}-raw"),
            semantic_result_digest=digest(f"{scenario_id}-semantic"),
            cell_count=16,
            trial_count=48,
        )
        for scenario_id in BENCHMARK_SCENARIO_IDS
    )
    source_digest = next(
        entry.source_bundle_digest
        for entry in scenario_entries
        if entry.scenario_id == DETECTION_SCENARIO_ID
    )
    receipts = tuple(
        CorruptionReceipt(
            wire_schema="assurance-lab.benchmark.corruption-receipt/v1",
            corruption_id=f"C{number:02d}",
            source_bundle_digest=source_digest,
            corrupted_bundle_digest=digest(f"corrupted-{number}"),
            target_artifact_path="records/runtime.jsonl",
            target_record_key=f"trial-{number:03d}",
            target_field_path="/observed",
            before_digest=digest(f"before-{number}"),
            after_digest=digest(f"after-{number}"),
            manifest_rebuilt=False,
            mutation_spec_digest=digest(f"mutation-spec-{number}"),
            verifier_receipt_digest=digest(f"verifier-receipt-{number}"),
        )
        for number in range(1, 21)
    )
    corruptions = tuple(
        CorruptionIndexEntry(
            corruption_id=receipt.corruption_id,
            source_scenario_id=DETECTION_SCENARIO_ID,
            source_bundle_digest=receipt.source_bundle_digest,
            corrupted_bundle_digest=receipt.corrupted_bundle_digest,
            receipt_digest=canonical_digest(receipt.model_dump(mode="json")),
        )
        for receipt in receipts
    )
    index = BenchmarkIndex(
        wire_schema="assurance-lab.benchmark.index/v1",
        benchmark_id="fixed-lifecycle-v1",
        benchmark_version="1.0.0",
        corpus_digest=digest("corpus"),
        semantic_result_digest=digest("semantic"),
        scenario_count=3,
        cell_count=48,
        trial_count=144,
        replicates_per_cell=3,
        corruption_count=20,
        scenarios=scenario_entries,
        corruptions=corruptions,
    )
    IndexedCorruptionCorpus(
        wire_schema="assurance-lab.benchmark.indexed-corruption-corpus/v1",
        index=index,
        receipts=receipts,
    )

    mismatched = list(receipts)
    mismatched[0] = mismatched[0].model_copy(
        update={"corrupted_bundle_digest": digest("different-corrupted-bundle")}
    )
    with pytest.raises(ValidationError, match="exact receipt"):
        IndexedCorruptionCorpus(
            wire_schema="assurance-lab.benchmark.indexed-corruption-corpus/v1",
            index=index,
            receipts=tuple(mismatched),
        )


@pytest.mark.parametrize("pointer", ["/valid/~0tilde/~1slash", "/"])
def test_corruption_receipt_accepts_canonical_json_pointers(pointer: str) -> None:
    CorruptionReceipt(
        wire_schema="assurance-lab.benchmark.corruption-receipt/v1",
        corruption_id="C01",
        source_bundle_digest=digest("source"),
        corrupted_bundle_digest=digest("corrupted"),
        target_artifact_path="records/runtime.jsonl",
        target_record_key="trial-001",
        target_field_path=pointer,
        before_digest=digest("before"),
        after_digest=digest("after"),
        manifest_rebuilt=False,
        mutation_spec_digest=digest("mutation-spec"),
        verifier_receipt_digest=digest("verifier-receipt"),
    )


@pytest.mark.parametrize("pointer", ["/bad~escape", "/also~2bad", "/~~01"])
def test_corruption_receipt_rejects_noncanonical_json_pointer_escape(
    pointer: str,
) -> None:
    with pytest.raises(ValidationError, match="JSON Pointer"):
        CorruptionReceipt(
            wire_schema="assurance-lab.benchmark.corruption-receipt/v1",
            corruption_id="C01",
            source_bundle_digest=digest("source"),
            corrupted_bundle_digest=digest("corrupted"),
            target_artifact_path="records/runtime.jsonl",
            target_record_key="trial-001",
            target_field_path=pointer,
            before_digest=digest("before"),
            after_digest=digest("after"),
            manifest_rebuilt=False,
            mutation_spec_digest=digest("mutation-spec"),
            verifier_receipt_digest=digest("verifier-receipt"),
        )


@pytest.mark.parametrize(
    "path",
    [
        ".",
        "..",
        "records/./runtime.jsonl",
        "records/../runtime.jsonl",
        "records//runtime.jsonl",
        "records/runtime.jsonl/",
        "/records/runtime.jsonl",
        r"records\runtime.jsonl",
        "records/\0runtime.jsonl",
        "records/\nruntime.jsonl",
        "records/\u202eruntime.jsonl",
        "records/résumé.jsonl",
        f"records/{'x' * 256}.jsonl",
        "x/" * 512 + "runtime.jsonl",
    ],
)
def test_corruption_receipt_rejects_nonportable_artifact_paths(path: str) -> None:
    document = corruption_receipt().model_dump(mode="python")
    document["target_artifact_path"] = path

    with pytest.raises(ValidationError, match="target_artifact_path"):
        CorruptionReceipt.model_validate(document)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("target_record_key", "trial-001\nforged"),
        ("target_record_key", "trial-001\u2066forged"),
        ("target_record_key", "x" * 513),
        ("target_field_path", "/observed\n/forged"),
        ("target_field_path", "/observed\u200b"),
        ("target_field_path", "/" + "x" * 2_048),
    ],
)
def test_corruption_receipt_rejects_unsafe_or_oversized_locator_text(
    field_name: str,
    value: str,
) -> None:
    document = corruption_receipt().model_dump(mode="python")
    document[field_name] = value

    with pytest.raises(ValidationError):
        CorruptionReceipt.model_validate(document)


@pytest.mark.parametrize(
    "trace_id",
    [
        "trace-001\nFORGED",
        "trace-001\u202eFORGED",
        "trace-001\u200b",
        "x" * 2_000_000,
    ],
)
def test_runtime_identity_rejects_controls_bidi_and_unbounded_input(
    trace_id: str,
) -> None:
    with pytest.raises((ValidationError, ValueError)):
        raw_trial(1, trace_id=trace_id)


@pytest.mark.parametrize(
    ("clone_id", "runner_resource_id"),
    [
        ("clone-001\nforged", "runner-001"),
        ("clone-001", "runner-001\u2066forged"),
        ("x" * 513, "runner-001"),
        ("clone-001", "x" * 513),
    ],
)
def test_clone_and_runner_identities_are_bounded_and_display_safe(
    clone_id: str,
    runner_resource_id: str,
) -> None:
    with pytest.raises(ValidationError):
        clone_readback(
            1,
            clone_id=clone_id,
            runner_resource_id=runner_resource_id,
        )


@pytest.mark.parametrize(
    "subject_path",
    [
        "/real\n/forged",
        "/real\u2066forged",
        "/real\u2028forged",
        "/" + "x" * 2_048,
    ],
)
def test_issue_subject_path_is_bounded_and_display_safe(subject_path: str) -> None:
    with pytest.raises(ValidationError):
        NormalizedIssue(
            code="unsafe-subject",
            disposition=IssueDisposition.REJECTED,
            subject_path=subject_path,
        )


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("benchmark_id", "benchmark\nforged"),
        ("benchmark_id", "\u202eforged"),
        ("benchmark_id", "x" * 129),
        ("benchmark_version", "1.0.0 forged"),
        ("benchmark_version", "x" * 65),
        ("evaluator_id", "evaluator\u2066forged"),
        ("evaluator_id", "x" * 257),
    ],
)
def test_benchmark_metadata_uses_bounded_portable_identifiers(
    field_name: str,
    value: str,
) -> None:
    document = benchmark_semantic_result().model_dump(mode="python")
    document[field_name] = value

    with pytest.raises(ValidationError):
        BenchmarkSemanticResult.model_validate(document)


@pytest.mark.parametrize("cell_key", ["cell-01\nforged", "cell-\u202e01", "x" * 513])
def test_compiler_cell_identity_is_bounded_portable_text(cell_key: str) -> None:
    with pytest.raises(ValueError, match="compiler-owned trial coordinates"):
        canonical_trial_key(
            spec_digest=digest("compiler-spec"),
            cell_key=cell_key,
            block="block-1",
            replicate=1,
        )
