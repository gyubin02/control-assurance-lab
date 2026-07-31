from __future__ import annotations

import hashlib
import json
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import cast

import pytest
from pydantic import BaseModel, JsonValue, ValidationError

import assurance_lab.benchmark.cab as benchmark_cab_module
from assurance_lab.benchmark import (
    BENCHMARK_JSON_LIMITS,
    BENCHMARK_SCENARIO_IDS,
    FROZEN_CORRUPTION_SPECS,
    AgreementDisposition,
    BaselineDisposition,
    BenchmarkAdmissionError,
    BenchmarkIndex,
    BenchmarkSemanticResult,
    CellSemanticResult,
    ClaimDisposition,
    CloneReadback,
    CorruptionIndexEntry,
    CorruptionReceipt,
    CorruptionVerificationReceipt,
    ExpectedVerifierResult,
    FrozenActionBinding,
    FrozenBenchmarkSpecification,
    FrozenCorruptionSpec,
    FrozenPlan,
    FrozenSpecificationAction,
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
    admit_benchmark_release,
    admit_raw_benchmark,
    benchmark_corpus_digest,
    canonical_digest,
    canonical_model_bytes,
    canonical_trial_key,
    compile_frozen_plan,
    corruption_spec_digest,
    parse_benchmark_bytes,
    replay_frozen_corruption,
    revalidate_benchmark_value,
    verify_benchmark_semantics,
    verify_corruption_corpus,
)
from assurance_lab.benchmark.admission import (
    ResolvedTrialInputs,
    VerifiedArtifactInput,
    _derive_recovery_pairs,
)
from assurance_lab.benchmark.cab import (
    BENCHMARK_PLAN_PATH,
    BENCHMARK_RAW_PATH,
    BENCHMARK_SPEC_PATH,
    BenchmarkCABError,
    decode_snapshot_entries,
    encode_snapshot_entries,
    raw_sha256,
    rebuild_manifest,
    verify_benchmark_cab,
)
from assurance_lab.benchmark.corruption_sources import (
    build_real_corruption_source_corpus,
    copy_real_corruption_members,
)
from assurance_lab.benchmark.models import (
    MatchedPairSemanticLineage,
    SingleTrialSemanticLineage,
)
from assurance_lab.contract import (
    EvidencePolicyRef,
    EvidenceWindow,
    ExperimentContract,
    ExperimentScope,
    TrialPlan,
    compile_experiment,
)
from assurance_lab.evidence.bundle import (
    BundleFile,
    BundleManifest,
    EvaluationRef,
    EvaluatorRef,
    ExperimentRef,
    Sensitivity,
)
from assurance_lab.evidence.canonical import (
    canonical_json_bytes,
)
from assurance_lab.evidence.snapshot import (
    MAX_CAB_SNAPSHOT_BYTES,
    CABSnapshotError,
    capture_cab_snapshot,
    verify_cab_snapshot,
)
from assurance_lab.scenarios.financial_detection_contract import (
    build_financial_detection_contract,
)
from assurance_lab.scenarios.financial_recovery_contract import (
    ATTACK as RECOVERY_ATTACK,
)
from assurance_lab.scenarios.financial_recovery_contract import (
    BENIGN as RECOVERY_BENIGN,
)
from assurance_lab.scenarios.financial_recovery_contract import (
    action_descriptor as recovery_action_descriptor,
)
from assurance_lab.scenarios.financial_recovery_contract import (
    build_financial_recovery_contract,
)
from assurance_lab.scenarios.financial_response_contract import (
    build_financial_response_contract,
)


def _digest_label(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def _digest_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def test_benchmark_uses_the_real_snapshot_codec_for_bundle_first_cabs() -> None:
    repository_root = Path(__file__).resolve().parents[1]
    sealed = capture_cab_snapshot(repository_root / "examples" / "masked-export.cab")

    entries = decode_snapshot_entries(sealed.snapshot_bytes)
    verified = verify_benchmark_cab(
        sealed.snapshot_bytes,
        expected_snapshot_digest=sealed.snapshot_digest,
    )

    assert entries[0][0] == "bundle.json"
    assert entries[1][0].startswith("artifacts/")
    assert [path for path, _payload in entries[1:]] == sorted(
        path for path, _payload in entries[1:]
    )
    assert encode_snapshot_entries(entries) == sealed.snapshot_bytes
    assert verified.entries == entries


def test_benchmark_rejects_oversized_snapshot_before_hashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_hash(_payload: bytes) -> str:
        raise AssertionError("oversized untrusted input reached the digest function")

    monkeypatch.setattr(benchmark_cab_module, "raw_sha256", unexpected_hash)

    with pytest.raises(BenchmarkCABError, match="exceeds the CAB snapshot byte limit"):
        verify_benchmark_cab(
            b"x" * (MAX_CAB_SNAPSHOT_BYTES + 1),
            expected_snapshot_digest=f"sha256:{'0' * 64}",
        )


def _json_bytes(value: JsonValue) -> bytes:
    return canonical_json_bytes(value, limits=BENCHMARK_JSON_LIMITS)


def _model_bytes(value: BaseModel) -> bytes:
    return canonical_json_bytes(
        value.model_dump(mode="json"),
        limits=BENCHMARK_JSON_LIMITS,
    )


def _supported() -> SemanticVector:
    return SemanticVector(
        target=ClaimDisposition.SUPPORTED,
        compensator=ClaimDisposition.NOT_EXERCISED,
        path=ClaimDisposition.SUPPORTED,
        benign=ClaimDisposition.NOT_EXERCISED,
        baseline=BaselineDisposition.PASS,
        residual=ResidualDisposition.TARGET_EFFECTIVE,
    )


class _ReferenceScenarioVerifier:
    evaluator_id = "independent-reference-verifier"
    evaluator_digest = _digest_label("independent-reference-verifier")

    def verify_scenario(
        self,
        *,
        plan: FrozenPlan,
        raw_trial_set: RawTrialSet,
        trial_inputs: tuple[ResolvedTrialInputs, ...],
    ) -> ScenarioSemanticResult:
        assert len(plan.entries) == len(trial_inputs) == 48
        raw_by_trial_key = {trial.trial_key: trial for trial in raw_trial_set.trials}
        inputs_by_trial_key = {trial_input.trial_key: trial_input for trial_input in trial_inputs}
        plan_by_trial_key = {entry.trial_key: entry for entry in plan.entries}
        assert raw_by_trial_key.keys() == plan_by_trial_key.keys() == inputs_by_trial_key.keys()
        for trial_key, raw in raw_by_trial_key.items():
            planned = plan_by_trial_key[trial_key]
            assert (
                raw.ordinal,
                raw.cell_key,
                raw.block,
                raw.replicate,
            ) == (
                planned.ordinal,
                planned.cell_key,
                planned.block,
                planned.replicate,
            )
        for raw in raw_trial_set.trials:
            trial_input = inputs_by_trial_key[raw.trial_key]
            action = json.loads(trial_input.action.canonical_bytes)
            runtime = json.loads(trial_input.runtime.canonical_bytes)
            assert isinstance(action, dict)
            assert action["schema"] == trial_input.action.reference.schema_name
            assert isinstance(runtime, dict)
            assert runtime["schema"] == "assurance-lab.runtime-observation/v1"
            assert runtime["scenario"] == raw.scenario_id
            assert runtime["ordinal"] == raw.ordinal
            if trial_input.expected_matched_pair is None:
                assert trial_input.shared_lifecycle_proof is None
            else:
                proof_input = trial_input.shared_lifecycle_proof
                assert proof_input is not None
                proof = json.loads(proof_input.canonical_bytes)
                assert proof["schema"] == "assurance-lab.recovery-lifecycle-proof/v1"
                assert runtime["lifecycle_proof_digest"] == (proof_input.reference.artifact_digest)
                assert runtime["actual_branch_digest"] == proof["actual_branch_digest"]
                assert runtime["comparison_branch_digest"] == (proof["comparison_branch_digest"])

        vector = _supported()
        trials: list[TrialSemanticResult] = []
        for raw in raw_trial_set.trials:
            trial_input = inputs_by_trial_key[raw.trial_key]
            expected_pair = trial_input.expected_matched_pair
            lineage: SingleTrialSemanticLineage | MatchedPairSemanticLineage
            if expected_pair is None:
                lineage_body: dict[str, JsonValue] = {
                    "mode": "single-trial",
                    "lineage_schema": ("assurance-lab.benchmark.single-trial-lineage/v1"),
                    "subject_trial_key": raw.trial_key,
                    "action_artifact": raw.action.artifact.model_dump(mode="json"),
                    "runtime_artifact": raw.runtime_artifact.model_dump(mode="json"),
                }
                lineage = SingleTrialSemanticLineage.model_validate(
                    {
                        **lineage_body,
                        "lineage_digest": canonical_digest(lineage_body),
                    },
                    strict=True,
                )
            else:
                attack = raw_by_trial_key[expected_pair.attack_trial_key]
                benign = raw_by_trial_key[expected_pair.benign_trial_key]
                assert attack.shared_lifecycle_proof is not None
                lineage_body = {
                    "mode": "matched-pair",
                    "lineage_schema": ("assurance-lab.benchmark.matched-pair-lineage/v1"),
                    "subject_trial_key": raw.trial_key,
                    "attack_trial_key": attack.trial_key,
                    "benign_trial_key": benign.trial_key,
                    "attack_action_artifact": (attack.action.artifact.model_dump(mode="json")),
                    "benign_action_artifact": (benign.action.artifact.model_dump(mode="json")),
                    "attack_runtime_artifact": (attack.runtime_artifact.model_dump(mode="json")),
                    "benign_runtime_artifact": (benign.runtime_artifact.model_dump(mode="json")),
                    "shared_lifecycle_proof": (
                        attack.shared_lifecycle_proof.model_dump(mode="json")
                    ),
                }
                lineage = MatchedPairSemanticLineage.model_validate(
                    {
                        **lineage_body,
                        "lineage_digest": canonical_digest(lineage_body),
                    },
                    strict=True,
                )
            trials.append(
                TrialSemanticResult(
                    scenario_id=raw.scenario_id,
                    spec_digest=raw.spec_digest,
                    trial_key=raw.trial_key,
                    cell_key=raw.cell_key,
                    block=raw.block,
                    replicate=raw.replicate,
                    ordinal=raw.ordinal,
                    trace_id=raw.trace_id,
                    clone_unique_instance_id=raw.clone_readback.unique_instance_id,
                    clone_readback_digest=raw.clone_readback.readback_digest,
                    attestation_bundle_digest=raw.clone_readback.attestation_bundle_digest,
                    runner_resource_id=raw.clone_readback.runner_resource_id,
                    lineage=lineage,
                    semantics=vector,
                )
            )
        semantic_digest = canonical_digest(vector.model_dump(mode="json"))
        trials_by_cell: dict[str, list[TrialSemanticResult]] = {}
        for trial in trials:
            trials_by_cell.setdefault(trial.cell_key, []).append(trial)
        cells = tuple(
            CellSemanticResult(
                scenario_id=raw_trial_set.scenario_id,
                spec_digest=raw_trial_set.spec_digest,
                cell_key=cell_key,
                trials=tuple(
                    sorted(
                        trials_by_cell[cell_key],
                        key=lambda trial: trial.replicate,
                    )
                ),
                agreement=ReplicateAgreement(
                    disposition=AgreementDisposition.AGREED,
                    semantic_digests=(semantic_digest,),
                ),
                semantics=vector,
            )
            for cell_key in sorted(trials_by_cell)
        )
        return ScenarioSemanticResult(
            scenario_id=raw_trial_set.scenario_id,
            spec_digest=raw_trial_set.spec_digest,
            raw_trial_set_digest=_digest_bytes(_model_bytes(raw_trial_set)),
            cells=cells,
        )


def _replace_semantic_trial_lineage(
    result: ScenarioSemanticResult,
    *,
    trial_key: str,
    lineage: MatchedPairSemanticLineage,
) -> ScenarioSemanticResult:
    document = result.model_dump(mode="python")
    changed = 0
    for cell in document["cells"]:
        for trial in cell["trials"]:
            if trial["trial_key"] == trial_key:
                trial["lineage"] = lineage.model_dump(mode="python")
                changed += 1
    assert changed == 1
    return ScenarioSemanticResult.model_validate(document, strict=True)


def _cell_labels(cell_key: str) -> dict[str, str]:
    return dict(component.split("=", maxsplit=1) for component in cell_key.split(";"))


class _ForgedRecoveryLineageVerifier(_ReferenceScenarioVerifier):
    """Return a structurally valid but input-unbound recovery lineage."""

    def __init__(self, mutation: str) -> None:
        self.mutation = mutation

    def verify_scenario(
        self,
        *,
        plan: FrozenPlan,
        raw_trial_set: RawTrialSet,
        trial_inputs: tuple[ResolvedTrialInputs, ...],
    ) -> ScenarioSemanticResult:
        valid = super().verify_scenario(
            plan=plan,
            raw_trial_set=raw_trial_set,
            trial_inputs=trial_inputs,
        )
        if raw_trial_set.scenario_id != BENCHMARK_SCENARIO_IDS[0]:
            return valid

        raw_by_key = {trial.trial_key: trial for trial in raw_trial_set.trials}
        inputs_by_key = {trial_input.trial_key: trial_input for trial_input in trial_inputs}
        subject_input = next(
            trial_input
            for trial_input in trial_inputs
            if trial_input.expected_matched_pair is not None
            and trial_input.trial_key == trial_input.expected_matched_pair.attack_trial_key
        )
        expected = subject_input.expected_matched_pair
        assert expected is not None
        subject = raw_by_key[subject_input.trial_key]
        attack = raw_by_key[expected.attack_trial_key]
        benign = raw_by_key[expected.benign_trial_key]
        proof = attack.shared_lifecycle_proof
        assert proof is not None

        if self.mutation in {"target", "guard", "sham", "replicate"}:
            subject_labels = _cell_labels(subject.cell_key)
            dimension_label = {
                "target": "target",
                "guard": "compensator",
                "sham": "sham",
            }.get(self.mutation)
            candidates = []
            for candidate in raw_trial_set.trials:
                candidate_input = inputs_by_key[candidate.trial_key]
                candidate_pair = candidate_input.expected_matched_pair
                if candidate_pair is None or candidate.trial_key != candidate_pair.benign_trial_key:
                    continue
                labels = _cell_labels(candidate.cell_key)
                same_axes = all(
                    labels[axis] == subject_labels[axis]
                    for axis in ("target", "compensator", "sham")
                    if axis != dimension_label
                )
                changed_axis = (
                    candidate.replicate != subject.replicate
                    if self.mutation == "replicate"
                    else labels[dimension_label] != subject_labels[dimension_label]  # type: ignore[index]
                )
                replicate_matches = (
                    candidate.replicate == subject.replicate
                    if self.mutation != "replicate"
                    else True
                )
                if same_axes and changed_axis and replicate_matches:
                    candidates.append(candidate)
            assert candidates
            benign = candidates[0]

        attack_runtime = attack.runtime_artifact
        benign_runtime = benign.runtime_artifact
        if self.mutation == "swap-actual-comparison":
            attack_runtime, benign_runtime = benign_runtime, attack_runtime
        elif self.mutation == "unreferenced-proof":
            proof = OpaqueArtifactReference(
                schema_name="assurance-lab.recovery-lifecycle-proof/v1",
                artifact_digest=_digest_bytes(
                    _corruption_members(BENCHMARK_SCENARIO_IDS[0])[
                        "records/lifecycle/admitted-receipts.json"
                    ]
                ),
            )
        elif self.mutation == "outside-cab-proof":
            proof = OpaqueArtifactReference(
                schema_name="assurance-lab.recovery-lifecycle-proof/v1",
                artifact_digest=_digest_label("outside-cab-lifecycle-proof"),
            )

        lineage_body: dict[str, JsonValue] = {
            "mode": "matched-pair",
            "lineage_schema": "assurance-lab.benchmark.matched-pair-lineage/v1",
            "subject_trial_key": subject.trial_key,
            "attack_trial_key": attack.trial_key,
            "benign_trial_key": benign.trial_key,
            "attack_action_artifact": attack.action.artifact.model_dump(mode="json"),
            "benign_action_artifact": benign.action.artifact.model_dump(mode="json"),
            "attack_runtime_artifact": attack_runtime.model_dump(mode="json"),
            "benign_runtime_artifact": benign_runtime.model_dump(mode="json"),
            "shared_lifecycle_proof": proof.model_dump(mode="json"),
        }
        forged = MatchedPairSemanticLineage.model_validate(
            {
                **lineage_body,
                "lineage_digest": canonical_digest(lineage_body),
            },
            strict=True,
        )
        return _replace_semantic_trial_lineage(
            valid,
            trial_key=subject.trial_key,
            lineage=forged,
        )


class _ReferenceCorruptionVerifier:
    verifier_id = "independent-corruption-verifier"
    verifier_digest = _digest_label("independent-corruption-verifier")

    def verify_corruption(
        self,
        *,
        source_bundle_bytes: bytes,
        corrupted_bundle_bytes: bytes,
        specification: FrozenCorruptionSpec,
    ) -> CorruptionVerificationReceipt:
        assert source_bundle_bytes != corrupted_bundle_bytes
        disposition = {
            ExpectedVerifierResult.REJECTED: IssueDisposition.REJECTED,
            ExpectedVerifierResult.INDETERMINATE: IssueDisposition.INDETERMINATE,
            ExpectedVerifierResult.CONFLICTING: IssueDisposition.CONFLICTING,
        }[specification.expected_verifier_result]
        return CorruptionVerificationReceipt(
            wire_schema=("assurance-lab.benchmark.corruption-verification-receipt/v1"),
            verifier_id=self.verifier_id,
            verifier_digest=self.verifier_digest,
            corruption_id=specification.corruption_id,
            mutation_spec_digest=corruption_spec_digest(specification),
            source_bundle_digest=_digest_bytes(source_bundle_bytes),
            corrupted_bundle_digest=_digest_bytes(corrupted_bundle_bytes),
            result=specification.expected_verifier_result,
            issues=(
                NormalizedIssue(
                    code=(
                        f"{specification.corruption_id.lower()}-"
                        f"{specification.expected_verifier_result.value}"
                    ),
                    disposition=disposition,
                    subject_path=f"/corruptions/{specification.corruption_id}",
                ),
            ),
        )


class _BundleResolver:
    def __init__(
        self,
        *,
        sources: dict[str, bytes],
        corruptions: dict[str, bytes],
    ) -> None:
        self.sources = sources
        self.corruptions = corruptions
        self.source_resolutions = 0

    def resolve_source_bundle(self, *, scenario_id: str, bundle_digest: str) -> bytes:
        del scenario_id
        self.source_resolutions += 1
        return self.sources[bundle_digest]

    def resolve_corrupted_bundle(
        self,
        *,
        corruption_id: str,
        bundle_digest: str,
    ) -> bytes:
        del corruption_id
        return self.corruptions[bundle_digest]


@dataclass(frozen=True)
class _ScenarioFixture:
    specification: FrozenBenchmarkSpecification
    plan: FrozenPlan
    raw: RawTrialSet
    raw_bytes: bytes
    semantic: ScenarioSemanticResult
    source_bundle: bytes
    source_bundle_digest: str


@dataclass(frozen=True)
class _BenchmarkFixture:
    index: BenchmarkIndex
    index_bytes: bytes
    scenarios: tuple[_ScenarioFixture, _ScenarioFixture, _ScenarioFixture]
    raw_bytes: tuple[bytes, bytes, bytes]
    plans: tuple[FrozenPlan, FrozenPlan, FrozenPlan]
    source_bundles: dict[str, bytes]
    corrupted_bundles: dict[str, bytes]
    receipts: tuple[CorruptionReceipt, ...]
    receipt_bytes: tuple[bytes, ...]
    semantic_result: BenchmarkSemanticResult
    semantic_bytes: bytes


_CONTRACT_BUILDERS = {
    BENCHMARK_SCENARIO_IDS[0]: build_financial_recovery_contract,
    BENCHMARK_SCENARIO_IDS[1]: build_financial_detection_contract,
    BENCHMARK_SCENARIO_IDS[2]: build_financial_response_contract,
}


def _contract(scenario_id: ScenarioId) -> ExperimentContract:
    start = datetime(2026, 7, 29, 0, 0, tzinfo=UTC)
    scope = ExperimentScope(
        scenario_id=scenario_id,
        build_digest=_digest_label(f"{scenario_id}-build"),
        dataset_digest=_digest_label(f"{scenario_id}-dataset"),
        fixture_digest=_digest_label(f"{scenario_id}-fixture"),
        assessment_as_of=start + timedelta(hours=1),
        evidence_window=EvidenceWindow(start=start, end=start + timedelta(hours=2)),
        evidence_policy=EvidencePolicyRef(
            id="benchmark-evidence-v1",
            version="1.0.0",
            digest=_digest_label("benchmark-evidence-v1"),
        ),
    )
    builder = _CONTRACT_BUILDERS[scenario_id]
    return builder(
        scope=scope,
        plan=TrialPlan(
            blocks=("fresh-clone-a",),
            replicates=3,
            order_seed=f"{scenario_id}-published-seed",
        ),
    )


@lru_cache(maxsize=1)
def _real_corruption_members() -> dict[ScenarioId, dict[str, bytes]]:
    with tempfile.TemporaryDirectory(prefix="assurance-benchmark-corruption-") as directory:
        corpus = build_real_corruption_source_corpus(Path(directory) / "corpus")
        return {
            scenario_id: copy_real_corruption_members(corpus, scenario_id)
            for scenario_id in BENCHMARK_SCENARIO_IDS
        }


def _corruption_members(scenario_id: ScenarioId) -> dict[str, bytes]:
    """Embed actual runtime/writer members, never mutation-shaped toy records."""

    return dict(_real_corruption_members()[scenario_id])


def _snapshot(
    *,
    scenario_id: ScenarioId,
    spec_digest: str,
    members: dict[str, bytes],
) -> bytes:
    descriptors = [
        BundleFile(
            path=path,
            sha256=hashlib.sha256(payload).hexdigest(),
            size=len(payload),
            media_type=("application/x-ndjson" if path.endswith(".jsonl") else "application/json"),
            role="benchmark-release-input",
            sensitivity=Sensitivity.SYNTHETIC,
            required_for=["benchmark-release"],
        )
        for path, payload in sorted(members.items())
    ]
    manifest = BundleManifest(
        media_type="application/vnd.control-assurance.bundle.v1+json",
        schema_version="1.0.0",
        profile="integrity-only",
        created_at="2026-07-29T00:00:00.000000Z",
        as_of="2026-07-29T00:00:00.000000Z",
        experiment=ExperimentRef(
            id=scenario_id,
            spec_version="3.0.0",
            spec_digest=spec_digest,
        ),
        evaluation=EvaluationRef(
            policy_id="benchmark-admission-v1",
            policy_digest=_digest_label("benchmark-admission-v1"),
            evaluator=EvaluatorRef(
                name="benchmark-fixture",
                version="1.0.0",
                source_revision="fixture",
                image_digest=None,
            ),
        ),
        parent_bundles=[],
        files=descriptors,
    )
    entries = (
        ("bundle.json", canonical_json_bytes(manifest.model_dump(mode="json"))),
        *tuple(sorted(members.items())),
    )
    snapshot = encode_snapshot_entries(entries)
    verify_benchmark_cab(snapshot, expected_snapshot_digest=raw_sha256(snapshot))
    return snapshot


def _frozen_specification(
    contract: ExperimentContract,
    action_reference: OpaqueArtifactReference,
    *,
    action_references_by_cell: dict[str, OpaqueArtifactReference] | None = None,
) -> FrozenBenchmarkSpecification:
    compiled = compile_experiment(contract)
    actions = tuple(
        FrozenSpecificationAction(
            ordinal=planned.ordinal,
            trial_key=planned.key,
            cell_key=planned.cell_key,
            block=planned.block,
            replicate=planned.replicate,
            action=(
                action_reference
                if action_references_by_cell is None
                else action_references_by_cell[planned.cell_key]
            ),
        )
        for planned in compiled.planned_trials
    )
    specification_body = {
        "wire_schema": "assurance-lab.benchmark.compiled-spec/v1",
        "scenario_id": contract.id,
        "contract": contract.model_dump(mode="json"),
        "actions": [action.model_dump(mode="json") for action in actions],
        "spec_digest": compiled.spec_digest,
    }
    return FrozenBenchmarkSpecification(
        wire_schema="assurance-lab.benchmark.compiled-spec/v1",
        scenario_id=cast(ScenarioId, contract.id),
        contract=contract,
        actions=actions,
        spec_digest=compiled.spec_digest,
        benchmark_specification_digest=canonical_digest(specification_body),
    )


def _scenario_fixture(
    scenario_id: ScenarioId,
    verifier: _ReferenceScenarioVerifier,
) -> _ScenarioFixture:
    contract = _contract(scenario_id)
    compiled_contract = compile_experiment(contract)
    action_payloads: dict[str, bytes]
    action_references_by_cell: dict[str, OpaqueArtifactReference] | None
    if scenario_id == BENCHMARK_SCENARIO_IDS[0]:
        attack_bytes = _json_bytes(recovery_action_descriptor(RECOVERY_ATTACK))
        benign_bytes = _json_bytes(recovery_action_descriptor(RECOVERY_BENIGN))
        action_payloads = {
            _digest_bytes(attack_bytes): attack_bytes,
            _digest_bytes(benign_bytes): benign_bytes,
        }
        action_references_by_cell = {}
        for cell in compiled_contract.cells:
            payload = (
                attack_bytes
                if cell.selector.input == contract.profile.input.attack
                else benign_bytes
            )
            reference = OpaqueArtifactReference(
                schema_name="assurance-lab.recovery-export-action/v1",
                artifact_digest=_digest_bytes(payload),
            )
            action_references_by_cell[cell.key] = reference
        action_reference = next(iter(action_references_by_cell.values()))
    else:
        action_bytes = _json_bytes(
            {
                "scenario": scenario_id,
                "schema": "assurance-lab.action/v1",
            }
        )
        action_reference = OpaqueArtifactReference(
            schema_name="assurance-lab.action/v1",
            artifact_digest=_digest_bytes(action_bytes),
        )
        action_payloads = {action_reference.artifact_digest: action_bytes}
        action_references_by_cell = None
    specification = _frozen_specification(
        contract,
        action_reference,
        action_references_by_cell=action_references_by_cell,
    )
    plan = compile_frozen_plan(specification)

    members: dict[str, bytes] = {
        **{
            f"records/objects/{digest[7:]}.json": payload
            for digest, payload in action_payloads.items()
        },
        **_corruption_members(scenario_id),
    }
    lifecycle_proof_reference: OpaqueArtifactReference | None = None
    lifecycle_proof_bytes: bytes | None = None
    if scenario_id == BENCHMARK_SCENARIO_IDS[0]:
        lifecycle_proof_bytes = _json_bytes(
            {
                "actual_branch_digest": _digest_label("recovery-actual-branch"),
                "comparison_branch_digest": _digest_label("recovery-matched-comparison-branch"),
                "schema": "assurance-lab.recovery-lifecycle-proof/v1",
            }
        )
        lifecycle_proof_reference = OpaqueArtifactReference(
            schema_name="assurance-lab.recovery-lifecycle-proof/v1",
            artifact_digest=_digest_bytes(lifecycle_proof_bytes),
        )
        members[f"records/objects/{lifecycle_proof_reference.artifact_digest[7:]}.json"] = (
            lifecycle_proof_bytes
        )
    trials: list[RawTrialEnvelope] = []
    for entry in plan.entries:
        runtime_document: JsonValue = {
            "ordinal": entry.ordinal,
            "scenario": scenario_id,
            "schema": "assurance-lab.runtime-observation/v1",
        }
        if lifecycle_proof_reference is not None:
            assert lifecycle_proof_bytes is not None
            lifecycle_document = json.loads(lifecycle_proof_bytes)
            assert isinstance(runtime_document, dict)
            runtime_document.update(
                {
                    "actual_branch_digest": lifecycle_document["actual_branch_digest"],
                    "comparison_branch_digest": lifecycle_document["comparison_branch_digest"],
                    "lifecycle_proof_digest": (lifecycle_proof_reference.artifact_digest),
                }
            )
        runtime_bytes = _json_bytes(runtime_document)
        runtime_digest = _digest_bytes(runtime_bytes)
        members[f"records/objects/{runtime_digest[7:]}.json"] = runtime_bytes

        attestation_bytes = _json_bytes(
            {
                "ordinal": entry.ordinal,
                "scenario": scenario_id,
                "wire_schema": "assurance-lab.attestation/v1",
            }
        )
        attestation_digest = _digest_bytes(attestation_bytes)
        members[f"records/objects/{attestation_digest[7:]}.json"] = attestation_bytes
        binding_body: dict[str, JsonValue] = {
            "binding_schema": "assurance-lab.benchmark.frozen-action-binding/v1",
            "spec_digest": specification.spec_digest,
            "trial_key": entry.trial_key,
            "artifact": entry.action.model_dump(mode="json"),
        }
        binding = FrozenActionBinding(
            binding_schema="assurance-lab.benchmark.frozen-action-binding/v1",
            spec_digest=specification.spec_digest,
            trial_key=entry.trial_key,
            artifact=entry.action,
            binding_digest=canonical_digest(binding_body),
        )
        readback_body: dict[str, JsonValue] = {
            "readback_schema": "assurance-lab.clone-readback/v1",
            "unique_instance_id": f"{scenario_id}-clone-{entry.ordinal:03d}",
            "runner_resource_id": f"{scenario_id}-runner",
            "base_snapshot_digest": _digest_label(f"{scenario_id}-snapshot"),
            "covariate_digest": _digest_label(f"{scenario_id}-covariate-{entry.ordinal:03d}"),
            "attestation_bundle_digest": attestation_digest,
        }
        clone = CloneReadback(
            readback_schema="assurance-lab.clone-readback/v1",
            unique_instance_id=f"{scenario_id}-clone-{entry.ordinal:03d}",
            runner_resource_id=f"{scenario_id}-runner",
            base_snapshot_digest=_digest_label(f"{scenario_id}-snapshot"),
            covariate_digest=_digest_label(f"{scenario_id}-covariate-{entry.ordinal:03d}"),
            attestation_bundle_digest=attestation_digest,
            readback_digest=canonical_digest(readback_body),
        )
        trials.append(
            RawTrialEnvelope(
                wire_schema="assurance-lab.benchmark.raw-trial/v1",
                scenario_id=scenario_id,
                spec_digest=specification.spec_digest,
                trial_key=entry.trial_key,
                cell_key=entry.cell_key,
                block=entry.block,
                replicate=entry.replicate,
                ordinal=entry.ordinal,
                trace_id=f"{scenario_id}-trace-{entry.ordinal:03d}",
                action=binding,
                clone_readback=clone,
                runtime_artifact=OpaqueArtifactReference(
                    schema_name="assurance-lab.runtime-observation/v1",
                    artifact_digest=runtime_digest,
                ),
                shared_lifecycle_proof=lifecycle_proof_reference,
            )
        )
    raw = RawTrialSet(
        wire_schema="assurance-lab.benchmark.raw-trial-set/v1",
        scenario_id=scenario_id,
        spec_digest=specification.spec_digest,
        trials=tuple(trials),
    )
    raw_bytes = _model_bytes(raw)
    members[BENCHMARK_SPEC_PATH] = _model_bytes(specification)
    members[BENCHMARK_PLAN_PATH] = _model_bytes(plan)
    members[BENCHMARK_RAW_PATH] = raw_bytes
    source_bundle = _snapshot(
        scenario_id=scenario_id,
        spec_digest=specification.spec_digest,
        members=members,
    )
    expected_pairs = (
        _derive_recovery_pairs(
            specification=specification,
            plan=plan,
            raw=raw,
        )
        if scenario_id == BENCHMARK_SCENARIO_IDS[0]
        else {}
    )
    trial_inputs = tuple(
        ResolvedTrialInputs(
            trial_key=trial.trial_key,
            action=VerifiedArtifactInput(
                reference=trial.action.artifact,
                canonical_bytes=members[
                    f"records/objects/{trial.action.artifact.artifact_digest[7:]}.json"
                ],
            ),
            runtime=VerifiedArtifactInput(
                reference=trial.runtime_artifact,
                canonical_bytes=members[
                    f"records/objects/{trial.runtime_artifact.artifact_digest[7:]}.json"
                ],
            ),
            shared_lifecycle_proof=(
                None
                if trial.shared_lifecycle_proof is None
                else VerifiedArtifactInput(
                    reference=trial.shared_lifecycle_proof,
                    canonical_bytes=members[
                        f"records/objects/{trial.shared_lifecycle_proof.artifact_digest[7:]}.json"
                    ],
                )
            ),
            expected_matched_pair=expected_pairs.get(trial.trial_key),
        )
        for trial in raw.trials
    )
    semantic = verifier.verify_scenario(
        plan=plan,
        raw_trial_set=raw,
        trial_inputs=trial_inputs,
    )
    return _ScenarioFixture(
        specification=specification,
        plan=plan,
        raw=raw,
        raw_bytes=raw_bytes,
        semantic=semantic,
        source_bundle=source_bundle,
        source_bundle_digest=_digest_bytes(source_bundle),
    )


def test_frozen_response_plan_uses_compiler_identity_and_seeded_order() -> None:
    contract = _contract(BENCHMARK_SCENARIO_IDS[2])
    compiled = compile_experiment(contract)
    action_reference = OpaqueArtifactReference(
        schema_name="assurance-lab.action/v1",
        artifact_digest=_digest_label("response-compiler-action"),
    )
    specification = _frozen_specification(contract, action_reference)
    plan = compile_frozen_plan(specification)

    assert specification.spec_digest == compiled.spec_digest
    assert specification.benchmark_specification_digest != compiled.spec_digest
    assert tuple(
        (
            entry.ordinal,
            entry.trial_key,
            entry.cell_key,
            entry.block,
            entry.replicate,
        )
        for entry in plan.entries
    ) == tuple(
        (
            planned.ordinal,
            planned.key,
            planned.cell_key,
            planned.block,
            planned.replicate,
        )
        for planned in compiled.planned_trials
    )
    assert tuple(entry.trial_key for entry in plan.entries) != tuple(
        planned.key
        for planned in sorted(
            compiled.planned_trials,
            key=lambda planned: (
                planned.cell_key,
                planned.block,
                planned.replicate,
            ),
        )
    )


def test_changed_order_seed_recompiles_to_its_own_exact_plan() -> None:
    base = _contract(BENCHMARK_SCENARIO_IDS[2])
    plans: list[tuple[str, ...]] = []
    spec_digests: list[str] = []
    for order_seed in ("response-seed-alpha", "response-seed-bravo"):
        document = base.model_dump(mode="python")
        document["plan"]["order_seed"] = order_seed
        contract = ExperimentContract.model_validate(document, strict=True)
        compiled = compile_experiment(contract)
        specification = _frozen_specification(
            contract,
            OpaqueArtifactReference(
                schema_name="assurance-lab.action/v1",
                artifact_digest=_digest_label(f"action-{order_seed}"),
            ),
        )
        plan = compile_frozen_plan(specification)

        assert tuple(entry.trial_key for entry in plan.entries) == tuple(
            planned.key for planned in compiled.planned_trials
        )
        assert tuple(entry.ordinal for entry in plan.entries) == tuple(
            planned.ordinal for planned in compiled.planned_trials
        )
        plans.append(tuple(entry.trial_key for entry in plan.entries))
        spec_digests.append(specification.spec_digest)

    assert plans[0] != plans[1]
    assert spec_digests[0] != spec_digests[1]


def test_caller_authored_canonical_action_order_is_rejected() -> None:
    contract = _contract(BENCHMARK_SCENARIO_IDS[2])
    compiled = compile_experiment(contract)
    action_reference = OpaqueArtifactReference(
        schema_name="assurance-lab.action/v1",
        artifact_digest=_digest_label("canonical-order-action"),
    )
    caller_order = sorted(
        compiled.planned_trials,
        key=lambda planned: (
            planned.cell_key,
            planned.block,
            planned.replicate,
        ),
    )
    assert tuple(planned.key for planned in caller_order) != tuple(
        planned.key for planned in compiled.planned_trials
    )
    actions = tuple(
        FrozenSpecificationAction(
            ordinal=ordinal,
            trial_key=planned.key,
            cell_key=planned.cell_key,
            block=planned.block,
            replicate=planned.replicate,
            action=action_reference,
        )
        for ordinal, planned in enumerate(caller_order, start=1)
    )
    body = {
        "wire_schema": "assurance-lab.benchmark.compiled-spec/v1",
        "scenario_id": contract.id,
        "contract": contract.model_dump(mode="json"),
        "actions": [action.model_dump(mode="json") for action in actions],
        "spec_digest": compiled.spec_digest,
    }

    with pytest.raises(ValidationError, match="compiler-planned trial order"):
        FrozenBenchmarkSpecification(
            wire_schema="assurance-lab.benchmark.compiled-spec/v1",
            scenario_id=BENCHMARK_SCENARIO_IDS[2],
            contract=contract,
            actions=actions,
            spec_digest=compiled.spec_digest,
            benchmark_specification_digest=canonical_digest(body),
        )


def test_wrapper_content_address_cannot_replace_compiler_spec_digest() -> None:
    contract = _contract(BENCHMARK_SCENARIO_IDS[2])
    valid = _frozen_specification(
        contract,
        OpaqueArtifactReference(
            schema_name="assurance-lab.action/v1",
            artifact_digest=_digest_label("outer-fake-action"),
        ),
    )
    document = valid.model_dump(mode="json")
    fake_spec_digest = valid.benchmark_specification_digest
    document["spec_digest"] = fake_spec_digest
    for action in document["actions"]:
        action["trial_key"] = canonical_trial_key(
            spec_digest=fake_spec_digest,
            cell_key=action["cell_key"],
            block=action["block"],
            replicate=action["replicate"],
        )
    document["benchmark_specification_digest"] = canonical_digest(
        {key: value for key, value in document.items() if key != "benchmark_specification_digest"}
    )

    with pytest.raises(
        ValidationError,
        match="experiment compiler spec_digest",
    ):
        FrozenBenchmarkSpecification.model_validate_json(
            canonical_json_bytes(document),
        )


@pytest.fixture(scope="module")
def benchmark_fixture() -> _BenchmarkFixture:
    scenario_verifier = _ReferenceScenarioVerifier()
    values = tuple(
        _scenario_fixture(scenario_id, scenario_verifier) for scenario_id in BENCHMARK_SCENARIO_IDS
    )
    scenarios = (values[0], values[1], values[2])
    semantic_result = BenchmarkSemanticResult(
        wire_schema="assurance-lab.benchmark.semantic-result/v1",
        benchmark_id="fixed-lifecycle-v1",
        benchmark_version="1.0.0",
        evaluator_id=scenario_verifier.evaluator_id,
        evaluator_digest=scenario_verifier.evaluator_digest,
        scenarios=tuple(scenario.semantic for scenario in scenarios),
    )
    semantic_bytes = _model_bytes(semantic_result)
    scenario_entries = tuple(
        ScenarioIndexEntry(
            scenario_id=scenario.raw.scenario_id,
            spec_digest=scenario.raw.spec_digest,
            source_bundle_digest=scenario.source_bundle_digest,
            raw_trial_set_digest=_digest_bytes(scenario.raw_bytes),
            semantic_result_digest=_digest_bytes(_model_bytes(scenario.semantic)),
            cell_count=16,
            trial_count=48,
        )
        for scenario in scenarios
    )

    corruption_verifier = _ReferenceCorruptionVerifier()
    source_by_scenario = {
        scenario.raw.scenario_id: verify_benchmark_cab(
            scenario.source_bundle,
            expected_snapshot_digest=scenario.source_bundle_digest,
        )
        for scenario in scenarios
    }
    corrupted_bundles: dict[str, bytes] = {}
    receipts: list[CorruptionReceipt] = []
    receipt_bytes: list[bytes] = []
    corruption_entries: list[CorruptionIndexEntry] = []
    for specification in FROZEN_CORRUPTION_SPECS:
        source = source_by_scenario[specification.source_scenario_id]
        replay = replay_frozen_corruption(source, specification)
        corrupted_bundles[replay.corrupted_bundle_digest] = replay.corrupted_bundle_bytes
        verifier_receipt = corruption_verifier.verify_corruption(
            source_bundle_bytes=source.snapshot_bytes,
            corrupted_bundle_bytes=replay.corrupted_bundle_bytes,
            specification=specification,
        )
        receipt = CorruptionReceipt(
            wire_schema="assurance-lab.benchmark.corruption-receipt/v1",
            corruption_id=specification.corruption_id,
            source_bundle_digest=source.snapshot_digest,
            corrupted_bundle_digest=replay.corrupted_bundle_digest,
            target_artifact_path=specification.target_artifact_path,
            target_record_key=specification.target_record_key,
            target_field_path=specification.target_field_path,
            before_digest=_digest_bytes(replay.before_bytes),
            after_digest=_digest_bytes(replay.after_bytes),
            mutation_spec_digest=corruption_spec_digest(specification),
            verifier_receipt_digest=_digest_bytes(canonical_model_bytes(verifier_receipt)),
            manifest_rebuilt=replay.manifest_rebuilt,
        )
        receipt_wire = _model_bytes(receipt)
        receipts.append(receipt)
        receipt_bytes.append(receipt_wire)
        corruption_entries.append(
            CorruptionIndexEntry(
                corruption_id=specification.corruption_id,
                source_scenario_id=specification.source_scenario_id,
                source_bundle_digest=source.snapshot_digest,
                corrupted_bundle_digest=replay.corrupted_bundle_digest,
                receipt_digest=_digest_bytes(receipt_wire),
            )
        )

    index = BenchmarkIndex(
        wire_schema="assurance-lab.benchmark.index/v1",
        benchmark_id="fixed-lifecycle-v1",
        benchmark_version="1.0.0",
        corpus_digest=_digest_label("pending-corpus"),
        semantic_result_digest=_digest_bytes(semantic_bytes),
        scenario_count=3,
        cell_count=48,
        trial_count=144,
        replicates_per_cell=3,
        corruption_count=20,
        scenarios=scenario_entries,
        corruptions=tuple(corruption_entries),
    )
    index = BenchmarkIndex.model_validate(
        {
            **index.model_dump(mode="python"),
            "corpus_digest": benchmark_corpus_digest(
                index,
                (scenarios[0].plan, scenarios[1].plan, scenarios[2].plan),
            ),
        }
    )
    return _BenchmarkFixture(
        index=index,
        index_bytes=_model_bytes(index),
        scenarios=scenarios,
        raw_bytes=(
            scenarios[0].raw_bytes,
            scenarios[1].raw_bytes,
            scenarios[2].raw_bytes,
        ),
        plans=(scenarios[0].plan, scenarios[1].plan, scenarios[2].plan),
        source_bundles={
            scenario.source_bundle_digest: scenario.source_bundle for scenario in scenarios
        },
        corrupted_bundles=corrupted_bundles,
        receipts=tuple(receipts),
        receipt_bytes=tuple(receipt_bytes),
        semantic_result=semantic_result,
        semantic_bytes=semantic_bytes,
    )


def _resolver(fixture: _BenchmarkFixture) -> _BundleResolver:
    return _BundleResolver(
        sources=dict(fixture.source_bundles),
        corruptions=dict(fixture.corrupted_bundles),
    )


def _replace_cab_member(
    source: bytes,
    *,
    path: str,
    payload: bytes,
) -> bytes:
    entries = dict(decode_snapshot_entries(source))
    entries[path] = payload
    rebuilt = rebuild_manifest(
        tuple(sorted(entries.items())),
        changed_paths=frozenset({path}),
    )
    return encode_snapshot_entries(rebuilt)


def _remove_cab_member(source: bytes, *, path: str) -> bytes:
    entries = dict(decode_snapshot_entries(source))
    del entries[path]
    manifest = BundleManifest.model_validate_json(entries["bundle.json"])
    document = manifest.model_dump(mode="python")
    document["files"] = [
        descriptor for descriptor in document["files"] if descriptor["path"] != path
    ]
    entries["bundle.json"] = canonical_json_bytes(
        BundleManifest.model_validate(document).model_dump(mode="json")
    )
    return encode_snapshot_entries(tuple(sorted(entries.items())))


def _rewire_source_index(
    fixture: _BenchmarkFixture,
    *,
    scenario_id: ScenarioId,
    source_digest: str,
) -> BenchmarkIndex:
    document = fixture.index.model_dump(mode="python")
    for scenario in document["scenarios"]:
        if scenario["scenario_id"] == scenario_id:
            scenario["source_bundle_digest"] = source_digest
    for corruption in document["corruptions"]:
        if corruption["source_scenario_id"] == scenario_id:
            corruption["source_bundle_digest"] = source_digest
    interim = BenchmarkIndex.model_validate(document)
    document["corpus_digest"] = benchmark_corpus_digest(interim, fixture.plans)
    return BenchmarkIndex.model_validate(document)


def test_source_manifest_raw_and_actions_use_compiler_identity(
    benchmark_fixture: _BenchmarkFixture,
) -> None:
    for scenario in benchmark_fixture.scenarios:
        compiled = compile_experiment(scenario.specification.contract)
        verified = verify_benchmark_cab(
            scenario.source_bundle,
            expected_snapshot_digest=scenario.source_bundle_digest,
        )
        manifest_spec_digest = verified.manifest.experiment.spec_digest

        assert scenario.specification.spec_digest == compiled.spec_digest
        assert scenario.plan.spec_digest == compiled.spec_digest
        assert scenario.raw.spec_digest == compiled.spec_digest
        assert manifest_spec_digest == compiled.spec_digest
        planned_by_key = {planned.key: planned for planned in compiled.planned_trials}
        assert {trial.trial_key for trial in scenario.raw.trials} == set(planned_by_key)
        for trial in scenario.raw.trials:
            planned = planned_by_key[trial.trial_key]
            assert trial.action.spec_digest == compiled.spec_digest
            assert trial.action.trial_key == planned.key
            assert (
                trial.ordinal,
                trial.cell_key,
                trial.block,
                trial.replicate,
            ) == (
                planned.ordinal,
                planned.cell_key,
                planned.block,
                planned.replicate,
            )


def test_semantic_lineage_is_joined_by_trial_key_not_tuple_position(
    benchmark_fixture: _BenchmarkFixture,
) -> None:
    response = benchmark_fixture.scenarios[2]
    raw_order = tuple(trial.trial_key for trial in response.raw.trials)
    semantic_cell_order = tuple(
        trial.trial_key for cell in response.semantic.cells for trial in cell.trials
    )
    assert raw_order != semantic_cell_order

    admitted = verify_benchmark_semantics(
        index_bytes=benchmark_fixture.index_bytes,
        raw_trial_set_bytes=benchmark_fixture.raw_bytes,
        semantic_result_bytes=benchmark_fixture.semantic_bytes,
        source_bundle_resolver=_resolver(benchmark_fixture),
        scenario_verifier=_ReferenceScenarioVerifier(),
    )
    assert admitted == benchmark_fixture.semantic_result


@pytest.mark.parametrize("mismatch", ["target", "guard", "sham", "replicate"])
def test_recovery_pair_is_derived_from_frozen_axes_not_producer_lineage(
    benchmark_fixture: _BenchmarkFixture,
    mismatch: str,
) -> None:
    with pytest.raises(BenchmarkAdmissionError, match="exact verifier inputs"):
        verify_benchmark_semantics(
            index_bytes=benchmark_fixture.index_bytes,
            raw_trial_set_bytes=benchmark_fixture.raw_bytes,
            semantic_result_bytes=benchmark_fixture.semantic_bytes,
            source_bundle_resolver=_resolver(benchmark_fixture),
            scenario_verifier=_ForgedRecoveryLineageVerifier(mismatch),
        )


def test_recovery_actual_and_comparison_observations_cannot_be_substituted(
    benchmark_fixture: _BenchmarkFixture,
) -> None:
    with pytest.raises(BenchmarkAdmissionError, match="exact verifier inputs"):
        verify_benchmark_semantics(
            index_bytes=benchmark_fixture.index_bytes,
            raw_trial_set_bytes=benchmark_fixture.raw_bytes,
            semantic_result_bytes=benchmark_fixture.semantic_bytes,
            source_bundle_resolver=_resolver(benchmark_fixture),
            scenario_verifier=_ForgedRecoveryLineageVerifier("swap-actual-comparison"),
        )


@pytest.mark.parametrize(
    "mutation",
    ["unreferenced-proof", "outside-cab-proof"],
)
def test_recovery_lineage_cannot_name_unadmitted_proof_bytes(
    benchmark_fixture: _BenchmarkFixture,
    mutation: str,
) -> None:
    with pytest.raises(BenchmarkAdmissionError, match="exact verifier inputs"):
        verify_benchmark_semantics(
            index_bytes=benchmark_fixture.index_bytes,
            raw_trial_set_bytes=benchmark_fixture.raw_bytes,
            semantic_result_bytes=benchmark_fixture.semantic_bytes,
            source_bundle_resolver=_resolver(benchmark_fixture),
            scenario_verifier=_ForgedRecoveryLineageVerifier(mutation),
        )


def test_recovery_lifecycle_reference_must_resolve_inside_the_same_cab(
    benchmark_fixture: _BenchmarkFixture,
) -> None:
    recovery = benchmark_fixture.scenarios[0]
    proof_digest = recovery.raw.trials[0].shared_lifecycle_proof
    assert proof_digest is not None
    verified = verify_benchmark_cab(
        recovery.source_bundle,
        expected_snapshot_digest=recovery.source_bundle_digest,
    )
    proof_path = next(
        path
        for path, payload in verified.entries
        if path != "bundle.json" and _digest_bytes(payload) == proof_digest.artifact_digest
    )
    stripped = _remove_cab_member(recovery.source_bundle, path=proof_path)
    stripped_digest = _digest_bytes(stripped)
    forged_index = _rewire_source_index(
        benchmark_fixture,
        scenario_id=recovery.raw.scenario_id,
        source_digest=stripped_digest,
    )
    resolver = _resolver(benchmark_fixture)
    resolver.sources[stripped_digest] = stripped

    with pytest.raises(BenchmarkAdmissionError, match="does not contain"):
        admit_raw_benchmark(
            index_bytes=_model_bytes(forged_index),
            raw_trial_set_bytes=benchmark_fixture.raw_bytes,
            source_bundle_resolver=resolver,
        )


def test_bounded_parser_rejects_duplicate_keys_and_oversized_input(
    benchmark_fixture: _BenchmarkFixture,
) -> None:
    receipt = benchmark_fixture.receipts[0]
    wire = _model_bytes(receipt)
    duplicated = wire.replace(
        b'"corruption_id":"C01"',
        b'"corruption_id":"C01","corruption_id":"C20"',
    )
    with pytest.raises(BenchmarkAdmissionError):
        parse_benchmark_bytes(duplicated, CorruptionReceipt)

    oversized = b'{"unknown":"' + b"x" * BENCHMARK_JSON_LIMITS.max_bytes + b'"}'
    with pytest.raises(BenchmarkAdmissionError):
        parse_benchmark_bytes(oversized, CorruptionReceipt)


def test_typed_pydantic_bypass_is_dumped_and_revalidated(
    benchmark_fixture: _BenchmarkFixture,
) -> None:
    invalid = benchmark_fixture.semantic_result.model_copy(
        update={"scenarios": benchmark_fixture.semantic_result.scenarios[:1]}
    )
    with pytest.raises(BenchmarkAdmissionError):
        revalidate_benchmark_value(invalid, BenchmarkSemanticResult)


def test_one_release_admission_closes_semantics_and_all_corruptions(
    benchmark_fixture: _BenchmarkFixture,
) -> None:
    resolver = _resolver(benchmark_fixture)
    admitted = admit_benchmark_release(
        index_bytes=benchmark_fixture.index_bytes,
        raw_trial_set_bytes=benchmark_fixture.raw_bytes,
        semantic_result_bytes=benchmark_fixture.semantic_bytes,
        corruption_receipt_bytes=benchmark_fixture.receipt_bytes,
        source_bundle_resolver=resolver,
        corrupted_bundle_resolver=resolver,
        scenario_verifier=_ReferenceScenarioVerifier(),
        corruption_verifier=_ReferenceCorruptionVerifier(),
    )
    assert len(admitted.raw_corpus.raw_trial_sets) == 3
    assert len(admitted.corruption_corpus.receipts) == 20
    assert admitted.semantic_result == benchmark_fixture.semantic_result
    assert resolver.source_resolutions == 3


def test_raw_and_semantic_boundaries_resolve_the_same_exact_source_cabs(
    benchmark_fixture: _BenchmarkFixture,
) -> None:
    resolver = _resolver(benchmark_fixture)
    raw = admit_raw_benchmark(
        index_bytes=benchmark_fixture.index_bytes,
        raw_trial_set_bytes=benchmark_fixture.raw_bytes,
        source_bundle_resolver=resolver,
    )
    semantic = verify_benchmark_semantics(
        index_bytes=benchmark_fixture.index_bytes,
        raw_trial_set_bytes=benchmark_fixture.raw_bytes,
        semantic_result_bytes=benchmark_fixture.semantic_bytes,
        source_bundle_resolver=resolver,
        scenario_verifier=_ReferenceScenarioVerifier(),
    )
    assert len(raw.raw_trial_sets) == 3
    assert semantic == benchmark_fixture.semantic_result


def test_source_bundle_substitution_is_rejected_by_the_index_digest(
    benchmark_fixture: _BenchmarkFixture,
) -> None:
    resolver = _resolver(benchmark_fixture)
    first_digest = benchmark_fixture.scenarios[0].source_bundle_digest
    resolver.sources[first_digest] = benchmark_fixture.scenarios[1].source_bundle
    with pytest.raises(BenchmarkAdmissionError, match="integrity verification"):
        admit_raw_benchmark(
            index_bytes=benchmark_fixture.index_bytes,
            raw_trial_set_bytes=benchmark_fixture.raw_bytes,
            source_bundle_resolver=resolver,
        )


def test_raw_bytes_must_be_the_manifested_source_member(
    benchmark_fixture: _BenchmarkFixture,
) -> None:
    altered = list(benchmark_fixture.raw_bytes)
    altered[0] += b" "
    with pytest.raises(BenchmarkAdmissionError):
        admit_raw_benchmark(
            index_bytes=benchmark_fixture.index_bytes,
            raw_trial_set_bytes=tuple(altered),
            source_bundle_resolver=_resolver(benchmark_fixture),
        )


def test_same_spec_digest_cannot_name_a_substituted_plan(
    benchmark_fixture: _BenchmarkFixture,
) -> None:
    scenario = benchmark_fixture.scenarios[0]
    document = scenario.plan.model_dump(mode="python")
    document["entries"][0]["action"] = document["entries"][1]["action"]
    document["entries"][0]["action"]["artifact_digest"] = _digest_label("substituted-action")
    substituted = FrozenPlan.model_validate(document)
    forged_cab = _replace_cab_member(
        scenario.source_bundle,
        path=BENCHMARK_PLAN_PATH,
        payload=_model_bytes(substituted),
    )
    forged_digest = _digest_bytes(forged_cab)
    verify_benchmark_cab(forged_cab, expected_snapshot_digest=forged_digest)
    forged_index = _rewire_source_index(
        benchmark_fixture,
        scenario_id=scenario.raw.scenario_id,
        source_digest=forged_digest,
    )
    resolver = _resolver(benchmark_fixture)
    resolver.sources[forged_digest] = forged_cab
    with pytest.raises(BenchmarkAdmissionError, match="recompilation"):
        admit_raw_benchmark(
            index_bytes=_model_bytes(forged_index),
            raw_trial_set_bytes=benchmark_fixture.raw_bytes,
            source_bundle_resolver=resolver,
        )


def test_caller_canonical_plan_order_is_rejected_by_recompilation(
    benchmark_fixture: _BenchmarkFixture,
) -> None:
    scenario = benchmark_fixture.scenarios[2]
    document = scenario.plan.model_dump(mode="python")
    canonical_entries = sorted(
        document["entries"],
        key=lambda entry: (
            entry["cell_key"],
            entry["block"],
            entry["replicate"],
        ),
    )
    assert [entry["trial_key"] for entry in canonical_entries] != [
        entry["trial_key"] for entry in document["entries"]
    ]
    for ordinal, entry in enumerate(canonical_entries, start=1):
        entry["ordinal"] = ordinal
    document["entries"] = tuple(canonical_entries)
    caller_plan = FrozenPlan.model_validate(document, strict=True)
    forged_cab = _replace_cab_member(
        scenario.source_bundle,
        path=BENCHMARK_PLAN_PATH,
        payload=_model_bytes(caller_plan),
    )
    forged_digest = _digest_bytes(forged_cab)
    forged_index = _rewire_source_index(
        benchmark_fixture,
        scenario_id=scenario.raw.scenario_id,
        source_digest=forged_digest,
    )
    resolver = _resolver(benchmark_fixture)
    resolver.sources[forged_digest] = forged_cab

    with pytest.raises(BenchmarkAdmissionError, match="recompilation"):
        admit_raw_benchmark(
            index_bytes=_model_bytes(forged_index),
            raw_trial_set_bytes=benchmark_fixture.raw_bytes,
            source_bundle_resolver=resolver,
        )


def test_manifested_action_and_attestation_members_cannot_be_omitted(
    benchmark_fixture: _BenchmarkFixture,
) -> None:
    scenario = benchmark_fixture.scenarios[0]
    referenced = scenario.raw.trials[0].clone_readback.attestation_bundle_digest
    verified = verify_benchmark_cab(
        scenario.source_bundle,
        expected_snapshot_digest=scenario.source_bundle_digest,
    )
    attestation_path = next(
        path
        for path, payload in verified.entries
        if path != "bundle.json" and _digest_bytes(payload) == referenced
    )
    forged_cab = _remove_cab_member(
        scenario.source_bundle,
        path=attestation_path,
    )
    forged_digest = _digest_bytes(forged_cab)
    verify_benchmark_cab(forged_cab, expected_snapshot_digest=forged_digest)
    forged_index = _rewire_source_index(
        benchmark_fixture,
        scenario_id=scenario.raw.scenario_id,
        source_digest=forged_digest,
    )
    resolver = _resolver(benchmark_fixture)
    resolver.sources[forged_digest] = forged_cab
    with pytest.raises(BenchmarkAdmissionError, match="attestation"):
        admit_raw_benchmark(
            index_bytes=_model_bytes(forged_index),
            raw_trial_set_bytes=benchmark_fixture.raw_bytes,
            source_bundle_resolver=resolver,
        )


def test_standalone_corruption_verification_reopens_the_exact_raw_corpus(
    benchmark_fixture: _BenchmarkFixture,
) -> None:
    document = benchmark_fixture.index.model_dump(mode="python")
    document["corpus_digest"] = _digest_label("self-asserted-corpus")
    forged = BenchmarkIndex.model_validate(document)
    with pytest.raises(BenchmarkAdmissionError, match="cross-binding"):
        verify_corruption_corpus(
            index_bytes=_model_bytes(forged),
            raw_trial_set_bytes=benchmark_fixture.raw_bytes,
            receipt_bytes=benchmark_fixture.receipt_bytes,
            source_bundle_resolver=_resolver(benchmark_fixture),
            corrupted_bundle_resolver=_resolver(benchmark_fixture),
            verifier=_ReferenceCorruptionVerifier(),
        )


def test_frozen_locator_must_exist_in_the_real_source_cab(
    benchmark_fixture: _BenchmarkFixture,
) -> None:
    detection = benchmark_fixture.scenarios[1]
    stripped = _remove_cab_member(
        detection.source_bundle,
        path="records/runtime-observations.jsonl",
    )
    verified = verify_benchmark_cab(
        stripped,
        expected_snapshot_digest=_digest_bytes(stripped),
    )
    with pytest.raises(BenchmarkCABError, match="frozen corruption target"):
        replay_frozen_corruption(verified, FROZEN_CORRUPTION_SPECS[0])


def test_c01_keeps_a_stale_manifest_and_changes_exactly_one_target_byte(
    benchmark_fixture: _BenchmarkFixture,
) -> None:
    detection = benchmark_fixture.scenarios[1]
    source = verify_benchmark_cab(
        detection.source_bundle,
        expected_snapshot_digest=detection.source_bundle_digest,
    )
    replay = replay_frozen_corruption(source, FROZEN_CORRUPTION_SPECS[0])
    assert replay.manifest_rebuilt is False
    assert replay.source_manifest_digest == replay.corrupted_manifest_digest
    with pytest.raises(CABSnapshotError):
        verify_cab_snapshot(replay.corrupted_bundle_bytes)


@pytest.mark.parametrize("corruption_id", ["C02", "C17", "C18"])
def test_rebuild_mutations_produce_a_new_integrity_verified_cab(
    benchmark_fixture: _BenchmarkFixture,
    corruption_id: str,
) -> None:
    specification = FROZEN_CORRUPTION_SPECS[int(corruption_id[1:]) - 1]
    scenario = next(
        item
        for item in benchmark_fixture.scenarios
        if item.raw.scenario_id == specification.source_scenario_id
    )
    source = verify_benchmark_cab(
        scenario.source_bundle,
        expected_snapshot_digest=scenario.source_bundle_digest,
    )
    replay = replay_frozen_corruption(source, specification)
    assert replay.manifest_rebuilt is True
    assert replay.source_manifest_digest != replay.corrupted_manifest_digest
    verify_benchmark_cab(
        replay.corrupted_bundle_bytes,
        expected_snapshot_digest=replay.corrupted_bundle_digest,
    )


class _EnumOnlyVerifier:
    verifier_id = "enum-only"
    verifier_digest = _digest_label("enum-only")

    def verify_corruption(
        self,
        *,
        source_bundle_bytes: bytes,
        corrupted_bundle_bytes: bytes,
        specification: FrozenCorruptionSpec,
    ) -> ExpectedVerifierResult:
        del source_bundle_bytes, corrupted_bundle_bytes
        return specification.expected_verifier_result


def test_plain_verdict_enum_is_not_a_verifier_receipt(
    benchmark_fixture: _BenchmarkFixture,
) -> None:
    with pytest.raises(BenchmarkAdmissionError, match="Pydantic model"):
        verify_corruption_corpus(
            index_bytes=benchmark_fixture.index_bytes,
            raw_trial_set_bytes=benchmark_fixture.raw_bytes,
            receipt_bytes=benchmark_fixture.receipt_bytes,
            source_bundle_resolver=_resolver(benchmark_fixture),
            corrupted_bundle_resolver=_resolver(benchmark_fixture),
            verifier=_EnumOnlyVerifier(),  # type: ignore[arg-type]
        )


class _WrongInputVerifier(_ReferenceCorruptionVerifier):
    def verify_corruption(
        self,
        *,
        source_bundle_bytes: bytes,
        corrupted_bundle_bytes: bytes,
        specification: FrozenCorruptionSpec,
    ) -> CorruptionVerificationReceipt:
        valid = super().verify_corruption(
            source_bundle_bytes=source_bundle_bytes,
            corrupted_bundle_bytes=corrupted_bundle_bytes,
            specification=specification,
        )
        return valid.model_copy(update={"source_bundle_digest": _digest_label("different-source")})


def test_verifier_receipt_must_bind_identity_and_exact_input_digests(
    benchmark_fixture: _BenchmarkFixture,
) -> None:
    with pytest.raises(BenchmarkAdmissionError, match="not bound to the replay"):
        verify_corruption_corpus(
            index_bytes=benchmark_fixture.index_bytes,
            raw_trial_set_bytes=benchmark_fixture.raw_bytes,
            receipt_bytes=benchmark_fixture.receipt_bytes,
            source_bundle_resolver=_resolver(benchmark_fixture),
            corrupted_bundle_resolver=_resolver(benchmark_fixture),
            verifier=_WrongInputVerifier(),
        )


def test_corrupted_bundle_resolver_cannot_substitute_other_bytes(
    benchmark_fixture: _BenchmarkFixture,
) -> None:
    resolver = _resolver(benchmark_fixture)
    first = benchmark_fixture.receipts[0]
    resolver.corruptions[first.corrupted_bundle_digest] = benchmark_fixture.scenarios[
        0
    ].source_bundle
    with pytest.raises(BenchmarkAdmissionError, match="wrong digest"):
        verify_corruption_corpus(
            index_bytes=benchmark_fixture.index_bytes,
            raw_trial_set_bytes=benchmark_fixture.raw_bytes,
            receipt_bytes=benchmark_fixture.receipt_bytes,
            source_bundle_resolver=resolver,
            corrupted_bundle_resolver=resolver,
            verifier=_ReferenceCorruptionVerifier(),
        )
