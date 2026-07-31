"""Build the executable 144-trial public lifecycle benchmark.

The generator executes the real synthetic financial runtimes.  It does not
manufacture generic ``runtime-observation`` documents or copy verdict fields
into the benchmark result:

* detection observations are lossless renderings of
  :class:`FinancialDetectionRuntimeResult`;
* response observations are the raw SQLite records emitted by
  :class:`FinancialResponseExperimentRunner`;
* recovery observations are lossless renderings of
  :class:`FinancialRecoveryRuntimeResult`, with the local absolute CAB path
  replaced by the content address of the embedded producer snapshot; and
* the primary semantic result is recomputed with the public scenario
  assessment functions.

All resources are synthetic and in-process.  The clone attestations below bind
SQLite readbacks and exact producer artifacts.  They make no claim about a
virtual-machine clone, hardware attestation, external custody, or production
execution.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, is_dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Final, cast

from pydantic import BaseModel

import assurance_lab.scenarios.financial_recovery_runtime as recovery_runtime_module
from assurance_lab.benchmark.cab import (
    BENCHMARK_PLAN_PATH,
    BENCHMARK_RAW_PATH,
    BENCHMARK_SPEC_PATH,
    VerifiedBenchmarkCAB,
    verify_benchmark_cab,
)
from assurance_lab.benchmark.corruption_sources import (
    RealCorruptionSourceCorpus,
    build_real_corruption_source_corpus,
    detection_corruption_compiled,
    response_corruption_compiled,
)
from assurance_lab.benchmark.models import (
    BENCHMARK_SCENARIO_IDS,
    DETECTION_SCENARIO_ID,
    RECOVERY_SCENARIO_ID,
    RESPONSE_SCENARIO_ID,
    AgreementDisposition,
    BaselineDisposition,
    BenchmarkSemanticResult,
    CellSemanticResult,
    ClaimDisposition,
    CloneReadback,
    FrozenActionBinding,
    FrozenBenchmarkSpecification,
    FrozenPlan,
    FrozenSpecificationAction,
    MatchedPairSemanticLineage,
    OpaqueArtifactReference,
    RawTrialEnvelope,
    RawTrialSet,
    ReplicateAgreement,
    ResidualDisposition,
    ScenarioId,
    ScenarioSemanticResult,
    SemanticVector,
    SingleTrialSemanticLineage,
    TrialSemanticResult,
    canonical_digest,
    compile_frozen_plan,
)
from assurance_lab.contract import (
    CellSelector,
    CompiledExperiment,
    EvidencePolicyRef,
    EvidenceWindow,
    ExperimentScope,
    StringValue,
    TrialPlan,
    compile_experiment,
)
from assurance_lab.evidence.bundle import (
    BundleStatus,
    EvaluationRef,
    EvaluatorRef,
    ExperimentRef,
    Sensitivity,
)
from assurance_lab.evidence.canonical import canonical_json_bytes, strict_json_loads
from assurance_lab.evidence.snapshot import SNAPSHOT_MEDIA_TYPE, capture_cab_snapshot
from assurance_lab.evidence.writer import BundleMetadata, PayloadFile, write_bundle
from assurance_lab.scenarios.financial_data import (
    DatasetProfile,
    SyntheticDataset,
    generate_dataset,
)
from assurance_lab.scenarios.financial_detection_contract import (
    ATTACK as DETECTION_ATTACK,
)
from assurance_lab.scenarios.financial_detection_contract import (
    BENIGN as DETECTION_BENIGN,
)
from assurance_lab.scenarios.financial_detection_contract import (
    action_descriptor as detection_action_descriptor,
)
from assurance_lab.scenarios.financial_detection_runtime import (
    BaselineVerdict as DetectionBaselineVerdict,
)
from assurance_lab.scenarios.financial_detection_runtime import (
    DetectionClaimState,
    DetectionResidualClassification,
    FinancialDetectionRuntime,
    FinancialDetectionRuntimeResult,
    NamedAlertAbsence,
    assess_detection_case,
    conclude_named_alert_absence,
)
from assurance_lab.scenarios.financial_recovery_contract import (
    ATTACK as RECOVERY_ATTACK,
)
from assurance_lab.scenarios.financial_recovery_contract import (
    BENIGN as RECOVERY_BENIGN,
)
from assurance_lab.scenarios.financial_recovery_contract import (
    SCENARIO_ID as RECOVERY_CONTRACT_ID,
)
from assurance_lab.scenarios.financial_recovery_contract import (
    action_descriptor as recovery_action_descriptor,
)
from assurance_lab.scenarios.financial_recovery_contract import (
    build_financial_recovery_contract,
)
from assurance_lab.scenarios.financial_recovery_e2e import (
    FinancialRecoveryLifecycleEvidence,
    write_reference_recovery_lifecycle_bundle,
)
from assurance_lab.scenarios.financial_recovery_runtime import (
    FinancialRecoveryRuntime,
    FinancialRecoveryRuntimeResult,
    RecoveryBaselineVerdict,
    RecoveryResidualClassification,
    assess_recovery_case,
)
from assurance_lab.scenarios.financial_response_contract import (
    ATTACK as RESPONSE_ATTACK,
)
from assurance_lab.scenarios.financial_response_contract import (
    BENIGN as RESPONSE_BENIGN,
)
from assurance_lab.scenarios.financial_response_contract import (
    action_descriptor as response_action_descriptor,
)
from assurance_lab.scenarios.financial_response_e2e import (
    FinancialResponseRuntimeObservationArtifact,
    _TrialAttestationArtifact,
)
from assurance_lab.scenarios.financial_response_e2e import (
    _covariate_digest as response_covariate_digest,
)
from assurance_lab.scenarios.financial_response_e2e import (
    _intervention_digest as response_intervention_digest,
)
from assurance_lab.scenarios.financial_response_e2e import (
    _runtime_observation as response_runtime_observation,
)
from assurance_lab.scenarios.financial_response_runtime import (
    BaselineVerdict as ResponseBaselineVerdict,
)
from assurance_lab.scenarios.financial_response_runtime import (
    FinancialResponseRuntime,
    FinancialResponseRuntimeResult,
    ResponseResidualClassification,
    assess_response_case,
)
from assurance_lab.source_identity import package_source_digest

_START: Final = datetime(2026, 7, 29, 0, 0, tzinfo=UTC)
_BLOCK: Final = "sqlite-fresh-clone"
_RUNTIME_SCHEMAS: Final[dict[ScenarioId, str]] = {
    DETECTION_SCENARIO_ID: ("assurance-lab.financial-detection-runtime-observation/v1"),
    RESPONSE_SCENARIO_ID: ("assurance-lab.financial-response-runtime-observation/v1"),
    RECOVERY_SCENARIO_ID: ("assurance-lab.financial-recovery-runtime-observation/v1"),
}
_ACTION_SCHEMAS: Final[dict[ScenarioId, str]] = {
    DETECTION_SCENARIO_ID: "assurance-lab.financial-detection-action/v1",
    RESPONSE_SCENARIO_ID: "assurance-lab.identity-session-action/v1",
    RECOVERY_SCENARIO_ID: "assurance-lab.recovery-export-action/v1",
}
_PROOF_SCHEMA: Final = "assurance-lab.recovery-lifecycle-proof/v1"
_EVALUATOR_ID: Final = "control-assurance/python-primary-semantic-verifier"
_BENCHMARK_ID: Final = "financial-control-lifecycle"
_BENCHMARK_VERSION: Final = "1.0.0"


@dataclass(frozen=True, slots=True)
class GeneratedScenarioSource:
    """One exact public source CAB and the benchmark values it carries."""

    scenario_id: ScenarioId
    specification: FrozenBenchmarkSpecification
    plan: FrozenPlan
    raw_trial_set: RawTrialSet
    snapshot_bytes: bytes
    snapshot_digest: str


@dataclass(frozen=True, slots=True)
class GeneratedPublicBenchmark:
    """The three source snapshots and their primary 144-trial result."""

    sources: tuple[
        GeneratedScenarioSource,
        GeneratedScenarioSource,
        GeneratedScenarioSource,
    ]
    primary_semantic_result: BenchmarkSemanticResult

    def source(self, scenario_id: ScenarioId) -> GeneratedScenarioSource:
        """Return one scenario without exposing a mutable result mapping."""

        for source in self.sources:
            if source.scenario_id == scenario_id:
                return source
        raise KeyError(scenario_id)


@dataclass(frozen=True, slots=True)
class _ScenarioExecution:
    source: GeneratedScenarioSource
    semantic_trials: tuple[TrialSemanticResult, ...]


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _json_value(value: Any) -> Any:
    """Render a runtime tree as JSON without dropping typed fields."""

    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, BaseModel):
        return _json_value(value.model_dump(mode="json", by_alias=True))
    if is_dataclass(value) and not isinstance(value, type):
        return _json_value(asdict(value))
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if value is None or type(value) in {str, int, bool, float}:
        return value
    raise TypeError(f"runtime result contains unsupported JSON value {type(value)!r}")


def _recovery_result_value(
    result: FinancialRecoveryRuntimeResult,
    *,
    producer_snapshot_digest: str,
) -> dict[str, Any]:
    """Preserve recovery evidence while removing a machine-local absolute path.

    ``lifecycle_bundle_root`` is a transport location, not an observation.  The
    public record replaces it with the exact embedded CAB snapshot address;
    every other result field is rendered losslessly.
    """

    rendered = cast(dict[str, Any], _json_value(result))
    rendered.pop("lifecycle_bundle_root")
    rendered["lifecycle_bundle_locator"] = {
        "kind": "embedded-cab-snapshot",
        "snapshot_digest": producer_snapshot_digest,
    }
    return rendered


def _canonical_jsonl_rows(payload: bytes) -> tuple[dict[str, Any], ...]:
    if not payload.endswith(b"\n"):
        raise ValueError("producer JSONL must end with one newline")
    result: list[dict[str, Any]] = []
    for line in payload.splitlines():
        document = strict_json_loads(line)
        if not isinstance(document, dict):
            raise ValueError("producer JSONL row must be an object")
        if canonical_json_bytes(document) != line:
            raise ValueError("producer JSONL row is not canonical JSON")
        result.append(document)
    return tuple(result)


def _producer_member(
    source: VerifiedBenchmarkCAB,
    *,
    suffix: str,
) -> bytes:
    matches = [payload for path, payload in source.entries if path.endswith(suffix)]
    if len(matches) != 1:
        raise RuntimeError(f"producer source does not contain one {suffix!r} member")
    return matches[0]


def _selector_level(selector: CellSelector, axis: str) -> str:
    value = getattr(selector, axis)
    if not isinstance(value, StringValue):
        raise TypeError(f"{axis} selector is not a string value")
    return value.value


def _action_for(
    scenario_id: ScenarioId,
    selector: CellSelector,
) -> dict[str, Any]:
    is_attack = (
        _selector_level(selector, "input")
        == {
            DETECTION_SCENARIO_ID: DETECTION_ATTACK.value,
            RESPONSE_SCENARIO_ID: RESPONSE_ATTACK.value,
            RECOVERY_SCENARIO_ID: RECOVERY_ATTACK.value,
        }[scenario_id]
    )
    if scenario_id == DETECTION_SCENARIO_ID:
        return detection_action_descriptor(DETECTION_ATTACK if is_attack else DETECTION_BENIGN)
    if scenario_id == RESPONSE_SCENARIO_ID:
        return response_action_descriptor(RESPONSE_ATTACK if is_attack else RESPONSE_BENIGN)
    return recovery_action_descriptor(RECOVERY_ATTACK if is_attack else RECOVERY_BENIGN)


def _frozen_specification(
    compiled: CompiledExperiment,
    action_references: dict[str, OpaqueArtifactReference],
) -> FrozenBenchmarkSpecification:
    actions = tuple(
        FrozenSpecificationAction(
            ordinal=planned.ordinal,
            trial_key=planned.key,
            cell_key=planned.cell_key,
            block=planned.block,
            replicate=planned.replicate,
            action=action_references[planned.cell_key],
        )
        for planned in compiled.planned_trials
    )
    body = {
        "wire_schema": "assurance-lab.benchmark.compiled-spec/v1",
        "scenario_id": compiled.contract.id,
        "contract": compiled.contract.model_dump(mode="json"),
        "actions": [item.model_dump(mode="json") for item in actions],
        "spec_digest": compiled.spec_digest,
    }
    return FrozenBenchmarkSpecification(
        wire_schema="assurance-lab.benchmark.compiled-spec/v1",
        scenario_id=cast(ScenarioId, compiled.contract.id),
        contract=compiled.contract,
        actions=actions,
        spec_digest=compiled.spec_digest,
        benchmark_specification_digest=canonical_digest(body),
    )


def _binding(
    *,
    specification: FrozenBenchmarkSpecification,
    trial_key: str,
    artifact: OpaqueArtifactReference,
) -> FrozenActionBinding:
    body = {
        "binding_schema": "assurance-lab.benchmark.frozen-action-binding/v1",
        "spec_digest": specification.spec_digest,
        "trial_key": trial_key,
        "artifact": artifact.model_dump(mode="json"),
    }
    return FrozenActionBinding(
        binding_schema="assurance-lab.benchmark.frozen-action-binding/v1",
        spec_digest=specification.spec_digest,
        trial_key=trial_key,
        artifact=artifact,
        binding_digest=canonical_digest(body),
    )


def _clone_readback(
    *,
    unique_instance_id: str,
    runner_resource_id: str,
    base_snapshot_digest: str,
    covariate_digest: str,
    attestation_digest: str,
) -> CloneReadback:
    body = {
        "readback_schema": "assurance-lab.clone-readback/v1",
        "unique_instance_id": unique_instance_id,
        "runner_resource_id": runner_resource_id,
        "base_snapshot_digest": base_snapshot_digest,
        "covariate_digest": covariate_digest,
        "attestation_bundle_digest": attestation_digest,
    }
    return CloneReadback(
        readback_schema="assurance-lab.clone-readback/v1",
        unique_instance_id=unique_instance_id,
        runner_resource_id=runner_resource_id,
        base_snapshot_digest=base_snapshot_digest,
        covariate_digest=covariate_digest,
        attestation_bundle_digest=attestation_digest,
        readback_digest=canonical_digest(body),
    )


def _artifact_member(
    members: dict[str, bytes],
    payload: bytes,
) -> str:
    digest = _sha256(payload)
    path = f"records/objects/{digest[7:]}.json"
    previous = members.setdefault(path, payload)
    if previous != payload:
        raise RuntimeError("content-address collision while building source CAB")
    return digest


def _runtime_wrapper(
    *,
    schema_name: str,
    spec_digest: str,
    planned: Any,
    result: dict[str, Any],
) -> bytes:
    return canonical_json_bytes(
        {
            "schema": schema_name,
            "spec_digest": spec_digest,
            "trial_key": planned.key,
            "cell_key": planned.cell_key,
            "block": planned.block,
            "replicate": planned.replicate,
            "ordinal": planned.ordinal,
            "result": result,
        }
    )


def _synthetic_attestation(
    *,
    scenario_id: ScenarioId,
    spec_digest: str,
    planned: Any,
    trace_id: str,
    clone_identity: str,
    runner_resource_id: str,
    observation_digests: dict[str, str],
) -> bytes:
    return canonical_json_bytes(
        {
            "schema": "assurance-lab.synthetic-sqlite-attestation/v1",
            "scenario_id": scenario_id,
            "spec_digest": spec_digest,
            "trial_key": planned.key,
            "cell_key": planned.cell_key,
            "block": planned.block,
            "replicate": planned.replicate,
            "ordinal": planned.ordinal,
            "trace_id": trace_id,
            "clone_identity": clone_identity,
            "runner_resource_id": runner_resource_id,
            "attestation_kind": "deterministic-in-process-sqlite-readback",
            "external_attestation": False,
            "hardware_attestation": False,
            "virtual_machine_clone": False,
            "observation_digests": dict(sorted(observation_digests.items())),
        }
    )


def _proof_wrapper(source: VerifiedBenchmarkCAB) -> bytes:
    paths = (
        "records/lifecycle/admitted-receipts.json",
        "records/lifecycle/incident-lifecycle.json",
        "records/lifecycle/verified-lifecycle.json",
    )
    by_path = dict(source.entries)
    members: list[dict[str, Any]] = []
    for path in paths:
        payload = by_path[path]
        document = strict_json_loads(payload)
        if canonical_json_bytes(document) != payload:
            raise RuntimeError("lifecycle producer emitted non-canonical proof bytes")
        members.append(
            {
                "path": path,
                "artifact_digest": _sha256(payload),
                "document": document,
            }
        )
    verified = cast(dict[str, Any], members[-1]["document"])
    actual = verified.get("actual_head_digest")
    comparison = verified.get("matched_comparison_head_digest")
    if not isinstance(actual, str) or not isinstance(comparison, str):
        raise RuntimeError("verified lifecycle lacks both branch head digests")
    return canonical_json_bytes(
        {
            "schema": _PROOF_SCHEMA,
            "source_bundle_id": source.cab_id,
            "source_snapshot_digest": source.snapshot_digest,
            "actual_branch_digest": actual,
            "comparison_branch_digest": comparison,
            "members": members,
        }
    )


def _write_source_cab(
    *,
    destination: Path,
    scenario_id: ScenarioId,
    specification: FrozenBenchmarkSpecification,
    plan: FrozenPlan,
    raw: RawTrialSet,
    members: dict[str, bytes],
    producer_snapshot: bytes,
) -> tuple[bytes, str]:
    payloads = [
        PayloadFile(
            path=path,
            content=payload,
            media_type=(
                "application/json"
                if path.endswith(".json")
                else SNAPSHOT_MEDIA_TYPE
            ),
            role=(
                "embedded real financial producer CAB snapshot"
                if path.endswith(".cab.snapshot")
                else "content-addressed benchmark source member"
            ),
            sensitivity=Sensitivity.SYNTHETIC,
            required_for=("benchmark-replay", "semantic-verification"),
        )
        for path, payload in sorted(
            {
                **members,
                BENCHMARK_SPEC_PATH: canonical_json_bytes(specification.model_dump(mode="json")),
                BENCHMARK_PLAN_PATH: canonical_json_bytes(plan.model_dump(mode="json")),
                BENCHMARK_RAW_PATH: canonical_json_bytes(raw.model_dump(mode="json")),
                (f"artifacts/producers/{scenario_id}/source.cab.snapshot"): producer_snapshot,
            }.items()
        )
    ]
    verification = write_bundle(
        destination,
        metadata=BundleMetadata(
            created_at=_START + timedelta(hours=4),
            as_of=_START + timedelta(hours=4),
            experiment=ExperimentRef(
                id=scenario_id,
                spec_version=_BENCHMARK_VERSION,
                spec_digest=specification.spec_digest,
            ),
            evaluation=EvaluationRef(
                policy_id="public-lifecycle-benchmark-source-v1",
                policy_digest=canonical_digest(
                    {
                        "schema": "assurance-lab.public-benchmark-source-policy/v1",
                        "requires": [
                            "exact-compiler-plan",
                            "content-addressed-actions",
                            "lossless-runtime-readback",
                            "in-process-sqlite-attestation",
                            "embedded-producer-snapshot",
                        ],
                    }
                ),
                evaluator=EvaluatorRef(
                    name="assurance-lab-public-benchmark-generator",
                    version=_BENCHMARK_VERSION,
                    source_revision="public-lifecycle-benchmark-v1",
                    image_digest=None,
                ),
            ),
        ),
        payloads=tuple(payloads),
    )
    if verification.status is not BundleStatus.INTEGRITY_VERIFIED:
        raise RuntimeError("generated benchmark source CAB failed integrity verification")
    sealed = capture_cab_snapshot(destination)
    verified = verify_benchmark_cab(
        sealed.snapshot_bytes,
        expected_snapshot_digest=sealed.snapshot_digest,
    )
    return verified.snapshot_bytes, verified.snapshot_digest


def _claim(value: bool) -> ClaimDisposition:
    return ClaimDisposition.SUPPORTED if value else ClaimDisposition.REFUTED


def _detection_vector(
    result: FinancialDetectionRuntimeResult,
) -> SemanticVector:
    if result.input_level == DETECTION_ATTACK.value:
        assessment = assess_detection_case(result)
        residual = {
            DetectionResidualClassification.MASKED_NAMED_DETECTION_FAILURE: (
                ResidualDisposition.MASKED_TARGET_FAILURE
            ),
            DetectionResidualClassification.EXPOSED_DETECTION_GAP: (
                ResidualDisposition.EXPOSED_PATH
            ),
            DetectionResidualClassification.NAMED_DETECTION_EFFECTIVE: (
                ResidualDisposition.TARGET_EFFECTIVE
            ),
            DetectionResidualClassification.INDETERMINATE: (ResidualDisposition.UNRESOLVED),
        }[assessment.residual_classification]
        target = {
            DetectionClaimState.SUPPORTED: ClaimDisposition.SUPPORTED,
            DetectionClaimState.REFUTED: ClaimDisposition.REFUTED,
            DetectionClaimState.INDETERMINATE: ClaimDisposition.INDETERMINATE,
        }[assessment.target_state]
        return SemanticVector(
            target=target,
            compensator=_claim(
                assessment.fallback_telemetry_supported and assessment.fallback_alert_supported
            ),
            path=_claim(assessment.alert_path_supported),
            benign=ClaimDisposition.NOT_EXERCISED,
            baseline=(
                BaselineDisposition.PASS
                if assessment.baseline.verdict is DetectionBaselineVerdict.PASS
                else BaselineDisposition.FAIL
            ),
            residual=residual,
        )

    benign_supported = (
        conclude_named_alert_absence(result) is NamedAlertAbsence.CONCLUDED and not result.alerts
    )
    return SemanticVector(
        target=ClaimDisposition.NOT_EXERCISED,
        compensator=ClaimDisposition.NOT_EXERCISED,
        path=ClaimDisposition.NOT_EXERCISED,
        benign=_claim(benign_supported),
        baseline=(BaselineDisposition.PASS if benign_supported else BaselineDisposition.FAIL),
        residual=ResidualDisposition.UNRESOLVED,
    )


def _response_vector(
    result: FinancialResponseRuntimeResult,
) -> SemanticVector:
    if result.action_digest == _sha256(
        canonical_json_bytes(response_action_descriptor(RESPONSE_ATTACK))
    ):
        assessment = assess_response_case(result)
        residual = {
            ResponseResidualClassification.MASKED_REVOCATION_FAILURE: (
                ResidualDisposition.MASKED_TARGET_FAILURE
            ),
            ResponseResidualClassification.EXPOSED_REPLAY: (ResidualDisposition.EXPOSED_PATH),
            ResponseResidualClassification.TARGET_EFFECTIVE: (ResidualDisposition.TARGET_EFFECTIVE),
            ResponseResidualClassification.UNRESOLVED: (ResidualDisposition.UNRESOLVED),
        }[assessment.residual_classification]
        return SemanticVector(
            target=_claim(assessment.target_supported),
            compensator=_claim(assessment.compensator_supported),
            path=_claim(assessment.path_supported),
            benign=_claim(assessment.benign_service_supported),
            baseline=(
                BaselineDisposition.PASS
                if assessment.baseline.verdict is ResponseBaselineVerdict.PASS
                else BaselineDisposition.FAIL
            ),
            residual=residual,
        )

    action = response_action_descriptor(RESPONSE_BENIGN)
    decisions = [
        decision
        for decision in result.gateway_decisions
        if decision.principal_id == action["principal_id"]
        and decision.session_id == action["session_id"]
    ]
    if len(decisions) != 1:
        raise RuntimeError("benign response run lacks its exact gateway decision")
    benign_supported = decisions[0].available
    return SemanticVector(
        target=ClaimDisposition.NOT_EXERCISED,
        compensator=ClaimDisposition.NOT_EXERCISED,
        path=ClaimDisposition.NOT_EXERCISED,
        benign=_claim(benign_supported),
        baseline=(BaselineDisposition.PASS if benign_supported else BaselineDisposition.FAIL),
        residual=ResidualDisposition.UNRESOLVED,
    )


def _recovery_vector(
    attack: FinancialRecoveryRuntimeResult,
    benign: FinancialRecoveryRuntimeResult,
) -> SemanticVector:
    assessment = assess_recovery_case(attack, benign)
    residual = {
        RecoveryResidualClassification.MASKED_RESTORE_FAILURE: (
            ResidualDisposition.MASKED_TARGET_FAILURE
        ),
        RecoveryResidualClassification.EXPOSED_PATH: (ResidualDisposition.EXPOSED_PATH),
        RecoveryResidualClassification.TARGET_EFFECTIVE: (ResidualDisposition.TARGET_EFFECTIVE),
        RecoveryResidualClassification.UNRESOLVED: (ResidualDisposition.UNRESOLVED),
    }[assessment.residual_classification]
    return SemanticVector(
        target=_claim(assessment.target_supported),
        compensator=_claim(assessment.release_guard_supported),
        path=_claim(assessment.path_supported),
        benign=_claim(assessment.benign_service_supported),
        baseline=(
            BaselineDisposition.PASS
            if assessment.baseline.verdict is RecoveryBaselineVerdict.PASS
            else BaselineDisposition.FAIL
        ),
        residual=residual,
    )


def _single_semantic_trial(
    raw: RawTrialEnvelope,
    semantics: SemanticVector,
) -> TrialSemanticResult:
    body = {
        "mode": "single-trial",
        "lineage_schema": "assurance-lab.benchmark.single-trial-lineage/v1",
        "subject_trial_key": raw.trial_key,
        "action_artifact": raw.action.artifact.model_dump(mode="json"),
        "runtime_artifact": raw.runtime_artifact.model_dump(mode="json"),
    }
    lineage = SingleTrialSemanticLineage(
        mode="single-trial",
        lineage_schema="assurance-lab.benchmark.single-trial-lineage/v1",
        subject_trial_key=raw.trial_key,
        action_artifact=raw.action.artifact,
        runtime_artifact=raw.runtime_artifact,
        lineage_digest=canonical_digest(body),
    )
    return _semantic_trial(raw, semantics, lineage)


def _paired_semantic_trial(
    raw: RawTrialEnvelope,
    *,
    attack: RawTrialEnvelope,
    benign: RawTrialEnvelope,
    semantics: SemanticVector,
) -> TrialSemanticResult:
    proof = attack.shared_lifecycle_proof
    if proof is None or proof != benign.shared_lifecycle_proof:
        raise RuntimeError("recovery pair does not share one lifecycle proof")
    body = {
        "mode": "matched-pair",
        "lineage_schema": "assurance-lab.benchmark.matched-pair-lineage/v1",
        "subject_trial_key": raw.trial_key,
        "attack_trial_key": attack.trial_key,
        "benign_trial_key": benign.trial_key,
        "attack_action_artifact": attack.action.artifact.model_dump(mode="json"),
        "benign_action_artifact": benign.action.artifact.model_dump(mode="json"),
        "attack_runtime_artifact": attack.runtime_artifact.model_dump(mode="json"),
        "benign_runtime_artifact": benign.runtime_artifact.model_dump(mode="json"),
        "shared_lifecycle_proof": proof.model_dump(mode="json"),
    }
    lineage = MatchedPairSemanticLineage(
        mode="matched-pair",
        lineage_schema="assurance-lab.benchmark.matched-pair-lineage/v1",
        subject_trial_key=raw.trial_key,
        attack_trial_key=attack.trial_key,
        benign_trial_key=benign.trial_key,
        attack_action_artifact=attack.action.artifact,
        benign_action_artifact=benign.action.artifact,
        attack_runtime_artifact=attack.runtime_artifact,
        benign_runtime_artifact=benign.runtime_artifact,
        shared_lifecycle_proof=proof,
        lineage_digest=canonical_digest(body),
    )
    return _semantic_trial(raw, semantics, lineage)


def _semantic_trial(
    raw: RawTrialEnvelope,
    semantics: SemanticVector,
    lineage: SingleTrialSemanticLineage | MatchedPairSemanticLineage,
) -> TrialSemanticResult:
    return TrialSemanticResult(
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
        semantics=semantics,
    )


def _scenario_semantics(
    source: GeneratedScenarioSource,
    trials: tuple[TrialSemanticResult, ...],
) -> ScenarioSemanticResult:
    cells: list[CellSemanticResult] = []
    by_cell: dict[str, list[TrialSemanticResult]] = {}
    for trial in trials:
        by_cell.setdefault(trial.cell_key, []).append(trial)
    for cell_key in sorted(by_cell):
        cell_trials = tuple(sorted(by_cell[cell_key], key=lambda item: item.replicate))
        semantic_digests = tuple(
            sorted(
                {canonical_digest(trial.semantics.model_dump(mode="json")) for trial in cell_trials}
            )
        )
        if len(semantic_digests) != 1:
            raise RuntimeError("deterministic primary executions disagree across replicates")
        agreement = ReplicateAgreement(
            disposition=AgreementDisposition.AGREED,
            semantic_digests=semantic_digests,
        )
        cells.append(
            CellSemanticResult(
                scenario_id=source.scenario_id,
                spec_digest=source.specification.spec_digest,
                cell_key=cell_key,
                trials=cell_trials,
                agreement=agreement,
                semantics=cell_trials[0].semantics,
            )
        )
    raw_bytes = canonical_json_bytes(source.raw_trial_set.model_dump(mode="json"))
    return ScenarioSemanticResult(
        scenario_id=source.scenario_id,
        spec_digest=source.specification.spec_digest,
        raw_trial_set_digest=_sha256(raw_bytes),
        cells=cast(tuple[CellSemanticResult, ...], tuple(cells)),
    )


def _detection_execution(
    *,
    destination: Path,
    producer: VerifiedBenchmarkCAB,
) -> _ScenarioExecution:
    compiled = detection_corruption_compiled()
    cells = {cell.key: cell.selector for cell in compiled.cells}
    producer_records = {
        cast(str, record["trial_key"]): record
        for record in _canonical_jsonl_rows(
            _producer_member(producer, suffix="records/runtime-observations.jsonl")
        )
    }
    runtime = FinancialDetectionRuntime()
    action_payloads: dict[str, bytes] = {}
    action_refs: dict[str, OpaqueArtifactReference] = {}
    for cell in compiled.cells:
        payload = canonical_json_bytes(_action_for(DETECTION_SCENARIO_ID, cell.selector))
        digest = _sha256(payload)
        action_payloads[digest] = payload
        action_refs[cell.key] = OpaqueArtifactReference(
            schema_name=_ACTION_SCHEMAS[DETECTION_SCENARIO_ID],
            artifact_digest=digest,
        )
    specification = _frozen_specification(compiled, action_refs)
    plan = compile_frozen_plan(specification)
    members: dict[str, bytes] = {}
    for payload in action_payloads.values():
        _artifact_member(members, payload)

    raw_trials: list[RawTrialEnvelope] = []
    results: dict[str, FinancialDetectionRuntimeResult] = {}
    vectors: dict[str, SemanticVector] = {}
    for planned in compiled.planned_trials:
        selector = cells[planned.cell_key]
        trace_id = f"financial-detection-trace-{planned.ordinal:04d}-{planned.key[-12:]}"
        result = runtime.execute(selector, trace_id=trace_id)
        rendered = cast(dict[str, Any], _json_value(result))
        if producer_records[planned.key]["result"] != rendered:
            raise RuntimeError("detection producer record differs from a fresh real execution")
        runtime_bytes = _runtime_wrapper(
            schema_name=_RUNTIME_SCHEMAS[DETECTION_SCENARIO_ID],
            spec_digest=specification.spec_digest,
            planned=planned,
            result=rendered,
        )
        runtime_digest = _artifact_member(members, runtime_bytes)
        clone_id = f"detection-sqlite-memory-{planned.key[-24:]}"
        runner_id = result.collector_run_readback.collector_run_id
        attestation_bytes = _synthetic_attestation(
            scenario_id=DETECTION_SCENARIO_ID,
            spec_digest=specification.spec_digest,
            planned=planned,
            trace_id=trace_id,
            clone_identity=clone_id,
            runner_resource_id=runner_id,
            observation_digests={
                "alert-query": result.alert_query.readback_digest,
                "collector-run": result.collector_run_readback.readback_digest,
                "detector-run": result.detector_run.readback_digest,
                "window-closure": result.window_closure.artifact_digest,
            },
        )
        attestation_digest = _artifact_member(members, attestation_bytes)
        covariate_digest = canonical_digest(
            {
                "schema": "assurance-lab.financial-detection-covariate/v1",
                "clock_readback_digest": result.clock_readback.readback_digest,
                "collector_instance_id": runner_id,
                "selector": selector.model_dump(mode="json"),
                "block": planned.block,
                "replicate": planned.replicate,
            }
        )
        raw_trials.append(
            RawTrialEnvelope(
                wire_schema="assurance-lab.benchmark.raw-trial/v1",
                scenario_id=DETECTION_SCENARIO_ID,
                spec_digest=specification.spec_digest,
                trial_key=planned.key,
                cell_key=planned.cell_key,
                block=planned.block,
                replicate=planned.replicate,
                ordinal=planned.ordinal,
                trace_id=trace_id,
                action=_binding(
                    specification=specification,
                    trial_key=planned.key,
                    artifact=action_refs[planned.cell_key],
                ),
                clone_readback=_clone_readback(
                    unique_instance_id=clone_id,
                    runner_resource_id=runner_id,
                    base_snapshot_digest=compiled.contract.scope.dataset_digest,
                    covariate_digest=covariate_digest,
                    attestation_digest=attestation_digest,
                ),
                runtime_artifact=OpaqueArtifactReference(
                    schema_name=_RUNTIME_SCHEMAS[DETECTION_SCENARIO_ID],
                    artifact_digest=runtime_digest,
                ),
            )
        )
        results[planned.key] = result
        vectors[planned.key] = _detection_vector(result)
    raw = RawTrialSet(
        wire_schema="assurance-lab.benchmark.raw-trial-set/v1",
        scenario_id=DETECTION_SCENARIO_ID,
        spec_digest=specification.spec_digest,
        trials=tuple(raw_trials),
    )
    snapshot, digest = _write_source_cab(
        destination=destination,
        scenario_id=DETECTION_SCENARIO_ID,
        specification=specification,
        plan=plan,
        raw=raw,
        members=members,
        producer_snapshot=producer.snapshot_bytes,
    )
    source = GeneratedScenarioSource(
        scenario_id=DETECTION_SCENARIO_ID,
        specification=specification,
        plan=plan,
        raw_trial_set=raw,
        snapshot_bytes=snapshot,
        snapshot_digest=digest,
    )
    semantic_trials = tuple(
        _single_semantic_trial(trial, vectors[trial.trial_key]) for trial in raw.trials
    )
    return _ScenarioExecution(source=source, semantic_trials=semantic_trials)


def _response_execution(
    *,
    destination: Path,
    producer: VerifiedBenchmarkCAB,
) -> _ScenarioExecution:
    compiled = response_corruption_compiled()
    cells = {cell.key: cell.selector for cell in compiled.cells}
    observation_rows = {
        cast(str, row["trial_key"]): row
        for row in _canonical_jsonl_rows(
            _producer_member(producer, suffix="records/runtime-observations.jsonl")
        )
    }
    attestation_rows = {
        cast(str, row["trial_key"]): row
        for row in _canonical_jsonl_rows(
            _producer_member(producer, suffix="artifacts/trial-attestations.jsonl")
        )
    }
    runtime = FinancialResponseRuntime()
    action_payloads: dict[str, bytes] = {}
    action_refs: dict[str, OpaqueArtifactReference] = {}
    for cell in compiled.cells:
        payload = canonical_json_bytes(_action_for(RESPONSE_SCENARIO_ID, cell.selector))
        digest = _sha256(payload)
        action_payloads[digest] = payload
        action_refs[cell.key] = OpaqueArtifactReference(
            schema_name=_ACTION_SCHEMAS[RESPONSE_SCENARIO_ID],
            artifact_digest=digest,
        )
    specification = _frozen_specification(compiled, action_refs)
    plan = compile_frozen_plan(specification)
    members: dict[str, bytes] = {}
    for payload in action_payloads.values():
        _artifact_member(members, payload)

    raw_trials: list[RawTrialEnvelope] = []
    vectors: dict[str, SemanticVector] = {}
    for planned in compiled.planned_trials:
        selector = cells[planned.cell_key]
        trace_id = f"financial-response-trace-{planned.ordinal:04d}-{planned.key[-12:]}"
        clone_id = f"response-sqlite-clone-{planned.ordinal:04d}-{planned.key[-12:]}"
        result = runtime.execute(
            selector,
            trace_id=trace_id,
            clone_nonce=clone_id,
            runner_resource_id="financial-response-sqlite-runner",
        )
        try:
            producer_observation = (
                FinancialResponseRuntimeObservationArtifact.model_validate_json(
                    canonical_json_bytes(observation_rows[planned.key]),
                    strict=True,
                )
            )
            fresh_observation = response_runtime_observation(
                compiled,
                planned.key,
                result,
            )
        except (KeyError, TypeError, ValueError) as error:
            raise RuntimeError(
                "response producer observation is not the fixed typed artifact"
            ) from error
        producer_observation_bytes = canonical_json_bytes(
            producer_observation.model_dump(mode="json")
        )
        fresh_observation_bytes = canonical_json_bytes(
            fresh_observation.model_dump(mode="json")
        )
        if producer_observation_bytes != fresh_observation_bytes:
            raise RuntimeError(
                "response producer observation differs from a fresh real execution"
            )
        runtime_bytes = _runtime_wrapper(
            schema_name=_RUNTIME_SCHEMAS[RESPONSE_SCENARIO_ID],
            spec_digest=specification.spec_digest,
            planned=planned,
            result=fresh_observation.model_dump(mode="json"),
        )
        runtime_digest = _artifact_member(members, runtime_bytes)
        try:
            attestation = _TrialAttestationArtifact.model_validate_json(
                canonical_json_bytes(attestation_rows[planned.key]),
                strict=True,
            )
        except (KeyError, TypeError, ValueError) as error:
            raise RuntimeError(
                "response producer attestation is not the fixed typed artifact"
            ) from error
        scope = compiled.contract.scope
        expected_covariate_digest = response_covariate_digest(
            scope.fixture_digest,
            planned.block,
            planned.replicate,
        )
        expected_intervention_digest = response_intervention_digest(selector)
        expected_observation_digest = _sha256(fresh_observation_bytes)
        if (
            attestation.id != f"response-attestation-{planned.ordinal:04d}"
            or attestation.spec_digest != specification.spec_digest
            or attestation.trial_key != planned.key
            or attestation.cell_key != planned.cell_key
            or attestation.block != planned.block
            or attestation.replicate != planned.replicate
            or attestation.ordinal != planned.ordinal
            or attestation.trace_id != trace_id
            or attestation.action_digest != result.action_digest
            or attestation.clone_unique_instance_id != clone_id
            or attestation.runner_resource_id
            != "financial-response-sqlite-runner"
            or attestation.observed_build_digest != scope.build_digest
            or attestation.observed_dataset_digest != scope.dataset_digest
            or attestation.observed_fixture_digest != scope.fixture_digest
            or attestation.observed_selector != selector
            or attestation.base_snapshot_digest != scope.dataset_digest
            or attestation.covariate_digest != expected_covariate_digest
            or attestation.intervention_digest != expected_intervention_digest
            or attestation.runtime_observation_digest
            != expected_observation_digest
            or attestation.time_basis != "simulated"
            or attestation.started_at < scope.evidence_window.start
            or attestation.ended_at > scope.evidence_window.end
            or attestation.ended_at > scope.assessment_as_of
        ):
            raise RuntimeError(
                "response producer attestation differs from the fixed execution"
            )
        attestation_bytes = canonical_json_bytes(attestation.model_dump(mode="json"))
        attestation_digest = _artifact_member(members, attestation_bytes)
        raw_trials.append(
            RawTrialEnvelope(
                wire_schema="assurance-lab.benchmark.raw-trial/v1",
                scenario_id=RESPONSE_SCENARIO_ID,
                spec_digest=specification.spec_digest,
                trial_key=planned.key,
                cell_key=planned.cell_key,
                block=planned.block,
                replicate=planned.replicate,
                ordinal=planned.ordinal,
                trace_id=trace_id,
                action=_binding(
                    specification=specification,
                    trial_key=planned.key,
                    artifact=action_refs[planned.cell_key],
                ),
                clone_readback=_clone_readback(
                    unique_instance_id=clone_id,
                    runner_resource_id="financial-response-sqlite-runner",
                    base_snapshot_digest=scope.dataset_digest,
                    covariate_digest=expected_covariate_digest,
                    attestation_digest=attestation_digest,
                ),
                runtime_artifact=OpaqueArtifactReference(
                    schema_name=_RUNTIME_SCHEMAS[RESPONSE_SCENARIO_ID],
                    artifact_digest=runtime_digest,
                ),
            )
        )
        vectors[planned.key] = _response_vector(result)
    raw = RawTrialSet(
        wire_schema="assurance-lab.benchmark.raw-trial-set/v1",
        scenario_id=RESPONSE_SCENARIO_ID,
        spec_digest=specification.spec_digest,
        trials=tuple(raw_trials),
    )
    snapshot, digest = _write_source_cab(
        destination=destination,
        scenario_id=RESPONSE_SCENARIO_ID,
        specification=specification,
        plan=plan,
        raw=raw,
        members=members,
        producer_snapshot=producer.snapshot_bytes,
    )
    source = GeneratedScenarioSource(
        scenario_id=RESPONSE_SCENARIO_ID,
        specification=specification,
        plan=plan,
        raw_trial_set=raw,
        snapshot_bytes=snapshot,
        snapshot_digest=digest,
    )
    semantic_trials = tuple(
        _single_semantic_trial(trial, vectors[trial.trial_key]) for trial in raw.trials
    )
    return _ScenarioExecution(source=source, semantic_trials=semantic_trials)


def _recovery_compiled(
    *,
    dataset: SyntheticDataset,
    producer: VerifiedBenchmarkCAB,
) -> CompiledExperiment:
    runtime_source_path = recovery_runtime_module.__file__
    if runtime_source_path is None:
        raise RuntimeError("recovery runtime source path is unavailable")
    runtime_source = Path(runtime_source_path).read_bytes()
    scope = ExperimentScope(
        scenario_id=RECOVERY_CONTRACT_ID,
        build_digest=_sha256(runtime_source),
        dataset_digest=f"sha256:{dataset.logical_digest()}",
        fixture_digest=producer.snapshot_digest,
        assessment_as_of=_START + timedelta(hours=3),
        evidence_window=EvidenceWindow(
            start=_START,
            end=_START + timedelta(hours=4),
        ),
        evidence_policy=EvidencePolicyRef(
            id="financial-recovery-public-benchmark-v1",
            version="1.0.0",
            digest=canonical_digest(
                {
                    "schema": "assurance-lab.financial-recovery-benchmark-policy/v1",
                    "requires": [
                        "shared-lifecycle-proof",
                        "deterministic-sqlite-clone-readback",
                        "matched-attack-benign-retest",
                    ],
                }
            ),
        ),
    )
    return compile_experiment(
        build_financial_recovery_contract(
            scope=scope,
            plan=TrialPlan(
                blocks=(_BLOCK,),
                replicates=3,
                order_seed="financial-recovery-public-benchmark-v1",
            ),
        )
    )


def _recovery_execution(
    *,
    destination: Path,
    producer: VerifiedBenchmarkCAB,
    evidence: FinancialRecoveryLifecycleEvidence,
) -> _ScenarioExecution:
    dataset = generate_dataset(seed=2907, profile=DatasetProfile.DEFAULT)
    compiled = _recovery_compiled(dataset=dataset, producer=producer)
    cells = {cell.key: cell.selector for cell in compiled.cells}
    runtime = FinancialRecoveryRuntime(
        dataset,
        cutover_fixtures=evidence.cutover_fixtures(),
    )
    action_payloads: dict[str, bytes] = {}
    action_refs: dict[str, OpaqueArtifactReference] = {}
    for cell in compiled.cells:
        payload = canonical_json_bytes(_action_for(RECOVERY_SCENARIO_ID, cell.selector))
        digest = _sha256(payload)
        action_payloads[digest] = payload
        action_refs[cell.key] = OpaqueArtifactReference(
            schema_name=_ACTION_SCHEMAS[RECOVERY_SCENARIO_ID],
            artifact_digest=digest,
        )
    specification = _frozen_specification(compiled, action_refs)
    plan = compile_frozen_plan(specification)
    members: dict[str, bytes] = {}
    for payload in action_payloads.values():
        _artifact_member(members, payload)
    producer_entries = dict(producer.entries)
    for path in (
        "records/lifecycle/admitted-receipts.json",
        "records/lifecycle/incident-lifecycle.json",
        "records/lifecycle/verified-lifecycle.json",
    ):
        _artifact_member(members, producer_entries[path])
    proof_bytes = _proof_wrapper(producer)
    proof_digest = _artifact_member(members, proof_bytes)
    proof_reference = OpaqueArtifactReference(
        schema_name=_PROOF_SCHEMA,
        artifact_digest=proof_digest,
    )

    raw_trials: list[RawTrialEnvelope] = []
    results: dict[str, FinancialRecoveryRuntimeResult] = {}
    for planned in compiled.planned_trials:
        selector = cells[planned.cell_key]
        trace_id = f"financial-recovery-trace-{planned.ordinal:04d}-{planned.key[-12:]}"
        clone_nonce = hashlib.sha256(f"recovery-clone\\0{planned.key}".encode()).hexdigest()[:32]
        result = runtime.execute(
            selector,
            trace_id=trace_id,
            clone_nonce=clone_nonce,
        )
        rendered = _recovery_result_value(
            result,
            producer_snapshot_digest=producer.snapshot_digest,
        )
        runtime_bytes = _runtime_wrapper(
            schema_name=_RUNTIME_SCHEMAS[RECOVERY_SCENARIO_ID],
            spec_digest=specification.spec_digest,
            planned=planned,
            result=rendered,
        )
        runtime_digest = _artifact_member(members, runtime_bytes)
        runner_id = "financial-recovery-sqlite-memory"
        attestation_bytes = _synthetic_attestation(
            scenario_id=RECOVERY_SCENARIO_ID,
            spec_digest=specification.spec_digest,
            planned=planned,
            trace_id=trace_id,
            clone_identity=result.clone_id,
            runner_resource_id=runner_id,
            observation_digests={
                "clone-readback": result.clone_readback_digest,
                "clone-cleanup-probe": result.clone_cleanup_probe_digest,
                "delivery-receipts": result.delivery_receipts_digest,
                "lifecycle-snapshot": result.lifecycle_snapshot_digest,
                "session-resolution": result.session_resolution_digest,
            },
        )
        attestation_digest = _artifact_member(members, attestation_bytes)
        covariate_digest = canonical_digest(
            {
                "schema": "assurance-lab.financial-recovery-covariate/v1",
                "lifecycle_snapshot_digest": result.lifecycle_snapshot_digest,
                "snapshot_digest": result.snapshot_digest,
                "selector": selector.model_dump(mode="json"),
                "block": planned.block,
                "replicate": planned.replicate,
            }
        )
        raw_trials.append(
            RawTrialEnvelope(
                wire_schema="assurance-lab.benchmark.raw-trial/v1",
                scenario_id=RECOVERY_SCENARIO_ID,
                spec_digest=specification.spec_digest,
                trial_key=planned.key,
                cell_key=planned.cell_key,
                block=planned.block,
                replicate=planned.replicate,
                ordinal=planned.ordinal,
                trace_id=trace_id,
                action=_binding(
                    specification=specification,
                    trial_key=planned.key,
                    artifact=action_refs[planned.cell_key],
                ),
                clone_readback=_clone_readback(
                    unique_instance_id=result.clone_id,
                    runner_resource_id=runner_id,
                    base_snapshot_digest=result.lifecycle_snapshot_digest,
                    covariate_digest=covariate_digest,
                    attestation_digest=attestation_digest,
                ),
                runtime_artifact=OpaqueArtifactReference(
                    schema_name=_RUNTIME_SCHEMAS[RECOVERY_SCENARIO_ID],
                    artifact_digest=runtime_digest,
                ),
                shared_lifecycle_proof=proof_reference,
            )
        )
        results[planned.key] = result
    raw = RawTrialSet(
        wire_schema="assurance-lab.benchmark.raw-trial-set/v1",
        scenario_id=RECOVERY_SCENARIO_ID,
        spec_digest=specification.spec_digest,
        trials=tuple(raw_trials),
    )
    snapshot, digest = _write_source_cab(
        destination=destination,
        scenario_id=RECOVERY_SCENARIO_ID,
        specification=specification,
        plan=plan,
        raw=raw,
        members=members,
        producer_snapshot=producer.snapshot_bytes,
    )
    source = GeneratedScenarioSource(
        scenario_id=RECOVERY_SCENARIO_ID,
        specification=specification,
        plan=plan,
        raw_trial_set=raw,
        snapshot_bytes=snapshot,
        snapshot_digest=digest,
    )

    selector_by_cell = cells
    raw_by_coordinate = {
        (trial.cell_key, trial.block, trial.replicate): trial for trial in raw.trials
    }
    cell_by_selector = {
        canonical_json_bytes(cell.selector.model_dump(mode="json")): cell.key
        for cell in compiled.cells
    }
    pairs: dict[str, tuple[RawTrialEnvelope, RawTrialEnvelope]] = {}
    vectors: dict[str, SemanticVector] = {}
    for trial in raw.trials:
        selector = selector_by_cell[trial.cell_key]
        counterpart_document = selector.model_dump(mode="python")
        input_value = cast(StringValue, selector.input)
        counterpart_document["input"] = (
            RECOVERY_BENIGN.model_dump(mode="python")
            if input_value == RECOVERY_ATTACK
            else RECOVERY_ATTACK.model_dump(mode="python")
        )
        counterpart_selector = CellSelector.model_validate(
            counterpart_document,
            strict=True,
        )
        counterpart_cell = cell_by_selector[
            canonical_json_bytes(counterpart_selector.model_dump(mode="json"))
        ]
        counterpart = raw_by_coordinate[(counterpart_cell, trial.block, trial.replicate)]
        if input_value == RECOVERY_ATTACK:
            attack, benign = trial, counterpart
        else:
            attack, benign = counterpart, trial
        vector = _recovery_vector(
            results[attack.trial_key],
            results[benign.trial_key],
        )
        pairs[trial.trial_key] = (attack, benign)
        vectors[trial.trial_key] = vector
    semantic_trials = tuple(
        _paired_semantic_trial(
            trial,
            attack=pairs[trial.trial_key][0],
            benign=pairs[trial.trial_key][1],
            semantics=vectors[trial.trial_key],
        )
        for trial in raw.trials
    )
    return _ScenarioExecution(source=source, semantic_trials=semantic_trials)


def build_public_benchmark(root: Path) -> GeneratedPublicBenchmark:
    """Execute and seal the exact public three-scenario, 144-trial corpus.

    ``root`` must not exist.  Rebuilding into a different empty location yields
    byte-identical snapshots and an equal semantic result.
    """

    if root.exists():
        raise FileExistsError("benchmark build root must not already exist")
    root.mkdir(parents=True, mode=0o700)
    producer_corpus: RealCorruptionSourceCorpus = build_real_corruption_source_corpus(
        root / "producer-cabs"
    )
    recovery_evidence = write_reference_recovery_lifecycle_bundle(
        root / "producer-cabs" / "recovery-runtime-lifecycle.cab"
    )
    # The independently captured producer corpus and the runtime fixture must
    # be the same deterministic lifecycle CAB.
    lifecycle_sealed = capture_cab_snapshot(recovery_evidence.lifecycle_bundle_root)
    lifecycle_producer = producer_corpus.source(RECOVERY_SCENARIO_ID)
    if lifecycle_sealed.snapshot_digest != lifecycle_producer.snapshot_digest:
        raise RuntimeError("recovery lifecycle producer is not byte deterministic")

    executions = (
        _recovery_execution(
            destination=root / f"{RECOVERY_SCENARIO_ID}.cab",
            producer=lifecycle_producer,
            evidence=recovery_evidence,
        ),
        _detection_execution(
            destination=root / f"{DETECTION_SCENARIO_ID}.cab",
            producer=producer_corpus.source(DETECTION_SCENARIO_ID),
        ),
        _response_execution(
            destination=root / f"{RESPONSE_SCENARIO_ID}.cab",
            producer=producer_corpus.source(RESPONSE_SCENARIO_ID),
        ),
    )
    if tuple(item.source.scenario_id for item in executions) != BENCHMARK_SCENARIO_IDS:
        raise RuntimeError("generated scenarios are not in the canonical benchmark order")
    evaluator_digest = package_source_digest()
    primary = BenchmarkSemanticResult(
        wire_schema="assurance-lab.benchmark.semantic-result/v1",
        benchmark_id=_BENCHMARK_ID,
        benchmark_version=_BENCHMARK_VERSION,
        evaluator_id=_EVALUATOR_ID,
        evaluator_digest=evaluator_digest,
        scenarios=tuple(
            _scenario_semantics(execution.source, execution.semantic_trials)
            for execution in executions
        ),
    )
    return GeneratedPublicBenchmark(
        sources=cast(
            tuple[
                GeneratedScenarioSource,
                GeneratedScenarioSource,
                GeneratedScenarioSource,
            ],
            tuple(execution.source for execution in executions),
        ),
        primary_semantic_result=primary,
    )


__all__ = [
    "GeneratedPublicBenchmark",
    "GeneratedScenarioSource",
    "build_public_benchmark",
]
