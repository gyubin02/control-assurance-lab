"""Bounded release admission for the deterministic lifecycle benchmark.

The wire models describe data.  They are not, by themselves, proof that the
referenced bytes exist or that a semantic result was recomputed.  This module is
the bytes-only boundary that closes those references over canonical inputs and
trusted, scenario-specific verifiers.

It deliberately does not authenticate the resolver or verifier, establish
custody, or make any digest externally immutable.  Those remain external policy
and attestation responsibilities.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from pydantic import BaseModel as PydanticBaseModel
from pydantic import ValidationError

from assurance_lab.benchmark.cab import (
    BENCHMARK_PLAN_PATH,
    BENCHMARK_RAW_PATH,
    BENCHMARK_SPEC_PATH,
    BenchmarkCABError,
    VerifiedBenchmarkCAB,
    verify_benchmark_cab,
)
from assurance_lab.benchmark.models import (
    BENCHMARK_SCENARIO_IDS,
    RECOVERY_SCENARIO_ID,
    BenchmarkIndex,
    BenchmarkSemanticResult,
    CombinedRawBenchmarkCorpus,
    FrozenBenchmarkSpecification,
    FrozenPlan,
    MatchedPairSemanticLineage,
    OpaqueArtifactReference,
    RawTrialEnvelope,
    RawTrialSet,
    ScenarioIndexEntry,
    ScenarioSemanticResult,
    SingleTrialSemanticLineage,
    TrialSemanticLineage,
    canonical_digest,
    compile_frozen_plan,
)
from assurance_lab.contract import (
    CellSelector,
    GeneratedCell,
    TypedValue,
    compile_experiment,
)
from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)

BENCHMARK_JSON_LIMITS = JSONLimits(
    max_bytes=16 * 1024 * 1024,
    max_line_bytes=2 * 1024 * 1024,
    max_depth=64,
    max_collection_items=100_000,
    max_string_length=2 * 1024 * 1024,
)


class BenchmarkAdmissionError(ValueError):
    """The benchmark cannot be admitted without weakening a release claim."""


class SourceBundleResolver(Protocol):
    """Resolve one immutable canonical CAB snapshot by the index digest."""

    def resolve_source_bundle(self, *, scenario_id: str, bundle_digest: str) -> bytes:
        """Return exact deterministic CAB snapshot bytes for one source scenario."""


@dataclass(frozen=True, slots=True)
class VerifiedArtifactInput:
    """One exact canonical artifact resolved from the verified source CAB."""

    reference: OpaqueArtifactReference
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class ExpectedMatchedPair:
    """Verifier-owned attack/benign identity derived from the frozen selectors."""

    subject_trial_key: str
    attack_trial_key: str
    benign_trial_key: str


@dataclass(frozen=True, slots=True)
class ResolvedTrialInputs:
    """All immutable inputs a scenario verifier may use for one trial verdict."""

    trial_key: str
    action: VerifiedArtifactInput
    runtime: VerifiedArtifactInput
    shared_lifecycle_proof: VerifiedArtifactInput | None
    expected_matched_pair: ExpectedMatchedPair | None


class ScenarioVerifier(Protocol):
    """Independently recompute one scenario result from resolved raw inputs.

    The common admission layer guarantees bounded duplicate-safe JSON and exact
    digest resolution.  The implementation must additionally enforce each
    declared action/runtime schema and derive semantic meaning from the frozen
    plan rather than from producer-authored labels.
    """

    @property
    def evaluator_id(self) -> str:
        """Stable identity of the verifier implementation."""

    @property
    def evaluator_digest(self) -> str:
        """Externally supplied content address of the verifier implementation."""

    def verify_scenario(
        self,
        *,
        plan: FrozenPlan,
        raw_trial_set: RawTrialSet,
        trial_inputs: tuple[ResolvedTrialInputs, ...],
    ) -> ScenarioSemanticResult:
        """Recompute the complete scenario result from the resolved artifacts."""


def _raw_sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _require_bytes(payload: object, *, subject: str) -> bytes:
    if type(payload) is not bytes:
        raise BenchmarkAdmissionError(f"{subject} must be supplied as immutable bytes")
    return payload


def canonical_model_bytes(value: PydanticBaseModel) -> bytes:
    """Revalidate a typed value through primitives and return bounded canonical bytes."""

    validated = revalidate_benchmark_value(value, type(value))
    try:
        return canonical_json_bytes(
            validated.model_dump(mode="json"),
            limits=BENCHMARK_JSON_LIMITS,
        )
    except StrictJSONError as exc:
        raise BenchmarkAdmissionError("validated benchmark model exceeds wire limits") from exc


def revalidate_benchmark_value[ModelT: PydanticBaseModel](
    value: PydanticBaseModel,
    model_type: type[ModelT],
) -> ModelT:
    """Defeat ``model_copy``/``model_construct`` by validating a primitive dump."""

    if not isinstance(value, PydanticBaseModel):
        raise BenchmarkAdmissionError("typed benchmark value must be a Pydantic model")
    try:
        primitive = value.model_dump(mode="json")
        primitive_bytes = canonical_json_bytes(
            primitive,
            limits=BENCHMARK_JSON_LIMITS,
        )
        validated = model_type.model_validate_json(primitive_bytes)
        canonical_json_bytes(
            validated.model_dump(mode="json"),
            limits=BENCHMARK_JSON_LIMITS,
        )
    except (StrictJSONError, ValidationError, ValueError, TypeError) as exc:
        raise BenchmarkAdmissionError(
            "typed benchmark value failed primitive revalidation"
        ) from exc
    return validated


def parse_benchmark_bytes[ModelT: PydanticBaseModel](
    payload: bytes,
    model_type: type[ModelT],
) -> ModelT:
    """Parse exact canonical benchmark bytes with duplicate and resource limits."""

    wire = _require_bytes(payload, subject=model_type.__name__)
    try:
        document = strict_json_loads(wire, limits=BENCHMARK_JSON_LIMITS)
        duplicate_safe_bytes = canonical_json_bytes(
            document,
            limits=BENCHMARK_JSON_LIMITS,
        )
        validated = model_type.model_validate_json(duplicate_safe_bytes)
        canonical = canonical_json_bytes(
            validated.model_dump(mode="json"),
            limits=BENCHMARK_JSON_LIMITS,
        )
    except (StrictJSONError, ValidationError, ValueError, TypeError) as exc:
        raise BenchmarkAdmissionError(f"invalid {model_type.__name__} wire document") from exc
    if wire != canonical:
        raise BenchmarkAdmissionError(
            f"{model_type.__name__} wire document is not exact canonical JSON"
        )
    return validated


@dataclass(frozen=True, slots=True)
class _ResolvedScenario:
    index_entry: ScenarioIndexEntry
    raw: RawTrialSet
    raw_bytes: bytes
    specification: FrozenBenchmarkSpecification
    plan: FrozenPlan
    cab: VerifiedBenchmarkCAB
    trial_inputs: tuple[ResolvedTrialInputs, ...]


@dataclass(frozen=True, slots=True)
class _ResolvedBenchmark:
    combined: CombinedRawBenchmarkCorpus
    scenarios: tuple[_ResolvedScenario, _ResolvedScenario, _ResolvedScenario]


def _resolve_source_bundle(
    resolver: SourceBundleResolver,
    *,
    entry: ScenarioIndexEntry,
) -> VerifiedBenchmarkCAB:
    try:
        payload = resolver.resolve_source_bundle(
            scenario_id=entry.scenario_id,
            bundle_digest=entry.source_bundle_digest,
        )
    except Exception as exc:
        raise BenchmarkAdmissionError("source bundle resolver failed") from exc
    try:
        return verify_benchmark_cab(
            _require_bytes(payload, subject="resolved source CAB"),
            expected_snapshot_digest=entry.source_bundle_digest,
        )
    except BenchmarkCABError as exc:
        raise BenchmarkAdmissionError("source CAB failed bounded integrity verification") from exc


def _artifact_input(
    members: dict[str, bytes],
    reference: OpaqueArtifactReference,
) -> VerifiedArtifactInput:
    payload = members.get(reference.artifact_digest)
    if payload is None:
        raise BenchmarkAdmissionError(
            f"source CAB does not contain {reference.schema_name} by its content digest"
        )
    try:
        document = strict_json_loads(payload, limits=BENCHMARK_JSON_LIMITS)
        canonical = canonical_json_bytes(document, limits=BENCHMARK_JSON_LIMITS)
    except StrictJSONError as exc:
        raise BenchmarkAdmissionError("manifested benchmark artifact is not bounded JSON") from exc
    if canonical != payload:
        raise BenchmarkAdmissionError("manifested benchmark artifact is not exact canonical JSON")
    if not isinstance(document, dict):
        raise BenchmarkAdmissionError("benchmark artifact must be a JSON object")
    declared_schema = document.get("schema", document.get("wire_schema"))
    if declared_schema != reference.schema_name:
        raise BenchmarkAdmissionError("artifact bytes do not declare the referenced schema")
    return VerifiedArtifactInput(reference=reference, canonical_bytes=payload)


def _find_matching_recovery_cell(
    *,
    compiled_cells: tuple[GeneratedCell, ...],
    source_selector: CellSelector,
    replacement_input: TypedValue,
) -> str:
    source_document = source_selector.model_dump(mode="python")
    source_document["input"] = replacement_input.model_dump(mode="python")
    matches = [
        cell.key
        for cell in compiled_cells
        if cell.selector.model_dump(mode="python") == source_document
    ]
    if len(matches) != 1:
        raise BenchmarkAdmissionError(
            "frozen recovery selectors do not yield one exact matched input cell"
        )
    return matches[0]


def _derive_recovery_pairs(
    *,
    specification: FrozenBenchmarkSpecification,
    plan: FrozenPlan,
    raw: RawTrialSet,
) -> dict[str, ExpectedMatchedPair]:
    """Derive every pair from compiler selectors, never producer-authored labels."""

    compiled = compile_experiment(specification.contract)
    cells_by_key = {cell.key: cell for cell in compiled.cells}
    raw_by_key = {trial.trial_key: trial for trial in raw.trials}
    plan_by_key = {entry.trial_key: entry for entry in plan.entries}
    if raw_by_key.keys() != plan_by_key.keys():
        raise BenchmarkAdmissionError("recovery raw and frozen plan trial-key sets differ")
    raw_by_coordinates: dict[tuple[str, str, int], RawTrialEnvelope] = {}
    for trial_key, trial in raw_by_key.items():
        planned = plan_by_key[trial_key]
        if (
            trial.ordinal,
            trial.cell_key,
            trial.block,
            trial.replicate,
            trial.action.artifact,
        ) != (
            planned.ordinal,
            planned.cell_key,
            planned.block,
            planned.replicate,
            planned.action,
        ):
            raise BenchmarkAdmissionError(
                "recovery raw trial does not match its compiler-owned plan entry"
            )
        raw_by_coordinates[(trial.cell_key, trial.block, trial.replicate)] = trial

    profile = specification.contract.profile
    attack_value = profile.input.attack
    benign_value = profile.input.benign
    result: dict[str, ExpectedMatchedPair] = {}
    for trial in raw.trials:
        cell = cells_by_key.get(trial.cell_key)
        if cell is None:
            raise BenchmarkAdmissionError("recovery raw trial names an unknown frozen cell")
        input_value = cell.selector.input
        if input_value == attack_value:
            counterpart_input = benign_value
            expected_action_digest = profile.input.attack_action_digest
            is_attack = True
        elif input_value == benign_value:
            counterpart_input = attack_value
            expected_action_digest = profile.input.benign_action_digest
            is_attack = False
        else:
            raise BenchmarkAdmissionError(
                "recovery cell input is outside the frozen attack/benign axis"
            )
        if trial.action.artifact.artifact_digest != expected_action_digest:
            raise BenchmarkAdmissionError(
                "recovery action artifact does not match the frozen input-axis digest"
            )
        counterpart_cell_key = _find_matching_recovery_cell(
            compiled_cells=compiled.cells,
            source_selector=cell.selector,
            replacement_input=counterpart_input,
        )
        counterpart = raw_by_coordinates.get((counterpart_cell_key, trial.block, trial.replicate))
        if counterpart is None:
            raise BenchmarkAdmissionError(
                "recovery trial has no matched input trial in the same block and replicate"
            )
        if (
            trial.shared_lifecycle_proof is None
            or counterpart.shared_lifecycle_proof is None
            or trial.shared_lifecycle_proof != counterpart.shared_lifecycle_proof
        ):
            raise BenchmarkAdmissionError(
                "matched recovery trials do not bind the same lifecycle proof bytes"
            )
        if is_attack:
            attack, benign = trial, counterpart
        else:
            attack, benign = counterpart, trial
        if (
            attack.action.artifact.artifact_digest != profile.input.attack_action_digest
            or benign.action.artifact.artifact_digest != profile.input.benign_action_digest
        ):
            raise BenchmarkAdmissionError(
                "derived recovery pair does not bind the frozen attack and benign actions"
            )
        result[trial.trial_key] = ExpectedMatchedPair(
            subject_trial_key=trial.trial_key,
            attack_trial_key=attack.trial_key,
            benign_trial_key=benign.trial_key,
        )
    return result


def _resolve_scenario(
    *,
    entry: ScenarioIndexEntry,
    raw: RawTrialSet,
    raw_bytes: bytes,
    source_bundle_resolver: SourceBundleResolver,
) -> _ResolvedScenario:
    cab = _resolve_source_bundle(source_bundle_resolver, entry=entry)
    if (
        cab.manifest.experiment.id != entry.scenario_id
        or cab.manifest.experiment.spec_digest != entry.spec_digest
    ):
        raise BenchmarkAdmissionError("source CAB provenance does not match the scenario index")
    try:
        specification = parse_benchmark_bytes(
            cab.member(BENCHMARK_SPEC_PATH),
            FrozenBenchmarkSpecification,
        )
        supplied_plan_bytes = cab.member(BENCHMARK_PLAN_PATH)
        supplied_plan = parse_benchmark_bytes(supplied_plan_bytes, FrozenPlan)
        manifested_raw = cab.member(BENCHMARK_RAW_PATH)
    except BenchmarkCABError as exc:
        raise BenchmarkAdmissionError("source CAB is incomplete for benchmark admission") from exc
    if manifested_raw != raw_bytes:
        raise BenchmarkAdmissionError("raw trial-set bytes are not the source CAB member")
    if (
        specification.scenario_id != entry.scenario_id
        or specification.spec_digest != entry.spec_digest
    ):
        raise BenchmarkAdmissionError("compiled specification does not match the scenario index")
    expected_plan = compile_frozen_plan(specification)
    if supplied_plan != expected_plan or supplied_plan_bytes != canonical_model_bytes(
        expected_plan
    ):
        raise BenchmarkAdmissionError(
            "source CAB frozen plan differs from deterministic specification recompilation"
        )
    members = cab.content_by_digest()
    if any(trial.clone_readback.attestation_bundle_digest not in members for trial in raw.trials):
        raise BenchmarkAdmissionError("source CAB omits a referenced attestation artifact")
    expected_pairs = (
        _derive_recovery_pairs(
            specification=specification,
            plan=expected_plan,
            raw=raw,
        )
        if raw.scenario_id == RECOVERY_SCENARIO_ID
        else {}
    )
    trial_inputs = tuple(
        ResolvedTrialInputs(
            trial_key=trial.trial_key,
            action=_artifact_input(members, trial.action.artifact),
            runtime=_artifact_input(members, trial.runtime_artifact),
            shared_lifecycle_proof=(
                None
                if trial.shared_lifecycle_proof is None
                else _artifact_input(members, trial.shared_lifecycle_proof)
            ),
            expected_matched_pair=expected_pairs.get(trial.trial_key),
        )
        for trial in raw.trials
    )
    return _ResolvedScenario(
        index_entry=entry,
        raw=raw,
        raw_bytes=raw_bytes,
        specification=specification,
        plan=expected_plan,
        cab=cab,
        trial_inputs=trial_inputs,
    )


def _resolve_benchmark(
    *,
    index_bytes: bytes,
    raw_trial_set_bytes: Sequence[bytes],
    source_bundle_resolver: SourceBundleResolver,
) -> _ResolvedBenchmark:
    if len(raw_trial_set_bytes) != len(BENCHMARK_SCENARIO_IDS):
        raise BenchmarkAdmissionError("raw benchmark requires exactly three trial-set documents")
    index = parse_benchmark_bytes(index_bytes, BenchmarkIndex)
    raw_wires = tuple(
        _require_bytes(payload, subject=f"raw trial set {position}")
        for position, payload in enumerate(raw_trial_set_bytes, start=1)
    )
    raw_sets = tuple(parse_benchmark_bytes(payload, RawTrialSet) for payload in raw_wires)
    if tuple(raw.scenario_id for raw in raw_sets) != BENCHMARK_SCENARIO_IDS:
        raise BenchmarkAdmissionError("raw trial sets are not in frozen scenario order")
    index_by_scenario = {entry.scenario_id: entry for entry in index.scenarios}
    raw_by_scenario = {raw.scenario_id: raw for raw in raw_sets}
    raw_wire_by_scenario = {
        raw.scenario_id: raw_wires[position] for position, raw in enumerate(raw_sets)
    }
    resolved_values = tuple(
        _resolve_scenario(
            entry=index_by_scenario[scenario_id],
            raw=raw_by_scenario[scenario_id],
            raw_bytes=raw_wire_by_scenario[scenario_id],
            source_bundle_resolver=source_bundle_resolver,
        )
        for scenario_id in BENCHMARK_SCENARIO_IDS
    )
    resolved = (
        resolved_values[0],
        resolved_values[1],
        resolved_values[2],
    )
    try:
        combined = CombinedRawBenchmarkCorpus(
            wire_schema="assurance-lab.benchmark.combined-raw-corpus/v1",
            index=index,
            raw_trial_sets=raw_sets,
            frozen_plans=tuple(item.plan for item in resolved),
        )
    except ValidationError as exc:
        raise BenchmarkAdmissionError("raw benchmark failed exact cross-binding") from exc
    canonical_model_bytes(combined)
    return _ResolvedBenchmark(combined=combined, scenarios=resolved)


def admit_raw_benchmark(
    *,
    index_bytes: bytes,
    raw_trial_set_bytes: Sequence[bytes],
    source_bundle_resolver: SourceBundleResolver,
) -> CombinedRawBenchmarkCorpus:
    """Bind one index to exact verified CABs, specs, plans, raw sets, and members."""

    return _resolve_benchmark(
        index_bytes=index_bytes,
        raw_trial_set_bytes=raw_trial_set_bytes,
        source_bundle_resolver=source_bundle_resolver,
    ).combined


def _assert_exact_scenario_lineage(
    resolved: _ResolvedScenario,
    semantic: ScenarioSemanticResult,
) -> None:
    raw = resolved.raw
    raw_digest = _raw_sha256(canonical_model_bytes(raw))
    if (
        semantic.scenario_id != raw.scenario_id
        or semantic.spec_digest != raw.spec_digest
        or semantic.raw_trial_set_digest != raw_digest
    ):
        raise BenchmarkAdmissionError("semantic scenario does not bind its exact raw trial set")

    semantic_trials = [trial for cell in semantic.cells for trial in cell.trials]
    if len(semantic_trials) != len(raw.trials):
        raise BenchmarkAdmissionError("semantic scenario carries the wrong trial count")
    raw_trials_by_key = {trial.trial_key: trial for trial in raw.trials}
    inputs_by_key = {trial_inputs.trial_key: trial_inputs for trial_inputs in resolved.trial_inputs}
    semantic_trials_by_key = {trial.trial_key: trial for trial in semantic_trials}
    if raw_trials_by_key.keys() != semantic_trials_by_key.keys():
        raise BenchmarkAdmissionError("semantic and raw trial-key sets differ")
    for trial_key, raw_trial in raw_trials_by_key.items():
        semantic_trial = semantic_trials_by_key[trial_key]
        expected = (
            raw_trial.scenario_id,
            raw_trial.spec_digest,
            raw_trial.trial_key,
            raw_trial.cell_key,
            raw_trial.block,
            raw_trial.replicate,
            raw_trial.ordinal,
            raw_trial.trace_id,
            raw_trial.clone_readback.unique_instance_id,
            raw_trial.clone_readback.readback_digest,
            raw_trial.clone_readback.attestation_bundle_digest,
            raw_trial.clone_readback.runner_resource_id,
        )
        observed = (
            semantic_trial.scenario_id,
            semantic_trial.spec_digest,
            semantic_trial.trial_key,
            semantic_trial.cell_key,
            semantic_trial.block,
            semantic_trial.replicate,
            semantic_trial.ordinal,
            semantic_trial.trace_id,
            semantic_trial.clone_unique_instance_id,
            semantic_trial.clone_readback_digest,
            semantic_trial.attestation_bundle_digest,
            semantic_trial.runner_resource_id,
        )
        if observed != expected:
            raise BenchmarkAdmissionError(f"semantic trial {trial_key} does not match raw lineage")
        trial_inputs = inputs_by_key[trial_key]
        expected_pair = trial_inputs.expected_matched_pair
        expected_lineage: TrialSemanticLineage
        if expected_pair is None:
            lineage_body = {
                "mode": "single-trial",
                "lineage_schema": ("assurance-lab.benchmark.single-trial-lineage/v1"),
                "subject_trial_key": trial_key,
                "action_artifact": raw_trial.action.artifact.model_dump(mode="json"),
                "runtime_artifact": raw_trial.runtime_artifact.model_dump(mode="json"),
            }
            expected_lineage = SingleTrialSemanticLineage.model_validate(
                {
                    **lineage_body,
                    "lineage_digest": canonical_digest(lineage_body),
                },
                strict=True,
            )
        else:
            attack = raw_trials_by_key[expected_pair.attack_trial_key]
            benign = raw_trials_by_key[expected_pair.benign_trial_key]
            if attack.shared_lifecycle_proof is None:
                raise BenchmarkAdmissionError(
                    "derived recovery lineage lost its lifecycle proof reference"
                )
            lineage_body = {
                "mode": "matched-pair",
                "lineage_schema": ("assurance-lab.benchmark.matched-pair-lineage/v1"),
                "subject_trial_key": trial_key,
                "attack_trial_key": attack.trial_key,
                "benign_trial_key": benign.trial_key,
                "attack_action_artifact": attack.action.artifact.model_dump(mode="json"),
                "benign_action_artifact": benign.action.artifact.model_dump(mode="json"),
                "attack_runtime_artifact": attack.runtime_artifact.model_dump(mode="json"),
                "benign_runtime_artifact": benign.runtime_artifact.model_dump(mode="json"),
                "shared_lifecycle_proof": (attack.shared_lifecycle_proof.model_dump(mode="json")),
            }
            expected_lineage = MatchedPairSemanticLineage.model_validate(
                {
                    **lineage_body,
                    "lineage_digest": canonical_digest(lineage_body),
                },
                strict=True,
            )
        if semantic_trial.lineage != expected_lineage:
            raise BenchmarkAdmissionError(
                f"semantic trial {trial_key} does not bind its exact verifier inputs"
            )


def _verify_semantics(
    *,
    resolved: _ResolvedBenchmark,
    semantic_result_bytes: bytes,
    scenario_verifier: ScenarioVerifier,
) -> BenchmarkSemanticResult:
    combined = resolved.combined
    result = parse_benchmark_bytes(semantic_result_bytes, BenchmarkSemanticResult)
    if _raw_sha256(semantic_result_bytes) != combined.index.semantic_result_digest:
        raise BenchmarkAdmissionError("benchmark index does not bind the semantic result bytes")
    if (
        result.benchmark_id != combined.index.benchmark_id
        or result.benchmark_version != combined.index.benchmark_version
    ):
        raise BenchmarkAdmissionError("semantic result benchmark identity does not match index")
    if result.evaluator_id != scenario_verifier.evaluator_id:
        raise BenchmarkAdmissionError("semantic result names a different evaluator")
    if result.evaluator_digest != scenario_verifier.evaluator_digest:
        raise BenchmarkAdmissionError("semantic result carries a different evaluator digest")
    if result.issues:
        raise BenchmarkAdmissionError(
            "benchmark-wide issues require a dedicated benchmark verifier in this profile"
        )

    supplied_by_scenario = {scenario.scenario_id: scenario for scenario in result.scenarios}
    index_by_scenario = {scenario.scenario_id: scenario for scenario in combined.index.scenarios}
    for scenario in resolved.scenarios:
        raw = scenario.raw
        plan = scenario.plan
        try:
            verifier_output = scenario_verifier.verify_scenario(
                plan=plan,
                raw_trial_set=raw,
                trial_inputs=scenario.trial_inputs,
            )
        except Exception as exc:
            raise BenchmarkAdmissionError("scenario verifier failed") from exc
        recomputed = revalidate_benchmark_value(verifier_output, ScenarioSemanticResult)
        _assert_exact_scenario_lineage(scenario, recomputed)
        scenario_index = index_by_scenario[raw.scenario_id]
        if _raw_sha256(canonical_model_bytes(recomputed)) != (
            scenario_index.semantic_result_digest
        ):
            raise BenchmarkAdmissionError(
                "scenario index does not bind the recomputed semantic result"
            )
        if recomputed != supplied_by_scenario[raw.scenario_id]:
            raise BenchmarkAdmissionError(
                "producer semantic result differs from independent recomputation"
            )
    return result


def verify_benchmark_semantics(
    *,
    index_bytes: bytes,
    raw_trial_set_bytes: Sequence[bytes],
    semantic_result_bytes: bytes,
    source_bundle_resolver: SourceBundleResolver,
    scenario_verifier: ScenarioVerifier,
) -> BenchmarkSemanticResult:
    """Recompute and admit the exact indexed 144-trial semantic result."""

    resolved = _resolve_benchmark(
        index_bytes=index_bytes,
        raw_trial_set_bytes=raw_trial_set_bytes,
        source_bundle_resolver=source_bundle_resolver,
    )
    return _verify_semantics(
        resolved=resolved,
        semantic_result_bytes=semantic_result_bytes,
        scenario_verifier=scenario_verifier,
    )
