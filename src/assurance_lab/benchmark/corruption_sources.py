"""Deterministic, executable source CABs for the C01-C20 corruption profile.

The corruption suite is not allowed to invent a parallel ``records/*.jsonl``
shape merely because that shape is convenient to mutate.  This module creates
the three source CABs from the real financial implementations:

* detection records are a lossless JSON rendering of
  :class:`FinancialDetectionRuntimeResult` from all compiler-planned trials;
* response evidence is written by ``FinancialResponseExperimentRunner``; and
* recovery lifecycle evidence is written by the lifecycle CAB producer.

The fixed plan helpers below are also the only source of trial identities used
by ``benchmark.corruption``.  A locator therefore changes when, and only when,
the producing contract changes.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, is_dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any, cast

from assurance_lab.benchmark.cab import VerifiedBenchmarkCAB, verify_benchmark_cab
from assurance_lab.benchmark.models import (
    DETECTION_SCENARIO_ID,
    RECOVERY_SCENARIO_ID,
    RESPONSE_SCENARIO_ID,
    ScenarioId,
)
from assurance_lab.contract import (
    CellSelector,
    CompiledExperiment,
    EvidencePolicyRef,
    EvidenceWindow,
    ExperimentScope,
    PlannedTrial,
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
from assurance_lab.evidence.canonical import canonical_json_bytes, canonical_jsonl_bytes
from assurance_lab.evidence.snapshot import capture_cab_snapshot
from assurance_lab.evidence.writer import BundleMetadata, PayloadFile, write_bundle
from assurance_lab.scenarios.financial_detection_contract import (
    build_financial_detection_contract,
)
from assurance_lab.scenarios.financial_detection_runtime import (
    CLOCK_SPEC_DIGEST,
    FinancialDetectionRuntime,
)
from assurance_lab.scenarios.financial_recovery_e2e import (
    write_reference_recovery_lifecycle_bundle,
)
from assurance_lab.scenarios.financial_response_contract import (
    build_financial_response_contract,
)
from assurance_lab.scenarios.financial_response_e2e import (
    build_reference_financial_response_experiment,
)

_START = datetime(2026, 7, 29, 0, 0, tzinfo=UTC)
_BLOCK = "sqlite-fresh-clone"
_REPLICATES = 3
_DETECTION_ORDER_SEED = "financial-detection-corruption-v1"
_RESPONSE_ORDER_SEED = "financial-response-corruption-v1"
_DETECTION_RUNTIME_PATH = "records/runtime-observations.jsonl"
_DETECTION_SPEC_PATH = "spec/experiment.json"
_DETECTION_COMPILED_PATH = "spec/compiled-experiment.json"


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


@lru_cache(maxsize=1)
def detection_corruption_compiled() -> CompiledExperiment:
    """Return the exact three-replicate detection plan used by the corpus."""

    scope = ExperimentScope(
        scenario_id=DETECTION_SCENARIO_ID,
        build_digest=_digest("financial-detection-runtime/v1"),
        dataset_digest=CLOCK_SPEC_DIGEST,
        fixture_digest=_digest("financial-detection-fixed-fixture/v1"),
        assessment_as_of=_START + timedelta(minutes=30),
        evidence_window=EvidenceWindow(
            start=_START,
            end=_START + timedelta(hours=1),
        ),
        evidence_policy=EvidencePolicyRef(
            id="financial-detection-bundle-v1",
            version="1.0.0",
            digest=_digest("financial-detection-bundle-v1"),
        ),
    )
    return compile_experiment(
        build_financial_detection_contract(
            scope=scope,
            plan=TrialPlan(
                blocks=(_BLOCK,),
                replicates=_REPLICATES,
                order_seed=_DETECTION_ORDER_SEED,
            ),
        )
    )


@lru_cache(maxsize=1)
def response_corruption_compiled() -> CompiledExperiment:
    """Return the exact three-replicate plan accepted by the response writer."""

    _runner, reference = build_reference_financial_response_experiment(start=_START)
    return compile_experiment(
        build_financial_response_contract(
            scope=reference.contract.scope,
            plan=TrialPlan(
                blocks=(_BLOCK,),
                replicates=_REPLICATES,
                order_seed=_RESPONSE_ORDER_SEED,
            ),
        )
    )


def planned_trial(
    compiled: CompiledExperiment,
    *,
    input_level: str,
    target_level: str,
    compensator_level: str,
    sham_level: str,
    replicate: int,
) -> PlannedTrial:
    """Select one compiler-owned trial by its four factor values and replicate."""

    cells = {cell.key: cell.selector for cell in compiled.cells}
    matches = [
        planned
        for planned in compiled.planned_trials
        if planned.replicate == replicate
        and _selector_values(cells[planned.cell_key])
        == (input_level, target_level, compensator_level, sham_level)
    ]
    if len(matches) != 1:
        raise RuntimeError("frozen corruption coordinate did not select one planned trial")
    return matches[0]


def _selector_values(selector: CellSelector) -> tuple[str, str, str, str]:
    values = (
        selector.input,
        selector.target,
        selector.compensator,
        selector.sham,
    )
    result: list[str] = []
    for value in values:
        rendered = getattr(value, "value", None)
        if not isinstance(rendered, str):
            raise RuntimeError("financial corruption profile requires string factors")
        result.append(rendered)
    return cast(tuple[str, str, str, str], tuple(result))


def _json_value(value: Any) -> Any:
    """Convert one runtime dataclass tree to ordinary JSON values, losslessly."""

    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return _json_value(asdict(value))
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if value is None or type(value) in {str, int, bool, float}:
        return value
    raise TypeError(f"runtime result contains unsupported JSON value {type(value)!r}")


def write_detection_corruption_source(destination: Path) -> CompiledExperiment:
    """Run all 48 real detection trials and write their canonical CAB."""

    compiled = detection_corruption_compiled()
    runtime = FinancialDetectionRuntime()
    cells = {cell.key: cell.selector for cell in compiled.cells}
    records: list[dict[str, Any]] = []
    for planned in sorted(compiled.planned_trials, key=lambda item: item.ordinal):
        result = runtime.execute(
            cells[planned.cell_key],
            trace_id=f"financial-detection-trace-{planned.ordinal:04d}-{planned.key[-12:]}",
        )
        records.append(
            {
                "id": planned.key,
                "schema_name": (
                    "assurance-lab.financial-detection-runtime-observation/v1"
                ),
                "spec_digest": compiled.spec_digest,
                "trial_key": planned.key,
                "cell_key": planned.cell_key,
                "block": planned.block,
                "replicate": planned.replicate,
                "ordinal": planned.ordinal,
                "result": _json_value(result),
            }
        )
    scope = compiled.contract.scope
    verification = write_bundle(
        destination,
        metadata=BundleMetadata(
            created_at=scope.assessment_as_of,
            as_of=scope.assessment_as_of,
            experiment=ExperimentRef(
                id=compiled.contract.id,
                spec_version=compiled.contract.version,
                spec_digest=compiled.spec_digest,
            ),
            evaluation=EvaluationRef(
                policy_id=scope.evidence_policy.id,
                policy_digest=scope.evidence_policy.digest,
                evaluator=EvaluatorRef(
                    name="assurance-lab-financial-detection-runtime",
                    version="1.0.0",
                    source_revision="financial-detection-runtime-v1",
                    image_digest=None,
                ),
            ),
        ),
        payloads=(
            PayloadFile(
                path=_DETECTION_SPEC_PATH,
                content=compiled.canonical_spec.encode("utf-8"),
                media_type="application/json",
                role="compiler-owned detection experiment",
                sensitivity=Sensitivity.SYNTHETIC,
                required_for=("design", "corruption-replay"),
            ),
            PayloadFile(
                path=_DETECTION_COMPILED_PATH,
                content=canonical_json_bytes(compiled.model_dump(mode="json")),
                media_type="application/json",
                role="compiler-owned detection cells and execution plan",
                sensitivity=Sensitivity.SYNTHETIC,
                required_for=("design", "protocol-coverage", "corruption-replay"),
            ),
            PayloadFile(
                path=_DETECTION_RUNTIME_PATH,
                content=canonical_jsonl_bytes(records),
                media_type="application/x-ndjson",
                role="lossless financial detection runtime readbacks",
                sensitivity=Sensitivity.SYNTHETIC,
                required_for=("runtime-reconstruction", "corruption-replay"),
            ),
        ),
    )
    if verification.status is not BundleStatus.INTEGRITY_VERIFIED:
        raise RuntimeError("detection corruption source failed CAB integrity")
    return compiled


def write_response_corruption_source(destination: Path) -> CompiledExperiment:
    """Use the existing response writer to produce all 48 source trials."""

    runner, _reference = build_reference_financial_response_experiment(start=_START)
    compiled = response_corruption_compiled()
    verification = runner.run(compiled, destination)
    if verification.status is not BundleStatus.INTEGRITY_VERIFIED:
        raise RuntimeError("response corruption source failed CAB integrity")
    return compiled


@dataclass(frozen=True, slots=True)
class RealCorruptionSourceCorpus:
    """Three exact source snapshots addressed by benchmark scenario identity."""

    sources: dict[ScenarioId, VerifiedBenchmarkCAB]

    def source(self, scenario_id: ScenarioId) -> VerifiedBenchmarkCAB:
        return self.sources[scenario_id]


def build_real_corruption_source_corpus(root: Path) -> RealCorruptionSourceCorpus:
    """Create, snapshot, and independently verify all real source CABs."""

    root.mkdir(parents=False, mode=0o700)
    paths: dict[ScenarioId, Path] = {
        DETECTION_SCENARIO_ID: root / "detection.cab",
        RESPONSE_SCENARIO_ID: root / "response.cab",
        RECOVERY_SCENARIO_ID: root / "recovery.cab",
    }
    write_detection_corruption_source(paths[DETECTION_SCENARIO_ID])
    write_response_corruption_source(paths[RESPONSE_SCENARIO_ID])
    write_reference_recovery_lifecycle_bundle(paths[RECOVERY_SCENARIO_ID])

    sources: dict[ScenarioId, VerifiedBenchmarkCAB] = {}
    for scenario_id, path in paths.items():
        sealed = capture_cab_snapshot(path)
        sources[scenario_id] = verify_benchmark_cab(
            sealed.snapshot_bytes,
            expected_snapshot_digest=sealed.snapshot_digest,
        )
    return RealCorruptionSourceCorpus(sources=sources)


def copy_real_corruption_members(
    corpus: RealCorruptionSourceCorpus,
    scenario_id: ScenarioId,
) -> dict[str, bytes]:
    """Return real producer members for embedding in a benchmark source CAB."""

    return {
        path: payload
        for path, payload in corpus.source(scenario_id).entries
        if path != "bundle.json"
    }


__all__ = [
    "RealCorruptionSourceCorpus",
    "build_real_corruption_source_corpus",
    "copy_real_corruption_members",
    "detection_corruption_compiled",
    "planned_trial",
    "response_corruption_compiled",
    "write_detection_corruption_source",
    "write_response_corruption_source",
]
