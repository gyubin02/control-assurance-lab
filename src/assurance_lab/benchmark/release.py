"""One fail-closed admission boundary for a complete benchmark release."""

from __future__ import annotations

from dataclasses import dataclass

from assurance_lab.benchmark.admission import (
    ScenarioVerifier,
    SourceBundleResolver,
    _resolve_benchmark,
    _verify_semantics,
)
from assurance_lab.benchmark.corruption import (
    CorruptionBundleResolver,
    CorruptionVerifier,
    _verify_corruptions,
)
from assurance_lab.benchmark.models import (
    BenchmarkSemanticResult,
    CombinedRawBenchmarkCorpus,
    IndexedCorruptionCorpus,
)


@dataclass(frozen=True, slots=True)
class AdmittedBenchmarkRelease:
    """All release components admitted against one exact index and source corpus."""

    raw_corpus: CombinedRawBenchmarkCorpus
    semantic_result: BenchmarkSemanticResult
    corruption_corpus: IndexedCorruptionCorpus


def admit_benchmark_release(
    *,
    index_bytes: bytes,
    raw_trial_set_bytes: tuple[bytes, bytes, bytes],
    semantic_result_bytes: bytes,
    corruption_receipt_bytes: tuple[bytes, ...],
    source_bundle_resolver: SourceBundleResolver,
    corrupted_bundle_resolver: CorruptionBundleResolver,
    scenario_verifier: ScenarioVerifier,
    corruption_verifier: CorruptionVerifier,
) -> AdmittedBenchmarkRelease:
    """Admit semantics and C01-C20 against one resolved, verified CAB corpus."""

    resolved = _resolve_benchmark(
        index_bytes=index_bytes,
        raw_trial_set_bytes=raw_trial_set_bytes,
        source_bundle_resolver=source_bundle_resolver,
    )
    semantic = _verify_semantics(
        resolved=resolved,
        semantic_result_bytes=semantic_result_bytes,
        scenario_verifier=scenario_verifier,
    )
    corruptions = _verify_corruptions(
        resolved=resolved,
        receipt_bytes=corruption_receipt_bytes,
        corrupted_bundle_resolver=corrupted_bundle_resolver,
        verifier=corruption_verifier,
    )
    if corruptions.index != resolved.combined.index:
        raise RuntimeError("release admission produced two different benchmark indexes")
    return AdmittedBenchmarkRelease(
        raw_corpus=resolved.combined,
        semantic_result=semantic,
        corruption_corpus=corruptions,
    )


__all__ = ["AdmittedBenchmarkRelease", "admit_benchmark_release"]
