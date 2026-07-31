from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from assurance_lab.benchmark.admission import canonical_model_bytes
from assurance_lab.benchmark.cab import (
    BenchmarkCABError,
    decode_snapshot_entries,
    encode_snapshot_entries,
    raw_sha256,
    rebuild_manifest,
    verify_benchmark_cab,
)
from assurance_lab.benchmark.generator import (
    GeneratedPublicBenchmark,
    build_public_benchmark,
)
from assurance_lab.benchmark.models import (
    BENCHMARK_SCENARIO_IDS,
    DETECTION_SCENARIO_ID,
    RECOVERY_SCENARIO_ID,
    RESPONSE_SCENARIO_ID,
    TRIALS_PER_BENCHMARK,
    BenchmarkIndex,
    CorruptionIndexEntry,
    RawTrialSet,
    ScenarioIndexEntry,
    benchmark_corpus_digest,
)
from assurance_lab.benchmark.release_builder import _augment_benchmark
from assurance_lab.evidence.bundle import BundleManifest
from assurance_lab.evidence.canonical import canonical_json_bytes, strict_json_loads
from assurance_lab.evidence.snapshot import SNAPSHOT_MEDIA_TYPE


@pytest.fixture(scope="module")
def repeated_builds(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[GeneratedPublicBenchmark, GeneratedPublicBenchmark]:
    root = tmp_path_factory.mktemp("public-benchmark")
    return (
        build_public_benchmark(root / "first"),
        build_public_benchmark(root / "second"),
    )


def test_real_public_benchmark_is_byte_deterministic(
    repeated_builds: tuple[GeneratedPublicBenchmark, GeneratedPublicBenchmark],
) -> None:
    first, second = repeated_builds

    assert first.primary_semantic_result == second.primary_semantic_result
    assert tuple(source.scenario_id for source in first.sources) == (BENCHMARK_SCENARIO_IDS)
    assert tuple(source.snapshot_bytes for source in first.sources) == tuple(
        source.snapshot_bytes for source in second.sources
    )
    assert tuple(source.snapshot_digest for source in first.sources) == tuple(
        source.snapshot_digest for source in second.sources
    )
    assert (
        sum(
            len(cell.trials)
            for scenario in first.primary_semantic_result.scenarios
            for cell in scenario.cells
        )
        == TRIALS_PER_BENCHMARK
    )


def test_sources_bind_real_actions_runtimes_attestations_and_proof(
    repeated_builds: tuple[GeneratedPublicBenchmark, GeneratedPublicBenchmark],
) -> None:
    benchmark, _second = repeated_builds

    for source in benchmark.sources:
        cab = verify_benchmark_cab(
            source.snapshot_bytes,
            expected_snapshot_digest=source.snapshot_digest,
        )
        content = cab.content_by_digest()
        assert b"assurance-lab.runtime-observation/v1" not in source.snapshot_bytes
        assert len(source.raw_trial_set.trials) == 48
        for trial in source.raw_trial_set.trials:
            action = strict_json_loads(content[trial.action.artifact.artifact_digest])
            runtime = strict_json_loads(content[trial.runtime_artifact.artifact_digest])
            assert action["schema"] == trial.action.artifact.schema_name
            assert runtime["schema"] == trial.runtime_artifact.schema_name
            assert runtime["spec_digest"] == trial.spec_digest
            assert runtime["trial_key"] == trial.trial_key
            assert trial.clone_readback.attestation_bundle_digest in content

        embedded = [
            payload for path, payload in cab.entries if path.endswith("/source.cab.snapshot")
        ]
        assert len(embedded) == 1
        embedded_descriptors = [
            descriptor
            for descriptor in cab.manifest.files
            if descriptor.path.endswith("/source.cab.snapshot")
        ]
        assert len(embedded_descriptors) == 1
        assert embedded_descriptors[0].media_type == SNAPSHOT_MEDIA_TYPE
        if source.scenario_id == RECOVERY_SCENARIO_ID:
            proof_ref = source.raw_trial_set.trials[0].shared_lifecycle_proof
            assert proof_ref is not None
            proof = strict_json_loads(content[proof_ref.artifact_digest])
            assert proof["schema"] == ("assurance-lab.recovery-lifecycle-proof/v1")
            assert proof["source_snapshot_digest"] == raw_sha256(embedded[0])
            assert [item["path"] for item in proof["members"]] == [
                "records/lifecycle/admitted-receipts.json",
                "records/lifecycle/incident-lifecycle.json",
                "records/lifecycle/verified-lifecycle.json",
            ]
            assert (
                len(
                    {
                        trial.shared_lifecycle_proof.artifact_digest
                        for trial in source.raw_trial_set.trials
                        if trial.shared_lifecycle_proof is not None
                    }
                )
                == 1
            )


def test_source_snapshot_tampering_fails_closed(
    repeated_builds: tuple[GeneratedPublicBenchmark, GeneratedPublicBenchmark],
) -> None:
    source = repeated_builds[0].sources[0]
    changed = bytearray(source.snapshot_bytes)
    changed[-1] ^= 1

    with pytest.raises(BenchmarkCABError, match="index digest"):
        verify_benchmark_cab(
            bytes(changed),
            expected_snapshot_digest=source.snapshot_digest,
        )


def _semantic_crosscheck_index(
    benchmark: GeneratedPublicBenchmark,
) -> BenchmarkIndex:
    semantic_bytes = canonical_model_bytes(benchmark.primary_semantic_result)
    scenario_entries = tuple(
        ScenarioIndexEntry(
            scenario_id=source.scenario_id,
            spec_digest=source.specification.spec_digest,
            source_bundle_digest=source.snapshot_digest,
            raw_trial_set_digest=raw_sha256(canonical_model_bytes(source.raw_trial_set)),
            semantic_result_digest=raw_sha256(
                canonical_model_bytes(benchmark.primary_semantic_result.scenarios[position])
            ),
            cell_count=16,
            trial_count=48,
        )
        for position, source in enumerate(benchmark.sources)
    )
    corruptions = tuple(
        CorruptionIndexEntry(
            corruption_id=f"C{number:02d}",
            source_scenario_id=benchmark.sources[(number - 1) % 3].scenario_id,
            source_bundle_digest=benchmark.sources[(number - 1) % 3].snapshot_digest,
            corrupted_bundle_digest=raw_sha256(
                (
                    f"synthetic-corruption-index-for-semantic-crosscheck\\0bundle\\0{number:02d}"
                ).encode()
            ),
            receipt_digest=raw_sha256(
                (
                    f"synthetic-corruption-index-for-semantic-crosscheck\\0receipt\\0{number:02d}"
                ).encode()
            ),
        )
        for number in range(1, 21)
    )
    index = BenchmarkIndex(
        wire_schema="assurance-lab.benchmark.index/v1",
        benchmark_id="financial-control-lifecycle",
        benchmark_version="1.0.0",
        corpus_digest=raw_sha256(b"synthetic-corruption-index-for-semantic-crosscheck\\0pending"),
        semantic_result_digest=raw_sha256(semantic_bytes),
        scenario_count=3,
        cell_count=48,
        trial_count=144,
        replicates_per_cell=3,
        corruption_count=20,
        scenarios=scenario_entries,
        corruptions=corruptions,
    )
    return index.model_copy(
        update={
            "corpus_digest": benchmark_corpus_digest(
                index,
                (
                    benchmark.sources[0].plan,
                    benchmark.sources[1].plan,
                    benchmark.sources[2].plan,
                ),
            )
        }
    )


def _invoke_independent_node(
    benchmark: GeneratedPublicBenchmark,
    tmp_path: Path,
) -> subprocess.CompletedProcess[bytes]:
    repository_root = Path(__file__).resolve().parents[1]
    index_path = tmp_path / "index.json"
    semantic_path = tmp_path / "semantic-result.json"
    index_path.write_bytes(canonical_model_bytes(_semantic_crosscheck_index(benchmark)))
    semantic_path.write_bytes(canonical_model_bytes(benchmark.primary_semantic_result))
    command = [
        "node",
        str(repository_root / "verifier-js" / "src" / "benchmark-cli.js"),
        "--index",
        str(index_path),
        "--semantic",
        str(semantic_path),
    ]
    for source in benchmark.sources:
        source_path = tmp_path / f"{source.scenario_id}.cab.snapshot"
        source_path.write_bytes(source.snapshot_bytes)
        command.extend(["--source", f"{source.scenario_id}={source_path}"])
    return subprocess.run(
        command,
        cwd=repository_root,
        check=False,
        capture_output=True,
        timeout=30,
    )


def _mutate_one_runtime_object(
    benchmark: GeneratedPublicBenchmark,
    *,
    scenario_id: str,
    mutate: Callable[[dict[str, Any]], None],
) -> GeneratedPublicBenchmark:
    source = benchmark.source(scenario_id)  # type: ignore[arg-type]
    entries = dict(decode_snapshot_entries(source.snapshot_bytes))
    raw_document = strict_json_loads(entries["records/benchmark-raw-trial-set.json"])
    assert isinstance(raw_document, dict)
    trial = raw_document["trials"][0]
    old_digest = trial["runtime_artifact"]["artifact_digest"]
    assert (
        sum(
            item["runtime_artifact"]["artifact_digest"] == old_digest
            for item in raw_document["trials"]
        )
        == 1
    )
    old_path = f"records/objects/{old_digest.removeprefix('sha256:')}.json"
    runtime_document = strict_json_loads(entries.pop(old_path))
    assert isinstance(runtime_document, dict)
    mutate(runtime_document)
    runtime_bytes = canonical_json_bytes(runtime_document)
    new_digest = raw_sha256(runtime_bytes)
    assert new_digest != old_digest
    new_path = f"records/objects/{new_digest.removeprefix('sha256:')}.json"
    entries[new_path] = runtime_bytes
    trial["runtime_artifact"]["artifact_digest"] = new_digest
    raw_bytes = canonical_json_bytes(raw_document)
    entries["records/benchmark-raw-trial-set.json"] = raw_bytes

    manifest = BundleManifest.model_validate_json(entries["bundle.json"])
    descriptors: list[dict[str, Any]] = []
    for descriptor in manifest.files:
        document = descriptor.model_dump(mode="python")
        if descriptor.path == old_path:
            document.update(
                path=new_path,
                sha256=new_digest.removeprefix("sha256:"),
                size=len(runtime_bytes),
            )
        elif descriptor.path == "records/benchmark-raw-trial-set.json":
            document.update(
                sha256=raw_sha256(raw_bytes).removeprefix("sha256:"),
                size=len(raw_bytes),
            )
        descriptors.append(document)
    manifest_document = manifest.model_dump(mode="python")
    manifest_document["files"] = sorted(
        descriptors,
        key=lambda item: item["path"],
    )
    entries["bundle.json"] = canonical_json_bytes(
        BundleManifest.model_validate(manifest_document).model_dump(mode="json")
    )
    snapshot = encode_snapshot_entries(
        (
            ("bundle.json", entries["bundle.json"]),
            *tuple(
                sorted(
                    (path, payload) for path, payload in entries.items() if path != "bundle.json"
                )
            ),
        )
    )
    replacement_source = replace(
        source,
        raw_trial_set=RawTrialSet.model_validate_json(raw_bytes),
        snapshot_bytes=snapshot,
        snapshot_digest=raw_sha256(snapshot),
    )
    replacement_sources = tuple(
        replacement_source if item.scenario_id == scenario_id else item
        for item in benchmark.sources
    )
    return GeneratedPublicBenchmark(
        sources=replacement_sources,  # type: ignore[arg-type]
        primary_semantic_result=benchmark.primary_semantic_result,
    )


def _replace_source(
    benchmark: GeneratedPublicBenchmark,
    *,
    scenario_id: str,
    snapshot_bytes: bytes,
) -> GeneratedPublicBenchmark:
    source = benchmark.source(scenario_id)  # type: ignore[arg-type]
    replacement = replace(
        source,
        snapshot_bytes=snapshot_bytes,
        snapshot_digest=raw_sha256(snapshot_bytes),
    )
    sources = tuple(
        replacement if item.scenario_id == scenario_id else item for item in benchmark.sources
    )
    return GeneratedPublicBenchmark(
        sources=sources,  # type: ignore[arg-type]
        primary_semantic_result=benchmark.primary_semantic_result,
    )


def _deeply_mutate_embedded_recovery_producer(
    benchmark: GeneratedPublicBenchmark,
) -> GeneratedPublicBenchmark:
    source = benchmark.source(RECOVERY_SCENARIO_ID)
    outer_entries = dict(decode_snapshot_entries(source.snapshot_bytes))
    producer_path = "artifacts/producers/financial-entitlement-recovery/source.cab.snapshot"
    producer_entries = dict(decode_snapshot_entries(outer_entries[producer_path]))
    target = "records/lifecycle/approved-case-scoped/cutover-reference.json"
    document = strict_json_loads(producer_entries[target])
    assert isinstance(document, dict)
    document["replacement_session_id"] = "SYNTH-COHERENT-BUT-UNPINNED-SESSION"
    producer_entries[target] = canonical_json_bytes(document)
    rebuilt_producer = rebuild_manifest(
        (
            ("bundle.json", producer_entries["bundle.json"]),
            *tuple(
                sorted(
                    (path, payload)
                    for path, payload in producer_entries.items()
                    if path != "bundle.json"
                )
            ),
        ),
        changed_paths=frozenset({target}),
    )
    producer_snapshot = encode_snapshot_entries(rebuilt_producer)
    verify_benchmark_cab(
        producer_snapshot,
        expected_snapshot_digest=raw_sha256(producer_snapshot),
    )
    outer_entries[producer_path] = producer_snapshot
    rebuilt_outer = rebuild_manifest(
        (
            ("bundle.json", outer_entries["bundle.json"]),
            *tuple(
                sorted(
                    (path, payload)
                    for path, payload in outer_entries.items()
                    if path != "bundle.json"
                )
            ),
        ),
        changed_paths=frozenset({producer_path}),
    )
    snapshot = encode_snapshot_entries(rebuilt_outer)
    verify_benchmark_cab(snapshot, expected_snapshot_digest=raw_sha256(snapshot))
    return _replace_source(
        benchmark,
        scenario_id=RECOVERY_SCENARIO_ID,
        snapshot_bytes=snapshot,
    )


def _add_coherently_manifested_object(
    benchmark: GeneratedPublicBenchmark,
    *,
    scenario_id: str,
) -> GeneratedPublicBenchmark:
    source = benchmark.source(scenario_id)  # type: ignore[arg-type]
    entries = dict(decode_snapshot_entries(source.snapshot_bytes))
    payload = canonical_json_bytes(
        {
            "schema": "assurance-lab.hostile-extra-object/v1",
            "value": "coherently manifested but outside the pinned source profile",
        }
    )
    digest = raw_sha256(payload)
    path = f"records/objects/{digest.removeprefix('sha256:')}.json"
    assert path not in entries
    entries[path] = payload
    manifest = BundleManifest.model_validate_json(entries["bundle.json"], strict=True)
    exemplar = next(
        descriptor
        for descriptor in manifest.files
        if descriptor.path.startswith("records/objects/")
    )
    descriptor = exemplar.model_copy(
        update={
            "path": path,
            "sha256": digest.removeprefix("sha256:"),
            "size": len(payload),
        }
    )
    manifest_document = manifest.model_dump(mode="python")
    manifest_document["files"] = sorted(
        [*manifest.files, descriptor],
        key=lambda item: item.path,
    )
    entries["bundle.json"] = canonical_json_bytes(
        BundleManifest.model_validate(manifest_document, strict=True).model_dump(mode="json")
    )
    snapshot = encode_snapshot_entries(
        (
            ("bundle.json", entries["bundle.json"]),
            *tuple(
                sorted(
                    (member_path, member)
                    for member_path, member in entries.items()
                    if member_path != "bundle.json"
                )
            ),
        )
    )
    verify_benchmark_cab(snapshot, expected_snapshot_digest=raw_sha256(snapshot))
    return _replace_source(
        benchmark,
        scenario_id=scenario_id,
        snapshot_bytes=snapshot,
    )


def _mutate_augmented_producer_witness(
    benchmark: GeneratedPublicBenchmark,
    *,
    scenario_id: str,
    witness_path: str,
) -> GeneratedPublicBenchmark:
    source = benchmark.source(scenario_id)  # type: ignore[arg-type]
    entries = dict(decode_snapshot_entries(source.snapshot_bytes))
    original = entries[witness_path]
    if witness_path.endswith(".json"):
        document = strict_json_loads(original)
        assert isinstance(document, dict)
        document["hostile_extension"] = "valid JSON, but not the pinned producer witness"
        replacement = canonical_json_bytes(document)
    else:
        documents = [strict_json_loads(line) for line in original.splitlines() if line]
        assert documents and isinstance(documents[0], dict)
        documents[0]["hostile_extension"] = (
            "valid NDJSON, but not the pinned producer witness"
        )
        replacement = b"\n".join(canonical_json_bytes(document) for document in documents)
        if original.endswith(b"\n"):
            replacement += b"\n"
    assert replacement != original
    entries[witness_path] = replacement
    rebuilt = rebuild_manifest(
        (
            ("bundle.json", entries["bundle.json"]),
            *tuple(
                sorted(
                    (path, payload) for path, payload in entries.items() if path != "bundle.json"
                )
            ),
        ),
        changed_paths=frozenset({witness_path}),
    )
    snapshot = encode_snapshot_entries(rebuilt)
    verify_benchmark_cab(snapshot, expected_snapshot_digest=raw_sha256(snapshot))
    return _replace_source(
        benchmark,
        scenario_id=scenario_id,
        snapshot_bytes=snapshot,
    )


def test_independent_node_verifier_matches_real_python_primary_semantics(
    repeated_builds: tuple[GeneratedPublicBenchmark, GeneratedPublicBenchmark],
    tmp_path: Path,
) -> None:
    """Cross-check the real 144 trials; corruptions here are index placeholders only."""

    unaugmented_benchmark, _second = repeated_builds
    benchmark = _augment_benchmark(unaugmented_benchmark)
    completed = _invoke_independent_node(benchmark, tmp_path)
    assert completed.returncode == 0, (
        completed.stdout.decode(errors="replace"),
        completed.stderr.decode(errors="replace"),
    )
    receipt = strict_json_loads(completed.stdout)
    assert receipt["status"] == "verified"
    assert receipt["agreement"] == "agreed"
    assert receipt["issues"] == []
    assert (
        receipt["claimed_semantic_projection_digest"]
        == receipt["recomputed_semantic_projection_digest"]
        == "sha256:22a2d0cd7124aa01826614140630c2d98c2e0b1df2943370e0ea058cf7d911f9"
    )
    assert len(receipt["source_snapshot_digests"]) == 3
    assert (
        sum(
            len(cell.trials)
            for scenario in benchmark.primary_semantic_result.scenarios
            for cell in scenario.cells
        )
        == TRIALS_PER_BENCHMARK
    )


def test_independent_node_verifier_rejects_a_deep_embedded_producer_rewrite(
    repeated_builds: tuple[GeneratedPublicBenchmark, GeneratedPublicBenchmark],
    tmp_path: Path,
) -> None:
    benchmark = _augment_benchmark(repeated_builds[0])
    hostile = _deeply_mutate_embedded_recovery_producer(benchmark)

    completed = _invoke_independent_node(hostile, tmp_path)

    assert completed.returncode == 1, completed.stderr.decode(errors="replace")
    receipt = strict_json_loads(completed.stdout)
    assert receipt["status"] == "rejected"
    assert receipt["issues"][0]["code"] == "source-substitution"


def test_independent_node_verifier_rejects_a_coherent_extra_object(
    repeated_builds: tuple[GeneratedPublicBenchmark, GeneratedPublicBenchmark],
    tmp_path: Path,
) -> None:
    benchmark = _augment_benchmark(repeated_builds[0])
    hostile = _add_coherently_manifested_object(
        benchmark,
        scenario_id=DETECTION_SCENARIO_ID,
    )

    completed = _invoke_independent_node(hostile, tmp_path)

    assert completed.returncode == 1, completed.stderr.decode(errors="replace")
    receipt = strict_json_loads(completed.stdout)
    assert receipt["status"] == "rejected"
    assert receipt["issues"][0]["code"] == "invalid-manifest"


@pytest.mark.parametrize(
    ("scenario_id", "witness_path"),
    (
        (DETECTION_SCENARIO_ID, "spec/compiled-experiment.json"),
        (RESPONSE_SCENARIO_ID, "records/trial-records.jsonl"),
    ),
)
def test_independent_node_verifier_rejects_augmented_producer_witness_rewrite(
    repeated_builds: tuple[GeneratedPublicBenchmark, GeneratedPublicBenchmark],
    tmp_path: Path,
    scenario_id: str,
    witness_path: str,
) -> None:
    benchmark = _augment_benchmark(repeated_builds[0])
    hostile = _mutate_augmented_producer_witness(
        benchmark,
        scenario_id=scenario_id,
        witness_path=witness_path,
    )

    completed = _invoke_independent_node(hostile, tmp_path)

    assert completed.returncode == 1, completed.stderr.decode(errors="replace")
    receipt = strict_json_loads(completed.stdout)
    assert receipt["status"] == "rejected"
    assert receipt["issues"][0]["code"] == "producer-witness-substitution"


def test_independent_node_verifier_rejects_forged_primary_evaluator_attribution(
    repeated_builds: tuple[GeneratedPublicBenchmark, GeneratedPublicBenchmark],
    tmp_path: Path,
) -> None:
    benchmark = _augment_benchmark(repeated_builds[0])
    hostile = GeneratedPublicBenchmark(
        sources=benchmark.sources,
        primary_semantic_result=benchmark.primary_semantic_result.model_copy(
            update={"evaluator_id": "control-assurance/coherently-forged-producer"}
        ),
    )

    completed = _invoke_independent_node(hostile, tmp_path)

    assert completed.returncode == 1, completed.stderr.decode(errors="replace")
    receipt = strict_json_loads(completed.stdout)
    assert receipt["status"] == "rejected"
    assert receipt["issues"][0]["code"] == "semantic-result-substitution"


def _corrupt_detection_window_closure(runtime: dict[str, Any]) -> None:
    runtime["result"]["window_closure"]["closed_at_ms"] = 1_999


def _corrupt_response_resource_identity(runtime: dict[str, Any]) -> None:
    runtime["result"]["resource_identity"]["observed_runner_resource_id"] = "forged-response-runner"


@pytest.mark.parametrize(
    ("scenario_id", "mutate", "expected_code"),
    (
        (
            DETECTION_SCENARIO_ID,
            _corrupt_detection_window_closure,
            "runtime-contradiction",
        ),
        (
            RESPONSE_SCENARIO_ID,
            _corrupt_response_resource_identity,
            "attestation-substitution",
        ),
    ),
    ids=("nested-detection-closure", "nested-response-resource"),
)
def test_independent_node_verifier_rejects_nested_runtime_substitution(
    repeated_builds: tuple[GeneratedPublicBenchmark, GeneratedPublicBenchmark],
    tmp_path: Path,
    scenario_id: str,
    mutate: Callable[[dict[str, Any]], None],
    expected_code: str,
) -> None:
    """Rebuild every content address around a hostile nested runtime change."""

    benchmark = _augment_benchmark(repeated_builds[0])
    corrupted = _mutate_one_runtime_object(
        benchmark,
        scenario_id=scenario_id,
        mutate=mutate,
    )

    completed = _invoke_independent_node(corrupted, tmp_path)

    assert completed.returncode == 1, completed.stderr.decode(errors="replace")
    receipt = strict_json_loads(completed.stdout)
    assert receipt["status"] == "rejected"
    assert receipt["agreement"] == "not-compared"
    assert receipt["issues"][0]["code"] == expected_code
