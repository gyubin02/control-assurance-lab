from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from assurance_lab.benchmark.cab import (
    BenchmarkCABError,
    VerifiedBenchmarkCAB,
    decode_snapshot_entries,
    verify_benchmark_cab,
)
from assurance_lab.benchmark.corruption import (
    FROZEN_CORRUPTION_SPECS,
    CorruptionReplay,
    ExpectedVerifierResult,
    ManifestPolicy,
    MutationOperation,
    replay_frozen_corruption,
)
from assurance_lab.benchmark.corruption_sources import (
    RealCorruptionSourceCorpus,
    build_real_corruption_source_corpus,
)
from assurance_lab.benchmark.models import (
    DETECTION_SCENARIO_ID,
    RECOVERY_SCENARIO_ID,
    RESPONSE_SCENARIO_ID,
)
from assurance_lab.evidence.bundle import BundleManifest
from assurance_lab.evidence.canonical import (
    canonical_json_bytes,
    strict_json_loads,
    strict_jsonl_loads,
)
from assurance_lab.evidence.snapshot import CABSnapshotError, verify_cab_snapshot

_ABSENT = b"assurance-lab:json-pointer-absent/v1"


@pytest.fixture(scope="module")
def real_sources(tmp_path_factory: pytest.TempPathFactory) -> RealCorruptionSourceCorpus:
    return build_real_corruption_source_corpus(
        tmp_path_factory.mktemp("real-corruption-corpus") / "sources"
    )


@pytest.fixture(scope="module")
def real_replays(
    real_sources: RealCorruptionSourceCorpus,
) -> dict[str, CorruptionReplay]:
    return {
        specification.corruption_id: replay_frozen_corruption(
            real_sources.source(specification.source_scenario_id),
            specification,
        )
        for specification in FROZEN_CORRUPTION_SPECS
    }


def _tokens(pointer: str) -> tuple[str, ...]:
    return tuple(
        part.replace("~1", "/").replace("~0", "~")
        for part in pointer.removeprefix("/").split("/")
    )


def _value(document: Any, pointer: str) -> Any:
    current = document
    for token in _tokens(pointer):
        current = current[token] if isinstance(current, dict) else current[int(token)]
    return current


def _target_value(
    source: VerifiedBenchmarkCAB | bytes,
    *,
    path: str,
    record_key: str,
    pointer: str,
) -> bytes:
    entries = (
        dict(source.entries)
        if isinstance(source, VerifiedBenchmarkCAB)
        else dict(decode_snapshot_entries(source))
    )
    payload = entries[path]
    if path.endswith(".jsonl"):
        records = strict_jsonl_loads(payload, require_sorted_ids=True)
        matches = [record for record in records if record.get("id") == record_key]
        assert len(matches) == 1
        document = matches[0]
    else:
        document = strict_json_loads(payload)
        assert isinstance(document, dict)
        assert record_key == "$"
    try:
        return canonical_json_bytes(_value(document, pointer))
    except (KeyError, IndexError):
        return _ABSENT


def test_real_source_cabs_are_deterministic(
    real_sources: RealCorruptionSourceCorpus,
    tmp_path: Path,
) -> None:
    repeated = build_real_corruption_source_corpus(tmp_path / "repeat")

    assert set(real_sources.sources) == {
        DETECTION_SCENARIO_ID,
        RESPONSE_SCENARIO_ID,
        RECOVERY_SCENARIO_ID,
    }
    for scenario_id, source in real_sources.sources.items():
        assert source.snapshot_bytes == repeated.source(scenario_id).snapshot_bytes
        assert source.snapshot_digest == repeated.source(scenario_id).snapshot_digest
        verify_benchmark_cab(
            source.snapshot_bytes,
            expected_snapshot_digest=source.snapshot_digest,
        )


def test_frozen_map_names_only_real_producer_members(
    real_sources: RealCorruptionSourceCorpus,
) -> None:
    expected_paths = {
        "C01": "records/runtime-observations.jsonl",
        "C02": "spec/compiled-experiment.json",
        "C03": "records/trial-records.jsonl",
        "C04": "artifacts/trial-attestations.jsonl",
        "C05": "records/trial-records.jsonl",
        "C06": "records/runtime-observations.jsonl",
        "C07": "records/runtime-observations.jsonl",
        "C08": "records/runtime-observations.jsonl",
        "C09": "records/runtime-observations.jsonl",
        "C10": "records/runtime-observations.jsonl",
        "C11": "records/runtime-observations.jsonl",
        "C12": "artifacts/cleanup-observations.jsonl",
        "C13": "records/runtime-observations.jsonl",
        "C14": "records/lifecycle/admitted-receipts.json",
        "C15": "records/lifecycle/incident-lifecycle.json",
        "C16": "records/lifecycle/incident-lifecycle.json",
        "C17": "bundle.json",
        "C18": "records/stage-events.jsonl",
        "C19": "records/runtime-observations.jsonl",
        "C20": "records/runtime-observations.jsonl",
    }

    assert {
        specification.corruption_id: specification.target_artifact_path
        for specification in FROZEN_CORRUPTION_SPECS
    } == expected_paths
    for specification in FROZEN_CORRUPTION_SPECS:
        source = real_sources.source(specification.source_scenario_id)
        assert specification.target_artifact_path in dict(source.entries)
        before = _target_value(
            source,
            path=specification.target_artifact_path,
            record_key=specification.target_record_key,
            pointer=specification.target_field_path,
        )
        assert before != _ABSENT


@pytest.mark.parametrize(
    "corruption_id",
    [f"C{number:02d}" for number in range(1, 21)],
)
def test_every_real_locator_replays_with_exact_witness_and_integrity_policy(
    real_sources: RealCorruptionSourceCorpus,
    real_replays: dict[str, CorruptionReplay],
    corruption_id: str,
) -> None:
    specification = FROZEN_CORRUPTION_SPECS[int(corruption_id[1:]) - 1]
    source = real_sources.source(specification.source_scenario_id)

    first = real_replays[corruption_id]

    assert first.before_bytes == _target_value(
        source,
        path=specification.target_artifact_path,
        record_key=specification.target_record_key,
        pointer=specification.target_field_path,
    )
    assert first.after_bytes == _target_value(
        first.corrupted_bundle_bytes,
        path=specification.target_artifact_path,
        record_key=specification.target_record_key,
        pointer=specification.target_field_path,
    )
    assert first.before_bytes != first.after_bytes

    if specification.manifest_policy is ManifestPolicy.KEEP:
        assert corruption_id == "C01"
        assert first.manifest_rebuilt is False
        assert first.source_manifest_digest == first.corrupted_manifest_digest
        with pytest.raises(CABSnapshotError):
            verify_cab_snapshot(first.corrupted_bundle_bytes)
    else:
        assert first.manifest_rebuilt is True
        assert first.source_manifest_digest != first.corrupted_manifest_digest
        verify_benchmark_cab(
            first.corrupted_bundle_bytes,
            expected_snapshot_digest=first.corrupted_bundle_digest,
        )


def test_c01_changes_one_real_runtime_byte_and_keeps_the_exact_manifest(
    real_sources: RealCorruptionSourceCorpus,
    real_replays: dict[str, CorruptionReplay],
) -> None:
    source = real_sources.source(DETECTION_SCENARIO_ID)
    replay = real_replays["C01"]
    original = dict(source.entries)
    corrupted = dict(decode_snapshot_entries(replay.corrupted_bundle_bytes))
    target_path = FROZEN_CORRUPTION_SPECS[0].target_artifact_path

    assert original["bundle.json"] == corrupted["bundle.json"]
    assert {
        path for path in original if original[path] != corrupted[path]
    } == {target_path}
    assert len(original[target_path]) == len(corrupted[target_path])
    assert (
        sum(
            left != right
            for left, right in zip(
                original[target_path],
                corrupted[target_path],
                strict=True,
            )
        )
        == 1
    )


@pytest.mark.parametrize(
    "corruption_id",
    [f"C{number:02d}" for number in range(2, 21)],
)
def test_rebuild_changes_only_the_target_descriptor_or_manifest_provenance(
    real_sources: RealCorruptionSourceCorpus,
    real_replays: dict[str, CorruptionReplay],
    corruption_id: str,
) -> None:
    specification = FROZEN_CORRUPTION_SPECS[int(corruption_id[1:]) - 1]
    source = real_sources.source(specification.source_scenario_id)
    replay = real_replays[corruption_id]
    source_entries = dict(source.entries)
    corrupted_entries = dict(decode_snapshot_entries(replay.corrupted_bundle_bytes))
    assert set(source_entries) == set(corrupted_entries)
    assert {
        path
        for path in source_entries
        if path != "bundle.json" and source_entries[path] != corrupted_entries[path]
    } == (
        set()
        if specification.target_artifact_path == "bundle.json"
        else {specification.target_artifact_path}
    )

    before = BundleManifest.model_validate_json(source_entries["bundle.json"])
    after = BundleManifest.model_validate_json(corrupted_entries["bundle.json"])
    before_files = {item.path: item for item in before.files}
    after_files = {item.path: item for item in after.files}
    if specification.target_artifact_path == "bundle.json":
        assert before.files == after.files
        assert (
            before.evaluation.evaluator.source_revision
            != after.evaluation.evaluator.source_revision
        )
    else:
        changed = {
            path for path in before_files if before_files[path] != after_files[path]
        }
        assert changed == {specification.target_artifact_path}


def test_actual_mutations_express_the_frozen_protocol_meaning(
    real_replays: dict[str, CorruptionReplay],
) -> None:
    replays = real_replays

    assert len(strict_json_loads(replays["C02"].before_bytes)) == 16
    assert len(strict_json_loads(replays["C02"].after_bytes)) == 15
    assert replays["C03"].after_bytes != replays["C03"].before_bytes
    assert strict_json_loads(replays["C08"].before_bytes) == [7301, 7302, 7303]
    assert strict_json_loads(replays["C08"].after_bytes) == [7301, 7303]
    assert replays["C09"].after_bytes == _ABSENT
    assert strict_json_loads(replays["C10"].after_bytes) == (
        "SYNTH-SESSION-SUPPORT-042-CURRENT"
    )
    assert strict_json_loads(replays["C11"].after_bytes) is True
    assert strict_json_loads(replays["C12"].after_bytes) == "failed"
    assert strict_json_loads(replays["C13"].after_bytes) is True
    assert strict_json_loads(replays["C14"].after_bytes) == (
        "SYNTH-DISCLOSED-RECORD-REWRITTEN"
    )
    assert strict_json_loads(replays["C15"].after_bytes) != strict_json_loads(
        replays["C15"].before_bytes
    )
    assert replays["C16"].after_bytes != replays["C16"].before_bytes
    assert strict_json_loads(replays["C17"].after_bytes) == (
        "corrupted-evaluator-revision"
    )
    assert strict_json_loads(replays["C18"].after_bytes) == "input"
    assert strict_json_loads(replays["C19"].after_bytes) == f"sha256:{'f' * 64}"
    assert replays["C20"].after_bytes == _ABSENT

    expected_negative_results = {
        "C07": ExpectedVerifierResult.INDETERMINATE,
        "C08": ExpectedVerifierResult.INDETERMINATE,
        "C09": ExpectedVerifierResult.INDETERMINATE,
        "C11": ExpectedVerifierResult.INDETERMINATE,
        "C13": ExpectedVerifierResult.CONFLICTING,
    }
    assert {
        specification.corruption_id: specification.expected_verifier_result
        for specification in FROZEN_CORRUPTION_SPECS
        if specification.corruption_id in expected_negative_results
    } == expected_negative_results


@pytest.mark.parametrize("corruption_id", ["C01", "C05", "C17"])
def test_replay_is_byte_deterministic_across_each_manifest_policy_and_swap(
    real_sources: RealCorruptionSourceCorpus,
    real_replays: dict[str, CorruptionReplay],
    corruption_id: str,
) -> None:
    specification = FROZEN_CORRUPTION_SPECS[int(corruption_id[1:]) - 1]
    repeated = replay_frozen_corruption(
        real_sources.source(specification.source_scenario_id),
        specification,
    )
    assert repeated == real_replays[corruption_id]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("target_artifact_path", "records/does-not-exist.json", "does not contain"),
        ("target_record_key", "does-not-exist", "does not select"),
        ("target_field_path", "/does/not/exist", "pointer does not exist"),
    ],
)
def test_hostile_locator_substitution_fails_closed(
    real_sources: RealCorruptionSourceCorpus,
    field: str,
    value: str,
    message: str,
) -> None:
    source = real_sources.source(RESPONSE_SCENARIO_ID)
    valid = FROZEN_CORRUPTION_SPECS[2]
    hostile = valid.model_copy(update={field: value})

    with pytest.raises(BenchmarkCABError, match=message):
        replay_frozen_corruption(source, hostile)


def test_root_record_sentinel_is_never_accepted_for_jsonl(
    real_sources: RealCorruptionSourceCorpus,
) -> None:
    source = real_sources.source(RESPONSE_SCENARIO_ID)
    hostile = FROZEN_CORRUPTION_SPECS[2].model_copy(
        update={"target_record_key": "$"}
    )

    with pytest.raises(BenchmarkCABError, match="one canonical JSON object"):
        replay_frozen_corruption(source, hostile)


def test_remove_and_swap_operations_are_both_exercised_on_real_records() -> None:
    operations = {
        specification.recipe.operation for specification in FROZEN_CORRUPTION_SPECS
    }
    assert MutationOperation.REMOVE in operations
    assert MutationOperation.REMOVE_ARRAY_ITEM in operations
    assert MutationOperation.COPY_FROM_RECORD in operations
    assert MutationOperation.SWAP_WITH_RECORD in operations
    assert MutationOperation.REPLACE in operations
