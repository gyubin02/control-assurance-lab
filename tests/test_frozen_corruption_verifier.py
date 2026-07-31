from __future__ import annotations

import pytest

from assurance_lab.benchmark.cab import (
    decode_snapshot_entries,
    encode_snapshot_entries,
    rebuild_manifest,
    verify_benchmark_cab,
)
from assurance_lab.benchmark.corruption import (
    FROZEN_CORRUPTION_SPECS,
    CorruptionReplay,
    ExpectedVerifierResult,
    replay_frozen_corruption,
)
from assurance_lab.benchmark.corruption_sources import (
    RealCorruptionSourceCorpus,
    build_real_corruption_source_corpus,
)
from assurance_lab.benchmark.corruption_verifier import (
    CorruptionVerificationError,
    FrozenProfileCorruptionVerifier,
)
from assurance_lab.benchmark.models import (
    DETECTION_SCENARIO_ID,
    IssueDisposition,
)
from assurance_lab.evidence.canonical import canonical_jsonl_bytes, strict_jsonl_loads
from assurance_lab.source_identity import package_source_digest

_EXPECTED_ISSUES = {
    "C01": "cab-manifest-payload-mismatch",
    "C02": "compiled-cell-coverage-missing",
    "C03": "clone-lineage-reused",
    "C04": "selector-attestation-mismatch",
    "C05": "action-attestation-mismatch",
    "C06": "trace-lineage-reused",
    "C07": "window-clock-outside-bound",
    "C08": "window-source-sequence-gap",
    "C09": "collector-completion-readback-missing",
    "C10": "target-subject-mismatch",
    "C11": "fallback-readback-cannot-prove-named-alert",
    "C12": "cleanup-not-verified",
    "C13": "target-state-observation-conflict",
    "C14": "disclosure-receipt-mismatch",
    "C15": "comparison-head-promoted",
    "C16": "compromised-session-reused",
    "C17": "evaluator-provenance-mismatch",
    "C18": "derived-stage-coordinate-invalid",
    "C19": "forwarded-source-readback-disconnected",
    "C20": "sham-operation-receipt-missing",
}


@pytest.fixture(scope="module")
def real_sources(
    tmp_path_factory: pytest.TempPathFactory,
) -> RealCorruptionSourceCorpus:
    return build_real_corruption_source_corpus(
        tmp_path_factory.mktemp("frozen-corruption-verifier") / "sources"
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


@pytest.mark.parametrize(
    "corruption_id",
    [f"C{number:02d}" for number in range(1, 21)],
)
def test_all_twenty_real_corruptions_are_independently_classified_and_bound(
    real_sources: RealCorruptionSourceCorpus,
    real_replays: dict[str, CorruptionReplay],
    corruption_id: str,
) -> None:
    specification = FROZEN_CORRUPTION_SPECS[int(corruption_id[1:]) - 1]
    source = real_sources.source(specification.source_scenario_id)
    replay = real_replays[corruption_id]
    verifier = FrozenProfileCorruptionVerifier()

    receipt = verifier.verify_corruption(
        source_bundle_bytes=source.snapshot_bytes,
        corrupted_bundle_bytes=replay.corrupted_bundle_bytes,
        specification=specification,
    )

    assert receipt.verifier_id == verifier.verifier_id
    assert receipt.verifier_digest == package_source_digest()
    assert receipt.corruption_id == corruption_id
    assert receipt.source_bundle_digest == source.snapshot_digest
    assert receipt.corrupted_bundle_digest == replay.corrupted_bundle_digest
    assert receipt.result is specification.expected_verifier_result
    assert len(receipt.issues) == 1
    assert receipt.issues[0].code == _EXPECTED_ISSUES[corruption_id]
    assert (
        receipt.issues[0].disposition
        is {
            ExpectedVerifierResult.REJECTED: IssueDisposition.REJECTED,
            ExpectedVerifierResult.INDETERMINATE: IssueDisposition.INDETERMINATE,
            ExpectedVerifierResult.CONFLICTING: IssueDisposition.CONFLICTING,
        }[receipt.result]
    )


def test_receipts_are_byte_deterministic(
    real_sources: RealCorruptionSourceCorpus,
    real_replays: dict[str, CorruptionReplay],
) -> None:
    specification = FROZEN_CORRUPTION_SPECS[10]
    source = real_sources.source(specification.source_scenario_id)
    replay = real_replays[specification.corruption_id]
    verifier = FrozenProfileCorruptionVerifier()

    first = verifier.verify_corruption(
        source_bundle_bytes=source.snapshot_bytes,
        corrupted_bundle_bytes=replay.corrupted_bundle_bytes,
        specification=specification,
    )
    second = verifier.verify_corruption(
        source_bundle_bytes=source.snapshot_bytes,
        corrupted_bundle_bytes=replay.corrupted_bundle_bytes,
        specification=specification,
    )

    assert first == second
    assert first.model_dump_json() == second.model_dump_json()


def test_altered_frozen_specification_is_rejected_before_inspection(
    real_sources: RealCorruptionSourceCorpus,
    real_replays: dict[str, CorruptionReplay],
) -> None:
    specification = FROZEN_CORRUPTION_SPECS[0]
    hostile = specification.model_copy(
        update={"expected_verifier_result": ExpectedVerifierResult.CONFLICTING}
    )

    with pytest.raises(
        CorruptionVerificationError,
        match="differs from the frozen profile",
    ):
        FrozenProfileCorruptionVerifier().verify_corruption(
            source_bundle_bytes=real_sources.source(
                specification.source_scenario_id
            ).snapshot_bytes,
            corrupted_bundle_bytes=real_replays["C01"].corrupted_bundle_bytes,
            specification=hostile,
        )


def test_other_corruption_cannot_be_substituted_under_a_valid_id(
    real_sources: RealCorruptionSourceCorpus,
    real_replays: dict[str, CorruptionReplay],
) -> None:
    specification = FROZEN_CORRUPTION_SPECS[0]

    with pytest.raises(CorruptionVerificationError):
        FrozenProfileCorruptionVerifier().verify_corruption(
            source_bundle_bytes=real_sources.source(
                specification.source_scenario_id
            ).snapshot_bytes,
            corrupted_bundle_bytes=real_replays["C02"].corrupted_bundle_bytes,
            specification=specification,
        )


def test_coherently_rebuilt_extra_mutation_is_rejected(
    real_sources: RealCorruptionSourceCorpus,
    real_replays: dict[str, CorruptionReplay],
) -> None:
    specification = FROZEN_CORRUPTION_SPECS[2]
    replay = real_replays[specification.corruption_id]
    entries = dict(decode_snapshot_entries(replay.corrupted_bundle_bytes))
    target_path = specification.target_artifact_path
    records = strict_jsonl_loads(entries[target_path], require_sorted_ids=True)
    assert isinstance(records[0], dict)
    record = records[0]["record"]
    assert isinstance(record, dict)
    trace = record["trace"]
    assert isinstance(trace, dict)
    trace["trace_id"] = "hostile-second-mutation"
    entries[target_path] = canonical_jsonl_bytes(records)
    rebuilt = rebuild_manifest(
        tuple(
            (
                ("bundle.json", entries["bundle.json"]),
                *tuple(
                    sorted(
                        (path, payload)
                        for path, payload in entries.items()
                        if path != "bundle.json"
                    )
                ),
            )
        ),
        changed_paths=frozenset({target_path}),
    )
    hostile = encode_snapshot_entries(rebuilt)
    verify_benchmark_cab(hostile, expected_snapshot_digest=_digest(hostile))

    with pytest.raises(
        CorruptionVerificationError,
        match="independent mutation replay",
    ):
        FrozenProfileCorruptionVerifier().verify_corruption(
            source_bundle_bytes=real_sources.source(
                specification.source_scenario_id
            ).snapshot_bytes,
            corrupted_bundle_bytes=hostile,
            specification=specification,
        )


def test_valid_but_noncanonical_source_and_its_matching_corruption_are_rejected(
    real_sources: RealCorruptionSourceCorpus,
) -> None:
    source = real_sources.source(DETECTION_SCENARIO_ID)
    entries = dict(source.entries)
    target_path = "records/runtime-observations.jsonl"
    records = strict_jsonl_loads(entries[target_path], require_sorted_ids=True)
    assert isinstance(records[0], dict)
    records[0]["schema_name"] = "assurance-lab.financial-detection-runtime-observation/alternate"
    entries[target_path] = canonical_jsonl_bytes(records)
    rebuilt = rebuild_manifest(
        (
            ("bundle.json", entries["bundle.json"]),
            *tuple(
                sorted(
                    (path, payload) for path, payload in entries.items() if path != "bundle.json"
                )
            ),
        ),
        changed_paths=frozenset({target_path}),
    )
    alternate_bytes = encode_snapshot_entries(rebuilt)
    alternate = verify_benchmark_cab(
        alternate_bytes,
        expected_snapshot_digest=_digest(alternate_bytes),
    )
    specification = FROZEN_CORRUPTION_SPECS[0]
    alternate_corruption = replay_frozen_corruption(alternate, specification)

    with pytest.raises(
        CorruptionVerificationError,
        match="differs from the regenerated frozen scenario CAB",
    ):
        FrozenProfileCorruptionVerifier().verify_corruption(
            source_bundle_bytes=alternate.snapshot_bytes,
            corrupted_bundle_bytes=alternate_corruption.corrupted_bundle_bytes,
            specification=specification,
        )


@pytest.mark.parametrize(
    ("source_bytes", "corrupted_bytes", "message"),
    [
        (b"not-a-cab", b"still-not-a-cab", "source input"),
        (b"", b"", "identical"),
    ],
)
def test_malformed_or_identical_inputs_fail_closed(
    source_bytes: bytes,
    corrupted_bytes: bytes,
    message: str,
) -> None:
    with pytest.raises(CorruptionVerificationError, match=message):
        FrozenProfileCorruptionVerifier().verify_corruption(
            source_bundle_bytes=source_bytes,
            corrupted_bundle_bytes=corrupted_bytes,
            specification=FROZEN_CORRUPTION_SPECS[0],
        )


def test_mutable_bytearray_inputs_are_not_accepted(
    real_sources: RealCorruptionSourceCorpus,
    real_replays: dict[str, CorruptionReplay],
) -> None:
    specification = FROZEN_CORRUPTION_SPECS[0]
    source = real_sources.source(specification.source_scenario_id)

    with pytest.raises(CorruptionVerificationError, match="immutable bytes"):
        FrozenProfileCorruptionVerifier().verify_corruption(
            source_bundle_bytes=bytearray(source.snapshot_bytes),  # type: ignore[arg-type]
            corrupted_bundle_bytes=real_replays["C01"].corrupted_bundle_bytes,
            specification=specification,
        )


def _digest(payload: bytes) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(payload).hexdigest()
