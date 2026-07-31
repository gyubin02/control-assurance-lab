from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from assurance_lab.benchmark.cab import VerifiedBenchmarkCAB
from assurance_lab.benchmark.corruption_sources import (
    build_real_corruption_source_corpus,
)
from assurance_lab.benchmark.generator import _response_execution
from assurance_lab.benchmark.models import RESPONSE_SCENARIO_ID
from assurance_lab.evidence.canonical import (
    canonical_jsonl_bytes,
    strict_jsonl_loads,
)


@pytest.fixture(scope="module")
def response_producer(
    tmp_path_factory: pytest.TempPathFactory,
) -> VerifiedBenchmarkCAB:
    root = tmp_path_factory.mktemp("response-lineage-producer") / "corpus"
    return build_real_corruption_source_corpus(root).source(RESPONSE_SCENARIO_ID)


def _rewrite_jsonl_member(
    producer: VerifiedBenchmarkCAB,
    *,
    suffix: str,
    rewrite: Any,
) -> VerifiedBenchmarkCAB:
    entries = list(producer.entries)
    matches = [
        position
        for position, (path, _payload) in enumerate(entries)
        if path.endswith(suffix)
    ]
    assert len(matches) == 1
    position = matches[0]
    path, payload = entries[position]
    records = strict_jsonl_loads(payload)
    rewrite(records[0])
    entries[position] = (path, canonical_jsonl_bytes(records))
    return replace(producer, entries=tuple(entries))


def test_response_source_rejects_a_coherently_typed_runtime_substitution(
    response_producer: VerifiedBenchmarkCAB,
    tmp_path: Path,
) -> None:
    def rewrite(record: dict[str, Any]) -> None:
        target = cast(dict[str, Any], record["target_mutation"])
        target["rows_affected"] = cast(int, target["rows_affected"]) + 1

    changed = _rewrite_jsonl_member(
        response_producer,
        suffix="records/runtime-observations.jsonl",
        rewrite=rewrite,
    )

    with pytest.raises(
        RuntimeError,
        match="differs from a fresh real execution",
    ):
        _response_execution(
            destination=tmp_path / "changed-runtime.cab",
            producer=changed,
        )


def test_response_source_rejects_a_valid_but_wrong_trial_attestation(
    response_producer: VerifiedBenchmarkCAB,
    tmp_path: Path,
) -> None:
    def rewrite(record: dict[str, Any]) -> None:
        record["covariate_digest"] = "sha256:" + "0" * 64

    changed = _rewrite_jsonl_member(
        response_producer,
        suffix="artifacts/trial-attestations.jsonl",
        rewrite=rewrite,
    )

    with pytest.raises(
        RuntimeError,
        match="differs from the fixed execution",
    ):
        _response_execution(
            destination=tmp_path / "changed-attestation.cab",
            producer=changed,
        )
