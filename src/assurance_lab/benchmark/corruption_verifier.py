"""Independent verifier for the frozen C01-C20 corruption profile.

The corruption producer and this verifier deliberately do not share mutation
execution code.  The verifier:

* regenerates the current frozen source CABs and requires an exact source match;
* applies a second, local interpretation of the frozen mutation recipe;
* checks the complete corrupted snapshot and manifest, not only one field;
* invokes the scenario consumer (or reconstructs its raw proof) to derive the
  negative classification; and
* returns a canonical receipt bound to the implementation, specification, source,
  and corrupted bytes.

The implementation digest identifies the complete installed ``assurance_lab``
source set.  It is a content identity, not an author signature or a custody
claim.
"""

from __future__ import annotations

import copy
import hashlib
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Final, cast

from pydantic import TypeAdapter, ValidationError
from pydantic_core import ErrorDetails

from assurance_lab.benchmark.cab import (
    BenchmarkCABError,
    VerifiedBenchmarkCAB,
    decode_snapshot_entries,
    encode_snapshot_entries,
    raw_sha256,
    rebuild_manifest,
    verify_benchmark_cab,
)
from assurance_lab.benchmark.corruption import (
    FROZEN_CORRUPTION_SPECS,
    CorruptionVerificationReceipt,
    ExpectedVerifierResult,
    FrozenCorruptionSpec,
    ManifestPolicy,
    MutationOperation,
    corruption_spec_digest,
)
from assurance_lab.benchmark.corruption_sources import (
    build_real_corruption_source_corpus,
    detection_corruption_compiled,
)
from assurance_lab.benchmark.models import (
    DETECTION_SCENARIO_ID,
    RECOVERY_SCENARIO_ID,
    RESPONSE_SCENARIO_ID,
    IssueDisposition,
    NormalizedIssue,
)
from assurance_lab.contract import CompiledExperiment
from assurance_lab.evidence.bundle import BundleManifest
from assurance_lab.evidence.canonical import (
    canonical_json_bytes,
    canonical_jsonl_bytes,
    strict_json_loads,
    strict_jsonl_loads,
)
from assurance_lab.lifecycle import (
    AdmittedReceiptEvidence,
    IncidentLifecycle,
    LifecycleVerificationError,
    VerifiedLifecycle,
    verify_lifecycle,
)
from assurance_lab.scenarios.financial_detection_runtime import (
    DetectionClaimState,
    FinancialDetectionRuntimeResult,
    _result_closure_valid,
    assess_detection_case,
)
from assurance_lab.scenarios.financial_response_e2e import (
    FinancialResponseBundleError,
    FinancialResponseBundleRepository,
)
from assurance_lab.source_identity import package_source_digest

_VERIFIER_ID: Final = "assurance-lab-python-corruption-verifier/v1"
_ROOT_RECORD_KEY: Final = "$"
_FILE_FLAGS: Final = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_DETECTION_RESULT_ADAPTER: Final = TypeAdapter(FinancialDetectionRuntimeResult)


class CorruptionVerificationError(ValueError):
    """The supplied bytes do not form one exact frozen negative case."""


class FrozenProfileCorruptionVerifier:
    """Verify the exact C01-C20 corpus against the current reviewed source set."""

    @property
    def verifier_id(self) -> str:
        return _VERIFIER_ID

    @property
    def verifier_digest(self) -> str:
        return package_source_digest()

    def verify_corruption(
        self,
        *,
        source_bundle_bytes: bytes,
        corrupted_bundle_bytes: bytes,
        specification: FrozenCorruptionSpec,
    ) -> CorruptionVerificationReceipt:
        if type(source_bundle_bytes) is not bytes or type(corrupted_bundle_bytes) is not bytes:
            raise CorruptionVerificationError("corruption inputs must be immutable bytes")
        if source_bundle_bytes == corrupted_bundle_bytes:
            raise CorruptionVerificationError("corrupted input is identical to its source")

        implementation_digest = self.verifier_digest
        frozen = _require_frozen_specification(specification)
        source = _verify_exact_source(
            source_bundle_bytes,
            scenario_id=frozen.source_scenario_id,
            implementation_digest=implementation_digest,
        )
        corrupted_entries = _inspect_exact_mutation(
            source,
            corrupted_bundle_bytes,
            frozen,
        )
        finding = _derive_negative_finding(
            source=source,
            corrupted_bundle_bytes=corrupted_bundle_bytes,
            corrupted_entries=corrupted_entries,
            specification=frozen,
        )
        if finding.result is not frozen.expected_verifier_result:
            raise CorruptionVerificationError(
                "derived negative classification differs from the frozen profile"
            )
        if self.verifier_digest != implementation_digest:
            raise CorruptionVerificationError(
                "verifier source changed during corruption verification"
            )

        return CorruptionVerificationReceipt(
            wire_schema=("assurance-lab.benchmark.corruption-verification-receipt/v1"),
            verifier_id=self.verifier_id,
            verifier_digest=implementation_digest,
            corruption_id=frozen.corruption_id,
            mutation_spec_digest=corruption_spec_digest(frozen),
            source_bundle_digest=source.snapshot_digest,
            corrupted_bundle_digest=raw_sha256(corrupted_bundle_bytes),
            result=finding.result,
            issues=(
                NormalizedIssue(
                    code=finding.issue_code,
                    disposition=_disposition(finding.result),
                    subject_path=f"/corruptions/{frozen.corruption_id}",
                    related_trial_keys=_related_trial_keys(frozen),
                ),
            ),
        )


@dataclass(frozen=True, slots=True)
class _NegativeFinding:
    """Small immutable pair without accepting producer-authored prose."""

    result: ExpectedVerifierResult
    issue_code: str


def _finding(result: ExpectedVerifierResult, issue_code: str) -> _NegativeFinding:
    return _NegativeFinding(result, issue_code)


def _disposition(result: ExpectedVerifierResult) -> IssueDisposition:
    return {
        ExpectedVerifierResult.REJECTED: IssueDisposition.REJECTED,
        ExpectedVerifierResult.INDETERMINATE: IssueDisposition.INDETERMINATE,
        ExpectedVerifierResult.CONFLICTING: IssueDisposition.CONFLICTING,
    }[result]


def _related_trial_keys(specification: FrozenCorruptionSpec) -> tuple[str, ...]:
    key = specification.target_record_key
    if key.startswith("sha256:") and len(key) == 71 and ":" not in key[7:]:
        return (key,)
    return ()


def _require_frozen_specification(
    specification: FrozenCorruptionSpec,
) -> FrozenCorruptionSpec:
    if type(specification) is not FrozenCorruptionSpec:
        raise CorruptionVerificationError("corruption specification must use the frozen wire model")
    try:
        frozen = FROZEN_CORRUPTION_SPECS[int(specification.corruption_id[1:]) - 1]
    except (IndexError, ValueError) as exc:
        raise CorruptionVerificationError("unknown frozen corruption id") from exc
    if (
        frozen.corruption_id != specification.corruption_id
        or corruption_spec_digest(frozen) != corruption_spec_digest(specification)
        or frozen != specification
    ):
        raise CorruptionVerificationError(
            "corruption specification differs from the frozen profile"
        )
    return frozen


@lru_cache(maxsize=2)
def _reference_sources(
    implementation_digest: str,
) -> tuple[tuple[str, VerifiedBenchmarkCAB], ...]:
    del implementation_digest
    with tempfile.TemporaryDirectory(prefix="assurance-lab-corruption-sources-") as directory:
        corpus = build_real_corruption_source_corpus(Path(directory) / "sources")
        return tuple(sorted(corpus.sources.items()))


def _verify_exact_source(
    payload: bytes,
    *,
    scenario_id: str,
    implementation_digest: str,
) -> VerifiedBenchmarkCAB:
    try:
        verified = verify_benchmark_cab(
            payload,
            expected_snapshot_digest=raw_sha256(payload),
        )
    except BenchmarkCABError as exc:
        raise CorruptionVerificationError(
            "source input is not an integrity-verified canonical CAB"
        ) from exc
    references = dict(_reference_sources(implementation_digest))
    reference = references.get(scenario_id)
    if reference is None:
        raise CorruptionVerificationError("scenario has no frozen producer CAB")
    if verified.snapshot_bytes == reference.snapshot_bytes:
        return verified

    embedded_path = f"artifacts/producers/{scenario_id}/source.cab.snapshot"
    members = dict(verified.entries)
    if members.get(embedded_path) != reference.snapshot_bytes:
        raise CorruptionVerificationError(
            "source input differs from the regenerated frozen scenario CAB"
        )
    reference_members = dict(reference.entries)
    required_targets = {
        item.target_artifact_path
        for item in FROZEN_CORRUPTION_SPECS
        if item.source_scenario_id == scenario_id and item.target_artifact_path != "bundle.json"
    }
    if any(members.get(path) != reference_members.get(path) for path in required_targets):
        raise CorruptionVerificationError(
            "indexed source does not expose exact embedded producer corruption members"
        )
    return verified


def _inspect_exact_mutation(
    source: VerifiedBenchmarkCAB,
    corrupted: bytes,
    specification: FrozenCorruptionSpec,
) -> tuple[tuple[str, bytes], ...]:
    try:
        source_entries = source.entries
        corrupted_entries = decode_snapshot_entries(corrupted)
        if encode_snapshot_entries(corrupted_entries) != corrupted:
            raise CorruptionVerificationError(
                "corrupted snapshot is not in canonical container form"
            )
    except BenchmarkCABError as exc:
        raise CorruptionVerificationError(
            "corrupted input is not a bounded canonical snapshot"
        ) from exc
    source_paths = tuple(path for path, _payload in source_entries)
    corrupted_paths = tuple(path for path, _payload in corrupted_entries)
    if source_paths != corrupted_paths:
        raise CorruptionVerificationError(
            "corrupted snapshot changes the frozen member set or order"
        )

    source_map = dict(source_entries)
    corrupted_map = dict(corrupted_entries)
    target = specification.target_artifact_path
    if target not in source_map:
        raise CorruptionVerificationError("frozen mutation target is absent")
    expected_target = _independent_target_mutation(
        source_map[target],
        specification,
    )
    if corrupted_map[target] != expected_target:
        raise CorruptionVerificationError(
            "corrupted target does not match the independent mutation replay"
        )

    expected_changed_non_manifest = set() if target == "bundle.json" else {target}
    changed_non_manifest = {
        path
        for path in source_map
        if path != "bundle.json" and source_map[path] != corrupted_map[path]
    }
    if changed_non_manifest != expected_changed_non_manifest:
        raise CorruptionVerificationError(
            "corrupted snapshot changes members outside the frozen target"
        )

    if specification.manifest_policy is ManifestPolicy.KEEP:
        _verify_stale_manifest_case(
            source_map=source_map,
            corrupted_map=corrupted_map,
            corrupted=corrupted,
            target=target,
        )
    else:
        _verify_rebuilt_manifest_case(
            source_map=source_map,
            corrupted_map=corrupted_map,
            corrupted=corrupted,
            target=target,
            expected_target=expected_target,
        )
    return corrupted_entries


def _verify_stale_manifest_case(
    *,
    source_map: dict[str, bytes],
    corrupted_map: dict[str, bytes],
    corrupted: bytes,
    target: str,
) -> None:
    if corrupted_map["bundle.json"] != source_map["bundle.json"]:
        raise CorruptionVerificationError("stale-manifest case changed bundle.json")
    original = source_map[target]
    changed = corrupted_map[target]
    differing = abs(len(original) - len(changed)) + sum(
        left != right for left, right in zip(original, changed, strict=False)
    )
    if differing != 1:
        raise CorruptionVerificationError("stale-manifest case must change exactly one target byte")
    try:
        verify_benchmark_cab(
            corrupted,
            expected_snapshot_digest=raw_sha256(corrupted),
        )
    except BenchmarkCABError:
        return
    raise CorruptionVerificationError("stale-manifest case unexpectedly passes CAB integrity")


def _verify_rebuilt_manifest_case(
    *,
    source_map: dict[str, bytes],
    corrupted_map: dict[str, bytes],
    corrupted: bytes,
    target: str,
    expected_target: bytes,
) -> None:
    try:
        verify_benchmark_cab(
            corrupted,
            expected_snapshot_digest=raw_sha256(corrupted),
        )
    except BenchmarkCABError as exc:
        raise CorruptionVerificationError(
            "rebuilt-manifest case is not an integrity-verified CAB"
        ) from exc
    if target == "bundle.json":
        expected_manifest = expected_target
    else:
        expected_manifest = _manifest_with_one_rebuilt_descriptor(
            source_map["bundle.json"],
            target=target,
            target_payload=expected_target,
        )
    if corrupted_map["bundle.json"] != expected_manifest:
        raise CorruptionVerificationError(
            "rebuilt manifest differs outside the frozen target descriptor"
        )


def _manifest_with_one_rebuilt_descriptor(
    manifest_bytes: bytes,
    *,
    target: str,
    target_payload: bytes,
) -> bytes:
    try:
        manifest = BundleManifest.model_validate_json(manifest_bytes, strict=True)
    except ValidationError as exc:
        raise CorruptionVerificationError("source manifest is not strict") from exc
    descriptors = []
    found = False
    for descriptor in manifest.files:
        if descriptor.path != target:
            descriptors.append(descriptor)
            continue
        document = descriptor.model_dump(mode="python")
        document["size"] = len(target_payload)
        document["sha256"] = hashlib.sha256(target_payload).hexdigest()
        descriptors.append(type(descriptor).model_validate(document, strict=True))
        found = True
    if not found:
        raise CorruptionVerificationError("frozen target is not declared by the source manifest")
    document = manifest.model_dump(mode="python")
    document["files"] = descriptors
    rebuilt = BundleManifest.model_validate(document, strict=True)
    return canonical_json_bytes(rebuilt.model_dump(mode="json"))


def _independent_target_mutation(
    source_payload: bytes,
    specification: FrozenCorruptionSpec,
) -> bytes:
    is_jsonl = specification.target_artifact_path.endswith(".jsonl")
    try:
        if is_jsonl:
            loaded = strict_jsonl_loads(source_payload, require_sorted_ids=True)
            records = cast(list[dict[str, object]], copy.deepcopy(loaded))
        else:
            loaded = strict_json_loads(source_payload)
            if not isinstance(loaded, dict):
                raise CorruptionVerificationError("JSON mutation target is not one object")
            records = [cast(dict[str, object], copy.deepcopy(loaded))]
    except ValueError as exc:
        raise CorruptionVerificationError("source mutation target is not canonical JSON") from exc

    target = _select_record(
        records,
        specification.target_record_key,
        allow_root=not is_jsonl,
    )
    recipe = specification.recipe
    if recipe.operation is MutationOperation.REPLACE:
        _set_pointer(
            target,
            specification.target_field_path,
            copy.deepcopy(recipe.replacement),
        )
    elif recipe.operation is MutationOperation.REMOVE:
        _remove_pointer(target, specification.target_field_path)
    elif recipe.operation is MutationOperation.REMOVE_ARRAY_ITEM:
        value = _get_pointer(target, specification.target_field_path)
        if not isinstance(value, list) or recipe.array_index is None:
            raise CorruptionVerificationError("frozen array mutation does not target an array")
        if recipe.array_index >= len(value):
            raise CorruptionVerificationError("frozen array mutation index is outside its target")
        del value[recipe.array_index]
    else:
        if recipe.donor_record_key is None or recipe.donor_field_path is None:
            raise CorruptionVerificationError("frozen donor mutation is incomplete")
        donor = _select_record(
            records,
            recipe.donor_record_key,
            allow_root=not is_jsonl,
        )
        target_value = copy.deepcopy(_get_pointer(target, specification.target_field_path))
        donor_value = copy.deepcopy(_get_pointer(donor, recipe.donor_field_path))
        _set_pointer(target, specification.target_field_path, donor_value)
        if recipe.operation is MutationOperation.SWAP_WITH_RECORD:
            _set_pointer(donor, recipe.donor_field_path, target_value)

    if is_jsonl:
        return canonical_jsonl_bytes(records)
    return canonical_json_bytes(records[0])


def _pointer_tokens(pointer: str) -> tuple[str, ...]:
    if not pointer.startswith("/"):
        raise CorruptionVerificationError("mutation field is not a JSON pointer")
    return tuple(token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/"))


def _get_pointer(document: object, pointer: str) -> object:
    current = document
    for token in _pointer_tokens(pointer):
        if isinstance(current, dict):
            if token not in current:
                raise CorruptionVerificationError("mutation pointer is absent from its object")
            current = current[token]
        elif isinstance(current, list):
            try:
                index = int(token)
            except ValueError as exc:
                raise CorruptionVerificationError("mutation array pointer is not numeric") from exc
            if index < 0 or index >= len(current):
                raise CorruptionVerificationError("mutation array pointer is outside its target")
            current = current[index]
        else:
            raise CorruptionVerificationError("mutation pointer traverses a scalar")
    return current


def _pointer_parent(
    document: object,
    pointer: str,
) -> tuple[dict[str, object] | list[object], str]:
    tokens = _pointer_tokens(pointer)
    if not tokens:
        raise CorruptionVerificationError("root replacement is not supported")
    parent: object = document
    for token in tokens[:-1]:
        if isinstance(parent, dict):
            if token not in parent:
                raise CorruptionVerificationError("mutation parent pointer is absent")
            parent = parent[token]
        elif isinstance(parent, list):
            try:
                index = int(token)
            except ValueError as exc:
                raise CorruptionVerificationError(
                    "mutation parent array pointer is not numeric"
                ) from exc
            if index < 0 or index >= len(parent):
                raise CorruptionVerificationError(
                    "mutation parent array pointer is outside its target"
                )
            parent = parent[index]
        else:
            raise CorruptionVerificationError("mutation parent pointer traverses a scalar")
    if not isinstance(parent, (dict, list)):
        raise CorruptionVerificationError("mutation parent is not a container")
    return parent, tokens[-1]


def _set_pointer(document: object, pointer: str, value: object) -> None:
    parent, token = _pointer_parent(document, pointer)
    if isinstance(parent, dict):
        if token not in parent:
            raise CorruptionVerificationError("replacement target is absent")
        parent[token] = value
        return
    try:
        index = int(token)
    except ValueError as exc:
        raise CorruptionVerificationError("replacement array pointer is not numeric") from exc
    if index < 0 or index >= len(parent):
        raise CorruptionVerificationError("replacement array pointer is outside its target")
    parent[index] = value


def _remove_pointer(document: object, pointer: str) -> None:
    parent, token = _pointer_parent(document, pointer)
    if isinstance(parent, dict):
        if token not in parent:
            raise CorruptionVerificationError("removal target is absent")
        del parent[token]
        return
    try:
        index = int(token)
    except ValueError as exc:
        raise CorruptionVerificationError("removal array pointer is not numeric") from exc
    if index < 0 or index >= len(parent):
        raise CorruptionVerificationError("removal array pointer is outside its target")
    del parent[index]


def _select_record(
    records: list[dict[str, object]],
    key: str,
    *,
    allow_root: bool,
) -> dict[str, object]:
    if key == _ROOT_RECORD_KEY:
        if not allow_root or len(records) != 1:
            raise CorruptionVerificationError("root record key does not select one JSON object")
        return records[0]
    matches = [record for record in records if record.get("id") == key]
    if len(matches) != 1:
        raise CorruptionVerificationError("record key does not select exactly one object")
    return matches[0]


def _derive_negative_finding(
    *,
    source: VerifiedBenchmarkCAB,
    corrupted_bundle_bytes: bytes,
    corrupted_entries: tuple[tuple[str, bytes], ...],
    specification: FrozenCorruptionSpec,
) -> _NegativeFinding:
    if specification.source_scenario_id == DETECTION_SCENARIO_ID:
        return _verify_detection_negative(
            source=source,
            corrupted_bundle_bytes=corrupted_bundle_bytes,
            corrupted_entries=dict(corrupted_entries),
            specification=specification,
        )
    if specification.source_scenario_id == RESPONSE_SCENARIO_ID:
        return _verify_response_negative(
            source=source,
            corrupted_entries=dict(corrupted_entries),
            specification=specification,
        )
    if specification.source_scenario_id == RECOVERY_SCENARIO_ID:
        return _verify_recovery_negative(
            source=source,
            corrupted_entries=dict(corrupted_entries),
            specification=specification,
        )
    raise CorruptionVerificationError("unsupported corruption scenario")


def _verify_detection_negative(
    *,
    source: VerifiedBenchmarkCAB,
    corrupted_bundle_bytes: bytes,
    corrupted_entries: dict[str, bytes],
    specification: FrozenCorruptionSpec,
) -> _NegativeFinding:
    corruption_id = specification.corruption_id
    if corruption_id == "C01":
        try:
            verify_benchmark_cab(
                corrupted_bundle_bytes,
                expected_snapshot_digest=raw_sha256(corrupted_bundle_bytes),
            )
        except BenchmarkCABError:
            return _finding(
                ExpectedVerifierResult.REJECTED,
                "cab-manifest-payload-mismatch",
            )
        raise CorruptionVerificationError("C01 did not break CAB integrity")

    if corruption_id == "C02":
        payload = corrupted_entries["spec/compiled-experiment.json"]
        try:
            parsed = CompiledExperiment.model_validate_json(payload, strict=True)
        except ValidationError as exc:
            if not _has_validation_error(exc.errors(), ("cells",), "too_short"):
                raise CorruptionVerificationError(
                    "C02 failed for an unexpected compiled-plan reason"
                ) from exc
            return _finding(
                ExpectedVerifierResult.REJECTED,
                "compiled-cell-coverage-missing",
            )
        if parsed == detection_corruption_compiled():
            raise CorruptionVerificationError("C02 did not remove a declared cell")
        raise CorruptionVerificationError("C02 produced an unexpected valid compiled plan")

    source_records = _jsonl_records(dict(source.entries)["records/runtime-observations.jsonl"])
    corrupted_records = _jsonl_records(corrupted_entries["records/runtime-observations.jsonl"])
    source_record = _one_record(source_records, specification.target_record_key)
    corrupted_record = _one_record(
        corrupted_records,
        specification.target_record_key,
    )
    source_result = _result_dict(source_record)
    corrupted_result = _result_dict(corrupted_record)

    if corruption_id == "C09":
        if (
            "collector_run_readback" not in corrupted_result
            and "collector_run_readback" in source_result
        ):
            try:
                _DETECTION_RESULT_ADAPTER.validate_python(corrupted_result)
            except ValidationError as exc:
                if _has_validation_error(
                    exc.errors(),
                    ("collector_run_readback",),
                    "missing",
                ):
                    return _finding(
                        ExpectedVerifierResult.INDETERMINATE,
                        "collector-completion-readback-missing",
                    )
        raise CorruptionVerificationError("C09 did not remove the required collector readback")

    try:
        result = _DETECTION_RESULT_ADAPTER.validate_python(corrupted_result)
        source_typed = _DETECTION_RESULT_ADAPTER.validate_python(source_result)
    except ValidationError as exc:
        raise CorruptionVerificationError(
            f"{corruption_id} detection observation is unexpectedly malformed"
        ) from exc
    if not _result_closure_valid(source_typed):
        raise CorruptionVerificationError("frozen detection source has no valid closure proof")

    if corruption_id == "C06":
        trace_ids = tuple(
            cast(dict[str, object], record["result"])["trace_id"] for record in corrupted_records
        )
        if (
            result.trace_id != source_typed.trace_id
            and trace_ids.count(result.trace_id) == 2
            and not _result_closure_valid(result)
        ):
            return _finding(
                ExpectedVerifierResult.REJECTED,
                "trace-lineage-reused",
            )
    elif corruption_id == "C07":
        if (
            result.window_closure.closed_at_ms > result.clock_readback.current_time_ms
            and result.observation_window_closed
            and not _result_closure_valid(result)
        ):
            return _finding(
                ExpectedVerifierResult.INDETERMINATE,
                "window-clock-outside-bound",
            )
    elif corruption_id == "C08":
        raw_sequences = tuple(event.source_sequence for event in result.source_events)
        if (
            result.window_closure.observed_source_sequences != raw_sequences
            and result.observation_window_closed
            and not _result_closure_valid(result)
        ):
            return _finding(
                ExpectedVerifierResult.INDETERMINATE,
                "window-source-sequence-gap",
            )
    elif corruption_id == "C11":
        assessment = assess_detection_case(result)
        if (
            _result_closure_valid(result)
            and result.named_exact_correlation_alert_proven
            and result.fallback_alert_binding_valid
            and assessment.target_state is DetectionClaimState.REFUTED
        ):
            return _finding(
                ExpectedVerifierResult.INDETERMINATE,
                "fallback-readback-cannot-prove-named-alert",
            )
    elif corruption_id == "C13":
        expected_rule_active = result.target_level == "exact-rule-active"
        if (
            _result_closure_valid(result)
            and result.named_rule_active is not expected_rule_active
            and result.detector_run.rule_active is expected_rule_active
        ):
            return _finding(
                ExpectedVerifierResult.CONFLICTING,
                "target-state-observation-conflict",
            )
    elif corruption_id == "C19":
        source_digests = {event.event_digest for event in result.source_events}
        disconnected = tuple(
            event
            for event in result.forwarded_events
            if event.source_event_digest not in source_digests
        )
        if (
            len(disconnected) == 1
            and result.fallback_telemetry_forwarded
            and not _result_closure_valid(result)
        ):
            return _finding(
                ExpectedVerifierResult.REJECTED,
                "forwarded-source-readback-disconnected",
            )
    raise CorruptionVerificationError(
        f"{corruption_id} did not produce its declared detection failure"
    )


_RESPONSE_FAILURES: Final = {
    "C03": ("differs from compiler plan", "clone-lineage-reused"),
    "C04": ("differs from its attestation", "selector-attestation-mismatch"),
    "C05": ("differs from its attestation", "action-attestation-mismatch"),
    "C10": ("inconsistent selector or provenance", "target-subject-mismatch"),
    "C12": ("state", "cleanup-not-verified"),
    "C17": ("manifest provenance differs", "evaluator-provenance-mismatch"),
    "C18": ("duplicate stage coordinate", "derived-stage-coordinate-invalid"),
    "C20": ("sham_operation", "sham-operation-receipt-missing"),
}


def _verify_response_negative(
    *,
    source: VerifiedBenchmarkCAB,
    corrupted_entries: dict[str, bytes],
    specification: FrozenCorruptionSpec,
) -> _NegativeFinding:
    expected = _RESPONSE_FAILURES.get(specification.corruption_id)
    if expected is None:
        raise CorruptionVerificationError("unknown response corruption")
    fragment, issue_code = expected
    producer = _embedded_or_direct_producer(source, RESPONSE_SCENARIO_ID)
    _load_response_repository(producer.snapshot_bytes)
    if specification.corruption_id == "C17":
        source_revision = source.manifest.evaluation.evaluator.source_revision
        corrupted_manifest = BundleManifest.model_validate_json(
            corrupted_entries["bundle.json"],
            strict=True,
        )
        if (
            source_revision != "corrupted-evaluator-revision"
            and corrupted_manifest.evaluation.evaluator.source_revision
            == "corrupted-evaluator-revision"
        ):
            return _finding(ExpectedVerifierResult.REJECTED, issue_code)
        raise CorruptionVerificationError("C17 did not rewrite the indexed evaluator provenance")
    projected = _project_producer_corruption(
        producer,
        target=specification.target_artifact_path,
        target_payload=corrupted_entries[specification.target_artifact_path],
    )
    try:
        _load_response_repository(projected)
    except FinancialResponseBundleError as exc:
        if fragment not in str(exc):
            raise CorruptionVerificationError(
                "response consumer rejected the corruption for an unexpected reason"
            ) from exc
        return _finding(ExpectedVerifierResult.REJECTED, issue_code)
    raise CorruptionVerificationError("response consumer accepted the corrupted CAB")


def _embedded_or_direct_producer(
    source: VerifiedBenchmarkCAB,
    scenario_id: str,
) -> VerifiedBenchmarkCAB:
    embedded_path = f"artifacts/producers/{scenario_id}/source.cab.snapshot"
    embedded = dict(source.entries).get(embedded_path)
    if embedded is None:
        return source
    try:
        return verify_benchmark_cab(
            embedded,
            expected_snapshot_digest=raw_sha256(embedded),
        )
    except BenchmarkCABError as exc:
        raise CorruptionVerificationError(
            "embedded producer snapshot failed bounded integrity verification"
        ) from exc


def _project_producer_corruption(
    producer: VerifiedBenchmarkCAB,
    *,
    target: str,
    target_payload: bytes,
) -> bytes:
    entries = dict(producer.entries)
    if target == "bundle.json" or target not in entries:
        raise CorruptionVerificationError(
            "response corruption target is absent from the embedded producer"
        )
    entries[target] = target_payload
    rebuilt = rebuild_manifest(
        (
            ("bundle.json", entries["bundle.json"]),
            *tuple(
                sorted(
                    (path, payload) for path, payload in entries.items() if path != "bundle.json"
                )
            ),
        ),
        changed_paths=frozenset({target}),
    )
    projected = encode_snapshot_entries(rebuilt)
    verify_benchmark_cab(
        projected,
        expected_snapshot_digest=raw_sha256(projected),
    )
    return projected


_RECOVERY_FAILURES: Final = {
    "C14": (
        "new disclosure requires matching admitted receipt evidence",
        "disclosure-receipt-mismatch",
    ),
    "C15": (
        "matched-comparison snapshot cannot qualify as current evidence",
        "comparison-head-promoted",
    ),
    "C16": (
        "replacement session must be distinct from the compromised session",
        "compromised-session-reused",
    ),
}


def _verify_recovery_negative(
    *,
    source: VerifiedBenchmarkCAB,
    corrupted_entries: dict[str, bytes],
    specification: FrozenCorruptionSpec,
) -> _NegativeFinding:
    producer = _embedded_or_direct_producer(source, RECOVERY_SCENARIO_ID)
    _verify_recovery_proof(dict(producer.entries))
    expected = _RECOVERY_FAILURES.get(specification.corruption_id)
    if expected is None:
        raise CorruptionVerificationError("unknown recovery corruption")
    fragment, issue_code = expected
    projected = _project_producer_corruption(
        producer,
        target=specification.target_artifact_path,
        target_payload=corrupted_entries[specification.target_artifact_path],
    )
    try:
        _verify_recovery_proof(dict(decode_snapshot_entries(projected)))
    except LifecycleVerificationError as exc:
        if fragment not in str(exc):
            raise CorruptionVerificationError(
                "lifecycle verifier rejected the corruption for an unexpected reason"
            ) from exc
        return _finding(ExpectedVerifierResult.REJECTED, issue_code)
    raise CorruptionVerificationError("lifecycle verifier accepted the corrupted proof")


def _verify_recovery_proof(entries: dict[str, bytes]) -> None:
    lifecycle_path = "records/lifecycle/incident-lifecycle.json"
    receipts_path = "records/lifecycle/admitted-receipts.json"
    verified_path = "records/lifecycle/verified-lifecycle.json"
    try:
        lifecycle = IncidentLifecycle.model_validate_json(
            entries[lifecycle_path],
            strict=True,
        )
        receipt_document = strict_json_loads(entries[receipts_path])
        if (
            not isinstance(receipt_document, dict)
            or set(receipt_document) != {"wire_schema", "receipts"}
            or receipt_document["wire_schema"] != "assurance-lab.lifecycle-admitted-receipts/v1"
            or not isinstance(receipt_document["receipts"], list)
        ):
            raise CorruptionVerificationError("lifecycle admitted-receipts envelope is malformed")
        receipts = tuple(
            AdmittedReceiptEvidence.model_validate_json(
                canonical_json_bytes(item),
                strict=True,
            )
            for item in receipt_document["receipts"]
        )
        declared = VerifiedLifecycle.model_validate_json(
            entries[verified_path],
            strict=True,
        )
    except (KeyError, TypeError, ValidationError, ValueError) as exc:
        if isinstance(exc, LifecycleVerificationError):
            raise
        raise CorruptionVerificationError("lifecycle proof members failed strict parsing") from exc
    derived = verify_lifecycle(lifecycle, admitted_receipts=receipts)
    if derived != declared:
        raise CorruptionVerificationError(
            "bundled lifecycle verifier output differs from raw proof"
        )


@lru_cache(maxsize=8)
def _load_response_repository(snapshot_bytes: bytes) -> None:
    with _materialized_snapshot(snapshot_bytes) as root:
        FinancialResponseBundleRepository(root)


@contextmanager
def _materialized_snapshot(snapshot_bytes: bytes) -> Iterator[Path]:
    entries = decode_snapshot_entries(snapshot_bytes)
    with tempfile.TemporaryDirectory(prefix="assurance-lab-corruption-response-") as directory:
        root = Path(directory)
        for relative, payload in entries:
            destination = root.joinpath(*relative.split("/"))
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor = -1
            try:
                descriptor = os.open(destination, _FILE_FLAGS, 0o600)
                view = memoryview(payload)
                written = 0
                while written < len(payload):
                    count = os.write(descriptor, view[written:])
                    if count <= 0:
                        raise CorruptionVerificationError(
                            "response CAB materialization made no progress"
                        )
                    written += count
            except OSError as exc:
                raise CorruptionVerificationError("response CAB materialization failed") from exc
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        yield root


def _jsonl_records(payload: bytes) -> list[dict[str, object]]:
    try:
        records = strict_jsonl_loads(payload, require_sorted_ids=True)
    except ValueError as exc:
        raise CorruptionVerificationError("detection observations are not canonical JSONL") from exc
    return cast(list[dict[str, object]], records)


def _one_record(
    records: list[dict[str, object]],
    record_id: str,
) -> dict[str, object]:
    matches = [record for record in records if record.get("id") == record_id]
    if len(matches) != 1:
        raise CorruptionVerificationError("detection record id does not select one observation")
    return matches[0]


def _result_dict(record: dict[str, object]) -> dict[str, object]:
    result = record.get("result")
    if not isinstance(result, dict):
        raise CorruptionVerificationError("detection observation has no result object")
    return cast(dict[str, object], result)


def _has_validation_error(
    errors: list[ErrorDetails],
    location: tuple[str, ...],
    error_type: str,
) -> bool:
    return any(
        tuple(str(item) for item in error["loc"]) == location and error["type"] == error_type
        for error in errors
    )


__all__ = [
    "CorruptionVerificationError",
    "FrozenProfileCorruptionVerifier",
]
