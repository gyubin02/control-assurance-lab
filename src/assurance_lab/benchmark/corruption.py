"""Deterministic corruption replay over the concrete canonical CAB profile.

The mutation engine in this module is intentionally not pluggable.  C01-C20
freeze a complete JSON/JSONL recipe and the engine itself extracts the declared
target, mutates it, rebuilds (or deliberately preserves) the CAB manifest, and
returns byte witnesses.  A collaborator may evaluate the resulting CAB, but it
must return a typed receipt bound to the exact inputs and its pinned identity.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from pydantic import BaseModel as PydanticBaseModel
from pydantic import ConfigDict, Field, JsonValue, ValidationError, model_validator

from assurance_lab.benchmark.admission import (
    BenchmarkAdmissionError,
    SourceBundleResolver,
    _resolve_benchmark,
    _ResolvedBenchmark,
    canonical_model_bytes,
    parse_benchmark_bytes,
    revalidate_benchmark_value,
)
from assurance_lab.benchmark.cab import (
    BenchmarkCABError,
    VerifiedBenchmarkCAB,
    decode_snapshot_entries,
    encode_snapshot_entries,
    raw_sha256,
    rebuild_manifest,
    verify_benchmark_cab,
)
from assurance_lab.benchmark.corruption_sources import (
    detection_corruption_compiled,
    planned_trial,
    response_corruption_compiled,
)
from assurance_lab.benchmark.models import (
    CORRUPTIONS_PER_BENCHMARK,
    DETECTION_SCENARIO_ID,
    RECOVERY_SCENARIO_ID,
    RESPONSE_SCENARIO_ID,
    ArtifactPath,
    CorruptionId,
    CorruptionReceipt,
    Digest,
    IndexedCorruptionCorpus,
    IssueDisposition,
    JsonPointer,
    NormalizedIssue,
    PortableEvaluatorId,
    RecordKey,
    ScenarioId,
    canonical_digest,
)
from assurance_lab.contract import PlannedTrial
from assurance_lab.evidence.canonical import (
    StrictJSONError,
    canonical_json_bytes,
    canonical_jsonl_bytes,
    strict_json_loads,
    strict_jsonl_loads,
)
from assurance_lab.evidence.snapshot import (
    MAX_CAB_SNAPSHOT_BYTES,
    CABSnapshotError,
    verify_cab_snapshot,
)
from assurance_lab.lifecycle import incident_snapshot_digest
from assurance_lab.scenarios.financial_recovery_e2e import (
    build_reference_recovery_lifecycle,
)
from assurance_lab.scenarios.financial_response_contract import (
    UNRELATED_SESSION_ID,
)


class CorruptionMutationKind(StrEnum):
    RAW_BYTE_WITH_STALE_MANIFEST = "raw-byte-with-stale-manifest"
    REMOVE_DECLARED_CELL = "remove-declared-cell"
    DUPLICATE_TRIAL_LINEAGE = "duplicate-trial-lineage"
    RELABEL_SELECTOR = "relabel-selector"
    SWAP_ACTION_DIGESTS = "swap-action-digests"
    REUSE_EVENT_ARTIFACT = "reuse-event-artifact"
    EXPIRE_REQUIRED_EVIDENCE = "expire-required-evidence"
    GAP_CLOSED_SEQUENCE = "gap-closed-sequence"
    OMIT_COMPLETION_OR_CLOCK = "omit-completion-or-clock"
    REPLACE_TARGET_SUBJECT = "replace-target-subject"
    SUBSTITUTE_FALLBACK_READBACK = "substitute-fallback-readback"
    REMOVE_OR_FAIL_CLEANUP = "remove-or-fail-cleanup"
    CONTRADICT_TARGET_OBSERVATION = "contradict-target-observation"
    REWRITE_DISCLOSURE_ENTRY = "rewrite-disclosure-entry"
    PROMOTE_COMPARISON_SNAPSHOT = "promote-comparison-snapshot"
    REUSE_COMPROMISED_SESSION = "reuse-compromised-session"
    REWRITE_PROVENANCE = "rewrite-provenance"
    REWRITE_DERIVED_STAGE = "rewrite-derived-stage"
    DISCONNECT_FORWARDED_READBACK = "disconnect-forwarded-readback"
    OMIT_SHAM_OPERATION_RECEIPT = "omit-sham-operation-receipt"


class ManifestPolicy(StrEnum):
    KEEP = "keep"
    REBUILD = "rebuild"


class ExpectedVerifierResult(StrEnum):
    REJECTED = "rejected"
    INDETERMINATE = "indeterminate"
    CONFLICTING = "conflicting"


class MutationOperation(StrEnum):
    REPLACE = "replace"
    REMOVE = "remove"
    REMOVE_ARRAY_ITEM = "remove-array-item"
    COPY_FROM_RECORD = "copy-from-record"
    SWAP_WITH_RECORD = "swap-with-record"


class FrozenMutationRecipe(PydanticBaseModel):
    """Complete deterministic operation; no replacement choice remains to a caller."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    operation: MutationOperation
    replacement: JsonValue | None = None
    donor_record_key: RecordKey | None = None
    donor_field_path: JsonPointer | None = None
    array_index: int | None = Field(default=None, ge=0, le=10_000)

    @model_validator(mode="after")
    def exact_operation_arguments(self) -> FrozenMutationRecipe:
        donor = self.donor_record_key is not None or self.donor_field_path is not None
        if self.operation is MutationOperation.REPLACE:
            if self.replacement is None or donor or self.array_index is not None:
                raise ValueError("replace requires only a non-null replacement")
        elif self.operation is MutationOperation.REMOVE:
            if self.replacement is not None or donor or self.array_index is not None:
                raise ValueError("remove accepts no operation arguments")
        elif self.operation is MutationOperation.REMOVE_ARRAY_ITEM:
            if self.array_index is None or self.replacement is not None or donor:
                raise ValueError("remove-array-item requires only array_index")
        elif (
            self.donor_record_key is None
            or self.donor_field_path is None
            or self.replacement is not None
            or self.array_index is not None
        ):
            raise ValueError("copy/swap requires one complete donor locator")
        return self


class FrozenCorruptionSpec(PydanticBaseModel):
    """One non-caller-selectable corruption contract and exact mutation recipe."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    corruption_id: CorruptionId
    source_scenario_id: ScenarioId
    target_artifact_path: ArtifactPath
    target_record_key: RecordKey
    target_field_path: JsonPointer
    mutation_kind: CorruptionMutationKind
    recipe: FrozenMutationRecipe
    manifest_policy: ManifestPolicy
    expected_verifier_result: ExpectedVerifierResult


def _recipe(
    operation: MutationOperation,
    *,
    replacement: JsonValue | None = None,
    donor_record_key: str | None = None,
    donor_field_path: str | None = None,
    array_index: int | None = None,
) -> FrozenMutationRecipe:
    return FrozenMutationRecipe(
        operation=operation,
        replacement=replacement,
        donor_record_key=donor_record_key,
        donor_field_path=donor_field_path,
        array_index=array_index,
    )


def _spec(
    number: int,
    scenario_id: ScenarioId,
    artifact_path: str,
    record_key: str,
    field_path: str,
    mutation_kind: CorruptionMutationKind,
    recipe: FrozenMutationRecipe,
    *,
    expected: ExpectedVerifierResult = ExpectedVerifierResult.REJECTED,
    manifest: ManifestPolicy = ManifestPolicy.REBUILD,
) -> FrozenCorruptionSpec:
    return FrozenCorruptionSpec(
        corruption_id=f"C{number:02d}",
        source_scenario_id=scenario_id,
        target_artifact_path=artifact_path,
        target_record_key=record_key,
        target_field_path=field_path,
        mutation_kind=mutation_kind,
        recipe=recipe,
        manifest_policy=manifest,
        expected_verifier_result=expected,
    )


_ROOT_RECORD_KEY = "$"


def _detection_trial(
    *,
    input_level: str = "compromised-session-sensitive-replay",
    target_level: str = "exact-rule-inactive",
    compensator_level: str = "fallback-forward",
    sham_level: str = "collector-steady",
    replicate: int = 1,
) -> str:
    return planned_trial(
        detection_corruption_compiled(),
        input_level=input_level,
        target_level=target_level,
        compensator_level=compensator_level,
        sham_level=sham_level,
        replicate=replicate,
    ).key


def _response_planned(
    *,
    input_level: str = "compromised-old-session-replay",
    target_level: str = "report-only",
    compensator_level: str = "quarantine-on",
    sham_level: str = "steady",
    replicate: int = 1,
) -> PlannedTrial:
    return planned_trial(
        response_corruption_compiled(),
        input_level=input_level,
        target_level=target_level,
        compensator_level=compensator_level,
        sham_level=sham_level,
        replicate=replicate,
    )


_DETECTION_PRIMARY = _detection_trial()
_DETECTION_DONOR = _detection_trial(replicate=2)
_DETECTION_TARGET_EFFECTIVE = _detection_trial(target_level="exact-rule-active")
_DETECTION_NO_FALLBACK = _detection_trial(compensator_level="fallback-drop")
_RESPONSE_PRIMARY = _response_planned()
_RESPONSE_DONOR = _response_planned(replicate=2)
_RESPONSE_BENIGN = _response_planned(input_level="unrelated-support-normal-action")
_RESPONSE_RELOAD = _response_planned(sham_level="responder-reload")
_RECOVERY_LIFECYCLE, _RECOVERY_RECEIPTS, _RECOVERY_VERIFIED = (
    build_reference_recovery_lifecycle()
)
_MATCHED_COMPARISON_HEAD_DIGEST = incident_snapshot_digest(
    _RECOVERY_LIFECYCLE.matched_comparison.snapshots[-1]
)


FROZEN_CORRUPTION_SPECS: tuple[FrozenCorruptionSpec, ...] = (
    _spec(
        1,
        DETECTION_SCENARIO_ID,
        "records/runtime-observations.jsonl",
        _DETECTION_TARGET_EFFECTIVE,
        "/result/source_events/0/source_sequence",
        CorruptionMutationKind.RAW_BYTE_WITH_STALE_MANIFEST,
        _recipe(MutationOperation.REPLACE, replacement=7302),
        manifest=ManifestPolicy.KEEP,
    ),
    _spec(
        2,
        DETECTION_SCENARIO_ID,
        "spec/compiled-experiment.json",
        _ROOT_RECORD_KEY,
        "/cells",
        CorruptionMutationKind.REMOVE_DECLARED_CELL,
        _recipe(MutationOperation.REMOVE_ARRAY_ITEM, array_index=0),
    ),
    _spec(
        3,
        RESPONSE_SCENARIO_ID,
        "records/trial-records.jsonl",
        _RESPONSE_PRIMARY.key,
        "/record/clone/unique_instance_id",
        CorruptionMutationKind.DUPLICATE_TRIAL_LINEAGE,
        _recipe(
            MutationOperation.COPY_FROM_RECORD,
            donor_record_key=_RESPONSE_DONOR.key,
            donor_field_path="/record/clone/unique_instance_id",
        ),
    ),
    _spec(
        4,
        RESPONSE_SCENARIO_ID,
        "artifacts/trial-attestations.jsonl",
        f"response-attestation-{_RESPONSE_PRIMARY.ordinal:04d}",
        "/observed_selector/target/value",
        CorruptionMutationKind.RELABEL_SELECTOR,
        _recipe(MutationOperation.REPLACE, replacement="revoke-exact"),
    ),
    _spec(
        5,
        RESPONSE_SCENARIO_ID,
        "records/trial-records.jsonl",
        _RESPONSE_PRIMARY.key,
        "/record/trace/action_digest",
        CorruptionMutationKind.SWAP_ACTION_DIGESTS,
        _recipe(
            MutationOperation.SWAP_WITH_RECORD,
            donor_record_key=_RESPONSE_BENIGN.key,
            donor_field_path="/record/trace/action_digest",
        ),
    ),
    _spec(
        6,
        DETECTION_SCENARIO_ID,
        "records/runtime-observations.jsonl",
        _DETECTION_PRIMARY,
        "/result/trace_id",
        CorruptionMutationKind.REUSE_EVENT_ARTIFACT,
        _recipe(
            MutationOperation.COPY_FROM_RECORD,
            donor_record_key=_DETECTION_DONOR,
            donor_field_path="/result/trace_id",
        ),
    ),
    _spec(
        7,
        DETECTION_SCENARIO_ID,
        "records/runtime-observations.jsonl",
        _DETECTION_PRIMARY,
        "/result/window_closure/closed_at_ms",
        CorruptionMutationKind.EXPIRE_REQUIRED_EVIDENCE,
        _recipe(MutationOperation.REPLACE, replacement=999999),
        expected=ExpectedVerifierResult.INDETERMINATE,
    ),
    _spec(
        8,
        DETECTION_SCENARIO_ID,
        "records/runtime-observations.jsonl",
        _DETECTION_PRIMARY,
        "/result/window_closure/observed_source_sequences",
        CorruptionMutationKind.GAP_CLOSED_SEQUENCE,
        _recipe(MutationOperation.REMOVE_ARRAY_ITEM, array_index=1),
        expected=ExpectedVerifierResult.INDETERMINATE,
    ),
    _spec(
        9,
        DETECTION_SCENARIO_ID,
        "records/runtime-observations.jsonl",
        _DETECTION_PRIMARY,
        "/result/collector_run_readback",
        CorruptionMutationKind.OMIT_COMPLETION_OR_CLOCK,
        _recipe(MutationOperation.REMOVE),
        expected=ExpectedVerifierResult.INDETERMINATE,
    ),
    _spec(
        10,
        RESPONSE_SCENARIO_ID,
        "records/runtime-observations.jsonl",
        f"{_RESPONSE_PRIMARY.key}:runtime-observation",
        "/target_mutation/session_id",
        CorruptionMutationKind.REPLACE_TARGET_SUBJECT,
        _recipe(MutationOperation.REPLACE, replacement=UNRELATED_SESSION_ID),
    ),
    _spec(
        11,
        DETECTION_SCENARIO_ID,
        "records/runtime-observations.jsonl",
        _DETECTION_PRIMARY,
        "/result/named_exact_correlation_alert_proven",
        CorruptionMutationKind.SUBSTITUTE_FALLBACK_READBACK,
        _recipe(
            MutationOperation.COPY_FROM_RECORD,
            donor_record_key=_DETECTION_PRIMARY,
            donor_field_path="/result/fallback_alert_binding_valid",
        ),
        expected=ExpectedVerifierResult.INDETERMINATE,
    ),
    _spec(
        12,
        RESPONSE_SCENARIO_ID,
        "artifacts/cleanup-observations.jsonl",
        f"response-cleanup-{_RESPONSE_PRIMARY.ordinal:04d}",
        "/state",
        CorruptionMutationKind.REMOVE_OR_FAIL_CLEANUP,
        _recipe(MutationOperation.REPLACE, replacement="failed"),
    ),
    _spec(
        13,
        DETECTION_SCENARIO_ID,
        "records/runtime-observations.jsonl",
        _DETECTION_NO_FALLBACK,
        "/result/named_rule_active",
        CorruptionMutationKind.CONTRADICT_TARGET_OBSERVATION,
        _recipe(MutationOperation.REPLACE, replacement=True),
        expected=ExpectedVerifierResult.CONFLICTING,
    ),
    _spec(
        14,
        RECOVERY_SCENARIO_ID,
        "records/lifecycle/admitted-receipts.json",
        _ROOT_RECORD_KEY,
        "/receipts/0/record_token",
        CorruptionMutationKind.REWRITE_DISCLOSURE_ENTRY,
        _recipe(
            MutationOperation.REPLACE,
            replacement="SYNTH-DISCLOSED-RECORD-REWRITTEN",
        ),
    ),
    _spec(
        15,
        RECOVERY_SCENARIO_ID,
        "records/lifecycle/incident-lifecycle.json",
        _ROOT_RECORD_KEY,
        "/current_snapshot_digest",
        CorruptionMutationKind.PROMOTE_COMPARISON_SNAPSHOT,
        _recipe(
            MutationOperation.REPLACE,
            replacement=_MATCHED_COMPARISON_HEAD_DIGEST,
        ),
    ),
    _spec(
        16,
        RECOVERY_SCENARIO_ID,
        "records/lifecycle/incident-lifecycle.json",
        _ROOT_RECORD_KEY,
        "/actual/snapshots/4/replacement_session_digest",
        CorruptionMutationKind.REUSE_COMPROMISED_SESSION,
        _recipe(
            MutationOperation.COPY_FROM_RECORD,
            donor_record_key=_ROOT_RECORD_KEY,
            donor_field_path="/actual/snapshots/4/compromised_session_digest",
        ),
    ),
    _spec(
        17,
        RESPONSE_SCENARIO_ID,
        "bundle.json",
        _ROOT_RECORD_KEY,
        "/evaluation/evaluator/source_revision",
        CorruptionMutationKind.REWRITE_PROVENANCE,
        _recipe(
            MutationOperation.REPLACE,
            replacement="corrupted-evaluator-revision",
        ),
    ),
    _spec(
        18,
        RESPONSE_SCENARIO_ID,
        "records/stage-events.jsonl",
        (
            f"financial-response-trace-{_RESPONSE_PRIMARY.ordinal:04d}-"
            f"{_RESPONSE_PRIMARY.key[-12:]}:target"
        ),
        "/stage",
        CorruptionMutationKind.REWRITE_DERIVED_STAGE,
        _recipe(MutationOperation.REPLACE, replacement="input"),
    ),
    _spec(
        19,
        DETECTION_SCENARIO_ID,
        "records/runtime-observations.jsonl",
        _DETECTION_PRIMARY,
        "/result/forwarded_events/0/source_event_digest",
        CorruptionMutationKind.DISCONNECT_FORWARDED_READBACK,
        _recipe(
            MutationOperation.REPLACE,
            replacement=(
                "sha256:ffffffffffffffffffffffffffffffff"
                "ffffffffffffffffffffffffffffffff"
            ),
        ),
    ),
    _spec(
        20,
        RESPONSE_SCENARIO_ID,
        "records/runtime-observations.jsonl",
        f"{_RESPONSE_RELOAD.key}:runtime-observation",
        "/sham_operation",
        CorruptionMutationKind.OMIT_SHAM_OPERATION_RECEIPT,
        _recipe(MutationOperation.REMOVE),
    ),
)


def corruption_spec_digest(specification: FrozenCorruptionSpec) -> str:
    return canonical_digest(specification.model_dump(mode="json"))


def _validate_frozen_specs() -> None:
    expected_ids = tuple(f"C{number:02d}" for number in range(1, 21))
    if tuple(spec.corruption_id for spec in FROZEN_CORRUPTION_SPECS) != expected_ids:
        raise RuntimeError("frozen corruption specifications are incomplete or unordered")
    identities = {
        (
            spec.source_scenario_id,
            spec.target_artifact_path,
            spec.target_record_key,
            spec.target_field_path,
            spec.mutation_kind,
        )
        for spec in FROZEN_CORRUPTION_SPECS
    }
    if len(identities) != CORRUPTIONS_PER_BENCHMARK:
        raise RuntimeError("frozen corruption specifications contain a duplicate mutation")


_validate_frozen_specs()


@dataclass(frozen=True, slots=True)
class CorruptionReplay:
    """Deterministically extracted target witnesses and complete mutated CAB bytes."""

    source_bundle_digest: str
    corrupted_bundle_bytes: bytes
    corrupted_bundle_digest: str
    before_bytes: bytes
    after_bytes: bytes
    source_manifest_digest: str
    corrupted_manifest_digest: str
    manifest_rebuilt: bool


class CorruptionVerificationReceipt(PydanticBaseModel):
    """Independent verifier output bound to exact replay inputs and verifier identity."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    wire_schema: str = Field(
        pattern=r"^assurance-lab\.benchmark\.corruption-verification-receipt/v1$"
    )
    verifier_id: PortableEvaluatorId
    verifier_digest: Digest
    corruption_id: CorruptionId
    mutation_spec_digest: Digest
    source_bundle_digest: Digest
    corrupted_bundle_digest: Digest
    result: ExpectedVerifierResult
    issues: tuple[NormalizedIssue, ...] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def outcome_has_exact_negative_issue(self) -> CorruptionVerificationReceipt:
        keys = [
            (issue.code, issue.disposition.value, issue.subject_path, issue.related_trial_keys)
            for issue in self.issues
        ]
        if keys != sorted(keys) or len(keys) != len(set(keys)):
            raise ValueError("corruption verifier issues must be unique and canonical")
        expected_disposition = {
            ExpectedVerifierResult.REJECTED: IssueDisposition.REJECTED,
            ExpectedVerifierResult.INDETERMINATE: IssueDisposition.INDETERMINATE,
            ExpectedVerifierResult.CONFLICTING: IssueDisposition.CONFLICTING,
        }[self.result]
        if expected_disposition not in {issue.disposition for issue in self.issues}:
            raise ValueError("corruption verifier result lacks its normalized negative issue")
        return self


class CorruptionBundleResolver(Protocol):
    """Resolve an indexed corrupted CAB snapshot by exact content digest."""

    def resolve_corrupted_bundle(
        self,
        *,
        corruption_id: str,
        bundle_digest: str,
    ) -> bytes:
        """Return exact deterministic corrupted snapshot bytes."""


class CorruptionVerifier(Protocol):
    """Evaluate one exact deterministic corruption and issue a bound receipt."""

    @property
    def verifier_id(self) -> str:
        """Stable verifier implementation identity."""

    @property
    def verifier_digest(self) -> str:
        """Pinned content address of the verifier implementation."""

    def verify_corruption(
        self,
        *,
        source_bundle_bytes: bytes,
        corrupted_bundle_bytes: bytes,
        specification: FrozenCorruptionSpec,
    ) -> CorruptionVerificationReceipt:
        """Return a normalized receipt for these exact bytes and mutation."""


_ABSENT_WITNESS = b"assurance-lab:json-pointer-absent/v1"


def _pointer_tokens(pointer: str) -> tuple[str, ...]:
    return tuple(token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/"))


def _pointer_get(document: JsonValue, pointer: str) -> JsonValue:
    current: JsonValue = document
    for token in _pointer_tokens(pointer):
        if isinstance(current, dict):
            if token not in current:
                raise BenchmarkCABError("corruption JSON pointer does not exist")
            current = current[token]
        elif isinstance(current, list):
            try:
                index = int(token)
            except ValueError as exc:
                raise BenchmarkCABError("corruption JSON pointer has a non-numeric index") from exc
            if index < 0 or index >= len(current):
                raise BenchmarkCABError("corruption JSON pointer index is outside the array")
            current = current[index]
        else:
            raise BenchmarkCABError("corruption JSON pointer traverses a scalar")
    return current


def _pointer_parent(
    document: JsonValue,
    pointer: str,
) -> tuple[dict[str, JsonValue] | list[JsonValue], str]:
    tokens = _pointer_tokens(pointer)
    if not tokens:
        raise BenchmarkCABError("corruption cannot replace a document root")
    parent_pointer = "/" + "/".join(
        token.replace("~", "~0").replace("/", "~1") for token in tokens[:-1]
    )
    parent: JsonValue = document if len(tokens) == 1 else _pointer_get(document, parent_pointer)
    if not isinstance(parent, (dict, list)):
        raise BenchmarkCABError("corruption target parent is not a container")
    return parent, tokens[-1]


def _pointer_set(document: JsonValue, pointer: str, value: JsonValue) -> None:
    parent, token = _pointer_parent(document, pointer)
    if isinstance(parent, dict):
        if token not in parent:
            raise BenchmarkCABError("corruption replacement target does not exist")
        parent[token] = value
        return
    try:
        index = int(token)
    except ValueError as exc:
        raise BenchmarkCABError("corruption array target is not numeric") from exc
    if index < 0 or index >= len(parent):
        raise BenchmarkCABError("corruption array target is outside the array")
    parent[index] = value


def _pointer_remove(document: JsonValue, pointer: str) -> None:
    parent, token = _pointer_parent(document, pointer)
    if isinstance(parent, dict):
        if token not in parent:
            raise BenchmarkCABError("corruption removal target does not exist")
        del parent[token]
        return
    try:
        index = int(token)
    except ValueError as exc:
        raise BenchmarkCABError("corruption array target is not numeric") from exc
    if index < 0 or index >= len(parent):
        raise BenchmarkCABError("corruption array target is outside the array")
    del parent[index]


def _load_records(path: str, payload: bytes) -> tuple[list[dict[str, JsonValue]], bool]:
    try:
        if path.endswith(".jsonl"):
            records = strict_jsonl_loads(payload, require_sorted_ids=True)
            return cast(list[dict[str, JsonValue]], records), True
        document = strict_json_loads(payload)
        if canonical_json_bytes(document) != payload or not isinstance(document, dict):
            raise StrictJSONError("JSON corruption target must be one canonical object")
        return [cast(dict[str, JsonValue], document)], False
    except StrictJSONError as exc:
        raise BenchmarkCABError("corruption target is not canonical JSON/JSONL") from exc


def _record(
    records: list[dict[str, JsonValue]],
    key: str,
    *,
    allow_root: bool,
) -> dict[str, JsonValue]:
    if key == _ROOT_RECORD_KEY:
        if not allow_root or len(records) != 1:
            raise BenchmarkCABError(
                "root corruption key requires one canonical JSON object"
            )
        return records[0]
    matches = [record for record in records if record.get("id") == key]
    if len(matches) != 1:
        raise BenchmarkCABError("corruption record key does not select exactly one record")
    return matches[0]


def _value_bytes(value: JsonValue) -> bytes:
    return canonical_json_bytes(value)


def _mutate_records(
    records: list[dict[str, JsonValue]],
    specification: FrozenCorruptionSpec,
    *,
    allow_root: bool,
) -> tuple[bytes, bytes]:
    target = _record(
        records,
        specification.target_record_key,
        allow_root=allow_root,
    )
    before_value = copy.deepcopy(_pointer_get(target, specification.target_field_path))
    recipe = specification.recipe
    if recipe.operation is MutationOperation.REPLACE:
        assert recipe.replacement is not None
        _pointer_set(target, specification.target_field_path, copy.deepcopy(recipe.replacement))
    elif recipe.operation is MutationOperation.REMOVE:
        _pointer_remove(target, specification.target_field_path)
    elif recipe.operation is MutationOperation.REMOVE_ARRAY_ITEM:
        value = _pointer_get(target, specification.target_field_path)
        if not isinstance(value, list) or recipe.array_index is None:
            raise BenchmarkCABError("remove-array-item target is not an array")
        if recipe.array_index >= len(value):
            raise BenchmarkCABError("remove-array-item index is outside the array")
        del value[recipe.array_index]
    else:
        assert recipe.donor_record_key is not None
        assert recipe.donor_field_path is not None
        donor = _record(
            records,
            recipe.donor_record_key,
            allow_root=allow_root,
        )
        donor_value = copy.deepcopy(_pointer_get(donor, recipe.donor_field_path))
        if recipe.operation is MutationOperation.COPY_FROM_RECORD:
            _pointer_set(target, specification.target_field_path, donor_value)
        else:
            target_value = copy.deepcopy(before_value)
            _pointer_set(target, specification.target_field_path, donor_value)
            _pointer_set(donor, recipe.donor_field_path, target_value)
    try:
        after_value = _pointer_get(target, specification.target_field_path)
        after_bytes = _value_bytes(after_value)
    except BenchmarkCABError:
        if recipe.operation is not MutationOperation.REMOVE:
            raise
        after_bytes = _ABSENT_WITNESS
    return _value_bytes(before_value), after_bytes


def replay_frozen_corruption(
    source: VerifiedBenchmarkCAB,
    specification: FrozenCorruptionSpec,
) -> CorruptionReplay:
    """Apply one frozen recipe to an actual verified CAB and prove manifest policy."""

    if type(source) is not VerifiedBenchmarkCAB:
        raise BenchmarkCABError("corruption replay requires a verified source CAB")
    entries = dict(decode_snapshot_entries(source.snapshot_bytes))
    source_manifest = entries["bundle.json"]
    payload = entries.get(specification.target_artifact_path)
    if payload is None:
        raise BenchmarkCABError("source CAB does not contain the frozen corruption target")
    records, is_jsonl = _load_records(specification.target_artifact_path, payload)
    before_bytes, after_bytes = _mutate_records(
        records,
        specification,
        allow_root=not is_jsonl,
    )
    mutated_payload = (
        canonical_jsonl_bytes(records)
        if is_jsonl
        else canonical_json_bytes(cast(JsonValue, records[0]))
    )
    if mutated_payload == payload or before_bytes == after_bytes:
        raise BenchmarkCABError("frozen corruption recipe produced a no-op")
    if specification.corruption_id == "C01":
        differing = abs(len(payload) - len(mutated_payload)) + sum(
            left != right for left, right in zip(payload, mutated_payload, strict=False)
        )
        if differing != 1:
            raise BenchmarkCABError("C01 must alter exactly one raw target byte")
    entries[specification.target_artifact_path] = mutated_payload
    ordered = (
        ("bundle.json", entries["bundle.json"]),
        *tuple(
            sorted(
                (path, member)
                for path, member in entries.items()
                if path != "bundle.json"
            )
        ),
    )
    if specification.manifest_policy is ManifestPolicy.REBUILD:
        if specification.target_artifact_path == "bundle.json":
            # ``bundle.json`` is the root manifest, not one of its own file
            # descriptors.  Canonical mutation plus complete snapshot
            # re-encoding is the manifest rebuild for C17.
            ordered = (
                ("bundle.json", entries["bundle.json"]),
                *tuple(
                    sorted(
                        (path, member)
                        for path, member in entries.items()
                        if path != "bundle.json"
                    )
                ),
            )
        else:
            ordered = rebuild_manifest(
                ordered,
                changed_paths=frozenset({specification.target_artifact_path}),
            )
    corrupted = encode_snapshot_entries(ordered)
    corrupted_entries = dict(decode_snapshot_entries(corrupted))
    corrupted_manifest = corrupted_entries["bundle.json"]
    if specification.manifest_policy is ManifestPolicy.KEEP:
        if corrupted_manifest != source_manifest:
            raise BenchmarkCABError("KEEP mutation changed the source manifest")
        try:
            verify_cab_snapshot(corrupted)
        except CABSnapshotError:
            pass
        else:
            raise BenchmarkCABError("KEEP mutation unexpectedly preserved CAB integrity")
    else:
        if corrupted_manifest == source_manifest:
            raise BenchmarkCABError("REBUILD mutation did not change the manifest")
        verify_benchmark_cab(corrupted, expected_snapshot_digest=raw_sha256(corrupted))
    return CorruptionReplay(
        source_bundle_digest=source.snapshot_digest,
        corrupted_bundle_bytes=corrupted,
        corrupted_bundle_digest=raw_sha256(corrupted),
        before_bytes=before_bytes,
        after_bytes=after_bytes,
        source_manifest_digest=raw_sha256(source_manifest),
        corrupted_manifest_digest=raw_sha256(corrupted_manifest),
        manifest_rebuilt=specification.manifest_policy is ManifestPolicy.REBUILD,
    )


def _resolve_corrupted(
    resolver: CorruptionBundleResolver,
    *,
    corruption_id: str,
    digest: str,
) -> bytes:
    try:
        payload = resolver.resolve_corrupted_bundle(
            corruption_id=corruption_id,
            bundle_digest=digest,
        )
    except Exception as exc:
        raise BenchmarkAdmissionError("corrupted bundle resolver failed") from exc
    if type(payload) is not bytes:
        raise BenchmarkAdmissionError("corrupted bundle resolver must return immutable bytes")
    if len(payload) > MAX_CAB_SNAPSHOT_BYTES:
        raise BenchmarkAdmissionError("resolved corrupted bundle exceeds the CAB profile")
    if raw_sha256(payload) != digest:
        raise BenchmarkAdmissionError("resolved corrupted bundle has the wrong digest")
    try:
        decode_snapshot_entries(payload)
    except BenchmarkCABError as exc:
        raise BenchmarkAdmissionError(
            "resolved corrupted bundle is not a bounded CAB snapshot"
        ) from exc
    return payload


def _verify_corruptions(
    *,
    resolved: _ResolvedBenchmark,
    receipt_bytes: tuple[bytes, ...],
    corrupted_bundle_resolver: CorruptionBundleResolver,
    verifier: CorruptionVerifier,
) -> IndexedCorruptionCorpus:
    if len(receipt_bytes) != CORRUPTIONS_PER_BENCHMARK:
        raise BenchmarkAdmissionError("corruption corpus requires exactly twenty receipts")
    receipts = tuple(
        parse_benchmark_bytes(payload, CorruptionReceipt) for payload in receipt_bytes
    )
    try:
        corpus = IndexedCorruptionCorpus(
            wire_schema="assurance-lab.benchmark.indexed-corruption-corpus/v1",
            index=resolved.combined.index,
            receipts=receipts,
        )
    except ValidationError as exc:
        raise BenchmarkAdmissionError("receipt corpus does not match its admitted index") from exc
    scenario_by_id = {
        scenario.raw.scenario_id: scenario for scenario in resolved.scenarios
    }
    entries = {
        entry.corruption_id: entry for entry in resolved.combined.index.corruptions
    }
    for specification, receipt, receipt_wire in zip(
        FROZEN_CORRUPTION_SPECS,
        receipts,
        receipt_bytes,
        strict=True,
    ):
        entry = entries[specification.corruption_id]
        expected_manifest = specification.manifest_policy is ManifestPolicy.REBUILD
        expected_spec_digest = corruption_spec_digest(specification)
        if (
            entry.source_scenario_id != specification.source_scenario_id
            or receipt.corruption_id != specification.corruption_id
            or receipt.target_artifact_path != specification.target_artifact_path
            or receipt.target_record_key != specification.target_record_key
            or receipt.target_field_path != specification.target_field_path
            or receipt.manifest_rebuilt is not expected_manifest
            or receipt.mutation_spec_digest != expected_spec_digest
        ):
            raise BenchmarkAdmissionError(
                f"{specification.corruption_id} does not match its frozen mutation contract"
            )
        if raw_sha256(receipt_wire) != entry.receipt_digest:
            raise BenchmarkAdmissionError(
                f"{specification.corruption_id} index does not bind actual receipt bytes"
            )
        source = scenario_by_id[specification.source_scenario_id].cab
        try:
            replay = replay_frozen_corruption(source, specification)
        except BenchmarkCABError as exc:
            raise BenchmarkAdmissionError(
                f"{specification.corruption_id} deterministic CAB replay failed"
            ) from exc
        corrupted = _resolve_corrupted(
            corrupted_bundle_resolver,
            corruption_id=specification.corruption_id,
            digest=receipt.corrupted_bundle_digest,
        )
        if (
            receipt.source_bundle_digest != replay.source_bundle_digest
            or receipt.corrupted_bundle_digest != replay.corrupted_bundle_digest
            or corrupted != replay.corrupted_bundle_bytes
            or receipt.before_digest != raw_sha256(replay.before_bytes)
            or receipt.after_digest != raw_sha256(replay.after_bytes)
        ):
            raise BenchmarkAdmissionError(
                f"{specification.corruption_id} receipt differs from deterministic byte replay"
            )
        try:
            output = verifier.verify_corruption(
                source_bundle_bytes=source.snapshot_bytes,
                corrupted_bundle_bytes=corrupted,
                specification=specification,
            )
        except Exception as exc:
            raise BenchmarkAdmissionError(
                f"{specification.corruption_id} independent verifier failed"
            ) from exc
        verified = revalidate_benchmark_value(output, CorruptionVerificationReceipt)
        if (
            verified.verifier_id != verifier.verifier_id
            or verified.verifier_digest != verifier.verifier_digest
            or verified.corruption_id != specification.corruption_id
            or verified.mutation_spec_digest != expected_spec_digest
            or verified.source_bundle_digest != replay.source_bundle_digest
            or verified.corrupted_bundle_digest != replay.corrupted_bundle_digest
            or verified.result is not specification.expected_verifier_result
        ):
            raise BenchmarkAdmissionError(
                f"{specification.corruption_id} verifier receipt is not bound to the replay"
            )
        if receipt.verifier_receipt_digest != raw_sha256(canonical_model_bytes(verified)):
            raise BenchmarkAdmissionError(
                f"{specification.corruption_id} receipt does not bind verifier output"
            )
    return corpus


def verify_corruption_corpus(
    *,
    index_bytes: bytes,
    raw_trial_set_bytes: tuple[bytes, bytes, bytes],
    receipt_bytes: tuple[bytes, ...],
    source_bundle_resolver: SourceBundleResolver,
    corrupted_bundle_resolver: CorruptionBundleResolver,
    verifier: CorruptionVerifier,
) -> IndexedCorruptionCorpus:
    """Close corruptions over the same exact CAB/spec/raw corpus used by admission."""

    resolved = _resolve_benchmark(
        index_bytes=index_bytes,
        raw_trial_set_bytes=raw_trial_set_bytes,
        source_bundle_resolver=source_bundle_resolver,
    )
    return _verify_corruptions(
        resolved=resolved,
        receipt_bytes=receipt_bytes,
        corrupted_bundle_resolver=corrupted_bundle_resolver,
        verifier=verifier,
    )


__all__ = [
    "FROZEN_CORRUPTION_SPECS",
    "CorruptionBundleResolver",
    "CorruptionMutationKind",
    "CorruptionReplay",
    "CorruptionVerificationReceipt",
    "CorruptionVerifier",
    "ExpectedVerifierResult",
    "FrozenCorruptionSpec",
    "FrozenMutationRecipe",
    "ManifestPolicy",
    "MutationOperation",
    "corruption_spec_digest",
    "replay_frozen_corruption",
    "verify_corruption_corpus",
]
