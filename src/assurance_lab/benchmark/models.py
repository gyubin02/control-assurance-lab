"""Canonical wire models for the fixed lifecycle benchmark.

These models bind identities to content-addressed observations and normalized
semantic results.  A digest proves only the integrity of the bytes represented
by a model.  It does not authenticate the producer, establish custody, or make
the benchmark output externally immutable.

Selectors are intentionally absent from :class:`RawTrialEnvelope`.  A verifier
must recover factor meaning from the frozen specification and the bound action,
not accept a producer-authored selector beside the observation.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from enum import StrEnum
from typing import Annotated, Any, Final, Literal

from pydantic import AfterValidator, ConfigDict, Field, PositiveInt, model_validator
from pydantic import BaseModel as PydanticBaseModel

from assurance_lab.contract import DIGEST_PATTERN, ExperimentContract, compile_experiment
from assurance_lab.evidence.canonical import canonical_json_bytes

Digest = Annotated[str, Field(pattern=DIGEST_PATTERN)]
IssueCode = Annotated[
    str,
    Field(max_length=128, pattern=r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$"),
]
CorruptionId = Annotated[
    str,
    Field(pattern=r"^C(?:0[1-9]|1[0-9]|20)$"),
]
CompilerBlock = Annotated[
    str,
    Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9._-]*$"),
]
CompilerReplicate = Annotated[int, Field(ge=1, le=1_000)]
SchemaName = Annotated[
    str,
    Field(
        min_length=1,
        max_length=256,
        pattern=r"^[a-z][a-z0-9.-]*/v[1-9][0-9]*$",
    ),
]
_DIGEST_RE: Final[re.Pattern[str]] = re.compile(DIGEST_PATTERN)
_PORTABLE_PATH_COMPONENT_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9._-]+$")
_BIDI_CLASSES: Final[frozenset[str]] = frozenset(
    {"R", "AL", "AN", "RLE", "RLO", "LRE", "LRO", "PDF", "LRI", "RLI", "FSI", "PDI"}
)
_UNSAFE_DISPLAY_CATEGORIES: Final[frozenset[str]] = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
MAX_CELL_KEY_LENGTH: Final = 512
MAX_EXTERNAL_ID_LENGTH: Final = 512
MAX_SUBJECT_PATH_LENGTH: Final = 2_048
MAX_BENCHMARK_ID_LENGTH: Final = 128
MAX_BENCHMARK_VERSION_LENGTH: Final = 64
MAX_EVALUATOR_ID_LENGTH: Final = 256
MAX_ARTIFACT_PATH_BYTES: Final = 1_024
MAX_ARTIFACT_PATH_COMPONENT_BYTES: Final = 255
MAX_RECORD_KEY_LENGTH: Final = 512
MAX_JSON_POINTER_LENGTH: Final = 2_048
MAX_TRIAL_ISSUES: Final = 64
MAX_CELL_TREE_ISSUES: Final = 128
MAX_SCENARIO_TREE_ISSUES: Final = 256
MAX_BENCHMARK_TREE_ISSUES: Final = 512


def _safe_display_text(value: str) -> str:
    if any(
        unicodedata.category(character) in _UNSAFE_DISPLAY_CATEGORIES
        or unicodedata.bidirectional(character) in _BIDI_CLASSES
        for character in value
    ):
        raise ValueError("text contains a control, surrogate, or bidirectional character")
    return value


def _safe_external_identity(value: str) -> str:
    _safe_display_text(value)
    if value.strip() != value:
        raise ValueError("identity must not have surrounding whitespace")
    return value


def _is_safe_compiler_cell_key(value: str) -> bool:
    return (
        bool(value)
        and len(value) <= MAX_CELL_KEY_LENGTH
        and value.isascii()
        and value.strip() == value
        and all(0x20 <= ord(character) <= 0x7E for character in value)
    )


def _safe_compiler_cell_key(value: str) -> str:
    if not _is_safe_compiler_cell_key(value):
        raise ValueError("compiler cell key must be portable printable ASCII")
    return value


def _portable_artifact_path(value: str) -> str:
    if value.startswith("/") or "\\" in value:
        raise ValueError("target_artifact_path must be a relative POSIX path")
    if not value.isascii():
        raise ValueError("target_artifact_path must use portable ASCII")
    if len(value.encode("ascii")) > MAX_ARTIFACT_PATH_BYTES:
        raise ValueError("target_artifact_path exceeds the byte limit")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("target_artifact_path contains an empty or dot component")
    if any(
        len(part.encode("ascii")) > MAX_ARTIFACT_PATH_COMPONENT_BYTES
        or _PORTABLE_PATH_COMPONENT_RE.fullmatch(part) is None
        for part in parts
    ):
        raise ValueError("target_artifact_path contains a non-portable component")
    return value


def _canonical_json_pointer(value: str) -> str:
    """Validate RFC 6901 escapes without overlapping replacements."""

    offset = 0
    while offset < len(value):
        if value[offset] != "~":
            offset += 1
            continue
        if offset + 1 >= len(value) or value[offset + 1] not in {"0", "1"}:
            raise ValueError("target_field_path must use canonical JSON Pointer escaping")
        offset += 2
    return value


CompilerCellKey = Annotated[
    str,
    Field(min_length=1, max_length=MAX_CELL_KEY_LENGTH),
    AfterValidator(_safe_compiler_cell_key),
]
ExternalIdentity = Annotated[
    str,
    Field(min_length=1, max_length=MAX_EXTERNAL_ID_LENGTH),
    AfterValidator(_safe_external_identity),
]
SubjectPath = Annotated[
    str,
    Field(min_length=1, max_length=MAX_SUBJECT_PATH_LENGTH, pattern=r"^/"),
    AfterValidator(_safe_display_text),
]
PortableBenchmarkId = Annotated[
    str,
    Field(
        min_length=1,
        max_length=MAX_BENCHMARK_ID_LENGTH,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@+/-]*$",
    ),
]
PortableBenchmarkVersion = Annotated[
    str,
    Field(
        min_length=1,
        max_length=MAX_BENCHMARK_VERSION_LENGTH,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]*$",
    ),
]
PortableEvaluatorId = Annotated[
    str,
    Field(
        min_length=1,
        max_length=MAX_EVALUATOR_ID_LENGTH,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@+/-]*$",
    ),
]
ArtifactPath = Annotated[
    str,
    Field(min_length=1, max_length=MAX_ARTIFACT_PATH_BYTES),
    AfterValidator(_portable_artifact_path),
]
RecordKey = Annotated[
    str,
    Field(min_length=1, max_length=MAX_RECORD_KEY_LENGTH),
    AfterValidator(_safe_external_identity),
]
JsonPointer = Annotated[
    str,
    Field(min_length=1, max_length=MAX_JSON_POINTER_LENGTH, pattern=r"^/"),
    AfterValidator(_safe_display_text),
    AfterValidator(_canonical_json_pointer),
]

DETECTION_SCENARIO_ID: Final[Literal["financial-exact-correlation-detection"]] = (
    "financial-exact-correlation-detection"
)
RESPONSE_SCENARIO_ID: Final[Literal["financial-exact-session-response"]] = (
    "financial-exact-session-response"
)
RECOVERY_SCENARIO_ID: Final[Literal["financial-entitlement-recovery"]] = (
    "financial-entitlement-recovery"
)
type ScenarioId = Literal[
    "financial-exact-correlation-detection",
    "financial-exact-session-response",
    "financial-entitlement-recovery",
]
BENCHMARK_SCENARIO_IDS: Final[tuple[ScenarioId, ScenarioId, ScenarioId]] = (
    RECOVERY_SCENARIO_ID,
    DETECTION_SCENARIO_ID,
    RESPONSE_SCENARIO_ID,
)

SCENARIOS_PER_BENCHMARK = 3
CELLS_PER_SCENARIO = 16
REPLICATES_PER_CELL = 3
TRIALS_PER_SCENARIO = CELLS_PER_SCENARIO * REPLICATES_PER_CELL
CELLS_PER_BENCHMARK = SCENARIOS_PER_BENCHMARK * CELLS_PER_SCENARIO
TRIALS_PER_BENCHMARK = CELLS_PER_BENCHMARK * REPLICATES_PER_CELL
CORRUPTIONS_PER_BENCHMARK = 20


class BaseModel(PydanticBaseModel):
    """Strict immutable benchmark value object."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        revalidate_instances="always",
    )


def canonical_digest(value: Any) -> str:
    """Return the benchmark's RFC 8785 content address for one JSON value."""

    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def canonical_trial_key(
    *,
    spec_digest: str,
    cell_key: str,
    block: str,
    replicate: int,
) -> str:
    """Reproduce the compiler-owned identity for one planned trial.

    The compiler's v3 identity is retained byte-for-byte.  Because it uses NUL
    delimiters rather than a length-prefixed encoding, this boundary rejects
    NUL in every textual coordinate.  The digest-shaped specification identity
    and compiler identifier-shaped block already exclude NUL; the cell key is
    checked explicitly.  This preserves every valid compiler key while making
    ambiguous coordinate tuples unrepresentable on this wire.
    """

    valid_coordinates = (
        _DIGEST_RE.fullmatch(spec_digest) is not None
        and _is_safe_compiler_cell_key(cell_key)
        and re.fullmatch(r"[a-z][a-z0-9._-]{0,127}", block) is not None
        and type(replicate) is int
        and 1 <= replicate <= 1_000
    )
    if not valid_coordinates:
        raise ValueError("invalid compiler-owned trial coordinates")
    material = "\0".join((spec_digest, cell_key, block, str(replicate))).encode()
    return "sha256:" + hashlib.sha256(material).hexdigest()


def _canonical_issues(issues: tuple[NormalizedIssue, ...]) -> bool:
    keys = [
        (
            issue.code,
            issue.disposition.value,
            issue.subject_path,
            issue.related_trial_keys,
        )
        for issue in issues
    ]
    return keys == sorted(keys) and len(keys) == len(set(keys))


class IssueDisposition(StrEnum):
    """How an issue constrains the result; never a positive verdict."""

    REJECTED = "rejected"
    INDETERMINATE = "indeterminate"
    CONFLICTING = "conflicting"
    NON_REPEATABLE = "non-repeatable"


class NormalizedIssue(BaseModel):
    """Stable machine-comparable issue, without evaluator-specific prose."""

    code: IssueCode
    disposition: IssueDisposition
    subject_path: SubjectPath
    related_trial_keys: tuple[Digest, ...] = Field(default=(), max_length=144)

    @model_validator(mode="after")
    def canonical_related_trials(self) -> NormalizedIssue:
        if tuple(sorted(self.related_trial_keys)) != self.related_trial_keys:
            raise ValueError("related_trial_keys must be in canonical lexical order")
        if len(set(self.related_trial_keys)) != len(self.related_trial_keys):
            raise ValueError("related_trial_keys must be unique")
        return self


class CloneReadback(BaseModel):
    """Observed fresh-clone identity and its immutable runtime covariates."""

    readback_schema: Literal["assurance-lab.clone-readback/v1"]
    unique_instance_id: ExternalIdentity
    runner_resource_id: ExternalIdentity
    base_snapshot_digest: Digest
    covariate_digest: Digest
    attestation_bundle_digest: Digest
    readback_digest: Digest

    @model_validator(mode="after")
    def content_addressed(self) -> CloneReadback:
        body = self.model_dump(mode="json", exclude={"readback_digest"})
        if self.readback_digest != canonical_digest(body):
            raise ValueError("readback_digest does not match the canonical clone readback")
        return self


class OpaqueArtifactReference(BaseModel):
    """A content address only; the common wire cannot interpret its payload.

    Scenario-specific verifiers must resolve the bytes by digest, parse the
    declared schema strictly, and derive factors from the frozen specification.
    There is deliberately no producer-authored JSON payload on this model.
    """

    schema_name: SchemaName
    artifact_digest: Digest


class SingleTrialSemanticLineage(BaseModel):
    """Exact action and runtime bytes used for a single-trial conclusion."""

    mode: Literal["single-trial"]
    lineage_schema: Literal["assurance-lab.benchmark.single-trial-lineage/v1"]
    subject_trial_key: Digest
    action_artifact: OpaqueArtifactReference
    runtime_artifact: OpaqueArtifactReference
    lineage_digest: Digest

    @model_validator(mode="after")
    def content_addressed_lineage(self) -> SingleTrialSemanticLineage:
        body = self.model_dump(mode="json", exclude={"lineage_digest"})
        if self.lineage_digest != canonical_digest(body):
            raise ValueError("lineage_digest does not address the single-trial lineage")
        return self


class MatchedPairSemanticLineage(BaseModel):
    """Exact attack/benign observations and shared lifecycle proof used together.

    The attack and benign labels are not accepted as producer assertions.
    Release admission derives them from the frozen contract's input axis and
    requires every field below to match that derived pair.
    """

    mode: Literal["matched-pair"]
    lineage_schema: Literal["assurance-lab.benchmark.matched-pair-lineage/v1"]
    subject_trial_key: Digest
    attack_trial_key: Digest
    benign_trial_key: Digest
    attack_action_artifact: OpaqueArtifactReference
    benign_action_artifact: OpaqueArtifactReference
    attack_runtime_artifact: OpaqueArtifactReference
    benign_runtime_artifact: OpaqueArtifactReference
    shared_lifecycle_proof: OpaqueArtifactReference
    lineage_digest: Digest

    @model_validator(mode="after")
    def exact_content_addressed_pair(self) -> MatchedPairSemanticLineage:
        if self.attack_trial_key == self.benign_trial_key:
            raise ValueError("matched lineage requires distinct attack and benign trials")
        if self.subject_trial_key not in {
            self.attack_trial_key,
            self.benign_trial_key,
        }:
            raise ValueError("matched lineage subject must be one member of the pair")
        if self.attack_runtime_artifact == self.benign_runtime_artifact:
            raise ValueError("matched lineage requires two distinct runtime observations")
        body = self.model_dump(mode="json", exclude={"lineage_digest"})
        if self.lineage_digest != canonical_digest(body):
            raise ValueError("lineage_digest does not address the matched-trial lineage")
        return self


type TrialSemanticLineage = Annotated[
    SingleTrialSemanticLineage | MatchedPairSemanticLineage,
    Field(discriminator="mode"),
]


class FrozenSpecificationAction(BaseModel):
    """One action bound to an exact compiler-planned trial."""

    ordinal: Annotated[int, Field(ge=1, le=TRIALS_PER_SCENARIO)]
    trial_key: Digest
    cell_key: CompilerCellKey
    block: CompilerBlock
    replicate: Annotated[int, Field(ge=1, le=REPLICATES_PER_CELL)]
    action: OpaqueArtifactReference


class FrozenBenchmarkSpecification(BaseModel):
    """Compiler-owned contract identity plus every action needed to rebuild its plan.

    ``spec_digest`` is *only* the digest emitted by :func:`compile_experiment`.
    The wrapper, which additionally binds action artifacts, has the separate
    ``benchmark_specification_digest`` content address.  Keeping those identities
    distinct prevents a benchmark envelope from inventing a second namespace for
    compiler trial keys.
    """

    wire_schema: Literal["assurance-lab.benchmark.compiled-spec/v1"]
    scenario_id: ScenarioId
    contract: ExperimentContract
    actions: tuple[FrozenSpecificationAction, ...] = Field(
        min_length=TRIALS_PER_SCENARIO,
        max_length=TRIALS_PER_SCENARIO,
    )
    spec_digest: Digest
    benchmark_specification_digest: Digest

    @model_validator(mode="after")
    def exact_recompilable_specification(self) -> FrozenBenchmarkSpecification:
        compiled = compile_experiment(self.contract)
        if self.contract.id != self.scenario_id:
            raise ValueError("compiled specification scenario does not match its contract")
        if len(self.contract.plan.blocks) != 1 or self.contract.plan.replicates != 3:
            raise ValueError("benchmark specification requires one block and three replicates")
        if self.spec_digest != compiled.spec_digest:
            raise ValueError("spec_digest must equal the experiment compiler spec_digest")
        expected_coordinates = tuple(
            (
                planned.ordinal,
                planned.key,
                planned.cell_key,
                planned.block,
                planned.replicate,
            )
            for planned in compiled.planned_trials
        )
        observed_coordinates = tuple(
            (
                action.ordinal,
                action.trial_key,
                action.cell_key,
                action.block,
                action.replicate,
            )
            for action in self.actions
        )
        if observed_coordinates != expected_coordinates:
            raise ValueError("specification actions do not match the compiler-planned trial order")
        body = self.model_dump(
            mode="json",
            exclude={"benchmark_specification_digest"},
        )
        if self.benchmark_specification_digest != canonical_digest(body):
            raise ValueError("benchmark_specification_digest does not address the exact wrapper")
        return self


class FrozenActionBinding(BaseModel):
    """Bind one opaque action artifact to one frozen spec and planned trial."""

    binding_schema: Literal["assurance-lab.benchmark.frozen-action-binding/v1"]
    spec_digest: Digest
    trial_key: Digest
    artifact: OpaqueArtifactReference
    binding_digest: Digest

    @model_validator(mode="after")
    def content_addressed_binding(self) -> FrozenActionBinding:
        body = self.model_dump(mode="json", exclude={"binding_digest"})
        if self.binding_digest != canonical_digest(body):
            raise ValueError("binding_digest does not match the frozen action binding")
        return self


class RawTrialEnvelope(BaseModel):
    """One strict, factor-free runtime envelope on the common benchmark wire.

    The common layer carries only opaque content addresses.  It cannot inspect
    action or observation fields and therefore cannot accept a producer's
    selector as semantic input.  A scenario verifier still has to resolve and
    validate both artifacts and prove that ``action.artifact`` is the action
    expected by the frozen specification; this model does not make that latter
    scenario-specific claim.
    """

    wire_schema: Literal["assurance-lab.benchmark.raw-trial/v1"]
    scenario_id: ScenarioId
    spec_digest: Digest
    trial_key: Digest
    cell_key: CompilerCellKey
    block: CompilerBlock
    replicate: CompilerReplicate
    ordinal: PositiveInt
    trace_id: ExternalIdentity
    action: FrozenActionBinding
    clone_readback: CloneReadback
    runtime_artifact: OpaqueArtifactReference
    shared_lifecycle_proof: OpaqueArtifactReference | None = None

    @model_validator(mode="after")
    def bind_coordinates_and_action(self) -> RawTrialEnvelope:
        expected_trial_key = canonical_trial_key(
            spec_digest=self.spec_digest,
            cell_key=self.cell_key,
            block=self.block,
            replicate=self.replicate,
        )
        if self.trial_key != expected_trial_key:
            raise ValueError("trial_key does not match the compiler-owned trial coordinates")
        if self.action.spec_digest != self.spec_digest or self.action.trial_key != self.trial_key:
            raise ValueError("frozen action binding must match the enclosing spec and trial")
        if self.scenario_id == RECOVERY_SCENARIO_ID:
            if self.shared_lifecycle_proof is None:
                raise ValueError("recovery trials require a shared lifecycle proof reference")
            if (
                self.shared_lifecycle_proof.schema_name
                != "assurance-lab.recovery-lifecycle-proof/v1"
            ):
                raise ValueError("recovery lifecycle proof uses an unexpected schema")
        elif self.shared_lifecycle_proof is not None:
            raise ValueError("only recovery trials may reference a shared lifecycle proof")
        return self


class RawTrialSet(BaseModel):
    """The complete 16-cell, three-replicate wire corpus for one scenario."""

    wire_schema: Literal["assurance-lab.benchmark.raw-trial-set/v1"]
    scenario_id: ScenarioId
    spec_digest: Digest
    trials: tuple[RawTrialEnvelope, ...] = Field(
        min_length=TRIALS_PER_SCENARIO,
        max_length=TRIALS_PER_SCENARIO,
    )

    @model_validator(mode="after")
    def complete_unique_design(self) -> RawTrialSet:
        if any(
            trial.scenario_id != self.scenario_id or trial.spec_digest != self.spec_digest
            for trial in self.trials
        ):
            raise ValueError("every raw trial must match the set scenario and specification")

        trial_keys = [trial.trial_key for trial in self.trials]
        trace_ids = [trial.trace_id for trial in self.trials]
        clone_ids = [trial.clone_readback.unique_instance_id for trial in self.trials]
        clone_readback_digests = [trial.clone_readback.readback_digest for trial in self.trials]
        attestation_digests = [
            trial.clone_readback.attestation_bundle_digest for trial in self.trials
        ]
        runtime_artifact_digests = [trial.runtime_artifact.artifact_digest for trial in self.trials]
        ordinals = [trial.ordinal for trial in self.trials]
        for name, identities in (
            ("trial keys", trial_keys),
            ("trace ids", trace_ids),
            ("clone identities", clone_ids),
            ("clone readback digests", clone_readback_digests),
            ("attestation bundle digests", attestation_digests),
            ("runtime artifact digests", runtime_artifact_digests),
            ("ordinals", ordinals),
        ):
            if len(set(identities)) != len(identities):
                raise ValueError(f"raw trial {name} must be unique")

        if sorted(ordinals) != list(range(1, TRIALS_PER_SCENARIO + 1)):
            raise ValueError("raw trial ordinals must be exactly 1 through 48")
        if ordinals != list(range(1, TRIALS_PER_SCENARIO + 1)):
            raise ValueError("raw trials must be ordered by ordinal")

        by_cell: dict[str, set[int]] = {}
        for trial in self.trials:
            by_cell.setdefault(trial.cell_key, set()).add(trial.replicate)
        if len(by_cell) != CELLS_PER_SCENARIO:
            raise ValueError("a scenario must contain exactly 16 distinct cells")
        expected_replicates = set(range(1, REPLICATES_PER_CELL + 1))
        if any(replicates != expected_replicates for replicates in by_cell.values()):
            raise ValueError("every cell must contain replicates 1, 2, and 3")
        if len({trial.block for trial in self.trials}) != 1:
            raise ValueError("the fixed 48-trial scenario must use one declared runner block")
        return self


class FrozenPlanEntry(BaseModel):
    """One compiler-owned trial coordinate and its exact frozen action."""

    entry_schema: Literal["assurance-lab.benchmark.frozen-plan-entry/v1"]
    cell_key: CompilerCellKey
    block: CompilerBlock
    replicate: Annotated[int, Field(ge=1, le=REPLICATES_PER_CELL)]
    ordinal: Annotated[int, Field(ge=1, le=TRIALS_PER_SCENARIO)]
    trial_key: Digest
    action: OpaqueArtifactReference


class FrozenPlan(BaseModel):
    """Exact compiler-ordered output for one 16-cell scenario plan.

    ``spec_digest`` identifies the exact compiled specification. Release
    admission recompiles this value and byte-compares it with the CAB member;
    callers do not get to substitute an opaque plan digest.
    """

    wire_schema: Literal["assurance-lab.benchmark.frozen-plan/v1"]
    scenario_id: ScenarioId
    spec_digest: Digest
    entries: tuple[FrozenPlanEntry, ...] = Field(
        min_length=TRIALS_PER_SCENARIO,
        max_length=TRIALS_PER_SCENARIO,
    )

    @model_validator(mode="after")
    def complete_compiler_identity(self) -> FrozenPlan:
        if tuple(entry.ordinal for entry in self.entries) != tuple(
            range(1, TRIALS_PER_SCENARIO + 1)
        ):
            raise ValueError("frozen plan entries must be ordered by ordinal 1 through 48")

        distinct_cells = {entry.cell_key for entry in self.entries}
        if len(distinct_cells) != CELLS_PER_SCENARIO:
            raise ValueError("frozen plan must contain exactly 16 cells")
        replicates_by_cell: dict[str, set[int]] = {}
        for entry in self.entries:
            replicates_by_cell.setdefault(entry.cell_key, set()).add(entry.replicate)
        expected_replicates = set(range(1, REPLICATES_PER_CELL + 1))
        if any(replicates != expected_replicates for replicates in replicates_by_cell.values()):
            raise ValueError("every frozen plan cell must contain replicates 1, 2, and 3")
        if len({entry.block for entry in self.entries}) != 1:
            raise ValueError("frozen plan must use one declared runner block")
        coordinates = [(entry.cell_key, entry.block, entry.replicate) for entry in self.entries]
        if len(set(coordinates)) != TRIALS_PER_SCENARIO:
            raise ValueError("frozen plan coordinates must be unique")
        if len({entry.trial_key for entry in self.entries}) != TRIALS_PER_SCENARIO:
            raise ValueError("frozen plan trial keys must be unique")
        for entry in self.entries:
            expected_trial_key = canonical_trial_key(
                spec_digest=self.spec_digest,
                cell_key=entry.cell_key,
                block=entry.block,
                replicate=entry.replicate,
            )
            if entry.trial_key != expected_trial_key:
                raise ValueError("frozen plan trial_key does not match its coordinates")
        return self


def compile_frozen_plan(specification: FrozenBenchmarkSpecification) -> FrozenPlan:
    """Recompile the only accepted plan from exact specification bytes."""

    clean = FrozenBenchmarkSpecification.model_validate(
        specification.model_dump(mode="python"),
        strict=True,
    )
    compiled = compile_experiment(clean.contract)
    actions_by_trial_key = {action.trial_key: action for action in clean.actions}
    entries = tuple(
        FrozenPlanEntry(
            entry_schema="assurance-lab.benchmark.frozen-plan-entry/v1",
            cell_key=planned.cell_key,
            block=planned.block,
            replicate=planned.replicate,
            ordinal=planned.ordinal,
            trial_key=planned.key,
            action=actions_by_trial_key[planned.key].action,
        )
        for planned in compiled.planned_trials
    )
    return FrozenPlan(
        wire_schema="assurance-lab.benchmark.frozen-plan/v1",
        scenario_id=clean.scenario_id,
        spec_digest=clean.spec_digest,
        entries=entries,
    )


class ClaimDisposition(StrEnum):
    SUPPORTED = "supported"
    REFUTED = "refuted"
    INDETERMINATE = "indeterminate"
    CONFLICTING = "conflicting"
    NON_REPEATABLE = "non-repeatable"
    NOT_EXERCISED = "not-exercised"


class BaselineDisposition(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    INDETERMINATE = "indeterminate"
    CONFLICTING = "conflicting"
    NON_REPEATABLE = "non-repeatable"


class ResidualDisposition(StrEnum):
    MASKED_TARGET_FAILURE = "masked-target-failure"
    EXPOSED_PATH = "exposed-path"
    TARGET_EFFECTIVE = "target-effective"
    UNRESOLVED = "unresolved"
    CONFLICTING = "conflicting"
    NON_REPEATABLE = "non-repeatable"


class SemanticVector(BaseModel):
    """Scenario-neutral conclusions recomputed from one raw observation."""

    target: ClaimDisposition
    compensator: ClaimDisposition
    path: ClaimDisposition
    benign: ClaimDisposition
    baseline: BaselineDisposition
    residual: ResidualDisposition


def _all_conflicting_semantics() -> SemanticVector:
    return SemanticVector(
        target=ClaimDisposition.CONFLICTING,
        compensator=ClaimDisposition.CONFLICTING,
        path=ClaimDisposition.CONFLICTING,
        benign=ClaimDisposition.CONFLICTING,
        baseline=BaselineDisposition.CONFLICTING,
        residual=ResidualDisposition.CONFLICTING,
    )


def _all_non_repeatable_semantics() -> SemanticVector:
    return SemanticVector(
        target=ClaimDisposition.NON_REPEATABLE,
        compensator=ClaimDisposition.NON_REPEATABLE,
        path=ClaimDisposition.NON_REPEATABLE,
        benign=ClaimDisposition.NON_REPEATABLE,
        baseline=BaselineDisposition.NON_REPEATABLE,
        residual=ResidualDisposition.NON_REPEATABLE,
    )


def _has_positive_semantics(semantics: SemanticVector) -> bool:
    return (
        ClaimDisposition.SUPPORTED
        in {
            semantics.target,
            semantics.compensator,
            semantics.path,
            semantics.benign,
        }
        or semantics.baseline == BaselineDisposition.PASS
        or semantics.residual
        in {
            ResidualDisposition.MASKED_TARGET_FAILURE,
            ResidualDisposition.EXPOSED_PATH,
            ResidualDisposition.TARGET_EFFECTIVE,
        }
    )


def _validate_issue_constrained_semantics(
    issues: tuple[NormalizedIssue, ...],
    semantics: SemanticVector,
) -> None:
    dispositions = {issue.disposition for issue in issues}
    if IssueDisposition.CONFLICTING in dispositions:
        if semantics != _all_conflicting_semantics():
            raise ValueError("conflicting issues require an entirely conflicting semantic vector")
    elif IssueDisposition.NON_REPEATABLE in dispositions:
        if semantics != _all_non_repeatable_semantics():
            raise ValueError(
                "non-repeatable issues require an entirely non-repeatable semantic vector"
            )
    elif issues and _has_positive_semantics(semantics):
        raise ValueError("negative issues must not coexist with positive semantics")


class TrialSemanticResult(BaseModel):
    scenario_id: ScenarioId
    spec_digest: Digest
    trial_key: Digest
    cell_key: CompilerCellKey
    block: CompilerBlock
    replicate: CompilerReplicate
    ordinal: PositiveInt
    trace_id: ExternalIdentity
    clone_unique_instance_id: ExternalIdentity
    clone_readback_digest: Digest
    attestation_bundle_digest: Digest
    runner_resource_id: ExternalIdentity
    lineage: TrialSemanticLineage
    semantics: SemanticVector
    issues: tuple[NormalizedIssue, ...] = Field(default=(), max_length=MAX_TRIAL_ISSUES)

    @model_validator(mode="after")
    def canonical_issue_order(self) -> TrialSemanticResult:
        if not _canonical_issues(self.issues):
            raise ValueError("issues must be unique and in canonical order")
        if self.trial_key != canonical_trial_key(
            spec_digest=self.spec_digest,
            cell_key=self.cell_key,
            block=self.block,
            replicate=self.replicate,
        ):
            raise ValueError(
                "semantic trial_key does not match the compiler-owned trial coordinates"
            )
        if self.lineage.subject_trial_key != self.trial_key:
            raise ValueError("semantic lineage subject does not match the containing trial")
        if self.scenario_id == RECOVERY_SCENARIO_ID:
            if not isinstance(self.lineage, MatchedPairSemanticLineage):
                raise ValueError("recovery semantics require matched-pair lineage")
        elif not isinstance(self.lineage, SingleTrialSemanticLineage):
            raise ValueError("single-trial scenarios require single-trial lineage")
        for issue in self.issues:
            if any(trial_key != self.trial_key for trial_key in issue.related_trial_keys):
                raise ValueError("trial issues may only reference their containing trial")
        _validate_issue_constrained_semantics(self.issues, self.semantics)
        return self


def _validate_issues_against_exact_trials(
    issues: tuple[NormalizedIssue, ...],
    trials_by_key: dict[str, TrialSemanticResult],
) -> None:
    """Apply a scoped issue to its trials before any aggregate conclusion.

    Aggregate suppression is not a substitute for suppressing the implicated
    observation.  An empty scope means the issue applies to every trial in the
    containing cell, scenario, or benchmark.
    """

    all_trials = tuple(trials_by_key.values())
    for issue in issues:
        affected_trials = (
            all_trials
            if not issue.related_trial_keys
            else tuple(trials_by_key[key] for key in issue.related_trial_keys)
        )
        for trial in affected_trials:
            _validate_issue_constrained_semantics((issue,), trial.semantics)


class AgreementDisposition(StrEnum):
    AGREED = "agreed"
    NON_REPEATABLE = "non-repeatable"
    CONFLICTING = "conflicting"


class ReplicateAgreement(BaseModel):
    """Exact replicate agreement; two matching trials never outvote a third."""

    disposition: AgreementDisposition
    semantic_digests: tuple[Digest, ...] = Field(min_length=1, max_length=3)
    divergent_trial_keys: tuple[Digest, ...] = Field(default=(), max_length=3)

    @model_validator(mode="after")
    def canonical_summary(self) -> ReplicateAgreement:
        if tuple(sorted(set(self.semantic_digests))) != self.semantic_digests:
            raise ValueError("semantic_digests must be unique and canonically ordered")
        if tuple(sorted(set(self.divergent_trial_keys))) != self.divergent_trial_keys:
            raise ValueError("divergent_trial_keys must be unique and canonically ordered")
        if self.disposition == AgreementDisposition.AGREED:
            if len(self.semantic_digests) != 1 or self.divergent_trial_keys:
                raise ValueError("agreed replicates require one digest and no divergence")
        elif len(self.semantic_digests) < 2 or len(self.divergent_trial_keys) != 3:
            raise ValueError(
                "divergent replicates require all three trial keys and multiple semantics"
            )
        return self


class CellSemanticResult(BaseModel):
    """Three trials and the non-voting semantic conclusion for one cell."""

    scenario_id: ScenarioId
    spec_digest: Digest
    cell_key: CompilerCellKey
    trials: tuple[TrialSemanticResult, ...] = Field(
        min_length=REPLICATES_PER_CELL,
        max_length=REPLICATES_PER_CELL,
    )
    agreement: ReplicateAgreement
    semantics: SemanticVector
    issues: tuple[NormalizedIssue, ...] = Field(default=(), max_length=64)

    @model_validator(mode="after")
    def exact_non_voting_aggregate(self) -> CellSemanticResult:
        if len(self.issues) + sum(len(trial.issues) for trial in self.trials) > (
            MAX_CELL_TREE_ISSUES
        ):
            raise ValueError("cell semantic issue tree exceeds the global cell limit")
        if not _canonical_issues(self.issues):
            raise ValueError("issues must be unique and in canonical order")
        if any(
            trial.scenario_id != self.scenario_id
            or trial.spec_digest != self.spec_digest
            or trial.cell_key != self.cell_key
            for trial in self.trials
        ):
            raise ValueError("every semantic trial must match its cell")
        if {trial.replicate for trial in self.trials} != {1, 2, 3}:
            raise ValueError("a semantic cell requires replicates 1, 2, and 3")
        if tuple(trial.replicate for trial in self.trials) != (1, 2, 3):
            raise ValueError("semantic trials must be ordered by replicate")
        trial_keys = tuple(sorted(trial.trial_key for trial in self.trials))
        if len(set(trial_keys)) != REPLICATES_PER_CELL:
            raise ValueError("semantic trial keys must be unique within a cell")
        trials_by_key = {trial.trial_key: trial for trial in self.trials}
        for issue in self.issues:
            if any(trial_key not in trial_keys for trial_key in issue.related_trial_keys):
                raise ValueError("cell issues reference a trial outside the cell")
        _validate_issues_against_exact_trials(self.issues, trials_by_key)

        semantic_digests = tuple(
            sorted(
                {canonical_digest(trial.semantics.model_dump(mode="json")) for trial in self.trials}
            )
        )
        has_conflict = any(
            ClaimDisposition.CONFLICTING
            in {
                trial.semantics.target,
                trial.semantics.compensator,
                trial.semantics.path,
                trial.semantics.benign,
            }
            or trial.semantics.baseline == BaselineDisposition.CONFLICTING
            or trial.semantics.residual == ResidualDisposition.CONFLICTING
            for trial in self.trials
        )
        if len(semantic_digests) == 1:
            expected_disposition = AgreementDisposition.AGREED
        elif has_conflict:
            expected_disposition = AgreementDisposition.CONFLICTING
        else:
            expected_disposition = AgreementDisposition.NON_REPEATABLE

        if self.agreement.disposition != expected_disposition:
            raise ValueError("replicate agreement does not match all three trials")
        if self.agreement.semantic_digests != semantic_digests:
            raise ValueError("replicate agreement carries the wrong semantic digests")
        expected_divergence = (
            () if expected_disposition == AgreementDisposition.AGREED else trial_keys
        )
        if self.agreement.divergent_trial_keys != expected_divergence:
            raise ValueError("replicate agreement carries the wrong divergent trial keys")

        if expected_disposition == AgreementDisposition.AGREED:
            if self.semantics != self.trials[0].semantics:
                raise ValueError("agreed cell semantics must equal every replicate")
        elif expected_disposition == AgreementDisposition.CONFLICTING:
            expected = _all_conflicting_semantics()
            if self.semantics != expected:
                raise ValueError("conflicting cells must not retain a positive conclusion")
        else:
            expected = _all_non_repeatable_semantics()
            if self.semantics != expected:
                raise ValueError("non-repeatable cells must not use majority-vote semantics")
        _validate_issue_constrained_semantics(self.issues, self.semantics)
        return self


class ScenarioSemanticResult(BaseModel):
    scenario_id: ScenarioId
    spec_digest: Digest
    raw_trial_set_digest: Digest
    cells: tuple[CellSemanticResult, ...] = Field(
        min_length=CELLS_PER_SCENARIO,
        max_length=CELLS_PER_SCENARIO,
    )
    issues: tuple[NormalizedIssue, ...] = Field(default=(), max_length=256)

    @model_validator(mode="after")
    def complete_unique_scenario(self) -> ScenarioSemanticResult:
        issue_count = len(self.issues) + sum(
            len(cell.issues) + sum(len(trial.issues) for trial in cell.trials)
            for cell in self.cells
        )
        if issue_count > MAX_SCENARIO_TREE_ISSUES:
            raise ValueError("scenario semantic issue tree exceeds the global scenario limit")
        if not _canonical_issues(self.issues):
            raise ValueError("issues must be unique and in canonical order")
        if any(
            cell.scenario_id != self.scenario_id or cell.spec_digest != self.spec_digest
            for cell in self.cells
        ):
            raise ValueError("every cell must match the scenario result")
        cell_keys = [cell.cell_key for cell in self.cells]
        if len(set(cell_keys)) != CELLS_PER_SCENARIO:
            raise ValueError("scenario cell keys must be unique")
        if cell_keys != sorted(cell_keys):
            raise ValueError("scenario cells must be canonically ordered")
        trial_keys = [trial.trial_key for cell in self.cells for trial in cell.trials]
        trace_ids = [trial.trace_id for cell in self.cells for trial in cell.trials]
        clone_ids = [trial.clone_unique_instance_id for cell in self.cells for trial in cell.trials]
        clone_readback_digests = [
            trial.clone_readback_digest for cell in self.cells for trial in cell.trials
        ]
        attestation_digests = [
            trial.attestation_bundle_digest for cell in self.cells for trial in cell.trials
        ]
        ordinals = [trial.ordinal for cell in self.cells for trial in cell.trials]
        for name, identities in (
            ("trial keys", trial_keys),
            ("trace ids", trace_ids),
            ("clone identities", clone_ids),
            ("clone readback digests", clone_readback_digests),
            ("attestation bundle digests", attestation_digests),
            ("ordinals", ordinals),
        ):
            if len(set(identities)) != len(identities):
                raise ValueError(f"scenario semantic {name} must be unique")
        if sorted(ordinals) != list(range(1, TRIALS_PER_SCENARIO + 1)):
            raise ValueError("scenario semantic ordinals must be exactly 1 through 48")
        if len({trial.block for cell in self.cells for trial in cell.trials}) != 1:
            raise ValueError("the fixed 48-trial scenario must use one declared runner block")

        trial_to_cell = {trial.trial_key: cell for cell in self.cells for trial in cell.trials}
        trials_by_key = {trial.trial_key: trial for cell in self.cells for trial in cell.trials}
        for issue in self.issues:
            if any(trial_key not in trial_to_cell for trial_key in issue.related_trial_keys):
                raise ValueError("scenario issues reference a trial outside the scenario")
        _validate_issues_against_exact_trials(self.issues, trials_by_key)
        for issue in self.issues:
            affected_cells = (
                set(self.cells)
                if not issue.related_trial_keys
                else {trial_to_cell[trial_key] for trial_key in issue.related_trial_keys}
            )
            for cell in affected_cells:
                _validate_issue_constrained_semantics((issue,), cell.semantics)
        return self


class BenchmarkSemanticResult(BaseModel):
    """The exact three-scenario, 144-trial normalized benchmark result."""

    wire_schema: Literal["assurance-lab.benchmark.semantic-result/v1"]
    benchmark_id: PortableBenchmarkId
    benchmark_version: PortableBenchmarkVersion
    evaluator_id: PortableEvaluatorId
    evaluator_digest: Digest
    scenarios: tuple[ScenarioSemanticResult, ...] = Field(
        min_length=SCENARIOS_PER_BENCHMARK,
        max_length=SCENARIOS_PER_BENCHMARK,
    )
    issues: tuple[NormalizedIssue, ...] = Field(default=(), max_length=512)

    @model_validator(mode="after")
    def complete_unique_benchmark(self) -> BenchmarkSemanticResult:
        issue_count = len(self.issues) + sum(
            len(scenario.issues)
            + sum(
                len(cell.issues) + sum(len(trial.issues) for trial in cell.trials)
                for cell in scenario.cells
            )
            for scenario in self.scenarios
        )
        if issue_count > MAX_BENCHMARK_TREE_ISSUES:
            raise ValueError("benchmark semantic issue tree exceeds the global benchmark limit")
        if not _canonical_issues(self.issues):
            raise ValueError("issues must be unique and in canonical order")
        scenario_ids = [scenario.scenario_id for scenario in self.scenarios]
        spec_digests = [scenario.spec_digest for scenario in self.scenarios]
        raw_trial_set_digests = [scenario.raw_trial_set_digest for scenario in self.scenarios]
        if len(set(scenario_ids)) != SCENARIOS_PER_BENCHMARK:
            raise ValueError("benchmark scenario identities must be unique")
        if len(set(spec_digests)) != SCENARIOS_PER_BENCHMARK:
            raise ValueError("benchmark specification digests must be unique")
        if len(set(raw_trial_set_digests)) != SCENARIOS_PER_BENCHMARK:
            raise ValueError("benchmark raw trial sets must not be reused")
        if scenario_ids != sorted(scenario_ids):
            raise ValueError("benchmark scenarios must be canonically ordered")
        if tuple(scenario_ids) != BENCHMARK_SCENARIO_IDS:
            raise ValueError("benchmark must contain the exact frozen lifecycle scenarios")
        all_trials = [
            trial for scenario in self.scenarios for cell in scenario.cells for trial in cell.trials
        ]
        for name, identities in (
            ("trial keys", [trial.trial_key for trial in all_trials]),
            ("trace ids", [trial.trace_id for trial in all_trials]),
            (
                "clone identities",
                [trial.clone_unique_instance_id for trial in all_trials],
            ),
            (
                "clone readback digests",
                [trial.clone_readback_digest for trial in all_trials],
            ),
            (
                "attestation bundle digests",
                [trial.attestation_bundle_digest for trial in all_trials],
            ),
        ):
            if len(set(identities)) != TRIALS_PER_BENCHMARK:
                raise ValueError(f"benchmark {name} must be globally unique")
        trial_to_cell = {
            trial.trial_key: cell
            for scenario in self.scenarios
            for cell in scenario.cells
            for trial in cell.trials
        }
        trials_by_key = {
            trial.trial_key: trial
            for scenario in self.scenarios
            for cell in scenario.cells
            for trial in cell.trials
        }
        for issue in self.issues:
            if any(trial_key not in trial_to_cell for trial_key in issue.related_trial_keys):
                raise ValueError("benchmark issues reference a trial outside the benchmark")
        _validate_issues_against_exact_trials(self.issues, trials_by_key)
        for issue in self.issues:
            affected_cells = (
                set(cell for scenario in self.scenarios for cell in scenario.cells)
                if not issue.related_trial_keys
                else {trial_to_cell[trial_key] for trial_key in issue.related_trial_keys}
            )
            for cell in affected_cells:
                _validate_issue_constrained_semantics((issue,), cell.semantics)
        return self


class CorruptionReceipt(BaseModel):
    """One deterministic mutation, addressed independently of record ordering."""

    wire_schema: Literal["assurance-lab.benchmark.corruption-receipt/v1"]
    corruption_id: CorruptionId
    source_bundle_digest: Digest
    corrupted_bundle_digest: Digest
    target_artifact_path: ArtifactPath
    target_record_key: RecordKey
    target_field_path: JsonPointer
    before_digest: Digest
    after_digest: Digest
    mutation_spec_digest: Digest
    verifier_receipt_digest: Digest
    manifest_rebuilt: bool

    @model_validator(mode="after")
    def stable_changed_target(self) -> CorruptionReceipt:
        if self.before_digest == self.after_digest:
            raise ValueError("a corruption receipt must identify changed content")
        if self.source_bundle_digest == self.corrupted_bundle_digest:
            raise ValueError("source and corrupted bundle digests must differ")
        return self


class ScenarioIndexEntry(BaseModel):
    scenario_id: ScenarioId
    spec_digest: Digest
    source_bundle_digest: Digest
    raw_trial_set_digest: Digest
    semantic_result_digest: Digest
    cell_count: Literal[16]
    trial_count: Literal[48]


class CorruptionIndexEntry(BaseModel):
    corruption_id: CorruptionId
    source_scenario_id: ScenarioId
    source_bundle_digest: Digest
    corrupted_bundle_digest: Digest
    receipt_digest: Digest


class BenchmarkIndex(BaseModel):
    """Portable identities, digests, and counts; never an evidence verdict."""

    wire_schema: Literal["assurance-lab.benchmark.index/v1"]
    benchmark_id: PortableBenchmarkId
    benchmark_version: PortableBenchmarkVersion
    corpus_digest: Digest
    semantic_result_digest: Digest
    scenario_count: Literal[3]
    cell_count: Literal[48]
    trial_count: Literal[144]
    replicates_per_cell: Literal[3]
    corruption_count: Literal[20]
    scenarios: tuple[ScenarioIndexEntry, ...] = Field(
        min_length=SCENARIOS_PER_BENCHMARK,
        max_length=SCENARIOS_PER_BENCHMARK,
    )
    corruptions: tuple[CorruptionIndexEntry, ...] = Field(
        min_length=CORRUPTIONS_PER_BENCHMARK,
        max_length=CORRUPTIONS_PER_BENCHMARK,
    )

    @model_validator(mode="after")
    def canonical_complete_index(self) -> BenchmarkIndex:
        if tuple(entry.scenario_id for entry in self.scenarios) != tuple(
            sorted(entry.scenario_id for entry in self.scenarios)
        ):
            raise ValueError("scenario index entries must be canonically ordered")
        scenario_ids = {entry.scenario_id for entry in self.scenarios}
        spec_digests = {entry.spec_digest for entry in self.scenarios}
        source_bundle_digests = {entry.source_bundle_digest for entry in self.scenarios}
        raw_trial_set_digests = {entry.raw_trial_set_digest for entry in self.scenarios}
        semantic_result_digests = {entry.semantic_result_digest for entry in self.scenarios}
        if (
            len(scenario_ids) != 3
            or len(spec_digests) != 3
            or len(source_bundle_digests) != 3
            or len(raw_trial_set_digests) != 3
            or len(semantic_result_digests) != 3
        ):
            raise ValueError("scenario index identities and specifications must be unique")
        if tuple(entry.scenario_id for entry in self.scenarios) != BENCHMARK_SCENARIO_IDS:
            raise ValueError("scenario index must contain the frozen lifecycle scenarios")

        source_bundle_by_scenario = {
            entry.scenario_id: entry.source_bundle_digest for entry in self.scenarios
        }

        expected_corruptions = tuple(f"C{number:02d}" for number in range(1, 21))
        observed_corruptions = tuple(entry.corruption_id for entry in self.corruptions)
        if observed_corruptions != expected_corruptions:
            raise ValueError("corruption index must contain C01 through C20 in order")
        if any(
            entry.source_bundle_digest != source_bundle_by_scenario[entry.source_scenario_id]
            for entry in self.corruptions
        ):
            raise ValueError("every corruption source must match its indexed scenario bundle")
        corrupted_digests = {entry.corrupted_bundle_digest for entry in self.corruptions}
        receipt_digests = {entry.receipt_digest for entry in self.corruptions}
        if len(corrupted_digests) != 20 or len(receipt_digests) != 20:
            raise ValueError("corrupted bundle and receipt digests must be unique")
        if corrupted_digests & source_bundle_digests:
            raise ValueError("a corrupted bundle must not equal any source bundle")
        return self


def benchmark_corpus_digest(
    index: BenchmarkIndex,
    frozen_plans: tuple[FrozenPlan, FrozenPlan, FrozenPlan],
) -> str:
    """Address every indexed corpus edge plus the exact resolved frozen plans.

    ``corpus_digest`` itself is excluded to avoid a circular address.  The
    result still covers the semantic result, scenario source/raw/result
    addresses, all corruption/receipt edges, and canonical plan bytes.
    """

    body = index.model_dump(mode="json", exclude={"corpus_digest"})
    body["frozen_plan_digests"] = [
        canonical_digest(plan.model_dump(mode="json")) for plan in frozen_plans
    ]
    return canonical_digest(body)


class CombinedRawBenchmarkCorpus(BaseModel):
    """Index-bound raw inputs and resolved compiler plans for all 144 trials.

    This value is structural. Release admission still has to create it from
    bounded canonical bytes, verified source CABs, and plans recompiled from
    the exact compiled specifications.
    """

    wire_schema: Literal["assurance-lab.benchmark.combined-raw-corpus/v1"]
    index: BenchmarkIndex
    raw_trial_sets: tuple[RawTrialSet, ...] = Field(
        min_length=SCENARIOS_PER_BENCHMARK,
        max_length=SCENARIOS_PER_BENCHMARK,
    )
    frozen_plans: tuple[FrozenPlan, ...] = Field(
        min_length=SCENARIOS_PER_BENCHMARK,
        max_length=SCENARIOS_PER_BENCHMARK,
    )

    @model_validator(mode="after")
    def exact_indexed_raw_design(self) -> CombinedRawBenchmarkCorpus:
        raw_scenarios = tuple(raw.scenario_id for raw in self.raw_trial_sets)
        plan_scenarios = tuple(plan.scenario_id for plan in self.frozen_plans)
        if raw_scenarios != BENCHMARK_SCENARIO_IDS or plan_scenarios != BENCHMARK_SCENARIO_IDS:
            raise ValueError("raw sets and frozen plans must use frozen scenario order")
        typed_plans = (
            self.frozen_plans[0],
            self.frozen_plans[1],
            self.frozen_plans[2],
        )
        if self.index.corpus_digest != benchmark_corpus_digest(self.index, typed_plans):
            raise ValueError("benchmark index carries the wrong canonical corpus digest")

        index_by_scenario = {entry.scenario_id: entry for entry in self.index.scenarios}
        raw_by_scenario = {raw.scenario_id: raw for raw in self.raw_trial_sets}
        plan_by_scenario = {plan.scenario_id: plan for plan in self.frozen_plans}
        for scenario_id in BENCHMARK_SCENARIO_IDS:
            raw = raw_by_scenario[scenario_id]
            plan = plan_by_scenario[scenario_id]
            index_entry = index_by_scenario[raw.scenario_id]
            if (
                raw.spec_digest != plan.spec_digest
                or raw.spec_digest != index_entry.spec_digest
                or canonical_digest(raw.model_dump(mode="json")) != index_entry.raw_trial_set_digest
            ):
                raise ValueError("raw set, frozen plan, and index specification do not bind")
            raw_trials_by_key = {trial.trial_key: trial for trial in raw.trials}
            plan_entries_by_key = {entry.trial_key: entry for entry in plan.entries}
            if raw_trials_by_key.keys() != plan_entries_by_key.keys():
                raise ValueError("raw and frozen plan trial-key sets differ")
            for trial_key, trial in raw_trials_by_key.items():
                entry = plan_entries_by_key[trial_key]
                if (
                    trial.ordinal != entry.ordinal
                    or trial.cell_key != entry.cell_key
                    or trial.block != entry.block
                    or trial.replicate != entry.replicate
                    or trial.trial_key != entry.trial_key
                    or trial.action.artifact != entry.action
                ):
                    raise ValueError("raw trial does not match its exact frozen plan entry")

        all_trials = [trial for raw in self.raw_trial_sets for trial in raw.trials]
        for name, identities in (
            ("trial keys", [trial.trial_key for trial in all_trials]),
            ("trace ids", [trial.trace_id for trial in all_trials]),
            (
                "clone identities",
                [trial.clone_readback.unique_instance_id for trial in all_trials],
            ),
            (
                "clone readback digests",
                [trial.clone_readback.readback_digest for trial in all_trials],
            ),
            (
                "attestation bundle digests",
                [trial.clone_readback.attestation_bundle_digest for trial in all_trials],
            ),
            (
                "runtime artifact digests",
                [trial.runtime_artifact.artifact_digest for trial in all_trials],
            ),
        ):
            if len(set(identities)) != TRIALS_PER_BENCHMARK:
                raise ValueError(f"combined raw benchmark {name} must be globally unique")
        return self


class IndexedCorruptionCorpus(BaseModel):
    """Close the corruption index over the exact twenty mutation receipts.

    A receipt is useful only when the public index addresses those exact bytes
    and repeats the same source/corrupted bundle edge.  Keeping this as a
    separate binding avoids pretending that :class:`BenchmarkIndex` alone can
    prove the receipt files were present.
    """

    wire_schema: Literal["assurance-lab.benchmark.indexed-corruption-corpus/v1"]
    index: BenchmarkIndex
    receipts: tuple[CorruptionReceipt, ...] = Field(
        min_length=CORRUPTIONS_PER_BENCHMARK,
        max_length=CORRUPTIONS_PER_BENCHMARK,
    )

    @model_validator(mode="after")
    def exact_receipt_cross_binding(self) -> IndexedCorruptionCorpus:
        expected_ids = tuple(f"C{number:02d}" for number in range(1, 21))
        if tuple(receipt.corruption_id for receipt in self.receipts) != expected_ids:
            raise ValueError("corruption receipts must contain C01 through C20 in order")

        entries = {entry.corruption_id: entry for entry in self.index.corruptions}
        for receipt in self.receipts:
            entry = entries[receipt.corruption_id]
            receipt_digest = canonical_digest(receipt.model_dump(mode="json"))
            if (
                entry.receipt_digest != receipt_digest
                or entry.source_bundle_digest != receipt.source_bundle_digest
                or entry.corrupted_bundle_digest != receipt.corrupted_bundle_digest
            ):
                raise ValueError(
                    f"{receipt.corruption_id} index entry does not bind the exact receipt"
                )
        return self
