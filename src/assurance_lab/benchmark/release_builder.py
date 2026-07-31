"""Atomic builder and fail-closed verifier for the public benchmark release.

The release is one closed directory, not a collection of conveniently named
files.  Its index addresses the three exact source snapshots, all twenty
corruption snapshots and mutation receipts, and the primary semantic result.
An independently implemented Node verifier recomputes the 144-trial semantic
projection and emits a canonical, self-addressed receipt.  A self-excluding
outer manifest then addresses every published file.

The outer digest and the verifier implementation digests are content
identities.  They are not signatures, timestamps, or claims of external
custody.  The ordinary 0600/0700 filesystem objects remain mutable by their
owner; publication does not protect against a same-UID writer acting after the
final verification boundary.
"""

from __future__ import annotations

import ctypes
import errno
import os
import re
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, cast

from pydantic import (
    BaseModel as PydanticBaseModel,
)
from pydantic import (
    ConfigDict,
    Field,
    ValidationError,
    model_validator,
)

from assurance_lab.benchmark.admission import (
    BenchmarkAdmissionError,
    admit_raw_benchmark,
    canonical_model_bytes,
    parse_benchmark_bytes,
)
from assurance_lab.benchmark.cab import (
    BenchmarkCABError,
    encode_snapshot_entries,
    raw_sha256,
    verify_benchmark_cab,
)
from assurance_lab.benchmark.corruption import (
    FROZEN_CORRUPTION_SPECS,
    CorruptionVerificationReceipt,
    ExpectedVerifierResult,
    corruption_spec_digest,
    replay_frozen_corruption,
    verify_corruption_corpus,
)
from assurance_lab.benchmark.corruption_verifier import (
    FrozenProfileCorruptionVerifier,
)
from assurance_lab.benchmark.generator import (
    GeneratedPublicBenchmark,
    GeneratedScenarioSource,
    build_public_benchmark,
)
from assurance_lab.benchmark.models import (
    BENCHMARK_SCENARIO_IDS,
    AgreementDisposition,
    BaselineDisposition,
    BenchmarkIndex,
    BenchmarkSemanticResult,
    ClaimDisposition,
    CorruptionIndexEntry,
    CorruptionReceipt,
    Digest,
    ResidualDisposition,
    ScenarioIndexEntry,
    benchmark_corpus_digest,
    canonical_digest,
)
from assurance_lab.evidence.bundle import BundleManifest
from assurance_lab.evidence.canonical import (
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)
from assurance_lab.evidence.snapshot import MAX_CAB_SNAPSHOT_BYTES
from assurance_lab.source_identity import package_source_manifest

_BENCHMARK_ID: Final = "financial-control-lifecycle"
_BENCHMARK_VERSION: Final = "1.0.0"
_PRIMARY_IMPLEMENTATION_ID: Final = "control-assurance/python-primary-semantic-verifier"
_NODE_IMPLEMENTATION_ID: Final = "control-assurance/independent-lifecycle-semantic-verifier-js"
_NODE_SOURCE_SCHEMA: Final = "assurance-lab.verifier-source-set/v1"
_NODE_PACKAGE_NAME: Final = "cab-integrity-verifier"
_NODE_RECEIPT_SCHEMA: Final = "assurance-lab.benchmark.semantic-verification-receipt/v1"
_NODE_SOURCE_NAME: Final = re.compile(r"^[A-Za-z0-9._-]+\.js$")
_MAX_NODE_SOURCE_FILES: Final = 64
_MAX_NODE_SOURCE_BYTES: Final = 64 * 1024 * 1024
_RELEASE_MANIFEST_PATH: Final = "release-manifest.json"
_MAX_RELEASE_FILE_BYTES: Final = 16 * 1024 * 1024
_MAX_RELEASE_BYTES: Final = 256 * 1024 * 1024
_MAX_RELEASE_FILES: Final = 256
_MAX_RELEASE_DIRECTORIES: Final = 32
_MAX_RELEASE_DEPTH: Final = 2
_MAX_RELEASE_DIRECTORY_ENTRIES: Final = 64
if not all(hasattr(os, name) for name in ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW")):
    raise RuntimeError("public release tooling requires O_CLOEXEC, O_DIRECTORY, and O_NOFOLLOW")
_DIRECTORY_FLAGS: Final = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
_FILE_READ_FLAGS: Final = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
_FILE_WRITE_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
_RENAME_NOREPLACE: Final = 1


class PublicReleaseError(ValueError):
    """The public release could not be built or independently re-admitted."""


class _StrictModel(PydanticBaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        revalidate_instances="always",
        populate_by_name=True,
    )


class VerifierSourceFile(_StrictModel):
    path: str
    size: int = Field(ge=1, le=_MAX_RELEASE_FILE_BYTES)
    sha256: Digest

    @model_validator(mode="after")
    def portable_path(self) -> VerifierSourceFile:
        _require_portable_path(self.path)
        return self


class VerifierPackageIdentity(_StrictModel):
    name: Literal["cab-integrity-verifier"]
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")


class VerifierSourceIdentity(_StrictModel):
    wire_schema: Literal["assurance-lab.verifier-source-set/v1"] = Field(
        alias="schema",
        serialization_alias="schema",
    )
    implementation_id: Literal["control-assurance/independent-lifecycle-semantic-verifier-js"]
    package: VerifierPackageIdentity
    files: tuple[VerifierSourceFile, ...] = Field(
        min_length=2,
        max_length=_MAX_NODE_SOURCE_FILES + 1,
    )

    @model_validator(mode="after")
    def canonical_source_set(self) -> VerifierSourceIdentity:
        paths = tuple(item.path for item in self.files)
        if paths[0] != "package.json" or paths[1:] != tuple(sorted(paths[1:])):
            raise ValueError("verifier source files are not canonically ordered")
        if len(paths) != len(set(paths)):
            raise ValueError("verifier source manifest repeats a file")
        if any(not path.startswith("src/") or not path.endswith(".js") for path in paths[1:]):
            raise ValueError("verifier source manifest has a foreign source member")
        return self


class PythonSourceIdentity(_StrictModel):
    wire_schema: Literal["assurance-lab.python-source-set/v1"] = Field(
        alias="schema",
        serialization_alias="schema",
    )
    claim_boundary: Literal[
        "identifies the shipped assurance_lab source bytes; does not "
        "authenticate origin, Python, the standard library, or dependencies"
    ]
    files: tuple[VerifierSourceFile, ...] = Field(min_length=1, max_length=4096)

    @model_validator(mode="after")
    def canonical_source_set(self) -> PythonSourceIdentity:
        paths = tuple(item.path for item in self.files)
        if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
            raise ValueError("Python source files are not unique and sorted")
        if any(
            not (path.endswith(".py") or path.endswith("/py.typed") or path == "py.typed")
            for path in paths
        ):
            raise ValueError("Python source identity includes a foreign member")
        return self


class SemanticVerifierIdentity(_StrictModel):
    implementation_id: Literal["control-assurance/independent-lifecycle-semantic-verifier-js"]
    implementation_digest: Digest
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")


class SemanticVerificationIssue(_StrictModel):
    code: str = Field(min_length=1, max_length=128)
    detail: str = Field(min_length=1, max_length=2048)
    path: str | None


class SemanticVerificationReceipt(_StrictModel):
    """Exact successful receipt emitted by the independent Node verifier.

    Its implementation digest addresses the on-disk source set checked before
    and after the subprocess.  It is not an attestation of already-loaded
    modules, the Node runtime, or the operating system.
    """

    wire_schema: Literal["assurance-lab.benchmark.semantic-verification-receipt/v1"]
    verifier: SemanticVerifierIdentity
    benchmark_id: Literal["financial-control-lifecycle"]
    benchmark_version: Literal["1.0.0"]
    benchmark_index_digest: Digest
    corpus_digest: Digest
    source_snapshot_digests: tuple[Digest, Digest, Digest]
    claimed_semantic_result_digest: Digest
    recomputed_semantic_result_digest: Digest
    claimed_semantic_projection_digest: Digest
    recomputed_semantic_projection_digest: Digest
    agreement: Literal["agreed"]
    status: Literal["verified"]
    issues: tuple[SemanticVerificationIssue, ...] = Field(max_length=0)
    receipt_digest: Digest

    @model_validator(mode="after")
    def exact_success_receipt(self) -> SemanticVerificationReceipt:
        if len(set(self.source_snapshot_digests)) != 3:
            raise ValueError("semantic receipt source snapshots must be unique")
        if self.claimed_semantic_projection_digest != self.recomputed_semantic_projection_digest:
            raise ValueError("successful semantic receipt projections disagree")
        body = self.model_dump(mode="json", exclude={"receipt_digest"})
        if self.receipt_digest != canonical_digest(body):
            raise ValueError("semantic verification receipt has the wrong self address")
        return self


class PublicReleaseSummary(_StrictModel):
    wire_schema: Literal["assurance-lab.benchmark.public-release-summary/v1"]
    benchmark_id: Literal["financial-control-lifecycle"]
    benchmark_version: Literal["1.0.0"]
    scenario_count: Literal[3]
    cell_count: Literal[48]
    trial_count: Literal[144]
    corruption_count: Literal[20]
    total_cells: int = Field(ge=0, le=48)
    agreed_cells: int = Field(ge=0, le=48)
    total_trials: int = Field(ge=0, le=144)
    seeded_masked_target_failure_cells: int = Field(ge=0, le=48)
    baseline_pass_target_refuted_masking_cells: int = Field(ge=0, le=48)
    false_supported_target_cells: int = Field(ge=0, le=48)
    semantic_issue_count: int = Field(ge=0, le=100_000)
    rejected: tuple[str, ...]
    indeterminate: tuple[str, ...]
    conflicting: tuple[str, ...]

    @model_validator(mode="after")
    def exact_negative_partition(self) -> PublicReleaseSummary:
        combined = self.rejected + self.indeterminate + self.conflicting
        if tuple(sorted(combined)) != tuple(f"C{number:02d}" for number in range(1, 21)):
            raise ValueError("release summary does not partition C01 through C20")
        if (
            len(self.rejected),
            len(self.indeterminate),
            len(self.conflicting),
        ) != (15, 4, 1):
            raise ValueError("frozen negative profile must classify as 15/4/1")
        if self.total_cells != 48 or self.total_trials != 144:
            raise ValueError("semantic summary has the wrong frozen corpus size")
        if self.indeterminate != ("C07", "C08", "C09", "C11"):
            raise ValueError("frozen indeterminate set changed")
        if self.conflicting != ("C13",):
            raise ValueError("frozen conflicting set changed")
        if (
            self.baseline_pass_target_refuted_masking_cells
            > self.seeded_masked_target_failure_cells
            or self.false_supported_target_cells > self.seeded_masked_target_failure_cells
        ):
            raise ValueError("semantic masking counters are internally inconsistent")
        return self


class PublicReleaseFile(_StrictModel):
    path: str
    size: int = Field(ge=1, le=_MAX_RELEASE_FILE_BYTES)
    sha256: Digest

    @model_validator(mode="after")
    def portable_path(self) -> PublicReleaseFile:
        _require_portable_path(self.path)
        if self.path == _RELEASE_MANIFEST_PATH:
            raise ValueError("release manifest must exclude itself from its file set")
        return self


class PublicReleaseManifest(_StrictModel):
    """Self-excluding outer closure over every other published byte string."""

    wire_schema: Literal["assurance-lab.benchmark.public-release-manifest/v1"]
    benchmark_id: Literal["financial-control-lifecycle"]
    benchmark_version: Literal["1.0.0"]
    index_digest: Digest
    corpus_digest: Digest
    semantic_result_digest: Digest
    semantic_verification_receipt_digest: Digest
    semantic_verifier_source_identity_digest: Digest
    primary_semantic_source_identity_digest: Digest
    corruption_specifications_digest: Digest
    corruption_verification_receipt_set_digest: Digest
    scenario_count: Literal[3]
    cell_count: Literal[48]
    trial_count: Literal[144]
    corruption_count: Literal[20]
    total_cells: int = Field(ge=0, le=48)
    agreed_cells: int = Field(ge=0, le=48)
    total_trials: int = Field(ge=0, le=144)
    seeded_masked_target_failure_cells: int = Field(ge=0, le=48)
    baseline_pass_target_refuted_masking_cells: int = Field(ge=0, le=48)
    false_supported_target_cells: int = Field(ge=0, le=48)
    semantic_issue_count: int = Field(ge=0, le=100_000)
    rejected_count: Literal[15]
    indeterminate_count: Literal[4]
    conflicting_count: Literal[1]
    file_count: int = Field(ge=1, le=_MAX_RELEASE_FILES)
    files: tuple[PublicReleaseFile, ...] = Field(
        min_length=1,
        max_length=_MAX_RELEASE_FILES,
    )
    release_digest: Digest

    @model_validator(mode="after")
    def exact_outer_closure(self) -> PublicReleaseManifest:
        paths = tuple(item.path for item in self.files)
        if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
            raise ValueError("release file entries must be unique and sorted")
        if self.file_count != len(self.files):
            raise ValueError("release file count does not match the manifest")
        body = self.model_dump(mode="json", exclude={"release_digest"})
        if self.release_digest != canonical_digest(body):
            raise ValueError("release manifest has the wrong self address")
        return self


@dataclass(frozen=True, slots=True)
class VerifiedPublicRelease:
    """Typed result of reopening and independently admitting a release."""

    root: Path
    release_digest: str
    release_manifest_digest: str
    index_digest: str
    corpus_digest: str
    semantic_verification_receipt_digest: str
    rejected_count: int
    indeterminate_count: int
    conflicting_count: int


@dataclass(frozen=True, slots=True)
class PublishedBenchmarkRelease(VerifiedPublicRelease):
    """A verified release that was atomically published without replacement."""


@dataclass(frozen=True, slots=True)
class _NodeSourceIdentityResult:
    identity: VerifierSourceIdentity
    canonical_bytes: bytes
    digest: str


@dataclass(frozen=True, slots=True)
class _HeldVerifierSource:
    descriptor: int
    parent_descriptor: int
    name: str
    relative_path: str
    opened: os.stat_result
    payload: bytes


@dataclass(frozen=True, slots=True)
class _MemorySourceResolver:
    sources: Mapping[str, bytes]

    def resolve_source_bundle(self, *, scenario_id: str, bundle_digest: str) -> bytes:
        payload = self.sources.get(scenario_id)
        if payload is None or raw_sha256(payload) != bundle_digest:
            raise PublicReleaseError("source resolver received an unknown content address")
        return payload


@dataclass(frozen=True, slots=True)
class _MemoryCorruptionResolver:
    corruptions: Mapping[str, bytes]

    def resolve_corrupted_bundle(
        self,
        *,
        corruption_id: str,
        bundle_digest: str,
    ) -> bytes:
        payload = self.corruptions.get(corruption_id)
        if payload is None or raw_sha256(payload) != bundle_digest:
            raise PublicReleaseError("corruption resolver received an unknown content address")
        return payload


def _require_portable_path(path: str) -> None:
    if (
        type(path) is not str
        or not path
        or path.startswith("/")
        or "\\" in path
        or "\x00" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        raise ValueError("release path is not portable and relative")
    try:
        path.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError("release paths must use portable ASCII") from exc


def _canonical_model_bytes(value: PydanticBaseModel) -> bytes:
    try:
        validated = type(value).model_validate_json(
            canonical_json_bytes(value.model_dump(mode="json", by_alias=True)),
            strict=True,
        )
        return canonical_json_bytes(validated.model_dump(mode="json", by_alias=True))
    except (StrictJSONError, ValidationError, ValueError, TypeError) as exc:
        raise PublicReleaseError("release value failed strict canonicalization") from exc


def _parse_canonical_model[ModelT: PydanticBaseModel](
    payload: bytes,
    model_type: type[ModelT],
) -> ModelT:
    if type(payload) is not bytes:
        raise PublicReleaseError("release document must be immutable bytes")
    try:
        document = strict_json_loads(payload)
        duplicate_safe = canonical_json_bytes(document)
        value = model_type.model_validate_json(duplicate_safe, strict=True)
        canonical = canonical_json_bytes(value.model_dump(mode="json", by_alias=True))
    except (StrictJSONError, ValidationError, ValueError, TypeError) as exc:
        raise PublicReleaseError(f"invalid {model_type.__name__} release document") from exc
    if payload != canonical:
        raise PublicReleaseError(
            f"{model_type.__name__} release document is not exact canonical JSON"
        )
    return value


def _augmented_source(
    source: GeneratedScenarioSource,
) -> GeneratedScenarioSource:
    """Expose exact frozen producer targets without weakening the public CAB."""

    try:
        public = verify_benchmark_cab(
            source.snapshot_bytes,
            expected_snapshot_digest=source.snapshot_digest,
        )
        embedded_path = f"artifacts/producers/{source.scenario_id}/source.cab.snapshot"
        embedded_bytes = public.member(embedded_path)
        producer = verify_benchmark_cab(
            embedded_bytes,
            expected_snapshot_digest=raw_sha256(embedded_bytes),
        )
    except BenchmarkCABError as exc:
        raise PublicReleaseError(
            "generated source does not contain one verified producer snapshot"
        ) from exc

    required_targets = tuple(
        sorted(
            {
                specification.target_artifact_path
                for specification in FROZEN_CORRUPTION_SPECS
                if specification.source_scenario_id == source.scenario_id
                and specification.target_artifact_path != "bundle.json"
            }
        )
    )
    public_entries = dict(public.entries)
    producer_entries = dict(producer.entries)
    public_descriptors = {item.path: item for item in public.manifest.files}
    producer_descriptors = {item.path: item for item in producer.manifest.files}
    for target in required_targets:
        if target in public_entries or target in public_descriptors:
            raise PublicReleaseError(
                "public source unexpectedly collides with a frozen producer target"
            )
        payload = producer_entries.get(target)
        descriptor = producer_descriptors.get(target)
        if payload is None or descriptor is None:
            raise PublicReleaseError("embedded producer lacks a frozen corruption target")
        public_entries[target] = payload
        public_descriptors[target] = descriptor

    manifest_document = public.manifest.model_dump(mode="python")
    manifest_document["files"] = [public_descriptors[path] for path in sorted(public_descriptors)]
    try:
        manifest = BundleManifest.model_validate(manifest_document, strict=True)
    except ValidationError as exc:
        raise PublicReleaseError("augmented source manifest is invalid") from exc
    public_entries["bundle.json"] = canonical_json_bytes(manifest.model_dump(mode="json"))
    snapshot = encode_snapshot_entries(
        (
            ("bundle.json", public_entries["bundle.json"]),
            *tuple(
                sorted(
                    (path, payload)
                    for path, payload in public_entries.items()
                    if path != "bundle.json"
                )
            ),
        )
    )
    digest = raw_sha256(snapshot)
    verified = verify_benchmark_cab(
        snapshot,
        expected_snapshot_digest=digest,
    )
    if verified.member(embedded_path) != embedded_bytes or any(
        verified.member(target) != producer.member(target) for target in required_targets
    ):
        raise PublicReleaseError("augmented source changed a producer witness")
    return GeneratedScenarioSource(
        scenario_id=source.scenario_id,
        specification=source.specification,
        plan=source.plan,
        raw_trial_set=source.raw_trial_set,
        snapshot_bytes=snapshot,
        snapshot_digest=digest,
    )


def _augment_benchmark(
    benchmark: GeneratedPublicBenchmark,
) -> GeneratedPublicBenchmark:
    sources = cast(
        tuple[
            GeneratedScenarioSource,
            GeneratedScenarioSource,
            GeneratedScenarioSource,
        ],
        tuple(_augmented_source(source) for source in benchmark.sources),
    )
    if tuple(source.scenario_id for source in sources) != BENCHMARK_SCENARIO_IDS:
        raise PublicReleaseError("augmented sources changed canonical scenario order")
    return GeneratedPublicBenchmark(
        sources=sources,
        primary_semantic_result=benchmark.primary_semantic_result,
    )


def _scenario_file_name(scenario_id: str) -> str:
    _require_portable_path(scenario_id)
    return scenario_id


def _frozen_corruption_profile_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "wire_schema": ("assurance-lab.benchmark.frozen-corruption-profile/v1"),
            "corruptions": [item.model_dump(mode="json") for item in FROZEN_CORRUPTION_SPECS],
        }
    )


def _expected_release_payload_paths() -> frozenset[str]:
    paths = {
        "index.json",
        "semantic/primary.json",
        "semantic/primary-source-identity.json",
        "semantic/independent-verification.json",
        "semantic/verifier-source-identity.json",
        "corruptions/specifications.json",
        "summary.json",
    }
    paths.update(f"sources/{scenario_id}.cab.snapshot" for scenario_id in BENCHMARK_SCENARIO_IDS)
    paths.update(f"raw/{scenario_id}.json" for scenario_id in BENCHMARK_SCENARIO_IDS)
    for specification in FROZEN_CORRUPTION_SPECS:
        prefix = f"corruptions/{specification.corruption_id}"
        paths.update(
            {
                f"{prefix}/corrupted.cab.snapshot",
                f"{prefix}/mutation-receipt.json",
                f"{prefix}/verification-receipt.json",
            }
        )
    return frozenset(paths)


def _expected_release_directory_paths() -> frozenset[str]:
    return frozenset(
        {
            "corruptions",
            "raw",
            "semantic",
            "sources",
            *(f"corruptions/{item.corruption_id}" for item in FROZEN_CORRUPTION_SPECS),
        }
    )


def _build_release_payloads(
    benchmark: GeneratedPublicBenchmark,
) -> tuple[
    dict[str, bytes],
    BenchmarkIndex,
    tuple[bytes, ...],
    tuple[CorruptionVerificationReceipt, ...],
]:
    files: dict[str, bytes] = {}
    semantic_bytes = canonical_model_bytes(benchmark.primary_semantic_result)
    semantic_digest = raw_sha256(semantic_bytes)
    files["semantic/primary.json"] = semantic_bytes

    scenario_entries: list[ScenarioIndexEntry] = []
    raw_bytes: list[bytes] = []
    for position, source in enumerate(benchmark.sources):
        scenario_name = _scenario_file_name(source.scenario_id)
        source_path = f"sources/{scenario_name}.cab.snapshot"
        raw_path = f"raw/{scenario_name}.json"
        raw_payload = canonical_model_bytes(source.raw_trial_set)
        files[source_path] = source.snapshot_bytes
        files[raw_path] = raw_payload
        raw_bytes.append(raw_payload)
        scenario_entries.append(
            ScenarioIndexEntry(
                scenario_id=source.scenario_id,
                spec_digest=source.specification.spec_digest,
                source_bundle_digest=source.snapshot_digest,
                raw_trial_set_digest=raw_sha256(raw_payload),
                semantic_result_digest=raw_sha256(
                    canonical_model_bytes(benchmark.primary_semantic_result.scenarios[position])
                ),
                cell_count=16,
                trial_count=48,
            )
        )

    files["corruptions/specifications.json"] = _frozen_corruption_profile_bytes()

    verifier = FrozenProfileCorruptionVerifier()
    source_by_id = {
        source.scenario_id: verify_benchmark_cab(
            source.snapshot_bytes,
            expected_snapshot_digest=source.snapshot_digest,
        )
        for source in benchmark.sources
    }
    corruption_entries: list[CorruptionIndexEntry] = []
    mutation_receipt_bytes: list[bytes] = []
    verification_receipts: list[CorruptionVerificationReceipt] = []
    for specification in FROZEN_CORRUPTION_SPECS:
        verified_source = source_by_id[specification.source_scenario_id]
        replay = replay_frozen_corruption(verified_source, specification)
        verification = verifier.verify_corruption(
            source_bundle_bytes=verified_source.snapshot_bytes,
            corrupted_bundle_bytes=replay.corrupted_bundle_bytes,
            specification=specification,
        )
        verification_bytes = canonical_model_bytes(verification)
        mutation_receipt = CorruptionReceipt(
            wire_schema="assurance-lab.benchmark.corruption-receipt/v1",
            corruption_id=specification.corruption_id,
            source_bundle_digest=replay.source_bundle_digest,
            corrupted_bundle_digest=replay.corrupted_bundle_digest,
            target_artifact_path=specification.target_artifact_path,
            target_record_key=specification.target_record_key,
            target_field_path=specification.target_field_path,
            before_digest=raw_sha256(replay.before_bytes),
            after_digest=raw_sha256(replay.after_bytes),
            mutation_spec_digest=corruption_spec_digest(specification),
            verifier_receipt_digest=raw_sha256(verification_bytes),
            manifest_rebuilt=replay.manifest_rebuilt,
        )
        mutation_bytes = canonical_model_bytes(mutation_receipt)
        prefix = f"corruptions/{specification.corruption_id}"
        files[f"{prefix}/corrupted.cab.snapshot"] = replay.corrupted_bundle_bytes
        files[f"{prefix}/mutation-receipt.json"] = mutation_bytes
        files[f"{prefix}/verification-receipt.json"] = verification_bytes
        mutation_receipt_bytes.append(mutation_bytes)
        verification_receipts.append(verification)
        corruption_entries.append(
            CorruptionIndexEntry(
                corruption_id=specification.corruption_id,
                source_scenario_id=specification.source_scenario_id,
                source_bundle_digest=replay.source_bundle_digest,
                corrupted_bundle_digest=replay.corrupted_bundle_digest,
                receipt_digest=raw_sha256(mutation_bytes),
            )
        )

    index = BenchmarkIndex(
        wire_schema="assurance-lab.benchmark.index/v1",
        benchmark_id=_BENCHMARK_ID,
        benchmark_version=_BENCHMARK_VERSION,
        corpus_digest=raw_sha256(b"pending-public-benchmark-corpus"),
        semantic_result_digest=semantic_digest,
        scenario_count=3,
        cell_count=48,
        trial_count=144,
        replicates_per_cell=3,
        corruption_count=20,
        scenarios=tuple(scenario_entries),
        corruptions=tuple(corruption_entries),
    )
    plans = (
        benchmark.sources[0].plan,
        benchmark.sources[1].plan,
        benchmark.sources[2].plan,
    )
    index_document = index.model_dump(mode="python")
    index_document["corpus_digest"] = benchmark_corpus_digest(index, plans)
    try:
        index = BenchmarkIndex.model_validate(index_document, strict=True)
    except ValidationError as exc:
        raise PublicReleaseError("generated benchmark index is not valid") from exc
    index_bytes = canonical_model_bytes(index)
    files["index.json"] = index_bytes
    return (
        files,
        index,
        tuple(mutation_receipt_bytes),
        tuple(verification_receipts),
    )


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        stat.S_ISREG(left.st_mode)
        and stat.S_ISREG(right.st_mode)
        and left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_nlink == right.st_nlink == 1
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_ctime_ns == right.st_ctime_ns
    )


def _read_regular_file(path: Path, *, maximum: int) -> bytes:
    try:
        listed = os.lstat(path)
        descriptor = os.open(path, _FILE_READ_FLAGS)
    except OSError as exc:
        raise PublicReleaseError(f"cannot safely open {path.name!r}") from exc
    try:
        opened = os.fstat(descriptor)
        if not _same_file(listed, opened) or not 1 <= opened.st_size <= maximum:
            raise PublicReleaseError("release input is not a bounded single-link regular file")
        output = bytearray()
        while len(output) < opened.st_size:
            chunk = os.read(descriptor, min(1024 * 1024, opened.st_size - len(output)))
            if not chunk:
                raise PublicReleaseError("release input ended before its opened size")
            output.extend(chunk)
        closed = os.fstat(descriptor)
        if not _same_file(opened, closed):
            raise PublicReleaseError("release input changed while it was read")
        return bytes(output)
    finally:
        os.close(descriptor)


def _directory_identity(value: os.stat_result) -> tuple[int, int, int]:
    return (value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode))


def _same_directory(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(left.st_mode)
        and stat.S_ISDIR(right.st_mode)
        and left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_mode == right.st_mode
        and left.st_nlink == right.st_nlink
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_ctime_ns == right.st_ctime_ns
    )


def _read_file_at(
    directory: int,
    name: str,
    *,
    relative_path: str,
    maximum: int,
) -> _HeldVerifierSource:
    if "/" in name or name in {"", ".", ".."}:
        raise PublicReleaseError("verifier source member name is invalid")
    try:
        listed = os.stat(name, dir_fd=directory, follow_symlinks=False)
        descriptor = os.open(name, _FILE_READ_FLAGS, dir_fd=directory)
    except OSError as exc:
        raise PublicReleaseError("cannot safely open verifier source member") from exc
    try:
        opened = os.fstat(descriptor)
        if not _same_file(listed, opened) or not 1 <= opened.st_size <= maximum:
            raise PublicReleaseError("verifier source is not a bounded single-link regular file")
        payload = bytearray()
        while len(payload) < opened.st_size:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, opened.st_size - len(payload)),
            )
            if not chunk:
                raise PublicReleaseError("verifier source ended before its opened size")
            payload.extend(chunk)
        after = os.fstat(descriptor)
        if not _same_file(opened, after):
            raise PublicReleaseError("verifier source changed while it was read")
        return _HeldVerifierSource(
            descriptor=descriptor,
            parent_descriptor=directory,
            name=name,
            relative_path=relative_path,
            opened=opened,
            payload=bytes(payload),
        )
    except BaseException:
        os.close(descriptor)
        raise


def _bounded_node_source_names(directory: int) -> tuple[str, ...]:
    names: list[str] = []
    with os.scandir(directory) as iterator:
        for entry in iterator:
            if len(names) >= _MAX_NODE_SOURCE_FILES:
                raise PublicReleaseError("independent verifier source set exceeds its file bound")
            if _NODE_SOURCE_NAME.fullmatch(entry.name) is None or not entry.is_file(
                follow_symlinks=False
            ):
                raise PublicReleaseError("independent verifier source set has a foreign member")
            names.append(entry.name)
    if not names or len(names) != len(set(names)):
        raise PublicReleaseError("independent verifier source set is empty or ambiguous")
    return tuple(sorted(names))


def _derive_node_source_identity(repository_root: Path) -> _NodeSourceIdentityResult:
    package_root = repository_root / "verifier-js"
    held_sources: list[_HeldVerifierSource] = []
    package_descriptor = -1
    source_descriptor = -1
    try:
        package_listed = os.lstat(package_root)
        package_descriptor = os.open(package_root, _DIRECTORY_FLAGS)
        package_opened = os.fstat(package_descriptor)
        if stat.S_ISLNK(package_listed.st_mode) or not _same_directory(
            package_listed, package_opened
        ):
            raise PublicReleaseError("independent verifier package is not a pinned real directory")
        source_listed = os.stat(
            "src",
            dir_fd=package_descriptor,
            follow_symlinks=False,
        )
        source_descriptor = os.open(
            "src",
            _DIRECTORY_FLAGS,
            dir_fd=package_descriptor,
        )
        source_opened = os.fstat(source_descriptor)
        if not _same_directory(source_listed, source_opened):
            raise PublicReleaseError("independent verifier source is not a pinned real directory")
        names_before = _bounded_node_source_names(source_descriptor)
        package_source = _read_file_at(
            package_descriptor,
            "package.json",
            relative_path="package.json",
            maximum=_MAX_RELEASE_FILE_BYTES,
        )
        held_sources.append(package_source)
        total_source_bytes = len(package_source.payload)
        for name in names_before:
            source = _read_file_at(
                source_descriptor,
                name,
                relative_path=f"src/{name}",
                maximum=_MAX_RELEASE_FILE_BYTES,
            )
            held_sources.append(source)
            total_source_bytes += len(source.payload)
            if total_source_bytes > _MAX_NODE_SOURCE_BYTES:
                raise PublicReleaseError("independent verifier source set exceeds its byte bound")
        names_after = _bounded_node_source_names(source_descriptor)
        if (
            names_after != names_before
            or not _same_directory(
                source_opened,
                os.fstat(source_descriptor),
            )
            or not _same_directory(
                package_opened,
                os.fstat(package_descriptor),
            )
        ):
            raise PublicReleaseError(
                "independent verifier source set changed while it was addressed"
            )
        for held in held_sources:
            named_now = os.stat(
                held.name,
                dir_fd=held.parent_descriptor,
                follow_symlinks=False,
            )
            if not _same_file(held.opened, os.fstat(held.descriptor)) or not _same_file(
                held.opened, named_now
            ):
                raise PublicReleaseError(
                    "independent verifier source changed during source-set identity"
                )
        rebound_source = os.stat(
            "src",
            dir_fd=package_descriptor,
            follow_symlinks=False,
        )
        if not _same_directory(source_opened, rebound_source):
            raise PublicReleaseError("independent verifier source directory path was replaced")
        rebound_package = os.lstat(package_root)
        if not _same_directory(package_opened, rebound_package):
            raise PublicReleaseError("independent verifier package directory path was replaced")
        payloads = {held.relative_path: held.payload for held in held_sources}
        try:
            package_document = strict_json_loads(payloads["package.json"])
        except StrictJSONError as exc:
            raise PublicReleaseError("independent verifier package manifest is invalid") from exc
        if not isinstance(package_document, dict):
            raise PublicReleaseError("independent verifier package manifest is not an object")
        version = package_document.get("version")
        if package_document.get("name") != _NODE_PACKAGE_NAME or type(version) is not str:
            raise PublicReleaseError("independent verifier package identity is foreign")
        paths = ("package.json", *(f"src/{name}" for name in names_before))
        identity = VerifierSourceIdentity(
            schema=_NODE_SOURCE_SCHEMA,
            implementation_id=_NODE_IMPLEMENTATION_ID,
            package=VerifierPackageIdentity(
                name=_NODE_PACKAGE_NAME,
                version=version,
            ),
            files=tuple(
                VerifierSourceFile(
                    path=path,
                    size=len(payloads[path]),
                    sha256=raw_sha256(payloads[path]),
                )
                for path in paths
            ),
        )
        canonical = _canonical_model_bytes(identity)
        return _NodeSourceIdentityResult(
            identity=identity,
            canonical_bytes=canonical,
            digest=raw_sha256(canonical),
        )
    except OSError as exc:
        raise PublicReleaseError(
            "independent verifier source tree changed during identity derivation"
        ) from exc
    finally:
        for held in reversed(held_sources):
            os.close(held.descriptor)
        if source_descriptor >= 0:
            os.close(source_descriptor)
        if package_descriptor >= 0:
            os.close(package_descriptor)


def _invoke_independent_node(
    release_root: Path,
    *,
    repository_root: Path,
) -> tuple[SemanticVerificationReceipt, bytes, _NodeSourceIdentityResult]:
    before = _derive_node_source_identity(repository_root)
    cli_path = repository_root / "verifier-js" / "src" / "benchmark-cli.js"
    command = [
        "node",
        str(cli_path),
        "--index",
        str(release_root / "index.json"),
        "--semantic",
        str(release_root / "semantic" / "primary.json"),
    ]
    for scenario_id in BENCHMARK_SCENARIO_IDS:
        command.extend(
            [
                "--source",
                (f"{scenario_id}={release_root / 'sources' / f'{scenario_id}.cab.snapshot'}"),
            ]
        )
    try:
        completed = subprocess.run(
            command,
            cwd=repository_root,
            check=False,
            capture_output=True,
            timeout=180,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PublicReleaseError("independent Node verification did not run") from exc
    if completed.returncode != 0 or completed.stderr:
        raise PublicReleaseError("independent Node semantic verification did not succeed")
    if not completed.stdout.endswith(b"\n") or completed.stdout.count(b"\n") != 1:
        raise PublicReleaseError("independent Node verifier emitted a non-canonical frame")
    receipt_bytes = completed.stdout[:-1]
    receipt = _parse_canonical_model(
        receipt_bytes,
        SemanticVerificationReceipt,
    )
    after = _derive_node_source_identity(repository_root)
    if before != after:
        raise PublicReleaseError("independent verifier implementation changed during verification")
    index_bytes = _read_regular_file(
        release_root / "index.json",
        maximum=_MAX_RELEASE_FILE_BYTES,
    )
    semantic_bytes = _read_regular_file(
        release_root / "semantic" / "primary.json",
        maximum=_MAX_RELEASE_FILE_BYTES,
    )
    expected_sources = tuple(
        raw_sha256(
            _read_regular_file(
                release_root / "sources" / f"{scenario_id}.cab.snapshot",
                maximum=MAX_CAB_SNAPSHOT_BYTES,
            )
        )
        for scenario_id in BENCHMARK_SCENARIO_IDS
    )
    index = parse_benchmark_bytes(index_bytes, BenchmarkIndex)
    if (
        receipt.verifier.implementation_id != before.identity.implementation_id
        or receipt.verifier.implementation_digest != before.digest
        or receipt.verifier.version != before.identity.package.version
        or receipt.benchmark_index_digest != raw_sha256(index_bytes)
        or receipt.corpus_digest != index.corpus_digest
        or receipt.source_snapshot_digests != expected_sources
        or receipt.claimed_semantic_result_digest != raw_sha256(semantic_bytes)
    ):
        raise PublicReleaseError(
            "independent semantic receipt is not bound to the invoked implementation"
        )
    return receipt, receipt_bytes, before


def _write_new_file(root: Path, relative_path: str, payload: bytes) -> None:
    _require_portable_path(relative_path)
    if type(payload) is not bytes or not 1 <= len(payload) <= _MAX_RELEASE_FILE_BYTES:
        raise PublicReleaseError("release output file is empty or exceeds its bound")
    path = root.joinpath(*relative_path.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        descriptor = os.open(path, _FILE_WRITE_FLAGS, 0o600)
    except OSError as exc:
        raise PublicReleaseError(f"cannot create release file {relative_path!r}") from exc
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise PublicReleaseError("short write while creating release file")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@dataclass(frozen=True, slots=True)
class _HeldReleaseDirectory:
    descriptor: int
    parent_descriptor: int | None
    name: str | None
    relative_path: str
    opened: os.stat_result
    entries: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _HeldReleaseFile:
    descriptor: int
    parent_descriptor: int
    name: str
    relative_path: str
    opened: os.stat_result
    payload: bytes


@dataclass(frozen=True, slots=True)
class _SafeReleaseTree:
    files: dict[str, bytes]
    directories: frozenset[str]


def _bounded_directory_entries(directory: int) -> tuple[str, ...]:
    names: list[str] = []
    with os.scandir(directory) as iterator:
        for entry in iterator:
            if len(names) >= _MAX_RELEASE_DIRECTORY_ENTRIES:
                raise PublicReleaseError("release directory exceeds its entry bound")
            names.append(entry.name)
    return tuple(sorted(names))


def _safe_release_tree(root: Path) -> _SafeReleaseTree:
    """Hold and globally revalidate every opened release object."""

    directories: list[_HeldReleaseDirectory] = []
    files: list[_HeldReleaseFile] = []
    root_descriptor = -1
    try:
        listed_root = os.lstat(root)
        root_descriptor = os.open(root, _DIRECTORY_FLAGS)
        opened_root = os.fstat(root_descriptor)
        if (
            stat.S_ISLNK(listed_root.st_mode)
            or not stat.S_ISDIR(listed_root.st_mode)
            or not _same_directory(listed_root, opened_root)
        ):
            raise PublicReleaseError("release root is not a pinned real directory")
        total = 0

        def walk(
            directory: int,
            *,
            parent_descriptor: int | None,
            name: str | None,
            prefix: str,
            depth: int,
        ) -> None:
            nonlocal total
            if depth > _MAX_RELEASE_DEPTH or len(directories) >= _MAX_RELEASE_DIRECTORIES:
                raise PublicReleaseError("release tree exceeds its directory bounds")
            opened_directory = os.fstat(directory)
            entries = _bounded_directory_entries(directory)
            if any(
                type(entry) is not str or "/" in entry or entry in {"", ".", ".."}
                for entry in entries
            ):
                raise PublicReleaseError("release directory has an invalid member")
            directories.append(
                _HeldReleaseDirectory(
                    descriptor=directory,
                    parent_descriptor=parent_descriptor,
                    name=name,
                    relative_path=prefix,
                    opened=opened_directory,
                    entries=entries,
                )
            )
            for entry_name in entries:
                relative = f"{prefix}/{entry_name}" if prefix else entry_name
                _require_portable_path(relative)
                listed = os.stat(
                    entry_name,
                    dir_fd=directory,
                    follow_symlinks=False,
                )
                if stat.S_ISDIR(listed.st_mode):
                    if depth >= _MAX_RELEASE_DEPTH:
                        raise PublicReleaseError("release tree exceeds its depth bound")
                    child = os.open(
                        entry_name,
                        _DIRECTORY_FLAGS,
                        dir_fd=directory,
                    )
                    child_opened = os.fstat(child)
                    if not _same_directory(listed, child_opened):
                        os.close(child)
                        raise PublicReleaseError("release directory changed before it was opened")
                    try:
                        walk(
                            child,
                            parent_descriptor=directory,
                            name=entry_name,
                            prefix=relative,
                            depth=depth + 1,
                        )
                    except BaseException:
                        if not any(held.descriptor == child for held in directories):
                            os.close(child)
                        raise
                    continue
                if (
                    not stat.S_ISREG(listed.st_mode)
                    or listed.st_nlink != 1
                    or not 1 <= listed.st_size <= _MAX_RELEASE_FILE_BYTES
                ):
                    raise PublicReleaseError("release contains an unsafe or oversized member")
                if len(files) >= _MAX_RELEASE_FILES:
                    raise PublicReleaseError("release tree exceeds its file bound")
                descriptor = os.open(
                    entry_name,
                    _FILE_READ_FLAGS,
                    dir_fd=directory,
                )
                try:
                    opened = os.fstat(descriptor)
                    if not _same_file(listed, opened):
                        raise PublicReleaseError("release member changed before it was opened")
                    payload = bytearray()
                    while len(payload) < opened.st_size:
                        chunk = os.read(
                            descriptor,
                            min(
                                1024 * 1024,
                                opened.st_size - len(payload),
                            ),
                        )
                        if not chunk:
                            raise PublicReleaseError("release member ended before its opened size")
                        payload.extend(chunk)
                    if not _same_file(opened, os.fstat(descriptor)):
                        raise PublicReleaseError("release member changed while it was read")
                    files.append(
                        _HeldReleaseFile(
                            descriptor=descriptor,
                            parent_descriptor=directory,
                            name=entry_name,
                            relative_path=relative,
                            opened=opened,
                            payload=bytes(payload),
                        )
                    )
                except BaseException:
                    if not any(held.descriptor == descriptor for held in files):
                        os.close(descriptor)
                    raise
                total += len(payload)
                if len(files) > _MAX_RELEASE_FILES or total > _MAX_RELEASE_BYTES:
                    raise PublicReleaseError("release tree exceeds its resource bounds")

        walk(
            root_descriptor,
            parent_descriptor=None,
            name=None,
            prefix="",
            depth=0,
        )
        for file_item in files:
            opened_now = os.fstat(file_item.descriptor)
            named_now = os.stat(
                file_item.name,
                dir_fd=file_item.parent_descriptor,
                follow_symlinks=False,
            )
            if not _same_file(file_item.opened, opened_now) or not _same_file(
                file_item.opened, named_now
            ):
                raise PublicReleaseError("release member changed during whole-tree verification")
        for directory_item in reversed(directories):
            opened_now = os.fstat(directory_item.descriptor)
            entries_now = _bounded_directory_entries(directory_item.descriptor)
            if (
                not _same_directory(directory_item.opened, opened_now)
                or entries_now != directory_item.entries
            ):
                raise PublicReleaseError("release directory changed during whole-tree verification")
            if directory_item.parent_descriptor is not None and directory_item.name is not None:
                named_now = os.stat(
                    directory_item.name,
                    dir_fd=directory_item.parent_descriptor,
                    follow_symlinks=False,
                )
                if not _same_directory(directory_item.opened, named_now):
                    raise PublicReleaseError("release directory path was replaced")
        named_root = os.lstat(root)
        if not _same_directory(opened_root, os.fstat(root_descriptor)) or not _same_directory(
            opened_root, named_root
        ):
            raise PublicReleaseError("release root changed while it was read")
        return _SafeReleaseTree(
            files={file_item.relative_path: file_item.payload for file_item in files},
            directories=frozenset(item.relative_path for item in directories if item.relative_path),
        )
    except OSError as exc:
        raise PublicReleaseError("release tree changed during safe read") from exc
    finally:
        for file_item in reversed(files):
            os.close(file_item.descriptor)
        for directory_item in reversed(directories):
            os.close(directory_item.descriptor)
        if root_descriptor >= 0 and not any(
            directory_item.descriptor == root_descriptor for directory_item in directories
        ):
            os.close(root_descriptor)


def _summary_from_receipts(
    receipts: tuple[CorruptionVerificationReceipt, ...],
    semantic: BenchmarkSemanticResult,
) -> PublicReleaseSummary:
    def ids(result: ExpectedVerifierResult) -> tuple[str, ...]:
        return tuple(receipt.corruption_id for receipt in receipts if receipt.result is result)

    cells = tuple(cell for scenario in semantic.scenarios for cell in scenario.cells)
    trials = tuple(trial for cell in cells for trial in cell.trials)
    semantic_issue_count = len(semantic.issues) + sum(
        len(scenario.issues)
        + sum(
            len(cell.issues) + sum(len(trial.issues) for trial in cell.trials)
            for cell in scenario.cells
        )
        for scenario in semantic.scenarios
    )
    return PublicReleaseSummary(
        wire_schema="assurance-lab.benchmark.public-release-summary/v1",
        benchmark_id=_BENCHMARK_ID,
        benchmark_version=_BENCHMARK_VERSION,
        scenario_count=3,
        cell_count=48,
        trial_count=144,
        corruption_count=20,
        total_cells=len(cells),
        agreed_cells=sum(
            cell.agreement.disposition is AgreementDisposition.AGREED for cell in cells
        ),
        total_trials=len(trials),
        seeded_masked_target_failure_cells=sum(
            cell.semantics.residual is ResidualDisposition.MASKED_TARGET_FAILURE for cell in cells
        ),
        baseline_pass_target_refuted_masking_cells=sum(
            cell.semantics.baseline is BaselineDisposition.PASS
            and cell.semantics.target is ClaimDisposition.REFUTED
            and cell.semantics.residual is ResidualDisposition.MASKED_TARGET_FAILURE
            for cell in cells
        ),
        false_supported_target_cells=sum(
            cell.semantics.target is ClaimDisposition.SUPPORTED
            and cell.semantics.residual is ResidualDisposition.MASKED_TARGET_FAILURE
            for cell in cells
        ),
        semantic_issue_count=semantic_issue_count,
        rejected=ids(ExpectedVerifierResult.REJECTED),
        indeterminate=ids(ExpectedVerifierResult.INDETERMINATE),
        conflicting=ids(ExpectedVerifierResult.CONFLICTING),
    )


def _verify_primary_evaluator_identity(
    semantic: BenchmarkSemanticResult,
    source_identity_bytes: bytes,
) -> None:
    if semantic.evaluator_id != _PRIMARY_IMPLEMENTATION_ID:
        raise PublicReleaseError("primary semantic result has a foreign evaluator identity")
    if raw_sha256(source_identity_bytes) != semantic.evaluator_digest:
        raise PublicReleaseError(
            "primary semantic result does not bind its recorded Python source set"
        )


def _release_manifest(
    files: Mapping[str, bytes],
    *,
    index: BenchmarkIndex,
    semantic_receipt_bytes: bytes,
    source_identity_bytes: bytes,
    primary_source_identity_bytes: bytes,
    verification_receipts: tuple[CorruptionVerificationReceipt, ...],
    summary: PublicReleaseSummary,
) -> PublicReleaseManifest:
    if _RELEASE_MANIFEST_PATH in files:
        raise PublicReleaseError("outer release manifest must exclude itself")
    if set(files) != _expected_release_payload_paths():
        raise PublicReleaseError("release payload tree differs from the exact v1 profile")
    entries = tuple(
        PublicReleaseFile(
            path=path,
            size=len(payload),
            sha256=raw_sha256(payload),
        )
        for path, payload in sorted(files.items())
    )
    receipt_set_digest = canonical_digest(
        [raw_sha256(canonical_model_bytes(receipt)) for receipt in verification_receipts]
    )
    body = {
        "wire_schema": "assurance-lab.benchmark.public-release-manifest/v1",
        "benchmark_id": _BENCHMARK_ID,
        "benchmark_version": _BENCHMARK_VERSION,
        "index_digest": raw_sha256(files["index.json"]),
        "corpus_digest": index.corpus_digest,
        "semantic_result_digest": index.semantic_result_digest,
        "semantic_verification_receipt_digest": raw_sha256(semantic_receipt_bytes),
        "semantic_verifier_source_identity_digest": raw_sha256(source_identity_bytes),
        "primary_semantic_source_identity_digest": raw_sha256(primary_source_identity_bytes),
        "corruption_specifications_digest": raw_sha256(files["corruptions/specifications.json"]),
        "corruption_verification_receipt_set_digest": receipt_set_digest,
        "scenario_count": 3,
        "cell_count": 48,
        "trial_count": 144,
        "corruption_count": 20,
        "total_cells": summary.total_cells,
        "agreed_cells": summary.agreed_cells,
        "total_trials": summary.total_trials,
        "seeded_masked_target_failure_cells": summary.seeded_masked_target_failure_cells,
        "baseline_pass_target_refuted_masking_cells": (
            summary.baseline_pass_target_refuted_masking_cells
        ),
        "false_supported_target_cells": summary.false_supported_target_cells,
        "semantic_issue_count": summary.semantic_issue_count,
        "rejected_count": len(summary.rejected),
        "indeterminate_count": len(summary.indeterminate),
        "conflicting_count": len(summary.conflicting),
        "file_count": len(entries),
        "files": [entry.model_dump(mode="json") for entry in entries],
    }
    body["release_digest"] = canonical_digest(body)
    # Strict model validation intentionally requires the immutable tuple used
    # by the in-memory manifest.  Its JSON representation is the list hashed
    # above; substitute the typed entries only after the wire digest exists.
    body["files"] = entries
    try:
        return PublicReleaseManifest.model_validate(body, strict=True)
    except ValidationError as exc:
        raise PublicReleaseError("outer release manifest is invalid") from exc


def _expected_repository_root() -> Path:
    module_path = Path(__file__).resolve()
    candidates = (
        module_path.parents[3],
        module_path.parents[1] / "_release_assets",
    )
    for candidate in candidates:
        if (candidate / "verifier-js" / "package.json").is_file() and (
            candidate / "verifier-js" / "src"
        ).is_dir():
            return candidate
    raise PublicReleaseError(
        "independent Node verifier assets are absent from the checkout and installed package"
    )


def verify_public_release(
    root: Path,
    *,
    repository_root: Path | None = None,
) -> VerifiedPublicRelease:
    """Reopen, hash, structurally admit, and independently re-evaluate a release."""

    release_root = Path(root)
    repository = _expected_repository_root() if repository_root is None else Path(repository_root)
    tree = _safe_release_tree(release_root)
    files = tree.files
    if tree.directories != _expected_release_directory_paths():
        raise PublicReleaseError("release directory topology differs from the exact v1 profile")
    manifest_bytes = files.get(_RELEASE_MANIFEST_PATH)
    if manifest_bytes is None:
        raise PublicReleaseError("release is missing its outer manifest")
    manifest = _parse_canonical_model(manifest_bytes, PublicReleaseManifest)
    payload_files = {
        path: payload for path, payload in files.items() if path != _RELEASE_MANIFEST_PATH
    }
    if set(payload_files) != _expected_release_payload_paths():
        raise PublicReleaseError("release payload tree differs from the exact v1 profile")
    described = {entry.path: entry for entry in manifest.files}
    if set(payload_files) != set(described):
        raise PublicReleaseError("outer manifest does not close the exact file tree")
    for path, payload in payload_files.items():
        entry = described[path]
        if len(payload) != entry.size or raw_sha256(payload) != entry.sha256:
            raise PublicReleaseError(f"outer manifest does not bind {path!r}")
    if payload_files.get("corruptions/specifications.json") != _frozen_corruption_profile_bytes():
        raise PublicReleaseError("published corruption profile differs from C01 through C20")

    index_bytes = payload_files["index.json"]
    index = parse_benchmark_bytes(index_bytes, BenchmarkIndex)
    semantic_bytes = payload_files["semantic/primary.json"]
    semantic = parse_benchmark_bytes(semantic_bytes, BenchmarkSemanticResult)
    if (
        semantic.benchmark_id != index.benchmark_id
        or semantic.benchmark_version != index.benchmark_version
        or raw_sha256(semantic_bytes) != index.semantic_result_digest
    ):
        raise PublicReleaseError("primary semantic result differs from the index")
    primary_source_identity_bytes = payload_files["semantic/primary-source-identity.json"]
    _parse_canonical_model(
        primary_source_identity_bytes,
        PythonSourceIdentity,
    )
    _verify_primary_evaluator_identity(semantic, primary_source_identity_bytes)

    source_payloads = {
        scenario_id: payload_files[f"sources/{scenario_id}.cab.snapshot"]
        for scenario_id in BENCHMARK_SCENARIO_IDS
    }
    raw_payloads = cast(
        tuple[bytes, bytes, bytes],
        tuple(payload_files[f"raw/{scenario_id}.json"] for scenario_id in BENCHMARK_SCENARIO_IDS),
    )
    corruption_payloads = {
        specification.corruption_id: payload_files[
            f"corruptions/{specification.corruption_id}/corrupted.cab.snapshot"
        ]
        for specification in FROZEN_CORRUPTION_SPECS
    }
    mutation_receipt_bytes = tuple(
        payload_files[f"corruptions/{specification.corruption_id}/mutation-receipt.json"]
        for specification in FROZEN_CORRUPTION_SPECS
    )
    mutation_receipts = tuple(
        parse_benchmark_bytes(payload, CorruptionReceipt) for payload in mutation_receipt_bytes
    )
    verification_receipt_bytes = tuple(
        payload_files[(f"corruptions/{specification.corruption_id}/verification-receipt.json")]
        for specification in FROZEN_CORRUPTION_SPECS
    )
    verification_receipts = tuple(
        _parse_canonical_model(
            payload,
            CorruptionVerificationReceipt,
        )
        for payload in verification_receipt_bytes
    )
    source_resolver = _MemorySourceResolver(cast(Mapping[str, bytes], source_payloads))
    corruption_resolver = _MemoryCorruptionResolver(corruption_payloads)
    try:
        admitted = admit_raw_benchmark(
            index_bytes=index_bytes,
            raw_trial_set_bytes=raw_payloads,
            source_bundle_resolver=source_resolver,
        )
        corruption_corpus = verify_corruption_corpus(
            index_bytes=index_bytes,
            raw_trial_set_bytes=raw_payloads,
            receipt_bytes=mutation_receipt_bytes,
            source_bundle_resolver=source_resolver,
            corrupted_bundle_resolver=corruption_resolver,
            verifier=FrozenProfileCorruptionVerifier(),
        )
    except BenchmarkAdmissionError as exc:
        raise PublicReleaseError("release failed benchmark admission") from exc
    if admitted.index != index or corruption_corpus.index != index:
        raise PublicReleaseError("release admission returned a different index")
    fresh_verifier = FrozenProfileCorruptionVerifier()
    for (
        specification,
        mutation_receipt,
        stored_verification,
        stored_verification_bytes,
    ) in zip(
        FROZEN_CORRUPTION_SPECS,
        mutation_receipts,
        verification_receipts,
        verification_receipt_bytes,
        strict=True,
    ):
        if mutation_receipt.verifier_receipt_digest != raw_sha256(stored_verification_bytes):
            raise PublicReleaseError(
                f"{specification.corruption_id} mutation receipt does not bind "
                "the stored verifier receipt"
            )
        fresh = fresh_verifier.verify_corruption(
            source_bundle_bytes=source_payloads[specification.source_scenario_id],
            corrupted_bundle_bytes=corruption_payloads[specification.corruption_id],
            specification=specification,
        )
        if (
            fresh != stored_verification
            or canonical_model_bytes(fresh) != stored_verification_bytes
        ):
            raise PublicReleaseError(
                f"{specification.corruption_id} stored verifier receipt "
                "differs from fresh independent verification"
            )

    summary = _parse_canonical_model(
        payload_files["summary.json"],
        PublicReleaseSummary,
    )
    if summary != _summary_from_receipts(verification_receipts, semantic):
        raise PublicReleaseError("release summary differs from verifier receipts")

    source_identity_bytes = payload_files["semantic/verifier-source-identity.json"]
    source_identity = _parse_canonical_model(
        source_identity_bytes,
        VerifierSourceIdentity,
    )
    receipt_bytes = payload_files["semantic/independent-verification.json"]
    stored_receipt = _parse_canonical_model(
        receipt_bytes,
        SemanticVerificationReceipt,
    )
    recomputed_receipt, recomputed_bytes, current_identity = _invoke_independent_node(
        release_root,
        repository_root=repository,
    )
    if (
        source_identity != current_identity.identity
        or source_identity_bytes != current_identity.canonical_bytes
        or stored_receipt != recomputed_receipt
        or receipt_bytes != recomputed_bytes
    ):
        raise PublicReleaseError("stored independent semantic receipt is not reproducible")

    verification_set_digest = canonical_digest(
        [raw_sha256(canonical_model_bytes(receipt)) for receipt in verification_receipts]
    )
    if (
        manifest.index_digest != raw_sha256(index_bytes)
        or manifest.corpus_digest != index.corpus_digest
        or manifest.semantic_result_digest != index.semantic_result_digest
        or manifest.semantic_verification_receipt_digest != raw_sha256(receipt_bytes)
        or manifest.semantic_verifier_source_identity_digest != raw_sha256(source_identity_bytes)
        or manifest.primary_semantic_source_identity_digest
        != raw_sha256(primary_source_identity_bytes)
        or manifest.corruption_specifications_digest
        != raw_sha256(payload_files["corruptions/specifications.json"])
        or manifest.corruption_verification_receipt_set_digest != verification_set_digest
        or (
            manifest.total_cells,
            manifest.agreed_cells,
            manifest.total_trials,
            manifest.seeded_masked_target_failure_cells,
            manifest.baseline_pass_target_refuted_masking_cells,
            manifest.false_supported_target_cells,
            manifest.semantic_issue_count,
        )
        != (
            summary.total_cells,
            summary.agreed_cells,
            summary.total_trials,
            summary.seeded_masked_target_failure_cells,
            summary.baseline_pass_target_refuted_masking_cells,
            summary.false_supported_target_cells,
            summary.semantic_issue_count,
        )
        or (
            manifest.rejected_count,
            manifest.indeterminate_count,
            manifest.conflicting_count,
        )
        != (
            len(summary.rejected),
            len(summary.indeterminate),
            len(summary.conflicting),
        )
    ):
        raise PublicReleaseError("outer manifest bindings disagree with admitted content")
    return VerifiedPublicRelease(
        root=release_root,
        release_digest=manifest.release_digest,
        release_manifest_digest=raw_sha256(manifest_bytes),
        index_digest=raw_sha256(index_bytes),
        corpus_digest=index.corpus_digest,
        semantic_verification_receipt_digest=raw_sha256(receipt_bytes),
        rejected_count=len(summary.rejected),
        indeterminate_count=len(summary.indeterminate),
        conflicting_count=len(summary.conflicting),
    )


def _fsync_tree(root: Path) -> None:
    directories = [root, *(path for path in root.rglob("*") if path.is_dir())]
    for directory in sorted(directories, key=lambda path: len(path.parts), reverse=True):
        descriptor = os.open(directory, _DIRECTORY_FLAGS)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _pinned_real_parent(destination: Path) -> os.stat_result:
    try:
        parent = os.lstat(destination.parent)
    except OSError as exc:
        raise PublicReleaseError("release destination parent must already exist") from exc
    if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
        raise PublicReleaseError("release destination parent is not a real directory")
    if parent.st_mode & 0o022:
        raise PublicReleaseError("release destination parent must not be group/world writable")
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("public release destination already exists")
    return parent


def _rename_noreplace(
    staging: Path,
    destination: Path,
    *,
    pinned_parent: os.stat_result,
) -> None:
    if staging.parent != destination.parent:
        raise PublicReleaseError("atomic release staging is not a sibling")
    parent_descriptor = os.open(destination.parent, _DIRECTORY_FLAGS)
    try:
        opened_parent = os.fstat(parent_descriptor)
        if _directory_identity(opened_parent) != _directory_identity(pinned_parent):
            raise PublicReleaseError("release destination parent changed")
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise PublicReleaseError("atomic no-replace publication is unsupported")
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            parent_descriptor,
            os.fsencode(staging.name),
            parent_descriptor,
            os.fsencode(destination.name),
            _RENAME_NOREPLACE,
        )
        if result != 0:
            error = ctypes.get_errno()
            if error == errno.EEXIST:
                raise FileExistsError("public release destination already exists")
            raise PublicReleaseError(f"atomic no-replace publication failed with errno {error}")
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)


def _remove_pinned_tree(path: Path, pinned: os.stat_result | None) -> None:
    if pinned is None:
        return
    try:
        current = os.lstat(path)
    except OSError:
        return
    if (
        stat.S_ISDIR(current.st_mode)
        and not stat.S_ISLNK(current.st_mode)
        and _directory_identity(current) == _directory_identity(pinned)
    ):
        shutil.rmtree(path)


def _publish_verified_staging(
    staging: Path,
    destination: Path,
    *,
    pinned_parent: os.stat_result,
    pinned_staging: os.stat_result,
) -> os.stat_result:
    """Publish one verified inode and clean it on every post-rename failure."""

    try:
        _rename_noreplace(
            staging,
            destination,
            pinned_parent=pinned_parent,
        )
        published = os.lstat(destination)
        if (
            stat.S_ISLNK(published.st_mode)
            or not stat.S_ISDIR(published.st_mode)
            or _directory_identity(published) != _directory_identity(pinned_staging)
        ):
            raise PublicReleaseError("published release is not the verified staging inode")
        return published
    except BaseException:
        # ``renameat2`` can succeed before a later parent fsync or lstat fails.
        # In that case the staging name is already gone, so clean the exact
        # published inode rather than leaving a destination behind on failure.
        _remove_pinned_tree(destination, pinned_staging)
        _remove_pinned_tree(staging, pinned_staging)
        raise


def build_public_release(
    destination: Path,
    *,
    repository_root: Path | None = None,
) -> PublishedBenchmarkRelease:
    """Build, reopen, verify, and atomically publish one content-closed tree.

    ``destination`` must not exist.  The complete release is built in a sibling
    staging directory, all files and directories are flushed, and Linux
    ``renameat2(RENAME_NOREPLACE)`` performs the only publication step.
    """

    release_destination = Path(destination).absolute()
    repository = (
        _expected_repository_root() if repository_root is None else Path(repository_root).absolute()
    )
    pinned_parent = _pinned_real_parent(release_destination)
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{release_destination.name}.staging-",
            dir=release_destination.parent,
        )
    )
    work = Path(
        tempfile.mkdtemp(
            prefix=f".{release_destination.name}.work-",
            dir=release_destination.parent,
        )
    )
    # These are directories containing unpublished evidence. Owner-only access
    # is deliberate; the scanner's suggested 0644 would also remove traversal.
    os.chmod(staging, 0o700)  # nosemgrep
    os.chmod(work, 0o700)  # nosemgrep
    pinned_staging: os.stat_result | None = os.lstat(staging)
    pinned_work: os.stat_result | None = os.lstat(work)
    pinned_published: os.stat_result | None = None
    try:
        generated = build_public_benchmark(work / "generated")
        benchmark = _augment_benchmark(generated)
        files, index, _mutation_receipts, verification_receipts = _build_release_payloads(benchmark)
        primary_source_identity_bytes = canonical_json_bytes(package_source_manifest())
        _parse_canonical_model(
            primary_source_identity_bytes,
            PythonSourceIdentity,
        )
        _verify_primary_evaluator_identity(
            benchmark.primary_semantic_result,
            primary_source_identity_bytes,
        )
        files["semantic/primary-source-identity.json"] = primary_source_identity_bytes
        for path, payload in sorted(files.items()):
            _write_new_file(staging, path, payload)

        semantic_receipt, semantic_receipt_bytes, source_identity = _invoke_independent_node(
            staging,
            repository_root=repository,
        )
        del semantic_receipt
        files["semantic/independent-verification.json"] = semantic_receipt_bytes
        files["semantic/verifier-source-identity.json"] = source_identity.canonical_bytes
        _write_new_file(
            staging,
            "semantic/independent-verification.json",
            semantic_receipt_bytes,
        )
        _write_new_file(
            staging,
            "semantic/verifier-source-identity.json",
            source_identity.canonical_bytes,
        )

        summary = _summary_from_receipts(
            verification_receipts,
            benchmark.primary_semantic_result,
        )
        summary_bytes = _canonical_model_bytes(summary)
        files["summary.json"] = summary_bytes
        _write_new_file(staging, "summary.json", summary_bytes)
        manifest = _release_manifest(
            files,
            index=index,
            semantic_receipt_bytes=semantic_receipt_bytes,
            source_identity_bytes=source_identity.canonical_bytes,
            primary_source_identity_bytes=primary_source_identity_bytes,
            verification_receipts=verification_receipts,
            summary=summary,
        )
        manifest_bytes = _canonical_model_bytes(manifest)
        _write_new_file(staging, _RELEASE_MANIFEST_PATH, manifest_bytes)
        _fsync_tree(staging)

        verified = verify_public_release(
            staging,
            repository_root=repository,
        )
        if (
            verified.release_digest != manifest.release_digest
            or verified.release_manifest_digest != raw_sha256(manifest_bytes)
            or (
                verified.rejected_count,
                verified.indeterminate_count,
                verified.conflicting_count,
            )
            != (15, 4, 1)
        ):
            raise PublicReleaseError("reopened staged release differs from its built result")
        published_stat = _publish_verified_staging(
            staging,
            release_destination,
            pinned_parent=pinned_parent,
            pinned_staging=cast(os.stat_result, pinned_staging),
        )
        pinned_published = published_stat
        return PublishedBenchmarkRelease(
            root=release_destination,
            release_digest=verified.release_digest,
            release_manifest_digest=verified.release_manifest_digest,
            index_digest=verified.index_digest,
            corpus_digest=verified.corpus_digest,
            semantic_verification_receipt_digest=(verified.semantic_verification_receipt_digest),
            rejected_count=verified.rejected_count,
            indeterminate_count=verified.indeterminate_count,
            conflicting_count=verified.conflicting_count,
        )
    except BaseException:
        _remove_pinned_tree(release_destination, pinned_published)
        _remove_pinned_tree(staging, pinned_staging)
        raise
    finally:
        _remove_pinned_tree(work, pinned_work)


__all__ = [
    "PublicReleaseError",
    "PublicReleaseManifest",
    "PublicReleaseSummary",
    "PublishedBenchmarkRelease",
    "SemanticVerificationReceipt",
    "VerifiedPublicRelease",
    "VerifierSourceIdentity",
    "build_public_release",
    "verify_public_release",
]
