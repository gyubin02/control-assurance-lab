"""Bundle-backed execution of the financial support-export experiment.

Each trial contains one lower-level runtime observation: SQLite identity,
dataset rows used by the decision, persisted request and decision receipts,
and a client readback.  Stage summaries are conveniences.  The repository
reconstructs them from the lower-level observation before admitting metrics.

The bundled source-set digest identifies the exact source bytes claimed by an
integrity-only run.  It does not authenticate their author, publisher, or
origin.
"""

from __future__ import annotations

import ast
import hashlib
import re
from collections.abc import Callable, Hashable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, overload

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    PositiveInt,
    model_validator,
)

from assurance_lab.contract import (
    DIGEST_PATTERN,
    BooleanValue,
    CellSelector,
    CompiledExperiment,
    ExperimentContract,
    IntegerValue,
    Stage,
    StringValue,
    compile_experiment,
)
from assurance_lab.evaluation import (
    AdmittedCleanupEvidence,
    AdmittedMetricEvidence,
    AdmittedTrialAttestation,
    CleanupBinding,
    CleanupEvidenceFailure,
    CleanupReference,
    CleanupState,
    CleanupVerificationResult,
    EvidenceBinding,
    ExecutedStageEvent,
    FreshClone,
    MetricEvidenceFailure,
    MetricEvidenceResult,
    SkippedStageEvent,
    Trace,
    TrialAttestationBinding,
    TrialAttestationFailure,
    TrialAttestationResult,
    TrialRecord,
)
from assurance_lab.evidence.bundle import (
    BundleStatus,
    BundleVerification,
    EvaluationRef,
    EvaluatorRef,
    ExperimentRef,
    Sensitivity,
    verify_bundle,
)
from assurance_lab.evidence.canonical import (
    canonical_json_bytes,
    canonical_jsonl_bytes,
    strict_json_loads,
    strict_jsonl_loads,
)
from assurance_lab.evidence.writer import (
    BundleMetadata,
    PayloadFile,
    write_bundle,
)
from assurance_lab.scenarios.financial_data import (
    DatasetProfile,
    SyntheticDataset,
    generate_dataset,
)
from assurance_lab.scenarios.financial_support_contract import (
    ATTACK,
    ATTACK_ACTION_DIGEST,
    BENIGN,
    BENIGN_ACTION_DIGEST,
    SCENARIO_ID,
    action_descriptor,
    build_financial_support_contract,
)
from assurance_lab.scenarios.financial_support_runtime import (
    ActionRequestReceipt,
    AuthorizationReceipt,
    ClientReceipt,
    CustomerRow,
    DeliveryReceipt,
    FinancialRuntimeResult,
    FinancialSupportRuntime,
    GuardDecisionReceipt,
    PrincipalRow,
    RedeployOperationReceipt,
    ResourceIdentityReceipt,
    RuntimeEvent,
    SelectionReceipt,
    SupportCaseRow,
    runtime_database_snapshot_digest,
    runtime_dataset_snapshot,
)

Digest = Annotated[str, Field(pattern=DIGEST_PATTERN)]
Scalar = str | int | bool
type Payload = tuple[tuple[str, Scalar], ...]
TimeBasis = Literal["simulated"]

_STAGE_PATH = "records/stage-events.jsonl"
_RUNTIME_OBSERVATION_PATH = "records/runtime-observations.jsonl"
_ATTESTATION_PATH = "artifacts/trial-attestations.jsonl"
_CLEANUP_PATH = "artifacts/cleanup-observations.jsonl"
_TRIAL_PATH = "records/trial-records.jsonl"
_SPEC_PATH = "spec/experiment.json"
_SOURCE_SET_PATH = "spec/runtime-source-set.json"
_DATASET_PATH = "spec/dataset-manifest.json"
_RUNTIME_DATASET_PATH = "spec/runtime-dataset.json"
_FIXTURE_PATH = "spec/fixture-manifest.json"
_RUNNER_RESOURCE_ID: Literal["financial-support-sqlite-runner"] = (
    "financial-support-sqlite-runner"
)
_SOURCE_SET_ROOT_MODULES = (
    "assurance_lab.scenarios.financial_support_e2e",
)
_SOURCE_SET_MODULES = (
    "assurance_lab",
    "assurance_lab.contract",
    "assurance_lab.evaluation",
    "assurance_lab.evidence",
    "assurance_lab.evidence.bundle",
    "assurance_lab.evidence.canonical",
    "assurance_lab.evidence.writer",
    "assurance_lab.scenarios",
    "assurance_lab.scenarios.financial_data",
    "assurance_lab.scenarios.financial_support",
    "assurance_lab.scenarios.financial_support_contract",
    "assurance_lab.scenarios.financial_support_e2e",
    "assurance_lab.scenarios.financial_support_runtime",
)
_SYNTHETIC_CUSTOMER_ID = re.compile(r"^SYNTH-CUSTOMER-[0-9]{6}$")


def _sha256(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _digest_value(value: object) -> str:
    return _sha256(canonical_json_bytes(value))


def _source_set_descriptor() -> dict[str, object]:
    source_root = Path(__file__).resolve().parents[2]
    observed_modules = _local_python_dependency_closure(
        source_root,
        _SOURCE_SET_ROOT_MODULES,
    )
    expected_modules = frozenset(_SOURCE_SET_MODULES)
    if observed_modules != expected_modules:
        missing = sorted(observed_modules.difference(expected_modules))
        stale = sorted(expected_modules.difference(observed_modules))
        raise RuntimeError(
            "financial-support source allowlist differs from its local Python "
            f"dependency closure; missing={missing!r}; stale={stale!r}"
        )
    files: list[dict[str, object]] = []
    for module in sorted(observed_modules):
        path = _local_module_path(source_root, module)
        content = path.read_bytes()
        files.append(
            {
                "module": module,
                "path": path.relative_to(source_root).as_posix(),
                "sha256": _sha256(content),
                "size": len(content),
            }
        )
    return {
        "schema": "assurance-lab.financial-support-source-set/v1",
        "claim_boundary": (
            "integrity-only: identifies the statically imported local Python "
            "dependency closure; does not authenticate author, origin, the "
            "Python runtime, standard library, or third-party packages"
        ),
        "dependency_resolver": "python-ast-local-import-closure/v1",
        "root_modules": list(_SOURCE_SET_ROOT_MODULES),
        "files": files,
    }


def _local_python_dependency_closure(
    source_root: Path,
    root_modules: tuple[str, ...],
) -> frozenset[str]:
    discovered: set[str] = set()
    pending = list(root_modules)
    while pending:
        module = pending.pop()
        if module in discovered:
            continue
        path = _local_module_path(source_root, module)
        discovered.add(module)
        for package in _parent_package_modules(source_root, module):
            if package not in discovered:
                pending.append(package)
        for imported in _local_imports(source_root, module, path):
            if imported not in discovered:
                pending.append(imported)
    return frozenset(discovered)


def _local_module_path(source_root: Path, module: str) -> Path:
    if module != "assurance_lab" and not module.startswith("assurance_lab."):
        raise RuntimeError(f"source closure contains a non-local module: {module!r}")
    relative = Path(*module.split("."))
    module_path = source_root / relative.with_suffix(".py")
    package_path = source_root / relative / "__init__.py"
    if module_path.is_file():
        return module_path
    if package_path.is_file():
        return package_path
    raise RuntimeError(f"local Python module has no source file: {module!r}")


def _local_module_exists(source_root: Path, module: str) -> bool:
    try:
        _local_module_path(source_root, module)
    except RuntimeError:
        return False
    return True


def _parent_package_modules(
    source_root: Path,
    module: str,
) -> tuple[str, ...]:
    parts = module.split(".")
    packages: list[str] = []
    for index in range(1, len(parts)):
        candidate = ".".join(parts[:index])
        if (
            _local_module_exists(source_root, candidate)
            and _local_module_path(source_root, candidate).name == "__init__.py"
        ):
            packages.append(candidate)
    return tuple(packages)


def _local_imports(
    source_root: Path,
    module: str,
    path: Path,
) -> frozenset[str]:
    try:
        tree = ast.parse(path.read_bytes(), filename=str(path))
    except (SyntaxError, ValueError) as error:
        raise RuntimeError(f"cannot parse local source dependency {module!r}") from error
    package = module if path.name == "__init__.py" else module.rpartition(".")[0]
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            candidates = tuple(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = _resolved_import_from(package, node)
            candidates = (
                base,
                *(f"{base}.{alias.name}" for alias in node.names),
            )
        else:
            continue
        for candidate in candidates:
            if (
                candidate == "assurance_lab"
                or candidate.startswith("assurance_lab.")
            ) and _local_module_exists(source_root, candidate):
                imports.add(candidate)
    return frozenset(imports)


def _resolved_import_from(package: str, node: ast.ImportFrom) -> str:
    if node.level == 0:
        return node.module or ""
    package_parts = package.split(".")
    keep = len(package_parts) - (node.level - 1)
    if keep < 1:
        raise RuntimeError("relative import escapes the assurance_lab package")
    base_parts = package_parts[:keep]
    if node.module:
        base_parts.extend(node.module.split("."))
    return ".".join(base_parts)


FINANCIAL_SUPPORT_RUNTIME_BUILD_DIGEST = _digest_value(_source_set_descriptor())
_EVIDENCE_POLICY_DESCRIPTOR = {
    "schema": "assurance-lab.financial-support-evidence-policy/v1",
    "profile": "integrity-only",
}
FINANCIAL_SUPPORT_EVIDENCE_POLICY_DIGEST = _digest_value(
    _EVIDENCE_POLICY_DESCRIPTOR
)


class FinancialSupportBundleError(ValueError):
    """The runner or repository rejected an inconsistent evidence bundle."""


class _ArtifactModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        revalidate_instances="always",
    )


class _BundledContractArtifact(_ArtifactModel):
    contract_schema: Literal["assurance-lab.preventive-non-masking.v3"]
    contract: ExperimentContract


class _DatasetCounts(_ArtifactModel):
    accounts: int = Field(ge=0)
    customers: int = Field(ge=0)
    principals: int = Field(ge=0)
    support_cases: int = Field(ge=0)
    transactions: int = Field(ge=0)


class _DatasetManifestArtifact(_ArtifactModel):
    schema_id: Literal["assurance.synthetic-dataset/v1"] = Field(alias="schema")
    generator_version: Literal["financial-support-data/v1"]
    seed: int
    profile: Literal["smoke", "default", "benchmark"]
    counts: _DatasetCounts
    logical_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class _DatasetPrincipalArtifact(_ArtifactModel):
    principal_id: str = Field(min_length=1)
    role: str = Field(min_length=1)
    status: str = Field(min_length=1)
    entitlement_version: int = Field(ge=0)


class _DatasetCustomerArtifact(_ArtifactModel):
    customer_id: str = Field(pattern=r"^SYNTH-CUSTOMER-[0-9]{6}$")
    display_name: str = Field(min_length=1)
    email: str = Field(min_length=1)
    customer_type: str = Field(min_length=1)
    region_code: str = Field(min_length=1)
    risk_tier: str = Field(min_length=1)
    synthetic: Literal[True]


class _DatasetSupportCaseArtifact(_ArtifactModel):
    case_id: str = Field(min_length=1)
    customer_id: str = Field(pattern=r"^SYNTH-CUSTOMER-[0-9]{6}$")
    assigned_principal_id: str = Field(min_length=1)
    purpose: str = Field(min_length=1)
    status: str = Field(min_length=1)
    valid_from_offset_seconds: int = Field(ge=0)
    valid_until_offset_seconds: int = Field(ge=0)


class _RuntimeDatasetArtifact(_ArtifactModel):
    schema_id: Literal["assurance-lab.financial-support-runtime-dataset/v1"] = Field(
        alias="schema"
    )
    generator_version: Literal["financial-support-data/v1"]
    seed: int
    profile: Literal["smoke", "default", "benchmark"]
    principals: tuple[_DatasetPrincipalArtifact, ...]
    customers: tuple[_DatasetCustomerArtifact, ...]
    support_cases: tuple[_DatasetSupportCaseArtifact, ...]

    @model_validator(mode="after")
    def unique_sorted_rows(self) -> _RuntimeDatasetArtifact:
        identities = (
            tuple(item.principal_id for item in self.principals),
            tuple(item.customer_id for item in self.customers),
            tuple(item.case_id for item in self.support_cases),
        )
        for values in identities:
            if values != tuple(sorted(values)) or len(values) != len(set(values)):
                raise ValueError("runtime dataset rows must be unique and sorted")
        return self


class FinancialSupportActionArtifact(_ArtifactModel):
    schema_id: Literal["assurance-lab.support-action/v1"] = Field(alias="schema")
    principal_id: Literal["support-017"]
    role: Literal["support"]
    data_class: Literal["customer_confidential"]
    action: Literal["out-of-case-bulk-export", "assigned-case-summary"]
    requested_customer_ids: tuple[str, ...] = Field(min_length=1)
    records_per_customer: Literal[1]

    @model_validator(mode="after")
    def synthetic_unique_customers(self) -> FinancialSupportActionArtifact:
        if len(set(self.requested_customer_ids)) != len(self.requested_customer_ids):
            raise ValueError("requested synthetic customer ids must be unique")
        if any(
            _SYNTHETIC_CUSTOMER_ID.fullmatch(customer_id) is None
            for customer_id in self.requested_customer_ids
        ):
            raise ValueError("action contains a non-synthetic customer id")
        return self


class _FixtureManifestArtifact(_ArtifactModel):
    schema_id: Literal["assurance-lab.financial-support-fixture/v3"] = Field(alias="schema")
    dataset_manifest_digest: Digest
    runtime_dataset_digest: Digest
    bulk_threshold_records: Literal[10]
    attack_action: FinancialSupportActionArtifact
    benign_action: FinancialSupportActionArtifact
    attack_action_digest: Digest
    benign_action_digest: Digest

    @model_validator(mode="after")
    def fixed_actions(self) -> _FixtureManifestArtifact:
        if (
            self.attack_action.action != ATTACK.value
            or self.benign_action.action != BENIGN.value
            or len(self.attack_action.requested_customer_ids) != 10
            or len(self.benign_action.requested_customer_ids) != 1
            or _digest_value(self.attack_action.model_dump(mode="json", by_alias=True))
            != self.attack_action_digest
            or _digest_value(self.benign_action.model_dump(mode="json", by_alias=True))
            != self.benign_action_digest
            or self.attack_action_digest != ATTACK_ACTION_DIGEST
            or self.benign_action_digest != BENIGN_ACTION_DIGEST
        ):
            raise ValueError("fixture manifest actions or digests do not match the scenario")
        return self


class StageDatum(_ArtifactModel):
    name: str = Field(min_length=1)
    value: Scalar


class FinancialSupportStageArtifact(_ArtifactModel):
    """One stage summary derived from a lower-level runtime observation."""

    id: str = Field(min_length=1)
    schema_name: Literal["assurance-lab.financial-support-stage/v1"]
    spec_digest: Digest
    trial_key: Digest
    trace_id: str = Field(min_length=1)
    event_id: str = Field(min_length=1)
    action_digest: Digest
    runtime_observation_digest: Digest
    sequence: PositiveInt
    stage: Stage
    component: str = Field(min_length=1)
    event_type: str = Field(min_length=1)
    time_basis: TimeBasis
    started_at: AwareDatetime
    ended_at: AwareDatetime
    blocks_downstream: bool
    payload: tuple[StageDatum, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def coherent_observation(self) -> FinancialSupportStageArtifact:
        if self.id != self.event_id:
            raise ValueError("stage artifact id must equal its event id")
        if self.ended_at <= self.started_at:
            raise ValueError("stage artifact must have positive duration")
        names = [item.name for item in self.payload]
        if len(set(names)) != len(names):
            raise ValueError("stage artifact payload names must be unique")
        return self

    def value(self, name: str) -> Scalar:
        for datum in self.payload:
            if datum.name == name:
                return datum.value
        raise KeyError(name)

    def payload_pairs(self) -> tuple[tuple[str, Scalar], ...]:
        return tuple((item.name, item.value) for item in self.payload)


class _PrincipalRowArtifact(_ArtifactModel):
    principal_id: str = Field(min_length=1)
    role: str = Field(min_length=1)
    status: str = Field(min_length=1)
    entitlement_version: int = Field(ge=0)


class _CustomerRowArtifact(_ArtifactModel):
    customer_id: str = Field(pattern=r"^SYNTH-CUSTOMER-[0-9]{6}$")
    display_name: str = Field(min_length=1)
    email: str = Field(min_length=1)
    customer_type: str = Field(min_length=1)
    region_code: str = Field(min_length=1)
    risk_tier: str = Field(min_length=1)
    synthetic: Literal[True]


class _SupportCaseRowArtifact(_ArtifactModel):
    case_id: str = Field(min_length=1)
    customer_id: str = Field(pattern=r"^SYNTH-CUSTOMER-[0-9]{6}$")
    assigned_principal_id: str = Field(min_length=1)
    purpose: str = Field(min_length=1)
    status: str = Field(min_length=1)
    valid_from_offset_seconds: int = Field(ge=0)
    valid_until_offset_seconds: int = Field(ge=0)


class _ResourceIdentityArtifact(_ArtifactModel):
    requested_clone_nonce: str = Field(min_length=1)
    requested_runner_resource_id: str = Field(min_length=1)
    observed_clone_nonce: str = Field(min_length=1)
    observed_runner_resource_id: str = Field(min_length=1)
    observed_runtime_instance_id: str = Field(min_length=1)
    observed_generation: PositiveInt
    observed_dataset_snapshot_digest: Digest

    @model_validator(mode="after")
    def requested_identity_was_read_back(self) -> _ResourceIdentityArtifact:
        if (
            self.requested_clone_nonce != self.observed_clone_nonce
            or self.requested_runner_resource_id != self.observed_runner_resource_id
        ):
            raise ValueError("runtime resource identity differs from the runner request")
        return self


class _ActionRequestArtifact(_ArtifactModel):
    request_id: str = Field(min_length=1)
    trace_id: str = Field(min_length=1)
    action_digest: Digest
    principal_id: str = Field(min_length=1)
    requested_customer_ids: tuple[str, ...] = Field(min_length=1)


class _AuthorizationArtifact(_ArtifactModel):
    request_id: str = Field(min_length=1)
    target_mode: Literal["wildcard-misgrant", "case-scoped"]
    decision: Literal["allow", "deny"]
    allowed: bool
    assigned_customer_ids: tuple[str, ...]
    requested_customer_ids: tuple[str, ...] = Field(min_length=1)
    assigned_rows_evaluated: int = Field(ge=0)
    requested_rows_found: int = Field(ge=0)

    @model_validator(mode="after")
    def decision_matches_flag(self) -> _AuthorizationArtifact:
        if (self.decision == "allow") is not self.allowed:
            raise ValueError("authorization decision differs from allowed flag")
        return self


class _SelectionArtifact(_ArtifactModel):
    request_id: str = Field(min_length=1)
    query_id: str = Field(min_length=1)
    selected_customer_ids: tuple[str, ...]
    row_count: int = Field(ge=0)

    @model_validator(mode="after")
    def count_matches_rows(self) -> _SelectionArtifact:
        if self.row_count != len(self.selected_customer_ids):
            raise ValueError("selection row count differs from selected ids")
        return self


class _GuardArtifact(_ArtifactModel):
    request_id: str = Field(min_length=1)
    compensator_mode: Literal["monitor-only", "enforce"]
    reached: bool
    decision: Literal["not_reached", "allow", "block"]
    selected_record_count: int = Field(ge=0)
    bulk_threshold_records: Literal[10]


class _DeliveryArtifact(_ArtifactModel):
    request_id: str = Field(min_length=1)
    selected_customer_ids: tuple[str, ...]
    delivered_customer_ids: tuple[str, ...]
    payload_digest: Digest


class _ClientArtifact(_ArtifactModel):
    request_id: str = Field(min_length=1)
    received_customer_ids: tuple[str, ...]
    payload_digest: Digest


class _RedeployArtifact(_ArtifactModel):
    operation_id: str = Field(min_length=1)
    requested: bool
    performed: bool
    before_runtime_instance_id: str = Field(min_length=1)
    after_runtime_instance_id: str = Field(min_length=1)
    before_dataset_snapshot_digest: Digest
    after_dataset_snapshot_digest: Digest
    before_principal_count: int = Field(ge=0)
    after_principal_count: int = Field(ge=0)
    before_customer_count: int = Field(ge=0)
    after_customer_count: int = Field(ge=0)
    before_support_case_count: int = Field(ge=0)
    after_support_case_count: int = Field(ge=0)
    previous_handle_closed: bool


class FinancialSupportRuntimeObservationArtifact(_ArtifactModel):
    """One trial's lower-level SQLite rows and persisted operation receipts."""

    id: str = Field(min_length=1)
    schema_name: Literal[
        "assurance-lab.financial-support-runtime-observation/v1"
    ]
    spec_digest: Digest
    trial_key: Digest
    trace_id: str = Field(min_length=1)
    action_digest: Digest
    resource_identity: _ResourceIdentityArtifact
    redeploy_operation: _RedeployArtifact
    principal_rows: tuple[_PrincipalRowArtifact, ...]
    requested_customer_rows: tuple[_CustomerRowArtifact, ...]
    assigned_support_case_rows: tuple[_SupportCaseRowArtifact, ...]
    request: _ActionRequestArtifact
    authorization: _AuthorizationArtifact
    selection: _SelectionArtifact
    guard: _GuardArtifact
    delivery: _DeliveryArtifact
    client: _ClientArtifact

    @model_validator(mode="after")
    def row_identities_are_unique_and_sorted(
        self,
    ) -> FinancialSupportRuntimeObservationArtifact:
        identities = (
            tuple(item.principal_id for item in self.principal_rows),
            tuple(item.customer_id for item in self.requested_customer_rows),
            tuple(item.case_id for item in self.assigned_support_case_rows),
        )
        for values in identities:
            if values != tuple(sorted(values)) or len(values) != len(set(values)):
                raise ValueError("runtime observation rows must be unique and sorted")
        return self


class _TrialAttestationArtifact(_ArtifactModel):
    id: str = Field(min_length=1)
    schema_name: Literal["assurance-lab.financial-support-attestation/v1"]
    spec_digest: Digest
    trial_key: Digest
    cell_key: str = Field(min_length=1)
    block: str = Field(min_length=1)
    replicate: PositiveInt
    ordinal: PositiveInt
    trace_id: str = Field(min_length=1)
    action_digest: Digest
    clone_unique_instance_id: str = Field(min_length=1)
    runner_resource_id: Literal["financial-support-sqlite-runner"]
    observed_build_digest: Digest
    observed_dataset_digest: Digest
    observed_fixture_digest: Digest
    observed_selector: CellSelector
    base_snapshot_digest: Digest
    covariate_digest: Digest
    intervention_digest: Digest
    runtime_observation_digest: Digest
    time_basis: TimeBasis
    started_at: AwareDatetime
    ended_at: AwareDatetime

    @model_validator(mode="after")
    def positive_duration(self) -> _TrialAttestationArtifact:
        if self.ended_at <= self.started_at:
            raise ValueError("trial attestation artifact must have positive duration")
        return self


class _CleanupArtifact(_ArtifactModel):
    id: str = Field(min_length=1)
    schema_name: Literal["assurance-lab.financial-support-cleanup/v1"]
    spec_digest: Digest
    trial_key: Digest
    trace_id: str = Field(min_length=1)
    clone_unique_instance_id: str = Field(min_length=1)
    runner_resource_id: Literal["financial-support-sqlite-runner"]
    runtime_instance_id: str = Field(min_length=1)
    outcome_ended_at: AwareDatetime
    observed_at: AwareDatetime
    state: Literal["verified"]
    method: Literal["sqlite-memory-connection-closed"]
    runtime_observation_digest: Digest
    probe_operation: Literal["select-runtime-identity-after-close"]
    probe_error_type: Literal["sqlite3.ProgrammingError"]
    closed_handle_rejected_operation: Literal[True]
    time_basis: TimeBasis

    @model_validator(mode="after")
    def after_outcome(self) -> _CleanupArtifact:
        if self.observed_at <= self.outcome_ended_at:
            raise ValueError("cleanup artifact must be observed after the outcome")
        return self


class _StoredTrialRecord(_ArtifactModel):
    id: Digest
    schema_name: Literal["assurance-lab.trial-record/v1"]
    record: TrialRecord

    @model_validator(mode="after")
    def id_matches_record(self) -> _StoredTrialRecord:
        if self.id != self.record.trial_key:
            raise ValueError("stored trial id must equal its trial key")
        return self


def _artifact_dict(model: BaseModel) -> dict[str, object]:
    return model.model_dump(mode="json")


def _artifact_digest(model: BaseModel) -> str:
    return _sha256(canonical_json_bytes(_artifact_dict(model)))


@dataclass(frozen=True, slots=True)
class _PayloadMetadata:
    media_type: str
    role: str
    required_for: tuple[str, ...]


_PAYLOAD_METADATA = {
    _SPEC_PATH: _PayloadMetadata(
        "application/json",
        "compiler-owned financial support experiment",
        ("design", "evaluation"),
    ),
    _SOURCE_SET_PATH: _PayloadMetadata(
        "application/json",
        "claimed evaluator source-set descriptor",
        ("scope", "provenance"),
    ),
    _DATASET_PATH: _PayloadMetadata(
        "application/json",
        "deterministic generator manifest",
        ("scope", "dataset-regeneration"),
    ),
    _RUNTIME_DATASET_PATH: _PayloadMetadata(
        "application/json",
        "exact dataset rows loaded by the SQLite runtime",
        ("scope", "attestation", "runtime-reconstruction"),
    ),
    _FIXTURE_PATH: _PayloadMetadata(
        "application/json",
        "fixed financial support executable fixture",
        ("scope", "attestation"),
    ),
    _RUNTIME_OBSERVATION_PATH: _PayloadMetadata(
        "application/x-ndjson",
        "raw SQLite rows and persisted operation receipts",
        ("runtime-reconstruction", "trace-lineage", "cleanup-admission"),
    ),
    _STAGE_PATH: _PayloadMetadata(
        "application/x-ndjson",
        "stage summaries derived from raw runtime observations",
        ("trace-lineage", "metric-validation"),
    ),
    _ATTESTATION_PATH: _PayloadMetadata(
        "application/x-ndjson",
        "trial attestations bound to raw runtime observations",
        ("trial-admission",),
    ),
    _CLEANUP_PATH: _PayloadMetadata(
        "application/x-ndjson",
        "post-close SQLite operation probes",
        ("cleanup-admission",),
    ),
    _TRIAL_PATH: _PayloadMetadata(
        "application/x-ndjson",
        "metric-free financial support trial records",
        ("evaluation",),
    ),
}


def _payload_file(path: str, content: bytes) -> PayloadFile:
    metadata = _PAYLOAD_METADATA[path]
    return PayloadFile(
        path=path,
        content=content,
        media_type=metadata.media_type,
        role=metadata.role,
        sensitivity=Sensitivity.SYNTHETIC,
        required_for=metadata.required_for,
    )


def _payload(
    path: str,
    models: tuple[BaseModel, ...],
) -> PayloadFile:
    return _payload_file(
        path,
        canonical_jsonl_bytes(_artifact_dict(model) for model in models),
    )


def _evaluator_ref() -> EvaluatorRef:
    return EvaluatorRef(
        name="assurance-lab",
        version="0.0.1",
        source_revision=(
            "source-set-"
            f"{FINANCIAL_SUPPORT_RUNTIME_BUILD_DIGEST.removeprefix('sha256:')}"
        ),
        image_digest=None,
    )


def _timestamp_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise FinancialSupportBundleError("bundle timestamp must be timezone-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _fixture_manifest(
    dataset_manifest: dict[str, object],
    runtime_dataset: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "assurance-lab.financial-support-fixture/v3",
        "dataset_manifest_digest": _digest_value(dataset_manifest),
        "runtime_dataset_digest": _digest_value(runtime_dataset),
        "bulk_threshold_records": 10,
        "attack_action": action_descriptor(ATTACK),
        "benign_action": action_descriptor(BENIGN),
        "attack_action_digest": ATTACK_ACTION_DIGEST,
        "benign_action_digest": BENIGN_ACTION_DIGEST,
    }


def _principal_row(value: PrincipalRow) -> _PrincipalRowArtifact:
    return _PrincipalRowArtifact(
        principal_id=value.principal_id,
        role=value.role,
        status=value.status,
        entitlement_version=value.entitlement_version,
    )


def _customer_row(value: CustomerRow) -> _CustomerRowArtifact:
    return _CustomerRowArtifact.model_validate(
        {
            "customer_id": value.customer_id,
            "display_name": value.display_name,
            "email": value.email,
            "customer_type": value.customer_type,
            "region_code": value.region_code,
            "risk_tier": value.risk_tier,
            "synthetic": value.synthetic,
        },
        strict=True,
    )


def _support_case_row(value: SupportCaseRow) -> _SupportCaseRowArtifact:
    return _SupportCaseRowArtifact(
        case_id=value.case_id,
        customer_id=value.customer_id,
        assigned_principal_id=value.assigned_principal_id,
        purpose=value.purpose,
        status=value.status,
        valid_from_offset_seconds=value.valid_from_offset_seconds,
        valid_until_offset_seconds=value.valid_until_offset_seconds,
    )


def _resource_receipt(value: ResourceIdentityReceipt) -> _ResourceIdentityArtifact:
    return _ResourceIdentityArtifact(
        requested_clone_nonce=value.requested_clone_nonce,
        requested_runner_resource_id=value.requested_runner_resource_id,
        observed_clone_nonce=value.observed_clone_nonce,
        observed_runner_resource_id=value.observed_runner_resource_id,
        observed_runtime_instance_id=value.observed_runtime_instance_id,
        observed_generation=value.observed_generation,
        observed_dataset_snapshot_digest=value.observed_dataset_snapshot_digest,
    )


def _request_receipt(value: ActionRequestReceipt) -> _ActionRequestArtifact:
    return _ActionRequestArtifact(
        request_id=value.request_id,
        trace_id=value.trace_id,
        action_digest=value.action_digest,
        principal_id=value.principal_id,
        requested_customer_ids=value.requested_customer_ids,
    )


def _authorization_receipt(value: AuthorizationReceipt) -> _AuthorizationArtifact:
    return _AuthorizationArtifact.model_validate(
        {
            "request_id": value.request_id,
            "target_mode": value.target_mode,
            "decision": value.decision.value,
            "allowed": value.allowed,
            "assigned_customer_ids": value.assigned_customer_ids,
            "requested_customer_ids": value.requested_customer_ids,
            "assigned_rows_evaluated": value.assigned_rows_evaluated,
            "requested_rows_found": value.requested_rows_found,
        },
        strict=True,
    )


def _selection_receipt(value: SelectionReceipt) -> _SelectionArtifact:
    return _SelectionArtifact(
        request_id=value.request_id,
        query_id=value.query_id,
        selected_customer_ids=value.selected_customer_ids,
        row_count=value.row_count,
    )


def _guard_receipt(value: GuardDecisionReceipt) -> _GuardArtifact:
    return _GuardArtifact.model_validate(
        {
            "request_id": value.request_id,
            "compensator_mode": value.compensator_mode,
            "reached": value.reached,
            "decision": value.decision.value,
            "selected_record_count": value.selected_record_count,
            "bulk_threshold_records": value.bulk_threshold_records,
        },
        strict=True,
    )


def _delivery_receipt(value: DeliveryReceipt) -> _DeliveryArtifact:
    return _DeliveryArtifact(
        request_id=value.request_id,
        selected_customer_ids=value.selected_customer_ids,
        delivered_customer_ids=value.delivered_customer_ids,
        payload_digest=value.payload_digest,
    )


def _client_receipt(value: ClientReceipt) -> _ClientArtifact:
    return _ClientArtifact(
        request_id=value.request_id,
        received_customer_ids=value.received_customer_ids,
        payload_digest=value.payload_digest,
    )


def _redeploy_receipt(value: RedeployOperationReceipt) -> _RedeployArtifact:
    return _RedeployArtifact(
        operation_id=value.operation_id,
        requested=value.requested,
        performed=value.performed,
        before_runtime_instance_id=value.before_runtime_instance_id,
        after_runtime_instance_id=value.after_runtime_instance_id,
        before_dataset_snapshot_digest=value.before_dataset_snapshot_digest,
        after_dataset_snapshot_digest=value.after_dataset_snapshot_digest,
        before_principal_count=value.before_principal_count,
        after_principal_count=value.after_principal_count,
        before_customer_count=value.before_customer_count,
        after_customer_count=value.after_customer_count,
        before_support_case_count=value.before_support_case_count,
        after_support_case_count=value.after_support_case_count,
        previous_handle_closed=value.previous_handle_closed,
    )


def _runtime_observation(
    compiled: CompiledExperiment,
    trial_key: str,
    result: FinancialRuntimeResult,
) -> FinancialSupportRuntimeObservationArtifact:
    return FinancialSupportRuntimeObservationArtifact(
        id=f"{trial_key}:runtime-observation",
        schema_name="assurance-lab.financial-support-runtime-observation/v1",
        spec_digest=compiled.spec_digest,
        trial_key=trial_key,
        trace_id=result.trace_id,
        action_digest=result.action_digest,
        resource_identity=_resource_receipt(result.resource_identity),
        redeploy_operation=_redeploy_receipt(result.redeploy_operation),
        principal_rows=tuple(_principal_row(item) for item in result.principal_rows),
        requested_customer_rows=tuple(
            _customer_row(item) for item in result.requested_customer_rows
        ),
        assigned_support_case_rows=tuple(
            _support_case_row(item) for item in result.assigned_support_case_rows
        ),
        request=_request_receipt(result.request_receipt),
        authorization=_authorization_receipt(result.authorization_receipt),
        selection=_selection_receipt(result.selection_receipt),
        guard=_guard_receipt(result.guard_receipt),
        delivery=_delivery_receipt(result.delivery_receipt),
        client=_client_receipt(result.client_receipt),
    )


class FinancialSupportExperimentRunner:
    """Execute one simulated 16-cell plan and write its raw evidence.

    A truthful wall-clock lifecycle needs separate execute and assessment
    finalization phases and is intentionally not implemented by this one-shot
    runner.
    """

    def __init__(
        self,
        dataset: SyntheticDataset,
        *,
        bulk_threshold_records: int = 10,
        clock: Callable[[], datetime] | None = None,
        time_basis: TimeBasis | None = None,
    ) -> None:
        if time_basis != "simulated" or clock is None:
            raise ValueError(
                "the one-shot runner requires an explicit simulated time basis and clock; "
                "wall-clock finalization is not implemented"
            )
        if bulk_threshold_records != 10:
            raise ValueError("the financial-support fixture fixes the bulk threshold at 10")
        self._clock = clock
        self._time_basis = time_basis
        self._runtime = FinancialSupportRuntime(
            dataset,
            bulk_threshold_records=bulk_threshold_records,
        )
        self._source_set = _source_set_descriptor()
        self._dataset_manifest = dataset.manifest()
        self._runtime_dataset = runtime_dataset_snapshot(dataset)
        self.build_digest = FINANCIAL_SUPPORT_RUNTIME_BUILD_DIGEST
        self.dataset_digest = _digest_value(self._runtime_dataset)
        self._database_snapshot_digest = runtime_database_snapshot_digest(dataset)
        self._fixture_manifest = _fixture_manifest(
            self._dataset_manifest,
            self._runtime_dataset,
        )
        self.fixture_digest = _digest_value(self._fixture_manifest)

    def run(
        self,
        compiled: CompiledExperiment,
        destination: Path,
    ) -> BundleVerification:
        compiled = self._validated_compiled(compiled)
        cells = {cell.key: cell.selector for cell in compiled.cells}
        runtime_observations: list[FinancialSupportRuntimeObservationArtifact] = []
        stages: list[FinancialSupportStageArtifact] = []
        attestations: list[_TrialAttestationArtifact] = []
        cleanups: list[_CleanupArtifact] = []
        stored_trials: list[_StoredTrialRecord] = []
        scope = compiled.contract.scope
        previous_observation: datetime | None = None

        for planned in sorted(compiled.planned_trials, key=lambda item: item.ordinal):
            selector = cells[planned.cell_key]
            trial_started_at = self._next_time(previous_observation)
            trace_id = f"financial-support-trace-{planned.ordinal:04d}-{planned.key[-12:]}"
            clone_id = f"sqlite-clone-{planned.ordinal:04d}-{planned.key[-12:]}"
            result = self._runtime.execute(
                selector,
                trace_id=trace_id,
                clone_nonce=clone_id,
                runner_resource_id=_RUNNER_RESOURCE_ID,
            )
            runtime_observation = _runtime_observation(
                compiled,
                planned.key,
                result,
            )
            runtime_observation_digest = _artifact_digest(runtime_observation)
            runtime_observations.append(runtime_observation)
            runtime_observed_at = self._next_time(trial_started_at)
            expected_action = (
                ATTACK_ACTION_DIGEST
                if selector.input == compiled.contract.profile.input.attack
                else BENIGN_ACTION_DIGEST
            )
            if result.action_digest != expected_action:
                raise FinancialSupportBundleError(
                    f"runtime action digest differs for trial {planned.key}"
                )

            stage_artifacts = self._stage_artifacts(
                compiled,
                planned.key,
                result.events,
                result.action_digest,
                runtime_observation_digest,
                runtime_observed_at,
                target_blocks=result.target_blocks_downstream,
                compensator_blocks=result.compensator_blocks_downstream,
            )
            stages.extend(stage_artifacts)
            stage_by_name = {artifact.stage: artifact for artifact in stage_artifacts}
            input_event = _executed_event(stage_by_name[Stage.INPUT])
            target_event = _executed_event(stage_by_name[Stage.TARGET])
            outcome_event = _executed_event(stage_by_name[Stage.OUTCOME])
            compensator_artifact = stage_by_name.get(Stage.COMPENSATOR)
            if compensator_artifact is None:
                if not result.target_blocks_downstream:
                    raise FinancialSupportBundleError(
                        f"trial {planned.key} omitted an unblocked compensator stage"
                    )
                compensator_event: ExecutedStageEvent | SkippedStageEvent = SkippedStageEvent(
                    event_id=f"{trace_id}:compensator:skipped",
                    stage=Stage.COMPENSATOR,
                    blocked_by_event_id=target_event.event_id,
                )
            else:
                compensator_event = _executed_event(compensator_artifact)

            trace = Trace(
                trace_id=trace_id,
                action_digest=result.action_digest,
                input=input_event,
                target=target_event,
                compensator=compensator_event,
                outcome=outcome_event,
            )
            base_snapshot_digest = self.dataset_digest
            covariate_digest = _covariate_digest(
                self.fixture_digest,
                planned.block,
                planned.replicate,
            )
            intervention_digest = _intervention_digest(selector)
            attestation_ended_at = self._next_time(
                max(artifact.ended_at for artifact in stage_artifacts)
            )
            attestation = _TrialAttestationArtifact(
                id=f"attestation-{planned.ordinal:04d}",
                schema_name="assurance-lab.financial-support-attestation/v1",
                spec_digest=compiled.spec_digest,
                trial_key=planned.key,
                cell_key=planned.cell_key,
                block=planned.block,
                replicate=planned.replicate,
                ordinal=planned.ordinal,
                trace_id=trace_id,
                action_digest=result.action_digest,
                clone_unique_instance_id=clone_id,
                runner_resource_id=_RUNNER_RESOURCE_ID,
                observed_build_digest=self.build_digest,
                observed_dataset_digest=self.dataset_digest,
                observed_fixture_digest=self.fixture_digest,
                observed_selector=selector,
                base_snapshot_digest=base_snapshot_digest,
                covariate_digest=covariate_digest,
                intervention_digest=intervention_digest,
                runtime_observation_digest=runtime_observation_digest,
                time_basis=self._time_basis,
                started_at=trial_started_at,
                ended_at=attestation_ended_at,
            )
            attestation_digest = _artifact_digest(attestation)
            clone = FreshClone(
                unique_instance_id=clone_id,
                base_snapshot_digest=base_snapshot_digest,
                covariate_digest=covariate_digest,
                attestation_bundle_digest=attestation_digest,
                runner_resource_id=_RUNNER_RESOURCE_ID,
            )
            cleanup_observed_at = self._next_time(attestation_ended_at)
            cleanup_probe = result.cleanup_probe
            if (
                cleanup_probe.clone_nonce != clone_id
                or cleanup_probe.runner_resource_id != _RUNNER_RESOURCE_ID
                or cleanup_probe.runtime_instance_id
                != result.resource_identity.observed_runtime_instance_id
            ):
                raise FinancialSupportBundleError(
                    f"runtime cleanup receipt differs for trial {planned.key}"
                )
            cleanup = _CleanupArtifact(
                id=f"cleanup-{planned.ordinal:04d}",
                schema_name="assurance-lab.financial-support-cleanup/v1",
                spec_digest=compiled.spec_digest,
                trial_key=planned.key,
                trace_id=trace_id,
                clone_unique_instance_id=clone_id,
                runner_resource_id=_RUNNER_RESOURCE_ID,
                runtime_instance_id=cleanup_probe.runtime_instance_id,
                outcome_ended_at=outcome_event.ended_at,
                observed_at=cleanup_observed_at,
                state="verified",
                method="sqlite-memory-connection-closed",
                runtime_observation_digest=runtime_observation_digest,
                probe_operation=cleanup_probe.probe_operation,
                probe_error_type=cleanup_probe.error_type,
                closed_handle_rejected_operation=(
                    cleanup_probe.closed_handle_rejected_operation
                ),
                time_basis=self._time_basis,
            )
            cleanup_digest = _artifact_digest(cleanup)
            record = TrialRecord(
                spec_digest=compiled.spec_digest,
                trial_key=planned.key,
                cell_key=planned.cell_key,
                block=planned.block,
                replicate=planned.replicate,
                clone=clone,
                trace=trace,
                cleanup=CleanupReference(
                    evidence_bundle_digest=cleanup_digest,
                ),
            )
            attestations.append(attestation)
            cleanups.append(cleanup)
            stored_trials.append(
                _StoredTrialRecord(
                    id=planned.key,
                    schema_name="assurance-lab.trial-record/v1",
                    record=record,
                )
            )
            previous_observation = cleanup_observed_at

        latest_cleanup = max(item.observed_at for item in cleanups)
        if latest_cleanup > scope.evidence_window.end or latest_cleanup > scope.assessment_as_of:
            raise FinancialSupportBundleError(
                "the evidence window cannot contain the 16 compiler-planned executions"
            )

        payloads = (
            _payload_file(_SPEC_PATH, compiled.canonical_spec.encode("utf-8")),
            _payload_file(
                _SOURCE_SET_PATH,
                canonical_json_bytes(self._source_set),
            ),
            _payload_file(
                _DATASET_PATH,
                canonical_json_bytes(self._dataset_manifest),
            ),
            _payload_file(
                _RUNTIME_DATASET_PATH,
                canonical_json_bytes(self._runtime_dataset),
            ),
            _payload_file(
                _FIXTURE_PATH,
                canonical_json_bytes(self._fixture_manifest),
            ),
            _payload(
                _RUNTIME_OBSERVATION_PATH,
                tuple(runtime_observations),
            ),
            _payload(
                _STAGE_PATH,
                tuple(stages),
            ),
            _payload(
                _ATTESTATION_PATH,
                tuple(attestations),
            ),
            _payload(
                _CLEANUP_PATH,
                tuple(cleanups),
            ),
            _payload(
                _TRIAL_PATH,
                tuple(stored_trials),
            ),
        )
        return write_bundle(
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
                    evaluator=_evaluator_ref(),
                ),
            ),
            payloads=payloads,
        )

    def _validated_compiled(
        self,
        compiled: CompiledExperiment,
    ) -> CompiledExperiment:
        try:
            clean = CompiledExperiment.model_validate(
                compiled.model_dump(mode="python", round_trip=True),
                strict=True,
            )
            regenerated = compile_experiment(clean.contract)
        except (AttributeError, TypeError, ValueError) as error:
            raise FinancialSupportBundleError(f"compiled experiment is invalid: {error}") from error
        if clean != regenerated:
            raise FinancialSupportBundleError(
                "compiled experiment differs from a fresh compiler result"
            )
        if clean.contract.id != SCENARIO_ID or len(clean.cells) != 16:
            raise FinancialSupportBundleError(
                "financial-support runner requires complete coverage of the fixed 16 cells"
            )
        scope = clean.contract.scope
        expected_compiled = compile_experiment(
            build_financial_support_contract(
                scope=scope,
                plan=clean.contract.plan,
            )
        )
        if clean.canonical_spec != expected_compiled.canonical_spec:
            raise FinancialSupportBundleError(
                "financial-support contract differs from the fixed scenario contract"
            )
        observed = (
            self.build_digest,
            self.dataset_digest,
            self.fixture_digest,
        )
        declared = (
            scope.build_digest,
            scope.dataset_digest,
            scope.fixture_digest,
        )
        if observed != declared:
            raise FinancialSupportBundleError(
                "contract scope does not match the runner build, dataset, or fixture"
            )
        if (
            scope.evidence_policy.id != "financial-support-bundle-v1"
            or scope.evidence_policy.version != "1.0.0"
            or scope.evidence_policy.digest
            != FINANCIAL_SUPPORT_EVIDENCE_POLICY_DIGEST
        ):
            raise FinancialSupportBundleError(
                "contract evidence policy differs from the fixed financial-support policy"
            )
        if (
            clean.contract.profile.input.attack_action_digest != ATTACK_ACTION_DIGEST
            or clean.contract.profile.input.benign_action_digest != BENIGN_ACTION_DIGEST
        ):
            raise FinancialSupportBundleError(
                "contract input actions do not match the executable runtime"
            )
        return clean

    def _next_time(
        self,
        after: datetime | None,
    ) -> datetime:
        for _ in range(10_000):
            observed = self._clock()
            if observed.tzinfo is None or observed.utcoffset() is None:
                raise FinancialSupportBundleError(
                    "runner clock must return timezone-aware datetimes"
                )
            observed = observed.astimezone(UTC)
            if after is None or observed > after:
                return observed
        raise FinancialSupportBundleError(
            "runner clock did not advance to a strictly later observation"
        )

    def _stage_artifacts(
        self,
        compiled: CompiledExperiment,
        trial_key: str,
        events: tuple[RuntimeEvent, ...],
        action_digest: str,
        runtime_observation_digest: str,
        after: datetime,
        *,
        target_blocks: bool,
        compensator_blocks: bool,
    ) -> tuple[FinancialSupportStageArtifact, ...]:
        result: list[FinancialSupportStageArtifact] = []
        previous = after
        for event in events:
            stage = Stage(event.stage)
            event_id = f"{event.trace_id}:{stage.value}"
            blocks = (
                target_blocks
                if stage == Stage.TARGET
                else compensator_blocks
                if stage == Stage.COMPENSATOR
                else False
            )
            start = self._next_time(previous)
            end = self._next_time(start)
            result.append(
                FinancialSupportStageArtifact(
                    id=event_id,
                    schema_name="assurance-lab.financial-support-stage/v1",
                    spec_digest=compiled.spec_digest,
                    trial_key=trial_key,
                    trace_id=event.trace_id,
                    event_id=event_id,
                    action_digest=action_digest,
                    runtime_observation_digest=runtime_observation_digest,
                    sequence=event.sequence,
                    stage=stage,
                    component=event.component,
                    event_type=event.event_type,
                    time_basis=self._time_basis,
                    started_at=start,
                    ended_at=end,
                    blocks_downstream=blocks,
                    payload=tuple(
                        StageDatum(name=name, value=value) for name, value in event.payload
                    ),
                )
            )
            previous = end
        return tuple(result)


def _executed_event(
    artifact: FinancialSupportStageArtifact,
) -> ExecutedStageEvent:
    return ExecutedStageEvent(
        event_id=artifact.event_id,
        evidence_bundle_digest=_artifact_digest(artifact),
        stage=artifact.stage,
        started_at=artifact.started_at,
        ended_at=artifact.ended_at,
        blocks_downstream=artifact.blocks_downstream,
    )


class FinancialSupportBundleRepository:
    """Independently verify, rehash, and extract evaluator admissions."""

    def __init__(self, root: Path) -> None:
        self._root = root
        verification = verify_bundle(root)
        if (
            verification.status != BundleStatus.INTEGRITY_VERIFIED
            or verification.manifest is None
            or verification.bundle_id is None
        ):
            detail = "; ".join(f"{issue.code}: {issue.detail}" for issue in verification.issues)
            raise FinancialSupportBundleError(f"bundle integrity verification failed: {detail}")
        self.bundle_id = verification.bundle_id
        self._manifest = verification.manifest
        self.bundle_profile = self._manifest.profile

        spec = self._read_rehashed(_SPEC_PATH)
        try:
            bundled_spec = _BundledContractArtifact.model_validate_json(
                spec,
                strict=True,
            )
            compiled = compile_experiment(bundled_spec.contract)
        except ValueError as error:
            raise FinancialSupportBundleError(
                f"bundled experiment contract failed strict compilation: {error}"
            ) from error
        if compiled.canonical_spec.encode("utf-8") != spec:
            raise FinancialSupportBundleError(
                "bundled experiment bytes differ from the compiler canonical form"
            )
        if compiled.spec_digest != _sha256(spec):
            raise FinancialSupportBundleError(
                "compiler spec digest differs from the canonical bundled bytes"
            )
        expected_compiled = compile_experiment(
            build_financial_support_contract(
                scope=compiled.contract.scope,
                plan=compiled.contract.plan,
            )
        )
        if compiled.canonical_spec != expected_compiled.canonical_spec:
            raise FinancialSupportBundleError(
                "bundled contract differs from the fixed financial-support scenario"
            )
        if (
            self._manifest.experiment.id != compiled.contract.id
            or self._manifest.experiment.spec_version != compiled.contract.version
            or self._manifest.experiment.spec_digest != compiled.spec_digest
        ):
            raise FinancialSupportBundleError(
                "bundle manifest experiment reference does not match the bundled contract"
            )
        scope = compiled.contract.scope
        if (
            self._manifest.evaluation.policy_id != scope.evidence_policy.id
            or self._manifest.evaluation.policy_digest != scope.evidence_policy.digest
        ):
            raise FinancialSupportBundleError(
                "bundle manifest evidence policy does not match the bundled contract"
            )
        if compiled.contract.id != SCENARIO_ID:
            raise FinancialSupportBundleError("bundle contains the wrong scenario")
        self.compiled_experiment = compiled
        self._validate_manifest_metadata(compiled)

        source_bytes = self._read_rehashed(_SOURCE_SET_PATH)
        dataset_bytes = self._read_rehashed(_DATASET_PATH)
        runtime_dataset_bytes = self._read_rehashed(_RUNTIME_DATASET_PATH)
        fixture_bytes = self._read_rehashed(_FIXTURE_PATH)
        try:
            source_set = strict_json_loads(source_bytes)
            dataset_manifest = _DatasetManifestArtifact.model_validate_json(
                dataset_bytes,
                strict=True,
            )
            runtime_dataset = _RuntimeDatasetArtifact.model_validate_json(
                runtime_dataset_bytes,
                strict=True,
            )
            fixture_manifest = _FixtureManifestArtifact.model_validate_json(
                fixture_bytes,
                strict=True,
            )
        except (TypeError, ValueError) as error:
            raise FinancialSupportBundleError(
                f"bundle provenance manifest failed strict validation: {error}"
            ) from error
        current_source_set = _source_set_descriptor()
        if (
            not isinstance(source_set, dict)
            or source_set != current_source_set
            or canonical_json_bytes(source_set) != source_bytes
            or _sha256(source_bytes) != scope.build_digest
        ):
            raise FinancialSupportBundleError(
                "bundled source set differs from the current canonical source bytes"
            )
        if (
            canonical_json_bytes(dataset_manifest.model_dump(mode="json", by_alias=True))
            != dataset_bytes
            or canonical_json_bytes(
                runtime_dataset.model_dump(mode="json", by_alias=True)
            )
            != runtime_dataset_bytes
            or canonical_json_bytes(fixture_manifest.model_dump(mode="json", by_alias=True))
            != fixture_bytes
        ):
            raise FinancialSupportBundleError(
                "bundle provenance manifest differs from its strict canonical model"
            )
        try:
            regenerated_dataset = generate_dataset(
                seed=dataset_manifest.seed,
                profile=DatasetProfile(dataset_manifest.profile),
            )
        except ValueError as error:
            raise FinancialSupportBundleError(
                f"dataset manifest cannot regenerate the declared dataset: {error}"
            ) from error
        regenerated_manifest = regenerated_dataset.manifest()
        regenerated_runtime_dataset = runtime_dataset_snapshot(regenerated_dataset)
        if (
            regenerated_manifest
            != dataset_manifest.model_dump(mode="json", by_alias=True)
            or regenerated_runtime_dataset
            != runtime_dataset.model_dump(mode="json", by_alias=True)
        ):
            raise FinancialSupportBundleError(
                "dataset manifest or runtime rows differ from deterministic regeneration"
            )
        if (
            fixture_manifest.dataset_manifest_digest != _sha256(dataset_bytes)
            or fixture_manifest.runtime_dataset_digest
            != _sha256(runtime_dataset_bytes)
        ):
            raise FinancialSupportBundleError(
                "fixture manifest is not bound to the regenerated dataset artifacts"
            )
        input_profile = compiled.contract.profile.input
        if (
            fixture_manifest.attack_action_digest != input_profile.attack_action_digest
            or fixture_manifest.benign_action_digest != input_profile.benign_action_digest
        ):
            raise FinancialSupportBundleError(
                "fixture actions do not match the compiler-owned input digests"
            )
        self.attack_action = fixture_manifest.attack_action
        self.benign_action = fixture_manifest.benign_action
        self.dataset_digest = _sha256(runtime_dataset_bytes)
        self._database_snapshot_digest = runtime_database_snapshot_digest(
            regenerated_dataset
        )
        self._runtime_dataset = runtime_dataset
        self.fixture_digest = _sha256(fixture_bytes)
        if (
            self.dataset_digest != scope.dataset_digest
            or self.fixture_digest != scope.fixture_digest
        ):
            raise FinancialSupportBundleError(
                "dataset or fixture manifest digest does not match the bundled contract scope"
            )
        if (
            scope.build_digest != FINANCIAL_SUPPORT_RUNTIME_BUILD_DIGEST
            or scope.evidence_policy.id != "financial-support-bundle-v1"
            or scope.evidence_policy.version != "1.0.0"
            or scope.evidence_policy.digest
            != FINANCIAL_SUPPORT_EVIDENCE_POLICY_DIGEST
        ):
            raise FinancialSupportBundleError(
                "bundled contract provenance or evidence policy is not the fixed runtime"
            )
        if _sha256(spec) != self._manifest.experiment.spec_digest:
            raise FinancialSupportBundleError(
                "canonical experiment bytes do not match the manifest spec digest"
            )
        runtime_entries = _parse_jsonl_models(
            self._read_rehashed(_RUNTIME_OBSERVATION_PATH),
            FinancialSupportRuntimeObservationArtifact,
        )
        stage_entries = _parse_jsonl_models(
            self._read_rehashed(_STAGE_PATH),
            FinancialSupportStageArtifact,
        )
        attestation_entries = _parse_jsonl_models(
            self._read_rehashed(_ATTESTATION_PATH),
            _TrialAttestationArtifact,
        )
        cleanup_entries = _parse_jsonl_models(
            self._read_rehashed(_CLEANUP_PATH),
            _CleanupArtifact,
        )
        stored_entries = _parse_jsonl_models(
            self._read_rehashed(_TRIAL_PATH),
            _StoredTrialRecord,
        )

        self._runtime_observations = _unique_entries(
            runtime_entries,
            key=lambda entry: entry[0].trial_key,
            label="runtime observation",
        )
        self._stages_by_digest = _unique_entries(
            stage_entries,
            key=lambda entry: entry[1],
            label="stage artifact digest",
        )
        self._stages_by_coordinate = _unique_entries(
            stage_entries,
            key=lambda entry: (entry[0].trial_key, entry[0].stage),
            label="trial stage coordinate",
        )
        self._attestations = _unique_entries(
            attestation_entries,
            key=lambda entry: entry[0].trial_key,
            label="trial attestation",
        )
        self._cleanups_by_digest = _unique_entries(
            cleanup_entries,
            key=lambda entry: entry[1],
            label="cleanup artifact digest",
        )
        stored_by_key = _unique_entries(
            stored_entries,
            key=lambda entry: entry[0].record.trial_key,
            label="stored trial record",
        )
        time_bases = {
            *(entry[0].time_basis for entry in stage_entries),
            *(entry[0].time_basis for entry in attestation_entries),
            *(entry[0].time_basis for entry in cleanup_entries),
        }
        if len(time_bases) != 1:
            raise FinancialSupportBundleError(
                "stage, attestation, and cleanup artifacts must use one time basis"
            )
        self.time_basis = next(iter(time_bases))
        if self.time_basis != "simulated":
            raise FinancialSupportBundleError(
                "this one-shot repository admits only explicitly simulated runs"
            )
        self.trial_records = tuple(
            entry[0].record
            for entry in sorted(
                stored_by_key.values(),
                key=lambda entry: self._attestation_ordinal(entry[0].record.trial_key),
            )
        )
        self._validate_cross_references()

        final_verification = verify_bundle(root)
        if (
            final_verification.status != BundleStatus.INTEGRITY_VERIFIED
            or final_verification.bundle_id != self.bundle_id
        ):
            raise FinancialSupportBundleError(
                "bundle changed while the repository loaded and rehashed it"
            )

    def stage_artifact(
        self,
        trial_key: str,
        stage: Stage,
    ) -> FinancialSupportStageArtifact:
        try:
            return self._stages_by_coordinate[(trial_key, stage)][0]
        except KeyError as error:
            raise KeyError(f"no executed {stage.value} artifact for {trial_key}") from error

    @overload
    def verify(self, request: TrialRecord, /) -> TrialAttestationResult: ...

    @overload
    def verify(self, request: EvidenceBinding, /) -> MetricEvidenceResult: ...

    @overload
    def verify(self, request: CleanupBinding, /) -> CleanupVerificationResult: ...

    def verify(
        self,
        request: TrialRecord | EvidenceBinding | CleanupBinding,
        /,
    ) -> TrialAttestationResult | MetricEvidenceResult | CleanupVerificationResult:
        if isinstance(request, TrialRecord):
            return self._verify_attestation(request)
        if isinstance(request, EvidenceBinding):
            return self._verify_metric(request)
        if isinstance(request, CleanupBinding):
            return self._verify_cleanup(request)
        raise TypeError(f"unsupported verification request: {type(request).__name__}")

    def _read_rehashed(self, path: str) -> bytes:
        descriptor = next(
            (item for item in self._manifest.files if item.path == path),
            None,
        )
        if descriptor is None:
            raise FinancialSupportBundleError(f"bundle is missing required payload {path}")
        content = self._root.joinpath(*path.split("/")).read_bytes()
        if len(content) != descriptor.size:
            raise FinancialSupportBundleError(f"payload size changed for {path}")
        if hashlib.sha256(content).hexdigest() != descriptor.sha256:
            raise FinancialSupportBundleError(f"payload digest changed for {path}")
        return content

    def _validate_manifest_metadata(
        self,
        compiled: CompiledExperiment,
    ) -> None:
        scope = compiled.contract.scope
        expected_timestamp = _timestamp_text(scope.assessment_as_of)
        if (
            self._manifest.created_at != expected_timestamp
            or self._manifest.as_of != expected_timestamp
            or self._manifest.parent_bundles
            or self._manifest.evaluation.evaluator != _evaluator_ref()
        ):
            raise FinancialSupportBundleError(
                "manifest provenance differs from the fixed financial-support run"
            )
        descriptors = {item.path: item for item in self._manifest.files}
        if (
            len(descriptors) != len(self._manifest.files)
            or set(descriptors) != set(_PAYLOAD_METADATA)
        ):
            raise FinancialSupportBundleError(
                "manifest payload set differs from the fixed financial-support bundle"
            )
        for path, expected in _PAYLOAD_METADATA.items():
            descriptor = descriptors[path]
            if (
                descriptor.media_type != expected.media_type
                or descriptor.role != expected.role
                or descriptor.sensitivity != Sensitivity.SYNTHETIC
                or tuple(descriptor.required_for) != expected.required_for
            ):
                raise FinancialSupportBundleError(
                    f"manifest descriptor metadata differs for {path}"
                )

    def _attestation_ordinal(self, trial_key: str) -> int:
        try:
            return self._attestations[trial_key][0].ordinal
        except KeyError as error:
            raise FinancialSupportBundleError(
                f"trial {trial_key} has no raw attestation"
            ) from error

    def _validate_cross_references(self) -> None:
        compiled = self.compiled_experiment
        planned_by_key = {trial.key: trial for trial in compiled.planned_trials}
        cells_by_key = {cell.key: cell.selector for cell in compiled.cells}
        if (
            len(compiled.cells) != 16
            or {record.trial_key for record in self.trial_records}
            != set(planned_by_key)
            or set(self._runtime_observations) != set(planned_by_key)
        ):
            raise FinancialSupportBundleError(
                "trial records and runtime observations do not exactly cover the compiler plan"
            )
        used_runtime_digests: set[str] = set()
        used_stage_digests: set[str] = set()
        used_attestations: set[str] = set()
        used_cleanups: set[str] = set()
        clone_ids: set[str] = set()
        trace_ids: set[str] = set()
        for record in self.trial_records:
            planned = planned_by_key[record.trial_key]
            selector = cells_by_key[planned.cell_key]
            expected_trace_id = (
                f"financial-support-trace-{planned.ordinal:04d}-{planned.key[-12:]}"
            )
            expected_clone_id = (
                f"sqlite-clone-{planned.ordinal:04d}-{planned.key[-12:]}"
            )
            if (
                record.spec_digest != compiled.spec_digest
                or record.cell_key != planned.cell_key
                or record.block != planned.block
                or record.replicate != planned.replicate
                or record.trace.trace_id != expected_trace_id
                or record.clone.unique_instance_id != expected_clone_id
            ):
                raise FinancialSupportBundleError(
                    f"trial {record.trial_key} disagrees with the bundled compiler plan"
                )
            if record.clone.unique_instance_id in clone_ids:
                raise FinancialSupportBundleError("fresh clone id was reused")
            if record.trace.trace_id in trace_ids:
                raise FinancialSupportBundleError("trace id was reused")
            clone_ids.add(record.clone.unique_instance_id)
            trace_ids.add(record.trace.trace_id)
            attestation_entry = self._attestations.get(record.trial_key)
            if attestation_entry is None:
                raise FinancialSupportBundleError(
                    f"trial {record.trial_key} has no raw attestation"
                )
            attestation, attestation_digest = attestation_entry
            if not _attestation_matches_record(
                attestation,
                attestation_digest,
                record,
            ) or attestation.id != f"attestation-{planned.ordinal:04d}":
                raise FinancialSupportBundleError(
                    f"trial {record.trial_key} disagrees with its raw attestation"
                )
            runtime_observation, runtime_digest = self._runtime_observations[
                record.trial_key
            ]
            expected_action = _action_digest_for(selector)
            resource = runtime_observation.resource_identity
            scope = compiled.contract.scope
            if (
                attestation.ordinal != planned.ordinal
                or runtime_observation.id
                != f"{record.trial_key}:runtime-observation"
                or attestation.observed_selector != selector
                or attestation.action_digest != expected_action
                or record.trace.action_digest != expected_action
                or attestation.observed_build_digest != scope.build_digest
                or attestation.observed_dataset_digest != self.dataset_digest
                or attestation.observed_fixture_digest != self.fixture_digest
                or attestation.base_snapshot_digest != self.dataset_digest
                or record.clone.base_snapshot_digest != self.dataset_digest
                or attestation.covariate_digest
                != _covariate_digest(
                    self.fixture_digest,
                    planned.block,
                    planned.replicate,
                )
                or attestation.intervention_digest != _intervention_digest(selector)
                or attestation.runtime_observation_digest != runtime_digest
                or runtime_observation.spec_digest != record.spec_digest
                or runtime_observation.trace_id != record.trace.trace_id
                or runtime_observation.action_digest != expected_action
                or resource.requested_clone_nonce
                != record.clone.unique_instance_id
                or resource.observed_clone_nonce != record.clone.unique_instance_id
                or resource.requested_runner_resource_id
                != record.clone.runner_resource_id
                or resource.observed_runner_resource_id
                != record.clone.runner_resource_id
                or resource.observed_dataset_snapshot_digest
                != self._database_snapshot_digest
                or attestation.time_basis != self.time_basis
            ):
                raise FinancialSupportBundleError(
                    f"trial {record.trial_key} has inconsistent scope or provenance"
                )
            used_attestations.add(record.trial_key)
            used_runtime_digests.add(runtime_digest)

            expected_events = _derived_events(
                selector,
                expected_action,
                runtime_observation,
                self._runtime_dataset,
            )
            expected_executed = set(expected_events)
            actual_executed = {
                event.stage for event in _executed_trace_events(record.trace)
            }
            if expected_executed != actual_executed:
                raise FinancialSupportBundleError(
                    f"trial {record.trial_key} stage execution differs from runtime rows"
                )
            if Stage.COMPENSATOR not in expected_executed:
                compensator = record.trace.compensator
                if (
                    not isinstance(compensator, SkippedStageEvent)
                    or compensator.blocked_by_event_id
                    != record.trace.target.event_id
                ):
                    raise FinancialSupportBundleError(
                        f"trial {record.trial_key} has an invalid skipped compensator"
                    )
            for stage, expected in expected_events.items():
                coordinate = self._stages_by_coordinate.get(
                    (record.trial_key, stage)
                )
                if coordinate is None:
                    raise FinancialSupportBundleError(
                        f"trial {record.trial_key} has no derived {stage.value} stage"
                    )
                artifact, digest = coordinate
                trace_event = record.trace.event_for(stage)
                if not isinstance(trace_event, ExecutedStageEvent):
                    raise FinancialSupportBundleError(
                        f"trial {record.trial_key} unexpectedly skipped {stage.value}"
                    )
                entry = self._stages_by_digest.get(trace_event.evidence_bundle_digest)
                if entry is None:
                    raise FinancialSupportBundleError(
                        f"event {trace_event.event_id} has no content-addressed stage artifact"
                    )
                if entry != coordinate or not _stage_matches_event(
                    artifact,
                    digest,
                    record,
                    trace_event,
                ):
                    raise FinancialSupportBundleError(
                        f"event {trace_event.event_id} disagrees with its stage artifact"
                    )
                sequence, component, event_type, payload, blocks = expected
                if (
                    artifact.sequence != sequence
                    or artifact.component != component
                    or artifact.event_type != event_type
                    or artifact.payload_pairs() != payload
                    or artifact.blocks_downstream is not blocks
                    or artifact.runtime_observation_digest != runtime_digest
                    or artifact.time_basis != self.time_basis
                ):
                    raise FinancialSupportBundleError(
                        f"event {trace_event.event_id} differs from reconstructed runtime facts"
                    )
                used_stage_digests.add(digest)

            cleanup_entry = self._cleanups_by_digest.get(record.cleanup.evidence_bundle_digest)
            if cleanup_entry is None:
                raise FinancialSupportBundleError(
                    f"trial {record.trial_key} has no cleanup artifact"
                )
            cleanup, cleanup_digest = cleanup_entry
            if (
                not _cleanup_matches_record(cleanup, cleanup_digest, record)
                or cleanup.id != f"cleanup-{planned.ordinal:04d}"
            ):
                raise FinancialSupportBundleError(
                    f"trial {record.trial_key} disagrees with its cleanup artifact"
                )
            if (
                cleanup.time_basis != self.time_basis
                or cleanup.runtime_observation_digest != runtime_digest
                or cleanup.runtime_instance_id
                != resource.observed_runtime_instance_id
            ):
                raise FinancialSupportBundleError(
                    f"trial {record.trial_key} cleanup is not bound to its runtime resource"
                )
            used_cleanups.add(cleanup_digest)

        if used_runtime_digests != {
            item[1] for item in self._runtime_observations.values()
        }:
            raise FinancialSupportBundleError(
                "bundle contains unbound runtime observations"
            )
        if used_stage_digests != set(self._stages_by_digest):
            raise FinancialSupportBundleError("bundle contains unbound stage artifacts")
        if used_attestations != set(self._attestations):
            raise FinancialSupportBundleError("bundle contains unbound trial attestations")
        if used_cleanups != set(self._cleanups_by_digest):
            raise FinancialSupportBundleError("bundle contains unbound cleanup artifacts")

    def _verify_attestation(
        self,
        record: TrialRecord,
    ) -> TrialAttestationResult:
        entry = self._attestations.get(record.trial_key)
        if entry is None:
            return TrialAttestationFailure(
                status="missing",
                reason="bundle has no attestation for the trial key",
            )
        artifact, digest = entry
        if not _attestation_matches_record(artifact, digest, record):
            return TrialAttestationFailure(
                status="rejected",
                reason="raw attestation does not bind the supplied trial record",
                artifact_ids=(digest,),
                observed_selectors=(artifact.observed_selector,),
                observed_digests=(
                    artifact.spec_digest,
                    artifact.action_digest,
                    digest,
                ),
            )
        binding = TrialAttestationBinding(
            spec_digest=artifact.spec_digest,
            trial_key=artifact.trial_key,
            cell_key=artifact.cell_key,
            block=artifact.block,
            replicate=artifact.replicate,
            ordinal=artifact.ordinal,
            trace_id=artifact.trace_id,
            action_digest=artifact.action_digest,
            clone_unique_instance_id=artifact.clone_unique_instance_id,
            runner_resource_id=artifact.runner_resource_id,
            attestation_bundle_digest=digest,
        )
        return AdmittedTrialAttestation(
            evidence_id=_admission_id("trial-attestation", binding, digest),
            binding=binding,
            observed_build_digest=artifact.observed_build_digest,
            observed_dataset_digest=artifact.observed_dataset_digest,
            observed_fixture_digest=artifact.observed_fixture_digest,
            executed_ordinal=artifact.ordinal,
            observed_selector=artifact.observed_selector,
            base_snapshot_digest=artifact.base_snapshot_digest,
            covariate_digest=artifact.covariate_digest,
            intervention_digest=artifact.intervention_digest,
            artifact_ids=(digest,),
            started_at=artifact.started_at,
            ended_at=artifact.ended_at,
        )

    def _verify_metric(
        self,
        binding: EvidenceBinding,
    ) -> MetricEvidenceResult:
        entry = self._stages_by_digest.get(binding.evidence_bundle_digest)
        if entry is None:
            return MetricEvidenceFailure(
                status="missing",
                reason="bundle has no stage artifact with the requested digest",
            )
        artifact, digest = entry
        if (
            artifact.spec_digest != binding.spec_digest
            or artifact.trial_key != binding.trial_key
            or artifact.trace_id != binding.trace_id
            or artifact.event_id != binding.event_id
            or artifact.stage != binding.stage
            or digest != binding.evidence_bundle_digest
        ):
            return MetricEvidenceFailure(
                status="rejected",
                reason="raw stage artifact does not bind the metric request",
                artifact_ids=(digest,),
            )
        extraction = _METRIC_EXTRACTIONS.get(binding.metric_id)
        if extraction is None:
            return MetricEvidenceFailure(
                status="missing",
                reason="bundle repository has no extractor for the requested metric",
                artifact_ids=(digest,),
            )
        expected_stage, field_name, value_kind = extraction
        if artifact.stage != expected_stage:
            return MetricEvidenceFailure(
                status="rejected",
                reason="metric extractor was requested from the wrong stage",
                artifact_ids=(digest,),
            )
        try:
            raw_value = artifact.value(field_name)
        except KeyError:
            return MetricEvidenceFailure(
                status="missing",
                reason=f"raw stage artifact has no field {field_name!r}",
                artifact_ids=(digest,),
            )
        value: IntegerValue | BooleanValue
        if value_kind == "integer":
            if type(raw_value) is not int:
                return MetricEvidenceFailure(
                    status="rejected",
                    reason="raw metric value is not an integer",
                    artifact_ids=(digest,),
                )
            value = IntegerValue(value=raw_value)
        else:
            if type(raw_value) is not bool:
                return MetricEvidenceFailure(
                    status="rejected",
                    reason="raw metric value is not a boolean",
                    artifact_ids=(digest,),
                )
            value = BooleanValue(value=raw_value)
        return AdmittedMetricEvidence(
            evidence_id=_admission_id("metric", binding, digest),
            binding=binding,
            value=value,
            observed_at=artifact.ended_at,
            artifact_ids=(digest,),
        )

    def _verify_cleanup(
        self,
        binding: CleanupBinding,
    ) -> CleanupVerificationResult:
        entry = self._cleanups_by_digest.get(binding.evidence_bundle_digest)
        if entry is None:
            return CleanupEvidenceFailure(
                status="missing",
                reason="bundle has no cleanup artifact with the requested digest",
            )
        artifact, digest = entry
        if (
            artifact.spec_digest != binding.spec_digest
            or artifact.trial_key != binding.trial_key
            or artifact.trace_id != binding.trace_id
            or artifact.clone_unique_instance_id != binding.clone_unique_instance_id
            or artifact.runner_resource_id != binding.runner_resource_id
            or artifact.outcome_ended_at != binding.outcome_ended_at
            or digest != binding.evidence_bundle_digest
        ):
            return CleanupEvidenceFailure(
                status="rejected",
                reason="raw cleanup artifact does not bind the cleanup request",
                artifact_ids=(digest,),
            )
        return AdmittedCleanupEvidence(
            state=CleanupState.VERIFIED,
            binding=binding,
            evidence_id=_admission_id("cleanup", binding, digest),
            observed_at=artifact.observed_at,
            artifact_ids=(digest,),
        )


type _DerivedEvent = tuple[int, str, str, Payload, bool]


def _action_digest_for(selector: CellSelector) -> str:
    return ATTACK_ACTION_DIGEST if selector.input == ATTACK else BENIGN_ACTION_DIGEST


def _covariate_digest(
    fixture_digest: str,
    block: str,
    replicate: int,
) -> str:
    return _digest_value(
        {
            "schema": "assurance-lab.financial-support-covariate/v1",
            "fixture_digest": fixture_digest,
            "block": block,
            "replicate": replicate,
        }
    )


def _intervention_digest(selector: CellSelector) -> str:
    return _digest_value(
        {
            "schema": "assurance-lab.financial-support-intervention/v1",
            "selector": selector.model_dump(mode="json"),
        }
    )


def _derived_events(
    selector: CellSelector,
    action_digest: str,
    observation: FinancialSupportRuntimeObservationArtifact,
    dataset: _RuntimeDatasetArtifact,
) -> dict[Stage, _DerivedEvent]:
    """Reconstruct all admitted stage facts from lower-level rows and receipts."""

    attack = selector.input == ATTACK
    action = action_descriptor(ATTACK if attack else BENIGN)
    principal_id = str(action["principal_id"])
    requested_value = action["requested_customer_ids"]
    if not isinstance(requested_value, list) or not all(
        isinstance(item, str) for item in requested_value
    ):
        raise FinancialSupportBundleError("fixed action has invalid customer ids")
    requested = tuple(requested_value)
    target_mode = _selector_text(selector.target, "target")
    compensator_mode = _selector_text(selector.compensator, "compensator")
    sham = _selector_bool(selector.sham, "sham")
    request = observation.request
    expected_request_id = f"request-{observation.trace_id}"
    if (
        observation.action_digest != action_digest
        or request.request_id != expected_request_id
        or request.trace_id != observation.trace_id
        or request.action_digest != action_digest
        or request.principal_id != principal_id
        or request.requested_customer_ids != requested
    ):
        raise FinancialSupportBundleError(
            "raw request receipt differs from the compiler-owned action"
        )

    dataset_principals = {
        item.principal_id: item for item in dataset.principals
    }
    dataset_customers = {
        item.customer_id: item for item in dataset.customers
    }
    expected_principal = dataset_principals.get(principal_id)
    if expected_principal is None:
        raise FinancialSupportBundleError("runtime dataset has no action principal")
    expected_principal_rows = (
        _PrincipalRowArtifact.model_validate(
            expected_principal.model_dump(mode="python"),
            strict=True,
        ),
    )
    if (
        observation.principal_rows != expected_principal_rows
        or expected_principal.role != "support"
        or expected_principal.status != "active"
    ):
        raise FinancialSupportBundleError(
            "principal query rows differ from the regenerated runtime dataset"
        )

    try:
        expected_customers = tuple(
            _CustomerRowArtifact.model_validate(
                dataset_customers[customer_id].model_dump(mode="python"),
                strict=True,
            )
            for customer_id in sorted(requested)
        )
    except KeyError as error:
        raise FinancialSupportBundleError(
            "action customer is absent from the regenerated runtime dataset"
        ) from error
    if observation.requested_customer_rows != expected_customers:
        raise FinancialSupportBundleError(
            "customer query rows differ from the regenerated runtime dataset"
        )

    expected_cases = tuple(
        _SupportCaseRowArtifact.model_validate(
            item.model_dump(mode="python"),
            strict=True,
        )
        for item in dataset.support_cases
        if item.assigned_principal_id == principal_id and item.status == "active"
    )
    if observation.assigned_support_case_rows != expected_cases:
        raise FinancialSupportBundleError(
            "assignment query rows differ from the regenerated runtime dataset"
        )
    assigned_ids = tuple(sorted(item.customer_id for item in expected_cases))
    authorization = observation.authorization
    allowed = (
        target_mode == "wildcard-misgrant"
        or set(requested).issubset(assigned_ids)
    )
    expected_decision = "allow" if allowed else "deny"
    if (
        authorization.request_id != request.request_id
        or authorization.target_mode != target_mode
        or authorization.decision != expected_decision
        or authorization.allowed is not allowed
        or authorization.assigned_customer_ids != assigned_ids
        or authorization.requested_customer_ids != requested
        or authorization.assigned_rows_evaluated != len(expected_cases)
        or authorization.requested_rows_found != len(expected_customers)
    ):
        raise FinancialSupportBundleError(
            "authorization receipt differs from its source rows and selector"
        )

    selected = tuple(sorted(requested)) if allowed else ()
    selection = observation.selection
    if (
        selection.request_id != request.request_id
        or selection.query_id != f"selection-{request.request_id}"
        or selection.selected_customer_ids != selected
        or selection.row_count != len(selected)
    ):
        raise FinancialSupportBundleError(
            "selection receipt differs from authorization and customer rows"
        )

    reached = allowed
    should_block = (
        reached and compensator_mode == "enforce" and len(selected) >= 10
    )
    expected_guard_decision = (
        "not_reached"
        if not reached
        else "block"
        if should_block
        else "allow"
    )
    guard = observation.guard
    if (
        guard.request_id != request.request_id
        or guard.compensator_mode != compensator_mode
        or guard.reached is not reached
        or guard.decision != expected_guard_decision
        or guard.selected_record_count != len(selected)
        or guard.bulk_threshold_records != 10
    ):
        raise FinancialSupportBundleError(
            "guard receipt differs from selection and compensator selector"
        )

    delivered = () if not allowed or should_block else selected
    expected_payload_digest = _digest_value(
        {
            "trace_id": observation.trace_id,
            "delivered_customer_ids": list(delivered),
        }
    )
    delivery = observation.delivery
    client = observation.client
    if (
        delivery.request_id != request.request_id
        or delivery.selected_customer_ids != selected
        or delivery.delivered_customer_ids != delivered
        or delivery.payload_digest != expected_payload_digest
        or client.request_id != request.request_id
        or client.received_customer_ids != delivered
        or client.payload_digest != expected_payload_digest
    ):
        raise FinancialSupportBundleError(
            "delivery or client receipt differs from the selected records"
        )

    resource = observation.resource_identity
    redeploy = observation.redeploy_operation
    principal_count = len(dataset.principals)
    customer_count = len(dataset.customers)
    case_count = len(dataset.support_cases)
    before_instance = f"{resource.observed_clone_nonce}:generation-1"
    after_instance = (
        f"{resource.observed_clone_nonce}:generation-2"
        if sham
        else before_instance
    )
    if (
        resource.observed_generation != (2 if sham else 1)
        or resource.observed_runtime_instance_id != after_instance
        or redeploy.operation_id != f"redeploy-{observation.trace_id}"
        or redeploy.requested is not sham
        or redeploy.performed is not sham
        or redeploy.before_runtime_instance_id != before_instance
        or redeploy.after_runtime_instance_id != after_instance
        or redeploy.before_dataset_snapshot_digest
        != resource.observed_dataset_snapshot_digest
        or redeploy.after_dataset_snapshot_digest
        != resource.observed_dataset_snapshot_digest
        or redeploy.before_principal_count != principal_count
        or redeploy.after_principal_count != principal_count
        or redeploy.before_customer_count != customer_count
        or redeploy.after_customer_count != customer_count
        or redeploy.before_support_case_count != case_count
        or redeploy.after_support_case_count != case_count
        or redeploy.previous_handle_closed is not sham
    ):
        raise FinancialSupportBundleError(
            "redeploy receipt does not prove the declared pre/post operation"
        )

    outside = set(requested).difference(assigned_ids)
    selected_outside = sum(item in outside for item in selected)
    delivered_outside = sum(item in outside for item in delivered)
    assigned_delivered = sum(item in set(assigned_ids) for item in delivered)
    events: dict[Stage, _DerivedEvent] = {
        Stage.INPUT: (
            1,
            "support-client",
            "action-issued",
            (
                ("action_digest", action_digest),
                ("sham_redeploy", sham),
            ),
            False,
        ),
        Stage.TARGET: (
            2,
            "authorization-boundary",
            "authorization-and-selection-observed",
            (
                ("authorization_decision", expected_decision),
                ("out_of_scope_records_selected", selected_outside),
            ),
            not allowed,
        ),
        Stage.OUTCOME: (
            4,
            "support-client",
            "client-receipt-observed",
            (
                ("out_of_scope_records_delivered", delivered_outside),
                ("assigned_case_records_delivered", assigned_delivered),
                ("delivered_payload_digest", expected_payload_digest),
            ),
            False,
        ),
    }
    if reached:
        events[Stage.COMPENSATOR] = (
            3,
            "release-gateway",
            "release-decision-observed",
            (
                ("release_guard_reached", True),
                ("unapproved_release_blocked", should_block),
            ),
            should_block,
        )
    return events


def _selector_text(value: object, axis: str) -> str:
    if not isinstance(value, StringValue):
        raise FinancialSupportBundleError(
            f"financial-support {axis} selector must be a string"
        )
    return value.value


def _selector_bool(value: object, axis: str) -> bool:
    if not isinstance(value, BooleanValue):
        raise FinancialSupportBundleError(
            f"financial-support {axis} selector must be boolean"
        )
    return value.value


_METRIC_EXTRACTIONS: dict[
    str,
    tuple[Stage, str, Literal["integer", "boolean"]],
] = {
    "out-of-scope-records-selected": (
        Stage.TARGET,
        "out_of_scope_records_selected",
        "integer",
    ),
    "unapproved-release-blocked": (
        Stage.COMPENSATOR,
        "unapproved_release_blocked",
        "boolean",
    ),
    "out-of-scope-records-delivered": (
        Stage.OUTCOME,
        "out_of_scope_records_delivered",
        "integer",
    ),
    "assigned-case-records-delivered": (
        Stage.OUTCOME,
        "assigned_case_records_delivered",
        "integer",
    ),
}


def _parse_jsonl_models[ModelT: BaseModel](
    content: bytes,
    model_type: type[ModelT],
) -> tuple[tuple[ModelT, str], ...]:
    try:
        parsed = strict_jsonl_loads(content, require_sorted_ids=True)
        return tuple(
            (
                model_type.model_validate_json(
                    canonical_json_bytes(item),
                    strict=True,
                ),
                _sha256(canonical_json_bytes(item)),
            )
            for item in parsed
        )
    except (TypeError, ValueError) as error:
        raise FinancialSupportBundleError(
            f"bundle JSONL failed strict artifact validation: {error}"
        ) from error


def _unique_entries[ModelT: BaseModel, KeyT: Hashable](
    entries: tuple[tuple[ModelT, str], ...],
    *,
    key: Callable[[tuple[ModelT, str]], KeyT],
    label: str,
) -> dict[KeyT, tuple[ModelT, str]]:
    result: dict[KeyT, tuple[ModelT, str]] = {}
    for entry in entries:
        identity = key(entry)
        if identity in result:
            raise FinancialSupportBundleError(f"duplicate {label}: {identity!r}")
        result[identity] = entry
    return result


def _executed_trace_events(trace: Trace) -> tuple[ExecutedStageEvent, ...]:
    return tuple(
        event
        for event in (
            trace.input,
            trace.target,
            trace.compensator,
            trace.outcome,
        )
        if isinstance(event, ExecutedStageEvent)
    )


def _attestation_matches_record(
    artifact: _TrialAttestationArtifact,
    digest: str,
    record: TrialRecord,
) -> bool:
    clone = record.clone
    return (
        artifact.spec_digest == record.spec_digest
        and artifact.trial_key == record.trial_key
        and artifact.cell_key == record.cell_key
        and artifact.block == record.block
        and artifact.replicate == record.replicate
        and artifact.trace_id == record.trace.trace_id
        and artifact.action_digest == record.trace.action_digest
        and artifact.clone_unique_instance_id == clone.unique_instance_id
        and artifact.runner_resource_id == clone.runner_resource_id
        and artifact.base_snapshot_digest == clone.base_snapshot_digest
        and artifact.covariate_digest == clone.covariate_digest
        and digest == clone.attestation_bundle_digest
    )


def _stage_matches_event(
    artifact: FinancialSupportStageArtifact,
    digest: str,
    record: TrialRecord,
    event: ExecutedStageEvent,
) -> bool:
    return (
        artifact.spec_digest == record.spec_digest
        and artifact.trial_key == record.trial_key
        and artifact.trace_id == record.trace.trace_id
        and artifact.action_digest == record.trace.action_digest
        and artifact.event_id == event.event_id
        and artifact.stage == event.stage
        and artifact.started_at == event.started_at
        and artifact.ended_at == event.ended_at
        and artifact.blocks_downstream == event.blocks_downstream
        and digest == event.evidence_bundle_digest
    )


def _cleanup_matches_record(
    artifact: _CleanupArtifact,
    digest: str,
    record: TrialRecord,
) -> bool:
    return (
        artifact.spec_digest == record.spec_digest
        and artifact.trial_key == record.trial_key
        and artifact.trace_id == record.trace.trace_id
        and artifact.clone_unique_instance_id == record.clone.unique_instance_id
        and artifact.runner_resource_id == record.clone.runner_resource_id
        and artifact.outcome_ended_at == record.trace.outcome.ended_at
        and digest == record.cleanup.evidence_bundle_digest
    )


def _admission_id(
    kind: str,
    binding: BaseModel,
    artifact_digest: str,
) -> str:
    return _digest_value(
        {
            "schema": "assurance-lab.bundle-admission/v1",
            "kind": kind,
            "binding": binding.model_dump(mode="json"),
            "artifact_digest": artifact_digest,
        }
    )
