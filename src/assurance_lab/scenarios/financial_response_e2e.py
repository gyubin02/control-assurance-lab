"""Bundle-backed execution and independent admission of response evidence.

Every trial is tied to the compiler-owned plan, a fixed synthetic identity
snapshot, the exact action digest, a SQLite clone identity readback, one
lower-level runtime observation, four derived stage summaries, six metric
observations, and a post-close probe.  The repository reconstructs the stage
facts from before/after rows and gateway query receipts before admitting a
value to the generic evaluator.

The bundled source-set hash identifies the source bytes claimed by this
integrity-only run.  It does not authenticate who supplied those bytes.
"""

from __future__ import annotations

import ast
import hashlib
from collections.abc import Callable, Hashable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import pairwise
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
    EvidencePolicyRef,
    EvidenceWindow,
    ExperimentContract,
    ExperimentScope,
    Stage,
    StringValue,
    TrialPlan,
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
    EvaluationReport,
    EvidenceBinding,
    ExecutedStageEvent,
    ExperimentEvaluator,
    FreshClone,
    MetricEvidenceFailure,
    MetricEvidenceResult,
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
from assurance_lab.evidence.writer import BundleMetadata, PayloadFile, write_bundle
from assurance_lab.scenarios.financial_response_contract import (
    ATTACK,
    ATTACK_ACTION_DIGEST,
    BENIGN,
    BENIGN_ACTION_DIGEST,
    COMPENSATOR_ON,
    COMPROMISED_PRINCIPAL_ID,
    COMPROMISED_SESSION_ID,
    SCENARIO_ID,
    SHAM_RELOAD,
    SIBLING_SESSION_ID,
    TARGET_EFFECTIVE,
    UNRELATED_PRINCIPAL_ID,
    UNRELATED_SESSION_ID,
    action_descriptor,
    build_financial_response_contract,
)
from assurance_lab.scenarios.financial_response_runtime import (
    RESPONDER_CONFIG_DIGEST,
    BaselineVerdict,
    FinancialResponseRuntime,
    FinancialResponseRuntimeResult,
    GatewayDecisionReceipt,
    MutationReceipt,
    PrincipalReadback,
    ResourceIdentityReceipt,
    ResponderRuntimeReadback,
    ResponderShamReceipt,
    ResponseActionReceipt,
    ResponseCaseAssessment,
    ResponseResidualClassification,
    ResponseStatusAndReplayBaseline,
    RuntimeEvent,
    SessionReadback,
    _expected_responder_instance_id,
    _expected_response_action_operation_id,
    _expected_sham_operation_id,
    responder_config_descriptor,
)

Digest = Annotated[str, Field(pattern=DIGEST_PATTERN)]
Scalar = str | int | bool
TimeBasis = Literal["simulated"]

_SPEC_PATH = "spec/experiment.json"
_SOURCE_SET_PATH = "spec/runtime-source-set.json"
_SNAPSHOT_PATH = "spec/identity-snapshot.json"
_FIXTURE_PATH = "spec/response-fixture.json"
_RESPONDER_CONFIG_PATH = "spec/responder-config.json"
_STAGE_PATH = "records/stage-events.jsonl"
_RUNTIME_OBSERVATION_PATH = "records/runtime-observations.jsonl"
_METRIC_PATH = "records/metric-observations.jsonl"
_ATTESTATION_PATH = "artifacts/trial-attestations.jsonl"
_CLEANUP_PATH = "artifacts/cleanup-observations.jsonl"
_TRIAL_PATH = "records/trial-records.jsonl"
_RUNNER_RESOURCE_ID: Literal["financial-response-sqlite-runner"] = (
    "financial-response-sqlite-runner"
)
_SOURCE_SET_ROOT_MODULES = (
    "assurance_lab.scenarios.financial_response_e2e",
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
    "assurance_lab.scenarios.financial_response_contract",
    "assurance_lab.scenarios.financial_response_e2e",
    "assurance_lab.scenarios.financial_response_runtime",
)
_IDENTITY_SNAPSHOT = {
    "schema": "assurance-lab.synthetic-identity-snapshot/v1",
    "principals": [
        {
            "principal_id": COMPROMISED_PRINCIPAL_ID,
            "role": "support",
            "quarantined": False,
        },
        {
            "principal_id": UNRELATED_PRINCIPAL_ID,
            "role": "support",
            "quarantined": False,
        },
    ],
    "sessions": [
        {
            "session_id": COMPROMISED_SESSION_ID,
            "principal_id": COMPROMISED_PRINCIPAL_ID,
            "issued_at": "2026-07-01T00:00:00Z",
            "active": True,
        },
        {
            "session_id": SIBLING_SESSION_ID,
            "principal_id": COMPROMISED_PRINCIPAL_ID,
            "issued_at": "2026-07-28T08:00:00Z",
            "active": True,
        },
        {
            "session_id": UNRELATED_SESSION_ID,
            "principal_id": UNRELATED_PRINCIPAL_ID,
            "issued_at": "2026-07-28T08:30:00Z",
            "active": True,
        },
    ],
}


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
            "financial-response source allowlist differs from its local Python "
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
        "schema": "assurance-lab.financial-response-source-set/v1",
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


FINANCIAL_RESPONSE_SOURCE_SET_DIGEST = _digest_value(_source_set_descriptor())
FINANCIAL_RESPONSE_SNAPSHOT_DIGEST = _digest_value(_IDENTITY_SNAPSHOT)
_EVIDENCE_POLICY_DESCRIPTOR = {
    "schema": "assurance-lab.financial-response-policy/v1",
    "requires": [
        "exact-plan-coverage",
        "raw-runtime-observation-binding",
        "raw-event-binding",
        "raw-metric-binding",
        "fresh-clone-identity-readback",
        "cleanup-close-probe",
    ],
}
_EVIDENCE_POLICY_DIGEST = _digest_value(_EVIDENCE_POLICY_DESCRIPTOR)


class FinancialResponseBundleError(ValueError):
    """The runner or repository rejected inconsistent response evidence."""


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


class _IdentityPrincipal(_ArtifactModel):
    principal_id: str = Field(min_length=1)
    role: Literal["support"]
    quarantined: Literal[False]


class _IdentitySession(_ArtifactModel):
    session_id: str = Field(min_length=1)
    principal_id: str = Field(min_length=1)
    issued_at: str = Field(min_length=1)
    active: Literal[True]


class _IdentitySnapshotArtifact(_ArtifactModel):
    schema_id: Literal["assurance-lab.synthetic-identity-snapshot/v1"] = Field(
        alias="schema"
    )
    principals: tuple[_IdentityPrincipal, ...]
    sessions: tuple[_IdentitySession, ...]

    @model_validator(mode="after")
    def fixed_snapshot(self) -> _IdentitySnapshotArtifact:
        if self.model_dump(mode="json", by_alias=True) != _IDENTITY_SNAPSHOT:
            raise ValueError("identity snapshot differs from the fixed synthetic clone")
        return self


class FinancialResponseActionArtifact(_ArtifactModel):
    schema_id: Literal["assurance-lab.identity-session-action/v1"] = Field(
        alias="schema"
    )
    data_class: Literal["synthetic-customer-confidential"]
    action: Literal[
        "compromised-old-session-replay",
        "unrelated-support-normal-action",
    ]
    principal_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    request_id: str = Field(min_length=1)
    operation: Literal[
        "read-support-workbench",
        "read-assigned-case-summary",
    ]

    @model_validator(mode="after")
    def fixed_action(self) -> FinancialResponseActionArtifact:
        level = ATTACK if self.action == ATTACK.value else BENIGN
        if self.model_dump(mode="json", by_alias=True) != action_descriptor(level):
            raise ValueError("action subjects differ from the fixed scenario action")
        return self


class _ResponseFixtureArtifact(_ArtifactModel):
    schema_id: Literal["assurance-lab.financial-response-fixture/v1"] = Field(
        alias="schema"
    )
    identity_snapshot_digest: Digest
    compromised_principal_id: Literal["support-017"]
    compromised_session_id: Literal["SYNTH-SESSION-SUPPORT-017-OLD"]
    sibling_session_id: Literal["SYNTH-SESSION-SUPPORT-017-CURRENT"]
    unrelated_principal_id: Literal["support-042"]
    unrelated_session_id: Literal["SYNTH-SESSION-SUPPORT-042-CURRENT"]
    attack_action: FinancialResponseActionArtifact
    benign_action: FinancialResponseActionArtifact
    attack_action_digest: Digest
    benign_action_digest: Digest
    responder_config_digest: Digest

    @model_validator(mode="after")
    def fixed_fixture(self) -> _ResponseFixtureArtifact:
        if (
            self.identity_snapshot_digest != FINANCIAL_RESPONSE_SNAPSHOT_DIGEST
            or self.attack_action_digest != ATTACK_ACTION_DIGEST
            or self.benign_action_digest != BENIGN_ACTION_DIGEST
            or self.responder_config_digest != RESPONDER_CONFIG_DIGEST
            or _digest_value(
                self.attack_action.model_dump(mode="json", by_alias=True)
            )
            != self.attack_action_digest
            or _digest_value(
                self.benign_action.model_dump(mode="json", by_alias=True)
            )
            != self.benign_action_digest
        ):
            raise ValueError("response fixture does not match the fixed scenario")
        return self


class StageDatum(_ArtifactModel):
    name: str = Field(min_length=1)
    value: Scalar


class FinancialResponseStageArtifact(_ArtifactModel):
    """One raw response runtime event."""

    id: str = Field(min_length=1)
    schema_name: Literal["assurance-lab.financial-response-stage/v1"]
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
    blocks_downstream: Literal[False]
    payload: tuple[StageDatum, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def coherent_event(self) -> FinancialResponseStageArtifact:
        if self.id != self.event_id:
            raise ValueError("stage artifact id must equal event id")
        if self.ended_at <= self.started_at:
            raise ValueError("stage artifact must have positive duration")
        names = tuple(item.name for item in self.payload)
        if len(set(names)) != len(names):
            raise ValueError("stage payload names must be unique")
        return self

    def value(self, name: str) -> Scalar:
        for item in self.payload:
            if item.name == name:
                return item.value
        raise KeyError(name)

    def payload_pairs(self) -> tuple[tuple[str, Scalar], ...]:
        return tuple((item.name, item.value) for item in self.payload)


class _SessionRow(_ArtifactModel):
    session_id: str = Field(min_length=1)
    principal_id: str = Field(min_length=1)
    active: bool


class _PrincipalRow(_ArtifactModel):
    principal_id: str = Field(min_length=1)
    role: str = Field(min_length=1)
    quarantined: bool


class _ResponderRuntimeRow(_ArtifactModel):
    clone_nonce: str = Field(min_length=1)
    instance_id: str = Field(min_length=1)
    generation: int = Field(ge=0)
    config_digest: Digest


class _ResponderShamReceiptArtifact(_ArtifactModel):
    operation_id: str = Field(min_length=1)
    operation: Literal["steady-observation", "reload"]
    clone_nonce: str = Field(min_length=1)
    before_instance_id: str = Field(min_length=1)
    after_instance_id: str = Field(min_length=1)
    before_generation: int = Field(ge=0)
    after_generation: int = Field(ge=0)
    config_digest: Digest
    rows_affected: int = Field(ge=0)


class _ResponseActionReceiptArtifact(_ArtifactModel):
    operation_id: str = Field(min_length=1)
    responder_instance_id: str = Field(min_length=1)
    trace_id: str = Field(min_length=1)
    action_digest: Digest
    target_mode: str = Field(min_length=1)
    principal_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    operation: Literal["not-triggered", "report-only", "revoke-exact"]
    status: Literal["not-triggered", "reported-success"]
    rows_affected: int = Field(ge=0)


class _MutationReceiptArtifact(_ArtifactModel):
    component: Literal["session-revoker", "principal-quarantine"]
    operation: Literal["not-triggered", "report-only", "revoke-exact", "quarantine"]
    principal_id: str = Field(min_length=1)
    session_id: str | None
    rows_affected: int = Field(ge=0)


class _GatewayDecisionArtifact(_ArtifactModel):
    query_id: str = Field(min_length=1)
    principal_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    session_found: bool
    principal_found: bool
    session_revoked: bool
    principal_quarantined: bool
    available: bool

    @model_validator(mode="after")
    def decision_matches_query_rows(self) -> _GatewayDecisionArtifact:
        expected = (
            self.session_found
            and self.principal_found
            and not self.session_revoked
            and not self.principal_quarantined
        )
        if self.available is not expected:
            raise ValueError("gateway availability differs from its query row receipt")
        return self


class _ResourceIdentityArtifact(_ArtifactModel):
    requested_clone_nonce: str = Field(min_length=1)
    requested_runner_resource_id: str = Field(min_length=1)
    observed_clone_nonce: str = Field(min_length=1)
    observed_runner_resource_id: str = Field(min_length=1)

    @model_validator(mode="after")
    def requested_identity_was_read_back(self) -> _ResourceIdentityArtifact:
        if (
            self.requested_clone_nonce != self.observed_clone_nonce
            or self.requested_runner_resource_id != self.observed_runner_resource_id
        ):
            raise ValueError("runtime resource identity readback differs from its request")
        return self


class FinancialResponseRuntimeObservationArtifact(_ArtifactModel):
    """Lower-level SQLite rows and gateway query receipts for one trial."""

    id: str = Field(min_length=1)
    schema_name: Literal["assurance-lab.financial-response-runtime-observation/v1"]
    spec_digest: Digest
    trial_key: Digest
    trace_id: str = Field(min_length=1)
    action_digest: Digest
    resource_identity: _ResourceIdentityArtifact
    responder_before_sham: _ResponderRuntimeRow
    responder_after_sham: _ResponderRuntimeRow
    sham_operation: _ResponderShamReceiptArtifact
    response_action: _ResponseActionReceiptArtifact
    sessions_before_target: tuple[_SessionRow, ...]
    sessions_after_target: tuple[_SessionRow, ...]
    sessions_after_compensator: tuple[_SessionRow, ...]
    principals_before_target: tuple[_PrincipalRow, ...]
    principals_after_target: tuple[_PrincipalRow, ...]
    principals_after_compensator: tuple[_PrincipalRow, ...]
    target_mutation: _MutationReceiptArtifact
    compensator_mutation: _MutationReceiptArtifact
    gateway_decisions: tuple[_GatewayDecisionArtifact, ...]

    @model_validator(mode="after")
    def rows_are_unique_and_sorted(
        self,
    ) -> FinancialResponseRuntimeObservationArtifact:
        identities = (
            tuple(item.session_id for item in self.sessions_before_target),
            tuple(item.session_id for item in self.sessions_after_target),
            tuple(item.session_id for item in self.sessions_after_compensator),
            tuple(item.principal_id for item in self.principals_before_target),
            tuple(item.principal_id for item in self.principals_after_target),
            tuple(item.principal_id for item in self.principals_after_compensator),
            tuple(item.query_id for item in self.gateway_decisions),
        )
        for values in identities:
            if len(values) != len(set(values)) or values != tuple(sorted(values)):
                raise ValueError(
                    "runtime observation identities must be unique and sorted"
                )
        return self


class FinancialResponseMetricArtifact(_ArtifactModel):
    """One raw metric observation bound to one raw stage event."""

    id: str = Field(min_length=1)
    schema_name: Literal["assurance-lab.financial-response-metric/v1"]
    spec_digest: Digest
    trial_key: Digest
    trace_id: str = Field(min_length=1)
    event_id: str = Field(min_length=1)
    event_digest: Digest
    metric_id: str = Field(min_length=1)
    subject_id: str = Field(min_length=1)
    component: str = Field(min_length=1)
    stage: Stage
    value: BooleanValue
    observed_at: AwareDatetime


class _TrialAttestationArtifact(_ArtifactModel):
    id: str = Field(min_length=1)
    schema_name: Literal["assurance-lab.financial-response-attestation/v1"]
    spec_digest: Digest
    trial_key: Digest
    cell_key: str = Field(min_length=1)
    block: str = Field(min_length=1)
    replicate: PositiveInt
    ordinal: PositiveInt
    trace_id: str = Field(min_length=1)
    action_digest: Digest
    clone_unique_instance_id: str = Field(min_length=1)
    runner_resource_id: Literal["financial-response-sqlite-runner"]
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
            raise ValueError("trial attestation must have positive duration")
        return self


class _CleanupArtifact(_ArtifactModel):
    id: str = Field(min_length=1)
    schema_name: Literal["assurance-lab.financial-response-cleanup/v1"]
    spec_digest: Digest
    trial_key: Digest
    trace_id: str = Field(min_length=1)
    clone_unique_instance_id: str = Field(min_length=1)
    runner_resource_id: Literal["financial-response-sqlite-runner"]
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
            raise ValueError("cleanup must be observed after the outcome")
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


@dataclass(frozen=True, slots=True)
class FinancialResponseBundleAssessment:
    """The generic evaluator report beside the response-specific shallow check."""

    report: EvaluationReport
    response_case: ResponseCaseAssessment


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
        "compiler-owned response experiment",
        ("design", "evaluation"),
    ),
    _SOURCE_SET_PATH: _PayloadMetadata(
        "application/json",
        "claimed evaluator source-set descriptor",
        ("scope", "provenance"),
    ),
    _SNAPSHOT_PATH: _PayloadMetadata(
        "application/json",
        "fixed synthetic identity snapshot",
        ("scope", "attestation"),
    ),
    _FIXTURE_PATH: _PayloadMetadata(
        "application/json",
        "fixed exact-session response fixture",
        ("scope", "attestation"),
    ),
    _RESPONDER_CONFIG_PATH: _PayloadMetadata(
        "application/json",
        "synthetic persisted responder configuration",
        ("scope", "runtime-reconstruction", "attestation"),
    ),
    _RUNTIME_OBSERVATION_PATH: _PayloadMetadata(
        "application/x-ndjson",
        "raw SQLite rows and gateway query receipts",
        ("runtime-reconstruction", "trace-lineage", "cleanup-admission"),
    ),
    _STAGE_PATH: _PayloadMetadata(
        "application/x-ndjson",
        "stage summaries derived from raw runtime observations",
        ("trace-lineage", "metric-validation"),
    ),
    _METRIC_PATH: _PayloadMetadata(
        "application/x-ndjson",
        "metric observations extracted from derived stage summaries",
        ("metric-extraction",),
    ),
    _ATTESTATION_PATH: _PayloadMetadata(
        "application/x-ndjson",
        "response trial attestations bound to runtime observations",
        ("trial-admission",),
    ),
    _CLEANUP_PATH: _PayloadMetadata(
        "application/x-ndjson",
        "post-close SQLite operation probes",
        ("cleanup-admission",),
    ),
    _TRIAL_PATH: _PayloadMetadata(
        "application/x-ndjson",
        "metric-free response trial records",
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
            f"{FINANCIAL_RESPONSE_SOURCE_SET_DIGEST.removeprefix('sha256:')}"
        ),
        image_digest=None,
    )


def _timestamp_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise FinancialResponseBundleError("bundle timestamp must be timezone-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _fixture_manifest() -> dict[str, object]:
    return {
        "schema": "assurance-lab.financial-response-fixture/v1",
        "identity_snapshot_digest": FINANCIAL_RESPONSE_SNAPSHOT_DIGEST,
        "compromised_principal_id": COMPROMISED_PRINCIPAL_ID,
        "compromised_session_id": COMPROMISED_SESSION_ID,
        "sibling_session_id": SIBLING_SESSION_ID,
        "unrelated_principal_id": UNRELATED_PRINCIPAL_ID,
        "unrelated_session_id": UNRELATED_SESSION_ID,
        "attack_action": action_descriptor(ATTACK),
        "benign_action": action_descriptor(BENIGN),
        "attack_action_digest": ATTACK_ACTION_DIGEST,
        "benign_action_digest": BENIGN_ACTION_DIGEST,
        "responder_config_digest": RESPONDER_CONFIG_DIGEST,
    }


def _session_rows(values: tuple[SessionReadback, ...]) -> tuple[_SessionRow, ...]:
    return tuple(
        _SessionRow(
            session_id=value.session_id,
            principal_id=value.principal_id,
            active=value.active,
        )
        for value in values
    )


def _principal_rows(
    values: tuple[PrincipalReadback, ...],
) -> tuple[_PrincipalRow, ...]:
    return tuple(
        _PrincipalRow(
            principal_id=value.principal_id,
            role=value.role,
            quarantined=value.quarantined,
        )
        for value in values
    )


def _responder_row(value: ResponderRuntimeReadback) -> _ResponderRuntimeRow:
    return _ResponderRuntimeRow(
        clone_nonce=value.clone_nonce,
        instance_id=value.instance_id,
        generation=value.generation,
        config_digest=value.config_digest,
    )


def _sham_receipt(
    value: ResponderShamReceipt,
) -> _ResponderShamReceiptArtifact:
    return _ResponderShamReceiptArtifact(
        operation_id=value.operation_id,
        operation=value.operation,
        clone_nonce=value.clone_nonce,
        before_instance_id=value.before_instance_id,
        after_instance_id=value.after_instance_id,
        before_generation=value.before_generation,
        after_generation=value.after_generation,
        config_digest=value.config_digest,
        rows_affected=value.rows_affected,
    )


def _response_action_receipt(
    value: ResponseActionReceipt,
) -> _ResponseActionReceiptArtifact:
    return _ResponseActionReceiptArtifact(
        operation_id=value.operation_id,
        responder_instance_id=value.responder_instance_id,
        trace_id=value.trace_id,
        action_digest=value.action_digest,
        target_mode=value.target_mode,
        principal_id=value.principal_id,
        session_id=value.session_id,
        operation=value.operation,
        status=value.status.value,
        rows_affected=value.rows_affected,
    )


def _mutation_receipt(value: MutationReceipt) -> _MutationReceiptArtifact:
    return _MutationReceiptArtifact(
        component=value.component,
        operation=value.operation,
        principal_id=value.principal_id,
        session_id=value.session_id,
        rows_affected=value.rows_affected,
    )


def _gateway_receipt(value: GatewayDecisionReceipt) -> _GatewayDecisionArtifact:
    return _GatewayDecisionArtifact(
        query_id=value.query_id,
        principal_id=value.principal_id,
        session_id=value.session_id,
        session_found=value.session_found,
        principal_found=value.principal_found,
        session_revoked=value.session_revoked,
        principal_quarantined=value.principal_quarantined,
        available=value.available,
    )


def _resource_receipt(value: ResourceIdentityReceipt) -> _ResourceIdentityArtifact:
    return _ResourceIdentityArtifact.model_validate(
        {
            "requested_clone_nonce": value.requested_clone_nonce,
            "requested_runner_resource_id": value.requested_runner_resource_id,
            "observed_clone_nonce": value.observed_clone_nonce,
            "observed_runner_resource_id": value.observed_runner_resource_id,
        },
        strict=True,
    )


def _runtime_observation(
    compiled: CompiledExperiment,
    trial_key: str,
    result: FinancialResponseRuntimeResult,
) -> FinancialResponseRuntimeObservationArtifact:
    return FinancialResponseRuntimeObservationArtifact(
        id=f"{trial_key}:runtime-observation",
        schema_name="assurance-lab.financial-response-runtime-observation/v1",
        spec_digest=compiled.spec_digest,
        trial_key=trial_key,
        trace_id=result.trace_id,
        action_digest=result.action_digest,
        resource_identity=_resource_receipt(result.resource_identity),
        responder_before_sham=_responder_row(result.responder_before_sham),
        responder_after_sham=_responder_row(result.responder_after_sham),
        sham_operation=_sham_receipt(result.sham_operation),
        response_action=_response_action_receipt(
            result.response_action_receipt
        ),
        sessions_before_target=_session_rows(result.sessions_before_target),
        sessions_after_target=_session_rows(result.sessions_after_target),
        sessions_after_compensator=_session_rows(
            result.sessions_after_compensator
        ),
        principals_before_target=_principal_rows(result.principals_before_target),
        principals_after_target=_principal_rows(result.principals_after_target),
        principals_after_compensator=_principal_rows(
            result.principals_after_compensator
        ),
        target_mutation=_mutation_receipt(result.target_mutation),
        compensator_mutation=_mutation_receipt(result.compensator_mutation),
        gateway_decisions=tuple(
            _gateway_receipt(value)
            for value in sorted(
                result.gateway_decisions,
                key=lambda item: item.query_id,
            )
        ),
    )


def _covariate_digest(
    fixture_digest: str,
    block: str,
    replicate: int,
) -> str:
    return _digest_value(
        {
            "schema": "assurance-lab.financial-response-covariate/v1",
            "fixture_digest": fixture_digest,
            "block": block,
            "replicate": replicate,
        }
    )


def _intervention_digest(selector: CellSelector) -> str:
    return _digest_value(
        {
            "schema": "assurance-lab.financial-response-intervention/v1",
            "selector": selector.model_dump(mode="json"),
        }
    )


class FinancialResponseExperimentRunner:
    """Execute the exact 16-cell plan against fresh in-memory clones."""

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] | None,
        time_basis: TimeBasis | None,
    ) -> None:
        if time_basis != "simulated" or clock is None:
            raise ValueError(
                "the one-shot response runner requires an explicit simulated "
                "time basis and clock"
            )
        self._clock = clock
        self._time_basis: TimeBasis = time_basis
        self._runtime = FinancialResponseRuntime()
        self._source_set = _source_set_descriptor()
        self._snapshot = _IDENTITY_SNAPSHOT
        self._fixture = _fixture_manifest()
        self._responder_config = responder_config_descriptor()
        self.build_digest = FINANCIAL_RESPONSE_SOURCE_SET_DIGEST
        self.dataset_digest = FINANCIAL_RESPONSE_SNAPSHOT_DIGEST
        self.fixture_digest = _digest_value(self._fixture)

    def run(
        self,
        compiled: CompiledExperiment,
        destination: Path,
    ) -> BundleVerification:
        compiled = self._validated_compiled(compiled)
        cells = {cell.key: cell.selector for cell in compiled.cells}
        runtime_observations: list[FinancialResponseRuntimeObservationArtifact] = []
        stages: list[FinancialResponseStageArtifact] = []
        metrics: list[FinancialResponseMetricArtifact] = []
        attestations: list[_TrialAttestationArtifact] = []
        cleanups: list[_CleanupArtifact] = []
        records: list[_StoredTrialRecord] = []
        previous: datetime | None = None

        for planned in sorted(compiled.planned_trials, key=lambda item: item.ordinal):
            selector = cells[planned.cell_key]
            trial_started = self._next_time(previous)
            trace_id = f"financial-response-trace-{planned.ordinal:04d}-{planned.key[-12:]}"
            clone_id = f"response-sqlite-clone-{planned.ordinal:04d}-{planned.key[-12:]}"
            result = self._runtime.execute(
                selector,
                trace_id=trace_id,
                clone_nonce=clone_id,
                runner_resource_id=_RUNNER_RESOURCE_ID,
            )
            expected_action = _action_digest_for(selector)
            if result.action_digest != expected_action:
                raise FinancialResponseBundleError(
                    f"runtime action digest differs for trial {planned.key}"
                )
            runtime_observation = _runtime_observation(
                compiled,
                planned.key,
                result,
            )
            runtime_observation_digest = _artifact_digest(runtime_observation)
            runtime_observations.append(runtime_observation)
            runtime_observed = self._next_time(trial_started)
            trial_stages = self._stage_artifacts(
                compiled,
                planned.key,
                result.events,
                result.action_digest,
                runtime_observation_digest,
                runtime_observed,
            )
            stages.extend(trial_stages)
            stage_by_kind = {item.stage: item for item in trial_stages}
            trial_metrics = self._metric_artifacts(
                compiled,
                planned.key,
                selector,
                stage_by_kind,
            )
            metrics.extend(trial_metrics)

            input_event = _executed_event(stage_by_kind[Stage.INPUT])
            target_event = _executed_event(stage_by_kind[Stage.TARGET])
            compensator_event = _executed_event(stage_by_kind[Stage.COMPENSATOR])
            outcome_event = _executed_event(stage_by_kind[Stage.OUTCOME])
            trace = Trace(
                trace_id=trace_id,
                action_digest=result.action_digest,
                input=input_event,
                target=target_event,
                compensator=compensator_event,
                outcome=outcome_event,
            )
            covariate_digest = _covariate_digest(
                self.fixture_digest,
                planned.block,
                planned.replicate,
            )
            intervention_digest = _intervention_digest(selector)
            attestation_ended = self._next_time(
                max(item.ended_at for item in trial_stages)
            )
            attestation = _TrialAttestationArtifact(
                id=f"response-attestation-{planned.ordinal:04d}",
                schema_name="assurance-lab.financial-response-attestation/v1",
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
                base_snapshot_digest=self.dataset_digest,
                covariate_digest=covariate_digest,
                intervention_digest=intervention_digest,
                runtime_observation_digest=runtime_observation_digest,
                time_basis=self._time_basis,
                started_at=trial_started,
                ended_at=attestation_ended,
            )
            attestation_digest = _artifact_digest(attestation)
            clone = FreshClone(
                unique_instance_id=clone_id,
                base_snapshot_digest=self.dataset_digest,
                covariate_digest=covariate_digest,
                attestation_bundle_digest=attestation_digest,
                runner_resource_id=_RUNNER_RESOURCE_ID,
            )
            cleanup_observed = self._next_time(attestation_ended)
            cleanup_probe = result.cleanup_probe
            if (
                cleanup_probe.clone_nonce != clone_id
                or cleanup_probe.runner_resource_id != _RUNNER_RESOURCE_ID
            ):
                raise FinancialResponseBundleError(
                    f"runtime cleanup receipt differs for trial {planned.key}"
                )
            cleanup = _CleanupArtifact(
                id=f"response-cleanup-{planned.ordinal:04d}",
                schema_name="assurance-lab.financial-response-cleanup/v1",
                spec_digest=compiled.spec_digest,
                trial_key=planned.key,
                trace_id=trace_id,
                clone_unique_instance_id=clone_id,
                runner_resource_id=_RUNNER_RESOURCE_ID,
                outcome_ended_at=outcome_event.ended_at,
                observed_at=cleanup_observed,
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
            record = TrialRecord(
                spec_digest=compiled.spec_digest,
                trial_key=planned.key,
                cell_key=planned.cell_key,
                block=planned.block,
                replicate=planned.replicate,
                clone=clone,
                trace=trace,
                cleanup=CleanupReference(
                    evidence_bundle_digest=_artifact_digest(cleanup)
                ),
            )
            attestations.append(attestation)
            cleanups.append(cleanup)
            records.append(
                _StoredTrialRecord(
                    id=planned.key,
                    schema_name="assurance-lab.trial-record/v1",
                    record=record,
                )
            )
            previous = cleanup_observed

        latest = max(item.observed_at for item in cleanups)
        scope = compiled.contract.scope
        if latest > scope.evidence_window.end or latest > scope.assessment_as_of:
            raise FinancialResponseBundleError(
                "the evidence window cannot contain all compiler-planned executions"
            )

        payloads = (
            _payload_file(
                _SPEC_PATH,
                compiled.canonical_spec.encode("utf-8"),
            ),
            _payload_file(
                _SOURCE_SET_PATH,
                canonical_json_bytes(self._source_set),
            ),
            _payload_file(
                _SNAPSHOT_PATH,
                canonical_json_bytes(self._snapshot),
            ),
            _payload_file(
                _FIXTURE_PATH,
                canonical_json_bytes(self._fixture),
            ),
            _payload_file(
                _RESPONDER_CONFIG_PATH,
                canonical_json_bytes(self._responder_config),
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
                _METRIC_PATH,
                tuple(metrics),
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
                tuple(records),
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
            raise FinancialResponseBundleError(
                f"compiled experiment is invalid: {error}"
            ) from error
        if clean != regenerated:
            raise FinancialResponseBundleError(
                "compiled experiment differs from a fresh compiler result"
            )
        if clean.contract.id != SCENARIO_ID or len(clean.cells) != 16:
            raise FinancialResponseBundleError(
                "response runner requires complete coverage of the fixed 16 cells"
            )
        scope = clean.contract.scope
        expected_compiled = compile_experiment(
            build_financial_response_contract(
                scope=scope,
                plan=clean.contract.plan,
            )
        )
        if clean.canonical_spec != expected_compiled.canonical_spec:
            raise FinancialResponseBundleError(
                "response contract differs from the fixed scenario contract"
            )
        if (
            scope.build_digest,
            scope.dataset_digest,
            scope.fixture_digest,
        ) != (
            self.build_digest,
            self.dataset_digest,
            self.fixture_digest,
        ):
            raise FinancialResponseBundleError(
                "contract scope does not match the response runner"
            )
        if (
            scope.evidence_policy.id != "financial-response-bundle-v1"
            or scope.evidence_policy.version != "1.0.0"
            or scope.evidence_policy.digest != _EVIDENCE_POLICY_DIGEST
        ):
            raise FinancialResponseBundleError(
                "contract evidence policy differs from the fixed response policy"
            )
        if (
            clean.contract.profile.input.attack_action_digest
            != ATTACK_ACTION_DIGEST
            or clean.contract.profile.input.benign_action_digest
            != BENIGN_ACTION_DIGEST
        ):
            raise FinancialResponseBundleError(
                "contract action digests do not match the response fixture"
            )
        return clean

    def _next_time(self, after: datetime | None) -> datetime:
        for _ in range(10_000):
            observed = self._clock()
            if observed.tzinfo is None or observed.utcoffset() is None:
                raise FinancialResponseBundleError(
                    "runner clock must return timezone-aware datetimes"
                )
            observed = observed.astimezone(UTC)
            if after is None or observed > after:
                return observed
        raise FinancialResponseBundleError(
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
    ) -> tuple[FinancialResponseStageArtifact, ...]:
        result: list[FinancialResponseStageArtifact] = []
        previous = after
        for event in events:
            stage = Stage(event.stage)
            started = self._next_time(previous)
            ended = self._next_time(started)
            event_id = f"{event.trace_id}:{stage.value}"
            result.append(
                FinancialResponseStageArtifact(
                    id=event_id,
                    schema_name="assurance-lab.financial-response-stage/v1",
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
                    started_at=started,
                    ended_at=ended,
                    blocks_downstream=False,
                    payload=tuple(
                        StageDatum(name=name, value=value)
                        for name, value in event.payload
                    ),
                )
            )
            previous = ended
        return tuple(result)

    def _metric_artifacts(
        self,
        compiled: CompiledExperiment,
        trial_key: str,
        selector: CellSelector,
        stages: dict[Stage, FinancialResponseStageArtifact],
    ) -> tuple[FinancialResponseMetricArtifact, ...]:
        result: list[FinancialResponseMetricArtifact] = []
        expected_action = _action_digest_for(selector)
        for metric_id, (stage, field_name, subject_id) in _METRIC_BINDINGS.items():
            event = stages[stage]
            value = event.value(field_name)
            if type(value) is not bool:
                raise FinancialResponseBundleError(
                    f"runtime metric {metric_id!r} is not boolean"
                )
            result.append(
                FinancialResponseMetricArtifact(
                    id=f"{trial_key}:{metric_id}",
                    schema_name="assurance-lab.financial-response-metric/v1",
                    spec_digest=compiled.spec_digest,
                    trial_key=trial_key,
                    trace_id=event.trace_id,
                    event_id=event.event_id,
                    event_digest=_artifact_digest(event),
                    metric_id=metric_id,
                    subject_id=subject_id,
                    component=event.component,
                    stage=stage,
                    value=BooleanValue(value=value),
                    observed_at=event.ended_at,
                )
            )
        if any(event.action_digest != expected_action for event in stages.values()):
            raise FinancialResponseBundleError(
                f"stage action digest drifted for trial {trial_key}"
            )
        return tuple(result)


def _executed_event(
    artifact: FinancialResponseStageArtifact,
) -> ExecutedStageEvent:
    return ExecutedStageEvent(
        event_id=artifact.event_id,
        evidence_bundle_digest=_artifact_digest(artifact),
        stage=artifact.stage,
        started_at=artifact.started_at,
        ended_at=artifact.ended_at,
        blocks_downstream=False,
    )


class FinancialResponseBundleRepository:
    """Rehash, cross-bind, and semantically admit response evidence."""

    def __init__(self, root: Path) -> None:
        self._root = root
        verification = verify_bundle(root)
        if (
            verification.status != BundleStatus.INTEGRITY_VERIFIED
            or verification.manifest is None
            or verification.bundle_id is None
        ):
            detail = "; ".join(
                f"{issue.code}: {issue.detail}" for issue in verification.issues
            )
            raise FinancialResponseBundleError(
                f"bundle integrity verification failed: {detail}"
            )
        self.bundle_id = verification.bundle_id
        self._manifest = verification.manifest
        self.bundle_profile = self._manifest.profile

        spec = self._read_rehashed(_SPEC_PATH)
        try:
            bundled = _BundledContractArtifact.model_validate_json(spec, strict=True)
            compiled = compile_experiment(bundled.contract)
        except ValueError as error:
            raise FinancialResponseBundleError(
                f"bundled response contract failed strict compilation: {error}"
            ) from error
        if (
            compiled.canonical_spec.encode("utf-8") != spec
            or compiled.spec_digest != _sha256(spec)
        ):
            raise FinancialResponseBundleError(
                "bundled response experiment is not compiler canonical"
            )
        if (
            self._manifest.experiment.id != compiled.contract.id
            or self._manifest.experiment.spec_version != compiled.contract.version
            or self._manifest.experiment.spec_digest != compiled.spec_digest
        ):
            raise FinancialResponseBundleError(
                "manifest experiment reference differs from bundled contract"
            )
        scope = compiled.contract.scope
        if (
            self._manifest.evaluation.policy_id != scope.evidence_policy.id
            or self._manifest.evaluation.policy_digest
            != scope.evidence_policy.digest
        ):
            raise FinancialResponseBundleError(
                "manifest policy differs from bundled contract"
            )
        if compiled.contract.id != SCENARIO_ID:
            raise FinancialResponseBundleError("bundle contains the wrong scenario")
        expected_compiled = compile_experiment(
            build_financial_response_contract(
                scope=scope,
                plan=compiled.contract.plan,
            )
        )
        if compiled.canonical_spec != expected_compiled.canonical_spec:
            raise FinancialResponseBundleError(
                "bundled contract differs from the fixed response contract"
            )
        if (
            scope.evidence_policy.id != "financial-response-bundle-v1"
            or scope.evidence_policy.version != "1.0.0"
            or scope.evidence_policy.digest != _EVIDENCE_POLICY_DIGEST
        ):
            raise FinancialResponseBundleError(
                "bundled evidence policy differs from the fixed response policy"
            )
        self._validate_manifest_metadata(compiled)
        self.compiled_experiment = compiled

        source_set_bytes = self._read_rehashed(_SOURCE_SET_PATH)
        try:
            source_set = strict_json_loads(source_set_bytes)
        except ValueError as error:
            raise FinancialResponseBundleError(
                f"source-set descriptor failed strict validation: {error}"
            ) from error
        if (
            source_set != _source_set_descriptor()
            or canonical_json_bytes(source_set) != source_set_bytes
            or _sha256(source_set_bytes) != scope.build_digest
            or scope.build_digest != FINANCIAL_RESPONSE_SOURCE_SET_DIGEST
        ):
            raise FinancialResponseBundleError(
                "bundled source-set descriptor differs from the verifier source"
            )
        self.source_set_digest = _sha256(source_set_bytes)

        snapshot_bytes = self._read_rehashed(_SNAPSHOT_PATH)
        fixture_bytes = self._read_rehashed(_FIXTURE_PATH)
        responder_config_bytes = self._read_rehashed(_RESPONDER_CONFIG_PATH)
        try:
            snapshot = _IdentitySnapshotArtifact.model_validate_json(
                snapshot_bytes,
                strict=True,
            )
            fixture = _ResponseFixtureArtifact.model_validate_json(
                fixture_bytes,
                strict=True,
            )
            responder_config = strict_json_loads(responder_config_bytes)
        except ValueError as error:
            raise FinancialResponseBundleError(
                f"response provenance failed strict validation: {error}"
            ) from error
        if (
            canonical_json_bytes(snapshot.model_dump(mode="json", by_alias=True))
            != snapshot_bytes
            or canonical_json_bytes(fixture.model_dump(mode="json", by_alias=True))
            != fixture_bytes
            or responder_config != responder_config_descriptor()
            or canonical_json_bytes(responder_config) != responder_config_bytes
            or _sha256(responder_config_bytes) != RESPONDER_CONFIG_DIGEST
            or fixture.responder_config_digest != RESPONDER_CONFIG_DIGEST
        ):
            raise FinancialResponseBundleError(
                "response responder configuration or provenance differs from "
                "its verifier-owned canonical model"
            )
        self.attack_action = fixture.attack_action
        self.benign_action = fixture.benign_action
        self.dataset_digest = _sha256(snapshot_bytes)
        self.fixture_digest = _sha256(fixture_bytes)
        self.responder_config_digest = _sha256(responder_config_bytes)
        if (
            self.dataset_digest != scope.dataset_digest
            or self.fixture_digest != scope.fixture_digest
            or scope.build_digest != self.source_set_digest
        ):
            raise FinancialResponseBundleError(
                "response scope digests do not match executable provenance"
            )

        runtime_entries = _parse_jsonl_models(
            self._read_rehashed(_RUNTIME_OBSERVATION_PATH),
            FinancialResponseRuntimeObservationArtifact,
        )
        stage_entries = _parse_jsonl_models(
            self._read_rehashed(_STAGE_PATH),
            FinancialResponseStageArtifact,
        )
        metric_entries = _parse_jsonl_models(
            self._read_rehashed(_METRIC_PATH),
            FinancialResponseMetricArtifact,
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
            label="stage digest",
        )
        self._stages_by_coordinate = _unique_entries(
            stage_entries,
            key=lambda entry: (entry[0].trial_key, entry[0].stage),
            label="stage coordinate",
        )
        self._metrics = _unique_entries(
            metric_entries,
            key=lambda entry: (entry[0].trial_key, entry[0].metric_id),
            label="metric coordinate",
        )
        self._attestations = _unique_entries(
            attestation_entries,
            key=lambda entry: entry[0].trial_key,
            label="trial attestation",
        )
        self._cleanups_by_digest = _unique_entries(
            cleanup_entries,
            key=lambda entry: entry[1],
            label="cleanup digest",
        )
        stored_by_key = _unique_entries(
            stored_entries,
            key=lambda entry: entry[0].record.trial_key,
            label="stored trial",
        )
        time_bases = {
            *(entry[0].time_basis for entry in stage_entries),
            *(entry[0].time_basis for entry in attestation_entries),
            *(entry[0].time_basis for entry in cleanup_entries),
        }
        if time_bases != {"simulated"}:
            raise FinancialResponseBundleError(
                "all one-shot response artifacts must use simulated time"
            )
        self.time_basis: TimeBasis = "simulated"
        self.trial_records = tuple(
            entry[0].record
            for entry in sorted(
                stored_by_key.values(),
                key=lambda entry: self._attestation_ordinal(
                    entry[0].record.trial_key
                ),
            )
        )
        self._validate_cross_references()

        final = verify_bundle(root)
        if (
            final.status != BundleStatus.INTEGRITY_VERIFIED
            or final.bundle_id != self.bundle_id
        ):
            raise FinancialResponseBundleError(
                "bundle changed while it was loaded and rehashed"
            )

    def stage_artifact(
        self,
        trial_key: str,
        stage: Stage,
    ) -> FinancialResponseStageArtifact:
        try:
            return self._stages_by_coordinate[(trial_key, stage)][0]
        except KeyError as error:
            raise KeyError(f"no {stage.value} event for {trial_key}") from error

    def metric_value(self, trial_key: str, metric_id: str) -> bool:
        try:
            return self._metrics[(trial_key, metric_id)][0].value.value
        except KeyError as error:
            raise KeyError(f"no metric {metric_id!r} for {trial_key}") from error

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
        raise TypeError(f"unsupported request: {type(request).__name__}")

    def _read_rehashed(self, path: str) -> bytes:
        descriptor = next(
            (item for item in self._manifest.files if item.path == path),
            None,
        )
        if descriptor is None:
            raise FinancialResponseBundleError(
                f"bundle is missing required payload {path}"
            )
        content = self._root.joinpath(*path.split("/")).read_bytes()
        if (
            len(content) != descriptor.size
            or hashlib.sha256(content).hexdigest() != descriptor.sha256
        ):
            raise FinancialResponseBundleError(f"payload changed for {path}")
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
            raise FinancialResponseBundleError(
                "manifest provenance differs from the fixed response run"
            )
        descriptors = {item.path: item for item in self._manifest.files}
        if len(descriptors) != len(self._manifest.files) or set(descriptors) != set(
            _PAYLOAD_METADATA
        ):
            raise FinancialResponseBundleError(
                "manifest payload set differs from the fixed response bundle"
            )
        for path, expected in _PAYLOAD_METADATA.items():
            descriptor = descriptors[path]
            if (
                descriptor.media_type != expected.media_type
                or descriptor.role != expected.role
                or descriptor.sensitivity != Sensitivity.SYNTHETIC
                or tuple(descriptor.required_for) != expected.required_for
            ):
                raise FinancialResponseBundleError(
                    f"manifest descriptor metadata differs for {path}"
                )

    def _attestation_ordinal(self, trial_key: str) -> int:
        try:
            return self._attestations[trial_key][0].ordinal
        except KeyError as error:
            raise FinancialResponseBundleError(
                f"trial {trial_key} has no attestation"
            ) from error

    def _validate_cross_references(self) -> None:
        compiled = self.compiled_experiment
        planned = {item.key: item for item in compiled.planned_trials}
        selectors = {cell.key: cell.selector for cell in compiled.cells}
        if (
            len(compiled.cells) != 16
            or {item.trial_key for item in self.trial_records} != set(planned)
        ):
            raise FinancialResponseBundleError(
                "trial records do not exactly cover the compiler plan"
            )
        expected_stage_coordinates = {
            (trial_key, stage)
            for trial_key in planned
            for stage in Stage
        }
        expected_metric_coordinates = {
            (trial_key, metric_id)
            for trial_key in planned
            for metric_id in _METRIC_BINDINGS
        }
        if set(self._stages_by_coordinate) != expected_stage_coordinates:
            raise FinancialResponseBundleError(
                "stage events do not exactly cover every trial and stage"
            )
        if set(self._metrics) != expected_metric_coordinates:
            raise FinancialResponseBundleError(
                "metric observations do not exactly cover every trial and metric"
            )
        if set(self._runtime_observations) != set(planned):
            raise FinancialResponseBundleError(
                "runtime observations do not exactly cover every trial"
            )

        used_runtime_observations: set[str] = set()
        used_stage_digests: set[str] = set()
        used_metric_digests: set[str] = set()
        used_attestations: set[str] = set()
        used_cleanups: set[str] = set()
        clone_ids: set[str] = set()
        trace_ids: set[str] = set()
        scope = compiled.contract.scope
        metric_contracts = {
            metric.id: metric for metric in compiled.contract.metrics
        }

        for record in self.trial_records:
            planned_trial = planned[record.trial_key]
            selector = selectors[planned_trial.cell_key]
            expected_trace_id = (
                f"financial-response-trace-{planned_trial.ordinal:04d}-"
                f"{planned_trial.key[-12:]}"
            )
            expected_clone_id = (
                f"response-sqlite-clone-{planned_trial.ordinal:04d}-"
                f"{planned_trial.key[-12:]}"
            )
            if (
                record.spec_digest != compiled.spec_digest
                or record.cell_key != planned_trial.cell_key
                or record.block != planned_trial.block
                or record.replicate != planned_trial.replicate
                or record.trace.trace_id != expected_trace_id
                or record.clone.unique_instance_id != expected_clone_id
            ):
                raise FinancialResponseBundleError(
                    f"trial {record.trial_key} differs from compiler plan"
                )
            if record.clone.unique_instance_id in clone_ids:
                raise FinancialResponseBundleError("fresh clone id was reused")
            if record.trace.trace_id in trace_ids:
                raise FinancialResponseBundleError("trace id was reused")
            clone_ids.add(record.clone.unique_instance_id)
            trace_ids.add(record.trace.trace_id)

            entry = self._attestations.get(record.trial_key)
            if entry is None:
                raise FinancialResponseBundleError(
                    f"trial {record.trial_key} has no attestation"
                )
            attestation, attestation_digest = entry
            if not _attestation_matches_record(
                attestation,
                attestation_digest,
                record,
            ):
                raise FinancialResponseBundleError(
                    f"trial {record.trial_key} differs from its attestation"
                )
            expected_action = _action_digest_for(selector)
            runtime_observation, runtime_observation_digest = (
                self._runtime_observations[record.trial_key]
            )
            resource = runtime_observation.resource_identity
            if (
                attestation.id
                != f"response-attestation-{planned_trial.ordinal:04d}"
                or attestation.ordinal != planned_trial.ordinal
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
                    planned_trial.block,
                    planned_trial.replicate,
                )
                or attestation.intervention_digest
                != _intervention_digest(selector)
                or attestation.runtime_observation_digest
                != runtime_observation_digest
                or runtime_observation.spec_digest != record.spec_digest
                or runtime_observation.trace_id != record.trace.trace_id
                or runtime_observation.action_digest != expected_action
                or runtime_observation.id
                != f"{record.trial_key}:runtime-observation"
                or resource.requested_clone_nonce
                != record.clone.unique_instance_id
                or resource.observed_clone_nonce
                != record.clone.unique_instance_id
                or resource.requested_runner_resource_id
                != record.clone.runner_resource_id
                or resource.observed_runner_resource_id
                != record.clone.runner_resource_id
            ):
                raise FinancialResponseBundleError(
                    f"trial {record.trial_key} has inconsistent selector or provenance"
                )
            used_attestations.add(record.trial_key)
            used_runtime_observations.add(runtime_observation_digest)

            derived_events = _derived_events(
                selector,
                expected_action,
                runtime_observation,
            )
            for stage, expected in derived_events.items():
                artifact, digest = self._stages_by_coordinate[
                    (record.trial_key, stage)
                ]
                trace_event = record.trace.event_for(stage)
                if not isinstance(trace_event, ExecutedStageEvent):
                    raise FinancialResponseBundleError(
                        f"response stage {stage.value} was unexpectedly skipped"
                    )
                if not _stage_matches_event(
                    artifact,
                    digest,
                    record,
                    trace_event,
                ):
                    raise FinancialResponseBundleError(
                        f"stage {stage.value} differs from trace"
                    )
                sequence, component, event_type, payload = expected
                if (
                    artifact.sequence != sequence
                    or artifact.component != component
                    or artifact.event_type != event_type
                    or artifact.action_digest != expected_action
                    or artifact.runtime_observation_digest
                    != runtime_observation_digest
                    or artifact.payload_pairs() != payload
                ):
                    raise FinancialResponseBundleError(
                        f"stage {stage.value} differs from declared cell semantics"
                    )
                used_stage_digests.add(digest)

            ordered_stages = tuple(
                self._stages_by_coordinate[(record.trial_key, stage)][0]
                for stage in Stage
            )
            if (
                attestation.started_at < scope.evidence_window.start
                or attestation.started_at >= ordered_stages[0].started_at
                or any(
                    previous.ended_at >= current.started_at
                    for previous, current in pairwise(ordered_stages)
                )
                or ordered_stages[-1].ended_at >= attestation.ended_at
                or attestation.ended_at > scope.evidence_window.end
                or attestation.ended_at > scope.assessment_as_of
            ):
                raise FinancialResponseBundleError(
                    f"trial {record.trial_key} has an impossible evidence timeline"
                )

            for metric_id, (stage, field_name, subject_id) in _METRIC_BINDINGS.items():
                observation, observation_digest = self._metrics[
                    (record.trial_key, metric_id)
                ]
                stage_artifact, stage_digest = self._stages_by_coordinate[
                    (record.trial_key, stage)
                ]
                raw_value = stage_artifact.value(field_name)
                if type(raw_value) is not bool:
                    raise FinancialResponseBundleError(
                        f"raw metric {metric_id} is not boolean"
                    )
                metric_contract = metric_contracts[metric_id]
                if (
                    observation.id != f"{record.trial_key}:{metric_id}"
                    or observation.spec_digest != record.spec_digest
                    or observation.trace_id != record.trace.trace_id
                    or observation.event_id != stage_artifact.event_id
                    or observation.event_digest != stage_digest
                    or observation.subject_id != subject_id
                    or observation.component != metric_contract.component
                    or observation.component != stage_artifact.component
                    or observation.stage != metric_contract.stage
                    or observation.stage != stage
                    or observation.observed_at != stage_artifact.ended_at
                    or observation.value.value is not raw_value
                ):
                    raise FinancialResponseBundleError(
                        f"metric {metric_id} differs from its subject or raw event"
                    )
                used_metric_digests.add(observation_digest)

            cleanup_entry = self._cleanups_by_digest.get(
                record.cleanup.evidence_bundle_digest
            )
            if cleanup_entry is None:
                raise FinancialResponseBundleError(
                    f"trial {record.trial_key} has no cleanup evidence"
                )
            cleanup, cleanup_digest = cleanup_entry
            if not _cleanup_matches_record(cleanup, cleanup_digest, record):
                raise FinancialResponseBundleError(
                    f"trial {record.trial_key} differs from cleanup evidence"
                )
            if (
                cleanup.id != f"response-cleanup-{planned_trial.ordinal:04d}"
                or cleanup.runtime_observation_digest
                != runtime_observation_digest
                or cleanup.observed_at <= attestation.ended_at
                or cleanup.observed_at > scope.evidence_window.end
                or cleanup.observed_at > scope.assessment_as_of
            ):
                raise FinancialResponseBundleError(
                    f"trial {record.trial_key} cleanup is not bound to runtime rows"
                )
            used_cleanups.add(cleanup_digest)

        if used_runtime_observations != {
            entry[1] for entry in self._runtime_observations.values()
        }:
            raise FinancialResponseBundleError(
                "bundle contains unbound runtime observations"
            )
        if used_stage_digests != set(self._stages_by_digest):
            raise FinancialResponseBundleError("bundle contains unbound stage events")
        if used_metric_digests != {entry[1] for entry in self._metrics.values()}:
            raise FinancialResponseBundleError(
                "bundle contains unbound metric observations"
            )
        if used_attestations != set(self._attestations):
            raise FinancialResponseBundleError(
                "bundle contains unbound trial attestations"
            )
        if used_cleanups != set(self._cleanups_by_digest):
            raise FinancialResponseBundleError(
                "bundle contains unbound cleanup observations"
            )

    def _verify_attestation(self, record: TrialRecord) -> TrialAttestationResult:
        entry = self._attestations.get(record.trial_key)
        if entry is None:
            return TrialAttestationFailure(
                status="missing",
                reason="bundle has no attestation for the trial",
            )
        artifact, digest = entry
        if not _attestation_matches_record(artifact, digest, record):
            return TrialAttestationFailure(
                status="rejected",
                reason="attestation does not bind the supplied trial",
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

    def _verify_metric(self, binding: EvidenceBinding) -> MetricEvidenceResult:
        entry = self._metrics.get((binding.trial_key, binding.metric_id))
        if entry is None:
            return MetricEvidenceFailure(
                status="missing",
                reason="bundle has no requested metric observation",
            )
        artifact, digest = entry
        if (
            artifact.spec_digest != binding.spec_digest
            or artifact.trial_key != binding.trial_key
            or artifact.trace_id != binding.trace_id
            or artifact.event_id != binding.event_id
            or artifact.event_digest != binding.evidence_bundle_digest
            or artifact.stage != binding.stage
        ):
            return MetricEvidenceFailure(
                status="rejected",
                reason="metric observation does not bind the requested stage",
                artifact_ids=(digest,),
            )
        return AdmittedMetricEvidence(
            evidence_id=_admission_id("metric", binding, digest),
            binding=binding,
            value=artifact.value,
            observed_at=artifact.observed_at,
            artifact_ids=(artifact.event_digest, digest),
        )

    def _verify_cleanup(self, binding: CleanupBinding) -> CleanupVerificationResult:
        entry = self._cleanups_by_digest.get(binding.evidence_bundle_digest)
        if entry is None:
            return CleanupEvidenceFailure(
                status="missing",
                reason="bundle has no requested cleanup observation",
            )
        artifact, digest = entry
        if (
            artifact.spec_digest != binding.spec_digest
            or artifact.trial_key != binding.trial_key
            or artifact.trace_id != binding.trace_id
            or artifact.clone_unique_instance_id
            != binding.clone_unique_instance_id
            or artifact.runner_resource_id != binding.runner_resource_id
            or artifact.outcome_ended_at != binding.outcome_ended_at
            or digest != binding.evidence_bundle_digest
        ):
            return CleanupEvidenceFailure(
                status="rejected",
                reason="cleanup observation does not bind the requested trial",
                artifact_ids=(digest,),
            )
        return AdmittedCleanupEvidence(
            state=CleanupState.VERIFIED,
            binding=binding,
            evidence_id=_admission_id("cleanup", binding, digest),
            observed_at=artifact.observed_at,
            artifact_ids=(digest,),
        )


_METRIC_BINDINGS: dict[str, tuple[Stage, str, str]] = {
    "compromised-session-active": (
        Stage.TARGET,
        "compromised_session_active",
        COMPROMISED_SESSION_ID,
    ),
    "non-target-sessions-active": (
        Stage.TARGET,
        "non_target_sessions_active",
        f"all-sessions-except-{COMPROMISED_SESSION_ID}",
    ),
    "response-action-reported-success": (
        Stage.TARGET,
        "response_action_reported_success",
        COMPROMISED_SESSION_ID,
    ),
    "compromised-principal-quarantined": (
        Stage.COMPENSATOR,
        "compromised_principal_quarantined",
        COMPROMISED_PRINCIPAL_ID,
    ),
    "compromised-session-replay-denied": (
        Stage.OUTCOME,
        "compromised_session_replay_denied",
        COMPROMISED_SESSION_ID,
    ),
    "unrelated-support-principal-available": (
        Stage.OUTCOME,
        "unrelated_support_principal_available",
        UNRELATED_PRINCIPAL_ID,
    ),
}


def _action_digest_for(selector: CellSelector) -> str:
    return ATTACK_ACTION_DIGEST if selector.input == ATTACK else BENIGN_ACTION_DIGEST


def _modified_set_evidence(session_ids: tuple[str, ...]) -> tuple[str, str]:
    value = {
        "schema": "assurance-lab.modified-session-set/v1",
        "session_ids": list(session_ids),
    }
    canonical = canonical_json_bytes(value)
    return canonical.decode("utf-8"), _sha256(canonical)


def _derived_events(
    selector: CellSelector,
    action_digest: str,
    observation: FinancialResponseRuntimeObservationArtifact,
) -> dict[
    Stage,
    tuple[int, str, str, tuple[tuple[str, Scalar], ...]],
]:
    attack = selector.input == ATTACK
    sham_level = _selector_text(selector.sham, "sham")
    expected_sham_operation: Literal["steady-observation", "reload"] = (
        "reload"
        if sham_level == SHAM_RELOAD.value
        else "steady-observation"
    )
    expected_after_generation = (
        1 if expected_sham_operation == "reload" else 0
    )
    expected_sham_rows = 1 if expected_sham_operation == "reload" else 0
    responder_before = observation.responder_before_sham
    responder_after = observation.responder_after_sham
    sham_receipt = observation.sham_operation
    before_readback = ResponderRuntimeReadback(
        clone_nonce=responder_before.clone_nonce,
        instance_id=responder_before.instance_id,
        generation=responder_before.generation,
        config_digest=responder_before.config_digest,
    )
    after_readback = ResponderRuntimeReadback(
        clone_nonce=responder_after.clone_nonce,
        instance_id=responder_after.instance_id,
        generation=responder_after.generation,
        config_digest=responder_after.config_digest,
    )
    resource = observation.resource_identity
    if (
        responder_before.clone_nonce != resource.observed_clone_nonce
        or responder_after.clone_nonce != resource.observed_clone_nonce
        or responder_before.generation != 0
        or responder_after.generation != expected_after_generation
        or responder_before.config_digest != RESPONDER_CONFIG_DIGEST
        or responder_after.config_digest != RESPONDER_CONFIG_DIGEST
        or responder_before.instance_id
        != _expected_responder_instance_id(
            resource.observed_clone_nonce,
            0,
        )
        or responder_after.instance_id
        != _expected_responder_instance_id(
            resource.observed_clone_nonce,
            expected_after_generation,
        )
        or sham_receipt.operation != expected_sham_operation
        or sham_receipt.operation_id
        != _expected_sham_operation_id(
            expected_sham_operation,
            before_readback,
            after_readback,
        )
        or sham_receipt.clone_nonce != resource.observed_clone_nonce
        or sham_receipt.before_instance_id != responder_before.instance_id
        or sham_receipt.after_instance_id != responder_after.instance_id
        or sham_receipt.before_generation != responder_before.generation
        or sham_receipt.after_generation != responder_after.generation
        or sham_receipt.config_digest != RESPONDER_CONFIG_DIGEST
        or sham_receipt.rows_affected != expected_sham_rows
    ):
        raise FinancialResponseBundleError(
            "raw responder configuration or generation transition differs "
            "from the planned intervention"
        )

    expected_target_operation = (
        "revoke-exact"
        if attack and selector.target == TARGET_EFFECTIVE
        else "report-only"
        if attack
        else "not-triggered"
    )
    expected_response_status: Literal["not-triggered", "reported-success"] = (
        "reported-success" if attack else "not-triggered"
    )
    expected_compensator_operation = (
        "quarantine"
        if attack and selector.compensator == COMPENSATOR_ON
        else "not-triggered"
    )
    target_receipt = observation.target_mutation
    compensator_receipt = observation.compensator_mutation
    response_receipt = observation.response_action
    if (
        response_receipt.operation_id
        != _expected_response_action_operation_id(
            trace_id=observation.trace_id,
            action_digest=action_digest,
            target_mode=_selector_text(selector.target, "target"),
            responder_instance_id=responder_after.instance_id,
        )
        or response_receipt.responder_instance_id
        != responder_after.instance_id
        or response_receipt.trace_id != observation.trace_id
        or response_receipt.action_digest != action_digest
        or response_receipt.target_mode
        != _selector_text(selector.target, "target")
        or response_receipt.principal_id != COMPROMISED_PRINCIPAL_ID
        or response_receipt.session_id != COMPROMISED_SESSION_ID
        or response_receipt.operation != expected_target_operation
        or response_receipt.status != expected_response_status
        or response_receipt.rows_affected != target_receipt.rows_affected
        or target_receipt.component != "session-revoker"
        or target_receipt.operation != expected_target_operation
        or target_receipt.principal_id != COMPROMISED_PRINCIPAL_ID
        or target_receipt.session_id != COMPROMISED_SESSION_ID
        or compensator_receipt.component != "principal-quarantine"
        or compensator_receipt.operation != expected_compensator_operation
        or compensator_receipt.principal_id != COMPROMISED_PRINCIPAL_ID
        or compensator_receipt.session_id is not None
    ):
        raise FinancialResponseBundleError(
            "runtime mutation receipts differ from the planned interventions"
        )

    before_sessions = _session_state_map(observation.sessions_before_target)
    target_sessions = _session_state_map(observation.sessions_after_target)
    compensator_sessions = _session_state_map(
        observation.sessions_after_compensator
    )
    before_principals = _principal_state_map(observation.principals_before_target)
    target_principals = _principal_state_map(observation.principals_after_target)
    compensator_principals = _principal_state_map(
        observation.principals_after_compensator
    )
    expected_session_subjects = {
        COMPROMISED_SESSION_ID: COMPROMISED_PRINCIPAL_ID,
        SIBLING_SESSION_ID: COMPROMISED_PRINCIPAL_ID,
        UNRELATED_SESSION_ID: UNRELATED_PRINCIPAL_ID,
    }
    expected_principal_roles = {
        COMPROMISED_PRINCIPAL_ID: "support",
        UNRELATED_PRINCIPAL_ID: "support",
    }
    if (
        {key: value[0] for key, value in before_sessions.items()}
        != expected_session_subjects
        or {key: value[0] for key, value in target_sessions.items()}
        != expected_session_subjects
        or {key: value[0] for key, value in compensator_sessions.items()}
        != expected_session_subjects
        or {key: value[0] for key, value in before_principals.items()}
        != expected_principal_roles
        or {key: value[0] for key, value in target_principals.items()}
        != expected_principal_roles
        or {key: value[0] for key, value in compensator_principals.items()}
        != expected_principal_roles
    ):
        raise FinancialResponseBundleError(
            "runtime observation rows differ from the fixed identity snapshot"
        )
    if (
        not all(value[1] for value in before_sessions.values())
        or any(value[1] for value in before_principals.values())
    ):
        raise FinancialResponseBundleError(
            "runtime observation differs from the fixed initial state"
        )

    expected_target_sessions = dict(before_sessions)
    if attack and selector.target == TARGET_EFFECTIVE:
        expected_target_sessions[COMPROMISED_SESSION_ID] = (
            COMPROMISED_PRINCIPAL_ID,
            False,
        )
    expected_compensator_principals = dict(before_principals)
    if attack and selector.compensator == COMPENSATOR_ON:
        expected_compensator_principals[COMPROMISED_PRINCIPAL_ID] = (
            "support",
            True,
        )
    if (
        target_sessions != expected_target_sessions
        or target_principals != before_principals
        or compensator_sessions != target_sessions
        or compensator_principals != expected_compensator_principals
    ):
        raise FinancialResponseBundleError(
            "runtime before/after rows differ from the fixed response transitions"
        )

    target_modified = tuple(
        session_id
        for session_id in sorted(before_sessions)
        if before_sessions[session_id] != target_sessions[session_id]
    )
    compensator_modified = tuple(
        session_id
        for session_id in sorted(target_sessions)
        if target_sessions[session_id] != compensator_sessions[session_id]
    )
    principal_modified = tuple(
        principal_id
        for principal_id in sorted(target_principals)
        if target_principals[principal_id] != compensator_principals[principal_id]
    )
    if (
        target_receipt.rows_affected != len(target_modified)
        or compensator_receipt.rows_affected != len(principal_modified)
        or target_receipt.rows_affected
        != (1 if attack and selector.target == TARGET_EFFECTIVE else 0)
        or compensator_receipt.rows_affected
        != (1 if attack and selector.compensator == COMPENSATOR_ON else 0)
        or compensator_modified
    ):
        raise FinancialResponseBundleError(
            "runtime mutation row count differs from before/after readback"
        )
    target_modified_canonical, target_modified_digest = _modified_set_evidence(
        target_modified
    )
    compensator_modified_canonical, compensator_modified_digest = (
        _modified_set_evidence(compensator_modified)
    )
    gateway = {item.query_id: item for item in observation.gateway_decisions}
    if set(gateway) != {
        "probe-compromised-session-replay",
        "probe-unrelated-support-action",
    }:
        raise FinancialResponseBundleError(
            "runtime observation has the wrong gateway query receipts"
        )
    replay = gateway["probe-compromised-session-replay"]
    unrelated = gateway["probe-unrelated-support-action"]
    for receipt, principal_id, session_id in (
        (
            replay,
            COMPROMISED_PRINCIPAL_ID,
            COMPROMISED_SESSION_ID,
        ),
        (
            unrelated,
            UNRELATED_PRINCIPAL_ID,
            UNRELATED_SESSION_ID,
        ),
    ):
        session = compensator_sessions[session_id]
        principal = compensator_principals[principal_id]
        if (
            receipt.principal_id != principal_id
            or receipt.session_id != session_id
            or not receipt.session_found
            or not receipt.principal_found
            or receipt.session_revoked != (not session[1])
            or receipt.principal_quarantined != principal[1]
        ):
            raise FinancialResponseBundleError(
                "gateway query receipt differs from final identity rows"
            )

    compromised_active = target_sessions[COMPROMISED_SESSION_ID][1]
    non_target_active = all(
        value[1]
        for session_id, value in target_sessions.items()
        if session_id != COMPROMISED_SESSION_ID
    )
    quarantined = compensator_principals[COMPROMISED_PRINCIPAL_ID][1]
    exact_revoke_executed = target_receipt.operation == "revoke-exact"
    quarantine_applied = compensator_receipt.operation == "quarantine"
    action = action_descriptor(ATTACK if attack else BENIGN)
    return {
        Stage.INPUT: (
            1,
            "identity-gateway",
            "action-issued",
            (
                ("action", str(action["action"])),
                ("action_digest", action_digest),
                ("sham", sham_level),
            ),
        ),
        Stage.TARGET: (
            2,
            "session-revoker",
            "response-and-session-readback",
            (
                ("target_mode", _selector_text(selector.target, "target")),
                ("target_principal_id", COMPROMISED_PRINCIPAL_ID),
                ("target_session_id", COMPROMISED_SESSION_ID),
                (
                    "response_action_status",
                    response_receipt.status,
                ),
                (
                    "response_action_reported_success",
                    response_receipt.status == "reported-success",
                ),
                ("exact_revocation_executed", exact_revoke_executed),
                ("compromised_session_active", compromised_active),
                ("non_target_sessions_active", non_target_active),
                ("target_modified_session_count", len(target_modified)),
                (
                    "target_modified_session_ids_canonical",
                    target_modified_canonical,
                ),
                ("target_modified_session_ids_digest", target_modified_digest),
            ),
        ),
        Stage.COMPENSATOR: (
            3,
            "principal-quarantine",
            "quarantine-readback",
            (
                (
                    "compensator_mode",
                    _selector_text(selector.compensator, "compensator"),
                ),
                ("quarantine_principal_id", COMPROMISED_PRINCIPAL_ID),
                ("quarantine_applied", quarantine_applied),
                ("compromised_principal_quarantined", quarantined),
                ("compensator_modified_session_count", len(compensator_modified)),
                (
                    "compensator_modified_session_ids_canonical",
                    compensator_modified_canonical,
                ),
                (
                    "compensator_modified_session_ids_digest",
                    compensator_modified_digest,
                ),
            ),
        ),
        Stage.OUTCOME: (
            4,
            "identity-gateway",
            "availability-observed",
            (
                ("compromised_session_replay_denied", not replay.available),
                (
                    "unrelated_support_principal_available",
                    unrelated.available,
                ),
            ),
        ),
    }


def _session_state_map(
    rows: tuple[_SessionRow, ...],
) -> dict[str, tuple[str, bool]]:
    return {
        row.session_id: (row.principal_id, row.active)
        for row in rows
    }


def _principal_state_map(
    rows: tuple[_PrincipalRow, ...],
) -> dict[str, tuple[str, bool]]:
    return {
        row.principal_id: (row.role, row.quarantined)
        for row in rows
    }


def _selector_text(value: object, axis: str) -> str:
    if not isinstance(value, StringValue):
        raise FinancialResponseBundleError(
            f"response {axis} selector must be a string value"
        )
    return value.value


def evaluate_financial_response_bundle(
    repository: FinancialResponseBundleRepository,
) -> FinancialResponseBundleAssessment:
    """Run generic inference and independently recompute the shallow response check."""

    report = ExperimentEvaluator().evaluate(
        repository.compiled_experiment,
        repository.trial_records,
        repository,
        repository,
        repository,
    )
    compiled = repository.compiled_experiment
    selectors = {cell.key: cell.selector for cell in compiled.cells}
    current_keys = tuple(
        trial.key
        for trial in compiled.planned_trials
        if selectors[trial.cell_key] == compiled.current_selector
    )
    if not current_keys:
        raise FinancialResponseBundleError("compiled plan has no current response cell")

    status_success = all(
        repository.metric_value(key, "response-action-reported-success")
        for key in current_keys
    )
    replay_denied = all(
        repository.metric_value(key, "compromised-session-replay-denied")
        for key in current_keys
    )
    target_supported = all(
        not repository.metric_value(key, "compromised-session-active")
        for key in current_keys
    )
    compensator_supported = all(
        repository.metric_value(key, "compromised-principal-quarantined")
        for key in current_keys
    )
    path_supported = replay_denied
    benign_keys = tuple(
        trial.key
        for trial in compiled.planned_trials
        if selectors[trial.cell_key].input == BENIGN
    )
    benign_supported = bool(benign_keys) and all(
        repository.metric_value(key, "unrelated-support-principal-available")
        for key in benign_keys
    )
    if (
        not target_supported
        and compensator_supported
        and path_supported
        and benign_supported
    ):
        classification = ResponseResidualClassification.MASKED_REVOCATION_FAILURE
    elif not path_supported:
        classification = ResponseResidualClassification.EXPOSED_REPLAY
    elif target_supported and path_supported and benign_supported:
        classification = ResponseResidualClassification.TARGET_EFFECTIVE
    else:
        classification = ResponseResidualClassification.UNRESOLVED
    response_case = ResponseCaseAssessment(
        baseline=ResponseStatusAndReplayBaseline(
            name="response-status-and-replay-only",
            verdict=(
                BaselineVerdict.PASS
                if status_success and replay_denied
                else BaselineVerdict.FAIL
            ),
            response_action_reported_success=status_success,
            replay_denied=replay_denied,
        ),
        target_supported=target_supported,
        compensator_supported=compensator_supported,
        path_supported=path_supported,
        benign_service_supported=benign_supported,
        residual_classification=classification,
    )
    return FinancialResponseBundleAssessment(
        report=report,
        response_case=response_case,
    )


class _ReferenceClock:
    def __init__(self, start: datetime) -> None:
        self._next = start

    def __call__(self) -> datetime:
        result = self._next
        self._next += timedelta(milliseconds=1)
        return result


def build_reference_financial_response_experiment(
    *,
    start: datetime = datetime(2026, 7, 29, 0, 0, tzinfo=UTC),
) -> tuple[FinancialResponseExperimentRunner, CompiledExperiment]:
    """Build the deterministic reference runner and compiler-owned plan."""

    if start.tzinfo is None or start.utcoffset() is None:
        raise ValueError("reference start must be timezone-aware")
    start = start.astimezone(UTC)
    runner = FinancialResponseExperimentRunner(
        clock=_ReferenceClock(start + timedelta(seconds=1)),
        time_basis="simulated",
    )
    scope = ExperimentScope(
        scenario_id=SCENARIO_ID,
        build_digest=runner.build_digest,
        dataset_digest=runner.dataset_digest,
        fixture_digest=runner.fixture_digest,
        assessment_as_of=start + timedelta(minutes=30),
        evidence_window=EvidenceWindow(
            start=start,
            end=start + timedelta(hours=1),
        ),
        evidence_policy=EvidencePolicyRef(
            id="financial-response-bundle-v1",
            version="1.0.0",
            digest=_EVIDENCE_POLICY_DIGEST,
        ),
    )
    compiled = compile_experiment(
        build_financial_response_contract(
            scope=scope,
            plan=TrialPlan(
                blocks=("sqlite-fresh-clone",),
                replicates=1,
                order_seed="financial-response-reference-seed",
            ),
        )
    )
    return runner, compiled


def write_reference_financial_response_bundle(
    destination: Path,
    *,
    start: datetime = datetime(2026, 7, 29, 0, 0, tzinfo=UTC),
) -> tuple[CompiledExperiment, BundleVerification]:
    """Write deterministic reference evidence without editing checked-in examples."""

    runner, compiled = build_reference_financial_response_experiment(start=start)
    return compiled, runner.run(compiled, destination)


def _parse_jsonl_models[ModelT: BaseModel](
    content: bytes,
    model_type: type[ModelT],
) -> tuple[tuple[ModelT, str], ...]:
    try:
        values = strict_jsonl_loads(content, require_sorted_ids=True)
        return tuple(
            (
                model_type.model_validate_json(
                    canonical_json_bytes(value),
                    strict=True,
                ),
                _sha256(canonical_json_bytes(value)),
            )
            for value in values
        )
    except (TypeError, ValueError) as error:
        raise FinancialResponseBundleError(
            f"bundle JSONL failed strict validation: {error}"
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
            raise FinancialResponseBundleError(f"duplicate {label}: {identity!r}")
        result[identity] = entry
    return result


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
    artifact: FinancialResponseStageArtifact,
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
