"""Bundle-backed execution of the compiled financial-support experiment."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Hashable
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
    strict_jsonl_loads,
)
from assurance_lab.evidence.writer import (
    BundleMetadata,
    PayloadFile,
    write_bundle,
)
from assurance_lab.scenarios.financial_data import SyntheticDataset
from assurance_lab.scenarios.financial_support_contract import (
    ATTACK_ACTION_DIGEST,
    BENIGN_ACTION_DIGEST,
    SCENARIO_ID,
)
from assurance_lab.scenarios.financial_support_runtime import (
    FinancialSupportRuntime,
    RuntimeEvent,
)

Digest = Annotated[str, Field(pattern=DIGEST_PATTERN)]
Scalar = str | int | bool
TimeBasis = Literal["wall-clock-observation", "simulated"]

_STAGE_PATH = "records/stage-events.jsonl"
_ATTESTATION_PATH = "artifacts/trial-attestations.jsonl"
_CLEANUP_PATH = "artifacts/cleanup-observations.jsonl"
_TRIAL_PATH = "records/trial-records.jsonl"
_SPEC_PATH = "spec/experiment.json"
_DATASET_PATH = "spec/dataset-manifest.json"
_FIXTURE_PATH = "spec/fixture-manifest.json"
_RUNNER_RESOURCE_ID = "financial-support-sqlite-runner"
_BUILD_DESCRIPTOR = {
    "schema": "assurance-lab.financial-support-runtime-build/v1",
    "implementation": "assurance_lab.scenarios.financial_support_runtime",
    "database": "sqlite-memory",
}


def _sha256(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _digest_value(value: object) -> str:
    return _sha256(canonical_json_bytes(value))


FINANCIAL_SUPPORT_RUNTIME_BUILD_DIGEST = _digest_value(_BUILD_DESCRIPTOR)


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


class _FixtureManifestArtifact(_ArtifactModel):
    schema_id: Literal["assurance-lab.financial-support-fixture/v1"] = Field(alias="schema")
    dataset: _DatasetManifestArtifact
    bulk_threshold_records: Literal[10]
    attack_action_digest: Digest
    benign_action_digest: Digest

    @model_validator(mode="after")
    def fixed_actions(self) -> _FixtureManifestArtifact:
        if (
            self.attack_action_digest != ATTACK_ACTION_DIGEST
            or self.benign_action_digest != BENIGN_ACTION_DIGEST
        ):
            raise ValueError("fixture manifest action digests do not match the scenario")
        return self


class StageDatum(_ArtifactModel):
    name: str = Field(min_length=1)
    value: Scalar


class FinancialSupportStageArtifact(_ArtifactModel):
    """One raw runtime stage observation, before metric extraction."""

    id: str = Field(min_length=1)
    schema_name: Literal["assurance-lab.financial-support-stage/v1"]
    spec_digest: Digest
    trial_key: Digest
    trace_id: str = Field(min_length=1)
    event_id: str = Field(min_length=1)
    action_digest: Digest
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
    runner_resource_id: str = Field(min_length=1)
    observed_build_digest: Digest
    observed_dataset_digest: Digest
    observed_fixture_digest: Digest
    observed_selector: CellSelector
    base_snapshot_digest: Digest
    covariate_digest: Digest
    intervention_digest: Digest
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
    runner_resource_id: str = Field(min_length=1)
    outcome_ended_at: AwareDatetime
    observed_at: AwareDatetime
    state: Literal["verified"]
    method: Literal["sqlite-memory-connection-closed"]
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


def _payload(
    path: str,
    models: tuple[BaseModel, ...],
    *,
    role: str,
    required_for: tuple[str, ...],
) -> PayloadFile:
    return PayloadFile(
        path=path,
        content=canonical_jsonl_bytes(_artifact_dict(model) for model in models),
        media_type="application/x-ndjson",
        role=role,
        sensitivity=Sensitivity.SYNTHETIC,
        required_for=required_for,
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
        self._dataset_manifest = dataset.manifest()
        self.build_digest = FINANCIAL_SUPPORT_RUNTIME_BUILD_DIGEST
        self.dataset_digest = f"sha256:{self._dataset_manifest['logical_digest']}"
        self._fixture_manifest = {
            "schema": "assurance-lab.financial-support-fixture/v1",
            "dataset": self._dataset_manifest,
            "bulk_threshold_records": bulk_threshold_records,
            "attack_action_digest": ATTACK_ACTION_DIGEST,
            "benign_action_digest": BENIGN_ACTION_DIGEST,
        }
        self.fixture_digest = _digest_value(self._fixture_manifest)

    def run(
        self,
        compiled: CompiledExperiment,
        destination: Path,
    ) -> BundleVerification:
        compiled = self._validated_compiled(compiled)
        cells = {cell.key: cell.selector for cell in compiled.cells}
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
            result = self._runtime.execute(selector, trace_id=trace_id)
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
            clone_id = f"sqlite-clone-{planned.ordinal:04d}-{planned.key[-12:]}"
            base_snapshot_digest = self.dataset_digest
            covariate_digest = _digest_value(
                {
                    "schema": "assurance-lab.financial-support-covariate/v1",
                    "fixture_digest": self.fixture_digest,
                    "block": planned.block,
                    "replicate": planned.replicate,
                }
            )
            intervention_digest = _digest_value(
                {
                    "schema": "assurance-lab.financial-support-intervention/v1",
                    "selector": selector.model_dump(mode="json"),
                }
            )
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
            cleanup = _CleanupArtifact(
                id=f"cleanup-{planned.ordinal:04d}",
                schema_name="assurance-lab.financial-support-cleanup/v1",
                spec_digest=compiled.spec_digest,
                trial_key=planned.key,
                trace_id=trace_id,
                clone_unique_instance_id=clone_id,
                runner_resource_id=_RUNNER_RESOURCE_ID,
                outcome_ended_at=outcome_event.ended_at,
                observed_at=cleanup_observed_at,
                state="verified",
                method="sqlite-memory-connection-closed",
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
            PayloadFile(
                path=_SPEC_PATH,
                content=compiled.canonical_spec.encode("utf-8"),
                media_type="application/json",
                role="compiler-owned experiment specification",
                sensitivity=Sensitivity.SYNTHETIC,
                required_for=("design", "evaluation"),
            ),
            PayloadFile(
                path=_DATASET_PATH,
                content=canonical_json_bytes(self._dataset_manifest),
                media_type="application/json",
                role="synthetic dataset manifest",
                sensitivity=Sensitivity.SYNTHETIC,
                required_for=("scope", "attestation"),
            ),
            PayloadFile(
                path=_FIXTURE_PATH,
                content=canonical_json_bytes(self._fixture_manifest),
                media_type="application/json",
                role="financial-support executable fixture manifest",
                sensitivity=Sensitivity.SYNTHETIC,
                required_for=("scope", "attestation"),
            ),
            _payload(
                _STAGE_PATH,
                tuple(stages),
                role="raw SQLite runtime stage observations",
                required_for=("metric-extraction", "trace-lineage"),
            ),
            _payload(
                _ATTESTATION_PATH,
                tuple(attestations),
                role="raw trial attestations",
                required_for=("trial-admission",),
            ),
            _payload(
                _CLEANUP_PATH,
                tuple(cleanups),
                role="raw cleanup observations",
                required_for=("cleanup-admission",),
            ),
            _payload(
                _TRIAL_PATH,
                tuple(stored_trials),
                role="metric-free trial records",
                required_for=("evaluation",),
            ),
        )
        return write_bundle(
            destination,
            metadata=BundleMetadata(
                created_at=_utc_now(),
                as_of=scope.assessment_as_of,
                experiment=ExperimentRef(
                    id=compiled.contract.id,
                    spec_version=compiled.contract.version,
                    spec_digest=compiled.spec_digest,
                ),
                evaluation=EvaluationRef(
                    policy_id=scope.evidence_policy.id,
                    policy_digest=scope.evidence_policy.digest,
                    evaluator=EvaluatorRef(
                        name="assurance-lab",
                        version="0.0.1",
                        source_revision="financial-support-e2e-simulated-v1",
                        image_digest=None,
                    ),
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
        if clean.contract.id != SCENARIO_ID:
            raise FinancialSupportBundleError(f"runner only supports scenario {SCENARIO_ID!r}")
        if len(clean.planned_trials) != 16:
            raise FinancialSupportBundleError(
                "financial-support runner requires exactly 16 planned trials"
            )
        scope = clean.contract.scope
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

        dataset_bytes = self._read_rehashed(_DATASET_PATH)
        fixture_bytes = self._read_rehashed(_FIXTURE_PATH)
        try:
            dataset_manifest = _DatasetManifestArtifact.model_validate_json(
                dataset_bytes,
                strict=True,
            )
            fixture_manifest = _FixtureManifestArtifact.model_validate_json(
                fixture_bytes,
                strict=True,
            )
        except ValueError as error:
            raise FinancialSupportBundleError(
                f"bundle provenance manifest failed strict validation: {error}"
            ) from error
        if (
            canonical_json_bytes(dataset_manifest.model_dump(mode="json", by_alias=True))
            != dataset_bytes
            or canonical_json_bytes(fixture_manifest.model_dump(mode="json", by_alias=True))
            != fixture_bytes
        ):
            raise FinancialSupportBundleError(
                "bundle provenance manifest differs from its strict canonical model"
            )
        if fixture_manifest.dataset != dataset_manifest:
            raise FinancialSupportBundleError(
                "fixture manifest embeds a different dataset manifest"
            )
        self.dataset_digest = f"sha256:{dataset_manifest.logical_digest}"
        self.fixture_digest = _sha256(fixture_bytes)
        if (
            self.dataset_digest != scope.dataset_digest
            or self.fixture_digest != scope.fixture_digest
        ):
            raise FinancialSupportBundleError(
                "dataset or fixture manifest digest does not match the bundled contract scope"
            )
        if scope.build_digest != FINANCIAL_SUPPORT_RUNTIME_BUILD_DIGEST:
            raise FinancialSupportBundleError(
                "bundled contract build digest does not match the executable runtime"
            )
        if _sha256(spec) != self._manifest.experiment.spec_digest:
            raise FinancialSupportBundleError(
                "canonical experiment bytes do not match the manifest spec digest"
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

    def _attestation_ordinal(self, trial_key: str) -> int:
        try:
            return self._attestations[trial_key][0].ordinal
        except KeyError as error:
            raise FinancialSupportBundleError(
                f"trial {trial_key} has no raw attestation"
            ) from error

    def _validate_cross_references(self) -> None:
        planned_by_key = {trial.key: trial for trial in self.compiled_experiment.planned_trials}
        cells_by_key = {cell.key: cell.selector for cell in self.compiled_experiment.cells}
        if {record.trial_key for record in self.trial_records} != set(planned_by_key):
            raise FinancialSupportBundleError(
                "trial records do not exactly cover the bundled compiler plan"
            )
        used_stage_digests: set[str] = set()
        used_attestations: set[str] = set()
        used_cleanups: set[str] = set()
        for record in self.trial_records:
            planned = planned_by_key[record.trial_key]
            if (
                record.spec_digest != self.compiled_experiment.spec_digest
                or record.cell_key != planned.cell_key
                or record.block != planned.block
                or record.replicate != planned.replicate
            ):
                raise FinancialSupportBundleError(
                    f"trial {record.trial_key} disagrees with the bundled compiler plan"
                )
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
            ):
                raise FinancialSupportBundleError(
                    f"trial {record.trial_key} disagrees with its raw attestation"
                )
            scope = self.compiled_experiment.contract.scope
            if (
                attestation.ordinal != planned.ordinal
                or attestation.observed_selector != cells_by_key[planned.cell_key]
                or attestation.observed_build_digest != scope.build_digest
                or attestation.observed_dataset_digest != self.dataset_digest
                or attestation.observed_fixture_digest != self.fixture_digest
                or attestation.base_snapshot_digest != self.dataset_digest
                or record.clone.base_snapshot_digest != self.dataset_digest
                or attestation.time_basis != self.time_basis
            ):
                raise FinancialSupportBundleError(
                    f"trial {record.trial_key} has inconsistent scope or provenance"
                )
            used_attestations.add(record.trial_key)

            for event in _executed_trace_events(record.trace):
                entry = self._stages_by_digest.get(event.evidence_bundle_digest)
                if entry is None:
                    raise FinancialSupportBundleError(
                        f"event {event.event_id} has no content-addressed stage artifact"
                    )
                artifact, digest = entry
                if not _stage_matches_event(artifact, digest, record, event):
                    raise FinancialSupportBundleError(
                        f"event {event.event_id} disagrees with its stage artifact"
                    )
                if artifact.time_basis != self.time_basis:
                    raise FinancialSupportBundleError(
                        f"event {event.event_id} uses a different time basis"
                    )
                used_stage_digests.add(digest)

            cleanup_entry = self._cleanups_by_digest.get(record.cleanup.evidence_bundle_digest)
            if cleanup_entry is None:
                raise FinancialSupportBundleError(
                    f"trial {record.trial_key} has no cleanup artifact"
                )
            cleanup, cleanup_digest = cleanup_entry
            if not _cleanup_matches_record(cleanup, cleanup_digest, record):
                raise FinancialSupportBundleError(
                    f"trial {record.trial_key} disagrees with its cleanup artifact"
                )
            if cleanup.time_basis != self.time_basis:
                raise FinancialSupportBundleError(
                    f"trial {record.trial_key} cleanup uses a different time basis"
                )
            used_cleanups.add(cleanup_digest)

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
