"""Bind one independently verified connector capture into a portable CAB.

The vendor connectors deliberately return two different things:

* an exact receipt containing the source exchanges; and
* canonical JSONL records recomputed from those exchanges.

This module keeps that distinction when the capture enters the evidence plane.
It never treats a collector-supplied count or digest as a verdict.  A caller
provides an externally anchored receipt verifier, and both the writer and the
reader invoke it before accepting the bundle.

The resulting CAB can be handed to the existing DSSE/admission/custody
boundary.  This profile is intentionally a *capture* profile: it proves which
bounded source response was collected for one authorized request.  It does not
by itself claim that the source was honest or that a security control worked.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

from assurance_lab._version import __version__
from assurance_lab.connectors.contract import (
    ConnectorCapture,
    ConnectorDescriptor,
    VerifiedConnectorCapture,
)
from assurance_lab.evidence.bundle import (
    BundleLimits,
    BundleManifest,
    BundleStatus,
    EvaluationRef,
    EvaluatorRef,
    ExperimentRef,
    Sensitivity,
)
from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)
from assurance_lab.evidence.snapshot import (
    SealedCABSnapshot,
    capture_cab_snapshot,
    decode_cab_snapshot_entries,
)
from assurance_lab.evidence.stream_snapshot import (
    StreamSnapshotLimits,
    capture_streamed_cab_snapshot,
    read_streamed_cab_snapshot_entries,
    verify_streamed_cab_snapshot,
)
from assurance_lab.evidence.writer import (
    BundleMetadata,
    PayloadFile,
    write_bundle,
)

CONNECTOR_EVIDENCE_JOB_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.connector-evidence-job.v1+json"]
] = "application/vnd.control-assurance.connector-evidence-job.v1+json"
CONNECTOR_EVIDENCE_POLICY_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.connector-evidence-policy.v1+json"]
] = "application/vnd.control-assurance.connector-evidence-policy.v1+json"
CONNECTOR_EVIDENCE_VERIFICATION_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.connector-evidence-verification.v1+json"]
] = "application/vnd.control-assurance.connector-evidence-verification.v1+json"
CONNECTOR_EVIDENCE_SCHEMA_VERSION: Final[Literal["1.0.0"]] = "1.0.0"
CONNECTOR_EVIDENCE_SPEC_VERSION: Final[Literal["1.0.0"]] = "1.0.0"
CONNECTOR_EVIDENCE_EVALUATOR_ID: Final[
    Literal["control-assurance-lab/connector-evidence-v1"]
] = "control-assurance-lab/connector-evidence-v1"

# One evidence-plane contract covers the largest currently declared Elastic
# Security and Defender XDR captures.  Vendor modules must not silently widen
# this profile: adding a larger connector requires an intentional profile
# revision here.
MAX_CONNECTOR_EVIDENCE_RECEIPT_BYTES: Final = 96 * 1024 * 1024
MAX_CONNECTOR_EVIDENCE_RECORD_BYTES: Final = 64 * 1024 * 1024
MAX_CONNECTOR_EVIDENCE_PROFILE_BYTES: Final = 1024 * 1024
MAX_CONNECTOR_EVIDENCE_MANIFEST_BYTES: Final = 2 * 1024 * 1024
MAX_CONNECTOR_EVIDENCE_TOTAL_BYTES: Final = (
    MAX_CONNECTOR_EVIDENCE_MANIFEST_BYTES
    + MAX_CONNECTOR_EVIDENCE_RECEIPT_BYTES
    + MAX_CONNECTOR_EVIDENCE_RECORD_BYTES
    + 4 * MAX_CONNECTOR_EVIDENCE_PROFILE_BYTES
)
MAX_CONNECTOR_EVIDENCE_FILES: Final = 7

_JOB_PATH = "spec/connector-job.json"
_REQUEST_PATH = "spec/connector-request.json"
_POLICY_PATH = "spec/connector-evidence-policy.json"
_RECEIPT_PATH = "artifacts/source-receipt.json"
_RECORDS_PATH = "records/source-records.jsonl"
_VERIFICATION_PATH = "derived/connector-verification.json"
_EXPECTED_PATHS = frozenset(
    {
        _JOB_PATH,
        _REQUEST_PATH,
        _POLICY_PATH,
        _RECEIPT_PATH,
        _RECORDS_PATH,
        _VERIFICATION_PATH,
    }
)

_VERIFIER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$")
_REQUEST_LIMITS = JSONLimits(
    max_bytes=MAX_CONNECTOR_EVIDENCE_PROFILE_BYTES,
    max_line_bytes=MAX_CONNECTOR_EVIDENCE_PROFILE_BYTES,
    max_depth=24,
    max_collection_items=100_000,
    max_string_length=256 * 1024,
)
_PROFILE_LIMITS = JSONLimits(
    max_bytes=MAX_CONNECTOR_EVIDENCE_PROFILE_BYTES,
    max_line_bytes=MAX_CONNECTOR_EVIDENCE_PROFILE_BYTES,
    max_depth=12,
    max_collection_items=1_024,
    max_string_length=256 * 1024,
)
_CONNECTOR_STREAM_LIMITS = StreamSnapshotLimits(
    max_manifest_bytes=MAX_CONNECTOR_EVIDENCE_MANIFEST_BYTES,
    max_file_bytes=MAX_CONNECTOR_EVIDENCE_RECEIPT_BYTES,
    max_total_bytes=MAX_CONNECTOR_EVIDENCE_TOTAL_BYTES,
    max_files=MAX_CONNECTOR_EVIDENCE_FILES,
)
_CONNECTOR_BUNDLE_LIMITS: BundleLimits = _CONNECTOR_STREAM_LIMITS.bundle_limits()
_STREAMED_READ_LIMITS = {
    "bundle.json": MAX_CONNECTOR_EVIDENCE_MANIFEST_BYTES,
    _JOB_PATH: MAX_CONNECTOR_EVIDENCE_PROFILE_BYTES,
    _REQUEST_PATH: MAX_CONNECTOR_EVIDENCE_PROFILE_BYTES,
    _POLICY_PATH: MAX_CONNECTOR_EVIDENCE_PROFILE_BYTES,
    _RECEIPT_PATH: MAX_CONNECTOR_EVIDENCE_RECEIPT_BYTES,
    _VERIFICATION_PATH: MAX_CONNECTOR_EVIDENCE_PROFILE_BYTES,
}


class ConnectorEvidenceError(ValueError):
    """A connector capture could not be bound to or recovered from a CAB."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ConnectorEvidenceJob(_StrictModel):
    """Externally authorized identity of one source collection job."""

    media_type: Literal[
        "application/vnd.control-assurance.connector-evidence-job.v1+json"
    ] = CONNECTOR_EVIDENCE_JOB_MEDIA_TYPE
    schema_version: Literal["1.0.0"] = CONNECTOR_EVIDENCE_SCHEMA_VERSION
    job_id: str = Field(pattern=r"^[a-z][a-z0-9._-]{0,127}$")
    connector_id: str = Field(pattern=r"^[a-z][a-z0-9._-]{0,127}$")
    connector_version: str = Field(min_length=1, max_length=64)
    capture_media_type: str = Field(
        pattern=r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$",
        max_length=128,
    )
    source_locator_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    data_sensitivity: Literal["synthetic", "lab-internal"]
    request_media_type: str = Field(
        pattern=r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$",
        max_length=128,
    )
    request_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"), limits=_PROFILE_LIMITS)

    @property
    def descriptor(self) -> ConnectorDescriptor:
        return ConnectorDescriptor(
            connector_id=self.connector_id,
            connector_version=self.connector_version,
            capture_media_type=self.capture_media_type,
        )


@dataclass(frozen=True, slots=True)
class ConnectorEvidenceBundle:
    """A written and immediately reverified connector evidence CAB."""

    cab_id: str
    stream_snapshot_root: Path
    snapshot_digest: str
    job_digest: str
    receipt_digest: str
    records_digest: str
    record_count: int
    verified_capture: VerifiedConnectorCapture


@dataclass(frozen=True, slots=True)
class VerifiedConnectorEvidenceBundle:
    """A connector CAB reopened from sealed bytes and semantically reverified."""

    cab_id: str
    snapshot_digest: str
    job_digest: str
    receipt_digest: str
    records_digest: str
    record_count: int
    verified_capture: VerifiedConnectorCapture


ReceiptVerifier = Callable[[bytes], VerifiedConnectorCapture]


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _require_capture_limits(
    *,
    receipt_bytes: bytes,
    records_jsonl: bytes,
) -> None:
    if len(receipt_bytes) > MAX_CONNECTOR_EVIDENCE_RECEIPT_BYTES:
        raise ConnectorEvidenceError("connector receipt exceeds the evidence profile")
    if len(records_jsonl) > MAX_CONNECTOR_EVIDENCE_RECORD_BYTES:
        raise ConnectorEvidenceError("connector records exceed the evidence profile")


def _canonical_request_bytes(value: bytes) -> bytes:
    if type(value) is not bytes or not value:
        raise ConnectorEvidenceError("connector request must be non-empty immutable bytes")
    try:
        parsed = strict_json_loads(value, limits=_REQUEST_LIMITS)
        canonical = canonical_json_bytes(parsed, limits=_REQUEST_LIMITS)
    except StrictJSONError as exc:
        raise ConnectorEvidenceError("connector request is not bounded strict JSON") from exc
    if canonical != value:
        raise ConnectorEvidenceError("connector request is not canonical JSON")
    if not isinstance(parsed, dict):
        raise ConnectorEvidenceError("connector request must be one canonical JSON object")
    return canonical


def create_connector_evidence_job(
    *,
    job_id: str,
    descriptor: ConnectorDescriptor,
    source_locator_digest: str,
    request_media_type: str,
    request_bytes: bytes,
    data_sensitivity: Sensitivity = Sensitivity.LAB_INTERNAL,
) -> ConnectorEvidenceJob:
    """Create the external job anchor for one exact connector request."""

    if type(descriptor) is not ConnectorDescriptor:
        raise TypeError("descriptor must be an exact ConnectorDescriptor")
    request = _canonical_request_bytes(request_bytes)
    try:
        return ConnectorEvidenceJob(
            job_id=job_id,
            connector_id=descriptor.connector_id,
            connector_version=descriptor.connector_version,
            capture_media_type=descriptor.capture_media_type,
            source_locator_digest=source_locator_digest,
            data_sensitivity=data_sensitivity.value,
            request_media_type=request_media_type,
            request_digest=_sha256(request),
        )
    except (TypeError, ValueError) as exc:
        raise ConnectorEvidenceError("connector evidence job is outside the profile") from exc


def _require_verifier_id(value: str) -> str:
    if type(value) is not str or _VERIFIER_ID_RE.fullmatch(value) is None:
        raise ConnectorEvidenceError("receipt verifier id is not portable")
    return value


def _profile_policy_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "media_type": CONNECTOR_EVIDENCE_POLICY_MEDIA_TYPE,
            "required_payloads": sorted(_EXPECTED_PATHS),
            "rules": [
                "external-job-exact-match",
                "external-source-locator-anchor",
                "independent-receipt-recomputation",
                "records-byte-exact-match",
                "no-source-authenticity-claim",
            ],
            "schema_version": CONNECTOR_EVIDENCE_SCHEMA_VERSION,
        },
        limits=_PROFILE_LIMITS,
    )


def _assert_capture_matches(
    *,
    capture: ConnectorCapture,
    verified: VerifiedConnectorCapture,
    job: ConnectorEvidenceJob,
) -> None:
    if type(capture) is not ConnectorCapture:
        raise TypeError("capture must be an exact ConnectorCapture")
    if type(verified) is not VerifiedConnectorCapture:
        raise TypeError("receipt verifier must return an exact VerifiedConnectorCapture")
    if capture.descriptor != verified.descriptor:
        raise ConnectorEvidenceError("capture and verifier identify different connectors")
    if (
        capture.descriptor.connector_id != job.connector_id
        or capture.descriptor.connector_version != job.connector_version
    ):
        raise ConnectorEvidenceError("capture connector does not match the external job")
    if verified.source_locator_digest != job.source_locator_digest:
        raise ConnectorEvidenceError("verified source does not match the external job")
    if (
        capture.receipt_digest != verified.receipt_digest
        or capture.records_jsonl != verified.records_jsonl
        or capture.records_digest != verified.records_digest
        or capture.record_count != verified.record_count
    ):
        raise ConnectorEvidenceError(
            "collector output differs from independent receipt recomputation"
        )


def _verification_bytes(
    *,
    job: ConnectorEvidenceJob,
    verified: VerifiedConnectorCapture,
    verifier_id: str,
) -> bytes:
    return canonical_json_bytes(
        {
            "connector": {
                "id": verified.descriptor.connector_id,
                "version": verified.descriptor.connector_version,
            },
            "job_digest": _sha256(job.canonical_bytes()),
            "media_type": CONNECTOR_EVIDENCE_VERIFICATION_MEDIA_TYPE,
            "record_count": verified.record_count,
            "records_digest": verified.records_digest,
            "receipt_digest": verified.receipt_digest,
            "schema_version": CONNECTOR_EVIDENCE_SCHEMA_VERSION,
            "source": {
                "locator_digest": verified.source_locator_digest,
                "product": verified.source_product,
                "version": verified.source_version,
            },
            "verifier_id": _require_verifier_id(verifier_id),
        },
        limits=_PROFILE_LIMITS,
    )


def write_connector_evidence_bundle(
    destination: Path,
    *,
    stream_snapshot_destination: Path | None = None,
    job: ConnectorEvidenceJob,
    request_bytes: bytes,
    capture: ConnectorCapture,
    receipt_verifier: ReceiptVerifier,
    receipt_verifier_id: str,
    created_at: datetime,
    as_of: datetime,
    source_revision: str,
    parent_bundles: tuple[str, ...] = (),
) -> ConnectorEvidenceBundle:
    """Verify, bind, write, reopen, and semantically verify one capture CAB."""

    if type(job) is not ConnectorEvidenceJob:
        raise TypeError("job must be an exact ConnectorEvidenceJob")
    if type(capture) is not ConnectorCapture:
        raise TypeError("capture must be an exact ConnectorCapture")
    if not isinstance(destination, Path):
        raise TypeError("destination must be a pathlib.Path")
    if stream_snapshot_destination is None:
        stream_snapshot_destination = destination.with_name(
            f"{destination.name}.stream-snapshot-v2"
        )
    elif not isinstance(stream_snapshot_destination, Path):
        raise TypeError("stream snapshot destination must be a pathlib.Path")
    cab_path = destination.absolute()
    snapshot_path = stream_snapshot_destination.absolute()
    if (
        cab_path == snapshot_path
        or cab_path in snapshot_path.parents
        or snapshot_path in cab_path.parents
    ):
        raise ConnectorEvidenceError(
            "connector CAB and stream snapshot destinations must not overlap"
        )
    if stream_snapshot_destination.exists() or stream_snapshot_destination.is_symlink():
        raise ConnectorEvidenceError("stream snapshot destination already exists")
    request = _canonical_request_bytes(request_bytes)
    if _sha256(request) != job.request_digest:
        raise ConnectorEvidenceError("request bytes do not match the external job")
    verifier_id = _require_verifier_id(receipt_verifier_id)
    _require_capture_limits(
        receipt_bytes=capture.receipt_bytes,
        records_jsonl=capture.records_jsonl,
    )
    try:
        verified = receipt_verifier(capture.receipt_bytes)
    except Exception as exc:
        raise ConnectorEvidenceError("receipt verifier rejected the source capture") from exc
    if type(verified) is not VerifiedConnectorCapture:
        raise ConnectorEvidenceError("receipt verifier returned an unsupported result")
    _require_capture_limits(
        receipt_bytes=capture.receipt_bytes,
        records_jsonl=verified.records_jsonl,
    )
    _assert_capture_matches(capture=capture, verified=verified, job=job)

    job_bytes = job.canonical_bytes()
    policy_bytes = _profile_policy_bytes()
    verification_bytes = _verification_bytes(
        job=job,
        verified=verified,
        verifier_id=verifier_id,
    )
    sensitivity = Sensitivity(job.data_sensitivity)
    job_digest = _sha256(job_bytes)
    metadata = BundleMetadata(
        created_at=created_at,
        as_of=as_of,
        experiment=ExperimentRef(
            id=job.job_id,
            spec_version=CONNECTOR_EVIDENCE_SPEC_VERSION,
            spec_digest=job_digest,
        ),
        evaluation=EvaluationRef(
            policy_id="policy:connector-evidence:v1",
            policy_digest=_sha256(policy_bytes),
            evaluator=EvaluatorRef(
                name=CONNECTOR_EVIDENCE_EVALUATOR_ID,
                version=__version__,
                source_revision=source_revision,
                image_digest=None,
            ),
        ),
        parent_bundles=parent_bundles,
    )
    payloads = (
        PayloadFile(
            path=_RECEIPT_PATH,
            content=capture.receipt_bytes,
            media_type=capture.descriptor.capture_media_type,
            role="exact-source-exchange-receipt",
            sensitivity=sensitivity,
            required_for=("connector-capture-recomputation", "admission"),
        ),
        PayloadFile(
            path=_VERIFICATION_PATH,
            content=verification_bytes,
            media_type=CONNECTOR_EVIDENCE_VERIFICATION_MEDIA_TYPE,
            role="recomputed-connector-verification",
            sensitivity=sensitivity,
            required_for=("connector-capture-recomputation",),
        ),
        PayloadFile(
            path=_RECORDS_PATH,
            content=capture.records_jsonl,
            media_type="application/x-ndjson",
            role="canonical-source-records",
            sensitivity=sensitivity,
            required_for=("connector-capture-recomputation", "control-evaluation"),
        ),
        PayloadFile(
            path=_POLICY_PATH,
            content=policy_bytes,
            media_type=CONNECTOR_EVIDENCE_POLICY_MEDIA_TYPE,
            role="connector-evidence-profile",
            sensitivity=sensitivity,
            required_for=("connector-capture-recomputation",),
        ),
        PayloadFile(
            path=_JOB_PATH,
            content=job_bytes,
            media_type=CONNECTOR_EVIDENCE_JOB_MEDIA_TYPE,
            role="externally-authorized-connector-job",
            sensitivity=sensitivity,
            required_for=("connector-capture-recomputation", "admission"),
        ),
        PayloadFile(
            path=_REQUEST_PATH,
            content=request,
            media_type=job.request_media_type,
            role="exact-structured-connector-request",
            sensitivity=sensitivity,
            required_for=("connector-capture-recomputation", "admission"),
        ),
    )
    result = write_bundle(
        destination,
        metadata=metadata,
        payloads=payloads,
        limits=_CONNECTOR_BUNDLE_LIMITS,
    )
    if result.status != BundleStatus.INTEGRITY_VERIFIED or result.bundle_id is None:
        raise ConnectorEvidenceError("connector evidence CAB failed integrity verification")

    streamed = capture_streamed_cab_snapshot(
        destination,
        stream_snapshot_destination,
        limits=_CONNECTOR_STREAM_LIMITS,
    )
    reopened = verify_streamed_connector_evidence_bundle(
        stream_snapshot_destination,
        expected_snapshot_digest=streamed.snapshot_digest,
        expected_job=job,
        expected_request_bytes=request,
        receipt_verifier=receipt_verifier,
        receipt_verifier_id=verifier_id,
        expected_source_revision=source_revision,
    )
    if reopened.cab_id != result.bundle_id:
        raise ConnectorEvidenceError("written connector CAB reopened with a different identity")
    return ConnectorEvidenceBundle(
        cab_id=result.bundle_id,
        stream_snapshot_root=stream_snapshot_destination,
        snapshot_digest=streamed.snapshot_digest,
        job_digest=job_digest,
        receipt_digest=verified.receipt_digest,
        records_digest=verified.records_digest,
        record_count=verified.record_count,
        verified_capture=verified,
    )


def _load_manifest(value: bytes) -> BundleManifest:
    try:
        strict_json_loads(value, limits=_PROFILE_LIMITS)
        manifest = BundleManifest.model_validate_json(value)
    except (StrictJSONError, TypeError, ValueError) as exc:
        raise ConnectorEvidenceError("connector CAB manifest is invalid") from exc
    if manifest.canonical_bytes() != value:
        raise ConnectorEvidenceError("connector CAB manifest is not canonical JSON")
    return manifest


def _load_job(value: bytes) -> ConnectorEvidenceJob:
    try:
        parsed = strict_json_loads(value, limits=_PROFILE_LIMITS)
        job = ConnectorEvidenceJob.model_validate(parsed)
    except (StrictJSONError, TypeError, ValueError) as exc:
        raise ConnectorEvidenceError("connector CAB job is invalid") from exc
    if job.canonical_bytes() != value:
        raise ConnectorEvidenceError("connector CAB job is not canonical JSON")
    return job


def _require_exact_profile(
    *,
    manifest: BundleManifest,
    entries: dict[str, bytes],
    job: ConnectorEvidenceJob,
    expected_source_revision: str,
) -> None:
    descriptors = {descriptor.path: descriptor for descriptor in manifest.files}
    if frozenset(descriptors) != _EXPECTED_PATHS:
        raise ConnectorEvidenceError("connector CAB manifest contains the wrong payload set")
    if (
        manifest.experiment.id != job.job_id
        or manifest.experiment.spec_version != CONNECTOR_EVIDENCE_SPEC_VERSION
        or manifest.experiment.spec_digest != _sha256(entries[_JOB_PATH])
    ):
        raise ConnectorEvidenceError("connector CAB experiment identity is inconsistent")
    policy_digest = _sha256(entries[_POLICY_PATH])
    if (
        manifest.evaluation.policy_id != "policy:connector-evidence:v1"
        or manifest.evaluation.policy_digest != policy_digest
        or manifest.evaluation.evaluator.name != CONNECTOR_EVIDENCE_EVALUATOR_ID
        or manifest.evaluation.evaluator.version != __version__
        or manifest.evaluation.evaluator.source_revision != expected_source_revision
        or manifest.evaluation.evaluator.image_digest is not None
    ):
        raise ConnectorEvidenceError("connector CAB evaluator identity is inconsistent")
    expected_media_types = {
        _JOB_PATH: CONNECTOR_EVIDENCE_JOB_MEDIA_TYPE,
        _REQUEST_PATH: job.request_media_type,
        _POLICY_PATH: CONNECTOR_EVIDENCE_POLICY_MEDIA_TYPE,
        _RECEIPT_PATH: job.capture_media_type,
        _RECORDS_PATH: "application/x-ndjson",
        _VERIFICATION_PATH: CONNECTOR_EVIDENCE_VERIFICATION_MEDIA_TYPE,
    }
    expected_roles = {
        _JOB_PATH: (
            "externally-authorized-connector-job",
            ["connector-capture-recomputation", "admission"],
        ),
        _REQUEST_PATH: (
            "exact-structured-connector-request",
            ["connector-capture-recomputation", "admission"],
        ),
        _POLICY_PATH: (
            "connector-evidence-profile",
            ["connector-capture-recomputation"],
        ),
        _RECEIPT_PATH: (
            "exact-source-exchange-receipt",
            ["connector-capture-recomputation", "admission"],
        ),
        _RECORDS_PATH: (
            "canonical-source-records",
            ["connector-capture-recomputation", "control-evaluation"],
        ),
        _VERIFICATION_PATH: (
            "recomputed-connector-verification",
            ["connector-capture-recomputation"],
        ),
    }
    for path, media_type in expected_media_types.items():
        descriptor = descriptors[path]
        expected_role, expected_required_for = expected_roles[path]
        if (
            descriptor.media_type != media_type
            or descriptor.role != expected_role
            or descriptor.required_for != expected_required_for
            or descriptor.sensitivity.value != job.data_sensitivity
        ):
            raise ConnectorEvidenceError(f"connector CAB descriptor is wrong for {path}")
    if entries[_POLICY_PATH] != _profile_policy_bytes():
        raise ConnectorEvidenceError("connector CAB profile policy is not the frozen policy")


def _verify_reopened_connector_entries(
    *,
    cab_id: str,
    snapshot_digest: str,
    manifest: BundleManifest,
    entries: dict[str, bytes],
    expected_job: ConnectorEvidenceJob,
    request: bytes,
    receipt_verifier: ReceiptVerifier,
    verifier_id: str,
    expected_source_revision: str,
) -> VerifiedConnectorEvidenceBundle:
    observed_job = _load_job(entries.get(_JOB_PATH, b""))
    if observed_job != expected_job or entries.get(_JOB_PATH) != expected_job.canonical_bytes():
        raise ConnectorEvidenceError("connector CAB job differs from the external job")
    if entries.get(_REQUEST_PATH) != request:
        raise ConnectorEvidenceError("connector CAB request differs from the external request")
    _require_exact_profile(
        manifest=manifest,
        entries=entries,
        job=observed_job,
        expected_source_revision=expected_source_revision,
    )
    receipt = entries.get(_RECEIPT_PATH)
    if receipt is None:
        raise ConnectorEvidenceError("connector CAB receipt is absent")
    if len(receipt) > MAX_CONNECTOR_EVIDENCE_RECEIPT_BYTES:
        raise ConnectorEvidenceError("connector CAB receipt exceeds the evidence profile")
    try:
        verified = receipt_verifier(receipt)
    except Exception as exc:
        raise ConnectorEvidenceError("receipt verifier rejected the connector CAB") from exc
    if type(verified) is not VerifiedConnectorCapture:
        raise ConnectorEvidenceError("receipt verifier returned an unsupported result")
    _require_capture_limits(
        receipt_bytes=receipt,
        records_jsonl=verified.records_jsonl,
    )
    if (
        verified.descriptor.connector_id != expected_job.connector_id
        or verified.descriptor.connector_version != expected_job.connector_version
        or verified.source_locator_digest != expected_job.source_locator_digest
    ):
        raise ConnectorEvidenceError("reverified capture differs from the external job")

    descriptors = {descriptor.path: descriptor for descriptor in manifest.files}
    receipt_descriptor = descriptors[_RECEIPT_PATH]
    records_descriptor = descriptors[_RECORDS_PATH]
    if (
        f"sha256:{receipt_descriptor.sha256}" != verified.receipt_digest
        or receipt_descriptor.size != len(receipt)
    ):
        raise ConnectorEvidenceError("CAB receipt differs from receipt recomputation")
    if (
        f"sha256:{records_descriptor.sha256}" != verified.records_digest
        or records_descriptor.size != len(verified.records_jsonl)
    ):
        raise ConnectorEvidenceError("CAB records differ from receipt recomputation")
    records = entries.get(_RECORDS_PATH)
    if records is not None and records != verified.records_jsonl:
        raise ConnectorEvidenceError("CAB records differ from receipt recomputation")
    expected_verification = _verification_bytes(
        job=expected_job,
        verified=verified,
        verifier_id=verifier_id,
    )
    if entries.get(_VERIFICATION_PATH) != expected_verification:
        raise ConnectorEvidenceError("CAB verification statement was not recomputed exactly")
    return VerifiedConnectorEvidenceBundle(
        cab_id=cab_id,
        snapshot_digest=snapshot_digest,
        job_digest=_sha256(expected_job.canonical_bytes()),
        receipt_digest=verified.receipt_digest,
        records_digest=verified.records_digest,
        record_count=verified.record_count,
        verified_capture=verified,
    )


def verify_streamed_connector_evidence_bundle(
    snapshot_root: Path,
    *,
    expected_snapshot_digest: str,
    expected_job: ConnectorEvidenceJob,
    expected_request_bytes: bytes,
    receipt_verifier: ReceiptVerifier,
    receipt_verifier_id: str,
    expected_source_revision: str,
) -> VerifiedConnectorEvidenceBundle:
    """Recompute connector semantics from one externally anchored v2 snapshot.

    The expected job and request are supplied out of band.  Reading those
    values from the bundle itself would allow an attacker to redefine the
    collection target while preserving internal consistency.

    The 64 MiB records member is hashed but not copied into a second Python
    buffer.  Its verified descriptor is compared to the independently
    recomputed canonical records returned by the receipt verifier.
    """

    if type(expected_job) is not ConnectorEvidenceJob:
        raise TypeError("expected job must be an exact ConnectorEvidenceJob")
    request = _canonical_request_bytes(expected_request_bytes)
    if _sha256(request) != expected_job.request_digest:
        raise ConnectorEvidenceError("expected request does not match the expected job")
    verifier_id = _require_verifier_id(receipt_verifier_id)
    try:
        streamed, decoded = read_streamed_cab_snapshot_entries(
            snapshot_root,
            expected_snapshot_digest=expected_snapshot_digest,
            entry_limits=dict(_STREAMED_READ_LIMITS),
            limits=_CONNECTOR_STREAM_LIMITS,
        )
    except Exception as exc:
        raise ConnectorEvidenceError(
            "connector CAB stream snapshot could not be safely reopened"
        ) from exc
    entries = dict(decoded)
    if len(entries) != len(decoded):
        raise ConnectorEvidenceError("connector CAB snapshot contains duplicate paths")
    manifest = _load_manifest(entries.get("bundle.json", b""))
    result = _verify_reopened_connector_entries(
        cab_id=streamed.cab_id,
        snapshot_digest=streamed.snapshot_digest,
        manifest=manifest,
        entries=entries,
        expected_job=expected_job,
        request=request,
        receipt_verifier=receipt_verifier,
        verifier_id=verifier_id,
        expected_source_revision=expected_source_revision,
    )
    try:
        closing = verify_streamed_cab_snapshot(
            snapshot_root,
            expected_snapshot_digest=streamed.snapshot_digest,
            limits=_CONNECTOR_STREAM_LIMITS,
        )
    except Exception as exc:
        raise ConnectorEvidenceError(
            "connector CAB stream snapshot changed during semantic verification"
        ) from exc
    if closing.cab_id != result.cab_id:
        raise ConnectorEvidenceError(
            "connector CAB identity changed during semantic verification"
        )
    return result


def verify_connector_evidence_bundle(
    source: Path,
    *,
    expected_job: ConnectorEvidenceJob,
    expected_request_bytes: bytes,
    receipt_verifier: ReceiptVerifier,
    receipt_verifier_id: str,
    expected_source_revision: str,
) -> VerifiedConnectorEvidenceBundle:
    """Legacy small-CAB reopen path retained for v1 admission compatibility.

    New connector custody paths should use
    :func:`verify_streamed_connector_evidence_bundle`; this v1 codec is
    intentionally capped at 4 MiB.
    """

    if type(expected_job) is not ConnectorEvidenceJob:
        raise TypeError("expected job must be an exact ConnectorEvidenceJob")
    request = _canonical_request_bytes(expected_request_bytes)
    if _sha256(request) != expected_job.request_digest:
        raise ConnectorEvidenceError("expected request does not match the expected job")
    verifier_id = _require_verifier_id(receipt_verifier_id)
    try:
        sealed: SealedCABSnapshot = capture_cab_snapshot(source)
        decoded = decode_cab_snapshot_entries(sealed.snapshot_bytes)
    except Exception as exc:
        raise ConnectorEvidenceError("connector CAB could not be safely sealed") from exc
    entries = dict(decoded)
    if len(entries) != len(decoded):
        raise ConnectorEvidenceError("connector CAB snapshot contains duplicate paths")
    manifest = _load_manifest(entries.get("bundle.json", b""))
    return _verify_reopened_connector_entries(
        cab_id=sealed.cab_id,
        snapshot_digest=sealed.snapshot_digest,
        manifest=manifest,
        entries=entries,
        expected_job=expected_job,
        request=request,
        receipt_verifier=receipt_verifier,
        verifier_id=verifier_id,
        expected_source_revision=expected_source_revision,
    )


def connector_request_bytes(request: dict[str, Any]) -> bytes:
    """Canonicalize a connector request object for an external job document."""

    if type(request) is not dict:
        raise TypeError("connector request must be an exact dict")
    try:
        result = canonical_json_bytes(request, limits=_REQUEST_LIMITS)
    except StrictJSONError as exc:
        raise ConnectorEvidenceError("connector request exceeds the evidence profile") from exc
    return _canonical_request_bytes(result)


__all__ = [
    "CONNECTOR_EVIDENCE_EVALUATOR_ID",
    "CONNECTOR_EVIDENCE_JOB_MEDIA_TYPE",
    "CONNECTOR_EVIDENCE_POLICY_MEDIA_TYPE",
    "CONNECTOR_EVIDENCE_SCHEMA_VERSION",
    "CONNECTOR_EVIDENCE_VERIFICATION_MEDIA_TYPE",
    "MAX_CONNECTOR_EVIDENCE_FILES",
    "MAX_CONNECTOR_EVIDENCE_MANIFEST_BYTES",
    "MAX_CONNECTOR_EVIDENCE_PROFILE_BYTES",
    "MAX_CONNECTOR_EVIDENCE_RECEIPT_BYTES",
    "MAX_CONNECTOR_EVIDENCE_RECORD_BYTES",
    "MAX_CONNECTOR_EVIDENCE_TOTAL_BYTES",
    "ConnectorEvidenceBundle",
    "ConnectorEvidenceError",
    "ConnectorEvidenceJob",
    "VerifiedConnectorEvidenceBundle",
    "connector_request_bytes",
    "create_connector_evidence_job",
    "verify_connector_evidence_bundle",
    "verify_streamed_connector_evidence_bundle",
    "write_connector_evidence_bundle",
]
