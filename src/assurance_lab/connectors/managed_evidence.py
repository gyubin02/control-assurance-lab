"""Close one managed connector run over source and PAM lifecycle evidence.

This profile is deliberately separate from :mod:`assurance_lab.connectors.evidence`.
The v1 connector profile proves that an independently verified source receipt
recomputes to one exact record stream.  This v2 managed profile additionally
binds that capture to:

* one externally anchored runtime run and half-open collection window;
* one externally anchored control profile and independently recomputed result;
* one frozen authorization profile;
* one independently verified, closed JIT/PAM lifecycle receipt; and
* the exact connector and PAM verifier identities selected by the operator.

The writer does not return after merely creating files.  It writes a CAB,
streams that CAB into a content-addressed snapshot, reopens the snapshot, and
repeats both semantic verifications.  The reopen API requires the run anchor
and request out of band so an internally consistent bundle cannot redefine the
run it claims to represent.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from assurance_lab._version import __version__
from assurance_lab.connectors.contract import (
    ConnectorCapture,
    ConnectorDescriptor,
    ConnectorWindow,
    VerifiedConnectorCapture,
)
from assurance_lab.connectors.evidence import ReceiptVerifier
from assurance_lab.controls.alert_window import (
    ALERT_WINDOW_EVALUATION_MEDIA_TYPE,
    ALERT_WINDOW_PROFILE_MEDIA_TYPE,
    AlertWindowEvaluation,
    AlertWindowEvaluationError,
    AlertWindowProfile,
    evaluate_alert_window,
    parse_alert_window_profile,
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
from assurance_lab.evidence.stream_snapshot import (
    StreamSnapshotLimits,
    capture_streamed_cab_snapshot,
    read_streamed_cab_snapshot_entries,
    verify_streamed_cab_snapshot,
)
from assurance_lab.evidence.writer import BundleMetadata, PayloadFile, write_bundle

MANAGED_CONNECTOR_JOB_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.managed-connector-job.v2+json"]
] = "application/vnd.control-assurance.managed-connector-job.v2+json"
MANAGED_CONNECTOR_POLICY_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.managed-connector-policy.v2+json"]
] = "application/vnd.control-assurance.managed-connector-policy.v2+json"
MANAGED_CONNECTOR_VERIFICATION_MEDIA_TYPE: Final[
    Literal[
        "application/vnd.control-assurance.managed-connector-verification.v2+json"
    ]
] = "application/vnd.control-assurance.managed-connector-verification.v2+json"
MANAGED_PAM_VERIFICATION_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.pam-lifecycle-verification.v1+json"]
] = "application/vnd.control-assurance.pam-lifecycle-verification.v1+json"
MANAGED_AUTHORIZATION_PROFILE_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.authorization-profile.v1+json"]
] = "application/vnd.control-assurance.authorization-profile.v1+json"
MANAGED_CONNECTOR_SCHEMA_VERSION: Final[Literal["2.0.0"]] = "2.0.0"
MANAGED_PAM_VERIFICATION_SCHEMA_VERSION: Final[Literal["1.0.0"]] = "1.0.0"
MANAGED_CONNECTOR_SPEC_VERSION: Final[Literal["2.0.0"]] = "2.0.0"
MANAGED_CONNECTOR_EVALUATOR_ID: Final[
    Literal["control-assurance-lab/managed-connector-evidence-v2"]
] = "control-assurance-lab/managed-connector-evidence-v2"

MAX_MANAGED_CONNECTOR_SOURCE_RECEIPT_BYTES: Final = 96 * 1024 * 1024
MAX_MANAGED_CONNECTOR_RECORD_BYTES: Final = 64 * 1024 * 1024
MAX_MANAGED_CONNECTOR_PAM_RECEIPT_BYTES: Final = 2 * 1024 * 1024
MAX_MANAGED_CONNECTOR_PROFILE_BYTES: Final = 1024 * 1024
MAX_MANAGED_CONNECTOR_MANIFEST_BYTES: Final = 2 * 1024 * 1024
MAX_MANAGED_CONNECTOR_FILES: Final = 12
MAX_MANAGED_CONNECTOR_TOTAL_BYTES: Final = (
    MAX_MANAGED_CONNECTOR_MANIFEST_BYTES
    + MAX_MANAGED_CONNECTOR_SOURCE_RECEIPT_BYTES
    + MAX_MANAGED_CONNECTOR_RECORD_BYTES
    + MAX_MANAGED_CONNECTOR_PAM_RECEIPT_BYTES
    + 8 * MAX_MANAGED_CONNECTOR_PROFILE_BYTES
)

_JOB_PATH = "spec/managed-connector-job.json"
_REQUEST_PATH = "spec/connector-request.json"
_CONTROL_PROFILE_PATH = "spec/control-profile.json"
_AUTHORIZATION_PROFILE_PATH = "spec/authorization-profile.json"
_POLICY_PATH = "spec/managed-connector-policy.json"
_SOURCE_RECEIPT_PATH = "artifacts/source-receipt.json"
_RECORDS_PATH = "records/source-records.jsonl"
_CONNECTOR_VERIFICATION_PATH = "derived/connector-verification.json"
_PAM_RECEIPT_PATH = "artifacts/pam-lifecycle-receipt.json"
_PAM_VERIFICATION_PATH = "derived/pam-verification.json"
_CONTROL_EVALUATION_PATH = "derived/control-evaluation.json"
_EXPECTED_PATHS = frozenset(
    {
        _JOB_PATH,
        _REQUEST_PATH,
        _CONTROL_PROFILE_PATH,
        _AUTHORIZATION_PROFILE_PATH,
        _POLICY_PATH,
        _SOURCE_RECEIPT_PATH,
        _RECORDS_PATH,
        _CONNECTOR_VERIFICATION_PATH,
        _PAM_RECEIPT_PATH,
        _PAM_VERIFICATION_PATH,
        _CONTROL_EVALUATION_PATH,
    }
)

_DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
_PORTABLE_ID_PATTERN = r"^[a-z][a-z0-9._-]{0,127}$"
_MEDIA_TYPE_PATTERN = r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$"
_UTC_SECOND_PATTERN = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
_DIGEST_RE = re.compile(_DIGEST_PATTERN)
_VERIFIER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$")
_AUTHORIZATION_PROFILE_ID_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$"
)
_AUTHORIZATION_ENTRY_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:/@*+-]{0,255}$"
)

_REQUEST_LIMITS = JSONLimits(
    max_bytes=MAX_MANAGED_CONNECTOR_PROFILE_BYTES,
    max_line_bytes=MAX_MANAGED_CONNECTOR_PROFILE_BYTES,
    max_depth=24,
    max_collection_items=100_000,
    max_string_length=256 * 1024,
)
_PROFILE_LIMITS = JSONLimits(
    max_bytes=MAX_MANAGED_CONNECTOR_PROFILE_BYTES,
    max_line_bytes=MAX_MANAGED_CONNECTOR_PROFILE_BYTES,
    max_depth=16,
    max_collection_items=4_096,
    max_string_length=256 * 1024,
)
_PAM_RECEIPT_LIMITS = JSONLimits(
    max_bytes=MAX_MANAGED_CONNECTOR_PAM_RECEIPT_BYTES,
    max_line_bytes=MAX_MANAGED_CONNECTOR_PAM_RECEIPT_BYTES,
    max_depth=24,
    max_collection_items=32_768,
    max_string_length=512 * 1024,
)
_MANIFEST_LIMITS = JSONLimits(
    max_bytes=MAX_MANAGED_CONNECTOR_MANIFEST_BYTES,
    max_line_bytes=MAX_MANAGED_CONNECTOR_MANIFEST_BYTES,
    max_depth=16,
    max_collection_items=4_096,
    max_string_length=256 * 1024,
)
_STREAM_LIMITS = StreamSnapshotLimits(
    max_manifest_bytes=MAX_MANAGED_CONNECTOR_MANIFEST_BYTES,
    max_file_bytes=MAX_MANAGED_CONNECTOR_SOURCE_RECEIPT_BYTES,
    max_total_bytes=MAX_MANAGED_CONNECTOR_TOTAL_BYTES,
    max_files=MAX_MANAGED_CONNECTOR_FILES,
)
_BUNDLE_LIMITS: BundleLimits = _STREAM_LIMITS.bundle_limits()
_STREAMED_READ_LIMITS = {
    "bundle.json": MAX_MANAGED_CONNECTOR_MANIFEST_BYTES,
    _JOB_PATH: MAX_MANAGED_CONNECTOR_PROFILE_BYTES,
    _REQUEST_PATH: MAX_MANAGED_CONNECTOR_PROFILE_BYTES,
    _CONTROL_PROFILE_PATH: MAX_MANAGED_CONNECTOR_PROFILE_BYTES,
    _AUTHORIZATION_PROFILE_PATH: MAX_MANAGED_CONNECTOR_PROFILE_BYTES,
    _POLICY_PATH: MAX_MANAGED_CONNECTOR_PROFILE_BYTES,
    _SOURCE_RECEIPT_PATH: MAX_MANAGED_CONNECTOR_SOURCE_RECEIPT_BYTES,
    _CONNECTOR_VERIFICATION_PATH: MAX_MANAGED_CONNECTOR_PROFILE_BYTES,
    _PAM_RECEIPT_PATH: MAX_MANAGED_CONNECTOR_PAM_RECEIPT_BYTES,
    _PAM_VERIFICATION_PATH: MAX_MANAGED_CONNECTOR_PROFILE_BYTES,
    _CONTROL_EVALUATION_PATH: MAX_MANAGED_CONNECTOR_PROFILE_BYTES,
}


class ManagedConnectorEvidenceError(ValueError):
    """A managed capture failed a bounded, secret-free evidence transition."""


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class ManagedConnectorWindow(_StrictFrozenModel):
    """Canonical half-open UTC interval carried by the external run anchor."""

    start_inclusive: str = Field(pattern=_UTC_SECOND_PATTERN)
    end_exclusive: str = Field(pattern=_UTC_SECOND_PATTERN)

    @model_validator(mode="after")
    def valid_half_open_interval(self) -> ManagedConnectorWindow:
        try:
            start = datetime.strptime(
                self.start_inclusive,
                "%Y-%m-%dT%H:%M:%SZ",
            ).replace(tzinfo=UTC)
            end = datetime.strptime(
                self.end_exclusive,
                "%Y-%m-%dT%H:%M:%SZ",
            ).replace(tzinfo=UTC)
        except ValueError as exc:
            raise ValueError("managed connector window contains an invalid UTC time") from exc
        if start >= end:
            raise ValueError("managed connector window must have positive duration")
        return self

    @property
    def start(self) -> datetime:
        return datetime.strptime(
            self.start_inclusive,
            "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=UTC)

    @property
    def end(self) -> datetime:
        return datetime.strptime(
            self.end_exclusive,
            "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=UTC)


class ManagedAuthorizationProfile(_StrictFrozenModel):
    """Secret-free authorization facts required to verify one PAM receipt."""

    media_type: Literal[
        "application/vnd.control-assurance.authorization-profile.v1+json"
    ] = MANAGED_AUTHORIZATION_PROFILE_MEDIA_TYPE
    schema_version: Literal["1.0.0"] = "1.0.0"
    profile_id: str = Field(pattern=_PORTABLE_ID_PATTERN)
    provider_id: str = Field(pattern=_PORTABLE_ID_PATTERN)
    authorization_binding_digest: str = Field(pattern=_DIGEST_PATTERN)
    credential_reference_digest: str = Field(pattern=_DIGEST_PATTERN)
    permission_ids: tuple[str, ...] = Field(min_length=1, max_length=64)
    resource_scope_digests: tuple[str, ...] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def canonical_sets(self) -> ManagedAuthorizationProfile:
        if (
            any(_AUTHORIZATION_ENTRY_RE.fullmatch(value) is None for value in self.permission_ids)
            or len(set(self.permission_ids)) != len(self.permission_ids)
            or tuple(sorted(self.permission_ids)) != self.permission_ids
        ):
            raise ValueError(
                "authorization permission ids must be unique sorted references"
            )
        if (
            len(set(self.resource_scope_digests))
            != len(self.resource_scope_digests)
            or tuple(sorted(self.resource_scope_digests))
            != self.resource_scope_digests
        ):
            raise ValueError(
                "authorization resource scopes must be unique sorted digests"
            )
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            self.model_dump(mode="json"),
            limits=_PROFILE_LIMITS,
        )

    @property
    def digest(self) -> str:
        return _sha256(self.canonical_bytes())


class ManagedConnectorEvidenceJob(_StrictFrozenModel):
    """Frozen external authority for one managed connector execution."""

    media_type: Literal[
        "application/vnd.control-assurance.managed-connector-job.v2+json"
    ] = MANAGED_CONNECTOR_JOB_MEDIA_TYPE
    schema_version: Literal["2.0.0"] = MANAGED_CONNECTOR_SCHEMA_VERSION
    run_id: str = Field(pattern=_DIGEST_PATTERN)
    tenant_id: str = Field(pattern=_PORTABLE_ID_PATTERN)
    control_id: str = Field(pattern=_PORTABLE_ID_PATTERN)
    control_profile_id: str = Field(pattern=_PORTABLE_ID_PATTERN)
    control_profile_digest: str = Field(pattern=_DIGEST_PATTERN)
    configuration_digest: str = Field(pattern=_DIGEST_PATTERN)
    deployment_receipt_digest: str = Field(pattern=_DIGEST_PATTERN)
    window: ManagedConnectorWindow
    connector_id: str = Field(pattern=_PORTABLE_ID_PATTERN)
    connector_version: str = Field(min_length=1, max_length=64)
    capture_media_type: str = Field(pattern=_MEDIA_TYPE_PATTERN, max_length=128)
    source_locator_digest: str = Field(pattern=_DIGEST_PATTERN)
    request_media_type: str = Field(pattern=_MEDIA_TYPE_PATTERN, max_length=128)
    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    authorization_profile_id: str = Field(min_length=1, max_length=256)
    authorization_profile_digest: str = Field(pattern=_DIGEST_PATTERN)
    authorization_binding_digest: str = Field(pattern=_DIGEST_PATTERN)
    connector_receipt_verifier_id: str = Field(min_length=1, max_length=256)
    pam_receipt_verifier_id: str = Field(min_length=1, max_length=256)
    data_sensitivity: Literal["synthetic", "lab-internal"]

    @model_validator(mode="after")
    def portable_external_identities(self) -> ManagedConnectorEvidenceJob:
        if (
            _AUTHORIZATION_PROFILE_ID_RE.fullmatch(self.authorization_profile_id)
            is None
        ):
            raise ValueError("authorization profile id is not portable")
        if (
            _VERIFIER_ID_RE.fullmatch(self.connector_receipt_verifier_id) is None
            or _VERIFIER_ID_RE.fullmatch(self.pam_receipt_verifier_id) is None
        ):
            raise ValueError("managed connector verifier id is not portable")
        try:
            ConnectorDescriptor(
                connector_id=self.connector_id,
                connector_version=self.connector_version,
                capture_media_type=self.capture_media_type,
            )
        except ValueError as exc:
            raise ValueError("managed connector descriptor is invalid") from exc
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            self.model_dump(mode="json"),
            limits=_PROFILE_LIMITS,
        )

    @property
    def digest(self) -> str:
        return _sha256(self.canonical_bytes())

    @property
    def descriptor(self) -> ConnectorDescriptor:
        return ConnectorDescriptor(
            connector_id=self.connector_id,
            connector_version=self.connector_version,
            capture_media_type=self.capture_media_type,
        )


class PamReceiptVerificationContext(_StrictFrozenModel):
    """Exact public anchors handed to one vendor-specific PAM verifier."""

    job_digest: str = Field(pattern=_DIGEST_PATTERN)
    run_id: str = Field(pattern=_DIGEST_PATTERN)
    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    source_locator_digest: str = Field(pattern=_DIGEST_PATTERN)
    capture_receipt_digest: str = Field(pattern=_DIGEST_PATTERN)
    capture_records_digest: str = Field(pattern=_DIGEST_PATTERN)
    authorization_profile_id: str = Field(min_length=1, max_length=256)
    authorization_profile_digest: str = Field(pattern=_DIGEST_PATTERN)
    authorization_binding_digest: str = Field(pattern=_DIGEST_PATTERN)
    capture_window_end_epoch_millis: int = Field(ge=0)

    @model_validator(mode="after")
    def portable_profile(self) -> PamReceiptVerificationContext:
        if (
            _AUTHORIZATION_PROFILE_ID_RE.fullmatch(self.authorization_profile_id)
            is None
        ):
            raise ValueError("authorization profile id is not portable")
        return self


class VerifiedPamLifecycleReceipt(_StrictFrozenModel):
    """Vendor-neutral result proving one bounded PAM lifecycle is closed."""

    media_type: Literal[
        "application/vnd.control-assurance.pam-lifecycle-verification.v1+json"
    ] = MANAGED_PAM_VERIFICATION_MEDIA_TYPE
    schema_version: Literal["1.0.0"] = MANAGED_PAM_VERIFICATION_SCHEMA_VERSION
    verifier_id: str = Field(min_length=1, max_length=256)
    receipt_digest: str = Field(pattern=_DIGEST_PATTERN)
    job_digest: str = Field(pattern=_DIGEST_PATTERN)
    run_id: str = Field(pattern=_DIGEST_PATTERN)
    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    source_locator_digest: str = Field(pattern=_DIGEST_PATTERN)
    capture_receipt_digest: str = Field(pattern=_DIGEST_PATTERN)
    capture_records_digest: str = Field(pattern=_DIGEST_PATTERN)
    authorization_profile_id: str = Field(min_length=1, max_length=256)
    authorization_profile_digest: str = Field(pattern=_DIGEST_PATTERN)
    authorization_binding_digest: str = Field(pattern=_DIGEST_PATTERN)
    lifecycle_reference_digest: str = Field(pattern=_DIGEST_PATTERN)
    closure_state: Literal["closed"] = "closed"
    credential_exposure_state: Literal[
        "revoked",
        "released-awaiting-expiry",
    ]
    residual_exposure_end_epoch_millis: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def portable_identities(self) -> VerifiedPamLifecycleReceipt:
        if _VERIFIER_ID_RE.fullmatch(self.verifier_id) is None:
            raise ValueError("PAM verifier id is not portable")
        if (
            _AUTHORIZATION_PROFILE_ID_RE.fullmatch(self.authorization_profile_id)
            is None
        ):
            raise ValueError("authorization profile id is not portable")
        if (
            self.credential_exposure_state == "revoked"
            and self.residual_exposure_end_epoch_millis is not None
        ):
            raise ValueError(
                "revoked credentials cannot retain a residual exposure bound"
            )
        if (
            self.credential_exposure_state == "released-awaiting-expiry"
            and self.residual_exposure_end_epoch_millis is None
        ):
            raise ValueError(
                "released credentials require a residual exposure bound"
            )
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            self.model_dump(mode="json"),
            limits=_PROFILE_LIMITS,
        )


PamReceiptVerifier = Callable[
    [bytes, PamReceiptVerificationContext],
    VerifiedPamLifecycleReceipt,
]


class ManagedConnectorEvidenceBundle(_StrictFrozenModel):
    """Identity returned only after write, snapshot, reopen, and reverify."""

    cab_id: str = Field(pattern=r"^cab:sha256:[a-f0-9]{64}$")
    stream_snapshot_root: Path
    snapshot_digest: str = Field(pattern=_DIGEST_PATTERN)
    job_digest: str = Field(pattern=_DIGEST_PATTERN)
    source_receipt_digest: str = Field(pattern=_DIGEST_PATTERN)
    records_digest: str = Field(pattern=_DIGEST_PATTERN)
    pam_receipt_digest: str = Field(pattern=_DIGEST_PATTERN)
    evaluation_digest: str = Field(pattern=_DIGEST_PATTERN)
    record_count: int = Field(ge=0)
    connector_verification: bytes
    pam_verification: VerifiedPamLifecycleReceipt
    evaluation: AlertWindowEvaluation


class VerifiedManagedConnectorEvidenceBundle(_StrictFrozenModel):
    """A streamed managed CAB reopened under external anchors."""

    cab_id: str = Field(pattern=r"^cab:sha256:[a-f0-9]{64}$")
    snapshot_digest: str = Field(pattern=_DIGEST_PATTERN)
    job_digest: str = Field(pattern=_DIGEST_PATTERN)
    source_receipt_digest: str = Field(pattern=_DIGEST_PATTERN)
    records_digest: str = Field(pattern=_DIGEST_PATTERN)
    pam_receipt_digest: str = Field(pattern=_DIGEST_PATTERN)
    evaluation_digest: str = Field(pattern=_DIGEST_PATTERN)
    record_count: int = Field(ge=0)
    connector_verification: bytes
    pam_verification: VerifiedPamLifecycleReceipt
    evaluation: AlertWindowEvaluation


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _require_digest(value: str, *, label: str) -> str:
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        raise ManagedConnectorEvidenceError(f"{label} is not a canonical digest")
    return value


def _require_verifier_id(value: str, *, label: str) -> str:
    if type(value) is not str or _VERIFIER_ID_RE.fullmatch(value) is None:
        raise ManagedConnectorEvidenceError(f"{label} is not portable")
    return value


def _canonical_object(
    value: bytes,
    *,
    label: str,
    limits: JSONLimits,
) -> bytes:
    if type(value) is not bytes or not value:
        raise ManagedConnectorEvidenceError(
            f"{label} must be non-empty immutable bytes"
        )
    try:
        parsed = strict_json_loads(value, limits=limits)
        canonical = canonical_json_bytes(parsed, limits=limits)
    except StrictJSONError as exc:
        raise ManagedConnectorEvidenceError(
            f"{label} is not bounded strict JSON"
        ) from exc
    if not isinstance(parsed, dict) or canonical != value:
        raise ManagedConnectorEvidenceError(
            f"{label} is not one canonical JSON object"
        )
    return canonical


def _control_profile(
    value: bytes,
    *,
    expected_profile_id: str,
    expected_profile_digest: str,
) -> AlertWindowProfile:
    if type(value) is not bytes or len(value) > MAX_MANAGED_CONNECTOR_PROFILE_BYTES:
        raise ManagedConnectorEvidenceError(
            "control profile exceeds the managed evidence profile"
        )
    try:
        return parse_alert_window_profile(
            value,
            expected_profile_id=expected_profile_id,
            expected_profile_digest=expected_profile_digest,
        )
    except (AlertWindowEvaluationError, TypeError, ValueError) as exc:
        raise ManagedConnectorEvidenceError(
            "control profile differs from its external anchor"
        ) from exc


def _authorization_profile(
    value: bytes,
    *,
    expected_profile_id: str,
    expected_profile_digest: str,
) -> ManagedAuthorizationProfile:
    if type(value) is not bytes or len(value) > MAX_MANAGED_CONNECTOR_PROFILE_BYTES:
        raise ManagedConnectorEvidenceError(
            "authorization profile exceeds the managed evidence profile"
        )
    try:
        strict_json_loads(value, limits=_PROFILE_LIMITS)
        profile = ManagedAuthorizationProfile.model_validate_json(value)
    except (StrictJSONError, TypeError, ValueError) as exc:
        raise ManagedConnectorEvidenceError(
            "authorization profile is not canonical bounded public data"
        ) from exc
    if (
        profile.canonical_bytes() != value
        or profile.profile_id != expected_profile_id
        or profile.digest != expected_profile_digest
    ):
        raise ManagedConnectorEvidenceError(
            "authorization profile differs from its external anchor"
        )
    return profile


def _validated_job(
    value: ManagedConnectorEvidenceJob,
) -> ManagedConnectorEvidenceJob:
    if type(value) is not ManagedConnectorEvidenceJob:
        raise TypeError("job must be an exact ManagedConnectorEvidenceJob")
    try:
        encoded = value.canonical_bytes()
        parsed = strict_json_loads(encoded, limits=_PROFILE_LIMITS)
        normalized = ManagedConnectorEvidenceJob.model_validate(parsed)
    except (StrictJSONError, TypeError, ValueError) as exc:
        raise ManagedConnectorEvidenceError(
            "managed connector job is outside the frozen profile"
        ) from exc
    if normalized != value or normalized.canonical_bytes() != encoded:
        raise ManagedConnectorEvidenceError(
            "managed connector job is outside the frozen profile"
        )
    return normalized


def managed_connector_request_bytes(request: dict[str, Any]) -> bytes:
    """Canonicalize one source request under the managed evidence profile."""

    if type(request) is not dict:
        raise TypeError("managed connector request must be an exact dict")
    try:
        encoded = canonical_json_bytes(request, limits=_REQUEST_LIMITS)
    except StrictJSONError as exc:
        raise ManagedConnectorEvidenceError(
            "managed connector request exceeds the evidence profile"
        ) from exc
    return _canonical_object(
        encoded,
        label="managed connector request",
        limits=_REQUEST_LIMITS,
    )


def create_managed_connector_evidence_job(
    *,
    run_id: str,
    tenant_id: str,
    control_id: str,
    control_profile_id: str,
    control_profile_digest: str,
    control_profile_bytes: bytes,
    configuration_digest: str,
    deployment_receipt_digest: str,
    window: ConnectorWindow,
    descriptor: ConnectorDescriptor,
    source_locator_digest: str,
    request_media_type: str,
    request_bytes: bytes,
    authorization_profile_id: str,
    authorization_profile_digest: str,
    authorization_profile_bytes: bytes,
    connector_receipt_verifier_id: str,
    pam_receipt_verifier_id: str,
    data_sensitivity: Sensitivity = Sensitivity.LAB_INTERNAL,
) -> ManagedConnectorEvidenceJob:
    """Create the canonical external run anchor for one managed capture."""

    if type(window) is not ConnectorWindow:
        raise TypeError("window must be an exact ConnectorWindow")
    if type(descriptor) is not ConnectorDescriptor:
        raise TypeError("descriptor must be an exact ConnectorDescriptor")
    if type(data_sensitivity) is not Sensitivity:
        raise TypeError("data sensitivity must be an exact Sensitivity")
    request = _canonical_object(
        request_bytes,
        label="managed connector request",
        limits=_REQUEST_LIMITS,
    )
    _control_profile(
        control_profile_bytes,
        expected_profile_id=control_profile_id,
        expected_profile_digest=control_profile_digest,
    )
    authorization_profile = _authorization_profile(
        authorization_profile_bytes,
        expected_profile_id=authorization_profile_id,
        expected_profile_digest=authorization_profile_digest,
    )
    window_json = window.as_json()
    try:
        return ManagedConnectorEvidenceJob(
            run_id=run_id,
            tenant_id=tenant_id,
            control_id=control_id,
            control_profile_id=control_profile_id,
            control_profile_digest=control_profile_digest,
            configuration_digest=configuration_digest,
            deployment_receipt_digest=deployment_receipt_digest,
            window=ManagedConnectorWindow(
                start_inclusive=window_json["start_inclusive"],
                end_exclusive=window_json["end_exclusive"],
            ),
            connector_id=descriptor.connector_id,
            connector_version=descriptor.connector_version,
            capture_media_type=descriptor.capture_media_type,
            source_locator_digest=source_locator_digest,
            request_media_type=request_media_type,
            request_digest=_sha256(request),
            authorization_profile_id=authorization_profile_id,
            authorization_profile_digest=authorization_profile_digest,
            authorization_binding_digest=(
                authorization_profile.authorization_binding_digest
            ),
            connector_receipt_verifier_id=connector_receipt_verifier_id,
            pam_receipt_verifier_id=pam_receipt_verifier_id,
            data_sensitivity=data_sensitivity.value,
        )
    except (TypeError, ValueError) as exc:
        raise ManagedConnectorEvidenceError(
            "managed connector job is outside the frozen profile"
        ) from exc


def _profile_policy_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "media_type": MANAGED_CONNECTOR_POLICY_MEDIA_TYPE,
            "required_payloads": sorted(_EXPECTED_PATHS),
            "rules": [
                "external-run-job-exact-match",
                "half-open-window-exact-match",
                "configuration-and-deployment-exact-match",
                "connector-receipt-independent-recomputation",
                "records-byte-exact-match",
                "pam-lifecycle-independent-closure-verification",
                "pam-request-source-capture-exact-binding",
                "credential-exposure-never-overstated",
                "residual-credential-exposure-explicitly-bounded",
                "control-profile-external-exact-match",
                "control-evaluation-independent-recomputation",
                "missing-field-evidence-remains-unresolved",
                "authorization-profile-public-exact-match",
                "verifier-identity-exact-match",
                "no-optimistic-partial-result",
            ],
            "schema_version": MANAGED_CONNECTOR_SCHEMA_VERSION,
        },
        limits=_PROFILE_LIMITS,
    )


def _require_capture_limits(
    *,
    source_receipt: bytes,
    records: bytes,
    pam_receipt: bytes,
) -> None:
    if len(source_receipt) > MAX_MANAGED_CONNECTOR_SOURCE_RECEIPT_BYTES:
        raise ManagedConnectorEvidenceError(
            "source receipt exceeds the managed evidence profile"
        )
    if len(records) > MAX_MANAGED_CONNECTOR_RECORD_BYTES:
        raise ManagedConnectorEvidenceError(
            "source records exceed the managed evidence profile"
        )
    if len(pam_receipt) > MAX_MANAGED_CONNECTOR_PAM_RECEIPT_BYTES:
        raise ManagedConnectorEvidenceError(
            "PAM receipt exceeds the managed evidence profile"
        )


def _assert_capture_matches(
    *,
    capture: ConnectorCapture,
    verified: VerifiedConnectorCapture,
    job: ManagedConnectorEvidenceJob,
) -> None:
    if type(capture) is not ConnectorCapture:
        raise TypeError("capture must be an exact ConnectorCapture")
    if type(verified) is not VerifiedConnectorCapture:
        raise ManagedConnectorEvidenceError(
            "connector receipt verifier returned an unsupported result"
        )
    if capture.descriptor != verified.descriptor:
        raise ManagedConnectorEvidenceError(
            "capture and connector verifier identify different descriptors"
        )
    if capture.descriptor != job.descriptor:
        raise ManagedConnectorEvidenceError(
            "capture descriptor differs from the external run anchor"
        )
    if verified.source_locator_digest != job.source_locator_digest:
        raise ManagedConnectorEvidenceError(
            "verified source differs from the external run anchor"
        )
    if (
        capture.receipt_digest != verified.receipt_digest
        or capture.records_jsonl != verified.records_jsonl
        or capture.records_digest != verified.records_digest
        or capture.record_count != verified.record_count
    ):
        raise ManagedConnectorEvidenceError(
            "collector output differs from independent receipt recomputation"
        )


def _connector_verification_bytes(
    *,
    job: ManagedConnectorEvidenceJob,
    verified: VerifiedConnectorCapture,
) -> bytes:
    return canonical_json_bytes(
        {
            "connector": {
                "capture_media_type": verified.descriptor.capture_media_type,
                "id": verified.descriptor.connector_id,
                "version": verified.descriptor.connector_version,
            },
            "job_digest": job.digest,
            "media_type": MANAGED_CONNECTOR_VERIFICATION_MEDIA_TYPE,
            "record_count": verified.record_count,
            "records_digest": verified.records_digest,
            "receipt_digest": verified.receipt_digest,
            "schema_version": MANAGED_CONNECTOR_SCHEMA_VERSION,
            "source": {
                "locator_digest": verified.source_locator_digest,
                "product": verified.source_product,
                "version": verified.source_version,
            },
            "verifier_id": job.connector_receipt_verifier_id,
        },
        limits=_PROFILE_LIMITS,
    )


def _evaluate_control(
    *,
    job: ManagedConnectorEvidenceJob,
    control_profile_bytes: bytes,
    verified: VerifiedConnectorCapture,
) -> AlertWindowEvaluation:
    profile = _control_profile(
        control_profile_bytes,
        expected_profile_id=job.control_profile_id,
        expected_profile_digest=job.control_profile_digest,
    )
    try:
        evaluation = evaluate_alert_window(
            profile=profile,
            expected_profile_digest=job.control_profile_digest,
            source_kind=profile.source_kind,
            records_jsonl=verified.records_jsonl,
            window_start=job.window.start,
            window_end=job.window.end,
        )
    except (AlertWindowEvaluationError, TypeError, ValueError) as exc:
        raise ManagedConnectorEvidenceError(
            "source records could not be evaluated under the control profile"
        ) from exc
    try:
        evaluation_bytes = evaluation.canonical_bytes()
        strict_json_loads(evaluation_bytes, limits=_PROFILE_LIMITS)
        normalized = AlertWindowEvaluation.model_validate_json(evaluation_bytes)
    except (StrictJSONError, TypeError, ValueError) as exc:
        raise ManagedConnectorEvidenceError(
            "control evaluator returned an unsupported result"
        ) from exc
    if normalized != evaluation or normalized.canonical_bytes() != evaluation_bytes:
        raise ManagedConnectorEvidenceError(
            "control evaluator returned an unsupported result"
        )
    if (
        normalized.records_digest != verified.records_digest
        or normalized.record_count != verified.record_count
    ):
        raise ManagedConnectorEvidenceError(
            "control evaluation differs from connector receipt recomputation"
        )
    if len(evaluation_bytes) > MAX_MANAGED_CONNECTOR_PROFILE_BYTES:
        raise ManagedConnectorEvidenceError(
            "control evaluation exceeds the managed evidence profile"
        )
    return normalized


def _pam_context(
    *,
    job: ManagedConnectorEvidenceJob,
    verified: VerifiedConnectorCapture,
) -> PamReceiptVerificationContext:
    return PamReceiptVerificationContext(
        job_digest=job.digest,
        run_id=job.run_id,
        request_digest=job.request_digest,
        source_locator_digest=job.source_locator_digest,
        capture_receipt_digest=verified.receipt_digest,
        capture_records_digest=verified.records_digest,
        authorization_profile_id=job.authorization_profile_id,
        authorization_profile_digest=job.authorization_profile_digest,
        authorization_binding_digest=job.authorization_binding_digest,
        capture_window_end_epoch_millis=int(
            job.window.end.timestamp() * 1_000
        ),
    )


def _assert_pam_verification(
    *,
    receipt_bytes: bytes,
    context: PamReceiptVerificationContext,
    verified: VerifiedPamLifecycleReceipt,
    verifier_id: str,
) -> None:
    if type(verified) is not VerifiedPamLifecycleReceipt:
        raise ManagedConnectorEvidenceError(
            "PAM receipt verifier returned an unsupported result"
        )
    expected = (
        context.job_digest,
        context.run_id,
        context.request_digest,
        context.source_locator_digest,
        context.capture_receipt_digest,
        context.capture_records_digest,
        context.authorization_profile_id,
        context.authorization_profile_digest,
        context.authorization_binding_digest,
    )
    observed = (
        verified.job_digest,
        verified.run_id,
        verified.request_digest,
        verified.source_locator_digest,
        verified.capture_receipt_digest,
        verified.capture_records_digest,
        verified.authorization_profile_id,
        verified.authorization_profile_digest,
        verified.authorization_binding_digest,
    )
    if observed != expected:
        raise ManagedConnectorEvidenceError(
            "PAM verification differs from its external anchors"
        )
    if verified.verifier_id != verifier_id:
        raise ManagedConnectorEvidenceError(
            "PAM verification uses a different verifier identity"
        )
    if verified.receipt_digest != _sha256(receipt_bytes):
        raise ManagedConnectorEvidenceError(
            "PAM verification receipt digest differs from the exact receipt"
        )
    if (
        verified.credential_exposure_state == "released-awaiting-expiry"
        and (
            verified.residual_exposure_end_epoch_millis is None
            or verified.residual_exposure_end_epoch_millis
            <= context.capture_window_end_epoch_millis
        )
    ):
        raise ManagedConnectorEvidenceError(
            "PAM verification residual exposure is not future-bounded"
        )


def _verify_source_receipt(
    *,
    capture: ConnectorCapture,
    job: ManagedConnectorEvidenceJob,
    receipt_verifier: ReceiptVerifier,
) -> VerifiedConnectorCapture:
    try:
        verified = receipt_verifier(capture.receipt_bytes)
    except Exception as exc:
        raise ManagedConnectorEvidenceError(
            "connector receipt verifier rejected the source capture"
        ) from exc
    if type(verified) is not VerifiedConnectorCapture:
        raise ManagedConnectorEvidenceError(
            "connector receipt verifier returned an unsupported result"
        )
    _require_capture_limits(
        source_receipt=capture.receipt_bytes,
        records=verified.records_jsonl,
        pam_receipt=b"",
    )
    _assert_capture_matches(capture=capture, verified=verified, job=job)
    return verified


def _verify_pam_receipt(
    *,
    receipt_bytes: bytes,
    context: PamReceiptVerificationContext,
    pam_receipt_verifier: PamReceiptVerifier,
    verifier_id: str,
) -> VerifiedPamLifecycleReceipt:
    try:
        verified = pam_receipt_verifier(receipt_bytes, context)
    except Exception as exc:
        raise ManagedConnectorEvidenceError(
            "PAM receipt verifier rejected the managed lifecycle"
        ) from exc
    if type(verified) is not VerifiedPamLifecycleReceipt:
        raise ManagedConnectorEvidenceError(
            "PAM receipt verifier returned an unsupported result"
        )
    try:
        verified_bytes = verified.canonical_bytes()
        parsed = strict_json_loads(verified_bytes, limits=_PROFILE_LIMITS)
        normalized = VerifiedPamLifecycleReceipt.model_validate(parsed)
    except (StrictJSONError, TypeError, ValueError) as exc:
        raise ManagedConnectorEvidenceError(
            "PAM receipt verifier returned an unsupported result"
        ) from exc
    if normalized != verified or normalized.canonical_bytes() != verified_bytes:
        raise ManagedConnectorEvidenceError(
            "PAM receipt verifier returned an unsupported result"
        )
    _assert_pam_verification(
        receipt_bytes=receipt_bytes,
        context=context,
        verified=normalized,
        verifier_id=verifier_id,
    )
    return normalized


def _require_verifier_selection(
    *,
    job: ManagedConnectorEvidenceJob,
    connector_receipt_verifier_id: str,
    pam_receipt_verifier_id: str,
) -> None:
    connector_id = _require_verifier_id(
        connector_receipt_verifier_id,
        label="connector receipt verifier id",
    )
    pam_id = _require_verifier_id(
        pam_receipt_verifier_id,
        label="PAM receipt verifier id",
    )
    if (
        connector_id != job.connector_receipt_verifier_id
        or pam_id != job.pam_receipt_verifier_id
    ):
        raise ManagedConnectorEvidenceError(
            "selected verifier identity differs from the external run anchor"
        )


def write_managed_connector_evidence_bundle(
    destination: Path,
    *,
    stream_snapshot_destination: Path | None = None,
    job: ManagedConnectorEvidenceJob,
    request_bytes: bytes,
    control_profile_bytes: bytes,
    authorization_profile_bytes: bytes,
    capture: ConnectorCapture,
    pam_receipt_bytes: bytes,
    pam_receipt_digest: str,
    receipt_verifier: ReceiptVerifier,
    connector_receipt_verifier_id: str,
    pam_receipt_verifier: PamReceiptVerifier,
    pam_receipt_verifier_id: str,
    created_at: datetime,
    source_revision: str,
    parent_bundles: tuple[str, ...] = (),
) -> ManagedConnectorEvidenceBundle:
    """Write, stream-snapshot, reopen, and semantically reverify one run."""

    job = _validated_job(job)
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
        raise ManagedConnectorEvidenceError(
            "managed CAB and stream snapshot destinations must not overlap"
        )
    if stream_snapshot_destination.exists() or stream_snapshot_destination.is_symlink():
        raise ManagedConnectorEvidenceError(
            "managed stream snapshot destination already exists"
        )
    _require_verifier_selection(
        job=job,
        connector_receipt_verifier_id=connector_receipt_verifier_id,
        pam_receipt_verifier_id=pam_receipt_verifier_id,
    )
    request = _canonical_object(
        request_bytes,
        label="managed connector request",
        limits=_REQUEST_LIMITS,
    )
    if _sha256(request) != job.request_digest:
        raise ManagedConnectorEvidenceError(
            "managed connector request differs from the external run anchor"
        )
    control_profile = _control_profile(
        control_profile_bytes,
        expected_profile_id=job.control_profile_id,
        expected_profile_digest=job.control_profile_digest,
    )
    control_profile_bytes = control_profile.canonical_bytes()
    authorization_profile = _authorization_profile(
        authorization_profile_bytes,
        expected_profile_id=job.authorization_profile_id,
        expected_profile_digest=job.authorization_profile_digest,
    )
    if (
        authorization_profile.authorization_binding_digest
        != job.authorization_binding_digest
    ):
        raise ManagedConnectorEvidenceError(
            "authorization profile binding differs from the external run anchor"
        )
    authorization_profile_bytes = authorization_profile.canonical_bytes()
    pam_receipt = _canonical_object(
        pam_receipt_bytes,
        label="PAM lifecycle receipt",
        limits=_PAM_RECEIPT_LIMITS,
    )
    claimed_pam_digest = _require_digest(
        pam_receipt_digest,
        label="PAM receipt digest",
    )
    if _sha256(pam_receipt) != claimed_pam_digest:
        raise ManagedConnectorEvidenceError(
            "claimed PAM receipt digest differs from the exact receipt"
        )
    _require_capture_limits(
        source_receipt=capture.receipt_bytes,
        records=capture.records_jsonl,
        pam_receipt=pam_receipt,
    )
    verified_capture = _verify_source_receipt(
        capture=capture,
        job=job,
        receipt_verifier=receipt_verifier,
    )
    context = _pam_context(job=job, verified=verified_capture)
    verified_pam = _verify_pam_receipt(
        receipt_bytes=pam_receipt,
        context=context,
        pam_receipt_verifier=pam_receipt_verifier,
        verifier_id=pam_receipt_verifier_id,
    )

    job_bytes = job.canonical_bytes()
    policy_bytes = _profile_policy_bytes()
    connector_verification = _connector_verification_bytes(
        job=job,
        verified=verified_capture,
    )
    evaluation = _evaluate_control(
        job=job,
        control_profile_bytes=control_profile_bytes,
        verified=verified_capture,
    )
    evaluation_bytes = evaluation.canonical_bytes()
    pam_verification = verified_pam.canonical_bytes()
    sensitivity = Sensitivity(job.data_sensitivity)
    metadata = BundleMetadata(
        created_at=created_at,
        as_of=job.window.end,
        experiment=ExperimentRef(
            id=job.run_id,
            spec_version=MANAGED_CONNECTOR_SPEC_VERSION,
            spec_digest=job.digest,
        ),
        evaluation=EvaluationRef(
            policy_id="policy:managed-connector-evidence:v2",
            policy_digest=_sha256(policy_bytes),
            evaluator=EvaluatorRef(
                name=MANAGED_CONNECTOR_EVALUATOR_ID,
                version=__version__,
                source_revision=source_revision,
                image_digest=None,
            ),
        ),
        parent_bundles=parent_bundles,
    )
    payloads = (
        PayloadFile(
            path=_JOB_PATH,
            content=job_bytes,
            media_type=MANAGED_CONNECTOR_JOB_MEDIA_TYPE,
            role="external-managed-run-anchor",
            sensitivity=sensitivity,
            required_for=("managed-capture-recomputation", "admission"),
        ),
        PayloadFile(
            path=_REQUEST_PATH,
            content=request,
            media_type=job.request_media_type,
            role="exact-structured-connector-request",
            sensitivity=sensitivity,
            required_for=("managed-capture-recomputation", "admission"),
        ),
        PayloadFile(
            path=_CONTROL_PROFILE_PATH,
            content=control_profile_bytes,
            media_type=ALERT_WINDOW_PROFILE_MEDIA_TYPE,
            role="external-control-profile",
            sensitivity=sensitivity,
            required_for=(
                "managed-capture-recomputation",
                "control-evaluation",
                "admission",
            ),
        ),
        PayloadFile(
            path=_AUTHORIZATION_PROFILE_PATH,
            content=authorization_profile_bytes,
            media_type=MANAGED_AUTHORIZATION_PROFILE_MEDIA_TYPE,
            role="external-authorization-profile",
            sensitivity=sensitivity,
            required_for=(
                "managed-capture-recomputation",
                "pam-lifecycle-verification",
                "admission",
            ),
        ),
        PayloadFile(
            path=_POLICY_PATH,
            content=policy_bytes,
            media_type=MANAGED_CONNECTOR_POLICY_MEDIA_TYPE,
            role="frozen-managed-evidence-policy",
            sensitivity=sensitivity,
            required_for=("managed-capture-recomputation",),
        ),
        PayloadFile(
            path=_SOURCE_RECEIPT_PATH,
            content=capture.receipt_bytes,
            media_type=job.capture_media_type,
            role="exact-source-exchange-receipt",
            sensitivity=sensitivity,
            required_for=("managed-capture-recomputation", "admission"),
        ),
        PayloadFile(
            path=_RECORDS_PATH,
            content=capture.records_jsonl,
            media_type="application/x-ndjson",
            role="canonical-source-records",
            sensitivity=sensitivity,
            required_for=("managed-capture-recomputation", "control-evaluation"),
        ),
        PayloadFile(
            path=_CONNECTOR_VERIFICATION_PATH,
            content=connector_verification,
            media_type=MANAGED_CONNECTOR_VERIFICATION_MEDIA_TYPE,
            role="recomputed-connector-verification",
            sensitivity=sensitivity,
            required_for=("managed-capture-recomputation",),
        ),
        PayloadFile(
            path=_PAM_RECEIPT_PATH,
            content=pam_receipt,
            media_type="application/json",
            role="exact-pam-lifecycle-receipt",
            sensitivity=sensitivity,
            required_for=("managed-capture-recomputation", "admission"),
        ),
        PayloadFile(
            path=_PAM_VERIFICATION_PATH,
            content=pam_verification,
            media_type=MANAGED_PAM_VERIFICATION_MEDIA_TYPE,
            role="recomputed-pam-lifecycle-verification",
            sensitivity=sensitivity,
            required_for=("managed-capture-recomputation",),
        ),
        PayloadFile(
            path=_CONTROL_EVALUATION_PATH,
            content=evaluation_bytes,
            media_type=ALERT_WINDOW_EVALUATION_MEDIA_TYPE,
            role="recomputed-control-evaluation",
            sensitivity=sensitivity,
            required_for=("control-evaluation", "admission"),
        ),
    )
    try:
        result = write_bundle(
            destination,
            metadata=metadata,
            payloads=payloads,
            limits=_BUNDLE_LIMITS,
        )
    except Exception as exc:
        raise ManagedConnectorEvidenceError(
            "managed evidence CAB could not be written safely"
        ) from exc
    if result.status != BundleStatus.INTEGRITY_VERIFIED or result.bundle_id is None:
        raise ManagedConnectorEvidenceError(
            "managed evidence CAB failed integrity verification"
        )
    try:
        streamed = capture_streamed_cab_snapshot(
            destination,
            stream_snapshot_destination,
            limits=_STREAM_LIMITS,
        )
    except Exception as exc:
        raise ManagedConnectorEvidenceError(
            "managed evidence CAB could not enter a stream snapshot"
        ) from exc
    reopened = verify_streamed_managed_connector_evidence_bundle(
        stream_snapshot_destination,
        expected_snapshot_digest=streamed.snapshot_digest,
        expected_job=job,
        expected_request_bytes=request,
        expected_control_profile_bytes=control_profile_bytes,
        expected_authorization_profile_bytes=authorization_profile_bytes,
        receipt_verifier=receipt_verifier,
        connector_receipt_verifier_id=connector_receipt_verifier_id,
        pam_receipt_verifier=pam_receipt_verifier,
        pam_receipt_verifier_id=pam_receipt_verifier_id,
        expected_source_revision=source_revision,
    )
    if reopened.cab_id != result.bundle_id:
        raise ManagedConnectorEvidenceError(
            "written managed CAB reopened with a different identity"
        )
    return ManagedConnectorEvidenceBundle(
        cab_id=result.bundle_id,
        stream_snapshot_root=stream_snapshot_destination,
        snapshot_digest=streamed.snapshot_digest,
        job_digest=job.digest,
        source_receipt_digest=verified_capture.receipt_digest,
        records_digest=verified_capture.records_digest,
        pam_receipt_digest=verified_pam.receipt_digest,
        evaluation_digest=evaluation.digest,
        record_count=verified_capture.record_count,
        connector_verification=connector_verification,
        pam_verification=verified_pam,
        evaluation=evaluation,
    )


def _load_manifest(value: bytes) -> BundleManifest:
    try:
        strict_json_loads(value, limits=_MANIFEST_LIMITS)
        manifest = BundleManifest.model_validate_json(value)
    except (StrictJSONError, TypeError, ValueError) as exc:
        raise ManagedConnectorEvidenceError("managed CAB manifest is invalid") from exc
    if manifest.canonical_bytes() != value:
        raise ManagedConnectorEvidenceError(
            "managed CAB manifest is not canonical JSON"
        )
    return manifest


def _load_job(value: bytes) -> ManagedConnectorEvidenceJob:
    try:
        parsed = strict_json_loads(value, limits=_PROFILE_LIMITS)
        job = ManagedConnectorEvidenceJob.model_validate(parsed)
    except (StrictJSONError, TypeError, ValueError) as exc:
        raise ManagedConnectorEvidenceError("managed CAB job is invalid") from exc
    if job.canonical_bytes() != value:
        raise ManagedConnectorEvidenceError("managed CAB job is not canonical JSON")
    return job


def _require_exact_profile(
    *,
    manifest: BundleManifest,
    entries: dict[str, bytes],
    job: ManagedConnectorEvidenceJob,
    expected_source_revision: str,
) -> None:
    descriptors = {descriptor.path: descriptor for descriptor in manifest.files}
    if frozenset(descriptors) != _EXPECTED_PATHS:
        raise ManagedConnectorEvidenceError(
            "managed CAB contains the wrong payload set"
        )
    if (
        manifest.experiment.id != job.run_id
        or manifest.experiment.spec_version != MANAGED_CONNECTOR_SPEC_VERSION
        or manifest.experiment.spec_digest != job.digest
    ):
        raise ManagedConnectorEvidenceError(
            "managed CAB run identity is inconsistent"
        )
    policy_digest = _sha256(entries[_POLICY_PATH])
    if (
        manifest.evaluation.policy_id != "policy:managed-connector-evidence:v2"
        or manifest.evaluation.policy_digest != policy_digest
        or manifest.evaluation.evaluator.name != MANAGED_CONNECTOR_EVALUATOR_ID
        or manifest.evaluation.evaluator.version != __version__
        or manifest.evaluation.evaluator.source_revision != expected_source_revision
        or manifest.evaluation.evaluator.image_digest is not None
    ):
        raise ManagedConnectorEvidenceError(
            "managed CAB evaluator identity is inconsistent"
        )
    expected_media_types = {
        _JOB_PATH: MANAGED_CONNECTOR_JOB_MEDIA_TYPE,
        _REQUEST_PATH: job.request_media_type,
        _CONTROL_PROFILE_PATH: ALERT_WINDOW_PROFILE_MEDIA_TYPE,
        _AUTHORIZATION_PROFILE_PATH: MANAGED_AUTHORIZATION_PROFILE_MEDIA_TYPE,
        _POLICY_PATH: MANAGED_CONNECTOR_POLICY_MEDIA_TYPE,
        _SOURCE_RECEIPT_PATH: job.capture_media_type,
        _RECORDS_PATH: "application/x-ndjson",
        _CONNECTOR_VERIFICATION_PATH: MANAGED_CONNECTOR_VERIFICATION_MEDIA_TYPE,
        _PAM_RECEIPT_PATH: "application/json",
        _PAM_VERIFICATION_PATH: MANAGED_PAM_VERIFICATION_MEDIA_TYPE,
        _CONTROL_EVALUATION_PATH: ALERT_WINDOW_EVALUATION_MEDIA_TYPE,
    }
    expected_roles = {
        _JOB_PATH: (
            "external-managed-run-anchor",
            ["managed-capture-recomputation", "admission"],
        ),
        _REQUEST_PATH: (
            "exact-structured-connector-request",
            ["managed-capture-recomputation", "admission"],
        ),
        _CONTROL_PROFILE_PATH: (
            "external-control-profile",
            ["managed-capture-recomputation", "control-evaluation", "admission"],
        ),
        _AUTHORIZATION_PROFILE_PATH: (
            "external-authorization-profile",
            [
                "managed-capture-recomputation",
                "pam-lifecycle-verification",
                "admission",
            ],
        ),
        _POLICY_PATH: (
            "frozen-managed-evidence-policy",
            ["managed-capture-recomputation"],
        ),
        _SOURCE_RECEIPT_PATH: (
            "exact-source-exchange-receipt",
            ["managed-capture-recomputation", "admission"],
        ),
        _RECORDS_PATH: (
            "canonical-source-records",
            ["managed-capture-recomputation", "control-evaluation"],
        ),
        _CONNECTOR_VERIFICATION_PATH: (
            "recomputed-connector-verification",
            ["managed-capture-recomputation"],
        ),
        _PAM_RECEIPT_PATH: (
            "exact-pam-lifecycle-receipt",
            ["managed-capture-recomputation", "admission"],
        ),
        _PAM_VERIFICATION_PATH: (
            "recomputed-pam-lifecycle-verification",
            ["managed-capture-recomputation"],
        ),
        _CONTROL_EVALUATION_PATH: (
            "recomputed-control-evaluation",
            ["control-evaluation", "admission"],
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
            raise ManagedConnectorEvidenceError(
                "managed CAB payload descriptor is inconsistent"
            )
    if entries[_POLICY_PATH] != _profile_policy_bytes():
        raise ManagedConnectorEvidenceError(
            "managed CAB policy differs from the frozen profile"
        )


def _descriptor_digest(
    *,
    manifest: BundleManifest,
    path: str,
) -> tuple[str, int]:
    descriptor = next(
        (candidate for candidate in manifest.files if candidate.path == path),
        None,
    )
    if descriptor is None:
        raise ManagedConnectorEvidenceError("managed CAB payload is absent")
    return f"sha256:{descriptor.sha256}", descriptor.size


def _verify_reopened_entries(
    *,
    cab_id: str,
    snapshot_digest: str,
    manifest: BundleManifest,
    entries: dict[str, bytes],
    expected_job: ManagedConnectorEvidenceJob,
    request: bytes,
    control_profile_bytes: bytes,
    authorization_profile_bytes: bytes,
    receipt_verifier: ReceiptVerifier,
    pam_receipt_verifier: PamReceiptVerifier,
    expected_source_revision: str,
) -> VerifiedManagedConnectorEvidenceBundle:
    observed_job = _load_job(entries.get(_JOB_PATH, b""))
    if (
        observed_job != expected_job
        or entries.get(_JOB_PATH) != expected_job.canonical_bytes()
    ):
        raise ManagedConnectorEvidenceError(
            "managed CAB job differs from the external run anchor"
        )
    if entries.get(_REQUEST_PATH) != request:
        raise ManagedConnectorEvidenceError(
            "managed CAB request differs from the external request"
        )
    if entries.get(_CONTROL_PROFILE_PATH) != control_profile_bytes:
        raise ManagedConnectorEvidenceError(
            "managed CAB control profile differs from the external profile"
        )
    if entries.get(_AUTHORIZATION_PROFILE_PATH) != authorization_profile_bytes:
        raise ManagedConnectorEvidenceError(
            "managed CAB authorization profile differs from the external profile"
        )
    _require_exact_profile(
        manifest=manifest,
        entries=entries,
        job=observed_job,
        expected_source_revision=expected_source_revision,
    )

    source_receipt = entries.get(_SOURCE_RECEIPT_PATH)
    pam_receipt = entries.get(_PAM_RECEIPT_PATH)
    if source_receipt is None or pam_receipt is None:
        raise ManagedConnectorEvidenceError(
            "managed CAB does not contain both exact receipts"
        )
    _canonical_object(
        pam_receipt,
        label="PAM lifecycle receipt",
        limits=_PAM_RECEIPT_LIMITS,
    )
    source_digest, source_size = _descriptor_digest(
        manifest=manifest,
        path=_SOURCE_RECEIPT_PATH,
    )
    records_digest, records_size = _descriptor_digest(
        manifest=manifest,
        path=_RECORDS_PATH,
    )
    pam_digest, pam_size = _descriptor_digest(
        manifest=manifest,
        path=_PAM_RECEIPT_PATH,
    )
    if source_digest != _sha256(source_receipt) or source_size != len(source_receipt):
        raise ManagedConnectorEvidenceError(
            "managed CAB source receipt descriptor differs"
        )
    if pam_digest != _sha256(pam_receipt) or pam_size != len(pam_receipt):
        raise ManagedConnectorEvidenceError(
            "managed CAB PAM receipt descriptor differs"
        )
    try:
        verified_capture = receipt_verifier(source_receipt)
    except Exception as exc:
        raise ManagedConnectorEvidenceError(
            "connector receipt verifier rejected the reopened CAB"
        ) from exc
    if type(verified_capture) is not VerifiedConnectorCapture:
        raise ManagedConnectorEvidenceError(
            "connector receipt verifier returned an unsupported result"
        )
    _require_capture_limits(
        source_receipt=source_receipt,
        records=verified_capture.records_jsonl,
        pam_receipt=pam_receipt,
    )
    if (
        verified_capture.descriptor != expected_job.descriptor
        or verified_capture.source_locator_digest
        != expected_job.source_locator_digest
    ):
        raise ManagedConnectorEvidenceError(
            "reverified connector capture differs from the external run anchor"
        )
    if (
        source_digest != verified_capture.receipt_digest
        or records_digest != verified_capture.records_digest
        or records_size != len(verified_capture.records_jsonl)
    ):
        raise ManagedConnectorEvidenceError(
            "managed CAB source artifacts differ from receipt recomputation"
        )
    connector_verification = _connector_verification_bytes(
        job=expected_job,
        verified=verified_capture,
    )
    if entries.get(_CONNECTOR_VERIFICATION_PATH) != connector_verification:
        raise ManagedConnectorEvidenceError(
            "managed CAB connector verification was not recomputed exactly"
        )
    evaluation = _evaluate_control(
        job=expected_job,
        control_profile_bytes=control_profile_bytes,
        verified=verified_capture,
    )
    evaluation_bytes = evaluation.canonical_bytes()
    if entries.get(_CONTROL_EVALUATION_PATH) != evaluation_bytes:
        raise ManagedConnectorEvidenceError(
            "managed CAB control evaluation was not recomputed exactly"
        )
    evaluation_digest, evaluation_size = _descriptor_digest(
        manifest=manifest,
        path=_CONTROL_EVALUATION_PATH,
    )
    if (
        evaluation_digest != evaluation.digest
        or evaluation_size != len(evaluation_bytes)
    ):
        raise ManagedConnectorEvidenceError(
            "managed CAB control evaluation descriptor differs"
        )

    context = _pam_context(job=expected_job, verified=verified_capture)
    verified_pam = _verify_pam_receipt(
        receipt_bytes=pam_receipt,
        context=context,
        pam_receipt_verifier=pam_receipt_verifier,
        verifier_id=expected_job.pam_receipt_verifier_id,
    )
    if entries.get(_PAM_VERIFICATION_PATH) != verified_pam.canonical_bytes():
        raise ManagedConnectorEvidenceError(
            "managed CAB PAM verification was not recomputed exactly"
        )
    return VerifiedManagedConnectorEvidenceBundle(
        cab_id=cab_id,
        snapshot_digest=snapshot_digest,
        job_digest=expected_job.digest,
        source_receipt_digest=verified_capture.receipt_digest,
        records_digest=verified_capture.records_digest,
        pam_receipt_digest=verified_pam.receipt_digest,
        evaluation_digest=evaluation.digest,
        record_count=verified_capture.record_count,
        connector_verification=connector_verification,
        pam_verification=verified_pam,
        evaluation=evaluation,
    )


def verify_streamed_managed_connector_evidence_bundle(
    snapshot_root: Path,
    *,
    expected_snapshot_digest: str,
    expected_job: ManagedConnectorEvidenceJob,
    expected_request_bytes: bytes,
    expected_control_profile_bytes: bytes,
    expected_authorization_profile_bytes: bytes,
    receipt_verifier: ReceiptVerifier,
    connector_receipt_verifier_id: str,
    pam_receipt_verifier: PamReceiptVerifier,
    pam_receipt_verifier_id: str,
    expected_source_revision: str,
) -> VerifiedManagedConnectorEvidenceBundle:
    """Reopen and reverify a streamed managed CAB under external authority."""

    expected_job = _validated_job(expected_job)
    _require_verifier_selection(
        job=expected_job,
        connector_receipt_verifier_id=connector_receipt_verifier_id,
        pam_receipt_verifier_id=pam_receipt_verifier_id,
    )
    request = _canonical_object(
        expected_request_bytes,
        label="managed connector request",
        limits=_REQUEST_LIMITS,
    )
    if _sha256(request) != expected_job.request_digest:
        raise ManagedConnectorEvidenceError(
            "expected request differs from the external run anchor"
        )
    control_profile = _control_profile(
        expected_control_profile_bytes,
        expected_profile_id=expected_job.control_profile_id,
        expected_profile_digest=expected_job.control_profile_digest,
    )
    control_profile_bytes = control_profile.canonical_bytes()
    authorization_profile = _authorization_profile(
        expected_authorization_profile_bytes,
        expected_profile_id=expected_job.authorization_profile_id,
        expected_profile_digest=expected_job.authorization_profile_digest,
    )
    if (
        authorization_profile.authorization_binding_digest
        != expected_job.authorization_binding_digest
    ):
        raise ManagedConnectorEvidenceError(
            "authorization profile binding differs from the external run anchor"
        )
    authorization_profile_bytes = authorization_profile.canonical_bytes()
    try:
        streamed, decoded = read_streamed_cab_snapshot_entries(
            snapshot_root,
            expected_snapshot_digest=expected_snapshot_digest,
            entry_limits=dict(_STREAMED_READ_LIMITS),
            limits=_STREAM_LIMITS,
        )
    except Exception as exc:
        raise ManagedConnectorEvidenceError(
            "managed CAB stream snapshot could not be safely reopened"
        ) from exc
    entries = dict(decoded)
    if len(entries) != len(decoded):
        raise ManagedConnectorEvidenceError(
            "managed CAB stream snapshot contains duplicate paths"
        )
    manifest = _load_manifest(entries.get("bundle.json", b""))
    result = _verify_reopened_entries(
        cab_id=streamed.cab_id,
        snapshot_digest=streamed.snapshot_digest,
        manifest=manifest,
        entries=entries,
        expected_job=expected_job,
        request=request,
        control_profile_bytes=control_profile_bytes,
        authorization_profile_bytes=authorization_profile_bytes,
        receipt_verifier=receipt_verifier,
        pam_receipt_verifier=pam_receipt_verifier,
        expected_source_revision=expected_source_revision,
    )
    try:
        closing = verify_streamed_cab_snapshot(
            snapshot_root,
            expected_snapshot_digest=streamed.snapshot_digest,
            limits=_STREAM_LIMITS,
        )
    except Exception as exc:
        raise ManagedConnectorEvidenceError(
            "managed CAB stream snapshot changed during semantic verification"
        ) from exc
    if closing.cab_id != result.cab_id:
        raise ManagedConnectorEvidenceError(
            "managed CAB identity changed during semantic verification"
        )
    return result


__all__ = [
    "MANAGED_AUTHORIZATION_PROFILE_MEDIA_TYPE",
    "MANAGED_CONNECTOR_EVALUATOR_ID",
    "MANAGED_CONNECTOR_JOB_MEDIA_TYPE",
    "MANAGED_CONNECTOR_POLICY_MEDIA_TYPE",
    "MANAGED_CONNECTOR_SCHEMA_VERSION",
    "MANAGED_CONNECTOR_VERIFICATION_MEDIA_TYPE",
    "MANAGED_PAM_VERIFICATION_MEDIA_TYPE",
    "MAX_MANAGED_CONNECTOR_FILES",
    "MAX_MANAGED_CONNECTOR_MANIFEST_BYTES",
    "MAX_MANAGED_CONNECTOR_PAM_RECEIPT_BYTES",
    "MAX_MANAGED_CONNECTOR_PROFILE_BYTES",
    "MAX_MANAGED_CONNECTOR_RECORD_BYTES",
    "MAX_MANAGED_CONNECTOR_SOURCE_RECEIPT_BYTES",
    "MAX_MANAGED_CONNECTOR_TOTAL_BYTES",
    "ManagedAuthorizationProfile",
    "ManagedConnectorEvidenceBundle",
    "ManagedConnectorEvidenceError",
    "ManagedConnectorEvidenceJob",
    "ManagedConnectorWindow",
    "PamReceiptVerificationContext",
    "PamReceiptVerifier",
    "VerifiedManagedConnectorEvidenceBundle",
    "VerifiedPamLifecycleReceipt",
    "create_managed_connector_evidence_job",
    "managed_connector_request_bytes",
    "verify_streamed_managed_connector_evidence_bundle",
    "write_managed_connector_evidence_bundle",
]
