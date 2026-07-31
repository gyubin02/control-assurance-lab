"""Publish one frozen managed-connector observation into durable custody.

This module is the narrow boundary between a prepared SIEM/EDR connector and
the runtime journal.  It does not resolve credentials and it does not invent
runtime authority.  Every external input is reopened against the scheduler's
exact request before the connector is called.

The returned executor receipt is the signed stream-custody closure.  Its
signature authenticates the exact CAB snapshot, component Object Lock
acknowledgements, retention instant, KMS pin, and component VersionIds.  The
closure's own S3 acknowledgement is returned separately because putting that
VersionId inside the bytes being uploaded would be circular.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Literal, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, model_validator

from assurance_lab._version import __version__
from assurance_lab.connectors.contract import ConnectorWindow
from assurance_lab.connectors.defender_xdr import (
    DEFENDER_XDR_CAPTURE_MEDIA_TYPE,
    DEFENDER_XDR_CONNECTOR_ID,
    DefenderXDRRequest,
)
from assurance_lab.connectors.elastic_security import (
    ELASTIC_SECURITY_CAPTURE_MEDIA_TYPE,
    ELASTIC_SECURITY_CONNECTOR_ID,
    ElasticSecurityRequest,
)
from assurance_lab.connectors.managed_evidence import (
    MAX_MANAGED_CONNECTOR_FILES,
    MAX_MANAGED_CONNECTOR_MANIFEST_BYTES,
    MAX_MANAGED_CONNECTOR_SOURCE_RECEIPT_BYTES,
    MAX_MANAGED_CONNECTOR_TOTAL_BYTES,
    ManagedConnectorEvidenceJob,
    VerifiedManagedConnectorEvidenceBundle,
    create_managed_connector_evidence_job,
    verify_streamed_managed_connector_evidence_bundle,
    write_managed_connector_evidence_bundle,
)
from assurance_lab.control_plane.models import (
    ControlConfiguration,
    DefenderSourceConfiguration,
    ElasticSourceConfiguration,
)
from assurance_lab.evidence.admission import (
    DetachedSignature,
    LeaseAuthorityVerifier,
    ReceiptSigner,
)
from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)
from assurance_lab.evidence.s3_object_lock import (
    S3CustodyAcknowledgement,
    S3ObjectLockCustody,
    S3ObjectLockError,
)
from assurance_lab.evidence.stream_custody import (
    CustodyAcknowledgementRecord,
    SignedStreamCustodyClosure,
    StreamCustodyAdapter,
    seal_streamed_cab_snapshot,
    verify_stream_custody_closure,
)
from assurance_lab.evidence.stream_snapshot import (
    StreamSnapshotDescriptor,
    StreamSnapshotLimits,
    capture_streamed_cab_snapshot,
    verify_streamed_cab_snapshot,
)
from assurance_lab.evidence.vault_transit import (
    VaultTransitEd25519ReceiptSigner,
)
from assurance_lab.runtime.custody_identity import (
    ControlRunCustodyRuntimeIdentity,
    CustodyRuntimeIdentityError,
    S3ObjectLockPublicDeploymentIdentity,
    VaultTransitPublicDeploymentIdentity,
    parse_control_run_custody_runtime_identity,
)
from assurance_lab.runtime.execution_identity import (
    EXECUTION_ENVIRONMENT_IDENTITY_MEDIA_TYPE,
    ExecutionEnvironmentIdentity,
    ExecutionEnvironmentIdentityError,
    parse_execution_environment_identity,
)
from assurance_lab.runtime.execution_plan import (
    ControlRunExecutionPlan,
    verify_control_run_execution_plan,
)
from assurance_lab.runtime.managed_source import PreparedManagedSource
from assurance_lab.runtime.models import (
    ControlRunExecutionRequest,
    ControlRunExecutionResult,
    sha256_digest,
)

_DIGEST_RE: Final = re.compile(r"^sha256:[a-f0-9]{64}$")
_CAB_ID_RE: Final = re.compile(r"^cab:sha256:[a-f0-9]{64}$")
_STAGE_RE: Final = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_UTC_SECOND_RE: Final = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
MANAGED_EXECUTION_RECEIPT_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.managed-execution-receipt.v1+json"]
] = "application/vnd.control-assurance.managed-execution-receipt.v1+json"
SIGNED_MANAGED_EXECUTION_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.signed-managed-execution.v1+json"]
] = "application/vnd.control-assurance.signed-managed-execution.v1+json"
MANAGED_EXECUTION_RECEIPT_SCHEMA_VERSION: Final[Literal["1.0.0"]] = "1.0.0"
MANAGED_EXECUTION_SIGNATURE_DOMAIN: Final[
    Literal["control-assurance:managed-execution-receipt:v1"]
] = "control-assurance:managed-execution-receipt:v1"
MAX_MANAGED_EXECUTION_RECEIPT_BYTES: Final = 1024 * 1024
_EXECUTION_SIGNATURE_PREFIX: Final = (
    MANAGED_EXECUTION_SIGNATURE_DOMAIN.encode("ascii") + b"\x00"
)
_EXECUTION_RECEIPT_LIMITS: Final = JSONLimits(
    max_bytes=MAX_MANAGED_EXECUTION_RECEIPT_BYTES,
    max_line_bytes=MAX_MANAGED_EXECUTION_RECEIPT_BYTES,
    max_depth=32,
    max_collection_items=100_000,
    max_string_length=256 * 1024,
)
_MANAGED_STREAM_LIMITS: Final = StreamSnapshotLimits(
    max_manifest_bytes=MAX_MANAGED_CONNECTOR_MANIFEST_BYTES,
    max_file_bytes=MAX_MANAGED_CONNECTOR_SOURCE_RECEIPT_BYTES,
    max_total_bytes=MAX_MANAGED_CONNECTOR_TOTAL_BYTES,
    max_files=MAX_MANAGED_CONNECTOR_FILES,
)


class ManagedEvidencePublicationError(RuntimeError):
    """Secret-free, bounded failure at one stable publication stage."""

    __slots__ = ("stage",)

    def __init__(self, stage: str, detail: str) -> None:
        if type(stage) is not str or _STAGE_RE.fullmatch(stage) is None:
            raise ValueError("publication error stage is invalid")
        if (
            type(detail) is not str
            or not detail
            or len(detail) > 256
            or any(ord(character) < 0x20 for character in detail)
        ):
            raise ValueError("publication error detail is invalid")
        self.stage = stage
        super().__init__(detail)


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class ManagedExecutionReceipt(_StrictFrozenModel):
    """Signed body joining runtime authority to exact immutable custody."""

    media_type: Literal[
        "application/vnd.control-assurance.managed-execution-receipt.v1+json"
    ] = MANAGED_EXECUTION_RECEIPT_MEDIA_TYPE
    schema_version: Literal["1.0.0"] = MANAGED_EXECUTION_RECEIPT_SCHEMA_VERSION
    run_id: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    tenant_id: str = Field(pattern=r"^[a-z][a-z0-9._-]{0,127}$")
    control_id: str = Field(pattern=r"^[a-z][a-z0-9._-]{0,127}$")
    deployment_operation_id: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    deployment_receipt_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    configuration_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    control_profile_id: str = Field(pattern=r"^[a-z][a-z0-9._-]{0,127}$")
    control_profile_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    artifact_set_id: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    custody_scope_id: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    executor_receipt_id: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    execution_plan_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    window_start: str = Field(pattern=_UTC_SECOND_RE.pattern)
    window_end: str = Field(pattern=_UTC_SECOND_RE.pattern)
    prepared_at: str = Field(pattern=_UTC_SECOND_RE.pattern)
    custody_retain_until: str = Field(pattern=_UTC_SECOND_RE.pattern)
    source_kind: Literal["elastic-security", "defender-xdr"]
    source_revision: str = Field(
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._+/@:-]{0,255}$",
    )
    connector_request_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    authorization_profile_id: str = Field(min_length=1, max_length=256)
    authorization_profile_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    authorization_binding_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    execution_environment_identity_media_type: Literal[
        "application/vnd.control-assurance.execution-environment-identity.v1+json"
    ] = EXECUTION_ENVIRONMENT_IDENTITY_MEDIA_TYPE
    execution_environment_identity_digest: str = Field(
        pattern=r"^sha256:[a-f0-9]{64}$"
    )
    custody_deployment_profile_digest: str = Field(
        pattern=r"^sha256:[a-f0-9]{64}$"
    )
    cab_id: str = Field(pattern=r"^cab:sha256:[a-f0-9]{64}$")
    snapshot_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    snapshot_descriptor: StreamSnapshotDescriptor
    job_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    source_receipt_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    records_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    pam_receipt_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    evaluation_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    record_count: int = Field(ge=0)
    exact_versions_reverified: Literal[True] = True
    custody_closure_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    custody_closure: SignedStreamCustodyClosure
    custody_acknowledgement_digest: str = Field(
        pattern=r"^sha256:[a-f0-9]{64}$"
    )
    custody_acknowledgement: CustodyAcknowledgementRecord

    @model_validator(mode="after")
    def receipt_is_closed(self) -> ManagedExecutionReceipt:
        try:
            timestamps = tuple(
                datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
                    tzinfo=UTC
                )
                for value in (
                    self.window_start,
                    self.window_end,
                    self.prepared_at,
                    self.custody_retain_until,
                )
            )
        except ValueError as exc:
            raise ValueError("managed execution receipt timestamp is invalid") from exc
        window_start, window_end, prepared_at, retain_until = timestamps
        if (
            window_end <= window_start
            or prepared_at < window_end
            or retain_until <= prepared_at
        ):
            raise ValueError("managed execution receipt timeline is invalid")
        descriptor_bytes = self.snapshot_descriptor.canonical_bytes()
        closure_bytes = self.custody_closure.canonical_bytes()
        acknowledgement = self.custody_acknowledgement.as_acknowledgement()
        acknowledgement_bytes = acknowledgement.to_canonical_bytes()
        closure_scope = self.custody_closure.receipt.custody
        if (
            self.snapshot_descriptor.snapshot_digest() != self.snapshot_digest
            or self.snapshot_descriptor.cab_id != self.cab_id
            or self.custody_closure.closure_digest()
            != self.custody_closure_digest
            or self.custody_closure.receipt.snapshot_digest
            != self.snapshot_digest
            or self.custody_closure.receipt.cab_id != self.cab_id
            or self.custody_closure.receipt.descriptor_size
            != len(descriptor_bytes)
            or acknowledgement.acknowledgement_digest
            != self.custody_acknowledgement_digest
            or acknowledgement.object_digest != self.custody_closure_digest
            or acknowledgement.bucket_arn_digest
            != closure_scope.bucket_arn_digest
            or acknowledgement.cab_scope_digest
            != closure_scope.cab_scope_digest
            or acknowledgement.encryption != closure_scope.encryption
            or acknowledgement.kms_key_arn_digest
            != closure_scope.kms_key_arn_digest
            or acknowledgement.retain_until != closure_scope.retain_until
            or acknowledgement.retention_mode
            != closure_scope.retention_mode
            or acknowledgement.tenant_scope_digest
            != closure_scope.tenant_scope_digest
            or sha256_digest(closure_bytes) != self.custody_closure_digest
            or sha256_digest(acknowledgement_bytes)
            != self.custody_acknowledgement_digest
            or self.custody_retain_until != closure_scope.retain_until
        ):
            raise ValueError("managed execution receipt crosses its custody boundary")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            self.model_dump(mode="json", warnings="error"),
            limits=_EXECUTION_RECEIPT_LIMITS,
        )

    @property
    def digest(self) -> str:
        return sha256_digest(self.canonical_bytes())


class SignedManagedExecutionReceipt(_StrictFrozenModel):
    """Domain-separated signed executor receipt persisted by the journal."""

    media_type: Literal[
        "application/vnd.control-assurance.signed-managed-execution.v1+json"
    ] = SIGNED_MANAGED_EXECUTION_MEDIA_TYPE
    schema_version: Literal["1.0.0"] = MANAGED_EXECUTION_RECEIPT_SCHEMA_VERSION
    signature_domain: Literal[
        "control-assurance:managed-execution-receipt:v1"
    ] = MANAGED_EXECUTION_SIGNATURE_DOMAIN
    receipt_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    signer_public_key_fingerprint: str = Field(
        pattern=r"^sha256:[a-f0-9]{64}$"
    )
    receipt: ManagedExecutionReceipt
    signature: DetachedSignature

    @model_validator(mode="after")
    def signature_identity_is_closed(self) -> SignedManagedExecutionReceipt:
        inner = self.receipt.custody_closure
        if (
            self.receipt.digest != self.receipt_digest
            or inner.signer_public_key_fingerprint
            != self.signer_public_key_fingerprint
            or inner.signature.key_id != self.signature.key_id
            or inner.signature.algorithm != "ed25519"
            or self.signature.algorithm != "ed25519"
        ):
            raise ValueError("managed executor signature identity is inconsistent")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            self.model_dump(mode="json", warnings="error"),
            limits=_EXECUTION_RECEIPT_LIMITS,
        )

    @property
    def digest(self) -> str:
        return sha256_digest(self.canonical_bytes())


@dataclass(frozen=True, slots=True)
class ManagedExecutionReceiptVerification:
    """Independent result for one journaled managed-execution receipt."""

    receipt: SignedManagedExecutionReceipt
    executor_receipt_digest: str
    evidence_digest: str
    custody_closure_digest: str
    custody_acknowledgement_digest: str
    exact_versions_reverified: bool


@dataclass(frozen=True, slots=True)
class ManagedEvidencePublication:
    """Durable identities returned only after exact-VersionId verification."""

    run_id: str
    artifact_set_id: str
    custody_scope_id: str
    executor_receipt_id: str
    cab_id: str
    evidence_digest: str
    executor_receipt_digest: str
    executor_receipt_bytes: bytes
    custody_acknowledgement_digest: str
    custody_acknowledgement_bytes: bytes
    job_digest: str
    source_receipt_digest: str
    records_digest: str
    pam_receipt_digest: str
    evaluation_digest: str
    record_count: int
    exact_versions_reverified: bool

    def __post_init__(self) -> None:
        digest_values = (
            self.run_id,
            self.artifact_set_id,
            self.custody_scope_id,
            self.executor_receipt_id,
            self.evidence_digest,
            self.executor_receipt_digest,
            self.custody_acknowledgement_digest,
            self.job_digest,
            self.source_receipt_digest,
            self.records_digest,
            self.pam_receipt_digest,
            self.evaluation_digest,
        )
        if any(
            type(value) is not str or _DIGEST_RE.fullmatch(value) is None
            for value in digest_values
        ):
            raise ValueError("publication contains a noncanonical digest")
        if type(self.cab_id) is not str or _CAB_ID_RE.fullmatch(self.cab_id) is None:
            raise ValueError("publication contains a noncanonical CAB id")
        if (
            type(self.executor_receipt_bytes) is not bytes
            or not self.executor_receipt_bytes
            or sha256_digest(self.executor_receipt_bytes)
            != self.executor_receipt_digest
        ):
            raise ValueError("executor receipt digest differs from its exact bytes")
        if (
            type(self.custody_acknowledgement_bytes) is not bytes
            or not self.custody_acknowledgement_bytes
            or sha256_digest(self.custody_acknowledgement_bytes)
            != self.custody_acknowledgement_digest
        ):
            raise ValueError(
                "custody acknowledgement digest differs from its exact bytes"
            )
        if type(self.record_count) is not int or self.record_count < 0:
            raise ValueError("publication record count is invalid")
        if self.exact_versions_reverified is not True:
            raise ValueError("publication did not reverify exact custody versions")
        try:
            envelope = SignedManagedExecutionReceipt.model_validate_json(
                self.executor_receipt_bytes,
                strict=True,
            )
            acknowledgement = S3CustodyAcknowledgement.from_canonical_bytes(
                self.custody_acknowledgement_bytes
            )
        except (S3ObjectLockError, TypeError, ValueError) as exc:
            raise ValueError("publication custody documents are invalid") from exc
        receipt = envelope.receipt
        if (
            envelope.canonical_bytes() != self.executor_receipt_bytes
            or envelope.digest != self.executor_receipt_digest
            or receipt.run_id != self.run_id
            or receipt.artifact_set_id != self.artifact_set_id
            or receipt.custody_scope_id != self.custody_scope_id
            or receipt.executor_receipt_id != self.executor_receipt_id
            or receipt.cab_id != self.cab_id
            or receipt.snapshot_digest != self.evidence_digest
            or receipt.job_digest != self.job_digest
            or receipt.source_receipt_digest != self.source_receipt_digest
            or receipt.records_digest != self.records_digest
            or receipt.pam_receipt_digest != self.pam_receipt_digest
            or receipt.evaluation_digest != self.evaluation_digest
            or receipt.record_count != self.record_count
            or receipt.custody_acknowledgement_digest
            != self.custody_acknowledgement_digest
            or acknowledgement.to_canonical_bytes()
            != self.custody_acknowledgement_bytes
            or acknowledgement.acknowledgement_digest
            != self.custody_acknowledgement_digest
            or receipt.custody_acknowledgement
            != CustodyAcknowledgementRecord.from_acknowledgement(
                acknowledgement
            )
        ):
            raise ValueError("publication custody documents cross their exact boundary")

    def execution_result(self, *, lease_fence: int) -> ControlRunExecutionResult:
        """Project the verified publication into the scheduler's result type."""

        return ControlRunExecutionResult(
            run_id=self.run_id,
            lease_fence=lease_fence,
            evidence_digest=self.evidence_digest,
            executor_receipt_digest=self.executor_receipt_digest,
        )


@dataclass(frozen=True, slots=True)
class _Workspace:
    root: Path
    cab: Path
    snapshot: Path
    device: int
    inode: int
    owner: int


def _workspace(
    work_root: Path,
    *,
    artifact_set_id: str,
) -> _Workspace:
    if not isinstance(work_root, Path):
        raise TypeError("work_root must be a pathlib.Path")
    if not work_root.is_absolute():
        raise ManagedEvidencePublicationError(
            "workspace",
            "managed evidence work root must be absolute",
        )
    current = Path(work_root.anchor)
    try:
        for component in work_root.parts[1:]:
            current /= component
            listed = os.lstat(current)
            if stat.S_ISLNK(listed.st_mode) or not stat.S_ISDIR(listed.st_mode):
                raise ManagedEvidencePublicationError(
                    "workspace",
                    "managed evidence work root contains an unsafe component",
                )
        root_stat = os.lstat(work_root)
    except ManagedEvidencePublicationError:
        raise
    except OSError:
        raise ManagedEvidencePublicationError(
            "workspace",
            "managed evidence work root is unavailable",
        ) from None
    if root_stat.st_uid != os.geteuid() or root_stat.st_mode & 0o022:
        raise ManagedEvidencePublicationError(
            "workspace",
            "managed evidence work root is not owner-controlled",
        )
    leaf = artifact_set_id.removeprefix("sha256:")
    return _Workspace(
        root=work_root,
        cab=work_root / f"{leaf}.managed.cab",
        snapshot=work_root / f"{leaf}.stream-snapshot-v2",
        device=root_stat.st_dev,
        inode=root_stat.st_ino,
        owner=root_stat.st_uid,
    )


def _require_workspace_unchanged(workspace: _Workspace) -> None:
    try:
        current = os.lstat(workspace.root)
    except OSError:
        raise ManagedEvidencePublicationError(
            "workspace",
            "managed evidence work root disappeared",
        ) from None
    if (
        stat.S_ISLNK(current.st_mode)
        or not stat.S_ISDIR(current.st_mode)
        or (current.st_dev, current.st_ino, current.st_uid)
        != (workspace.device, workspace.inode, workspace.owner)
        or current.st_mode & 0o022
    ):
        raise ManagedEvidencePublicationError(
            "workspace",
            "managed evidence work root changed during publication",
        )


def _require_source_binding(
    execution_request: ControlRunExecutionRequest,
    execution_plan: ControlRunExecutionPlan,
    source: PreparedManagedSource,
    *,
    source_revision: str,
) -> None:
    if type(execution_request) is not ControlRunExecutionRequest:
        raise TypeError("execution_request must be exact")
    if type(execution_plan) is not ControlRunExecutionPlan:
        raise TypeError("execution_plan must be exact")
    if type(source) is not PreparedManagedSource:
        raise TypeError("source must be an exact PreparedManagedSource")
    if (
        type(source_revision) is not str
        or not source_revision
        or len(source_revision) > 256
        or source_revision.strip() != source_revision
        or any(ord(character) < 0x20 for character in source_revision)
    ):
        raise ManagedEvidencePublicationError(
            "input",
            "planned source revision is invalid",
        )
    try:
        reopened, request = verify_control_run_execution_plan(
            execution_plan.canonical_bytes(),
            expected_request=execution_request,
        )
    except (TypeError, ValueError):
        raise ManagedEvidencePublicationError(
            "input",
            "execution plan does not match the exact scheduler request",
        ) from None
    if (
        reopened != execution_plan
        or execution_plan.source_revision != source_revision
        or source.connector_request_bytes != execution_plan.connector_request_bytes
        or canonical_json_bytes(request.as_json()) != source.connector_request_bytes
        or type(request) is not type(source.connector_request)
    ):
        raise ManagedEvidencePublicationError(
            "input",
            "managed source does not match the frozen execution plan",
        )
    expected_descriptor = {
        "elastic-security": (
            ElasticSecurityRequest,
            ELASTIC_SECURITY_CONNECTOR_ID,
            ELASTIC_SECURITY_CAPTURE_MEDIA_TYPE,
        ),
        "defender-xdr": (
            DefenderXDRRequest,
            DEFENDER_XDR_CONNECTOR_ID,
            DEFENDER_XDR_CAPTURE_MEDIA_TYPE,
        ),
    }[execution_plan.source_kind]
    request_type, connector_id, capture_media_type = expected_descriptor
    if (
        type(source.connector_request) is not request_type
        or source.descriptor.connector_id != connector_id
        or source.descriptor.connector_version != __version__
        or source.descriptor.capture_media_type != capture_media_type
    ):
        raise ManagedEvidencePublicationError(
            "input",
            "managed source descriptor differs from the frozen connector",
        )
    authorization_bytes = source.authorization_profile.canonical_bytes()
    if (
        sha256_digest(authorization_bytes) != source.authorization_profile.digest
        or source.authorization_profile.canonical_bytes() != authorization_bytes
    ):
        raise ManagedEvidencePublicationError(
            "input",
            "managed authorization profile is not exact",
        )


def _require_execution_environment_binding(
    value: bytes,
    *,
    execution_request: ControlRunExecutionRequest,
    execution_plan: ControlRunExecutionPlan,
    source: PreparedManagedSource,
) -> tuple[ExecutionEnvironmentIdentity, ControlRunCustodyRuntimeIdentity]:
    """Reopen the exact journaled public identity and bind its nested anchors."""

    try:
        identity = parse_execution_environment_identity(value)
        custody_identity = parse_control_run_custody_runtime_identity(
            identity.custody_identity_bytes
        )
        configuration = ControlConfiguration.model_validate_json(
            execution_request.configuration_bytes,
            strict=True,
        )
    except (
        CustodyRuntimeIdentityError,
        ExecutionEnvironmentIdentityError,
        TypeError,
        ValueError,
    ):
        raise ManagedEvidencePublicationError(
            "input",
            "execution environment identity is invalid",
        ) from None
    if (
        configuration.canonical_bytes()
        != execution_request.configuration_bytes
        or identity.run_id != execution_plan.run_id
        or identity.tenant_id != execution_plan.tenant_id
        or identity.control_id != execution_plan.control_id
        or identity.configuration_digest
        != execution_plan.configuration_digest
        or identity.execution_plan_digest != execution_plan.digest
        or identity.source_revision != execution_plan.source_revision
        or identity.source_kind != execution_plan.source_kind
        or custody_identity.run_id != execution_plan.run_id
        or custody_identity.tenant_id != execution_plan.tenant_id
        or custody_identity.control_id != execution_plan.control_id
        or custody_identity.configuration_digest
        != execution_plan.configuration_digest
        or custody_identity.execution_plan_digest != execution_plan.digest
        or custody_identity.custody_scope_id
        != execution_plan.custody_scope_id
        or custody_identity.prepared_at != execution_plan.prepared_at
        or custody_identity.custody_retain_until
        != execution_plan.custody_retain_until
    ):
        raise ManagedEvidencePublicationError(
            "input",
            "execution environment identity differs from frozen runtime authority",
        )
    try:
        source_document = strict_json_loads(identity.source_identity_bytes)
    except StrictJSONError:
        raise ManagedEvidencePublicationError(
            "input",
            "source runtime identity is invalid",
        ) from None
    if not isinstance(source_document, dict):
        raise ManagedEvidencePublicationError(
            "input",
            "source runtime identity is invalid",
        )
    source_configuration = configuration.source
    source_matches = False
    if (
        identity.source_kind == "defender-xdr"
        and isinstance(source_configuration, DefenderSourceConfiguration)
    ):
        source_matches = (
            source_document.get("tenant_id") == source_configuration.tenant_id
            and source_document.get("client_id") == source_configuration.client_id
            and source_document.get("cloud") == source_configuration.cloud
            and source_document.get("permission") == source_configuration.permission
            and source_document.get("table") == source_configuration.table
            and source_document.get("graph_origin_digest")
            == source.source_locator_digest
        )
    elif (
        identity.source_kind == "elastic-security"
        and isinstance(source_configuration, ElasticSourceConfiguration)
    ):
        source_matches = (
            source_document.get("index_alias")
            == source_configuration.index_alias
            and source_document.get("lease_ttl_seconds")
            == source_configuration.lease_ttl_seconds
            and source_document.get("pam_mode") == source_configuration.pam_mode
            and source_document.get("endpoint_origin_digest")
            == source.source_locator_digest
        )
    if not source_matches:
        raise ManagedEvidencePublicationError(
            "input",
            "source runtime identity differs from the prepared managed source",
        )
    return identity, custody_identity


def _require_prepared_runtime_anchors(
    environment_identity: ExecutionEnvironmentIdentity,
    custody_identity: ControlRunCustodyRuntimeIdentity,
    *,
    source: PreparedManagedSource,
    custody: StreamCustodyAdapter,
    receipt_signer: ReceiptSigner,
) -> None:
    """Re-derive every prepared public anchor before an external side effect."""

    if (
        source.runtime_identity_media_type
        != environment_identity.source_identity_media_type
        or source.runtime_identity_bytes
        != environment_identity.source_identity_bytes
        or source.runtime_identity_digest
        != environment_identity.source_identity_digest
    ):
        raise ManagedEvidencePublicationError(
            "input",
            "prepared source runtime identity differs from the durable identity",
        )

    try:
        if type(custody) is S3ObjectLockCustody:
            prepared_custody = (
                S3ObjectLockPublicDeploymentIdentity.from_adapter(custody)
            )
        else:
            prepared_custody = cast(
                Any,
                custody,
            ).public_deployment_identity
        if type(receipt_signer) is VaultTransitEd25519ReceiptSigner:
            prepared_signing = VaultTransitPublicDeploymentIdentity.from_signer(
                receipt_signer
            )
        else:
            prepared_signing = cast(
                Any,
                receipt_signer,
            ).public_deployment_identity
    except Exception:
        raise ManagedEvidencePublicationError(
            "input",
            "prepared custody or signing public identity is unavailable",
        ) from None
    if (
        type(prepared_custody) is not S3ObjectLockPublicDeploymentIdentity
        or prepared_custody != custody_identity.deployment_profile.custody
        or type(prepared_signing) is not VaultTransitPublicDeploymentIdentity
        or prepared_signing != custody_identity.deployment_profile.signing
    ):
        raise ManagedEvidencePublicationError(
            "input",
            "prepared custody or signing runtime differs from the durable identity",
        )

    _key_id, _public_key, signer_fingerprint = _signer_material(
        receipt_signer
    )
    if signer_fingerprint != prepared_signing.public_key_fingerprint:
        raise ManagedEvidencePublicationError(
            "input",
            "prepared signing key differs from its public runtime identity",
        )


def _require_custody_identity_anchors(
    identity: ControlRunCustodyRuntimeIdentity,
    *,
    closure: SignedStreamCustodyClosure,
    receipt_signer: LeaseAuthorityVerifier,
) -> None:
    """Match the public deployment profile to the custody actually exercised."""

    profile = identity.deployment_profile
    custody = profile.custody
    signing = profile.signing
    _key_id, _public_key, signer_fingerprint = _signer_material(receipt_signer)
    scope = closure.receipt.custody
    if (
        sha256_digest(custody.bucket_arn.encode("ascii"))
        != scope.bucket_arn_digest
        or sha256_digest(custody.kms_key_arn.encode("ascii"))
        != scope.kms_key_arn_digest
        or custody.encryption != scope.encryption
        or custody.retention_mode != scope.retention_mode
        or signing.public_key_fingerprint != signer_fingerprint
        or signing.signature_algorithm != closure.signature.algorithm
        or closure.signer_public_key_fingerprint != signer_fingerprint
    ):
        raise ManagedEvidencePublicationError(
            "custody-verify",
            "custody runtime identity differs from exercised public anchors",
        )


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _execution_signing_message(receipt_digest: str) -> bytes:
    if type(receipt_digest) is not str or _DIGEST_RE.fullmatch(receipt_digest) is None:
        raise ValueError("managed execution receipt digest is invalid")
    raw = bytes.fromhex(receipt_digest.removeprefix("sha256:"))
    return _EXECUTION_SIGNATURE_PREFIX + len(raw).to_bytes(2, "big") + raw


def _signer_material(
    signer: LeaseAuthorityVerifier,
) -> tuple[str, bytes, str]:
    try:
        key_id = signer.key_id
        public_key_bytes = signer.public_key_bytes
    except Exception:
        raise ManagedEvidencePublicationError(
            "receipt-sign",
            "managed execution signer identity is unavailable",
        ) from None
    if (
        type(key_id) is not str
        or not key_id
        or len(key_id) > 256
        or type(public_key_bytes) is not bytes
        or len(public_key_bytes) != 32
    ):
        raise ManagedEvidencePublicationError(
            "receipt-sign",
            "managed execution signer identity is invalid",
        )
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes)
    except ValueError:
        raise ManagedEvidencePublicationError(
            "receipt-sign",
            "managed execution signer is not Ed25519",
        ) from None
    return key_id, public_key_bytes, sha256_digest(public_key_bytes)


def _verify_execution_signature(
    envelope: SignedManagedExecutionReceipt,
    *,
    receipt_signer: LeaseAuthorityVerifier,
) -> None:
    key_id, public_key_bytes, fingerprint = _signer_material(receipt_signer)
    if (
        envelope.signer_public_key_fingerprint != fingerprint
        or envelope.signature.key_id != key_id
        or envelope.signature.algorithm != "ed25519"
    ):
        raise ManagedEvidencePublicationError(
            "executor-receipt-verify",
            "managed executor receipt uses a different signer identity",
        )
    try:
        encoded = envelope.signature.signature.encode("ascii", errors="strict")
        signature = base64.b64decode(encoded, validate=True)
        if len(signature) != 64 or base64.b64encode(signature) != encoded:
            raise ValueError
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            signature,
            _execution_signing_message(envelope.receipt_digest),
        )
    except (
        InvalidSignature,
        UnicodeEncodeError,
        ValueError,
        binascii.Error,
    ):
        raise ManagedEvidencePublicationError(
            "executor-receipt-verify",
            "managed executor receipt signature is invalid",
        ) from None


def _parse_execution_receipt(value: bytes) -> SignedManagedExecutionReceipt:
    if (
        type(value) is not bytes
        or not value
        or len(value) > MAX_MANAGED_EXECUTION_RECEIPT_BYTES
    ):
        raise ManagedEvidencePublicationError(
            "executor-receipt-verify",
            "managed executor receipt exceeds its bounded profile",
        )
    try:
        parsed = strict_json_loads(value, limits=_EXECUTION_RECEIPT_LIMITS)
        envelope = SignedManagedExecutionReceipt.model_validate_json(value)
    except (StrictJSONError, TypeError, ValueError):
        raise ManagedEvidencePublicationError(
            "executor-receipt-verify",
            "managed executor receipt is invalid",
        ) from None
    if not isinstance(parsed, dict) or envelope.canonical_bytes() != value:
        raise ManagedEvidencePublicationError(
            "executor-receipt-verify",
            "managed executor receipt is not canonical JSON",
        )
    return envelope


def _sign_execution_receipt(
    receipt: ManagedExecutionReceipt,
    *,
    receipt_signer: ReceiptSigner,
) -> SignedManagedExecutionReceipt:
    if type(receipt) is not ManagedExecutionReceipt:
        raise TypeError("managed execution receipt must be exact")
    before = _signer_material(receipt_signer)
    try:
        signature = receipt_signer.sign(
            _execution_signing_message(receipt.digest)
        )
    except Exception:
        raise ManagedEvidencePublicationError(
            "receipt-sign",
            "managed execution receipt could not be signed",
        ) from None
    if not isinstance(signature, DetachedSignature) or _signer_material(
        receipt_signer
    ) != before:
        raise ManagedEvidencePublicationError(
            "receipt-sign",
            "managed execution signer identity changed while signing",
        )
    try:
        envelope = SignedManagedExecutionReceipt(
            receipt_digest=receipt.digest,
            signer_public_key_fingerprint=before[2],
            receipt=receipt,
            signature=signature,
        )
        encoded = envelope.canonical_bytes()
    except (StrictJSONError, TypeError, ValueError):
        raise ManagedEvidencePublicationError(
            "receipt-sign",
            "managed execution receipt could not enter its bounded profile",
        ) from None
    if len(encoded) > MAX_MANAGED_EXECUTION_RECEIPT_BYTES:
        raise ManagedEvidencePublicationError(
            "receipt-sign",
            "managed execution receipt exceeds the journal limit",
        )
    _verify_execution_signature(envelope, receipt_signer=receipt_signer)
    return envelope


def _job(
    execution_request: ControlRunExecutionRequest,
    execution_plan: ControlRunExecutionPlan,
    source: PreparedManagedSource,
) -> ManagedConnectorEvidenceJob:
    try:
        return create_managed_connector_evidence_job(
            run_id=execution_plan.run_id,
            tenant_id=execution_plan.tenant_id,
            control_id=execution_plan.control_id,
            control_profile_id=execution_plan.control_profile_id,
            control_profile_digest=execution_plan.control_profile_digest,
            control_profile_bytes=execution_request.control_profile_bytes,
            configuration_digest=execution_plan.configuration_digest,
            deployment_receipt_digest=(
                execution_plan.deployment_receipt_digest
            ),
            window=ConnectorWindow(
                start=execution_plan.window_start,
                end=execution_plan.window_end,
            ),
            descriptor=source.descriptor,
            source_locator_digest=source.source_locator_digest,
            request_media_type=execution_plan.connector_request_media_type,
            request_bytes=source.connector_request_bytes,
            authorization_profile_id=source.authorization_profile.profile_id,
            authorization_profile_digest=source.authorization_profile.digest,
            authorization_profile_bytes=(
                source.authorization_profile.canonical_bytes()
            ),
            connector_receipt_verifier_id=(
                source.connector_receipt_verifier_id
            ),
            pam_receipt_verifier_id=source.pam_receipt_verifier_id,
        )
    except (TypeError, ValueError):
        raise ManagedEvidencePublicationError(
            "input",
            "managed evidence job could not be derived from frozen inputs",
        ) from None


def verify_managed_evidence_executor_receipt(
    value: bytes,
    *,
    expected_execution_request: ControlRunExecutionRequest,
    expected_execution_plan: ControlRunExecutionPlan,
    expected_source: PreparedManagedSource,
    execution_environment_identity_bytes: bytes,
    custody: StreamCustodyAdapter,
    receipt_signer: LeaseAuthorityVerifier,
    online_reverify: bool = False,
) -> ManagedExecutionReceiptVerification:
    """Reopen a journaled receipt and optionally reread every exact S3 version."""

    if type(online_reverify) is not bool:
        raise TypeError("online_reverify must be a boolean")
    _require_source_binding(
        expected_execution_request,
        expected_execution_plan,
        expected_source,
        source_revision=expected_execution_plan.source_revision,
    )
    environment_identity, custody_identity = (
        _require_execution_environment_binding(
            execution_environment_identity_bytes,
            execution_request=expected_execution_request,
            execution_plan=expected_execution_plan,
            source=expected_source,
        )
    )
    envelope = _parse_execution_receipt(value)
    _verify_execution_signature(envelope, receipt_signer=receipt_signer)
    receipt = envelope.receipt
    authorization = expected_source.authorization_profile
    expected_job = _job(
        expected_execution_request,
        expected_execution_plan,
        expected_source,
    )
    expected_anchors = (
        expected_execution_plan.run_id,
        expected_execution_plan.tenant_id,
        expected_execution_plan.control_id,
        expected_execution_plan.deployment_operation_id,
        expected_execution_plan.deployment_receipt_digest,
        expected_execution_plan.configuration_digest,
        expected_execution_plan.control_profile_id,
        expected_execution_plan.control_profile_digest,
        expected_execution_plan.artifact_set_id,
        expected_execution_plan.custody_scope_id,
        expected_execution_plan.executor_receipt_id,
        expected_execution_plan.digest,
        _utc_text(expected_execution_plan.window_start),
        _utc_text(expected_execution_plan.window_end),
        _utc_text(expected_execution_plan.prepared_at),
        _utc_text(expected_execution_plan.custody_retain_until),
        expected_execution_plan.source_kind,
        expected_execution_plan.source_revision,
        expected_execution_plan.connector_request_digest,
        authorization.profile_id,
        authorization.digest,
        authorization.authorization_binding_digest,
        EXECUTION_ENVIRONMENT_IDENTITY_MEDIA_TYPE,
        environment_identity.digest,
        environment_identity.custody_deployment_profile_digest,
        expected_job.digest,
    )
    observed_anchors = (
        receipt.run_id,
        receipt.tenant_id,
        receipt.control_id,
        receipt.deployment_operation_id,
        receipt.deployment_receipt_digest,
        receipt.configuration_digest,
        receipt.control_profile_id,
        receipt.control_profile_digest,
        receipt.artifact_set_id,
        receipt.custody_scope_id,
        receipt.executor_receipt_id,
        receipt.execution_plan_digest,
        receipt.window_start,
        receipt.window_end,
        receipt.prepared_at,
        receipt.custody_retain_until,
        receipt.source_kind,
        receipt.source_revision,
        receipt.connector_request_digest,
        receipt.authorization_profile_id,
        receipt.authorization_profile_digest,
        receipt.authorization_binding_digest,
        receipt.execution_environment_identity_media_type,
        receipt.execution_environment_identity_digest,
        receipt.custody_deployment_profile_digest,
        receipt.job_digest,
    )
    if observed_anchors != expected_anchors:
        raise ManagedEvidencePublicationError(
            "executor-receipt-verify",
            "managed executor receipt differs from frozen runtime authority",
        )
    _require_custody_identity_anchors(
        custody_identity,
        closure=receipt.custody_closure,
        receipt_signer=receipt_signer,
    )
    try:
        closure_verification = verify_stream_custody_closure(
            receipt.custody_closure.canonical_bytes(),
            receipt.custody_acknowledgement.as_acknowledgement(),
            receipt.snapshot_descriptor.canonical_bytes(),
            expected_snapshot_digest=receipt.snapshot_digest,
            tenant_id=receipt.tenant_id,
            custody=custody,
            receipt_signer=receipt_signer,
            online_reverify=online_reverify,
            limits=_MANAGED_STREAM_LIMITS,
        )
    except Exception:
        raise ManagedEvidencePublicationError(
            "executor-receipt-verify",
            "managed executor custody closure failed independent verification",
        ) from None
    if (
        closure_verification.closure_digest
        != receipt.custody_closure_digest
        or closure_verification.snapshot_digest != receipt.snapshot_digest
        or closure_verification.exact_versions_reverified is not online_reverify
    ):
        raise ManagedEvidencePublicationError(
            "executor-receipt-verify",
            "managed executor custody identities changed during verification",
        )
    return ManagedExecutionReceiptVerification(
        receipt=envelope,
        executor_receipt_digest=envelope.digest,
        evidence_digest=receipt.snapshot_digest,
        custody_closure_digest=receipt.custody_closure_digest,
        custody_acknowledgement_digest=(
            receipt.custody_acknowledgement_digest
        ),
        exact_versions_reverified=closure_verification.exact_versions_reverified,
    )


def _reopen(
    snapshot: Path,
    *,
    expected_snapshot_digest: str,
    job: ManagedConnectorEvidenceJob,
    execution_request: ControlRunExecutionRequest,
    execution_plan: ControlRunExecutionPlan,
    source: PreparedManagedSource,
) -> VerifiedManagedConnectorEvidenceBundle:
    return verify_streamed_managed_connector_evidence_bundle(
        snapshot,
        expected_snapshot_digest=expected_snapshot_digest,
        expected_job=job,
        expected_request_bytes=source.connector_request_bytes,
        expected_control_profile_bytes=execution_request.control_profile_bytes,
        expected_authorization_profile_bytes=(
            source.authorization_profile.canonical_bytes()
        ),
        receipt_verifier=source.receipt_verifier,
        connector_receipt_verifier_id=(
            source.connector_receipt_verifier_id
        ),
        pam_receipt_verifier=source.pam_receipt_verifier,
        pam_receipt_verifier_id=source.pam_receipt_verifier_id,
        expected_source_revision=execution_plan.source_revision,
    )


def _stage_snapshot(
    workspace: _Workspace,
    *,
    job: ManagedConnectorEvidenceJob,
    execution_request: ControlRunExecutionRequest,
    execution_plan: ControlRunExecutionPlan,
    source: PreparedManagedSource,
) -> tuple[str, VerifiedManagedConnectorEvidenceBundle]:
    if workspace.snapshot.exists() or workspace.snapshot.is_symlink():
        try:
            snapshot = verify_streamed_cab_snapshot(
                workspace.snapshot,
                limits=_MANAGED_STREAM_LIMITS,
            )
            reopened = _reopen(
                workspace.snapshot,
                expected_snapshot_digest=snapshot.snapshot_digest,
                job=job,
                execution_request=execution_request,
                execution_plan=execution_plan,
                source=source,
            )
        except Exception:
            raise ManagedEvidencePublicationError(
                "cab-reopen",
                "existing managed evidence snapshot failed exact re-verification",
            ) from None
        return snapshot.snapshot_digest, reopened

    if workspace.cab.exists() or workspace.cab.is_symlink():
        try:
            snapshot = capture_streamed_cab_snapshot(
                workspace.cab,
                workspace.snapshot,
                limits=_MANAGED_STREAM_LIMITS,
            )
            reopened = _reopen(
                workspace.snapshot,
                expected_snapshot_digest=snapshot.snapshot_digest,
                job=job,
                execution_request=execution_request,
                execution_plan=execution_plan,
                source=source,
            )
        except Exception:
            raise ManagedEvidencePublicationError(
                "cab-reopen",
                "existing managed evidence CAB could not be safely recovered",
            ) from None
        return snapshot.snapshot_digest, reopened

    try:
        captured = source.capture()
    except Exception:
        raise ManagedEvidencePublicationError(
            "source-capture",
            "managed source capture failed",
        ) from None
    try:
        written = write_managed_connector_evidence_bundle(
            workspace.cab,
            stream_snapshot_destination=workspace.snapshot,
            job=job,
            request_bytes=source.connector_request_bytes,
            control_profile_bytes=execution_request.control_profile_bytes,
            authorization_profile_bytes=(
                source.authorization_profile.canonical_bytes()
            ),
            capture=captured.capture,
            pam_receipt_bytes=captured.pam_receipt_bytes,
            pam_receipt_digest=captured.pam_receipt_digest,
            receipt_verifier=source.receipt_verifier,
            connector_receipt_verifier_id=(
                source.connector_receipt_verifier_id
            ),
            pam_receipt_verifier=source.pam_receipt_verifier,
            pam_receipt_verifier_id=source.pam_receipt_verifier_id,
            created_at=execution_plan.prepared_at,
            source_revision=execution_plan.source_revision,
        )
        reopened = _reopen(
            workspace.snapshot,
            expected_snapshot_digest=written.snapshot_digest,
            job=job,
            execution_request=execution_request,
            execution_plan=execution_plan,
            source=source,
        )
    except ManagedEvidencePublicationError:
        raise
    except Exception:
        raise ManagedEvidencePublicationError(
            "cab-write",
            "managed evidence CAB failed write-and-reopen verification",
        ) from None
    if (
        reopened.cab_id != written.cab_id
        or reopened.snapshot_digest != written.snapshot_digest
        or reopened.job_digest != written.job_digest
        or reopened.evaluation_digest != written.evaluation_digest
    ):
        raise ManagedEvidencePublicationError(
            "cab-reopen",
            "managed evidence identity changed during explicit reopen",
        )
    return written.snapshot_digest, reopened


def publish_managed_evidence(
    execution_request: ControlRunExecutionRequest,
    execution_plan: ControlRunExecutionPlan,
    source: PreparedManagedSource,
    *,
    execution_environment_identity_bytes: bytes,
    work_root: Path,
    custody: StreamCustodyAdapter,
    receipt_signer: ReceiptSigner,
    source_revision: str,
) -> ManagedEvidencePublication:
    """Capture, close, Object-Lock, and exactly reverify one managed run.

    A complete deterministic local snapshot is reusable after an ambiguous
    custody failure.  An existing incomplete or inconsistent artifact is never
    overwritten and never causes a second source capture.
    """

    _require_source_binding(
        execution_request,
        execution_plan,
        source,
        source_revision=source_revision,
    )
    environment_identity, custody_identity = (
        _require_execution_environment_binding(
            execution_environment_identity_bytes,
            execution_request=execution_request,
            execution_plan=execution_plan,
            source=source,
        )
    )
    _require_prepared_runtime_anchors(
        environment_identity,
        custody_identity,
        source=source,
        custody=custody,
        receipt_signer=receipt_signer,
    )
    workspace = _workspace(
        work_root,
        artifact_set_id=execution_plan.artifact_set_id,
    )
    job = _job(execution_request, execution_plan, source)
    _require_workspace_unchanged(workspace)
    snapshot_digest, opened_before_custody = _stage_snapshot(
        workspace,
        job=job,
        execution_request=execution_request,
        execution_plan=execution_plan,
        source=source,
    )
    _require_workspace_unchanged(workspace)
    try:
        snapshot_before_custody = verify_streamed_cab_snapshot(
            workspace.snapshot,
            expected_snapshot_digest=snapshot_digest,
            limits=_MANAGED_STREAM_LIMITS,
        )
    except Exception:
        raise ManagedEvidencePublicationError(
            "cab-reopen",
            "managed evidence snapshot changed before custody",
        ) from None
    try:
        seal = seal_streamed_cab_snapshot(
            workspace.snapshot,
            expected_snapshot_digest=snapshot_digest,
            tenant_id=execution_plan.tenant_id,
            retain_until=execution_plan.custody_retain_until,
            custody=custody,
            receipt_signer=receipt_signer,
            limits=_MANAGED_STREAM_LIMITS,
        )
    except Exception:
        raise ManagedEvidencePublicationError(
            "custody-seal",
            "managed evidence could not enter signed immutable custody",
        ) from None
    _require_workspace_unchanged(workspace)
    try:
        snapshot_after_custody = verify_streamed_cab_snapshot(
            workspace.snapshot,
            expected_snapshot_digest=snapshot_digest,
            limits=_MANAGED_STREAM_LIMITS,
        )
        custody_verification = verify_stream_custody_closure(
            seal.closure_bytes,
            seal.closure_acknowledgement,
            snapshot_after_custody.descriptor_bytes,
            expected_snapshot_digest=snapshot_digest,
            tenant_id=execution_plan.tenant_id,
            custody=custody,
            receipt_signer=receipt_signer,
            online_reverify=True,
            limits=_MANAGED_STREAM_LIMITS,
        )
    except Exception:
        raise ManagedEvidencePublicationError(
            "custody-verify",
            "signed custody closure failed exact-version re-verification",
        ) from None
    try:
        opened_after_custody = _reopen(
            workspace.snapshot,
            expected_snapshot_digest=snapshot_digest,
            job=job,
            execution_request=execution_request,
            execution_plan=execution_plan,
            source=source,
        )
    except Exception:
        raise ManagedEvidencePublicationError(
            "post-custody-reopen",
            "managed evidence changed after custody verification",
        ) from None
    _require_workspace_unchanged(workspace)
    if (
        snapshot_before_custody.descriptor_bytes
        != snapshot_after_custody.descriptor_bytes
        or opened_before_custody != opened_after_custody
        or custody_verification.closure_digest != seal.closure_digest
        or custody_verification.snapshot_digest != snapshot_digest
        or custody_verification.exact_versions_reverified is not True
        or seal.closure.receipt.custody.retain_until
        != execution_plan.custody_retain_until.strftime("%Y-%m-%dT%H:%M:%SZ")
    ):
        raise ManagedEvidencePublicationError(
            "custody-verify",
            "managed evidence identities changed across the custody boundary",
        )
    _require_custody_identity_anchors(
        custody_identity,
        closure=seal.closure,
        receipt_signer=receipt_signer,
    )
    acknowledgement_bytes = (
        seal.closure_acknowledgement.to_canonical_bytes()
    )
    acknowledgement_digest = sha256_digest(acknowledgement_bytes)
    authorization = source.authorization_profile
    try:
        execution_receipt = ManagedExecutionReceipt(
            run_id=execution_plan.run_id,
            tenant_id=execution_plan.tenant_id,
            control_id=execution_plan.control_id,
            deployment_operation_id=execution_plan.deployment_operation_id,
            deployment_receipt_digest=(
                execution_plan.deployment_receipt_digest
            ),
            configuration_digest=execution_plan.configuration_digest,
            control_profile_id=execution_plan.control_profile_id,
            control_profile_digest=execution_plan.control_profile_digest,
            artifact_set_id=execution_plan.artifact_set_id,
            custody_scope_id=execution_plan.custody_scope_id,
            executor_receipt_id=execution_plan.executor_receipt_id,
            execution_plan_digest=execution_plan.digest,
            window_start=_utc_text(execution_plan.window_start),
            window_end=_utc_text(execution_plan.window_end),
            prepared_at=_utc_text(execution_plan.prepared_at),
            custody_retain_until=_utc_text(
                execution_plan.custody_retain_until
            ),
            source_kind=execution_plan.source_kind,
            source_revision=execution_plan.source_revision,
            connector_request_digest=(
                execution_plan.connector_request_digest
            ),
            authorization_profile_id=authorization.profile_id,
            authorization_profile_digest=authorization.digest,
            authorization_binding_digest=(
                authorization.authorization_binding_digest
            ),
            execution_environment_identity_media_type=(
                EXECUTION_ENVIRONMENT_IDENTITY_MEDIA_TYPE
            ),
            execution_environment_identity_digest=environment_identity.digest,
            custody_deployment_profile_digest=(
                environment_identity.custody_deployment_profile_digest
            ),
            cab_id=opened_after_custody.cab_id,
            snapshot_digest=snapshot_digest,
            snapshot_descriptor=snapshot_after_custody.descriptor,
            job_digest=opened_after_custody.job_digest,
            source_receipt_digest=(
                opened_after_custody.source_receipt_digest
            ),
            records_digest=opened_after_custody.records_digest,
            pam_receipt_digest=opened_after_custody.pam_receipt_digest,
            evaluation_digest=opened_after_custody.evaluation_digest,
            record_count=opened_after_custody.record_count,
            custody_closure_digest=seal.closure_digest,
            custody_closure=seal.closure,
            custody_acknowledgement_digest=acknowledgement_digest,
            custody_acknowledgement=(
                CustodyAcknowledgementRecord.from_acknowledgement(
                    seal.closure_acknowledgement
                )
            ),
        )
    except (TypeError, ValueError):
        raise ManagedEvidencePublicationError(
            "receipt-sign",
            "managed execution receipt could not close over custody",
        ) from None
    envelope = _sign_execution_receipt(
        execution_receipt,
        receipt_signer=receipt_signer,
    )
    envelope_bytes = envelope.canonical_bytes()
    try:
        receipt_verification = verify_managed_evidence_executor_receipt(
            envelope_bytes,
            expected_execution_request=execution_request,
            expected_execution_plan=execution_plan,
            expected_source=source,
            execution_environment_identity_bytes=(
                execution_environment_identity_bytes
            ),
            custody=custody,
            receipt_signer=receipt_signer,
            online_reverify=True,
        )
    except ManagedEvidencePublicationError:
        raise
    except Exception:
        raise ManagedEvidencePublicationError(
            "executor-receipt-verify",
            "managed execution receipt failed final independent verification",
        ) from None
    if (
        receipt_verification.executor_receipt_digest != envelope.digest
        or receipt_verification.evidence_digest != snapshot_digest
        or receipt_verification.custody_closure_digest
        != seal.closure_digest
        or receipt_verification.custody_acknowledgement_digest
        != acknowledgement_digest
        or receipt_verification.exact_versions_reverified is not True
    ):
        raise ManagedEvidencePublicationError(
            "executor-receipt-verify",
            "managed execution receipt changed during final verification",
        )
    return ManagedEvidencePublication(
        run_id=execution_plan.run_id,
        artifact_set_id=execution_plan.artifact_set_id,
        custody_scope_id=execution_plan.custody_scope_id,
        executor_receipt_id=execution_plan.executor_receipt_id,
        cab_id=opened_after_custody.cab_id,
        evidence_digest=snapshot_digest,
        executor_receipt_digest=envelope.digest,
        executor_receipt_bytes=envelope_bytes,
        custody_acknowledgement_digest=acknowledgement_digest,
        custody_acknowledgement_bytes=acknowledgement_bytes,
        job_digest=opened_after_custody.job_digest,
        source_receipt_digest=opened_after_custody.source_receipt_digest,
        records_digest=opened_after_custody.records_digest,
        pam_receipt_digest=opened_after_custody.pam_receipt_digest,
        evaluation_digest=opened_after_custody.evaluation_digest,
        record_count=opened_after_custody.record_count,
        exact_versions_reverified=True,
    )


__all__ = [
    "MANAGED_EXECUTION_RECEIPT_MEDIA_TYPE",
    "MANAGED_EXECUTION_RECEIPT_SCHEMA_VERSION",
    "MANAGED_EXECUTION_SIGNATURE_DOMAIN",
    "MAX_MANAGED_EXECUTION_RECEIPT_BYTES",
    "SIGNED_MANAGED_EXECUTION_MEDIA_TYPE",
    "ManagedEvidencePublication",
    "ManagedEvidencePublicationError",
    "ManagedExecutionReceipt",
    "ManagedExecutionReceiptVerification",
    "SignedManagedExecutionReceipt",
    "publish_managed_evidence",
    "verify_managed_evidence_executor_receipt",
]
