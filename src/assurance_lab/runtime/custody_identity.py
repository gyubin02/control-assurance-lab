"""Exact, public runtime identity for immutable custody and receipt signing.

The control configuration contains secret-free references, not enough
information to construct a production S3 Object Lock writer or Vault Transit
signer.  This module deliberately does not interpret those references or
perform cloud discovery.  An injected registry binds the exact references and
configuration digest to already pinned adapters, then emits canonical public
identity bytes before evidence collection is allowed to start.

Vault origins and logical paths are represented only by digests in the public
identity.  Tokens, credentials, CA paths, clients, and endpoint strings never
enter the canonical document.
"""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Final, Literal, Protocol, cast, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from assurance_lab.control_plane.models import (
    ControlConfiguration,
    Digest,
    Environment,
)
from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)
from assurance_lab.evidence.s3_object_lock import (
    MAX_RETENTION_SECONDS,
    MAX_SINGLE_PUT_BYTES,
    MIN_RETENTION_SECONDS,
    S3ObjectLockCustody,
)
from assurance_lab.evidence.vault_transit import VaultTransitEd25519ReceiptSigner
from assurance_lab.runtime.execution_plan import (
    ControlRunExecutionPlan,
    ControlRunExecutionPlanError,
    verify_control_run_execution_plan,
)
from assurance_lab.runtime.models import (
    ControlRunExecutionRequest,
    PortableId,
    sha256_digest,
    utc_second,
)

CUSTODY_SIGNING_DEPLOYMENT_PROFILE_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.custody-signing-profile.v1+json"]
] = "application/vnd.control-assurance.custody-signing-profile.v1+json"
CUSTODY_SIGNING_DEPLOYMENT_PROFILE_SCHEMA_VERSION: Final[Literal["1.0.0"]] = (
    "1.0.0"
)
CUSTODY_RUNTIME_IDENTITY_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.custody-runtime-identity.v1+json"]
] = "application/vnd.control-assurance.custody-runtime-identity.v1+json"
CUSTODY_RUNTIME_IDENTITY_SCHEMA_VERSION: Final[Literal["1.0.0"]] = "1.0.0"

_PROFILE_LIMITS = JSONLimits(
    max_bytes=128 * 1024,
    max_line_bytes=128 * 1024,
    max_depth=12,
    max_collection_items=256,
    max_string_length=4096,
)
_IDENTITY_LIMITS = JSONLimits(
    max_bytes=256 * 1024,
    max_line_bytes=256 * 1024,
    max_depth=16,
    max_collection_items=512,
    max_string_length=4096,
)
_ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9.-]{0,63}$")
_BUCKET_RE = re.compile(
    r"^(?!xn--)(?!.*[.][.])(?!.*-[.])"
    r"[a-z0-9](?:[a-z0-9.-]{1,61}[a-z0-9])$"
)
_BUCKET_ARN_RE = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):s3:::"
    r"([a-z0-9](?:[a-z0-9.-]{1,61}[a-z0-9]))$"
)
_KMS_ARN_RE = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):kms:"
    r"([a-z]{2}(?:-gov)?-[a-z]+-[0-9]):([0-9]{12}):"
    r"key/((?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12})|(?:mrk-[0-9a-f]{32}))$"
)
_OWNER_RE = re.compile(r"^[0-9]{12}$")
_APPROVED_CUSTODY_SCHEMES = frozenset({"s3-object-lock"})
_APPROVED_SIGNING_SCHEMES = frozenset({"vault-transit"})


class CustodyRuntimeIdentityError(RuntimeError):
    """Bounded failure safe for durable classification and ordinary logs."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        if type(code) is not str or _ERROR_CODE_RE.fullmatch(code) is None:
            raise ValueError("custody runtime error code is invalid")
        super().__init__(code)
        self.code = code


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


def _reference(value: str, *, schemes: frozenset[str]) -> str:
    if type(value) is not str or not value or len(value) > 2048:
        raise ValueError("runtime reference is absent or too long")
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme not in schemes
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.path
        or parsed.path == "/"
        or parsed.query
        or parsed.fragment
        or "\\" in value
        or any(character.isspace() for character in value)
    ):
        raise ValueError("runtime reference is not canonical")
    return value


class S3ObjectLockPublicDeploymentIdentity(_FrozenModel):
    """Non-secret S3 Object Lock boundary selected by one deployment profile."""

    kind: Literal["s3-object-lock"] = "s3-object-lock"
    bucket_name: str = Field(min_length=3, max_length=63)
    bucket_arn: str = Field(min_length=16, max_length=128)
    expected_bucket_owner: str = Field(min_length=12, max_length=12)
    aws_region: str = Field(min_length=9, max_length=32)
    kms_key_arn: str = Field(min_length=40, max_length=256)
    encryption: Literal["aws:kms", "aws:kms:dsse"]
    object_lock_enabled: Literal[True] = True
    versioning_enabled: Literal[True] = True
    retention_mode: Literal["COMPLIANCE"] = "COMPLIANCE"
    minimum_retention_seconds: int = Field(
        ge=MIN_RETENTION_SECONDS,
        le=MAX_RETENTION_SECONDS,
    )
    maximum_retention_seconds: int = Field(
        ge=MIN_RETENTION_SECONDS,
        le=MAX_RETENTION_SECONDS,
    )
    maximum_object_bytes: int = Field(ge=1, le=MAX_SINGLE_PUT_BYTES)

    @model_validator(mode="after")
    def validate_aws_identity(self) -> S3ObjectLockPublicDeploymentIdentity:
        bucket = _BUCKET_ARN_RE.fullmatch(self.bucket_arn)
        kms = _KMS_ARN_RE.fullmatch(self.kms_key_arn)
        if (
            _BUCKET_RE.fullmatch(self.bucket_name) is None
            or bucket is None
            or bucket.group(2) != self.bucket_name
            or _OWNER_RE.fullmatch(self.expected_bucket_owner) is None
            or kms is None
            or kms.group(1) != bucket.group(1)
            or kms.group(2) != self.aws_region
            or kms.group(3) != self.expected_bucket_owner
        ):
            raise ValueError("S3 custody deployment identity is internally inconsistent")
        if self.maximum_retention_seconds < self.minimum_retention_seconds:
            raise ValueError("S3 custody retention range is inverted")
        return self

    @classmethod
    def from_adapter(
        cls,
        adapter: S3ObjectLockCustody,
    ) -> S3ObjectLockPublicDeploymentIdentity:
        if type(adapter) is not S3ObjectLockCustody:
            raise TypeError("custody adapter must be exact S3ObjectLockCustody")
        kms = _KMS_ARN_RE.fullmatch(adapter.kms_key_arn)
        if kms is None:
            raise CustodyRuntimeIdentityError("custody-adapter-invalid")
        policy = adapter.retention_policy
        return cls(
            bucket_name=adapter.bucket_name,
            bucket_arn=adapter.bucket_arn,
            expected_bucket_owner=adapter.expected_bucket_owner,
            aws_region=kms.group(2),
            kms_key_arn=adapter.kms_key_arn,
            encryption=cast(
                Literal["aws:kms", "aws:kms:dsse"],
                adapter.encryption,
            ),
            minimum_retention_seconds=policy.minimum_seconds,
            maximum_retention_seconds=policy.maximum_seconds,
            maximum_object_bytes=policy.max_object_bytes,
        )


class VaultTransitPublicDeploymentIdentity(_FrozenModel):
    """Public anchors for one version-pinned Vault Transit Ed25519 key."""

    kind: Literal["vault-transit-ed25519"] = "vault-transit-ed25519"
    endpoint_origin_digest: Digest
    namespace_digest: Digest
    mount_path_digest: Digest
    key_name_digest: Digest
    key_id_digest: Digest
    key_version: int = Field(ge=1, le=2**31 - 1)
    public_key_fingerprint: Digest
    signature_algorithm: Literal["ed25519"] = "ed25519"
    private_key_exported: Literal[False] = False

    @classmethod
    def from_signer(
        cls,
        signer: VaultTransitEd25519ReceiptSigner,
    ) -> VaultTransitPublicDeploymentIdentity:
        if type(signer) is not VaultTransitEd25519ReceiptSigner:
            raise TypeError(
                "receipt signer must be exact VaultTransitEd25519ReceiptSigner"
            )
        return cls(
            endpoint_origin_digest=signer.endpoint_origin_digest,
            namespace_digest=signer.namespace_digest,
            mount_path_digest=signer.mount_path_digest,
            key_name_digest=signer.key_name_digest,
            key_id_digest=signer.key_id_digest,
            key_version=signer.key_version,
            public_key_fingerprint=signer.public_key_fingerprint,
        )


class CustodySigningDeploymentProfile(_FrozenModel):
    """Canonical public profile for one exact control configuration."""

    media_type: Literal[
        "application/vnd.control-assurance.custody-signing-profile.v1+json"
    ] = CUSTODY_SIGNING_DEPLOYMENT_PROFILE_MEDIA_TYPE
    schema_version: Literal["1.0.0"] = (
        CUSTODY_SIGNING_DEPLOYMENT_PROFILE_SCHEMA_VERSION
    )
    profile_id: PortableId
    tenant_id: PortableId
    control_id: PortableId
    environment: Environment
    configuration_digest: Digest
    custody_ref: str = Field(min_length=1, max_length=2048)
    signing_key_ref: str = Field(min_length=1, max_length=2048)
    configured_retention_days: int = Field(ge=30, le=3650)
    legal_hold: Literal[False] = False
    custody: S3ObjectLockPublicDeploymentIdentity
    signing: VaultTransitPublicDeploymentIdentity

    @field_validator("custody_ref")
    @classmethod
    def validate_custody_ref(cls, value: str) -> str:
        return _reference(value, schemes=_APPROVED_CUSTODY_SCHEMES)

    @field_validator("signing_key_ref")
    @classmethod
    def validate_signing_key_ref(cls, value: str) -> str:
        return _reference(value, schemes=_APPROVED_SIGNING_SCHEMES)

    @model_validator(mode="after")
    def validate_retention(self) -> CustodySigningDeploymentProfile:
        requested_seconds = self.configured_retention_days * 24 * 60 * 60
        if not (
            self.custody.minimum_retention_seconds
            <= requested_seconds
            <= self.custody.maximum_retention_seconds
        ):
            raise ValueError(
                "configured evidence retention is outside the S3 custody policy"
            )
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            self.model_dump(mode="json"),
            limits=_PROFILE_LIMITS,
        )

    @property
    def digest(self) -> str:
        return sha256_digest(self.canonical_bytes())

    @classmethod
    def from_runtime(
        cls,
        *,
        profile_id: str,
        configuration: ControlConfiguration,
        custody: S3ObjectLockCustody,
        signer: VaultTransitEd25519ReceiptSigner,
    ) -> CustodySigningDeploymentProfile:
        if type(configuration) is not ControlConfiguration:
            raise TypeError("configuration must be exact ControlConfiguration")
        if configuration.evidence.legal_hold:
            raise CustodyRuntimeIdentityError("legal-hold-unsupported")
        try:
            return cls(
                profile_id=profile_id,
                tenant_id=configuration.tenant_id,
                control_id=configuration.control_id,
                environment=configuration.environment,
                configuration_digest=configuration.digest,
                custody_ref=configuration.evidence.custody_ref,
                signing_key_ref=configuration.evidence.signing_key_ref,
                configured_retention_days=configuration.evidence.retention_days,
                custody=S3ObjectLockPublicDeploymentIdentity.from_adapter(custody),
                signing=VaultTransitPublicDeploymentIdentity.from_signer(signer),
            )
        except (TypeError, ValueError):
            raise CustodyRuntimeIdentityError("deployment-profile-invalid") from None


class ControlRunCustodyRuntimeIdentity(_FrozenModel):
    """Canonical selection of one deployment profile for one frozen run."""

    media_type: Literal[
        "application/vnd.control-assurance.custody-runtime-identity.v1+json"
    ] = CUSTODY_RUNTIME_IDENTITY_MEDIA_TYPE
    schema_version: Literal["1.0.0"] = CUSTODY_RUNTIME_IDENTITY_SCHEMA_VERSION
    run_id: Digest
    tenant_id: PortableId
    control_id: PortableId
    configuration_digest: Digest
    execution_plan_digest: Digest
    custody_scope_id: Digest
    prepared_at: datetime
    custody_retain_until: datetime
    custody_ref: str = Field(min_length=1, max_length=2048)
    signing_key_ref: str = Field(min_length=1, max_length=2048)
    deployment_profile_digest: Digest
    deployment_profile: CustodySigningDeploymentProfile

    @field_validator("prepared_at", "custody_retain_until")
    @classmethod
    def validate_times(cls, value: datetime) -> datetime:
        return utc_second(value, label="custody runtime identity time")

    @field_validator("custody_ref")
    @classmethod
    def validate_custody_ref(cls, value: str) -> str:
        return _reference(value, schemes=_APPROVED_CUSTODY_SCHEMES)

    @field_validator("signing_key_ref")
    @classmethod
    def validate_signing_key_ref(cls, value: str) -> str:
        return _reference(value, schemes=_APPROVED_SIGNING_SCHEMES)

    @model_validator(mode="after")
    def validate_profile_binding(self) -> ControlRunCustodyRuntimeIdentity:
        profile = self.deployment_profile
        if (
            self.custody_retain_until <= self.prepared_at
            or self.deployment_profile_digest != profile.digest
            or profile.tenant_id != self.tenant_id
            or profile.control_id != self.control_id
            or profile.configuration_digest != self.configuration_digest
            or profile.custody_ref != self.custody_ref
            or profile.signing_key_ref != self.signing_key_ref
        ):
            raise ValueError("custody runtime identity crosses its deployment profile")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            self.model_dump(mode="json"),
            limits=_IDENTITY_LIMITS,
        )

    @property
    def digest(self) -> str:
        return sha256_digest(self.canonical_bytes())


def parse_custody_signing_deployment_profile(
    value: bytes,
) -> CustodySigningDeploymentProfile:
    """Reopen one bounded, canonical deployment profile."""

    if type(value) is not bytes or not value:
        raise CustodyRuntimeIdentityError("deployment-profile-invalid")
    try:
        document = strict_json_loads(value, limits=_PROFILE_LIMITS)
        profile = CustodySigningDeploymentProfile.model_validate_json(value)
    except (StrictJSONError, TypeError, ValueError):
        raise CustodyRuntimeIdentityError("deployment-profile-invalid") from None
    if not isinstance(document, dict) or profile.canonical_bytes() != value:
        raise CustodyRuntimeIdentityError("deployment-profile-noncanonical")
    return profile


def parse_control_run_custody_runtime_identity(
    value: bytes,
) -> ControlRunCustodyRuntimeIdentity:
    """Reopen one bounded, canonical run-specific custody identity."""

    if type(value) is not bytes or not value:
        raise CustodyRuntimeIdentityError("runtime-identity-invalid")
    try:
        document = strict_json_loads(value, limits=_IDENTITY_LIMITS)
        identity = ControlRunCustodyRuntimeIdentity.model_validate_json(value)
    except (StrictJSONError, TypeError, ValueError):
        raise CustodyRuntimeIdentityError("runtime-identity-invalid") from None
    if not isinstance(document, dict) or identity.canonical_bytes() != value:
        raise CustodyRuntimeIdentityError("runtime-identity-noncanonical")
    return identity


def _runtime_matches_profile(
    profile: CustodySigningDeploymentProfile,
    *,
    custody: S3ObjectLockCustody,
    signer: VaultTransitEd25519ReceiptSigner,
) -> bool:
    try:
        return (
            S3ObjectLockPublicDeploymentIdentity.from_adapter(custody)
            == profile.custody
            and VaultTransitPublicDeploymentIdentity.from_signer(signer)
            == profile.signing
        )
    except (CustodyRuntimeIdentityError, TypeError, ValueError):
        return False


@dataclass(frozen=True, slots=True, repr=False)
class RegisteredCustodySigningRuntime:
    """One registry entry; clients, signers, and tokens are never serialized."""

    profile_bytes: bytes
    custody: S3ObjectLockCustody
    signer: VaultTransitEd25519ReceiptSigner
    profile: CustodySigningDeploymentProfile = field(init=False)

    def __post_init__(self) -> None:
        profile = parse_custody_signing_deployment_profile(self.profile_bytes)
        if not _runtime_matches_profile(
            profile,
            custody=self.custody,
            signer=self.signer,
        ):
            raise CustodyRuntimeIdentityError("registered-runtime-substitution")
        object.__setattr__(self, "profile", profile)

    def __repr__(self) -> str:
        return (
            "RegisteredCustodySigningRuntime("
            f"profile_digest={self.profile.digest!r})"
        )


@runtime_checkable
class CustodyRuntimeProfileRegistry(Protocol):
    """Exact configuration-digest lookup with no reference interpretation."""

    def resolve(
        self,
        *,
        tenant_id: str,
        control_id: str,
        configuration_digest: str,
        custody_ref: str,
        signing_key_ref: str,
    ) -> RegisteredCustodySigningRuntime: ...


_RegistryKey = tuple[str, str, str, str, str]


class ExactCustodyRuntimeProfileRegistry:
    """Immutable in-process registry assembled by the deployment bootstrap."""

    __slots__ = ("_entries",)

    def __init__(self, entries: Iterable[RegisteredCustodySigningRuntime]) -> None:
        selected: dict[_RegistryKey, RegisteredCustodySigningRuntime] = {}
        for entry in entries:
            if type(entry) is not RegisteredCustodySigningRuntime:
                raise TypeError(
                    "registry entries must be RegisteredCustodySigningRuntime"
                )
            profile = entry.profile
            key = (
                profile.tenant_id,
                profile.control_id,
                profile.configuration_digest,
                profile.custody_ref,
                profile.signing_key_ref,
            )
            if key in selected:
                raise CustodyRuntimeIdentityError("duplicate-runtime-profile")
            selected[key] = entry
        if not selected:
            raise CustodyRuntimeIdentityError("runtime-profile-registry-empty")
        self._entries: Mapping[_RegistryKey, RegisteredCustodySigningRuntime] = (
            MappingProxyType(selected)
        )

    def __repr__(self) -> str:
        return f"ExactCustodyRuntimeProfileRegistry(entries={len(self._entries)})"

    def resolve(
        self,
        *,
        tenant_id: str,
        control_id: str,
        configuration_digest: str,
        custody_ref: str,
        signing_key_ref: str,
    ) -> RegisteredCustodySigningRuntime:
        key = (
            tenant_id,
            control_id,
            configuration_digest,
            custody_ref,
            signing_key_ref,
        )
        entry = self._entries.get(key)
        if entry is None:
            raise CustodyRuntimeIdentityError("runtime-profile-not-registered")
        return entry


@dataclass(frozen=True, slots=True, repr=False)
class PreparedCustodySigningRuntime:
    """Exact adapters plus the public identity that must be journaled first."""

    identity: ControlRunCustodyRuntimeIdentity
    custody: S3ObjectLockCustody
    signer: VaultTransitEd25519ReceiptSigner

    @property
    def identity_bytes(self) -> bytes:
        return self.identity.canonical_bytes()

    @property
    def identity_digest(self) -> Digest:
        return self.identity.digest

    @property
    def identity_media_type(
        self,
    ) -> Literal[
        "application/vnd.control-assurance.custody-runtime-identity.v1+json"
    ]:
        return self.identity.media_type

    @property
    def deployment_profile_digest(self) -> Digest:
        return self.identity.deployment_profile_digest

    def __repr__(self) -> str:
        return (
            "PreparedCustodySigningRuntime("
            f"run_id={self.identity.run_id!r}, "
            f"identity_digest={self.identity_digest!r})"
        )


def prepare_custody_signing_runtime(
    request: ControlRunExecutionRequest,
    plan: ControlRunExecutionPlan,
    *,
    registry: CustodyRuntimeProfileRegistry,
    expected_identity_bytes: bytes | None = None,
) -> PreparedCustodySigningRuntime:
    """Select and recheck the only custody/signing runtime allowed for a run.

    On a first attempt, persist ``identity_bytes`` before connector or custody
    side effects.  On every retry, supply those bytes as
    ``expected_identity_bytes``; a registry rollout or key rotation then fails
    closed instead of changing the run's runtime identity.
    """

    if type(request) is not ControlRunExecutionRequest:
        raise TypeError("request must be exact ControlRunExecutionRequest")
    if type(plan) is not ControlRunExecutionPlan:
        raise TypeError("plan must be exact ControlRunExecutionPlan")
    if not isinstance(registry, CustodyRuntimeProfileRegistry):
        raise TypeError("registry must implement CustodyRuntimeProfileRegistry")
    try:
        reopened_plan, _ = verify_control_run_execution_plan(
            plan.canonical_bytes(),
            expected_request=request,
        )
    except (ControlRunExecutionPlanError, TypeError, ValueError):
        raise CustodyRuntimeIdentityError("execution-plan-invalid") from None
    if reopened_plan != plan:
        raise CustodyRuntimeIdentityError("execution-plan-substitution")
    try:
        configuration = ControlConfiguration.model_validate_json(
            request.configuration_bytes
        )
    except (TypeError, ValueError):
        raise CustodyRuntimeIdentityError("configuration-invalid") from None
    evidence = configuration.evidence
    if evidence.legal_hold:
        raise CustodyRuntimeIdentityError("legal-hold-unsupported")
    try:
        registration = registry.resolve(
            tenant_id=request.tenant_id,
            control_id=request.control_id,
            configuration_digest=request.configuration_digest,
            custody_ref=evidence.custody_ref,
            signing_key_ref=evidence.signing_key_ref,
        )
    except CustodyRuntimeIdentityError:
        raise
    except Exception:
        raise CustodyRuntimeIdentityError("runtime-profile-registry-failed") from None
    if type(registration) is not RegisteredCustodySigningRuntime:
        raise CustodyRuntimeIdentityError("runtime-profile-registry-invalid")
    profile = registration.profile
    if (
        profile.tenant_id != request.tenant_id
        or profile.control_id != request.control_id
        or profile.environment != configuration.environment
        or profile.configuration_digest != request.configuration_digest
        or profile.custody_ref != evidence.custody_ref
        or profile.signing_key_ref != evidence.signing_key_ref
        or profile.configured_retention_days != evidence.retention_days
        or profile.legal_hold is not evidence.legal_hold
    ):
        raise CustodyRuntimeIdentityError("deployment-profile-drift")
    if not _runtime_matches_profile(
        profile,
        custody=registration.custody,
        signer=registration.signer,
    ):
        raise CustodyRuntimeIdentityError("registered-runtime-substitution")
    if (
        plan.run_id != request.run_id
        or plan.configuration_digest != request.configuration_digest
        or (
            plan.custody_retain_until - plan.prepared_at
        ).total_seconds()
        != evidence.retention_days * 24 * 60 * 60
    ):
        raise CustodyRuntimeIdentityError("execution-retention-drift")
    try:
        identity = ControlRunCustodyRuntimeIdentity(
            run_id=request.run_id,
            tenant_id=request.tenant_id,
            control_id=request.control_id,
            configuration_digest=request.configuration_digest,
            execution_plan_digest=plan.digest,
            custody_scope_id=plan.custody_scope_id,
            prepared_at=plan.prepared_at,
            custody_retain_until=plan.custody_retain_until,
            custody_ref=evidence.custody_ref,
            signing_key_ref=evidence.signing_key_ref,
            deployment_profile_digest=profile.digest,
            deployment_profile=profile,
        )
    except (TypeError, ValueError):
        raise CustodyRuntimeIdentityError("runtime-identity-invalid") from None
    identity_bytes = identity.canonical_bytes()
    if expected_identity_bytes is not None:
        expected = parse_control_run_custody_runtime_identity(
            expected_identity_bytes
        )
        if expected.canonical_bytes() != identity_bytes:
            raise CustodyRuntimeIdentityError("runtime-identity-drift")
    return PreparedCustodySigningRuntime(
        identity=identity,
        custody=registration.custody,
        signer=registration.signer,
    )
