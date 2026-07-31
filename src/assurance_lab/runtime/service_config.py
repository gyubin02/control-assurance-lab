"""Strict, secret-free configuration for the production runtime worker.

The document names environment variables and protected files; it never accepts
database passwords, cloud credentials, Vault tokens, or projected assertions
as configuration values.  The CLI separately pins the canonical document
digest so a ConfigMap rollout cannot silently change an executing worker.
"""

from __future__ import annotations

import os
import re
import urllib.parse
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Final, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from assurance_lab.control_plane.models import (
    ControlConfiguration,
    DefenderSourceConfiguration,
    ElasticSourceConfiguration,
)
from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)
from assurance_lab.runtime.models import sha256_digest

_CONFIG_LIMITS: Final = JSONLimits(
    max_bytes=4 * 1024 * 1024,
    max_line_bytes=4 * 1024 * 1024,
    max_depth=32,
    max_collection_items=16_384,
    max_string_length=1024 * 1024,
)
_ENV_NAME_RE: Final = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_DATABASE_ROLE_RE: Final = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_DIGEST_RE: Final = re.compile(r"^sha256:[a-f0-9]{64}$")
_PORTABLE_ID_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")
_EXECUTOR_WORKER_ID_RE: Final = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_SOURCE_REVISION_RE: Final = re.compile(
    r"^(?:oci:)?sha256:[a-f0-9]{64}$|^[a-f0-9]{40}$"
)
_AWS_REGION_RE: Final = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]$")
_PROFILE_ID_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")
_UUID_RE: Final = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

PortableId = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128, pattern=_PORTABLE_ID_RE.pattern),
]
Digest = Annotated[
    str,
    StringConstraints(min_length=71, max_length=71, pattern=_DIGEST_RE.pattern),
]
DatabaseRoleName = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=63,
        pattern=_DATABASE_ROLE_RE.pattern,
    ),
]


class RuntimeServiceConfigurationError(ValueError):
    """Stable configuration failure that never contains resolved secret values."""


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=False,
    )


class EnvironmentReference(_StrictFrozenModel):
    """Name one injected environment variable without storing its value."""

    kind: Literal["environment"] = "environment"
    name: str = Field(min_length=1, max_length=128)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if _ENV_NAME_RE.fullmatch(value) is None:
            raise ValueError("environment reference name is invalid")
        return value

    def resolve(
        self,
        environment: Mapping[str, str],
        *,
        maximum_bytes: int,
    ) -> str:
        if type(maximum_bytes) is not int or maximum_bytes < 1:
            raise ValueError("environment value limit is invalid")
        value = environment.get(self.name)
        if (
            type(value) is not str
            or not value
            or "\x00" in value
            or len(value.encode("utf-8")) > maximum_bytes
        ):
            raise RuntimeServiceConfigurationError(
                f"required environment reference {self.name} is unavailable"
            )
        return value


class DatabaseSettings(_StrictFrozenModel):
    runtime_dsn: EnvironmentReference
    runtime_role: DatabaseRoleName
    execution_journal_dsn: EnvironmentReference
    execution_journal_role: DatabaseRoleName
    pam_journal_dsn: EnvironmentReference
    pam_journal_role: DatabaseRoleName
    ca_bundle: PinnedPublicFileSettings
    min_pool_size: int = Field(default=2, ge=1, le=256)
    max_pool_size: int = Field(default=16, ge=1, le=256)
    connect_timeout_seconds: int = Field(default=10, ge=1, le=60)
    statement_timeout_ms: int = Field(default=15_000, ge=100, le=120_000)
    lock_timeout_ms: int = Field(default=5_000, ge=100, le=120_000)
    require_tls: Literal[True] = True

    @model_validator(mode="after")
    def validate_pool(self) -> DatabaseSettings:
        if self.max_pool_size < self.min_pool_size:
            raise ValueError("database maximum pool size is below its minimum")
        if self.lock_timeout_ms > self.statement_timeout_ms:
            raise ValueError("database lock timeout exceeds statement timeout")
        if len(
            {
                self.runtime_role,
                self.execution_journal_role,
                self.pam_journal_role,
            }
        ) != 3:
            raise ValueError("runtime database roles must be pairwise distinct")
        if len(
            {
                self.runtime_dsn.name,
                self.execution_journal_dsn.name,
                self.pam_journal_dsn.name,
            }
        ) != 3:
            raise ValueError("runtime database DSN references must be pairwise distinct")
        return self


class WorkerLoopSettings(_StrictFrozenModel):
    max_runs_per_cycle: int = Field(default=32, ge=1, le=1_000)
    materialization_interval_seconds: float = Field(
        default=30.0,
        ge=0.1,
        le=86_400.0,
    )
    idle_poll_seconds: float = Field(default=2.0, ge=0.01, le=300.0)
    backoff_base_seconds: float = Field(default=1.0, ge=0.01, le=300.0)
    backoff_max_seconds: float = Field(default=60.0, ge=0.01, le=3_600.0)
    lease_ttl_seconds: int = Field(default=300, ge=15, le=3_600)
    max_attempts: int = Field(default=8, ge=1, le=32)
    run_retry_base_seconds: int = Field(default=30, ge=1, le=86_400)
    run_retry_max_seconds: int = Field(default=3_600, ge=1, le=86_400)

    @model_validator(mode="after")
    def validate_backoff(self) -> WorkerLoopSettings:
        if self.backoff_max_seconds < self.backoff_base_seconds:
            raise ValueError("worker backoff maximum is below its base")
        if self.run_retry_max_seconds < self.run_retry_base_seconds:
            raise ValueError("run retry maximum is below its base")
        return self


class HealthSettings(_StrictFrozenModel):
    bind_host: Literal["0.0.0.0", "127.0.0.1", "::"] = "0.0.0.0"
    port: int = Field(default=8080, ge=1_024, le=65_535)


class SharedWorkRootSettings(_StrictFrozenModel):
    path: str = Field(min_length=1, max_length=4_096)
    volume_id: PortableId
    marker_owner_uid: int = Field(ge=0, le=2**31 - 1)
    marker_group_gid: int | None = Field(default=None, ge=0, le=2**31 - 1)
    marker_mode: Literal[256, 288] = 256  # 0400 or 0440

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        path = Path(value)
        if (
            not path.is_absolute()
            or value != os.fspath(path)
            or "\x00" in value
            or value == "/"
            or ".." in path.parts
        ):
            raise ValueError("shared work root must be one canonical absolute path")
        return value

    @property
    def marker_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "kind": "control-assurance-shared-work-root",
                "schema_version": "1.0.0",
                "volume_id": self.volume_id,
            }
        )

    @property
    def marker_digest(self) -> str:
        return sha256_digest(self.marker_bytes)


class ProtectedFileSettings(_StrictFrozenModel):
    """Exact ownership policy for a rotated credential or assertion file."""

    path: str = Field(min_length=1, max_length=4_096)
    mount_root: str = Field(min_length=1, max_length=4_096)
    owner_uid: int = Field(ge=0, le=2**31 - 1)
    group_gid: int | None = Field(default=None, ge=0, le=2**31 - 1)
    mode: Literal[256, 288] = 256  # 0400 or 0440

    @field_validator("path", "mount_root")
    @classmethod
    def validate_absolute_path(cls, value: str) -> str:
        path = Path(value)
        if (
            not path.is_absolute()
            or value != os.fspath(path)
            or "\x00" in value
            or ".." in path.parts
        ):
            raise ValueError("protected file paths must be canonical and absolute")
        return value

    @model_validator(mode="after")
    def validate_containment(self) -> ProtectedFileSettings:
        if self.mount_root == "/" or self.path == self.mount_root:
            raise ValueError("protected file must be below a bounded mount root")
        try:
            Path(self.path).relative_to(Path(self.mount_root))
        except ValueError:
            raise ValueError("protected file must be below its mount root") from None
        return self


class PinnedPublicFileSettings(_StrictFrozenModel):
    """A non-secret local trust file whose exact bytes are release-pinned."""

    file: ProtectedFileSettings
    sha256_digest: Digest


class AzureWorkloadIdentitySettings(_StrictFrozenModel):
    tenant_id: str = Field(min_length=36, max_length=36)
    client_id: str = Field(min_length=36, max_length=36)
    token: ProtectedFileSettings
    expected_issuer: str = Field(min_length=9, max_length=2_048)
    expected_subject: str = Field(min_length=1, max_length=600)
    refresh_skew_seconds: int = Field(default=120, ge=30, le=900)
    timeout_seconds: int = Field(default=30, ge=1, le=120)
    key_vault_ca_bundle: PinnedPublicFileSettings | None = None

    @field_validator("tenant_id", "client_id")
    @classmethod
    def validate_uuid(cls, value: str) -> str:
        if _UUID_RE.fullmatch(value) is None:
            raise ValueError("Azure workload identity must use canonical UUIDs")
        return value

class ProjectedFederatedAssertionSettings(_StrictFrozenModel):
    source_reference: str = Field(min_length=1, max_length=1_024)
    token: ProtectedFileSettings


class ElasticRuntimeSettings(_StrictFrozenModel):
    kind: Literal["elastic-security"] = "elastic-security"
    azure_workload_identity: AzureWorkloadIdentitySettings
    ca_bundle: PinnedPublicFileSettings
    request_timeout_seconds: int = Field(default=30, ge=1, le=120)


class DefenderRuntimeSettings(_StrictFrozenModel):
    kind: Literal["defender-xdr"] = "defender-xdr"
    credential_mode: Literal["certificate-ps256", "federated-rs256"]
    azure_workload_identity: AzureWorkloadIdentitySettings
    federated_assertion: ProjectedFederatedAssertionSettings | None = None
    entra_ca_bundle: PinnedPublicFileSettings | None = None
    request_timeout_seconds: int = Field(default=30, ge=1, le=120)
    key_vault_operation_timeout_seconds: int = Field(default=60, ge=1, le=120)

    @model_validator(mode="after")
    def validate_mode(self) -> DefenderRuntimeSettings:
        if (self.credential_mode == "federated-rs256") != (
            self.federated_assertion is not None
        ):
            raise ValueError(
                "Defender federation settings must exactly match credential mode"
            )
        return self


SourceRuntimeSettings = Annotated[
    ElasticRuntimeSettings | DefenderRuntimeSettings,
    Field(discriminator="kind"),
]


class S3CustodySettings(_StrictFrozenModel):
    region: str = Field(min_length=9, max_length=32)
    bucket_name: str = Field(min_length=3, max_length=63)
    bucket_arn: str = Field(min_length=16, max_length=128)
    expected_bucket_owner: str = Field(min_length=12, max_length=12)
    kms_key_arn: str = Field(min_length=40, max_length=256)
    encryption: Literal["aws:kms", "aws:kms:dsse"] = "aws:kms"
    minimum_retention_seconds: int = Field(ge=1, le=10 * 365 * 24 * 60 * 60)
    maximum_retention_seconds: int = Field(ge=1, le=10 * 365 * 24 * 60 * 60)
    maximum_object_bytes: int = Field(
        default=5 * 1024 * 1024 * 1024,
        ge=1,
        le=5 * 1024 * 1024 * 1024,
    )
    connect_timeout_seconds: int = Field(default=5, ge=1, le=60)
    read_timeout_seconds: int = Field(default=60, ge=1, le=300)

    @field_validator("region")
    @classmethod
    def validate_region(cls, value: str) -> str:
        if _AWS_REGION_RE.fullmatch(value) is None:
            raise ValueError("AWS Region is invalid")
        return value

    @model_validator(mode="after")
    def validate_retention(self) -> S3CustodySettings:
        if self.maximum_retention_seconds < self.minimum_retention_seconds:
            raise ValueError("S3 custody retention range is inverted")
        return self


class VaultTransitSettings(_StrictFrozenModel):
    endpoint: str = Field(min_length=9, max_length=2_048)
    mount_path: str = Field(min_length=1, max_length=512)
    key_name: str = Field(min_length=1, max_length=255)
    key_id: str = Field(min_length=1, max_length=256)
    namespace: str | None = Field(default=None, max_length=512)
    ca_bundle: PinnedPublicFileSettings
    token: ProtectedFileSettings
    token_validity_seconds: int = Field(default=30, ge=5, le=300)
    request_timeout_seconds: int = Field(default=10, ge=1, le=120)
    initialization_timeout_seconds: int = Field(default=30, ge=1, le=300)
    sign_timeout_seconds: int = Field(default=30, ge=1, le=300)

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        parsed = urllib.parse.urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Vault endpoint must be a credential-free HTTPS origin")
        try:
            _ = parsed.port
        except ValueError:
            raise ValueError("Vault endpoint port is invalid") from None
        return value

class CustodyRuntimeSettings(_StrictFrozenModel):
    profile_id: str = Field(min_length=1, max_length=128)
    expected_profile_digest: Digest
    s3: S3CustodySettings
    vault_transit: VaultTransitSettings

    @field_validator("profile_id")
    @classmethod
    def validate_profile_id(cls, value: str) -> str:
        if _PROFILE_ID_RE.fullmatch(value) is None:
            raise ValueError("custody profile id is invalid")
        return value


class ControlRuntimeRegistration(_StrictFrozenModel):
    configuration: ControlConfiguration
    source_runtime: SourceRuntimeSettings
    custody_runtime: CustodyRuntimeSettings

    @model_validator(mode="after")
    def validate_source_kind(self) -> ControlRuntimeRegistration:
        source = self.configuration.source
        if (
            type(source) is ElasticSourceConfiguration
            and type(self.source_runtime) is not ElasticRuntimeSettings
        ) or (
            type(source) is DefenderSourceConfiguration
            and type(self.source_runtime) is not DefenderRuntimeSettings
        ):
            raise ValueError(
                "source runtime kind differs from control configuration"
            )
        return self


class RuntimeWorkerServiceConfig(_StrictFrozenModel):
    """Canonical public bootstrap contract for one tenant worker fleet."""

    kind: Literal["control-assurance-runtime-worker"] = (
        "control-assurance-runtime-worker"
    )
    schema_version: Literal["1.0.0"] = "1.0.0"
    tenant_id: PortableId
    worker_id: EnvironmentReference
    worker_credential_digest: EnvironmentReference
    source_revision: EnvironmentReference
    database: DatabaseSettings
    work_root: SharedWorkRootSettings
    worker: WorkerLoopSettings = WorkerLoopSettings()
    health: HealthSettings = HealthSettings()
    registrations: tuple[ControlRuntimeRegistration, ...] = Field(
        min_length=1,
        max_length=1_024,
    )

    @model_validator(mode="after")
    def validate_registrations(self) -> RuntimeWorkerServiceConfig:
        configurations: set[str] = set()
        source_runtimes: dict[str, bytes] = {}
        custody_keys: set[tuple[str, str, str, str, str]] = set()
        for registration in self.registrations:
            configuration = registration.configuration
            if configuration.tenant_id != self.tenant_id:
                raise ValueError("registered control crosses the worker tenant")
            if configuration.digest in configurations:
                raise ValueError("control configuration is registered twice")
            configurations.add(configuration.digest)

            source_digest = sha256_digest(
                canonical_json_bytes(
                    configuration.source.model_dump(mode="json")
                )
            )
            runtime_bytes = canonical_json_bytes(
                registration.source_runtime.model_dump(mode="json")
            )
            previous = source_runtimes.setdefault(source_digest, runtime_bytes)
            if previous != runtime_bytes:
                raise ValueError(
                    "one source configuration selects conflicting runtimes"
                )

            evidence = configuration.evidence
            custody_key = (
                configuration.tenant_id,
                configuration.control_id,
                configuration.digest,
                evidence.custody_ref,
                evidence.signing_key_ref,
            )
            if custody_key in custody_keys:
                raise ValueError("custody runtime registry key is duplicated")
            custody_keys.add(custody_key)
        return self

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"))

    @property
    def digest(self) -> str:
        return sha256_digest(self.canonical_bytes)

    def resolve_worker_id(self, environment: Mapping[str, str]) -> str:
        value = self.worker_id.resolve(environment, maximum_bytes=128)
        if _EXECUTOR_WORKER_ID_RE.fullmatch(value) is None:
            raise RuntimeServiceConfigurationError(
                "resolved worker identity is not a portable executor identity"
            )
        return value

    def resolve_worker_credential_digest(
        self,
        environment: Mapping[str, str],
    ) -> str:
        value = self.worker_credential_digest.resolve(
            environment,
            maximum_bytes=71,
        )
        if _DIGEST_RE.fullmatch(value) is None:
            raise RuntimeServiceConfigurationError(
                "resolved worker credential digest is invalid"
            )
        return value

    def resolve_source_revision(self, environment: Mapping[str, str]) -> str:
        value = self.source_revision.resolve(environment, maximum_bytes=256)
        if _SOURCE_REVISION_RE.fullmatch(value) is None:
            raise RuntimeServiceConfigurationError(
                "resolved source revision is not immutable"
            )
        return value


def parse_runtime_worker_service_config(
    value: bytes,
    *,
    expected_digest: str,
) -> RuntimeWorkerServiceConfig:
    """Parse one bounded strict document and require its canonical digest."""

    if (
        type(value) is not bytes
        or not value
        or type(expected_digest) is not str
        or _DIGEST_RE.fullmatch(expected_digest) is None
    ):
        raise RuntimeServiceConfigurationError(
            "runtime worker configuration input is invalid"
        )
    try:
        document = strict_json_loads(value, limits=_CONFIG_LIMITS)
        if not isinstance(document, dict):
            raise ValueError
        # Strict Pydantic models intentionally reject Python ``list`` values
        # for tuple fields.  JSON arrays are the correct wire representation,
        # so validate the already bounded, duplicate-key-checked bytes through
        # Pydantic's JSON path instead of weakening Python-mode strictness.
        configuration = RuntimeWorkerServiceConfig.model_validate_json(value)
    except (StrictJSONError, TypeError, ValueError):
        raise RuntimeServiceConfigurationError(
            "runtime worker configuration is invalid"
        ) from None
    if configuration.digest != expected_digest:
        raise RuntimeServiceConfigurationError(
            "runtime worker configuration digest differs"
        )
    return configuration


def load_runtime_worker_service_config(
    path: Path,
    *,
    expected_digest: str,
) -> RuntimeWorkerServiceConfig:
    """Read one bounded public config file and reopen its canonical identity."""

    if not isinstance(path, Path) or not path.is_absolute():
        raise RuntimeServiceConfigurationError(
            "runtime worker configuration path must be absolute"
        )
    try:
        with path.open("rb") as stream:
            value = stream.read(_CONFIG_LIMITS.max_bytes + 1)
    except OSError:
        raise RuntimeServiceConfigurationError(
            "runtime worker configuration could not be read"
        ) from None
    if len(value) > _CONFIG_LIMITS.max_bytes:
        raise RuntimeServiceConfigurationError(
            "runtime worker configuration exceeds its byte limit"
        )
    return parse_runtime_worker_service_config(
        value,
        expected_digest=expected_digest,
    )


__all__ = [
    "AzureWorkloadIdentitySettings",
    "ControlRuntimeRegistration",
    "CustodyRuntimeSettings",
    "DatabaseRoleName",
    "DatabaseSettings",
    "DefenderRuntimeSettings",
    "ElasticRuntimeSettings",
    "EnvironmentReference",
    "HealthSettings",
    "PinnedPublicFileSettings",
    "ProjectedFederatedAssertionSettings",
    "ProtectedFileSettings",
    "RuntimeServiceConfigurationError",
    "RuntimeWorkerServiceConfig",
    "S3CustodySettings",
    "SharedWorkRootSettings",
    "VaultTransitSettings",
    "WorkerLoopSettings",
    "load_runtime_worker_service_config",
    "parse_runtime_worker_service_config",
]
