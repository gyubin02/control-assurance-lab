"""Secret-free, digest-pinned configuration for the control-plane service.

The configuration document contains only public deployment policy and
references.  PostgreSQL credentials are supplied through a named environment
variable, the rotating Azure federation assertion is a protected file, and the
CSRF key is an exact-version Key Vault secret.  The command line requires the
canonical configuration digest independently from the ConfigMap that contains
the document.
"""

from __future__ import annotations

import ipaddress
import os
import re
import urllib.parse
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Final, Literal, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from assurance_lab.control_plane.models import Role
from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)

_CONFIG_LIMITS: Final = JSONLimits(
    max_bytes=2 * 1024 * 1024,
    max_line_bytes=2 * 1024 * 1024,
    max_depth=24,
    max_collection_items=4_096,
    max_string_length=64 * 1024,
)
_DIGEST_RE: Final = re.compile(r"^sha256:[a-f0-9]{64}$")
_ENVIRONMENT_RE: Final = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_DEPLOYMENT_ID_RE: Final = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_GROUP_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}$")
_TENANT_RE: Final = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_DATABASE_ROLE_RE: Final = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_UUID_RE: Final = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_VAULT_RE: Final = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,22}[a-z0-9])?$")
_KEY_NAME_RE: Final = re.compile(r"^[A-Za-z0-9-]{1,127}$")
_KEY_VERSION_RE: Final = re.compile(r"^[a-f0-9]{32}$")
_SECRET_REFERENCE_RE: Final = re.compile(
    r"^azure-keyvault://[a-z0-9](?:[a-z0-9-]{1,22}[a-z0-9])?"
    r"/secrets/[A-Za-z0-9-]{1,127}/[a-f0-9]{32}$"
)
_CLAIM_RE: Final = re.compile(r"^[^\x00-\x1f\x7f]{1,255}$")
_SCOPE_RE: Final = re.compile(r"^[A-Za-z0-9._:/-]{1,64}$")

Digest = Annotated[
    str,
    StringConstraints(min_length=71, max_length=71, pattern=_DIGEST_RE.pattern),
]


class ControlPlaneConfigurationError(ValueError):
    """Stable configuration failure that never contains a resolved secret."""


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=False,
    )


def _absolute_path(value: str, *, label: str) -> str:
    path = Path(value)
    if (
        not path.is_absolute()
        or value != os.fspath(path)
        or value == "/"
        or "\x00" in value
        or ".." in path.parts
    ):
        raise ValueError(f"{label} must be one canonical absolute path")
    return value


def _https_url(value: str, *, label: str, origin_only: bool = False) -> str:
    if type(value) is not str or not value or len(value) > 2_048:
        raise ValueError(f"{label} is absent or too long")
    parsed = urllib.parse.urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{label} has an invalid port") from exc
    path = parsed.path or ""
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port == 0
        or "\\" in path
        or "%" in path
        or "//" in path
        or any(segment in {".", ".."} for segment in path.split("/"))
        or any(character.isspace() for character in value)
        or (origin_only and path not in {"", "/"})
    ):
        raise ValueError(f"{label} must be one credential-free HTTPS URL")
    host = parsed.hostname.lower()
    rendered_host = f"[{host}]" if ":" in host else host
    authority = rendered_host if port in {None, 443} else f"{rendered_host}:{port}"
    normalized_path = "" if origin_only else path
    return urllib.parse.urlunsplit(("https", authority, normalized_path, "", ""))


class EnvironmentReference(_StrictFrozenModel):
    """Name one injected environment value without placing it in the document."""

    kind: Literal["environment"] = "environment"
    name: str = Field(min_length=1, max_length=128)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if _ENVIRONMENT_RE.fullmatch(value) is None:
            raise ValueError("environment reference name is invalid")
        return value

    def resolve(self, environment: Mapping[str, str], *, maximum_bytes: int) -> str:
        if type(maximum_bytes) is not int or maximum_bytes < 1:
            raise ValueError("environment value limit is invalid")
        value = environment.get(self.name)
        if (
            type(value) is not str
            or not value
            or "\x00" in value
            or "\r" in value
            or "\n" in value
            or len(value.encode("utf-8")) > maximum_bytes
        ):
            raise ControlPlaneConfigurationError(
                f"required environment reference {self.name} is unavailable"
            )
        return value


class ProtectedFileReference(_StrictFrozenModel):
    """Exact local ownership policy for a projected or mounted file."""

    kind: Literal["protected-file"] = "protected-file"
    path: str = Field(min_length=2, max_length=4_096)
    mount_root: str = Field(min_length=2, max_length=4_096)
    owner_uid: int = Field(ge=0, le=2**31 - 1)
    group_gid: int | None = Field(default=None, ge=0, le=2**31 - 1)
    mode: Literal[256, 288] = 288  # 0400 or 0440

    @field_validator("path", "mount_root")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _absolute_path(value, label="protected file path")

    @model_validator(mode="after")
    def validate_containment(self) -> ProtectedFileReference:
        if self.path == self.mount_root:
            raise ValueError("protected file must be below its mount root")
        try:
            Path(self.path).relative_to(Path(self.mount_root))
        except ValueError:
            raise ValueError("protected file must be below its mount root") from None
        return self


class PinnedPublicFile(_StrictFrozenModel):
    """A protected public file whose exact bytes are release-pinned."""

    file: ProtectedFileReference
    sha256_digest: Digest


class DatabaseSettings(_StrictFrozenModel):
    control_dsn: EnvironmentReference
    auth_dsn: EnvironmentReference
    control_role: str = Field(min_length=1, max_length=63)
    auth_role: str = Field(min_length=1, max_length=63)
    migration_owner_role: str = Field(min_length=1, max_length=63)
    ca_bundle: PinnedPublicFile
    min_pool_size: int = Field(default=2, ge=1, le=64)
    max_pool_size: int = Field(default=16, ge=2, le=128)
    connect_timeout_seconds: int = Field(default=10, ge=1, le=60)
    statement_timeout_ms: int = Field(default=15_000, ge=100, le=120_000)
    lock_timeout_ms: int = Field(default=5_000, ge=100, le=120_000)
    require_tls_verify_full: Literal[True] = True
    require_read_write_primary: Literal[True] = True

    @field_validator(
        "control_role",
        "auth_role",
        "migration_owner_role",
    )
    @classmethod
    def validate_role(cls, value: str) -> str:
        if _DATABASE_ROLE_RE.fullmatch(value) is None:
            raise ValueError("database role must be one portable unquoted name")
        return value

    @model_validator(mode="after")
    def validate_pool(self) -> DatabaseSettings:
        if self.max_pool_size < self.min_pool_size:
            raise ValueError("database maximum pool size is below its minimum")
        if self.lock_timeout_ms > self.statement_timeout_ms:
            raise ValueError("database lock timeout exceeds statement timeout")
        if self.control_dsn.name == self.auth_dsn.name:
            raise ValueError("control and authentication DSNs must be distinct")
        if len(
            {
                self.control_role,
                self.auth_role,
                self.migration_owner_role,
            }
        ) != 3:
            raise ValueError("database runtime and migration roles must be distinct")
        return self


class AzureWorkloadIdentitySettings(_StrictFrozenModel):
    tenant_id: str = Field(min_length=36, max_length=36)
    client_id: str = Field(min_length=36, max_length=36)
    token: ProtectedFileReference
    expected_issuer: str = Field(min_length=9, max_length=2_048)
    expected_subject: str = Field(min_length=1, max_length=600)
    refresh_skew_seconds: int = Field(default=120, ge=30, le=900)
    timeout_seconds: int = Field(default=30, ge=1, le=120)

    @field_validator("tenant_id", "client_id")
    @classmethod
    def validate_uuid(cls, value: str) -> str:
        if _UUID_RE.fullmatch(value) is None:
            raise ValueError("Azure workload identity must use canonical UUIDs")
        return value

    @field_validator("expected_issuer")
    @classmethod
    def validate_issuer(cls, value: str) -> str:
        return _https_url(value, label="Azure workload identity issuer")

    @field_validator("expected_subject")
    @classmethod
    def validate_subject(cls, value: str) -> str:
        if any(character in value for character in "\x00\r\n"):
            raise ValueError("Azure workload identity subject is invalid")
        return value


class KeyVaultKeySettings(_StrictFrozenModel):
    vault_name: str = Field(min_length=3, max_length=24)
    key_name: str = Field(min_length=1, max_length=127)
    key_version: str = Field(min_length=32, max_length=32)

    @field_validator("vault_name")
    @classmethod
    def validate_vault(cls, value: str) -> str:
        if _VAULT_RE.fullmatch(value) is None:
            raise ValueError("Key Vault name is invalid")
        return value

    @field_validator("key_name")
    @classmethod
    def validate_key_name(cls, value: str) -> str:
        if _KEY_NAME_RE.fullmatch(value) is None:
            raise ValueError("Key Vault key name is invalid")
        return value

    @field_validator("key_version")
    @classmethod
    def validate_key_version(cls, value: str) -> str:
        if _KEY_VERSION_RE.fullmatch(value) is None:
            raise ValueError("Key Vault key version is invalid")
        return value


class KeyManagementSettings(_StrictFrozenModel):
    azure_workload_identity: AzureWorkloadIdentitySettings
    key_vault_ca_bundle: PinnedPublicFile
    pkce_wrapping_key: KeyVaultKeySettings
    oidc_client_signing_key: KeyVaultKeySettings
    oidc_client_certificate: PinnedPublicFile
    csrf_key_secret_ref: str = Field(min_length=1, max_length=2_048)
    request_timeout_seconds: int = Field(default=30, ge=1, le=120)
    operation_timeout_seconds: int = Field(default=60, ge=1, le=120)

    @field_validator("csrf_key_secret_ref")
    @classmethod
    def validate_secret_reference(cls, value: str) -> str:
        if _SECRET_REFERENCE_RE.fullmatch(value) is None:
            raise ValueError("CSRF key must be one exact-version Key Vault secret")
        return value


class EntitlementSettings(_StrictFrozenModel):
    group: str = Field(min_length=1, max_length=255)
    tenant_id: str = Field(min_length=1, max_length=128)
    roles: tuple[Role, ...]

    @field_validator("group")
    @classmethod
    def validate_group(cls, value: str) -> str:
        if _GROUP_RE.fullmatch(value) is None:
            raise ValueError("OIDC entitlement group is invalid")
        return value

    @field_validator("tenant_id")
    @classmethod
    def validate_tenant(cls, value: str) -> str:
        if _TENANT_RE.fullmatch(value) is None:
            raise ValueError("OIDC entitlement tenant is invalid")
        return value

    @field_validator("roles", mode="before")
    @classmethod
    def parse_roles(cls, value: object) -> tuple[Role, ...]:
        if (
            type(value) is not list
            or not value
            or len(value) > 6
            or any(type(item) is not str for item in value)
            or len(value) != len(set(value))
        ):
            raise ValueError("OIDC entitlement roles are invalid")
        return cast(tuple[Role, ...], tuple(sorted(cast(list[str], value))))


class MFASettings(_StrictFrozenModel):
    required: Literal[True] = True
    accepted_acr: tuple[str, ...] = ()
    required_amr: tuple[str, ...] = ("mfa",)
    maximum_authentication_age_seconds: int = Field(default=3_600, ge=60, le=86_400)

    @field_validator("accepted_acr", "required_amr", mode="before")
    @classmethod
    def parse_claims(cls, value: object) -> tuple[str, ...]:
        if (
            type(value) is not list
            or len(value) > 32
            or any(type(item) is not str for item in value)
            or len(value) != len(set(value))
        ):
            raise ValueError("OIDC MFA evidence is invalid")
        claims = cast(list[str], value)
        if any(_CLAIM_RE.fullmatch(item) is None for item in claims):
            raise ValueError("OIDC MFA evidence is invalid")
        return tuple(sorted(claims))

    @model_validator(mode="after")
    def validate_evidence(self) -> MFASettings:
        if not self.accepted_acr and not self.required_amr:
            raise ValueError("required MFA policy must name evidence")
        return self


class OIDCLoginAdmissionSettings(_StrictFrozenModel):
    global_active_limit: int = Field(default=512, ge=1, le=100_000)
    source_active_limit: int = Field(default=4, ge=1, le=100_000)
    reservation_ttl_seconds: int = Field(default=30, ge=5, le=120)
    burn_capacity: int = Field(default=4_096, ge=1, le=1_000_000)
    trusted_proxy_cidrs: tuple[str, ...] = ()

    @field_validator("trusted_proxy_cidrs", mode="before")
    @classmethod
    def parse_trusted_proxy_cidrs(cls, value: object) -> tuple[str, ...]:
        if (
            type(value) is not list
            or len(value) > 32
            or any(type(item) is not str for item in value)
            or len(value) != len(set(cast(list[str], value)))
        ):
            raise ValueError("OIDC trusted proxy CIDRs are invalid")
        result: list[str] = []
        for item in cast(list[str], value):
            try:
                network = ipaddress.ip_network(item, strict=True)
            except ValueError:
                raise ValueError("OIDC trusted proxy CIDRs are invalid") from None
            if str(network) != item:
                raise ValueError("OIDC trusted proxy CIDRs must be canonical")
            result.append(item)
        return tuple(sorted(result))

    @model_validator(mode="after")
    def validate_capacities(self) -> OIDCLoginAdmissionSettings:
        if self.source_active_limit > self.global_active_limit:
            raise ValueError("OIDC source active limit exceeds global limit")
        if self.burn_capacity < self.global_active_limit:
            raise ValueError("OIDC burn capacity is below the active limit")
        return self


class OIDCSettings(_StrictFrozenModel):
    issuer: str = Field(min_length=9, max_length=2_048)
    authorization_endpoint: str = Field(min_length=9, max_length=2_048)
    token_endpoint: str = Field(min_length=9, max_length=2_048)
    jwks_uri: str = Field(min_length=9, max_length=2_048)
    client_id: str = Field(min_length=1, max_length=255)
    entitlements: tuple[EntitlementSettings, ...]
    mfa_policy: MFASettings = Field(default_factory=MFASettings)
    login_admission: OIDCLoginAdmissionSettings = Field(
        default_factory=OIDCLoginAdmissionSettings
    )
    scopes: tuple[str, ...] = ("openid", "profile")
    transaction_ttl_seconds: int = Field(default=300, ge=60, le=900)
    session_ttl_seconds: int = Field(default=28_800, ge=300, le=86_400)
    clock_skew_seconds: int = Field(default=60, ge=0, le=300)
    maximum_id_token_age_seconds: int = Field(default=300, ge=30, le=900)
    maximum_id_token_lifetime_seconds: int = Field(default=3_600, ge=60, le=86_400)
    jwks_ca_bundle: PinnedPublicFile
    request_timeout_seconds: int = Field(default=15, ge=1, le=120)
    jwks_cache_seconds: int = Field(default=60, ge=0, le=300)
    jwks_negative_cache_seconds: int = Field(default=5, ge=1, le=30)

    @field_validator(
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
    )
    @classmethod
    def validate_url(cls, value: str, info: object) -> str:
        field_name = getattr(info, "field_name", "endpoint")
        return _https_url(value, label=f"OIDC {field_name}")

    @field_validator("client_id")
    @classmethod
    def validate_client_id(cls, value: str) -> str:
        if any(ord(character) < 0x21 or ord(character) > 0x7E for character in value):
            raise ValueError("OIDC client id is invalid")
        return value

    @field_validator("scopes", mode="before")
    @classmethod
    def parse_scopes(cls, value: object) -> tuple[str, ...]:
        if (
            type(value) is not list
            or not value
            or len(value) > 16
            or any(type(item) is not str for item in value)
            or len(value) != len(set(value))
        ):
            raise ValueError("OIDC scopes are invalid")
        scopes = cast(list[str], value)
        if "openid" not in scopes or any(
            _SCOPE_RE.fullmatch(item) is None for item in scopes
        ):
            raise ValueError("OIDC scopes are invalid")
        return tuple(scopes)

    @field_validator("entitlements", mode="before")
    @classmethod
    def parse_entitlements(
        cls,
        value: object,
    ) -> tuple[object, ...]:
        if type(value) is not list:
            raise ValueError("OIDC entitlements must be a JSON array")
        return tuple(value)

    @field_validator("entitlements")
    @classmethod
    def validate_entitlements(
        cls,
        value: tuple[EntitlementSettings, ...],
    ) -> tuple[EntitlementSettings, ...]:
        groups = [item.group for item in value]
        if not value or len(value) > 512 or len(groups) != len(set(groups)):
            raise ValueError("OIDC entitlements must be bounded and unique")
        return value


class HTTPSettings(_StrictFrozenModel):
    bind_host: Literal["0.0.0.0", "127.0.0.1", "::"] = "0.0.0.0"
    port: int = Field(default=8080, ge=1_024, le=65_535)
    offload_workers: int = Field(default=8, ge=1, le=256)
    offload_queue_capacity: int = Field(default=32, ge=0, le=4_096)
    offload_admission_timeout_seconds: float = Field(default=0.25, ge=0.001, le=30.0)
    readiness_cache_seconds: int = Field(default=300, ge=30, le=3_600)


class ControlPlaneServiceConfig(_StrictFrozenModel):
    media_type: Literal["application/vnd.control-assurance.control-plane-config+json"]
    schema_version: Literal["2.0.0"]
    deployment_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    public_origin: str = Field(min_length=9, max_length=2_048)
    database: DatabaseSettings
    key_management: KeyManagementSettings
    oidc: OIDCSettings
    http: HTTPSettings = Field(default_factory=HTTPSettings)

    @field_validator("deployment_id")
    @classmethod
    def validate_deployment_id(cls, value: str) -> str:
        if _DEPLOYMENT_ID_RE.fullmatch(value) is None:
            raise ValueError("deployment id is invalid")
        return value

    @field_validator("tenant_id")
    @classmethod
    def validate_tenant_id(cls, value: str) -> str:
        if _TENANT_RE.fullmatch(value) is None:
            raise ValueError("deployment tenant is invalid")
        return value

    @field_validator("public_origin")
    @classmethod
    def validate_public_origin(cls, value: str) -> str:
        return _https_url(value, label="public origin", origin_only=True)

    @model_validator(mode="after")
    def validate_cross_references(self) -> ControlPlaneServiceConfig:
        if self.public_origin.endswith("/"):
            raise ValueError("public origin must not end in a slash")
        if self.key_management.oidc_client_signing_key.vault_name != (
            self.key_management.pkce_wrapping_key.vault_name
        ):
            raise ValueError("control-plane Key Vault keys must share one pinned vault")
        parsed_secret = urllib.parse.urlsplit(
            self.key_management.csrf_key_secret_ref
        )
        if parsed_secret.hostname != self.key_management.pkce_wrapping_key.vault_name:
            raise ValueError("CSRF secret and control-plane keys must share one pinned vault")
        if any(
            entitlement.tenant_id != self.tenant_id
            for entitlement in self.oidc.entitlements
        ):
            raise ValueError(
                "every OIDC entitlement must use the deployment tenant"
            )
        return self

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"))

    @property
    def digest(self) -> str:
        import hashlib

        return f"sha256:{hashlib.sha256(self.canonical_bytes).hexdigest()}"


def load_control_plane_service_config(
    path: Path,
    *,
    expected_digest: str,
) -> ControlPlaneServiceConfig:
    """Load one canonical config whose digest came from a separate channel."""

    if not isinstance(path, Path) or not path.is_absolute():
        raise ControlPlaneConfigurationError(
            "control-plane config path must be absolute"
        )
    if type(expected_digest) is not str or _DIGEST_RE.fullmatch(expected_digest) is None:
        raise ControlPlaneConfigurationError(
            "control-plane config digest is invalid"
        )
    try:
        with path.open("rb") as stream:
            payload = stream.read(_CONFIG_LIMITS.max_bytes + 1)
        if len(payload) > _CONFIG_LIMITS.max_bytes:
            raise ValueError
        raw = strict_json_loads(payload, limits=_CONFIG_LIMITS)
        if not isinstance(raw, dict):
            raise ValueError
        configuration = ControlPlaneServiceConfig.model_validate(raw)
    except (OSError, StrictJSONError, TypeError, ValueError):
        raise ControlPlaneConfigurationError(
            "control-plane configuration is invalid"
        ) from None
    if configuration.digest != expected_digest:
        raise ControlPlaneConfigurationError(
            "control-plane configuration digest does not match"
        )
    return configuration


__all__ = [
    "AzureWorkloadIdentitySettings",
    "ControlPlaneConfigurationError",
    "ControlPlaneServiceConfig",
    "DatabaseSettings",
    "EntitlementSettings",
    "EnvironmentReference",
    "HTTPSettings",
    "KeyManagementSettings",
    "KeyVaultKeySettings",
    "MFASettings",
    "OIDCLoginAdmissionSettings",
    "OIDCSettings",
    "PinnedPublicFile",
    "ProtectedFileReference",
    "load_control_plane_service_config",
]
