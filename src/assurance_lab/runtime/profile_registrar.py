"""One-shot, least-privilege registration of immutable control profiles.

The long-running worker intentionally has no authority to change the profile
registry.  This module is the deployment-time boundary that reads exact,
digest-pinned profile artifacts and appends them with a separately injected
PostgreSQL identity.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from assurance_lab.controls.alert_window import (
    ALERT_WINDOW_PROFILE_MEDIA_TYPE,
    parse_alert_window_profile,
)
from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)
from assurance_lab.runtime.bootstrap import (
    RuntimeBootstrapError,
    _preflight_database,
    _validate_database_transport,
)
from assurance_lab.runtime.deployment_io import (
    read_pinned_public_file,
    read_protected_file,
)
from assurance_lab.runtime.models import RegisteredControlProfile, sha256_digest
from assurance_lab.runtime.postgres import PostgresRuntimeCatalog
from assurance_lab.runtime.service_config import (
    DatabaseRoleName,
    Digest,
    EnvironmentReference,
    PinnedPublicFileSettings,
    ProtectedFileSettings,
    RuntimeServiceConfigurationError,
)

_MANIFEST_LIMITS = JSONLimits(
    max_bytes=4 * 1024 * 1024,
    max_line_bytes=4 * 1024 * 1024,
    max_depth=24,
    max_collection_items=8_192,
    max_string_length=1024 * 1024,
)
_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_REGISTRAR_ID_RE = re.compile(r"^[a-z][a-z0-9._:@/-]{0,127}$")

ProfileId = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9._-]{0,127}$",
    ),
]


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=False,
    )


class ControlProfileArtifact(_FrozenModel):
    """Exact public profile bytes made available by the release system."""

    profile_id: ProfileId
    expected_digest: Digest
    media_type: Literal[
        "application/vnd.control-assurance.alert-window-profile.v1+json"
    ] = ALERT_WINDOW_PROFILE_MEDIA_TYPE
    file: ProtectedFileSettings


class ProfileRegistrationDatabaseSettings(_FrozenModel):
    runtime_dsn: EnvironmentReference
    runtime_role: DatabaseRoleName
    ca_bundle: PinnedPublicFileSettings
    connect_timeout_seconds: int = Field(default=10, ge=1, le=60)
    statement_timeout_ms: int = Field(default=15_000, ge=100, le=120_000)
    lock_timeout_ms: int = Field(default=5_000, ge=100, le=120_000)
    require_tls: Literal[True] = True

    @model_validator(mode="after")
    def validate_timeouts(self) -> ProfileRegistrationDatabaseSettings:
        if self.lock_timeout_ms > self.statement_timeout_ms:
            raise ValueError("database lock timeout exceeds statement timeout")
        return self


class RuntimeProfileRegistrationManifest(_FrozenModel):
    """Canonical, secret-free manifest consumed by the registrar Job."""

    kind: Literal["control-assurance-runtime-profile-registration"] = (
        "control-assurance-runtime-profile-registration"
    )
    schema_version: Literal["1.0.0"] = "1.0.0"
    tenant_id: ProfileId
    registrar_id: EnvironmentReference
    database: ProfileRegistrationDatabaseSettings
    profiles: tuple[ControlProfileArtifact, ...] = Field(
        min_length=1,
        max_length=1_024,
    )

    @field_validator("profiles")
    @classmethod
    def validate_unique_profiles(
        cls,
        value: tuple[ControlProfileArtifact, ...],
    ) -> tuple[ControlProfileArtifact, ...]:
        identities = tuple(
            (profile.profile_id, profile.expected_digest) for profile in value
        )
        if len(set(identities)) != len(identities):
            raise ValueError("profile registration manifest contains duplicates")
        return value

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"))

    @property
    def digest(self) -> str:
        return sha256_digest(self.canonical_bytes)


def parse_profile_registration_manifest(
    value: bytes,
    *,
    expected_digest: str,
) -> RuntimeProfileRegistrationManifest:
    """Parse one bounded manifest and require its release-pinned digest."""

    if (
        type(value) is not bytes
        or not value
        or type(expected_digest) is not str
        or _DIGEST_RE.fullmatch(expected_digest) is None
    ):
        raise RuntimeServiceConfigurationError(
            "profile registration manifest input is invalid"
        )
    try:
        document = strict_json_loads(value, limits=_MANIFEST_LIMITS)
        if not isinstance(document, dict):
            raise ValueError
        manifest = RuntimeProfileRegistrationManifest.model_validate_json(value)
    except (StrictJSONError, TypeError, ValueError):
        raise RuntimeServiceConfigurationError(
            "profile registration manifest is invalid"
        ) from None
    if manifest.digest != expected_digest:
        raise RuntimeServiceConfigurationError(
            "profile registration manifest digest differs"
        )
    return manifest


def load_profile_registration_manifest(
    path: Path,
    *,
    expected_digest: str,
) -> RuntimeProfileRegistrationManifest:
    if type(path) is not Path or not path.is_absolute():
        raise RuntimeServiceConfigurationError(
            "profile registration manifest path must be absolute"
        )
    try:
        with path.open("rb") as stream:
            value = stream.read(_MANIFEST_LIMITS.max_bytes + 1)
    except OSError:
        raise RuntimeServiceConfigurationError(
            "profile registration manifest is unavailable"
        ) from None
    if len(value) > _MANIFEST_LIMITS.max_bytes:
        raise RuntimeServiceConfigurationError(
            "profile registration manifest exceeds its byte limit"
        )
    return parse_profile_registration_manifest(
        value,
        expected_digest=expected_digest,
    )


def register_control_profiles(
    manifest: RuntimeProfileRegistrationManifest,
    *,
    environment: Mapping[str, str],
) -> tuple[RegisteredControlProfile, ...]:
    """Append every exact profile or reopen the existing identical row."""

    if type(manifest) is not RuntimeProfileRegistrationManifest:
        raise TypeError("profile registration manifest must be exact")
    registrar_id = manifest.registrar_id.resolve(environment, maximum_bytes=128)
    if _REGISTRAR_ID_RE.fullmatch(registrar_id) is None:
        raise RuntimeServiceConfigurationError(
            "resolved profile registrar identity is invalid"
        )
    database = manifest.database
    dsn = database.runtime_dsn.resolve(environment, maximum_bytes=8_192)
    if "\r" in dsn or "\n" in dsn:
        raise RuntimeServiceConfigurationError(
            "database environment reference contains invalid framing"
        )
    try:
        read_pinned_public_file(database.ca_bundle)
        conninfo = importlib.import_module("psycopg.conninfo")
        parameters = cast(
            Mapping[str, str],
            conninfo.conninfo_to_dict(dsn),
        )
        _validate_database_transport(
            parameters,
            expected_ca_file=Path(database.ca_bundle.file.path),
        )
    except RuntimeBootstrapError:
        raise
    except Exception:
        raise RuntimeBootstrapError("database-trust") from None
    validated_profiles: list[tuple[ControlProfileArtifact, bytes]] = []
    for artifact in manifest.profiles:
        try:
            profile_bytes = read_protected_file(
                artifact.file,
                maximum_bytes=1024 * 1024,
            )
            parse_alert_window_profile(
                profile_bytes,
                expected_profile_id=artifact.profile_id,
                expected_profile_digest=artifact.expected_digest,
            )
        except RuntimeServiceConfigurationError:
            raise
        except Exception:
            raise RuntimeBootstrapError("profile-registration") from None
        validated_profiles.append((artifact, profile_bytes))

    _preflight_database(
        dsn,
        schema="control_assurance_runtime",
        expected_version=3,
        expected_tenant=manifest.tenant_id,
        expected_database_role=database.runtime_role,
        expected_principal_kind="registrar",
        connect_timeout_seconds=database.connect_timeout_seconds,
    )
    catalog: PostgresRuntimeCatalog | None = None
    operation_failed = False
    try:
        catalog = PostgresRuntimeCatalog.from_dsn(
            dsn,
            min_size=1,
            max_size=2,
            connect_timeout_seconds=database.connect_timeout_seconds,
            statement_timeout_ms=database.statement_timeout_ms,
            lock_timeout_ms=database.lock_timeout_ms,
        )
        registered: list[RegisteredControlProfile] = []
        for artifact, profile_bytes in validated_profiles:
            registered.append(
                catalog.register_control_profile(
                    RegisteredControlProfile(
                        tenant_id=manifest.tenant_id,
                        profile_id=artifact.profile_id,
                        profile_digest=artifact.expected_digest,
                        media_type=artifact.media_type,
                        profile_bytes=profile_bytes,
                        registered_at=datetime.now(UTC).replace(microsecond=0),
                        registered_by=registrar_id,
                    )
                )
            )
        return tuple(registered)
    except RuntimeBootstrapError:
        operation_failed = True
        raise
    except RuntimeServiceConfigurationError:
        operation_failed = True
        raise
    except Exception:
        operation_failed = True
        raise RuntimeBootstrapError("profile-registration") from None
    except BaseException:
        operation_failed = True
        raise
    finally:
        if catalog is not None:
            try:
                catalog.close()
            except Exception:
                if not operation_failed:
                    raise RuntimeBootstrapError(
                        "profile-registrar-close"
                    ) from None


__all__ = [
    "ControlProfileArtifact",
    "ProfileRegistrationDatabaseSettings",
    "RuntimeProfileRegistrationManifest",
    "load_profile_registration_manifest",
    "parse_profile_registration_manifest",
    "register_control_profiles",
]
