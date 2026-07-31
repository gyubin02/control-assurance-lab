from __future__ import annotations

import hashlib
import os
import urllib.parse
from pathlib import Path
from typing import Any

import pytest

import assurance_lab.runtime.profile_registrar as registrar_module
from assurance_lab.controls.alert_window import (
    AlertWindowProfile,
    Criterion,
    ElasticAlertSource,
    TotalRecordCount,
)
from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.runtime.bootstrap import RuntimeBootstrapError
from assurance_lab.runtime.models import RegisteredControlProfile
from assurance_lab.runtime.profile_registrar import (
    ControlProfileArtifact,
    ProfileRegistrationDatabaseSettings,
    RuntimeProfileRegistrationManifest,
    parse_profile_registration_manifest,
    register_control_profiles,
)
from assurance_lab.runtime.service_config import (
    EnvironmentReference,
    PinnedPublicFileSettings,
    ProtectedFileSettings,
    RuntimeServiceConfigurationError,
)


def _profile() -> AlertWindowProfile:
    return AlertWindowProfile(
        profile_id="alert-window-v1",
        profile_version="1.0.0",
        title="Alert ingestion continuity",
        source=ElasticAlertSource(fields=("@timestamp",)),
        criteria=(
            Criterion(
                criterion_id="window-has-alert",
                description="At least one alert was retained in the window.",
                metric=TotalRecordCount(),
                comparison="ge",
                expected_count=1,
            ),
        ),
    )


def _manifest(tmp_path: Path) -> RuntimeProfileRegistrationManifest:
    profile = _profile()
    profile_path = tmp_path / "alert-window-v1.json"
    profile_path.write_bytes(profile.canonical_bytes())
    profile_path.chmod(0o400)
    database_ca_path = tmp_path / "postgres-ca.pem"
    database_ca = b"profile-registrar-postgres-ca"
    database_ca_path.write_bytes(database_ca)
    database_ca_path.chmod(0o400)
    return RuntimeProfileRegistrationManifest(
        tenant_id="tenant-a",
        registrar_id=EnvironmentReference(name="PROFILE_REGISTRAR_ID"),
        database=ProfileRegistrationDatabaseSettings(
            runtime_dsn=EnvironmentReference(name="RUNTIME_DATABASE_DSN"),
            runtime_role="control_assurance_runtime_registrar",
            ca_bundle=PinnedPublicFileSettings(
                file=ProtectedFileSettings(
                    path=str(database_ca_path),
                    mount_root=str(tmp_path),
                    owner_uid=os.geteuid(),
                    group_gid=os.getegid(),
                    mode=0o400,
                ),
                sha256_digest=(
                    f"sha256:{hashlib.sha256(database_ca).hexdigest()}"
                ),
            ),
        ),
        profiles=(
            ControlProfileArtifact(
                profile_id=profile.profile_id,
                expected_digest=profile.digest,
                file=ProtectedFileSettings(
                    path=str(profile_path),
                    mount_root=str(tmp_path),
                    owner_uid=os.geteuid(),
                    group_gid=os.getegid(),
                    mode=0o400,
                ),
            ),
        ),
    )


def _database_dsn(
    manifest: RuntimeProfileRegistrationManifest,
) -> str:
    ca_path = urllib.parse.quote(
        manifest.database.ca_bundle.file.path,
        safe="",
    )
    return (
        "postgresql://worker@db.internal.example/runtime"
        "?sslmode=verify-full&target_session_attrs=read-write"
        f"&sslrootcert={ca_path}"
    )


def test_profile_manifest_round_trips_only_under_its_release_digest(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)

    assert (
        parse_profile_registration_manifest(
            manifest.canonical_bytes,
            expected_digest=manifest.digest,
        )
        == manifest
    )
    with pytest.raises(RuntimeServiceConfigurationError, match="digest differs"):
        parse_profile_registration_manifest(
            manifest.canonical_bytes,
            expected_digest=f"sha256:{'f' * 64}",
        )

    document = manifest.model_dump(mode="json")
    document["database"]["password"] = "must-not-enter-the-manifest"
    with pytest.raises(RuntimeServiceConfigurationError) as error:
        parse_profile_registration_manifest(
            canonical_json_bytes(document),
            expected_digest=manifest.digest,
        )
    assert "must-not-enter-the-manifest" not in str(error.value)


def test_registrar_appends_exact_profile_and_closes_its_separate_catalog(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest(tmp_path)
    seen: list[RegisteredControlProfile] = []
    closed: list[bool] = []

    class Catalog:
        @classmethod
        def from_dsn(cls, *_args: object, **_kwargs: object) -> Catalog:
            return cls()

        def register_control_profile(
            self,
            profile: RegisteredControlProfile,
        ) -> RegisteredControlProfile:
            seen.append(profile)
            return profile

        def close(self) -> None:
            closed.append(True)

    monkeypatch.setattr(
        registrar_module,
        "_preflight_database",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(registrar_module, "PostgresRuntimeCatalog", Catalog)

    result = register_control_profiles(
        manifest,
        environment={
            "PROFILE_REGISTRAR_ID": "release.profile-registrar",
            "RUNTIME_DATABASE_DSN": _database_dsn(manifest),
        },
    )

    assert result == tuple(seen)
    assert len(seen) == 1
    assert seen[0].tenant_id == "tenant-a"
    assert seen[0].profile_bytes == _profile().canonical_bytes()
    assert seen[0].registered_by == "release.profile-registrar"
    assert closed == [True]


def test_registrar_rejects_noncanonical_profile_before_database_append(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest(tmp_path)
    profile_path = Path(manifest.profiles[0].file.path)
    profile_path.chmod(0o600)
    profile_path.write_bytes(b'{ "profile_id": "alert-window-v1" }')
    profile_path.chmod(0o400)

    class Catalog:
        @classmethod
        def from_dsn(cls, *_args: object, **_kwargs: object) -> Catalog:
            return cls()

        def register_control_profile(self, _profile: object) -> Any:
            raise AssertionError("invalid profile reached the database")

        def close(self) -> None:
            return None

    monkeypatch.setattr(
        registrar_module,
        "_preflight_database",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(registrar_module, "PostgresRuntimeCatalog", Catalog)

    with pytest.raises(
        RuntimeBootstrapError,
        match="profile-registration",
    ):
        register_control_profiles(
            manifest,
            environment={
                "PROFILE_REGISTRAR_ID": "release.profile-registrar",
                "RUNTIME_DATABASE_DSN": _database_dsn(manifest),
            },
        )


def test_registrar_rejects_database_ca_tamper_before_database_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest(tmp_path)
    ca_path = Path(manifest.database.ca_bundle.file.path)
    ca_path.chmod(0o600)
    ca_path.write_bytes(b"tampered-profile-database-ca")
    ca_path.chmod(0o400)
    network_reached = False

    def must_not_connect(*_args: object, **_kwargs: object) -> None:
        nonlocal network_reached
        network_reached = True
        raise AssertionError("profile registrar reached the database")

    monkeypatch.setattr(
        registrar_module,
        "_preflight_database",
        must_not_connect,
    )

    with pytest.raises(RuntimeBootstrapError) as error:
        register_control_profiles(
            manifest,
            environment={
                "PROFILE_REGISTRAR_ID": "release.profile-registrar",
                "RUNTIME_DATABASE_DSN": _database_dsn(manifest),
            },
        )
    assert error.value.stage == "database-trust"
    assert network_reached is False
