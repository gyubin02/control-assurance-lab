from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import assurance_lab.control_plane.bootstrap as bootstrap
from assurance_lab.control_plane.bootstrap import (
    ControlPlaneBootstrapError,
    ControlPlaneReadiness,
    read_protected_file,
)
from assurance_lab.control_plane.service_cli import main
from assurance_lab.control_plane.service_config import (
    ControlPlaneConfigurationError,
    ControlPlaneServiceConfig,
    ProtectedFileReference,
    load_control_plane_service_config,
)
from assurance_lab.evidence.canonical import canonical_json_bytes

_DIGEST_A = f"sha256:{'a' * 64}"
_DIGEST_B = f"sha256:{'b' * 64}"
_DIGEST_C = f"sha256:{'c' * 64}"
_VERSION_A = "a" * 32
_VERSION_B = "b" * 32
_TENANT_ID = "11111111-2222-4333-8444-555555555555"
_CLIENT_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


def _document() -> dict[str, object]:
    protected_token = {
        "kind": "protected-file",
        "path": "/var/run/control-assurance/azure/token",
        "mount_root": "/var/run/control-assurance/azure",
        "owner_uid": 0,
        "group_gid": 2000,
        "mode": 288,
    }
    database_ca = {
        "file": {
            "kind": "protected-file",
            "path": "/etc/control-assurance/trust/postgres-ca.pem",
            "mount_root": "/etc/control-assurance/trust",
            "owner_uid": 0,
            "group_gid": 2000,
            "mode": 288,
        },
        "sha256_digest": _DIGEST_A,
    }
    oidc_ca = {
        "file": {
            "kind": "protected-file",
            "path": "/etc/control-assurance/trust/oidc-ca.pem",
            "mount_root": "/etc/control-assurance/trust",
            "owner_uid": 0,
            "group_gid": 2000,
            "mode": 288,
        },
        "sha256_digest": _DIGEST_B,
    }
    key_vault_ca = {
        "file": {
            "kind": "protected-file",
            "path": "/etc/control-assurance/trust/key-vault-ca.pem",
            "mount_root": "/etc/control-assurance/trust",
            "owner_uid": 0,
            "group_gid": 2000,
            "mode": 288,
        },
        "sha256_digest": _DIGEST_C,
    }
    certificate = {
        "file": {
            "kind": "protected-file",
            "path": "/etc/control-assurance/identity/oidc-client.der",
            "mount_root": "/etc/control-assurance/identity",
            "owner_uid": 0,
            "group_gid": 2000,
            "mode": 288,
        },
        "sha256_digest": _DIGEST_A,
    }
    return {
        "media_type": "application/vnd.control-assurance.control-plane-config+json",
        "schema_version": "2.0.0",
        "deployment_id": "seoul-production",
        "tenant_id": "acme-bank",
        "public_origin": "https://assurance.example.test",
        "database": {
            "control_dsn": {
                "kind": "environment",
                "name": "ASSURANCE_CONTROL_PLANE_CONTROL_DSN",
            },
            "auth_dsn": {
                "kind": "environment",
                "name": "ASSURANCE_CONTROL_PLANE_AUTH_DSN",
            },
            "control_role": "assurance_control_runtime",
            "auth_role": "assurance_auth_runtime",
            "migration_owner_role": "assurance_migration_owner",
            "ca_bundle": database_ca,
            "min_pool_size": 2,
            "max_pool_size": 16,
            "connect_timeout_seconds": 10,
            "statement_timeout_ms": 15000,
            "lock_timeout_ms": 5000,
            "require_tls_verify_full": True,
            "require_read_write_primary": True,
        },
        "key_management": {
            "azure_workload_identity": {
                "tenant_id": _TENANT_ID,
                "client_id": _CLIENT_ID,
                "token": protected_token,
                "expected_issuer": "https://oidc.prod-aks.azure.com/tenant/cluster/",
                "expected_subject": (
                    "system:serviceaccount:control-assurance:"
                    "control-assurance-control-plane"
                ),
                "refresh_skew_seconds": 120,
                "timeout_seconds": 30,
            },
            "key_vault_ca_bundle": key_vault_ca,
            "pkce_wrapping_key": {
                "vault_name": "assurance-prod",
                "key_name": "oidc-pkce",
                "key_version": _VERSION_A,
            },
            "oidc_client_signing_key": {
                "vault_name": "assurance-prod",
                "key_name": "oidc-client",
                "key_version": _VERSION_B,
            },
            "oidc_client_certificate": certificate,
            "csrf_key_secret_ref": (
                "azure-keyvault://assurance-prod/secrets/control-csrf/"
                f"{_VERSION_A}"
            ),
            "request_timeout_seconds": 30,
            "operation_timeout_seconds": 60,
        },
        "oidc": {
            "issuer": "https://login.example.test/tenant/v2.0",
            "authorization_endpoint": (
                "https://login.example.test/tenant/oauth2/v2.0/authorize"
            ),
            "token_endpoint": (
                "https://login.example.test/tenant/oauth2/v2.0/token"
            ),
            "jwks_uri": "https://login.example.test/tenant/discovery/v2.0/keys",
            "client_id": _CLIENT_ID,
            "entitlements": [
                {
                    "group": "secops-platform",
                    "tenant_id": "acme-bank",
                    "roles": ["editor", "viewer"],
                },
                {
                    "group": "secops-approvers",
                    "tenant_id": "acme-bank",
                    "roles": ["approver", "viewer"],
                },
            ],
            "mfa_policy": {
                "required": True,
                "accepted_acr": [],
                "required_amr": ["mfa"],
                "maximum_authentication_age_seconds": 3600,
            },
            "login_admission": {
                "global_active_limit": 512,
                "source_active_limit": 4,
                "reservation_ttl_seconds": 30,
                "burn_capacity": 4096,
                "trusted_proxy_cidrs": [],
            },
            "scopes": ["openid", "profile"],
            "transaction_ttl_seconds": 300,
            "session_ttl_seconds": 28800,
            "clock_skew_seconds": 60,
            "maximum_id_token_age_seconds": 300,
            "maximum_id_token_lifetime_seconds": 3600,
            "jwks_ca_bundle": oidc_ca,
            "request_timeout_seconds": 15,
            "jwks_cache_seconds": 60,
            "jwks_negative_cache_seconds": 5,
        },
        "http": {
            "bind_host": "0.0.0.0",
            "port": 8080,
            "offload_workers": 8,
            "offload_queue_capacity": 32,
            "offload_admission_timeout_seconds": 0.25,
            "readiness_cache_seconds": 300,
        },
    }


def _configuration() -> ControlPlaneServiceConfig:
    return ControlPlaneServiceConfig.model_validate(_document())


def test_configuration_is_secret_free_canonical_and_digest_pinned(
    tmp_path: Path,
) -> None:
    configuration = _configuration()
    path = tmp_path / "control-plane.json"
    path.write_bytes(configuration.canonical_bytes)

    loaded = load_control_plane_service_config(
        path,
        expected_digest=configuration.digest,
    )

    assert loaded == configuration
    assert b"ASSURANCE_CONTROL_PLANE_CONTROL_DSN" in loaded.canonical_bytes
    assert b"ASSURANCE_CONTROL_PLANE_AUTH_DSN" in loaded.canonical_bytes
    assert b"password" not in loaded.canonical_bytes.lower()
    assert b"latest" not in loaded.canonical_bytes.lower()
    with pytest.raises(
        ControlPlaneConfigurationError,
        match="digest does not match",
    ):
        load_control_plane_service_config(
            path,
            expected_digest=f"sha256:{'0' * 64}",
        )


def test_configuration_normalizes_json_format_but_rejects_raw_secret_fields(
    tmp_path: Path,
) -> None:
    configuration = _configuration()
    path = tmp_path / "control-plane.json"
    path.write_bytes(configuration.canonical_bytes + b"\n")
    assert (
        load_control_plane_service_config(
            path,
            expected_digest=configuration.digest,
        )
        == configuration
    )

    document = _document()
    database = document["database"]
    assert isinstance(database, dict)
    database["password"] = "must-not-be-configurable"
    with pytest.raises(ValueError):
        ControlPlaneServiceConfig.model_validate(document)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("public_origin",), "http://assurance.example.test"),
        (
            ("key_management", "pkce_wrapping_key", "key_version"),
            "latest",
        ),
        (
            ("key_management", "csrf_key_secret_ref"),
            "azure-keyvault://assurance-prod/secrets/control-csrf/latest",
        ),
        (
            ("key_management", "oidc_client_signing_key", "vault_name"),
            "different-vault",
        ),
    ],
)
def test_configuration_rejects_unpinned_or_cross_boundary_values(
    path: tuple[str, ...],
    value: str,
) -> None:
    document = _document()
    target: dict[str, object] = document
    for component in path[:-1]:
        nested = target[component]
        assert isinstance(nested, dict)
        target = nested
    target[path[-1]] = value
    with pytest.raises(ValueError):
        ControlPlaneServiceConfig.model_validate(document)


def test_login_admission_configuration_is_bounded_and_proxy_trust_is_explicit() -> None:
    configuration = _configuration()
    assert configuration.oidc.login_admission.global_active_limit == 512
    assert configuration.oidc.login_admission.source_active_limit == 4
    assert configuration.oidc.login_admission.trusted_proxy_cidrs == ()

    noncanonical = _document()
    oidc = noncanonical["oidc"]
    assert isinstance(oidc, dict)
    admission = oidc["login_admission"]
    assert isinstance(admission, dict)
    admission["trusted_proxy_cidrs"] = ["10.0.0.1/8"]
    with pytest.raises(ValueError, match="trusted proxy CIDRs"):
        ControlPlaneServiceConfig.model_validate(noncanonical)

    inverted = _document()
    oidc = inverted["oidc"]
    assert isinstance(oidc, dict)
    admission = oidc["login_admission"]
    assert isinstance(admission, dict)
    admission["global_active_limit"] = 2
    admission["source_active_limit"] = 3
    with pytest.raises(ValueError, match="source active limit"):
        ControlPlaneServiceConfig.model_validate(inverted)


def test_configuration_enforces_one_tenant_and_separate_database_roles() -> None:
    crossed = _document()
    oidc = crossed["oidc"]
    assert isinstance(oidc, dict)
    entitlements = oidc["entitlements"]
    assert isinstance(entitlements, list)
    entitlement = entitlements[0]
    assert isinstance(entitlement, dict)
    entitlement["tenant_id"] = "other-bank"
    with pytest.raises(ValueError, match="deployment tenant"):
        ControlPlaneServiceConfig.model_validate(crossed)

    shared_dsn = _document()
    database = shared_dsn["database"]
    assert isinstance(database, dict)
    database["auth_dsn"] = database["control_dsn"]
    with pytest.raises(ValueError, match="DSNs must be distinct"):
        ControlPlaneServiceConfig.model_validate(shared_dsn)

    shared_role = _document()
    database = shared_role["database"]
    assert isinstance(database, dict)
    database["auth_role"] = database["control_role"]
    with pytest.raises(ValueError, match="roles must be distinct"):
        ControlPlaneServiceConfig.model_validate(shared_role)


def test_protected_file_checks_exact_mode_owner_and_digestable_bytes(
    tmp_path: Path,
) -> None:
    mount = tmp_path / "mount"
    mount.mkdir()
    target = mount / "value"
    content = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=")
    target.write_bytes(content)
    target.chmod(0o400)
    reference = ProtectedFileReference(
        path=str(target),
        mount_root=str(mount),
        owner_uid=os.geteuid(),
        group_gid=os.getegid(),
        mode=0o400,
    )

    assert read_protected_file(reference, maximum_bytes=1024) == content

    target.chmod(0o600)
    with pytest.raises(
        ControlPlaneConfigurationError,
        match="ownership, mode, or stability",
    ):
        read_protected_file(reference, maximum_bytes=1024)


def test_readiness_is_cached_single_state_and_fails_closed() -> None:
    calls = 0

    def succeeds() -> None:
        nonlocal calls
        calls += 1

    readiness = ControlPlaneReadiness(succeeds, cache_seconds=300)
    assert readiness.check(force=True) is True
    assert readiness.check() is True
    assert calls == 1
    readiness.close()
    assert readiness.check(force=True) is False
    assert calls == 1

    def fails() -> None:
        raise ControlPlaneBootstrapError("database-preflight")

    failed = ControlPlaneReadiness(fails, cache_seconds=300)
    assert failed.check(force=True) is False


def test_database_preflight_requires_exact_runtime_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Cursor:
        def __init__(self, row: dict[str, object] | None = None) -> None:
            self._row = row

        def fetchone(self) -> dict[str, object] | None:
            return self._row

    class Context:
        def __init__(self, value: object) -> None:
            self._value = value

        def __enter__(self) -> object:
            return self._value

        def __exit__(self, *args: object) -> None:
            del args

    class Connection:
        def transaction(self) -> Context:
            return Context(self)

        def execute(
            self,
            statement: str,
            parameters: object = None,
        ) -> Cursor:
            del parameters
            return Cursor({"tls": True} if "pg_stat_ssl" in statement else None)

    class Pool:
        def __init__(self) -> None:
            self._connection = Connection()

        def connection(self) -> Context:
            return Context(self._connection)

    monkeypatch.setattr(
        bootstrap,
        "runtime_boundary_is_safe",
        lambda connection, expectation: (
            expectation.tenant_id == "acme-bank"
            and expectation.login_role == "assurance_control_runtime"
            and expectation.migration_owner_role == "assurance_migration_owner"
        ),
    )
    bootstrap._preflight_database(
        Pool(),  # type: ignore[arg-type]
        _configuration(),
        role_kind="control",
    )
    monkeypatch.setattr(
        bootstrap,
        "runtime_boundary_is_safe",
        lambda connection, expectation: False,
    )
    with pytest.raises(
        ControlPlaneBootstrapError,
        match="database-preflight",
    ):
        bootstrap._preflight_database(
            Pool(),  # type: ignore[arg-type]
            _configuration(),
            role_kind="control",
        )


def test_control_plane_cli_calculates_digest_and_rejects_unpinned_run(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configuration = _configuration()
    path = tmp_path / "control-plane.json"
    path.write_bytes(configuration.canonical_bytes)

    assert main(["config-digest", "--config", str(path)], environment={}) == 0
    assert capsys.readouterr().out.strip() == configuration.digest

    assert main(["run", "--config", str(path)], environment={}) == 2
    assert capsys.readouterr().err.strip() == "control-plane-config-invalid"


def test_control_plane_cli_redacts_unclassified_startup_failure(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration = _configuration()
    path = tmp_path / "control-plane.json"
    path.write_bytes(configuration.canonical_bytes)

    def fail_startup(*args: object) -> None:
        del args
        raise RuntimeError("postgresql://user:password@must-not-leak")

    monkeypatch.setattr(
        "assurance_lab.control_plane.service_cli._serve",
        fail_startup,
    )

    assert (
        main(
            ["run", "--config", str(path)],
            environment={
                "ASSURANCE_CONTROL_PLANE_CONFIG_DIGEST": (
                    configuration.digest
                )
            },
        )
        == 1
    )
    assert capsys.readouterr().err.strip() == "control-plane-failed"


def test_canonical_fixture_has_no_accidental_nondeterminism() -> None:
    first = _configuration()
    second = _configuration()
    assert first.canonical_bytes == second.canonical_bytes
    assert first.canonical_bytes == canonical_json_bytes(first.model_dump(mode="json"))
    assert first.digest == second.digest


def test_production_factory_rejects_public_trust_tamper_before_clients(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _document()
    selected = (
        (
            document["database"],
            "ca_bundle",
            tmp_path / "trust" / "postgres-ca.pem",
        ),
        (
            document["oidc"],
            "jwks_ca_bundle",
            tmp_path / "trust" / "oidc-ca.pem",
        ),
        (
            document["key_management"],
            "key_vault_ca_bundle",
            tmp_path / "trust" / "key-vault-ca.pem",
        ),
        (
            document["key_management"],
            "oidc_client_certificate",
            tmp_path / "identity" / "oidc-client.der",
        ),
    )
    for owner, field, path in selected:
        assert isinstance(owner, dict)
        pin = owner[field]
        assert isinstance(pin, dict)
        file_settings = pin["file"]
        assert isinstance(file_settings, dict)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = f"test-only:{field}".encode()
        path.write_bytes(content)
        path.chmod(0o400)
        file_settings.update(
            {
                "path": str(path),
                "mount_root": str(path.parent),
                "owner_uid": os.geteuid(),
                "group_gid": os.getegid(),
                "mode": 0o400,
            }
        )
        pin["sha256_digest"] = (
            f"sha256:{hashlib.sha256(content).hexdigest()}"
        )
    configuration = ControlPlaneServiceConfig.model_validate(document)
    oidc_ca = tmp_path / "trust" / "oidc-ca.pem"
    oidc_ca.chmod(0o600)
    oidc_ca.write_bytes(b"tampered-oidc-ca")
    oidc_ca.chmod(0o400)
    clients_reached = False

    def must_not_create_clients(*_args: object, **_kwargs: object) -> object:
        nonlocal clients_reached
        clients_reached = True
        raise AssertionError("network-capable client construction was reached")

    monkeypatch.setattr(bootstrap, "_azure_provider", must_not_create_clients)

    with pytest.raises(ControlPlaneBootstrapError) as error:
        bootstrap.ProductionControlPlaneFactory(
            configuration,
            environment={
                "ASSURANCE_CONTROL_PLANE_CONTROL_DSN": "not-reached",
                "ASSURANCE_CONTROL_PLANE_AUTH_DSN": "not-reached",
            },
        ).build()
    assert error.value.stage == "public-file-digest"
    assert clients_reached is False


def test_production_factory_runs_all_preflights_and_closes_separate_pools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class Pool:
        def __init__(self, name: str) -> None:
            self.name = name
            self.close_calls = 0

        def close(self) -> None:
            self.close_calls += 1

    control_pool = Pool("control")
    auth_pool = Pool("auth")

    class Secret:
        def consume(
            self,
            decoder: object,
            *,
            expected_content_type: str,
        ) -> bytes:
            assert expected_content_type.endswith("+base64url")
            assert callable(decoder)
            value = base64.urlsafe_b64encode(b"k" * 32).rstrip(b"=")
            return decoder(value)  # type: ignore[no-any-return]

    class SecretClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        def get(self) -> Secret:
            return Secret()

    class Reference:
        @classmethod
        def parse(cls, value: str) -> object:
            assert value.startswith("azure-keyvault://")
            return object()

    class Authenticator:
        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

    class Resolver:
        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

    class Store:
        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

    class Service:
        def __init__(self, store: object) -> None:
            del store

    class Assertions:
        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

    class HTTP:
        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

    monkeypatch.setattr(
        bootstrap,
        "_read_pinned_public_file",
        lambda *args, **kwargs: b"public",
    )
    monkeypatch.setattr(bootstrap, "_azure_provider", lambda value: object())
    monkeypatch.setattr(
        bootstrap,
        "_crypto_client",
        lambda *args, **kwargs: object(),
    )
    monkeypatch.setattr(
        bootstrap,
        "AzureKeyVaultEnvelopeProtector",
        lambda value: object(),
    )
    monkeypatch.setattr(
        bootstrap,
        "AzureKeyVaultPS256Signer",
        lambda *args, **kwargs: object(),
    )
    monkeypatch.setattr(bootstrap, "CertificatePrivateKeyJWT", Assertions)
    monkeypatch.setattr(bootstrap, "PinnedOIDCHTTPClient", HTTP)
    monkeypatch.setattr(bootstrap, "AzureKeyVaultSecretReference", Reference)
    monkeypatch.setattr(bootstrap, "AzureKeyVaultSecretClient", SecretClient)
    monkeypatch.setattr(
        bootstrap,
        "_validate_database_transport",
        lambda dsn, **kwargs: {
            "host": "postgres.example.test",
            "dbname": "assurance",
            "sslrootcert": "/test/ca.pem",
            "user": (
                "assurance_control_runtime"
                if dsn == "control-dsn"
                else "assurance_auth_runtime"
            ),
        },
    )
    monkeypatch.setattr(
        bootstrap,
        "_create_pool",
        lambda dsn, configuration: (
            control_pool if dsn == "control-dsn" else auth_pool
        ),
    )
    monkeypatch.setattr(bootstrap, "PostgresControlPlaneStore", Store)
    monkeypatch.setattr(bootstrap, "PostgresOIDCStateStore", Store)
    monkeypatch.setattr(bootstrap, "ControlPlaneService", Service)
    monkeypatch.setattr(bootstrap, "OIDCAuthenticator", Authenticator)
    monkeypatch.setattr(bootstrap, "OIDCIdentityResolver", Resolver)
    monkeypatch.setattr(
        bootstrap,
        "create_control_plane_app",
        lambda *args, **kwargs: FastAPI(),
    )
    monkeypatch.setattr(
        bootstrap,
        "_preflight_database",
        lambda *args, **kwargs: calls.append(
            f"database-{kwargs['role_kind']}"
        ),
    )
    monkeypatch.setattr(
        bootstrap,
        "_preflight_kms",
        lambda *args: calls.append("kms"),
    )
    monkeypatch.setattr(
        bootstrap,
        "_preflight_jwks",
        lambda *args: calls.append("oidc"),
    )

    configuration = _configuration()
    components = bootstrap.ProductionControlPlaneFactory(
        configuration,
        environment={
            "ASSURANCE_CONTROL_PLANE_CONTROL_DSN": "control-dsn",
            "ASSURANCE_CONTROL_PLANE_AUTH_DSN": "auth-dsn",
        },
    ).build()

    assert calls == ["database-control", "database-auth", "kms", "oidc"]
    with TestClient(components.application) as client:
        response = client.get("/health/ready")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}
        assert control_pool.close_calls == 0
        assert auth_pool.close_calls == 0
    assert control_pool.close_calls == 1
    assert auth_pool.close_calls == 1
    components.close()
    assert control_pool.close_calls == 1
    assert auth_pool.close_calls == 1
