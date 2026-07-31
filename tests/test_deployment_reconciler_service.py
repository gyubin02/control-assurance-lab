from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from assurance_lab.control_plane.deployment import (
    DeploymentApplyError,
    DeploymentApplyRequest,
    DeploymentTargetAcknowledgement,
)
from assurance_lab.control_plane.reconciler_cli import main
from assurance_lab.control_plane.reconciler_service import (
    RegisteredConfigurationDeploymentTarget,
    _required_digest,
    _verify_pinned_database_ca,
)
from assurance_lab.runtime.bootstrap import RuntimeBootstrapError
from assurance_lab.runtime.service_config import RuntimeWorkerServiceConfig


def _runtime_configuration() -> RuntimeWorkerServiceConfig:
    path = (
        Path(__file__).parents[1]
        / "deploy"
        / "kubernetes"
        / "runtime-worker-config.example.json"
    )
    return RuntimeWorkerServiceConfig.model_validate_json(path.read_bytes())


class _Target:
    def __init__(self) -> None:
        self.requests: list[DeploymentApplyRequest] = []

    def ensure_applied(
        self,
        request: DeploymentApplyRequest,
    ) -> DeploymentTargetAcknowledgement:
        self.requests.append(request)
        return DeploymentTargetAcknowledgement(
            operation_id=request.operation_id,
            lease_fence=request.lease_fence,
            applied_configuration_digest=request.configuration_digest,
            target_receipt_digest=f"sha256:{'f' * 64}",
        )


def _request(
    configuration: RuntimeWorkerServiceConfig,
    *,
    registered: bool,
) -> DeploymentApplyRequest:
    control = configuration.registrations[0].configuration
    if not registered:
        control = control.model_copy(
            update={"display_name": f"{control.display_name} changed"}
        )
    return DeploymentApplyRequest(
        operation_id=f"sha256:{'1' * 64}",
        tenant_id=control.tenant_id,
        control_id=control.control_id,
        revision_id=f"sha256:{'2' * 64}",
        configuration_digest=control.digest,
        configuration_bytes=control.canonical_bytes(),
        operation_sequence=1,
        lease_fence=1,
    )


def test_reconciler_target_delegates_only_exact_registered_configuration() -> None:
    configuration = _runtime_configuration()
    delegate = _Target()
    target = RegisteredConfigurationDeploymentTarget(delegate, configuration)
    request = _request(configuration, registered=True)

    acknowledgement = target.ensure_applied(request)

    assert acknowledgement.operation_id == request.operation_id
    assert delegate.requests == [request]

    with pytest.raises(DeploymentApplyError) as caught:
        target.ensure_applied(_request(configuration, registered=False))
    assert caught.value.code == "runtime-release-registration-missing"
    assert caught.value.retryable is False
    assert delegate.requests == [request]


def test_reconciler_capability_gate_rejects_legal_hold_before_database_write() -> None:
    configuration = _runtime_configuration()
    registration = configuration.registrations[0]
    evidence = registration.configuration.evidence.model_copy(
        update={"legal_hold": True}
    )
    control = registration.configuration.model_copy(
        update={"evidence": evidence}
    )
    unsupported = configuration.model_copy(
        update={
            "registrations": (
                registration.model_copy(update={"configuration": control}),
            )
        }
    )

    with pytest.raises(
        ValueError,
        match="unsupported custody capability",
    ):
        RegisteredConfigurationDeploymentTarget(_Target(), unsupported)


@pytest.mark.parametrize(
    "reference",
    (
        "vault://kv/elastic-parent",
        "aws-secretsmanager://security/elastic-parent",
        "gcp-secretmanager://security/elastic-parent",
        "azure-keyvault://security-kv/secrets/elastic-parent/latest",
    ),
)
def test_reconciler_capability_gate_rejects_uncomposable_credential(
    reference: str,
) -> None:
    configuration = _runtime_configuration()
    registration = configuration.registrations[0]
    source = registration.configuration.source.model_copy(
        update={"parent_credential_ref": reference}
    )
    control = registration.configuration.model_copy(update={"source": source})
    unsupported = configuration.model_copy(
        update={
            "registrations": (
                registration.model_copy(update={"configuration": control}),
            )
        }
    )

    with pytest.raises(
        ValueError,
        match="not exact-version Azure Key Vault",
    ):
        RegisteredConfigurationDeploymentTarget(_Target(), unsupported)


def test_reconciler_capability_gate_rejects_unpinned_elastic_ca() -> None:
    configuration = _runtime_configuration()
    registration = configuration.registrations[0]
    source = registration.configuration.source.model_copy(
        update={
            "ca_bundle_ref": (
                "azure-keyvault://security-kv/secrets/elastic-ca/latest"
            )
        }
    )
    control = registration.configuration.model_copy(update={"source": source})
    unsupported = configuration.model_copy(
        update={
            "registrations": (
                registration.model_copy(update={"configuration": control}),
            )
        }
    )

    with pytest.raises(
        ValueError,
        match="CA is not exact-version Azure Key Vault",
    ):
        RegisteredConfigurationDeploymentTarget(_Target(), unsupported)


def test_reconciler_cli_requires_separately_pinned_runtime_release(
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = (
        Path(__file__).parents[1]
        / "deploy"
        / "kubernetes"
        / "runtime-worker-config.example.json"
    )
    assert (
        main(
            ["run", "--runtime-config", str(path)],
            environment={},
        )
        == 2
    )
    assert capsys.readouterr().err.strip() == (
        "deployment-reconciler-config-invalid"
    )


def test_reconciler_verifies_database_ca_bytes_before_connection(
    tmp_path: Path,
) -> None:
    certificate = tmp_path / "postgres-ca.pem"
    certificate.write_bytes(b"test-only-postgresql-root")
    certificate.chmod(0o400)
    digest = f"sha256:{hashlib.sha256(certificate.read_bytes()).hexdigest()}"
    dsn = (
        "host=postgres.internal.example "
        "dbname=control_assurance user=reconciler "
        "sslmode=verify-full target_session_attrs=read-write "
        f"sslrootcert={certificate}"
    )

    _verify_pinned_database_ca(
        dsn,
        expected_digest=digest,
        expected_path=certificate,
        mount_root=tmp_path,
    )

    with pytest.raises(RuntimeBootstrapError) as mismatch:
        _verify_pinned_database_ca(
            dsn,
            expected_digest=f"sha256:{'f' * 64}",
            expected_path=certificate,
            mount_root=tmp_path,
        )
    assert mismatch.value.stage == "database-trust"

    certificate.chmod(0o600)
    with pytest.raises(RuntimeBootstrapError) as writable:
        _verify_pinned_database_ca(
            dsn,
            expected_digest=digest,
            expected_path=certificate,
            mount_root=tmp_path,
        )
    assert writable.value.stage == "database-trust"

    certificate.chmod(0o400)
    linked = tmp_path / "linked-ca.pem"
    os.link(certificate, linked)
    with pytest.raises(RuntimeBootstrapError) as linked_error:
        _verify_pinned_database_ca(
            dsn,
            expected_digest=digest,
            expected_path=certificate,
            mount_root=tmp_path,
        )
    assert linked_error.value.stage == "database-transport-policy"


def test_reconciler_rejects_a_validly_pinned_ca_at_an_unapproved_dsn_path(
    tmp_path: Path,
) -> None:
    approved = tmp_path / "approved-ca.pem"
    approved.write_bytes(b"approved-postgresql-root")
    approved.chmod(0o400)
    alternate = tmp_path / "alternate-ca.pem"
    alternate.write_bytes(approved.read_bytes())
    alternate.chmod(0o400)
    digest = f"sha256:{hashlib.sha256(approved.read_bytes()).hexdigest()}"
    dsn = (
        "host=postgres.internal.example "
        "dbname=control_assurance user=reconciler "
        "sslmode=verify-full target_session_attrs=read-write "
        f"sslrootcert={alternate}"
    )

    with pytest.raises(RuntimeBootstrapError) as mismatch:
        _verify_pinned_database_ca(
            dsn,
            expected_digest=digest,
            expected_path=approved,
            mount_root=tmp_path,
        )
    assert mismatch.value.stage == "database-transport-policy"


def test_reconciler_requires_out_of_band_ca_digest() -> None:
    digest = f"sha256:{'a' * 64}"
    assert _required_digest({"PIN": digest}, name="PIN") == digest
    for environment in ({}, {"PIN": "sha256:latest"}, {"PIN": ""}):
        with pytest.raises(
            ValueError,
            match="database CA digest is unavailable",
        ):
            _required_digest(environment, name="PIN")
