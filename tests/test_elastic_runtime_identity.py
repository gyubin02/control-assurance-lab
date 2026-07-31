from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from assurance_lab.connectors.elastic_pam import (
    ELASTIC_PAM_BROKER_ID,
    ElasticJitApiKeyBroker,
    ElasticPamPolicy,
)
from assurance_lab.connectors.elastic_security import (
    ELASTIC_SECURITY_CONNECTOR_ID,
    elastic_endpoint_origin_digest,
)
from assurance_lab.connectors.postgres_pam_journal import (
    PostgresElasticLeaseJournal,
)
from assurance_lab.connectors.secret_profiles import (
    ELASTIC_PARENT_CREDENTIAL_CONTENT_TYPE,
)
from assurance_lab.control_plane.models import (
    ControlConfiguration,
    ElasticSourceConfiguration,
    EvidenceConfiguration,
    ScheduleConfiguration,
)
from assurance_lab.controls.alert_window import (
    ALERT_WINDOW_PROFILE_MEDIA_TYPE,
    AlertWindowProfile,
    Criterion,
    ElasticAlertSource,
    EqualsPredicate,
    MatchingRecordCount,
)
from assurance_lab.evidence.canonical import (
    canonical_json_bytes,
    strict_json_loads,
)
from assurance_lab.key_management import azure_secret as azs
from assurance_lab.key_management.azure_key_vault import (
    AzureKeyVaultBearerToken,
)
from assurance_lab.runtime.elastic_identity import (
    ELASTIC_CA_TRUST_PROFILE,
    ELASTIC_RUNTIME_IDENTITY_MEDIA_TYPE,
    ElasticRuntimeIdentityError,
    PreparedElasticRuntimeIdentity,
    PrevalidatedElasticCATrust,
    prepare_elastic_managed_source_from_identity,
    prepare_elastic_runtime_identity,
)
from assurance_lab.runtime.execution_plan import (
    ControlRunExecutionPlan,
    create_control_run_execution_plan,
)
from assurance_lab.runtime.managed_source import (
    ELASTIC_AUTHORIZATION_PROFILE_ID,
    PreparedManagedSource,
)
from assurance_lab.runtime.models import (
    ControlRunExecutionRequest,
    ControlRunRequest,
    sha256_digest,
)

_NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
_WINDOW_START = _NOW - timedelta(minutes=7)
_WINDOW_END = _NOW - timedelta(minutes=2)
_SECRET_VERSION = "a" * 32
_CA_VERSION = "b" * 32
_PARENT_REF = (
    "azure-keyvault://assurance-prod/secrets/elastic-parent/"
    + _SECRET_VERSION
)
_CA_REF = (
    "azure-keyvault://assurance-prod/secrets/elastic-ca/" + _CA_VERSION
)
_NAMESPACE_DIGEST = "sha256:" + ("c" * 64)
_DEPLOYMENT_ID = "sha256:" + ("1" * 64)
_DEPLOYMENT_RECEIPT = "sha256:" + ("2" * 64)
_REVISION_ID = "sha256:" + ("3" * 64)
_CAPTURE_NONCE = "4" * 64


class _UnusedPool:
    def connection(self) -> Any:
        raise AssertionError("identity preparation must not contact PostgreSQL")


class _TokenProvider:
    def get_token(
        self,
        *,
        scope: str,
        deadline: float,
    ) -> AzureKeyVaultBearerToken:
        del scope
        return AzureKeyVaultBearerToken(
            b"unit-test-workload-token",
            valid_until_monotonic=deadline + 60,
        )


@dataclass
class _SecretTransport:
    response: azs._SecretHTTPResponse | None
    failure: str | None = None

    def get(
        self,
        *,
        target: str,
        token: AzureKeyVaultBearerToken,
        deadline: float,
    ) -> azs._SecretHTTPResponse:
        del target, token, deadline
        if self.failure is not None:
            raise RuntimeError(self.failure)
        assert self.response is not None
        return self.response


def _credential_profile(
    *,
    scheme: str = "basic",
    marker: str = "parent-password-must-not-leak",
) -> bytes:
    if scheme == "basic":
        return canonical_json_bytes(
            {
                "kind": "elastic-parent-credential",
                "password": marker,
                "schema_version": "1.0.0",
                "scheme": "basic",
                "username": "jit-broker",
            }
        )
    return canonical_json_bytes(
        {
            "kind": "elastic-parent-credential",
            "schema_version": "1.0.0",
            "scheme": "bearer",
            "token": marker,
        }
    )


def _secret_client(
    profile: bytes,
    *,
    reference: azs.AzureKeyVaultSecretReference | None = None,
    content_type: str | None = ELASTIC_PARENT_CREDENTIAL_CONTENT_TYPE,
    failure: str | None = None,
) -> azs.AzureKeyVaultSecretClient:
    selected = reference or azs.AzureKeyVaultSecretReference.parse(_PARENT_REF)
    document: dict[str, object] = {
        "attributes": {"enabled": True},
        "id": selected.secret_uri,
        "value": profile.decode("utf-8"),
    }
    if content_type is not None:
        document["contentType"] = content_type
    response = azs._SecretHTTPResponse(
        status=200,
        headers=(("content-type", "application/json"),),
        body=canonical_json_bytes(document),
    )
    return azs.AzureKeyVaultSecretClient(
        _TokenProvider(),
        selected,
        _transport=_SecretTransport(
            None if failure is not None else response,
            failure=failure,
        ),
        _monotonic=lambda: 100.0,
        _now=lambda: _NOW,
    )


@pytest.fixture
def ca_path(tmp_path: Path) -> Path:
    private_key = rsa.generate_private_key(
        public_exponent=65_537,
        key_size=2_048,
    )
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Elastic test CA")]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(7)
        .not_valid_before(datetime(2026, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=UTC))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    path = tmp_path / "elastic-ca.pem"
    path.write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM)
    )
    path.chmod(0o600)
    return path


def _source(
    *,
    endpoint: str = "https://elastic.bank.invalid",
    parent_ref: str = _PARENT_REF,
    ca_ref: str | None = _CA_REF,
    ttl: int = 1_200,
) -> ElasticSourceConfiguration:
    return ElasticSourceConfiguration(
        endpoint_origin=endpoint,
        index_alias=".alerts-security.alerts-payments",
        parent_credential_ref=parent_ref,
        ca_bundle_ref=ca_ref,
        lease_ttl_seconds=ttl,
    )


def _identity(
    ca_path: Path,
    *,
    source: ElasticSourceConfiguration | None = None,
    profile: bytes | None = None,
    content_type: str | None = ELASTIC_PARENT_CREDENTIAL_CONTENT_TYPE,
) -> PreparedElasticRuntimeIdentity:
    configuration = source or _source()
    trust = PrevalidatedElasticCATrust.from_path(
        ca_path,
        configured_reference=configuration.ca_bundle_ref,
    )
    return prepare_elastic_runtime_identity(
        configuration,
        parent_secret_client=_secret_client(
            profile or _credential_profile(),
            content_type=content_type,
        ),
        journal_pool=_UnusedPool(),
        journal_namespace_digest=_NAMESPACE_DIGEST,
        ca_trust=trust,
        request_timeout_seconds=20,
    )


def _profile() -> AlertWindowProfile:
    return AlertWindowProfile(
        profile_id="high-alert-window",
        profile_version="1.0.0",
        title="High alert window",
        source=ElasticAlertSource(
            fields=("@timestamp", "kibana.alert.severity"),
        ),
        criteria=(
            Criterion(
                criterion_id="high-alert",
                description="At least one high alert is present.",
                metric=MatchingRecordCount(
                    all=(
                        EqualsPredicate(
                            field="kibana.alert.severity",
                            value="high",
                        ),
                    )
                ),
                comparison="ge",
                expected_count=1,
            ),
        ),
    )


def _execution(
    source: ElasticSourceConfiguration,
) -> tuple[ControlRunExecutionRequest, ControlRunExecutionPlan]:
    profile = _profile()
    configuration = ControlConfiguration(
        tenant_id="bank-a",
        control_id="high-alert",
        display_name="High alert",
        description="Re-evaluate one closed Elastic alert window.",
        environment="production",
        owner_group="security/detection",
        control_profile_id=profile.profile_id,
        control_profile_digest=profile.digest,
        source=source,
        schedule=ScheduleConfiguration(
            interval_seconds=300,
            collection_lag_seconds=120,
            window_seconds=300,
        ),
        evidence=EvidenceConfiguration(
            custody_ref="s3-object-lock://evidence/bank-a/high-alert",
            signing_key_ref="vault-transit://assurance/runtime",
            retention_days=365,
        ),
    )
    run = ControlRunRequest(
        tenant_id=configuration.tenant_id,
        control_id=configuration.control_id,
        deployment_operation_id=_DEPLOYMENT_ID,
        deployment_operation_sequence=1,
        deployment_receipt_digest=_DEPLOYMENT_RECEIPT,
        control_profile_id=profile.profile_id,
        control_profile_digest=profile.digest,
        revision_id=_REVISION_ID,
        configuration_digest=configuration.digest,
        window_start=_WINDOW_START,
        window_end=_WINDOW_END,
        due_at=_NOW,
    )
    request = ControlRunExecutionRequest(
        run_id=run.run_id,
        run_request_bytes=run.canonical_bytes(),
        tenant_id=configuration.tenant_id,
        control_id=configuration.control_id,
        deployment_operation_id=run.deployment_operation_id,
        deployment_receipt_digest=run.deployment_receipt_digest,
        configuration_digest=configuration.digest,
        configuration_bytes=configuration.canonical_bytes(),
        control_profile_id=profile.profile_id,
        control_profile_digest=profile.digest,
        control_profile_media_type=ALERT_WINDOW_PROFILE_MEDIA_TYPE,
        control_profile_bytes=profile.canonical_bytes(),
        window_start=_WINDOW_START,
        window_end=_WINDOW_END,
        attempt_count=1,
        lease_fence=1,
    )
    plan = create_control_run_execution_plan(
        request,
        capture_nonce=_CAPTURE_NONCE,
        prepared_at=_NOW,
    )
    return request, plan


def test_exact_secret_postgres_journal_broker_and_public_identity(
    ca_path: Path,
) -> None:
    prepared = _identity(ca_path)
    identity = strict_json_loads(prepared.runtime_identity_bytes)
    policy = ElasticPamPolicy(
        index_alias=".alerts-security.alerts-payments",
        ttl_seconds=1_200,
    )

    assert type(prepared.broker) is ElasticJitApiKeyBroker
    assert identity["media_type"] == ELASTIC_RUNTIME_IDENTITY_MEDIA_TYPE
    assert identity["broker_id"] == ELASTIC_PAM_BROKER_ID
    assert identity["connector_id"] == ELASTIC_SECURITY_CONNECTOR_ID
    assert identity["endpoint_origin_digest"] == elastic_endpoint_origin_digest(
        "https://elastic.bank.invalid"
    )
    assert identity["index_alias"] == ".alerts-security.alerts-payments"
    assert identity["lease_ttl_seconds"] == 1_200
    assert identity["role_descriptor"] == policy.role_descriptor()
    assert identity["role_descriptor_digest"] == (
        policy.role_descriptor_digest
    )
    assert identity["journal_namespace_digest"] == _NAMESPACE_DIGEST
    assert identity["ca_trust_profile"] == ELASTIC_CA_TRUST_PROFILE
    assert identity["parent_authentication_scheme"] == "Basic"
    assert prepared.runtime_identity_digest == sha256_digest(
        prepared.runtime_identity_bytes
    )
    assert (
        prepared.broker.endpoint_origin_digest
        == prepared.endpoint_origin_digest
    )
    rendered = prepared.runtime_identity_bytes.decode("utf-8")
    assert "parent-password-must-not-leak" not in rendered
    assert _PARENT_REF not in rendered
    assert os.fspath(ca_path) not in rendered
    assert "parent-password-must-not-leak" not in repr(prepared)
    assert os.fspath(ca_path) not in repr(prepared)


def test_bearer_profile_changes_only_public_scheme_and_never_exposes_token(
    ca_path: Path,
) -> None:
    token = "opaque-bearer-parent-token"
    prepared = _identity(
        ca_path,
        profile=_credential_profile(scheme="bearer", marker=token),
    )
    identity = strict_json_loads(prepared.runtime_identity_bytes)

    assert identity["parent_authentication_scheme"] == "Bearer"
    assert token not in prepared.runtime_identity_bytes.decode("utf-8")
    assert token not in repr(prepared)


def test_identity_is_deterministic_for_same_public_inputs(ca_path: Path) -> None:
    first = _identity(ca_path)
    second = _identity(ca_path)

    assert first.runtime_identity_bytes == second.runtime_identity_bytes
    assert first.runtime_identity_digest == second.runtime_identity_digest


def test_identity_can_be_compared_to_exact_approved_bytes(ca_path: Path) -> None:
    prepared = _identity(ca_path)

    prepared.assert_runtime_identity(
        expected_bytes=prepared.runtime_identity_bytes,
        expected_digest=prepared.runtime_identity_digest,
    )
    tampered = prepared.runtime_identity_bytes.replace(
        b'"lease_ttl_seconds":1200',
        b'"lease_ttl_seconds":1201',
    )
    with pytest.raises(ElasticRuntimeIdentityError, match="differs"):
        prepared.assert_runtime_identity(
            expected_bytes=tampered,
            expected_digest=sha256_digest(tampered),
        )


def test_frozen_request_and_plan_prepare_the_exact_managed_source(
    ca_path: Path,
) -> None:
    source = _source()
    runtime = _identity(ca_path, source=source)
    request, plan = _execution(source)

    prepared = prepare_elastic_managed_source_from_identity(
        request,
        plan,
        runtime_identity=runtime,
    )

    assert type(prepared) is PreparedManagedSource
    assert prepared.authorization_profile.profile_id == (
        ELASTIC_AUTHORIZATION_PROFILE_ID
    )
    assert prepared.source_locator_digest == (
        runtime.endpoint_origin_digest
    )
    assert prepared.authorization_profile.credential_reference_digest == (
        sha256_digest(_PARENT_REF.encode("utf-8"))
    )
    assert prepared.connector_request_bytes == plan.connector_request_bytes


def test_endpoint_or_source_policy_drift_is_rejected_before_network(
    ca_path: Path,
) -> None:
    runtime = _identity(ca_path, source=_source())
    request, plan = _execution(
        _source(endpoint="https://elastic-other.bank.invalid")
    )

    with pytest.raises(
        ElasticRuntimeIdentityError,
        match="frozen execution source differs",
    ):
        runtime.prepare_managed_source(request, plan)


def test_parent_reference_and_secret_client_must_match_exact_version(
    ca_path: Path,
) -> None:
    source = _source()
    trust = PrevalidatedElasticCATrust.from_path(
        ca_path,
        configured_reference=source.ca_bundle_ref,
    )
    other = azs.AzureKeyVaultSecretReference(
        vault_name="another-vault",
        secret_name="elastic-parent",
        secret_version="d" * 32,
    )

    with pytest.raises(
        ElasticRuntimeIdentityError,
        match="secret client differs",
    ):
        prepare_elastic_runtime_identity(
            source,
            parent_secret_client=_secret_client(
                _credential_profile(),
                reference=other,
            ),
            journal_pool=_UnusedPool(),
            journal_namespace_digest=_NAMESPACE_DIGEST,
            ca_trust=trust,
        )


def test_only_exact_azure_parent_and_ca_references_are_accepted(
    ca_path: Path,
) -> None:
    non_azure_parent = _source(parent_ref="vault://kv/elastic-parent")
    trust = PrevalidatedElasticCATrust.from_path(
        ca_path,
        configured_reference=non_azure_parent.ca_bundle_ref,
    )
    with pytest.raises(ElasticRuntimeIdentityError, match="exact Azure"):
        prepare_elastic_runtime_identity(
            non_azure_parent,
            parent_secret_client=_secret_client(_credential_profile()),
            journal_pool=_UnusedPool(),
            journal_namespace_digest=_NAMESPACE_DIGEST,
            ca_trust=trust,
        )

    with pytest.raises(ElasticRuntimeIdentityError, match="exact Azure"):
        PrevalidatedElasticCATrust.from_path(
            ca_path,
            configured_reference="vault://kv/elastic-ca",
        )


def test_content_type_decode_and_transport_errors_are_sanitized(
    ca_path: Path,
) -> None:
    marker = "DO-NOT-REFLECT-ELASTIC-SECRET"
    source = _source()
    trust = PrevalidatedElasticCATrust.from_path(
        ca_path,
        configured_reference=source.ca_bundle_ref,
    )

    with pytest.raises(ElasticRuntimeIdentityError) as wrong_type:
        prepare_elastic_runtime_identity(
            source,
            parent_secret_client=_secret_client(
                _credential_profile(marker=marker),
                content_type="application/octet-stream",
            ),
            journal_pool=_UnusedPool(),
            journal_namespace_digest=_NAMESPACE_DIGEST,
            ca_trust=trust,
        )
    assert marker not in str(wrong_type.value)
    assert marker not in repr(wrong_type.value)

    malformed = canonical_json_bytes(
        {
            "kind": "elastic-parent-credential",
            "password": marker,
            "schema_version": "1.0.0",
            "scheme": "basic",
            "unexpected": True,
            "username": "jit-broker",
        }
    )
    with pytest.raises(ElasticRuntimeIdentityError) as decode:
        prepare_elastic_runtime_identity(
            source,
            parent_secret_client=_secret_client(malformed),
            journal_pool=_UnusedPool(),
            journal_namespace_digest=_NAMESPACE_DIGEST,
            ca_trust=trust,
        )
    assert marker not in str(decode.value)
    assert marker not in repr(decode.value)

    with pytest.raises(ElasticRuntimeIdentityError) as transport:
        prepare_elastic_runtime_identity(
            source,
            parent_secret_client=_secret_client(
                _credential_profile(),
                failure=marker,
            ),
            journal_pool=_UnusedPool(),
            journal_namespace_digest=_NAMESPACE_DIGEST,
            ca_trust=trust,
        )
    assert marker not in str(transport.value)
    assert marker not in repr(transport.value)


def test_ca_path_is_owner_only_nonsymlink_and_rechecked(ca_path: Path) -> None:
    ca_path.chmod(0o644)
    with pytest.raises(ElasticRuntimeIdentityError, match="owner-only"):
        PrevalidatedElasticCATrust.from_path(
            ca_path,
            configured_reference=_CA_REF,
        )

    ca_path.chmod(0o600)
    symlink = ca_path.parent / "elastic-ca-link.pem"
    symlink.symlink_to(ca_path)
    with pytest.raises(ElasticRuntimeIdentityError, match="symbolic"):
        PrevalidatedElasticCATrust.from_path(
            symlink,
            configured_reference=_CA_REF,
        )

    runtime = _identity(ca_path)
    ca_path.write_bytes(ca_path.read_bytes() + b"\n")
    ca_path.chmod(0o600)
    request, plan = _execution(_source())
    with pytest.raises(ElasticRuntimeIdentityError, match="bytes changed"):
        runtime.prepare_managed_source(request, plan)


def test_ca_reference_and_journal_namespace_fail_closed(ca_path: Path) -> None:
    source = _source()
    unbound = PrevalidatedElasticCATrust.from_path(
        ca_path,
        configured_reference=None,
    )
    with pytest.raises(ElasticRuntimeIdentityError, match="differs"):
        prepare_elastic_runtime_identity(
            source,
            parent_secret_client=_secret_client(_credential_profile()),
            journal_pool=_UnusedPool(),
            journal_namespace_digest=_NAMESPACE_DIGEST,
            ca_trust=unbound,
        )

    trust = PrevalidatedElasticCATrust.from_path(
        ca_path,
        configured_reference=source.ca_bundle_ref,
    )
    with pytest.raises(ValueError, match="journal namespace"):
        prepare_elastic_runtime_identity(
            source,
            parent_secret_client=_secret_client(_credential_profile()),
            journal_pool=_UnusedPool(),
            journal_namespace_digest="bank-a",
            ca_trust=trust,
        )


def test_preparation_constructs_exact_postgres_journal_without_db_io(
    ca_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}
    original = PostgresElasticLeaseJournal.__init__

    def record(
        self: PostgresElasticLeaseJournal,
        pool: Any,
        *,
        journal_namespace_digest: str,
        statement_timeout_ms: int = 15_000,
        lock_timeout_ms: int = 5_000,
        owns_pool: bool = False,
    ) -> None:
        observed.update(
            {
                "pool": pool,
                "namespace": journal_namespace_digest,
                "statement": statement_timeout_ms,
                "lock": lock_timeout_ms,
                "owns_pool": owns_pool,
            }
        )
        original(
            self,
            pool,
            journal_namespace_digest=journal_namespace_digest,
            statement_timeout_ms=statement_timeout_ms,
            lock_timeout_ms=lock_timeout_ms,
            owns_pool=owns_pool,
        )

    monkeypatch.setattr(PostgresElasticLeaseJournal, "__init__", record)
    pool = _UnusedPool()
    source = _source()
    trust = PrevalidatedElasticCATrust.from_path(
        ca_path,
        configured_reference=source.ca_bundle_ref,
    )
    prepare_elastic_runtime_identity(
        source,
        parent_secret_client=_secret_client(_credential_profile()),
        journal_pool=pool,
        journal_namespace_digest=_NAMESPACE_DIGEST,
        ca_trust=trust,
        journal_statement_timeout_ms=9_000,
        journal_lock_timeout_ms=2_000,
    )

    assert observed == {
        "pool": pool,
        "namespace": _NAMESPACE_DIGEST,
        "statement": 9_000,
        "lock": 2_000,
        "owns_pool": False,
    }
