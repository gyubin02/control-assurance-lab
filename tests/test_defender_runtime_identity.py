from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from assurance_lab.connectors.defender_credentials import (
    DEFENDER_CREDENTIAL_PROFILE_CONTENT_TYPE,
    decode_defender_credential_profile,
)
from assurance_lab.connectors.defender_pam import (
    FEDERATED_ASSERTION_AUDIENCE,
    FederatedClientAssertion,
    SQLiteDefenderTokenJournal,
)
from assurance_lab.control_plane.models import DefenderSourceConfiguration
from assurance_lab.evidence.canonical import (
    canonical_json_bytes,
    strict_json_loads,
)
from assurance_lab.key_management.azure_key_vault import (
    AzureKeyVaultBearerToken,
)
from assurance_lab.key_management.azure_secret import (
    AzureKeyVaultSecretReference,
    AzureKeyVaultSecretValue,
)
from assurance_lab.runtime.defender_identity import (
    DEFENDER_RUNTIME_IDENTITY_MEDIA_TYPE,
    DefenderRuntimeIdentityError,
    PreparedDefenderRuntimeIdentity,
    prepare_defender_runtime_identity,
)

_NOW = datetime(2027, 1, 1, tzinfo=UTC)
_SECRET_VERSION = "a" * 32
_KEY_VERSION = "b" * 32
_SECRET_REF = (
    "azure-keyvault://runtime-secrets/secrets/defender-credential/"
    + _SECRET_VERSION
)
_KEY_URI = (
    "https://runtime-signing.vault.azure.net/keys/defender-client/"
    + _KEY_VERSION
)
_TENANT_ID = "11111111-2222-4333-8444-555555555555"
_CLIENT_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


def _certificate(private_key: rsa.RSAPrivateKey) -> bytes:
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Defender runtime")]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(42)
        .not_valid_before(datetime(2026, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2028, 1, 1, tzinfo=UTC))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


@pytest.fixture(scope="module")
def certificate_der() -> bytes:
    private_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    return _certificate(private_key)


def _certificate_profile(certificate: bytes, **changes: object) -> bytes:
    profile: dict[str, object] = {
        "algorithm": "PS256",
        "certificate_der": base64.b64encode(certificate).decode("ascii"),
        "certificate_not_after": "2028-01-01T00:00:00Z",
        "certificate_not_before": "2026-01-01T00:00:00Z",
        "kind": "defender-credential-profile",
        "mode": "certificate-ps256",
        "schema_version": "1.0.0",
        "signing_key_uri": _KEY_URI,
    }
    profile.update(changes)
    return canonical_json_bytes(profile)


def _federated_profile(**changes: object) -> bytes:
    profile: dict[str, object] = {
        "algorithm": "RS256",
        "issuer": "https://oidc.prod-aks.azure.com/tenant/cluster/",
        "kind": "defender-credential-profile",
        "mode": "federated-rs256",
        "schema_version": "1.0.0",
        "source_reference": "kubernetes://prod-aks/assurance/defender",
        "subject": "system:serviceaccount:assurance:defender",
    }
    profile.update(changes)
    return canonical_json_bytes(profile)


def _configuration(
    *,
    cloud: str = "global",
    credential_ref: str = _SECRET_REF,
) -> DefenderSourceConfiguration:
    return DefenderSourceConfiguration.model_validate(
        {
            "client_credential_ref": credential_ref,
            "client_id": _CLIENT_ID,
            "cloud": cloud,
            "kind": "defender-xdr",
            "permission": "ThreatHunting.Read.All",
            "table": "AlertInfo",
            "tenant_id": _TENANT_ID,
        }
    )


def _secret_value(
    value: bytes,
    *,
    reference: AzureKeyVaultSecretReference | None = None,
    content_type: str | None = DEFENDER_CREDENTIAL_PROFILE_CONTENT_TYPE,
) -> AzureKeyVaultSecretValue:
    return AzureKeyVaultSecretValue(
        value,
        reference=reference or AzureKeyVaultSecretReference.parse(_SECRET_REF),
        content_type=content_type,
        retrieved_at=_NOW,
    )


@dataclass
class _SecretClient:
    value: AzureKeyVaultSecretValue
    reference_digest: str
    fail_marker: str | None = None

    def get(self) -> AzureKeyVaultSecretValue:
        if self.fail_marker is not None:
            raise RuntimeError(self.fail_marker)
        return self.value


class _KeyVaultTokenProvider:
    calls = 0

    def get_token(
        self,
        *,
        scope: str,
        deadline: float,
    ) -> AzureKeyVaultBearerToken:
        del scope
        self.calls += 1
        return AzureKeyVaultBearerToken(
            b"test-key-vault-token",
            valid_until_monotonic=max(deadline, time.monotonic() + 60),
        )


@dataclass
class _FederatedSource:
    source_reference: str = "kubernetes://prod-aks/assurance/defender"
    calls: int = 0

    def get_assertion(
        self,
        *,
        audience: str,
        deadline: float,
    ) -> FederatedClientAssertion:
        del deadline
        assert audience == FEDERATED_ASSERTION_AUDIENCE
        self.calls += 1
        return FederatedClientAssertion(b"e30.e30.c2lnbmF0dXJl")


def _client(value: AzureKeyVaultSecretValue) -> _SecretClient:
    reference = AzureKeyVaultSecretReference.parse(_SECRET_REF)
    return _SecretClient(
        value=value,
        reference_digest=reference.reference_digest,
    )


def _journal(tmp_path: Path, name: str) -> SQLiteDefenderTokenJournal:
    return SQLiteDefenderTokenJournal(tmp_path / name)


def test_certificate_profile_constructs_exact_key_vault_broker_and_identity(
    tmp_path: Path,
    certificate_der: bytes,
) -> None:
    profile_bytes = _certificate_profile(certificate_der)
    decoded = decode_defender_credential_profile(profile_bytes)
    token_provider = _KeyVaultTokenProvider()

    prepared = prepare_defender_runtime_identity(
        _configuration(),
        credential_secret_client=_client(_secret_value(profile_bytes)),
        journal=_journal(tmp_path, "certificate.sqlite3"),
        key_vault_token_provider=token_provider,
        wall_clock=lambda: _NOW,
    )

    assert type(prepared) is PreparedDefenderRuntimeIdentity
    assert prepared.credential_mode == "certificate-ps256"
    assert token_provider.calls == 0
    assert prepared.broker.credential_reference_digest == (
        "sha256:" + hashlib.sha256(_KEY_URI.encode()).hexdigest()
    )
    assert (
        prepared.credential_reference_digest
        == prepared.broker.credential_reference_digest
    )
    assert (
        prepared.credential_authorization_profile_bytes
        == decoded.authorization_profile_bytes
    )
    assert (
        prepared.credential_authorization_profile_digest
        == decoded.authorization_profile_digest
    )
    runtime = strict_json_loads(prepared.runtime_identity_bytes)
    assert runtime["media_type"] == DEFENDER_RUNTIME_IDENTITY_MEDIA_TYPE
    assert runtime["tenant_id"] == _TENANT_ID
    assert runtime["client_id"] == _CLIENT_ID
    assert runtime["cloud"] == "global"
    assert runtime["permission"] == "ThreatHunting.Read.All"
    assert runtime["table"] == "AlertInfo"
    assert (
        runtime["credential_authorization_profile"]
        == strict_json_loads(decoded.authorization_profile_bytes)
    )
    assert (
        runtime["credential_authorization_profile_digest"]
        == decoded.authorization_profile_digest
    )
    assert runtime["token_endpoint_digest"] == prepared.token_endpoint_digest
    assert runtime["graph_origin_digest"] == prepared.graph_origin_digest
    assert runtime["scope_digest"] == prepared.scope_digest
    assert (
        runtime["credential_reference_digest"]
        == prepared.credential_reference_digest
    )
    assert base64.b64encode(certificate_der) not in prepared.runtime_identity_bytes
    assert prepared.runtime_identity_digest == (
        "sha256:" + hashlib.sha256(prepared.runtime_identity_bytes).hexdigest()
    )


def test_federated_profile_constructs_exact_source_without_reading_token(
    tmp_path: Path,
) -> None:
    source = _FederatedSource()
    profile_bytes = _federated_profile()

    prepared = prepare_defender_runtime_identity(
        _configuration(),
        credential_secret_client=_client(_secret_value(profile_bytes)),
        journal=_journal(tmp_path, "federated.sqlite3"),
        federated_assertion_source=source,
        wall_clock=lambda: _NOW,
    )

    assert prepared.credential_mode == "federated-rs256"
    assert source.calls == 0
    assert prepared.broker.credential_reference_digest == (
        "sha256:"
        + hashlib.sha256(source.source_reference.encode("utf-8")).hexdigest()
    )
    runtime = strict_json_loads(prepared.runtime_identity_bytes)
    public_profile = runtime["credential_authorization_profile"]
    assert public_profile["issuer"] == (
        "https://oidc.prod-aks.azure.com/tenant/cluster/"
    )
    assert public_profile["subject"] == (
        "system:serviceaccount:assurance:defender"
    )
    rendered = prepared.runtime_identity_bytes.decode()
    assert "e30.e30.c2lnbmF0dXJl" not in rendered
    assert "client_secret" not in rendered
    assert "refresh_token" not in rendered


def test_runtime_identity_is_deterministic_for_same_public_inputs(
    tmp_path: Path,
) -> None:
    profile_bytes = _federated_profile()
    first = prepare_defender_runtime_identity(
        _configuration(),
        credential_secret_client=_client(_secret_value(profile_bytes)),
        journal=_journal(tmp_path, "first.sqlite3"),
        federated_assertion_source=_FederatedSource(),
        wall_clock=lambda: _NOW,
    )
    second = prepare_defender_runtime_identity(
        _configuration(),
        credential_secret_client=_client(_secret_value(profile_bytes)),
        journal=_journal(tmp_path, "second.sqlite3"),
        federated_assertion_source=_FederatedSource(),
        wall_clock=lambda: _NOW,
    )

    assert first.runtime_identity_bytes == second.runtime_identity_bytes
    assert first.runtime_identity_digest == second.runtime_identity_digest


def test_cloud_and_endpoints_are_bound_into_public_identity(tmp_path: Path) -> None:
    profile_bytes = _federated_profile()
    global_identity = prepare_defender_runtime_identity(
        _configuration(cloud="global"),
        credential_secret_client=_client(_secret_value(profile_bytes)),
        journal=_journal(tmp_path, "global.sqlite3"),
        federated_assertion_source=_FederatedSource(),
        wall_clock=lambda: _NOW,
    )
    government_identity = prepare_defender_runtime_identity(
        _configuration(cloud="us-government-l4"),
        credential_secret_client=_client(_secret_value(profile_bytes)),
        journal=_journal(tmp_path, "government.sqlite3"),
        federated_assertion_source=_FederatedSource(),
        wall_clock=lambda: _NOW,
    )

    assert global_identity.runtime_identity_digest != (
        government_identity.runtime_identity_digest
    )
    assert global_identity.graph_origin_digest != (
        government_identity.graph_origin_digest
    )
    assert global_identity.scope_digest != government_identity.scope_digest
    assert global_identity.token_endpoint_digest != (
        government_identity.token_endpoint_digest
    )


def test_runtime_identity_can_be_compared_to_approved_exact_bytes(
    tmp_path: Path,
) -> None:
    profile_bytes = _federated_profile()
    prepared = prepare_defender_runtime_identity(
        _configuration(),
        credential_secret_client=_client(_secret_value(profile_bytes)),
        journal=_journal(tmp_path, "binding.sqlite3"),
        federated_assertion_source=_FederatedSource(),
        wall_clock=lambda: _NOW,
    )

    prepared.assert_runtime_identity(
        expected_bytes=prepared.runtime_identity_bytes,
        expected_digest=prepared.runtime_identity_digest,
    )
    tampered = prepared.runtime_identity_bytes.replace(b'"global"', b'"globalx"')
    tampered_digest = "sha256:" + hashlib.sha256(tampered).hexdigest()
    with pytest.raises(DefenderRuntimeIdentityError, match="differs"):
        prepared.assert_runtime_identity(
            expected_bytes=tampered,
            expected_digest=tampered_digest,
        )
    with pytest.raises(DefenderRuntimeIdentityError, match="invalid"):
        prepared.assert_runtime_identity(
            expected_bytes=tampered,
            expected_digest="sha256:" + ("0" * 64),
        )


def test_secret_client_and_returned_value_must_match_configuration(
    tmp_path: Path,
) -> None:
    profile_bytes = _federated_profile()
    reference = AzureKeyVaultSecretReference.parse(_SECRET_REF)
    wrong_reference = AzureKeyVaultSecretReference.parse(
        "azure-keyvault://other-secrets/secrets/defender-credential/"
        + ("c" * 32)
    )

    wrong_client = _SecretClient(
        value=_secret_value(profile_bytes),
        reference_digest=wrong_reference.reference_digest,
    )
    with pytest.raises(DefenderRuntimeIdentityError, match="differs"):
        prepare_defender_runtime_identity(
            _configuration(),
            credential_secret_client=wrong_client,
            journal=_journal(tmp_path, "wrong-client.sqlite3"),
            federated_assertion_source=_FederatedSource(),
        )

    wrong_value_client = _SecretClient(
        value=_secret_value(profile_bytes, reference=wrong_reference),
        reference_digest=reference.reference_digest,
    )
    with pytest.raises(DefenderRuntimeIdentityError, match="exact-version"):
        prepare_defender_runtime_identity(
            _configuration(),
            credential_secret_client=wrong_value_client,
            journal=_journal(tmp_path, "wrong-value.sqlite3"),
            federated_assertion_source=_FederatedSource(),
        )


def test_only_exact_azure_secret_references_are_supported(tmp_path: Path) -> None:
    profile_bytes = _federated_profile()
    configuration = _configuration(
        credential_ref="vault://secret/defender-credential/version"
    )

    with pytest.raises(DefenderRuntimeIdentityError, match="exact Azure"):
        prepare_defender_runtime_identity(
            configuration,
            credential_secret_client=_client(_secret_value(profile_bytes)),
            journal=_journal(tmp_path, "wrong-scheme.sqlite3"),
            federated_assertion_source=_FederatedSource(),
        )


def test_secret_decode_and_transport_failures_are_sanitized(
    tmp_path: Path,
) -> None:
    marker = "DO-NOT-REFLECT-RUNTIME-SECRET"
    reference = AzureKeyVaultSecretReference.parse(_SECRET_REF)
    failing = _SecretClient(
        value=_secret_value(_federated_profile()),
        reference_digest=reference.reference_digest,
        fail_marker=marker,
    )
    with pytest.raises(DefenderRuntimeIdentityError) as transport_error:
        prepare_defender_runtime_identity(
            _configuration(),
            credential_secret_client=failing,
            journal=_journal(tmp_path, "failure.sqlite3"),
            federated_assertion_source=_FederatedSource(),
        )
    assert marker not in str(transport_error.value)

    secret_profile = canonical_json_bytes(
        {
            "algorithm": "RS256",
            "client_secret": marker,
            "issuer": "https://oidc.prod-aks.azure.com/tenant/cluster/",
            "kind": "defender-credential-profile",
            "mode": "federated-rs256",
            "schema_version": "1.0.0",
            "source_reference": "kubernetes://prod-aks/assurance/defender",
            "subject": "system:serviceaccount:assurance:defender",
        }
    )
    with pytest.raises(DefenderRuntimeIdentityError) as decode_error:
        prepare_defender_runtime_identity(
            _configuration(),
            credential_secret_client=_client(_secret_value(secret_profile)),
            journal=_journal(tmp_path, "decode.sqlite3"),
            federated_assertion_source=_FederatedSource(),
        )
    assert marker not in str(decode_error.value)

    with pytest.raises(DefenderRuntimeIdentityError, match="decoded safely"):
        prepare_defender_runtime_identity(
            _configuration(),
            credential_secret_client=_client(
                _secret_value(
                    _federated_profile(),
                    content_type="application/octet-stream",
                )
            ),
            journal=_journal(tmp_path, "content-type.sqlite3"),
            federated_assertion_source=_FederatedSource(),
        )


def test_mode_specific_dependencies_fail_closed(
    tmp_path: Path,
    certificate_der: bytes,
) -> None:
    certificate_profile = _certificate_profile(certificate_der)
    with pytest.raises(DefenderRuntimeIdentityError, match="token provider"):
        prepare_defender_runtime_identity(
            _configuration(),
            credential_secret_client=_client(_secret_value(certificate_profile)),
            journal=_journal(tmp_path, "no-signer.sqlite3"),
            wall_clock=lambda: _NOW,
        )
    with pytest.raises(DefenderRuntimeIdentityError, match="cannot use"):
        prepare_defender_runtime_identity(
            _configuration(),
            credential_secret_client=_client(_secret_value(certificate_profile)),
            journal=_journal(tmp_path, "both-certificate.sqlite3"),
            key_vault_token_provider=_KeyVaultTokenProvider(),
            federated_assertion_source=_FederatedSource(),
            wall_clock=lambda: _NOW,
        )

    federated_profile = _federated_profile()
    with pytest.raises(DefenderRuntimeIdentityError, match="assertion source"):
        prepare_defender_runtime_identity(
            _configuration(),
            credential_secret_client=_client(_secret_value(federated_profile)),
            journal=_journal(tmp_path, "no-source.sqlite3"),
        )
    with pytest.raises(DefenderRuntimeIdentityError, match="cannot use"):
        prepare_defender_runtime_identity(
            _configuration(),
            credential_secret_client=_client(_secret_value(federated_profile)),
            journal=_journal(tmp_path, "both-federated.sqlite3"),
            key_vault_token_provider=_KeyVaultTokenProvider(),
            federated_assertion_source=_FederatedSource(),
        )


def test_federated_source_reference_and_certificate_clock_are_enforced(
    tmp_path: Path,
    certificate_der: bytes,
) -> None:
    with pytest.raises(DefenderRuntimeIdentityError, match="differs"):
        prepare_defender_runtime_identity(
            _configuration(),
            credential_secret_client=_client(
                _secret_value(_federated_profile())
            ),
            journal=_journal(tmp_path, "wrong-source.sqlite3"),
            federated_assertion_source=_FederatedSource(
                source_reference="kubernetes://prod-aks/assurance/other"
            ),
        )

    with pytest.raises(DefenderRuntimeIdentityError, match="composed safely"):
        prepare_defender_runtime_identity(
            _configuration(),
            credential_secret_client=_client(
                _secret_value(_certificate_profile(certificate_der))
            ),
            journal=_journal(tmp_path, "expired.sqlite3"),
            key_vault_token_provider=_KeyVaultTokenProvider(),
            wall_clock=lambda: datetime(2028, 1, 1, tzinfo=UTC),
        )


def test_prepared_repr_contains_only_public_digests(tmp_path: Path) -> None:
    prepared = prepare_defender_runtime_identity(
        _configuration(),
        credential_secret_client=_client(
            _secret_value(_federated_profile())
        ),
        journal=_journal(tmp_path, "repr.sqlite3"),
        federated_assertion_source=_FederatedSource(),
    )

    rendered = repr(prepared)
    assert _TENANT_ID not in rendered
    assert _CLIENT_ID not in rendered
    assert _SECRET_REF not in rendered
    assert "oidc.prod-aks.azure.com" not in rendered
    assert "system:serviceaccount" not in rendered
