from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from assurance_lab.connectors.defender_credentials import (
    DEFENDER_AUTHORIZATION_PROFILE_CONTENT_TYPE,
    CertificatePS256CredentialPlan,
    DefenderCredentialProfileError,
    FederatedRS256CredentialPlan,
    decode_defender_credential_profile,
)
from assurance_lab.evidence.canonical import (
    canonical_json_bytes,
    strict_json_loads,
)

_NOT_BEFORE = datetime(2026, 1, 1, tzinfo=UTC)
_NOT_AFTER = datetime(2028, 1, 1, tzinfo=UTC)
_VERSION = "0123456789abcdef0123456789abcdef"
_KEY_URI = (
    "https://assurance-prod.vault.azure.net/keys/defender-signing/" + _VERSION
)


def _certificate(
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    *,
    not_before: datetime = _NOT_BEFORE,
    not_after: datetime = _NOT_AFTER,
    ca: bool = False,
    digital_signature: bool = True,
) -> bytes:
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Defender workload identity")]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(0x123456789ABC)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=digital_signature,
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
def rsa_material() -> tuple[rsa.RSAPrivateKey, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    return private_key, _certificate(private_key)


def _certificate_document(certificate: bytes, **changes: object) -> bytes:
    document: dict[str, object] = {
        "algorithm": "PS256",
        "certificate_der": base64.b64encode(certificate).decode("ascii"),
        "certificate_not_after": "2028-01-01T00:00:00Z",
        "certificate_not_before": "2026-01-01T00:00:00Z",
        "kind": "defender-credential-profile",
        "mode": "certificate-ps256",
        "schema_version": "1.0.0",
        "signing_key_uri": _KEY_URI,
    }
    document.update(changes)
    return canonical_json_bytes(document)


def _federated_document(**changes: object) -> bytes:
    document: dict[str, object] = {
        "algorithm": "RS256",
        "issuer": "https://oidc.prod-aks.azure.com/tenant/cluster/",
        "kind": "defender-credential-profile",
        "mode": "federated-rs256",
        "schema_version": "1.0.0",
        "source_reference": "kubernetes://prod-aks/assurance/defender",
        "subject": "system:serviceaccount:assurance:defender",
    }
    document.update(changes)
    return canonical_json_bytes(document)


def test_certificate_profile_yields_only_public_identity_anchors(
    rsa_material: tuple[rsa.RSAPrivateKey, bytes],
) -> None:
    private_key, certificate_der = rsa_material

    plan = decode_defender_credential_profile(
        _certificate_document(certificate_der)
    )

    assert type(plan) is CertificatePS256CredentialPlan
    assert plan.mode == "certificate-ps256"
    assert plan.key_reference == _KEY_URI
    assert plan.vault_name == "assurance-prod"
    assert plan.key_name == "defender-signing"
    assert plan.key_version == _VERSION
    assert plan.certificate_der == certificate_der
    assert plan.certificate_sha256 == (
        "sha256:" + hashlib.sha256(certificate_der).hexdigest()
    )
    spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert plan.certificate_spki_sha256 == (
        "sha256:" + hashlib.sha256(spki).hexdigest()
    )

    authorization = strict_json_loads(plan.authorization_profile_bytes)
    assert authorization == {
        "algorithm": "PS256",
        "certificate_not_after": "2028-01-01T00:00:00Z",
        "certificate_not_before": "2026-01-01T00:00:00Z",
        "certificate_sha256": plan.certificate_sha256,
        "certificate_spki_sha256": plan.certificate_spki_sha256,
        "certificate_thumbprint_s256": plan.certificate_thumbprint_s256,
        "content_type": DEFENDER_AUTHORIZATION_PROFILE_CONTENT_TYPE,
        "kind": "defender-authorization-profile",
        "mode": "certificate-ps256",
        "schema_version": "1.0.0",
        "signing_key_uri": _KEY_URI,
    }
    assert b"PRIVATE KEY" not in plan.authorization_profile_bytes
    assert base64.b64encode(certificate_der) not in plan.authorization_profile_bytes
    assert plan.authorization_profile_digest == (
        "sha256:" + hashlib.sha256(plan.authorization_profile_bytes).hexdigest()
    )


def test_certificate_authorization_profile_is_deterministic(
    rsa_material: tuple[rsa.RSAPrivateKey, bytes],
) -> None:
    _, certificate_der = rsa_material

    first = decode_defender_credential_profile(
        _certificate_document(certificate_der)
    )
    second = decode_defender_credential_profile(
        _certificate_document(certificate_der)
    )

    assert first.authorization_profile_bytes == second.authorization_profile_bytes
    assert first.authorization_profile_digest == second.authorization_profile_digest


def test_certificate_validity_is_checked_at_use_time_not_decode_time(
    rsa_material: tuple[rsa.RSAPrivateKey, bytes],
) -> None:
    _, certificate_der = rsa_material
    plan = decode_defender_credential_profile(
        _certificate_document(certificate_der)
    )
    assert isinstance(plan, CertificatePS256CredentialPlan)

    plan.assert_valid_at(_NOT_BEFORE)
    plan.assert_valid_at(_NOT_AFTER - timedelta(microseconds=1))
    with pytest.raises(DefenderCredentialProfileError, match="not valid"):
        plan.assert_valid_at(_NOT_BEFORE - timedelta(microseconds=1))
    with pytest.raises(DefenderCredentialProfileError, match="not valid"):
        plan.assert_valid_at(_NOT_AFTER)
    with pytest.raises(DefenderCredentialProfileError, match="timezone-aware"):
        plan.assert_valid_at(datetime(2027, 1, 1))


def test_remote_key_must_match_certificate_identity(
    rsa_material: tuple[rsa.RSAPrivateKey, bytes],
) -> None:
    private_key, certificate_der = rsa_material
    plan = decode_defender_credential_profile(
        _certificate_document(certificate_der)
    )
    assert isinstance(plan, CertificatePS256CredentialPlan)
    public_key = private_key.public_key()
    public_key_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    plan.assert_remote_public_key(public_key)
    plan.assert_remote_public_key_der(public_key_der)
    plan.assert_remote_public_key_fingerprint(plan.certificate_spki_sha256)

    other = rsa.generate_private_key(
        public_exponent=65_537, key_size=2_048
    ).public_key()
    with pytest.raises(DefenderCredentialProfileError, match="does not match"):
        plan.assert_remote_public_key(other)
    with pytest.raises(DefenderCredentialProfileError, match="does not match"):
        plan.assert_remote_public_key_fingerprint("sha256:" + ("0" * 64))
    with pytest.raises(DefenderCredentialProfileError, match="invalid"):
        plan.assert_remote_public_key_der(b"not-a-public-key")


@pytest.mark.parametrize(
    "key_uri",
    [
        "https://assurance-prod.vault.azure.net/keys/defender-signing",
        "https://assurance-prod.vault.azure.net/keys/defender-signing/latest",
        "https://assurance-prod.vault.azure.net/keys/defender-signing/"
        + ("A" * 32),
        "https://ASSURANCE-PROD.vault.azure.net/keys/defender-signing/" + _VERSION,
        "http://assurance-prod.vault.azure.net/keys/defender-signing/" + _VERSION,
        "https://assurance-prod.vault.azure.net:443/keys/defender-signing/"
        + _VERSION,
        "https://assurance-prod.vault.azure.net/keys/defender-signing/"
        + _VERSION
        + "?api-version=latest",
        "https://assurance-prod.vault.azure.net/secrets/defender-signing/"
        + _VERSION,
        "azure-keyvault://assurance-prod/keys/defender-signing/" + _VERSION,
        "https://user@assurance-prod.vault.azure.net/keys/defender-signing/"
        + _VERSION,
    ],
)
def test_certificate_key_reference_is_exact_and_version_pinned(
    rsa_material: tuple[rsa.RSAPrivateKey, bytes],
    key_uri: str,
) -> None:
    _, certificate_der = rsa_material

    with pytest.raises(DefenderCredentialProfileError, match="key URI"):
        decode_defender_credential_profile(
            _certificate_document(certificate_der, signing_key_uri=key_uri)
        )


def test_certificate_metadata_must_exactly_match_der(
    rsa_material: tuple[rsa.RSAPrivateKey, bytes],
) -> None:
    _, certificate_der = rsa_material

    with pytest.raises(DefenderCredentialProfileError, match="does not match"):
        decode_defender_credential_profile(
            _certificate_document(
                certificate_der,
                certificate_not_after="2029-01-01T00:00:00Z",
            )
        )


@pytest.mark.parametrize("key_size", [1_024])
def test_weak_rsa_certificates_are_rejected(key_size: int) -> None:
    private_key = rsa.generate_private_key(
        public_exponent=65_537, key_size=key_size
    )
    certificate_der = _certificate(private_key)

    with pytest.raises(DefenderCredentialProfileError, match="at least 2048"):
        decode_defender_credential_profile(
            _certificate_document(certificate_der)
        )


def test_non_rsa_ca_and_non_signing_certificates_are_rejected() -> None:
    ec_private_key = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(DefenderCredentialProfileError, match="RSA"):
        decode_defender_credential_profile(
            _certificate_document(_certificate(ec_private_key))
        )

    ca_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    with pytest.raises(DefenderCredentialProfileError, match="end-entity"):
        decode_defender_credential_profile(
            _certificate_document(_certificate(ca_key, ca=True))
        )

    non_signing_key = rsa.generate_private_key(
        public_exponent=65_537, key_size=2_048
    )
    with pytest.raises(DefenderCredentialProfileError, match="digital signatures"):
        decode_defender_credential_profile(
            _certificate_document(
                _certificate(non_signing_key, digital_signature=False)
            )
        )


def test_pem_private_key_and_noncanonical_base64_are_rejected(
    rsa_material: tuple[rsa.RSAPrivateKey, bytes],
) -> None:
    private_key, certificate_der = rsa_material
    private_der = private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    for forbidden in (private_der, private_pem):
        with pytest.raises(DefenderCredentialProfileError, match=r"X[.]509"):
            decode_defender_credential_profile(
                _certificate_document(forbidden)
            )

    encoded = base64.b64encode(certificate_der).decode("ascii")
    with pytest.raises(DefenderCredentialProfileError, match="canonical base64"):
        decode_defender_credential_profile(
            _certificate_document(certificate_der, certificate_der=encoded + "\n")
        )


def test_federated_profile_contains_identity_but_never_an_assertion() -> None:
    plan = decode_defender_credential_profile(_federated_document())

    assert type(plan) is FederatedRS256CredentialPlan
    assert plan.mode == "federated-rs256"
    assert plan.issuer == "https://oidc.prod-aks.azure.com/tenant/cluster/"
    assert plan.subject == "system:serviceaccount:assurance:defender"
    assert plan.source_reference == "kubernetes://prod-aks/assurance/defender"
    assert plan.cluster == "prod-aks"
    assert plan.namespace == "assurance"
    assert plan.service_account == "defender"
    authorization = strict_json_loads(plan.authorization_profile_bytes)
    assert authorization == {
        "algorithm": "RS256",
        "content_type": DEFENDER_AUTHORIZATION_PROFILE_CONTENT_TYPE,
        "issuer": plan.issuer,
        "kind": "defender-authorization-profile",
        "mode": "federated-rs256",
        "schema_version": "1.0.0",
        "source_reference": plan.source_reference,
        "subject": plan.subject,
    }
    assert b"token" not in plan.authorization_profile_bytes.lower()
    assert b"assertion" not in plan.authorization_profile_bytes.lower()
    assert plan.authorization_profile_digest == (
        "sha256:" + hashlib.sha256(plan.authorization_profile_bytes).hexdigest()
    )


@pytest.mark.parametrize(
    "issuer",
    [
        "http://oidc.prod-aks.azure.com/tenant/cluster/",
        "https://user@oidc.prod-aks.azure.com/tenant/cluster/",
        "https://oidc.prod-aks.azure.com:443/tenant/cluster/",
        "https://OIDC.prod-aks.azure.com/tenant/cluster/",
        "https://127.0.0.1/tenant/cluster/",
        "https://oidc.prod-aks.azure.com/tenant/../cluster/",
        "https://oidc.prod-aks.azure.com/tenant//cluster/",
        "https://oidc.prod-aks.azure.com/tenant/cluster/?version=1",
        "https://oidc.prod-aks.azure.com/%74enant/cluster/",
    ],
)
def test_federated_issuer_is_one_canonical_https_identity(issuer: str) -> None:
    with pytest.raises(DefenderCredentialProfileError, match="issuer URL"):
        decode_defender_credential_profile(_federated_document(issuer=issuer))


@pytest.mark.parametrize(
    ("source_reference", "subject"),
    [
        (
            "kubernetes://prod-aks/assurance/other",
            "system:serviceaccount:assurance:defender",
        ),
        (
            "kubernetes://prod-aks/assurance/defender?token=latest",
            "system:serviceaccount:assurance:defender",
        ),
        (
            "kubernetes://PROD-AKS/assurance/defender",
            "system:serviceaccount:assurance:defender",
        ),
        (
            "file:///var/run/secrets/token",
            "system:serviceaccount:assurance:defender",
        ),
        (
            "kubernetes://prod-aks/assurance",
            "system:serviceaccount:assurance:defender",
        ),
        (
            "kubernetes://prod-aks/assurance/defender",
            "system:serviceaccount:other:defender",
        ),
    ],
)
def test_federated_source_and_subject_are_bound(
    source_reference: str,
    subject: str,
) -> None:
    with pytest.raises(DefenderCredentialProfileError):
        decode_defender_credential_profile(
            _federated_document(
                source_reference=source_reference,
                subject=subject,
            )
        )


@pytest.mark.parametrize(
    "document",
    [
        b"",
        b'{ "kind":"defender-credential-profile"}',
        canonical_json_bytes(
            {
                "algorithm": "RS256",
                "client_secret": "DO-NOT-REFLECT-THIS-SECRET",
                "issuer": "https://oidc.prod-aks.azure.com/tenant/cluster/",
                "kind": "defender-credential-profile",
                "mode": "federated-rs256",
                "schema_version": "1.0.0",
                "source_reference": "kubernetes://prod-aks/assurance/defender",
                "subject": "system:serviceaccount:assurance:defender",
            }
        ),
        canonical_json_bytes(
            {
                "algorithm": "RS256",
                "assertion": "DO-NOT-REFLECT-THIS-ASSERTION",
                "issuer": "https://oidc.prod-aks.azure.com/tenant/cluster/",
                "kind": "defender-credential-profile",
                "mode": "federated-rs256",
                "schema_version": "1.0.0",
                "source_reference": "kubernetes://prod-aks/assurance/defender",
                "subject": "system:serviceaccount:assurance:defender",
            }
        ),
        _federated_document(algorithm="PS256"),
        _federated_document(schema_version="2.0.0"),
        _federated_document(mode="unknown"),
    ],
)
def test_ambiguous_extra_or_secret_fields_fail_closed(document: bytes) -> None:
    with pytest.raises(DefenderCredentialProfileError) as raised:
        decode_defender_credential_profile(document)

    rendered = str(raised.value)
    assert "DO-NOT-REFLECT-THIS-SECRET" not in rendered
    assert "DO-NOT-REFLECT-THIS-ASSERTION" not in rendered


def test_duplicate_members_oversize_and_wrong_input_type_are_rejected() -> None:
    duplicate = (
        b'{"algorithm":"RS256","issuer":"https://issuer.example/",'
        b'"kind":"defender-credential-profile","mode":"federated-rs256",'
        b'"mode":"certificate-ps256","schema_version":"1.0.0",'
        b'"source_reference":"kubernetes://prod-aks/assurance/defender",'
        b'"subject":"system:serviceaccount:assurance:defender"}'
    )
    with pytest.raises(DefenderCredentialProfileError, match="strict bounded JSON"):
        decode_defender_credential_profile(duplicate)
    with pytest.raises(DefenderCredentialProfileError, match="exceeds"):
        decode_defender_credential_profile(b"x" * (128 * 1024 + 1))
    with pytest.raises(DefenderCredentialProfileError, match="absent"):
        decode_defender_credential_profile(Any)  # type: ignore[arg-type]


def test_repr_and_errors_do_not_reflect_profile_values(
    rsa_material: tuple[rsa.RSAPrivateKey, bytes],
) -> None:
    _, certificate_der = rsa_material
    certificate_plan = decode_defender_credential_profile(
        _certificate_document(certificate_der)
    )
    federated_plan = decode_defender_credential_profile(_federated_document())

    assert _KEY_URI not in repr(certificate_plan)
    assert "oidc.prod-aks.azure.com" not in repr(federated_plan)
    assert "system:serviceaccount" not in repr(federated_plan)

    marker = "DO-NOT-REFLECT-URL-SECRET"
    with pytest.raises(DefenderCredentialProfileError) as raised:
        decode_defender_credential_profile(
            _federated_document(
                issuer=f"https://{marker}@oidc.prod-aks.azure.com/"
            )
        )
    assert marker not in str(raised.value)
