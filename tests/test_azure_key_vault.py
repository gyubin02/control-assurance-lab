from __future__ import annotations

import base64
import hashlib
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.x509.oid import NameOID

from assurance_lab.connectors.defender_pam import (
    CertificateAssertionCredential,
    PS256AssertionSigner,
)
from assurance_lab.control_plane.postgres_oidc_store import ProtectedCodeVerifier
from assurance_lab.evidence.canonical import canonical_json_bytes, strict_json_loads
from assurance_lab.key_management import azure_key_vault as akv

_TOKEN = b"eyJhbGciOiJSUzI1NiJ9.test-signature"
_VAULT = "assurance-prod"
_KEY = "control-assurance"
_VERSION = "a" * 32
_KEY_URI = f"https://{_VAULT}.vault.azure.net/keys/{_KEY}/{_VERSION}"
_TRANSACTION = f"sha256:{'b' * 64}"
_OTHER_TRANSACTION = f"sha256:{'c' * 64}"
_VERIFIER = "a" * 43


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))


class _TokenProvider:
    def __init__(self, *, valid: bool = True) -> None:
        self.valid = valid
        self.calls: list[tuple[str, float]] = []

    def get_token(
        self,
        *,
        scope: str,
        deadline: float,
    ) -> akv.AzureKeyVaultBearerToken:
        self.calls.append((scope, deadline))
        return akv.AzureKeyVaultBearerToken(
            _TOKEN,
            valid_until_monotonic=(
                time.monotonic() + 300 if self.valid else time.monotonic() - 1
            ),
        )


class _FakeTransport:
    def __init__(self, private_key: rsa.RSAPrivateKey) -> None:
        self.private_key = private_key
        self.calls: list[tuple[str, bytes]] = []
        self.status = 200
        self.headers: tuple[tuple[str, str], ...] = (
            ("content-type", "application/json"),
            ("content-encoding", "identity"),
        )
        self.kid = _KEY_URI
        self.fail: BaseException | None = None
        self.reflect_token = False
        self.result_override: bytes | None = None
        self._lock = threading.Lock()

    def post(
        self,
        *,
        target: str,
        body: bytes,
        token: akv.AzureKeyVaultBearerToken,
        deadline: float,
    ) -> akv._HTTPResponse:
        del token
        if time.monotonic() >= deadline:
            raise TimeoutError("deadline")
        with self._lock:
            self.calls.append((target, body))
        if self.fail is not None:
            raise self.fail
        if self.reflect_token:
            return akv._HTTPResponse(self.status, self.headers, _TOKEN)
        document = strict_json_loads(body)
        assert isinstance(document, dict)
        value = _decode(str(document["value"]))
        if target.endswith(f"/sign?api-version={akv.AZURE_KEY_VAULT_API_VERSION}"):
            assert document["alg"] == "PS256"
            result = self.private_key.sign(
                value,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                utils.Prehashed(hashes.SHA256()),
            )
        elif target.endswith(
            f"/wrapkey?api-version={akv.AZURE_KEY_VAULT_API_VERSION}"
        ):
            assert document["alg"] == "RSA-OAEP-256"
            result = self.private_key.public_key().encrypt(
                value,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        elif target.endswith(
            f"/unwrapkey?api-version={akv.AZURE_KEY_VAULT_API_VERSION}"
        ):
            assert document["alg"] == "RSA-OAEP-256"
            result = self.private_key.decrypt(
                value,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        else:
            raise AssertionError(f"unexpected Key Vault target: {target}")
        if self.result_override is not None:
            result = self.result_override
        response = canonical_json_bytes({"kid": self.kid, "value": _b64url(result)})
        return akv._HTTPResponse(self.status, self.headers, response)


def _certificate(
    private_key: rsa.RSAPrivateKey,
    *,
    common_name: str = "control-assurance-workload",
) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def _client(
    private_key: rsa.RSAPrivateKey,
    *,
    provider: _TokenProvider | None = None,
    transport: _FakeTransport | None = None,
) -> tuple[akv.AzureKeyVaultCryptoClient, _TokenProvider, _FakeTransport]:
    selected_provider = provider or _TokenProvider()
    selected_transport = transport or _FakeTransport(private_key)
    client = akv.AzureKeyVaultCryptoClient(
        selected_provider,
        vault_name=_VAULT,
        key_name=_KEY,
        key_version=_VERSION,
        _transport=selected_transport,
    )
    return client, selected_provider, selected_transport


def test_ps256_signer_pins_key_version_scope_and_verifies_locally() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client, provider, transport = _client(private_key)
    signer = akv.AzureKeyVaultPS256Signer(
        client,
        certificate_der=_certificate(private_key),
    )
    signing_input = b"header.payload"

    signature = signer.sign_ps256(
        signing_input,
        deadline=time.monotonic() + 30,
    )

    assert isinstance(signer, PS256AssertionSigner)
    assert signer.key_reference == _KEY_URI
    private_key.public_key().verify(
        signature,
        signing_input,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    assert provider.calls[0][0] == akv.AZURE_KEY_VAULT_SCOPE
    target, body = transport.calls[0]
    assert target == (
        f"/keys/{_KEY}/{_VERSION}/sign"
        f"?api-version={akv.AZURE_KEY_VAULT_API_VERSION}"
    )
    request = strict_json_loads(body)
    assert request == {
        "alg": "PS256",
        "value": _b64url(hashlib.sha256(signing_input).digest()),
    }
    assert _TOKEN not in body


def test_certificate_credential_accepts_the_real_key_vault_signer() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client, _provider, _transport = _client(private_key)
    certificate = _certificate(private_key)
    signer = akv.AzureKeyVaultPS256Signer(client, certificate_der=certificate)
    credential = CertificateAssertionCredential(
        certificate,
        signer,
        _jti=lambda: "12345678-1234-4234-8234-123456789abc",
    )

    issued = credential.issue(
        client_id="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        token_endpoint=(
            "https://login.microsoftonline.com/"
            "11111111-2222-4333-8444-555555555555/oauth2/v2.0/token"
        ),
        now_epoch_seconds=int(datetime.now(UTC).timestamp()),
        deadline=time.monotonic() + 30,
    )

    assert issued.mode == "certificate-ps256"
    assert issued.value.count(b".") == 2
    assert _TOKEN not in issued.value


def test_signer_rejects_a_signature_from_a_different_key() -> None:
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    registered_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client, _provider, _transport = _client(signing_key)
    signer = akv.AzureKeyVaultPS256Signer(
        client,
        certificate_der=_certificate(registered_key),
    )

    with pytest.raises(akv.AzureKeyVaultError, match="registered certificate"):
        signer.sign_ps256(b"header.payload", deadline=time.monotonic() + 30)


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        ("wrong-kid", "pinned key"),
        ("compression", "content encoding"),
        ("duplicate-type", "duplicate"),
        ("not-json", "application/json"),
        ("redirect", "rejected"),
    ],
)
def test_remote_response_contract_fails_closed(
    mutation: str,
    match: str,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client, _provider, transport = _client(private_key)
    if mutation == "wrong-kid":
        transport.kid = _KEY_URI + "-substituted"
    elif mutation == "compression":
        transport.headers = (
            ("content-type", "application/json"),
            ("content-encoding", "gzip"),
        )
    elif mutation == "duplicate-type":
        transport.headers = (
            ("content-type", "application/json"),
            ("content-type", "application/json"),
        )
    elif mutation == "not-json":
        transport.headers = (("content-type", "text/plain"),)
    else:
        transport.status = 307

    with pytest.raises(akv.AzureKeyVaultError, match=match):
        client.sign_ps256_digest(
            hashlib.sha256(b"value").digest(),
            deadline=time.monotonic() + 30,
        )
    assert len(transport.calls) == 1


def test_transport_failure_is_not_retried_or_reflected() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client, _provider, transport = _client(private_key)
    secret = "token=must-not-escape"
    transport.fail = RuntimeError(secret)

    with pytest.raises(akv.AzureKeyVaultError) as raised:
        client.sign_ps256_digest(
            hashlib.sha256(b"value").digest(),
            deadline=time.monotonic() + 30,
        )

    assert len(transport.calls) == 1
    assert secret not in str(raised.value)
    assert raised.value.__cause__ is None


def test_reflected_access_token_is_rejected_without_disclosure() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client, _provider, transport = _client(private_key)
    transport.reflect_token = True

    with pytest.raises(akv.AzureKeyVaultError, match="credential material") as raised:
        client.sign_ps256_digest(
            hashlib.sha256(b"value").digest(),
            deadline=time.monotonic() + 30,
        )

    assert _TOKEN.decode() not in str(raised.value)


def test_expired_token_never_reaches_the_transport() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    provider = _TokenProvider(valid=False)
    transport = _FakeTransport(private_key)
    client, _provider, _transport = _client(
        private_key,
        provider=provider,
        transport=transport,
    )

    with pytest.raises(akv.AzureKeyVaultError, match="currently valid"):
        client.sign_ps256_digest(
            hashlib.sha256(b"value").digest(),
            deadline=time.monotonic() + 30,
        )

    assert transport.calls == []


def test_pkce_envelope_round_trip_binds_transaction_and_hides_plaintext() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client, provider, transport = _client(private_key)
    random_values = iter((b"k" * 32, b"n" * 12))
    protector = akv.AzureKeyVaultEnvelopeProtector(
        client,
        _random=lambda size: next(random_values),
    )

    protected = protector.protect(
        code_verifier=_VERIFIER,
        transaction_digest=_TRANSACTION,
    )
    recovered = protector.unprotect(
        protected=protected,
        transaction_digest=_TRANSACTION,
    )

    assert recovered == _VERIFIER
    assert protected.key_reference == _KEY_URI
    assert protected.algorithm == "A256GCM+RSA-OAEP-256"
    assert _VERIFIER.encode() not in protected.ciphertext
    assert b"k" * 32 not in protected.ciphertext
    assert _TOKEN not in protected.ciphertext
    assert "<redacted>" in repr(protected)
    assert [call[0].split("/")[-1].split("?", 1)[0] for call in transport.calls] == [
        "wrapkey",
        "unwrapkey",
    ]
    assert all(scope == akv.AZURE_KEY_VAULT_SCOPE for scope, _ in provider.calls)


def test_transaction_substitution_fails_before_key_unwrap() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client, _provider, transport = _client(private_key)
    random_values = iter((b"k" * 32, b"n" * 12))
    protector = akv.AzureKeyVaultEnvelopeProtector(
        client,
        _random=lambda size: next(random_values),
    )
    protected = protector.protect(
        code_verifier=_VERIFIER,
        transaction_digest=_TRANSACTION,
    )

    with pytest.raises(akv.AzureKeyVaultError, match="binding"):
        protector.unprotect(
            protected=protected,
            transaction_digest=_OTHER_TRANSACTION,
        )

    assert len(transport.calls) == 1


def test_ciphertext_tamper_is_detected_after_exact_key_unwrap() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client, _provider, _transport = _client(private_key)
    random_values = iter((b"k" * 32, b"n" * 12))
    protector = akv.AzureKeyVaultEnvelopeProtector(
        client,
        _random=lambda size: next(random_values),
    )
    protected = protector.protect(
        code_verifier=_VERIFIER,
        transaction_digest=_TRANSACTION,
    )
    document = strict_json_loads(protected.ciphertext)
    assert isinstance(document, dict)
    encrypted = bytearray(_decode(str(document["ciphertext"])))
    encrypted[-1] ^= 1
    document["ciphertext"] = _b64url(bytes(encrypted))
    tampered = ProtectedCodeVerifier(
        ciphertext=canonical_json_bytes(document),
        key_reference=protected.key_reference,
        algorithm=protected.algorithm,
    )

    with pytest.raises(akv.AzureKeyVaultError, match="authentication failed"):
        protector.unprotect(
            protected=tampered,
            transaction_digest=_TRANSACTION,
        )


@pytest.mark.parametrize(
    ("key_reference", "algorithm"),
    [
        ("https://other.vault.azure.net/keys/key/" + ("d" * 32), "A256GCM+RSA-OAEP-256"),
        (_KEY_URI, "A256GCM+RSA-OAEP"),
    ],
)
def test_outer_key_and_algorithm_substitution_is_rejected_before_remote_call(
    key_reference: str,
    algorithm: str,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client, _provider, transport = _client(private_key)
    random_values = iter((b"k" * 32, b"n" * 12))
    protector = akv.AzureKeyVaultEnvelopeProtector(
        client,
        _random=lambda size: next(random_values),
    )
    protected = protector.protect(
        code_verifier=_VERIFIER,
        transaction_digest=_TRANSACTION,
    )
    substituted = ProtectedCodeVerifier(
        ciphertext=protected.ciphertext,
        key_reference=key_reference,
        algorithm=algorithm,
    )

    with pytest.raises(akv.AzureKeyVaultError, match="different key or algorithm"):
        protector.unprotect(
            protected=substituted,
            transaction_digest=_TRANSACTION,
        )

    assert len(transport.calls) == 1


def test_invalid_random_source_fails_before_remote_key_operation() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client, _provider, transport = _client(private_key)
    protector = akv.AzureKeyVaultEnvelopeProtector(
        client,
        _random=lambda size: b"x",
    )

    with pytest.raises(akv.AzureKeyVaultError, match="randomness"):
        protector.protect(
            code_verifier=_VERIFIER,
            transaction_digest=_TRANSACTION,
        )

    assert transport.calls == []


def test_concurrent_signing_uses_independent_exact_operations() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client, _provider, transport = _client(private_key)
    signer = akv.AzureKeyVaultPS256Signer(
        client,
        certificate_der=_certificate(private_key),
    )
    messages = tuple(f"message-{index}".encode() for index in range(16))

    with ThreadPoolExecutor(max_workers=8) as executor:
        signatures = tuple(
            executor.map(
                lambda message: signer.sign_ps256(
                    message,
                    deadline=time.monotonic() + 30,
                ),
                messages,
            )
        )

    assert len(signatures) == len(messages)
    assert len(transport.calls) == len(messages)
    for message, signature in zip(messages, signatures, strict=True):
        private_key.public_key().verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )


def test_configuration_rejects_unpinned_or_non_public_cloud_origins() -> None:
    provider = _TokenProvider()
    for vault, key, version in (
        ("A", _KEY, _VERSION),
        (_VAULT, "../key", _VERSION),
        (_VAULT, _KEY, "latest"),
    ):
        with pytest.raises(ValueError):
            akv.AzureKeyVaultCryptoClient(
                provider,
                vault_name=vault,
                key_name=key,
                key_version=version,
                _transport=_FakeTransport(
                    rsa.generate_private_key(public_exponent=65537, key_size=2048)
                ),
            )
