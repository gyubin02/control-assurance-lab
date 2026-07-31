from __future__ import annotations

import base64
import hashlib
import sqlite3
import urllib.parse
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from assurance_lab.connectors.contract import (
    ConnectorCapture,
    ConnectorCaptureError,
    ConnectorDescriptor,
    ConnectorWindow,
)
from assurance_lab.connectors.defender_pam import (
    CLIENT_ASSERTION_TYPE,
    FEDERATED_ASSERTION_AUDIENCE,
    CertificateAssertionCredential,
    DefenderPamAmbiguousRequest,
    DefenderPamError,
    DefenderWorkloadIdentityBroker,
    FederatedAssertionCredential,
    FederatedClientAssertion,
    SQLiteDefenderTokenJournal,
    _NoRedirect,
    _TokenHTTPResponse,
    _UrllibTokenTransport,
    defender_entra_cloud,
    verify_defender_pam_receipt,
)
from assurance_lab.connectors.defender_xdr import (
    DefenderBearerTokenProvider,
    DefenderXDRRequest,
)
from assurance_lab.evidence.canonical import (
    canonical_json_bytes,
    strict_json_loads,
)

_NOW_MS = 1_785_300_000_000
_NOW_SECONDS = _NOW_MS // 1_000
_TENANT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
_CLIENT = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
_ACQUISITION_ID = "ab" * 32
_JTI = "33333333-3333-4333-8333-333333333333"
_TOKEN = "eyJhbGciOiJSUzI1NiJ9.test-access-token.signature"


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


@dataclass
class _Signer:
    private_key: rsa.RSAPrivateKey
    key_reference: str = "vault://pki/defender-xdr/signing-key-v3"
    fail: bool = False
    corrupt: bool = False
    calls: int = 0

    def sign_ps256(self, signing_input: bytes, *, deadline: float) -> bytes:
        del deadline
        self.calls += 1
        if self.fail:
            raise RuntimeError("secret backend said token=do-not-leak")
        signature = self.private_key.sign(
            signing_input,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        return bytes([signature[0] ^ 1]) + signature[1:] if self.corrupt else signature


@pytest.fixture(scope="module")
def certificate_material() -> tuple[bytes, _Signer]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Defender workload test")]
    )
    now = datetime.fromtimestamp(_NOW_SECONDS, tz=UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(42)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(private_key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.DER),
        _Signer(private_key),
    )


def _certificate_credential(
    certificate_material: tuple[bytes, _Signer],
    *,
    signer: _Signer | None = None,
) -> CertificateAssertionCredential:
    certificate, default_signer = certificate_material
    return CertificateAssertionCredential(
        certificate,
        signer or default_signer,
        _jti=lambda: _JTI,
    )


def _federated_jwt(
    *,
    issuer: str = "https://issuer.example/workloads",
    subject: str = "system:serviceaccount:assurance:defender",
    audience: str = FEDERATED_ASSERTION_AUDIENCE,
    issued: int = _NOW_SECONDS,
    expires: int = _NOW_SECONDS + 300,
    alg: str = "RS256",
    extra_claim: bool = False,
) -> bytes:
    header = {"alg": alg, "kid": "workload-key-1", "typ": "JWT"}
    claims: dict[str, Any] = {
        "aud": audience,
        "exp": expires,
        "iat": issued,
        "iss": issuer,
        "jti": "federated-jti-0001",
        "nbf": issued,
        "sub": subject,
    }
    if extra_claim:
        claims["debug"] = True
    return (
        f"{_b64url(canonical_json_bytes(header))}."
        f"{_b64url(canonical_json_bytes(claims))}."
        f"{_b64url(b'test-signature')}"
    ).encode()


@dataclass
class _FederatedSource:
    value: bytes
    source_reference: str = "kubernetes://prod/assurance/defender"
    seen_audience: str | None = None
    fail: bool = False

    def get_assertion(
        self,
        *,
        audience: str,
        deadline: float,
    ) -> FederatedClientAssertion:
        del deadline
        self.seen_audience = audience
        if self.fail:
            raise RuntimeError(f"source leaked assertion {self.value.decode()}")
        return FederatedClientAssertion(self.value)


def _federated_credential(source: _FederatedSource) -> FederatedAssertionCredential:
    return FederatedAssertionCredential(
        source,
        expected_issuer="https://issuer.example/workloads",
        expected_subject="system:serviceaccount:assurance:defender",
    )


@dataclass(frozen=True)
class _Call:
    target: str
    body: bytes
    headers: tuple[tuple[str, str], ...]


class _Transport:
    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.calls: list[_Call] = []

    def request(
        self,
        *,
        target: str,
        body: bytes,
        headers: tuple[tuple[str, str], ...],
        deadline: float,
    ) -> _TokenHTTPResponse:
        del deadline
        self.calls.append(_Call(target, body, headers))
        if not self.responses:
            raise AssertionError("unexpected token request")
        result = self.responses.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result  # type: ignore[return-value]


def _token_response(
    *,
    status: int = 200,
    token: str = _TOKEN,
    expires_in: int = 3_599,
    extra: dict[str, Any] | None = None,
    headers: tuple[tuple[str, str], ...] = (
        ("content-type", "application/json; charset=utf-8"),
        ("request-id", "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
    ),
) -> _TokenHTTPResponse:
    body: dict[str, Any] = {
        "access_token": token,
        "expires_in": expires_in,
        "token_type": "Bearer",
    }
    if extra:
        body.update(extra)
    return _TokenHTTPResponse(
        status=status,
        headers=headers,
        body=canonical_json_bytes(body),
    )


def _request() -> DefenderXDRRequest:
    return DefenderXDRRequest(
        capture_id="defender-pam-test",
        capture_nonce="cd" * 32,
        window=ConnectorWindow(
            start=datetime(2026, 7, 29, 0, 0, tzinfo=UTC),
            end=datetime(2026, 7, 29, 0, 5, tzinfo=UTC),
        ),
        max_hits=100,
    )


def _capture() -> ConnectorCapture:
    receipt = canonical_json_bytes({"capture": "defender"})
    records = canonical_json_bytes({"alert": "one", "id": "alert-1"}) + b"\n"
    return ConnectorCapture(
        descriptor=ConnectorDescriptor(
            connector_id="microsoft-defender-xdr-readonly",
            connector_version="test",
            capture_media_type="application/test+json",
        ),
        receipt_bytes=receipt,
        receipt_digest=_digest(receipt),
        records_jsonl=records,
        records_digest=_digest(records),
        record_count=1,
    )


class _Connector:
    def __init__(
        self,
        provider: DefenderBearerTokenProvider,
        *,
        result: ConnectorCapture | BaseException | None = None,
        request_twice: bool = False,
    ) -> None:
        self.provider = provider
        self.result = result if result is not None else _capture()
        self.request_twice = request_twice
        self.seen_token_repr = ""

    def capture(self, request: object) -> ConnectorCapture:
        assert request == _request()
        token = self.provider.get_token(deadline=float("inf"))
        self.seen_token_repr = repr(token)
        if self.request_twice:
            self.provider.get_token(deadline=float("inf"))
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


def _broker(
    tmp_path: Path,
    credential: CertificateAssertionCredential | FederatedAssertionCredential,
    transport: _Transport,
    *,
    connector_result: ConnectorCapture | BaseException | None = None,
    request_twice: bool = False,
    now_values: list[int] | None = None,
) -> tuple[DefenderWorkloadIdentityBroker, SQLiteDefenderTokenJournal, list[_Connector]]:
    journal = SQLiteDefenderTokenJournal(tmp_path / "defender-token.sqlite3")
    connectors: list[_Connector] = []

    def factory(provider: DefenderBearerTokenProvider) -> _Connector:
        connector = _Connector(
            provider,
            result=connector_result,
            request_twice=request_twice,
        )
        connectors.append(connector)
        return connector

    values = iter(now_values) if now_values is not None else None
    broker = DefenderWorkloadIdentityBroker(
        tenant_id=_TENANT,
        client_id=_CLIENT,
        cloud="global",
        credential=credential,
        journal=journal,
        timeout_seconds=30,
        _transport=transport,
        _connector_factory=factory,
        _nonce=lambda: _ACQUISITION_ID,
        _now=(lambda: next(values)) if values is not None else (lambda: _NOW_MS),
    )
    return broker, journal, connectors


def test_cloud_profiles_bind_exact_authority_graph_and_scope() -> None:
    assert defender_entra_cloud("global").scope == "https://graph.microsoft.com/.default"
    assert (
        defender_entra_cloud("us-government-l4").scope
        == "https://graph.microsoft.us/.default"
    )
    assert (
        defender_entra_cloud("us-government-l5").scope
        == "https://dod-graph.microsoft.us/.default"
    )
    assert (
        defender_entra_cloud("us-government-l4").authority_origin
        == "https://login.microsoftonline.us"
    )
    with pytest.raises(ValueError, match="unsupported"):
        defender_entra_cloud("attacker-cloud")  # type: ignore[arg-type]


def test_certificate_assertion_is_ps256_exact_and_locally_verified(
    certificate_material: tuple[bytes, _Signer],
) -> None:
    credential = _certificate_credential(certificate_material)
    endpoint = f"https://login.microsoftonline.com/{_TENANT}/oauth2/v2.0/token"

    issued = credential.issue(
        client_id=_CLIENT,
        token_endpoint=endpoint,
        now_epoch_seconds=_NOW_SECONDS,
        deadline=float("inf"),
    )

    header_segment, claims_segment, _ = issued.value.split(b".")
    header = strict_json_loads(
        base64.urlsafe_b64decode(header_segment + b"=" * (-len(header_segment) % 4))
    )
    claims = strict_json_loads(
        base64.urlsafe_b64decode(claims_segment + b"=" * (-len(claims_segment) % 4))
    )
    assert header["alg"] == "PS256"
    assert header["typ"] == "JWT"
    assert set(header) == {"alg", "typ", "x5t#S256"}
    assert claims == {
        "aud": endpoint,
        "exp": _NOW_SECONDS + 300,
        "iat": _NOW_SECONDS,
        "iss": _CLIENT,
        "jti": _JTI,
        "nbf": _NOW_SECONDS,
        "sub": _CLIENT,
    }
    assert issued.mode == "certificate-ps256"
    assert "vault://" not in issued.reference_digest


def test_certificate_signer_failure_and_wrong_signature_are_sanitized(
    certificate_material: tuple[bytes, _Signer],
) -> None:
    certificate, signer_template = certificate_material
    for signer in (
        _Signer(signer_template.private_key, fail=True),
        _Signer(signer_template.private_key, corrupt=True),
    ):
        credential = CertificateAssertionCredential(
            certificate,
            signer,
            _jti=lambda: _JTI,
        )
        with pytest.raises(DefenderPamError) as caught:
            credential.issue(
                client_id=_CLIENT,
                token_endpoint=(
                    f"https://login.microsoftonline.com/{_TENANT}/oauth2/v2.0/token"
                ),
                now_epoch_seconds=_NOW_SECONDS,
                deadline=float("inf"),
            )
        assert "do-not-leak" not in str(caught.value)


def test_certificate_must_be_current_and_rsa_2048(
    certificate_material: tuple[bytes, _Signer],
) -> None:
    credential = _certificate_credential(certificate_material)
    with pytest.raises(DefenderPamError, match="not currently valid"):
        credential.issue(
            client_id=_CLIENT,
            token_endpoint=(
                f"https://login.microsoftonline.com/{_TENANT}/oauth2/v2.0/token"
            ),
            now_epoch_seconds=_NOW_SECONDS + (40 * 24 * 60 * 60),
            deadline=float("inf"),
        )


def test_federated_assertion_exact_identity_and_freshness() -> None:
    source = _FederatedSource(_federated_jwt())
    credential = _federated_credential(source)
    issued = credential.issue(
        client_id=_CLIENT,
        token_endpoint="unused",
        now_epoch_seconds=_NOW_SECONDS,
        deadline=float("inf"),
    )
    assert issued.mode == "federated-rs256"
    assert source.seen_audience == FEDERATED_ASSERTION_AUDIENCE
    assert str(FederatedClientAssertion(source.value)) == "<redacted>"
    assert source.value.decode() not in repr(FederatedClientAssertion(source.value))


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"audience": "https://attacker.invalid"}, "identity binding"),
        ({"issuer": "https://wrong.example"}, "identity binding"),
        ({"subject": "other-workload"}, "identity binding"),
        ({"alg": "none"}, "RS256"),
        ({"issued": _NOW_SECONDS - 301}, "freshness"),
        ({"expires": _NOW_SECONDS + 601}, "freshness"),
    ],
)
def test_federated_assertion_rejects_adversarial_claims(
    kwargs: dict[str, Any],
    message: str,
) -> None:
    credential = _federated_credential(_FederatedSource(_federated_jwt(**kwargs)))
    with pytest.raises(DefenderPamError, match=message):
        credential.issue(
            client_id=_CLIENT,
            token_endpoint="unused",
            now_epoch_seconds=_NOW_SECONDS,
            deadline=float("inf"),
        )


def test_federated_assertion_allows_bounded_provider_specific_claims() -> None:
    credential = _federated_credential(
        _FederatedSource(_federated_jwt(extra_claim=True))
    )

    issued = credential.issue(
        client_id=_CLIENT,
        token_endpoint="unused",
        now_epoch_seconds=_NOW_SECONDS,
        deadline=float("inf"),
    )

    assert issued.mode == "federated-rs256"


def test_federated_source_failure_does_not_leak_assertion() -> None:
    source = _FederatedSource(_federated_jwt(), fail=True)
    credential = _federated_credential(source)
    with pytest.raises(DefenderPamError) as caught:
        credential.issue(
            client_id=_CLIENT,
            token_endpoint="unused",
            now_epoch_seconds=_NOW_SECONDS,
            deadline=float("inf"),
        )
    assert source.value not in str(caught.value).encode()


def test_successful_capture_uses_exact_form_and_records_expiry_only_boundary(
    tmp_path: Path,
    certificate_material: tuple[bytes, _Signer],
) -> None:
    transport = _Transport([_token_response(extra={"ext_expires_in": 3_599})])
    credential = _certificate_credential(certificate_material)
    broker, journal, connectors = _broker(tmp_path, credential, transport)

    managed = broker.capture(_request())

    assert len(transport.calls) == 1
    assert transport.calls[0].target == f"/{_TENANT}/oauth2/v2.0/token"
    form = urllib.parse.parse_qs(
        transport.calls[0].body.decode(),
        strict_parsing=True,
    )
    assert form["client_id"] == [_CLIENT]
    assert form["scope"] == ["https://graph.microsoft.com/.default"]
    assert form["grant_type"] == ["client_credentials"]
    assert form["client_assertion_type"] == [CLIENT_ASSERTION_TYPE]
    assert "client_secret" not in form
    assert "refresh_token" not in form
    assert dict(transport.calls[0].headers) == {
        "accept": "application/json",
        "accept-encoding": "identity",
        "content-type": "application/x-www-form-urlencoded",
    }
    assert connectors[0].seen_token_repr == "DefenderBearerToken(<redacted>)"
    assert _TOKEN.encode() not in managed.pam_receipt_bytes
    assert form["client_assertion"][0].encode() not in managed.pam_receipt_bytes

    record = journal.get(_ACQUISITION_ID)
    assert record.state == "closed"
    assert record.closure == "capture-completed-token-release-only"
    assert record.access_token_expires_epoch_millis == _NOW_MS + 3_599_000
    assert record.last_error is None
    parsed = strict_json_loads(managed.pam_receipt_bytes)
    assert parsed["lifecycle"]["access_token_revocation_supported"] is False
    assert parsed["lifecycle"]["access_token_persisted"] is False
    assert (
        parsed["lifecycle"]["revocation_boundary"]
        == "expiry-only-no-individual-token-revocation"
    )
    assert (
        parsed["lifecycle"]["residual_exposure_end_epoch_millis"]
        == _NOW_MS + 3_599_000
    )
    verified = verify_defender_pam_receipt(
        managed.pam_receipt_bytes,
        expected_request_digest=record.request_digest,
        expected_token_endpoint_digest=broker.token_endpoint_digest,
        expected_graph_origin_digest=broker.graph_origin_digest,
        expected_scope_digest=broker.scope_digest,
        expected_credential_reference_digest=broker.credential_reference_digest,
        expected_capture_receipt_digest=managed.capture.receipt_digest,
        expected_capture_records_digest=managed.capture.records_digest,
    )
    assert verified.receipt_digest == managed.pam_receipt_digest


def test_federated_capture_has_no_long_lived_secret(
    tmp_path: Path,
) -> None:
    source = _FederatedSource(_federated_jwt())
    transport = _Transport([_token_response()])
    broker, _, _ = _broker(tmp_path, _federated_credential(source), transport)

    managed = broker.capture(_request())

    assert source.value not in managed.pam_receipt_bytes
    assert _TOKEN.encode() not in managed.pam_receipt_bytes
    assert source.seen_audience == FEDERATED_ASSERTION_AUDIENCE


def test_token_provider_is_single_use_and_capture_is_not_returned(
    tmp_path: Path,
    certificate_material: tuple[bytes, _Signer],
) -> None:
    broker, journal, _ = _broker(
        tmp_path,
        _certificate_credential(certificate_material),
        _Transport([_token_response()]),
        request_twice=True,
    )

    with pytest.raises(DefenderPamError, match="more than once"):
        broker.capture(_request())

    record = journal.get(_ACQUISITION_ID)
    assert record.state == "closed"
    assert record.closure == "capture-failed-token-release-only"


def test_connector_failure_is_closed_but_never_claimed_revoked(
    tmp_path: Path,
    certificate_material: tuple[bytes, _Signer],
) -> None:
    broker, journal, _ = _broker(
        tmp_path,
        _certificate_credential(certificate_material),
        _Transport([_token_response()]),
        connector_result=ConnectorCaptureError("verify", "count did not close"),
    )

    with pytest.raises(ConnectorCaptureError, match="count did not close"):
        broker.capture(_request())

    record = journal.get(_ACQUISITION_ID)
    assert record.closure == "capture-failed-token-release-only"
    assert record.access_token_expires_epoch_millis is not None


def test_http_rejection_is_definite_no_token_and_is_not_retried(
    tmp_path: Path,
    certificate_material: tuple[bytes, _Signer],
) -> None:
    transport = _Transport(
        [
            _TokenHTTPResponse(
                status=401,
                headers=(("content-type", "application/json"),),
                body=b'{"error":"invalid_client","error_description":"secret details"}',
            )
        ]
    )
    broker, journal, _ = _broker(
        tmp_path,
        _certificate_credential(certificate_material),
        transport,
    )

    with pytest.raises(DefenderPamError, match="HTTP 401") as caught:
        broker.capture(_request())

    assert "secret details" not in str(caught.value)
    assert len(transport.calls) == 1
    record = journal.get(_ACQUISITION_ID)
    assert record.closure == "token-request-rejected-no-token"
    assert record.access_token_expires_epoch_millis is None


def test_transport_failure_is_ambiguous_not_retried_and_keeps_exposure_ceiling(
    tmp_path: Path,
    certificate_material: tuple[bytes, _Signer],
) -> None:
    transport = _Transport(
        [TimeoutError("request body contained top-secret assertion")]
    )
    broker, journal, _ = _broker(
        tmp_path,
        _certificate_credential(certificate_material),
        transport,
    )

    with pytest.raises(DefenderPamAmbiguousRequest) as caught:
        broker.capture(_request())

    assert "top-secret" not in str(caught.value)
    assert len(transport.calls) == 1
    record = journal.get(_ACQUISITION_ID)
    assert record.state == "uncertain"
    assert record.closure == "token-request-ambiguous"
    assert (
        record.conservative_exposure_end_epoch_millis
        == _NOW_MS + (3_900 + 60) * 1_000
    )


def test_durable_activation_failure_never_becomes_false_no_token(
    tmp_path: Path,
    certificate_material: tuple[bytes, _Signer],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broker, journal, _ = _broker(
        tmp_path,
        _certificate_credential(certificate_material),
        _Transport([_token_response()]),
    )

    def fail_activation(
        self: SQLiteDefenderTokenJournal,
        **kwargs: object,
    ) -> object:
        del self, kwargs
        raise sqlite3.OperationalError("database error containing token-looking-secret")

    monkeypatch.setattr(SQLiteDefenderTokenJournal, "mark_issued", fail_activation)

    with pytest.raises(DefenderPamAmbiguousRequest, match="durably recorded") as caught:
        broker.capture(_request())

    assert "token-looking-secret" not in str(caught.value)
    record = journal.get(_ACQUISITION_ID)
    assert record.state == "uncertain"
    assert record.closure == "token-request-ambiguous"


@pytest.mark.parametrize(
    "response",
    [
        _token_response(extra={"refresh_token": "forbidden"}),
        _token_response(expires_in=59),
        _token_response(expires_in=3_901),
        _token_response(extra={"ext_expires_in": 100}),
        _token_response(headers=(("content-type", "text/html"),)),
        _token_response(
            headers=(
                ("content-encoding", "gzip"),
                ("content-type", "application/json"),
            )
        ),
        _TokenHTTPResponse(
            status=200,
            headers=(("content-type", "application/json"),),
            body=b'{"access_token":"x","expires_in":3600,"token_type":"bearer"}',
        ),
        _TokenHTTPResponse(
            status=200,
            headers=(("content-type", "application/json"),),
            body=b'{"access_token":"x","access_token":"y","expires_in":3600,'
            b'"token_type":"Bearer"}',
        ),
    ],
)
def test_http_200_that_cannot_be_consumed_is_ambiguous(
    tmp_path: Path,
    certificate_material: tuple[bytes, _Signer],
    response: _TokenHTTPResponse,
) -> None:
    broker, journal, _ = _broker(
        tmp_path,
        _certificate_credential(certificate_material),
        _Transport([response]),
    )

    with pytest.raises(DefenderPamAmbiguousRequest, match="could not be safely consumed"):
        broker.capture(_request())

    record = journal.get(_ACQUISITION_ID)
    assert record.state == "uncertain"
    assert record.access_token_expires_epoch_millis is None


def test_assertion_reflection_is_detected_without_echoing_it(
    tmp_path: Path,
    certificate_material: tuple[bytes, _Signer],
) -> None:
    class _ReflectingTransport:
        def request(
            self,
            *,
            target: str,
            body: bytes,
            headers: tuple[tuple[str, str], ...],
            deadline: float,
        ) -> _TokenHTTPResponse:
            del target, headers, deadline
            assertion = urllib.parse.parse_qs(body.decode())["client_assertion"][0]
            return _TokenHTTPResponse(
                status=200,
                headers=(("content-type", "application/json"),),
                body=canonical_json_bytes(
                    {
                        "access_token": _TOKEN,
                        "debug": assertion,
                        "expires_in": 3_599,
                        "token_type": "Bearer",
                    }
                ),
            )

    journal = SQLiteDefenderTokenJournal(tmp_path / "reflection.sqlite3")
    broker = DefenderWorkloadIdentityBroker(
        tenant_id=_TENANT,
        client_id=_CLIENT,
        cloud="global",
        credential=_certificate_credential(certificate_material),
        journal=journal,
        _transport=_ReflectingTransport(),
        _connector_factory=lambda provider: _Connector(provider),
        _nonce=lambda: _ACQUISITION_ID,
        _now=lambda: _NOW_MS,
    )

    with pytest.raises(DefenderPamAmbiguousRequest, match="reflected") as caught:
        broker.capture(_request())

    assert "eyJ" not in str(caught.value)
    assert journal.get(_ACQUISITION_ID).state == "uncertain"


def test_receipt_verifier_rejects_overstated_revocation_and_anchor_changes(
    tmp_path: Path,
    certificate_material: tuple[bytes, _Signer],
) -> None:
    broker, journal, _ = _broker(
        tmp_path,
        _certificate_credential(certificate_material),
        _Transport([_token_response()]),
    )
    managed = broker.capture(_request())
    record = journal.get(_ACQUISITION_ID)
    parsed = strict_json_loads(managed.pam_receipt_bytes)

    parsed["lifecycle"]["access_token_revocation_supported"] = True
    forged = canonical_json_bytes(parsed)
    with pytest.raises(DefenderPamError, match="overstates"):
        verify_defender_pam_receipt(
            forged,
            expected_request_digest=record.request_digest,
            expected_token_endpoint_digest=broker.token_endpoint_digest,
            expected_graph_origin_digest=broker.graph_origin_digest,
            expected_scope_digest=broker.scope_digest,
            expected_credential_reference_digest=broker.credential_reference_digest,
            expected_capture_receipt_digest=managed.capture.receipt_digest,
            expected_capture_records_digest=managed.capture.records_digest,
        )

    parsed = strict_json_loads(managed.pam_receipt_bytes)
    parsed["identity"]["cloud"] = "us-government-l4"
    with pytest.raises(DefenderPamError, match="cloud binding"):
        verify_defender_pam_receipt(
            canonical_json_bytes(parsed),
            expected_request_digest=record.request_digest,
            expected_token_endpoint_digest=broker.token_endpoint_digest,
            expected_graph_origin_digest=broker.graph_origin_digest,
            expected_scope_digest=broker.scope_digest,
            expected_credential_reference_digest=broker.credential_reference_digest,
            expected_capture_receipt_digest=managed.capture.receipt_digest,
            expected_capture_records_digest=managed.capture.records_digest,
        )
    with pytest.raises(DefenderPamError, match="external anchor"):
        verify_defender_pam_receipt(
            managed.pam_receipt_bytes,
            expected_request_digest=_digest(b"other request"),
            expected_token_endpoint_digest=broker.token_endpoint_digest,
            expected_graph_origin_digest=broker.graph_origin_digest,
            expected_scope_digest=broker.scope_digest,
            expected_credential_reference_digest=broker.credential_reference_digest,
            expected_capture_receipt_digest=managed.capture.receipt_digest,
            expected_capture_records_digest=managed.capture.records_digest,
        )
    with pytest.raises(DefenderPamError, match="canonical"):
        verify_defender_pam_receipt(
            managed.pam_receipt_bytes + b"\n",
            expected_request_digest=record.request_digest,
            expected_token_endpoint_digest=broker.token_endpoint_digest,
            expected_graph_origin_digest=broker.graph_origin_digest,
            expected_scope_digest=broker.scope_digest,
            expected_credential_reference_digest=broker.credential_reference_digest,
            expected_capture_receipt_digest=managed.capture.receipt_digest,
            expected_capture_records_digest=managed.capture.records_digest,
        )


def test_recovery_marks_prepared_as_ambiguous_and_issued_as_abandoned(
    tmp_path: Path,
    certificate_material: tuple[bytes, _Signer],
) -> None:
    journal = SQLiteDefenderTokenJournal(tmp_path / "recovery.sqlite3")
    credential = _certificate_credential(certificate_material)
    cloud = defender_entra_cloud("global")
    endpoint_digest = _digest(
        f"{cloud.authority_origin}/{_TENANT}/oauth2/v2.0/token".encode()
    )
    prepared = journal.prepare(
        acquisition_id="11" * 32,
        request_digest=_digest(b"one"),
        token_endpoint_digest=endpoint_digest,
        graph_origin_digest=cloud.graph_origin_digest,
        scope_digest=cloud.scope_digest,
        credential_mode=credential.mode,
        credential_reference_digest=credential.reference_digest,
        token_request_profile_digest=_digest(b"profile"),
        now_epoch_millis=_NOW_MS,
        conservative_exposure_end_epoch_millis=_NOW_MS + 4_000_000,
    )
    second = journal.prepare(
        acquisition_id="22" * 32,
        request_digest=_digest(b"two"),
        token_endpoint_digest=endpoint_digest,
        graph_origin_digest=cloud.graph_origin_digest,
        scope_digest=cloud.scope_digest,
        credential_mode=credential.mode,
        credential_reference_digest=credential.reference_digest,
        token_request_profile_digest=_digest(b"profile"),
        now_epoch_millis=_NOW_MS,
        conservative_exposure_end_epoch_millis=_NOW_MS + 4_000_000,
    )
    journal.mark_issued(
        acquisition_id=second.acquisition_id,
        expected_revision=second.revision,
        now_epoch_millis=_NOW_MS,
        expires_epoch_millis=_NOW_MS + 3_599_000,
        assertion_id_digest=_digest(b"jti"),
        response_request_id_digest=None,
    )
    broker = DefenderWorkloadIdentityBroker(
        tenant_id=_TENANT,
        client_id=_CLIENT,
        cloud="global",
        credential=credential,
        journal=journal,
        _transport=_Transport([]),
        _connector_factory=lambda provider: _Connector(provider),
        _now=lambda: _NOW_MS + 1_000,
    )

    recovered = broker.recover_unsettled()

    assert [record.acquisition_id for record in recovered] == [
        prepared.acquisition_id,
        second.acquisition_id,
    ]
    assert recovered[0].state == "uncertain"
    assert recovered[0].closure == "token-request-ambiguous"
    assert recovered[1].state == "closed"
    assert recovered[1].closure == "abandoned-after-crash"


def test_request_scoped_recovery_does_not_close_another_run(
    tmp_path: Path,
    certificate_material: tuple[bytes, _Signer],
) -> None:
    journal = SQLiteDefenderTokenJournal(tmp_path / "scoped-recovery.sqlite3")
    credential = _certificate_credential(certificate_material)
    cloud = defender_entra_cloud("global")
    endpoint_digest = _digest(
        f"{cloud.authority_origin}/{_TENANT}/oauth2/v2.0/token".encode()
    )
    first_request_digest = _digest(b"first connector request")
    second_request_digest = _digest(b"second connector request")
    first = journal.prepare(
        acquisition_id="33" * 32,
        request_digest=first_request_digest,
        token_endpoint_digest=endpoint_digest,
        graph_origin_digest=cloud.graph_origin_digest,
        scope_digest=cloud.scope_digest,
        credential_mode=credential.mode,
        credential_reference_digest=credential.reference_digest,
        token_request_profile_digest=_digest(b"profile"),
        now_epoch_millis=_NOW_MS,
        conservative_exposure_end_epoch_millis=_NOW_MS + 4_000_000,
    )
    second = journal.prepare(
        acquisition_id="44" * 32,
        request_digest=second_request_digest,
        token_endpoint_digest=endpoint_digest,
        graph_origin_digest=cloud.graph_origin_digest,
        scope_digest=cloud.scope_digest,
        credential_mode=credential.mode,
        credential_reference_digest=credential.reference_digest,
        token_request_profile_digest=_digest(b"profile"),
        now_epoch_millis=_NOW_MS + 1,
        conservative_exposure_end_epoch_millis=_NOW_MS + 4_000_001,
    )
    broker = DefenderWorkloadIdentityBroker(
        tenant_id=_TENANT,
        client_id=_CLIENT,
        cloud="global",
        credential=credential,
        journal=journal,
        _transport=_Transport([]),
        _connector_factory=lambda provider: _Connector(provider),
        _now=lambda: _NOW_MS + 1_000,
    )

    recovered = broker.recover_request_digest(first_request_digest)

    assert [record.acquisition_id for record in recovered] == [
        first.acquisition_id
    ]
    assert recovered[0].state == "uncertain"
    assert journal.get(second.acquisition_id).state == "prepared"


def test_journal_rejects_group_readable_file_and_symlink(tmp_path: Path) -> None:
    unsafe = tmp_path / "unsafe.sqlite3"
    unsafe.write_bytes(b"")
    unsafe.chmod(0o640)
    with pytest.raises(DefenderPamError, match="owner-only"):
        SQLiteDefenderTokenJournal(unsafe)

    real = tmp_path / "real.sqlite3"
    SQLiteDefenderTokenJournal(real)
    link = tmp_path / "linked.sqlite3"
    link.symlink_to(real)
    with pytest.raises(DefenderPamError, match="regular file"):
        SQLiteDefenderTokenJournal(link)


def test_ids_are_canonical_and_custom_authority_cannot_be_injected(
    tmp_path: Path,
    certificate_material: tuple[bytes, _Signer],
) -> None:
    journal = SQLiteDefenderTokenJournal(tmp_path / "ids.sqlite3")
    credential = _certificate_credential(certificate_material)
    with pytest.raises(ValueError, match="canonical lowercase UUID"):
        DefenderWorkloadIdentityBroker(
            tenant_id=_TENANT.upper(),
            client_id=_CLIENT,
            cloud="global",
            credential=credential,
            journal=journal,
        )
    with pytest.raises(ValueError, match="unsupported"):
        DefenderWorkloadIdentityBroker(
            tenant_id=_TENANT,
            client_id=_CLIENT,
            cloud="https://evil.example",  # type: ignore[arg-type]
            credential=credential,
            journal=journal,
        )


def test_network_transport_explicitly_disables_proxy_and_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handlers: list[object] = []

    class _Opener:
        pass

    def fake_build_opener(*values: object) -> _Opener:
        handlers.extend(values)
        return _Opener()

    monkeypatch.setenv("HTTPS_PROXY", "https://attacker.invalid:8443")
    monkeypatch.setattr("urllib.request.build_opener", fake_build_opener)
    _UrllibTokenTransport(
        authority_origin="https://login.microsoftonline.com",
        timeout_seconds=30,
        ssl_context=__import__("ssl").create_default_context(),
    )

    proxy_handlers = [
        handler
        for handler in handlers
        if isinstance(handler, __import__("urllib").request.ProxyHandler)
    ]
    assert len(proxy_handlers) == 1
    assert proxy_handlers[0].proxies == {}
    assert any(isinstance(handler, _NoRedirect) for handler in handlers)


def test_no_secret_material_is_persisted_in_sqlite(
    tmp_path: Path,
    certificate_material: tuple[bytes, _Signer],
) -> None:
    transport = _Transport([_token_response()])
    broker, _, _ = _broker(
        tmp_path,
        _certificate_credential(certificate_material),
        transport,
    )

    broker.capture(_request())

    database = (tmp_path / "defender-token.sqlite3").read_bytes()
    assertion = urllib.parse.parse_qs(transport.calls[0].body.decode())[
        "client_assertion"
    ][0].encode()
    assert _TOKEN.encode() not in database
    assert assertion not in database
    assert b"client_secret" not in database
