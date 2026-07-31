from __future__ import annotations

import base64
import hashlib
import json
import ssl
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from assurance_lab.control_plane import oidc_http
from assurance_lab.control_plane.oidc import (
    GroupEntitlement,
    JWKSFetchRequest,
    OIDCConfiguration,
    TokenExchangeRequest,
)
from assurance_lab.evidence.canonical import canonical_json_bytes, strict_json_loads

_NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
_NOW_SECONDS = int(_NOW.timestamp())
_ISSUER = "https://login.example.test/tenant/v2.0"
_TOKEN_ENDPOINT = "https://login.example.test/tenant/oauth2/v2.0/token"
_JWKS_URI = "https://login.example.test/tenant/discovery/v2.0/keys"
_CLIENT_ID = "11111111-2222-4333-8444-555555555555"
_REDIRECT_URI = "https://assurance.example.test/oidc/callback"
_JTI = "12345678-1234-4234-8234-123456789abc"
_CODE = "authorization-code-one-time"
_VERIFIER = "v" * 43
_ID_TOKEN = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl"


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))


def _configuration() -> OIDCConfiguration:
    return OIDCConfiguration(
        issuer=_ISSUER,
        authorization_endpoint=f"{_ISSUER}/authorize",
        token_endpoint=_TOKEN_ENDPOINT,
        jwks_uri=_JWKS_URI,
        client_id=_CLIENT_ID,
        redirect_uri=_REDIRECT_URI,
        entitlements=(
            GroupEntitlement(
                group="security-platform",
                tenant_id="bank-a",
                roles=frozenset({"viewer"}),
            ),
        ),
    )


def _certificate(
    key: rsa.RSAPrivateKey,
    *,
    not_before: datetime = _NOW - timedelta(days=1),
    not_after: datetime = _NOW + timedelta(days=30),
) -> bytes:
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "control-assurance-oidc")]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


class _Signer:
    def __init__(
        self,
        key: rsa.RSAPrivateKey,
        *,
        signing_key: rsa.RSAPrivateKey | None = None,
    ) -> None:
        self.key = signing_key or key
        self.key_reference = (
            "https://assurance-prod.vault.azure.net/keys/oidc/"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        self.inputs: list[bytes] = []

    def sign_ps256(self, signing_input: bytes, *, deadline: float) -> bytes:
        assert deadline > time.monotonic()
        self.inputs.append(signing_input)
        return self.key.sign(
            signing_input,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )


def _credential(
    key: rsa.RSAPrivateKey,
    *,
    signer: _Signer | None = None,
    certificate: bytes | None = None,
) -> oidc_http.CertificatePrivateKeyJWT:
    return oidc_http.CertificatePrivateKeyJWT(
        client_id=_CLIENT_ID,
        token_endpoint=_TOKEN_ENDPOINT,
        certificate_der=certificate or _certificate(key),
        signer=signer or _Signer(key),
        _now=lambda: _NOW_SECONDS,
        _jti=lambda: _JTI,
    )


def _token_payload(**changes: object) -> bytes:
    value: dict[str, object] = {
        "access_token": "opaque-access-token",
        "expires_in": 3_600,
        "ext_expires_in": 3_600,
        "id_token": _ID_TOKEN,
        "scope": "openid profile",
        "token_type": "Bearer",
    }
    value.update(changes)
    return canonical_json_bytes(value)


_JWKS = canonical_json_bytes(
    {
        "keys": [
            {
                "alg": "RS256",
                "e": "AQAB",
                "kid": "signing-key",
                "kty": "RSA",
                "n": "sXch",
                "use": "sig",
            }
        ]
    }
)


class _Transport:
    def __init__(self) -> None:
        self.calls: list[
            tuple[
                str,
                str,
                bytes | None,
                tuple[tuple[str, str], ...],
                int,
            ]
        ] = []
        self.token_response = oidc_http._HTTPResponse(
            status=200,
            headers=(
                ("Content-Type", "application/json; charset=utf-8"),
                ("Content-Encoding", "identity"),
                ("Set-Cookie", "one=1; Secure"),
                ("Set-Cookie", "two=2; Secure"),
            ),
            body=_token_payload(),
        )
        self.jwks_response = oidc_http._HTTPResponse(
            status=200,
            headers=(("Content-Type", "application/jwk-set+json"),),
            body=_JWKS,
        )
        self.failure: BaseException | None = None
        self.jwks_delay = 0.0
        self._lock = threading.Lock()

    def request(
        self,
        *,
        method: str,
        url: str,
        body: bytes | None,
        headers: tuple[tuple[str, str], ...],
        maximum_response_bytes: int,
        deadline: float,
    ) -> oidc_http._HTTPResponse:
        assert deadline > time.monotonic()
        with self._lock:
            self.calls.append((method, url, body, headers, maximum_response_bytes))
        if self.failure is not None:
            raise self.failure
        if method == "POST":
            return self.token_response
        if self.jwks_delay:
            time.sleep(self.jwks_delay)
        return self.jwks_response


def _client(
    *,
    transport: _Transport | None = None,
    jwks_cache_seconds: int = 60,
    jwks_negative_cache_seconds: int = 5,
    timeout_seconds: int = 15,
) -> tuple[oidc_http.PinnedOIDCHTTPClient, _Transport]:
    key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    selected = transport or _Transport()
    return (
        oidc_http.PinnedOIDCHTTPClient(
            _configuration(),
            _credential(key),
            jwks_cache_seconds=jwks_cache_seconds,
            jwks_negative_cache_seconds=jwks_negative_cache_seconds,
            timeout_seconds=timeout_seconds,
            _transport=selected,
        ),
        selected,
    )


def _exchange_request(**changes: object) -> TokenExchangeRequest:
    values: dict[str, object] = {
        "endpoint": _TOKEN_ENDPOINT,
        "client_id": _CLIENT_ID,
        "redirect_uri": _REDIRECT_URI,
        "code": _CODE,
        "code_verifier": _VERIFIER,
    }
    values.update(changes)
    return TokenExchangeRequest(**values)  # type: ignore[arg-type]


def _jwks_request(**changes: object) -> JWKSFetchRequest:
    values: dict[str, object] = {
        "uri": _JWKS_URI,
        "expected_issuer": _ISSUER,
    }
    values.update(changes)
    return JWKSFetchRequest(**values)  # type: ignore[arg-type]


def test_private_key_jwt_is_exact_short_lived_and_locally_verified() -> None:
    key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    signer = _Signer(key)
    credential = _credential(key, signer=signer)

    assertion = credential.issue(deadline=time.monotonic() + 30.0)

    encoded_header, encoded_claims, encoded_signature = assertion._form_value().split(".")
    header = strict_json_loads(_b64url_decode(encoded_header))
    claims = strict_json_loads(_b64url_decode(encoded_claims))
    assert header == {
        "alg": "PS256",
        "typ": "JWT",
        "x5t#S256": header["x5t#S256"],
    }
    assert claims == {
        "aud": _TOKEN_ENDPOINT,
        "exp": _NOW_SECONDS + 300,
        "iat": _NOW_SECONDS,
        "iss": _CLIENT_ID,
        "jti": _JTI,
        "nbf": _NOW_SECONDS,
        "sub": _CLIENT_ID,
    }
    signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
    key.public_key().verify(
        _b64url_decode(encoded_signature),
        signing_input,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    assert signer.inputs == [signing_input]
    assert assertion.expires_epoch_seconds == _NOW_SECONDS + 300
    assert assertion._form_value() not in repr(assertion)
    assert str(assertion) == "<redacted>"


def test_private_key_jwt_rejects_wrong_remote_signature_and_expired_certificate() -> None:
    key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    other = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    wrong = _credential(key, signer=_Signer(key, signing_key=other))

    with pytest.raises(oidc_http.OIDCHTTPError) as signature_error:
        wrong.issue(deadline=time.monotonic() + 30.0)
    assert signature_error.value.stage == "assertion-signature"

    expired = _credential(
        key,
        certificate=_certificate(
            key,
            not_before=_NOW - timedelta(days=30),
            not_after=_NOW - timedelta(seconds=1),
        ),
    )
    with pytest.raises(oidc_http.OIDCHTTPError) as certificate_error:
        expired.issue(deadline=time.monotonic() + 30.0)
    assert certificate_error.value.stage == "assertion-certificate"


def test_code_redemption_uses_one_exact_secretless_request() -> None:
    client, transport = _client()

    result = client.redeem(_exchange_request())

    assert result.id_token == _ID_TOKEN
    assert result.effective_endpoint == _TOKEN_ENDPOINT
    assert len(transport.calls) == 1
    method, url, body, headers, maximum = transport.calls[0]
    assert method == "POST"
    assert url == _TOKEN_ENDPOINT
    assert maximum == 64 * 1024
    assert headers == (
        ("Accept", "application/json"),
        ("Accept-Encoding", "identity"),
        ("Content-Type", "application/x-www-form-urlencoded"),
    )
    assert body is not None
    form = urllib.parse.parse_qs(body.decode("ascii"), strict_parsing=True)
    assert form["client_id"] == [_CLIENT_ID]
    assert form["client_assertion_type"] == [
        oidc_http.PRIVATE_KEY_JWT_ASSERTION_TYPE
    ]
    assert form["code"] == [_CODE]
    assert form["code_verifier"] == [_VERIFIER]
    assert form["grant_type"] == ["authorization_code"]
    assert form["redirect_uri"] == [_REDIRECT_URI]
    assert "client_secret" not in form
    assert len(form["client_assertion"][0].split(".")) == 3


@pytest.mark.parametrize(
    ("mutation", "stage"),
    [
        ("redirect", "token-response"),
        ("compression", "token-response"),
        ("duplicate-content-type", "response-headers"),
        ("cl-te", "response-headers"),
        ("content-length-mismatch", "response-headers"),
        ("unsupported-transfer-coding", "response-headers"),
        ("wrong-content-type", "token-response"),
        ("invalid-refresh-token", "token-response"),
        ("invalid-scope", "token-response"),
        ("duplicate-json-member", "token-response"),
        ("malformed-json", "token-response"),
    ],
)
def test_token_response_contract_fails_closed(mutation: str, stage: str) -> None:
    transport = _Transport()
    if mutation == "redirect":
        transport.token_response = oidc_http._HTTPResponse(
            307,
            (("Content-Type", "application/json"), ("Location", "https://evil.invalid")),
            b"{}",
        )
    elif mutation == "compression":
        transport.token_response = oidc_http._HTTPResponse(
            200,
            (
                ("Content-Type", "application/json"),
                ("Content-Encoding", "gzip"),
            ),
            _token_payload(),
        )
    elif mutation == "duplicate-content-type":
        transport.token_response = oidc_http._HTTPResponse(
            200,
            (
                ("Content-Type", "application/json"),
                ("content-type", "application/json"),
            ),
            _token_payload(),
        )
    elif mutation == "cl-te":
        payload = _token_payload()
        transport.token_response = oidc_http._HTTPResponse(
            200,
            (
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(payload))),
                ("Transfer-Encoding", "chunked"),
            ),
            payload,
        )
    elif mutation == "content-length-mismatch":
        payload = _token_payload()
        transport.token_response = oidc_http._HTTPResponse(
            200,
            (
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(payload) + 1)),
            ),
            payload,
        )
    elif mutation == "unsupported-transfer-coding":
        transport.token_response = oidc_http._HTTPResponse(
            200,
            (
                ("Content-Type", "application/json"),
                ("Transfer-Encoding", "gzip"),
            ),
            _token_payload(),
        )
    elif mutation == "wrong-content-type":
        transport.token_response = oidc_http._HTTPResponse(
            200,
            (("Content-Type", "text/plain"),),
            _token_payload(),
        )
    elif mutation == "invalid-refresh-token":
        transport.token_response = oidc_http._HTTPResponse(
            200,
            (("Content-Type", "application/json"),),
            _token_payload(refresh_token="contains\ncontrol"),
        )
    elif mutation == "invalid-scope":
        transport.token_response = oidc_http._HTTPResponse(
            200,
            (("Content-Type", "application/json"),),
            _token_payload(scope="openid  profile"),
        )
    elif mutation == "duplicate-json-member":
        transport.token_response = oidc_http._HTTPResponse(
            200,
            (("Content-Type", "application/json"),),
            (
                b'{"access_token":"one","access_token":"two",'
                b'"id_token":"'
                + _ID_TOKEN.encode("ascii")
                + b'","token_type":"Bearer"}'
            ),
        )
    else:
        transport.token_response = oidc_http._HTTPResponse(
            200,
            (("Content-Type", "application/json"),),
            b'{"id_token":',
        )
    client, selected = _client(transport=transport)

    with pytest.raises(oidc_http.OIDCHTTPError) as raised:
        client.redeem(_exchange_request())

    assert raised.value.stage == stage
    assert len(selected.calls) == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"expires_in": None},
        {"token_type": "bearer"},
        {
            "refresh_token": "opaque refresh token",
            "scope": "openid",
            "provider_extension": {"bounded": True},
        },
    ],
)
def test_rfc6749_success_response_variants_are_admitted(
    changes: dict[str, object],
) -> None:
    transport = _Transport()
    payload_changes = dict(changes)
    omit_expiry = payload_changes.pop("expires_in", object()) is None
    payload = strict_json_loads(_token_payload(**payload_changes))
    assert isinstance(payload, dict)
    if omit_expiry:
        payload.pop("expires_in")
    transport.token_response = oidc_http._HTTPResponse(
        200,
        (
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(canonical_json_bytes(payload)))),
        ),
        canonical_json_bytes(payload),
    )
    client, _ = _client(transport=transport)

    result = client.redeem(_exchange_request())

    assert result.id_token == _ID_TOKEN
    assert "opaque refresh token" not in repr(result)


def test_decoded_chunked_response_is_accepted_without_content_length() -> None:
    transport = _Transport()
    transport.token_response = oidc_http._HTTPResponse(
        200,
        (
            ("Content-Type", "application/json"),
            ("Transfer-Encoding", "chunked"),
        ),
        _token_payload(),
    )
    client, _ = _client(transport=transport)

    assert client.redeem(_exchange_request()).id_token == _ID_TOKEN


@pytest.mark.parametrize("reflected", [_CODE, _VERIFIER])
def test_code_and_pkce_reflection_are_rejected_without_disclosure(
    reflected: str,
) -> None:
    transport = _Transport()
    transport.token_response = oidc_http._HTTPResponse(
        400,
        (("Content-Type", "application/json"), ("X-Debug", reflected)),
        b'{"error":"invalid_grant"}',
    )
    client, _ = _client(transport=transport)

    with pytest.raises(oidc_http.OIDCHTTPError) as raised:
        client.redeem(_exchange_request())

    assert raised.value.stage == "token-response-reflection"
    assert reflected not in str(raised.value)
    assert reflected not in repr(raised.value)


def test_assertion_reflection_is_rejected() -> None:
    transport = _Transport()

    class _ReflectingTransport(_Transport):
        def request(self, **kwargs: object) -> oidc_http._HTTPResponse:
            body = kwargs["body"]
            method = kwargs["method"]
            url = kwargs["url"]
            headers = kwargs["headers"]
            maximum = kwargs["maximum_response_bytes"]
            assert isinstance(body, bytes)
            assert isinstance(method, str)
            assert isinstance(url, str)
            assert isinstance(headers, tuple)
            assert isinstance(maximum, int)
            assertion = urllib.parse.parse_qs(
                body.decode("ascii"),
                strict_parsing=True,
            )["client_assertion"][0]
            with self._lock:
                self.calls.append(
                    (
                        method,
                        url,
                        body,
                        headers,
                        maximum,
                    )
                )
            return oidc_http._HTTPResponse(
                400,
                (("Content-Type", "application/json"),),
                assertion.encode("ascii"),
            )

    reflecting = _ReflectingTransport()
    client, _ = _client(transport=reflecting)

    with pytest.raises(oidc_http.OIDCHTTPError) as raised:
        client.redeem(_exchange_request())

    assert raised.value.stage == "token-response-reflection"
    assert "eyJ" not in str(raised.value)
    assert transport.calls == []


def test_ambiguous_transport_failure_is_not_retried_or_leaked() -> None:
    transport = _Transport()
    transport.failure = RuntimeError(f"secret:{_CODE}:{_VERIFIER}")
    client, selected = _client(transport=transport)

    with pytest.raises(oidc_http.OIDCHTTPError) as raised:
        client.redeem(_exchange_request())

    assert raised.value.stage == "token-transport-ambiguous"
    assert raised.value.__cause__ is None
    assert _CODE not in str(raised.value)
    assert _VERIFIER not in str(raised.value)
    assert len(selected.calls) == 1


def test_profile_substitution_is_rejected_before_remote_signing() -> None:
    client, transport = _client()

    with pytest.raises(oidc_http.OIDCHTTPError) as raised:
        client.redeem(_exchange_request(endpoint="https://other.example.test/token"))

    assert raised.value.stage == "token-request-profile"
    assert transport.calls == []


def test_jwks_fetch_is_exact_bounded_and_singleflight_cached() -> None:
    transport = _Transport()
    transport.jwks_delay = 0.02
    client, selected = _client(transport=transport, jwks_cache_seconds=60)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = tuple(executor.map(lambda _: client.fetch(_jwks_request()), range(16)))

    assert all(result.payload == _JWKS for result in results)
    assert all(result.effective_uri == _JWKS_URI for result in results)
    assert len(selected.calls) == 1
    method, url, body, headers, maximum = selected.calls[0]
    assert method == "GET"
    assert url == _JWKS_URI
    assert body is None
    assert headers == (
        ("Accept", "application/jwk-set+json, application/json"),
        ("Accept-Encoding", "identity"),
    )
    assert maximum == 1 * 1024 * 1024


@pytest.mark.parametrize(
    "response",
    [
        oidc_http._HTTPResponse(302, (("Location", "https://evil.invalid"),), b""),
        oidc_http._HTTPResponse(
            200,
            (("Content-Type", "application/json"), ("Content-Encoding", "gzip")),
            _JWKS,
        ),
        oidc_http._HTTPResponse(
            200,
            (("Content-Type", "application/json"), ("content-type", "application/json")),
            _JWKS,
        ),
        oidc_http._HTTPResponse(
            200,
            (
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(_JWKS))),
                ("Transfer-Encoding", "chunked"),
            ),
            _JWKS,
        ),
        oidc_http._HTTPResponse(
            200,
            (
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(_JWKS) - 1)),
            ),
            _JWKS,
        ),
        oidc_http._HTTPResponse(200, (("Content-Type", "text/plain"),), _JWKS),
        oidc_http._HTTPResponse(
            200,
            (("Content-Type", "application/json"),),
            b'{"keys":[]}',
        ),
        oidc_http._HTTPResponse(
            200,
            (("Content-Type", "application/json"),),
            b'{"keys":',
        ),
    ],
)
def test_jwks_response_contract_fails_closed(
    response: oidc_http._HTTPResponse,
) -> None:
    transport = _Transport()
    transport.jwks_response = response
    client, selected = _client(transport=transport, jwks_cache_seconds=0)

    with pytest.raises(oidc_http.OIDCHTTPError):
        client.fetch(_jwks_request())

    assert len(selected.calls) == 1


def test_jwks_failure_does_not_serve_unverified_or_stale_data() -> None:
    transport = _Transport()
    client, selected = _client(transport=transport, jwks_cache_seconds=0)
    assert client.fetch(_jwks_request()).payload == _JWKS
    transport.failure = RuntimeError("backend details must not escape")

    with pytest.raises(oidc_http.OIDCHTTPError) as raised:
        client.fetch(_jwks_request())

    assert raised.value.stage == "jwks-transport"
    assert raised.value.__cause__ is None
    assert len(selected.calls) == 2


def test_forced_jwks_refresh_bypasses_and_invalidates_the_cache() -> None:
    transport = _Transport()
    client, selected = _client(transport=transport, jwks_cache_seconds=60)
    assert client.fetch(_jwks_request()).payload == _JWKS

    replacement = canonical_json_bytes(
        {"keys": [{"kid": "replacement", "kty": "RSA", "n": "x", "e": "AQAB"}]}
    )
    transport.jwks_response = oidc_http._HTTPResponse(
        200,
        (("Content-Type", "application/jwk-set+json"),),
        replacement,
    )
    assert client.fetch(_jwks_request()).payload == _JWKS
    forced_request = _jwks_request(
        force_refresh=True,
        missing_kid="replacement",
        observed_generation_digest=(
            "sha256:" + hashlib.sha256(_JWKS).hexdigest()
        ),
    )
    assert client.fetch(forced_request).payload == replacement
    assert len(selected.calls) == 2

    failing_transport = _Transport()
    failing_client, failing_selected = _client(
        transport=failing_transport,
        jwks_cache_seconds=60,
    )
    assert failing_client.fetch(_jwks_request()).payload == _JWKS
    failing_transport.failure = RuntimeError("fresh retrieval failed")
    with pytest.raises(oidc_http.OIDCHTTPError):
        failing_client.fetch(
            _jwks_request(
                force_refresh=True,
                missing_kid="second",
                observed_generation_digest=(
                    "sha256:" + hashlib.sha256(_JWKS).hexdigest()
                ),
            )
        )
    # The failed forced refresh invalidated ``replacement``.  The short
    # failure bound rejects immediately; it neither serves stale bytes nor
    # creates an outage retry loop.
    with pytest.raises(oidc_http.OIDCHTTPError):
        failing_client.fetch(_jwks_request())
    assert len(failing_selected.calls) == 2


def test_fifty_concurrent_same_generation_and_kid_share_one_forced_get() -> None:
    transport = _Transport()
    client, selected = _client(transport=transport, jwks_cache_seconds=60)
    assert client.fetch(_jwks_request()).payload == _JWKS
    observed = "sha256:" + hashlib.sha256(_JWKS).hexdigest()
    replacement = canonical_json_bytes(
        {"keys": [{"kid": "rotated-key", "kty": "RSA", "n": "x", "e": "AQAB"}]}
    )
    transport.jwks_response = oidc_http._HTTPResponse(
        200,
        (("Content-Type", "application/jwk-set+json"),),
        replacement,
    )
    transport.jwks_delay = 0.05
    request = _jwks_request(
        force_refresh=True,
        missing_kid="rotated-key",
        observed_generation_digest=observed,
    )

    with ThreadPoolExecutor(max_workers=50) as executor:
        results = tuple(executor.map(lambda _: client.fetch(request), range(50)))

    assert all(item.payload == replacement for item in results)
    assert len(selected.calls) == 2


def test_arbitrary_missing_kids_are_network_and_memory_bounded_per_generation() -> None:
    transport = _Transport()
    client, selected = _client(
        transport=transport,
        jwks_cache_seconds=60,
        jwks_negative_cache_seconds=5,
    )
    assert client.fetch(_jwks_request()).payload == _JWKS
    observed = "sha256:" + hashlib.sha256(_JWKS).hexdigest()

    for index in range(256):
        result = client.fetch(
            _jwks_request(
                force_refresh=True,
                missing_kid=f"attacker-kid-{index}",
                observed_generation_digest=observed,
            )
        )
        assert result.payload == _JWKS

    assert len(selected.calls) == 2
    assert len(client._jwks_negative_cache) <= 128


def test_jwks_network_io_does_not_hold_the_cache_mutex() -> None:
    holder: dict[str, oidc_http.PinnedOIDCHTTPClient] = {}

    class _LockCheckingTransport(_Transport):
        def request(
            self,
            *,
            method: str,
            url: str,
            body: bytes | None,
            headers: tuple[tuple[str, str], ...],
            maximum_response_bytes: int,
            deadline: float,
        ) -> oidc_http._HTTPResponse:
            if method == "GET":
                lock = holder["client"]._jwks_cache_lock
                assert lock.acquire(timeout=0.2)
                lock.release()
            return super().request(
                method=method,
                url=url,
                body=body,
                headers=headers,
                maximum_response_bytes=maximum_response_bytes,
                deadline=deadline,
            )

    checking = _LockCheckingTransport()
    client, _ = _client(transport=checking)
    holder["client"] = client

    assert client.fetch(_jwks_request()).payload == _JWKS


def test_jwks_waiter_deadline_starts_when_the_waiter_calls_fetch() -> None:
    class _BlockingTransport(_Transport):
        def __init__(self) -> None:
            super().__init__()
            self.entered = threading.Event()
            self.release = threading.Event()

        def request(
            self,
            *,
            method: str,
            url: str,
            body: bytes | None,
            headers: tuple[tuple[str, str], ...],
            maximum_response_bytes: int,
            deadline: float,
        ) -> oidc_http._HTTPResponse:
            if method == "GET":
                self.entered.set()
                assert self.release.wait(timeout=3)
            return super().request(
                method=method,
                url=url,
                body=body,
                headers=headers,
                maximum_response_bytes=maximum_response_bytes,
                deadline=deadline,
            )

    transport = _BlockingTransport()
    client, _ = _client(transport=transport, timeout_seconds=1)
    with ThreadPoolExecutor(max_workers=2) as executor:
        leader = executor.submit(client.fetch, _jwks_request())
        assert transport.entered.wait(timeout=1)
        waiter = executor.submit(client.fetch, _jwks_request())
        try:
            with pytest.raises(oidc_http.OIDCHTTPError) as raised:
                waiter.result(timeout=2)
            assert raised.value.stage == "jwks-wait-timeout"
        finally:
            transport.release.set()
        with pytest.raises(oidc_http.OIDCHTTPError) as leader_error:
            leader.result(timeout=2)
        assert leader_error.value.stage == "jwks-transport"


@pytest.mark.parametrize(
    "field",
    ["uri", "expected_issuer"],
)
def test_jwks_request_substitution_is_rejected(field: str) -> None:
    client, transport = _client()
    replacement = "https://other.example.test/keys"

    with pytest.raises(oidc_http.OIDCHTTPError) as raised:
        client.fetch(_jwks_request(**{field: replacement}))

    assert raised.value.stage == "jwks-request-profile"
    assert transport.calls == []


def test_configuration_binding_rejects_mismatched_assertion_identity() -> None:
    key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    credential = oidc_http.CertificatePrivateKeyJWT(
        client_id="different-client",
        token_endpoint=_TOKEN_ENDPOINT,
        certificate_der=_certificate(key),
        signer=_Signer(key),
        _now=lambda: _NOW_SECONDS,
        _jti=lambda: _JTI,
    )

    with pytest.raises(ValueError, match="not bound"):
        oidc_http.PinnedOIDCHTTPClient(
            _configuration(),
            credential,
            _transport=_Transport(),
        )


@pytest.mark.parametrize("seconds", [0, 31, True])
def test_negative_cache_ttl_is_short_and_bounded(seconds: object) -> None:
    key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    with pytest.raises(ValueError, match="negative cache TTL"):
        oidc_http.PinnedOIDCHTTPClient(
            _configuration(),
            _credential(key),
            jwks_negative_cache_seconds=seconds,  # type: ignore[arg-type]
            _transport=_Transport(),
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"force_refresh": True},
        {
            "force_refresh": True,
            "missing_kid": "new",
            "observed_generation_digest": "sha256:not-a-digest",
        },
        {"missing_kid": "new"},
    ],
)
def test_forced_refresh_requires_exact_generation_and_kid_correlation(
    changes: dict[str, object],
) -> None:
    client, transport = _client()
    with pytest.raises(oidc_http.OIDCHTTPError) as raised:
        client.fetch(_jwks_request(**changes))
    assert raised.value.stage == "jwks-request-profile"
    assert transport.calls == []


def test_client_assertion_rejects_non_ascii_bytes() -> None:
    with pytest.raises(ValueError):
        oidc_http.ClientAssertion(
            b"\xff.a.b",
            expires_epoch_seconds=_NOW_SECONDS + 300,
            identifier_digest="sha256:" + ("a" * 64),
        )


def test_token_response_fixture_is_canonical_json() -> None:
    # Guard against accidentally testing permissive stdlib JSON while the
    # production boundary uses duplicate-key-rejecting strict JSON.
    payload = _token_payload()
    assert canonical_json_bytes(strict_json_loads(payload)) == payload
    assert json.loads(payload)["id_token"] == _ID_TOKEN


def test_default_transport_uses_real_tls_ignores_environment_proxy_and_stops_redirect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ca_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OIDC test CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(days=1))
        .not_valid_after(_NOW + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
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
        .sign(ca_key, hashes.SHA256())
    )
    server_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    server_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]
    )
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(days=1))
        .not_valid_after(_NOW + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = tmp_path / "ca.pem"
    certificate_path = tmp_path / "server.pem"
    key_path = tmp_path / "server-key.pem"
    ca_path.write_bytes(ca_certificate.public_bytes(serialization.Encoding.PEM))
    certificate_path.write_bytes(
        server_certificate.public_bytes(serialization.Encoding.PEM)
    )
    key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        redirect_token = False
        token_posts = 0
        jwks_gets = 0
        followed_redirects = 0
        last_form: ClassVar[dict[str, list[str]]] = {}

        def log_message(self, format: str, *args: object) -> None:
            del format, args

        def _send(self, status: int, payload: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Encoding", "identity")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self) -> None:
            if self.path == "/followed":
                type(self).followed_redirects += 1
                self._send(500, b"followed", "text/plain")
                return
            assert self.path == "/token"
            type(self).token_posts += 1
            length = int(self.headers["Content-Length"])
            body = self.rfile.read(length)
            type(self).last_form = urllib.parse.parse_qs(
                body.decode("ascii"),
                strict_parsing=True,
            )
            if type(self).redirect_token:
                self.send_response(307)
                self.send_header("Location", "/followed")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._send(200, _token_payload(), "application/json")

        def do_GET(self) -> None:
            if self.path == "/followed":
                type(self).followed_redirects += 1
                self._send(500, b"followed", "text/plain")
                return
            assert self.path == "/jwks"
            type(self).jwks_gets += 1
            self._send(200, _JWKS, "application/jwk-set+json")

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
    tls_context.load_cert_chain(certificate_path, key_path)
    server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        issuer = f"https://localhost:{port}/issuer"
        token_endpoint = f"https://localhost:{port}/token"
        jwks_uri = f"https://localhost:{port}/jwks"
        configuration = OIDCConfiguration(
            issuer=issuer,
            authorization_endpoint=f"{issuer}/authorize",
            token_endpoint=token_endpoint,
            jwks_uri=jwks_uri,
            client_id=_CLIENT_ID,
            redirect_uri=_REDIRECT_URI,
            entitlements=(
                GroupEntitlement(
                    group="security-platform",
                    tenant_id="bank-a",
                    roles=frozenset({"viewer"}),
                ),
            ),
        )
        client_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
        credential = oidc_http.CertificatePrivateKeyJWT(
            client_id=_CLIENT_ID,
            token_endpoint=token_endpoint,
            certificate_der=_certificate(client_key),
            signer=_Signer(client_key),
            _now=lambda: _NOW_SECONDS,
            _jti=lambda: _JTI,
        )
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
        monkeypatch.setenv("https_proxy", "http://127.0.0.1:1")
        monkeypatch.setenv("NO_PROXY", "")
        monkeypatch.setenv("no_proxy", "")
        client = oidc_http.PinnedOIDCHTTPClient(
            configuration,
            credential,
            ca_file=ca_path,
            timeout_seconds=5,
            jwks_cache_seconds=0,
        )
        request = TokenExchangeRequest(
            endpoint=token_endpoint,
            client_id=_CLIENT_ID,
            redirect_uri=_REDIRECT_URI,
            code=_CODE,
            code_verifier=_VERIFIER,
        )

        assert client.redeem(request).id_token == _ID_TOKEN
        assert client.fetch(
            JWKSFetchRequest(uri=jwks_uri, expected_issuer=issuer)
        ).payload == _JWKS
        assert _Handler.token_posts == 1
        assert _Handler.jwks_gets == 1
        assert _Handler.last_form["code"] == [_CODE]
        assert "client_secret" not in _Handler.last_form

        _Handler.redirect_token = True
        with pytest.raises(oidc_http.OIDCHTTPError) as raised:
            client.redeem(
                TokenExchangeRequest(
                    endpoint=token_endpoint,
                    client_id=_CLIENT_ID,
                    redirect_uri=_REDIRECT_URI,
                    code="second-code",
                    code_verifier=_VERIFIER,
                )
            )
        assert raised.value.stage == "token-response"
        assert _Handler.token_posts == 2
        assert _Handler.followed_redirects == 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
