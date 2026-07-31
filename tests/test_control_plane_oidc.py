from __future__ import annotations

import base64
import hashlib
import json
import urllib.parse
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256

from assurance_lab.control_plane.oidc import (
    AuthenticationResult,
    AuthorizationCodeRedeemer,
    GroupEntitlement,
    InMemoryOIDCStateStore,
    JWKSFetcher,
    JWKSFetchRequest,
    JWKSFetchResult,
    MFAPolicy,
    OIDCAuthenticator,
    OIDCConfiguration,
    OIDCError,
    OIDCLoginAdmissionPolicy,
    TokenExchangeRequest,
    TokenExchangeResult,
    verify_id_token,
)

_NOW = datetime(2026, 7, 29, 4, 0, tzinfo=UTC)
_ISSUER = "https://id.example.test/oidc"
_CLIENT_ID = "control-assurance"
_REDIRECT = "https://assurance.example.test/oidc/callback"
_KID = "signing-2026-07"
_SOURCE_DIGEST = f"hmac-sha256:{'1' * 64}"


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _json(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def _configuration(
    *,
    mfa_policy: MFAPolicy | None = None,
    entitlements: tuple[GroupEntitlement, ...] | None = None,
) -> OIDCConfiguration:
    return OIDCConfiguration(
        issuer=_ISSUER,
        authorization_endpoint=f"{_ISSUER}/authorize",
        token_endpoint=f"{_ISSUER}/token",
        jwks_uri=f"{_ISSUER}/jwks",
        client_id=_CLIENT_ID,
        redirect_uri=_REDIRECT,
        entitlements=entitlements
        or (
            GroupEntitlement(
                group="secops-platform",
                tenant_id="acme-bank",
                roles=frozenset({"viewer", "editor"}),
            ),
            GroupEntitlement(
                group="secops-approvers",
                tenant_id="acme-bank",
                roles=frozenset({"viewer", "approver"}),
            ),
        ),
        mfa_policy=mfa_policy or MFAPolicy(required_amr=frozenset({"mfa", "pwd"})),
    )


class _Keys:
    def __init__(self, algorithm: str = "RS256") -> None:
        self.algorithm = algorithm
        if algorithm == "RS256":
            self.private: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey = (
                rsa.generate_private_key(public_exponent=65537, key_size=2048)
            )
            rsa_numbers = self.private.public_key().public_numbers()
            assert isinstance(rsa_numbers, rsa.RSAPublicNumbers)
            self.jwk: dict[str, object] = {
                "kty": "RSA",
                "kid": _KID,
                "alg": "RS256",
                "use": "sig",
                "key_ops": ["verify"],
                "n": _b64(
                    rsa_numbers.n.to_bytes((rsa_numbers.n.bit_length() + 7) // 8, "big")
                ),
                "e": _b64(
                    rsa_numbers.e.to_bytes((rsa_numbers.e.bit_length() + 7) // 8, "big")
                ),
            }
        else:
            self.private = ec.generate_private_key(ec.SECP256R1())
            ec_numbers = self.private.public_key().public_numbers()
            assert isinstance(ec_numbers, ec.EllipticCurvePublicNumbers)
            self.jwk = {
                "kty": "EC",
                "kid": _KID,
                "alg": "ES256",
                "use": "sig",
                "key_ops": ["verify"],
                "crv": "P-256",
                "x": _b64(ec_numbers.x.to_bytes(32, "big")),
                "y": _b64(ec_numbers.y.to_bytes(32, "big")),
            }

    @property
    def jwks(self) -> bytes:
        return _json({"keys": [self.jwk]})

    def token(
        self,
        nonce: str,
        *,
        claims: dict[str, object] | None = None,
        header: dict[str, object] | None = None,
        raw_header: bytes | None = None,
        raw_payload: bytes | None = None,
    ) -> str:
        token_claims: dict[str, object] = {
            "iss": _ISSUER,
            "aud": _CLIENT_ID,
            "sub": "alice",
            "name": "Alice Example",
            "iat": int(_NOW.timestamp()),
            "exp": int((_NOW + timedelta(minutes=5)).timestamp()),
            "auth_time": int((_NOW - timedelta(minutes=1)).timestamp()),
            "nonce": nonce,
            "acr": "urn:example:loa:2",
            "amr": ["pwd", "mfa"],
            "groups": ["secops-platform"],
        }
        if claims:
            token_claims.update(claims)
        token_header: dict[str, object] = {
            "alg": self.algorithm,
            "kid": _KID,
            "typ": "JWT",
        }
        if header:
            token_header.update(header)
        encoded_header = _b64(raw_header or _json(token_header))
        encoded_payload = _b64(raw_payload or _json(token_claims))
        signing_input = f"{encoded_header}.{encoded_payload}".encode()
        if self.algorithm == "RS256":
            assert isinstance(self.private, rsa.RSAPrivateKey)
            signature = self.private.sign(signing_input, padding.PKCS1v15(), SHA256())
        else:
            assert isinstance(self.private, ec.EllipticCurvePrivateKey)
            der = self.private.sign(signing_input, ec.ECDSA(SHA256()))
            r_value, s_value = decode_dss_signature(der)
            signature = r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")
        return f"{encoded_header}.{encoded_payload}.{_b64(signature)}"


def _authorization_values(request_url: str) -> dict[str, str]:
    parsed = urllib.parse.urlsplit(request_url)
    values = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
    return {key: item[0] for key, item in values.items()}


class _Redeemer(AuthorizationCodeRedeemer):
    def __init__(
        self,
        token_factory: Callable[[TokenExchangeRequest], str],
        *,
        endpoint: str = f"{_ISSUER}/token",
    ) -> None:
        self.token_factory = token_factory
        self.endpoint = endpoint
        self.requests: list[TokenExchangeRequest] = []

    def redeem(self, request: TokenExchangeRequest) -> TokenExchangeResult:
        self.requests.append(request)
        return TokenExchangeResult(
            id_token=self.token_factory(request),
            effective_endpoint=self.endpoint,
        )


class _Fetcher(JWKSFetcher):
    def __init__(
        self,
        payload: bytes,
        *,
        uri: str = f"{_ISSUER}/jwks",
        callback: Callable[[], None] | None = None,
    ) -> None:
        self.payload = payload
        self.uri = uri
        self.callback = callback
        self.requests: list[JWKSFetchRequest] = []

    def fetch(self, request: JWKSFetchRequest) -> JWKSFetchResult:
        self.requests.append(request)
        if self.callback:
            self.callback()
        return JWKSFetchResult(payload=self.payload, effective_uri=self.uri)


def _authenticator(
    keys: _Keys,
    *,
    configuration: OIDCConfiguration | None = None,
    store: InMemoryOIDCStateStore | None = None,
    clock: Callable[[], datetime] = lambda: _NOW,
) -> tuple[OIDCAuthenticator, InMemoryOIDCStateStore, _Redeemer, _Fetcher]:
    actual_store = store or InMemoryOIDCStateStore()
    generated: list[bytes] = []
    counter = 0

    def random_bytes(size: int) -> bytes:
        nonlocal counter
        counter += 1
        value = bytes([counter % 251 or 1]) * size
        generated.append(value)
        return value

    def token_factory(_: TokenExchangeRequest) -> str:
        # begin() draws transaction, state, nonce, verifier in that order.
        return keys.token(_b64(generated[-2]))

    redeemer = _Redeemer(token_factory)
    fetcher = _Fetcher(keys.jwks)
    authenticator = OIDCAuthenticator(
        configuration or _configuration(),
        actual_store,
        redeemer,
        fetcher,
        clock=clock,
        random_bytes=random_bytes,
    )
    return authenticator, actual_store, redeemer, fetcher


def test_authorization_request_uses_state_nonce_and_pkce_s256() -> None:
    keys = _Keys()
    auth, _, _, _ = _authenticator(keys)
    request = auth.begin(source_digest=_SOURCE_DIGEST)
    values = _authorization_values(request.redirect_url)

    assert request.redirect_url.startswith(f"{_ISSUER}/authorize?")
    assert values["response_type"] == "code"
    assert values["client_id"] == _CLIENT_ID
    assert values["redirect_uri"] == _REDIRECT
    assert values["scope"] == "openid profile"
    assert "groups" not in values["scope"].split()
    assert values["code_challenge_method"] == "S256"
    assert len(values["state"]) == len(values["nonce"]) == len(request.transaction_cookie) == 43
    assert request.transaction_cookie not in request.redirect_url
    assert values["state"] not in request.transaction_cookie
    assert values["nonce"] not in request.transaction_cookie
    assert "<redacted>" in repr(request)


def test_two_replica_login_race_has_one_atomic_global_winner() -> None:
    keys = _Keys()
    store = InMemoryOIDCStateStore()
    configuration = replace(
        _configuration(),
        login_admission_policy=OIDCLoginAdmissionPolicy(
            global_active_limit=1,
            source_active_limit=1,
            burn_capacity=8,
        ),
    )
    replicas = (
        OIDCAuthenticator(
            configuration,
            store,
            _Redeemer(lambda _: ""),
            _Fetcher(keys.jwks),
            clock=lambda: _NOW,
            random_bytes=lambda size: b"A" * size,
        ),
        OIDCAuthenticator(
            configuration,
            store,
            _Redeemer(lambda _: ""),
            _Fetcher(keys.jwks),
            clock=lambda: _NOW,
            random_bytes=lambda size: b"B" * size,
        ),
    )

    def begin(replica: OIDCAuthenticator, source_digest: str) -> str:
        try:
            replica.begin(source_digest=source_digest)
        except OIDCError as exc:
            return exc.code
        return "accepted"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(
            executor.map(
                begin,
                replicas,
                (_SOURCE_DIGEST, f"hmac-sha256:{'2' * 64}"),
            )
        )

    assert sorted(outcomes) == ["accepted", "login_admission_limited"]


def test_two_replica_login_race_has_one_atomic_source_winner() -> None:
    keys = _Keys()
    store = InMemoryOIDCStateStore()
    configuration = replace(
        _configuration(),
        login_admission_policy=OIDCLoginAdmissionPolicy(
            global_active_limit=2,
            source_active_limit=1,
            burn_capacity=8,
        ),
    )

    def replica(seed: bytes) -> OIDCAuthenticator:
        return OIDCAuthenticator(
            configuration,
            store,
            _Redeemer(lambda _: ""),
            _Fetcher(keys.jwks),
            clock=lambda: _NOW,
            random_bytes=lambda size: seed * size,
        )

    def begin(current: OIDCAuthenticator) -> str:
        try:
            current.begin(source_digest=_SOURCE_DIGEST)
        except OIDCError as exc:
            return exc.code
        return "accepted"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(begin, (replica(b"A"), replica(b"B"))))

    assert sorted(outcomes) == ["accepted", "login_admission_limited"]


def test_active_limit_releases_only_after_transaction_expiry() -> None:
    keys = _Keys()
    current = [_NOW]
    store = InMemoryOIDCStateStore()
    configuration = replace(
        _configuration(),
        transaction_ttl_seconds=60,
        login_admission_policy=OIDCLoginAdmissionPolicy(
            global_active_limit=1,
            source_active_limit=1,
            burn_capacity=8,
        ),
    )

    def replica(seed: bytes) -> OIDCAuthenticator:
        return OIDCAuthenticator(
            configuration,
            store,
            _Redeemer(lambda _: ""),
            _Fetcher(keys.jwks),
            clock=lambda: current[0],
            random_bytes=lambda size: seed * size,
        )

    replica(b"A").begin(source_digest=_SOURCE_DIGEST)
    with pytest.raises(OIDCError, match="login_admission_limited"):
        replica(b"B").begin(source_digest=_SOURCE_DIGEST)
    current[0] += timedelta(seconds=60)
    replica(b"C").begin(source_digest=_SOURCE_DIGEST)


def test_complete_maps_groups_to_actor_and_server_side_session() -> None:
    keys = _Keys()
    auth, _, redeemer, fetcher = _authenticator(keys)
    request = auth.begin(source_digest=_SOURCE_DIGEST)
    state = _authorization_values(request.redirect_url)["state"]

    result = auth.complete(
        transaction_cookie=request.transaction_cookie,
        returned_state=state,
        authorization_code="one-time-code",
    )

    assert isinstance(result, AuthenticationResult)
    assert result.actor.tenant_id == "acme-bank"
    assert result.actor.subject == "oidc:alice"
    assert result.actor.roles == frozenset({"viewer", "editor"})
    assert result.actor.groups == ("secops-platform",)
    assert result.actor.mfa is True
    assert auth.authenticate_session(result.session_cookie) == result.actor
    assert redeemer.requests[0].code == "one-time-code"
    assert redeemer.requests[0].code_verifier
    values = _authorization_values(request.redirect_url)
    assert values["code_challenge"] == _b64(
        hashlib.sha256(redeemer.requests[0].code_verifier.encode()).digest()
    )
    assert redeemer.requests[0].code_verifier != request.transaction_cookie
    assert redeemer.requests[0].allow_redirects is False
    assert redeemer.requests[0].use_environment_proxy is False
    assert fetcher.requests[0].allow_redirects is False
    assert fetcher.requests[0].use_environment_proxy is False
    assert fetcher.requests[0].force_refresh is False
    assert "<redacted>" in repr(result)
    assert "one-time-code" not in repr(redeemer.requests[0])


@pytest.mark.parametrize("algorithm", ["RS256", "ES256"])
def test_rs256_and_es256_are_verified_with_exact_key_binding(algorithm: str) -> None:
    keys = _Keys(algorithm)
    nonce = _b64(b"n" * 32)
    identity = verify_id_token(
        keys.token(nonce),
        jwks=keys.jwks,
        configuration=_configuration(),
        expected_nonce_digest=f"sha256:{hashlib.sha256(nonce.encode()).hexdigest()}",
        now=_NOW,
    )
    assert identity.subject == "alice"
    assert identity.mfa is True


def test_jwk_without_optional_alg_remains_bound_by_rsa_key_type() -> None:
    keys = _Keys()
    nonce = _b64(b"n" * 32)
    jwk = dict(keys.jwk)
    jwk.pop("alg")
    identity = verify_id_token(
        keys.token(nonce),
        jwks=_json({"keys": [jwk]}),
        configuration=_configuration(),
        expected_nonce_digest=f"sha256:{hashlib.sha256(nonce.encode()).hexdigest()}",
        now=_NOW,
    )
    assert identity.subject == "alice"


def test_transaction_is_one_time_even_when_token_exchange_fails() -> None:
    keys = _Keys()
    auth, _, redeemer, _ = _authenticator(keys)
    request = auth.begin(source_digest=_SOURCE_DIGEST)
    state = _authorization_values(request.redirect_url)["state"]
    redeemer.token_factory = lambda _: "not-a-token"

    with pytest.raises(OIDCError, match="invalid_token"):
        auth.complete(
            transaction_cookie=request.transaction_cookie,
            returned_state=state,
            authorization_code="code",
        )
    with pytest.raises(OIDCError, match="invalid_transaction"):
        auth.complete(
            transaction_cookie=request.transaction_cookie,
            returned_state=state,
            authorization_code="code",
        )


def test_wrong_state_burns_transaction_and_never_calls_remote_service() -> None:
    keys = _Keys()
    auth, _, redeemer, fetcher = _authenticator(keys)
    request = auth.begin(source_digest=_SOURCE_DIGEST)
    with pytest.raises(OIDCError, match="invalid_transaction"):
        auth.complete(
            transaction_cookie=request.transaction_cookie,
            returned_state=_b64(b"x" * 32),
            authorization_code="code",
        )
    assert redeemer.requests == []
    assert fetcher.requests == []


def test_remote_calls_are_outside_store_lock() -> None:
    keys = _Keys()
    store = InMemoryOIDCStateStore()
    nonce_holder: dict[str, str] = {}

    def token_factory(_: TokenExchangeRequest) -> str:
        assert store.locked is False
        return keys.token(nonce_holder["nonce"])

    redeemer = _Redeemer(token_factory)
    fetcher = _Fetcher(keys.jwks, callback=lambda: assert_unlocked(store))
    auth = OIDCAuthenticator(_configuration(), store, redeemer, fetcher, clock=lambda: _NOW)
    request = auth.begin(source_digest=_SOURCE_DIGEST)
    values = _authorization_values(request.redirect_url)
    nonce_holder["nonce"] = values["nonce"]
    auth.complete(
        transaction_cookie=request.transaction_cookie,
        returned_state=values["state"],
        authorization_code="code",
    )


def assert_unlocked(store: InMemoryOIDCStateStore) -> None:
    assert store.locked is False


def test_mfa_requires_configured_acr_and_amr_evidence() -> None:
    keys = _Keys()
    nonce = _b64(b"n" * 32)
    configuration = _configuration(
        mfa_policy=MFAPolicy(
            accepted_acr=frozenset({"urn:example:loa:3"}),
            required_amr=frozenset({"mfa", "hwk"}),
        )
    )
    token = keys.token(
        nonce,
        claims={"acr": "urn:example:loa:2", "amr": ["mfa", "pwd"]},
    )
    with pytest.raises(OIDCError, match="mfa_required"):
        verify_id_token(
            token,
            jwks=keys.jwks,
            configuration=configuration,
            expected_nonce_digest=f"sha256:{hashlib.sha256(nonce.encode()).hexdigest()}",
            now=_NOW,
        )


def test_default_mfa_contract_is_fail_closed_without_claimed_evidence() -> None:
    keys = _Keys()
    nonce = _b64(b"n" * 32)
    configuration = OIDCConfiguration(
        issuer=_ISSUER,
        authorization_endpoint=f"{_ISSUER}/authorize",
        token_endpoint=f"{_ISSUER}/token",
        jwks_uri=f"{_ISSUER}/jwks",
        client_id=_CLIENT_ID,
        redirect_uri=_REDIRECT,
        entitlements=(
            GroupEntitlement(
                group="secops-platform",
                tenant_id="acme-bank",
                roles=frozenset({"viewer"}),
            ),
        ),
    )

    with pytest.raises(OIDCError, match="mfa_required"):
        verify_id_token(
            keys.token(nonce, claims={"amr": []}),
            jwks=keys.jwks,
            configuration=configuration,
            expected_nonce_digest=f"sha256:{hashlib.sha256(nonce.encode()).hexdigest()}",
            now=_NOW,
        )


def test_disabled_empty_mfa_policy_never_labels_a_session_as_mfa() -> None:
    keys = _Keys()
    nonce = _b64(b"n" * 32)
    identity = verify_id_token(
        keys.token(nonce, claims={"acr": None, "amr": []}),
        jwks=keys.jwks,
        configuration=_configuration(
            mfa_policy=MFAPolicy(
                required=False,
                accepted_acr=frozenset(),
                required_amr=frozenset(),
            )
        ),
        expected_nonce_digest=f"sha256:{hashlib.sha256(nonce.encode()).hexdigest()}",
        now=_NOW,
    )

    assert identity.mfa is False


def test_stale_auth_time_and_stale_token_are_rejected() -> None:
    keys = _Keys()
    nonce = _b64(b"n" * 32)
    digest = f"sha256:{hashlib.sha256(nonce.encode()).hexdigest()}"
    stale_auth = keys.token(
        nonce,
        claims={"auth_time": int((_NOW - timedelta(hours=2)).timestamp())},
    )
    with pytest.raises(OIDCError, match="stale_authentication"):
        verify_id_token(
            stale_auth,
            jwks=keys.jwks,
            configuration=_configuration(),
            expected_nonce_digest=digest,
            now=_NOW,
        )
    stale_token = keys.token(
        nonce,
        claims={
            "iat": int((_NOW - timedelta(minutes=10)).timestamp()),
            "auth_time": int((_NOW - timedelta(minutes=10)).timestamp()),
        },
    )
    with pytest.raises(OIDCError, match="stale_authentication"):
        verify_id_token(
            stale_token,
            jwks=keys.jwks,
            configuration=_configuration(),
            expected_nonce_digest=digest,
            now=_NOW,
        )


@pytest.mark.parametrize(
    ("claims", "match"),
    [
        ({"iss": "https://attacker.invalid"}, "invalid_claims"),
        ({"aud": "other-client"}, "invalid_claims"),
        ({"aud": [_CLIENT_ID, "other"], "azp": "other"}, "invalid_claims"),
        ({"nonce": _b64(b"x" * 32)}, "invalid_claims"),
        ({"sub": ""}, "invalid_claims"),
        ({"groups": ["same", "same"]}, "invalid_claims"),
        ({"exp": int((_NOW - timedelta(minutes=1)).timestamp())}, "stale_authentication"),
    ],
)
def test_critical_claim_failures_are_closed(
    claims: dict[str, object],
    match: str,
) -> None:
    keys = _Keys()
    nonce = _b64(b"n" * 32)
    with pytest.raises(OIDCError, match=match):
        verify_id_token(
            keys.token(nonce, claims=claims),
            jwks=keys.jwks,
            configuration=_configuration(),
            expected_nonce_digest=f"sha256:{hashlib.sha256(nonce.encode()).hexdigest()}",
            now=_NOW,
        )


def test_unknown_duplicate_and_wrong_type_jwks_keys_are_rejected() -> None:
    keys = _Keys()
    nonce = _b64(b"n" * 32)
    digest = f"sha256:{hashlib.sha256(nonce.encode()).hexdigest()}"
    token = keys.token(nonce)
    unknown = dict(keys.jwk, kid="another")
    duplicate = {"keys": [keys.jwk, dict(keys.jwk)]}
    wrong_type = dict(keys.jwk, kty="EC")

    for jwks, match in (
        (_json({"keys": [unknown]}), "unknown_signing_key"),
        (_json(duplicate), "invalid_jwks"),
        (_json({"keys": [wrong_type]}), "invalid_jwks"),
    ):
        with pytest.raises(OIDCError, match=match):
            verify_id_token(
                token,
                jwks=jwks,
                configuration=_configuration(),
                expected_nonce_digest=digest,
                now=_NOW,
            )


def test_unknown_kid_forces_one_fresh_jwks_fetch_and_then_verifies() -> None:
    keys = _Keys()
    stale_jwks = _json({"keys": [dict(keys.jwk, kid="retired-signing-key")]})
    nonce_holder: dict[str, str] = {}
    store = InMemoryOIDCStateStore()
    redeemer = _Redeemer(lambda _: keys.token(nonce_holder["nonce"]))

    class _RotatingFetcher(JWKSFetcher):
        def __init__(self) -> None:
            self.requests: list[JWKSFetchRequest] = []

        def fetch(self, request: JWKSFetchRequest) -> JWKSFetchResult:
            self.requests.append(request)
            return JWKSFetchResult(
                payload=keys.jwks if request.force_refresh else stale_jwks,
                effective_uri=f"{_ISSUER}/jwks",
            )

    fetcher = _RotatingFetcher()
    auth = OIDCAuthenticator(
        _configuration(),
        store,
        redeemer,
        fetcher,
        clock=lambda: _NOW,
    )
    request = auth.begin(source_digest=_SOURCE_DIGEST)
    values = _authorization_values(request.redirect_url)
    nonce_holder["nonce"] = values["nonce"]

    result = auth.complete(
        transaction_cookie=request.transaction_cookie,
        returned_state=values["state"],
        authorization_code="code",
    )

    assert result.actor.subject == "oidc:alice"
    assert [item.force_refresh for item in fetcher.requests] == [False, True]
    assert fetcher.requests[1].missing_kid == _KID
    assert fetcher.requests[1].observed_generation_digest == (
        "sha256:" + hashlib.sha256(stale_jwks).hexdigest()
    )


def test_unknown_kid_refresh_is_once_only_and_other_failures_do_not_refresh() -> None:
    keys = _Keys()
    stale_jwks = _json({"keys": [dict(keys.jwk, kid="retired-signing-key")]})

    def complete_with(payloads: tuple[bytes, ...]) -> list[JWKSFetchRequest]:
        nonce_holder: dict[str, str] = {}
        requests: list[JWKSFetchRequest] = []

        class _SequenceFetcher(JWKSFetcher):
            def fetch(self, request: JWKSFetchRequest) -> JWKSFetchResult:
                requests.append(request)
                index = min(len(requests) - 1, len(payloads) - 1)
                return JWKSFetchResult(
                    payload=payloads[index],
                    effective_uri=f"{_ISSUER}/jwks",
                )

        auth = OIDCAuthenticator(
            _configuration(),
            InMemoryOIDCStateStore(),
            _Redeemer(lambda _: keys.token(nonce_holder["nonce"])),
            _SequenceFetcher(),
            clock=lambda: _NOW,
        )
        request = auth.begin(source_digest=_SOURCE_DIGEST)
        values = _authorization_values(request.redirect_url)
        nonce_holder["nonce"] = values["nonce"]
        with pytest.raises(OIDCError):
            auth.complete(
                transaction_cookie=request.transaction_cookie,
                returned_state=values["state"],
                authorization_code="code",
            )
        return requests

    persistent_unknown = complete_with((stale_jwks, stale_jwks, keys.jwks))
    assert [item.force_refresh for item in persistent_unknown] == [False, True]

    wrong_key = _Keys()
    invalid_signature = complete_with((wrong_key.jwks, keys.jwks))
    assert [item.force_refresh for item in invalid_signature] == [False]


def test_algorithm_confusion_none_and_key_algorithm_mismatch_are_rejected() -> None:
    keys = _Keys()
    nonce = _b64(b"n" * 32)
    digest = f"sha256:{hashlib.sha256(nonce.encode()).hexdigest()}"
    none_token = keys.token(nonce, header={"alg": "none"})
    with pytest.raises(OIDCError, match="invalid_algorithm"):
        verify_id_token(
            none_token,
            jwks=keys.jwks,
            configuration=_configuration(),
            expected_nonce_digest=digest,
            now=_NOW,
        )
    mismatched = _json({"keys": [dict(keys.jwk, alg="ES256")]})
    with pytest.raises(OIDCError, match="invalid_jwks"):
        verify_id_token(
            keys.token(nonce),
            jwks=mismatched,
            configuration=_configuration(),
            expected_nonce_digest=digest,
            now=_NOW,
        )


def test_duplicate_json_members_in_header_payload_and_jwks_are_rejected() -> None:
    keys = _Keys()
    nonce = _b64(b"n" * 32)
    digest = f"sha256:{hashlib.sha256(nonce.encode()).hexdigest()}"
    duplicate_header = (
        b'{"alg":"RS256","alg":"RS256","kid":"signing-2026-07","typ":"JWT"}'
    )
    duplicate_payload = (
        b'{"iss":"https://id.example.test/oidc",'
        b'"iss":"https://id.example.test/oidc"}'
    )
    for token in (
        keys.token(nonce, raw_header=duplicate_header),
        keys.token(nonce, raw_payload=duplicate_payload),
    ):
        with pytest.raises(OIDCError, match="invalid_token"):
            verify_id_token(
                token,
                jwks=keys.jwks,
                configuration=_configuration(),
                expected_nonce_digest=digest,
                now=_NOW,
            )
    duplicate_jwks = (
        b'{"keys":[],"keys":[' + _json(keys.jwk) + b"]}"
    )
    with pytest.raises(OIDCError, match="invalid_jwks"):
        verify_id_token(
            keys.token(nonce),
            jwks=duplicate_jwks,
            configuration=_configuration(),
            expected_nonce_digest=digest,
            now=_NOW,
        )


def test_group_mapping_fails_closed_for_no_entitlement_or_cross_tenant_ambiguity() -> None:
    keys = _Keys()
    no_access = _configuration(
        entitlements=(
            GroupEntitlement(
                group="different",
                tenant_id="acme-bank",
                roles=frozenset({"viewer"}),
            ),
        )
    )
    auth, _, _, _ = _authenticator(keys, configuration=no_access)
    request = auth.begin(source_digest=_SOURCE_DIGEST)
    values = _authorization_values(request.redirect_url)
    with pytest.raises(OIDCError, match="not_entitled"):
        auth.complete(
            transaction_cookie=request.transaction_cookie,
            returned_state=values["state"],
            authorization_code="code",
        )

    ambiguous = _configuration(
        entitlements=(
            GroupEntitlement(
                group="secops-platform",
                tenant_id="acme-bank",
                roles=frozenset({"viewer"}),
            ),
            GroupEntitlement(
                group="second-tenant",
                tenant_id="other-bank",
                roles=frozenset({"viewer"}),
            ),
        )
    )
    nonce_holder: dict[str, str] = {}
    store = InMemoryOIDCStateStore()
    redeemer = _Redeemer(
        lambda _: keys.token(
            nonce_holder["nonce"],
            claims={"groups": ["secops-platform", "second-tenant"]},
        )
    )
    auth = OIDCAuthenticator(
        ambiguous,
        store,
        redeemer,
        _Fetcher(keys.jwks),
        clock=lambda: _NOW,
    )
    request = auth.begin(source_digest=_SOURCE_DIGEST)
    values = _authorization_values(request.redirect_url)
    nonce_holder["nonce"] = values["nonce"]
    with pytest.raises(OIDCError, match="ambiguous_tenant"):
        auth.complete(
            transaction_cookie=request.transaction_cookie,
            returned_state=values["state"],
            authorization_code="code",
        )


def test_redirected_token_and_jwks_responses_are_rejected() -> None:
    keys = _Keys()
    nonce_holder: dict[str, str] = {}
    store = InMemoryOIDCStateStore()
    redeemer = _Redeemer(
        lambda _: keys.token(nonce_holder["nonce"]),
        endpoint="https://attacker.invalid/token",
    )
    auth = OIDCAuthenticator(
        _configuration(),
        store,
        redeemer,
        _Fetcher(keys.jwks),
        clock=lambda: _NOW,
    )
    request = auth.begin(source_digest=_SOURCE_DIGEST)
    values = _authorization_values(request.redirect_url)
    nonce_holder["nonce"] = values["nonce"]
    with pytest.raises(OIDCError, match="token_exchange_failed"):
        auth.complete(
            transaction_cookie=request.transaction_cookie,
            returned_state=values["state"],
            authorization_code="code",
        )

    auth, _, _, fetcher = _authenticator(keys)
    fetcher.uri = "https://attacker.invalid/jwks"
    request = auth.begin(source_digest=_SOURCE_DIGEST)
    values = _authorization_values(request.redirect_url)
    with pytest.raises(OIDCError, match="jwks_fetch_failed"):
        auth.complete(
            transaction_cookie=request.transaction_cookie,
            returned_state=values["state"],
            authorization_code="code",
        )


def test_sessions_expire_and_logout_revokes_immediately() -> None:
    keys = _Keys()
    current = [_NOW]
    auth, _, _, _ = _authenticator(keys, clock=lambda: current[0])
    request = auth.begin(source_digest=_SOURCE_DIGEST)
    values = _authorization_values(request.redirect_url)
    result = auth.complete(
        transaction_cookie=request.transaction_cookie,
        returned_state=values["state"],
        authorization_code="code",
    )
    assert auth.logout(result.session_cookie) is True
    assert auth.logout(result.session_cookie) is False
    with pytest.raises(OIDCError, match="invalid_session"):
        auth.authenticate_session(result.session_cookie)

    request = auth.begin(source_digest=_SOURCE_DIGEST)
    values = _authorization_values(request.redirect_url)
    result = auth.complete(
        transaction_cookie=request.transaction_cookie,
        returned_state=values["state"],
        authorization_code="code",
    )
    current[0] = result.expires_at
    with pytest.raises(OIDCError, match="invalid_session"):
        auth.authenticate_session(result.session_cookie)


def test_configuration_rejects_insecure_endpoints_and_ambiguous_entitlements() -> None:
    values: dict[str, Any] = {
        "issuer": _ISSUER,
        "authorization_endpoint": f"{_ISSUER}/authorize",
        "token_endpoint": f"{_ISSUER}/token",
        "jwks_uri": f"{_ISSUER}/jwks",
        "client_id": _CLIENT_ID,
        "redirect_uri": _REDIRECT,
        "entitlements": (
            GroupEntitlement(
                group="secops",
                tenant_id="acme-bank",
                roles=frozenset({"viewer"}),
            ),
        ),
    }
    for field_name in (
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "redirect_uri",
    ):
        invalid = dict(values)
        invalid[field_name] = "http://insecure.example.test/path"
        with pytest.raises(ValueError, match="HTTPS"):
            OIDCConfiguration(**invalid)
    duplicate = dict(values)
    duplicate["entitlements"] = (
        values["entitlements"][0],
        values["entitlements"][0],
    )
    with pytest.raises(ValueError, match="unique"):
        OIDCConfiguration(**duplicate)


def test_error_and_sensitive_model_representations_do_not_leak_secrets() -> None:
    error = OIDCError("token_exchange_failed")
    assert "secret-code" not in str(error)
    assert "secret-code" not in repr(error)
    request = TokenExchangeRequest(
        endpoint=f"{_ISSUER}/token",
        client_id=_CLIENT_ID,
        redirect_uri=_REDIRECT,
        code="secret-code",
        code_verifier="secret-verifier",
    )
    rendered = repr(request)
    assert "secret-code" not in rendered
    assert "secret-verifier" not in rendered
    assert rendered.count("<redacted>") == 2
