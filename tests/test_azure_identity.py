from __future__ import annotations

import http.client
import os
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from email.message import Message
from pathlib import Path
from typing import Any, cast

import pytest

from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.key_management import azure_identity as identity
from assurance_lab.key_management.azure_key_vault import (
    AZURE_KEY_VAULT_SCOPE,
    AzureKeyVaultBearerToken,
    AzureKeyVaultCryptoClient,
    AzureKeyVaultTokenProvider,
)

_TENANT = "11111111-2222-4333-8444-555555555555"
_CLIENT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
_ISSUER = "https://oidc.prod-aks.azure.com/tenant/cluster/"
_SUBJECT = "system:serviceaccount:control-assurance:control-assurance"
_ACCESS_TOKEN = "opaque-key-vault-token.123"


def _b64url(value: bytes) -> bytes:
    import base64

    return base64.urlsafe_b64encode(value).rstrip(b"=")


def _assertion(
    now: int,
    *,
    header_updates: dict[str, Any] | None = None,
    claim_updates: dict[str, Any] | None = None,
    remove_claim: str | None = None,
) -> bytes:
    header: dict[str, Any] = {"alg": "RS256", "kid": "projected-key", "typ": "JWT"}
    claims: dict[str, Any] = {
        "aud": [identity.AZURE_WORKLOAD_IDENTITY_AUDIENCE],
        "exp": now + 3_600,
        "iat": now,
        "iss": _ISSUER,
        "jti": "projected-token-id",
        "kubernetes.io": {
            "namespace": "control-assurance",
            "serviceaccount": {"name": "control-assurance", "uid": "fake-uid"},
        },
        "nbf": now,
        "sub": _SUBJECT,
    }
    if header_updates:
        header.update(header_updates)
    if claim_updates:
        claims.update(claim_updates)
    if remove_claim:
        del claims[remove_claim]
    return b".".join(
        (
            _b64url(canonical_json_bytes(header)),
            _b64url(canonical_json_bytes(claims)),
            _b64url(b"test-signature-not-a-live-credential"),
        )
    )


class _Clock:
    def __init__(self, *, monotonic: float = 1_000.0, epoch: int = 2_000_000_000) -> None:
        self.monotonic_value = monotonic
        self.epoch_value = epoch

    def monotonic(self) -> float:
        return self.monotonic_value

    def epoch(self) -> int:
        return self.epoch_value

    def advance(self, seconds: int) -> None:
        self.monotonic_value += float(seconds)
        self.epoch_value += seconds


def _success_response(
    *,
    token: str = _ACCESS_TOKEN,
    expires_in: int = 3_599,
    extra: dict[str, Any] | None = None,
    headers: tuple[tuple[str, str], ...] = (("content-type", "application/json"),),
) -> identity._TokenHTTPResponse:
    body: dict[str, Any] = {
        "access_token": token,
        "expires_in": expires_in,
        "token_type": "Bearer",
    }
    if extra:
        body.update(extra)
    return identity._TokenHTTPResponse(
        status=200,
        headers=headers,
        body=canonical_json_bytes(body),
    )


class _Transport:
    def __init__(self, response: identity._TokenHTTPResponse | None = None) -> None:
        self.response = response or _success_response()
        self.calls: list[tuple[str, bytes, tuple[tuple[str, str], ...], float]] = []

    def request(
        self,
        *,
        endpoint: str,
        body: bytes,
        headers: tuple[tuple[str, str], ...],
        deadline: float,
    ) -> identity._TokenHTTPResponse:
        self.calls.append((endpoint, body, headers, deadline))
        return self.response


def _write_token(
    root: Path,
    token: bytes,
    *,
    mode: int = 0o400,
    name: str = "token",
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / name
    path.write_bytes(token)
    path.chmod(mode)
    return path


def _provider(
    *,
    token_file: Path,
    mount_root: Path,
    clock: _Clock,
    transport: identity._TokenHTTPTransport,
    owner_uid: int | None = None,
    group_gid: int | None = None,
    mode: int = 0o400,
) -> identity.AzureWorkloadIdentityTokenProvider:
    return identity.AzureWorkloadIdentityTokenProvider(
        tenant_id=_TENANT,
        client_id=_CLIENT,
        token_file=token_file,
        token_mount_root=mount_root,
        expected_issuer=_ISSUER,
        expected_subject=_SUBJECT,
        expected_file_owner_uid=os.getuid() if owner_uid is None else owner_uid,
        expected_file_group_gid=group_gid,
        expected_file_mode=mode,
        _transport=transport,
        _monotonic=clock.monotonic,
        _epoch_seconds=clock.epoch,
    )


def _get(
    provider: identity.AzureWorkloadIdentityTokenProvider,
    clock: _Clock,
) -> AzureKeyVaultBearerToken:
    return provider.get_token(
        scope=AZURE_KEY_VAULT_SCOPE,
        deadline=clock.monotonic() + 30.0,
    )


def test_exact_endpoint_scope_and_federated_assertion_form(tmp_path: Path) -> None:
    clock = _Clock()
    root = tmp_path / "projected"
    token_path = _write_token(root, _assertion(clock.epoch()))
    transport = _Transport()
    provider = _provider(
        token_file=token_path,
        mount_root=root,
        clock=clock,
        transport=transport,
    )

    token = _get(provider, clock)

    assert len(transport.calls) == 1
    endpoint, body, headers, deadline = transport.calls[0]
    assert endpoint == (f"https://login.microsoftonline.com/{_TENANT}/oauth2/v2.0/token")
    assert headers == (
        ("accept", "application/json"),
        ("accept-encoding", "identity"),
        ("content-type", "application/x-www-form-urlencoded"),
    )
    assert deadline == clock.monotonic() + 30.0
    pairs = urllib.parse.parse_qsl(body.decode("ascii"), keep_blank_values=True)
    assert pairs == [
        ("client_id", _CLIENT),
        ("scope", "https://vault.azure.net/.default"),
        ("grant_type", "client_credentials"),
        ("client_assertion_type", identity.CLIENT_ASSERTION_TYPE),
        ("client_assertion", _assertion(clock.epoch()).decode("ascii")),
    ]
    assert b"client_secret" not in body
    assert token._authorization_header() == f"Bearer {_ACCESS_TOKEN}"
    assert repr(token) == "AzureKeyVaultBearerToken(<redacted>)"
    assert repr(provider) == "AzureWorkloadIdentityTokenProvider(<configured>)"
    assert _ACCESS_TOKEN not in repr(token)


def test_wrong_scope_and_expired_deadline_never_reach_transport(tmp_path: Path) -> None:
    clock = _Clock()
    root = tmp_path / "projected"
    token_path = _write_token(root, _assertion(clock.epoch()))
    transport = _Transport()
    provider = _provider(
        token_file=token_path,
        mount_root=root,
        clock=clock,
        transport=transport,
    )

    with pytest.raises(identity.AzureWorkloadIdentityError, match="exact Azure"):
        provider.get_token(
            scope="https://management.azure.com/.default",
            deadline=clock.monotonic() + 30.0,
        )
    with pytest.raises(identity.AzureWorkloadIdentityError, match="deadline"):
        provider.get_token(
            scope=AZURE_KEY_VAULT_SCOPE,
            deadline=clock.monotonic(),
        )
    assert transport.calls == []


def test_constructor_has_no_client_secret_surface(tmp_path: Path) -> None:
    root = tmp_path / "projected"
    token_path = _write_token(root, _assertion(2_000_000_000))

    with pytest.raises(TypeError, match="client_secret"):
        identity.AzureWorkloadIdentityTokenProvider(
            tenant_id=_TENANT,
            client_id=_CLIENT,
            token_file=token_path,
            token_mount_root=root,
            expected_issuer=_ISSUER,
            expected_subject=_SUBJECT,
            expected_file_owner_uid=os.getuid(),
            expected_file_mode=0o400,
            client_secret="forbidden",  # type: ignore[call-arg]
        )


def test_provider_satisfies_key_vault_token_boundary(tmp_path: Path) -> None:
    clock = _Clock()
    root = tmp_path / "projected"
    token_path = _write_token(root, _assertion(clock.epoch()))
    provider = _provider(
        token_file=token_path,
        mount_root=root,
        clock=clock,
        transport=_Transport(),
    )

    assert isinstance(provider, AzureKeyVaultTokenProvider)
    client = AzureKeyVaultCryptoClient(
        provider,
        vault_name="assurance-prod",
        key_name="control-assurance",
        key_version="a" * 32,
    )
    assert client.key_reference.endswith("/keys/control-assurance/" + ("a" * 32))


def test_kubernetes_atomic_writer_symlinks_are_bounded_to_mount(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    root = tmp_path / "projected"
    generation = root / "..2026_07_29_00_00_00"
    token_target = _write_token(
        generation,
        _assertion(clock.epoch()),
        mode=0o440,
    )
    del token_target
    (root / "..data").symlink_to(generation.name)
    token_path = root / "token"
    token_path.symlink_to("..data/token")
    transport = _Transport()

    provider = _provider(
        token_file=token_path,
        mount_root=root,
        clock=clock,
        transport=transport,
        group_gid=os.getgid(),
        mode=0o440,
    )

    assert _get(provider, clock)._authorization_header().endswith(_ACCESS_TOKEN)
    assert len(transport.calls) == 1


def test_projected_symlink_escape_is_rejected_before_network(tmp_path: Path) -> None:
    clock = _Clock()
    root = tmp_path / "projected"
    root.mkdir()
    outside = _write_token(tmp_path / "outside", _assertion(clock.epoch()))
    token_path = root / "token"
    token_path.symlink_to(outside)
    transport = _Transport()
    provider = _provider(
        token_file=token_path,
        mount_root=root,
        clock=clock,
        transport=transport,
    )

    with pytest.raises(identity.AzureWorkloadIdentityError, match="escapes"):
        _get(provider, clock)
    assert transport.calls == []


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("owner", "owner"),
        ("group", "group"),
        ("mode", "mode"),
        ("hardlink", "hard-link"),
        ("small", "size"),
        ("large", "size"),
    ],
)
def test_projected_file_metadata_is_fail_closed(
    tmp_path: Path,
    case: str,
    expected: str,
) -> None:
    clock = _Clock()
    root = tmp_path / case
    token = _assertion(clock.epoch())
    if case == "small":
        token = b"a"
    if case == "large":
        token = b"a" * (128 * 1024 + 1)
    token_path = _write_token(root, token, mode=0o600 if case == "mode" else 0o400)
    if case == "hardlink":
        os.link(token_path, root / "second-link")
    transport = _Transport()
    provider = _provider(
        token_file=token_path,
        mount_root=root,
        clock=clock,
        transport=transport,
        owner_uid=os.getuid() + 1 if case == "owner" else None,
        group_gid=os.getgid() + 1 if case == "group" else None,
    )

    with pytest.raises(identity.AzureWorkloadIdentityError, match=expected):
        _get(provider, clock)
    assert transport.calls == []


def test_file_change_during_secure_open_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock()
    root = tmp_path / "projected"
    token_path = _write_token(root, _assertion(clock.epoch()))
    transport = _Transport()
    original_open = identity._secure_open_resolved

    def changing_open(path: Path) -> int:
        descriptor = original_open(path)
        token_path.chmod(0o600)
        token_path.write_bytes(_assertion(clock.epoch(), claim_updates={"jti": "changed"}))
        token_path.chmod(0o400)
        return descriptor

    monkeypatch.setattr(identity, "_secure_open_resolved", changing_open)
    provider = _provider(
        token_file=token_path,
        mount_root=root,
        clock=clock,
        transport=transport,
    )

    with pytest.raises(identity.AzureWorkloadIdentityError, match="changed"):
        _get(provider, clock)
    assert transport.calls == []


@pytest.mark.parametrize(
    "token",
    [
        lambda now: _assertion(now, header_updates={"alg": "HS256"}),
        lambda now: _assertion(now, header_updates={"crit": ["alg"]}),
        lambda now: _assertion(now, claim_updates={"aud": "other-audience"}),
        lambda now: _assertion(
            now,
            claim_updates={"aud": [identity.AZURE_WORKLOAD_IDENTITY_AUDIENCE, "other"]},
        ),
        lambda now: _assertion(now, claim_updates={"iss": "https://other.invalid/"}),
        lambda now: _assertion(now, claim_updates={"sub": "another-workload"}),
        lambda now: _assertion(now, claim_updates={"exp": now + 30}),
        lambda now: _assertion(now, claim_updates={"iat": now - 4_000}),
        lambda now: _assertion(now, claim_updates={"iat": True}),
        lambda now: _assertion(now, remove_claim="nbf"),
        lambda now: _assertion(now) + b"\n",
    ],
)
def test_projected_jwt_validation_fails_before_exchange(
    tmp_path: Path,
    token: Any,
) -> None:
    clock = _Clock()
    root = tmp_path / "projected"
    token_path = _write_token(root, token(clock.epoch()))
    transport = _Transport()
    provider = _provider(
        token_file=token_path,
        mount_root=root,
        clock=clock,
        transport=transport,
    )

    with pytest.raises(identity.AzureWorkloadIdentityError):
        _get(provider, clock)
    assert transport.calls == []


@pytest.mark.parametrize(
    "response",
    [
        identity._TokenHTTPResponse(
            status=302,
            headers=(("content-type", "application/json"),),
            body=b"{}",
        ),
        identity._TokenHTTPResponse(
            status=200,
            headers=(),
            body=canonical_json_bytes(
                {
                    "access_token": _ACCESS_TOKEN,
                    "expires_in": 3_599,
                    "token_type": "Bearer",
                }
            ),
        ),
        _success_response(
            headers=(
                ("content-encoding", "gzip"),
                ("content-type", "application/json"),
            )
        ),
        _success_response(
            headers=(
                ("content-type", "application/json"),
                ("content-type", "application/json"),
            )
        ),
        _success_response(extra={"refresh_token": "forbidden"}),
        _success_response(expires_in=30),
        _success_response(expires_in=4_000),
        _success_response(token="token with spaces"),
        _success_response(token="토큰"),
        identity._TokenHTTPResponse(
            status=200,
            headers=(("content-type", "application/json"),),
            body=b'{"access_token":',
        ),
        identity._TokenHTTPResponse(
            status=200,
            headers=(("content-type", "application/json"),),
            body=b"x" * (256 * 1024 + 1),
        ),
        identity._TokenHTTPResponse(
            status=200,
            headers=(
                ("a", "1"),
                ("b", "2"),
                ("c", "3"),
                ("d", "4"),
                ("e", "5"),
            ),
            body=b"{}",
        ),
    ],
)
def test_response_contract_is_bounded_strict_and_fail_closed(
    tmp_path: Path,
    response: identity._TokenHTTPResponse,
) -> None:
    clock = _Clock()
    root = tmp_path / "projected"
    token_path = _write_token(root, _assertion(clock.epoch()))
    transport = _Transport(response)
    provider = _provider(
        token_file=token_path,
        mount_root=root,
        clock=clock,
        transport=transport,
    )

    with pytest.raises(identity.AzureWorkloadIdentityError):
        _get(provider, clock)
    assert len(transport.calls) == 1


class _DeadlineAdvancingTransport(_Transport):
    def __init__(self, clock: _Clock) -> None:
        super().__init__()
        self.clock = clock

    def request(
        self,
        *,
        endpoint: str,
        body: bytes,
        headers: tuple[tuple[str, str], ...],
        deadline: float,
    ) -> identity._TokenHTTPResponse:
        response = super().request(
            endpoint=endpoint,
            body=body,
            headers=headers,
            deadline=deadline,
        )
        self.clock.advance(31)
        return response


def test_response_arriving_after_deadline_is_not_cached(tmp_path: Path) -> None:
    clock = _Clock()
    root = tmp_path / "projected"
    token_path = _write_token(root, _assertion(clock.epoch()))
    transport = _DeadlineAdvancingTransport(clock)
    provider = _provider(
        token_file=token_path,
        mount_root=root,
        clock=clock,
        transport=transport,
    )

    with pytest.raises(identity.AzureWorkloadIdentityError) as caught:
        provider.get_token(
            scope=AZURE_KEY_VAULT_SCOPE,
            deadline=clock.monotonic() + 30.0,
        )
    assert caught.value.stage == "deadline"
    assert len(transport.calls) == 1


class _ReflectingTransport:
    def __init__(self, *, location: str) -> None:
        self.location = location
        self.calls = 0
        self.assertion = ""

    def request(
        self,
        *,
        endpoint: str,
        body: bytes,
        headers: tuple[tuple[str, str], ...],
        deadline: float,
    ) -> identity._TokenHTTPResponse:
        del endpoint, headers, deadline
        self.calls += 1
        self.assertion = dict(urllib.parse.parse_qsl(body.decode("ascii")))["client_assertion"]
        if self.location == "body":
            return identity._TokenHTTPResponse(
                status=400,
                headers=(("content-type", "application/json"),),
                body=self.assertion.encode("ascii"),
            )
        if self.location == "header":
            return identity._TokenHTTPResponse(
                status=400,
                headers=(("request-id", self.assertion),),
                body=b"{}",
            )
        raise RuntimeError(self.assertion)


@pytest.mark.parametrize("location", ["body", "header", "exception"])
def test_assertion_reflection_and_transport_exceptions_are_redacted(
    tmp_path: Path,
    location: str,
) -> None:
    clock = _Clock()
    root = tmp_path / "projected"
    raw_assertion = _assertion(clock.epoch())
    token_path = _write_token(root, raw_assertion)
    transport = _ReflectingTransport(location=location)
    provider = _provider(
        token_file=token_path,
        mount_root=root,
        clock=clock,
        transport=transport,
    )

    with pytest.raises(identity.AzureWorkloadIdentityError) as caught:
        _get(provider, clock)
    wire_secret = raw_assertion.decode("ascii")
    assert wire_secret not in str(caught.value)
    assert wire_secret not in repr(caught.value)
    assert transport.calls == 1


def test_access_token_reflection_in_headers_is_rejected_and_redacted(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    root = tmp_path / "projected"
    token_path = _write_token(root, _assertion(clock.epoch()))
    response = _success_response(
        headers=(
            ("content-type", "application/json"),
            ("request-id", _ACCESS_TOKEN),
        )
    )
    provider = _provider(
        token_file=token_path,
        mount_root=root,
        clock=clock,
        transport=_Transport(response),
    )

    with pytest.raises(identity.AzureWorkloadIdentityError) as caught:
        _get(provider, clock)
    assert _ACCESS_TOKEN not in str(caught.value)
    assert _ACCESS_TOKEN not in repr(caught.value)


def test_token_is_cached_then_refreshed_once_inside_skew(tmp_path: Path) -> None:
    clock = _Clock()
    root = tmp_path / "projected"
    token_path = _write_token(root, _assertion(clock.epoch()))
    transport = _Transport()
    provider = _provider(
        token_file=token_path,
        mount_root=root,
        clock=clock,
        transport=transport,
    )

    first = _get(provider, clock)
    assert _get(provider, clock) is first
    assert len(transport.calls) == 1

    clock.advance(3_480)
    refreshed = _get(provider, clock)

    assert refreshed is not first
    assert len(transport.calls) == 2


class _BlockingTransport:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls = 0
        self.started = threading.Event()
        self.release = threading.Event()
        self.lock = threading.Lock()

    def request(
        self,
        *,
        endpoint: str,
        body: bytes,
        headers: tuple[tuple[str, str], ...],
        deadline: float,
    ) -> identity._TokenHTTPResponse:
        del endpoint, body, headers, deadline
        with self.lock:
            self.calls += 1
        self.started.set()
        assert self.release.wait(timeout=5)
        if self.fail:
            raise RuntimeError("upstream secret-shaped diagnostic")
        return _success_response()


def test_concurrent_callers_share_one_refresh_and_one_cached_object(
    tmp_path: Path,
) -> None:
    now = int(time.time())
    root = tmp_path / "projected"
    token_path = _write_token(root, _assertion(now))
    transport = _BlockingTransport()
    provider = identity.AzureWorkloadIdentityTokenProvider(
        tenant_id=_TENANT,
        client_id=_CLIENT,
        token_file=token_path,
        token_mount_root=root,
        expected_issuer=_ISSUER,
        expected_subject=_SUBJECT,
        expected_file_owner_uid=os.getuid(),
        expected_file_mode=0o400,
        _transport=transport,
    )
    callers = 16
    barrier = threading.Barrier(callers)

    def call() -> object:
        barrier.wait()
        return provider.get_token(
            scope=AZURE_KEY_VAULT_SCOPE,
            deadline=time.monotonic() + 5.0,
        )

    with ThreadPoolExecutor(max_workers=callers) as pool:
        futures = [pool.submit(call) for _ in range(callers)]
        assert transport.started.wait(timeout=5)
        time.sleep(0.1)
        transport.release.set()
        tokens = [future.result(timeout=5) for future in futures]

    assert transport.calls == 1
    assert len({id(token) for token in tokens}) == 1


def test_concurrent_waiters_share_a_redacted_refresh_failure(
    tmp_path: Path,
) -> None:
    now = int(time.time())
    root = tmp_path / "projected"
    token_path = _write_token(root, _assertion(now))
    transport = _BlockingTransport(fail=True)
    provider = identity.AzureWorkloadIdentityTokenProvider(
        tenant_id=_TENANT,
        client_id=_CLIENT,
        token_file=token_path,
        token_mount_root=root,
        expected_issuer=_ISSUER,
        expected_subject=_SUBJECT,
        expected_file_owner_uid=os.getuid(),
        expected_file_mode=0o400,
        _transport=transport,
    )
    callers = 12
    barrier = threading.Barrier(callers)

    def call() -> identity.AzureWorkloadIdentityError:
        barrier.wait()
        try:
            provider.get_token(
                scope=AZURE_KEY_VAULT_SCOPE,
                deadline=time.monotonic() + 5.0,
            )
        except identity.AzureWorkloadIdentityError as exc:
            return exc
        raise AssertionError("token acquisition unexpectedly succeeded")

    with ThreadPoolExecutor(max_workers=callers) as pool:
        futures = [pool.submit(call) for _ in range(callers)]
        assert transport.started.wait(timeout=5)
        time.sleep(0.1)
        transport.release.set()
        failures = [future.result(timeout=5) for future in futures]

    assert transport.calls == 1
    assert {failure.stage for failure in failures} == {"transport"}
    assert {str(failure) for failure in failures} == {"workload token transport failed safely"}
    assert all("secret-shaped" not in repr(failure) for failure in failures)


def test_builtin_transport_disables_environment_proxy_and_redirects() -> None:
    context = ssl.create_default_context()
    transport = identity._UrllibTokenTransport(
        endpoint=f"{identity.AZURE_PUBLIC_AUTHORITY_ORIGIN}/{_TENANT}/oauth2/v2.0/token",
        timeout_seconds=30,
        ssl_context=context,
    )

    handlers = cast(Any, transport._opener).handlers
    proxy_handlers = [
        handler for handler in handlers if isinstance(handler, urllib.request.ProxyHandler)
    ]
    redirect_handlers = [
        handler for handler in handlers if isinstance(handler, identity._NoRedirect)
    ]
    # Supplying ProxyHandler({}) suppresses urllib's default environment
    # proxy handler; because the explicit map is empty it installs no handler.
    assert proxy_handlers == []
    assert len(redirect_handlers) == 1


class _WireResponse:
    def __init__(
        self,
        *,
        status: int = 200,
        body: bytes = b'{"ok":true}',
        headers: tuple[tuple[str, str], ...] = (("Content-Type", "application/json"),),
        read_error: BaseException | None = None,
    ) -> None:
        self.status = status
        self.headers = Message()
        for name, value in headers:
            self.headers.add_header(name, value)
        self._body = body
        self._offset = 0
        self._read_error = read_error
        self.closed = False

    def read1(self, size: int) -> bytes:
        if self._read_error is not None:
            raise self._read_error
        chunk = self._body[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk

    read = read1

    def close(self) -> None:
        self.closed = True


class _WireOpener:
    def __init__(
        self,
        response: _WireResponse | None = None,
        *,
        error: BaseException | None = None,
    ) -> None:
        self.response = response or _WireResponse()
        self.error = error
        self.calls: list[tuple[urllib.request.Request, float]] = []

    def open(
        self,
        request: urllib.request.Request,
        *,
        timeout: float,
    ) -> _WireResponse:
        self.calls.append((request, timeout))
        if self.error is not None:
            raise self.error
        return self.response


def _wire_transport(
    response: _WireResponse | None = None,
    *,
    error: BaseException | None = None,
) -> tuple[identity._UrllibTokenTransport, _WireOpener]:
    endpoint = f"{identity.AZURE_PUBLIC_AUTHORITY_ORIGIN}/{_TENANT}/oauth2/v2.0/token"
    transport = identity._UrllibTokenTransport(
        endpoint=endpoint,
        timeout_seconds=30,
        ssl_context=ssl.create_default_context(),
    )
    opener = _WireOpener(response, error=error)
    transport._opener = cast(Any, opener)
    return transport, opener


def test_builtin_transport_sends_one_exact_post_and_bounds_response() -> None:
    response = _WireResponse(
        status=200,
        body=b'{"token":"opaque"}',
        headers=(
            ("Content-Length", "18"),
            ("Content-Type", "application/json"),
            ("Request-Id", "request-123"),
        ),
    )
    transport, opener = _wire_transport(response)
    endpoint = f"{identity.AZURE_PUBLIC_AUTHORITY_ORIGIN}/{_TENANT}/oauth2/v2.0/token"

    result = transport.request(
        endpoint=endpoint,
        body=b"client_id=exact",
        headers=(
            ("accept", "application/json"),
            ("accept-encoding", "identity"),
            ("content-type", "application/x-www-form-urlencoded"),
        ),
        deadline=time.monotonic() + 60.0,
    )

    assert result == identity._TokenHTTPResponse(
        status=200,
        headers=(
            ("content-type", "application/json"),
            ("request-id", "request-123"),
        ),
        body=b'{"token":"opaque"}',
    )
    assert len(opener.calls) == 1
    request, timeout = opener.calls[0]
    assert request.full_url == endpoint
    assert request.method == "POST"
    assert request.data == b"client_id=exact"
    request_headers = {name.lower(): value for name, value in request.header_items()}
    assert request_headers == {
        "accept": "application/json",
        "accept-encoding": "identity",
        "content-type": "application/x-www-form-urlencoded",
    }
    assert 0 < timeout <= 30
    assert response.closed is True


def test_builtin_transport_rejects_endpoint_drift_and_expired_deadline() -> None:
    transport, opener = _wire_transport()

    with pytest.raises(identity.AzureWorkloadIdentityError, match="pinned endpoint"):
        transport.request(
            endpoint="https://evil.invalid/token",
            body=b"",
            headers=(),
            deadline=time.monotonic() + 10.0,
        )
    with pytest.raises(identity.AzureWorkloadIdentityError, match="deadline"):
        transport.request(
            endpoint=(f"{identity.AZURE_PUBLIC_AUTHORITY_ORIGIN}/{_TENANT}/oauth2/v2.0/token"),
            body=b"",
            headers=(),
            deadline=time.monotonic() - 1.0,
        )
    assert opener.calls == []


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (
            _WireResponse(headers=(("Content-Length", "not-an-integer"),)),
            "length is invalid",
        ),
        (
            _WireResponse(headers=(("Content-Length", str(256 * 1024 + 1)),)),
            "byte limit",
        ),
        (
            _WireResponse(
                headers=(("Content-Length", "1"), ("Content-Length", "1")),
            ),
            "duplicate length",
        ),
        (
            _WireResponse(
                headers=(
                    ("Content-Type", "application/json"),
                    ("Content-Type", "application/json"),
                ),
            ),
            "duplicate security",
        ),
        (
            _WireResponse(body=b"x" * (256 * 1024 + 1)),
            "byte limit",
        ),
        (
            _WireResponse(read_error=OSError("secret-shaped read error")),
            "read completely",
        ),
    ],
)
def test_builtin_transport_fails_closed_on_ambiguous_wire_responses(
    response: _WireResponse,
    expected: str,
) -> None:
    transport, opener = _wire_transport(response)
    endpoint = f"{identity.AZURE_PUBLIC_AUTHORITY_ORIGIN}/{_TENANT}/oauth2/v2.0/token"

    with pytest.raises(identity.AzureWorkloadIdentityError, match=expected) as caught:
        transport.request(
            endpoint=endpoint,
            body=b"assertion=redacted",
            headers=(),
            deadline=time.monotonic() + 60.0,
        )
    assert "secret-shaped" not in repr(caught.value)
    assert len(opener.calls) == 1
    assert response.closed is True


@pytest.mark.parametrize(
    "error",
    [
        TimeoutError("secret-shaped timeout"),
        urllib.error.URLError("secret-shaped URL failure"),
        http.client.HTTPException("secret-shaped HTTP failure"),
        OSError("secret-shaped OS failure"),
    ],
)
def test_builtin_transport_redacts_network_exceptions(error: BaseException) -> None:
    transport, opener = _wire_transport(error=error)
    endpoint = f"{identity.AZURE_PUBLIC_AUTHORITY_ORIGIN}/{_TENANT}/oauth2/v2.0/token"

    with pytest.raises(identity.AzureWorkloadIdentityError) as caught:
        transport.request(
            endpoint=endpoint,
            body=b"assertion=redacted",
            headers=(),
            deadline=time.monotonic() + 60.0,
        )
    assert caught.value.stage == "transport"
    assert "secret-shaped" not in repr(caught.value)
    assert len(opener.calls) == 1
