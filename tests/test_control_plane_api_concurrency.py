from __future__ import annotations

import asyncio
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import Request

from assurance_lab.control_plane.api import (
    AuthenticatedSession,
    OIDCIdentityResolver,
    create_control_plane_app,
)
from assurance_lab.control_plane.models import Actor
from assurance_lab.control_plane.oidc import (
    AuthenticationResult,
    AuthorizationRequest,
    OIDCError,
)
from assurance_lab.control_plane.service import ControlPlaneService
from assurance_lab.control_plane.store import SQLiteControlPlaneStore

_ORIGIN = "https://control.acme.example"
_NOW = datetime(2026, 7, 29, 3, 0, tzinfo=UTC)
_SESSION_DIGEST = f"sha256:{'1' * 64}"
_CSRF = "a" * 43


def _actor() -> Actor:
    return Actor(
        tenant_id="acme-bank",
        subject="oidc:alice",
        display_name="Alice",
        roles=frozenset({"viewer"}),
        groups=(),
        authenticated_at=_NOW,
        session_id_digest=_SESSION_DIGEST,
        mfa=True,
    )


class _SyncIdentityResolver:
    def resolve(self, request: Request) -> AuthenticatedSession:
        if request.cookies.get("__Host-control_session") != "opaque":
            raise OIDCError("invalid_session")
        return AuthenticatedSession(_actor(), _CSRF)


class _BlockingStore:
    """Delegate every repository operation except the one under test."""

    def __init__(
        self,
        delegate: SQLiteControlPlaneStore,
        entered: threading.Event,
        release: threading.Event,
    ) -> None:
        self._delegate = delegate
        self._entered = entered
        self._release = release

    def __getattr__(self, name: str) -> Any:
        return getattr(self._delegate, name)

    def list_controls(self, *, tenant_id: str, limit: int = 100) -> tuple[Any, ...]:
        self._entered.set()
        if not self._release.wait(5):
            raise RuntimeError("private blocking-store diagnostic")
        return self._delegate.list_controls(tenant_id=tenant_id, limit=limit)


class _ThreadRecordingOIDC:
    issuer = "https://id.acme.example/oidc"
    redirect_uri = f"{_ORIGIN}/auth/callback"

    def __init__(self) -> None:
        self.method_threads: dict[str, list[int]] = {
            "authenticate_session": [],
            "begin": [],
            "complete": [],
            "logout": [],
        }

    def begin(self, *, source_digest: str) -> AuthorizationRequest:
        assert source_digest.startswith("hmac-sha256:")
        self.method_threads["begin"].append(threading.get_ident())
        return AuthorizationRequest(
            redirect_url=(
                "https://id.acme.example/oidc/authorize"
                "?client_id=control-assurance&state=provider-state"
            ),
            transaction_cookie="t" * 43,
            expires_at=datetime(2030, 1, 1, tzinfo=UTC),
        )

    def complete(
        self,
        *,
        transaction_cookie: str,
        returned_state: str,
        authorization_code: str,
    ) -> AuthenticationResult:
        self.method_threads["complete"].append(threading.get_ident())
        if (
            transaction_cookie != "t" * 43
            or returned_state != "a" * 43
            or authorization_code != "one-time-code"
        ):
            raise OIDCError("invalid_transaction")
        return AuthenticationResult(
            actor=_actor(),
            session_cookie="s" * 43,
            expires_at=datetime(2030, 1, 1, tzinfo=UTC),
        )

    def authenticate_session(self, session_cookie: str) -> Actor:
        self.method_threads["authenticate_session"].append(threading.get_ident())
        if session_cookie != "s" * 43:
            raise OIDCError("invalid_session")
        return _actor()

    def logout(self, session_cookie: str) -> bool:
        self.method_threads["logout"].append(threading.get_ident())
        return session_cookie == "s" * 43


class _BlockingCallbackOIDC(_ThreadRecordingOIDC):
    def __init__(self) -> None:
        super().__init__()
        self.complete_entered = threading.Event()
        self.complete_release = threading.Event()
        self.complete_calls = 0

    def complete(
        self,
        *,
        transaction_cookie: str,
        returned_state: str,
        authorization_code: str,
    ) -> AuthenticationResult:
        self.complete_calls += 1
        self.complete_entered.set()
        if not self.complete_release.wait(5):
            raise RuntimeError("private token endpoint diagnostic")
        return super().complete(
            transaction_cookie=transaction_cookie,
            returned_state=returned_state,
            authorization_code=authorization_code,
        )


async def _wait_for_event(event: threading.Event) -> None:
    for _ in range(200):
        if event.is_set():
            return
        await asyncio.sleep(0.005)
    raise AssertionError("blocking test double was not entered")


def test_blocking_store_is_bounded_while_liveness_and_static_assets_remain_live(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        entered = threading.Event()
        release = threading.Event()
        store = _BlockingStore(
            SQLiteControlPlaneStore(tmp_path / "blocking.sqlite3"),
            entered,
            release,
        )
        service = ControlPlaneService(store, now=lambda: _NOW)
        application = create_control_plane_app(
            service,
            _SyncIdentityResolver(),
            public_origin=_ORIGIN,
            offload_workers=1,
            offload_queue_capacity=0,
            offload_admission_timeout_seconds=0.03,
        )
        transport = httpx.ASGITransport(app=application)
        headers = {"cookie": "__Host-control_session=opaque"}

        async with httpx.AsyncClient(
            transport=transport,
            base_url=_ORIGIN,
        ) as client:
            blocked = asyncio.create_task(client.get("/api/v1/controls", headers=headers))
            try:
                await _wait_for_event(entered)

                live = await asyncio.wait_for(client.get("/health/live"), 0.5)
                static = await asyncio.wait_for(
                    client.get("/control/assets/model.js"),
                    0.5,
                )
                started = time.monotonic()
                saturated = await client.get("/api/v1/controls", headers=headers)
                elapsed = time.monotonic() - started

                assert live.status_code == 200
                assert live.json() == {"status": "ok"}
                assert static.status_code == 200
                assert "export function" in static.text
                assert saturated.status_code == 503
                assert saturated.json() == {
                    "error": {
                        "code": "service-busy",
                        "message": "The control-plane service is temporarily busy.",
                    }
                }
                assert elapsed < 0.5
                assert "blocking-store" not in saturated.text
                assert "diagnostic" not in saturated.text
            finally:
                release.set()
            completed = await asyncio.wait_for(blocked, 1)
            assert completed.status_code == 200
            assert completed.json() == {"items": []}

    asyncio.run(scenario())


def test_oidc_session_and_login_callback_logout_use_the_same_worker_bulkhead(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        coordinator = _ThreadRecordingOIDC()
        service = ControlPlaneService(
            SQLiteControlPlaneStore(tmp_path / "oidc-threads.sqlite3"),
            now=lambda: _NOW,
        )
        application = create_control_plane_app(
            service,
            OIDCIdentityResolver(coordinator, csrf_key=b"k" * 32),
            public_origin=_ORIGIN,
            oidc_authenticator=coordinator,
            offload_workers=1,
            offload_queue_capacity=1,
        )
        transport = httpx.ASGITransport(app=application)
        event_loop_thread = threading.get_ident()

        async with httpx.AsyncClient(
            transport=transport,
            base_url=_ORIGIN,
        ) as client:
            login = await client.get("/auth/login", follow_redirects=False)
            assert login.status_code == 303
            callback = await client.get(
                (
                    "/auth/callback?code=one-time-code&state="
                    f"{'a' * 43}&iss=https%3A%2F%2Fid.acme.example%2Foidc"
                ),
                follow_redirects=False,
            )
            assert callback.status_code == 303
            session = await client.get("/api/v1/session")
            assert session.status_code == 200
            logout = await client.post(
                "/auth/logout",
                json={},
                headers={
                    "origin": _ORIGIN,
                    "sec-fetch-site": "same-origin",
                    "x-csrf-token": session.json()["csrf_token"],
                },
            )
            assert logout.status_code == 204

        assert set(coordinator.method_threads) == {
            "authenticate_session",
            "begin",
            "complete",
            "logout",
        }
        assert len(coordinator.method_threads["authenticate_session"]) == 2
        assert len(coordinator.method_threads["begin"]) == 1
        assert len(coordinator.method_threads["complete"]) == 1
        assert len(coordinator.method_threads["logout"]) == 1
        for method_threads in coordinator.method_threads.values():
            assert all(thread_id != event_loop_thread for thread_id in method_threads)

    asyncio.run(scenario())


def test_cancelled_oidc_callback_never_retries_ambiguous_token_redemption(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        coordinator = _BlockingCallbackOIDC()
        service = ControlPlaneService(
            SQLiteControlPlaneStore(tmp_path / "oidc-cancel.sqlite3"),
            now=lambda: _NOW,
        )
        application = create_control_plane_app(
            service,
            OIDCIdentityResolver(coordinator, csrf_key=b"k" * 32),
            public_origin=_ORIGIN,
            oidc_authenticator=coordinator,
            offload_workers=1,
            offload_queue_capacity=0,
            offload_admission_timeout_seconds=0.03,
        )
        transport = httpx.ASGITransport(app=application)

        async with httpx.AsyncClient(
            transport=transport,
            base_url=_ORIGIN,
        ) as client:
            await client.get("/auth/login", follow_redirects=False)
            callback = asyncio.create_task(
                client.get(
                    (
                        "/auth/callback?code=one-time-code&state="
                        f"{'a' * 43}&iss=https%3A%2F%2Fid.acme.example%2Foidc"
                    ),
                    follow_redirects=False,
                )
            )
            await _wait_for_event(coordinator.complete_entered)
            callback.cancel()
            await asyncio.sleep(0.05)

            assert coordinator.complete_calls == 1
            live = await asyncio.wait_for(client.get("/health/live"), 0.5)
            assert live.status_code == 200
            saturated_login = await client.get(
                "/auth/login",
                follow_redirects=False,
            )
            assert saturated_login.status_code == 503
            assert saturated_login.json() == {
                "error": {
                    "code": "service-busy",
                    "message": "The control-plane service is temporarily busy.",
                }
            }
            assert "token endpoint" not in saturated_login.text
            assert coordinator.complete_calls == 1

            coordinator.complete_release.set()
            with pytest.raises(asyncio.CancelledError):
                await callback
            assert coordinator.complete_calls == 1
            assert len(coordinator.method_threads["complete"]) == 1

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"offload_workers": 0}, "offload_workers"),
        ({"offload_workers": True}, "offload_workers"),
        ({"offload_queue_capacity": -1}, "offload_queue_capacity"),
        (
            {"offload_admission_timeout_seconds": float("inf")},
            "offload_admission_timeout_seconds",
        ),
    ],
)
def test_offload_bounds_are_validated_at_composition(
    tmp_path: Path,
    kwargs: dict[str, object],
    message: str,
) -> None:
    service = ControlPlaneService(
        SQLiteControlPlaneStore(tmp_path / f"{message}.sqlite3"),
        now=lambda: _NOW,
    )
    with pytest.raises(ValueError, match=message):
        create_control_plane_app(
            service,
            _SyncIdentityResolver(),
            public_origin=_ORIGIN,
            **kwargs,  # type: ignore[arg-type]
        )
