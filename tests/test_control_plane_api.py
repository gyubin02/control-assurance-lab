from __future__ import annotations

import ipaddress
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from assurance_lab.control_plane.api import (
    APIIdentityError,
    AuthenticatedSession,
    OIDCIdentityResolver,
    create_control_plane_app,
)
from assurance_lab.control_plane.deployment import (
    DeploymentApplyError,
    DeploymentApplyRequest,
    DeploymentReconciler,
    DeploymentTarget,
    DeploymentTargetAcknowledgement,
)
from assurance_lab.control_plane.models import (
    Actor,
    ControlConfiguration,
    DeploymentWorkerIdentity,
    ElasticSourceConfiguration,
    EvidenceConfiguration,
    Role,
    ScheduleConfiguration,
)
from assurance_lab.control_plane.oidc import (
    AuthenticationResult,
    AuthorizationRequest,
    OIDCError,
)
from assurance_lab.control_plane.service import ControlPlaneService
from assurance_lab.control_plane.store import SQLiteControlPlaneStore

_NOW = datetime(2026, 7, 29, 3, 0, tzinfo=UTC)
_ORIGIN = "https://control.acme.example"
_CSRF = "a" * 43
_SESSION_DIGEST = f"sha256:{'1' * 64}"
_PROFILE_DIGEST = f"sha256:{'2' * 64}"
_TARGET_RECEIPT_DIGEST = f"sha256:{'3' * 64}"
_WORKER_CREDENTIAL_DIGEST = f"sha256:{'4' * 64}"


def _actor(
    subject: str,
    *roles: Role,
    tenant_id: str = "acme-bank",
    groups: tuple[str, ...] = (),
) -> Actor:
    return Actor(
        tenant_id=tenant_id,
        subject=subject,
        display_name=subject.removeprefix("oidc:").title(),
        roles=frozenset(roles),
        groups=groups,
        authenticated_at=_NOW,
        session_id_digest=_SESSION_DIGEST,
        mfa=True,
    )


def _configuration(*, tenant_id: str = "acme-bank") -> ControlConfiguration:
    return ControlConfiguration(
        tenant_id=tenant_id,
        control_id="elastic-alert-completeness",
        display_name="Elastic alert completeness",
        description="Proves that a declared alert window closed without partial shards.",
        environment="production",
        owner_group="secops/platform",
        control_profile_id="alert-window-v1",
        control_profile_digest=_PROFILE_DIGEST,
        source=ElasticSourceConfiguration(
            endpoint_origin="https://elastic.acme.example",
            index_alias=".alerts-security.alerts-default",
            parent_credential_ref="vault://kv/secops/elastic-jit-parent",
        ),
        schedule=ScheduleConfiguration(
            interval_seconds=900,
            collection_lag_seconds=120,
            window_seconds=900,
        ),
        evidence=EvidenceConfiguration(
            custody_ref="s3-object-lock://assurance-evidence/acme-bank/elastic",
            signing_key_ref="vault-transit://assurance/signing/elastic-prod",
            retention_days=365,
        ),
    )


class _CookieIdentityResolver:
    def __init__(self, sessions: dict[str, AuthenticatedSession]) -> None:
        self._sessions = sessions

    async def resolve(self, request: Request) -> AuthenticatedSession:
        token = request.cookies.get("__Host-control_session")
        if token is None or token not in self._sessions:
            raise APIIdentityError("opaque session is absent or invalid")
        return self._sessions[token]


class _UnavailableIdentityResolver:
    async def resolve(self, request: Request) -> AuthenticatedSession:
        del request
        raise RuntimeError("private identity backend diagnostic")


class _FakeOIDCCoordinator:
    issuer = "https://id.acme.example/oidc"
    redirect_uri = f"{_ORIGIN}/auth/callback"

    def __init__(self) -> None:
        self.completed: list[tuple[str, str, str]] = []
        self.sessions = {"s" * 43: _actor("oidc:alice", "viewer")}
        self.logged_out: list[str] = []
        self.login_sources: list[str] = []
        self.begin_error: OIDCError | None = None

    def begin(self, *, source_digest: str) -> AuthorizationRequest:
        assert source_digest.startswith("hmac-sha256:")
        self.login_sources.append(source_digest)
        if self.begin_error is not None:
            raise self.begin_error
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
        if transaction_cookie != "t" * 43:
            raise OIDCError("invalid_transaction")
        self.completed.append(
            (transaction_cookie, returned_state, authorization_code)
        )
        return AuthenticationResult(
            actor=self.sessions["s" * 43],
            session_cookie="s" * 43,
            expires_at=datetime(2030, 1, 1, tzinfo=UTC),
        )

    def authenticate_session(self, session_cookie: str) -> Actor:
        try:
            return self.sessions[session_cookie]
        except KeyError as exc:
            raise OIDCError("invalid_session") from exc

    def logout(self, session_cookie: str) -> bool:
        self.logged_out.append(session_cookie)
        return self.sessions.pop(session_cookie, None) is not None


def _application(tmp_path: Path) -> tuple[TestClient, dict[str, AuthenticatedSession]]:
    sessions = {
        "editor-session": AuthenticatedSession(
            _actor(
                "oidc:alice",
                "viewer",
                "editor",
                groups=("secops/platform",),
            ),
            _CSRF,
        ),
        "approver-session": AuthenticatedSession(
            _actor("oidc:bob", "viewer", "approver"),
            _CSRF,
        ),
        "deployer-session": AuthenticatedSession(
            _actor("oidc:carol", "viewer", "deployer"),
            _CSRF,
        ),
        "auditor-session": AuthenticatedSession(
            _actor("oidc:auditor", "viewer", "auditor"),
            _CSRF,
        ),
        "foreign-session": AuthenticatedSession(
            _actor("oidc:foreign", "viewer", tenant_id="other-bank"),
            _CSRF,
        ),
    }
    service = ControlPlaneService(
        SQLiteControlPlaneStore(tmp_path / "control-plane.sqlite3"),
        now=lambda: _NOW,
    )
    application = create_control_plane_app(
        service,
        _CookieIdentityResolver(sessions),
        public_origin=_ORIGIN,
    )
    return TestClient(application, base_url=_ORIGIN), sessions


def _oidc_application(tmp_path: Path) -> tuple[TestClient, _FakeOIDCCoordinator]:
    coordinator = _FakeOIDCCoordinator()
    resolver = OIDCIdentityResolver(coordinator, csrf_key=b"k" * 32)
    service = ControlPlaneService(
        SQLiteControlPlaneStore(tmp_path / "oidc-control-plane.sqlite3"),
        now=lambda: _NOW,
    )
    application = create_control_plane_app(
        service,
        resolver,
        public_origin=_ORIGIN,
        oidc_authenticator=coordinator,
    )
    return TestClient(application, base_url=_ORIGIN), coordinator


def _use_session(client: TestClient, token: str) -> None:
    client.cookies.clear()
    client.cookies.set(
        "__Host-control_session",
        token,
        domain="control.acme.example",
        path="/",
    )


def _mutation_headers() -> dict[str, str]:
    return {
        "content-type": "application/json",
        "origin": _ORIGIN,
        "sec-fetch-site": "same-origin",
        "x-csrf-token": _CSRF,
    }


def _approved_revision_via_api(
    client: TestClient,
    configuration: ControlConfiguration,
    *,
    parent_revision_id: str | None,
) -> dict[str, object]:
    _use_session(client, "editor-session")
    created = client.post(
        "/api/v1/revisions",
        json={
            "configuration": configuration.model_dump(mode="json"),
            "expected_parent_revision_id": parent_revision_id,
        },
        headers=_mutation_headers(),
    )
    assert created.status_code == 201
    submitted = client.post(
        f"/api/v1/revisions/{created.json()['revision_id']}/submit",
        json={"expected_state_version": created.json()["state_version"]},
        headers=_mutation_headers(),
    )
    assert submitted.status_code == 200
    _use_session(client, "approver-session")
    approved = client.post(
        f"/api/v1/revisions/{created.json()['revision_id']}/decision",
        json={
            "comment": "Exact target and recovery path reviewed.",
            "decision": "approved",
            "expected_state_version": submitted.json()["state_version"],
        },
        headers=_mutation_headers(),
    )
    assert approved.status_code == 200
    return cast(dict[str, object], approved.json()["revision"])


def _reconciler(
    tmp_path: Path,
    target: DeploymentTarget,
    *,
    max_attempts: int = 8,
) -> DeploymentReconciler:
    return DeploymentReconciler(
        SQLiteControlPlaneStore(tmp_path / "control-plane.sqlite3"),
        target,
        DeploymentWorkerIdentity(
            tenant_id="acme-bank",
            worker_id="api-test-reconciler",
            credential_digest=_WORKER_CREDENTIAL_DIGEST,
        ),
        now=lambda: _NOW,
        token_bytes=lambda _: b"w" * 32,
        max_attempts=max_attempts,
    )


class _AppliedTarget:
    def ensure_applied(
        self,
        request: DeploymentApplyRequest,
    ) -> DeploymentTargetAcknowledgement:
        return DeploymentTargetAcknowledgement(
            operation_id=request.operation_id,
            lease_fence=request.lease_fence,
            applied_configuration_digest=request.configuration_digest,
            target_receipt_digest=_TARGET_RECEIPT_DIGEST,
        )


class _FailedTarget:
    def ensure_applied(
        self,
        request: DeploymentApplyRequest,
    ) -> DeploymentTargetAcknowledgement:
        del request
        raise DeploymentApplyError("target-rejected", retryable=False)


def test_api_has_no_fallback_identity_and_sets_browser_boundaries(tmp_path: Path) -> None:
    client, _ = _application(tmp_path)

    unauthenticated = client.get("/api/v1/session")

    assert unauthenticated.status_code == 401
    assert unauthenticated.json() == {
        "error": {
            "code": "authentication-required",
            "message": "A valid SSO session is required.",
        }
    }
    assert unauthenticated.headers["cache-control"] == "no-store"
    assert unauthenticated.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in unauthenticated.headers["content-security-policy"]
    assert client.get("/health/live").json() == {"status": "ok"}
    assert client.get("/openapi.json").status_code == 404
    invalid_host = TestClient(
        client.app,
        base_url="https://untrusted.example",
    ).get("/health/live")
    assert invalid_host.status_code == 400
    assert invalid_host.json()["error"]["code"] == "invalid-host"
    assert invalid_host.headers["cache-control"] == "no-store"
    assert invalid_host.headers["x-content-type-options"] == "nosniff"


def test_identity_backend_failure_is_not_misreported_as_bad_authentication(
    tmp_path: Path,
) -> None:
    service = ControlPlaneService(
        SQLiteControlPlaneStore(tmp_path / "unavailable-identity.sqlite3"),
        now=lambda: _NOW,
    )
    application = create_control_plane_app(
        service,
        _UnavailableIdentityResolver(),
        public_origin=_ORIGIN,
    )

    response = TestClient(application, base_url=_ORIGIN).get("/api/v1/session")

    assert response.status_code == 503
    assert response.json() == {
        "error": {
            "code": "identity-service-unavailable",
            "message": "The SSO session service is temporarily unavailable.",
        }
    }
    assert "private identity backend diagnostic" not in response.text


def test_api_enforces_origin_json_csrf_and_bounded_request_stream(tmp_path: Path) -> None:
    client, _ = _application(tmp_path)
    _use_session(client, "editor-session")
    body = {"configuration": _configuration().model_dump(mode="json")}

    assert client.post("/api/v1/revisions", json=body).status_code == 403
    assert (
        client.post(
            "/api/v1/revisions",
            json=body,
            headers={**_mutation_headers(), "origin": "https://evil.example"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/revisions",
            content=b"{}",
            headers={
                **_mutation_headers(),
                "content-type": "text/plain",
            },
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/revisions",
            json=body,
            headers={**_mutation_headers(), "x-csrf-token": "b" * 43},
        ).status_code
        == 403
    )

    def oversized_stream() -> Iterator[bytes]:
        yield b"{" + (b" " * (1024 * 1024))
        yield b"}"

    oversized = client.post(
        "/api/v1/revisions",
        content=oversized_stream(),
        headers=_mutation_headers(),
    )
    assert oversized.status_code == 413
    assert oversized.json()["error"]["code"] == "request-too-large"
    assert oversized.headers["cache-control"] == "no-store"
    assert oversized.headers["x-frame-options"] == "DENY"


def test_non_default_public_origin_port_is_enforced_exactly(tmp_path: Path) -> None:
    origin = "https://control.acme.example:8443"
    service = ControlPlaneService(
        SQLiteControlPlaneStore(tmp_path / "port-control-plane.sqlite3"),
        now=lambda: _NOW,
    )
    application = create_control_plane_app(
        service,
        _CookieIdentityResolver({}),
        public_origin=origin,
    )

    accepted = TestClient(application, base_url=origin).get("/health/live")
    rejected = TestClient(
        application,
        base_url="https://control.acme.example",
    ).get("/health/live")

    assert accepted.status_code == 200
    assert rejected.status_code == 400
    assert rejected.json()["error"]["code"] == "invalid-host"


def test_complete_maker_checker_api_lifecycle_is_secret_free(tmp_path: Path) -> None:
    client, _ = _application(tmp_path)
    _use_session(client, "editor-session")

    session = client.get("/api/v1/session")
    assert session.status_code == 200
    assert session.json()["identity"]["roles"] == ["editor", "viewer"]
    created = client.post(
        "/api/v1/revisions",
        json={"configuration": _configuration().model_dump(mode="json")},
        headers=_mutation_headers(),
    )
    assert created.status_code == 201
    revision = created.json()
    assert revision["state"] == "draft"
    assert "configuration_bytes" not in revision
    assert "secret" not in created.text.lower()

    submitted = client.post(
        f"/api/v1/revisions/{revision['revision_id']}/submit",
        json={"expected_state_version": revision["state_version"]},
        headers=_mutation_headers(),
    )
    assert submitted.status_code == 200
    revision = submitted.json()
    assert revision["state"] == "submitted"

    _use_session(client, "approver-session")
    blank_decision = client.post(
        f"/api/v1/revisions/{revision['revision_id']}/decision",
        json={
            "comment": " \n\t ",
            "decision": "approved",
            "expected_state_version": revision["state_version"],
        },
        headers=_mutation_headers(),
    )
    assert blank_decision.status_code == 422
    assert blank_decision.json()["error"]["code"] == "invalid-request"
    invalid_decision = client.post(
        f"/api/v1/revisions/{revision['revision_id']}/decision",
        json={
            "comment": "Attempt an invalid transition.",
            "decision": "bypass",
            "expected_state_version": revision["state_version"],
        },
        headers=_mutation_headers(),
    )
    assert invalid_decision.status_code == 422
    assert "literal" not in invalid_decision.text
    approved = client.post(
        f"/api/v1/revisions/{revision['revision_id']}/decision",
        json={
            "comment": "Read-only source scope and rollback evidence reviewed.",
            "decision": "approved",
            "expected_state_version": revision["state_version"],
        },
        headers=_mutation_headers(),
    )
    assert approved.status_code == 200
    revision = approved.json()["revision"]
    assert revision["state"] == "approved"

    _use_session(client, "deployer-session")
    activated = client.post(
        f"/api/v1/revisions/{revision['revision_id']}/activate",
        json={"expected_deployment_version": None},
        headers=_mutation_headers(),
    )
    assert activated.status_code == 202
    activation = activated.json()
    assert activation["desired_deployment"]["deployment_version"] == 1
    assert (
        activation["desired_deployment"]["semantics"]
        == "desired-state-pointer"
    )
    assert activation["operation"]["state"] == "pending"
    assert activation["operation"]["retry_of_operation_id"] is None
    active = client.get("/api/v1/controls/elastic-alert-completeness/active")
    assert active.json()["revision_id"] == revision["revision_id"]
    assert active.json()["semantics"] == "desired-state-pointer"
    desired = client.get("/api/v1/controls/elastic-alert-completeness/desired")
    assert desired.json() == active.json()
    operations = client.get(
        "/api/v1/controls/elastic-alert-completeness/deployment-operations"
    )
    assert operations.status_code == 200
    assert len(operations.json()["items"]) == 1
    pending = operations.json()["items"][0]
    assert pending["state"] == "pending"
    assert pending["revision_id"] == revision["revision_id"]
    assert pending["semantics"] == "runtime-application-operation"
    assert client.get(
        f"/api/v1/deployment-operations/{pending['operation_id']}"
    ).json() == pending
    assert (
        client.get(
            "/api/v1/controls/elastic-alert-completeness/applied"
        ).status_code
        == 404
    )
    controls = client.get("/api/v1/controls")
    assert controls.status_code == 200
    assert len(controls.json()["items"]) == 1
    assert (
        controls.json()["items"][0]["active_deployment"]["revision_id"]
        == revision["revision_id"]
    )

    _use_session(client, "auditor-session")
    audit = client.get("/api/v1/audit")
    assert audit.status_code == 200
    assert [item["action"] for item in audit.json()["items"]] == [
        "revision-created",
        "revision-submitted",
        "revision-approved",
        "revision-activated",
    ]
    verified = client.get("/api/v1/audit/verification")
    assert verified.status_code == 200
    assert verified.json()["verified"] is True
    assert verified.json()["event_count"] == 4
    assert verified.json()["head_event_digest"] == audit.json()["items"][-1][
        "event_digest"
    ]
    assert client.get("/api/v1/audit?limit=0").status_code == 422
    assert client.get("/api/v1/audit?limit=1001").status_code == 422
    assert client.get("/api/v1/audit?after_sequence=-1").status_code == 422


def test_deployment_api_separates_desired_applied_and_rollback_lineage(
    tmp_path: Path,
) -> None:
    client, _ = _application(tmp_path)
    first = _approved_revision_via_api(
        client,
        _configuration(),
        parent_revision_id=None,
    )
    _use_session(client, "deployer-session")
    selected = client.post(
        f"/api/v1/revisions/{first['revision_id']}/activate",
        json={"expected_deployment_version": None},
        headers=_mutation_headers(),
    )
    assert selected.status_code == 202
    assert (
        selected.json()["desired_deployment"]["semantics"]
        == "desired-state-pointer"
    )
    assert selected.json()["operation"]["state"] == "pending"
    assert (
        selected.json()["operation"]["configuration_digest"]
        == selected.json()["desired_deployment"]["configuration_digest"]
    )
    pending = client.get(
        "/api/v1/controls/elastic-alert-completeness/deployment-operations"
    ).json()["items"][0]
    assert pending["state"] == "pending"
    assert (
        client.get(
            "/api/v1/controls/elastic-alert-completeness/applied"
        ).status_code
        == 404
    )

    applied = _reconciler(tmp_path, _AppliedTarget()).run_once()
    assert applied is not None and applied.state == "applied"
    observed = client.get(
        "/api/v1/controls/elastic-alert-completeness/applied"
    )
    assert observed.status_code == 200
    assert observed.json()["operation_id"] == pending["operation_id"]
    assert observed.json()["applied_configuration_digest"] == first[
        "configuration_digest"
    ]
    assert observed.json()["target_receipt_digest"] == _TARGET_RECEIPT_DIGEST

    second_configuration = _configuration().model_copy(
        update={"display_name": "Elastic alert completeness v2"}
    )
    second = _approved_revision_via_api(
        client,
        second_configuration,
        parent_revision_id=str(first["revision_id"]),
    )
    _use_session(client, "deployer-session")
    second_selection = client.post(
        f"/api/v1/revisions/{second['revision_id']}/activate",
        json={"expected_deployment_version": 1},
        headers=_mutation_headers(),
    )
    assert second_selection.status_code == 202
    second_pending = client.get(
        "/api/v1/controls/elastic-alert-completeness/deployment-operations"
    ).json()["items"][0]
    assert second_pending["predecessor_operation_id"] == pending["operation_id"]
    second_applied = _reconciler(tmp_path, _AppliedTarget()).run_once()
    assert second_applied is not None and second_applied.state == "applied"

    rollback = client.post(
        f"/api/v1/revisions/{first['revision_id']}/rollback",
        json={
            "expected_predecessor_operation_id": second_applied.operation_id,
        },
        headers=_mutation_headers(),
    )
    assert rollback.status_code == 202
    assert rollback.json()["kind"] == "rollback"
    assert rollback.json()["state"] == "pending"
    assert (
        rollback.json()["predecessor_operation_id"]
        == second_applied.operation_id
    )
    assert rollback.json()["revision_id"] == first["revision_id"]


def test_terminal_deployment_retry_is_new_intent_and_remains_mfa_authorized(
    tmp_path: Path,
) -> None:
    client, sessions = _application(tmp_path)
    revision = _approved_revision_via_api(
        client,
        _configuration(),
        parent_revision_id=None,
    )
    _use_session(client, "deployer-session")
    assert (
        client.post(
            f"/api/v1/revisions/{revision['revision_id']}/activate",
            json={"expected_deployment_version": None},
            headers=_mutation_headers(),
        ).status_code
        == 202
    )
    failed = _reconciler(
        tmp_path,
        _FailedTarget(),
        max_attempts=1,
    ).run_once()
    assert failed is not None and failed.state == "failed"
    observed = client.get(f"/api/v1/deployment-operations/{failed.operation_id}")
    assert observed.status_code == 200
    assert observed.json()["failure_digest"] == failed.failure_digest
    assert "target-rejected" not in observed.text

    sessions["deployer-session"] = AuthenticatedSession(
        sessions["deployer-session"].actor.model_copy(update={"mfa": False}),
        _CSRF,
    )
    denied = client.post(
        f"/api/v1/deployment-operations/{failed.operation_id}/retry",
        json={},
        headers=_mutation_headers(),
    )
    assert denied.status_code == 403

    sessions["deployer-session"] = AuthenticatedSession(
        _actor("oidc:carol", "viewer", "deployer"),
        _CSRF,
    )
    retried = client.post(
        f"/api/v1/deployment-operations/{failed.operation_id}/retry",
        json={},
        headers=_mutation_headers(),
    )
    assert retried.status_code == 202
    assert retried.json()["operation_id"] != failed.operation_id
    assert retried.json()["operation_sequence"] == failed.operation_sequence + 1
    assert retried.json()["state"] == "pending"
    assert retried.json()["retry_of_operation_id"] == failed.operation_id
    assert client.post(
        f"/api/v1/deployment-operations/{failed.operation_id}/retry",
        json={},
        headers=_mutation_headers(),
    ).status_code == 409


def test_control_ui_describes_pointer_semantics_and_separate_diffs(
    tmp_path: Path,
) -> None:
    client, _ = _application(tmp_path)

    page = client.get("/control/")

    assert page.status_code == 200
    assert "활성 포인터 대비" in page.text
    assert "직전 세대 대비" in page.text
    assert "RUNTIME APPLICATION" in page.text
    assert "배포 상태" in page.text
    assert 'id="deployment-operation-list"' in page.text
    assert 'id="audit-verification"' in page.text
    assert "실행 반영을 뜻하지 않음" in page.text
    assert 'id="configuration-form"' in page.text
    assert (
        'id="configuration-form" class="configuration-form" '
        'autocomplete="off" hidden'
    ) in page.text


def test_api_hides_cross_tenant_objects_and_internal_failures(tmp_path: Path) -> None:
    client, _ = _application(tmp_path)
    _use_session(client, "editor-session")
    created = client.post(
        "/api/v1/revisions",
        json={"configuration": _configuration().model_dump(mode="json")},
        headers=_mutation_headers(),
    ).json()

    _use_session(client, "foreign-session")
    assert client.get("/api/v1/controls").json() == {"items": []}
    hidden = client.get(f"/api/v1/revisions/{created['revision_id']}")
    assert hidden.status_code == 404
    assert hidden.json()["error"]["message"] == (
        "The requested control-plane object was not found."
    )
    malformed = client.get("/api/v1/revisions/not-a-digest")
    assert malformed.status_code == 404
    assert "digest" not in malformed.text.lower()


def test_oidc_http_flow_uses_host_cookies_and_never_open_redirects(tmp_path: Path) -> None:
    client, coordinator = _oidc_application(tmp_path)

    login = client.get(
        "/auth/login?return_to=https%3A%2F%2Fevil.example%2Fsteal",
        follow_redirects=False,
    )
    assert login.status_code == 303
    assert login.headers["location"].startswith(
        "https://id.acme.example/oidc/authorize?"
    )
    transaction_cookie = login.headers["set-cookie"]
    assert "__Host-control_oidc_transaction=" in transaction_cookie
    assert "HttpOnly" in transaction_cookie
    assert "Secure" in transaction_cookie
    assert "SameSite=lax" in transaction_cookie
    assert "Domain=" not in transaction_cookie

    callback = client.get(
        (
            "/auth/callback?code=one-time-code&state="
            f"{'a' * 43}&iss=https%3A%2F%2Fid.acme.example%2Foidc"
        ),
        follow_redirects=False,
    )
    assert callback.status_code == 303
    assert callback.headers["location"] == "/control/"
    assert coordinator.completed == [("t" * 43, "a" * 43, "one-time-code")]
    cookies = callback.headers.get_list("set-cookie")
    assert any("__Host-control_session=" in value for value in cookies)
    assert any(
        "__Host-control_oidc_transaction=" in value and "Max-Age=0" in value
        for value in cookies
    )

    session = client.get("/api/v1/session")
    assert session.status_code == 200
    assert session.json()["identity"]["subject"] == "oidc:alice"
    csrf = session.json()["csrf_token"]
    assert len(csrf) == 43

    logout = client.post(
        "/auth/logout",
        json={},
        headers={
            "origin": _ORIGIN,
            "sec-fetch-site": "same-origin",
            "x-csrf-token": csrf,
        },
    )
    assert logout.status_code == 204
    assert coordinator.logged_out == ["s" * 43]
    assert client.get("/api/v1/session").status_code == 401


def test_login_source_digest_ignores_spoofed_forwarding_unless_peer_is_trusted() -> None:
    coordinator = _FakeOIDCCoordinator()
    resolver = OIDCIdentityResolver(coordinator, csrf_key=b"k" * 32)
    trusted = (ipaddress.ip_network("10.0.0.0/8"),)

    def request(
        peer: str,
        *forwarded: bytes,
    ) -> Request:
        headers = [(b"host", b"control.acme.example")]
        headers.extend((b"x-forwarded-for", value) for value in forwarded)
        return Request(
            {
                "type": "http",
                "http_version": "1.1",
                "method": "GET",
                "scheme": "https",
                "path": "/auth/login",
                "raw_path": b"/auth/login",
                "query_string": b"",
                "headers": headers,
                "client": (peer, 12345),
                "server": ("control.acme.example", 443),
            }
        )

    direct = resolver.login_source_digest(
        request("198.51.100.8"),
        trusted_proxy_networks=trusted,
    )
    spoofed = resolver.login_source_digest(
        request("198.51.100.8", b"203.0.113.90"),
        trusted_proxy_networks=trusted,
    )
    forwarded = resolver.login_source_digest(
        request("10.1.2.3", b"203.0.113.90"),
        trusted_proxy_networks=trusted,
    )
    another = resolver.login_source_digest(
        request("10.1.2.3", b"203.0.113.91"),
        trusted_proxy_networks=trusted,
    )

    assert direct == spoofed
    assert forwarded != direct
    assert another != forwarded
    assert direct.startswith("hmac-sha256:")
    assert "198.51.100.8" not in direct
    with pytest.raises(OIDCError, match="login_source_unavailable"):
        resolver.login_source_digest(
            request("10.1.2.3", b"198.51.100.8, 203.0.113.90"),
            trusted_proxy_networks=trusted,
        )
    with pytest.raises(OIDCError, match="login_source_unavailable"):
        resolver.login_source_digest(
            request("10.1.2.3", b"198.51.100.8", b"203.0.113.90"),
            trusted_proxy_networks=trusted,
        )


def test_login_admission_returns_generic_429_and_backend_failure_503(
    tmp_path: Path,
) -> None:
    client, coordinator = _oidc_application(tmp_path)
    coordinator.begin_error = OIDCError("login_admission_limited")

    limited = client.get("/auth/login", follow_redirects=False)

    assert limited.status_code == 429
    assert limited.headers["retry-after"] == "5"
    assert limited.json() == {
        "error": {
            "code": "login-capacity-exceeded",
            "message": "Sign-in capacity is temporarily full.",
        }
    }

    coordinator.begin_error = OIDCError("state_store_protection_failed")
    unavailable = client.get("/auth/login", follow_redirects=False)

    assert unavailable.status_code == 503
    assert unavailable.json() == {
        "error": {
            "code": "login-service-unavailable",
            "message": "Sign-in is temporarily unavailable.",
        }
    }
    assert "state_store" not in unavailable.text


def test_oidc_callback_fails_closed_on_duplicates_mixup_and_oversize(
    tmp_path: Path,
) -> None:
    client, coordinator = _oidc_application(tmp_path)

    for query in (
        f"code=one&code=two&state={'a' * 43}",
        f"code=one&state={'a' * 43}&iss=https%3A%2F%2Fevil.example",
        f"error=access_denied&state={'a' * 43}",
        f"code={'x' * 4097}&state={'a' * 43}",
    ):
        client.get("/auth/login", follow_redirects=False)
        failed = client.get(f"/auth/callback?{query}", follow_redirects=False)
        assert failed.status_code == 401
        assert failed.json()["error"]["code"] == "authentication-failed"
        assert "one" not in failed.text
    assert coordinator.completed == []


def test_oidc_routes_require_the_same_resolver_and_callback_origin(tmp_path: Path) -> None:
    coordinator = _FakeOIDCCoordinator()
    service = ControlPlaneService(
        SQLiteControlPlaneStore(tmp_path / "misconfigured.sqlite3"),
        now=lambda: _NOW,
    )
    with pytest.raises(TypeError, match="share one authenticator"):
        create_control_plane_app(
            service,
            _CookieIdentityResolver({}),
            public_origin=_ORIGIN,
            oidc_authenticator=coordinator,
        )

    coordinator.redirect_uri = "https://another.example/auth/callback"
    resolver = OIDCIdentityResolver(coordinator, csrf_key=b"k" * 32)
    with pytest.raises(ValueError, match="redirect URI"):
        create_control_plane_app(
            service,
            resolver,
            public_origin=_ORIGIN,
            oidc_authenticator=coordinator,
        )
