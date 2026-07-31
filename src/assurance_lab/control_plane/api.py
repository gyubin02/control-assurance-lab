"""Authenticated JSON API for the immutable configuration control plane.

The application does not contain a development-login fallback.  A deployment
must supply an identity resolver backed by the OIDC session subsystem.  The
browser receives only an opaque session cookie from that subsystem; this API
works with the already-validated :class:`Actor`.
"""

import base64
import hashlib
import hmac
import inspect
import ipaddress
import math
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from functools import partial
from importlib import resources
from typing import Annotated, Any, Literal, ParamSpec, Protocol, TypeVar, cast
from urllib.parse import urlsplit

import anyio
from fastapi import Depends, FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from assurance_lab.control_plane.models import Actor, ControlConfiguration
from assurance_lab.control_plane.oidc import (
    AuthenticationResult,
    AuthorizationRequest,
    OIDCError,
)
from assurance_lab.control_plane.service import (
    ControlPlaneAuthorizationError,
    ControlPlaneService,
)
from assurance_lab.control_plane.store import (
    ControlPlaneConflict,
    ControlPlaneIntegrityError,
    ControlPlaneNotFound,
    ControlPlaneStoreError,
)
from assurance_lab.evidence.canonical import strict_json_loads

_MAX_REQUEST_BYTES = 1024 * 1024
_CSRF_RE = re.compile(r"^[A-Za-z0-9_-]{43,128}$")
_ID_RE = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_DEFAULT_OFFLOAD_WORKERS = 8
_DEFAULT_OFFLOAD_QUEUE_CAPACITY = 32
_DEFAULT_OFFLOAD_ADMISSION_TIMEOUT_SECONDS = 0.25
_MAX_TRUSTED_PROXY_CIDRS = 32
_OIDC_BACKEND_ERROR_CODES = frozenset(
    {
        "state_store_integrity_failure",
        "state_store_protection_failed",
        "state_store_unavailable",
    }
)

_P = ParamSpec("_P")
_T = TypeVar("_T")


class APIIdentityError(PermissionError):
    pass


class APIIdentityServiceError(RuntimeError):
    pass


class APIOffloadSaturated(RuntimeError):
    """The bounded synchronous-call bulkhead could not admit more work."""


class _BoundedOffloadGateway:
    """One bounded gateway for synchronous work reached from ASGI handlers.

    ``_admission`` bounds running and queued calls together.  Once admitted, a
    call waits for the dedicated worker limiter without another deadline.  That
    distinction is deliberate: an in-flight state change must not be abandoned
    and retried merely because the client disconnected.
    """

    __slots__ = ("_admission", "_admission_timeout", "_workers")

    def __init__(
        self,
        *,
        workers: int,
        queue_capacity: int,
        admission_timeout_seconds: float,
    ) -> None:
        self._admission = anyio.Semaphore(workers + queue_capacity)
        self._workers = anyio.CapacityLimiter(workers)
        self._admission_timeout = admission_timeout_seconds

    async def run(
        self,
        function: Callable[_P, _T],
        *args: _P.args,
        **kwargs: _P.kwargs,
    ) -> _T:
        acquired = False
        with anyio.move_on_after(self._admission_timeout) as admission_scope:
            await self._admission.acquire()
            acquired = True
        if admission_scope.cancel_called or not acquired:
            raise APIOffloadSaturated("synchronous-call admission timed out")

        call = partial(function, *args, **kwargs)
        try:
            return await anyio.to_thread.run_sync(
                call,
                abandon_on_cancel=False,
                limiter=self._workers,
            )
        finally:
            self._admission.release()


@dataclass(frozen=True, slots=True)
class AuthenticatedSession:
    actor: Actor
    csrf_token: str

    def __post_init__(self) -> None:
        if type(self.actor) is not Actor:
            raise TypeError("authenticated session must contain an exact Actor")
        if type(self.csrf_token) is not str or _CSRF_RE.fullmatch(self.csrf_token) is None:
            raise ValueError("CSRF token is invalid")


class IdentityResolver(Protocol):
    def resolve(
        self,
        request: Request,
    ) -> AuthenticatedSession | Awaitable[AuthenticatedSession]:
        """Resolve an opaque browser session or fail without redirecting.

        Synchronous implementations are executed through the application's
        bounded offload gateway.  Asynchronous implementations must keep their
        own event-loop work non-blocking.
        """


class OIDCSessionCoordinator(Protocol):
    @property
    def issuer(self) -> str: ...

    @property
    def redirect_uri(self) -> str: ...

    def begin(self, *, source_digest: str) -> AuthorizationRequest: ...

    def complete(
        self,
        *,
        transaction_cookie: str,
        returned_state: str,
        authorization_code: str,
    ) -> AuthenticationResult: ...

    def authenticate_session(self, session_cookie: str) -> Actor: ...

    def logout(self, session_cookie: str) -> bool: ...


class OIDCIdentityResolver:
    """Resolve one opaque OIDC session and derive a server-bound CSRF token."""

    __slots__ = ("_authenticator", "_csrf_key", "_login_source_key")

    def __init__(
        self,
        authenticator: OIDCSessionCoordinator,
        *,
        csrf_key: bytes,
    ) -> None:
        required = (
            "authenticate_session",
            "begin",
            "complete",
            "logout",
        )
        if any(not callable(getattr(authenticator, name, None)) for name in required):
            raise TypeError("OIDC authenticator does not implement the session protocol")
        if type(csrf_key) is not bytes or len(csrf_key) < 32:
            raise ValueError("OIDC CSRF key must contain at least 256 bits")
        self._authenticator = authenticator
        self._csrf_key = csrf_key
        self._login_source_key = hmac.new(
            csrf_key,
            b"control-assurance/oidc-login-source-key/v1",
            hashlib.sha256,
        ).digest()

    @property
    def authenticator(self) -> OIDCSessionCoordinator:
        return self._authenticator

    def login_source_digest(
        self,
        request: Request,
        *,
        trusted_proxy_networks: tuple[
            ipaddress.IPv4Network | ipaddress.IPv6Network,
            ...,
        ],
    ) -> str:
        """Return a keyed digest of the transport-authenticated client source.

        The direct ASGI peer is authoritative by default.  A trusted proxy must
        be explicitly pinned by CIDR and must replace, rather than append to,
        one ``X-Forwarded-For`` header containing one IP address.
        """

        client = request.client
        if client is None:
            raise OIDCError("login_source_unavailable")
        peer = client.host
        if (
            type(peer) is not str
            or not peer
            or len(peer) > 255
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in peer)
        ):
            raise OIDCError("login_source_unavailable")
        try:
            peer_address = ipaddress.ip_address(peer)
        except ValueError:
            peer_address = None

        source_address = peer_address
        peer_is_trusted_proxy = (
            peer_address is not None
            and any(peer_address in network for network in trusted_proxy_networks)
        )
        if peer_is_trusted_proxy:
            forwarded_values = [
                value
                for name, value in request.scope.get("headers", ())
                if name.lower() == b"x-forwarded-for"
            ]
            if len(forwarded_values) != 1:
                raise OIDCError("login_source_unavailable")
            try:
                forwarded = forwarded_values[0].decode("ascii", errors="strict")
            except UnicodeDecodeError:
                raise OIDCError("login_source_unavailable") from None
            if (
                not forwarded
                or forwarded != forwarded.strip()
                or "," in forwarded
                or len(forwarded) > 45
            ):
                raise OIDCError("login_source_unavailable")
            try:
                source_address = ipaddress.ip_address(forwarded)
            except ValueError:
                raise OIDCError("login_source_unavailable") from None

        if source_address is None:
            material = b"peer-name\x00" + peer.lower().encode("ascii")
        else:
            family = b"\x04" if source_address.version == 4 else b"\x06"
            material = b"ip\x00" + family + source_address.packed
        digest = hmac.new(
            self._login_source_key,
            b"control-assurance/oidc-login-source/v1\x00" + material,
            hashlib.sha256,
        ).hexdigest()
        # This is an internal opaque identifier, not an HTTP route response.
        return f"hmac-sha256:{digest}"  # nosemgrep

    def resolve(self, request: Request) -> AuthenticatedSession:
        opaque = request.cookies.get("__Host-control_session")
        if opaque is None:
            raise APIIdentityError("OIDC session cookie is absent")
        try:
            actor = self._authenticator.authenticate_session(opaque)
        except OIDCError as exc:
            raise APIIdentityError("OIDC session is invalid") from exc
        csrf = (
            base64.urlsafe_b64encode(
                hmac.new(
                    self._csrf_key,
                    b"control-assurance/csrf/v1\x00" + opaque.encode("ascii"),
                    hashlib.sha256,
                ).digest()
            )
            .rstrip(b"=")
            .decode("ascii")
        )
        return AuthenticatedSession(actor=actor, csrf_token=csrf)


class _StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CreateRevisionRequest(_StrictRequest):
    configuration: ControlConfiguration
    expected_parent_revision_id: str | None = None


class StateVersionRequest(_StrictRequest):
    expected_state_version: int = Field(ge=0, le=2**63 - 1)


class DecisionRequest(StateVersionRequest):
    decision: Literal["approved", "rejected"]
    comment: Annotated[str, StringConstraints(min_length=1, max_length=2_000)]

    @field_validator("comment")
    @classmethod
    def reject_blank_comment(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("review comment must contain non-whitespace text")
        return value.strip()


class ActivateRequest(_StrictRequest):
    expected_deployment_version: int | None = Field(
        default=None,
        ge=1,
        le=2**63 - 1,
    )


class RollbackRequest(_StrictRequest):
    expected_predecessor_operation_id: Annotated[
        str,
        StringConstraints(pattern=r"^sha256:[a-f0-9]{64}$"),
    ]


class RetryDeploymentRequest(_StrictRequest):
    pass


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={
            "error": {
                "code": code,
                "message": message,
            }
        },
    )


def _revision_view(revision: Any) -> dict[str, Any]:
    return {
        "configuration": revision.configuration.model_dump(mode="json"),
        "configuration_digest": revision.configuration_digest,
        "control_id": revision.control_id,
        "created_at": revision.created_at.isoformat().replace("+00:00", "Z"),
        "created_by": revision.created_by,
        "decided_at": (
            None
            if revision.decided_at is None
            else revision.decided_at.isoformat().replace("+00:00", "Z")
        ),
        "generation": revision.generation,
        "parent_revision_id": revision.parent_revision_id,
        "revision_id": revision.revision_id,
        "state": revision.state,
        "state_version": revision.state_version,
        "submitted_at": (
            None
            if revision.submitted_at is None
            else revision.submitted_at.isoformat().replace("+00:00", "Z")
        ),
        "tenant_id": revision.tenant_id,
    }


def _deployment_view(deployment: Any) -> dict[str, Any]:
    return {
        "activated_at": deployment.activated_at.isoformat().replace("+00:00", "Z"),
        "activated_by": deployment.activated_by,
        "configuration_digest": deployment.configuration_digest,
        "control_id": deployment.control_id,
        "deployment_version": deployment.deployment_version,
        "revision_id": deployment.revision_id,
        "semantics": "desired-state-pointer",
        "tenant_id": deployment.tenant_id,
    }


def _deployment_operation_view(operation: Any) -> dict[str, Any]:
    def timestamp(value: Any) -> str | None:
        return None if value is None else value.isoformat().replace("+00:00", "Z")

    return {
        "applied_at": timestamp(operation.applied_at),
        "applied_configuration_digest": operation.applied_configuration_digest,
        "attempt_count": operation.attempt_count,
        "configuration_digest": operation.configuration_digest,
        "control_id": operation.control_id,
        "failed_at": timestamp(operation.failed_at),
        "failure_digest": operation.failure_digest,
        "kind": operation.kind,
        "lease_expires_at": timestamp(operation.lease_expires_at),
        "lease_fence": operation.lease_fence,
        "lease_owner": operation.lease_owner,
        "leased_at": timestamp(operation.leased_at),
        "operation_id": operation.operation_id,
        "operation_sequence": operation.operation_sequence,
        "predecessor_operation_id": operation.predecessor_operation_id,
        "retry_of_operation_id": operation.retry_of_operation_id,
        "requested_at": timestamp(operation.requested_at),
        "requested_by": operation.requested_by,
        "retry_at": timestamp(operation.retry_at),
        "retryable": operation.retryable,
        "revision_id": operation.revision_id,
        "semantics": "runtime-application-operation",
        "state": operation.state,
        "state_version": operation.state_version,
        "target_receipt_digest": operation.target_receipt_digest,
        "tenant_id": operation.tenant_id,
    }


def _control_summary_view(summary: Any) -> dict[str, Any]:
    return {
        "active_deployment": (
            None
            if summary.active_deployment is None
            else _deployment_view(summary.active_deployment)
        ),
        "latest_revision": _revision_view(summary.latest_revision),
    }


def _public_origin(value: str) -> tuple[str, str]:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("control-plane public origin must be a credential-free HTTPS origin")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("control-plane public origin has an invalid port") from exc
    host = parsed.hostname.lower()
    rendered_host = f"[{host}]" if ":" in host else host
    authority = rendered_host if port in {None, 443} else f"{rendered_host}:{port}"
    return f"https://{authority}", authority


def create_control_plane_app(
    service: ControlPlaneService,
    identity_resolver: IdentityResolver,
    *,
    public_origin: str,
    oidc_authenticator: OIDCSessionCoordinator | None = None,
    oidc_trusted_proxy_cidrs: tuple[str, ...] = (),
    offload_workers: int = _DEFAULT_OFFLOAD_WORKERS,
    offload_queue_capacity: int = _DEFAULT_OFFLOAD_QUEUE_CAPACITY,
    offload_admission_timeout_seconds: float = (_DEFAULT_OFFLOAD_ADMISSION_TIMEOUT_SECONDS),
) -> FastAPI:
    """Build an API with no implicit identity or permissive cross-origin mode.

    Synchronous identity, OIDC, service, and repository work is isolated behind
    one per-application bulkhead.  The queue is bounded and saturated requests
    fail before they can create unbounded executor work.
    """

    if type(service) is not ControlPlaneService:
        raise TypeError("service must be an exact ControlPlaneService")
    if not callable(getattr(identity_resolver, "resolve", None)):
        raise TypeError("identity resolver does not implement resolve()")
    if type(offload_workers) is not int or not 1 <= offload_workers <= 256:
        raise ValueError("offload_workers must be an integer from 1 through 256")
    if type(offload_queue_capacity) is not int or not 0 <= offload_queue_capacity <= 4_096:
        raise ValueError("offload_queue_capacity must be an integer from 0 through 4096")
    if (
        type(offload_admission_timeout_seconds) not in {float, int}
        or isinstance(offload_admission_timeout_seconds, bool)
        or not math.isfinite(float(offload_admission_timeout_seconds))
        or not 0.001 <= float(offload_admission_timeout_seconds) <= 30.0
    ):
        raise ValueError("offload_admission_timeout_seconds must be from 0.001 through 30")
    if (
        type(oidc_trusted_proxy_cidrs) is not tuple
        or len(oidc_trusted_proxy_cidrs) > _MAX_TRUSTED_PROXY_CIDRS
        or any(type(value) is not str for value in oidc_trusted_proxy_cidrs)
    ):
        raise ValueError("OIDC trusted proxy CIDRs are invalid")
    trusted_proxy_networks: list[
        ipaddress.IPv4Network | ipaddress.IPv6Network
    ] = []
    for value in oidc_trusted_proxy_cidrs:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError:
            raise ValueError("OIDC trusted proxy CIDRs are invalid") from None
        if str(network) != value:
            raise ValueError("OIDC trusted proxy CIDRs must be canonical")
        trusted_proxy_networks.append(network)
    if len(trusted_proxy_networks) != len(set(trusted_proxy_networks)):
        raise ValueError("OIDC trusted proxy CIDRs must be unique")
    trusted_proxy_network_tuple = tuple(trusted_proxy_networks)
    offload = _BoundedOffloadGateway(
        workers=offload_workers,
        queue_capacity=offload_queue_capacity,
        admission_timeout_seconds=float(offload_admission_timeout_seconds),
    )
    origin, authority = _public_origin(public_origin)
    if oidc_authenticator is not None:
        if (
            type(identity_resolver) is not OIDCIdentityResolver
            or identity_resolver.authenticator is not oidc_authenticator
        ):
            raise TypeError("OIDC routes and identity resolver must share one authenticator")
        if oidc_authenticator.redirect_uri != f"{origin}/auth/callback":
            raise ValueError("OIDC redirect URI does not match the control-plane origin")
    static_root = resources.files("assurance_lab.control_plane").joinpath("static")
    static_assets = {
        "app.js": static_root.joinpath("app.js").read_bytes(),
        "index.html": static_root.joinpath("index.html").read_bytes(),
        "model.js": static_root.joinpath("model.js").read_bytes(),
        "styles.css": static_root.joinpath("styles.css").read_bytes(),
    }
    application = FastAPI(
        title="Control Assurance control plane",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @application.middleware("http")
    async def security_boundary(request: Request, call_next: Any) -> Any:
        def secured(response: Response) -> Response:
            response.headers["cache-control"] = "no-store"
            if request.url.path == "/control/" or request.url.path.startswith("/control/assets/"):
                response.headers["content-security-policy"] = (
                    "default-src 'none'; base-uri 'none'; connect-src 'self'; "
                    "form-action 'self'; frame-ancestors 'none'; img-src 'self'; "
                    "script-src 'self'; style-src 'self'"
                )
            else:
                response.headers["content-security-policy"] = (
                    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
                )
            response.headers["cross-origin-opener-policy"] = "same-origin"
            response.headers["cross-origin-resource-policy"] = "same-origin"
            response.headers["permissions-policy"] = (
                "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
            )
            response.headers["referrer-policy"] = "no-referrer"
            response.headers["x-content-type-options"] = "nosniff"
            response.headers["x-frame-options"] = "DENY"
            return response

        host_values = [
            value for name, value in request.scope.get("headers", ()) if name.lower() == b"host"
        ]
        try:
            host = host_values[0].decode("ascii", errors="strict")
        except (IndexError, UnicodeDecodeError):
            host = ""
        if len(host_values) != 1 or not host or host.lower() != authority.lower():
            return secured(_error(400, "invalid-host", "Invalid request authority."))
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except ValueError:
                return secured(_error(400, "invalid-content-length", "Invalid request framing."))
            if declared < 0 or declared > _MAX_REQUEST_BYTES:
                return secured(
                    _error(
                        413,
                        "request-too-large",
                        "Request body exceeds the API limit.",
                    )
                )
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            body = bytearray()
            async for chunk in request.stream():
                if len(body) + len(chunk) > _MAX_REQUEST_BYTES:
                    return secured(
                        _error(
                            413,
                            "request-too-large",
                            "Request body exceeds the API limit.",
                        )
                    )
                body.extend(chunk)
            request._body = bytes(body)
        response = await call_next(request)
        return secured(response)

    @application.exception_handler(RequestValidationError)
    async def validation_error(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        del request, exc
        return _error(422, "invalid-request", "Request fields did not match the API contract.")

    @application.exception_handler(APIIdentityError)
    async def identity_error(request: Request, exc: APIIdentityError) -> JSONResponse:
        del request, exc
        return _error(401, "authentication-required", "A valid SSO session is required.")

    @application.exception_handler(APIIdentityServiceError)
    async def identity_service_error(
        request: Request,
        exc: APIIdentityServiceError,
    ) -> JSONResponse:
        del request, exc
        return _error(
            503,
            "identity-service-unavailable",
            "The SSO session service is temporarily unavailable.",
        )

    @application.exception_handler(APIOffloadSaturated)
    async def offload_saturated(
        request: Request,
        exc: APIOffloadSaturated,
    ) -> JSONResponse:
        del request, exc
        return _error(
            503,
            "service-busy",
            "The control-plane service is temporarily busy.",
        )

    @application.exception_handler(ControlPlaneAuthorizationError)
    async def authorization_error(
        request: Request,
        exc: ControlPlaneAuthorizationError,
    ) -> JSONResponse:
        del request, exc
        return _error(
            403,
            "access-denied",
            "The authenticated identity cannot perform this action.",
        )

    @application.exception_handler(ControlPlaneNotFound)
    async def not_found(request: Request, exc: ControlPlaneNotFound) -> JSONResponse:
        del request, exc
        return _error(404, "not-found", "The requested control-plane object was not found.")

    @application.exception_handler(ControlPlaneConflict)
    async def conflict(request: Request, exc: ControlPlaneConflict) -> JSONResponse:
        del request, exc
        return _error(409, "state-conflict", "The object changed; reload before trying again.")

    @application.exception_handler(ControlPlaneIntegrityError)
    async def integrity_error(
        request: Request,
        exc: ControlPlaneIntegrityError,
    ) -> JSONResponse:
        del request, exc
        return _error(
            503,
            "integrity-check-failed",
            "The operation is unavailable because stored state failed verification.",
        )

    @application.exception_handler(ControlPlaneStoreError)
    async def store_error(request: Request, exc: ControlPlaneStoreError) -> JSONResponse:
        del request, exc
        return _error(503, "store-unavailable", "Control-plane storage is unavailable.")

    async def session(request: Request) -> AuthenticatedSession:
        try:
            candidate = await offload.run(identity_resolver.resolve, request)
            resolved = await candidate if inspect.isawaitable(candidate) else candidate
        except APIIdentityError:
            raise
        except APIOffloadSaturated:
            raise
        except Exception as exc:
            raise APIIdentityServiceError("session resolution failed") from exc
        if type(resolved) is not AuthenticatedSession:
            raise APIIdentityError("session resolver returned an invalid object")
        return resolved

    async def mutation_session(
        request: Request,
        resolved: Annotated[AuthenticatedSession, Depends(session)],
    ) -> AuthenticatedSession:
        if request.headers.get("origin") != origin:
            raise ControlPlaneAuthorizationError("mutation origin does not match")
        fetch_site = request.headers.get("sec-fetch-site")
        if fetch_site is not None and fetch_site not in {"same-origin", "none"}:
            raise ControlPlaneAuthorizationError("cross-site mutation is denied")
        content_type = request.headers.get("content-type", "")
        if content_type.split(";", 1)[0].strip().lower() != "application/json":
            raise ControlPlaneAuthorizationError("mutations require application/json")
        supplied = request.headers.get("x-csrf-token", "")
        if not hmac.compare_digest(supplied, resolved.csrf_token):
            raise ControlPlaneAuthorizationError("CSRF token does not match the session")
        return resolved

    ReadSession = Annotated[AuthenticatedSession, Depends(session)]
    MutationSession = Annotated[AuthenticatedSession, Depends(mutation_session)]

    @application.get("/health/live")
    async def live() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/control", include_in_schema=False)
    async def control_redirect() -> RedirectResponse:
        return RedirectResponse("/control/", status_code=308)

    @application.get("/control/", include_in_schema=False)
    async def control_ui() -> HTMLResponse:
        return HTMLResponse(static_assets["index.html"])

    @application.get("/control/assets/styles.css", include_in_schema=False)
    async def control_ui_styles() -> Response:
        return Response(static_assets["styles.css"], media_type="text/css")

    @application.get("/control/assets/model.js", include_in_schema=False)
    async def control_ui_model() -> Response:
        return Response(static_assets["model.js"], media_type="text/javascript")

    @application.get("/control/assets/app.js", include_in_schema=False)
    async def control_ui_application() -> Response:
        return Response(static_assets["app.js"], media_type="text/javascript")

    if oidc_authenticator is not None:
        login_identity_resolver = cast(OIDCIdentityResolver, identity_resolver)

        @application.get("/auth/login", include_in_schema=False)
        async def oidc_login(
            request: Request,
            return_to: str = "/control/",
        ) -> Response:
            if return_to != "/control/":
                return_to = "/control/"
            del return_to
            try:
                source_digest = login_identity_resolver.login_source_digest(
                    request,
                    trusted_proxy_networks=trusted_proxy_network_tuple,
                )
                authorization = await offload.run(
                    oidc_authenticator.begin,
                    source_digest=source_digest,
                )
            except OIDCError as exc:
                if exc.code == "login_admission_limited":
                    limited_response = _error(
                        429,
                        "login-capacity-exceeded",
                        "Sign-in capacity is temporarily full.",
                    )
                    limited_response.headers["retry-after"] = "5"
                    return limited_response
                return _error(
                    503,
                    "login-service-unavailable",
                    "Sign-in is temporarily unavailable.",
                )
            response = RedirectResponse(authorization.redirect_url, status_code=303)
            response.set_cookie(
                "__Host-control_oidc_transaction",
                authorization.transaction_cookie,
                expires=authorization.expires_at,
                httponly=True,
                path="/",
                samesite="lax",
                secure=True,
            )
            return response

        @application.get("/auth/callback", include_in_schema=False)
        async def oidc_callback(request: Request) -> Response:
            pairs = request.query_params.multi_items()
            names = [name for name, _ in pairs]
            allowed = {
                "code",
                "error",
                "error_description",
                "error_uri",
                "iss",
                "session_state",
                "state",
            }
            transaction_cookie = request.cookies.get(
                "__Host-control_oidc_transaction",
                "",
            )
            failure = (
                len(request.scope.get("query_string", b"")) > 8_192
                or any(len(value) > 4_096 for _, value in pairs)
                or any(name not in allowed for name in names)
                or len(names) != len(set(names))
                or "error" in names
                or "code" not in names
                or "state" not in names
                or ("iss" in names and request.query_params["iss"] != oidc_authenticator.issuer)
            )
            if failure:
                response: Response = _error(
                    401,
                    "authentication-failed",
                    "SSO authentication did not complete.",
                )
            else:
                try:
                    result = await offload.run(
                        oidc_authenticator.complete,
                        transaction_cookie=transaction_cookie,
                        returned_state=request.query_params["state"],
                        authorization_code=request.query_params["code"],
                    )
                except OIDCError as exc:
                    if exc.code in _OIDC_BACKEND_ERROR_CODES:
                        response = _error(
                            503,
                            "login-service-unavailable",
                            "Sign-in is temporarily unavailable.",
                        )
                    else:
                        response = _error(
                            401,
                            "authentication-failed",
                            "SSO authentication did not complete.",
                        )
                else:
                    response = RedirectResponse("/control/", status_code=303)
                    response.set_cookie(
                        "__Host-control_session",
                        result.session_cookie,
                        expires=result.expires_at,
                        httponly=True,
                        path="/",
                        samesite="lax",
                        secure=True,
                    )
            response.delete_cookie(
                "__Host-control_oidc_transaction",
                httponly=True,
                path="/",
                samesite="lax",
                secure=True,
            )
            return response

    @application.get("/api/v1/session")
    async def get_session(resolved: ReadSession) -> dict[str, Any]:
        actor = resolved.actor
        return {
            "csrf_token": resolved.csrf_token,
            "identity": {
                "display_name": actor.display_name,
                "groups": list(actor.groups),
                "mfa": actor.mfa,
                "roles": sorted(actor.roles),
                "subject": actor.subject,
                "tenant_id": actor.tenant_id,
            },
        }

    @application.get("/api/v1/revisions/{revision_id}")
    async def get_revision(revision_id: str, resolved: ReadSession) -> dict[str, Any]:
        if _DIGEST_RE.fullmatch(revision_id) is None:
            raise ControlPlaneNotFound("revision was not found")
        revision = await offload.run(
            service.get_revision,
            resolved.actor,
            revision_id,
        )
        return _revision_view(revision)

    @application.get("/api/v1/controls")
    async def list_controls(
        resolved: ReadSession,
        limit: Annotated[int, Query(ge=1, le=1_000)] = 100,
    ) -> dict[str, Any]:
        summaries = await offload.run(
            service.list_controls,
            resolved.actor,
            limit=limit,
        )
        return {
            "items": [_control_summary_view(summary) for summary in summaries],
        }

    @application.get("/api/v1/controls/{control_id}/revisions")
    async def list_revisions(
        control_id: str,
        resolved: ReadSession,
        limit: Annotated[int, Query(ge=1, le=1_000)] = 100,
    ) -> dict[str, Any]:
        if _ID_RE.fullmatch(control_id) is None:
            raise ControlPlaneNotFound("control was not found")
        revisions = await offload.run(
            service.list_revisions,
            resolved.actor,
            control_id,
            limit=limit,
        )
        return {"items": [_revision_view(revision) for revision in revisions]}

    @application.post("/api/v1/revisions", status_code=201)
    async def create_revision(
        body: CreateRevisionRequest,
        resolved: MutationSession,
    ) -> dict[str, Any]:
        revision = await offload.run(
            service.create_revision,
            resolved.actor,
            body.configuration,
            expected_parent_revision_id=body.expected_parent_revision_id,
        )
        return _revision_view(revision)

    @application.post("/api/v1/revisions/{revision_id}/submit")
    async def submit_revision(
        revision_id: str,
        body: StateVersionRequest,
        resolved: MutationSession,
    ) -> dict[str, Any]:
        if _DIGEST_RE.fullmatch(revision_id) is None:
            raise ControlPlaneNotFound("revision was not found")
        revision = await offload.run(
            service.submit_revision,
            resolved.actor,
            revision_id,
            expected_state_version=body.expected_state_version,
        )
        return _revision_view(revision)

    @application.post("/api/v1/revisions/{revision_id}/decision")
    async def decide_revision(
        revision_id: str,
        body: DecisionRequest,
        resolved: MutationSession,
    ) -> dict[str, Any]:
        if _DIGEST_RE.fullmatch(revision_id) is None:
            raise ControlPlaneNotFound("revision was not found")
        revision, decision = await offload.run(
            service.decide_revision,
            resolved.actor,
            revision_id,
            expected_state_version=body.expected_state_version,
            decision=body.decision,
            comment=body.comment,
        )
        return {
            "decision": decision.model_dump(mode="json"),
            "revision": _revision_view(revision),
        }

    @application.post("/api/v1/revisions/{revision_id}/activate", status_code=202)
    async def activate_revision(
        revision_id: str,
        body: ActivateRequest,
        resolved: MutationSession,
    ) -> dict[str, Any]:
        if _DIGEST_RE.fullmatch(revision_id) is None:
            raise ControlPlaneNotFound("revision was not found")
        deployment, operation = await offload.run(
            service.activate_revision_with_operation,
            resolved.actor,
            revision_id,
            expected_deployment_version=body.expected_deployment_version,
        )
        return {
            "desired_deployment": _deployment_view(deployment),
            "operation": _deployment_operation_view(operation),
        }

    @application.post(
        "/api/v1/revisions/{revision_id}/rollback",
        status_code=202,
    )
    async def rollback_revision(
        revision_id: str,
        body: RollbackRequest,
        resolved: MutationSession,
    ) -> dict[str, Any]:
        if _DIGEST_RE.fullmatch(revision_id) is None:
            raise ControlPlaneNotFound("revision was not found")
        operation = await offload.run(
            service.request_rollback,
            resolved.actor,
            revision_id,
            expected_predecessor_operation_id=(body.expected_predecessor_operation_id),
        )
        return _deployment_operation_view(operation)

    @application.post(
        "/api/v1/deployment-operations/{operation_id}/retry",
        status_code=202,
    )
    async def retry_deployment(
        operation_id: str,
        body: RetryDeploymentRequest,
        resolved: MutationSession,
    ) -> dict[str, Any]:
        del body
        if _DIGEST_RE.fullmatch(operation_id) is None:
            raise ControlPlaneNotFound("deployment operation was not found")
        operation = await offload.run(
            service.retry_deployment,
            resolved.actor,
            operation_id,
        )
        return _deployment_operation_view(operation)

    @application.get("/api/v1/deployment-operations/{operation_id}")
    async def deployment_operation(
        operation_id: str,
        resolved: ReadSession,
    ) -> dict[str, Any]:
        if _DIGEST_RE.fullmatch(operation_id) is None:
            raise ControlPlaneNotFound("deployment operation was not found")
        operation = await offload.run(
            service.deployment_operation,
            resolved.actor,
            operation_id,
        )
        return _deployment_operation_view(operation)

    @application.get("/api/v1/controls/{control_id}/deployment-operations")
    async def deployment_operations(
        control_id: str,
        resolved: ReadSession,
        limit: Annotated[int, Query(ge=1, le=1_000)] = 100,
    ) -> dict[str, Any]:
        if _ID_RE.fullmatch(control_id) is None:
            raise ControlPlaneNotFound("control was not found")
        operations = await offload.run(
            service.deployment_operations,
            resolved.actor,
            control_id,
            limit=limit,
        )
        return {"items": [_deployment_operation_view(operation) for operation in operations]}

    @application.get("/api/v1/controls/{control_id}/active")
    async def active_deployment(
        control_id: str,
        resolved: ReadSession,
    ) -> dict[str, Any]:
        if _ID_RE.fullmatch(control_id) is None:
            raise ControlPlaneNotFound("control was not found")
        deployment = await offload.run(
            service.active_deployment,
            resolved.actor,
            control_id,
        )
        return _deployment_view(deployment)

    @application.get("/api/v1/controls/{control_id}/desired")
    async def desired_deployment(
        control_id: str,
        resolved: ReadSession,
    ) -> dict[str, Any]:
        if _ID_RE.fullmatch(control_id) is None:
            raise ControlPlaneNotFound("control was not found")
        deployment = await offload.run(
            service.active_deployment,
            resolved.actor,
            control_id,
        )
        return _deployment_view(deployment)

    @application.get("/api/v1/controls/{control_id}/applied")
    async def applied_deployment(
        control_id: str,
        resolved: ReadSession,
    ) -> dict[str, Any]:
        if _ID_RE.fullmatch(control_id) is None:
            raise ControlPlaneNotFound("control was not found")
        operation = await offload.run(
            service.applied_deployment_operation,
            resolved.actor,
            control_id,
        )
        return _deployment_operation_view(operation)

    @application.get("/api/v1/audit/verification")
    async def audit_verification(
        resolved: ReadSession,
    ) -> dict[str, Any]:
        event_count, head_digest = await offload.run(
            service.verify_audit_chain,
            resolved.actor,
        )
        return {
            "event_count": event_count,
            "head_event_digest": head_digest,
            "verified": True,
        }

    @application.get("/api/v1/audit")
    async def audit(
        resolved: ReadSession,
        after_sequence: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=1_000)] = 1_000,
    ) -> dict[str, Any]:
        events = await offload.run(
            service.audit_events,
            resolved.actor,
            after_sequence=after_sequence,
            limit=limit,
        )
        return {
            "items": [
                {
                    "action": event.action,
                    "actor_subject": event.actor_subject,
                    "details": strict_json_loads(event.details_bytes),
                    "event_digest": event.event_digest,
                    "object_id": event.object_id,
                    "occurred_at": event.occurred_at.isoformat().replace(
                        "+00:00",
                        "Z",
                    ),
                    "previous_event_digest": event.previous_event_digest,
                    "sequence": event.sequence,
                    "tenant_id": event.tenant_id,
                }
                for event in events
            ]
        }

    if oidc_authenticator is not None:

        @application.post("/auth/logout", include_in_schema=False)
        async def oidc_logout(
            request: Request,
            resolved: MutationSession,
        ) -> Response:
            del resolved
            opaque = request.cookies.get("__Host-control_session", "")
            await offload.run(oidc_authenticator.logout, opaque)
            response = Response(status_code=204)
            response.delete_cookie(
                "__Host-control_session",
                httponly=True,
                path="/",
                samesite="lax",
                secure=True,
            )
            return response

    return application
