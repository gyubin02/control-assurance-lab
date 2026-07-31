"""Production composition and readiness boundary for the control-plane API."""

from __future__ import annotations

import base64
import hashlib
import importlib
import math
import os
import re
import stat
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, cast

import anyio
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from assurance_lab.control_plane.api import (
    OIDCIdentityResolver,
    create_control_plane_app,
)
from assurance_lab.control_plane.oidc import (
    GroupEntitlement,
    JWKSFetchRequest,
    MFAPolicy,
    OIDCAuthenticator,
    OIDCConfiguration,
    OIDCLoginAdmissionPolicy,
)
from assurance_lab.control_plane.oidc_http import (
    CertificatePrivateKeyJWT,
    PinnedOIDCHTTPClient,
)
from assurance_lab.control_plane.postgres_oidc_store import (
    PostgresOIDCStateStore,
)
from assurance_lab.control_plane.postgres_security import (
    RuntimeBoundaryExpectation,
    RuntimeRoleKind,
    runtime_boundary_is_safe,
)
from assurance_lab.control_plane.postgres_store import (
    ConnectionPool,
    PostgresControlPlaneStore,
)
from assurance_lab.control_plane.service import ControlPlaneService
from assurance_lab.control_plane.service_config import (
    ControlPlaneConfigurationError,
    ControlPlaneServiceConfig,
    KeyVaultKeySettings,
    PinnedPublicFile,
    ProtectedFileReference,
)
from assurance_lab.evidence.canonical import JSONLimits, strict_json_loads
from assurance_lab.key_management.azure_identity import (
    AzureWorkloadIdentityTokenProvider,
)
from assurance_lab.key_management.azure_key_vault import (
    AzureKeyVaultCryptoClient,
    AzureKeyVaultEnvelopeProtector,
    AzureKeyVaultPS256Signer,
)
from assurance_lab.key_management.azure_secret import (
    AzureKeyVaultSecretClient,
    AzureKeyVaultSecretError,
    AzureKeyVaultSecretReference,
)

_STAGE_RE: Final = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_B64URL_RE: Final = re.compile(r"^[A-Za-z0-9_-]{43,86}$")
_JWKS_LIMITS: Final = JSONLimits(
    max_bytes=1024 * 1024,
    max_line_bytes=1024 * 1024,
    max_depth=12,
    max_collection_items=1_024,
    max_string_length=16 * 1024,
)
_CSRF_CONTENT_TYPE: Final = "application/vnd.control-assurance.csrf-key+base64url"
_PRIVATE_JWK_MEMBERS: Final = frozenset(
    {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
)


class ControlPlaneBootstrapError(RuntimeError):
    """Secret-redacted startup failure with a stable operational stage."""

    __slots__ = ("stage",)

    def __init__(self, stage: str) -> None:
        if type(stage) is not str or _STAGE_RE.fullmatch(stage) is None:
            raise ValueError("control-plane bootstrap stage is invalid")
        self.stage = stage
        super().__init__(stage)


class _Closable(Protocol):
    def close(self) -> None: ...


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _open_flags(*, directory: bool = False) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os,
        "O_NOFOLLOW",
        0,
    )
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    return flags


def _metadata_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def read_protected_file(
    reference: ProtectedFileReference,
    *,
    maximum_bytes: int,
) -> bytes:
    """Read a Kubernetes atomic-writer file without permitting mount escape."""

    if type(reference) is not ProtectedFileReference:
        raise TypeError("protected file reference must be exact")
    if type(maximum_bytes) is not int or not 1 <= maximum_bytes <= 8 * 1024 * 1024:
        raise ValueError("protected file size limit is invalid")
    configured = Path(reference.path)
    mount_root = Path(reference.mount_root)
    try:
        root_before = mount_root.lstat()
        configured_before = configured.lstat()
        resolved_root = mount_root.resolve(strict=True)
        resolved_file = configured.resolve(strict=True)
        relative = resolved_file.relative_to(resolved_root)
        if (
            resolved_root != mount_root
            or not stat.S_ISDIR(root_before.st_mode)
            or not relative.parts
        ):
            raise OSError
    except (OSError, RuntimeError, ValueError):
        raise ControlPlaneConfigurationError(
            "protected file path is unavailable or escaped its mount"
        ) from None

    descriptors: list[int] = []
    try:
        parent = os.open(resolved_root, _open_flags(directory=True))
        descriptors.append(parent)
        for component in relative.parts[:-1]:
            parent = os.open(
                component,
                _open_flags(directory=True),
                dir_fd=parent,
            )
            descriptors.append(parent)
        descriptor = os.open(relative.parts[-1], _open_flags(), dir_fd=parent)
        descriptors.append(descriptor)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != reference.owner_uid
            or (
                reference.group_gid is not None
                and before.st_gid != reference.group_gid
            )
            or stat.S_IMODE(before.st_mode) != reference.mode
            or not 0 < before.st_size <= maximum_bytes
        ):
            raise OSError
        content = bytearray()
        while True:
            chunk = os.read(
                descriptor,
                min(64 * 1024, maximum_bytes + 1 - len(content)),
            )
            if not chunk:
                break
            content.extend(chunk)
            if len(content) > maximum_bytes:
                raise OSError
        after = os.fstat(descriptor)
        if _metadata_identity(before) != _metadata_identity(after):
            raise OSError
    except OSError:
        raise ControlPlaneConfigurationError(
            "protected file failed ownership, mode, or stability checks"
        ) from None
    finally:
        for descriptor in reversed(descriptors):
            with suppress(OSError):
                os.close(descriptor)

    try:
        if (
            _metadata_identity(mount_root.lstat())
            != _metadata_identity(root_before)
            or _metadata_identity(configured.lstat())
            != _metadata_identity(configured_before)
            or mount_root.resolve(strict=True) != resolved_root
            or configured.resolve(strict=True) != resolved_file
        ):
            raise OSError
    except (OSError, RuntimeError):
        raise ControlPlaneConfigurationError(
            "protected file path changed while it was read"
        ) from None
    return bytes(content)


def _read_pinned_public_file(
    settings: PinnedPublicFile,
    *,
    maximum_bytes: int,
) -> bytes:
    content = read_protected_file(settings.file, maximum_bytes=maximum_bytes)
    if _sha256(content) != settings.sha256_digest:
        raise ControlPlaneBootstrapError("public-file-digest")
    return content


def _decode_csrf_key(value: bytes) -> bytes:
    try:
        encoded = value.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        raise AzureKeyVaultSecretError(
            "decode",
            "CSRF key is not canonical base64url",
        ) from None
    if _B64URL_RE.fullmatch(encoded) is None:
        raise AzureKeyVaultSecretError(
            "decode",
            "CSRF key is not canonical base64url",
        )
    try:
        decoded = base64.b64decode(
            encoded + "=" * ((-len(encoded)) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (TypeError, ValueError):
        raise AzureKeyVaultSecretError(
            "decode",
            "CSRF key is not canonical base64url",
        ) from None
    if (
        not 32 <= len(decoded) <= 64
        or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
        != encoded
    ):
        raise AzureKeyVaultSecretError(
            "decode",
            "CSRF key length or encoding is invalid",
        )
    return decoded


def _azure_provider(
    configuration: ControlPlaneServiceConfig,
) -> AzureWorkloadIdentityTokenProvider:
    settings = configuration.key_management.azure_workload_identity
    token = settings.token
    try:
        return AzureWorkloadIdentityTokenProvider(
            tenant_id=settings.tenant_id,
            client_id=settings.client_id,
            token_file=Path(token.path),
            token_mount_root=Path(token.mount_root),
            expected_issuer=settings.expected_issuer,
            expected_subject=settings.expected_subject,
            expected_file_owner_uid=token.owner_uid,
            expected_file_group_gid=token.group_gid,
            expected_file_mode=token.mode,
            refresh_skew_seconds=settings.refresh_skew_seconds,
            timeout_seconds=settings.timeout_seconds,
        )
    except Exception:
        raise ControlPlaneBootstrapError("azure-workload-identity") from None


def _crypto_client(
    provider: AzureWorkloadIdentityTokenProvider,
    settings: KeyVaultKeySettings,
    configuration: ControlPlaneServiceConfig,
) -> AzureKeyVaultCryptoClient:
    key_management = configuration.key_management
    try:
        return AzureKeyVaultCryptoClient(
            provider,
            vault_name=settings.vault_name,
            key_name=settings.key_name,
            key_version=settings.key_version,
            ca_file=Path(key_management.key_vault_ca_bundle.file.path),
            request_timeout_seconds=key_management.request_timeout_seconds,
            operation_timeout_seconds=key_management.operation_timeout_seconds,
        )
    except Exception:
        raise ControlPlaneBootstrapError("key-vault-client") from None


def _oidc_configuration(
    configuration: ControlPlaneServiceConfig,
) -> OIDCConfiguration:
    settings = configuration.oidc
    try:
        return OIDCConfiguration(
            issuer=settings.issuer,
            authorization_endpoint=settings.authorization_endpoint,
            token_endpoint=settings.token_endpoint,
            jwks_uri=settings.jwks_uri,
            client_id=settings.client_id,
            redirect_uri=f"{configuration.public_origin}/auth/callback",
            entitlements=tuple(
                GroupEntitlement(
                    group=item.group,
                    tenant_id=item.tenant_id,
                    roles=frozenset(item.roles),
                )
                for item in settings.entitlements
            ),
            mfa_policy=MFAPolicy(
                required=settings.mfa_policy.required,
                accepted_acr=frozenset(settings.mfa_policy.accepted_acr),
                required_amr=frozenset(settings.mfa_policy.required_amr),
                maximum_authentication_age_seconds=(
                    settings.mfa_policy.maximum_authentication_age_seconds
                ),
            ),
            login_admission_policy=OIDCLoginAdmissionPolicy(
                global_active_limit=(
                    settings.login_admission.global_active_limit
                ),
                source_active_limit=(
                    settings.login_admission.source_active_limit
                ),
                reservation_ttl_seconds=(
                    settings.login_admission.reservation_ttl_seconds
                ),
                burn_capacity=settings.login_admission.burn_capacity,
            ),
            scopes=settings.scopes,
            transaction_ttl_seconds=settings.transaction_ttl_seconds,
            session_ttl_seconds=settings.session_ttl_seconds,
            clock_skew_seconds=settings.clock_skew_seconds,
            maximum_id_token_age_seconds=settings.maximum_id_token_age_seconds,
            maximum_id_token_lifetime_seconds=(
                settings.maximum_id_token_lifetime_seconds
            ),
        )
    except (TypeError, ValueError):
        raise ControlPlaneBootstrapError("oidc-profile") from None


def _validate_database_transport(
    dsn: str,
    *,
    expected_ca_file: Path,
) -> Mapping[str, str]:
    try:
        conninfo = importlib.import_module("psycopg.conninfo")
        parameters = cast(Mapping[str, str], conninfo.conninfo_to_dict(dsn))
    except Exception:
        raise ControlPlaneBootstrapError("database-dsn") from None
    host = parameters.get("host")
    if (
        parameters.get("sslmode") != "verify-full"
        or parameters.get("target_session_attrs") != "read-write"
        or parameters.get("sslrootcert") != os.fspath(expected_ca_file)
        or type(host) is not str
        or not host
        or any(not item for item in host.split(","))
        or parameters.get("service") is not None
        or not parameters.get("dbname")
        or not parameters.get("user")
    ):
        raise ControlPlaneBootstrapError("database-transport-policy")
    return parameters


def _create_pool(
    dsn: str,
    configuration: ControlPlaneServiceConfig,
) -> ConnectionPool:
    settings = configuration.database
    _validate_database_transport(
        dsn,
        expected_ca_file=Path(settings.ca_bundle.file.path),
    )
    try:
        pool_module = importlib.import_module("psycopg_pool")
        rows_module = importlib.import_module("psycopg.rows")
        pool = pool_module.ConnectionPool(
            conninfo=dsn,
            min_size=settings.min_pool_size,
            max_size=settings.max_pool_size,
            timeout=float(settings.connect_timeout_seconds),
            kwargs={
                "autocommit": True,
                "connect_timeout": settings.connect_timeout_seconds,
                "row_factory": rows_module.dict_row,
            },
            open=True,
        )
    except Exception:
        raise ControlPlaneBootstrapError("database-pool") from None
    return cast(ConnectionPool, pool)


def _preflight_database(
    pool: ConnectionPool,
    configuration: ControlPlaneServiceConfig,
    *,
    role_kind: RuntimeRoleKind,
) -> None:
    settings = configuration.database
    if role_kind == "control":
        login_role = settings.control_role
    elif role_kind == "auth":
        login_role = settings.auth_role
    else:
        raise ValueError("control-plane database preflight role is invalid")
    expectation = RuntimeBoundaryExpectation(
        tenant_id=configuration.tenant_id,
        login_role=login_role,
        role_kind=role_kind,
        migration_owner_role=settings.migration_owner_role,
    )
    try:
        with pool.connection() as connection, connection.transaction():
            connection.execute(
                "SELECT set_config('statement_timeout', %s, true)",
                (f"{settings.statement_timeout_ms}ms",),
            )
            connection.execute(
                "SELECT set_config('lock_timeout', %s, true)",
                (f"{settings.lock_timeout_ms}ms",),
            )
            row = connection.execute(
                """
                SELECT
                    COALESCE(
                        (
                            SELECT ssl
                            FROM pg_catalog.pg_stat_ssl
                            WHERE pid = pg_backend_pid()
                        ),
                        FALSE
                    ) AS tls
                """
            ).fetchone()
            safe = runtime_boundary_is_safe(connection, expectation)
    except Exception:
        raise ControlPlaneBootstrapError("database-preflight") from None
    if (
        not isinstance(row, Mapping)
        or row.get("tls") is not True
        or safe is not True
    ):
        raise ControlPlaneBootstrapError("database-preflight")


def _preflight_jwks(
    client: PinnedOIDCHTTPClient,
    configuration: OIDCConfiguration,
) -> None:
    try:
        result = client.fetch(
            JWKSFetchRequest(
                uri=configuration.jwks_uri,
                expected_issuer=configuration.issuer,
                force_refresh=True,
            )
        )
        document = strict_json_loads(result.payload, limits=_JWKS_LIMITS)
    except Exception:
        raise ControlPlaneBootstrapError("oidc-jwks-preflight") from None
    if (
        result.effective_uri != configuration.jwks_uri
        or type(document) is not dict
        or set(document) != {"keys"}
        or type(document.get("keys")) is not list
    ):
        raise ControlPlaneBootstrapError("oidc-jwks-preflight")
    keys = cast(list[object], document["keys"])
    kids: list[str] = []
    for item in keys:
        if (
            type(item) is not dict
            or any(name in item for name in _PRIVATE_JWK_MEMBERS)
            or type(item.get("kid")) is not str
            or item.get("kty") not in {"RSA", "EC"}
        ):
            raise ControlPlaneBootstrapError("oidc-jwks-preflight")
        kids.append(cast(str, item["kid"]))
    if not keys or len(keys) > 512 or len(kids) != len(set(kids)):
        raise ControlPlaneBootstrapError("oidc-jwks-preflight")


def _preflight_kms(
    protector: AzureKeyVaultEnvelopeProtector,
    assertion_provider: CertificatePrivateKeyJWT,
) -> None:
    transaction_digest = f"sha256:{'a' * 64}"
    verifier = "A" * 43
    try:
        protected = protector.protect(
            code_verifier=verifier,
            transaction_digest=transaction_digest,
        )
        if (
            protector.unprotect(
                protected=protected,
                transaction_digest=transaction_digest,
            )
            != verifier
        ):
            raise ValueError
        assertion = assertion_provider.issue(
            deadline=time.monotonic() + 30.0,
        )
        if not assertion.identifier_digest.startswith("sha256:"):
            raise ValueError
    except Exception:
        raise ControlPlaneBootstrapError("key-vault-preflight") from None


class ControlPlaneReadiness:
    """Single-flight, bounded-age readiness over DB, KMS, and OIDC trust."""

    __slots__ = (
        "_cache_seconds",
        "_check",
        "_closed",
        "_last_checked",
        "_lock",
        "_ready",
    )

    def __init__(
        self,
        check: Callable[[], None],
        *,
        cache_seconds: int,
    ) -> None:
        if not callable(check):
            raise TypeError("readiness check must be callable")
        if type(cache_seconds) is not int or not 30 <= cache_seconds <= 3_600:
            raise ValueError("readiness cache interval is invalid")
        self._check = check
        self._cache_seconds = cache_seconds
        self._lock = threading.Lock()
        self._last_checked = -math.inf
        self._ready = False
        self._closed = False

    def check(self, *, force: bool = False) -> bool:
        if type(force) is not bool:
            raise TypeError("readiness force flag must be boolean")
        with self._lock:
            if self._closed:
                return False
            now = time.monotonic()
            if not force and now - self._last_checked < self._cache_seconds:
                return self._ready
            try:
                self._check()
            except Exception:
                self._ready = False
            else:
                self._ready = True
            self._last_checked = time.monotonic()
            return self._ready

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._ready = False


@dataclass(slots=True)
class ProductionControlPlaneComponents:
    application: FastAPI
    readiness: ControlPlaneReadiness
    _control_pool: _Closable
    _auth_pool: _Closable
    _closed: bool = False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.readiness.close()
        failed = False
        for pool in (self._auth_pool, self._control_pool):
            try:
                pool.close()
            except Exception:
                failed = True
        if failed:
            raise ControlPlaneBootstrapError("resource-close") from None


class ProductionControlPlaneFactory:
    """Compose one production API instance without ambient credentials."""

    __slots__ = ("_configuration", "_environment")

    def __init__(
        self,
        configuration: ControlPlaneServiceConfig,
        *,
        environment: Mapping[str, str],
    ) -> None:
        if type(configuration) is not ControlPlaneServiceConfig:
            raise TypeError("control-plane service configuration must be exact")
        if not isinstance(environment, Mapping):
            raise TypeError("control-plane environment must be a mapping")
        self._configuration = configuration
        self._environment = environment

    def build(self) -> ProductionControlPlaneComponents:
        configuration = self._configuration
        database_ca = _read_pinned_public_file(
            configuration.database.ca_bundle,
            maximum_bytes=8 * 1024 * 1024,
        )
        oidc_ca = _read_pinned_public_file(
            configuration.oidc.jwks_ca_bundle,
            maximum_bytes=8 * 1024 * 1024,
        )
        key_vault_ca = _read_pinned_public_file(
            configuration.key_management.key_vault_ca_bundle,
            maximum_bytes=8 * 1024 * 1024,
        )
        certificate_der = _read_pinned_public_file(
            configuration.key_management.oidc_client_certificate,
            maximum_bytes=1024 * 1024,
        )
        # The reads above verify the mounted bytes; these names document why
        # they intentionally remain alive only through object construction.
        del database_ca, oidc_ca, key_vault_ca

        control_dsn = configuration.database.control_dsn.resolve(
            self._environment,
            maximum_bytes=8_192,
        )
        auth_dsn = configuration.database.auth_dsn.resolve(
            self._environment,
            maximum_bytes=8_192,
        )
        control_parameters = _validate_database_transport(
            control_dsn,
            expected_ca_file=Path(configuration.database.ca_bundle.file.path),
        )
        auth_parameters = _validate_database_transport(
            auth_dsn,
            expected_ca_file=Path(configuration.database.ca_bundle.file.path),
        )
        if (
            control_parameters.get("user") != configuration.database.control_role
            or auth_parameters.get("user") != configuration.database.auth_role
            or any(
                control_parameters.get(name) != auth_parameters.get(name)
                for name in ("host", "hostaddr", "port", "dbname", "sslrootcert")
            )
        ):
            raise ControlPlaneBootstrapError("database-role-boundary")
        provider = _azure_provider(configuration)
        wrapping_client = _crypto_client(
            provider,
            configuration.key_management.pkce_wrapping_key,
            configuration,
        )
        signing_client = _crypto_client(
            provider,
            configuration.key_management.oidc_client_signing_key,
            configuration,
        )
        protector = AzureKeyVaultEnvelopeProtector(wrapping_client)
        signer = AzureKeyVaultPS256Signer(
            signing_client,
            certificate_der=certificate_der,
        )
        oidc_configuration = _oidc_configuration(configuration)
        assertions = CertificatePrivateKeyJWT(
            client_id=oidc_configuration.client_id,
            token_endpoint=oidc_configuration.token_endpoint,
            certificate_der=certificate_der,
            signer=signer,
        )
        oidc_http = PinnedOIDCHTTPClient(
            oidc_configuration,
            assertions,
            ca_file=Path(configuration.oidc.jwks_ca_bundle.file.path),
            timeout_seconds=configuration.oidc.request_timeout_seconds,
            jwks_cache_seconds=configuration.oidc.jwks_cache_seconds,
            jwks_negative_cache_seconds=(
                configuration.oidc.jwks_negative_cache_seconds
            ),
        )
        secret_reference = AzureKeyVaultSecretReference.parse(
            configuration.key_management.csrf_key_secret_ref
        )
        csrf_client = AzureKeyVaultSecretClient(
            provider,
            secret_reference,
            ca_file=Path(
                configuration.key_management.key_vault_ca_bundle.file.path
            ),
            request_timeout_seconds=(
                configuration.key_management.request_timeout_seconds
            ),
            operation_timeout_seconds=(
                configuration.key_management.operation_timeout_seconds
            ),
        )
        try:
            csrf_key = csrf_client.get().consume(
                _decode_csrf_key,
                expected_content_type=_CSRF_CONTENT_TYPE,
            )
        except Exception:
            raise ControlPlaneBootstrapError("csrf-key") from None

        control_pool: ConnectionPool | None = None
        auth_pool: ConnectionPool | None = None
        try:
            control_pool = _create_pool(control_dsn, configuration)
            auth_pool = _create_pool(auth_dsn, configuration)
            control_store = PostgresControlPlaneStore(
                control_pool,
                tenant_id=configuration.tenant_id,
                expected_role=configuration.database.control_role,
                statement_timeout_ms=(
                    configuration.database.statement_timeout_ms
                ),
                lock_timeout_ms=configuration.database.lock_timeout_ms,
            )
            oidc_store = PostgresOIDCStateStore(
                auth_pool,
                tenant_id=configuration.tenant_id,
                expected_role=configuration.database.auth_role,
                protector=protector,
                burn_capacity=(
                    oidc_configuration.login_admission_policy.burn_capacity
                ),
                statement_timeout_ms=(
                    configuration.database.statement_timeout_ms
                ),
                lock_timeout_ms=configuration.database.lock_timeout_ms,
            )
            service = ControlPlaneService(control_store)
            authenticator = OIDCAuthenticator(
                oidc_configuration,
                oidc_store,
                oidc_http,
                oidc_http,
            )
            resolver = OIDCIdentityResolver(
                authenticator,
                csrf_key=csrf_key,
            )
            application = create_control_plane_app(
                service,
                resolver,
                public_origin=configuration.public_origin,
                oidc_authenticator=authenticator,
                oidc_trusted_proxy_cidrs=(
                    configuration.oidc.login_admission.trusted_proxy_cidrs
                ),
                offload_workers=configuration.http.offload_workers,
                offload_queue_capacity=(
                    configuration.http.offload_queue_capacity
                ),
                offload_admission_timeout_seconds=(
                    configuration.http.offload_admission_timeout_seconds
                ),
            )

            def verify_dependencies() -> None:
                _preflight_database(
                    control_pool,
                    configuration,
                    role_kind="control",
                )
                _preflight_database(
                    auth_pool,
                    configuration,
                    role_kind="auth",
                )
                _preflight_kms(protector, assertions)
                _preflight_jwks(oidc_http, oidc_configuration)

            readiness = ControlPlaneReadiness(
                verify_dependencies,
                cache_seconds=configuration.http.readiness_cache_seconds,
            )
            if not readiness.check(force=True):
                raise ControlPlaneBootstrapError("readiness-preflight")

            @application.get("/health/ready", include_in_schema=False)
            async def ready() -> JSONResponse:
                healthy = await anyio.to_thread.run_sync(readiness.check)
                return JSONResponse(
                    status_code=200 if healthy else 503,
                    content={"status": "ok" if healthy else "not-ready"},
                    headers={"cache-control": "no-store"},
                )

            components = ProductionControlPlaneComponents(
                application=application,
                readiness=readiness,
                _control_pool=cast(_Closable, control_pool),
                _auth_pool=cast(_Closable, auth_pool),
            )

            @asynccontextmanager
            async def lifespan(app: FastAPI) -> Any:
                del app
                try:
                    yield
                finally:
                    components.close()

            application.router.lifespan_context = lifespan
            return components
        except Exception:
            for pool in (auth_pool, control_pool):
                close = getattr(pool, "close", None)
                if callable(close):
                    with suppress(Exception):
                        close()
            raise


__all__ = [
    "ControlPlaneBootstrapError",
    "ControlPlaneReadiness",
    "ProductionControlPlaneComponents",
    "ProductionControlPlaneFactory",
    "read_protected_file",
]
