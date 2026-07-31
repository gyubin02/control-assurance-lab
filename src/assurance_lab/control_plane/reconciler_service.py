"""Separate least-privileged service for control-plane deployment outbox work."""

from __future__ import annotations

import importlib
import os
import re
import signal
import threading
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from types import FrameType
from typing import Any, Literal, Protocol, cast

from assurance_lab.control_plane.deployment import (
    DeploymentApplyError,
    DeploymentApplyRequest,
    DeploymentReconciler,
    DeploymentTargetAcknowledgement,
)
from assurance_lab.control_plane.models import (
    DefenderSourceConfiguration,
    DeploymentWorkerIdentity,
    ElasticSourceConfiguration,
)
from assurance_lab.control_plane.postgres_security import (
    RuntimeBoundaryExpectation,
    runtime_boundary_is_safe,
)
from assurance_lab.control_plane.postgres_store import PostgresControlPlaneStore
from assurance_lab.key_management.azure_secret import (
    AzureKeyVaultSecretReference,
)
from assurance_lab.runtime.bootstrap import (
    RuntimeBootstrapError,
    _preflight_database,
    _validate_database_transport,
)
from assurance_lab.runtime.deployment_io import read_pinned_public_file
from assurance_lab.runtime.postgres import PostgresRuntimeCatalog
from assurance_lab.runtime.service import RuntimeHealthServer
from assurance_lab.runtime.service_config import (
    DefenderRuntimeSettings,
    ElasticRuntimeSettings,
    PinnedPublicFileSettings,
    ProtectedFileSettings,
    RuntimeServiceConfigurationError,
    RuntimeWorkerServiceConfig,
)

_CONTROL_DSN_ENVIRONMENT = "ASSURANCE_DEPLOYMENT_RECONCILER_DSN"
_CONTROL_ROLE_ENVIRONMENT = "ASSURANCE_DEPLOYMENT_RECONCILER_EXPECTED_ROLE"
_RUNTIME_ROLE_ENVIRONMENT = "ASSURANCE_DEPLOYMENT_RECONCILER_RUNTIME_ROLE"
_MIGRATION_OWNER_ROLE_ENVIRONMENT = (
    "ASSURANCE_CONTROL_PLANE_MIGRATION_OWNER_ROLE"
)
_CONTROL_CA_DIGEST_ENVIRONMENT = (
    "ASSURANCE_DEPLOYMENT_RECONCILER_CONTROL_CA_DIGEST"
)
_RUNTIME_CA_DIGEST_ENVIRONMENT = (
    "ASSURANCE_DEPLOYMENT_RECONCILER_RUNTIME_CA_DIGEST"
)
_RUNTIME_SCHEMA = "control_assurance_runtime"
_RUNTIME_SCHEMA_VERSION = 3
_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_ROLE_RE = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_DATABASE_TRUST_ROOT = Path("/trust/runtime")
_CONTROL_DATABASE_CA = _DATABASE_TRUST_ROOT / "control-postgres-ca.pem"
_RUNTIME_DATABASE_CA = _DATABASE_TRUST_ROOT / "postgres-ca.pem"


class _RuntimeTarget(Protocol):
    def ensure_applied(
        self,
        request: DeploymentApplyRequest,
    ) -> DeploymentTargetAcknowledgement: ...


def _required_digest(
    environment: Mapping[str, str],
    *,
    name: str,
) -> str:
    value = environment.get(name)
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        raise RuntimeServiceConfigurationError(
            "deployment reconciler database CA digest is unavailable"
        )
    return value


def _verify_pinned_database_ca(
    dsn: str,
    *,
    expected_digest: str,
    expected_path: Path,
    mount_root: Path = _DATABASE_TRUST_ROOT,
) -> None:
    """Verify the exact CA bytes before any PostgreSQL connection is opened."""

    try:
        conninfo = importlib.import_module("psycopg.conninfo")
        parameters = cast(
            Mapping[str, str],
            conninfo.conninfo_to_dict(dsn),
        )
        _validate_database_transport(
            parameters,
            expected_ca_file=expected_path,
        )
        read_pinned_public_file(
            PinnedPublicFileSettings(
                file=ProtectedFileSettings(
                    path=os.fspath(expected_path),
                    mount_root=os.fspath(mount_root),
                    owner_uid=os.geteuid(),
                    group_gid=os.getegid(),
                    mode=0o400,
                ),
                sha256_digest=expected_digest,
            )
        )
    except RuntimeBootstrapError:
        raise
    except Exception:
        raise RuntimeBootstrapError("database-trust") from None


def _required_role(
    environment: Mapping[str, str],
    *,
    name: str,
) -> str:
    value = environment.get(name)
    if type(value) is not str or _ROLE_RE.fullmatch(value) is None:
        raise RuntimeServiceConfigurationError(
            "deployment reconciler database role is unavailable"
        )
    return value


def _preflight_control_database(
    dsn: str,
    *,
    tenant_id: str,
    expected_role: str,
    migration_owner_role: str,
    connect_timeout_seconds: int,
    statement_timeout_ms: int,
    lock_timeout_ms: int,
) -> None:
    expectation = RuntimeBoundaryExpectation(
        tenant_id=tenant_id,
        login_role=expected_role,
        role_kind="reconciler",
        migration_owner_role=migration_owner_role,
    )
    try:
        conninfo = importlib.import_module("psycopg.conninfo")
        parameters = cast(
            Mapping[str, str],
            conninfo.conninfo_to_dict(dsn),
        )
        if parameters.get("user") != expected_role:
            raise ValueError
        psycopg = importlib.import_module("psycopg")
        rows = importlib.import_module("psycopg.rows")
        with psycopg.connect(
            dsn,
            autocommit=True,
            connect_timeout=connect_timeout_seconds,
            row_factory=rows.dict_row,
        ) as connection, connection.transaction():
            connection.execute(
                "SELECT set_config('statement_timeout', %s, true)",
                (f"{statement_timeout_ms}ms",),
            )
            connection.execute(
                "SELECT set_config('lock_timeout', %s, true)",
                (f"{lock_timeout_ms}ms",),
            )
            row = connection.execute(
                """
                SELECT COALESCE(
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
        raise RuntimeBootstrapError("database-preflight") from None
    if (
        not isinstance(row, Mapping)
        or row.get("tls") is not True
        or safe is not True
    ):
        raise RuntimeBootstrapError("database-preflight")


def _production_capable(configuration: RuntimeWorkerServiceConfig) -> None:
    """Reject registrations the exact worker composition cannot execute."""

    for registration in configuration.registrations:
        control = registration.configuration
        source = control.source
        source_runtime = registration.source_runtime
        if type(source_runtime) not in {
            ElasticRuntimeSettings,
            DefenderRuntimeSettings,
        }:
            raise RuntimeServiceConfigurationError(
                "runtime registration selects an unsupported source"
            )
        if (
            type(source_runtime) is ElasticRuntimeSettings
            and type(source) is ElasticSourceConfiguration
        ):
            credential_reference = source.parent_credential_ref
            ca_reference = source.ca_bundle_ref
        elif (
            type(source_runtime) is DefenderRuntimeSettings
            and type(source) is DefenderSourceConfiguration
        ):
            credential_reference = source.client_credential_ref
            ca_reference = None
        else:
            raise RuntimeServiceConfigurationError(
                "runtime registration source and runtime differ"
            )
        try:
            AzureKeyVaultSecretReference.parse(credential_reference)
        except ValueError as exc:
            raise RuntimeServiceConfigurationError(
                "runtime registration credential is not exact-version Azure Key Vault"
            ) from exc
        if ca_reference is not None:
            try:
                AzureKeyVaultSecretReference.parse(ca_reference)
            except ValueError as exc:
                raise RuntimeServiceConfigurationError(
                    "runtime registration CA is not exact-version Azure Key Vault"
                ) from exc
        evidence = control.evidence
        if (
            evidence.legal_hold
            or not evidence.custody_ref.startswith("s3-object-lock://")
            or not evidence.signing_key_ref.startswith("vault-transit://")
        ):
            raise RuntimeServiceConfigurationError(
                "runtime registration selects unsupported custody capability"
            )


class RegisteredConfigurationDeploymentTarget:
    """Allow only exact configurations present in a pinned worker release."""

    __slots__ = ("_registrations", "_target")

    def __init__(
        self,
        target: _RuntimeTarget,
        configuration: RuntimeWorkerServiceConfig,
    ) -> None:
        if not callable(getattr(target, "ensure_applied", None)):
            raise TypeError("runtime deployment target is invalid")
        if type(configuration) is not RuntimeWorkerServiceConfig:
            raise TypeError("runtime worker configuration must be exact")
        _production_capable(configuration)
        self._target = target
        self._registrations = {
            (
                registration.configuration.tenant_id,
                registration.configuration.control_id,
                registration.configuration.digest,
            ): registration.configuration.canonical_bytes()
            for registration in configuration.registrations
        }

    def ensure_applied(
        self,
        request: DeploymentApplyRequest,
    ) -> DeploymentTargetAcknowledgement:
        if type(request) is not DeploymentApplyRequest:
            raise TypeError("deployment request must be exact")
        expected = self._registrations.get(
            (
                request.tenant_id,
                request.control_id,
                request.configuration_digest,
            )
        )
        if expected is None or expected != request.configuration_bytes:
            raise DeploymentApplyError(
                "runtime-release-registration-missing",
                retryable=False,
            )
        return self._target.ensure_applied(request)


ReconcilerPhase = Literal[
    "created",
    "running",
    "draining",
    "stopped",
    "failed",
]


@dataclass(frozen=True, slots=True)
class DeploymentReconcilerStatus:
    phase: ReconcilerPhase

    @property
    def live(self) -> bool:
        return self.phase in {"running", "draining"}

    @property
    def ready(self) -> bool:
        return self.phase == "running"


class DeploymentReconcilerService:
    """Run one fenced reconciliation loop and drain on SIGTERM."""

    __slots__ = (
        "_closed",
        "_control_store",
        "_health",
        "_idle_seconds",
        "_lock",
        "_phase",
        "_reconciler",
        "_runtime_store",
        "_stop",
    )

    def __init__(
        self,
        reconciler: DeploymentReconciler,
        *,
        control_store: PostgresControlPlaneStore,
        runtime_store: PostgresRuntimeCatalog,
        health_host: str,
        health_port: int,
        idle_seconds: float,
    ) -> None:
        if type(reconciler) is not DeploymentReconciler:
            raise TypeError("deployment reconciler must be exact")
        if type(control_store) is not PostgresControlPlaneStore:
            raise TypeError("control-plane store must be exact")
        if type(runtime_store) is not PostgresRuntimeCatalog:
            raise TypeError("runtime store must be exact")
        if (
            type(idle_seconds) not in {float, int}
            or isinstance(idle_seconds, bool)
            or not 0.01 <= float(idle_seconds) <= 300.0
        ):
            raise ValueError("deployment reconciler idle interval is invalid")
        self._reconciler = reconciler
        self._control_store = control_store
        self._runtime_store = runtime_store
        self._idle_seconds = float(idle_seconds)
        self._lock = threading.Lock()
        self._phase: ReconcilerPhase = "created"
        self._stop = threading.Event()
        self._closed = False
        self._health = RuntimeHealthServer(
            host=health_host,
            port=health_port,
            status=self.status,  # type: ignore[arg-type]
        )

    def status(self) -> DeploymentReconcilerStatus:
        with self._lock:
            return DeploymentReconcilerStatus(self._phase)

    def request_stop(self) -> None:
        with self._lock:
            if self._phase == "running":
                self._phase = "draining"
        self._stop.set()

    def run(self) -> None:
        with self._lock:
            if self._phase != "created":
                raise RuntimeError("deployment reconciler service is single-use")
            self._phase = "running"
        self._health.start()
        try:
            while not self._stop.is_set():
                result = self._reconciler.run_once()
                if result is None:
                    self._stop.wait(self._idle_seconds)
            with self._lock:
                self._phase = "stopped"
        except BaseException:
            with self._lock:
                self._phase = "failed"
            raise
        finally:
            self.close()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        failed = False
        for close in (
            self._health.close,
            self._runtime_store.close,
            self._control_store.close,
        ):
            try:
                close()
            except Exception:
                failed = True
        if failed:
            raise RuntimeBootstrapError("resource-close")


def build_deployment_reconciler_service(
    configuration: RuntimeWorkerServiceConfig,
    *,
    environment: Mapping[str, str],
) -> DeploymentReconcilerService:
    """Build separate control/read and runtime/write database identities."""

    if type(configuration) is not RuntimeWorkerServiceConfig:
        raise TypeError("runtime worker configuration must be exact")
    if not isinstance(environment, Mapping):
        raise TypeError("reconciler environment must be a mapping")
    _production_capable(configuration)
    control_dsn = environment.get(_CONTROL_DSN_ENVIRONMENT)
    if (
        type(control_dsn) is not str
        or not control_dsn
        or "\x00" in control_dsn
        or "\r" in control_dsn
        or "\n" in control_dsn
        or len(control_dsn.encode("utf-8")) > 8_192
    ):
        raise RuntimeServiceConfigurationError(
            "deployment reconciler control-plane DSN is unavailable"
        )
    runtime_dsn = configuration.database.runtime_dsn.resolve(
        environment,
        maximum_bytes=8_192,
    )
    expected_control_role = _required_role(
        environment,
        name=_CONTROL_ROLE_ENVIRONMENT,
    )
    expected_runtime_role = _required_role(
        environment,
        name=_RUNTIME_ROLE_ENVIRONMENT,
    )
    migration_owner_role = _required_role(
        environment,
        name=_MIGRATION_OWNER_ROLE_ENVIRONMENT,
    )
    if len(
        {
            expected_control_role,
            expected_runtime_role,
            migration_owner_role,
        }
    ) != 3:
        raise RuntimeServiceConfigurationError(
            "deployment reconciler database roles are not separated"
        )
    database = configuration.database
    _verify_pinned_database_ca(
        control_dsn,
        expected_digest=_required_digest(
            environment,
            name=_CONTROL_CA_DIGEST_ENVIRONMENT,
        ),
        expected_path=_CONTROL_DATABASE_CA,
    )
    _verify_pinned_database_ca(
        runtime_dsn,
        expected_digest=_required_digest(
            environment,
            name=_RUNTIME_CA_DIGEST_ENVIRONMENT,
        ),
        expected_path=_RUNTIME_DATABASE_CA,
    )
    _preflight_control_database(
        control_dsn,
        tenant_id=configuration.tenant_id,
        expected_role=expected_control_role,
        migration_owner_role=migration_owner_role,
        connect_timeout_seconds=database.connect_timeout_seconds,
        statement_timeout_ms=database.statement_timeout_ms,
        lock_timeout_ms=database.lock_timeout_ms,
    )
    _preflight_database(
        runtime_dsn,
        schema=_RUNTIME_SCHEMA,
        expected_version=_RUNTIME_SCHEMA_VERSION,
        expected_tenant=configuration.tenant_id,
        expected_database_role=expected_runtime_role,
        expected_principal_kind="reconciler",
        connect_timeout_seconds=database.connect_timeout_seconds,
    )
    control_store: PostgresControlPlaneStore | None = None
    runtime_store: PostgresRuntimeCatalog | None = None
    try:
        control_store = PostgresControlPlaneStore.from_dsn(
            control_dsn,
            tenant_id=configuration.tenant_id,
            expected_role=expected_control_role,
            role_kind="reconciler",
            min_size=database.min_pool_size,
            max_size=database.max_pool_size,
            connect_timeout_seconds=database.connect_timeout_seconds,
            statement_timeout_ms=database.statement_timeout_ms,
            lock_timeout_ms=database.lock_timeout_ms,
        )
        runtime_store = PostgresRuntimeCatalog.from_dsn(
            runtime_dsn,
            min_size=database.min_pool_size,
            max_size=database.max_pool_size,
            connect_timeout_seconds=database.connect_timeout_seconds,
            statement_timeout_ms=database.statement_timeout_ms,
            lock_timeout_ms=database.lock_timeout_ms,
            max_run_attempts=configuration.worker.max_attempts,
        )
        target = RegisteredConfigurationDeploymentTarget(
            runtime_store,
            configuration,
        )
        worker = DeploymentWorkerIdentity(
            tenant_id=configuration.tenant_id,
            worker_id=configuration.resolve_worker_id(environment),
            credential_digest=(
                configuration.resolve_worker_credential_digest(environment)
            ),
        )
        reconciler = DeploymentReconciler(
            control_store,
            target,
            worker,
            lease_ttl_seconds=configuration.worker.lease_ttl_seconds,
            max_attempts=configuration.worker.max_attempts,
            base_retry_seconds=configuration.worker.run_retry_base_seconds,
            max_retry_seconds=configuration.worker.run_retry_max_seconds,
        )
        return DeploymentReconcilerService(
            reconciler,
            control_store=control_store,
            runtime_store=runtime_store,
            health_host=configuration.health.bind_host,
            health_port=configuration.health.port,
            idle_seconds=configuration.worker.idle_poll_seconds,
        )
    except Exception:
        for store in (runtime_store, control_store):
            if store is not None:
                with suppress(Exception):
                    store.close()
        raise


def run_deployment_reconciler(
    configuration: RuntimeWorkerServiceConfig,
    *,
    environment: Mapping[str, str] | None = None,
) -> None:
    selected_environment = os.environ if environment is None else environment
    service = build_deployment_reconciler_service(
        configuration,
        environment=selected_environment,
    )
    previous: dict[signal.Signals, Any] = {}

    def stop(signum: int, frame: FrameType | None) -> None:
        del signum, frame
        service.request_stop()

    for signum in (signal.SIGTERM, signal.SIGINT):
        previous[signum] = signal.getsignal(signum)
        signal.signal(signum, stop)
    try:
        service.run()
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


__all__ = [
    "DeploymentReconcilerService",
    "DeploymentReconcilerStatus",
    "RegisteredConfigurationDeploymentTarget",
    "build_deployment_reconciler_service",
    "run_deployment_reconciler",
]
