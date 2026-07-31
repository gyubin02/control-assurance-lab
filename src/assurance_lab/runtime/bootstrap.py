"""Production composition for one non-interactive tenant runtime worker."""

from __future__ import annotations

import importlib
import os
import re
import stat
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, cast

from assurance_lab.connectors.postgres_pam_journal import (
    PostgresDefenderTokenJournal,
    PostgresPamConnectionPool,
)
from assurance_lab.control_plane.models import (
    DefenderSourceConfiguration,
    ElasticSourceConfiguration,
)
from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.evidence.s3_object_lock import (
    S3ObjectLockCustody,
    S3RetentionPolicy,
    create_boto3_s3_client,
)
from assurance_lab.evidence.vault_transit import (
    VaultTransitEd25519ReceiptSigner,
)
from assurance_lab.key_management.azure_identity import (
    AzureWorkloadIdentityTokenProvider,
)
from assurance_lab.key_management.azure_secret import (
    AzureKeyVaultSecretClient,
    AzureKeyVaultSecretReference,
)
from assurance_lab.runtime.custody_identity import (
    CustodySigningDeploymentProfile,
    ExactCustodyRuntimeProfileRegistry,
    RegisteredCustodySigningRuntime,
)
from assurance_lab.runtime.defender_identity import (
    prepare_defender_runtime_identity,
)
from assurance_lab.runtime.deployment_io import (
    ProjectedFederatedAssertionSource,
    SecureFileVaultTokenProvider,
    read_pinned_public_file,
    validate_shared_work_root,
)
from assurance_lab.runtime.elastic_identity import (
    PrevalidatedElasticCATrust,
    prepare_elastic_runtime_identity,
)
from assurance_lab.runtime.environment import (
    ExactExecutionEnvironmentProvider,
    ExactSourceRuntimeRegistry,
    PinnedDefenderSourceRuntimeProvider,
    PinnedElasticSourceRuntimeProvider,
    SourceRuntimeProvider,
    source_configuration_digest,
)
from assurance_lab.runtime.execution_journal import PostgresExecutionJournal
from assurance_lab.runtime.executor import DurableControlRunExecutor
from assurance_lab.runtime.models import RuntimeWorkerIdentity, sha256_digest
from assurance_lab.runtime.postgres import PostgresRuntimeCatalog
from assurance_lab.runtime.scheduling import RuntimeScheduler
from assurance_lab.runtime.service_config import (
    AzureWorkloadIdentitySettings,
    ControlRuntimeRegistration,
    DefenderRuntimeSettings,
    ElasticRuntimeSettings,
    PinnedPublicFileSettings,
    RuntimeServiceConfigurationError,
    RuntimeWorkerServiceConfig,
)
from assurance_lab.runtime.worker import (
    RuntimeWorkerEventSink,
    TenantRuntimeWorker,
)

_STAGE_RE: Final = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_PROHIBITED_AWS_SECRET_ENVIRONMENT: Final = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    }
)
_SCHEMA_VERSIONS: Final = {
    "control_assurance_runtime": 3,
    "control_assurance_execution": 6,
    "control_assurance_pam": 3,
}


class RuntimeBootstrapError(RuntimeError):
    """Stable startup failure with no secret-bearing low-level message."""

    __slots__ = ("stage",)

    def __init__(self, stage: str) -> None:
        if type(stage) is not str or _STAGE_RE.fullmatch(stage) is None:
            raise ValueError("runtime bootstrap stage is invalid")
        self.stage = stage
        super().__init__(stage)


class Closable(Protocol):
    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class RuntimeWorkerComponents:
    """Runnable worker plus resources closed after its drain completes."""

    worker: TenantRuntimeWorker
    closers: tuple[Callable[[], None], ...]

    def close(self) -> None:
        failed = False
        for close in self.closers:
            try:
                close()
            except Exception:
                failed = True
        if failed:
            raise RuntimeBootstrapError("resource-close")


@dataclass(frozen=True, slots=True)
class PamJournalNamespacePlan:
    """Secret-free owner-provisioning input derived from approved config."""

    tenant_id: str
    source_kind: str
    source_configuration_digest: str
    purpose: str
    journal_namespace_digest: str


def _resolve_dsn(
    configuration: RuntimeWorkerServiceConfig,
    environment: Mapping[str, str],
) -> tuple[str, str, str]:
    references = configuration.database
    values = (
        references.runtime_dsn.resolve(environment, maximum_bytes=8_192),
        references.execution_journal_dsn.resolve(
            environment,
            maximum_bytes=8_192,
        ),
        references.pam_journal_dsn.resolve(environment, maximum_bytes=8_192),
    )
    if any("\r" in value or "\n" in value for value in values):
        raise RuntimeServiceConfigurationError(
            "database environment reference contains invalid framing"
        )
    return values


def _preflight_database(
    dsn: str,
    *,
    schema: str,
    expected_version: int,
    expected_tenant: str,
    expected_database_role: str,
    expected_principal_kind: str,
    connect_timeout_seconds: int,
) -> None:
    """Require TLS, exact lineage, and one admitted database principal."""

    try:
        psycopg = importlib.import_module("psycopg")
        conninfo = importlib.import_module("psycopg.conninfo")
        rows = importlib.import_module("psycopg.rows")
        parameters = conninfo.conninfo_to_dict(dsn)
        _validate_database_transport(parameters)
        with psycopg.connect(
            dsn,
            autocommit=True,
            connect_timeout=connect_timeout_seconds,
            row_factory=rows.dict_row,
        ) as connection:
            tls = connection.execute(
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
            migration = connection.execute(
                f"""
                SELECT array_agg(version ORDER BY version)
                    AS schema_versions
                FROM {schema}.schema_migrations
                """
            ).fetchone()
            principal = connection.execute(
                f"""
                SELECT
                    current_user::text AS current_role,
                    session_user::text AS session_role,
                    {schema}.assert_session_principal(
                        %s,
                        %s,
                        %s,
                        current_user::text,
                        session_user::text
                    ) AS admitted
                """,
                (
                    expected_tenant,
                    expected_database_role,
                    expected_principal_kind,
                ),
            ).fetchone()
    except RuntimeBootstrapError:
        raise
    except Exception:
        raise RuntimeBootstrapError("database-preflight") from None
    if (
        not isinstance(tls, Mapping)
        or tls.get("tls") is not True
        or not isinstance(principal, Mapping)
        or principal.get("current_role") != expected_database_role
        or principal.get("session_role") != expected_database_role
        or principal.get("admitted") is not True
    ):
        raise RuntimeBootstrapError("database-preflight")
    _validate_schema_lineage(migration, expected_version=expected_version)


def _validate_schema_lineage(
    migration: object,
    *,
    expected_version: int,
) -> None:
    """Reject gaps, extras, duplicates, and downgrade-shaped lineages."""

    if (
        type(expected_version) is not int
        or expected_version < 1
        or not isinstance(migration, Mapping)
        or migration.get("schema_versions")
        != list(range(1, expected_version + 1))
    ):
        raise RuntimeBootstrapError("database-preflight")


def _validate_database_transport(
    parameters: Mapping[str, str],
    *,
    expected_ca_file: Path | None = None,
) -> None:
    """Reject encrypted-but-unauthenticated or standby-ambiguous libpq DSNs."""

    host = parameters.get("host")
    root_certificate = parameters.get("sslrootcert")
    if (
        parameters.get("sslmode") != "verify-full"
        or parameters.get("target_session_attrs") != "read-write"
        or type(host) is not str
        or not host
        or any(not item for item in host.split(","))
        or parameters.get("service") is not None
        or type(root_certificate) is not str
        or not root_certificate
        or (
            expected_ca_file is not None
            and root_certificate != os.fspath(expected_ca_file)
        )
    ):
        raise RuntimeBootstrapError("database-transport-policy")
    path = Path(root_certificate)
    try:
        metadata = path.lstat()
        if (
            not path.is_absolute()
            or path.resolve(strict=True) != path
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or not 0 < metadata.st_size <= 8 * 1024 * 1024
        ):
            raise OSError
    except (OSError, RuntimeError):
        raise RuntimeBootstrapError("database-transport-policy") from None


def _verify_pinned_database_trust(
    configuration: RuntimeWorkerServiceConfig,
    dsns: tuple[str, str, str],
) -> None:
    """Bind every libpq identity to the one digest-pinned database CA."""

    bundle = configuration.database.ca_bundle
    try:
        read_pinned_public_file(bundle)
        conninfo = importlib.import_module("psycopg.conninfo")
        for dsn in dsns:
            parameters = cast(Mapping[str, str], conninfo.conninfo_to_dict(dsn))
            _validate_database_transport(
                parameters,
                expected_ca_file=Path(bundle.file.path),
            )
    except RuntimeBootstrapError:
        raise
    except Exception:
        raise RuntimeBootstrapError("database-trust") from None


def _runtime_public_trust(
    configuration: RuntimeWorkerServiceConfig,
) -> tuple[PinnedPublicFileSettings, ...]:
    selected: list[PinnedPublicFileSettings] = []
    for registration in configuration.registrations:
        source = registration.source_runtime
        selected.append(registration.custody_runtime.vault_transit.ca_bundle)
        if type(source) is ElasticRuntimeSettings:
            selected.append(source.ca_bundle)
        elif type(source) is DefenderRuntimeSettings:
            if source.entra_ca_bundle is not None:
                selected.append(source.entra_ca_bundle)
        else:
            raise RuntimeBootstrapError("source-registration")
        if source.azure_workload_identity.key_vault_ca_bundle is not None:
            selected.append(
                source.azure_workload_identity.key_vault_ca_bundle
            )
    return tuple(selected)


def _verify_non_database_trust(
    configuration: RuntimeWorkerServiceConfig,
) -> None:
    """Verify each unique external trust root before creating network clients."""

    observed: dict[str, str] = {}
    try:
        for bundle in _runtime_public_trust(configuration):
            prior = observed.get(bundle.file.path)
            if prior is not None:
                if prior != bundle.sha256_digest:
                    raise RuntimeServiceConfigurationError(
                        "one public trust path has conflicting release digests"
                    )
                continue
            read_pinned_public_file(bundle)
            observed[bundle.file.path] = bundle.sha256_digest
    except RuntimeBootstrapError:
        raise
    except Exception:
        raise RuntimeBootstrapError("public-trust") from None


def _preflight_databases(
    configuration: RuntimeWorkerServiceConfig,
    dsns: tuple[str, str, str],
) -> None:
    timeout = configuration.database.connect_timeout_seconds
    database = configuration.database
    specifications = (
        (
            "control_assurance_runtime",
            _SCHEMA_VERSIONS["control_assurance_runtime"],
            database.runtime_role,
            "worker",
        ),
        (
            "control_assurance_execution",
            _SCHEMA_VERSIONS["control_assurance_execution"],
            database.execution_journal_role,
            "worker",
        ),
        (
            "control_assurance_pam",
            _SCHEMA_VERSIONS["control_assurance_pam"],
            database.pam_journal_role,
            "broker",
        ),
    )
    for dsn, (schema, version, expected_role, principal_kind) in zip(
        dsns,
        specifications,
        strict=True,
    ):
        _preflight_database(
            dsn,
            schema=schema,
            expected_version=version,
            expected_tenant=configuration.tenant_id,
            expected_database_role=expected_role,
            expected_principal_kind=principal_kind,
            connect_timeout_seconds=timeout,
        )


def _pam_pool(
    dsn: str,
    configuration: RuntimeWorkerServiceConfig,
) -> PostgresPamConnectionPool:
    database = configuration.database
    try:
        pool_module = importlib.import_module("psycopg_pool")
        rows_module = importlib.import_module("psycopg.rows")
        pool = pool_module.ConnectionPool(
            conninfo=dsn,
            min_size=database.min_pool_size,
            max_size=database.max_pool_size,
            timeout=float(database.connect_timeout_seconds),
            kwargs={
                "autocommit": True,
                "connect_timeout": database.connect_timeout_seconds,
                "row_factory": rows_module.dict_row,
            },
            open=True,
        )
    except Exception:
        raise RuntimeBootstrapError("pam-pool") from None
    return cast(PostgresPamConnectionPool, pool)


def _azure_provider(
    settings: AzureWorkloadIdentitySettings,
) -> AzureWorkloadIdentityTokenProvider:
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
        raise RuntimeBootstrapError("azure-workload-identity") from None


def _secret_client(
    reference: str,
    *,
    settings: AzureWorkloadIdentitySettings,
    token_provider: AzureWorkloadIdentityTokenProvider,
) -> AzureKeyVaultSecretClient:
    try:
        parsed = AzureKeyVaultSecretReference.parse(reference)
        return AzureKeyVaultSecretClient(
            token_provider,
            parsed,
            ca_file=(
                None
                if settings.key_vault_ca_bundle is None
                else Path(settings.key_vault_ca_bundle.file.path)
            ),
            request_timeout_seconds=settings.timeout_seconds,
            operation_timeout_seconds=min(
                120,
                max(settings.timeout_seconds, 60),
            ),
        )
    except Exception:
        raise RuntimeBootstrapError("azure-secret-client") from None


def pam_journal_namespace_digest(
    *,
    tenant_id: str,
    source_digest: str,
    purpose: str,
) -> str:
    return sha256_digest(
        canonical_json_bytes(
            {
                "kind": "control-assurance-pam-journal-namespace",
                "purpose": purpose,
                "schema_version": "1.0.0",
                "source_configuration_digest": source_digest,
                "tenant_id": tenant_id,
            }
        )
    )


def plan_pam_journal_namespaces(
    configuration: RuntimeWorkerServiceConfig,
) -> tuple[PamJournalNamespacePlan, ...]:
    """Derive each distinct PAM namespace without resolving any credential."""

    planned: dict[str, PamJournalNamespacePlan] = {}
    for registration in configuration.registrations:
        source = registration.configuration.source
        if type(source) is ElasticSourceConfiguration:
            purpose = "elastic-jit-api-key"
        elif type(source) is DefenderSourceConfiguration:
            purpose = "defender-workload-token"
        else:
            raise RuntimeBootstrapError("pam-namespace-plan")
        source_digest = source_configuration_digest(source)
        namespace_digest = pam_journal_namespace_digest(
            tenant_id=registration.configuration.tenant_id,
            source_digest=source_digest,
            purpose=purpose,
        )
        entry = PamJournalNamespacePlan(
            tenant_id=registration.configuration.tenant_id,
            source_kind=source.kind,
            source_configuration_digest=source_digest,
            purpose=purpose,
            journal_namespace_digest=namespace_digest,
        )
        previous = planned.setdefault(namespace_digest, entry)
        if previous != entry:
            raise RuntimeBootstrapError("pam-namespace-plan")
    return tuple(planned[key] for key in sorted(planned))


def _elastic_provider(
    registration: ControlRuntimeRegistration,
    *,
    pam_pool: PostgresPamConnectionPool,
    database_statement_timeout_ms: int,
    database_lock_timeout_ms: int,
) -> PinnedElasticSourceRuntimeProvider:
    configuration = registration.configuration.source
    runtime = registration.source_runtime
    if (
        type(configuration) is not ElasticSourceConfiguration
        or type(runtime) is not ElasticRuntimeSettings
    ):
        raise RuntimeBootstrapError("source-registration")
    azure = _azure_provider(runtime.azure_workload_identity)
    secret_client = _secret_client(
        configuration.parent_credential_ref,
        settings=runtime.azure_workload_identity,
        token_provider=azure,
    )
    try:
        ca_trust = PrevalidatedElasticCATrust.from_path(
            Path(runtime.ca_bundle.file.path),
            configured_reference=configuration.ca_bundle_ref,
        )
        if ca_trust.bundle_digest != runtime.ca_bundle.sha256_digest:
            raise RuntimeBootstrapError("elastic-ca-trust")
    except Exception:
        raise RuntimeBootstrapError("elastic-ca-trust") from None
    namespace = pam_journal_namespace_digest(
        tenant_id=registration.configuration.tenant_id,
        source_digest=source_configuration_digest(configuration),
        purpose="elastic-jit-api-key",
    )

    def compose() -> Any:
        try:
            key_vault_ca = (
                runtime.azure_workload_identity.key_vault_ca_bundle
            )
            if key_vault_ca is not None:
                read_pinned_public_file(key_vault_ca)
            return prepare_elastic_runtime_identity(
                configuration,
                parent_secret_client=secret_client,
                journal_pool=pam_pool,
                journal_namespace_digest=namespace,
                ca_trust=ca_trust,
                request_timeout_seconds=runtime.request_timeout_seconds,
                journal_statement_timeout_ms=database_statement_timeout_ms,
                journal_lock_timeout_ms=database_lock_timeout_ms,
            )
        except Exception:
            raise RuntimeBootstrapError("elastic-runtime-identity") from None

    first = [compose()]

    def resolve() -> Any:
        if first:
            return first.pop()
        return compose()

    return PinnedElasticSourceRuntimeProvider(configuration, resolve)


def _defender_provider(
    registration: ControlRuntimeRegistration,
    *,
    pam_pool: PostgresPamConnectionPool,
    database_statement_timeout_ms: int,
    database_lock_timeout_ms: int,
) -> PinnedDefenderSourceRuntimeProvider:
    configuration = registration.configuration.source
    runtime = registration.source_runtime
    if (
        type(configuration) is not DefenderSourceConfiguration
        or type(runtime) is not DefenderRuntimeSettings
    ):
        raise RuntimeBootstrapError("source-registration")
    azure = _azure_provider(runtime.azure_workload_identity)
    secret_client = _secret_client(
        configuration.client_credential_ref,
        settings=runtime.azure_workload_identity,
        token_provider=azure,
    )
    namespace = pam_journal_namespace_digest(
        tenant_id=registration.configuration.tenant_id,
        source_digest=source_configuration_digest(configuration),
        purpose="defender-workload-token",
    )
    try:
        journal = PostgresDefenderTokenJournal(
            pam_pool,
            journal_namespace_digest=namespace,
            statement_timeout_ms=database_statement_timeout_ms,
            lock_timeout_ms=database_lock_timeout_ms,
        )
        assertion_source = (
            None
            if runtime.federated_assertion is None
            else ProjectedFederatedAssertionSource(
                runtime.federated_assertion
            )
        )
    except Exception:
        raise RuntimeBootstrapError("defender-runtime-composition") from None

    def compose() -> Any:
        try:
            key_vault_ca = (
                runtime.azure_workload_identity.key_vault_ca_bundle
            )
            if key_vault_ca is not None:
                read_pinned_public_file(key_vault_ca)
            if runtime.entra_ca_bundle is not None:
                read_pinned_public_file(runtime.entra_ca_bundle)
            return prepare_defender_runtime_identity(
                configuration,
                credential_secret_client=secret_client,
                journal=journal,
                key_vault_token_provider=(
                    azure
                    if runtime.credential_mode == "certificate-ps256"
                    else None
                ),
                federated_assertion_source=assertion_source,
                key_vault_ca_file=(
                    None
                    if runtime.azure_workload_identity.key_vault_ca_bundle
                    is None
                    else Path(
                        runtime.azure_workload_identity.key_vault_ca_bundle.file.path
                    )
                ),
                entra_ca_file=(
                    None
                    if runtime.entra_ca_bundle is None
                    else Path(runtime.entra_ca_bundle.file.path)
                ),
                request_timeout_seconds=runtime.request_timeout_seconds,
                key_vault_operation_timeout_seconds=(
                    runtime.key_vault_operation_timeout_seconds
                ),
            )
        except Exception:
            raise RuntimeBootstrapError("defender-runtime-identity") from None

    first = [compose()]

    def resolve() -> Any:
        if first:
            return first.pop()
        return compose()

    return PinnedDefenderSourceRuntimeProvider(configuration, resolve)


def _physical_custody_key(
    registration: ControlRuntimeRegistration,
) -> bytes:
    settings = registration.custody_runtime
    return canonical_json_bytes(
        {
            "s3": settings.s3.model_dump(mode="json"),
            "vault_transit": settings.vault_transit.model_dump(mode="json"),
        }
    )


def _custody_runtime(
    registration: ControlRuntimeRegistration,
    *,
    cache: dict[
        bytes,
        tuple[S3ObjectLockCustody, VaultTransitEd25519ReceiptSigner],
    ],
) -> RegisteredCustodySigningRuntime:
    profile, custody, signer = _custody_deployment_profile(
        registration,
        cache=cache,
    )
    try:
        if profile.digest != registration.custody_runtime.expected_profile_digest:
            raise RuntimeBootstrapError("custody-profile-drift")
        return RegisteredCustodySigningRuntime(
            profile.canonical_bytes(),
            custody,
            signer,
        )
    except RuntimeBootstrapError:
        raise
    except Exception:
        raise RuntimeBootstrapError("custody-profile") from None


def _custody_deployment_profile(
    registration: ControlRuntimeRegistration,
    *,
    cache: dict[
        bytes,
        tuple[S3ObjectLockCustody, VaultTransitEd25519ReceiptSigner],
    ],
) -> tuple[
    CustodySigningDeploymentProfile,
    S3ObjectLockCustody,
    VaultTransitEd25519ReceiptSigner,
]:
    settings = registration.custody_runtime
    key = _physical_custody_key(registration)
    physical = cache.get(key)
    if physical is None:
        s3 = settings.s3
        vault = settings.vault_transit
        try:
            client = create_boto3_s3_client(
                region_name=s3.region,
                connect_timeout_seconds=s3.connect_timeout_seconds,
                read_timeout_seconds=s3.read_timeout_seconds,
            )
            custody = S3ObjectLockCustody(
                client,
                bucket_name=s3.bucket_name,
                bucket_arn=s3.bucket_arn,
                expected_bucket_owner=s3.expected_bucket_owner,
                kms_key_arn=s3.kms_key_arn,
                encryption=s3.encryption,
                retention_policy=S3RetentionPolicy(
                    minimum_seconds=s3.minimum_retention_seconds,
                    maximum_seconds=s3.maximum_retention_seconds,
                    max_object_bytes=s3.maximum_object_bytes,
                ),
            )
            token_provider = SecureFileVaultTokenProvider(
                vault.token,
                validity_seconds=vault.token_validity_seconds,
            )
            read_pinned_public_file(vault.ca_bundle)
            signer = VaultTransitEd25519ReceiptSigner(
                token_provider,
                endpoint=vault.endpoint,
                mount_path=vault.mount_path,
                key_name=vault.key_name,
                key_id=vault.key_id,
                namespace=vault.namespace,
                ca_file=Path(vault.ca_bundle.file.path),
                request_timeout_seconds=vault.request_timeout_seconds,
                initialization_timeout_seconds=(
                    vault.initialization_timeout_seconds
                ),
                sign_timeout_seconds=vault.sign_timeout_seconds,
            )
        except Exception:
            raise RuntimeBootstrapError("custody-runtime") from None
        physical = custody, signer
        cache[key] = physical
    custody, signer = physical
    try:
        profile = CustodySigningDeploymentProfile.from_runtime(
            profile_id=settings.profile_id,
            configuration=registration.configuration,
            custody=custody,
            signer=signer,
        )
        return profile, custody, signer
    except Exception:
        raise RuntimeBootstrapError("custody-profile") from None


def inspect_custody_deployment_profiles(
    configuration: RuntimeWorkerServiceConfig,
    *,
    environment: Mapping[str, str],
) -> tuple[CustodySigningDeploymentProfile, ...]:
    """Resolve only read-only public S3/Vault identities for release pinning."""

    if type(configuration) is not RuntimeWorkerServiceConfig:
        raise TypeError("runtime worker configuration must be exact")
    if any(environment.get(name) for name in _PROHIBITED_AWS_SECRET_ENVIRONMENT):
        raise RuntimeBootstrapError("static-aws-credentials")
    _verify_non_database_trust(configuration)
    cache: dict[
        bytes,
        tuple[S3ObjectLockCustody, VaultTransitEd25519ReceiptSigner],
    ] = {}
    return tuple(
        _custody_deployment_profile(registration, cache=cache)[0]
        for registration in configuration.registrations
    )


def _source_registry(
    configuration: RuntimeWorkerServiceConfig,
    *,
    pam_pool: PostgresPamConnectionPool,
) -> ExactSourceRuntimeRegistry:
    selected: dict[str, SourceRuntimeProvider] = {}
    for registration in configuration.registrations:
        source_digest = source_configuration_digest(
            registration.configuration.source
        )
        if source_digest in selected:
            continue
        runtime = registration.source_runtime
        if type(runtime) is ElasticRuntimeSettings:
            provider: SourceRuntimeProvider = _elastic_provider(
                registration,
                pam_pool=pam_pool,
                database_statement_timeout_ms=(
                    configuration.database.statement_timeout_ms
                ),
                database_lock_timeout_ms=(
                    configuration.database.lock_timeout_ms
                ),
            )
        elif type(runtime) is DefenderRuntimeSettings:
            provider = _defender_provider(
                registration,
                pam_pool=pam_pool,
                database_statement_timeout_ms=(
                    configuration.database.statement_timeout_ms
                ),
                database_lock_timeout_ms=(
                    configuration.database.lock_timeout_ms
                ),
            )
        else:
            raise RuntimeBootstrapError("source-registration")
        selected[source_digest] = provider
    try:
        return ExactSourceRuntimeRegistry(selected.values())
    except Exception:
        raise RuntimeBootstrapError("source-registry") from None


def _custody_registry(
    configuration: RuntimeWorkerServiceConfig,
) -> ExactCustodyRuntimeProfileRegistry:
    cache: dict[
        bytes,
        tuple[S3ObjectLockCustody, VaultTransitEd25519ReceiptSigner],
    ] = {}
    registrations = tuple(
        _custody_runtime(registration, cache=cache)
        for registration in configuration.registrations
    )
    try:
        return ExactCustodyRuntimeProfileRegistry(registrations)
    except Exception:
        raise RuntimeBootstrapError("custody-registry") from None


class ProductionRuntimeWorkerFactory:
    """Create the exact catalog → scheduler → executor → worker stack."""

    __slots__ = ("_configuration", "_environment")

    def __init__(
        self,
        configuration: RuntimeWorkerServiceConfig,
        *,
        environment: Mapping[str, str],
    ) -> None:
        if type(configuration) is not RuntimeWorkerServiceConfig:
            raise TypeError("runtime worker configuration must be exact")
        self._configuration = configuration
        references = configuration.database
        names = {
            configuration.worker_id.name,
            configuration.worker_credential_digest.name,
            configuration.source_revision.name,
            references.runtime_dsn.name,
            references.execution_journal_dsn.name,
            references.pam_journal_dsn.name,
            *_PROHIBITED_AWS_SECRET_ENVIRONMENT,
        }
        self._environment = {
            name: value
            for name in names
            if type(value := environment.get(name)) is str
        }

    def build(
        self,
        *,
        event_sink: RuntimeWorkerEventSink | None = None,
    ) -> RuntimeWorkerComponents:
        configuration = self._configuration
        environment = self._environment
        if any(environment.get(name) for name in _PROHIBITED_AWS_SECRET_ENVIRONMENT):
            raise RuntimeBootstrapError("static-aws-credentials")

        worker_id = configuration.resolve_worker_id(environment)
        credential_digest = configuration.resolve_worker_credential_digest(
            environment
        )
        source_revision = configuration.resolve_source_revision(environment)
        dsns = _resolve_dsn(configuration, environment)
        _verify_pinned_database_trust(configuration, dsns)
        _verify_non_database_trust(configuration)
        _preflight_databases(configuration, dsns)
        work_root = validate_shared_work_root(configuration.work_root)

        runtime_dsn, execution_dsn, pam_dsn = dsns
        database = configuration.database
        pam_pool = _pam_pool(pam_dsn, configuration)
        catalog: PostgresRuntimeCatalog | None = None
        journal: PostgresExecutionJournal | None = None
        try:
            source_registry = _source_registry(
                configuration,
                pam_pool=pam_pool,
            )
            custody_registry = _custody_registry(configuration)
            environment_provider = ExactExecutionEnvironmentProvider(
                source_registry=source_registry,
                custody_registry=custody_registry,
            )
            catalog = PostgresRuntimeCatalog.from_dsn(
                runtime_dsn,
                min_size=database.min_pool_size,
                max_size=database.max_pool_size,
                connect_timeout_seconds=database.connect_timeout_seconds,
                statement_timeout_ms=database.statement_timeout_ms,
                lock_timeout_ms=database.lock_timeout_ms,
                max_run_attempts=configuration.worker.max_attempts,
            )
            journal = PostgresExecutionJournal.from_dsn(
                execution_dsn,
                min_size=database.min_pool_size,
                max_size=database.max_pool_size,
                connect_timeout_seconds=database.connect_timeout_seconds,
                statement_timeout_ms=database.statement_timeout_ms,
                lock_timeout_ms=database.lock_timeout_ms,
            )
            executor = DurableControlRunExecutor(
                journal,
                environment_provider,
                work_root=work_root,
                worker_id=worker_id,
                source_revision=source_revision,
            )
            scheduler = RuntimeScheduler(
                catalog,
                executor,
                RuntimeWorkerIdentity(
                    tenant_id=configuration.tenant_id,
                    worker_id=worker_id,
                    credential_digest=credential_digest,
                ),
                lease_ttl_seconds=configuration.worker.lease_ttl_seconds,
                max_attempts=configuration.worker.max_attempts,
                base_retry_seconds=(
                    configuration.worker.run_retry_base_seconds
                ),
                max_retry_seconds=(
                    configuration.worker.run_retry_max_seconds
                ),
            )
            worker = TenantRuntimeWorker(
                catalog,
                scheduler,
                tenant_id=configuration.tenant_id,
                max_runs_per_cycle=(
                    configuration.worker.max_runs_per_cycle
                ),
                materialization_interval_seconds=(
                    configuration.worker.materialization_interval_seconds
                ),
                idle_poll_seconds=configuration.worker.idle_poll_seconds,
                backoff_base_seconds=(
                    configuration.worker.backoff_base_seconds
                ),
                backoff_max_seconds=(
                    configuration.worker.backoff_max_seconds
                ),
                event_sink=event_sink,
            )
        except Exception as exc:
            if journal is not None:
                with suppress(Exception):
                    journal.close_pool()
            if catalog is not None:
                with suppress(Exception):
                    catalog.close()
            close = getattr(pam_pool, "close", None)
            if callable(close):
                with suppress(Exception):
                    close()
            if isinstance(exc, RuntimeBootstrapError):
                raise
            raise RuntimeBootstrapError("runtime-composition") from None

        pam_close = getattr(pam_pool, "close", None)
        assert callable(pam_close)
        return RuntimeWorkerComponents(
            worker=worker,
            closers=(
                journal.close_pool,
                catalog.close,
                cast(Callable[[], None], pam_close),
            ),
        )


__all__ = [
    "ProductionRuntimeWorkerFactory",
    "RuntimeBootstrapError",
    "RuntimeWorkerComponents",
    "inspect_custody_deployment_profiles",
]
