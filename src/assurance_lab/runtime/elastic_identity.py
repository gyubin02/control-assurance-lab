"""Resolve and bind one production Elastic Security runtime identity.

The control plane stores references, not credentials.  This module is the
composition boundary that turns one exact-version Azure Key Vault secret into
an opaque Elastic parent credential, a PostgreSQL-backed JIT API-key broker,
and a canonical public identity describing the authority the broker may use.

The parent credential never becomes a field, log value, or exception detail.
The public identity contains only secret-free policy and content digests.

``ElasticJitApiKeyBroker`` currently accepts a CA bundle as a filesystem path.
For that reason this boundary requires a prevalidated, owner-controlled PEM
path and rechecks its content digest immediately before every managed source
is prepared and every child connector is constructed.  The remaining
secret-to-file bootstrap boundary is documented in
``docs/elastic-runtime-identity.md``.
"""

from __future__ import annotations

import hashlib
import os
import re
import ssl
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from assurance_lab.connectors.elastic_pam import (
    ELASTIC_PAM_BROKER_ID,
    ElasticJitApiKeyBroker,
    ElasticPamPolicy,
    ElasticParentCredential,
)
from assurance_lab.connectors.elastic_security import (
    ELASTIC_SECURITY_CONNECTOR_ID,
    ElasticApiKey,
    ElasticSecurityConnector,
    elastic_endpoint_origin_digest,
)
from assurance_lab.connectors.postgres_pam_journal import (
    PostgresElasticLeaseJournal,
    PostgresPamConnectionPool,
)
from assurance_lab.connectors.secret_profiles import (
    ELASTIC_PARENT_CREDENTIAL_CONTENT_TYPE,
    ConnectorSecretProfileError,
    decode_elastic_parent_credential,
)
from assurance_lab.control_plane.models import (
    ControlConfiguration,
    ElasticSourceConfiguration,
)
from assurance_lab.evidence.canonical import (
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)
from assurance_lab.key_management.azure_secret import (
    AzureKeyVaultSecretClient,
    AzureKeyVaultSecretError,
    AzureKeyVaultSecretReference,
    AzureKeyVaultSecretValue,
)
from assurance_lab.runtime.execution_plan import ControlRunExecutionPlan
from assurance_lab.runtime.managed_source import (
    PreparedManagedSource,
    prepare_elastic_managed_source,
)
from assurance_lab.runtime.models import (
    ControlRunExecutionRequest,
    sha256_digest,
)

ELASTIC_RUNTIME_IDENTITY_MEDIA_TYPE: Final = (
    "application/vnd.control-assurance.elastic-runtime-identity.v1+json"
)
ELASTIC_RUNTIME_IDENTITY_SCHEMA_VERSION: Final = "1.0.0"
ELASTIC_CA_TRUST_PROFILE: Final = "owner-controlled-pem-path-v1"

_DIGEST_RE: Final = re.compile(r"^sha256:[a-f0-9]{64}$")
_MAX_CA_BYTES: Final = 8 * 1024 * 1024
_MIN_TIMEOUT_SECONDS: Final = 1
_MAX_TIMEOUT_SECONDS: Final = 120


class ElasticRuntimeIdentityError(RuntimeError):
    """Stable runtime-composition failure without credential material."""

    __slots__ = ("stage",)

    def __init__(self, stage: str, detail: str) -> None:
        if (
            type(stage) is not str
            or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", stage) is None
        ):
            raise ValueError("runtime identity failure stage is invalid")
        if type(detail) is not str or not detail or len(detail) > 256:
            raise ValueError("runtime identity failure detail is invalid")
        self.stage = stage
        super().__init__(detail)


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _reference_digest(value: str | None) -> str | None:
    return None if value is None else _digest(value.encode("utf-8"))


def _timeout(value: int) -> int:
    if (
        type(value) is not int
        or not _MIN_TIMEOUT_SECONDS <= value <= _MAX_TIMEOUT_SECONDS
    ):
        raise ValueError("Elastic request timeout is outside the supported range")
    return value


def _source_digest(configuration: ElasticSourceConfiguration) -> str:
    return sha256_digest(
        canonical_json_bytes(configuration.model_dump(mode="json"))
    )


@dataclass(frozen=True, slots=True, repr=False)
class PrevalidatedElasticCATrust:
    """One owner-controlled PEM file and its exact public content identity.

    ``configured_reference`` records which immutable configuration reference
    the operator says was materialized.  This class verifies the path and
    bytes, but it deliberately does not claim to have retrieved those bytes
    from the secret manager.
    """

    path: Path = field(repr=False, compare=False)
    configured_reference: str | None
    configured_reference_digest: str | None
    bundle_digest: str
    _owner_uid: int = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.path, Path) or not self.path.is_absolute():
            raise ValueError("Elastic CA trust path must be absolute")
        if (
            self.configured_reference_digest
            != _reference_digest(self.configured_reference)
        ):
            raise ValueError("Elastic CA reference digest differs from its reference")
        if (
            type(self.bundle_digest) is not str
            or _DIGEST_RE.fullmatch(self.bundle_digest) is None
        ):
            raise ValueError("Elastic CA bundle digest is invalid")
        if type(self._owner_uid) is not int or self._owner_uid < 0:
            raise ValueError("Elastic CA owner identity is invalid")

    def __repr__(self) -> str:
        return (
            "PrevalidatedElasticCATrust("
            f"profile={ELASTIC_CA_TRUST_PROFILE!r}, "
            f"configured_reference_digest={self.configured_reference_digest!r}, "
            f"bundle_digest={self.bundle_digest!r}, path=<redacted>)"
        )

    @classmethod
    def from_path(
        cls,
        path: Path,
        *,
        configured_reference: str | None,
    ) -> PrevalidatedElasticCATrust:
        """Validate one exact path without retaining its certificate bytes."""

        if not isinstance(path, Path) or not path.is_absolute():
            raise ElasticRuntimeIdentityError(
                "ca-trust",
                "Elastic CA trust path must be one absolute owner-controlled path",
            )
        if configured_reference is not None:
            try:
                AzureKeyVaultSecretReference.parse(configured_reference)
            except ValueError:
                raise ElasticRuntimeIdentityError(
                    "ca-trust",
                    "Elastic CA reference is not one exact Azure Key Vault secret version",
                ) from None
        owner_uid = os.geteuid()
        bundle_digest = _read_and_validate_ca(
            path,
            expected_owner_uid=owner_uid,
        )
        return cls(
            path=path,
            configured_reference=configured_reference,
            configured_reference_digest=_reference_digest(
                configured_reference
            ),
            bundle_digest=bundle_digest,
            _owner_uid=owner_uid,
        )

    def assert_current(self) -> None:
        """Fail if pathname, ownership, permissions, or bytes have changed."""

        try:
            observed = _read_and_validate_ca(
                self.path,
                expected_owner_uid=self._owner_uid,
            )
        except ElasticRuntimeIdentityError:
            raise
        except Exception:
            raise ElasticRuntimeIdentityError(
                "ca-trust",
                "Elastic CA trust could not be revalidated safely",
            ) from None
        if observed != self.bundle_digest:
            raise ElasticRuntimeIdentityError(
                "ca-trust",
                "Elastic CA trust bytes changed after approval",
            )


def _read_and_validate_ca(path: Path, *, expected_owner_uid: int) -> str:
    """Safely read, parse, and identify one bounded PEM trust bundle."""

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    content = bytearray()
    try:
        resolved = path.resolve(strict=True)
        if resolved != path:
            raise ElasticRuntimeIdentityError(
                "ca-trust",
                "Elastic CA trust path must not traverse symbolic links",
            )
        parent = path.parent.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid not in {0, expected_owner_uid}
            or parent.st_mode & 0o022
        ):
            raise ElasticRuntimeIdentityError(
                "ca-trust",
                "Elastic CA trust parent directory is not operator-controlled",
            )
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_owner_uid
            or before.st_mode & 0o077
            or before.st_nlink != 1
            or not 1 <= before.st_size <= _MAX_CA_BYTES
        ):
            raise ElasticRuntimeIdentityError(
                "ca-trust",
                "Elastic CA trust must be one owner-only single-link regular file",
            )
        while len(content) <= _MAX_CA_BYTES:
            chunk = os.read(
                descriptor,
                min(64 * 1024, _MAX_CA_BYTES + 1 - len(content)),
            )
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if (
            identity_before != identity_after
            or len(content) != after.st_size
            or len(content) > _MAX_CA_BYTES
        ):
            raise ElasticRuntimeIdentityError(
                "ca-trust",
                "Elastic CA trust changed while it was inspected",
            )
    except ElasticRuntimeIdentityError:
        raise
    except (OSError, RuntimeError):
        raise ElasticRuntimeIdentityError(
            "ca-trust",
            "Elastic CA trust could not be read safely",
        ) from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    try:
        pem = bytes(content).decode("ascii", errors="strict")
        if "-----BEGIN CERTIFICATE-----" not in pem:
            raise ValueError
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cadata=pem)
    except (UnicodeDecodeError, ValueError, ssl.SSLError):
        raise ElasticRuntimeIdentityError(
            "ca-trust",
            "Elastic CA trust is not a usable PEM certificate bundle",
        ) from None
    return _digest(bytes(content))


@dataclass(frozen=True, slots=True, repr=False)
class PreparedElasticRuntimeIdentity:
    """Exact broker plus the secret-free identity under which it may run."""

    source_configuration_digest: str
    endpoint_origin_digest: str
    index_alias: str
    lease_ttl_seconds: int
    pam_mode: str
    parent_authentication_scheme: str
    parent_configuration_reference_digest: str
    parent_secret_reference_digest: str
    role_descriptor_bytes: bytes = field(repr=False)
    role_descriptor_digest: str
    ca_trust_profile: str
    ca_bundle_reference_digest: str | None
    ca_bundle_digest: str
    journal_namespace_digest: str
    request_timeout_seconds: int
    runtime_identity_bytes: bytes = field(repr=False)
    runtime_identity_digest: str
    broker: ElasticJitApiKeyBroker = field(repr=False, compare=False)
    ca_trust: PrevalidatedElasticCATrust = field(
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        digests = (
            self.source_configuration_digest,
            self.endpoint_origin_digest,
            self.parent_configuration_reference_digest,
            self.parent_secret_reference_digest,
            self.role_descriptor_digest,
            self.ca_bundle_digest,
            self.journal_namespace_digest,
            self.runtime_identity_digest,
        )
        if any(
            type(value) is not str or _DIGEST_RE.fullmatch(value) is None
            for value in digests
        ):
            raise ValueError("prepared Elastic identity contains an invalid digest")
        if self.ca_bundle_reference_digest is not None and (
            type(self.ca_bundle_reference_digest) is not str
            or _DIGEST_RE.fullmatch(self.ca_bundle_reference_digest) is None
        ):
            raise ValueError("prepared Elastic CA reference digest is invalid")
        if (
            type(self.broker) is not ElasticJitApiKeyBroker
            or type(self.ca_trust) is not PrevalidatedElasticCATrust
        ):
            raise TypeError("prepared Elastic runtime dependencies are invalid")
        try:
            policy = ElasticPamPolicy(
                index_alias=self.index_alias,
                ttl_seconds=self.lease_ttl_seconds,
            )
            timeout = _timeout(self.request_timeout_seconds)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "prepared Elastic policy is outside the runtime profile"
            ) from exc
        if (
            self.pam_mode != "elastic-jit-api-key"
            or self.parent_authentication_scheme not in {"Basic", "Bearer"}
            or self.ca_trust_profile != ELASTIC_CA_TRUST_PROFILE
            or timeout != self.request_timeout_seconds
            or canonical_json_bytes(policy.role_descriptor())
            != self.role_descriptor_bytes
            or policy.role_descriptor_digest != self.role_descriptor_digest
        ):
            raise ValueError(
                "prepared Elastic policy differs from its least-privilege profile"
            )
        if (
            self.broker.endpoint_origin_digest != self.endpoint_origin_digest
            or self.ca_trust.bundle_digest != self.ca_bundle_digest
            or self.ca_trust.configured_reference_digest
            != self.ca_bundle_reference_digest
        ):
            raise ValueError("prepared Elastic dependencies differ from identity")
        if (
            _digest(self.role_descriptor_bytes) != self.role_descriptor_digest
            or _digest(self.runtime_identity_bytes)
            != self.runtime_identity_digest
        ):
            raise ValueError("prepared Elastic identity digest differs from its bytes")
        try:
            role = strict_json_loads(self.role_descriptor_bytes)
            identity = strict_json_loads(self.runtime_identity_bytes)
        except StrictJSONError as exc:
            raise ValueError("prepared Elastic identity is not strict JSON") from exc
        if (
            not isinstance(role, dict)
            or canonical_json_bytes(role) != self.role_descriptor_bytes
            or not isinstance(identity, dict)
            or canonical_json_bytes(identity) != self.runtime_identity_bytes
        ):
            raise ValueError("prepared Elastic identity is not canonical JSON")
        expected = {
            "broker_id": ELASTIC_PAM_BROKER_ID,
            "ca_bundle_digest": self.ca_bundle_digest,
            "ca_bundle_reference_digest": (
                self.ca_bundle_reference_digest
            ),
            "ca_trust_profile": self.ca_trust_profile,
            "connector_id": ELASTIC_SECURITY_CONNECTOR_ID,
            "endpoint_origin_digest": self.endpoint_origin_digest,
            "index_alias": self.index_alias,
            "journal_namespace_digest": self.journal_namespace_digest,
            "kind": "elastic-runtime-identity",
            "lease_ttl_seconds": self.lease_ttl_seconds,
            "media_type": ELASTIC_RUNTIME_IDENTITY_MEDIA_TYPE,
            "pam_mode": self.pam_mode,
            "parent_authentication_scheme": (
                self.parent_authentication_scheme
            ),
            "parent_configuration_reference_digest": (
                self.parent_configuration_reference_digest
            ),
            "parent_secret_reference_digest": (
                self.parent_secret_reference_digest
            ),
            "request_timeout_seconds": self.request_timeout_seconds,
            "role_descriptor": role,
            "role_descriptor_digest": self.role_descriptor_digest,
            "schema_version": ELASTIC_RUNTIME_IDENTITY_SCHEMA_VERSION,
            "source_configuration_digest": (
                self.source_configuration_digest
            ),
        }
        if identity != expected:
            raise ValueError(
                "prepared Elastic runtime identity differs from its fields"
            )

    def __repr__(self) -> str:
        return (
            "PreparedElasticRuntimeIdentity("
            f"endpoint_origin_digest={self.endpoint_origin_digest!r}, "
            f"role_descriptor_digest={self.role_descriptor_digest!r}, "
            f"ca_bundle_digest={self.ca_bundle_digest!r}, "
            f"runtime_identity_digest={self.runtime_identity_digest!r}, "
            "broker=<redacted>, ca_trust_path=<redacted>)"
        )

    def assert_runtime_identity(
        self,
        *,
        expected_bytes: bytes,
        expected_digest: str,
    ) -> None:
        """Require exact approved public identity bytes at execution."""

        if (
            type(expected_bytes) is not bytes
            or type(expected_digest) is not str
            or _DIGEST_RE.fullmatch(expected_digest) is None
            or _digest(expected_bytes) != expected_digest
        ):
            raise ElasticRuntimeIdentityError(
                "identity-binding",
                "expected Elastic runtime identity is invalid",
            )
        if (
            expected_bytes != self.runtime_identity_bytes
            or expected_digest != self.runtime_identity_digest
        ):
            raise ElasticRuntimeIdentityError(
                "identity-binding",
                "Elastic runtime identity differs from the approved identity",
            )

    def prepare_managed_source(
        self,
        execution_request: ControlRunExecutionRequest,
        plan: ControlRunExecutionPlan,
    ) -> PreparedManagedSource:
        """Bind this exact broker to one frozen scheduler request and plan."""

        return prepare_elastic_managed_source_from_identity(
            execution_request,
            plan,
            runtime_identity=self,
        )


@dataclass(frozen=True, slots=True)
class _ExactElasticConnectorFactory:
    endpoint: str
    ca_trust: PrevalidatedElasticCATrust
    timeout_seconds: int

    def __call__(self, api_key: ElasticApiKey) -> ElasticSecurityConnector:
        self.ca_trust.assert_current()
        try:
            connector = ElasticSecurityConnector(
                self.endpoint,
                api_key,
                ca_file=self.ca_trust.path,
                timeout_seconds=self.timeout_seconds,
            )
            self.ca_trust.assert_current()
            return connector
        except (OSError, TypeError, ValueError):
            raise ElasticRuntimeIdentityError(
                "ca-trust",
                "Elastic connector could not establish the approved TLS trust",
            ) from None


def _load_parent_credential(
    configuration: ElasticSourceConfiguration,
    secret_client: AzureKeyVaultSecretClient,
) -> tuple[
    AzureKeyVaultSecretReference,
    ElasticParentCredential,
]:
    try:
        reference = AzureKeyVaultSecretReference.parse(
            configuration.parent_credential_ref
        )
    except ValueError:
        raise ElasticRuntimeIdentityError(
            "credential-reference",
            "Elastic parent credential is not one exact Azure Key Vault secret version",
        ) from None
    if type(secret_client) is not AzureKeyVaultSecretClient:
        raise TypeError(
            "parent credential client must be an exact AzureKeyVaultSecretClient"
        )
    if secret_client.reference_digest != reference.reference_digest:
        raise ElasticRuntimeIdentityError(
            "credential-reference",
            "Elastic secret client differs from the deployed parent credential reference",
        )
    try:
        secret_value = secret_client.get()
    except Exception:
        raise ElasticRuntimeIdentityError(
            "credential-secret",
            "Elastic parent credential could not be resolved safely",
        ) from None
    if (
        type(secret_value) is not AzureKeyVaultSecretValue
        or secret_value.reference_digest != reference.reference_digest
    ):
        raise ElasticRuntimeIdentityError(
            "credential-secret",
            "Elastic parent credential crossed its exact-version boundary",
        )
    try:
        credential = secret_value.consume(
            decode_elastic_parent_credential,
            expected_content_type=ELASTIC_PARENT_CREDENTIAL_CONTENT_TYPE,
        )
    except (AzureKeyVaultSecretError, ConnectorSecretProfileError):
        raise ElasticRuntimeIdentityError(
            "credential-profile",
            "Elastic parent credential profile could not be decoded safely",
        ) from None
    return reference, credential


def prepare_elastic_runtime_identity(
    configuration: ElasticSourceConfiguration,
    *,
    parent_secret_client: AzureKeyVaultSecretClient,
    journal_pool: PostgresPamConnectionPool,
    journal_namespace_digest: str,
    ca_trust: PrevalidatedElasticCATrust,
    request_timeout_seconds: int = 30,
    journal_statement_timeout_ms: int = 15_000,
    journal_lock_timeout_ms: int = 5_000,
) -> PreparedElasticRuntimeIdentity:
    """Resolve one exact parent credential and compose its production broker."""

    if type(configuration) is not ElasticSourceConfiguration:
        raise TypeError("configuration must be an exact Elastic source configuration")
    if (
        type(ca_trust) is not PrevalidatedElasticCATrust
        or ca_trust.configured_reference != configuration.ca_bundle_ref
    ):
        raise ElasticRuntimeIdentityError(
            "ca-trust",
            "Elastic CA trust differs from the deployed configuration",
        )
    if (
        type(journal_namespace_digest) is not str
        or _DIGEST_RE.fullmatch(journal_namespace_digest) is None
    ):
        raise ValueError(
            "Elastic journal namespace must be a canonical SHA-256 digest"
        )
    timeout = _timeout(request_timeout_seconds)
    ca_trust.assert_current()
    reference, opaque = _load_parent_credential(
        configuration,
        parent_secret_client,
    )
    if type(opaque) is not ElasticParentCredential:
        raise ElasticRuntimeIdentityError(
            "credential-profile",
            "Elastic parent credential decoder returned an unsupported value",
        )
    credential = opaque
    policy = ElasticPamPolicy(
        index_alias=configuration.index_alias,
        ttl_seconds=configuration.lease_ttl_seconds,
    )
    role_descriptor_bytes = canonical_json_bytes(policy.role_descriptor())
    try:
        journal = PostgresElasticLeaseJournal(
            journal_pool,
            journal_namespace_digest=journal_namespace_digest,
            statement_timeout_ms=journal_statement_timeout_ms,
            lock_timeout_ms=journal_lock_timeout_ms,
        )
        connector_factory = _ExactElasticConnectorFactory(
            endpoint=configuration.endpoint_origin,
            ca_trust=ca_trust,
            timeout_seconds=timeout,
        )
        broker = ElasticJitApiKeyBroker(
            configuration.endpoint_origin,
            credential,
            journal,
            ca_file=ca_trust.path,
            timeout_seconds=timeout,
            _connector_factory=connector_factory,
        )
        ca_trust.assert_current()
    except ElasticRuntimeIdentityError:
        raise
    except Exception:
        raise ElasticRuntimeIdentityError(
            "broker-composition",
            "Elastic JIT broker could not be composed safely",
        ) from None
    endpoint_digest = elastic_endpoint_origin_digest(
        configuration.endpoint_origin
    )
    if broker.endpoint_origin_digest != endpoint_digest:
        raise ElasticRuntimeIdentityError(
            "broker-binding",
            "Elastic broker endpoint differs from the deployed configuration",
        )
    runtime_identity_bytes = canonical_json_bytes(
        {
            "broker_id": ELASTIC_PAM_BROKER_ID,
            "ca_bundle_digest": ca_trust.bundle_digest,
            "ca_bundle_reference_digest": (
                ca_trust.configured_reference_digest
            ),
            "ca_trust_profile": ELASTIC_CA_TRUST_PROFILE,
            "connector_id": ELASTIC_SECURITY_CONNECTOR_ID,
            "endpoint_origin_digest": endpoint_digest,
            "index_alias": configuration.index_alias,
            "journal_namespace_digest": journal_namespace_digest,
            "kind": "elastic-runtime-identity",
            "lease_ttl_seconds": configuration.lease_ttl_seconds,
            "media_type": ELASTIC_RUNTIME_IDENTITY_MEDIA_TYPE,
            "pam_mode": configuration.pam_mode,
            "parent_authentication_scheme": credential.scheme,
            "parent_configuration_reference_digest": _reference_digest(
                configuration.parent_credential_ref
            ),
            "parent_secret_reference_digest": reference.reference_digest,
            "request_timeout_seconds": timeout,
            "role_descriptor": policy.role_descriptor(),
            "role_descriptor_digest": policy.role_descriptor_digest,
            "schema_version": ELASTIC_RUNTIME_IDENTITY_SCHEMA_VERSION,
            "source_configuration_digest": _source_digest(configuration),
        }
    )
    parent_configuration_reference_digest = _reference_digest(
        configuration.parent_credential_ref
    )
    assert parent_configuration_reference_digest is not None
    return PreparedElasticRuntimeIdentity(
        source_configuration_digest=_source_digest(configuration),
        endpoint_origin_digest=endpoint_digest,
        index_alias=configuration.index_alias,
        lease_ttl_seconds=configuration.lease_ttl_seconds,
        pam_mode=configuration.pam_mode,
        parent_authentication_scheme=credential.scheme,
        parent_configuration_reference_digest=(
            parent_configuration_reference_digest
        ),
        parent_secret_reference_digest=reference.reference_digest,
        role_descriptor_bytes=role_descriptor_bytes,
        role_descriptor_digest=policy.role_descriptor_digest,
        ca_trust_profile=ELASTIC_CA_TRUST_PROFILE,
        ca_bundle_reference_digest=ca_trust.configured_reference_digest,
        ca_bundle_digest=ca_trust.bundle_digest,
        journal_namespace_digest=journal_namespace_digest,
        request_timeout_seconds=timeout,
        runtime_identity_bytes=runtime_identity_bytes,
        runtime_identity_digest=_digest(runtime_identity_bytes),
        broker=broker,
        ca_trust=ca_trust,
    )


def prepare_elastic_managed_source_from_identity(
    execution_request: ControlRunExecutionRequest,
    plan: ControlRunExecutionPlan,
    *,
    runtime_identity: PreparedElasticRuntimeIdentity,
) -> PreparedManagedSource:
    """Use a public-identity-bound broker for one frozen execution."""

    if type(runtime_identity) is not PreparedElasticRuntimeIdentity:
        raise TypeError("runtime identity must be exact")
    if type(execution_request) is not ControlRunExecutionRequest:
        raise TypeError("execution request must be exact")
    if type(plan) is not ControlRunExecutionPlan:
        raise TypeError("execution plan must be exact")
    try:
        configuration = ControlConfiguration.model_validate_json(
            execution_request.configuration_bytes
        )
    except (TypeError, ValueError):
        raise ElasticRuntimeIdentityError(
            "source-binding",
            "execution request does not contain a valid deployed configuration",
        ) from None
    if (
        not isinstance(configuration.source, ElasticSourceConfiguration)
        or _source_digest(configuration.source)
        != runtime_identity.source_configuration_digest
        or configuration.source.index_alias != runtime_identity.index_alias
        or configuration.source.lease_ttl_seconds
        != runtime_identity.lease_ttl_seconds
        or elastic_endpoint_origin_digest(
            configuration.source.endpoint_origin
        )
        != runtime_identity.endpoint_origin_digest
    ):
        raise ElasticRuntimeIdentityError(
            "source-binding",
            "frozen execution source differs from the Elastic runtime identity",
        )
    runtime_identity.ca_trust.assert_current()
    try:
        source = prepare_elastic_managed_source(
            execution_request,
            plan,
            broker=runtime_identity.broker,
        )
        return source.bind_runtime_identity(
            media_type=ELASTIC_RUNTIME_IDENTITY_MEDIA_TYPE,
            identity_bytes=runtime_identity.runtime_identity_bytes,
            identity_digest=runtime_identity.runtime_identity_digest,
        )
    except ElasticRuntimeIdentityError:
        raise
    except Exception:
        raise ElasticRuntimeIdentityError(
            "managed-source",
            "Elastic managed source could not be prepared safely",
        ) from None


__all__ = [
    "ELASTIC_CA_TRUST_PROFILE",
    "ELASTIC_RUNTIME_IDENTITY_MEDIA_TYPE",
    "ELASTIC_RUNTIME_IDENTITY_SCHEMA_VERSION",
    "ElasticRuntimeIdentityError",
    "PreparedElasticRuntimeIdentity",
    "PrevalidatedElasticCATrust",
    "prepare_elastic_managed_source_from_identity",
    "prepare_elastic_runtime_identity",
]
