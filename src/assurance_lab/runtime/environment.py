"""Exact, retry-stable composition of one managed execution environment.

The runtime catalog freezes a control configuration and the execution journal
freezes a connector request.  This module closes the remaining deployment
boundary: it selects one pinned source runtime and one pinned custody/signing
runtime, then records their complete public identity as one canonical
document.

Preparation may resolve an exact-version credential and construct local
clients.  It does not acquire a PAM lease, query a SIEM or EDR, sign a receipt,
or write custody.  Those effects remain behind
``PreparedManagedSource.capture`` and the publication path.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final, Protocol, cast, runtime_checkable

from assurance_lab.control_plane.models import (
    ControlConfiguration,
    DefenderSourceConfiguration,
    ElasticSourceConfiguration,
)
from assurance_lab.evidence.canonical import (
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)
from assurance_lab.key_management.azure_secret import AzureKeyVaultSecretReference
from assurance_lab.runtime.custody_identity import (
    CustodyRuntimeIdentityError,
    CustodyRuntimeProfileRegistry,
    PreparedCustodySigningRuntime,
    prepare_custody_signing_runtime,
)
from assurance_lab.runtime.defender_identity import (
    DEFENDER_RUNTIME_IDENTITY_MEDIA_TYPE,
    DefenderRuntimeIdentityError,
    PreparedDefenderRuntimeIdentity,
)
from assurance_lab.runtime.elastic_identity import (
    ELASTIC_RUNTIME_IDENTITY_MEDIA_TYPE,
    ElasticRuntimeIdentityError,
    PreparedElasticRuntimeIdentity,
    prepare_elastic_managed_source_from_identity,
)
from assurance_lab.runtime.execution_identity import (
    EXECUTION_ENVIRONMENT_IDENTITY_MEDIA_TYPE,
    ExecutionEnvironmentIdentity,
    ExecutionEnvironmentIdentityError,
    SourceRuntimeKind,
    parse_execution_environment_identity,
)
from assurance_lab.runtime.execution_plan import (
    ControlRunExecutionPlan,
    ControlRunExecutionPlanError,
    verify_control_run_execution_plan,
)
from assurance_lab.runtime.executor import PreparedExecutionEnvironment
from assurance_lab.runtime.managed_source import (
    ManagedSourceError,
    PreparedManagedSource,
    prepare_defender_managed_source,
)
from assurance_lab.runtime.models import (
    ControlRunExecutionRequest,
    sha256_digest,
)

_DIGEST_RE: Final = re.compile(r"^sha256:[a-f0-9]{64}$")
_STAGE_RE: Final = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_SOURCE_KIND_BY_CONFIGURATION: Final[
    dict[type[object], SourceRuntimeKind]
] = {
    ElasticSourceConfiguration: "elastic-security",
    DefenderSourceConfiguration: "defender-xdr",
}
_IDENTITY_KIND_BY_SOURCE: Final[dict[SourceRuntimeKind, str]] = {
    "elastic-security": "elastic-runtime-identity",
    "defender-xdr": "defender-runtime-identity",
}
_IDENTITY_MEDIA_TYPE_BY_SOURCE: Final[dict[SourceRuntimeKind, str]] = {
    "elastic-security": ELASTIC_RUNTIME_IDENTITY_MEDIA_TYPE,
    "defender-xdr": DEFENDER_RUNTIME_IDENTITY_MEDIA_TYPE,
}


class ExecutionEnvironmentCompositionError(RuntimeError):
    """Stable, secret-free failure at one runtime composition stage."""

    __slots__ = ("stage",)

    def __init__(self, stage: str, detail: str) -> None:
        if type(stage) is not str or _STAGE_RE.fullmatch(stage) is None:
            raise ValueError("execution environment failure stage is invalid")
        if type(detail) is not str or not detail or len(detail) > 256:
            raise ValueError("execution environment failure detail is invalid")
        self.stage = stage
        super().__init__(detail)


def _source_configuration_bytes(
    configuration: ElasticSourceConfiguration | DefenderSourceConfiguration,
) -> bytes:
    return canonical_json_bytes(configuration.model_dump(mode="json"))


def source_configuration_digest(
    configuration: ElasticSourceConfiguration | DefenderSourceConfiguration,
) -> str:
    """Return the content address used by the immutable source registry."""

    if type(configuration) not in _SOURCE_KIND_BY_CONFIGURATION:
        raise TypeError("source configuration must be one exact supported model")
    return sha256_digest(_source_configuration_bytes(configuration))


def _canonical_public_source_identity(
    value: bytes,
    *,
    source_kind: SourceRuntimeKind,
    media_type: str,
) -> dict[str, object]:
    if type(value) is not bytes or not value:
        raise ExecutionEnvironmentCompositionError(
            "source-identity",
            "source runtime identity bytes are absent",
        )
    try:
        document = strict_json_loads(value)
        encoded = canonical_json_bytes(document)
    except StrictJSONError:
        raise ExecutionEnvironmentCompositionError(
            "source-identity",
            "source runtime identity is not bounded strict JSON",
        ) from None
    if (
        not isinstance(document, dict)
        or encoded != value
        or document.get("kind") != _IDENTITY_KIND_BY_SOURCE[source_kind]
        or document.get("media_type") != media_type
        or media_type != _IDENTITY_MEDIA_TYPE_BY_SOURCE[source_kind]
    ):
        raise ExecutionEnvironmentCompositionError(
            "source-identity",
            "source runtime identity crossed its public type boundary",
        )
    return document


def _configuration_from_request(
    request: ControlRunExecutionRequest,
) -> ControlConfiguration:
    try:
        configuration = ControlConfiguration.model_validate_json(
            request.configuration_bytes
        )
    except (TypeError, ValueError):
        raise ExecutionEnvironmentCompositionError(
            "configuration",
            "execution request configuration is invalid",
        ) from None
    if (
        configuration.canonical_bytes() != request.configuration_bytes
        or configuration.digest != request.configuration_digest
        or configuration.tenant_id != request.tenant_id
        or configuration.control_id != request.control_id
    ):
        raise ExecutionEnvironmentCompositionError(
            "configuration",
            "execution request configuration crossed its canonical boundary",
        )
    return configuration


def _verify_plan(
    request: ControlRunExecutionRequest,
    plan: ControlRunExecutionPlan,
) -> None:
    try:
        reopened, _ = verify_control_run_execution_plan(
            plan.canonical_bytes(),
            expected_request=request,
        )
    except (ControlRunExecutionPlanError, TypeError, ValueError):
        raise ExecutionEnvironmentCompositionError(
            "plan",
            "execution plan is invalid for this request",
        ) from None
    if reopened != plan:
        raise ExecutionEnvironmentCompositionError(
            "plan",
            "execution plan changed while it was reopened",
        )


@dataclass(frozen=True, slots=True, repr=False)
class PreparedSourceRuntime:
    """One managed source plus the exact public identity of its authority."""

    source_kind: SourceRuntimeKind
    source_configuration_digest: str
    identity_media_type: str
    identity_bytes: bytes = field(repr=False)
    identity_digest: str
    source: PreparedManagedSource = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            type(self.source_configuration_digest) is not str
            or _DIGEST_RE.fullmatch(self.source_configuration_digest) is None
            or type(self.identity_digest) is not str
            or _DIGEST_RE.fullmatch(self.identity_digest) is None
            or sha256_digest(self.identity_bytes) != self.identity_digest
        ):
            raise ValueError("prepared source runtime contains an invalid digest")
        if type(self.source) is not PreparedManagedSource:
            raise TypeError("prepared source runtime source must be exact")
        _canonical_public_source_identity(
            self.identity_bytes,
            source_kind=self.source_kind,
            media_type=self.identity_media_type,
        )

    def __repr__(self) -> str:
        return (
            "PreparedSourceRuntime("
            f"source_kind={self.source_kind!r}, "
            f"source_configuration_digest={self.source_configuration_digest!r}, "
            f"identity_digest={self.identity_digest!r})"
        )


@runtime_checkable
class SourceRuntimeProvider(Protocol):
    """Prepare one source registered under an exact configuration digest."""

    @property
    def source_kind(self) -> SourceRuntimeKind: ...

    @property
    def source_configuration_digest(self) -> str: ...

    def prepare(
        self,
        request: ControlRunExecutionRequest,
        plan: ControlRunExecutionPlan,
        *,
        expected_identity_bytes: bytes | None = None,
    ) -> PreparedSourceRuntime: ...


@dataclass(frozen=True, slots=True, repr=False)
class PinnedElasticSourceRuntimeProvider:
    """Bind one already composed Elastic JIT broker to one source document."""

    configuration: ElasticSourceConfiguration = field(repr=False)
    runtime_identity: (
        PreparedElasticRuntimeIdentity
        | Callable[[], PreparedElasticRuntimeIdentity]
    ) = field(
        repr=False,
        compare=False,
    )
    source_kind: SourceRuntimeKind = field(
        init=False,
        default="elastic-security",
    )
    source_configuration_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.configuration) is not ElasticSourceConfiguration:
            raise TypeError("Elastic provider configuration must be exact")
        digest = source_configuration_digest(self.configuration)
        if type(self.runtime_identity) is PreparedElasticRuntimeIdentity:
            self._validate_identity(self.runtime_identity, digest=digest)
        elif not callable(self.runtime_identity):
            raise TypeError(
                "Elastic provider requires an exact identity or resolver"
            )
        object.__setattr__(self, "source_configuration_digest", digest)

    def __repr__(self) -> str:
        return (
            "PinnedElasticSourceRuntimeProvider("
            f"source_configuration_digest={self.source_configuration_digest!r})"
        )

    def _validate_identity(
        self,
        identity: PreparedElasticRuntimeIdentity,
        *,
        digest: str,
    ) -> None:
        if (
            type(identity) is not PreparedElasticRuntimeIdentity
            or identity.source_configuration_digest != digest
        ):
            raise ExecutionEnvironmentCompositionError(
                "source-registration",
                "Elastic runtime identity differs from its registered source",
            )
        _canonical_public_source_identity(
            identity.runtime_identity_bytes,
            source_kind=self.source_kind,
            media_type=ELASTIC_RUNTIME_IDENTITY_MEDIA_TYPE,
        )

    def _resolve_identity(self) -> PreparedElasticRuntimeIdentity:
        configured = self.runtime_identity
        if type(configured) is PreparedElasticRuntimeIdentity:
            identity = configured
        else:
            resolver = cast(
                Callable[[], PreparedElasticRuntimeIdentity],
                configured,
            )
            try:
                identity = resolver()
            except Exception:
                raise ExecutionEnvironmentCompositionError(
                    "source-identity",
                    "Elastic runtime identity could not be resolved safely",
                ) from None
        self._validate_identity(
            identity,
            digest=self.source_configuration_digest,
        )
        return identity

    def prepare(
        self,
        request: ControlRunExecutionRequest,
        plan: ControlRunExecutionPlan,
        *,
        expected_identity_bytes: bytes | None = None,
    ) -> PreparedSourceRuntime:
        configuration = _configuration_from_request(request)
        if (
            type(configuration.source) is not ElasticSourceConfiguration
            or configuration.source != self.configuration
            or plan.source_kind != self.source_kind
        ):
            raise ExecutionEnvironmentCompositionError(
                "source-binding",
                "execution request differs from the registered Elastic source",
            )
        identity = self._resolve_identity()
        if expected_identity_bytes is not None:
            try:
                identity.assert_runtime_identity(
                    expected_bytes=expected_identity_bytes,
                    expected_digest=sha256_digest(expected_identity_bytes),
                )
            except ElasticRuntimeIdentityError:
                raise ExecutionEnvironmentCompositionError(
                    "source-identity",
                    "Elastic runtime identity drifted after the first bind",
                ) from None
        try:
            source = prepare_elastic_managed_source_from_identity(
                request,
                plan,
                runtime_identity=identity,
            )
            source = source.bind_runtime_identity(
                media_type=ELASTIC_RUNTIME_IDENTITY_MEDIA_TYPE,
                identity_bytes=identity.runtime_identity_bytes,
                identity_digest=identity.runtime_identity_digest,
            )
        except (ElasticRuntimeIdentityError, ManagedSourceError, TypeError, ValueError):
            raise ExecutionEnvironmentCompositionError(
                "source-runtime",
                "Elastic managed source could not be prepared safely",
            ) from None
        return PreparedSourceRuntime(
            source_kind=self.source_kind,
            source_configuration_digest=self.source_configuration_digest,
            identity_media_type=ELASTIC_RUNTIME_IDENTITY_MEDIA_TYPE,
            identity_bytes=identity.runtime_identity_bytes,
            identity_digest=identity.runtime_identity_digest,
            source=source,
        )


@dataclass(frozen=True, slots=True, repr=False)
class PinnedDefenderSourceRuntimeProvider:
    """Bind one already composed Defender workload broker to one source."""

    configuration: DefenderSourceConfiguration = field(repr=False)
    runtime_identity: (
        PreparedDefenderRuntimeIdentity
        | Callable[[], PreparedDefenderRuntimeIdentity]
    ) = field(
        repr=False,
        compare=False,
    )
    source_kind: SourceRuntimeKind = field(
        init=False,
        default="defender-xdr",
    )
    source_configuration_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.configuration) is not DefenderSourceConfiguration:
            raise TypeError("Defender provider configuration must be exact")
        digest = source_configuration_digest(self.configuration)
        if type(self.runtime_identity) is PreparedDefenderRuntimeIdentity:
            self._validate_identity(self.runtime_identity)
        elif not callable(self.runtime_identity):
            raise TypeError(
                "Defender provider requires an exact identity or resolver"
            )
        object.__setattr__(self, "source_configuration_digest", digest)

    def _validate_identity(
        self,
        identity: PreparedDefenderRuntimeIdentity,
    ) -> None:
        if type(identity) is not PreparedDefenderRuntimeIdentity:
            raise ExecutionEnvironmentCompositionError(
                "source-registration",
                "Defender identity resolver returned an unsupported runtime",
            )
        try:
            credential_reference = AzureKeyVaultSecretReference.parse(
                self.configuration.client_credential_ref
            )
        except ValueError:
            raise ExecutionEnvironmentCompositionError(
                "source-registration",
                "Defender source does not use one exact credential version",
            ) from None
        if (
            identity.tenant_id != self.configuration.tenant_id
            or identity.client_id != self.configuration.client_id
            or identity.cloud != self.configuration.cloud
            or identity.permission != self.configuration.permission
            or identity.table != self.configuration.table
            or identity.credential_secret_reference_digest
            != credential_reference.reference_digest
        ):
            raise ExecutionEnvironmentCompositionError(
                "source-registration",
                "Defender runtime identity differs from its registered source",
            )
        _canonical_public_source_identity(
            identity.runtime_identity_bytes,
            source_kind=self.source_kind,
            media_type=DEFENDER_RUNTIME_IDENTITY_MEDIA_TYPE,
        )

    def _resolve_identity(self) -> PreparedDefenderRuntimeIdentity:
        configured = self.runtime_identity
        if type(configured) is PreparedDefenderRuntimeIdentity:
            identity = configured
        else:
            resolver = cast(
                Callable[[], PreparedDefenderRuntimeIdentity],
                configured,
            )
            try:
                identity = resolver()
            except Exception:
                raise ExecutionEnvironmentCompositionError(
                    "source-identity",
                    "Defender runtime identity could not be resolved safely",
                ) from None
        self._validate_identity(identity)
        return identity

    def __repr__(self) -> str:
        return (
            "PinnedDefenderSourceRuntimeProvider("
            f"source_configuration_digest={self.source_configuration_digest!r})"
        )

    def prepare(
        self,
        request: ControlRunExecutionRequest,
        plan: ControlRunExecutionPlan,
        *,
        expected_identity_bytes: bytes | None = None,
    ) -> PreparedSourceRuntime:
        configuration = _configuration_from_request(request)
        if (
            type(configuration.source) is not DefenderSourceConfiguration
            or configuration.source != self.configuration
            or plan.source_kind != self.source_kind
        ):
            raise ExecutionEnvironmentCompositionError(
                "source-binding",
                "execution request differs from the registered Defender source",
            )
        identity = self._resolve_identity()
        if expected_identity_bytes is not None:
            try:
                identity.assert_runtime_identity(
                    expected_bytes=expected_identity_bytes,
                    expected_digest=sha256_digest(expected_identity_bytes),
                )
            except DefenderRuntimeIdentityError:
                raise ExecutionEnvironmentCompositionError(
                    "source-identity",
                    "Defender runtime identity drifted after the first bind",
                ) from None
        try:
            source = prepare_defender_managed_source(
                request,
                plan,
                broker=identity.broker,
            )
            source = source.bind_runtime_identity(
                media_type=DEFENDER_RUNTIME_IDENTITY_MEDIA_TYPE,
                identity_bytes=identity.runtime_identity_bytes,
                identity_digest=identity.runtime_identity_digest,
            )
        except (DefenderRuntimeIdentityError, ManagedSourceError, TypeError, ValueError):
            raise ExecutionEnvironmentCompositionError(
                "source-runtime",
                "Defender managed source could not be prepared safely",
            ) from None
        return PreparedSourceRuntime(
            source_kind=self.source_kind,
            source_configuration_digest=self.source_configuration_digest,
            identity_media_type=DEFENDER_RUNTIME_IDENTITY_MEDIA_TYPE,
            identity_bytes=identity.runtime_identity_bytes,
            identity_digest=identity.runtime_identity_digest,
            source=source,
        )


class ExactSourceRuntimeRegistry:
    """Immutable source lookup keyed only by canonical source content."""

    __slots__ = ("_entries",)

    def __init__(self, entries: Iterable[SourceRuntimeProvider]) -> None:
        selected: dict[str, SourceRuntimeProvider] = {}
        for entry in entries:
            if not isinstance(entry, SourceRuntimeProvider):
                raise TypeError("source registry entry is not a runtime provider")
            digest = entry.source_configuration_digest
            if type(digest) is not str or _DIGEST_RE.fullmatch(digest) is None:
                raise ValueError("source registry entry digest is invalid")
            if digest in selected:
                raise ExecutionEnvironmentCompositionError(
                    "source-registry",
                    "source registry contains a duplicate configuration digest",
                )
            selected[digest] = entry
        if not selected:
            raise ExecutionEnvironmentCompositionError(
                "source-registry",
                "source registry is empty",
            )
        self._entries: Mapping[str, SourceRuntimeProvider] = MappingProxyType(
            selected
        )

    def __repr__(self) -> str:
        return f"ExactSourceRuntimeRegistry(entries={len(self._entries)})"

    def resolve(self, configuration_digest: str) -> SourceRuntimeProvider:
        if (
            type(configuration_digest) is not str
            or _DIGEST_RE.fullmatch(configuration_digest) is None
        ):
            raise ExecutionEnvironmentCompositionError(
                "source-registry",
                "source configuration digest is invalid",
            )
        provider = self._entries.get(configuration_digest)
        if provider is None:
            raise ExecutionEnvironmentCompositionError(
                "source-registry",
                "source configuration is not registered for execution",
            )
        return provider


@dataclass(frozen=True, slots=True, repr=False)
class ExactExecutionEnvironmentProvider:
    """Compose and rebind the exact public environment for every attempt."""

    source_registry: ExactSourceRuntimeRegistry = field(repr=False)
    custody_registry: CustodyRuntimeProfileRegistry = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.source_registry) is not ExactSourceRuntimeRegistry:
            raise TypeError("source registry must be exact")
        if not isinstance(self.custody_registry, CustodyRuntimeProfileRegistry):
            raise TypeError("custody registry does not implement the exact protocol")

    def __repr__(self) -> str:
        return "ExactExecutionEnvironmentProvider(source=<registry>, custody=<registry>)"

    def prepare(
        self,
        request: ControlRunExecutionRequest,
        plan: ControlRunExecutionPlan,
        *,
        expected_identity_bytes: bytes | None = None,
    ) -> PreparedExecutionEnvironment:
        if type(request) is not ControlRunExecutionRequest:
            raise TypeError("execution request must be exact")
        if type(plan) is not ControlRunExecutionPlan:
            raise TypeError("execution plan must be exact")
        _verify_plan(request, plan)
        configuration = _configuration_from_request(request)

        expected: ExecutionEnvironmentIdentity | None = None
        if expected_identity_bytes is not None:
            try:
                expected = parse_execution_environment_identity(
                    expected_identity_bytes
                )
            except ExecutionEnvironmentIdentityError:
                raise ExecutionEnvironmentCompositionError(
                    "execution-identity",
                    "expected execution environment identity is invalid",
                ) from None
            if (
                expected.run_id != request.run_id
                or expected.tenant_id != request.tenant_id
                or expected.control_id != request.control_id
                or expected.configuration_digest
                != request.configuration_digest
                or expected.execution_plan_digest != plan.digest
                or expected.source_revision != plan.source_revision
                or expected.source_kind != plan.source_kind
            ):
                raise ExecutionEnvironmentCompositionError(
                    "execution-identity",
                    "expected execution environment identity crosses this run",
                )

        source_digest = source_configuration_digest(configuration.source)
        provider = self.source_registry.resolve(source_digest)
        if provider.source_kind != plan.source_kind:
            raise ExecutionEnvironmentCompositionError(
                "source-registry",
                "registered source kind differs from the frozen plan",
            )
        source = provider.prepare(
            request,
            plan,
            expected_identity_bytes=(
                None if expected is None else expected.source_identity_bytes
            ),
        )
        if (
            source.source_configuration_digest != source_digest
            or source.source_kind != plan.source_kind
        ):
            raise ExecutionEnvironmentCompositionError(
                "source-registry",
                "source provider substituted its registered configuration",
            )

        try:
            custody = prepare_custody_signing_runtime(
                request,
                plan,
                registry=self.custody_registry,
                expected_identity_bytes=(
                    None if expected is None else expected.custody_identity_bytes
                ),
            )
        except CustodyRuntimeIdentityError:
            raise ExecutionEnvironmentCompositionError(
                "custody-runtime",
                "custody and signing runtime could not be rebound exactly",
            ) from None
        if type(custody) is not PreparedCustodySigningRuntime:
            raise ExecutionEnvironmentCompositionError(
                "custody-runtime",
                "custody registry returned an unsupported runtime",
            )

        try:
            identity = ExecutionEnvironmentIdentity(
                run_id=request.run_id,
                tenant_id=request.tenant_id,
                control_id=request.control_id,
                configuration_digest=request.configuration_digest,
                execution_plan_digest=plan.digest,
                source_revision=plan.source_revision,
                source_kind=source.source_kind,
                source_identity_media_type=source.identity_media_type,
                source_identity_bytes=source.identity_bytes,
                source_identity_digest=source.identity_digest,
                custody_identity_media_type=custody.identity_media_type,
                custody_identity_bytes=custody.identity_bytes,
                custody_identity_digest=custody.identity_digest,
                custody_deployment_profile_digest=(
                    custody.deployment_profile_digest
                ),
            )
        except ExecutionEnvironmentIdentityError:
            raise ExecutionEnvironmentCompositionError(
                "execution-identity",
                "composed execution environment identity is invalid",
            ) from None
        identity_bytes = identity.canonical_bytes()
        if (
            expected_identity_bytes is not None
            and identity_bytes != expected_identity_bytes
        ):
            raise ExecutionEnvironmentCompositionError(
                "execution-identity",
                "execution environment drifted after the first durable bind",
            )

        return PreparedExecutionEnvironment(
            source=source.source,
            custody=custody.custody,
            receipt_signer=custody.signer,
            execution_identity_bytes=identity_bytes,
            execution_identity_digest=identity.digest,
            execution_identity_media_type=(
                EXECUTION_ENVIRONMENT_IDENTITY_MEDIA_TYPE
            ),
            custody_deployment_profile_digest=(
                custody.deployment_profile_digest
            ),
        )


__all__ = [
    "ExactExecutionEnvironmentProvider",
    "ExactSourceRuntimeRegistry",
    "ExecutionEnvironmentCompositionError",
    "PinnedDefenderSourceRuntimeProvider",
    "PinnedElasticSourceRuntimeProvider",
    "PreparedSourceRuntime",
    "SourceRuntimeProvider",
    "source_configuration_digest",
]
