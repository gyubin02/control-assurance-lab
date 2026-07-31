from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest

import assurance_lab.runtime.environment as environment_module
from assurance_lab.connectors.contract import ConnectorDescriptor, ConnectorWindow
from assurance_lab.connectors.defender_xdr import (
    DEFENDER_XDR_CAPTURE_MEDIA_TYPE,
    DEFENDER_XDR_CONNECTOR_ID,
    DefenderXDRRequest,
)
from assurance_lab.connectors.managed_evidence import ManagedAuthorizationProfile
from assurance_lab.control_plane.models import (
    ControlConfiguration,
    DefenderSourceConfiguration,
    ElasticSourceConfiguration,
    EvidenceConfiguration,
    ScheduleConfiguration,
)
from assurance_lab.controls.alert_window import (
    ALERT_WINDOW_PROFILE_MEDIA_TYPE,
    AlertWindowProfile,
    Criterion,
    DefenderAlertSource,
    ElasticAlertSource,
    TotalRecordCount,
)
from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.key_management.azure_secret import AzureKeyVaultSecretReference
from assurance_lab.runtime.custody_identity import (
    CUSTODY_RUNTIME_IDENTITY_MEDIA_TYPE,
    CustodyRuntimeIdentityError,
    PreparedCustodySigningRuntime,
)
from assurance_lab.runtime.defender_identity import (
    DEFENDER_RUNTIME_IDENTITY_MEDIA_TYPE,
    PreparedDefenderRuntimeIdentity,
)
from assurance_lab.runtime.elastic_identity import (
    ELASTIC_RUNTIME_IDENTITY_MEDIA_TYPE,
    PreparedElasticRuntimeIdentity,
)
from assurance_lab.runtime.environment import (
    ExactExecutionEnvironmentProvider,
    ExactSourceRuntimeRegistry,
    ExecutionEnvironmentCompositionError,
    PinnedDefenderSourceRuntimeProvider,
    PinnedElasticSourceRuntimeProvider,
    PreparedSourceRuntime,
    source_configuration_digest,
)
from assurance_lab.runtime.execution_identity import (
    EXECUTION_ENVIRONMENT_IDENTITY_MEDIA_TYPE,
    parse_execution_environment_identity,
)
from assurance_lab.runtime.execution_plan import (
    ControlRunExecutionPlan,
    create_control_run_execution_plan,
)
from assurance_lab.runtime.managed_source import PreparedManagedSource
from assurance_lab.runtime.models import (
    ControlRunExecutionRequest,
    ControlRunRequest,
    sha256_digest,
)

_START = datetime(2026, 7, 30, 1, 0, tzinfo=UTC)
_END = _START + timedelta(minutes=5)
_PREPARED = _END + timedelta(minutes=2)
_NONCE = "ab" * 32
_OPERATION = f"sha256:{'1' * 64}"
_DEPLOYMENT = f"sha256:{'2' * 64}"
_REVISION = f"sha256:{'3' * 64}"
_CUSTODY_PROFILE = f"sha256:{'4' * 64}"
_SOURCE_REVISION = "oci:sha256:0123456789abcdef"


class _CustodyAdapter:
    def put_bytes(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("environment preparation must not write custody")

    def put_file(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("environment preparation must not write custody")

    def verify_acknowledgement_scope(
        self,
        *args: object,
        **kwargs: object,
    ) -> None:
        del args, kwargs
        raise AssertionError("environment preparation must not read custody")

    def reverify_acknowledgement(
        self,
        *args: object,
        **kwargs: object,
    ) -> None:
        del args, kwargs
        raise AssertionError("environment preparation must not read custody")


class _Signer:
    key_id = "test:receipt:v1"
    public_key_bytes = b"\x01" * 32

    def sign(self, value: bytes) -> bytes:
        del value
        raise AssertionError("environment preparation must not sign")


@dataclass(frozen=True)
class _CustodyIdentity:
    run_id: str
    tenant_id: str
    control_id: str
    configuration_digest: str
    execution_plan_digest: str
    deployment_profile_digest: str = _CUSTODY_PROFILE
    media_type: str = CUSTODY_RUNTIME_IDENTITY_MEDIA_TYPE

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "configuration_digest": self.configuration_digest,
                "control_id": self.control_id,
                "deployment_profile_digest": self.deployment_profile_digest,
                "execution_plan_digest": self.execution_plan_digest,
                "media_type": self.media_type,
                "run_id": self.run_id,
                "schema_version": "1.0.0",
                "tenant_id": self.tenant_id,
            }
        )

    @property
    def digest(self) -> str:
        return sha256_digest(self.canonical_bytes())


class _CustodyRegistry:
    def resolve(self, **kwargs: object) -> object:
        del kwargs
        raise AssertionError("test replaces the custody preparation function")


def _fake_prepared_custody(
    request: ControlRunExecutionRequest,
    plan: ControlRunExecutionPlan,
    *,
    expected_identity_bytes: bytes | None,
    profile_digest: str = _CUSTODY_PROFILE,
) -> PreparedCustodySigningRuntime:
    identity = _CustodyIdentity(
        run_id=request.run_id,
        tenant_id=request.tenant_id,
        control_id=request.control_id,
        configuration_digest=request.configuration_digest,
        execution_plan_digest=plan.digest,
        deployment_profile_digest=profile_digest,
    )
    if (
        expected_identity_bytes is not None
        and expected_identity_bytes != identity.canonical_bytes()
    ):
        raise CustodyRuntimeIdentityError("runtime-identity-drift")
    prepared = object.__new__(PreparedCustodySigningRuntime)
    object.__setattr__(prepared, "identity", identity)
    object.__setattr__(prepared, "custody", _CustodyAdapter())
    object.__setattr__(prepared, "signer", _Signer())
    return prepared


def _patch_custody(
    monkeypatch: pytest.MonkeyPatch,
    *,
    profile_digest: str = _CUSTODY_PROFILE,
) -> None:
    def prepare(
        request: ControlRunExecutionRequest,
        plan: ControlRunExecutionPlan,
        *,
        registry: object,
        expected_identity_bytes: bytes | None = None,
    ) -> PreparedCustodySigningRuntime:
        del registry
        return _fake_prepared_custody(
            request,
            plan,
            expected_identity_bytes=expected_identity_bytes,
            profile_digest=profile_digest,
        )

    monkeypatch.setattr(
        environment_module,
        "prepare_custody_signing_runtime",
        prepare,
    )


def _fake_managed_source() -> PreparedManagedSource:
    connector_request = DefenderXDRRequest(
        capture_id="defender-xdr-test",
        capture_nonce=_NONCE,
        window=ConnectorWindow(start=_START, end=_END),
        max_hits=10,
    )

    def unused(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError("environment preparation must not capture")

    return PreparedManagedSource(
        descriptor=ConnectorDescriptor(
            connector_id=DEFENDER_XDR_CONNECTOR_ID,
            connector_version="0.1.0",
            capture_media_type=DEFENDER_XDR_CAPTURE_MEDIA_TYPE,
        ),
        source_locator_digest=sha256_digest(b"graph"),
        connector_request=connector_request,
        connector_request_bytes=canonical_json_bytes(
            connector_request.as_json()
        ),
        authorization_profile=ManagedAuthorizationProfile(
            profile_id="test-defender-auth-v1",
            provider_id="test-entra",
            authorization_binding_digest=sha256_digest(b"authorization"),
            credential_reference_digest=sha256_digest(b"credential"),
            permission_ids=("microsoft-graph:ThreatHunting.Read.All",),
            resource_scope_digests=(sha256_digest(b"graph"),),
        ),
        connector_receipt_verifier_id="test/defender-receipt-v1",
        pam_receipt_verifier_id="test/defender-pam-v1",
        _capture=unused,
        receipt_verifier=unused,
        pam_receipt_verifier=unused,
    )


def _elastic_source(
    *,
    endpoint: str = "https://elastic.internal.example",
) -> ElasticSourceConfiguration:
    return ElasticSourceConfiguration(
        endpoint_origin=endpoint,
        index_alias=".alerts-security.alerts-payments",
        parent_credential_ref=(
            "azure-keyvault://security-kv/"
            "secrets/elastic-parent/0123456789abcdef0123456789abcdef"
        ),
        ca_bundle_ref=(
            "azure-keyvault://security-kv/"
            "secrets/elastic-ca/abcdef0123456789abcdef0123456789"
        ),
    )


def _defender_source() -> DefenderSourceConfiguration:
    return DefenderSourceConfiguration(
        tenant_id="11111111-2222-4333-8444-555555555555",
        client_id="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        client_credential_ref=(
            "azure-keyvault://security-kv/"
            "secrets/defender/0123456789abcdef0123456789abcdef"
        ),
    )


def _profile(
    source: ElasticSourceConfiguration | DefenderSourceConfiguration,
) -> AlertWindowProfile:
    profile_source = (
        ElasticAlertSource(fields=("@timestamp",))
        if type(source) is ElasticSourceConfiguration
        else DefenderAlertSource()
    )
    return AlertWindowProfile(
        profile_id="alert-window",
        profile_version="1.0.0",
        title="Alert window",
        source=profile_source,
        criteria=(
            Criterion(
                criterion_id="one-alert",
                description="Observe at least one alert.",
                metric=TotalRecordCount(),
                comparison="ge",
                expected_count=1,
            ),
        ),
    )


def _execution(
    source: ElasticSourceConfiguration | DefenderSourceConfiguration,
) -> tuple[
    ControlConfiguration,
    ControlRunExecutionRequest,
    ControlRunExecutionPlan,
]:
    profile = _profile(source)
    configuration = ControlConfiguration(
        tenant_id="bank-a",
        control_id="alert-completeness",
        display_name="Alert completeness",
        description="Re-evaluate one closed source window.",
        environment="production",
        owner_group="security/detection",
        control_profile_id=profile.profile_id,
        control_profile_digest=profile.digest,
        source=source,
        schedule=ScheduleConfiguration(
            interval_seconds=300,
            collection_lag_seconds=120,
            window_seconds=300,
        ),
        evidence=EvidenceConfiguration(
            custody_ref="s3-object-lock://evidence/bank-a/alerts",
            signing_key_ref="vault-transit://assurance/runtime",
            retention_days=365,
        ),
    )
    run = ControlRunRequest(
        tenant_id=configuration.tenant_id,
        control_id=configuration.control_id,
        deployment_operation_id=_OPERATION,
        deployment_operation_sequence=1,
        deployment_receipt_digest=_DEPLOYMENT,
        control_profile_id=profile.profile_id,
        control_profile_digest=profile.digest,
        revision_id=_REVISION,
        configuration_digest=configuration.digest,
        window_start=_START,
        window_end=_END,
        due_at=_PREPARED,
    )
    request = ControlRunExecutionRequest(
        run_id=run.run_id,
        run_request_bytes=run.canonical_bytes(),
        tenant_id=configuration.tenant_id,
        control_id=configuration.control_id,
        deployment_operation_id=_OPERATION,
        deployment_receipt_digest=_DEPLOYMENT,
        configuration_digest=configuration.digest,
        configuration_bytes=configuration.canonical_bytes(),
        control_profile_id=profile.profile_id,
        control_profile_digest=profile.digest,
        control_profile_media_type=ALERT_WINDOW_PROFILE_MEDIA_TYPE,
        control_profile_bytes=profile.canonical_bytes(),
        window_start=_START,
        window_end=_END,
        attempt_count=1,
        lease_fence=1,
    )
    plan = create_control_run_execution_plan(
        request,
        capture_nonce=_NONCE,
        prepared_at=_PREPARED,
        source_revision=_SOURCE_REVISION,
    )
    return configuration, request, plan


def _elastic_identity(
    source: ElasticSourceConfiguration,
    *,
    generation: str = "a",
) -> PreparedElasticRuntimeIdentity:
    identity_bytes = canonical_json_bytes(
        {
            "generation": generation,
            "kind": "elastic-runtime-identity",
            "media_type": ELASTIC_RUNTIME_IDENTITY_MEDIA_TYPE,
            "schema_version": "1.0.0",
        }
    )
    identity = object.__new__(PreparedElasticRuntimeIdentity)
    object.__setattr__(
        identity,
        "source_configuration_digest",
        source_configuration_digest(source),
    )
    object.__setattr__(identity, "runtime_identity_bytes", identity_bytes)
    object.__setattr__(
        identity,
        "runtime_identity_digest",
        sha256_digest(identity_bytes),
    )
    return identity


def _defender_identity(
    source: DefenderSourceConfiguration,
    *,
    generation: str = "a",
) -> PreparedDefenderRuntimeIdentity:
    identity_bytes = canonical_json_bytes(
        {
            "generation": generation,
            "kind": "defender-runtime-identity",
            "media_type": DEFENDER_RUNTIME_IDENTITY_MEDIA_TYPE,
            "schema_version": "1.0.0",
        }
    )
    identity = object.__new__(PreparedDefenderRuntimeIdentity)
    credential_reference = AzureKeyVaultSecretReference.parse(
        source.client_credential_ref
    )
    for name, value in (
        ("tenant_id", source.tenant_id),
        ("client_id", source.client_id),
        ("cloud", source.cloud),
        ("permission", source.permission),
        ("table", source.table),
        (
            "credential_secret_reference_digest",
            credential_reference.reference_digest,
        ),
        ("runtime_identity_bytes", identity_bytes),
        ("runtime_identity_digest", sha256_digest(identity_bytes)),
        ("broker", object()),
    ):
        object.__setattr__(identity, name, value)
    return identity


def _environment(
    provider: object,
) -> ExactExecutionEnvironmentProvider:
    return ExactExecutionEnvironmentProvider(
        source_registry=ExactSourceRuntimeRegistry(
            (cast(Any, provider),)
        ),
        custody_registry=cast(Any, _CustodyRegistry()),
    )


@pytest.mark.parametrize("vendor", ["elastic", "defender"])
def test_first_bind_and_retry_reconstruct_exact_environment_identity(
    monkeypatch: pytest.MonkeyPatch,
    vendor: str,
) -> None:
    _patch_custody(monkeypatch)
    source: ElasticSourceConfiguration | DefenderSourceConfiguration
    provider: object
    if vendor == "elastic":
        elastic_source = _elastic_source()
        source = elastic_source
        provider = PinnedElasticSourceRuntimeProvider(
            elastic_source,
            _elastic_identity(elastic_source),
        )
        monkeypatch.setattr(
            environment_module,
            "prepare_elastic_managed_source_from_identity",
            lambda *args, **kwargs: _fake_managed_source(),
        )
    else:
        defender_source = _defender_source()
        source = defender_source
        provider = PinnedDefenderSourceRuntimeProvider(
            defender_source,
            _defender_identity(defender_source),
        )
        monkeypatch.setattr(
            environment_module,
            "prepare_defender_managed_source",
            lambda *args, **kwargs: _fake_managed_source(),
        )
    _, request, plan = _execution(source)
    environment = _environment(provider)

    first = environment.prepare(request, plan)
    retry = environment.prepare(
        request,
        plan,
        expected_identity_bytes=first.execution_identity_bytes,
    )

    assert retry.execution_identity_bytes == first.execution_identity_bytes
    assert retry.execution_identity_digest == first.execution_identity_digest
    assert (
        retry.execution_identity_media_type
        == EXECUTION_ENVIRONMENT_IDENTITY_MEDIA_TYPE
    )
    reopened = parse_execution_environment_identity(
        first.execution_identity_bytes
    )
    assert reopened.source_kind == plan.source_kind
    assert reopened.source_revision == _SOURCE_REVISION
    assert reopened.custody_deployment_profile_digest == _CUSTODY_PROFILE
    assert first.source.runtime_identity_media_type == (
        reopened.source_identity_media_type
    )
    assert first.source.runtime_identity_bytes == reopened.source_identity_bytes
    assert first.source.runtime_identity_digest == reopened.source_identity_digest
    assert retry.source.runtime_identity_bytes == reopened.source_identity_bytes


def test_retry_fails_closed_after_source_identity_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_custody(monkeypatch)
    monkeypatch.setattr(
        environment_module,
        "prepare_elastic_managed_source_from_identity",
        lambda *args, **kwargs: _fake_managed_source(),
    )
    source = _elastic_source()
    _, request, plan = _execution(source)
    first = _environment(
        PinnedElasticSourceRuntimeProvider(
            source,
            _elastic_identity(source, generation="a"),
        )
    ).prepare(request, plan)
    rotated = _environment(
        PinnedElasticSourceRuntimeProvider(
            source,
            _elastic_identity(source, generation="b"),
        )
    )

    with pytest.raises(
        ExecutionEnvironmentCompositionError,
        match="drifted",
    ):
        rotated.prepare(
            request,
            plan,
            expected_identity_bytes=first.execution_identity_bytes,
        )


def test_provider_reresolves_exact_credential_identity_on_every_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_custody(monkeypatch)
    monkeypatch.setattr(
        environment_module,
        "prepare_elastic_managed_source_from_identity",
        lambda *args, **kwargs: _fake_managed_source(),
    )
    source = _elastic_source()
    identities = [
        _elastic_identity(source, generation="a"),
        _elastic_identity(source, generation="b"),
    ]
    calls = 0

    def resolve() -> PreparedElasticRuntimeIdentity:
        nonlocal calls
        identity = identities[min(calls, len(identities) - 1)]
        calls += 1
        return identity

    _, request, plan = _execution(source)
    runtime = _environment(
        PinnedElasticSourceRuntimeProvider(source, resolve)
    )
    first = runtime.prepare(request, plan)

    with pytest.raises(
        ExecutionEnvironmentCompositionError,
        match="drifted",
    ):
        runtime.prepare(
            request,
            plan,
            expected_identity_bytes=first.execution_identity_bytes,
        )

    assert calls == 2


def test_retry_fails_closed_after_custody_profile_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        environment_module,
        "prepare_elastic_managed_source_from_identity",
        lambda *args, **kwargs: _fake_managed_source(),
    )
    source = _elastic_source()
    _, request, plan = _execution(source)
    runtime = _environment(
        PinnedElasticSourceRuntimeProvider(source, _elastic_identity(source))
    )
    _patch_custody(monkeypatch)
    first = runtime.prepare(request, plan)
    _patch_custody(
        monkeypatch,
        profile_digest=f"sha256:{'8' * 64}",
    )

    with pytest.raises(
        ExecutionEnvironmentCompositionError,
        match="custody and signing",
    ):
        runtime.prepare(
            request,
            plan,
            expected_identity_bytes=first.execution_identity_bytes,
        )


def test_registry_rejects_provider_result_substitution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_custody(monkeypatch)
    source = _elastic_source()
    _, request, plan = _execution(source)
    registered_digest = source_configuration_digest(source)
    other_digest = f"sha256:{'9' * 64}"
    identity = _elastic_identity(source)

    class _SubstitutingProvider:
        source_kind = "elastic-security"
        source_configuration_digest = registered_digest

        def prepare(
            self,
            request: ControlRunExecutionRequest,
            plan: ControlRunExecutionPlan,
            *,
            expected_identity_bytes: bytes | None = None,
        ) -> PreparedSourceRuntime:
            del request, plan, expected_identity_bytes
            return PreparedSourceRuntime(
                source_kind="elastic-security",
                source_configuration_digest=other_digest,
                identity_media_type=ELASTIC_RUNTIME_IDENTITY_MEDIA_TYPE,
                identity_bytes=identity.runtime_identity_bytes,
                identity_digest=identity.runtime_identity_digest,
                source=_fake_managed_source(),
            )

    runtime = _environment(_SubstitutingProvider())

    with pytest.raises(
        ExecutionEnvironmentCompositionError,
        match="substituted",
    ):
        runtime.prepare(request, plan)


def test_cross_configuration_cannot_reuse_registered_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_custody(monkeypatch)
    registered = _elastic_source()
    changed = _elastic_source(endpoint="https://elastic-dr.internal.example")
    _, request, plan = _execution(changed)
    runtime = _environment(
        PinnedElasticSourceRuntimeProvider(
            registered,
            _elastic_identity(registered),
        )
    )

    with pytest.raises(
        ExecutionEnvironmentCompositionError,
        match="not registered",
    ):
        runtime.prepare(request, plan)


def test_runtime_representations_exclude_source_locators() -> None:
    source = _elastic_source()
    provider = PinnedElasticSourceRuntimeProvider(
        source,
        _elastic_identity(source),
    )
    registry = ExactSourceRuntimeRegistry((provider,))
    runtime = ExactExecutionEnvironmentProvider(
        source_registry=registry,
        custody_registry=cast(Any, _CustodyRegistry()),
    )

    rendered = repr(provider) + repr(registry) + repr(runtime)

    assert "elastic.internal" not in rendered
    assert "azure-keyvault" not in rendered
    assert "source=<registry>" in rendered
