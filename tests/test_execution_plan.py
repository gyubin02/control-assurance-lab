from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from assurance_lab.connectors.postgres_pam_journal import PAMExecutionBinding
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
    EqualsPredicate,
    MatchingRecordCount,
)
from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.runtime.execution_plan import (
    CONTROL_RUN_EXECUTION_PLAN_MEDIA_TYPE,
    DEFENDER_REQUEST_MEDIA_TYPE,
    ELASTIC_REQUEST_MEDIA_TYPE,
    ControlRunExecutionPlan,
    ControlRunExecutionPlanError,
    create_control_run_execution_plan,
    execution_plan_pam_recovery_scopes,
    verify_control_run_execution_plan,
)
from assurance_lab.runtime.execution_recovery import (
    PAMRecoveryScope,
    publishing_recovery_execution_binding_digest,
    publishing_recovery_pam_scope_digest,
)
from assurance_lab.runtime.models import (
    ControlRunExecutionRequest,
    ControlRunRequest,
)

_START = datetime(2026, 7, 29, 1, 0, tzinfo=UTC)
_END = _START + timedelta(minutes=5)
_PREPARED = _END + timedelta(minutes=2)
_OPERATION = f"sha256:{'1' * 64}"
_DEPLOYMENT = f"sha256:{'2' * 64}"
_REVISION = f"sha256:{'3' * 64}"
_NONCE = "ab" * 32
_RULE = "12345678-1234-4234-9234-123456789abc"


def _profile(kind: str = "elastic-security") -> AlertWindowProfile:
    source = (
        ElasticAlertSource(
            fields=(
                "@timestamp",
                "kibana.alert.rule.uuid",
                "kibana.alert.severity",
            ),
            rule_uuids=(_RULE,),
            workflow_statuses=("open",),
            alert_statuses=("active",),
        )
        if kind == "elastic-security"
        else DefenderAlertSource()
    )
    field = "kibana.alert.severity" if kind == "elastic-security" else "Severity"
    return AlertWindowProfile(
        profile_id="high-alert-window",
        profile_version="1.0.0",
        title="High alert window",
        source=source,
        criteria=(
            Criterion(
                criterion_id="high-alert-observed",
                description="At least one high alert was observed.",
                metric=MatchingRecordCount(all=(EqualsPredicate(field=field, value="high"),)),
                comparison="ge",
                expected_count=1,
            ),
        ),
    )


def _configuration(
    profile: AlertWindowProfile,
    *,
    source_kind: str | None = None,
) -> ControlConfiguration:
    selected = source_kind or profile.source_kind
    source = (
        ElasticSourceConfiguration(
            endpoint_origin="https://elastic.bank.invalid",
            index_alias=".alerts-security.alerts-payments",
            parent_credential_ref=(
                "azure-keyvault://bank-vault/secrets/"
                "elastic-parent/0123456789abcdef0123456789abcdef"
            ),
            lease_ttl_seconds=900,
        )
        if selected == "elastic-security"
        else DefenderSourceConfiguration(
            cloud="global",
            tenant_id="11111111-1111-4111-8111-111111111111",
            client_id="22222222-2222-4222-8222-222222222222",
            client_credential_ref=(
                "azure-keyvault://bank-vault/secrets/"
                "defender-profile/0123456789abcdef0123456789abcdef"
            ),
        )
    )
    return ControlConfiguration(
        tenant_id="bank-a",
        control_id="high-alert-control",
        display_name="High alert control",
        description="Recomputes high-alert evidence for one closed window.",
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
            custody_ref="s3-object-lock://evidence/bank-a/high-alerts",
            signing_key_ref="vault-transit://assurance/runtime",
            retention_days=365,
        ),
    )


def _execution_request(
    profile: AlertWindowProfile,
    *,
    source_kind: str | None = None,
    attempt_count: int = 1,
) -> ControlRunExecutionRequest:
    configuration = _configuration(profile, source_kind=source_kind)
    run_request = ControlRunRequest(
        tenant_id=configuration.tenant_id,
        control_id=configuration.control_id,
        deployment_operation_id=_OPERATION,
        deployment_operation_sequence=7,
        deployment_receipt_digest=_DEPLOYMENT,
        control_profile_id=profile.profile_id,
        control_profile_digest=profile.digest,
        revision_id=_REVISION,
        configuration_digest=configuration.digest,
        window_start=_START,
        window_end=_END,
        due_at=_END + timedelta(minutes=2),
    )
    return ControlRunExecutionRequest(
        run_id=run_request.run_id,
        run_request_bytes=run_request.canonical_bytes(),
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
        attempt_count=attempt_count,
        lease_fence=attempt_count,
    )


def _plan(
    request: ControlRunExecutionRequest,
    *,
    nonce: str = _NONCE,
    prepared_at: datetime = _PREPARED,
    source_revision: str = "git:0123456789abcdef",
) -> ControlRunExecutionPlan:
    return create_control_run_execution_plan(
        request,
        capture_nonce=nonce,
        prepared_at=prepared_at,
        source_revision=source_revision,
    )


def test_elastic_plan_freezes_exact_profile_derived_request() -> None:
    request = _execution_request(_profile())

    plan = _plan(request)

    assert plan.source_kind == "elastic-security"
    assert plan.media_type == CONTROL_RUN_EXECUTION_PLAN_MEDIA_TYPE
    assert plan.schema_version == "2.0.0"
    assert plan.connector_request_media_type == ELASTIC_REQUEST_MEDIA_TYPE
    assert plan.capture_id == f"run-{request.run_id.removeprefix('sha256:')}"
    assert (
        len(
            {
                plan.artifact_set_id,
                plan.custody_scope_id,
                plan.executor_receipt_id,
            }
        )
        == 3
    )
    assert plan.prepared_at == _PREPARED
    assert plan.custody_retain_until == _PREPARED + timedelta(days=365)
    assert plan.source_revision == "git:0123456789abcdef"
    assert plan.connector_request["index_alias"] == (".alerts-security.alerts-payments")
    assert plan.connector_request["fields"] == [
        "@timestamp",
        "kibana.alert.rule.uuid",
        "kibana.alert.severity",
    ]
    assert plan.connector_request["rule_uuids"] == [_RULE]
    assert plan.connector_request["workflow_statuses"] == ["open"]
    assert plan.connector_request["alert_statuses"] == ["active"]
    assert tuple((scope.authority_class, scope.connector_id) for scope in plan.pam_scopes) == (
        ("custody", "s3-object-lock"),
        ("signing", "vault-transit"),
        ("source", "elastic-security"),
    )
    assert plan.pam_scopes[-1].connector_request_digest == (plan.connector_request_digest)
    assert execution_plan_pam_recovery_scopes(plan) == plan.pam_scopes
    assert publishing_recovery_pam_scope_digest(plan.pam_scopes) == (plan.pam_scope_digest)


def test_postgres_binding_rederives_the_exact_frozen_plan_scope() -> None:
    request = _execution_request(_profile())
    plan = _plan(request)
    execution_identity_digest = f"sha256:{'7' * 64}"
    lease_expires_at_epoch_millis = int((_PREPARED + timedelta(minutes=15)).timestamp() * 1_000)

    binding = PAMExecutionBinding.from_execution_plan(
        plan,
        execution_identity_digest=execution_identity_digest,
        lease_fence=request.lease_fence,
        lease_expires_at_epoch_millis=lease_expires_at_epoch_millis,
    )

    assert binding.pam_scopes == execution_plan_pam_recovery_scopes(plan)
    assert binding.pam_scope_digest == plan.pam_scope_digest
    assert binding.execution_plan_digest == plan.digest
    assert binding.execution_binding_digest == (
        publishing_recovery_execution_binding_digest(
            tenant_id=plan.tenant_id,
            run_id=plan.run_id,
            execution_plan_digest=plan.digest,
            execution_identity_digest=execution_identity_digest,
            abandoned_lease_fence=request.lease_fence,
            pam_scope_digest=plan.pam_scope_digest,
        )
    )


def test_postgres_binding_rejects_arbitrary_scope_self_assertion() -> None:
    with pytest.raises(
        TypeError,
        match="must be created from an exact execution plan",
    ):
        PAMExecutionBinding()


def test_defender_plan_uses_the_fixed_read_only_request_profile() -> None:
    request = _execution_request(_profile("defender-xdr"))

    plan = _plan(request)

    assert plan.source_kind == "defender-xdr"
    assert plan.connector_request_media_type == DEFENDER_REQUEST_MEDIA_TYPE
    assert plan.connector_request["profile"] == ("microsoft-graph-v1.0-alertinfo-exact-count-v1")
    assert plan.connector_request["window"] == {
        "end_exclusive": "2026-07-29T01:05:00Z",
        "start_inclusive": "2026-07-29T01:00:00Z",
    }


@pytest.mark.parametrize("kind", ["elastic-security", "defender-xdr"])
def test_canonical_plan_reopens_and_rederives_vendor_request(kind: str) -> None:
    request = _execution_request(_profile(kind))
    created = _plan(request)

    reopened, vendor_request = verify_control_run_execution_plan(
        created.canonical_bytes(),
        expected_request=request,
    )

    assert reopened == created
    assert canonical_json_bytes(vendor_request.as_json()) == (created.connector_request_bytes)


@pytest.mark.parametrize(
    "nonce",
    [
        "",
        "a" * 63,
        "A" * 64,
        "g" * 64,
        "a" * 65,
    ],
)
def test_nonce_must_be_exact_lowercase_256_bit_hex(nonce: str) -> None:
    with pytest.raises(ControlRunExecutionPlanError, match="256 bits"):
        _plan(_execution_request(_profile()), nonce=nonce)


def test_attempt_fence_does_not_change_stable_plan_identity() -> None:
    first = _plan(_execution_request(_profile(), attempt_count=1))
    retried = _plan(_execution_request(_profile(), attempt_count=2))

    assert retried == first
    assert retried.digest == first.digest


def test_new_nonce_is_a_distinct_plan_but_not_a_distinct_run() -> None:
    request = _execution_request(_profile())
    first = _plan(request)
    second = _plan(request, nonce="cd" * 32)

    assert first.run_id == second.run_id
    assert first.digest != second.digest
    assert first.connector_request_digest != second.connector_request_digest


def test_evaluator_revision_is_frozen_in_the_plan() -> None:
    request = _execution_request(_profile())

    first = _plan(request, source_revision="oci:sha256:1111")
    upgraded = _plan(request, source_revision="oci:sha256:2222")

    assert first.run_id == upgraded.run_id
    assert first.digest != upgraded.digest
    assert first.source_revision == "oci:sha256:1111"


@pytest.mark.parametrize(
    "source_revision",
    ["", " revision", "revision with spaces", "x" * 257],
)
def test_source_revision_must_be_one_bounded_build_identity(
    source_revision: str,
) -> None:
    with pytest.raises(ControlRunExecutionPlanError, match="source revision"):
        _plan(
            _execution_request(_profile()),
            source_revision=source_revision,
        )


def test_plan_cannot_claim_creation_before_the_source_window_closed() -> None:
    with pytest.raises(ControlRunExecutionPlanError, match=r"before.*closes"):
        _plan(
            _execution_request(_profile()),
            prepared_at=_END - timedelta(seconds=1),
        )


def test_retention_substitution_is_rejected_when_plan_is_reopened() -> None:
    request = _execution_request(_profile())
    plan = _plan(request)
    document = json.loads(plan.canonical_bytes())
    document["custody_retain_until"] = "2028-07-29T01:07:00Z"

    with pytest.raises(ControlRunExecutionPlanError, match="retention differs"):
        verify_control_run_execution_plan(
            canonical_json_bytes(document),
            expected_request=request,
        )


def test_profile_and_configuration_source_mismatch_fails_before_network() -> None:
    request = _execution_request(
        _profile("defender-xdr"),
        source_kind="elastic-security",
    )

    with pytest.raises(ControlRunExecutionPlanError, match="source differs"):
        _plan(request)


def test_noncanonical_plan_bytes_are_rejected() -> None:
    request = _execution_request(_profile())
    plan = _plan(request)
    document = json.loads(plan.canonical_bytes())
    noncanonical = json.dumps(document, indent=2).encode()

    with pytest.raises(ControlRunExecutionPlanError, match="not canonical"):
        verify_control_run_execution_plan(
            noncanonical,
            expected_request=request,
        )


def test_plan_with_an_extra_member_is_rejected() -> None:
    request = _execution_request(_profile())
    plan = _plan(request)
    document = json.loads(plan.canonical_bytes())
    document["operator_note"] = "trust me"

    with pytest.raises(ControlRunExecutionPlanError, match="invalid"):
        verify_control_run_execution_plan(
            canonical_json_bytes(document),
            expected_request=request,
        )


def test_connector_request_substitution_is_rejected_even_if_redigested() -> None:
    request = _execution_request(_profile())
    plan = _plan(request)
    document = json.loads(plan.canonical_bytes())
    document["connector_request"]["index_alias"] = ".alerts-security.alerts-another-space"
    substituted_request = canonical_json_bytes(document["connector_request"])
    from assurance_lab.runtime.models import sha256_digest

    document["connector_request_digest"] = sha256_digest(substituted_request)

    with pytest.raises(
        ControlRunExecutionPlanError,
        match=r"invalid|does not rederive",
    ):
        verify_control_run_execution_plan(
            canonical_json_bytes(document),
            expected_request=request,
        )


def test_scheduler_anchor_substitution_is_rejected() -> None:
    request = _execution_request(_profile())
    plan = _plan(request)
    document = json.loads(plan.canonical_bytes())
    document["deployment_receipt_digest"] = f"sha256:{'9' * 64}"

    with pytest.raises(
        ControlRunExecutionPlanError,
        match="scheduler request",
    ):
        verify_control_run_execution_plan(
            canonical_json_bytes(document),
            expected_request=request,
        )


def test_plan_model_rejects_internally_inconsistent_request_digest() -> None:
    plan = _plan(_execution_request(_profile()))
    document = plan.model_dump(mode="python")
    document["connector_request_digest"] = f"sha256:{'0' * 64}"

    with pytest.raises(ValidationError, match="digest differs"):
        ControlRunExecutionPlan.model_validate(document)


def test_logical_artifact_identity_cannot_be_substituted() -> None:
    plan = _plan(_execution_request(_profile()))
    document = plan.model_dump(mode="python")
    document["custody_scope_id"] = f"sha256:{'8' * 64}"

    with pytest.raises(ValidationError, match="do not derive"):
        ControlRunExecutionPlan.model_validate(document)


def test_arbitrary_pam_scope_self_assertion_is_rejected() -> None:
    plan = _plan(_execution_request(_profile()))
    document = plan.model_dump(mode="python")
    substituted_scopes = (
        *plan.pam_scopes[:-1],
        PAMRecoveryScope(
            authority_class="source",
            connector_id="elastic-security",
            connector_request_digest=f"sha256:{'9' * 64}",
        ),
    )
    document["pam_scopes"] = substituted_scopes
    document["pam_scope_digest"] = publishing_recovery_pam_scope_digest(substituted_scopes)

    with pytest.raises(ValidationError, match="not deterministically derived"):
        ControlRunExecutionPlan.model_validate(document)


def test_recomputed_signing_scope_cannot_override_deployed_configuration() -> None:
    request = _execution_request(_profile())
    plan = _plan(request)
    document = plan.model_dump(mode="python")
    document["signing_key_ref"] = "aws-kms://assurance/runtime"
    signing_scope = plan.pam_scopes[1]
    document["pam_scopes"] = (
        plan.pam_scopes[0],
        PAMRecoveryScope(
            authority_class="signing",
            connector_id="aws-kms",
            connector_request_digest=signing_scope.connector_request_digest,
        ),
        plan.pam_scopes[2],
    )

    with pytest.raises(
        ControlRunExecutionPlanError,
        match=r"invalid|does not rederive",
    ):
        verify_control_run_execution_plan(
            ControlRunExecutionPlan.model_construct(**document).canonical_bytes(),
            expected_request=request,
        )
