from __future__ import annotations

import hashlib
import itertools
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from assurance_lab.contract import (
    BooleanValue,
    CellSelector,
    CompiledExperiment,
    EvidencePolicyRef,
    EvidenceWindow,
    ExperimentScope,
    StringValue,
    TrialPlan,
    compile_experiment,
)
from assurance_lab.scenarios.financial_response_contract import (
    ATTACK,
    ATTACK_ACTION_DIGEST,
    BENIGN,
    BENIGN_ACTION_DIGEST,
    COMPENSATOR_OFF,
    COMPENSATOR_ON,
    COMPROMISED_PRINCIPAL_ID,
    COMPROMISED_SESSION_ID,
    SCENARIO_ID,
    SHAM_RELOAD,
    SHAM_STEADY,
    SIBLING_SESSION_ID,
    TARGET_EFFECTIVE,
    TARGET_INEFFECTIVE,
    UNRELATED_SESSION_ID,
    action_descriptor,
    build_financial_response_contract,
)
from assurance_lab.scenarios.financial_response_runtime import (
    RESPONDER_CONFIG_DIGEST,
    BaselineVerdict,
    FinancialResponseRuntime,
    ResponseActionStatus,
    ResponseResidualClassification,
    assess_response_case,
)


def _digest(fill: str) -> str:
    return f"sha256:{fill * 64}"


def _selector(
    *,
    attack: bool,
    target_effective: bool,
    quarantine_on: bool,
    sham_reload: bool = False,
) -> CellSelector:
    return CellSelector(
        input=ATTACK if attack else BENIGN,
        target=TARGET_EFFECTIVE if target_effective else TARGET_INEFFECTIVE,
        compensator=COMPENSATOR_ON if quarantine_on else COMPENSATOR_OFF,
        sham=SHAM_RELOAD if sham_reload else SHAM_STEADY,
    )


def _compiled() -> CompiledExperiment:
    start = datetime(2026, 7, 29, 0, 0, tzinfo=UTC)
    scope = ExperimentScope(
        scenario_id=SCENARIO_ID,
        build_digest=_digest("1"),
        dataset_digest=_digest("2"),
        fixture_digest=_digest("3"),
        assessment_as_of=start + timedelta(hours=1),
        evidence_window=EvidenceWindow(
            start=start,
            end=start + timedelta(hours=2),
        ),
        evidence_policy=EvidencePolicyRef(
            id="local-evidence-v1",
            version="1.0.0",
            digest=_digest("4"),
        ),
    )
    return compile_experiment(
        build_financial_response_contract(
            scope=scope,
            plan=TrialPlan(
                blocks=("fresh-clone-a",),
                replicates=2,
                order_seed="financial-response-published-seed",
            ),
        )
    )


def test_contract_compiles_the_owned_sixteen_cell_response_plan() -> None:
    compiled = _compiled()

    assert len(compiled.cells) == 16
    assert len(compiled.planned_trials) == 32
    assert compiled.current_selector == _selector(
        attack=True,
        target_effective=False,
        quarantine_on=True,
    )
    assert compiled.contract.profile.target_safe_value == BooleanValue(value=False)
    assert (
        compiled.contract.profile.input.attack_action_digest
        == ATTACK_ACTION_DIGEST
    )
    assert (
        compiled.contract.profile.input.benign_action_digest
        == BENIGN_ACTION_DIGEST
    )
    assert ATTACK_ACTION_DIGEST != BENIGN_ACTION_DIGEST
    assert _compiled().spec_digest == compiled.spec_digest
    obligations = {item.id: item for item in compiled.contract.obligations}
    specificity = obligations["revoke-exact-preserves-non-target-sessions"]
    assert specificity.selector == CellSelector(
        input=ATTACK,
        target=TARGET_EFFECTIVE,
    )
    assert specificity.predicate.metric_id == "non-target-sessions-active"
    coverage = {
        item.obligation_id: item.trial_keys for item in compiled.obligation_coverage
    }
    assert len(coverage[specificity.id]) == 8


def test_action_descriptors_are_fixed_and_semantically_distinct() -> None:
    attack = action_descriptor(ATTACK)
    benign = action_descriptor(BENIGN)

    assert attack["session_id"] == COMPROMISED_SESSION_ID
    assert benign["session_id"] == UNRELATED_SESSION_ID
    with pytest.raises(ValueError, match="unsupported"):
        action_descriptor(StringValue(value="invented-action"))


def test_all_sixteen_cells_run_from_fresh_identity_stores() -> None:
    runtime = FinancialResponseRuntime()
    results = []
    for attack, target_effective, quarantine_on, sham_reload in itertools.product(
        (False, True),
        repeat=4,
    ):
        result = runtime.execute(
            _selector(
                attack=attack,
                target_effective=target_effective,
                quarantine_on=quarantine_on,
                sham_reload=sham_reload,
            ),
            trace_id=(
                f"cell-{int(attack)}-{int(target_effective)}-"
                f"{int(quarantine_on)}-{int(sham_reload)}"
            ),
        )
        results.append(result)

    assert len(results) == 16
    assert all(len(result.events) == 4 for result in results)
    assert all(
        [event.sequence for event in result.events] == [1, 2, 3, 4]
        for result in results
    )


def test_each_execute_starts_from_a_fresh_clone() -> None:
    runtime = FinancialResponseRuntime()
    revoked = runtime.execute(
        _selector(
            attack=True,
            target_effective=True,
            quarantine_on=True,
        ),
        trace_id="first-revokes",
    )
    fresh = runtime.execute(
        _selector(
            attack=True,
            target_effective=False,
            quarantine_on=False,
        ),
        trace_id="second-is-fresh",
    )

    assert not revoked.compromised_session_active
    assert revoked.compromised_principal_quarantined
    assert fresh.compromised_session_active
    assert not fresh.compromised_principal_quarantined


@pytest.mark.parametrize("quarantine_on", (False, True))
@pytest.mark.parametrize("sham_reload", (False, True))
def test_exact_revocation_effect_does_not_depend_on_quarantine(
    quarantine_on: bool,
    sham_reload: bool,
) -> None:
    runtime = FinancialResponseRuntime()
    report_only = runtime.execute(
        _selector(
            attack=True,
            target_effective=False,
            quarantine_on=quarantine_on,
            sham_reload=sham_reload,
        ),
        trace_id=f"report-{int(quarantine_on)}-{int(sham_reload)}",
    )
    revoke_exact = runtime.execute(
        _selector(
            attack=True,
            target_effective=True,
            quarantine_on=quarantine_on,
            sham_reload=sham_reload,
        ),
        trace_id=f"revoke-{int(quarantine_on)}-{int(sham_reload)}",
    )

    assert report_only.compromised_session_active
    assert not revoke_exact.compromised_session_active
    assert report_only.non_target_sessions_active
    assert revoke_exact.non_target_sessions_active
    assert report_only.target_modified_session_ids == ()
    assert revoke_exact.target_modified_session_ids == (COMPROMISED_SESSION_ID,)


@pytest.mark.parametrize("target_effective", (False, True))
@pytest.mark.parametrize("sham_reload", (False, True))
def test_quarantine_effect_does_not_depend_on_exact_revocation(
    target_effective: bool,
    sham_reload: bool,
) -> None:
    runtime = FinancialResponseRuntime()
    off = runtime.execute(
        _selector(
            attack=True,
            target_effective=target_effective,
            quarantine_on=False,
            sham_reload=sham_reload,
        ),
        trace_id=f"quarantine-off-{int(target_effective)}-{int(sham_reload)}",
    )
    on = runtime.execute(
        _selector(
            attack=True,
            target_effective=target_effective,
            quarantine_on=True,
            sham_reload=sham_reload,
        ),
        trace_id=f"quarantine-on-{int(target_effective)}-{int(sham_reload)}",
    )

    assert not off.compromised_principal_quarantined
    assert on.compromised_principal_quarantined
    assert off.compensator_modified_session_ids == ()
    assert on.compensator_modified_session_ids == ()


@pytest.mark.parametrize(
    ("target_effective", "quarantine_on", "sham_reload"),
    tuple(itertools.product((False, True), repeat=3)),
)
def test_unrelated_principal_survives_the_full_benign_envelope(
    target_effective: bool,
    quarantine_on: bool,
    sham_reload: bool,
) -> None:
    result = FinancialResponseRuntime().execute(
        _selector(
            attack=False,
            target_effective=target_effective,
            quarantine_on=quarantine_on,
            sham_reload=sham_reload,
        ),
        trace_id=(
            f"benign-{int(target_effective)}-"
            f"{int(quarantine_on)}-{int(sham_reload)}"
        ),
    )

    assert result.unrelated_support_principal_available
    assert result.action_digest == BENIGN_ACTION_DIGEST
    assert result.response_action_status == ResponseActionStatus.NOT_TRIGGERED
    assert not result.exact_revocation_executed
    assert result.target_modified_session_ids == ()
    assert result.compensator_modified_session_ids == ()


@pytest.mark.parametrize(
    ("attack", "target_effective", "quarantine_on"),
    tuple(itertools.product((False, True), repeat=3)),
)
def test_responder_reload_is_a_behavior_free_sham(
    attack: bool,
    target_effective: bool,
    quarantine_on: bool,
) -> None:
    runtime = FinancialResponseRuntime()
    steady = runtime.execute(
        _selector(
            attack=attack,
            target_effective=target_effective,
            quarantine_on=quarantine_on,
        ),
        trace_id="steady",
    )
    reloaded = runtime.execute(
        _selector(
            attack=attack,
            target_effective=target_effective,
            quarantine_on=quarantine_on,
            sham_reload=True,
        ),
        trace_id="reloaded",
    )

    assert (
        steady.response_action_status,
        steady.exact_revocation_executed,
        steady.compromised_session_active,
        steady.non_target_sessions_active,
        steady.compromised_principal_quarantined,
        steady.compromised_session_replay_denied,
        steady.unrelated_support_principal_available,
        steady.target_modified_session_ids,
        steady.compensator_modified_session_ids,
        steady.session_readbacks,
    ) == (
        reloaded.response_action_status,
        reloaded.exact_revocation_executed,
        reloaded.compromised_session_active,
        reloaded.non_target_sessions_active,
        reloaded.compromised_principal_quarantined,
        reloaded.compromised_session_replay_denied,
        reloaded.unrelated_support_principal_available,
        reloaded.target_modified_session_ids,
        reloaded.compensator_modified_session_ids,
        reloaded.session_readbacks,
    )


def test_responder_reload_has_a_persisted_pre_post_operation_receipt() -> None:
    runtime = FinancialResponseRuntime()
    steady = runtime.execute(
        _selector(
            attack=True,
            target_effective=False,
            quarantine_on=False,
        ),
        trace_id="steady-operation-receipt",
        clone_nonce="steady-operation-clone",
    )
    reloaded = runtime.execute(
        _selector(
            attack=True,
            target_effective=False,
            quarantine_on=False,
            sham_reload=True,
        ),
        trace_id="reload-operation-receipt",
        clone_nonce="reload-operation-clone",
    )

    assert steady.sham_operation.operation == "steady-observation"
    assert steady.sham_operation.rows_affected == 0
    assert steady.responder_before_sham == steady.responder_after_sham
    assert reloaded.sham_operation.operation == "reload"
    assert reloaded.sham_operation.rows_affected == 1
    assert (
        reloaded.responder_after_sham.generation
        == reloaded.responder_before_sham.generation + 1
    )
    assert (
        reloaded.responder_after_sham.instance_id
        != reloaded.responder_before_sham.instance_id
    )
    assert (
        reloaded.responder_after_sham.config_digest
        == reloaded.responder_before_sham.config_digest
        == reloaded.sham_operation.config_digest
        == RESPONDER_CONFIG_DIGEST
    )
    assert (
        reloaded.responder_after_sham.clone_nonce
        == reloaded.resource_identity.observed_clone_nonce
        == "reload-operation-clone"
    )


def test_no_op_responder_reload_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = FinancialResponseRuntime()

    def no_op_reload(
        _connection: object,
        *,
        clone_nonce: str,
    ) -> int:
        assert clone_nonce == "no-op-reload-clone"
        return 0

    monkeypatch.setattr(runtime, "_reload_responder", no_op_reload)
    with pytest.raises(RuntimeError, match="sham operation"):
        runtime.execute(
            _selector(
                attack=True,
                target_effective=False,
                quarantine_on=False,
                sham_reload=True,
            ),
            trace_id="no-op-reload",
            clone_nonce="no-op-reload-clone",
        )


def test_relabelled_runtime_resource_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = FinancialResponseRuntime()
    original = runtime._fresh_database

    def relabelled_database(
        *,
        clone_nonce: str,
        runner_resource_id: str,
    ) -> sqlite3.Connection:
        connection = original(
            clone_nonce=clone_nonce,
            runner_resource_id=runner_resource_id,
        )
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute(
            "UPDATE runtime_identity SET clone_nonce = 'forged-clone-label'"
        )
        connection.commit()
        return connection

    monkeypatch.setattr(runtime, "_fresh_database", relabelled_database)
    with pytest.raises(RuntimeError, match="runtime identity readback"):
        runtime.execute(
            _selector(
                attack=True,
                target_effective=False,
                quarantine_on=False,
            ),
            trace_id="resource-relabel",
            clone_nonce="requested-clone-label",
        )


def test_revoke_exact_touches_only_the_compromised_old_session() -> None:
    result = FinancialResponseRuntime().execute(
        _selector(
            attack=True,
            target_effective=True,
            quarantine_on=False,
        ),
        trace_id="exact-session-only",
    )

    assert result.target_modified_session_ids == (COMPROMISED_SESSION_ID,)
    assert not result.session(COMPROMISED_SESSION_ID).active
    assert result.non_target_sessions_active
    assert result.session(SIBLING_SESSION_ID).active
    assert result.session(UNRELATED_SESSION_ID).active
    assert result.unrelated_support_principal_available


def test_current_cell_masks_the_failed_revocation() -> None:
    result = FinancialResponseRuntime().execute(
        _selector(
            attack=True,
            target_effective=False,
            quarantine_on=True,
        ),
        trace_id="current-masked-revocation",
    )
    assessment = assess_response_case(result)

    assert result.response_action_reported_success
    assert not result.exact_revocation_executed
    assert result.compromised_session_active
    assert result.compromised_principal_quarantined
    assert result.compromised_session_replay_denied
    assert result.unrelated_support_principal_available
    assert assessment.baseline.name == "response-status-and-replay-only"
    assert assessment.baseline.verdict == BaselineVerdict.PASS
    assert not assessment.target_supported
    assert assessment.compensator_supported
    assert assessment.path_supported
    assert assessment.benign_service_supported
    assert (
        assessment.residual_classification
        == ResponseResidualClassification.MASKED_REVOCATION_FAILURE
    )


def test_events_expose_status_and_each_independent_readback() -> None:
    result = FinancialResponseRuntime().execute(
        _selector(
            attack=True,
            target_effective=False,
            quarantine_on=True,
            sham_reload=True,
        ),
        trace_id="event-readbacks",
    )
    input_event, target_event, compensator_event, outcome_event = result.events

    assert input_event.value("action") == ATTACK.value
    assert input_event.value("action_digest") == ATTACK_ACTION_DIGEST
    assert input_event.value("sham") == SHAM_RELOAD.value
    assert (
        target_event.value("response_action_status")
        == ResponseActionStatus.REPORTED_SUCCESS.value
    )
    assert (
        result.response_action_receipt.status
        == ResponseActionStatus.REPORTED_SUCCESS
    )
    assert (
        result.response_action_receipt.responder_instance_id
        == result.responder_after_sham.instance_id
    )
    assert result.response_action_receipt.action_digest == ATTACK_ACTION_DIGEST
    assert result.response_action_receipt.trace_id == result.trace_id
    assert result.response_action_receipt.operation == "report-only"
    assert result.response_action_receipt.rows_affected == 0
    assert target_event.value("compromised_session_active") is True
    assert target_event.value("non_target_sessions_active") is True
    assert target_event.value("target_principal_id") == COMPROMISED_PRINCIPAL_ID
    assert (
        target_event.value("target_session_id")
        == COMPROMISED_SESSION_ID
    )
    assert target_event.value("target_modified_session_count") == 0
    assert (
        target_event.value("target_modified_session_ids_canonical")
        == '{"schema":"assurance-lab.modified-session-set/v1","session_ids":[]}'
    )
    assert str(
        target_event.value("target_modified_session_ids_digest")
    ).startswith("sha256:")
    assert (
        compensator_event.value("compromised_principal_quarantined") is True
    )
    assert (
        compensator_event.value("quarantine_principal_id")
        == COMPROMISED_PRINCIPAL_ID
    )
    assert compensator_event.value("compensator_modified_session_count") == 0
    assert (
        compensator_event.value("compensator_modified_session_ids_canonical")
        == '{"schema":"assurance-lab.modified-session-set/v1","session_ids":[]}'
    )
    assert str(
        compensator_event.value("compensator_modified_session_ids_digest")
    ).startswith("sha256:")
    assert outcome_event.value("compromised_session_replay_denied") is True
    assert outcome_event.value("unrelated_support_principal_available") is True


def test_target_event_binds_the_exact_modified_session_set() -> None:
    result = FinancialResponseRuntime().execute(
        _selector(
            attack=True,
            target_effective=True,
            quarantine_on=False,
        ),
        trace_id="event-exact-target",
    )
    target_event = result.events[1]
    canonical = (
        '{"schema":"assurance-lab.modified-session-set/v1",'
        f'"session_ids":["{COMPROMISED_SESSION_ID}"]}}'
    )
    expected_digest = (
        f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"
    )

    assert target_event.value("target_principal_id") == COMPROMISED_PRINCIPAL_ID
    assert target_event.value("target_session_id") == COMPROMISED_SESSION_ID
    assert target_event.value("target_modified_session_count") == 1
    assert target_event.value("target_modified_session_ids_canonical") == canonical
    assert target_event.value("target_modified_session_ids_digest") == expected_digest
    assert target_event.value("non_target_sessions_active") is True


def test_report_only_without_quarantine_exposes_the_replay() -> None:
    result = FinancialResponseRuntime().execute(
        _selector(
            attack=True,
            target_effective=False,
            quarantine_on=False,
        ),
        trace_id="exposed-replay",
    )
    assessment = assess_response_case(result)

    assert not result.compromised_session_replay_denied
    assert assessment.baseline.verdict == BaselineVerdict.FAIL
    assert (
        assessment.residual_classification
        == ResponseResidualClassification.EXPOSED_REPLAY
    )


def test_runtime_rejects_partial_wrong_typed_and_unknown_cells() -> None:
    runtime = FinancialResponseRuntime()
    with pytest.raises(ValueError, match="input selector"):
        runtime.execute(
            CellSelector(
                target=TARGET_INEFFECTIVE,
                compensator=COMPENSATOR_OFF,
                sham=SHAM_STEADY,
            ),
            trace_id="missing-input",
        )
    with pytest.raises(ValueError, match="sham selector"):
        runtime.execute(
            CellSelector(
                input=ATTACK,
                target=TARGET_INEFFECTIVE,
                compensator=COMPENSATOR_OFF,
                sham=BooleanValue(value=False),
            ),
            trace_id="wrong-type",
        )
    with pytest.raises(ValueError, match="unsupported target"):
        runtime.execute(
            CellSelector(
                input=ATTACK,
                target=StringValue(value="revoke-everything"),
                compensator=COMPENSATOR_OFF,
                sham=SHAM_STEADY,
            ),
            trace_id="unknown-target",
        )
    with pytest.raises(ValueError, match="trace_id"):
        runtime.execute(
            _selector(
                attack=True,
                target_effective=False,
                quarantine_on=False,
            ),
            trace_id="../unsafe",
        )
