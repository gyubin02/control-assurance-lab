from __future__ import annotations

import hashlib
import itertools
import json
import sqlite3
import tempfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import rfc8785

import assurance_lab.scenarios.financial_recovery_runtime as recovery_runtime_module
from assurance_lab.contract import (
    BooleanValue,
    CellSelector,
    CompiledExperiment,
    EvidencePolicyRef,
    EvidenceWindow,
    ExperimentScope,
    IntegerValue,
    StringValue,
    TrialPlan,
    compile_experiment,
)
from assurance_lab.evidence.bundle import (
    BundleFile,
    BundleManifest,
    BundleStatus,
    BundleVerification,
    EvaluationRef,
    EvaluatorRef,
    ExperimentRef,
    Sensitivity,
    verify_bundle,
)
from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.lifecycle import (
    ConfidentialityStatus,
    DisclosureLedger,
    IncidentSnapshot,
    incident_snapshot_digest,
)
from assurance_lab.scenarios.financial_data import DatasetProfile, generate_dataset
from assurance_lab.scenarios.financial_recovery_contract import (
    APPROVED_CUSTOMER_ID,
    APPROVED_ENTITLEMENT_SET_DIGEST,
    APPROVED_ENTITLEMENTS,
    APPROVED_SNAPSHOT_DIGEST,
    APPROVED_SNAPSHOT_ID,
    ATTACK,
    ATTACK_ACTION_DIGEST,
    BENIGN,
    BENIGN_ACTION_DIGEST,
    COMPARISON_REPLACEMENT_SESSION_ID,
    COMPENSATOR_OFF,
    COMPENSATOR_ON,
    OLD_SESSION_ID,
    REPLACEMENT_SESSION_ID,
    SCENARIO_ID,
    SHAM_REAPPLY,
    SHAM_STEADY,
    STALE_ENTITLEMENT_SET_DIGEST,
    STALE_SNAPSHOT_DIGEST,
    STALE_SNAPSHOT_ID,
    TARGET_EFFECTIVE,
    TARGET_INEFFECTIVE,
    action_descriptor,
    build_financial_recovery_contract,
    entitlement_set_descriptor,
    snapshot_descriptor,
)
from assurance_lab.scenarios.financial_recovery_e2e import (
    build_reference_recovery_lifecycle,
    write_reference_recovery_lifecycle_bundle,
)
from assurance_lab.scenarios.financial_recovery_runtime import (
    FinancialRecoveryRuntime,
    FinancialRecoveryRuntimeResult,
    LifecycleCutoverFixture,
    RecoveryBaselineVerdict,
    RecoveryReleaseDecision,
    RecoveryResidualClassification,
    RecoverySessionState,
    RuntimeEvent,
    assess_recovery_case,
    lifecycle_cutover_bundle_payloads,
    lifecycle_proof_bundle_payloads,
)

_BUNDLE_ROOTS: list[tempfile.TemporaryDirectory[str]] = []


def _digest(fill: str) -> str:
    return f"sha256:{fill * 64}"


def _selector(
    *,
    attack: bool,
    target_effective: bool,
    guard_on: bool,
    sham_reapply: bool = False,
) -> CellSelector:
    return CellSelector(
        input=ATTACK if attack else BENIGN,
        target=TARGET_EFFECTIVE if target_effective else TARGET_INEFFECTIVE,
        compensator=COMPENSATOR_ON if guard_on else COMPENSATOR_OFF,
        sham=SHAM_REAPPLY if sham_reapply else SHAM_STEADY,
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
        build_financial_recovery_contract(
            scope=scope,
            plan=TrialPlan(
                blocks=("fresh-clone-a",),
                replicates=2,
                order_seed="financial-recovery-published-seed",
            ),
        )
    )


def _bundle(fill: str) -> str:
    return f"cab:sha256:{fill * 64}"


def _cutover_fixtures() -> dict[str, LifecycleCutoverFixture]:
    owner = tempfile.TemporaryDirectory(prefix="assurance-recovery-cab-")
    _BUNDLE_ROOTS.append(owner)
    evidence = write_reference_recovery_lifecycle_bundle(Path(owner.name) / "lifecycle.cab")
    return evidence.cutover_fixtures()


def _verified_lifecycle_bundle(
    payloads: dict[str, bytes],
) -> tuple[BundleVerification, Path]:
    def role(path: str) -> str:
        if path.endswith("/incident-lifecycle.json"):
            return "lifecycle-verifier-input"
        if path.endswith("/admitted-receipts.json"):
            return "lifecycle-admitted-receipts"
        if path.endswith("/verified-lifecycle.json"):
            return "lifecycle-verifier-output"
        if path.endswith("/cutover-snapshot.json"):
            return "lifecycle-cutover-snapshot"
        return "lifecycle-cutover-reference"

    manifest = BundleManifest(
        media_type="application/vnd.control-assurance.bundle.v1+json",
        schema_version="1.0.0",
        profile="integrity-only",
        created_at="2026-07-29T00:00:00.000000Z",
        as_of="2026-07-29T00:00:00.000000Z",
        experiment=ExperimentRef(
            id="financial-recovery-lifecycle-fixture",
            spec_version="1.0.0",
            spec_digest=_digest("8"),
        ),
        evaluation=EvaluationRef(
            policy_id="lifecycle-verifier-v1",
            policy_digest=_digest("9"),
            evaluator=EvaluatorRef(
                name="assurance-lab-lifecycle-verifier",
                version="1.0.0",
                source_revision="test-fixture",
                image_digest=None,
            ),
        ),
        parent_bundles=[],
        files=[
            BundleFile(
                path=path,
                sha256=hashlib.sha256(payload).hexdigest(),
                size=len(payload),
                media_type="application/json",
                role=role(path),
                sensitivity=Sensitivity.SYNTHETIC,
                required_for=["financial-recovery-cutover"],
            )
            for path, payload in sorted(payloads.items())
        ],
    )
    owner = tempfile.TemporaryDirectory(prefix="assurance-recovery-cab-")
    _BUNDLE_ROOTS.append(owner)
    root = Path(owner.name)
    for path, payload in payloads.items():
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    (root / "bundle.json").write_bytes(manifest.canonical_bytes())
    verification = verify_bundle(root)
    assert verification.status == BundleStatus.INTEGRITY_VERIFIED
    assert not verification.issues
    return verification, root


@pytest.fixture(scope="module")
def runtime() -> FinancialRecoveryRuntime:
    return FinancialRecoveryRuntime(
        generate_dataset(seed=2907, profile=DatasetProfile.DEFAULT),
        cutover_fixtures=_cutover_fixtures(),
    )


def test_contract_compiles_the_owned_sixteen_cell_recovery_plan() -> None:
    compiled = _compiled()

    assert len(compiled.cells) == 16
    assert len(compiled.planned_trials) == 32
    assert compiled.current_selector == _selector(
        attack=True,
        target_effective=False,
        guard_on=True,
    )
    assert compiled.contract.profile.target_safe_value == IntegerValue(value=0)
    assert compiled.contract.profile.compensator_safe_value == BooleanValue(
        value=True
    )
    assert compiled.contract.profile.outcome_safe_value == IntegerValue(value=0)
    assert compiled.contract.profile.benign_safe_value == IntegerValue(value=1)
    assert (
        compiled.contract.profile.input.attack_action_digest
        == ATTACK_ACTION_DIGEST
    )
    assert (
        compiled.contract.profile.input.benign_action_digest
        == BENIGN_ACTION_DIGEST
    )
    assert _compiled().spec_digest == compiled.spec_digest
    coverage = {
        item.obligation_id: item.trial_keys
        for item in compiled.obligation_coverage
    }
    assert len(coverage["assigned-case-service-envelope"]) == 16
    assert len(coverage["restored-snapshot-identity"]) == 32
    assert len(coverage["lifecycle-disclosure-reference-preserved"]) == 32
    assert len(coverage["old-session-remains-revoked-at-retest"]) == 32
    assert len(coverage["replacement-session-is-active-at-retest"]) == 32
    assert (
        len(coverage["replacement-session-binds-restored-entitlements"])
        == 32
    )
    assert (
        len(coverage["cutover-reference-binds-verified-lifecycle-snapshot"])
        == 32
    )
    assert (
        len(coverage["sham-application-has-an-exact-operation-receipt"])
        == 32
    )
    assert len(coverage["fresh-clone-is-closed-after-each-trial"]) == 32


def test_the_five_compiled_contrasts_match_the_recovery_interventions(
    runtime: FinancialRecoveryRuntime,
) -> None:
    stale_monitor_attack = runtime.execute(
        _selector(attack=True, target_effective=False, guard_on=False),
        trace_id="contrast-stale-monitor-attack",
    )
    approved_monitor_attack = runtime.execute(
        _selector(attack=True, target_effective=True, guard_on=False),
        trace_id="contrast-approved-monitor-attack",
    )
    stale_monitor_benign = runtime.execute(
        _selector(attack=False, target_effective=False, guard_on=False),
        trace_id="contrast-stale-monitor-benign",
    )
    approved_monitor_benign = runtime.execute(
        _selector(attack=False, target_effective=True, guard_on=False),
        trace_id="contrast-approved-monitor-benign",
    )
    stale_enforce_attack = runtime.execute(
        _selector(attack=True, target_effective=False, guard_on=True),
        trace_id="contrast-stale-enforce-attack",
    )
    stale_enforce_reapply = runtime.execute(
        _selector(
            attack=True,
            target_effective=False,
            guard_on=True,
            sham_reapply=True,
        ),
        trace_id="contrast-stale-enforce-reapply",
    )
    stale_enforce_benign = runtime.execute(
        _selector(attack=False, target_effective=False, guard_on=True),
        trace_id="contrast-stale-enforce-benign",
    )

    assert (
        stale_monitor_attack.out_of_scope_records_selected
        > approved_monitor_attack.out_of_scope_records_selected
    )
    assert (
        stale_monitor_benign.assigned_case_records_delivered
        == approved_monitor_benign.assigned_case_records_delivered
        == stale_enforce_benign.assigned_case_records_delivered
        == 1
    )
    assert (
        stale_monitor_attack.out_of_scope_records_delivered
        > stale_enforce_attack.out_of_scope_records_delivered
    )
    assert (
        stale_enforce_attack.out_of_scope_records_delivered
        == stale_enforce_reapply.out_of_scope_records_delivered
        == 0
    )


def test_fixed_actions_and_snapshots_have_distinct_canonical_identities() -> None:
    attack = action_descriptor(ATTACK)
    benign = action_descriptor(BENIGN)
    stale = snapshot_descriptor(TARGET_INEFFECTIVE)
    approved = snapshot_descriptor(TARGET_EFFECTIVE)

    assert ATTACK_ACTION_DIGEST != BENIGN_ACTION_DIGEST
    assert STALE_SNAPSHOT_DIGEST != APPROVED_SNAPSHOT_DIGEST
    assert STALE_ENTITLEMENT_SET_DIGEST != APPROVED_ENTITLEMENT_SET_DIGEST
    assert attack["session_role"] == "active-replacement"
    assert "session_id" not in attack
    assert attack["requested_customer_ids"] == [
        f"SYNTH-CUSTOMER-{index:06d}" for index in range(21, 31)
    ]
    assert benign["requested_customer_ids"] == [APPROVED_CUSTOMER_ID]
    assert stale["snapshot_id"] == STALE_SNAPSHOT_ID
    assert approved["snapshot_id"] == APPROVED_SNAPSHOT_ID
    assert (
        entitlement_set_descriptor(TARGET_EFFECTIVE)["entitlements"]
        == list(APPROVED_ENTITLEMENTS)
    )
    with pytest.raises(ValueError, match="unsupported"):
        action_descriptor(StringValue(value="invented-action"))
    with pytest.raises(ValueError, match="unsupported"):
        snapshot_descriptor(StringValue(value="invented-snapshot"))


def test_runtime_rejects_a_fixture_without_the_fixed_recovery_principal() -> None:
    with pytest.raises(ValueError, match="support-017"):
        FinancialRecoveryRuntime(
            generate_dataset(seed=2907, profile=DatasetProfile.SMOKE),
            cutover_fixtures=_cutover_fixtures(),
        )


def test_all_sixteen_cells_run_from_fresh_sqlite_clones(
    runtime: FinancialRecoveryRuntime,
) -> None:
    results = []
    for attack, target_effective, guard_on, sham_reapply in itertools.product(
        (False, True),
        repeat=4,
    ):
        result = runtime.execute(
            _selector(
                attack=attack,
                target_effective=target_effective,
                guard_on=guard_on,
                sham_reapply=sham_reapply,
            ),
            trace_id=(
                f"cell-{int(attack)}-{int(target_effective)}-"
                f"{int(guard_on)}-{int(sham_reapply)}"
            ),
        )
        results.append(result)

    assert len(results) == 16
    assert all(len(result.events) == 6 for result in results)
    assert all(
        [event.sequence for event in result.events] == [1, 2, 3, 4, 5, 6]
        for result in results
    )
    assert all(result.cutover_fixture_valid for result in results)
    assert all(result.prior_disclosure_reference_unchanged for result in results)
    assert all(result.clone_cleanup_verified for result in results)
    assert all(
        recovery_runtime_module._sha256(
            result.clone_cleanup_probe_canonical.encode("utf-8")
        )
        == result.clone_cleanup_probe_digest
        for result in results
    )
    assert all(
        json.loads(result.clone_cleanup_probe_canonical)
        == {
            "schema": "assurance-lab.sqlite-clone-cleanup-probe/v1",
            "trace_id": result.trace_id,
            "clone_id": result.clone_id,
            "clone_nonce": result.clone_nonce,
            "probe": "execute-select-one-after-close",
            "outcome": "closed-connection-programming-error",
        }
        for result in results
    )
    assert all(
        result.prior_admitted_disclosure_count_before
        == result.prior_admitted_disclosure_count_after
        == 2
        for result in results
    )


@pytest.mark.parametrize("guard_on", (False, True))
@pytest.mark.parametrize("sham_reapply", (False, True))
def test_snapshot_intervention_has_a_guard_independent_local_effect(
    runtime: FinancialRecoveryRuntime,
    guard_on: bool,
    sham_reapply: bool,
) -> None:
    stale = runtime.execute(
        _selector(
            attack=True,
            target_effective=False,
            guard_on=guard_on,
            sham_reapply=sham_reapply,
        ),
        trace_id=f"stale-{int(guard_on)}-{int(sham_reapply)}",
    )
    approved = runtime.execute(
        _selector(
            attack=True,
            target_effective=True,
            guard_on=guard_on,
            sham_reapply=sham_reapply,
        ),
        trace_id=f"approved-{int(guard_on)}-{int(sham_reapply)}",
    )

    assert stale.out_of_scope_records_selected == 10
    assert approved.out_of_scope_records_selected == 0
    assert stale.snapshot_digest == STALE_SNAPSHOT_DIGEST
    assert approved.snapshot_digest == APPROVED_SNAPSHOT_DIGEST
    assert stale.snapshot_identity_matches_declared_target
    assert approved.snapshot_identity_matches_declared_target


def test_current_cell_exposes_the_masked_restore_failure(
    runtime: FinancialRecoveryRuntime,
) -> None:
    attack = runtime.execute(
        _selector(
            attack=True,
            target_effective=False,
            guard_on=True,
        ),
        trace_id="current-stale-attack",
    )
    benign = runtime.execute(
        _selector(
            attack=False,
            target_effective=False,
            guard_on=True,
        ),
        trace_id="current-stale-benign",
    )
    assessment = assess_recovery_case(attack, benign)

    assert attack.cutover_fixture_valid
    assert attack.out_of_scope_records_selected == 10
    assert attack.release_guard_reached
    assert attack.release_decision == RecoveryReleaseDecision.BLOCK
    assert attack.unapproved_release_blocked
    assert attack.out_of_scope_records_delivered == 0
    assert benign.assigned_case_records_delivered == 1
    assert benign.delivered_customer_ids == (APPROVED_CUSTOMER_ID,)
    assert assessment.baseline.name == "current-state-and-final-outcome-only"
    assert assessment.baseline.verdict == RecoveryBaselineVerdict.PASS
    assert assessment.baseline.prior_admitted_disclosure_count_ignored == 2
    assert not assessment.target_supported
    assert assessment.cutover_fixture_supported
    assert assessment.release_guard_supported
    assert assessment.path_supported
    assert assessment.benign_service_supported
    assert assessment.prior_disclosure_history_preserved
    assert assessment.prior_admitted_disclosure_count == 2
    assert (
        assessment.residual_classification
        == RecoveryResidualClassification.MASKED_RESTORE_FAILURE
    )


def test_monitor_only_exposes_the_stale_restore_path(
    runtime: FinancialRecoveryRuntime,
) -> None:
    attack = runtime.execute(
        _selector(
            attack=True,
            target_effective=False,
            guard_on=False,
        ),
        trace_id="stale-monitor-attack",
    )
    benign = runtime.execute(
        _selector(
            attack=False,
            target_effective=False,
            guard_on=False,
        ),
        trace_id="stale-monitor-benign",
    )
    assessment = assess_recovery_case(attack, benign)

    assert attack.out_of_scope_records_selected == 10
    assert attack.release_decision == RecoveryReleaseDecision.ALLOW
    assert attack.out_of_scope_records_delivered == 10
    assert assessment.baseline.verdict == RecoveryBaselineVerdict.FAIL
    assert (
        assessment.residual_classification
        == RecoveryResidualClassification.EXPOSED_PATH
    )


def test_approved_snapshot_stops_selection_before_the_release_gateway(
    runtime: FinancialRecoveryRuntime,
) -> None:
    result = runtime.execute(
        _selector(
            attack=True,
            target_effective=True,
            guard_on=True,
        ),
        trace_id="approved-target",
    )

    assert result.cutover_fixture_valid
    assert not result.snapshot_authorized_action
    assert result.out_of_scope_records_selected == 0
    assert not result.release_guard_reached
    assert result.release_decision == RecoveryReleaseDecision.NOT_REACHED
    assert result.release_reason == "restored-entitlement-denied"
    assert result.out_of_scope_records_delivered == 0


@pytest.mark.parametrize(
    ("target_effective", "guard_on", "sham_reapply"),
    tuple(itertools.product((False, True), repeat=3)),
)
def test_all_eight_benign_cells_preserve_one_row_of_legitimate_service(
    runtime: FinancialRecoveryRuntime,
    target_effective: bool,
    guard_on: bool,
    sham_reapply: bool,
) -> None:
    result = runtime.execute(
        _selector(
            attack=False,
            target_effective=target_effective,
            guard_on=guard_on,
            sham_reapply=sham_reapply,
        ),
        trace_id=(
            f"benign-{int(target_effective)}-"
            f"{int(guard_on)}-{int(sham_reapply)}"
        ),
    )

    assert result.action_digest == BENIGN_ACTION_DIGEST
    assert result.cutover_fixture_valid
    assert result.snapshot_authorized_action
    assert result.out_of_scope_records_selected == 0
    assert result.release_decision == RecoveryReleaseDecision.ALLOW
    assert result.out_of_scope_records_delivered == 0
    assert result.assigned_case_records_delivered == 1
    assert result.delivered_customer_ids == (APPROVED_CUSTOMER_ID,)


@pytest.mark.parametrize(
    ("attack", "target_effective", "guard_on"),
    tuple(itertools.product((False, True), repeat=3)),
)
def test_snapshot_reapply_is_a_behavior_free_sham(
    runtime: FinancialRecoveryRuntime,
    attack: bool,
    target_effective: bool,
    guard_on: bool,
) -> None:
    steady = runtime.execute(
        _selector(
            attack=attack,
            target_effective=target_effective,
            guard_on=guard_on,
        ),
        trace_id="steady",
    )
    reapplied = runtime.execute(
        _selector(
            attack=attack,
            target_effective=target_effective,
            guard_on=guard_on,
            sham_reapply=True,
        ),
        trace_id="reapplied",
    )

    assert not steady.snapshot_reapply_performed
    assert reapplied.snapshot_reapply_performed
    assert steady.snapshot_reapply_receipt_valid
    assert reapplied.snapshot_reapply_receipt_valid
    assert steady.snapshot_reapply_operation_id is None
    assert reapplied.snapshot_reapply_operation_id is not None
    assert reapplied.snapshot_reapply_snapshot_rows_deleted == 1
    assert reapplied.snapshot_reapply_entitlement_rows_deleted == 1
    assert reapplied.snapshot_reapply_snapshot_rows_inserted == 1
    assert reapplied.snapshot_reapply_entitlement_rows_inserted == 1
    assert steady.snapshot_reapply_semantics_unchanged
    assert reapplied.snapshot_reapply_semantics_unchanged
    assert (
        steady.snapshot_id,
        steady.snapshot_digest,
        steady.entitlement_set_digest,
        steady.old_session_state,
        steady.replacement_session_state,
        steady.replacement_session_entitlement_set_digest,
        steady.snapshot_authorized_action,
        steady.selected_customer_ids,
        steady.release_decision,
        steady.delivered_customer_ids,
        steady.prior_admitted_disclosure_count_after,
    ) == (
        reapplied.snapshot_id,
        reapplied.snapshot_digest,
        reapplied.entitlement_set_digest,
        reapplied.old_session_state,
        reapplied.replacement_session_state,
        reapplied.replacement_session_entitlement_set_digest,
        reapplied.snapshot_authorized_action,
        reapplied.selected_customer_ids,
        reapplied.release_decision,
        reapplied.delivered_customer_ids,
        reapplied.prior_admitted_disclosure_count_after,
    )


def test_cutover_fixture_is_fixed_and_bound_to_each_selected_snapshot(
    runtime: FinancialRecoveryRuntime,
) -> None:
    stale = runtime.execute(
        _selector(
            attack=True,
            target_effective=False,
            guard_on=True,
        ),
        trace_id="stale-cutover",
    )
    approved = runtime.execute(
        _selector(
            attack=True,
            target_effective=True,
            guard_on=True,
        ),
        trace_id="approved-cutover",
    )

    for result, expected_replacement in (
        (stale, REPLACEMENT_SESSION_ID),
        (approved, COMPARISON_REPLACEMENT_SESSION_ID),
    ):
        assert result.old_session_id == OLD_SESSION_ID
        assert result.old_session_state == RecoverySessionState.REVOKED
        assert result.replacement_session_id == expected_replacement
        assert result.replacement_session_state == RecoverySessionState.ACTIVE
        assert result.replacement_session_entitlement_digest_bound
        assert (
            result.replacement_session_entitlement_set_digest
            == result.entitlement_set_digest
        )
        assert result.cutover_fixture_valid
    assert (
        stale.replacement_session_entitlement_set_digest
        == STALE_ENTITLEMENT_SET_DIGEST
    )
    assert (
        approved.replacement_session_entitlement_set_digest
        == APPROVED_ENTITLEMENT_SET_DIGEST
    )


def test_reapply_does_not_leak_state_into_the_next_fresh_execution(
    runtime: FinancialRecoveryRuntime,
) -> None:
    first = runtime.execute(
        _selector(
            attack=True,
            target_effective=False,
            guard_on=True,
            sham_reapply=True,
        ),
        trace_id="first-reapply",
    )
    second = runtime.execute(
        _selector(
            attack=True,
            target_effective=True,
            guard_on=False,
        ),
        trace_id="second-fresh",
    )

    assert first.snapshot_digest == STALE_SNAPSHOT_DIGEST
    assert first.out_of_scope_records_selected == 10
    assert second.snapshot_digest == APPROVED_SNAPSHOT_DIGEST
    assert second.out_of_scope_records_selected == 0
    assert second.guard_level == COMPENSATOR_OFF.value


def test_events_bind_snapshot_cutover_selection_release_and_history(
    runtime: FinancialRecoveryRuntime,
) -> None:
    result = runtime.execute(
        _selector(
            attack=True,
            target_effective=False,
            guard_on=True,
            sham_reapply=True,
        ),
        trace_id="bound-recovery-evidence",
    )
    (
        input_event,
        cutover_event,
        target_event,
        guard_event,
        outcome_event,
        cleanup_event,
    ) = result.events

    assert input_event.value("action_digest") == ATTACK_ACTION_DIGEST
    assert input_event.value("principal_id") == "support-017"
    assert input_event.value("session_role") == "active-replacement"
    assert input_event.value("resolved_session_id") == REPLACEMENT_SESSION_ID
    assert input_event.value("session_resolution_digest") == result.session_resolution_digest
    assert (
        input_event.value("session_resolution_lifecycle_snapshot_digest")
        == result.lifecycle_snapshot_digest
    )
    assert str(input_event.value("requested_customer_ids_digest")).startswith(
        "sha256:"
    )
    assert cutover_event.value("old_session_id") == OLD_SESSION_ID
    assert cutover_event.value("old_session_state") == "revoked"
    assert cutover_event.value("replacement_session_id") == REPLACEMENT_SESSION_ID
    assert cutover_event.value("replacement_session_state") == "active"
    assert (
        cutover_event.value("replacement_session_entitlement_set_digest")
        == STALE_ENTITLEMENT_SET_DIGEST
    )
    assert cutover_event.value("cutover_fixture_valid") is True
    assert target_event.value("snapshot_id") == STALE_SNAPSHOT_ID
    assert target_event.value("snapshot_digest") == STALE_SNAPSHOT_DIGEST
    assert (
        target_event.value("entitlement_set_canonical")
        == result.entitlement_set_canonical
    )
    assert (
        target_event.value("entitlement_set_digest")
        == STALE_ENTITLEMENT_SET_DIGEST
    )
    assert target_event.value("out_of_scope_records_selected") == 10
    selected_canonical = str(
        target_event.value("selected_customer_ids_canonical")
    )
    assert (
        target_event.value("selected_customer_ids_digest")
        == f"sha256:{hashlib.sha256(selected_canonical.encode()).hexdigest()}"
    )
    assert guard_event.value("guard_mode") == "enforce"
    assert guard_event.value("release_decision") == "block"
    assert guard_event.value("unapproved_release_blocked") is True
    assert outcome_event.value("out_of_scope_records_delivered") == 0
    assert outcome_event.value("prior_admitted_disclosure_count_before") == 2
    assert outcome_event.value("prior_admitted_disclosure_count_after") == 2
    assert outcome_event.value("prior_disclosure_reference_unchanged") is True
    assert cleanup_event.value("connection_closed") is True


def test_assessment_rejects_unmatched_or_reversed_results(
    runtime: FinancialRecoveryRuntime,
) -> None:
    attack = runtime.execute(
        _selector(
            attack=True,
            target_effective=False,
            guard_on=True,
        ),
        trace_id="matched-attack",
    )
    mismatched_benign = runtime.execute(
        _selector(
            attack=False,
            target_effective=True,
            guard_on=True,
        ),
        trace_id="mismatched-benign",
    )

    with pytest.raises(ValueError, match="matched"):
        assess_recovery_case(attack, mismatched_benign)
    with pytest.raises(ValueError, match="attack result"):
        assess_recovery_case(mismatched_benign, attack)


def test_runtime_rejects_partial_wrong_typed_unknown_and_unsafe_inputs(
    runtime: FinancialRecoveryRuntime,
) -> None:
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
            trace_id="wrong-sham-type",
        )
    with pytest.raises(ValueError, match="unsupported target"):
        runtime.execute(
            CellSelector(
                input=ATTACK,
                target=StringValue(value="invented-restore"),
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
                guard_on=True,
            ),
            trace_id="../unsafe",
        )


def test_noop_snapshot_reapply_cannot_claim_a_sham_receipt(
    runtime: FinancialRecoveryRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connections: list[sqlite3.Connection] = []
    original_connect = sqlite3.connect

    def capturing_connect(database: str) -> sqlite3.Connection:
        connection = original_connect(database)
        connections.append(connection)
        return connection

    def no_op_reapply(
        connection: sqlite3.Connection,
        level: StringValue,
        *,
        trace_id: str,
        before_snapshot: dict[str, Any],
    ) -> None:
        del connection, level, trace_id, before_snapshot

    monkeypatch.setattr(sqlite3, "connect", capturing_connect)
    monkeypatch.setattr(
        recovery_runtime_module,
        "_reapply_snapshot",
        no_op_reapply,
    )

    with pytest.raises(RuntimeError, match="exact apply receipt"):
        runtime.execute(
            _selector(
                attack=True,
                target_effective=False,
                guard_on=True,
                sham_reapply=True,
            ),
            trace_id="adversarial-noop-reapply",
        )

    assert len(connections) == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connections[0].execute("SELECT 1")


def test_coherent_receipt_rewrite_without_mutations_is_rejected(
    runtime: FinancialRecoveryRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Claiming exact counts and digests cannot replace engine-observed writes."""

    def forged_receipt_only(
        connection: sqlite3.Connection,
        level: StringValue,
        *,
        trace_id: str,
        before_snapshot: dict[str, Any],
    ) -> None:
        canonical = rfc8785.dumps(before_snapshot).decode("utf-8")
        digest = (
            f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"
        )
        operation_id = recovery_runtime_module._sha256(
            rfc8785.dumps(
                {
                    "schema": "assurance-lab.snapshot-reapply-operation/v1",
                    "trace_id": trace_id,
                    "target_level": level.value,
                    "before_snapshot_digest": digest,
                }
            )
        )
        claimed_mutations = (
            recovery_runtime_module._expected_snapshot_apply_mutations(
                trace_id=trace_id,
                operation_id=operation_id,
                target_level=level.value,
                before_snapshot_canonical=canonical,
                after_snapshot_canonical=canonical,
            )
        )
        connection.execute(
            """
            INSERT INTO snapshot_apply_receipts
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                trace_id,
                operation_id,
                level.value,
                canonical,
                digest,
                canonical,
                digest,
                1,
                1,
                1,
                1,
                claimed_mutations,
                recovery_runtime_module._sha256(
                    claimed_mutations.encode("utf-8")
                ),
            ),
        )
        connection.commit()

    monkeypatch.setattr(
        recovery_runtime_module,
        "_reapply_snapshot",
        forged_receipt_only,
    )

    with pytest.raises(
        RuntimeError,
        match="does not bind the observed mutation rows",
    ):
        runtime.execute(
            _selector(
                attack=True,
                target_effective=False,
                guard_on=True,
                sham_reapply=True,
            ),
            trace_id="coherent-receipt-without-writes",
        )


def test_direct_mutation_audit_forgery_is_denied_by_sqlite_authorizer(
    runtime: FinancialRecoveryRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forge_lower_level_rows(
        connection: sqlite3.Connection,
        level: StringValue,
        *,
        trace_id: str,
        before_snapshot: dict[str, Any],
    ) -> None:
        canonical = rfc8785.dumps(before_snapshot).decode("utf-8")
        digest = recovery_runtime_module._sha256(canonical.encode("utf-8"))
        operation_id = recovery_runtime_module._sha256(
            rfc8785.dumps(
                {
                    "schema": "assurance-lab.snapshot-reapply-operation/v1",
                    "trace_id": trace_id,
                    "target_level": level.value,
                    "before_snapshot_digest": digest,
                }
            )
        )
        connection.execute(
            """
            INSERT INTO snapshot_apply_context
            VALUES (1, ?, ?, ?, 'open')
            """,
            (trace_id, operation_id, level.value),
        )
        connection.execute(
            """
            INSERT INTO snapshot_apply_mutations (
                trace_id, operation_id, entity_type, operation, row_key,
                snapshot_id, target_level, principal_id,
                restore_operation_id, entitlement
            )
            VALUES (?, ?, 'snapshot', 'delete', ?, ?, ?, ?, ?, NULL)
            """,
            (
                trace_id,
                operation_id,
                STALE_SNAPSHOT_ID,
                STALE_SNAPSHOT_ID,
                level.value,
                "support-017",
                "SYNTH-RESTORE-OPERATION-000001",
            ),
        )

    monkeypatch.setattr(
        recovery_runtime_module,
        "_reapply_snapshot",
        forge_lower_level_rows,
    )

    with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
        runtime.execute(
            _selector(
                attack=True,
                target_effective=False,
                guard_on=True,
                sham_reapply=True,
            ),
            trace_id="forged-mutation-audit",
        )


def _event_with_updates(
    event: RuntimeEvent,
    updates: dict[str, str | bool | int | None],
) -> RuntimeEvent:
    return replace(
        event,
        payload=tuple(
            (name, updates.get(name, value))
            for name, value in event.payload
        ),
    )


def _empty_identifier_evidence(schema_name: str) -> tuple[str, str]:
    canonical = rfc8785.dumps(
        {
            "schema": f"assurance-lab.{schema_name}/v1",
            "identifiers": [],
        }
    ).decode("utf-8")
    return canonical, recovery_runtime_module._sha256(canonical.encode())


def test_all_layer_delivery_rewrite_cannot_turn_exposed_path_into_effective_target(
    runtime: FinancialRecoveryRuntime,
) -> None:
    attack = runtime.execute(
        _selector(attack=True, target_effective=False, guard_on=False),
        trace_id="exposed-all-layer-attack",
    )
    benign = runtime.execute(
        _selector(attack=False, target_effective=False, guard_on=False),
        trace_id="exposed-all-layer-benign",
    )
    assert (
        assess_recovery_case(attack, benign).residual_classification
        == RecoveryResidualClassification.EXPOSED_PATH
    )

    selected_canonical, selected_digest = _empty_identifier_evidence(
        "selected-customer-set"
    )
    outside_selected_canonical, outside_selected_digest = (
        _empty_identifier_evidence(
            "selected-out-of-scope-customer-set"
        )
    )
    delivered_canonical, delivered_digest = _empty_identifier_evidence(
        "delivered-customer-set"
    )
    outside_delivered_canonical, outside_delivered_digest = (
        _empty_identifier_evidence(
            "delivered-out-of-scope-customer-set"
        )
    )
    assigned_delivered_canonical, assigned_delivered_digest = (
        _empty_identifier_evidence("delivered-assigned-customer-set")
    )
    receipts_canonical = rfc8785.dumps(
        {
            "schema": "assurance-lab.recovery-delivery-receipt-set/v1",
            "receipts": [],
        }
    ).decode("utf-8")
    receipts_digest = recovery_runtime_module._sha256(
        receipts_canonical.encode()
    )
    events = tuple(attack.events)
    events = (
        events[0],
        events[1],
        _event_with_updates(
            events[2],
            {
                "selected_customer_ids_canonical": selected_canonical,
                "selected_customer_ids_digest": selected_digest,
                "selected_out_of_scope_customer_ids_canonical": (
                    outside_selected_canonical
                ),
                "selected_out_of_scope_customer_ids_digest": (
                    outside_selected_digest
                ),
                "out_of_scope_records_selected": 0,
            },
        ),
        _event_with_updates(
            events[3],
            {"unapproved_release_blocked": False},
        ),
        _event_with_updates(
            events[4],
            {
                "delivery_receipts_canonical": receipts_canonical,
                "delivery_receipts_digest": receipts_digest,
                "delivered_customer_ids_canonical": delivered_canonical,
                "delivered_customer_ids_digest": delivered_digest,
                "delivered_out_of_scope_customer_ids_canonical": (
                    outside_delivered_canonical
                ),
                "delivered_out_of_scope_customer_ids_digest": (
                    outside_delivered_digest
                ),
                "delivered_assigned_customer_ids_canonical": (
                    assigned_delivered_canonical
                ),
                "delivered_assigned_customer_ids_digest": (
                    assigned_delivered_digest
                ),
                "out_of_scope_records_delivered": 0,
                "assigned_case_records_delivered": 0,
            },
        ),
        events[5],
    )
    rewritten_attack = replace(
        attack,
        selected_customer_ids=(),
        selected_out_of_scope_customer_ids=(),
        out_of_scope_records_selected=0,
        delivered_customer_ids=(),
        delivery_receipts_canonical=receipts_canonical,
        delivery_receipts_digest=receipts_digest,
        delivered_out_of_scope_customer_ids=(),
        delivered_assigned_customer_ids=(),
        out_of_scope_records_delivered=0,
        assigned_case_records_delivered=0,
        unapproved_release_blocked=False,
        events=events,
    )

    with pytest.raises(ValueError, match="fixed recovery execution"):
        assess_recovery_case(rewritten_attack, benign)


def test_joint_lifecycle_and_ledger_rehash_cannot_keep_the_old_cab_identity(
    runtime: FinancialRecoveryRuntime,
) -> None:
    attack = runtime.execute(
        _selector(attack=True, target_effective=False, guard_on=True),
        trace_id="joint-lifecycle-attack",
    )
    benign = runtime.execute(
        _selector(attack=False, target_effective=False, guard_on=True),
        trace_id="joint-lifecycle-benign",
    )
    original_bundle_id = attack.lifecycle_bundle_digest
    original_snapshot = IncidentSnapshot.model_validate_json(
        attack.lifecycle_snapshot_canonical,
        strict=True,
    )
    rebound_snapshot = original_snapshot.model_copy(
        update={
            "confidentiality_status": (
                ConfidentialityStatus.NONE_OBSERVED_ON_TESTED_BRANCH
            ),
            "disclosure_ledger": DisclosureLedger(),
        }
    )
    rebound_canonical = rfc8785.dumps(
        rebound_snapshot.model_dump(mode="json")
    ).decode("utf-8")
    rebound_digest = incident_snapshot_digest(rebound_snapshot)
    empty_ledger = rfc8785.dumps(
        {"data_class": "customer_confidential", "entries": []}
    ).decode("utf-8")
    empty_ledger_digest = recovery_runtime_module._sha256(
        empty_ledger.encode()
    )
    empty_ids, empty_ids_digest = _empty_identifier_evidence(
        "lifecycle-disclosure-entry-id-set"
    )

    def rewrite(
        result: FinancialRecoveryRuntimeResult,
    ) -> FinancialRecoveryRuntimeResult:
        events = tuple(result.events)
        events = (
            events[0],
            _event_with_updates(
                events[1],
                {
                    "lifecycle_snapshot_canonical": rebound_canonical,
                    "lifecycle_snapshot_digest": rebound_digest,
                    "lifecycle_bound_branch_head_digest": rebound_digest,
                    "prior_disclosure_ledger_canonical": empty_ledger,
                    "prior_disclosure_ledger_digest": empty_ledger_digest,
                    "prior_disclosure_entry_ids_canonical": empty_ids,
                    "prior_disclosure_entry_ids_digest": empty_ids_digest,
                    "prior_admitted_disclosure_count": 0,
                },
            ),
            events[2],
            events[3],
            _event_with_updates(
                events[4],
                {
                    "prior_disclosure_ledger_canonical_after": empty_ledger,
                    "prior_disclosure_ledger_digest_before": (
                        empty_ledger_digest
                    ),
                    "prior_disclosure_ledger_digest_after": (
                        empty_ledger_digest
                    ),
                    "prior_disclosure_entry_ids_digest_before": (
                        empty_ids_digest
                    ),
                    "prior_disclosure_entry_ids_digest_after": empty_ids_digest,
                    "prior_admitted_disclosure_count_before": 0,
                    "prior_admitted_disclosure_count_after": 0,
                    "prior_disclosure_reference_unchanged": True,
                },
            ),
            events[5],
        )
        return replace(
            result,
            lifecycle_snapshot_canonical=rebound_canonical,
            lifecycle_snapshot_digest=rebound_digest,
            lifecycle_bound_branch_head_digest=rebound_digest,
            prior_disclosure_ledger_canonical_before=empty_ledger,
            prior_disclosure_ledger_canonical_after=empty_ledger,
            prior_disclosure_ledger_digest_before=empty_ledger_digest,
            prior_disclosure_ledger_digest_after=empty_ledger_digest,
            prior_disclosure_entry_ids_canonical_before=empty_ids,
            prior_disclosure_entry_ids_canonical_after=empty_ids,
            prior_disclosure_entry_ids_digest_before=empty_ids_digest,
            prior_disclosure_entry_ids_digest_after=empty_ids_digest,
            prior_admitted_disclosure_count_before=0,
            prior_admitted_disclosure_count_after=0,
            prior_disclosure_reference_unchanged=True,
            events=events,
        )

    rebound_attack = rewrite(attack)
    rebound_benign = rewrite(benign)
    assert rebound_attack.lifecycle_bundle_digest == original_bundle_id

    with pytest.raises(
        ValueError,
        match=r"lifecycle CAB|session-role resolution",
    ):
        assess_recovery_case(rebound_attack, rebound_benign)


def test_allowlisted_trigger_replacement_cannot_forge_apply_mutations(
    runtime: FinancialRecoveryRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def replace_trigger_and_forge(
        connection: sqlite3.Connection,
        level: StringValue,
        *,
        trace_id: str,
        before_snapshot: dict[str, Any],
    ) -> None:
        canonical = rfc8785.dumps(before_snapshot).decode("utf-8")
        digest = recovery_runtime_module._sha256(canonical.encode())
        operation_id = recovery_runtime_module._sha256(
            rfc8785.dumps(
                {
                    "schema": "assurance-lab.snapshot-reapply-operation/v1",
                    "trace_id": trace_id,
                    "target_level": level.value,
                    "before_snapshot_digest": digest,
                }
            )
        )
        connection.execute(
            "DROP TRIGGER snapshot_apply_snapshot_delete_audit"
        )
        connection.executescript(
            f"""
            CREATE TRIGGER snapshot_apply_snapshot_delete_audit
            AFTER INSERT ON snapshot_apply_context
            BEGIN
                INSERT INTO snapshot_apply_mutations (
                    trace_id, operation_id, entity_type, operation, row_key,
                    snapshot_id, target_level, principal_id,
                    restore_operation_id, entitlement
                ) VALUES (
                    NEW.trace_id, NEW.operation_id, 'entitlement', 'delete',
                    '{STALE_SNAPSHOT_ID}:customer:*', '{STALE_SNAPSHOT_ID}',
                    NULL, NULL, NULL, 'customer:*'
                );
                INSERT INTO snapshot_apply_mutations (
                    trace_id, operation_id, entity_type, operation, row_key,
                    snapshot_id, target_level, principal_id,
                    restore_operation_id, entitlement
                ) VALUES (
                    NEW.trace_id, NEW.operation_id, 'snapshot', 'delete',
                    '{STALE_SNAPSHOT_ID}', '{STALE_SNAPSHOT_ID}',
                    NEW.target_level, 'support-017',
                    'SYNTH-RESTORE-OPERATION-000001', NULL
                );
                INSERT INTO snapshot_apply_mutations (
                    trace_id, operation_id, entity_type, operation, row_key,
                    snapshot_id, target_level, principal_id,
                    restore_operation_id, entitlement
                ) VALUES (
                    NEW.trace_id, NEW.operation_id, 'snapshot', 'insert',
                    '{STALE_SNAPSHOT_ID}', '{STALE_SNAPSHOT_ID}',
                    NEW.target_level, 'support-017',
                    'SYNTH-RESTORE-OPERATION-000001', NULL
                );
                INSERT INTO snapshot_apply_mutations (
                    trace_id, operation_id, entity_type, operation, row_key,
                    snapshot_id, target_level, principal_id,
                    restore_operation_id, entitlement
                ) VALUES (
                    NEW.trace_id, NEW.operation_id, 'entitlement', 'insert',
                    '{STALE_SNAPSHOT_ID}:customer:*', '{STALE_SNAPSHOT_ID}',
                    NULL, NULL, NULL, 'customer:*'
                );
            END;
            """
        )
        connection.execute(
            """
            INSERT INTO snapshot_apply_context
            VALUES (1, ?, ?, ?, 'open')
            """,
            (trace_id, operation_id, level.value),
        )
        mutations, mutations_digest = (
            recovery_runtime_module._snapshot_apply_mutation_readback(
                connection,
                trace_id=trace_id,
                operation_id=operation_id,
            )
        )
        connection.execute(
            """
            INSERT INTO snapshot_apply_receipts
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                trace_id,
                operation_id,
                level.value,
                canonical,
                digest,
                canonical,
                digest,
                1,
                1,
                1,
                1,
                mutations,
                mutations_digest,
            ),
        )
        connection.execute(
            "UPDATE snapshot_apply_context SET state = 'closed'"
        )
        connection.commit()

    monkeypatch.setattr(
        recovery_runtime_module,
        "_reapply_snapshot",
        replace_trigger_and_forge,
    )

    with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
        runtime.execute(
            _selector(
                attack=True,
                target_effective=False,
                guard_on=True,
                sham_reapply=True,
            ),
            trace_id="allowlisted-trigger-replacement",
        )


def test_clone_relabel_is_detected_from_run_control_readback(
    runtime: FinancialRecoveryRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = runtime._fresh_database

    def relabeled_database(**kwargs: object) -> sqlite3.Connection:
        connection = original(**kwargs)  # type: ignore[arg-type]
        connection.execute(
            "UPDATE run_control SET clone_id = ?",
            (_digest("f"),),
        )
        connection.commit()
        return connection

    monkeypatch.setattr(runtime, "_fresh_database", relabeled_database)

    with pytest.raises(RuntimeError, match="persisted readback"):
        runtime.execute(
            _selector(attack=True, target_effective=False, guard_on=True),
            trace_id="adversarial-clone-relabel",
        )


def test_repeated_trial_inputs_still_receive_distinct_clone_nonces(
    runtime: FinancialRecoveryRuntime,
) -> None:
    selector = _selector(
        attack=True,
        target_effective=False,
        guard_on=True,
    )
    first = runtime.execute(selector, trace_id="repeatable-trial-identity")
    second = runtime.execute(selector, trace_id="repeatable-trial-identity")

    assert first.clone_nonce != second.clone_nonce
    assert first.clone_id != second.clone_id


def test_assessment_rejects_coherently_rewritten_clone_identity(
    runtime: FinancialRecoveryRuntime,
) -> None:
    attack = runtime.execute(
        _selector(attack=True, target_effective=True, guard_on=True),
        trace_id="forged-clone-identity-attack",
    )
    benign = runtime.execute(
        _selector(attack=False, target_effective=True, guard_on=True),
        trace_id="forged-clone-identity-benign",
    )

    def rewrite(result: FinancialRecoveryRuntimeResult) -> FinancialRecoveryRuntimeResult:
        clone_id = _digest("a")
        clone_nonce = "a" * 32
        clone_readback = rfc8785.dumps(
            {
                "schema": "assurance-lab.sqlite-recovery-run-control/v1",
                "clone_id": clone_id,
                "clone_nonce": clone_nonce,
                "trace_id": result.trace_id,
                "storage_kind": "sqlite-memory",
            }
        ).decode("utf-8")
        clone_readback_digest = recovery_runtime_module._sha256(
            clone_readback.encode()
        )
        events = list(result.events)
        for index in (0, 5):
            updates: dict[str, str | bool | int | None] = {
                "clone_id": clone_id,
                "clone_nonce": clone_nonce,
            }
            if index == 0:
                updates.update(
                    {
                        "clone_readback_canonical": clone_readback,
                        "clone_readback_digest": clone_readback_digest,
                    }
                )
            events[index] = _event_with_updates(
                events[index],
                updates,
            )
        return replace(
            result,
            clone_id=clone_id,
            clone_nonce=clone_nonce,
            clone_readback_canonical=clone_readback,
            clone_readback_digest=clone_readback_digest,
            events=tuple(events),
        )

    with pytest.raises(ValueError, match="clone"):
        assess_recovery_case(rewrite(attack), rewrite(benign))


def test_assessment_rejects_a_forged_clone_cleanup_summary(
    runtime: FinancialRecoveryRuntime,
) -> None:
    attack = runtime.execute(
        _selector(attack=True, target_effective=True, guard_on=True),
        trace_id="forged-cleanup-probe-attack",
    )
    benign = runtime.execute(
        _selector(attack=False, target_effective=True, guard_on=True),
        trace_id="forged-cleanup-probe-benign",
    )

    def rewrite(result: FinancialRecoveryRuntimeResult) -> FinancialRecoveryRuntimeResult:
        forged = json.loads(result.clone_cleanup_probe_canonical)
        forged["outcome"] = "producer-claimed-closed"
        canonical = rfc8785.dumps(forged).decode("utf-8")
        digest = recovery_runtime_module._sha256(canonical.encode("utf-8"))
        events = list(result.events)
        events[-1] = _event_with_updates(
            events[-1],
            {
                "cleanup_probe_canonical": canonical,
                "cleanup_probe_digest": digest,
                "connection_closed": True,
            },
        )
        return replace(
            result,
            clone_cleanup_probe_canonical=canonical,
            clone_cleanup_probe_digest=digest,
            clone_cleanup_verified=True,
            events=tuple(events),
        )

    with pytest.raises(ValueError, match="cleanup evidence"):
        assess_recovery_case(rewrite(attack), rewrite(benign))


def test_assessment_rejects_coherently_forged_snapshot_apply_receipt(
    runtime: FinancialRecoveryRuntime,
) -> None:
    attack = runtime.execute(
        _selector(
            attack=True,
            target_effective=True,
            guard_on=True,
            sham_reapply=True,
        ),
        trace_id="forged-apply-receipt-attack",
    )
    benign = runtime.execute(
        _selector(
            attack=False,
            target_effective=True,
            guard_on=True,
            sham_reapply=True,
        ),
        trace_id="forged-apply-receipt-benign",
    )

    def rewrite(result: FinancialRecoveryRuntimeResult) -> FinancialRecoveryRuntimeResult:
        operation_id = _digest("f")
        mutations = rfc8785.dumps(
            {
                "schema": "assurance-lab.snapshot-apply-mutation-set/v1",
                "trace_id": result.trace_id,
                "operation_id": operation_id,
                "mutations": [{}],
            }
        ).decode("utf-8")
        mutations_digest = recovery_runtime_module._sha256(mutations.encode())
        target_event = _event_with_updates(
            result.events[2],
            {
                "snapshot_reapply_operation_id": operation_id,
                "snapshot_rows_deleted": 0,
                "entitlement_rows_deleted": 0,
                "snapshot_rows_inserted": 0,
                "entitlement_rows_inserted": 0,
                "snapshot_apply_mutation_rows_canonical": mutations,
                "snapshot_apply_mutation_rows_digest": mutations_digest,
            },
        )
        return replace(
            result,
            snapshot_reapply_operation_id=operation_id,
            snapshot_reapply_snapshot_rows_deleted=0,
            snapshot_reapply_entitlement_rows_deleted=0,
            snapshot_reapply_snapshot_rows_inserted=0,
            snapshot_reapply_entitlement_rows_inserted=0,
            snapshot_reapply_mutation_rows_canonical=mutations,
            snapshot_reapply_mutation_rows_digest=mutations_digest,
            events=(
                result.events[0],
                result.events[1],
                target_event,
                result.events[3],
                result.events[4],
                result.events[5],
            ),
        )

    with pytest.raises(ValueError, match="snapshot apply receipt"):
        assess_recovery_case(rewrite(attack), rewrite(benign))


def test_disclosure_ledger_rows_reject_insert_update_and_delete(
    runtime: FinancialRecoveryRuntime,
) -> None:
    target_level = TARGET_INEFFECTIVE.value
    fixture = runtime._cutover_fixtures[target_level]
    selector = _selector(
        attack=True,
        target_effective=False,
        guard_on=True,
    )
    nonce = "0" * 32
    clone_id = recovery_runtime_module._clone_id(
        "ledger-immutability",
        selector,
        fixture,
        nonce,
    )
    connection = runtime._fresh_database(
        target_level=target_level,
        fixture=fixture,
        clone_id=clone_id,
        clone_nonce=nonce,
        trace_id="ledger-immutability",
    )
    try:
        before = recovery_runtime_module._lifecycle_reference_readback(connection)
        statements = (
            (
                """
                INSERT INTO lifecycle_disclosure_entries
                VALUES (?, ?, ?)
                """,
                (_digest("a"), "{}", "SYNTH-INJECTED"),
            ),
            (
                """
                UPDATE lifecycle_disclosure_entries
                SET record_token = 'SYNTH-REBOUND'
                WHERE record_token = 'SYNTH-DISCLOSED-RECORD-0001'
                """,
                (),
            ),
            (
                """
                DELETE FROM lifecycle_disclosure_entries
                WHERE record_token = 'SYNTH-DISCLOSED-RECORD-0001'
                """,
                (),
            ),
            (
                """
                UPDATE lifecycle_cutover_reference
                SET disclosure_ledger_canonical = '{}'
                WHERE singleton = 1
                """,
                (),
            ),
            (
                "DELETE FROM lifecycle_cutover_reference WHERE singleton = 1",
                (),
            ),
        )
        for statement, parameters in statements:
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                connection.execute(statement, parameters)
            connection.rollback()
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO lifecycle_cutover_reference
                SELECT * FROM lifecycle_cutover_reference
                """
            )
        connection.rollback()
        after = recovery_runtime_module._lifecycle_reference_readback(connection)
        assert after == before
    finally:
        connection.close()


def test_cleanup_attestation_failure_is_not_reported_as_success(
    runtime: FinancialRecoveryRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_cleanup_probe(
        _connection: sqlite3.Connection,
        *,
        trace_id: str,
        clone_id: str,
        clone_nonce: str,
    ) -> tuple[str, str]:
        del trace_id, clone_id, clone_nonce
        raise RuntimeError("fresh SQLite clone remained usable after close")

    monkeypatch.setattr(
        recovery_runtime_module,
        "_closed_connection_probe_evidence",
        reject_cleanup_probe,
    )

    with pytest.raises(RuntimeError, match="remained usable"):
        runtime.execute(
            _selector(attack=True, target_effective=False, guard_on=True),
            trace_id="cleanup-attestation-failure",
        )


def test_rebound_disclosure_history_is_rejected_against_lifecycle_snapshot(
    runtime: FinancialRecoveryRuntime,
) -> None:
    attack = runtime.execute(
        _selector(attack=True, target_effective=False, guard_on=True),
        trace_id="history-bound-attack",
    )
    benign = runtime.execute(
        _selector(attack=False, target_effective=False, guard_on=True),
        trace_id="history-bound-benign",
    )
    cleared_ledger = rfc8785.dumps(
        {"data_class": "customer_confidential", "entries": []}
    ).decode("utf-8")
    cleared_entry_ids = rfc8785.dumps(
        {
            "schema": (
                "assurance-lab.lifecycle-disclosure-entry-id-set/v1"
            ),
            "identifiers": [],
        }
    ).decode("utf-8")
    cleared_ledger_digest = (
        f"sha256:{hashlib.sha256(cleared_ledger.encode()).hexdigest()}"
    )
    cleared_entry_ids_digest = (
        f"sha256:{hashlib.sha256(cleared_entry_ids.encode()).hexdigest()}"
    )

    def clear_after(
        result: FinancialRecoveryRuntimeResult,
    ) -> FinancialRecoveryRuntimeResult:
        return replace(
            result,
            prior_disclosure_ledger_canonical_after=cleared_ledger,
            prior_disclosure_ledger_digest_after=cleared_ledger_digest,
            prior_disclosure_entry_ids_canonical_after=cleared_entry_ids,
            prior_disclosure_entry_ids_digest_after=cleared_entry_ids_digest,
            prior_admitted_disclosure_count_after=0,
            prior_disclosure_reference_unchanged=False,
        )

    with pytest.raises(ValueError, match="not bound to the lifecycle snapshot"):
        assess_recovery_case(clear_after(attack), clear_after(benign))


def test_coherent_before_and_after_ledger_rewrite_is_rejected(
    runtime: FinancialRecoveryRuntime,
) -> None:
    attack = runtime.execute(
        _selector(attack=True, target_effective=False, guard_on=True),
        trace_id="coherent-history-attack",
    )
    benign = runtime.execute(
        _selector(attack=False, target_effective=False, guard_on=True),
        trace_id="coherent-history-benign",
    )
    cleared_ledger = rfc8785.dumps(
        {"data_class": "customer_confidential", "entries": []}
    ).decode("utf-8")
    cleared_ids = rfc8785.dumps(
        {
            "schema": "assurance-lab.lifecycle-disclosure-entry-id-set/v1",
            "identifiers": [],
        }
    ).decode("utf-8")
    ledger_digest = recovery_runtime_module._sha256(cleared_ledger.encode())
    ids_digest = recovery_runtime_module._sha256(cleared_ids.encode())

    def rewrite(
        result: FinancialRecoveryRuntimeResult,
    ) -> FinancialRecoveryRuntimeResult:
        return replace(
            result,
            prior_disclosure_ledger_canonical_before=cleared_ledger,
            prior_disclosure_ledger_canonical_after=cleared_ledger,
            prior_disclosure_ledger_digest_before=ledger_digest,
            prior_disclosure_ledger_digest_after=ledger_digest,
            prior_disclosure_entry_ids_canonical_before=cleared_ids,
            prior_disclosure_entry_ids_canonical_after=cleared_ids,
            prior_disclosure_entry_ids_digest_before=ids_digest,
            prior_disclosure_entry_ids_digest_after=ids_digest,
            prior_admitted_disclosure_count_before=0,
            prior_admitted_disclosure_count_after=0,
            prior_disclosure_reference_unchanged=True,
        )

    with pytest.raises(ValueError, match="not bound to the lifecycle snapshot"):
        assess_recovery_case(rewrite(attack), rewrite(benign))


def test_changed_lifecycle_head_cannot_reuse_the_verified_cutover_reference() -> None:
    fixtures = _cutover_fixtures()
    actual = fixtures[TARGET_INEFFECTIVE.value]
    rebound_snapshot = actual.snapshot.model_copy(
        update={
            "confidentiality_status": (
                ConfidentialityStatus.NONE_OBSERVED_ON_TESTED_BRANCH
            ),
            "disclosure_ledger": DisclosureLedger(),
        }
    )
    rebound_fixture = replace(actual, snapshot=rebound_snapshot)
    fixtures[TARGET_INEFFECTIVE.value] = rebound_fixture

    with pytest.raises(ValueError, match="verified lifecycle current head"):
        FinancialRecoveryRuntime(
            generate_dataset(seed=2907, profile=DatasetProfile.DEFAULT),
            cutover_fixtures=fixtures,
        )


@pytest.mark.parametrize(
    ("target_level", "verified_update", "message"),
    (
        (
            TARGET_INEFFECTIVE.value,
            {"actual_transition_ids": ()},
            "actual cutover snapshot",
        ),
        (
            TARGET_EFFECTIVE.value,
            {"matched_comparison_transition_ids": ()},
            "comparison cutover snapshot",
        ),
        (
            TARGET_INEFFECTIVE.value,
            {"current_snapshot_digest": _digest("e")},
            "current state",
        ),
    ),
)
def test_cutover_requires_exact_branch_head_and_rotation_membership(
    target_level: str,
    verified_update: dict[str, object],
    message: str,
) -> None:
    original = _cutover_fixtures()
    target_fixture = original[target_level]
    rebound_target = replace(
        target_fixture,
        verified_lifecycle=target_fixture.verified_lifecycle.model_copy(
            update=verified_update
        ),
    )
    fixtures = {
        target_level: rebound_target,
        **{
            level: fixture
            for level, fixture in original.items()
            if level != target_level
        },
    }

    with pytest.raises(ValueError, match=message):
        FinancialRecoveryRuntime(
            generate_dataset(seed=2907, profile=DatasetProfile.DEFAULT),
            cutover_fixtures=fixtures,
        )


def test_rebound_snapshot_and_lifecycle_cannot_reuse_old_verification(
) -> None:
    """Regression: changing both in-memory objects must not outrun the CAB bytes."""

    fixtures = _cutover_fixtures()
    actual = fixtures[TARGET_INEFFECTIVE.value]
    comparison = fixtures[TARGET_EFFECTIVE.value]
    rebound_snapshot = actual.snapshot.model_copy(
        update={
            "confidentiality_status": (
                ConfidentialityStatus.NONE_OBSERVED_ON_TESTED_BRANCH
            ),
            "disclosure_ledger": DisclosureLedger(),
        }
    )
    rebound_head = incident_snapshot_digest(rebound_snapshot)
    rebound_verified = actual.verified_lifecycle.model_copy(
        update={
            "current_snapshot_digest": rebound_head,
            "actual_head_digest": rebound_head,
        }
    )
    fixtures[TARGET_INEFFECTIVE.value] = replace(
        actual,
        snapshot=rebound_snapshot,
        verified_lifecycle=rebound_verified,
    )
    fixtures[TARGET_EFFECTIVE.value] = replace(
        comparison,
        verified_lifecycle=rebound_verified,
    )

    with pytest.raises(
        ValueError,
        match=r"descriptor is rebound|differs from independent replay",
    ):
        FinancialRecoveryRuntime(
            generate_dataset(seed=2907, profile=DatasetProfile.DEFAULT),
            cutover_fixtures=fixtures,
        )


def test_forged_bundle_verification_model_cannot_replace_fresh_cab_verification() -> None:
    """A Pydantic object shaped like verifier output is not provenance evidence."""

    fixtures = _cutover_fixtures()
    actual = fixtures[TARGET_INEFFECTIVE.value]
    comparison = fixtures[TARGET_EFFECTIVE.value]
    rebound_snapshot = actual.snapshot.model_copy(
        update={
            "confidentiality_status": (
                ConfidentialityStatus.NONE_OBSERVED_ON_TESTED_BRANCH
            ),
            "disclosure_ledger": DisclosureLedger(),
        }
    )
    rebound_head = incident_snapshot_digest(rebound_snapshot)
    rebound_verified = actual.verified_lifecycle.model_copy(
        update={
            "current_snapshot_digest": rebound_head,
            "actual_head_digest": rebound_head,
        }
    )
    payloads: dict[str, bytes] = {}
    for target_level, source, snapshot, target_digest in (
        (
            TARGET_INEFFECTIVE.value,
            actual,
            rebound_snapshot,
            STALE_SNAPSHOT_DIGEST,
        ),
        (
            TARGET_EFFECTIVE.value,
            comparison,
            comparison.snapshot,
            APPROVED_SNAPSHOT_DIGEST,
        ),
    ):
        payloads.update(
            lifecycle_cutover_bundle_payloads(
                target_level=target_level,
                session_rotation_transition_id=(
                    source.session_rotation_transition_id
                ),
                target_snapshot_digest=target_digest,
                old_session_id=source.old_session_id,
                replacement_session_id=source.replacement_session_id,
                snapshot=snapshot,
                verified_lifecycle=rebound_verified,
            )
        )

    def role(path: str) -> str:
        if path.endswith("/verified-lifecycle.json"):
            return "lifecycle-verifier-output"
        if path.endswith("/cutover-snapshot.json"):
            return "lifecycle-cutover-snapshot"
        return "lifecycle-cutover-reference"

    old_manifest = actual.bundle_verification.manifest
    assert old_manifest is not None
    forged_manifest = old_manifest.model_copy(
        update={
            "files": [
                BundleFile(
                    path=path,
                    sha256=hashlib.sha256(payload).hexdigest(),
                    size=len(payload),
                    media_type="application/json",
                    role=role(path),
                    sensitivity=Sensitivity.SYNTHETIC,
                    required_for=["financial-recovery-cutover"],
                )
                for path, payload in sorted(payloads.items())
            ]
        }
    )
    forged_bundle_id = forged_manifest.bundle_id()
    forged_verification = BundleVerification(
        status=BundleStatus.INTEGRITY_VERIFIED,
        bundle_id=forged_bundle_id,
        manifest=forged_manifest,
        issues=[],
    )
    fixtures[TARGET_INEFFECTIVE.value] = replace(
        actual,
        lifecycle_bundle_digest=forged_bundle_id,
        bundle_verification=forged_verification,
        snapshot=rebound_snapshot,
        verified_lifecycle=rebound_verified,
    )
    fixtures[TARGET_EFFECTIVE.value] = replace(
        comparison,
        lifecycle_bundle_digest=forged_bundle_id,
        bundle_verification=forged_verification,
        verified_lifecycle=rebound_verified,
    )

    with pytest.raises(ValueError, match="differs from fresh verification"):
        FinancialRecoveryRuntime(
            generate_dataset(seed=2907, profile=DatasetProfile.DEFAULT),
            cutover_fixtures=fixtures,
        )


def test_target_contrast_requires_one_shared_lifecycle_cab() -> None:
    """The effective cell must be the comparison branch of the same proof."""

    shared = _cutover_fixtures()
    FinancialRecoveryRuntime(
        generate_dataset(seed=2907, profile=DatasetProfile.DEFAULT),
        cutover_fixtures=shared,
    )

    split: dict[str, LifecycleCutoverFixture] = {}
    lifecycle, receipts, verified = build_reference_recovery_lifecycle()
    proof_payloads = lifecycle_proof_bundle_payloads(
        lifecycle=lifecycle,
        admitted_receipts=receipts,
        verified_lifecycle=verified,
    )
    for target_level in (
        TARGET_INEFFECTIVE.value,
        TARGET_EFFECTIVE.value,
    ):
        source = shared[target_level]
        payloads = {
            **proof_payloads,
            **lifecycle_cutover_bundle_payloads(
                target_level=target_level,
                session_rotation_transition_id=(
                    source.session_rotation_transition_id
                ),
                target_snapshot_digest=source.target_snapshot_digest,
                old_session_id=source.old_session_id,
                replacement_session_id=source.replacement_session_id,
                snapshot=source.snapshot,
                verified_lifecycle=verified,
            ),
        }
        verification, root = _verified_lifecycle_bundle(payloads)
        assert verification.bundle_id is not None
        split[target_level] = replace(
            source,
            lifecycle_bundle_digest=verification.bundle_id,
            lifecycle_bundle_root=root,
            bundle_verification=verification,
            verified_lifecycle=verified,
        )

    with pytest.raises(ValueError, match="one shared lifecycle CAB"):
        FinancialRecoveryRuntime(
            generate_dataset(seed=2907, profile=DatasetProfile.DEFAULT),
            cutover_fixtures=split,
        )


def test_cutover_transition_must_be_the_rotation_edge_that_created_the_snapshot() -> None:
    fixtures = _cutover_fixtures()
    lifecycle, receipts, verified = build_reference_recovery_lifecycle()
    payloads = lifecycle_proof_bundle_payloads(
        lifecycle=lifecycle,
        admitted_receipts=receipts,
        verified_lifecycle=verified,
    )
    wrong_transition_ids: dict[str, str] = {}
    for target_level, branch in (
        (TARGET_INEFFECTIVE.value, lifecycle.actual),
        (TARGET_EFFECTIVE.value, lifecycle.matched_comparison),
    ):
        source = fixtures[target_level]
        wrong_transition_id = branch.transitions[0].transition_id
        assert wrong_transition_id != branch.transitions[-1].transition_id
        wrong_transition_ids[target_level] = wrong_transition_id
        payloads.update(
            lifecycle_cutover_bundle_payloads(
                target_level=target_level,
                session_rotation_transition_id=wrong_transition_id,
                target_snapshot_digest=source.target_snapshot_digest,
                old_session_id=source.old_session_id,
                replacement_session_id=source.replacement_session_id,
                snapshot=source.snapshot,
                verified_lifecycle=verified,
            )
        )

    verification, root = _verified_lifecycle_bundle(payloads)
    assert verification.bundle_id is not None
    for target_level, fixture in tuple(fixtures.items()):
        fixtures[target_level] = replace(
            fixture,
            lifecycle_bundle_digest=verification.bundle_id,
            lifecycle_bundle_root=root,
            bundle_verification=verification,
            session_rotation_transition_id=wrong_transition_ids[target_level],
            verified_lifecycle=verified,
        )

    with pytest.raises(
        ValueError,
        match="session rotation transition does not produce",
    ):
        FinancialRecoveryRuntime(
            generate_dataset(seed=2907, profile=DatasetProfile.DEFAULT),
            cutover_fixtures=fixtures,
        )


def test_integrity_valid_bundle_cannot_self_assert_a_lifecycle_verdict() -> None:
    """Raw lifecycle inputs, not a producer-authored verdict, decide admission."""

    fixtures = _cutover_fixtures()
    source = fixtures[TARGET_INEFFECTIVE.value]
    lifecycle, receipts, verified = build_reference_recovery_lifecycle()
    raw_lifecycle = lifecycle.model_dump(mode="json")
    comparison_head = raw_lifecycle["matched_comparison"]["snapshots"][-1]
    comparison_head["replacement_session_digest"] = (
        raw_lifecycle["actual"]["snapshots"][-1]["replacement_session_digest"]
    )

    proof_payloads = lifecycle_proof_bundle_payloads(
        lifecycle=lifecycle,
        admitted_receipts=receipts,
        verified_lifecycle=verified,
    )
    proof_payloads["records/lifecycle/incident-lifecycle.json"] = (
        canonical_json_bytes(raw_lifecycle)
    )
    payloads = {
        **proof_payloads,
        **lifecycle_cutover_bundle_payloads(
            target_level=TARGET_INEFFECTIVE.value,
            session_rotation_transition_id=source.session_rotation_transition_id,
            target_snapshot_digest=source.target_snapshot_digest,
            old_session_id=source.old_session_id,
            replacement_session_id=source.replacement_session_id,
            snapshot=source.snapshot,
            verified_lifecycle=source.verified_lifecycle,
        ),
    }
    verification, root = _verified_lifecycle_bundle(payloads)
    assert verification.bundle_id is not None
    fixtures[TARGET_INEFFECTIVE.value] = replace(
        source,
        lifecycle_bundle_digest=verification.bundle_id,
        lifecycle_bundle_root=root,
        bundle_verification=verification,
    )

    with pytest.raises(
        ValueError,
        match="raw proof does not reproduce a valid lifecycle",
    ):
        FinancialRecoveryRuntime(
            generate_dataset(seed=2907, profile=DatasetProfile.DEFAULT),
            cutover_fixtures=fixtures,
        )


@pytest.mark.parametrize("rebound_field", ("sensitivity", "required_for"))
def test_lifecycle_payload_descriptor_is_exact_not_merely_hash_matched(
    rebound_field: str,
) -> None:
    fixtures = _cutover_fixtures()
    actual = fixtures[TARGET_INEFFECTIVE.value]
    manifest = actual.bundle_verification.manifest
    assert manifest is not None
    stale_reference_path = (
        "records/lifecycle/stale-wildcard/cutover-reference.json"
    )
    descriptors: list[BundleFile] = []
    for descriptor in manifest.files:
        if descriptor.path != stale_reference_path:
            descriptors.append(descriptor)
            continue
        update: dict[str, object]
        if rebound_field == "sensitivity":
            update = {"sensitivity": Sensitivity.LAB_INTERNAL}
        else:
            update = {
                "required_for": [
                    "financial-recovery-cutover",
                    "unrelated-consumer",
                ]
            }
        descriptors.append(descriptor.model_copy(update=update))
    rebound_manifest = manifest.model_copy(update={"files": descriptors})
    owner = tempfile.TemporaryDirectory(prefix="assurance-rebound-cab-")
    _BUNDLE_ROOTS.append(owner)
    rebound_root = Path(owner.name)
    for descriptor in descriptors:
        source = actual.lifecycle_bundle_root / descriptor.path
        destination = rebound_root / descriptor.path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())
    (rebound_root / "bundle.json").write_bytes(
        rebound_manifest.canonical_bytes()
    )
    rebound_verification = verify_bundle(rebound_root)
    assert rebound_verification.status == BundleStatus.INTEGRITY_VERIFIED
    assert rebound_verification.bundle_id is not None
    for target_level, fixture in tuple(fixtures.items()):
        fixtures[target_level] = replace(
            fixture,
            lifecycle_bundle_root=rebound_root,
            lifecycle_bundle_digest=rebound_verification.bundle_id,
            bundle_verification=rebound_verification,
        )

    with pytest.raises(ValueError, match="descriptor is rebound"):
        FinancialRecoveryRuntime(
            generate_dataset(seed=2907, profile=DatasetProfile.DEFAULT),
            cutover_fixtures=fixtures,
        )


def test_lifecycle_cab_is_freshly_reverified_at_execution_time() -> None:
    fixtures = _cutover_fixtures()
    runtime = FinancialRecoveryRuntime(
        generate_dataset(seed=2907, profile=DatasetProfile.DEFAULT),
        cutover_fixtures=fixtures,
    )
    actual = fixtures[TARGET_INEFFECTIVE.value]
    payload_path = (
        actual.lifecycle_bundle_root
        / "records/lifecycle/stale-wildcard/cutover-reference.json"
    )
    payload_path.write_bytes(payload_path.read_bytes() + b"\n")

    with pytest.raises(ValueError, match="differs from fresh verification"):
        runtime.execute(
            _selector(attack=True, target_effective=False, guard_on=True),
            trace_id="post-init-cab-mutation",
        )


def test_event_sets_reproduce_scope_and_delivery_metrics(
    runtime: FinancialRecoveryRuntime,
) -> None:
    result = runtime.execute(
        _selector(attack=True, target_effective=False, guard_on=False),
        trace_id="independent-set-reconstruction",
    )
    target_event = result.events[2]
    outcome_event = result.events[4]

    def identifiers(event: RuntimeEvent, field: str) -> tuple[str, ...]:
        value = event.value(field)
        assert isinstance(value, str)
        parsed = json.loads(value)
        assert isinstance(parsed, dict)
        raw = parsed["identifiers"]
        assert isinstance(raw, list)
        return tuple(str(item) for item in raw)

    requested = identifiers(
        result.events[0],
        "requested_customer_ids_canonical",
    )
    assigned = identifiers(target_event, "assigned_customer_ids_canonical")
    selected = identifiers(target_event, "selected_customer_ids_canonical")
    selected_outside = identifiers(
        target_event,
        "selected_out_of_scope_customer_ids_canonical",
    )
    delivered = identifiers(
        outcome_event,
        "delivered_customer_ids_canonical",
    )
    delivered_outside = identifiers(
        outcome_event,
        "delivered_out_of_scope_customer_ids_canonical",
    )

    assert requested == result.requested_customer_ids
    assert assigned == result.assigned_customer_ids
    assert selected == result.selected_customer_ids
    assert selected_outside == tuple(
        customer_id
        for customer_id in selected
        if customer_id not in set(assigned)
    )
    assert delivered == result.delivered_customer_ids
    assert delivered_outside == tuple(
        customer_id
        for customer_id in delivered
        if customer_id not in set(assigned)
    )
    assert len(selected_outside) == result.out_of_scope_records_selected
    assert len(delivered_outside) == result.out_of_scope_records_delivered
