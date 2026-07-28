from __future__ import annotations

import itertools
from datetime import UTC, datetime

import pytest

from assurance_lab.contract import CellSelector
from assurance_lab.scenarios.financial_data import DatasetProfile, generate_dataset
from assurance_lab.scenarios.financial_support import (
    ActorRole,
    EntitlementMode,
    ReleaseGuardMode,
    SupportExportInput,
    evaluate_support_export,
)
from assurance_lab.scenarios.financial_support_contract import (
    ATTACK,
    ATTACK_ACTION_DIGEST,
    BENIGN,
    BENIGN_ACTION_DIGEST,
    COMPENSATOR_OFF,
    COMPENSATOR_ON,
    SHAM_REDEPLOY,
    SHAM_STEADY,
    TARGET_EFFECTIVE,
    TARGET_INEFFECTIVE,
    action_descriptor,
)
from assurance_lab.scenarios.financial_support_runtime import FinancialSupportRuntime


@pytest.fixture(scope="module")
def runtime() -> FinancialSupportRuntime:
    return FinancialSupportRuntime(
        generate_dataset(seed=2907, profile=DatasetProfile.DEFAULT)
    )


def test_runtime_rejects_a_fixture_that_cannot_run_the_declared_action() -> None:
    with pytest.raises(ValueError, match="support-017"):
        FinancialSupportRuntime(
            generate_dataset(seed=2907, profile=DatasetProfile.SMOKE)
        )


def _selector(
    *,
    attack: bool,
    target_effective: bool,
    guard_on: bool,
    sham: bool = False,
) -> CellSelector:
    return CellSelector(
        input=ATTACK if attack else BENIGN,
        target=TARGET_EFFECTIVE if target_effective else TARGET_INEFFECTIVE,
        compensator=COMPENSATOR_ON if guard_on else COMPENSATOR_OFF,
        sham=SHAM_REDEPLOY if sham else SHAM_STEADY,
    )


def test_non_masking_cell_selects_data_before_the_guard_blocks_it(
    runtime: FinancialSupportRuntime,
) -> None:
    result = runtime.execute(
        _selector(attack=True, target_effective=False, guard_on=True),
        trace_id="trace-masked-target-failure",
    )

    assert result.out_of_scope_records_selected == 10
    assert result.release_guard_reached
    assert result.compensator_blocks_downstream
    assert result.out_of_scope_records_delivered == 0
    assert not result.target_blocks_downstream
    assert result.action_digest == ATTACK_ACTION_DIGEST


def test_effective_target_stops_selection_and_leaves_guard_not_exercised(
    runtime: FinancialSupportRuntime,
) -> None:
    result = runtime.execute(
        _selector(attack=True, target_effective=True, guard_on=True),
        trace_id="trace-target-effective",
    )

    assert result.target_blocks_downstream
    assert result.out_of_scope_records_selected == 0
    assert not result.release_guard_reached
    assert not result.compensator_blocks_downstream
    assert result.out_of_scope_records_delivered == 0
    assert {event.stage for event in result.events} == {"input", "target", "outcome"}


def test_monitor_only_exposes_the_failed_path(runtime: FinancialSupportRuntime) -> None:
    result = runtime.execute(
        _selector(attack=True, target_effective=False, guard_on=False),
        trace_id="trace-exposed-path",
    )

    assert result.out_of_scope_records_selected == 10
    assert result.out_of_scope_records_delivered == 10
    assert result.selected_customer_ids == result.delivered_customer_ids


@pytest.mark.parametrize(
    ("target_effective", "guard_on", "sham"),
    itertools.product((False, True), repeat=3),
)
def test_assigned_case_service_survives_every_intervention(
    runtime: FinancialSupportRuntime,
    target_effective: bool,
    guard_on: bool,
    sham: bool,
) -> None:
    result = runtime.execute(
        _selector(
            attack=False,
            target_effective=target_effective,
            guard_on=guard_on,
            sham=sham,
        ),
        trace_id=f"trace-benign-{int(target_effective)}-{int(guard_on)}-{int(sham)}",
    )

    assert result.authorization_decision.value == "allow"
    assert result.assigned_case_records_delivered == 1
    assert result.out_of_scope_records_delivered == 0
    assert result.action_digest == BENIGN_ACTION_DIGEST


@pytest.mark.parametrize(
    ("target_effective", "guard_on"),
    itertools.product((False, True), repeat=2),
)
def test_primary_attack_matrix_matches_the_independent_oracle(
    runtime: FinancialSupportRuntime,
    target_effective: bool,
    guard_on: bool,
) -> None:
    selector = _selector(
        attack=True,
        target_effective=target_effective,
        guard_on=guard_on,
    )
    result = runtime.execute(
        selector,
        trace_id=f"trace-oracle-{int(target_effective)}-{int(guard_on)}",
    )
    descriptor = action_descriptor(ATTACK)
    requested = frozenset(descriptor["requested_customer_ids"])
    expected = evaluate_support_export(
        SupportExportInput(
            trace_id="1" * 32,
            principal_id="support-017",
            role=ActorRole.SUPPORT,
            assigned_customer_ids=frozenset({"SYNTH-CUSTOMER-000017"}),
            requested_customer_ids=requested,
            records_per_customer=1,
            entitlement_mode=(
                EntitlementMode.CASE_SCOPED
                if target_effective
                else EntitlementMode.WILDCARD_MISGRANT
            ),
            release_guard_mode=(
                ReleaseGuardMode.ENFORCE
                if guard_on
                else ReleaseGuardMode.MONITOR_ONLY
            ),
            bulk_threshold_records=10,
            as_of=datetime(2026, 7, 28, tzinfo=UTC),
        )
    )

    assert result.out_of_scope_records_selected == expected.out_of_scope_records_selected
    assert result.release_guard_reached == expected.release_guard_reached
    assert result.out_of_scope_records_delivered == expected.delivered_record_count
