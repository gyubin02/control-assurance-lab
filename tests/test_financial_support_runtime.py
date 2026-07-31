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


def test_runner_identity_is_persisted_read_back_and_closed_after_the_trial(
    runtime: FinancialSupportRuntime,
) -> None:
    result = runtime.execute(
        _selector(attack=False, target_effective=True, guard_on=True),
        trace_id="trace-resource-receipts",
        clone_nonce="runner-chosen-clone-0001",
        runner_resource_id="test-sqlite-runner",
    )

    identity = result.resource_identity
    assert identity.requested_clone_nonce == "runner-chosen-clone-0001"
    assert identity.observed_clone_nonce == identity.requested_clone_nonce
    assert identity.requested_runner_resource_id == "test-sqlite-runner"
    assert identity.observed_runner_resource_id == identity.requested_runner_resource_id
    assert identity.observed_runtime_instance_id == (
        "runner-chosen-clone-0001:generation-1"
    )
    assert identity.observed_generation == 1

    cleanup = result.cleanup_probe
    assert cleanup.clone_nonce == identity.observed_clone_nonce
    assert cleanup.runner_resource_id == identity.observed_runner_resource_id
    assert cleanup.runtime_instance_id == identity.observed_runtime_instance_id
    assert cleanup.probe_operation == "select-runtime-identity-after-close"
    assert cleanup.error_type == "sqlite3.ProgrammingError"
    assert cleanup.closed_handle_rejected_operation is True


@pytest.mark.parametrize("sham", (False, True))
def test_redeploy_receipt_records_the_actual_pre_and_post_operation(
    runtime: FinancialSupportRuntime,
    sham: bool,
) -> None:
    clone_nonce = f"redeploy-receipt-{int(sham)}"
    result = runtime.execute(
        _selector(
            attack=False,
            target_effective=True,
            guard_on=True,
            sham=sham,
        ),
        trace_id=f"trace-redeploy-receipt-{int(sham)}",
        clone_nonce=clone_nonce,
    )

    operation = result.redeploy_operation
    assert operation.requested is sham
    assert operation.performed is sham
    assert operation.before_runtime_instance_id == f"{clone_nonce}:generation-1"
    assert operation.after_runtime_instance_id == (
        f"{clone_nonce}:generation-2" if sham else f"{clone_nonce}:generation-1"
    )
    assert operation.previous_handle_closed is sham
    assert operation.before_dataset_snapshot_digest == (
        operation.after_dataset_snapshot_digest
    )
    assert (
        operation.before_principal_count,
        operation.before_customer_count,
        operation.before_support_case_count,
    ) == (
        operation.after_principal_count,
        operation.after_customer_count,
        operation.after_support_case_count,
    )
    assert result.resource_identity.observed_generation == (2 if sham else 1)
    assert result.resource_identity.observed_runtime_instance_id == (
        operation.after_runtime_instance_id
    )


def test_persisted_receipts_join_one_request_from_source_rows_to_client(
    runtime: FinancialSupportRuntime,
) -> None:
    result = runtime.execute(
        _selector(attack=True, target_effective=False, guard_on=True),
        trace_id="trace-persisted-join",
        clone_nonce="persisted-join-clone",
    )

    request_id = result.request_receipt.request_id
    assert request_id == "request-trace-persisted-join"
    assert result.request_receipt.requested_customer_ids == tuple(
        row.customer_id for row in result.requested_customer_rows
    )
    assert result.authorization_receipt.request_id == request_id
    assert result.authorization_receipt.assigned_customer_ids == tuple(
        row.customer_id for row in result.assigned_support_case_rows
    )
    assert result.selection_receipt.request_id == request_id
    assert result.guard_receipt.request_id == request_id
    assert result.delivery_receipt.request_id == request_id
    assert result.client_receipt.request_id == request_id
    assert result.delivery_receipt.payload_digest == result.client_receipt.payload_digest
    assert result.delivery_receipt.delivered_customer_ids == (
        result.client_receipt.received_customer_ids
    )


@pytest.mark.parametrize(
    ("target_effective", "guard_on", "sham"),
    tuple(itertools.product((False, True), repeat=3)),
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
    tuple(itertools.product((False, True), repeat=2)),
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
