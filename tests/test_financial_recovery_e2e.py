from __future__ import annotations

import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest

import assurance_lab.scenarios.financial_recovery_runtime as runtime_module
from assurance_lab.contract import CellSelector, StringValue
from assurance_lab.lifecycle import (
    IncidentBranch,
    IncidentLifecycle,
    IncidentTransitionBody,
    IncidentTransitionRecord,
    LifecycleVerificationError,
    incident_snapshot_digest,
    verify_lifecycle,
)
from assurance_lab.scenarios.financial_data import DatasetProfile, generate_dataset
from assurance_lab.scenarios.financial_recovery_contract import (
    ACTIVE_REPLACEMENT_SESSION_ROLE,
    ATTACK,
    COMPENSATOR_ON,
    REPLACEMENT_SESSION_ID,
    SHAM_STEADY,
    TARGET_EFFECTIVE,
    TARGET_INEFFECTIVE,
)
from assurance_lab.scenarios.financial_recovery_e2e import (
    build_reference_recovery_lifecycle,
    write_reference_recovery_lifecycle_bundle,
)
from assurance_lab.scenarios.financial_recovery_runtime import (
    FinancialRecoveryRuntime,
)


def _selector(*, effective: bool) -> CellSelector:
    return CellSelector(
        input=ATTACK,
        target=TARGET_EFFECTIVE if effective else TARGET_INEFFECTIVE,
        compensator=COMPENSATOR_ON,
        sham=SHAM_STEADY,
    )


def test_real_lifecycle_proof_drives_both_recovery_branches(
    tmp_path: Path,
) -> None:
    evidence = write_reference_recovery_lifecycle_bundle(tmp_path / "recovery-lifecycle.cab")

    assert evidence.verified_lifecycle == verify_lifecycle(
        evidence.lifecycle,
        admitted_receipts=evidence.admitted_receipts,
    )
    stale_session = evidence.stale_fixture.snapshot.replacement_session_digest
    approved_session = evidence.approved_fixture.snapshot.replacement_session_digest
    assert stale_session is not None
    assert approved_session is not None
    assert stale_session != approved_session

    runtime = FinancialRecoveryRuntime(
        generate_dataset(seed=2907, profile=DatasetProfile.DEFAULT),
        cutover_fixtures=evidence.cutover_fixtures(),
    )
    stale = runtime.execute(_selector(effective=False), trace_id="stale-e2e")
    approved = runtime.execute(
        _selector(effective=True),
        trace_id="approved-e2e",
    )

    assert stale.action_digest == approved.action_digest
    assert (
        stale.action_session_role == approved.action_session_role == ACTIVE_REPLACEMENT_SESSION_ROLE
    )
    assert stale.replacement_session_id != approved.replacement_session_id
    assert stale.replacement_session_id == REPLACEMENT_SESSION_ID
    for result in (stale, approved):
        assert (
            result.session_resolution_lifecycle_snapshot_digest == result.lifecycle_snapshot_digest
        )
        assert (
            result.session_resolution_verified_lifecycle_digest == result.verified_lifecycle_digest
        )
        input_event = result.events[0]
        assert input_event.value("session_role") == ACTIVE_REPLACEMENT_SESSION_ROLE
        assert input_event.value("resolved_session_id") == result.replacement_session_id
        assert input_event.value("session_resolution_digest") == result.session_resolution_digest


def test_real_lifecycle_rejects_cross_branch_replacement_session_reuse() -> None:
    lifecycle, receipts, _verified = build_reference_recovery_lifecycle()
    actual_replacement = lifecycle.actual.snapshots[-1].replacement_session_digest
    assert actual_replacement is not None
    comparison = lifecycle.matched_comparison
    rebound_head = comparison.snapshots[-1].model_copy(
        update={"replacement_session_digest": actual_replacement}
    )
    prior_transition = comparison.transitions[-1]
    rebound_body = IncidentTransitionBody.model_validate(
        {
            **prior_transition.model_dump(
                mode="python",
                exclude={"transition_id", "to_snapshot_digest"},
            ),
            "to_snapshot_digest": incident_snapshot_digest(rebound_head),
        }
    )
    rebound_transition = IncidentTransitionRecord.from_body(rebound_body)
    rebound_comparison = IncidentBranch(
        branch_kind=comparison.branch_kind,
        snapshots=(*comparison.snapshots[:-1], rebound_head),
        transitions=(*comparison.transitions[:-1], rebound_transition),
    )
    rebound_lifecycle = IncidentLifecycle(
        actual=lifecycle.actual,
        matched_comparison=rebound_comparison,
        current_snapshot_digest=lifecycle.current_snapshot_digest,
    )

    with pytest.raises(
        LifecycleVerificationError,
        match="distinct replacement sessions",
    ):
        verify_lifecycle(rebound_lifecycle, admitted_receipts=receipts)


def test_runtime_rejects_action_descriptor_role_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = write_reference_recovery_lifecycle_bundle(tmp_path / "descriptor-drift.cab")
    runtime = FinancialRecoveryRuntime(
        generate_dataset(seed=2907, profile=DatasetProfile.DEFAULT),
        cutover_fixtures=evidence.cutover_fixtures(),
    )
    original = cast(
        Callable[[StringValue], dict[str, Any]],
        runtime_module.__dict__["action_descriptor"],
    )

    def drifted(level: StringValue) -> dict[str, Any]:
        descriptor = dict(original(level))
        descriptor["session_role"] = REPLACEMENT_SESSION_ID
        return descriptor

    monkeypatch.setattr(runtime_module, "action_descriptor", drifted)

    with pytest.raises(
        RuntimeError,
        match="contracted digest",
    ):
        runtime.execute(_selector(effective=False), trace_id="descriptor-drift")


def test_runtime_rejects_coherently_rehashed_resolution_record_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = write_reference_recovery_lifecycle_bundle(tmp_path / "resolution-tamper.cab")
    runtime = FinancialRecoveryRuntime(
        generate_dataset(seed=2907, profile=DatasetProfile.DEFAULT),
        cutover_fixtures=evidence.cutover_fixtures(),
    )
    original = runtime_module._resolve_session_role
    forged_lifecycle_digest = "sha256:" + "f" * 64

    def tampered_resolution(
        connection: sqlite3.Connection,
        *,
        trace_id: str,
        session_role: str,
    ) -> None:
        original(
            connection,
            trace_id=trace_id,
            session_role=session_role,
        )
        row = connection.execute(
            """
            SELECT resolved_session_id, resolved_session_digest,
                   lifecycle_snapshot_digest
            FROM session_role_resolutions
            WHERE trace_id = ?
            """,
            (trace_id,),
        ).fetchone()
        assert row is not None
        canonical, digest = runtime_module._session_resolution_evidence(
            session_role=session_role,
            resolved_session_id=str(row[0]),
            resolved_session_digest=str(row[1]),
            lifecycle_snapshot_digest=str(row[2]),
            verified_lifecycle_digest=forged_lifecycle_digest,
        )
        connection.execute(
            """
            UPDATE session_role_resolutions
            SET verified_lifecycle_digest = ?,
                resolution_canonical = ?,
                resolution_digest = ?
            WHERE trace_id = ?
            """,
            (forged_lifecycle_digest, canonical, digest, trace_id),
        )
        connection.commit()

    monkeypatch.setattr(
        runtime_module,
        "_resolve_session_role",
        tampered_resolution,
    )

    with pytest.raises(
        RuntimeError,
        match="differs from the lifecycle cutover",
    ):
        runtime.execute(_selector(effective=False), trace_id="resolution-tamper")
