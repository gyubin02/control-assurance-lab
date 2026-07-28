from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta

import pytest

from assurance_lab.lifecycle import (
    AdmittedReceiptEvidence,
    BranchKind,
    CompromisedSessionState,
    ConfidentialityStatus,
    DisclosureEntry,
    DisclosureLedger,
    FinalizationDisposition,
    IncidentBranch,
    IncidentLifecycle,
    IncidentSnapshot,
    IncidentTransitionBody,
    IncidentTransitionRecord,
    LifecycleAction,
    LifecyclePhase,
    LifecycleVerificationError,
    QuarantineState,
    ReplacementSessionState,
    incident_snapshot_digest,
    incident_transition_body_digest,
    incident_transition_digest,
    verify_lifecycle,
)

START = datetime(2026, 7, 29, 9, tzinfo=UTC)
FULL_PHASES = (
    LifecyclePhase.SOURCE_BOUND,
    LifecyclePhase.DETECTION_CLOSED,
    LifecyclePhase.RESPONSE_PROBED,
    LifecyclePhase.RESTORE_APPLIED,
    LifecyclePhase.SESSION_ROTATED,
    LifecyclePhase.RETESTED,
    LifecyclePhase.FINALIZED,
)
ACTION_FOR_PHASE = {
    LifecyclePhase.SOURCE_BOUND: LifecycleAction.BIND_SOURCE,
    LifecyclePhase.DETECTION_CLOSED: LifecycleAction.CLOSE_DETECTION,
    LifecyclePhase.RESPONSE_PROBED: LifecycleAction.PROBE_RESPONSE,
    LifecyclePhase.RESTORE_APPLIED: LifecycleAction.APPLY_RESTORE,
    LifecyclePhase.SESSION_ROTATED: LifecycleAction.ROTATE_SESSION,
    LifecyclePhase.RETESTED: LifecycleAction.RETEST,
    LifecyclePhase.FINALIZED: LifecycleAction.FINALIZE,
}


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def bundle(label: str) -> str:
    return "cab:" + digest(label)


def disclosure(
    *,
    token: str = "record-0001",
    trace_id: str = "source-trace-001",
    event_label: str = "actual-initial-delivery",
    observed_at: datetime = START,
) -> DisclosureEntry:
    return DisclosureEntry(
        record_token=token,
        first_delivery_trace_id=trace_id,
        first_delivery_event_digest=digest(event_label),
        first_observed_at=observed_at,
    )


def ledger(*entries: DisclosureEntry) -> DisclosureLedger:
    return DisclosureLedger(entries=tuple(sorted(entries, key=lambda entry: entry.record_token)))


def receipt_for(entry: DisclosureEntry) -> AdmittedReceiptEvidence:
    return AdmittedReceiptEvidence(
        record_token=entry.record_token,
        delivery_trace_id=entry.first_delivery_trace_id,
        delivery_event_digest=entry.first_delivery_event_digest,
        observed_at=entry.first_observed_at,
    )


def make_branch(
    kind: BranchKind,
    *,
    phases: Sequence[LifecyclePhase] = FULL_PHASES,
    ledgers: Mapping[int, DisclosureLedger] | None = None,
    entitlements: Mapping[int, str] | None = None,
    compromised_states: Mapping[int, CompromisedSessionState] | None = None,
    quarantine_states: Mapping[int, QuarantineState] | None = None,
    replacement_states: Mapping[int, ReplacementSessionState] | None = None,
    alert_ids: Mapping[int, str | None] | None = None,
    replacement_collision: bool = False,
    replacement_entitlement_override: str | None = None,
    first_evidence_override: str | None = None,
    transition_event_overrides: Mapping[int, str] | None = None,
    attestation_overrides: Mapping[int, str] | None = None,
    unbound_transition_at: int | None = None,
) -> IncidentBranch:
    prefix = "actual" if kind == BranchKind.ACTUAL else "comparison"
    branch_id = f"{prefix}-branch"
    ledgers = ledgers or {}
    entitlements = entitlements or {}
    compromised_states = compromised_states or {}
    quarantine_states = quarantine_states or {}
    replacement_states = replacement_states or {}
    alert_ids = alert_ids or {}
    transition_event_overrides = transition_event_overrides or {}
    attestation_overrides = attestation_overrides or {}
    snapshots: list[IncidentSnapshot] = []
    transitions: list[IncidentTransitionRecord] = []
    inherited_ledger = DisclosureLedger()
    current_entitlement = digest("source-entitlements")
    response_seen = False

    for index, phase in enumerate(phases):
        current_ledger = ledgers.get(index, inherited_ledger)
        inherited_ledger = current_ledger
        current_entitlement = entitlements.get(index, current_entitlement)
        if phase == LifecyclePhase.RESPONSE_PROBED:
            response_seen = True
        previous_digest = (
            None if not snapshots else incident_snapshot_digest(snapshots[-1])
        )
        after_rotation = phase in {
            LifecyclePhase.SESSION_ROTATED,
            LifecyclePhase.RETESTED,
            LifecyclePhase.FINALIZED,
        }
        replacement_digest = (
            digest("compromised-session")
            if replacement_collision and after_rotation
            else digest(f"{prefix}-replacement-session")
            if after_rotation
            else None
        )
        transition_event = transition_event_overrides.get(
            index,
            digest(f"{prefix}-transition-event-{index}"),
        )
        evidence = {
            (
                first_evidence_override
                if first_evidence_override is not None
                else digest("shared-source-snapshot-evidence")
            )
            if index == 0
            else digest(f"{prefix}-snapshot-evidence-{index}")
        }
        if index == 0:
            evidence.update(
                entry.first_delivery_event_digest for entry in current_ledger.entries
            )
        else:
            if index != unbound_transition_at:
                evidence.add(transition_event)
            previous_tokens = {
                entry.record_token
                for entry in snapshots[index - 1].disclosure_ledger.entries
            }
            evidence.update(
                entry.first_delivery_event_digest
                for entry in current_ledger.entries
                if entry.record_token not in previous_tokens
            )
        compromised_state = compromised_states.get(
            index,
            (
                CompromisedSessionState.REVOKED
                if response_seen
                else CompromisedSessionState.ACTIVE
            ),
        )
        snapshot = IncidentSnapshot(
            incident_id="incident-001",
            branch_id=branch_id,
            branch_kind=kind,
            ordinal=index + 1,
            phase=phase,
            source_prevention_bundle_id=bundle("prevention"),
            source_trial_key=digest("source-trial"),
            source_trace_id="source-trace-001",
            principal_id="support-017",
            entitlement_set_digest=current_entitlement,
            compromised_session_digest=digest("compromised-session"),
            compromised_session_state=compromised_state,
            quarantine_state=quarantine_states.get(
                index,
                (
                    QuarantineState.QUARANTINED
                    if phase
                    in {
                        LifecyclePhase.RESPONSE_PROBED,
                        LifecyclePhase.RESTORE_APPLIED,
                    }
                    else QuarantineState.NORMAL
                ),
            ),
            replacement_session_digest=replacement_digest,
            replacement_session_state=replacement_states.get(
                index,
                (
                    ReplacementSessionState.ACTIVE
                    if after_rotation
                    else ReplacementSessionState.NONE
                ),
            ),
            replacement_entitlement_digest=(
                replacement_entitlement_override or current_entitlement
                if after_rotation
                else None
            ),
            confidentiality_status=(
                ConfidentialityStatus.PRIOR_DISCLOSURE_OCCURRED
                if current_ledger.entries
                else ConfidentialityStatus.NONE_OBSERVED_ON_TESTED_BRANCH
            ),
            disclosure_ledger=current_ledger,
            last_alert_id=alert_ids.get(
                index,
                None
                if phase == LifecyclePhase.SOURCE_BOUND
                else f"{prefix}-alert-001",
            ),
            observed_at=START + timedelta(minutes=index * 10),
            previous_snapshot_digest=previous_digest,
            evidence_ids=tuple(sorted(evidence)),
        )
        snapshots.append(snapshot)

        if index == 0:
            continue

        previous_ledger = snapshots[index - 1].disclosure_ledger
        previous_tokens = {entry.record_token for entry in previous_ledger.entries}
        new_entries = tuple(
            entry
            for entry in current_ledger.entries
            if entry.record_token not in previous_tokens
        )
        artifacts = {transition_event}
        artifacts.update(entry.first_delivery_event_digest for entry in new_entries)
        action = ACTION_FOR_PHASE[phase]
        body = IncidentTransitionBody(
            case_spec_digest=digest("case-spec"),
            incident_id="incident-001",
            branch_id=branch_id,
            ordinal=index,
            action=action,
            from_snapshot_digest=incident_snapshot_digest(snapshots[index - 1]),
            to_snapshot_digest=incident_snapshot_digest(snapshot),
            previous_transition_digest=(
                None if not transitions else transitions[-1].transition_id
            ),
            factor_assignment_digest=digest(
                f"{prefix}-{action.value}-factor-assignment"
            ),
            trace_id=f"{prefix}-transition-trace-{index}",
            started_at=snapshots[index - 1].observed_at + timedelta(minutes=1),
            ended_at=snapshot.observed_at - timedelta(minutes=1),
            event_artifact_ids=tuple(sorted(artifacts)),
            attestation_bundle_digest=attestation_overrides.get(
                index,
                bundle(f"{prefix}-attestation-{index}"),
            ),
            cleanup_bundle_digest=bundle(f"{prefix}-cleanup-{index}"),
            finalization_disposition=(
                FinalizationDisposition.LIFECYCLE_COMPLETED
                if action == LifecycleAction.FINALIZE
                else None
            ),
            finalization_reason=(
                "All declared response and recovery phases completed."
                if action == LifecycleAction.FINALIZE
                else None
            ),
        )
        transitions.append(IncidentTransitionRecord.from_body(body))

    return IncidentBranch(
        branch_kind=kind,
        snapshots=tuple(snapshots),
        transitions=tuple(transitions),
    )


def make_lifecycle(
    *,
    actual: IncidentBranch | None = None,
    comparison: IncidentBranch | None = None,
    current_snapshot_digest: str | None = None,
) -> IncidentLifecycle:
    actual = actual or make_branch(BranchKind.ACTUAL)
    comparison = comparison or make_branch(
        BranchKind.MATCHED_COMPARISON
    )
    return IncidentLifecycle(
        actual=actual,
        matched_comparison=comparison,
        current_snapshot_digest=(
            current_snapshot_digest
            if current_snapshot_digest is not None
            else incident_snapshot_digest(actual.snapshots[-1])
        ),
    )


def test_valid_matched_lifecycle_is_content_addressed() -> None:
    lifecycle = make_lifecycle()

    verified = verify_lifecycle(lifecycle)
    serialized = lifecycle.model_dump(mode="json")

    assert verified.current_snapshot_digest == lifecycle.current_snapshot_digest
    assert verified.actual_head_digest == lifecycle.current_snapshot_digest
    assert "matched_comparison" in serialized
    assert (
        serialized["matched_comparison"]["branch_kind"]
        == "matched-comparison"
    )
    for transition in lifecycle.actual.transitions:
        assert transition.transition_id == incident_transition_digest(transition)
        body = IncidentTransitionBody.model_validate(
            transition.model_dump(mode="python", exclude={"transition_id"})
        )
        assert transition.transition_id == incident_transition_body_digest(body)


@pytest.mark.parametrize("mutation", ["removal", "rewrite"])
def test_disclosure_removal_or_rewrite_is_rejected(mutation: str) -> None:
    original = disclosure()
    rewritten = disclosure(
        trace_id="rewritten-trace",
        event_label="rewritten-delivery",
    )
    changed = DisclosureLedger() if mutation == "removal" else ledger(rewritten)
    actual = make_branch(
        BranchKind.ACTUAL,
        ledgers={
            0: ledger(original),
            1: ledger(original),
            2: changed,
        },
    )
    lifecycle = make_lifecycle(actual=actual)

    with pytest.raises(LifecycleVerificationError, match=r"removed|rewritten"):
        verify_lifecycle(
            lifecycle,
            admitted_receipts=(receipt_for(original), receipt_for(rewritten)),
        )


def test_new_disclosure_without_receipt_is_rejected() -> None:
    later = disclosure(
        trace_id="background-delivery-trace",
        event_label="later-delivery",
        observed_at=START + timedelta(minutes=5),
    )
    actual = make_branch(
        BranchKind.ACTUAL,
        ledgers={0: DisclosureLedger(), 1: ledger(later)},
    )

    with pytest.raises(LifecycleVerificationError, match="matching admitted receipt"):
        verify_lifecycle(make_lifecycle(actual=actual))


def test_matched_comparison_current_claim_is_rejected() -> None:
    actual = make_branch(BranchKind.ACTUAL)
    comparison = make_branch(BranchKind.MATCHED_COMPARISON)
    lifecycle = make_lifecycle(
        actual=actual,
        comparison=comparison,
        current_snapshot_digest=incident_snapshot_digest(
            comparison.snapshots[-1]
        ),
    )

    with pytest.raises(LifecycleVerificationError, match="matched-comparison snapshot"):
        verify_lifecycle(lifecycle)


def test_shared_source_evidence_and_disclosure_ledger_are_valid() -> None:
    shared_disclosure = disclosure(event_label="shared-source-delivery")
    actual = make_branch(
        BranchKind.ACTUAL,
        ledgers={0: ledger(shared_disclosure)},
    )
    comparison = make_branch(
        BranchKind.MATCHED_COMPARISON,
        ledgers={0: ledger(shared_disclosure)},
    )

    verified = verify_lifecycle(
        make_lifecycle(actual=actual, comparison=comparison),
        admitted_receipts=(receipt_for(shared_disclosure),),
    )

    assert verified.incident_id == "incident-001"


def test_later_branch_event_reuse_is_rejected() -> None:
    shared_event = digest("reused-post-fork-event")
    actual = make_branch(
        BranchKind.ACTUAL,
        transition_event_overrides={1: shared_event},
    )
    comparison = make_branch(
        BranchKind.MATCHED_COMPARISON,
        transition_event_overrides={1: shared_event},
    )

    with pytest.raises(LifecycleVerificationError, match="cannot reuse event"):
        verify_lifecycle(make_lifecycle(actual=actual, comparison=comparison))


def test_phase_rollback_is_rejected() -> None:
    actual = make_branch(
        BranchKind.ACTUAL,
        phases=(
            LifecyclePhase.SOURCE_BOUND,
            LifecyclePhase.DETECTION_CLOSED,
            LifecyclePhase.SOURCE_BOUND,
        ),
    )

    with pytest.raises(LifecycleVerificationError, match="phase rollback"):
        verify_lifecycle(make_lifecycle(actual=actual))


def test_replacement_collision_is_rejected() -> None:
    actual = make_branch(
        BranchKind.ACTUAL,
        replacement_collision=True,
    )

    with pytest.raises(LifecycleVerificationError, match="must be distinct"):
        verify_lifecycle(make_lifecycle(actual=actual))


def test_entitlement_drift_outside_restore_is_rejected() -> None:
    actual = make_branch(
        BranchKind.ACTUAL,
        entitlements={1: digest("unexplained-entitlement-drift")},
    )

    with pytest.raises(LifecycleVerificationError, match="only during apply_restore"):
        verify_lifecycle(make_lifecycle(actual=actual))


def test_restore_can_change_entitlement_and_rotation_preserves_it() -> None:
    restored = digest("restored-case-scoped-entitlements")
    actual = make_branch(
        BranchKind.ACTUAL,
        entitlements={3: restored},
    )

    verified = verify_lifecycle(make_lifecycle(actual=actual))

    assert verified.actual_head_digest == incident_snapshot_digest(actual.snapshots[-1])
    assert actual.snapshots[-1].replacement_entitlement_digest == restored


def test_replacement_entitlement_mismatch_is_rejected() -> None:
    actual = make_branch(
        BranchKind.ACTUAL,
        replacement_entitlement_override=digest("stale-entitlements"),
    )

    with pytest.raises(LifecycleVerificationError, match="replacement entitlement"):
        verify_lifecycle(make_lifecycle(actual=actual))


def test_compromised_session_reactivation_is_rejected() -> None:
    actual = make_branch(
        BranchKind.ACTUAL,
        compromised_states={3: CompromisedSessionState.ACTIVE},
    )

    with pytest.raises(LifecycleVerificationError, match="active to revoked"):
        verify_lifecycle(make_lifecycle(actual=actual))


@pytest.mark.parametrize(
    ("compromised_state", "quarantine_state", "alert_id", "message"),
    (
        (
            CompromisedSessionState.UNKNOWN,
            QuarantineState.NORMAL,
            None,
            "compromised session active",
        ),
        (
            CompromisedSessionState.ACTIVE,
            QuarantineState.QUARANTINED,
            None,
            "before principal quarantine",
        ),
        (
            CompromisedSessionState.ACTIVE,
            QuarantineState.NORMAL,
            "alert-before-source",
            "cannot claim a later detection alert",
        ),
    ),
)
def test_source_bound_state_cannot_start_after_a_later_control(
    compromised_state: CompromisedSessionState,
    quarantine_state: QuarantineState,
    alert_id: str | None,
    message: str,
) -> None:
    actual = make_branch(
        BranchKind.ACTUAL,
        compromised_states={0: compromised_state},
        quarantine_states={0: quarantine_state},
        alert_ids={0: alert_id},
    )

    with pytest.raises(LifecycleVerificationError, match=message):
        verify_lifecycle(make_lifecycle(actual=actual))


@pytest.mark.parametrize(
    ("alert_ids", "message"),
    (
        ({1: "detected-alert", 2: None}, "cannot later change or disappear"),
        (
            {1: "detected-alert", 2: "different-alert"},
            "cannot later change or disappear",
        ),
        ({1: None, 2: "late-alert"}, "only be established during close_detection"),
    ),
)
def test_alert_identity_cannot_drift_after_detection(
    alert_ids: Mapping[int, str | None],
    message: str,
) -> None:
    actual = make_branch(BranchKind.ACTUAL, alert_ids=alert_ids)

    with pytest.raises(LifecycleVerificationError, match=message):
        verify_lifecycle(make_lifecycle(actual=actual))


@pytest.mark.parametrize(
    ("replacement_state", "quarantine_state", "message"),
    (
        (
            ReplacementSessionState.REVOKED,
            QuarantineState.NORMAL,
            "active replacement session",
        ),
        (
            ReplacementSessionState.ACTIVE,
            QuarantineState.QUARANTINED,
            "quarantine released",
        ),
    ),
)
def test_completed_rotation_requires_usable_replacement_access(
    replacement_state: ReplacementSessionState,
    quarantine_state: QuarantineState,
    message: str,
) -> None:
    actual = make_branch(
        BranchKind.ACTUAL,
        replacement_states={4: replacement_state},
        quarantine_states={4: quarantine_state},
    )

    with pytest.raises(LifecycleVerificationError, match=message):
        verify_lifecycle(make_lifecycle(actual=actual))


@pytest.mark.parametrize("reuse_across_branches", [False, True])
def test_transition_bundle_reuse_is_rejected(reuse_across_branches: bool) -> None:
    if reuse_across_branches:
        actual = make_branch(BranchKind.ACTUAL)
        comparison = make_branch(
            BranchKind.MATCHED_COMPARISON,
            attestation_overrides={1: bundle("actual-attestation-1")},
        )
        lifecycle = make_lifecycle(actual=actual, comparison=comparison)
        match = "cannot reuse event"
    else:
        actual = make_branch(
            BranchKind.ACTUAL,
            attestation_overrides={2: bundle("actual-attestation-1")},
        )
        lifecycle = make_lifecycle(actual=actual)
        match = "bundles cannot be reused"

    with pytest.raises(LifecycleVerificationError, match=match):
        verify_lifecycle(lifecycle)


def test_unbound_transition_event_is_rejected() -> None:
    actual = make_branch(
        BranchKind.ACTUAL,
        unbound_transition_at=1,
    )

    with pytest.raises(LifecycleVerificationError, match="bound into the target"):
        verify_lifecycle(make_lifecycle(actual=actual))


def test_actual_no_alert_branch_can_finalize_after_detection() -> None:
    source = make_branch(
        BranchKind.ACTUAL,
        phases=(
            LifecyclePhase.SOURCE_BOUND,
            LifecyclePhase.DETECTION_CLOSED,
        ),
    )
    detection = source.snapshots[-1].model_copy(update={"last_alert_id": None})
    source_snapshot = source.snapshots[0]
    detection = detection.model_copy(
        update={"previous_snapshot_digest": incident_snapshot_digest(source_snapshot)}
    )
    finalization_event = digest("actual-finalization-event")
    final = detection.model_copy(
        update={
            "ordinal": 3,
            "phase": LifecyclePhase.FINALIZED,
            "observed_at": detection.observed_at + timedelta(minutes=10),
            "previous_snapshot_digest": incident_snapshot_digest(detection),
            "evidence_ids": tuple(
                sorted({*detection.evidence_ids, finalization_event})
            ),
        }
    )
    close_body = IncidentTransitionBody(
        **source.transitions[0].model_dump(
            mode="python",
            exclude={"transition_id", "to_snapshot_digest"},
        ),
        to_snapshot_digest=incident_snapshot_digest(detection),
    )
    close = IncidentTransitionRecord.from_body(close_body)
    finalize_body = IncidentTransitionBody(
        case_spec_digest=digest("case-spec"),
        incident_id="incident-001",
        branch_id="actual-branch",
        ordinal=2,
        action=LifecycleAction.FINALIZE,
        from_snapshot_digest=incident_snapshot_digest(detection),
        to_snapshot_digest=incident_snapshot_digest(final),
        previous_transition_digest=close.transition_id,
        factor_assignment_digest=digest("actual-factor-assignment"),
        trace_id="actual-no-alert-finalize",
        started_at=detection.observed_at + timedelta(minutes=1),
        ended_at=final.observed_at - timedelta(minutes=1),
        event_artifact_ids=(finalization_event,),
        attestation_bundle_digest=bundle("actual-finalization-attestation"),
        cleanup_bundle_digest=bundle("actual-finalization-cleanup"),
        finalization_disposition=FinalizationDisposition.NO_RELATED_ALERT,
        finalization_reason="No alert matched the declared incident correlation rule.",
    )
    actual = IncidentBranch(
        branch_kind=BranchKind.ACTUAL,
        snapshots=(source_snapshot, detection, final),
        transitions=(close, IncidentTransitionRecord.from_body(finalize_body)),
    )

    verified = verify_lifecycle(make_lifecycle(actual=actual))

    assert verified.actual_head_digest == incident_snapshot_digest(final)
