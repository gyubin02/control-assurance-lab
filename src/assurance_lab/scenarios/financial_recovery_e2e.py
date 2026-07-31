"""Reference lifecycle producer for the financial recovery runtime.

The recovery experiment compares two independently executed lifecycle
branches.  Both branches start from the same synthetic incident and compromised
session, but each rotation creates its own physical replacement session.  The
experiment action names the stable ``active-replacement`` role; the runtime
later resolves that role to the physical session recorded by the selected
branch.

This module is the producer side of the boundary.  It constructs the complete
two-branch lifecycle, runs :func:`verify_lifecycle`, writes the cutover CAB, and
returns fixtures accepted by :class:`FinancialRecoveryRuntime`.  It never
constructs ``VerifiedLifecycle`` directly.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from assurance_lab.evidence.bundle import (
    BundleStatus,
    BundleVerification,
    EvaluationRef,
    EvaluatorRef,
    ExperimentRef,
    Sensitivity,
)
from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.evidence.writer import BundleMetadata, PayloadFile, write_bundle
from assurance_lab.lifecycle import (
    AdmittedReceiptEvidence,
    BranchKind,
    CompromisedSessionState,
    ConfidentialityStatus,
    DisclosureEntry,
    DisclosureLedger,
    IncidentBranch,
    IncidentLifecycle,
    IncidentSnapshot,
    IncidentTransitionBody,
    IncidentTransitionRecord,
    LifecycleAction,
    LifecyclePhase,
    QuarantineState,
    ReplacementSessionState,
    VerifiedLifecycle,
    incident_snapshot_digest,
    verify_lifecycle,
)
from assurance_lab.scenarios.financial_recovery_contract import (
    APPROVED_ENTITLEMENT_SET_DIGEST,
    APPROVED_SNAPSHOT_DIGEST,
    COMPARISON_REPLACEMENT_SESSION_DIGEST,
    COMPARISON_REPLACEMENT_SESSION_ID,
    OLD_SESSION_DIGEST,
    OLD_SESSION_ID,
    REPLACEMENT_SESSION_DIGEST,
    REPLACEMENT_SESSION_ID,
    STALE_ENTITLEMENT_SET_DIGEST,
    STALE_SNAPSHOT_DIGEST,
    TARGET_EFFECTIVE,
    TARGET_INEFFECTIVE,
)
from assurance_lab.scenarios.financial_recovery_runtime import (
    LifecycleCutoverFixture,
    lifecycle_cutover_bundle_payloads,
    lifecycle_proof_bundle_payloads,
)

_START = datetime(2026, 7, 29, 0, 0, tzinfo=UTC)
_INCIDENT_ID = "INC-SYNTH-RECOVERY-0001"
_SOURCE_TRACE_ID = "synthetic-prevention-source"
_SOURCE_TRIAL_KEY = "sha256:" + hashlib.sha256(b"financial-recovery-source-trial").hexdigest()
_SOURCE_BUNDLE_ID = (
    "cab:sha256:" + hashlib.sha256(b"financial-recovery-prevention-bundle").hexdigest()
)
_CASE_SPEC_DIGEST = (
    "sha256:" + hashlib.sha256(b"financial-recovery-lifecycle-case-spec").hexdigest()
)
_PHASES = (
    LifecyclePhase.SOURCE_BOUND,
    LifecyclePhase.DETECTION_CLOSED,
    LifecyclePhase.RESPONSE_PROBED,
    LifecyclePhase.RESTORE_APPLIED,
    LifecyclePhase.SESSION_ROTATED,
)
_ACTION_FOR_PHASE = {
    LifecyclePhase.DETECTION_CLOSED: LifecycleAction.CLOSE_DETECTION,
    LifecyclePhase.RESPONSE_PROBED: LifecycleAction.PROBE_RESPONSE,
    LifecyclePhase.RESTORE_APPLIED: LifecycleAction.APPLY_RESTORE,
    LifecyclePhase.SESSION_ROTATED: LifecycleAction.ROTATE_SESSION,
}


def _sha256(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _bundle_id(label: str) -> str:
    return f"cab:{_sha256(label.encode())}"


def _digest(label: str) -> str:
    return _sha256(label.encode())


def _shared_disclosures() -> tuple[DisclosureEntry, ...]:
    observed_at = _START - timedelta(minutes=10)
    return (
        DisclosureEntry(
            record_token="SYNTH-DISCLOSED-RECORD-0001",
            first_delivery_trace_id="synthetic-prior-delivery",
            first_delivery_event_digest=_digest("prior-delivery-0001"),
            first_observed_at=observed_at,
        ),
        DisclosureEntry(
            record_token="SYNTH-DISCLOSED-RECORD-0002",
            first_delivery_trace_id="synthetic-prior-delivery",
            first_delivery_event_digest=_digest("prior-delivery-0002"),
            first_observed_at=observed_at,
        ),
    )


def _receipt(entry: DisclosureEntry) -> AdmittedReceiptEvidence:
    return AdmittedReceiptEvidence(
        record_token=entry.record_token,
        delivery_trace_id=entry.first_delivery_trace_id,
        delivery_event_digest=entry.first_delivery_event_digest,
        observed_at=entry.first_observed_at,
    )


def _build_branch(
    kind: BranchKind,
    *,
    entitlement_digest: str,
    replacement_session_digest: str,
) -> IncidentBranch:
    prefix = "actual" if kind == BranchKind.ACTUAL else "comparison"
    branch_id = f"recovery-{prefix}-branch"
    ledger = DisclosureLedger(entries=_shared_disclosures())
    snapshots: list[IncidentSnapshot] = []
    transitions: list[IncidentTransitionRecord] = []

    for index, phase in enumerate(_PHASES):
        transition_event = _digest(f"{prefix}-transition-event-{index}")
        evidence_ids = (
            tuple(
                sorted(
                    {
                        _digest("shared-source-snapshot-evidence"),
                        *(entry.first_delivery_event_digest for entry in ledger.entries),
                    }
                )
            )
            if index == 0
            else (transition_event,)
        )
        after_response = phase in {
            LifecyclePhase.RESPONSE_PROBED,
            LifecyclePhase.RESTORE_APPLIED,
            LifecyclePhase.SESSION_ROTATED,
        }
        after_restore = phase in {
            LifecyclePhase.RESTORE_APPLIED,
            LifecyclePhase.SESSION_ROTATED,
        }
        after_rotation = phase == LifecyclePhase.SESSION_ROTATED
        snapshot = IncidentSnapshot(
            incident_id=_INCIDENT_ID,
            branch_id=branch_id,
            branch_kind=kind,
            ordinal=index + 1,
            phase=phase,
            source_prevention_bundle_id=_SOURCE_BUNDLE_ID,
            source_trial_key=_SOURCE_TRIAL_KEY,
            source_trace_id=_SOURCE_TRACE_ID,
            principal_id="support-017",
            entitlement_set_digest=(
                entitlement_digest if after_restore else STALE_ENTITLEMENT_SET_DIGEST
            ),
            compromised_session_digest=OLD_SESSION_DIGEST,
            compromised_session_state=(
                CompromisedSessionState.REVOKED
                if after_response
                else CompromisedSessionState.ACTIVE
            ),
            quarantine_state=(
                QuarantineState.QUARANTINED
                if phase
                in {
                    LifecyclePhase.RESPONSE_PROBED,
                    LifecyclePhase.RESTORE_APPLIED,
                }
                else QuarantineState.NORMAL
            ),
            replacement_session_digest=(replacement_session_digest if after_rotation else None),
            replacement_session_state=(
                ReplacementSessionState.ACTIVE if after_rotation else ReplacementSessionState.NONE
            ),
            replacement_entitlement_digest=(entitlement_digest if after_rotation else None),
            confidentiality_status=(ConfidentialityStatus.PRIOR_DISCLOSURE_OCCURRED),
            disclosure_ledger=ledger,
            last_alert_id=(None if phase == LifecyclePhase.SOURCE_BOUND else f"{prefix}-alert"),
            observed_at=_START + timedelta(minutes=index * 10),
            previous_snapshot_digest=(
                None if not snapshots else incident_snapshot_digest(snapshots[-1])
            ),
            evidence_ids=evidence_ids,
        )
        snapshots.append(snapshot)
        if index == 0:
            continue

        action = _ACTION_FOR_PHASE[phase]
        transition = IncidentTransitionRecord.from_body(
            IncidentTransitionBody(
                case_spec_digest=_CASE_SPEC_DIGEST,
                incident_id=_INCIDENT_ID,
                branch_id=branch_id,
                ordinal=index,
                action=action,
                from_snapshot_digest=incident_snapshot_digest(snapshots[index - 1]),
                to_snapshot_digest=incident_snapshot_digest(snapshot),
                previous_transition_digest=(
                    None if not transitions else transitions[-1].transition_id
                ),
                factor_assignment_digest=_digest(f"{prefix}-{action.value}-factor-assignment"),
                trace_id=f"{prefix}-{action.value}-trace",
                started_at=snapshots[index - 1].observed_at + timedelta(minutes=1),
                ended_at=snapshot.observed_at - timedelta(minutes=1),
                event_artifact_ids=(transition_event,),
                attestation_bundle_digest=_bundle_id(f"{prefix}-{action.value}-attestation"),
                cleanup_bundle_digest=_bundle_id(f"{prefix}-{action.value}-cleanup"),
            )
        )
        transitions.append(transition)

    return IncidentBranch(
        branch_kind=kind,
        snapshots=tuple(snapshots),
        transitions=tuple(transitions),
    )


@dataclass(frozen=True, slots=True)
class FinancialRecoveryLifecycleEvidence:
    """Verified producer output and the two runtime fixtures derived from it."""

    lifecycle: IncidentLifecycle
    admitted_receipts: tuple[AdmittedReceiptEvidence, ...]
    verified_lifecycle: VerifiedLifecycle
    bundle_verification: BundleVerification
    lifecycle_bundle_root: Path
    stale_fixture: LifecycleCutoverFixture
    approved_fixture: LifecycleCutoverFixture

    def cutover_fixtures(self) -> dict[str, LifecycleCutoverFixture]:
        return {
            TARGET_INEFFECTIVE.value: self.stale_fixture,
            TARGET_EFFECTIVE.value: self.approved_fixture,
        }


def build_reference_recovery_lifecycle() -> tuple[
    IncidentLifecycle,
    tuple[AdmittedReceiptEvidence, ...],
    VerifiedLifecycle,
]:
    """Construct and verify the independent stale/approved lifecycle branches."""

    actual = _build_branch(
        BranchKind.ACTUAL,
        entitlement_digest=STALE_ENTITLEMENT_SET_DIGEST,
        replacement_session_digest=REPLACEMENT_SESSION_DIGEST,
    )
    comparison = _build_branch(
        BranchKind.MATCHED_COMPARISON,
        entitlement_digest=APPROVED_ENTITLEMENT_SET_DIGEST,
        replacement_session_digest=COMPARISON_REPLACEMENT_SESSION_DIGEST,
    )
    lifecycle = IncidentLifecycle(
        actual=actual,
        matched_comparison=comparison,
        current_snapshot_digest=incident_snapshot_digest(actual.snapshots[-1]),
    )
    receipts = tuple(_receipt(entry) for entry in _shared_disclosures())
    verified = verify_lifecycle(lifecycle, admitted_receipts=receipts)
    return lifecycle, receipts, verified


def write_reference_recovery_lifecycle_bundle(
    destination: Path,
    *,
    created_at: datetime = _START + timedelta(hours=1),
) -> FinancialRecoveryLifecycleEvidence:
    """Verify both branches, write their cutover CAB, and return runtime fixtures."""

    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise ValueError("lifecycle bundle timestamp must be timezone-aware")
    lifecycle, receipts, verified = build_reference_recovery_lifecycle()
    actual = lifecycle.actual
    comparison = lifecycle.matched_comparison
    actual_snapshot = actual.snapshots[-1]
    comparison_snapshot = comparison.snapshots[-1]
    actual_transition_id = actual.transitions[-1].transition_id
    comparison_transition_id = comparison.transitions[-1].transition_id

    payload_bytes = lifecycle_proof_bundle_payloads(
        lifecycle=lifecycle,
        admitted_receipts=receipts,
        verified_lifecycle=verified,
    )
    payload_bytes.update(
        lifecycle_cutover_bundle_payloads(
            target_level=TARGET_INEFFECTIVE.value,
            session_rotation_transition_id=actual_transition_id,
            target_snapshot_digest=STALE_SNAPSHOT_DIGEST,
            old_session_id=OLD_SESSION_ID,
            replacement_session_id=REPLACEMENT_SESSION_ID,
            snapshot=actual_snapshot,
            verified_lifecycle=verified,
        )
    )
    payload_bytes.update(
        lifecycle_cutover_bundle_payloads(
            target_level=TARGET_EFFECTIVE.value,
            session_rotation_transition_id=comparison_transition_id,
            target_snapshot_digest=APPROVED_SNAPSHOT_DIGEST,
            old_session_id=OLD_SESSION_ID,
            replacement_session_id=COMPARISON_REPLACEMENT_SESSION_ID,
            snapshot=comparison_snapshot,
            verified_lifecycle=verified,
        )
    )
    payloads = tuple(
        PayloadFile(
            path=path,
            content=content,
            media_type="application/json",
            role=(
                "lifecycle-verifier-input"
                if path.endswith("/incident-lifecycle.json")
                else "lifecycle-admitted-receipts"
                if path.endswith("/admitted-receipts.json")
                else
                "lifecycle-verifier-output"
                if path.endswith("/verified-lifecycle.json")
                else "lifecycle-cutover-snapshot"
                if path.endswith("/cutover-snapshot.json")
                else "lifecycle-cutover-reference"
            ),
            sensitivity=Sensitivity.SYNTHETIC,
            required_for=("financial-recovery-cutover",),
        )
        for path, content in sorted(payload_bytes.items())
    )
    lifecycle_digest = _sha256(canonical_json_bytes(lifecycle.model_dump(mode="json")))
    verification = write_bundle(
        destination,
        metadata=BundleMetadata(
            created_at=created_at.astimezone(UTC),
            as_of=created_at.astimezone(UTC),
            experiment=ExperimentRef(
                id="financial-recovery-lifecycle",
                spec_version="1.0.0",
                spec_digest=lifecycle_digest,
            ),
            evaluation=EvaluationRef(
                policy_id="verified-incident-lifecycle-v1",
                policy_digest=_digest("verified-incident-lifecycle-v1"),
                evaluator=EvaluatorRef(
                    name="assurance-lab-lifecycle-verifier",
                    version="1.0.0",
                    source_revision="financial-recovery-e2e",
                    image_digest=None,
                ),
            ),
        ),
        payloads=payloads,
    )
    if verification.status != BundleStatus.INTEGRITY_VERIFIED or verification.bundle_id is None:
        raise RuntimeError("reference lifecycle CAB did not verify")

    stale_fixture = LifecycleCutoverFixture(
        lifecycle_bundle_digest=verification.bundle_id,
        lifecycle_bundle_root=destination.resolve(),
        bundle_verification=verification,
        session_rotation_transition_id=actual_transition_id,
        target_snapshot_digest=STALE_SNAPSHOT_DIGEST,
        old_session_id=OLD_SESSION_ID,
        replacement_session_id=REPLACEMENT_SESSION_ID,
        snapshot=actual_snapshot,
        verified_lifecycle=verified,
    )
    approved_fixture = LifecycleCutoverFixture(
        lifecycle_bundle_digest=verification.bundle_id,
        lifecycle_bundle_root=destination.resolve(),
        bundle_verification=verification,
        session_rotation_transition_id=comparison_transition_id,
        target_snapshot_digest=APPROVED_SNAPSHOT_DIGEST,
        old_session_id=OLD_SESSION_ID,
        replacement_session_id=COMPARISON_REPLACEMENT_SESSION_ID,
        snapshot=comparison_snapshot,
        verified_lifecycle=verified,
    )
    return FinancialRecoveryLifecycleEvidence(
        lifecycle=lifecycle,
        admitted_receipts=receipts,
        verified_lifecycle=verified,
        bundle_verification=verification,
        lifecycle_bundle_root=destination.resolve(),
        stale_fixture=stale_fixture,
        approved_fixture=approved_fixture,
    )
