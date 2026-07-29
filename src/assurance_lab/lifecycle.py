"""Integrity rules for an incident's detective, response, and recovery record.

The preventive experiment establishes where an incident starts.  This module
does not run the response workflow and it does not infer attacker possession.
It verifies a pair of already-recorded branches:

* the branch that actually happened; and
* a separately executed matched comparison used as a counterfactual proxy.

The comparison can test whether a declared factor tracks an outcome under a
matched setup.  It is still an observed run, not literal counterfactual
causality, and it can never be promoted into evidence of the current state.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    ConfigDict,
    Field,
    PositiveInt,
    model_validator,
)
from pydantic import BaseModel as PydanticBaseModel

from assurance_lab.contract import DIGEST_PATTERN
from assurance_lab.evidence.canonical import canonical_json_bytes

Digest = Annotated[str, Field(pattern=DIGEST_PATTERN)]
BundleId = Annotated[str, Field(pattern=r"^cab:sha256:[a-f0-9]{64}$")]
NonEmptyText = Annotated[str, Field(min_length=1, max_length=512)]


class BaseModel(PydanticBaseModel):
    """Strict immutable lifecycle value object."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        revalidate_instances="always",
    )


class LifecyclePhase(StrEnum):
    SOURCE_BOUND = "source_bound"
    DETECTION_CLOSED = "detection_closed"
    RESPONSE_PROBED = "response_probed"
    RESTORE_APPLIED = "restore_applied"
    SESSION_ROTATED = "session_rotated"
    RETESTED = "retested"
    FINALIZED = "finalized"


_PHASE_RANK = {phase: ordinal for ordinal, phase in enumerate(LifecyclePhase)}


class BranchKind(StrEnum):
    ACTUAL = "actual"
    MATCHED_COMPARISON = "matched-comparison"


class CompromisedSessionState(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


class QuarantineState(StrEnum):
    NORMAL = "normal"
    QUARANTINED = "quarantined"
    UNKNOWN = "unknown"


class ReplacementSessionState(StrEnum):
    NONE = "none"
    ACTIVE = "active"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


class ConfidentialityStatus(StrEnum):
    """What the tested branch establishes, without claiming attacker possession."""

    NONE_OBSERVED_ON_TESTED_BRANCH = "none_observed_on_tested_branch"
    PRIOR_DISCLOSURE_OCCURRED = "prior_disclosure_occurred"
    UNKNOWN = "unknown"


class LifecycleAction(StrEnum):
    BIND_SOURCE = "bind_source"
    CLOSE_DETECTION = "close_detection"
    PROBE_RESPONSE = "probe_response"
    APPLY_RESTORE = "apply_restore"
    ROTATE_SESSION = "rotate_session"
    RETEST = "retest"
    FINALIZE = "finalize"


_ACTION_DESTINATION = {
    LifecycleAction.BIND_SOURCE: LifecyclePhase.SOURCE_BOUND,
    LifecycleAction.CLOSE_DETECTION: LifecyclePhase.DETECTION_CLOSED,
    LifecycleAction.PROBE_RESPONSE: LifecyclePhase.RESPONSE_PROBED,
    LifecycleAction.APPLY_RESTORE: LifecyclePhase.RESTORE_APPLIED,
    LifecycleAction.ROTATE_SESSION: LifecyclePhase.SESSION_ROTATED,
    LifecycleAction.RETEST: LifecyclePhase.RETESTED,
    LifecycleAction.FINALIZE: LifecyclePhase.FINALIZED,
}

_ACTION_ORIGIN = {
    LifecycleAction.BIND_SOURCE: LifecyclePhase.SOURCE_BOUND,
    LifecycleAction.CLOSE_DETECTION: LifecyclePhase.SOURCE_BOUND,
    LifecycleAction.PROBE_RESPONSE: LifecyclePhase.DETECTION_CLOSED,
    LifecycleAction.APPLY_RESTORE: LifecyclePhase.RESPONSE_PROBED,
    LifecycleAction.ROTATE_SESSION: LifecyclePhase.RESTORE_APPLIED,
    LifecycleAction.RETEST: LifecyclePhase.SESSION_ROTATED,
    LifecycleAction.FINALIZE: LifecyclePhase.RETESTED,
}


class FinalizationDisposition(StrEnum):
    LIFECYCLE_COMPLETED = "lifecycle_completed"
    NO_RELATED_ALERT = "no_related_alert"


class DisclosureEntry(BaseModel):
    """The first evidenced delivery of one opaque synthetic record token."""

    record_token: NonEmptyText
    first_delivery_trace_id: NonEmptyText
    first_delivery_event_digest: Digest
    first_observed_at: AwareDatetime


class DisclosureLedger(BaseModel):
    """A canonical set of first-delivery facts, never a list of presumed viewers."""

    data_class: Literal["customer_confidential"] = "customer_confidential"
    entries: tuple[DisclosureEntry, ...] = ()

    @model_validator(mode="after")
    def sorted_unique_entries(self) -> DisclosureLedger:
        tokens = tuple(entry.record_token for entry in self.entries)
        if len(tokens) != len(set(tokens)):
            raise ValueError("disclosure ledger record tokens must be unique")
        if tokens != tuple(sorted(tokens)):
            raise ValueError("disclosure ledger entries must be sorted by record token")
        return self


class IncidentSnapshot(BaseModel):
    schema_name: Literal["assurance-lab.incident-snapshot/v1"] = (
        "assurance-lab.incident-snapshot/v1"
    )
    incident_id: NonEmptyText
    branch_id: NonEmptyText
    branch_kind: BranchKind
    ordinal: PositiveInt
    phase: LifecyclePhase
    source_prevention_bundle_id: BundleId
    source_trial_key: Digest
    source_trace_id: NonEmptyText
    principal_id: Literal["support-017"]
    entitlement_set_digest: Digest
    compromised_session_digest: Digest
    compromised_session_state: CompromisedSessionState
    quarantine_state: QuarantineState
    replacement_session_digest: Digest | None = None
    replacement_session_state: ReplacementSessionState = ReplacementSessionState.NONE
    replacement_entitlement_digest: Digest | None = None
    confidentiality_status: ConfidentialityStatus
    disclosure_ledger: DisclosureLedger
    last_alert_id: NonEmptyText | None = None
    observed_at: AwareDatetime
    previous_snapshot_digest: Digest | None = None
    evidence_ids: tuple[Digest, ...] = Field(default=(), max_length=256)

    @model_validator(mode="after")
    def internally_coherent(self) -> IncidentSnapshot:
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("snapshot evidence ids must be unique")
        if self.evidence_ids != tuple(sorted(self.evidence_ids)):
            raise ValueError("snapshot evidence ids must be sorted")

        has_disclosure = bool(self.disclosure_ledger.entries)
        if has_disclosure and (
            self.confidentiality_status != ConfidentialityStatus.PRIOR_DISCLOSURE_OCCURRED
        ):
            raise ValueError("a non-empty disclosure ledger requires prior_disclosure_occurred")
        if not has_disclosure and (
            self.confidentiality_status == ConfidentialityStatus.PRIOR_DISCLOSURE_OCCURRED
        ):
            raise ValueError("prior_disclosure_occurred requires a disclosure ledger entry")

        replacement = self.replacement_session_digest
        replacement_state = self.replacement_session_state
        replacement_entitlement = self.replacement_entitlement_digest
        if replacement_state == ReplacementSessionState.NONE:
            if replacement is not None or replacement_entitlement is not None:
                raise ValueError("replacement state none cannot carry replacement material")
        elif replacement_state in {
            ReplacementSessionState.ACTIVE,
            ReplacementSessionState.REVOKED,
        }:
            if replacement is None or replacement_entitlement is None:
                raise ValueError(
                    "an active or revoked replacement requires session and entitlement digests"
                )
        elif replacement is None and replacement_entitlement is not None:
            raise ValueError("replacement entitlement cannot exist without a replacement session")
        return self


class IncidentTransitionBody(BaseModel):
    """Canonical body from which ``transition_id`` is derived."""

    case_spec_digest: Digest
    incident_id: NonEmptyText
    branch_id: NonEmptyText
    ordinal: PositiveInt
    action: LifecycleAction
    from_snapshot_digest: Digest
    to_snapshot_digest: Digest
    previous_transition_digest: Digest | None = None
    factor_assignment_digest: Digest
    trace_id: NonEmptyText
    started_at: AwareDatetime
    ended_at: AwareDatetime
    event_artifact_ids: tuple[Digest, ...] = Field(min_length=1, max_length=256)
    attestation_bundle_digest: BundleId
    cleanup_bundle_digest: BundleId
    finalization_disposition: FinalizationDisposition | None = None
    finalization_reason: NonEmptyText | None = None

    @model_validator(mode="after")
    def internally_coherent(self) -> IncidentTransitionBody:
        if self.ended_at <= self.started_at:
            raise ValueError("lifecycle transition must have positive duration")
        if len(self.event_artifact_ids) != len(set(self.event_artifact_ids)):
            raise ValueError("transition event artifact ids must be unique")
        if self.event_artifact_ids != tuple(sorted(self.event_artifact_ids)):
            raise ValueError("transition event artifact ids must be sorted")

        is_final = self.action == LifecycleAction.FINALIZE
        if is_final and (
            self.finalization_disposition is None or self.finalization_reason is None
        ):
            raise ValueError("finalize requires an explicit disposition and reason")
        if not is_final and (
            self.finalization_disposition is not None or self.finalization_reason is not None
        ):
            raise ValueError("only finalize can carry a finalization disposition")
        return self


class IncidentTransitionRecord(IncidentTransitionBody):
    transition_id: Digest

    @classmethod
    def from_body(cls, body: IncidentTransitionBody) -> IncidentTransitionRecord:
        return cls(
            **body.model_dump(mode="python"),
            transition_id=incident_transition_body_digest(body),
        )

    @model_validator(mode="after")
    def content_addressed(self) -> IncidentTransitionRecord:
        if self.transition_id != incident_transition_digest(self):
            raise ValueError("transition_id does not match the canonical transition body")
        return self


class IncidentBranch(BaseModel):
    branch_kind: BranchKind
    snapshots: tuple[IncidentSnapshot, ...] = Field(min_length=1)
    transitions: tuple[IncidentTransitionRecord, ...] = ()


class IncidentLifecycle(BaseModel):
    actual: IncidentBranch
    matched_comparison: IncidentBranch
    current_snapshot_digest: Digest


class AdmittedReceiptEvidence(BaseModel):
    """An independently admitted delivery receipt, matched on all four fields."""

    record_token: NonEmptyText
    delivery_trace_id: NonEmptyText
    delivery_event_digest: Digest
    observed_at: AwareDatetime


class VerifiedLifecycle(BaseModel):
    incident_id: NonEmptyText
    current_snapshot_digest: Digest
    actual_head_digest: Digest
    matched_comparison_head_digest: Digest
    actual_transition_ids: tuple[Digest, ...]
    matched_comparison_transition_ids: tuple[Digest, ...]


class LifecycleVerificationError(ValueError):
    """Raised when lifecycle evidence does not form the declared two-branch chain."""


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def incident_snapshot_digest(snapshot: IncidentSnapshot) -> str:
    """Return the content address of the complete canonical snapshot."""

    return _sha256(canonical_json_bytes(snapshot.model_dump(mode="json")))


def incident_transition_body_digest(body: IncidentTransitionBody) -> str:
    """Return the content address of a transition body."""

    return _sha256(canonical_json_bytes(body.model_dump(mode="json")))


def incident_transition_digest(transition: IncidentTransitionRecord) -> str:
    """Recompute a transition id, deliberately excluding ``transition_id``."""

    body = IncidentTransitionBody.model_validate(
        transition.model_dump(mode="python", exclude={"transition_id"})
    )
    return incident_transition_body_digest(body)


def _receipt_key(
    *,
    record_token: str,
    trace_id: str,
    event_digest: str,
    observed_at: AwareDatetime,
) -> tuple[str, str, str, AwareDatetime]:
    return (record_token, trace_id, event_digest, observed_at)


def _entry_key(
    entry: DisclosureEntry,
) -> tuple[str, str, str, AwareDatetime]:
    return _receipt_key(
        record_token=entry.record_token,
        trace_id=entry.first_delivery_trace_id,
        event_digest=entry.first_delivery_event_digest,
        observed_at=entry.first_observed_at,
    )


def _branch_identity(snapshot: IncidentSnapshot) -> tuple[str, str, str, str, str, str]:
    return (
        snapshot.incident_id,
        snapshot.source_prevention_bundle_id,
        snapshot.source_trial_key,
        snapshot.source_trace_id,
        snapshot.principal_id,
        snapshot.compromised_session_digest,
    )


def _branch_event_keys(branch: IncidentBranch) -> set[tuple[str, str]]:
    """Return post-fork evidence identities; the source fixture is intentionally shared."""

    events: set[tuple[str, str]] = set()
    source = branch.snapshots[0]
    source_evidence = set(source.evidence_ids)
    source_disclosures = {
        entry.record_token: entry for entry in source.disclosure_ledger.entries
    }
    for snapshot in branch.snapshots[1:]:
        events.update(
            ("artifact", value)
            for value in snapshot.evidence_ids
            if value not in source_evidence
        )
        if snapshot.last_alert_id is not None:
            events.add(("alert", snapshot.last_alert_id))
        events.update(
            ("delivery", entry.first_delivery_event_digest)
            for entry in snapshot.disclosure_ledger.entries
            if source_disclosures.get(entry.record_token) != entry
        )
    for transition in branch.transitions:
        events.add(("trace", transition.trace_id))
        events.update(("artifact", value) for value in transition.event_artifact_ids)
        events.add(("bundle", transition.attestation_bundle_digest))
        events.add(("bundle", transition.cleanup_bundle_digest))
    return events


def _verify_replacement(snapshot: IncidentSnapshot) -> None:
    replacement = snapshot.replacement_session_digest
    if replacement is not None and replacement == snapshot.compromised_session_digest:
        raise LifecycleVerificationError(
            "replacement session must be distinct from the compromised session"
        )


def _verify_disclosure_delta(
    *,
    prior: DisclosureLedger | None,
    current: DisclosureLedger,
    receipt_keys: frozenset[tuple[str, str, str, AwareDatetime]],
    evidence_ids: tuple[str, ...],
    observed_after: AwareDatetime | None,
    observed_before: AwareDatetime,
) -> None:
    previous = {} if prior is None else {entry.record_token: entry for entry in prior.entries}
    present = {entry.record_token: entry for entry in current.entries}

    missing = previous.keys() - present.keys()
    if missing:
        raise LifecycleVerificationError("disclosure ledger entries cannot be removed")
    for token, entry in previous.items():
        if present[token] != entry:
            raise LifecycleVerificationError("disclosure ledger entries cannot be rewritten")

    for token in present.keys() - previous.keys():
        entry = present[token]
        if _entry_key(entry) not in receipt_keys:
            raise LifecycleVerificationError(
                "new disclosure requires matching admitted receipt evidence"
            )
        if entry.first_delivery_event_digest not in evidence_ids:
            raise LifecycleVerificationError(
                "new disclosure receipt must be referenced by the admitting evidence"
            )
        if observed_after is not None and entry.first_observed_at < observed_after:
            raise LifecycleVerificationError(
                "new disclosure receipt predates the transition that admits it"
            )
        if entry.first_observed_at > observed_before:
            raise LifecycleVerificationError(
                "new disclosure receipt postdates the snapshot that records it"
            )


def _verify_phase_transition(
    *,
    branch_kind: BranchKind,
    source: IncidentSnapshot,
    target: IncidentSnapshot,
    transition: IncidentTransitionRecord,
) -> None:
    if _PHASE_RANK[target.phase] < _PHASE_RANK[source.phase]:
        raise LifecycleVerificationError("lifecycle phase rollback is not allowed")
    if target.phase != _ACTION_DESTINATION[transition.action]:
        raise LifecycleVerificationError("transition action does not match destination phase")

    expected_origin = _ACTION_ORIGIN[transition.action]
    if source.phase == expected_origin:
        if (
            transition.action == LifecycleAction.FINALIZE
            and transition.finalization_disposition
            != FinalizationDisposition.LIFECYCLE_COMPLETED
        ):
            raise LifecycleVerificationError(
                "normal finalization requires lifecycle_completed disposition"
            )
        return

    no_alert_finalization = (
        branch_kind == BranchKind.ACTUAL
        and source.phase == LifecyclePhase.DETECTION_CLOSED
        and target.phase == LifecyclePhase.FINALIZED
        and transition.action == LifecycleAction.FINALIZE
        and transition.finalization_disposition
        == FinalizationDisposition.NO_RELATED_ALERT
        and source.last_alert_id is None
        and target.last_alert_id is None
    )
    if not no_alert_finalization:
        raise LifecycleVerificationError("transition skipped a required lifecycle phase")


def _verify_branch(
    branch: IncidentBranch,
    receipt_keys: frozenset[tuple[str, str, str, AwareDatetime]],
) -> None:
    snapshots = branch.snapshots
    transitions = branch.transitions
    first = snapshots[0]

    if branch.branch_kind != first.branch_kind:
        raise LifecycleVerificationError("branch kind does not match its snapshots")
    if first.ordinal != 1 or first.phase != LifecyclePhase.SOURCE_BOUND:
        raise LifecycleVerificationError("a lifecycle branch must begin at source_bound ordinal 1")
    if first.previous_snapshot_digest is not None:
        raise LifecycleVerificationError("the source-bound snapshot cannot have a predecessor")
    if first.compromised_session_state != CompromisedSessionState.ACTIVE:
        raise LifecycleVerificationError(
            "the source-bound snapshot must begin with the compromised session active"
        )
    if first.quarantine_state != QuarantineState.NORMAL:
        raise LifecycleVerificationError(
            "the source-bound snapshot must begin before principal quarantine"
        )
    if first.last_alert_id is not None:
        raise LifecycleVerificationError(
            "the source-bound snapshot cannot claim a later detection alert"
        )
    if len(transitions) != len(snapshots) - 1:
        raise LifecycleVerificationError("each adjacent snapshot pair requires one transition")

    identity = _branch_identity(first)
    branch_id = first.branch_id
    previous_replacement: str | None = None
    previous_replacement_state = ReplacementSessionState.NONE

    _verify_replacement(first)
    _verify_disclosure_delta(
        prior=None,
        current=first.disclosure_ledger,
        receipt_keys=receipt_keys,
        evidence_ids=first.evidence_ids,
        observed_after=None,
        observed_before=first.observed_at,
    )

    for index, snapshot in enumerate(snapshots):
        expected_ordinal = index + 1
        if snapshot.ordinal != expected_ordinal:
            raise LifecycleVerificationError("snapshot ordinals must be contiguous from one")
        if snapshot.branch_kind != branch.branch_kind or snapshot.branch_id != branch_id:
            raise LifecycleVerificationError("snapshot crossed its declared branch boundary")
        if _branch_identity(snapshot) != identity:
            raise LifecycleVerificationError(
                "incident, source, principal, or compromised session changed within a branch"
            )
        _verify_replacement(snapshot)

        replacement = snapshot.replacement_session_digest
        if previous_replacement is not None and replacement != previous_replacement:
            raise LifecycleVerificationError(
                "replacement session identity cannot change after rotation"
            )
        if replacement is not None:
            previous_replacement = replacement
        if (
            previous_replacement_state == ReplacementSessionState.REVOKED
            and snapshot.replacement_session_state != ReplacementSessionState.REVOKED
        ):
            raise LifecycleVerificationError("a revoked replacement session cannot reactivate")
        if (
            previous_replacement_state
            in {ReplacementSessionState.ACTIVE, ReplacementSessionState.REVOKED}
            and snapshot.replacement_session_state == ReplacementSessionState.UNKNOWN
        ):
            raise LifecycleVerificationError(
                "a known replacement session state cannot regress to unknown"
            )
        previous_replacement_state = snapshot.replacement_session_state

        is_no_alert_final = (
            index > 0
            and snapshot.phase == LifecyclePhase.FINALIZED
            and transitions[index - 1].action == LifecycleAction.FINALIZE
            and transitions[index - 1].finalization_disposition
            == FinalizationDisposition.NO_RELATED_ALERT
        )
        if (
            _PHASE_RANK[snapshot.phase] < _PHASE_RANK[LifecyclePhase.SESSION_ROTATED]
            and snapshot.replacement_session_digest is not None
        ):
            raise LifecycleVerificationError(
                "a replacement session cannot exist before rotate_session"
            )
        if (
            _PHASE_RANK[snapshot.phase] >= _PHASE_RANK[LifecyclePhase.SESSION_ROTATED]
            and not is_no_alert_final
        ):
            if snapshot.compromised_session_state != CompromisedSessionState.REVOKED:
                raise LifecycleVerificationError(
                    "session_rotated and later snapshots require the compromised session revoked"
                )
            if snapshot.replacement_session_digest is None:
                raise LifecycleVerificationError(
                    "session_rotated and later snapshots require a replacement session"
                )
            if snapshot.replacement_session_state != ReplacementSessionState.ACTIVE:
                raise LifecycleVerificationError(
                    "session_rotated and later snapshots require an active replacement session"
                )
            if snapshot.replacement_entitlement_digest != snapshot.entitlement_set_digest:
                raise LifecycleVerificationError(
                    "replacement entitlement must equal the restored current entitlement"
                )
            if snapshot.quarantine_state != QuarantineState.NORMAL:
                raise LifecycleVerificationError(
                    "session_rotated and later snapshots require principal quarantine released"
                )

        if index == 0:
            continue

        previous = snapshots[index - 1]
        transition = transitions[index - 1]
        previous_digest = incident_snapshot_digest(previous)
        current_digest = incident_snapshot_digest(snapshot)

        if snapshot.previous_snapshot_digest != previous_digest:
            raise LifecycleVerificationError("snapshot predecessor digest is broken")
        if snapshot.observed_at < previous.observed_at:
            raise LifecycleVerificationError("snapshot observation times must be monotone")

        if transition.ordinal != index:
            raise LifecycleVerificationError("transition ordinals must be contiguous from one")
        if transition.incident_id != first.incident_id or transition.branch_id != branch_id:
            raise LifecycleVerificationError("transition crossed its incident or branch boundary")
        if transition.from_snapshot_digest != previous_digest:
            raise LifecycleVerificationError("transition input is not the preceding snapshot")
        if transition.to_snapshot_digest != current_digest:
            raise LifecycleVerificationError("transition output is not the following snapshot")
        if transition.started_at < previous.observed_at:
            raise LifecycleVerificationError("transition starts before its input snapshot")
        if transition.ended_at > snapshot.observed_at:
            raise LifecycleVerificationError("transition ends after its output snapshot")
        if not set(transition.event_artifact_ids).issubset(snapshot.evidence_ids):
            raise LifecycleVerificationError(
                "transition event artifacts must be bound into the target snapshot"
            )
        expected_previous_transition = (
            None if index == 1 else transitions[index - 2].transition_id
        )
        if transition.previous_transition_digest != expected_previous_transition:
            raise LifecycleVerificationError("transition predecessor digest is broken")
        if transition.transition_id != incident_transition_digest(transition):
            raise LifecycleVerificationError("transition content address is invalid")

        _verify_phase_transition(
            branch_kind=branch.branch_kind,
            source=previous,
            target=snapshot,
            transition=transition,
        )
        if (
            snapshot.entitlement_set_digest != previous.entitlement_set_digest
            and transition.action != LifecycleAction.APPLY_RESTORE
        ):
            raise LifecycleVerificationError(
                "entitlement set can change only during apply_restore"
            )
        if snapshot.last_alert_id != previous.last_alert_id:
            alert_established_by_detection = (
                transition.action == LifecycleAction.CLOSE_DETECTION
                and previous.last_alert_id is None
                and snapshot.last_alert_id is not None
            )
            if not alert_established_by_detection:
                raise LifecycleVerificationError(
                    "alert identity can only be established during close_detection "
                    "and cannot later change or disappear"
                )
        if snapshot.compromised_session_state != previous.compromised_session_state:
            valid_revocation = (
                transition.action == LifecycleAction.PROBE_RESPONSE
                and previous.compromised_session_state
                == CompromisedSessionState.ACTIVE
                and snapshot.compromised_session_state
                == CompromisedSessionState.REVOKED
            )
            if not valid_revocation:
                raise LifecycleVerificationError(
                    "compromised session state can only change active to revoked "
                    "during probe_response"
                )
        _verify_disclosure_delta(
            prior=previous.disclosure_ledger,
            current=snapshot.disclosure_ledger,
            receipt_keys=receipt_keys,
            evidence_ids=transition.event_artifact_ids,
            observed_after=transition.started_at,
            observed_before=transition.ended_at,
        )

        if transition.action == LifecycleAction.ROTATE_SESSION:
            if snapshot.replacement_session_state != ReplacementSessionState.ACTIVE:
                raise LifecycleVerificationError(
                    "rotate_session must produce an active replacement session"
                )
            if snapshot.compromised_session_state != CompromisedSessionState.REVOKED:
                raise LifecycleVerificationError(
                    "rotate_session must revoke the compromised session"
                )

    case_spec_digests = {transition.case_spec_digest for transition in transitions}
    trace_ids = [transition.trace_id for transition in transitions]
    event_artifact_ids = [
        artifact_id
        for transition in transitions
        for artifact_id in transition.event_artifact_ids
    ]
    transition_bundle_ids = [
        bundle_id
        for transition in transitions
        for bundle_id in (
            transition.attestation_bundle_digest,
            transition.cleanup_bundle_digest,
        )
    ]
    if len(case_spec_digests) > 1:
        raise LifecycleVerificationError("case specification changed within a branch")
    if len(trace_ids) != len(set(trace_ids)):
        raise LifecycleVerificationError("transition traces cannot be reused within a branch")
    if len(event_artifact_ids) != len(set(event_artifact_ids)):
        raise LifecycleVerificationError(
            "transition event artifacts cannot be reused within a branch"
        )
    if len(transition_bundle_ids) != len(set(transition_bundle_ids)):
        raise LifecycleVerificationError(
            "attestation and cleanup bundles cannot be reused within a branch"
        )
    if first.source_trace_id in trace_ids:
        raise LifecycleVerificationError(
            "post-fork transitions cannot reuse the source trace"
        )
    if first.source_prevention_bundle_id in transition_bundle_ids:
        raise LifecycleVerificationError(
            "post-fork transitions cannot reuse the source prevention bundle"
        )

    source_event_artifacts = set(first.evidence_ids)
    source_event_artifacts.update(
        entry.first_delivery_event_digest for entry in first.disclosure_ledger.entries
    )
    if source_event_artifacts & set(event_artifact_ids):
        raise LifecycleVerificationError(
            "post-fork transitions cannot reuse source-fixture event evidence"
        )


def verify_lifecycle(
    lifecycle: IncidentLifecycle,
    *,
    admitted_receipts: tuple[AdmittedReceiptEvidence, ...] = (),
) -> VerifiedLifecycle:
    """Verify two independently evidenced branches and their current-state claim."""

    actual = lifecycle.actual
    comparison = lifecycle.matched_comparison
    if actual.branch_kind != BranchKind.ACTUAL:
        raise LifecycleVerificationError("actual slot requires an actual branch")
    if comparison.branch_kind != BranchKind.MATCHED_COMPARISON:
        raise LifecycleVerificationError(
            "matched_comparison slot requires a matched-comparison branch"
        )

    receipt_values = tuple(
        _receipt_key(
            record_token=receipt.record_token,
            trace_id=receipt.delivery_trace_id,
            event_digest=receipt.delivery_event_digest,
            observed_at=receipt.observed_at,
        )
        for receipt in admitted_receipts
    )
    if len(receipt_values) != len(set(receipt_values)):
        raise LifecycleVerificationError("admitted receipt evidence must be unique")
    receipt_keys = frozenset(receipt_values)

    _verify_branch(actual, receipt_keys)
    _verify_branch(comparison, receipt_keys)
    referenced_receipt_keys = frozenset(
        _entry_key(entry)
        for branch in (actual, comparison)
        for snapshot in branch.snapshots
        for entry in snapshot.disclosure_ledger.entries
    )
    if receipt_keys != referenced_receipt_keys:
        raise LifecycleVerificationError(
            "admitted receipt evidence must exactly match disclosed ledger entries"
        )

    actual_first = actual.snapshots[0]
    comparison_first = comparison.snapshots[0]
    if actual_first.branch_id == comparison_first.branch_id:
        raise LifecycleVerificationError("actual and comparison branch ids must differ")
    if _branch_identity(actual_first) != _branch_identity(comparison_first):
        raise LifecycleVerificationError(
            "comparison is not matched to the same incident and preventive source"
        )
    if actual_first.entitlement_set_digest != comparison_first.entitlement_set_digest:
        raise LifecycleVerificationError(
            "comparison is not matched to the same source entitlement set"
        )

    actual_case_specs = {transition.case_spec_digest for transition in actual.transitions}
    comparison_case_specs = {
        transition.case_spec_digest for transition in comparison.transitions
    }
    if actual_case_specs != comparison_case_specs:
        raise LifecycleVerificationError("branches do not share one case specification")
    actual_factors = {
        transition.factor_assignment_digest for transition in actual.transitions
    }
    comparison_factors = {
        transition.factor_assignment_digest for transition in comparison.transitions
    }
    if actual_factors & comparison_factors:
        raise LifecycleVerificationError(
            "matched branches require distinct factor assignments"
        )

    reused_events = _branch_event_keys(actual) & _branch_event_keys(comparison)
    if reused_events:
        raise LifecycleVerificationError(
            "actual and comparison branches cannot reuse event or "
            "transition-bundle evidence"
        )

    actual_replacements = {
        snapshot.replacement_session_digest
        for snapshot in actual.snapshots
        if snapshot.replacement_session_digest is not None
    }
    comparison_replacements = {
        snapshot.replacement_session_digest
        for snapshot in comparison.snapshots
        if snapshot.replacement_session_digest is not None
    }
    if actual_replacements & comparison_replacements:
        raise LifecycleVerificationError(
            "actual and comparison branches require distinct replacement sessions"
        )

    actual_snapshot_digests = {
        incident_snapshot_digest(snapshot) for snapshot in actual.snapshots
    }
    comparison_snapshot_digests = {
        incident_snapshot_digest(snapshot) for snapshot in comparison.snapshots
    }
    if lifecycle.current_snapshot_digest in comparison_snapshot_digests:
        raise LifecycleVerificationError(
            "a matched-comparison snapshot cannot qualify as current evidence"
        )
    actual_head_digest = incident_snapshot_digest(actual.snapshots[-1])
    if lifecycle.current_snapshot_digest != actual_head_digest:
        if lifecycle.current_snapshot_digest in actual_snapshot_digests:
            raise LifecycleVerificationError(
                "only the actual branch head can qualify as current evidence"
            )
        raise LifecycleVerificationError("current snapshot is not part of the actual branch")

    return VerifiedLifecycle(
        incident_id=actual_first.incident_id,
        current_snapshot_digest=lifecycle.current_snapshot_digest,
        actual_head_digest=actual_head_digest,
        matched_comparison_head_digest=incident_snapshot_digest(
            comparison.snapshots[-1]
        ),
        actual_transition_ids=tuple(
            transition.transition_id for transition in actual.transitions
        ),
        matched_comparison_transition_ids=tuple(
            transition.transition_id for transition in comparison.transitions
        ),
    )
