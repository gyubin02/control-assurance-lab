"""Executable SQLite model for entitlement restore and recovery retesting.

Each run starts from a new in-memory database.  Session cutover is a fixed
fixture invariant, not an experimental intervention: the compromised old
session is revoked, a distinct replacement is active, and the replacement is
bound to the selected snapshot's entitlement-set digest.  The lifecycle layer
is responsible for proving the transition that produced this state.

The caller's trusted boundary is the result returned by the CAB verifier for a
lifecycle evidence bundle.  This runtime checks that manifest's content address
and the exact payload descriptors for the lifecycle snapshot, verifier output,
and cutover reference before materializing them in the clone.  It does not
re-run the lifecycle state-machine proof or authenticate who produced the
bundle.

The prior-disclosure ledger is materialized as immutable canonical entries and
read back before and after the retest.  Operational recovery is never treated
as erasing an earlier admitted delivery.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

import rfc8785

from assurance_lab.contract import DIGEST_PATTERN, CellSelector, StringValue
from assurance_lab.evidence.bundle import (
    BundleFile,
    BundleStatus,
    BundleVerification,
    Sensitivity,
    verify_bundle,
)
from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.lifecycle import (
    BranchKind,
    CompromisedSessionState,
    IncidentSnapshot,
    LifecyclePhase,
    ReplacementSessionState,
    VerifiedLifecycle,
    incident_snapshot_digest,
)
from assurance_lab.scenarios.financial_data import SyntheticDataset
from assurance_lab.scenarios.financial_recovery_contract import (
    APPROVED_CASE_ID,
    APPROVED_CUSTOMER_ID,
    APPROVED_ENTITLEMENT_SET_DIGEST,
    APPROVED_ENTITLEMENTS,
    APPROVED_SNAPSHOT_DIGEST,
    APPROVED_SNAPSHOT_ID,
    ATTACK,
    ATTACK_ACTION_DIGEST,
    BENIGN,
    BENIGN_ACTION_DIGEST,
    COMPENSATOR_OFF,
    COMPENSATOR_ON,
    OLD_SESSION_DIGEST,
    OLD_SESSION_ID,
    PRINCIPAL_ID,
    REPLACEMENT_SESSION_DIGEST,
    REPLACEMENT_SESSION_ID,
    SHAM_REAPPLY,
    SHAM_STEADY,
    STALE_ENTITLEMENT_SET_DIGEST,
    STALE_ENTITLEMENTS,
    STALE_SNAPSHOT_DIGEST,
    STALE_SNAPSHOT_ID,
    TARGET_EFFECTIVE,
    TARGET_INEFFECTIVE,
    action_descriptor,
    snapshot_descriptor,
)

type Scalar = str | bool | int | None
type Payload = tuple[tuple[str, Scalar], ...]

_TRACE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CLONE_NONCE = re.compile(r"^[a-f0-9]{32}$")
_DIGEST = re.compile(DIGEST_PATTERN)
_BUNDLE_ID = re.compile(r"^cab:sha256:[a-f0-9]{64}$")
_LIFECYCLE_VERIFIER_OUTPUT_PATH = (
    "records/lifecycle/verified-lifecycle.json"
)
_LIFECYCLE_BUNDLE_REQUIRED_FOR = "financial-recovery-cutover"


class RecoverySessionState(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"


class RecoveryReleaseDecision(StrEnum):
    NOT_REACHED = "not-reached"
    ALLOW = "allow"
    BLOCK = "block"


class RecoveryBaselineVerdict(StrEnum):
    PASS = "pass"
    FAIL = "fail"


class RecoveryResidualClassification(StrEnum):
    MASKED_RESTORE_FAILURE = "masked_restore_failure"
    EXPOSED_PATH = "exposed_path"
    TARGET_EFFECTIVE = "target_effective"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True, slots=True)
class LifecycleCutoverFixture:
    """Trusted reference to a lifecycle-owned, already-verified cutover state.

    ``bundle_verification`` records the producer's verification result, but it
    is not trusted merely because it has the right Pydantic shape.  The runtime
    freshly verifies ``lifecycle_bundle_root`` and reads the exact payload
    bytes on every execution.  The supplied result must equal that fresh
    result, and the manifest must bind the full snapshot, lifecycle verifier
    output, and cutover reference.

    This is an integrity boundary, not origin authentication.  The recovery
    runtime validates and carries the lifecycle verifier's output; it does not
    re-run the lifecycle state-machine proof.
    """

    lifecycle_bundle_digest: str
    lifecycle_bundle_root: Path
    bundle_verification: BundleVerification
    session_rotation_transition_id: str
    target_snapshot_digest: str
    old_session_id: str
    replacement_session_id: str
    snapshot: IncidentSnapshot
    verified_lifecycle: VerifiedLifecycle


@dataclass(frozen=True, slots=True)
class LifecycleReferenceReadback:
    lifecycle_bundle_digest: str
    lifecycle_snapshot_canonical: str
    lifecycle_snapshot_digest: str
    session_rotation_transition_id: str
    branch_id: str
    branch_kind: str
    bound_branch_head_digest: str
    verified_lifecycle_canonical: str
    verified_lifecycle_digest: str
    disclosure_ledger_canonical: str
    disclosure_ledger_digest: str
    disclosure_entry_ids_canonical: str
    disclosure_entry_ids_digest: str
    disclosure_entry_count: int


@dataclass(frozen=True, slots=True)
class SnapshotApplyReceipt:
    operation_id: str
    target_level: str
    before_snapshot_canonical: str
    before_snapshot_digest: str
    after_snapshot_canonical: str
    after_snapshot_digest: str
    snapshot_rows_deleted: int
    entitlement_rows_deleted: int
    snapshot_rows_inserted: int
    entitlement_rows_inserted: int
    mutation_rows_canonical: str
    mutation_rows_digest: str


@dataclass(frozen=True, slots=True)
class CloneReadback:
    clone_id: str
    clone_nonce: str
    trace_id: str
    storage_kind: str


@dataclass(frozen=True, slots=True)
class AssignmentReadback:
    customer_ids: tuple[str, ...]
    canonical: str
    digest: str


@dataclass(frozen=True, slots=True)
class DeliveryReceiptReadback:
    customer_ids: tuple[str, ...]
    canonical: str
    digest: str


@dataclass(frozen=True, slots=True)
class RuntimeEvent:
    trace_id: str
    sequence: int
    stage: str
    component: str
    event_type: str
    payload: Payload

    def value(self, name: str) -> Scalar:
        values = dict(self.payload)
        if name not in values:
            raise KeyError(name)
        return values[name]


@dataclass(frozen=True, slots=True)
class FinancialRecoveryRuntimeResult:
    trace_id: str
    input_level: str
    target_level: str
    guard_level: str
    sham_level: str
    action_digest: str
    snapshot_id: str
    snapshot_digest: str
    entitlement_set_canonical: str
    entitlement_set_digest: str
    snapshot_identity_matches_declared_target: bool
    snapshot_reapply_performed: bool
    snapshot_reapply_semantics_unchanged: bool
    snapshot_reapply_receipt_valid: bool
    snapshot_reapply_operation_id: str | None
    snapshot_reapply_snapshot_rows_deleted: int
    snapshot_reapply_entitlement_rows_deleted: int
    snapshot_reapply_snapshot_rows_inserted: int
    snapshot_reapply_entitlement_rows_inserted: int
    snapshot_reapply_mutation_rows_canonical: str
    snapshot_reapply_mutation_rows_digest: str
    old_session_id: str
    old_session_state: RecoverySessionState
    old_session_revoked: bool
    replacement_session_id: str
    replacement_session_state: RecoverySessionState
    replacement_session_active: bool
    replacement_session_entitlement_set_digest: str
    replacement_session_entitlement_digest_bound: bool
    cutover_fixture_valid: bool
    lifecycle_bundle_digest: str
    lifecycle_bundle_root: Path
    lifecycle_bundle_verification: BundleVerification
    lifecycle_snapshot_canonical: str
    lifecycle_snapshot_digest: str
    verified_lifecycle_canonical: str
    verified_lifecycle_digest: str
    session_rotation_transition_id: str
    lifecycle_branch_id: str
    lifecycle_branch_kind: str
    lifecycle_bound_branch_head_digest: str
    snapshot_authorized_action: bool
    requested_customer_ids: tuple[str, ...]
    assigned_customer_ids: tuple[str, ...]
    assignment_basis_canonical: str
    assignment_basis_digest: str
    selected_customer_ids: tuple[str, ...]
    selected_out_of_scope_customer_ids: tuple[str, ...]
    out_of_scope_records_selected: int
    release_guard_reached: bool
    release_decision: RecoveryReleaseDecision
    release_reason: str
    unapproved_release_blocked: bool
    delivered_customer_ids: tuple[str, ...]
    delivery_receipts_canonical: str
    delivery_receipts_digest: str
    delivered_out_of_scope_customer_ids: tuple[str, ...]
    delivered_assigned_customer_ids: tuple[str, ...]
    out_of_scope_records_delivered: int
    assigned_case_records_delivered: int
    prior_disclosure_ledger_canonical_before: str
    prior_disclosure_ledger_canonical_after: str
    prior_disclosure_ledger_digest_before: str
    prior_disclosure_ledger_digest_after: str
    prior_disclosure_entry_ids_canonical_before: str
    prior_disclosure_entry_ids_canonical_after: str
    prior_disclosure_entry_ids_digest_before: str
    prior_disclosure_entry_ids_digest_after: str
    prior_admitted_disclosure_count_before: int
    prior_admitted_disclosure_count_after: int
    prior_disclosure_reference_unchanged: bool
    clone_id: str
    clone_nonce: str
    clone_storage_kind: str
    clone_readback_canonical: str
    clone_readback_digest: str
    clone_cleanup_verified: bool
    events: tuple[RuntimeEvent, ...]


@dataclass(frozen=True, slots=True)
class CurrentStateAndFinalOutcomeBaseline:
    name: Literal["current-state-and-final-outcome-only"]
    verdict: RecoveryBaselineVerdict
    out_of_scope_records_delivered: int
    assigned_case_records_delivered: int
    prior_disclosure_ledger_digest_ignored: str
    prior_admitted_disclosure_count_ignored: int


@dataclass(frozen=True, slots=True)
class RecoveryCaseAssessment:
    baseline: CurrentStateAndFinalOutcomeBaseline
    target_supported: bool
    cutover_fixture_supported: bool
    release_guard_supported: bool
    path_supported: bool
    benign_service_supported: bool
    prior_disclosure_history_preserved: bool
    prior_disclosure_ledger_digest: str
    prior_admitted_disclosure_count: int
    residual_classification: RecoveryResidualClassification


class FinancialRecoveryRuntime:
    """Execute one recovery cell against an isolated synthetic database."""

    def __init__(
        self,
        dataset: SyntheticDataset,
        *,
        cutover_fixtures: Mapping[str, LifecycleCutoverFixture],
        bulk_threshold_records: int = 10,
    ):
        if bulk_threshold_records < 1:
            raise ValueError("bulk threshold must be positive")
        _validate_fixture(dataset)
        expected_levels = {TARGET_INEFFECTIVE.value, TARGET_EFFECTIVE.value}
        if set(cutover_fixtures) != expected_levels:
            raise ValueError(
                "cutover fixtures must bind exactly the stale and approved target levels"
            )
        for target_level, fixture in cutover_fixtures.items():
            _validate_cutover_fixture(fixture, target_level=target_level)
        _validate_cutover_fixture_bundle_sets(cutover_fixtures)
        self._dataset = dataset
        self._cutover_fixtures = dict(cutover_fixtures)
        self._bulk_threshold = bulk_threshold_records

    def execute(
        self,
        selector: CellSelector,
        *,
        trace_id: str,
    ) -> FinancialRecoveryRuntimeResult:
        _validate_trace_id(trace_id)
        input_level = _string_level(selector.input, "input")
        target_level = _string_level(selector.target, "target")
        guard_level = _string_level(selector.compensator, "compensator")
        sham_level = _string_level(selector.sham, "sham")
        _require_level(input_level, {ATTACK.value, BENIGN.value}, "input")
        _require_level(
            target_level,
            {TARGET_INEFFECTIVE.value, TARGET_EFFECTIVE.value},
            "target",
        )
        _require_level(
            guard_level,
            {COMPENSATOR_OFF.value, COMPENSATOR_ON.value},
            "compensator",
        )
        _require_level(
            sham_level,
            {SHAM_STEADY.value, SHAM_REAPPLY.value},
            "sham",
        )

        action_level = ATTACK if input_level == ATTACK.value else BENIGN
        target_value = (
            TARGET_INEFFECTIVE
            if target_level == TARGET_INEFFECTIVE.value
            else TARGET_EFFECTIVE
        )
        action = action_descriptor(action_level)
        action_digest = _sha256(rfc8785.dumps(action))
        expected_action_digest = (
            ATTACK_ACTION_DIGEST if action_level == ATTACK else BENIGN_ACTION_DIGEST
        )
        if action_digest != expected_action_digest:
            raise RuntimeError("fixed action no longer matches its contracted digest")
        requested_ids = _required_text_list(action, "requested_customer_ids")

        fixture = self._cutover_fixtures[target_level]
        _validate_cutover_fixture(fixture, target_level=target_level)
        clone_nonce = secrets.token_hex(16)
        clone_id = _clone_id(trace_id, selector, fixture, clone_nonce)
        connection = self._fresh_database(
            target_level=target_level,
            fixture=fixture,
            clone_id=clone_id,
            clone_nonce=clone_nonce,
            trace_id=trace_id,
        )
        closed = False
        try:
            clone_readback = _clone_readback(connection)
            if clone_readback != CloneReadback(
                clone_id=clone_id,
                clone_nonce=clone_nonce,
                trace_id=trace_id,
                storage_kind="sqlite-memory",
            ):
                raise RuntimeError(
                    "fresh SQLite clone identity differs from its persisted readback"
                )
            clone_readback_canonical, clone_readback_digest = (
                _clone_readback_evidence(clone_readback)
            )
            _record_request(
                connection,
                trace_id=trace_id,
                action=action,
                action_digest=action_digest,
                requested_ids=requested_ids,
            )
            (
                action_canonical,
                action_digest_readback,
                requested_ids_readback,
            ) = _request_readback(connection, trace_id)
            if (
                action_canonical != rfc8785.dumps(action).decode("utf-8")
                or
                action_digest_readback != action_digest
                or requested_ids_readback != requested_ids
                or _sha256(action_canonical.encode("utf-8")) != action_digest
            ):
                raise RuntimeError("request audit rows do not reproduce the fixed action")

            lifecycle_before = _lifecycle_reference_readback(connection)
            if not _lifecycle_reference_matches_fixture(
                lifecycle_before,
                fixture,
            ):
                raise RuntimeError(
                    "persisted lifecycle reference differs from the supplied fixture"
                )
            before_reapply = _snapshot_readback(connection)
            before_reapply_canonical = rfc8785.dumps(before_reapply).decode("utf-8")
            before_reapply_digest = _sha256(
                before_reapply_canonical.encode("utf-8")
            )
            if sham_level == SHAM_REAPPLY.value:
                _reapply_snapshot(
                    connection,
                    target_value,
                    trace_id=trace_id,
                    before_snapshot=before_reapply,
                )
            apply_receipt = _snapshot_apply_receipt_readback(connection, trace_id)
            after_reapply = _snapshot_readback(connection)
            after_reapply_canonical = rfc8785.dumps(after_reapply).decode("utf-8")
            after_reapply_digest = _sha256(after_reapply_canonical.encode("utf-8"))
            snapshot_reapply_unchanged = before_reapply == after_reapply
            snapshot_reapply_performed = apply_receipt is not None
            snapshot_reapply_receipt_valid = _validate_snapshot_apply_receipt(
                receipt=apply_receipt,
                trace_id=trace_id,
                sham_level=sham_level,
                target_level=target_level,
                before_snapshot_canonical=before_reapply_canonical,
                before_snapshot_digest=before_reapply_digest,
                after_snapshot_canonical=after_reapply_canonical,
                after_snapshot_digest=after_reapply_digest,
                expected_entitlement_rows=len(
                    STALE_ENTITLEMENTS
                    if target_value == TARGET_INEFFECTIVE
                    else APPROVED_ENTITLEMENTS
                ),
            )
            if not snapshot_reapply_receipt_valid:
                raise RuntimeError(
                    "snapshot sham selector is not backed by an exact apply receipt"
                )

            declared_snapshot = snapshot_descriptor(target_value)
            declared_snapshot_digest = _sha256(rfc8785.dumps(declared_snapshot))
            snapshot_identity_matches = (
                after_reapply == declared_snapshot
                and after_reapply_digest == declared_snapshot_digest
                and after_reapply_digest == fixture.target_snapshot_digest
            )
            if not snapshot_identity_matches:
                raise RuntimeError(
                    "restored snapshot readback differs from the declared lifecycle target"
                )

            raw_entitlement_set = after_reapply.get("entitlement_set")
            if not isinstance(raw_entitlement_set, dict):
                raise RuntimeError("snapshot readback has no entitlement set")
            entitlement_set_canonical = rfc8785.dumps(raw_entitlement_set).decode(
                "utf-8"
            )
            entitlement_set_digest = _sha256(
                entitlement_set_canonical.encode("utf-8")
            )
            expected_entitlement_digest = (
                STALE_ENTITLEMENT_SET_DIGEST
                if target_value == TARGET_INEFFECTIVE
                else APPROVED_ENTITLEMENT_SET_DIGEST
            )
            if (
                entitlement_set_digest != expected_entitlement_digest
                or entitlement_set_digest
                != fixture.snapshot.replacement_entitlement_digest
            ):
                raise RuntimeError(
                    "raw restored entitlement rows are not bound to the lifecycle cutover"
                )

            (
                old_state,
                replacement_state,
                replacement_binding_digest,
                cutover_lifecycle_snapshot_digest,
            ) = _cutover_readback(connection)
            replacement_binding_valid = (
                replacement_binding_digest == entitlement_set_digest
            )
            old_session_revoked = old_state == RecoverySessionState.REVOKED
            replacement_session_active = (
                replacement_state == RecoverySessionState.ACTIVE
            )
            cutover_valid = (
                OLD_SESSION_ID != REPLACEMENT_SESSION_ID
                and old_session_revoked
                and replacement_session_active
                and replacement_binding_valid
                and cutover_lifecycle_snapshot_digest
                == lifecycle_before.lifecycle_snapshot_digest
            )
            if not cutover_valid:
                raise RuntimeError("lifecycle-bound recovery cutover state is invalid")

            assignment_readback = _assignment_readback(
                connection,
                PRINCIPAL_ID,
            )
            assigned_ids = assignment_readback.customer_ids
            admitted_ids = tuple(
                customer_id
                for customer_id in requested_ids_readback
                if _entitlement_allows(connection, customer_id)
            )
            outside_assignment = set(requested_ids_readback).difference(
                assigned_ids
            )
            snapshot_authorized = len(admitted_ids) == len(
                requested_ids_readback
            )
            selected_query = (
                _select_customers(connection, requested_ids_readback)
                if snapshot_authorized
                else ()
            )
            _record_selection(connection, trace_id, selected_query)
            selected = _selection_readback(connection, trace_id)
            selected_outside = tuple(
                customer_id
                for customer_id in selected
                if customer_id in outside_assignment
            )

            if not snapshot_authorized:
                guard_reached = False
                release_decision = RecoveryReleaseDecision.NOT_REACHED
                release_reason = "restored-entitlement-denied"
            else:
                guard_reached = True
                sensitive_bulk = len(selected) >= self._bulk_threshold
                enforce = guard_level == COMPENSATOR_ON.value
                if enforce and (selected_outside or sensitive_bulk):
                    release_decision = RecoveryReleaseDecision.BLOCK
                    release_reason = "unapproved-or-bulk-export"
                else:
                    release_decision = RecoveryReleaseDecision.ALLOW
                    release_reason = (
                        "monitor-only-observation"
                        if selected_outside or sensitive_bulk
                        else "approved-assigned-case"
                    )
            _record_release_decision(
                connection,
                trace_id=trace_id,
                guard_level=guard_level,
                guard_reached=guard_reached,
                decision=release_decision,
                reason=release_reason,
            )
            (
                guard_level_readback,
                guard_reached_readback,
                release_decision_readback,
                release_reason_readback,
            ) = _release_decision_readback(connection, trace_id)
            if (
                guard_level_readback != guard_level
                or guard_reached_readback != guard_reached
                or release_decision_readback != release_decision
                or release_reason_readback != release_reason
            ):
                raise RuntimeError("release-decision row does not match execution")

            if release_decision_readback == RecoveryReleaseDecision.ALLOW:
                _record_delivery_receipts(
                    connection,
                    trace_id=trace_id,
                    request_id=_required_text(action, "request_id"),
                    customer_ids=selected,
                )
            delivery_readback = _delivery_receipt_readback(
                connection,
                trace_id,
            )
            delivered = delivery_readback.customer_ids
            delivered_outside = tuple(
                customer_id
                for customer_id in delivered
                if customer_id in outside_assignment
            )
            assigned_delivered = tuple(
                customer_id
                for customer_id in delivered
                if customer_id in assigned_ids
            )
            unapproved_release_blocked = (
                guard_reached_readback
                and release_decision_readback == RecoveryReleaseDecision.BLOCK
                and bool(selected_outside)
                and not delivered_outside
            )

            lifecycle_after = _lifecycle_reference_readback(connection)
            prior_disclosure_reference_unchanged = (
                lifecycle_before == lifecycle_after
            )
            if not prior_disclosure_reference_unchanged:
                raise RuntimeError(
                    "lifecycle disclosure reference changed during the recovery retest"
                )

            expected_snapshot_id = (
                STALE_SNAPSHOT_ID
                if target_value == TARGET_INEFFECTIVE
                else APPROVED_SNAPSHOT_ID
            )
            expected_snapshot_digest = (
                STALE_SNAPSHOT_DIGEST
                if target_value == TARGET_INEFFECTIVE
                else APPROVED_SNAPSHOT_DIGEST
            )
            if (
                str(after_reapply["snapshot_id"]) != expected_snapshot_id
                or after_reapply_digest != expected_snapshot_digest
            ):
                raise RuntimeError("snapshot identity no longer matches fixed constants")

            connection.close()
            closed = True
            clone_cleanup_verified = _connection_is_closed(connection)
            if not clone_cleanup_verified:
                raise RuntimeError("fresh SQLite clone did not close after execution")
        finally:
            if not closed:
                connection.close()

        events = _events(
            trace_id=trace_id,
            clone_id=clone_id,
            clone_nonce=clone_nonce,
            clone_storage_kind=clone_readback.storage_kind,
            clone_readback_canonical=clone_readback_canonical,
            clone_readback_digest=clone_readback_digest,
            clone_cleanup_verified=clone_cleanup_verified,
            action=action,
            action_canonical=action_canonical,
            action_digest=action_digest,
            requested_ids=requested_ids_readback,
            lifecycle_before=lifecycle_before,
            lifecycle_after=lifecycle_after,
            old_state=old_state,
            replacement_state=replacement_state,
            replacement_binding_digest=replacement_binding_digest,
            replacement_binding_valid=replacement_binding_valid,
            cutover_valid=cutover_valid,
            target_level=target_level,
            snapshot_id=expected_snapshot_id,
            snapshot_canonical=after_reapply_canonical,
            snapshot_digest=after_reapply_digest,
            entitlement_set_canonical=entitlement_set_canonical,
            entitlement_set_digest=entitlement_set_digest,
            snapshot_identity_matches=snapshot_identity_matches,
            snapshot_reapply_performed=snapshot_reapply_performed,
            snapshot_reapply_receipt_valid=snapshot_reapply_receipt_valid,
            apply_receipt=apply_receipt,
            before_reapply_digest=before_reapply_digest,
            after_reapply_digest=after_reapply_digest,
            snapshot_reapply_unchanged=snapshot_reapply_unchanged,
            snapshot_authorized=snapshot_authorized,
            assigned_ids=assigned_ids,
            assignment_readback=assignment_readback,
            selected_ids=selected,
            selected_outside_ids=selected_outside,
            guard_level=guard_level,
            guard_reached=guard_reached,
            release_decision=release_decision,
            release_reason=release_reason,
            unapproved_release_blocked=unapproved_release_blocked,
            delivered_ids=delivered,
            delivery_readback=delivery_readback,
            delivered_outside_ids=delivered_outside,
            assigned_delivered_ids=assigned_delivered,
        )
        return FinancialRecoveryRuntimeResult(
            trace_id=trace_id,
            input_level=input_level,
            target_level=target_level,
            guard_level=guard_level,
            sham_level=sham_level,
            action_digest=action_digest,
            snapshot_id=expected_snapshot_id,
            snapshot_digest=after_reapply_digest,
            entitlement_set_canonical=entitlement_set_canonical,
            entitlement_set_digest=entitlement_set_digest,
            snapshot_identity_matches_declared_target=snapshot_identity_matches,
            snapshot_reapply_performed=snapshot_reapply_performed,
            snapshot_reapply_semantics_unchanged=snapshot_reapply_unchanged,
            snapshot_reapply_receipt_valid=snapshot_reapply_receipt_valid,
            snapshot_reapply_operation_id=(
                None if apply_receipt is None else apply_receipt.operation_id
            ),
            snapshot_reapply_snapshot_rows_deleted=(
                0 if apply_receipt is None else apply_receipt.snapshot_rows_deleted
            ),
            snapshot_reapply_entitlement_rows_deleted=(
                0
                if apply_receipt is None
                else apply_receipt.entitlement_rows_deleted
            ),
            snapshot_reapply_snapshot_rows_inserted=(
                0 if apply_receipt is None else apply_receipt.snapshot_rows_inserted
            ),
            snapshot_reapply_entitlement_rows_inserted=(
                0
                if apply_receipt is None
                else apply_receipt.entitlement_rows_inserted
            ),
            snapshot_reapply_mutation_rows_canonical=(
                _empty_snapshot_apply_mutations(
                    trace_id=trace_id,
                )
                if apply_receipt is None
                else apply_receipt.mutation_rows_canonical
            ),
            snapshot_reapply_mutation_rows_digest=(
                _sha256(
                    _empty_snapshot_apply_mutations(
                        trace_id=trace_id,
                    ).encode("utf-8")
                )
                if apply_receipt is None
                else apply_receipt.mutation_rows_digest
            ),
            old_session_id=OLD_SESSION_ID,
            old_session_state=old_state,
            old_session_revoked=old_session_revoked,
            replacement_session_id=REPLACEMENT_SESSION_ID,
            replacement_session_state=replacement_state,
            replacement_session_active=replacement_session_active,
            replacement_session_entitlement_set_digest=(
                replacement_binding_digest
            ),
            replacement_session_entitlement_digest_bound=(
                replacement_binding_valid
            ),
            cutover_fixture_valid=cutover_valid,
            lifecycle_bundle_digest=lifecycle_before.lifecycle_bundle_digest,
            lifecycle_bundle_root=fixture.lifecycle_bundle_root,
            lifecycle_bundle_verification=fixture.bundle_verification,
            lifecycle_snapshot_canonical=(
                lifecycle_before.lifecycle_snapshot_canonical
            ),
            lifecycle_snapshot_digest=lifecycle_before.lifecycle_snapshot_digest,
            verified_lifecycle_canonical=(
                lifecycle_before.verified_lifecycle_canonical
            ),
            verified_lifecycle_digest=(
                lifecycle_before.verified_lifecycle_digest
            ),
            session_rotation_transition_id=(
                lifecycle_before.session_rotation_transition_id
            ),
            lifecycle_branch_id=lifecycle_before.branch_id,
            lifecycle_branch_kind=lifecycle_before.branch_kind,
            lifecycle_bound_branch_head_digest=(
                lifecycle_before.bound_branch_head_digest
            ),
            snapshot_authorized_action=snapshot_authorized,
            requested_customer_ids=requested_ids_readback,
            assigned_customer_ids=assigned_ids,
            assignment_basis_canonical=assignment_readback.canonical,
            assignment_basis_digest=assignment_readback.digest,
            selected_customer_ids=selected,
            selected_out_of_scope_customer_ids=selected_outside,
            out_of_scope_records_selected=len(selected_outside),
            release_guard_reached=guard_reached,
            release_decision=release_decision,
            release_reason=release_reason,
            unapproved_release_blocked=unapproved_release_blocked,
            delivered_customer_ids=delivered,
            delivery_receipts_canonical=delivery_readback.canonical,
            delivery_receipts_digest=delivery_readback.digest,
            delivered_out_of_scope_customer_ids=delivered_outside,
            delivered_assigned_customer_ids=assigned_delivered,
            out_of_scope_records_delivered=len(delivered_outside),
            assigned_case_records_delivered=len(assigned_delivered),
            prior_disclosure_ledger_digest_before=(
                lifecycle_before.disclosure_ledger_digest
            ),
            prior_disclosure_ledger_digest_after=(
                lifecycle_after.disclosure_ledger_digest
            ),
            prior_disclosure_ledger_canonical_before=(
                lifecycle_before.disclosure_ledger_canonical
            ),
            prior_disclosure_ledger_canonical_after=(
                lifecycle_after.disclosure_ledger_canonical
            ),
            prior_disclosure_entry_ids_canonical_before=(
                lifecycle_before.disclosure_entry_ids_canonical
            ),
            prior_disclosure_entry_ids_canonical_after=(
                lifecycle_after.disclosure_entry_ids_canonical
            ),
            prior_disclosure_entry_ids_digest_before=(
                lifecycle_before.disclosure_entry_ids_digest
            ),
            prior_disclosure_entry_ids_digest_after=(
                lifecycle_after.disclosure_entry_ids_digest
            ),
            prior_admitted_disclosure_count_before=(
                lifecycle_before.disclosure_entry_count
            ),
            prior_admitted_disclosure_count_after=(
                lifecycle_after.disclosure_entry_count
            ),
            prior_disclosure_reference_unchanged=(
                prior_disclosure_reference_unchanged
            ),
            clone_id=clone_id,
            clone_nonce=clone_nonce,
            clone_storage_kind=clone_readback.storage_kind,
            clone_readback_canonical=clone_readback_canonical,
            clone_readback_digest=clone_readback_digest,
            clone_cleanup_verified=clone_cleanup_verified,
            events=events,
        )

    def _fresh_database(
        self,
        *,
        target_level: str,
        fixture: LifecycleCutoverFixture,
        clone_id: str,
        clone_nonce: str,
        trace_id: str,
    ) -> sqlite3.Connection:
        connection = sqlite3.connect(":memory:")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            CREATE TABLE run_control (
                clone_id TEXT PRIMARY KEY,
                clone_nonce TEXT NOT NULL UNIQUE,
                trace_id TEXT NOT NULL UNIQUE,
                storage_kind TEXT NOT NULL CHECK (storage_kind = 'sqlite-memory')
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE customers (
                customer_id TEXT PRIMARY KEY,
                synthetic INTEGER NOT NULL CHECK (synthetic = 1)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE support_cases (
                case_id TEXT PRIMARY KEY,
                customer_id TEXT NOT NULL REFERENCES customers(customer_id),
                assigned_principal_id TEXT NOT NULL,
                status TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE restored_snapshot (
                snapshot_id TEXT PRIMARY KEY,
                target_level TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                restore_operation_id TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE restored_entitlements (
                snapshot_id TEXT NOT NULL REFERENCES restored_snapshot(snapshot_id),
                entitlement TEXT NOT NULL,
                PRIMARY KEY (snapshot_id, entitlement)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE sessions (
                session_id TEXT PRIMARY KEY,
                principal_id TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
                session_identity_digest TEXT NOT NULL,
                entitlement_set_digest TEXT,
                lifecycle_snapshot_digest TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE lifecycle_cutover_reference (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                lifecycle_bundle_digest TEXT NOT NULL,
                lifecycle_snapshot_canonical TEXT NOT NULL,
                lifecycle_snapshot_digest TEXT NOT NULL,
                session_rotation_transition_id TEXT NOT NULL,
                branch_id TEXT NOT NULL,
                branch_kind TEXT NOT NULL,
                bound_branch_head_digest TEXT NOT NULL,
                verified_lifecycle_canonical TEXT NOT NULL,
                verified_lifecycle_digest TEXT NOT NULL,
                disclosure_ledger_canonical TEXT NOT NULL,
                disclosure_ledger_digest TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE lifecycle_disclosure_entries (
                entry_digest TEXT PRIMARY KEY,
                entry_canonical TEXT NOT NULL,
                record_token TEXT NOT NULL UNIQUE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE recovery_requests (
                trace_id TEXT PRIMARY KEY,
                action_canonical TEXT NOT NULL,
                action_digest TEXT NOT NULL,
                request_id TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                session_id TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE recovery_request_items (
                trace_id TEXT NOT NULL REFERENCES recovery_requests(trace_id),
                ordinal INTEGER NOT NULL,
                customer_id TEXT NOT NULL REFERENCES customers(customer_id),
                PRIMARY KEY (trace_id, ordinal),
                UNIQUE (trace_id, customer_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE recovery_selection_audit (
                trace_id TEXT NOT NULL REFERENCES recovery_requests(trace_id),
                customer_id TEXT NOT NULL REFERENCES customers(customer_id),
                PRIMARY KEY (trace_id, customer_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE recovery_release_decisions (
                trace_id TEXT PRIMARY KEY REFERENCES recovery_requests(trace_id),
                guard_mode TEXT NOT NULL,
                guard_reached INTEGER NOT NULL CHECK (guard_reached IN (0, 1)),
                decision TEXT NOT NULL,
                reason TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE recovery_delivery_receipts (
                receipt_id TEXT PRIMARY KEY,
                trace_id TEXT NOT NULL REFERENCES recovery_requests(trace_id),
                request_id TEXT NOT NULL,
                customer_id TEXT NOT NULL REFERENCES customers(customer_id),
                UNIQUE (trace_id, customer_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE snapshot_apply_receipts (
                trace_id TEXT PRIMARY KEY REFERENCES recovery_requests(trace_id),
                operation_id TEXT NOT NULL UNIQUE,
                target_level TEXT NOT NULL,
                before_snapshot_canonical TEXT NOT NULL,
                before_snapshot_digest TEXT NOT NULL,
                after_snapshot_canonical TEXT NOT NULL,
                after_snapshot_digest TEXT NOT NULL,
                snapshot_rows_deleted INTEGER NOT NULL,
                entitlement_rows_deleted INTEGER NOT NULL,
                snapshot_rows_inserted INTEGER NOT NULL,
                entitlement_rows_inserted INTEGER NOT NULL,
                mutation_rows_canonical TEXT NOT NULL,
                mutation_rows_digest TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE snapshot_apply_context (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                trace_id TEXT NOT NULL REFERENCES recovery_requests(trace_id),
                operation_id TEXT NOT NULL UNIQUE,
                target_level TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('open', 'closed'))
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE snapshot_apply_mutations (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                trace_id TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                operation TEXT NOT NULL CHECK (operation IN ('delete', 'insert')),
                row_key TEXT NOT NULL,
                snapshot_id TEXT NOT NULL,
                target_level TEXT,
                principal_id TEXT,
                restore_operation_id TEXT,
                entitlement TEXT
            )
            """
        )
        connection.execute(
            "INSERT INTO run_control VALUES (?, ?, ?, 'sqlite-memory')",
            (clone_id, clone_nonce, trace_id),
        )
        connection.executemany(
            "INSERT INTO customers VALUES (?, ?)",
            (
                (customer.customer_id, int(customer.synthetic))
                for customer in self._dataset.customers
            ),
        )
        connection.executemany(
            "INSERT INTO support_cases VALUES (?, ?, ?, ?)",
            (
                (
                    support_case.case_id,
                    support_case.customer_id,
                    support_case.assigned_principal_id,
                    support_case.status,
                )
                for support_case in self._dataset.support_cases
            ),
        )
        target_value = (
            TARGET_INEFFECTIVE
            if target_level == TARGET_INEFFECTIVE.value
            else TARGET_EFFECTIVE
        )
        _insert_snapshot(connection, target_value)
        lifecycle_snapshot_digest = incident_snapshot_digest(fixture.snapshot)
        lifecycle_snapshot_canonical = canonical_json_bytes(
            fixture.snapshot.model_dump(mode="json")
        ).decode("utf-8")
        ledger_canonical = canonical_json_bytes(
            fixture.snapshot.disclosure_ledger.model_dump(mode="json")
        ).decode("utf-8")
        ledger_digest = _sha256(ledger_canonical.encode("utf-8"))
        verified_lifecycle_canonical = canonical_json_bytes(
            fixture.verified_lifecycle.model_dump(mode="json")
        ).decode("utf-8")
        verified_lifecycle_digest = _sha256(
            verified_lifecycle_canonical.encode("utf-8")
        )
        bound_branch_head_digest = _fixture_bound_branch_head_digest(fixture)
        connection.execute(
            """
            INSERT INTO lifecycle_cutover_reference
            VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                fixture.lifecycle_bundle_digest,
                lifecycle_snapshot_canonical,
                lifecycle_snapshot_digest,
                fixture.session_rotation_transition_id,
                fixture.snapshot.branch_id,
                fixture.snapshot.branch_kind.value,
                bound_branch_head_digest,
                verified_lifecycle_canonical,
                verified_lifecycle_digest,
                ledger_canonical,
                ledger_digest,
            ),
        )
        connection.executemany(
            "INSERT INTO lifecycle_disclosure_entries VALUES (?, ?, ?)",
            (
                (
                    _sha256(
                        canonical_json_bytes(entry.model_dump(mode="json"))
                    ),
                    canonical_json_bytes(entry.model_dump(mode="json")).decode(
                        "utf-8"
                    ),
                    entry.record_token,
                )
                for entry in fixture.snapshot.disclosure_ledger.entries
            ),
        )
        connection.executemany(
            "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?)",
            (
                (
                    fixture.old_session_id,
                    PRINCIPAL_ID,
                    fixture.snapshot.compromised_session_state.value,
                    fixture.snapshot.compromised_session_digest,
                    None,
                    lifecycle_snapshot_digest,
                ),
                (
                    fixture.replacement_session_id,
                    PRINCIPAL_ID,
                    fixture.snapshot.replacement_session_state.value,
                    fixture.snapshot.replacement_session_digest,
                    fixture.snapshot.replacement_entitlement_digest,
                    lifecycle_snapshot_digest,
                ),
            ),
        )
        connection.executescript(
            """
            CREATE TRIGGER snapshot_apply_entitlement_delete_audit
            AFTER DELETE ON restored_entitlements
            WHEN EXISTS (
                SELECT 1 FROM snapshot_apply_context
                WHERE singleton = 1 AND state = 'open'
            )
            BEGIN
                INSERT INTO snapshot_apply_mutations (
                    trace_id, operation_id, entity_type, operation, row_key,
                    snapshot_id, target_level, principal_id,
                    restore_operation_id, entitlement
                )
                SELECT trace_id, operation_id, 'entitlement', 'delete',
                       OLD.snapshot_id || ':' || OLD.entitlement,
                       OLD.snapshot_id, NULL, NULL, NULL, OLD.entitlement
                FROM snapshot_apply_context
                WHERE singleton = 1 AND state = 'open';
            END;
            CREATE TRIGGER snapshot_apply_snapshot_delete_audit
            AFTER DELETE ON restored_snapshot
            WHEN EXISTS (
                SELECT 1 FROM snapshot_apply_context
                WHERE singleton = 1 AND state = 'open'
            )
            BEGIN
                INSERT INTO snapshot_apply_mutations (
                    trace_id, operation_id, entity_type, operation, row_key,
                    snapshot_id, target_level, principal_id,
                    restore_operation_id, entitlement
                )
                SELECT trace_id, operation_id, 'snapshot', 'delete',
                       OLD.snapshot_id, OLD.snapshot_id, OLD.target_level,
                       OLD.principal_id, OLD.restore_operation_id, NULL
                FROM snapshot_apply_context
                WHERE singleton = 1 AND state = 'open';
            END;
            CREATE TRIGGER snapshot_apply_snapshot_insert_audit
            AFTER INSERT ON restored_snapshot
            WHEN EXISTS (
                SELECT 1 FROM snapshot_apply_context
                WHERE singleton = 1 AND state = 'open'
            )
            BEGIN
                INSERT INTO snapshot_apply_mutations (
                    trace_id, operation_id, entity_type, operation, row_key,
                    snapshot_id, target_level, principal_id,
                    restore_operation_id, entitlement
                )
                SELECT trace_id, operation_id, 'snapshot', 'insert',
                       NEW.snapshot_id, NEW.snapshot_id, NEW.target_level,
                       NEW.principal_id, NEW.restore_operation_id, NULL
                FROM snapshot_apply_context
                WHERE singleton = 1 AND state = 'open';
            END;
            CREATE TRIGGER snapshot_apply_entitlement_insert_audit
            AFTER INSERT ON restored_entitlements
            WHEN EXISTS (
                SELECT 1 FROM snapshot_apply_context
                WHERE singleton = 1 AND state = 'open'
            )
            BEGIN
                INSERT INTO snapshot_apply_mutations (
                    trace_id, operation_id, entity_type, operation, row_key,
                    snapshot_id, target_level, principal_id,
                    restore_operation_id, entitlement
                )
                SELECT trace_id, operation_id, 'entitlement', 'insert',
                       NEW.snapshot_id || ':' || NEW.entitlement,
                       NEW.snapshot_id, NULL, NULL, NULL, NEW.entitlement
                FROM snapshot_apply_context
                WHERE singleton = 1 AND state = 'open';
            END;
            CREATE TRIGGER lifecycle_reference_no_update
            BEFORE UPDATE ON lifecycle_cutover_reference
            BEGIN
                SELECT RAISE(ABORT, 'lifecycle reference is immutable');
            END;
            CREATE TRIGGER lifecycle_reference_no_delete
            BEFORE DELETE ON lifecycle_cutover_reference
            BEGIN
                SELECT RAISE(ABORT, 'lifecycle reference is immutable');
            END;
            CREATE TRIGGER lifecycle_entries_no_update
            BEFORE UPDATE ON lifecycle_disclosure_entries
            BEGIN
                SELECT RAISE(ABORT, 'lifecycle disclosure entries are immutable');
            END;
            CREATE TRIGGER lifecycle_entries_no_delete
            BEFORE DELETE ON lifecycle_disclosure_entries
            BEGIN
                SELECT RAISE(ABORT, 'lifecycle disclosure entries are immutable');
            END;
            CREATE TRIGGER lifecycle_entries_no_insert
            BEFORE INSERT ON lifecycle_disclosure_entries
            BEGIN
                SELECT RAISE(ABORT, 'lifecycle disclosure entries are immutable');
            END;
            """
        )
        connection.set_authorizer(_recovery_sqlite_authorizer)
        connection.commit()
        return connection


def assess_recovery_case(
    attack: FinancialRecoveryRuntimeResult,
    benign: FinancialRecoveryRuntimeResult,
) -> RecoveryCaseAssessment:
    """Compare a final-outcome baseline with the named restore control."""

    _validate_runtime_result_consistency(attack)
    _validate_runtime_result_consistency(benign)
    if attack.action_digest != ATTACK_ACTION_DIGEST:
        raise ValueError("attack result is not the fixed recovery attack retest")
    if benign.action_digest != BENIGN_ACTION_DIGEST:
        raise ValueError("benign result is not the fixed recovery service retest")
    if (
        attack.target_level,
        attack.guard_level,
        attack.sham_level,
    ) != (
        benign.target_level,
        benign.guard_level,
        benign.sham_level,
    ):
        raise ValueError("recovery assessment requires a matched attack/benign pair")
    if (
        attack.snapshot_digest != benign.snapshot_digest
        or attack.entitlement_set_digest != benign.entitlement_set_digest
        or attack.replacement_session_entitlement_set_digest
        != benign.replacement_session_entitlement_set_digest
        or attack.lifecycle_snapshot_digest != benign.lifecycle_snapshot_digest
        or attack.lifecycle_bundle_digest != benign.lifecycle_bundle_digest
    ):
        raise ValueError("matched recovery results disagree on restored state")
    if (
        attack.prior_disclosure_ledger_digest_before
        != benign.prior_disclosure_ledger_digest_before
        or attack.prior_disclosure_entry_ids_digest_before
        != benign.prior_disclosure_entry_ids_digest_before
        or attack.prior_admitted_disclosure_count_before
        != benign.prior_admitted_disclosure_count_before
    ):
        raise ValueError("matched results disagree on prior disclosure history")

    baseline_passes = (
        attack.out_of_scope_records_delivered == 0
        and benign.assigned_case_records_delivered == 1
    )
    target_supported = attack.out_of_scope_records_selected == 0
    cutover_supported = attack.cutover_fixture_valid and benign.cutover_fixture_valid
    release_guard_supported = attack.unapproved_release_blocked
    path_supported = attack.out_of_scope_records_delivered == 0
    benign_supported = benign.assigned_case_records_delivered == 1
    disclosure_preserved = (
        attack.prior_disclosure_reference_unchanged
        and benign.prior_disclosure_reference_unchanged
        and attack.prior_disclosure_ledger_digest_before
        == attack.prior_disclosure_ledger_digest_after
        == benign.prior_disclosure_ledger_digest_before
        == benign.prior_disclosure_ledger_digest_after
        and attack.prior_disclosure_entry_ids_digest_before
        == attack.prior_disclosure_entry_ids_digest_after
        == benign.prior_disclosure_entry_ids_digest_before
        == benign.prior_disclosure_entry_ids_digest_after
        and attack.prior_admitted_disclosure_count_before
        == attack.prior_admitted_disclosure_count_after
        == benign.prior_admitted_disclosure_count_before
        == benign.prior_admitted_disclosure_count_after
    )

    if (
        not target_supported
        and cutover_supported
        and release_guard_supported
        and path_supported
        and benign_supported
        and disclosure_preserved
        and attack.snapshot_reapply_receipt_valid
        and benign.snapshot_reapply_receipt_valid
        and attack.clone_cleanup_verified
        and benign.clone_cleanup_verified
    ):
        classification = RecoveryResidualClassification.MASKED_RESTORE_FAILURE
    elif not path_supported:
        classification = RecoveryResidualClassification.EXPOSED_PATH
    elif (
        target_supported
        and cutover_supported
        and path_supported
        and benign_supported
        and disclosure_preserved
        and attack.snapshot_reapply_receipt_valid
        and benign.snapshot_reapply_receipt_valid
        and attack.clone_cleanup_verified
        and benign.clone_cleanup_verified
    ):
        classification = RecoveryResidualClassification.TARGET_EFFECTIVE
    else:
        classification = RecoveryResidualClassification.UNRESOLVED

    prior_count = attack.prior_admitted_disclosure_count_before
    return RecoveryCaseAssessment(
        baseline=CurrentStateAndFinalOutcomeBaseline(
            name="current-state-and-final-outcome-only",
            verdict=(
                RecoveryBaselineVerdict.PASS
                if baseline_passes
                else RecoveryBaselineVerdict.FAIL
            ),
            out_of_scope_records_delivered=(
                attack.out_of_scope_records_delivered
            ),
            assigned_case_records_delivered=(
                benign.assigned_case_records_delivered
            ),
            prior_disclosure_ledger_digest_ignored=(
                attack.prior_disclosure_ledger_digest_before
            ),
            prior_admitted_disclosure_count_ignored=prior_count,
        ),
        target_supported=target_supported,
        cutover_fixture_supported=cutover_supported,
        release_guard_supported=release_guard_supported,
        path_supported=path_supported,
        benign_service_supported=benign_supported,
        prior_disclosure_history_preserved=disclosure_preserved,
        prior_disclosure_ledger_digest=(
            attack.prior_disclosure_ledger_digest_before
        ),
        prior_admitted_disclosure_count=prior_count,
        residual_classification=classification,
    )


def _validate_runtime_result_consistency(
    result: FinancialRecoveryRuntimeResult,
) -> None:
    _validate_trace_id(result.trace_id)
    expected_action = (
        action_descriptor(ATTACK)
        if result.input_level == ATTACK.value
        else action_descriptor(BENIGN)
        if result.input_level == BENIGN.value
        else None
    )
    if expected_action is None:
        raise ValueError("recovery result has an unknown input assignment")
    expected_requested = _required_text_list(
        expected_action,
        "requested_customer_ids",
    )
    expected_action_digest = _sha256(rfc8785.dumps(expected_action))
    if (
        result.action_digest != expected_action_digest
        or result.requested_customer_ids != expected_requested
    ):
        raise ValueError("recovery result is not bound to the fixed input action")

    target_value = (
        TARGET_INEFFECTIVE
        if result.target_level == TARGET_INEFFECTIVE.value
        else TARGET_EFFECTIVE
        if result.target_level == TARGET_EFFECTIVE.value
        else None
    )
    if (
        target_value is None
        or result.guard_level
        not in {COMPENSATOR_OFF.value, COMPENSATOR_ON.value}
        or result.sham_level not in {SHAM_STEADY.value, SHAM_REAPPLY.value}
    ):
        raise ValueError("recovery result has an unknown fixed selector assignment")
    expected_snapshot = snapshot_descriptor(target_value)
    expected_snapshot_canonical = rfc8785.dumps(expected_snapshot).decode(
        "utf-8"
    )
    expected_snapshot_digest = _sha256(
        expected_snapshot_canonical.encode("utf-8")
    )
    expected_snapshot_id = str(expected_snapshot["snapshot_id"])
    raw_expected_entitlement_set = expected_snapshot.get("entitlement_set")
    if not isinstance(raw_expected_entitlement_set, dict):
        raise RuntimeError("fixed recovery snapshot has no entitlement set")
    expected_entitlement_set_canonical = rfc8785.dumps(
        raw_expected_entitlement_set
    ).decode("utf-8")
    expected_entitlement_set_digest = _sha256(
        expected_entitlement_set_canonical.encode("utf-8")
    )
    if (
        result.snapshot_id != expected_snapshot_id
        or result.snapshot_digest != expected_snapshot_digest
        or result.entitlement_set_canonical
        != expected_entitlement_set_canonical
        or result.entitlement_set_digest != expected_entitlement_set_digest
        or not result.snapshot_identity_matches_declared_target
        or not result.snapshot_reapply_semantics_unchanged
        or not result.snapshot_reapply_receipt_valid
    ):
        raise ValueError(
            "recovery result is not the fixed recovery execution for its target"
        )
    if (
        result.old_session_id != OLD_SESSION_ID
        or result.replacement_session_id != REPLACEMENT_SESSION_ID
    ):
        raise ValueError("recovery result changed the fixed cutover identities")
    if (
        result.lifecycle_bound_branch_head_digest
        != result.lifecycle_snapshot_digest
    ):
        raise ValueError(
            "recovery result lifecycle branch head is not the cutover snapshot"
        )
    if (
        _sha256(result.lifecycle_snapshot_canonical.encode("utf-8"))
        != result.lifecycle_snapshot_digest
    ):
        raise ValueError("recovery result lifecycle snapshot digest is invalid")
    try:
        lifecycle_snapshot = IncidentSnapshot.model_validate_json(
            result.lifecycle_snapshot_canonical,
            strict=True,
        )
    except ValueError as error:
        raise ValueError(
            "recovery result lifecycle snapshot is invalid"
        ) from error
    if incident_snapshot_digest(lifecycle_snapshot) != result.lifecycle_snapshot_digest:
        raise ValueError("recovery result lifecycle snapshot is not content addressed")
    try:
        verified_lifecycle = VerifiedLifecycle.model_validate_json(
            result.verified_lifecycle_canonical,
            strict=True,
        )
    except ValueError as error:
        raise ValueError(
            "recovery result verified lifecycle is invalid"
        ) from error
    if (
        _sha256(result.verified_lifecycle_canonical.encode("utf-8"))
        != result.verified_lifecycle_digest
    ):
        raise ValueError(
            "recovery result verified lifecycle digest is invalid"
        )
    result_fixture = LifecycleCutoverFixture(
        lifecycle_bundle_digest=result.lifecycle_bundle_digest,
        lifecycle_bundle_root=result.lifecycle_bundle_root,
        bundle_verification=result.lifecycle_bundle_verification,
        session_rotation_transition_id=result.session_rotation_transition_id,
        target_snapshot_digest=result.snapshot_digest,
        old_session_id=result.old_session_id,
        replacement_session_id=result.replacement_session_id,
        snapshot=lifecycle_snapshot,
        verified_lifecycle=verified_lifecycle,
    )
    _validate_lifecycle_bundle_reference(
        result_fixture,
        target_level=result.target_level,
    )
    _validate_cutover_fixture(
        result_fixture,
        target_level=result.target_level,
    )
    if (
        _CLONE_NONCE.fullmatch(result.clone_nonce) is None
        or _DIGEST.fullmatch(result.clone_id) is None
        or result.clone_storage_kind != "sqlite-memory"
        or not result.clone_cleanup_verified
    ):
        raise ValueError("recovery result clone identity or cleanup claim is invalid")
    expected_clone_readback = CloneReadback(
        clone_id=result.clone_id,
        clone_nonce=result.clone_nonce,
        trace_id=result.trace_id,
        storage_kind=result.clone_storage_kind,
    )
    (
        expected_clone_readback_canonical,
        expected_clone_readback_digest,
    ) = _clone_readback_evidence(expected_clone_readback)
    if (
        result.clone_readback_canonical
        != expected_clone_readback_canonical
        or result.clone_readback_digest != expected_clone_readback_digest
        or _sha256(result.clone_readback_canonical.encode("utf-8"))
        != result.clone_readback_digest
    ):
        raise ValueError(
            "recovery result clone identity is not bound to its "
            "persisted run-control readback"
        )
    result_selector = CellSelector(
        input=ATTACK if result.input_level == ATTACK.value else BENIGN,
        target=target_value,
        compensator=(
            COMPENSATOR_ON
            if result.guard_level == COMPENSATOR_ON.value
            else COMPENSATOR_OFF
        ),
        sham=(
            SHAM_REAPPLY
            if result.sham_level == SHAM_REAPPLY.value
            else SHAM_STEADY
        ),
    )
    if (
        result.clone_id
        != _clone_id(
            result.trace_id,
            result_selector,
            result_fixture,
            result.clone_nonce,
        )
    ):
        raise ValueError(
            "recovery result clone id does not reproduce its fixed selector, "
            "nonce, lifecycle, and storage identity"
        )
    expected_cutover = (
        result.old_session_state == RecoverySessionState.REVOKED
        and result.old_session_revoked
        and result.replacement_session_state == RecoverySessionState.ACTIVE
        and result.replacement_session_active
        and result.replacement_session_entitlement_set_digest
        == result.entitlement_set_digest
        and result.replacement_session_entitlement_digest_bound
    )
    if result.cutover_fixture_valid != expected_cutover:
        raise ValueError("recovery result cutover claim contradicts its raw fields")
    if (
        _sha256(result.entitlement_set_canonical.encode("utf-8"))
        != result.entitlement_set_digest
    ):
        raise ValueError("recovery result entitlement-set digest is invalid")
    if (
        _sha256(
            result.snapshot_reapply_mutation_rows_canonical.encode("utf-8")
        )
        != result.snapshot_reapply_mutation_rows_digest
    ):
        raise ValueError("recovery result snapshot-mutation digest is invalid")
    mutation_set = _canonical_object(
        result.snapshot_reapply_mutation_rows_canonical,
        label="snapshot apply mutations",
    )
    raw_mutations = mutation_set.get("mutations")
    if (
        mutation_set.get("schema")
        != "assurance-lab.snapshot-apply-mutation-set/v1"
        or mutation_set.get("trace_id") != result.trace_id
        or not isinstance(raw_mutations, list)
    ):
        raise ValueError("recovery result snapshot mutations have invalid structure")
    expects_reapply = result.sham_level == SHAM_REAPPLY.value
    admitted_apply_receipt = (
        SnapshotApplyReceipt(
            operation_id=result.snapshot_reapply_operation_id,
            target_level=result.target_level,
            before_snapshot_canonical=expected_snapshot_canonical,
            before_snapshot_digest=expected_snapshot_digest,
            after_snapshot_canonical=expected_snapshot_canonical,
            after_snapshot_digest=expected_snapshot_digest,
            snapshot_rows_deleted=(
                result.snapshot_reapply_snapshot_rows_deleted
            ),
            entitlement_rows_deleted=(
                result.snapshot_reapply_entitlement_rows_deleted
            ),
            snapshot_rows_inserted=(
                result.snapshot_reapply_snapshot_rows_inserted
            ),
            entitlement_rows_inserted=(
                result.snapshot_reapply_entitlement_rows_inserted
            ),
            mutation_rows_canonical=(
                result.snapshot_reapply_mutation_rows_canonical
            ),
            mutation_rows_digest=result.snapshot_reapply_mutation_rows_digest,
        )
        if result.snapshot_reapply_operation_id is not None
        else None
    )
    expected_entitlement_rows = (
        len(STALE_ENTITLEMENTS)
        if target_value == TARGET_INEFFECTIVE
        else len(APPROVED_ENTITLEMENTS)
    )
    if (
        result.snapshot_reapply_performed != expects_reapply
        or (result.snapshot_reapply_operation_id is not None) != expects_reapply
        or bool(raw_mutations) != expects_reapply
        or mutation_set.get("operation_id")
        != result.snapshot_reapply_operation_id
        or not _validate_snapshot_apply_receipt(
            receipt=admitted_apply_receipt,
            trace_id=result.trace_id,
            sham_level=result.sham_level,
            target_level=result.target_level,
            before_snapshot_canonical=expected_snapshot_canonical,
            before_snapshot_digest=expected_snapshot_digest,
            after_snapshot_canonical=expected_snapshot_canonical,
            after_snapshot_digest=expected_snapshot_digest,
            expected_entitlement_rows=expected_entitlement_rows,
        )
    ):
        raise ValueError(
            "recovery result snapshot apply receipt does not reproduce "
            "the fixed mutation operation"
        )
    if not expects_reapply and (
        result.snapshot_reapply_snapshot_rows_deleted != 0
        or result.snapshot_reapply_entitlement_rows_deleted != 0
        or result.snapshot_reapply_snapshot_rows_inserted != 0
        or result.snapshot_reapply_entitlement_rows_inserted != 0
        or result.snapshot_reapply_mutation_rows_canonical
        != _empty_snapshot_apply_mutations(trace_id=result.trace_id)
    ):
        raise ValueError(
            "recovery result steady sham contains snapshot apply evidence"
        )

    if (
        _sha256(result.assignment_basis_canonical.encode("utf-8"))
        != result.assignment_basis_digest
    ):
        raise ValueError("recovery result assignment-basis digest is invalid")
    assignment_basis = _canonical_object(
        result.assignment_basis_canonical,
        label="assignment basis",
    )
    raw_assignments = assignment_basis.get("assignments")
    if (
        assignment_basis.get("schema")
        != "assurance-lab.active-support-assignment-set/v1"
        or assignment_basis.get("principal_id") != PRINCIPAL_ID
        or not isinstance(raw_assignments, list)
    ):
        raise ValueError("recovery result assignment basis has invalid structure")
    assigned_from_rows: list[str] = []
    for raw_assignment in raw_assignments:
        if (
            not isinstance(raw_assignment, dict)
            or set(raw_assignment)
            != {"case_id", "customer_id", "principal_id", "status"}
            or raw_assignment.get("principal_id") != PRINCIPAL_ID
            or raw_assignment.get("status") != "active"
            or not isinstance(raw_assignment.get("case_id"), str)
            or not isinstance(raw_assignment.get("customer_id"), str)
        ):
            raise ValueError("recovery result assignment basis contains an invalid row")
        assigned_from_rows.append(str(raw_assignment["customer_id"]))
    if tuple(sorted(set(assigned_from_rows))) != result.assigned_customer_ids:
        raise ValueError(
            "recovery result assigned-customer set is not derived from assignment rows"
        )

    if (
        _sha256(result.delivery_receipts_canonical.encode("utf-8"))
        != result.delivery_receipts_digest
    ):
        raise ValueError("recovery result delivery-receipt digest is invalid")
    receipt_set = _canonical_object(
        result.delivery_receipts_canonical,
        label="delivery receipt set",
    )
    raw_receipts = receipt_set.get("receipts")
    if (
        receipt_set.get("schema")
        != "assurance-lab.recovery-delivery-receipt-set/v1"
        or not isinstance(raw_receipts, list)
    ):
        raise ValueError("recovery result delivery receipts have invalid structure")
    expected_request_id = _required_text(expected_action, "request_id")
    delivered_from_receipts: list[str] = []
    for raw_receipt in raw_receipts:
        if (
            not isinstance(raw_receipt, dict)
            or set(raw_receipt)
            != {"receipt_id", "trace_id", "request_id", "customer_id"}
            or raw_receipt.get("trace_id") != result.trace_id
            or raw_receipt.get("request_id") != expected_request_id
            or not isinstance(raw_receipt.get("customer_id"), str)
        ):
            raise ValueError("recovery result contains an invalid delivery receipt")
        customer_id = str(raw_receipt["customer_id"])
        expected_receipt_id = _delivery_receipt_id(
            trace_id=result.trace_id,
            request_id=expected_request_id,
            customer_id=customer_id,
        )
        if raw_receipt.get("receipt_id") != expected_receipt_id:
            raise ValueError("recovery result delivery receipt id is invalid")
        delivered_from_receipts.append(customer_id)
    if tuple(delivered_from_receipts) != result.delivered_customer_ids:
        raise ValueError(
            "recovery result delivered-customer set is not derived from receipts"
        )

    assigned = set(result.assigned_customer_ids)
    expected_selected_outside = tuple(
        customer_id
        for customer_id in result.selected_customer_ids
        if customer_id not in assigned
    )
    expected_delivered_outside = tuple(
        customer_id
        for customer_id in result.delivered_customer_ids
        if customer_id not in assigned
    )
    expected_delivered_assigned = tuple(
        customer_id
        for customer_id in result.delivered_customer_ids
        if customer_id in assigned
    )
    if (
        result.selected_out_of_scope_customer_ids != expected_selected_outside
        or result.out_of_scope_records_selected != len(expected_selected_outside)
        or result.delivered_out_of_scope_customer_ids
        != expected_delivered_outside
        or result.out_of_scope_records_delivered != len(expected_delivered_outside)
        or result.delivered_assigned_customer_ids != expected_delivered_assigned
        or result.assigned_case_records_delivered
        != len(expected_delivered_assigned)
        or not set(result.delivered_customer_ids).issubset(
            result.selected_customer_ids
        )
    ):
        raise ValueError("recovery result sets do not reproduce their scope metrics")
    expected_blocked = (
        result.release_guard_reached
        and result.release_decision == RecoveryReleaseDecision.BLOCK
        and bool(expected_selected_outside)
        and not expected_delivered_outside
    )
    if result.unapproved_release_blocked != expected_blocked:
        raise ValueError("release-guard claim contradicts delivery receipt rows")

    for canonical, digest, label in (
        (
            result.prior_disclosure_ledger_canonical_before,
            result.prior_disclosure_ledger_digest_before,
            "before disclosure ledger",
        ),
        (
            result.prior_disclosure_ledger_canonical_after,
            result.prior_disclosure_ledger_digest_after,
            "after disclosure ledger",
        ),
        (
            result.prior_disclosure_entry_ids_canonical_before,
            result.prior_disclosure_entry_ids_digest_before,
            "before disclosure entry ids",
        ),
        (
            result.prior_disclosure_entry_ids_canonical_after,
            result.prior_disclosure_entry_ids_digest_after,
            "after disclosure entry ids",
        ),
    ):
        if _sha256(canonical.encode("utf-8")) != digest:
            raise ValueError(f"recovery result {label} digest is invalid")
    expected_ledger_canonical = canonical_json_bytes(
        lifecycle_snapshot.disclosure_ledger.model_dump(mode="json")
    ).decode("utf-8")
    expected_entry_ids = tuple(
        _sha256(canonical_json_bytes(entry.model_dump(mode="json")))
        for entry in lifecycle_snapshot.disclosure_ledger.entries
    )
    expected_entry_ids_canonical, expected_entry_ids_digest = (
        _identifier_set_evidence(
            "lifecycle-disclosure-entry-id-set",
            expected_entry_ids,
        )
    )
    if (
        result.prior_disclosure_ledger_canonical_before
        != expected_ledger_canonical
        or result.prior_disclosure_ledger_canonical_after
        != expected_ledger_canonical
        or result.prior_disclosure_entry_ids_canonical_before
        != expected_entry_ids_canonical
        or result.prior_disclosure_entry_ids_canonical_after
        != expected_entry_ids_canonical
        or result.prior_disclosure_entry_ids_digest_before
        != expected_entry_ids_digest
        or result.prior_disclosure_entry_ids_digest_after
        != expected_entry_ids_digest
        or result.prior_admitted_disclosure_count_before
        != len(expected_entry_ids)
        or result.prior_admitted_disclosure_count_after
        != len(expected_entry_ids)
    ):
        raise ValueError(
            "disclosure history is not bound to the lifecycle snapshot"
        )
    reference_unchanged = (
        result.prior_disclosure_ledger_canonical_before
        == result.prior_disclosure_ledger_canonical_after
        and result.prior_disclosure_ledger_digest_before
        == result.prior_disclosure_ledger_digest_after
        and result.prior_disclosure_entry_ids_canonical_before
        == result.prior_disclosure_entry_ids_canonical_after
        and result.prior_disclosure_entry_ids_digest_before
        == result.prior_disclosure_entry_ids_digest_after
        and result.prior_admitted_disclosure_count_before
        == result.prior_admitted_disclosure_count_after
    )
    if result.prior_disclosure_reference_unchanged != reference_unchanged:
        raise ValueError("disclosure-reference claim contradicts its exact references")
    _validate_fixed_execution_semantics(result)
    _validate_runtime_event_receipts(
        result,
        action=expected_action,
    )


def _validate_fixed_execution_semantics(
    result: FinancialRecoveryRuntimeResult,
) -> None:
    """Recompute the fixed trial from its contracted input and target.

    This deliberately does not accept a mutually consistent rewrite of the
    selected rows, delivery receipts, counters, and event payloads.  Those are
    observations of one named deterministic experiment, so the assessment
    admits them only when they also reproduce that experiment's fixed
    entitlement and release semantics.
    """

    if result.target_level == TARGET_INEFFECTIVE.value:
        expected_authorized = True
        expected_selected = result.requested_customer_ids
    else:
        expected_authorized = all(
            customer_id == APPROVED_CUSTOMER_ID
            for customer_id in result.requested_customer_ids
        )
        expected_selected = (
            result.requested_customer_ids if expected_authorized else ()
        )

    expected_selected_outside = tuple(
        customer_id
        for customer_id in expected_selected
        if customer_id != APPROVED_CUSTOMER_ID
    )
    if not expected_authorized:
        expected_guard_reached = False
        expected_decision = RecoveryReleaseDecision.NOT_REACHED
        expected_reason = "restored-entitlement-denied"
    else:
        expected_guard_reached = True
        should_block = (
            result.guard_level == COMPENSATOR_ON.value
            and bool(expected_selected_outside)
        )
        expected_decision = (
            RecoveryReleaseDecision.BLOCK
            if should_block
            else RecoveryReleaseDecision.ALLOW
        )
        if should_block:
            expected_reason = "unapproved-or-bulk-export"
        elif expected_selected_outside:
            expected_reason = "monitor-only-observation"
        else:
            expected_reason = "approved-assigned-case"
    expected_delivered = (
        expected_selected
        if expected_decision == RecoveryReleaseDecision.ALLOW
        else ()
    )
    expected_delivered_outside = tuple(
        customer_id
        for customer_id in expected_delivered
        if customer_id != APPROVED_CUSTOMER_ID
    )
    expected_delivered_assigned = tuple(
        customer_id
        for customer_id in expected_delivered
        if customer_id == APPROVED_CUSTOMER_ID
    )
    expected_blocked = (
        expected_guard_reached
        and expected_decision == RecoveryReleaseDecision.BLOCK
        and bool(expected_selected_outside)
        and not expected_delivered_outside
    )
    if (
        result.snapshot_authorized_action != expected_authorized
        or result.selected_customer_ids != expected_selected
        or result.selected_out_of_scope_customer_ids
        != expected_selected_outside
        or result.out_of_scope_records_selected
        != len(expected_selected_outside)
        or result.release_guard_reached != expected_guard_reached
        or result.release_decision != expected_decision
        or result.release_reason != expected_reason
        or result.delivered_customer_ids != expected_delivered
        or result.delivered_out_of_scope_customer_ids
        != expected_delivered_outside
        or result.delivered_assigned_customer_ids
        != expected_delivered_assigned
        or result.out_of_scope_records_delivered
        != len(expected_delivered_outside)
        or result.assigned_case_records_delivered
        != len(expected_delivered_assigned)
        or result.unapproved_release_blocked != expected_blocked
    ):
        raise ValueError(
            "recovery result does not reproduce the fixed recovery execution"
        )


def _validate_runtime_event_receipts(
    result: FinancialRecoveryRuntimeResult,
    *,
    action: dict[str, Any],
) -> None:
    """Require the admitted event stream to exactly reproduce all readbacks."""

    lifecycle_before = LifecycleReferenceReadback(
        lifecycle_bundle_digest=result.lifecycle_bundle_digest,
        lifecycle_snapshot_canonical=result.lifecycle_snapshot_canonical,
        lifecycle_snapshot_digest=result.lifecycle_snapshot_digest,
        session_rotation_transition_id=result.session_rotation_transition_id,
        branch_id=result.lifecycle_branch_id,
        branch_kind=result.lifecycle_branch_kind,
        bound_branch_head_digest=result.lifecycle_bound_branch_head_digest,
        verified_lifecycle_canonical=result.verified_lifecycle_canonical,
        verified_lifecycle_digest=result.verified_lifecycle_digest,
        disclosure_ledger_canonical=(
            result.prior_disclosure_ledger_canonical_before
        ),
        disclosure_ledger_digest=result.prior_disclosure_ledger_digest_before,
        disclosure_entry_ids_canonical=(
            result.prior_disclosure_entry_ids_canonical_before
        ),
        disclosure_entry_ids_digest=(
            result.prior_disclosure_entry_ids_digest_before
        ),
        disclosure_entry_count=result.prior_admitted_disclosure_count_before,
    )
    lifecycle_after = LifecycleReferenceReadback(
        lifecycle_bundle_digest=result.lifecycle_bundle_digest,
        lifecycle_snapshot_canonical=result.lifecycle_snapshot_canonical,
        lifecycle_snapshot_digest=result.lifecycle_snapshot_digest,
        session_rotation_transition_id=result.session_rotation_transition_id,
        branch_id=result.lifecycle_branch_id,
        branch_kind=result.lifecycle_branch_kind,
        bound_branch_head_digest=result.lifecycle_bound_branch_head_digest,
        verified_lifecycle_canonical=result.verified_lifecycle_canonical,
        verified_lifecycle_digest=result.verified_lifecycle_digest,
        disclosure_ledger_canonical=(
            result.prior_disclosure_ledger_canonical_after
        ),
        disclosure_ledger_digest=result.prior_disclosure_ledger_digest_after,
        disclosure_entry_ids_canonical=(
            result.prior_disclosure_entry_ids_canonical_after
        ),
        disclosure_entry_ids_digest=(
            result.prior_disclosure_entry_ids_digest_after
        ),
        disclosure_entry_count=result.prior_admitted_disclosure_count_after,
    )
    snapshot_canonical = rfc8785.dumps(
        snapshot_descriptor(
            TARGET_INEFFECTIVE
            if result.target_level == TARGET_INEFFECTIVE.value
            else TARGET_EFFECTIVE
        )
    ).decode("utf-8")
    apply_receipt = (
        SnapshotApplyReceipt(
            operation_id=result.snapshot_reapply_operation_id,
            target_level=result.target_level,
            before_snapshot_canonical=snapshot_canonical,
            before_snapshot_digest=result.snapshot_digest,
            after_snapshot_canonical=snapshot_canonical,
            after_snapshot_digest=result.snapshot_digest,
            snapshot_rows_deleted=(
                result.snapshot_reapply_snapshot_rows_deleted
            ),
            entitlement_rows_deleted=(
                result.snapshot_reapply_entitlement_rows_deleted
            ),
            snapshot_rows_inserted=(
                result.snapshot_reapply_snapshot_rows_inserted
            ),
            entitlement_rows_inserted=(
                result.snapshot_reapply_entitlement_rows_inserted
            ),
            mutation_rows_canonical=(
                result.snapshot_reapply_mutation_rows_canonical
            ),
            mutation_rows_digest=result.snapshot_reapply_mutation_rows_digest,
        )
        if result.snapshot_reapply_operation_id is not None
        else None
    )
    expected_events = _events(
        trace_id=result.trace_id,
        clone_id=result.clone_id,
        clone_nonce=result.clone_nonce,
        clone_storage_kind=result.clone_storage_kind,
        clone_readback_canonical=result.clone_readback_canonical,
        clone_readback_digest=result.clone_readback_digest,
        clone_cleanup_verified=result.clone_cleanup_verified,
        action=action,
        action_canonical=rfc8785.dumps(action).decode("utf-8"),
        action_digest=result.action_digest,
        requested_ids=result.requested_customer_ids,
        lifecycle_before=lifecycle_before,
        lifecycle_after=lifecycle_after,
        old_state=result.old_session_state,
        replacement_state=result.replacement_session_state,
        replacement_binding_digest=(
            result.replacement_session_entitlement_set_digest
        ),
        replacement_binding_valid=(
            result.replacement_session_entitlement_digest_bound
        ),
        cutover_valid=result.cutover_fixture_valid,
        target_level=result.target_level,
        snapshot_id=result.snapshot_id,
        snapshot_canonical=snapshot_canonical,
        snapshot_digest=result.snapshot_digest,
        entitlement_set_canonical=result.entitlement_set_canonical,
        entitlement_set_digest=result.entitlement_set_digest,
        snapshot_identity_matches=(
            result.snapshot_identity_matches_declared_target
        ),
        snapshot_reapply_performed=result.snapshot_reapply_performed,
        snapshot_reapply_receipt_valid=(
            result.snapshot_reapply_receipt_valid
        ),
        apply_receipt=apply_receipt,
        before_reapply_digest=result.snapshot_digest,
        after_reapply_digest=result.snapshot_digest,
        snapshot_reapply_unchanged=(
            result.snapshot_reapply_semantics_unchanged
        ),
        snapshot_authorized=result.snapshot_authorized_action,
        assigned_ids=result.assigned_customer_ids,
        assignment_readback=AssignmentReadback(
            customer_ids=result.assigned_customer_ids,
            canonical=result.assignment_basis_canonical,
            digest=result.assignment_basis_digest,
        ),
        selected_ids=result.selected_customer_ids,
        selected_outside_ids=result.selected_out_of_scope_customer_ids,
        guard_level=result.guard_level,
        guard_reached=result.release_guard_reached,
        release_decision=result.release_decision,
        release_reason=result.release_reason,
        unapproved_release_blocked=result.unapproved_release_blocked,
        delivered_ids=result.delivered_customer_ids,
        delivery_readback=DeliveryReceiptReadback(
            customer_ids=result.delivered_customer_ids,
            canonical=result.delivery_receipts_canonical,
            digest=result.delivery_receipts_digest,
        ),
        delivered_outside_ids=result.delivered_out_of_scope_customer_ids,
        assigned_delivered_ids=result.delivered_assigned_customer_ids,
    )
    if result.events != expected_events:
        raise ValueError(
            "recovery result events do not reproduce the admitted runtime readbacks"
        )


def _validate_fixture(dataset: SyntheticDataset) -> None:
    active_support = {
        principal.principal_id
        for principal in dataset.principals
        if principal.role == "support" and principal.status == "active"
    }
    if PRINCIPAL_ID not in active_support:
        raise ValueError(f"fixture does not contain active principal {PRINCIPAL_ID}")
    assignments = {
        (support_case.case_id, support_case.customer_id)
        for support_case in dataset.support_cases
        if support_case.assigned_principal_id == PRINCIPAL_ID
        and support_case.status == "active"
    }
    if (APPROVED_CASE_ID, APPROVED_CUSTOMER_ID) not in assignments:
        raise ValueError("fixture does not contain the fixed approved support case")
    customer_ids = {customer.customer_id for customer in dataset.customers}
    required = set(_required_text_list(action_descriptor(ATTACK), "requested_customer_ids"))
    required.update(
        _required_text_list(action_descriptor(BENIGN), "requested_customer_ids")
    )
    if not required.issubset(customer_ids):
        raise ValueError("fixture is missing a customer required by a fixed action")


def _validate_cutover_fixture(
    fixture: LifecycleCutoverFixture,
    *,
    target_level: str,
) -> None:
    if not _BUNDLE_ID.fullmatch(fixture.lifecycle_bundle_digest):
        raise ValueError("lifecycle bundle digest is not a content-addressed bundle id")
    if not _DIGEST.fullmatch(fixture.session_rotation_transition_id):
        raise ValueError("session rotation transition id is not a sha256 digest")
    if not _DIGEST.fullmatch(fixture.target_snapshot_digest):
        raise ValueError("target snapshot digest is not a sha256 digest")
    if fixture.old_session_id != OLD_SESSION_ID:
        raise ValueError("cutover fixture does not bind the fixed old session")
    if fixture.replacement_session_id != REPLACEMENT_SESSION_ID:
        raise ValueError("cutover fixture does not bind the fixed replacement session")

    snapshot = fixture.snapshot
    target_value = (
        TARGET_INEFFECTIVE
        if target_level == TARGET_INEFFECTIVE.value
        else TARGET_EFFECTIVE
        if target_level == TARGET_EFFECTIVE.value
        else None
    )
    if target_value is None:
        raise ValueError(f"unsupported cutover target level: {target_level!r}")
    expected_branch = (
        BranchKind.ACTUAL
        if target_value == TARGET_INEFFECTIVE
        else BranchKind.MATCHED_COMPARISON
    )
    expected_entitlement_digest = (
        STALE_ENTITLEMENT_SET_DIGEST
        if target_value == TARGET_INEFFECTIVE
        else APPROVED_ENTITLEMENT_SET_DIGEST
    )
    expected_snapshot_digest = (
        STALE_SNAPSHOT_DIGEST
        if target_value == TARGET_INEFFECTIVE
        else APPROVED_SNAPSHOT_DIGEST
    )
    if snapshot.phase != LifecyclePhase.SESSION_ROTATED:
        raise ValueError("cutover fixture must reference the session_rotated snapshot")
    if snapshot.branch_kind != expected_branch:
        raise ValueError("cutover fixture branch does not match the target assignment")
    if snapshot.principal_id != PRINCIPAL_ID:
        raise ValueError("cutover fixture principal does not match the recovery subject")
    if snapshot.compromised_session_state != CompromisedSessionState.REVOKED:
        raise ValueError("cutover fixture does not show the old session revoked")
    if snapshot.replacement_session_state != ReplacementSessionState.ACTIVE:
        raise ValueError("cutover fixture does not show an active replacement session")
    if snapshot.compromised_session_digest != _session_identity_digest(
        fixture.old_session_id
    ):
        raise ValueError("old session id is not bound to the lifecycle session digest")
    if snapshot.replacement_session_digest != _session_identity_digest(
        fixture.replacement_session_id
    ):
        raise ValueError(
            "replacement session id is not bound to the lifecycle session digest"
        )
    if (
        snapshot.entitlement_set_digest != expected_entitlement_digest
        or snapshot.replacement_entitlement_digest != expected_entitlement_digest
    ):
        raise ValueError(
            "lifecycle cutover entitlement digest does not match the target assignment"
        )
    if fixture.target_snapshot_digest != expected_snapshot_digest:
        raise ValueError("lifecycle fixture points at the wrong recovery target snapshot")
    verified = fixture.verified_lifecycle
    snapshot_digest = incident_snapshot_digest(snapshot)
    if verified.incident_id != snapshot.incident_id:
        raise ValueError("verified lifecycle and cutover snapshot incidents differ")
    if verified.current_snapshot_digest != verified.actual_head_digest:
        raise ValueError(
            "verified lifecycle current state is not its actual branch head"
        )
    if expected_branch == BranchKind.ACTUAL:
        if (
            verified.current_snapshot_digest != snapshot_digest
            or verified.actual_head_digest != snapshot_digest
            or fixture.session_rotation_transition_id
            not in verified.actual_transition_ids
        ):
            raise ValueError(
                "actual cutover snapshot is not the verified lifecycle current head"
            )
    elif (
        verified.matched_comparison_head_digest != snapshot_digest
        or fixture.session_rotation_transition_id
        not in verified.matched_comparison_transition_ids
    ):
        raise ValueError(
            "comparison cutover snapshot is not the verified lifecycle comparison head"
        )
    _validate_lifecycle_bundle_reference(
        fixture,
        target_level=target_level,
    )


def lifecycle_cutover_bundle_payloads(
    *,
    target_level: str,
    session_rotation_transition_id: str,
    target_snapshot_digest: str,
    old_session_id: str,
    replacement_session_id: str,
    snapshot: IncidentSnapshot,
    verified_lifecycle: VerifiedLifecycle,
) -> dict[str, bytes]:
    """Return the exact canonical payloads a lifecycle CAB must contain.

    The function makes the producer/consumer boundary explicit: a lifecycle
    bundle builder can use these bytes, and the recovery runtime later compares
    the verified manifest descriptors to the same bytes.  It is an integrity
    binding, not a second execution of ``verify_lifecycle``.
    """

    if target_level not in {
        TARGET_INEFFECTIVE.value,
        TARGET_EFFECTIVE.value,
    }:
        raise ValueError(f"unsupported cutover target level: {target_level!r}")
    snapshot_digest = incident_snapshot_digest(snapshot)
    bound_branch_head_digest = (
        verified_lifecycle.actual_head_digest
        if snapshot.branch_kind == BranchKind.ACTUAL
        else verified_lifecycle.matched_comparison_head_digest
    )
    cutover_reference = {
        "schema": "assurance-lab.lifecycle-cutover-reference/v1",
        "target_level": target_level,
        "target_snapshot_digest": target_snapshot_digest,
        "lifecycle_snapshot_digest": snapshot_digest,
        "session_rotation_transition_id": session_rotation_transition_id,
        "branch_id": snapshot.branch_id,
        "branch_kind": snapshot.branch_kind.value,
        "bound_branch_head_digest": bound_branch_head_digest,
        "old_session_id": old_session_id,
        "old_session_digest": snapshot.compromised_session_digest,
        "replacement_session_id": replacement_session_id,
        "replacement_session_digest": snapshot.replacement_session_digest,
        "replacement_entitlement_digest": (
            snapshot.replacement_entitlement_digest
        ),
    }
    prefix = f"records/lifecycle/{target_level}"
    return {
        f"{prefix}/cutover-reference.json": canonical_json_bytes(
            cutover_reference
        ),
        f"{prefix}/cutover-snapshot.json": canonical_json_bytes(
            snapshot.model_dump(mode="json")
        ),
        _LIFECYCLE_VERIFIER_OUTPUT_PATH: canonical_json_bytes(
            verified_lifecycle.model_dump(mode="json")
        ),
    }


def _validate_cutover_fixture_bundle_sets(
    fixtures: Mapping[str, LifecycleCutoverFixture],
) -> None:
    groups: dict[tuple[Path, str], list[tuple[str, LifecycleCutoverFixture]]] = {}
    for target_level, fixture in fixtures.items():
        key = (fixture.lifecycle_bundle_root, fixture.lifecycle_bundle_digest)
        groups.setdefault(key, []).append((target_level, fixture))

    if len(groups) != 1:
        raise ValueError(
            "recovery target contrast requires one shared lifecycle CAB"
        )

    for (root, _bundle_id), members in groups.items():
        verification = verify_bundle(root)
        manifest = verification.manifest
        if (
            verification.status != BundleStatus.INTEGRITY_VERIFIED
            or verification.issues
            or manifest is None
        ):
            raise ValueError("lifecycle fixture group is not an intact CAB")
        expected_paths: set[str] = set()
        for target_level, fixture in members:
            expected_paths.update(
                lifecycle_cutover_bundle_payloads(
                    target_level=target_level,
                    session_rotation_transition_id=(
                        fixture.session_rotation_transition_id
                    ),
                    target_snapshot_digest=fixture.target_snapshot_digest,
                    old_session_id=fixture.old_session_id,
                    replacement_session_id=fixture.replacement_session_id,
                    snapshot=fixture.snapshot,
                    verified_lifecycle=fixture.verified_lifecycle,
                )
            )
        observed_paths = {descriptor.path for descriptor in manifest.files}
        if observed_paths != expected_paths:
            raise ValueError(
                "lifecycle CAB payload set differs from its fixture declarations"
            )


def _validate_lifecycle_bundle_reference(
    fixture: LifecycleCutoverFixture,
    *,
    target_level: str,
) -> None:
    root = fixture.lifecycle_bundle_root
    if not root.is_absolute() or not root.is_dir():
        raise ValueError(
            "lifecycle bundle root must be an existing absolute directory"
        )
    verification = verify_bundle(root)
    if verification != fixture.bundle_verification:
        raise ValueError(
            "supplied lifecycle bundle verification differs from fresh verification"
        )
    manifest = verification.manifest
    if (
        verification.status != BundleStatus.INTEGRITY_VERIFIED
        or verification.issues
        or verification.bundle_id is None
        or manifest is None
    ):
        raise ValueError(
            "cutover fixture requires an integrity-verified lifecycle CAB"
        )
    if (
        verification.bundle_id != fixture.lifecycle_bundle_digest
        or manifest.bundle_id() != fixture.lifecycle_bundle_digest
    ):
        raise ValueError(
            "lifecycle bundle digest does not match the verified manifest"
        )

    descriptors = {descriptor.path: descriptor for descriptor in manifest.files}
    expected_payloads = lifecycle_cutover_bundle_payloads(
        target_level=target_level,
        session_rotation_transition_id=fixture.session_rotation_transition_id,
        target_snapshot_digest=fixture.target_snapshot_digest,
        old_session_id=fixture.old_session_id,
        replacement_session_id=fixture.replacement_session_id,
        snapshot=fixture.snapshot,
        verified_lifecycle=fixture.verified_lifecycle,
    )
    for path, payload in expected_payloads.items():
        descriptor = descriptors.get(path)
        if descriptor is None:
            raise ValueError(
                f"verified lifecycle CAB is missing exact payload {path!r}"
            )
        _validate_lifecycle_bundle_file(
            descriptor,
            payload=payload,
            expected_role=_lifecycle_payload_role(path),
        )
        try:
            observed_payload = (root / path).read_bytes()
        except OSError as error:
            raise ValueError(
                f"verified lifecycle CAB payload cannot be read: {path!r}"
            ) from error
        if observed_payload != payload:
            raise ValueError(
                f"verified lifecycle CAB payload bytes are rebound: {path!r}"
            )

    post_read_verification = verify_bundle(root)
    if post_read_verification != verification:
        raise ValueError("lifecycle CAB changed while its payloads were read")


def _validate_lifecycle_bundle_file(
    descriptor: BundleFile,
    *,
    payload: bytes,
    expected_role: str,
) -> None:
    if (
        descriptor.sha256 != hashlib.sha256(payload).hexdigest()
        or descriptor.size != len(payload)
        or descriptor.media_type != "application/json"
        or descriptor.role != expected_role
        or descriptor.sensitivity != Sensitivity.SYNTHETIC
        or descriptor.required_for != [_LIFECYCLE_BUNDLE_REQUIRED_FOR]
    ):
        raise ValueError(
            f"verified lifecycle CAB descriptor is rebound: {descriptor.path!r}"
        )


def _lifecycle_payload_role(path: str) -> str:
    if path == _LIFECYCLE_VERIFIER_OUTPUT_PATH:
        return "lifecycle-verifier-output"
    if path.endswith("/cutover-snapshot.json"):
        return "lifecycle-cutover-snapshot"
    if path.endswith("/cutover-reference.json"):
        return "lifecycle-cutover-reference"
    raise ValueError(f"unknown lifecycle payload path: {path!r}")


def _fixture_bound_branch_head_digest(
    fixture: LifecycleCutoverFixture,
) -> str:
    if fixture.snapshot.branch_kind == BranchKind.ACTUAL:
        return fixture.verified_lifecycle.actual_head_digest
    if fixture.snapshot.branch_kind == BranchKind.MATCHED_COMPARISON:
        return fixture.verified_lifecycle.matched_comparison_head_digest
    raise ValueError("cutover fixture uses an unsupported lifecycle branch")


def _validate_trace_id(trace_id: str) -> None:
    if not _TRACE_ID.fullmatch(trace_id):
        raise ValueError("trace_id must be 1-128 safe identifier characters")


def _session_identity_digest(session_id: str) -> str:
    if session_id == OLD_SESSION_ID:
        return OLD_SESSION_DIGEST
    if session_id == REPLACEMENT_SESSION_ID:
        return REPLACEMENT_SESSION_DIGEST
    raise ValueError("unsupported synthetic recovery session identity")


def _clone_id(
    trace_id: str,
    selector: CellSelector,
    fixture: LifecycleCutoverFixture,
    clone_nonce: str,
) -> str:
    """Address one clone instance; the nonce gives uniqueness, not authenticity."""

    return _sha256(
        rfc8785.dumps(
            {
                "schema": "assurance-lab.sqlite-recovery-clone/v1",
                "trace_id": trace_id,
                "clone_nonce": clone_nonce,
                "storage_kind": "sqlite-memory",
                "selector": selector.model_dump(mode="json"),
                "lifecycle_bundle_digest": fixture.lifecycle_bundle_digest,
                "lifecycle_snapshot_digest": incident_snapshot_digest(
                    fixture.snapshot
                ),
                "verified_lifecycle_digest": _sha256(
                    canonical_json_bytes(
                        fixture.verified_lifecycle.model_dump(mode="json")
                    )
                ),
            }
        )
    )


def _clone_readback(connection: sqlite3.Connection) -> CloneReadback:
    rows = connection.execute(
        """
        SELECT clone_id, clone_nonce, trace_id, storage_kind
        FROM run_control
        """
    ).fetchall()
    if len(rows) != 1:
        raise RuntimeError("fresh SQLite clone requires exactly one run-control row")
    clone_id, clone_nonce, trace_id, storage_kind = rows[0]
    return CloneReadback(
        clone_id=str(clone_id),
        clone_nonce=str(clone_nonce),
        trace_id=str(trace_id),
        storage_kind=str(storage_kind),
    )


def _clone_readback_evidence(readback: CloneReadback) -> tuple[str, str]:
    canonical = rfc8785.dumps(
        {
            "schema": "assurance-lab.sqlite-recovery-run-control/v1",
            "clone_id": readback.clone_id,
            "clone_nonce": readback.clone_nonce,
            "trace_id": readback.trace_id,
            "storage_kind": readback.storage_kind,
        }
    ).decode("utf-8")
    return canonical, _sha256(canonical.encode("utf-8"))


def _string_level(value: object, name: str) -> str:
    if not isinstance(value, StringValue):
        raise ValueError(f"{name} selector must be a string value")
    return value.value


def _require_level(value: str, supported: set[str], name: str) -> None:
    if value not in supported:
        raise ValueError(f"unsupported {name} level: {value!r}")


def _required_text(action: dict[str, Any], name: str) -> str:
    value = action.get(name)
    if not isinstance(value, str):
        raise RuntimeError(f"fixed action field {name!r} is not text")
    return value


def _required_text_list(action: dict[str, Any], name: str) -> tuple[str, ...]:
    value = action.get(name)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RuntimeError(f"fixed action field {name!r} is not a text list")
    return tuple(value)


def _record_request(
    connection: sqlite3.Connection,
    *,
    trace_id: str,
    action: dict[str, Any],
    action_digest: str,
    requested_ids: tuple[str, ...],
) -> None:
    action_canonical = rfc8785.dumps(action).decode("utf-8")
    connection.execute(
        """
        INSERT INTO recovery_requests
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            trace_id,
            action_canonical,
            action_digest,
            _required_text(action, "request_id"),
            _required_text(action, "principal_id"),
            _required_text(action, "session_id"),
        ),
    )
    connection.executemany(
        "INSERT INTO recovery_request_items VALUES (?, ?, ?)",
        (
            (trace_id, ordinal, customer_id)
            for ordinal, customer_id in enumerate(requested_ids, start=1)
        ),
    )
    connection.commit()


def _request_readback(
    connection: sqlite3.Connection,
    trace_id: str,
) -> tuple[str, str, tuple[str, ...]]:
    row = connection.execute(
        """
        SELECT action_canonical, action_digest, request_id, principal_id, session_id
        FROM recovery_requests
        WHERE trace_id = ?
        """,
        (trace_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError("recovery request audit row is missing")
    (
        action_canonical_raw,
        action_digest_raw,
        request_id_raw,
        principal_id_raw,
        session_id_raw,
    ) = row
    action_canonical = str(action_canonical_raw)
    try:
        action = json.loads(action_canonical)
    except json.JSONDecodeError as error:
        raise RuntimeError("recovery request canonical action is invalid JSON") from error
    if not isinstance(action, dict):
        raise RuntimeError("recovery request canonical action is not an object")
    requested = tuple(
        str(customer_id)
        for (customer_id,) in connection.execute(
            """
            SELECT customer_id
            FROM recovery_request_items
            WHERE trace_id = ?
            ORDER BY ordinal
            """,
            (trace_id,),
        )
    )
    if (
        action.get("request_id") != str(request_id_raw)
        or action.get("principal_id") != str(principal_id_raw)
        or action.get("session_id") != str(session_id_raw)
        or action.get("requested_customer_ids") != list(requested)
    ):
        raise RuntimeError("recovery request columns disagree with its canonical action")
    return action_canonical, str(action_digest_raw), requested


def _record_selection(
    connection: sqlite3.Connection,
    trace_id: str,
    customer_ids: tuple[str, ...],
) -> None:
    connection.executemany(
        "INSERT INTO recovery_selection_audit VALUES (?, ?)",
        ((trace_id, customer_id) for customer_id in customer_ids),
    )
    connection.commit()


def _selection_readback(
    connection: sqlite3.Connection,
    trace_id: str,
) -> tuple[str, ...]:
    return tuple(
        str(customer_id)
        for (customer_id,) in connection.execute(
            """
            SELECT customer_id
            FROM recovery_selection_audit
            WHERE trace_id = ?
            ORDER BY customer_id
            """,
            (trace_id,),
        )
    )


def _record_release_decision(
    connection: sqlite3.Connection,
    *,
    trace_id: str,
    guard_level: str,
    guard_reached: bool,
    decision: RecoveryReleaseDecision,
    reason: str,
) -> None:
    connection.execute(
        "INSERT INTO recovery_release_decisions VALUES (?, ?, ?, ?, ?)",
        (trace_id, guard_level, int(guard_reached), decision.value, reason),
    )
    connection.commit()


def _release_decision_readback(
    connection: sqlite3.Connection,
    trace_id: str,
) -> tuple[str, bool, RecoveryReleaseDecision, str]:
    row = connection.execute(
        """
        SELECT guard_mode, guard_reached, decision, reason
        FROM recovery_release_decisions
        WHERE trace_id = ?
        """,
        (trace_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError("release-decision audit row is missing")
    guard_mode, guard_reached, decision, reason = row
    return (
        str(guard_mode),
        bool(guard_reached),
        RecoveryReleaseDecision(str(decision)),
        str(reason),
    )


def _record_delivery_receipts(
    connection: sqlite3.Connection,
    *,
    trace_id: str,
    request_id: str,
    customer_ids: tuple[str, ...],
) -> None:
    connection.executemany(
        """
        INSERT INTO recovery_delivery_receipts
        VALUES (?, ?, ?, ?)
        """,
        (
            (
                _delivery_receipt_id(
                    trace_id=trace_id,
                    request_id=request_id,
                    customer_id=customer_id,
                ),
                trace_id,
                request_id,
                customer_id,
            )
            for customer_id in customer_ids
        ),
    )
    connection.commit()


def _delivery_receipt_readback(
    connection: sqlite3.Connection,
    trace_id: str,
) -> DeliveryReceiptReadback:
    rows = tuple(
        (str(receipt_id), str(request_id), str(customer_id))
        for receipt_id, request_id, customer_id in connection.execute(
            """
            SELECT receipt_id, request_id, customer_id
            FROM recovery_delivery_receipts
            WHERE trace_id = ?
            ORDER BY customer_id
            """,
            (trace_id,),
        )
    )
    receipts: list[dict[str, str]] = []
    for receipt_id, request_id, customer_id in rows:
        expected = _delivery_receipt_id(
            trace_id=trace_id,
            request_id=request_id,
            customer_id=customer_id,
        )
        if receipt_id != expected:
            raise RuntimeError("client delivery receipt content address is invalid")
        receipts.append(
            {
                "receipt_id": receipt_id,
                "trace_id": trace_id,
                "request_id": request_id,
                "customer_id": customer_id,
            }
        )
    canonical = rfc8785.dumps(
        {
            "schema": "assurance-lab.recovery-delivery-receipt-set/v1",
            "receipts": receipts,
        }
    ).decode("utf-8")
    return DeliveryReceiptReadback(
        customer_ids=tuple(customer_id for _, _, customer_id in rows),
        canonical=canonical,
        digest=_sha256(canonical.encode("utf-8")),
    )


def _delivery_receipt_id(
    *,
    trace_id: str,
    request_id: str,
    customer_id: str,
) -> str:
    return _sha256(
        rfc8785.dumps(
            {
                "schema": "assurance-lab.recovery-delivery-receipt/v1",
                "trace_id": trace_id,
                "request_id": request_id,
                "customer_id": customer_id,
            }
        )
    )


def _insert_snapshot(connection: sqlite3.Connection, level: StringValue) -> None:
    descriptor = snapshot_descriptor(level)
    snapshot_id = _required_text(descriptor, "snapshot_id")
    principal_id = _required_text(descriptor, "principal_id")
    restore_operation_id = _required_text(descriptor, "restore_operation_id")
    connection.execute(
        "INSERT INTO restored_snapshot VALUES (?, ?, ?, ?)",
        (snapshot_id, level.value, principal_id, restore_operation_id),
    )
    entitlements = (
        STALE_ENTITLEMENTS if level == TARGET_INEFFECTIVE else APPROVED_ENTITLEMENTS
    )
    connection.executemany(
        "INSERT INTO restored_entitlements VALUES (?, ?)",
        ((snapshot_id, entitlement) for entitlement in entitlements),
    )


def _reapply_snapshot(
    connection: sqlite3.Connection,
    level: StringValue,
    *,
    trace_id: str,
    before_snapshot: dict[str, Any],
) -> None:
    before_canonical = rfc8785.dumps(before_snapshot).decode("utf-8")
    before_digest = _sha256(before_canonical.encode("utf-8"))
    operation_id = _sha256(
        rfc8785.dumps(
            {
                "schema": "assurance-lab.snapshot-reapply-operation/v1",
                "trace_id": trace_id,
                "target_level": level.value,
                "before_snapshot_digest": before_digest,
            }
        )
    )
    with connection:
        connection.execute(
            """
            INSERT INTO snapshot_apply_context
            VALUES (1, ?, ?, ?, 'open')
            """,
            (trace_id, operation_id, level.value),
        )
        entitlement_delete = connection.execute(
            "DELETE FROM restored_entitlements"
        ).rowcount
        snapshot_delete = connection.execute("DELETE FROM restored_snapshot").rowcount
        _insert_snapshot(connection, level)
        after_snapshot = _snapshot_readback(connection)
        after_canonical = rfc8785.dumps(after_snapshot).decode("utf-8")
        after_digest = _sha256(after_canonical.encode("utf-8"))
        snapshot_insert = int(
            connection.execute("SELECT COUNT(*) FROM restored_snapshot").fetchone()[0]
        )
        entitlement_insert = int(
            connection.execute(
                "SELECT COUNT(*) FROM restored_entitlements"
            ).fetchone()[0]
        )
        mutation_rows_canonical, mutation_rows_digest = (
            _snapshot_apply_mutation_readback(
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
                before_canonical,
                before_digest,
                after_canonical,
                after_digest,
                snapshot_delete,
                entitlement_delete,
                snapshot_insert,
                entitlement_insert,
                mutation_rows_canonical,
                mutation_rows_digest,
            ),
        )
        connection.execute(
            """
            UPDATE snapshot_apply_context
            SET state = 'closed'
            WHERE singleton = 1 AND trace_id = ? AND operation_id = ?
            """,
            (trace_id, operation_id),
        )


def _snapshot_apply_mutation_readback(
    connection: sqlite3.Connection,
    *,
    trace_id: str,
    operation_id: str,
) -> tuple[str, str]:
    rows = [
        {
            "sequence": int(sequence),
            "trace_id": str(row_trace_id),
            "operation_id": str(row_operation_id),
            "entity_type": str(entity_type),
            "operation": str(operation),
            "row_key": str(row_key),
            "snapshot_id": str(snapshot_id),
            "target_level": (
                None if target_level is None else str(target_level)
            ),
            "principal_id": None if principal_id is None else str(principal_id),
            "restore_operation_id": (
                None
                if restore_operation_id is None
                else str(restore_operation_id)
            ),
            "entitlement": None if entitlement is None else str(entitlement),
        }
        for (
            sequence,
            row_trace_id,
            row_operation_id,
            entity_type,
            operation,
            row_key,
            snapshot_id,
            target_level,
            principal_id,
            restore_operation_id,
            entitlement,
        ) in connection.execute(
            """
            SELECT sequence, trace_id, operation_id, entity_type, operation,
                   row_key, snapshot_id, target_level, principal_id,
                   restore_operation_id, entitlement
            FROM snapshot_apply_mutations
            WHERE trace_id = ? AND operation_id = ?
            ORDER BY sequence
            """,
            (trace_id, operation_id),
        )
    ]
    canonical = rfc8785.dumps(
        {
            "schema": "assurance-lab.snapshot-apply-mutation-set/v1",
            "trace_id": trace_id,
            "operation_id": operation_id,
            "mutations": rows,
        }
    ).decode("utf-8")
    return canonical, _sha256(canonical.encode("utf-8"))


def _snapshot_apply_receipt_readback(
    connection: sqlite3.Connection,
    trace_id: str,
) -> SnapshotApplyReceipt | None:
    rows = connection.execute(
        """
        SELECT operation_id, target_level,
               before_snapshot_canonical, before_snapshot_digest,
               after_snapshot_canonical, after_snapshot_digest,
               snapshot_rows_deleted, entitlement_rows_deleted,
               snapshot_rows_inserted, entitlement_rows_inserted,
               mutation_rows_canonical, mutation_rows_digest
        FROM snapshot_apply_receipts
        WHERE trace_id = ?
        """,
        (trace_id,),
    ).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise RuntimeError("snapshot reapply has more than one operation receipt")
    row = rows[0]
    receipt = SnapshotApplyReceipt(
        operation_id=str(row[0]),
        target_level=str(row[1]),
        before_snapshot_canonical=str(row[2]),
        before_snapshot_digest=str(row[3]),
        after_snapshot_canonical=str(row[4]),
        after_snapshot_digest=str(row[5]),
        snapshot_rows_deleted=int(row[6]),
        entitlement_rows_deleted=int(row[7]),
        snapshot_rows_inserted=int(row[8]),
        entitlement_rows_inserted=int(row[9]),
        mutation_rows_canonical=str(row[10]),
        mutation_rows_digest=str(row[11]),
    )
    observed_canonical, observed_digest = _snapshot_apply_mutation_readback(
        connection,
        trace_id=trace_id,
        operation_id=receipt.operation_id,
    )
    context = connection.execute(
        """
        SELECT target_level, state
        FROM snapshot_apply_context
        WHERE singleton = 1 AND trace_id = ? AND operation_id = ?
        """,
        (trace_id, receipt.operation_id),
    ).fetchone()
    if (
        receipt.mutation_rows_canonical != observed_canonical
        or receipt.mutation_rows_digest != observed_digest
        or context != (receipt.target_level, "closed")
    ):
        raise RuntimeError(
            "snapshot apply receipt does not bind the observed mutation rows"
        )
    return receipt


def _validate_snapshot_apply_receipt(
    *,
    receipt: SnapshotApplyReceipt | None,
    trace_id: str,
    sham_level: str,
    target_level: str,
    before_snapshot_canonical: str,
    before_snapshot_digest: str,
    after_snapshot_canonical: str,
    after_snapshot_digest: str,
    expected_entitlement_rows: int,
) -> bool:
    expects_reapply = sham_level == SHAM_REAPPLY.value
    if not expects_reapply:
        return receipt is None
    if receipt is None:
        return False
    operation_id = _sha256(
        rfc8785.dumps(
            {
                "schema": "assurance-lab.snapshot-reapply-operation/v1",
                "trace_id": trace_id,
                "target_level": target_level,
                "before_snapshot_digest": before_snapshot_digest,
            }
        )
    )
    expected_mutations = _expected_snapshot_apply_mutations(
        trace_id=trace_id,
        operation_id=operation_id,
        target_level=target_level,
        before_snapshot_canonical=before_snapshot_canonical,
        after_snapshot_canonical=after_snapshot_canonical,
    )
    expected_mutation_digest = _sha256(expected_mutations.encode("utf-8"))
    return (
        receipt.operation_id == operation_id
        and receipt.target_level == target_level
        and receipt.before_snapshot_canonical == before_snapshot_canonical
        and receipt.before_snapshot_digest == before_snapshot_digest
        and _sha256(receipt.before_snapshot_canonical.encode("utf-8"))
        == receipt.before_snapshot_digest
        and receipt.after_snapshot_canonical == after_snapshot_canonical
        and receipt.after_snapshot_digest == after_snapshot_digest
        and _sha256(receipt.after_snapshot_canonical.encode("utf-8"))
        == receipt.after_snapshot_digest
        and receipt.snapshot_rows_deleted == 1
        and receipt.entitlement_rows_deleted == expected_entitlement_rows
        and receipt.snapshot_rows_inserted == 1
        and receipt.entitlement_rows_inserted == expected_entitlement_rows
        and receipt.mutation_rows_canonical == expected_mutations
        and receipt.mutation_rows_digest == expected_mutation_digest
        and _sha256(receipt.mutation_rows_canonical.encode("utf-8"))
        == receipt.mutation_rows_digest
    )


def _expected_snapshot_apply_mutations(
    *,
    trace_id: str,
    operation_id: str,
    target_level: str,
    before_snapshot_canonical: str,
    after_snapshot_canonical: str,
) -> str:
    before = _canonical_object(
        before_snapshot_canonical,
        label="pre-apply snapshot",
    )
    after = _canonical_object(
        after_snapshot_canonical,
        label="post-apply snapshot",
    )

    def entitlements(snapshot: dict[str, Any]) -> tuple[str, ...]:
        raw_set = snapshot.get("entitlement_set")
        if not isinstance(raw_set, dict):
            raise ValueError("snapshot apply evidence has no entitlement set")
        raw_values = raw_set.get("entitlements")
        if (
            not isinstance(raw_values, list)
            or not all(isinstance(value, str) for value in raw_values)
        ):
            raise ValueError("snapshot apply evidence has invalid entitlements")
        return tuple(raw_values)

    rows: list[dict[str, Scalar]] = []

    def append(
        *,
        entity_type: str,
        operation: str,
        row_key: str,
        snapshot_id: str,
        row_target_level: str | None,
        principal_id: str | None,
        restore_operation_id: str | None,
        entitlement: str | None,
    ) -> None:
        rows.append(
            {
                "sequence": len(rows) + 1,
                "trace_id": trace_id,
                "operation_id": operation_id,
                "entity_type": entity_type,
                "operation": operation,
                "row_key": row_key,
                "snapshot_id": snapshot_id,
                "target_level": row_target_level,
                "principal_id": principal_id,
                "restore_operation_id": restore_operation_id,
                "entitlement": entitlement,
            }
        )

    before_snapshot_id = str(before["snapshot_id"])
    for entitlement in entitlements(before):
        append(
            entity_type="entitlement",
            operation="delete",
            row_key=f"{before_snapshot_id}:{entitlement}",
            snapshot_id=before_snapshot_id,
            row_target_level=None,
            principal_id=None,
            restore_operation_id=None,
            entitlement=entitlement,
        )
    append(
        entity_type="snapshot",
        operation="delete",
        row_key=before_snapshot_id,
        snapshot_id=before_snapshot_id,
        row_target_level=target_level,
        principal_id=str(before["principal_id"]),
        restore_operation_id=str(before["restore_operation_id"]),
        entitlement=None,
    )
    after_snapshot_id = str(after["snapshot_id"])
    append(
        entity_type="snapshot",
        operation="insert",
        row_key=after_snapshot_id,
        snapshot_id=after_snapshot_id,
        row_target_level=target_level,
        principal_id=str(after["principal_id"]),
        restore_operation_id=str(after["restore_operation_id"]),
        entitlement=None,
    )
    for entitlement in entitlements(after):
        append(
            entity_type="entitlement",
            operation="insert",
            row_key=f"{after_snapshot_id}:{entitlement}",
            snapshot_id=after_snapshot_id,
            row_target_level=None,
            principal_id=None,
            restore_operation_id=None,
            entitlement=entitlement,
        )
    return rfc8785.dumps(
        {
            "schema": "assurance-lab.snapshot-apply-mutation-set/v1",
            "trace_id": trace_id,
            "operation_id": operation_id,
            "mutations": rows,
        }
    ).decode("utf-8")


def _empty_snapshot_apply_mutations(
    *,
    trace_id: str,
) -> str:
    return rfc8785.dumps(
        {
            "schema": "assurance-lab.snapshot-apply-mutation-set/v1",
            "trace_id": trace_id,
            "operation_id": None,
            "mutations": [],
        }
    ).decode("utf-8")


def _snapshot_readback(connection: sqlite3.Connection) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT snapshot_id, principal_id, restore_operation_id
        FROM restored_snapshot
        """
    ).fetchone()
    if row is None:
        raise RuntimeError("restored snapshot is missing")
    snapshot_id, principal_id, restore_operation_id = row
    entitlements = tuple(
        str(item[0])
        for item in connection.execute(
            """
            SELECT entitlement
            FROM restored_entitlements
            WHERE snapshot_id = ?
            ORDER BY entitlement
            """,
            (snapshot_id,),
        )
    )
    return {
        "schema": "assurance-lab.recovery-entitlement-snapshot/v1",
        "snapshot_id": str(snapshot_id),
        "principal_id": str(principal_id),
        "restore_operation_id": str(restore_operation_id),
        "entitlement_set": {
            "schema": "assurance-lab.recovery-entitlement-set/v1",
            "principal_id": str(principal_id),
            "entitlements": list(entitlements),
        },
    }


def _lifecycle_reference_readback(
    connection: sqlite3.Connection,
) -> LifecycleReferenceReadback:
    rows = connection.execute(
        """
        SELECT lifecycle_bundle_digest, lifecycle_snapshot_canonical,
               lifecycle_snapshot_digest,
               session_rotation_transition_id, branch_id, branch_kind,
               bound_branch_head_digest,
               verified_lifecycle_canonical, verified_lifecycle_digest,
               disclosure_ledger_canonical, disclosure_ledger_digest
        FROM lifecycle_cutover_reference
        """
    ).fetchall()
    if len(rows) != 1:
        raise RuntimeError("recovery clone requires exactly one lifecycle reference")
    (
        lifecycle_bundle_digest,
        lifecycle_snapshot_canonical_raw,
        lifecycle_snapshot_digest,
        session_rotation_transition_id,
        branch_id,
        branch_kind,
        bound_branch_head_digest,
        verified_lifecycle_canonical_raw,
        verified_lifecycle_digest,
        ledger_canonical_raw,
        ledger_digest,
    ) = rows[0]
    ledger_canonical = str(ledger_canonical_raw)
    lifecycle_snapshot_canonical = str(lifecycle_snapshot_canonical_raw)
    verified_lifecycle_canonical = str(verified_lifecycle_canonical_raw)
    if (
        _sha256(lifecycle_snapshot_canonical.encode("utf-8"))
        != str(lifecycle_snapshot_digest)
    ):
        raise RuntimeError("lifecycle snapshot digest is invalid")
    if (
        _sha256(verified_lifecycle_canonical.encode("utf-8"))
        != str(verified_lifecycle_digest)
    ):
        raise RuntimeError("verified lifecycle output digest is invalid")
    if _sha256(ledger_canonical.encode("utf-8")) != str(ledger_digest):
        raise RuntimeError("lifecycle disclosure ledger digest is invalid")

    entry_rows = tuple(
        (str(entry_digest), str(entry_canonical), str(record_token))
        for entry_digest, entry_canonical, record_token in connection.execute(
            """
            SELECT entry_digest, entry_canonical, record_token
            FROM lifecycle_disclosure_entries
            ORDER BY record_token
            """
        )
    )
    parsed_entries: list[dict[str, Any]] = []
    entry_ids: list[str] = []
    for entry_digest, entry_canonical, record_token in entry_rows:
        if _sha256(entry_canonical.encode("utf-8")) != entry_digest:
            raise RuntimeError("lifecycle disclosure entry digest is invalid")
        try:
            parsed = json.loads(entry_canonical)
        except json.JSONDecodeError as error:
            raise RuntimeError(
                "lifecycle disclosure entry canonical JSON is invalid"
            ) from error
        if not isinstance(parsed, dict) or parsed.get("record_token") != record_token:
            raise RuntimeError(
                "lifecycle disclosure entry row disagrees with its canonical form"
            )
        parsed_entries.append(parsed)
        entry_ids.append(entry_digest)
    reconstructed_ledger = rfc8785.dumps(
        {
            "data_class": "customer_confidential",
            "entries": parsed_entries,
        }
    ).decode("utf-8")
    if reconstructed_ledger != ledger_canonical:
        raise RuntimeError(
            "lifecycle disclosure entries do not reproduce the ledger reference"
        )
    entry_ids_canonical, entry_ids_digest = _identifier_set_evidence(
        "lifecycle-disclosure-entry-id-set",
        tuple(entry_ids),
    )
    return LifecycleReferenceReadback(
        lifecycle_bundle_digest=str(lifecycle_bundle_digest),
        lifecycle_snapshot_canonical=lifecycle_snapshot_canonical,
        lifecycle_snapshot_digest=str(lifecycle_snapshot_digest),
        session_rotation_transition_id=str(session_rotation_transition_id),
        branch_id=str(branch_id),
        branch_kind=str(branch_kind),
        bound_branch_head_digest=str(bound_branch_head_digest),
        verified_lifecycle_canonical=verified_lifecycle_canonical,
        verified_lifecycle_digest=str(verified_lifecycle_digest),
        disclosure_ledger_canonical=ledger_canonical,
        disclosure_ledger_digest=str(ledger_digest),
        disclosure_entry_ids_canonical=entry_ids_canonical,
        disclosure_entry_ids_digest=entry_ids_digest,
        disclosure_entry_count=len(entry_ids),
    )


def _lifecycle_reference_matches_fixture(
    reference: LifecycleReferenceReadback,
    fixture: LifecycleCutoverFixture,
) -> bool:
    expected_ledger = canonical_json_bytes(
        fixture.snapshot.disclosure_ledger.model_dump(mode="json")
    ).decode("utf-8")
    expected_verified_lifecycle = canonical_json_bytes(
        fixture.verified_lifecycle.model_dump(mode="json")
    ).decode("utf-8")
    expected_snapshot = canonical_json_bytes(
        fixture.snapshot.model_dump(mode="json")
    ).decode("utf-8")
    expected_ids = tuple(
        _sha256(canonical_json_bytes(entry.model_dump(mode="json")))
        for entry in fixture.snapshot.disclosure_ledger.entries
    )
    expected_ids_canonical, expected_ids_digest = _identifier_set_evidence(
        "lifecycle-disclosure-entry-id-set",
        expected_ids,
    )
    return (
        reference.lifecycle_bundle_digest == fixture.lifecycle_bundle_digest
        and reference.lifecycle_snapshot_canonical == expected_snapshot
        and reference.lifecycle_snapshot_digest
        == incident_snapshot_digest(fixture.snapshot)
        and reference.session_rotation_transition_id
        == fixture.session_rotation_transition_id
        and reference.branch_id == fixture.snapshot.branch_id
        and reference.branch_kind == fixture.snapshot.branch_kind.value
        and reference.bound_branch_head_digest
        == _fixture_bound_branch_head_digest(fixture)
        and reference.bound_branch_head_digest
        == reference.lifecycle_snapshot_digest
        and reference.verified_lifecycle_canonical
        == expected_verified_lifecycle
        and reference.verified_lifecycle_digest
        == _sha256(expected_verified_lifecycle.encode("utf-8"))
        and reference.disclosure_ledger_canonical == expected_ledger
        and reference.disclosure_ledger_digest
        == _sha256(expected_ledger.encode("utf-8"))
        and reference.disclosure_entry_ids_canonical == expected_ids_canonical
        and reference.disclosure_entry_ids_digest == expected_ids_digest
        and reference.disclosure_entry_count == len(expected_ids)
    )


def _cutover_readback(
    connection: sqlite3.Connection,
) -> tuple[RecoverySessionState, RecoverySessionState, str, str]:
    rows = {
        str(session_id): (
            str(principal_id),
            RecoverySessionState(str(state)),
            str(session_identity_digest),
            None if digest is None else str(digest),
            str(lifecycle_snapshot_digest),
        )
        for (
            session_id,
            principal_id,
            state,
            session_identity_digest,
            digest,
            lifecycle_snapshot_digest,
        ) in connection.execute(
            """
            SELECT session_id, principal_id, state, session_identity_digest,
                   entitlement_set_digest, lifecycle_snapshot_digest
            FROM sessions
            ORDER BY session_id
            """
        )
    }
    if set(rows) != {OLD_SESSION_ID, REPLACEMENT_SESSION_ID}:
        raise RuntimeError("cutover fixture has an unexpected session identity set")
    (
        old_principal,
        old_state,
        old_identity_digest,
        old_digest,
        old_lifecycle_digest,
    ) = rows[OLD_SESSION_ID]
    (
        replacement_principal,
        replacement_state,
        replacement_identity_digest,
        replacement_digest,
        replacement_lifecycle_digest,
    ) = rows[
        REPLACEMENT_SESSION_ID
    ]
    if old_principal != PRINCIPAL_ID or replacement_principal != PRINCIPAL_ID:
        raise RuntimeError("cutover fixture session principal binding is invalid")
    if old_digest is not None or replacement_digest is None:
        raise RuntimeError("cutover fixture entitlement binding is invalid")
    if old_identity_digest != _session_identity_digest(OLD_SESSION_ID):
        raise RuntimeError("old session row has an invalid identity digest")
    if replacement_identity_digest != _session_identity_digest(
        REPLACEMENT_SESSION_ID
    ):
        raise RuntimeError("replacement session row has an invalid identity digest")
    if old_lifecycle_digest != replacement_lifecycle_digest:
        raise RuntimeError("cutover session rows disagree on lifecycle provenance")
    return (
        old_state,
        replacement_state,
        replacement_digest,
        old_lifecycle_digest,
    )


def _assignment_readback(
    connection: sqlite3.Connection,
    principal_id: str,
) -> AssignmentReadback:
    rows = tuple(
        (str(case_id), str(customer_id), str(status))
        for case_id, customer_id, status in connection.execute(
            """
            SELECT case_id, customer_id, status
            FROM support_cases
            WHERE assigned_principal_id = ? AND status = 'active'
            ORDER BY case_id
            """,
            (principal_id,),
        )
    )
    assignments = [
        {
            "case_id": case_id,
            "customer_id": customer_id,
            "principal_id": principal_id,
            "status": status,
        }
        for case_id, customer_id, status in rows
    ]
    canonical = rfc8785.dumps(
        {
            "schema": "assurance-lab.active-support-assignment-set/v1",
            "principal_id": principal_id,
            "assignments": assignments,
        }
    ).decode("utf-8")
    return AssignmentReadback(
        customer_ids=tuple(sorted({customer_id for _, customer_id, _ in rows})),
        canonical=canonical,
        digest=_sha256(canonical.encode("utf-8")),
    )


def _entitlement_allows(
    connection: sqlite3.Connection,
    customer_id: str,
) -> bool:
    entitlements = tuple(
        str(row[0])
        for row in connection.execute(
            "SELECT entitlement FROM restored_entitlements ORDER BY entitlement"
        )
    )
    return "customer:*" in entitlements or f"customer:{customer_id}" in entitlements


def _select_customers(
    connection: sqlite3.Connection,
    customer_ids: tuple[str, ...],
) -> tuple[str, ...]:
    placeholders = ",".join("?" for _ in customer_ids)
    selected = tuple(
        str(row[0])
        for row in connection.execute(
            f"""
            SELECT customer_id
            FROM customers
            WHERE customer_id IN ({placeholders})
            ORDER BY customer_id
            """,
            customer_ids,
        )
    )
    if len(selected) != len(customer_ids):
        raise RuntimeError("fixed action references a missing synthetic customer")
    return selected


def _events(
    *,
    trace_id: str,
    clone_id: str,
    clone_nonce: str,
    clone_storage_kind: str,
    clone_readback_canonical: str,
    clone_readback_digest: str,
    clone_cleanup_verified: bool,
    action: dict[str, Any],
    action_canonical: str,
    action_digest: str,
    requested_ids: tuple[str, ...],
    lifecycle_before: LifecycleReferenceReadback,
    lifecycle_after: LifecycleReferenceReadback,
    old_state: RecoverySessionState,
    replacement_state: RecoverySessionState,
    replacement_binding_digest: str,
    replacement_binding_valid: bool,
    cutover_valid: bool,
    target_level: str,
    snapshot_id: str,
    snapshot_canonical: str,
    snapshot_digest: str,
    entitlement_set_canonical: str,
    entitlement_set_digest: str,
    snapshot_identity_matches: bool,
    snapshot_reapply_performed: bool,
    snapshot_reapply_receipt_valid: bool,
    apply_receipt: SnapshotApplyReceipt | None,
    before_reapply_digest: str,
    after_reapply_digest: str,
    snapshot_reapply_unchanged: bool,
    snapshot_authorized: bool,
    assigned_ids: tuple[str, ...],
    assignment_readback: AssignmentReadback,
    selected_ids: tuple[str, ...],
    selected_outside_ids: tuple[str, ...],
    guard_level: str,
    guard_reached: bool,
    release_decision: RecoveryReleaseDecision,
    release_reason: str,
    unapproved_release_blocked: bool,
    delivered_ids: tuple[str, ...],
    delivery_readback: DeliveryReceiptReadback,
    delivered_outside_ids: tuple[str, ...],
    assigned_delivered_ids: tuple[str, ...],
) -> tuple[RuntimeEvent, ...]:
    requested_canonical, requested_digest = _identifier_set_evidence(
        "requested-customer-set",
        requested_ids,
    )
    assigned_canonical, assigned_digest = _identifier_set_evidence(
        "assigned-customer-set",
        assigned_ids,
    )
    selected_canonical, selected_digest = _identifier_set_evidence(
        "selected-customer-set",
        selected_ids,
    )
    selected_outside_canonical, selected_outside_digest = _identifier_set_evidence(
        "selected-out-of-scope-customer-set",
        selected_outside_ids,
    )
    delivered_canonical, delivered_digest = _identifier_set_evidence(
        "delivered-customer-set",
        delivered_ids,
    )
    delivered_outside_canonical, delivered_outside_digest = (
        _identifier_set_evidence(
            "delivered-out-of-scope-customer-set",
            delivered_outside_ids,
        )
    )
    assigned_delivered_canonical, assigned_delivered_digest = (
        _identifier_set_evidence(
            "delivered-assigned-customer-set",
            assigned_delivered_ids,
        )
    )
    return (
        RuntimeEvent(
            trace_id=trace_id,
            sequence=1,
            stage="input",
            component="recovery-client",
            event_type="recovery-retest-issued",
            payload=(
                ("action", _required_text(action, "action")),
                ("request_id", _required_text(action, "request_id")),
                ("principal_id", PRINCIPAL_ID),
                ("session_id", REPLACEMENT_SESSION_ID),
                ("clone_id", clone_id),
                ("clone_nonce", clone_nonce),
                ("storage_kind", clone_storage_kind),
                ("clone_readback_canonical", clone_readback_canonical),
                ("clone_readback_digest", clone_readback_digest),
                ("action_canonical", action_canonical),
                ("action_digest", action_digest),
                ("requested_customer_ids_canonical", requested_canonical),
                ("requested_customer_ids_digest", requested_digest),
            ),
        ),
        RuntimeEvent(
            trace_id=trace_id,
            sequence=2,
            stage="input",
            component="recovery-access-session",
            event_type="lifecycle-cutover-reference-readback",
            payload=(
                (
                    "lifecycle_bundle_digest",
                    lifecycle_before.lifecycle_bundle_digest,
                ),
                (
                    "lifecycle_snapshot_digest",
                    lifecycle_before.lifecycle_snapshot_digest,
                ),
                (
                    "lifecycle_snapshot_canonical",
                    lifecycle_before.lifecycle_snapshot_canonical,
                ),
                (
                    "session_rotation_transition_id",
                    lifecycle_before.session_rotation_transition_id,
                ),
                (
                    "verified_lifecycle_digest",
                    lifecycle_before.verified_lifecycle_digest,
                ),
                ("lifecycle_branch_id", lifecycle_before.branch_id),
                ("lifecycle_branch_kind", lifecycle_before.branch_kind),
                (
                    "lifecycle_bound_branch_head_digest",
                    lifecycle_before.bound_branch_head_digest,
                ),
                ("old_session_id", OLD_SESSION_ID),
                ("old_session_state", old_state.value),
                ("old_session_revoked", old_state == RecoverySessionState.REVOKED),
                ("replacement_session_id", REPLACEMENT_SESSION_ID),
                ("replacement_session_state", replacement_state.value),
                (
                    "replacement_session_active",
                    replacement_state == RecoverySessionState.ACTIVE,
                ),
                (
                    "replacement_session_entitlement_set_digest",
                    replacement_binding_digest,
                ),
                (
                    "replacement_session_entitlement_digest_bound",
                    replacement_binding_valid,
                ),
                ("cutover_fixture_valid", cutover_valid),
                (
                    "prior_disclosure_ledger_canonical",
                    lifecycle_before.disclosure_ledger_canonical,
                ),
                (
                    "prior_disclosure_ledger_digest",
                    lifecycle_before.disclosure_ledger_digest,
                ),
                (
                    "prior_disclosure_entry_ids_canonical",
                    lifecycle_before.disclosure_entry_ids_canonical,
                ),
                (
                    "prior_disclosure_entry_ids_digest",
                    lifecycle_before.disclosure_entry_ids_digest,
                ),
                (
                    "prior_admitted_disclosure_count",
                    lifecycle_before.disclosure_entry_count,
                ),
            ),
        ),
        RuntimeEvent(
            trace_id=trace_id,
            sequence=3,
            stage="target",
            component="restored-entitlement-boundary",
            event_type="snapshot-and-selection-readback",
            payload=(
                ("target_mode", target_level),
                ("snapshot_id", snapshot_id),
                ("snapshot_canonical", snapshot_canonical),
                ("snapshot_digest", snapshot_digest),
                ("entitlement_set_canonical", entitlement_set_canonical),
                ("entitlement_set_digest", entitlement_set_digest),
                (
                    "snapshot_identity_matches_declared_target",
                    snapshot_identity_matches,
                ),
                ("snapshot_reapply_performed", snapshot_reapply_performed),
                (
                    "snapshot_reapply_receipt_valid",
                    snapshot_reapply_receipt_valid,
                ),
                (
                    "snapshot_reapply_operation_id",
                    None if apply_receipt is None else apply_receipt.operation_id,
                ),
                (
                    "snapshot_rows_deleted",
                    0
                    if apply_receipt is None
                    else apply_receipt.snapshot_rows_deleted,
                ),
                (
                    "entitlement_rows_deleted",
                    0
                    if apply_receipt is None
                    else apply_receipt.entitlement_rows_deleted,
                ),
                (
                    "snapshot_rows_inserted",
                    0
                    if apply_receipt is None
                    else apply_receipt.snapshot_rows_inserted,
                ),
                (
                    "entitlement_rows_inserted",
                    0
                    if apply_receipt is None
                    else apply_receipt.entitlement_rows_inserted,
                ),
                (
                    "snapshot_apply_mutation_rows_canonical",
                    _empty_snapshot_apply_mutations(
                        trace_id=trace_id,
                    )
                    if apply_receipt is None
                    else apply_receipt.mutation_rows_canonical,
                ),
                (
                    "snapshot_apply_mutation_rows_digest",
                    _sha256(
                        _empty_snapshot_apply_mutations(
                            trace_id=trace_id,
                        ).encode("utf-8")
                    )
                    if apply_receipt is None
                    else apply_receipt.mutation_rows_digest,
                ),
                ("pre_reapply_snapshot_digest", before_reapply_digest),
                ("post_reapply_snapshot_digest", after_reapply_digest),
                (
                    "snapshot_reapply_semantics_unchanged",
                    snapshot_reapply_unchanged,
                ),
                ("snapshot_authorized_action", snapshot_authorized),
                (
                    "assignment_basis_canonical",
                    assignment_readback.canonical,
                ),
                ("assignment_basis_digest", assignment_readback.digest),
                ("assigned_customer_ids_canonical", assigned_canonical),
                ("assigned_customer_ids_digest", assigned_digest),
                ("selected_customer_ids_canonical", selected_canonical),
                ("selected_customer_ids_digest", selected_digest),
                (
                    "selected_out_of_scope_customer_ids_canonical",
                    selected_outside_canonical,
                ),
                (
                    "selected_out_of_scope_customer_ids_digest",
                    selected_outside_digest,
                ),
                ("out_of_scope_records_selected", len(selected_outside_ids)),
            ),
        ),
        RuntimeEvent(
            trace_id=trace_id,
            sequence=4,
            stage="compensator",
            component="release-gateway",
            event_type="release-decision-readback",
            payload=(
                ("guard_mode", guard_level),
                ("release_guard_reached", guard_reached),
                ("release_decision", release_decision.value),
                ("release_reason", release_reason),
                ("unapproved_release_blocked", unapproved_release_blocked),
            ),
        ),
        RuntimeEvent(
            trace_id=trace_id,
            sequence=5,
            stage="outcome",
            component="recovery-client",
            event_type="delivery-and-history-readback",
            payload=(
                (
                    "delivery_receipts_canonical",
                    delivery_readback.canonical,
                ),
                ("delivery_receipts_digest", delivery_readback.digest),
                ("delivered_customer_ids_canonical", delivered_canonical),
                ("delivered_customer_ids_digest", delivered_digest),
                (
                    "delivered_out_of_scope_customer_ids_canonical",
                    delivered_outside_canonical,
                ),
                (
                    "delivered_out_of_scope_customer_ids_digest",
                    delivered_outside_digest,
                ),
                (
                    "delivered_assigned_customer_ids_canonical",
                    assigned_delivered_canonical,
                ),
                (
                    "delivered_assigned_customer_ids_digest",
                    assigned_delivered_digest,
                ),
                (
                    "out_of_scope_records_delivered",
                    len(delivered_outside_ids),
                ),
                (
                    "assigned_case_records_delivered",
                    len(assigned_delivered_ids),
                ),
                (
                    "prior_disclosure_ledger_canonical_after",
                    lifecycle_after.disclosure_ledger_canonical,
                ),
                (
                    "prior_disclosure_ledger_digest_before",
                    lifecycle_before.disclosure_ledger_digest,
                ),
                (
                    "prior_disclosure_ledger_digest_after",
                    lifecycle_after.disclosure_ledger_digest,
                ),
                (
                    "prior_disclosure_entry_ids_digest_before",
                    lifecycle_before.disclosure_entry_ids_digest,
                ),
                (
                    "prior_disclosure_entry_ids_digest_after",
                    lifecycle_after.disclosure_entry_ids_digest,
                ),
                (
                    "prior_admitted_disclosure_count_before",
                    lifecycle_before.disclosure_entry_count,
                ),
                (
                    "prior_admitted_disclosure_count_after",
                    lifecycle_after.disclosure_entry_count,
                ),
                (
                    "prior_disclosure_reference_unchanged",
                    lifecycle_before == lifecycle_after,
                ),
            ),
        ),
        RuntimeEvent(
            trace_id=trace_id,
            sequence=6,
            stage="cleanup",
            component="recovery-runtime",
            event_type="sqlite-clone-cleanup-attested",
            payload=(
                ("clone_id", clone_id),
                ("clone_nonce", clone_nonce),
                ("connection_closed", clone_cleanup_verified),
            ),
        ),
    )


def _identifier_set_evidence(
    schema_name: str,
    identifiers: tuple[str, ...],
) -> tuple[str, str]:
    canonical = rfc8785.dumps(
        {
            "schema": f"assurance-lab.{schema_name}/v1",
            "identifiers": list(identifiers),
        }
    )
    return canonical.decode("utf-8"), _sha256(canonical)


def _canonical_object(canonical: str, *, label: str) -> dict[str, Any]:
    try:
        parsed = json.loads(canonical)
    except json.JSONDecodeError as error:
        raise ValueError(f"recovery result {label} is invalid JSON") from error
    if not isinstance(parsed, dict):
        raise ValueError(f"recovery result {label} is not an object")
    if rfc8785.dumps(parsed).decode("utf-8") != canonical:
        raise ValueError(f"recovery result {label} is not canonical JSON")
    return parsed


def _connection_is_closed(connection: sqlite3.Connection) -> bool:
    try:
        connection.execute("SELECT 1")
    except sqlite3.ProgrammingError as error:
        return "closed" in str(error).lower()
    return False


_SNAPSHOT_MUTATION_TRIGGERS = frozenset(
    {
        "snapshot_apply_entitlement_delete_audit",
        "snapshot_apply_snapshot_delete_audit",
        "snapshot_apply_snapshot_insert_audit",
        "snapshot_apply_entitlement_insert_audit",
    }
)

_SCHEMA_MUTATION_ACTIONS = frozenset(
    {
        sqlite3.SQLITE_ALTER_TABLE,
        sqlite3.SQLITE_ANALYZE,
        sqlite3.SQLITE_ATTACH,
        sqlite3.SQLITE_CREATE_INDEX,
        sqlite3.SQLITE_CREATE_TABLE,
        sqlite3.SQLITE_CREATE_TEMP_INDEX,
        sqlite3.SQLITE_CREATE_TEMP_TABLE,
        sqlite3.SQLITE_CREATE_TEMP_TRIGGER,
        sqlite3.SQLITE_CREATE_TEMP_VIEW,
        sqlite3.SQLITE_CREATE_TRIGGER,
        sqlite3.SQLITE_CREATE_VIEW,
        sqlite3.SQLITE_CREATE_VTABLE,
        sqlite3.SQLITE_DETACH,
        sqlite3.SQLITE_DROP_INDEX,
        sqlite3.SQLITE_DROP_TABLE,
        sqlite3.SQLITE_DROP_TEMP_INDEX,
        sqlite3.SQLITE_DROP_TEMP_TABLE,
        sqlite3.SQLITE_DROP_TEMP_TRIGGER,
        sqlite3.SQLITE_DROP_TEMP_VIEW,
        sqlite3.SQLITE_DROP_TRIGGER,
        sqlite3.SQLITE_DROP_VIEW,
        sqlite3.SQLITE_DROP_VTABLE,
        sqlite3.SQLITE_REINDEX,
    }
)


def _recovery_sqlite_authorizer(
    action_code: int,
    arg1: str | None,
    arg2: str | None,
    database_name: str | None,
    trigger_or_view: str | None,
) -> int:
    del arg2, database_name
    if action_code in _SCHEMA_MUTATION_ACTIONS or action_code == sqlite3.SQLITE_PRAGMA:
        return sqlite3.SQLITE_DENY
    if arg1 != "snapshot_apply_mutations":
        return sqlite3.SQLITE_OK
    if action_code == sqlite3.SQLITE_INSERT:
        return (
            sqlite3.SQLITE_OK
            if trigger_or_view in _SNAPSHOT_MUTATION_TRIGGERS
            else sqlite3.SQLITE_DENY
        )
    if action_code in {sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE}:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def _sha256(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"
