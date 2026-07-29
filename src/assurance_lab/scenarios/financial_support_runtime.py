"""Executable SQLite boundary for the financial support-export experiment.

The runtime exposes the rows and operation receipts that its conclusions are
derived from.  Convenience summaries and stage events remain for callers, but
the bundle repository is expected to reconstruct them from these lower-level
observations instead of trusting the summaries.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from typing import Literal

import rfc8785

from assurance_lab.contract import BooleanValue, CellSelector, StringValue
from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.scenarios.financial_data import SyntheticDataset
from assurance_lab.scenarios.financial_support import (
    AuthorizationDecision,
    ReleaseDecision,
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

type Scalar = str | int | bool
type Payload = tuple[tuple[str, Scalar], ...]

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}$")


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
class PrincipalRow:
    principal_id: str
    role: str
    status: str
    entitlement_version: int


@dataclass(frozen=True, slots=True)
class CustomerRow:
    customer_id: str
    display_name: str
    email: str
    customer_type: str
    region_code: str
    risk_tier: str
    synthetic: bool


@dataclass(frozen=True, slots=True)
class SupportCaseRow:
    case_id: str
    customer_id: str
    assigned_principal_id: str
    purpose: str
    status: str
    valid_from_offset_seconds: int
    valid_until_offset_seconds: int


@dataclass(frozen=True, slots=True)
class ResourceIdentityReceipt:
    requested_clone_nonce: str
    requested_runner_resource_id: str
    observed_clone_nonce: str
    observed_runner_resource_id: str
    observed_runtime_instance_id: str
    observed_generation: int
    observed_dataset_snapshot_digest: str


@dataclass(frozen=True, slots=True)
class ActionRequestReceipt:
    request_id: str
    trace_id: str
    action_digest: str
    principal_id: str
    requested_customer_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AuthorizationReceipt:
    request_id: str
    target_mode: str
    decision: AuthorizationDecision
    allowed: bool
    assigned_customer_ids: tuple[str, ...]
    requested_customer_ids: tuple[str, ...]
    assigned_rows_evaluated: int
    requested_rows_found: int


@dataclass(frozen=True, slots=True)
class SelectionReceipt:
    request_id: str
    query_id: str
    selected_customer_ids: tuple[str, ...]
    row_count: int


@dataclass(frozen=True, slots=True)
class GuardDecisionReceipt:
    request_id: str
    compensator_mode: str
    reached: bool
    decision: ReleaseDecision
    selected_record_count: int
    bulk_threshold_records: int


@dataclass(frozen=True, slots=True)
class DeliveryReceipt:
    request_id: str
    selected_customer_ids: tuple[str, ...]
    delivered_customer_ids: tuple[str, ...]
    payload_digest: str


@dataclass(frozen=True, slots=True)
class ClientReceipt:
    request_id: str
    received_customer_ids: tuple[str, ...]
    payload_digest: str


@dataclass(frozen=True, slots=True)
class RedeployOperationReceipt:
    operation_id: str
    requested: bool
    performed: bool
    before_runtime_instance_id: str
    after_runtime_instance_id: str
    before_dataset_snapshot_digest: str
    after_dataset_snapshot_digest: str
    before_principal_count: int
    after_principal_count: int
    before_customer_count: int
    after_customer_count: int
    before_support_case_count: int
    after_support_case_count: int
    previous_handle_closed: bool


@dataclass(frozen=True, slots=True)
class CleanupProbeReceipt:
    clone_nonce: str
    runner_resource_id: str
    runtime_instance_id: str
    probe_operation: Literal["select-runtime-identity-after-close"]
    error_type: Literal["sqlite3.ProgrammingError"]
    closed_handle_rejected_operation: Literal[True]


@dataclass(frozen=True, slots=True)
class FinancialRuntimeResult:
    trace_id: str
    action_digest: str
    authorization_decision: AuthorizationDecision
    target_blocks_downstream: bool
    out_of_scope_records_selected: int
    release_guard_reached: bool
    release_guard_decision: ReleaseDecision
    compensator_blocks_downstream: bool
    out_of_scope_records_delivered: int
    assigned_case_records_delivered: int
    delivered_payload_digest: str
    selected_customer_ids: tuple[str, ...]
    delivered_customer_ids: tuple[str, ...]
    resource_identity: ResourceIdentityReceipt
    redeploy_operation: RedeployOperationReceipt
    principal_rows: tuple[PrincipalRow, ...]
    requested_customer_rows: tuple[CustomerRow, ...]
    assigned_support_case_rows: tuple[SupportCaseRow, ...]
    request_receipt: ActionRequestReceipt
    authorization_receipt: AuthorizationReceipt
    selection_receipt: SelectionReceipt
    guard_receipt: GuardDecisionReceipt
    delivery_receipt: DeliveryReceipt
    client_receipt: ClientReceipt
    cleanup_probe: CleanupProbeReceipt
    events: tuple[RuntimeEvent, ...]


class FinancialSupportRuntime:
    """Run one action against a fresh, runner-identified SQLite clone."""

    def __init__(
        self,
        dataset: SyntheticDataset,
        *,
        bulk_threshold_records: int = 10,
    ) -> None:
        if bulk_threshold_records < 1:
            raise ValueError("bulk threshold must be positive")
        _validate_fixture(dataset)
        self._dataset = dataset
        self._bulk_threshold = bulk_threshold_records

    def execute(
        self,
        selector: CellSelector,
        *,
        trace_id: str,
        clone_nonce: str | None = None,
        runner_resource_id: str = "financial-support-sqlite-runner",
    ) -> FinancialRuntimeResult:
        _validate_identifier(trace_id, "trace_id")
        if clone_nonce is None:
            clone_nonce = f"runtime-clone-{trace_id}"
        _validate_identifier(clone_nonce, "clone_nonce")
        _validate_identifier(runner_resource_id, "runner_resource_id")

        input_level = _string_level(selector.input, "input")
        target_level = _string_level(selector.target, "target")
        compensator_level = _string_level(selector.compensator, "compensator")
        sham_level = _boolean_level(selector.sham, "sham")
        _require_level(input_level, {ATTACK.value, BENIGN.value}, "input")
        _require_level(
            target_level,
            {TARGET_INEFFECTIVE.value, TARGET_EFFECTIVE.value},
            "target",
        )
        _require_level(
            compensator_level,
            {COMPENSATOR_OFF.value, COMPENSATOR_ON.value},
            "compensator",
        )
        if sham_level not in {SHAM_STEADY.value, SHAM_REDEPLOY.value}:
            raise ValueError(f"unsupported sham level: {sham_level!r}")

        action_level = ATTACK if input_level == ATTACK.value else BENIGN
        action = action_descriptor(action_level)
        action_digest = _sha256(rfc8785.dumps(action))
        expected_digest = (
            ATTACK_ACTION_DIGEST if action_level == ATTACK else BENIGN_ACTION_DIGEST
        )
        if action_digest != expected_digest:
            raise RuntimeError("fixed action no longer matches its contract digest")
        principal_id = _required_text(action, "principal_id")
        requested_ids = tuple(_required_text_list(action, "requested_customer_ids"))
        request_id = f"request-{trace_id}"

        connection = self._fresh_database(
            clone_nonce=clone_nonce,
            runner_resource_id=runner_resource_id,
            generation=1,
        )
        before_identity = _resource_identity(connection)
        before_counts = _source_table_counts(connection)
        previous_handle_closed = False
        if sham_level:
            _close_with_probe(
                connection,
                clone_nonce=clone_nonce,
                runner_resource_id=runner_resource_id,
                runtime_instance_id=before_identity.observed_runtime_instance_id,
            )
            previous_handle_closed = True
            connection = self._fresh_database(
                clone_nonce=clone_nonce,
                runner_resource_id=runner_resource_id,
                generation=2,
            )
        after_identity = _resource_identity(connection)
        after_counts = _source_table_counts(connection)
        redeploy = _persist_and_read_redeploy(
            connection,
            operation_id=f"redeploy-{trace_id}",
            requested=sham_level,
            performed=sham_level,
            before_identity=before_identity,
            after_identity=after_identity,
            before_counts=before_counts,
            after_counts=after_counts,
            previous_handle_closed=previous_handle_closed,
        )

        _persist_request(
            connection,
            request_id=request_id,
            trace_id=trace_id,
            action_digest=action_digest,
            principal_id=principal_id,
            requested_ids=requested_ids,
        )
        request_receipt = _request_receipt(connection, request_id)
        principal_rows = _principal_rows(connection, principal_id)
        assigned_case_rows = _assigned_support_case_rows(connection, principal_id)
        requested_customer_rows = _customer_rows(connection, requested_ids)
        if len(requested_customer_rows) != len(requested_ids):
            connection.close()
            raise ValueError("action references a customer outside the synthetic fixture")
        assigned_ids = tuple(sorted(row.customer_id for row in assigned_case_rows))
        wildcard = target_level == TARGET_INEFFECTIVE.value
        allowed = wildcard or set(requested_ids).issubset(assigned_ids)
        authorization = (
            AuthorizationDecision.ALLOW if allowed else AuthorizationDecision.DENY
        )
        _persist_authorization(
            connection,
            request_id=request_id,
            target_mode=target_level,
            authorization=authorization,
            allowed=allowed,
            assigned_ids=assigned_ids,
            requested_ids=requested_ids,
            requested_rows_found=len(requested_customer_rows),
        )
        authorization_receipt = _authorization_receipt(connection, request_id)

        selected = (
            tuple(row.customer_id for row in requested_customer_rows) if allowed else ()
        )
        selected = tuple(sorted(selected))
        _persist_selection(
            connection,
            request_id=request_id,
            selected_ids=selected,
        )
        selection_receipt = _selection_receipt(connection, request_id)

        guard_reached = allowed
        sensitive_bulk = len(selected) >= self._bulk_threshold
        enforce = compensator_level == COMPENSATOR_ON.value
        release_blocked = guard_reached and enforce and sensitive_bulk
        if not guard_reached:
            release_decision = ReleaseDecision.NOT_REACHED
        elif release_blocked:
            release_decision = ReleaseDecision.BLOCK
        else:
            release_decision = ReleaseDecision.ALLOW
        _persist_guard(
            connection,
            request_id=request_id,
            compensator_mode=compensator_level,
            reached=guard_reached,
            decision=release_decision,
            selected_record_count=len(selected),
            bulk_threshold_records=self._bulk_threshold,
        )
        guard_receipt = _guard_receipt(connection, request_id)

        delivered = () if release_blocked or not allowed else selected
        payload_digest = _sha256(
            rfc8785.dumps(
                {
                    "trace_id": trace_id,
                    "delivered_customer_ids": list(delivered),
                }
            )
        )
        _persist_delivery_and_client_receipt(
            connection,
            request_id=request_id,
            selected_ids=selected,
            delivered_ids=delivered,
            payload_digest=payload_digest,
        )
        delivery_receipt = _delivery_receipt(connection, request_id)
        client_receipt = _client_receipt(connection, request_id)

        outside_assignment = set(requested_ids).difference(assigned_ids)
        selected_outside = tuple(
            customer_id for customer_id in selected if customer_id in outside_assignment
        )
        delivered_outside = tuple(
            customer_id for customer_id in delivered if customer_id in outside_assignment
        )
        assigned_delivered = tuple(
            customer_id for customer_id in delivered if customer_id in set(assigned_ids)
        )
        target_blocks = not allowed
        events = _events(
            trace_id=trace_id,
            action_digest=action_digest,
            authorization=authorization,
            selected_outside=len(selected_outside),
            guard_reached=guard_reached,
            release_decision=release_decision,
            delivered_outside=len(delivered_outside),
            assigned_delivered=len(assigned_delivered),
            payload_digest=payload_digest,
            sham_redeploy=sham_level,
        )
        cleanup_probe = _close_with_probe(
            connection,
            clone_nonce=clone_nonce,
            runner_resource_id=runner_resource_id,
            runtime_instance_id=after_identity.observed_runtime_instance_id,
        )
        return FinancialRuntimeResult(
            trace_id=trace_id,
            action_digest=action_digest,
            authorization_decision=authorization,
            target_blocks_downstream=target_blocks,
            out_of_scope_records_selected=len(selected_outside),
            release_guard_reached=guard_reached,
            release_guard_decision=release_decision,
            compensator_blocks_downstream=release_blocked,
            out_of_scope_records_delivered=len(delivered_outside),
            assigned_case_records_delivered=len(assigned_delivered),
            delivered_payload_digest=payload_digest,
            selected_customer_ids=selected,
            delivered_customer_ids=delivered,
            resource_identity=after_identity,
            redeploy_operation=redeploy,
            principal_rows=principal_rows,
            requested_customer_rows=requested_customer_rows,
            assigned_support_case_rows=assigned_case_rows,
            request_receipt=request_receipt,
            authorization_receipt=authorization_receipt,
            selection_receipt=selection_receipt,
            guard_receipt=guard_receipt,
            delivery_receipt=delivery_receipt,
            client_receipt=client_receipt,
            cleanup_probe=cleanup_probe,
            events=events,
        )

    def _fresh_database(
        self,
        *,
        clone_nonce: str,
        runner_resource_id: str,
        generation: int,
    ) -> sqlite3.Connection:
        connection = sqlite3.connect(":memory:")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(
            """
            CREATE TABLE runtime_identity (
                clone_nonce TEXT PRIMARY KEY,
                runner_resource_id TEXT NOT NULL,
                runtime_instance_id TEXT NOT NULL UNIQUE,
                generation INTEGER NOT NULL,
                dataset_snapshot_digest TEXT NOT NULL
            );
            CREATE TABLE principals (
                principal_id TEXT PRIMARY KEY,
                role TEXT NOT NULL,
                status TEXT NOT NULL,
                entitlement_version INTEGER NOT NULL
            );
            CREATE TABLE customers (
                customer_id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                email TEXT NOT NULL,
                customer_type TEXT NOT NULL,
                region_code TEXT NOT NULL,
                risk_tier TEXT NOT NULL,
                synthetic INTEGER NOT NULL CHECK (synthetic = 1)
            );
            CREATE TABLE support_cases (
                case_id TEXT PRIMARY KEY,
                customer_id TEXT NOT NULL REFERENCES customers(customer_id),
                assigned_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
                purpose TEXT NOT NULL,
                status TEXT NOT NULL,
                valid_from_offset_seconds INTEGER NOT NULL,
                valid_until_offset_seconds INTEGER NOT NULL
            );
            CREATE TABLE redeploy_operations (
                operation_id TEXT PRIMARY KEY,
                requested INTEGER NOT NULL,
                performed INTEGER NOT NULL,
                before_runtime_instance_id TEXT NOT NULL,
                after_runtime_instance_id TEXT NOT NULL,
                before_dataset_snapshot_digest TEXT NOT NULL,
                after_dataset_snapshot_digest TEXT NOT NULL,
                before_principal_count INTEGER NOT NULL,
                after_principal_count INTEGER NOT NULL,
                before_customer_count INTEGER NOT NULL,
                after_customer_count INTEGER NOT NULL,
                before_support_case_count INTEGER NOT NULL,
                after_support_case_count INTEGER NOT NULL,
                previous_handle_closed INTEGER NOT NULL
            );
            CREATE TABLE action_requests (
                request_id TEXT PRIMARY KEY,
                trace_id TEXT NOT NULL,
                action_digest TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                requested_customer_ids_json TEXT NOT NULL
            );
            CREATE TABLE authorization_decisions (
                request_id TEXT PRIMARY KEY REFERENCES action_requests(request_id),
                target_mode TEXT NOT NULL,
                decision TEXT NOT NULL,
                allowed INTEGER NOT NULL,
                assigned_customer_ids_json TEXT NOT NULL,
                requested_customer_ids_json TEXT NOT NULL,
                assigned_rows_evaluated INTEGER NOT NULL,
                requested_rows_found INTEGER NOT NULL
            );
            CREATE TABLE selection_receipts (
                request_id TEXT PRIMARY KEY REFERENCES action_requests(request_id),
                query_id TEXT NOT NULL UNIQUE,
                selected_customer_ids_json TEXT NOT NULL,
                row_count INTEGER NOT NULL
            );
            CREATE TABLE guard_decisions (
                request_id TEXT PRIMARY KEY REFERENCES action_requests(request_id),
                compensator_mode TEXT NOT NULL,
                reached INTEGER NOT NULL,
                decision TEXT NOT NULL,
                selected_record_count INTEGER NOT NULL,
                bulk_threshold_records INTEGER NOT NULL
            );
            CREATE TABLE delivery_receipts (
                request_id TEXT PRIMARY KEY REFERENCES action_requests(request_id),
                selected_customer_ids_json TEXT NOT NULL,
                delivered_customer_ids_json TEXT NOT NULL,
                payload_digest TEXT NOT NULL
            );
            CREATE TABLE client_receipts (
                request_id TEXT PRIMARY KEY REFERENCES action_requests(request_id),
                received_customer_ids_json TEXT NOT NULL,
                payload_digest TEXT NOT NULL
            );
            """
        )
        connection.executemany(
            "INSERT INTO principals VALUES (?, ?, ?, ?)",
            (
                (
                    item.principal_id,
                    item.role,
                    item.status,
                    item.entitlement_version,
                )
                for item in self._dataset.principals
            ),
        )
        connection.executemany(
            "INSERT INTO customers VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                (
                    item.customer_id,
                    item.display_name,
                    item.email,
                    item.customer_type,
                    item.region_code,
                    item.risk_tier,
                    int(item.synthetic),
                )
                for item in self._dataset.customers
            ),
        )
        connection.executemany(
            "INSERT INTO support_cases VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                (
                    item.case_id,
                    item.customer_id,
                    item.assigned_principal_id,
                    item.purpose,
                    item.status,
                    item.valid_from_offset_seconds,
                    item.valid_until_offset_seconds,
                )
                for item in self._dataset.support_cases
            ),
        )
        snapshot_digest = _database_dataset_snapshot_digest(connection)
        runtime_instance_id = f"{clone_nonce}:generation-{generation}"
        connection.execute(
            "INSERT INTO runtime_identity VALUES (?, ?, ?, ?, ?)",
            (
                clone_nonce,
                runner_resource_id,
                runtime_instance_id,
                generation,
                snapshot_digest,
            ),
        )
        connection.commit()
        return connection


def runtime_dataset_snapshot(dataset: SyntheticDataset) -> dict[str, object]:
    """Return the exact source rows loaded by this runtime.

    Accounts and transactions are intentionally absent: this executable case
    never loads or queries them.  The full generator manifest remains bundled
    separately and is regenerated by the repository.
    """

    return {
        "schema": "assurance-lab.financial-support-runtime-dataset/v1",
        "generator_version": dataset.generator_version,
        "seed": dataset.seed,
        "profile": dataset.profile.value,
        "principals": [
            {
                "principal_id": item.principal_id,
                "role": item.role,
                "status": item.status,
                "entitlement_version": item.entitlement_version,
            }
            for item in sorted(dataset.principals, key=lambda row: row.principal_id)
        ],
        "customers": [
            {
                "customer_id": item.customer_id,
                "display_name": item.display_name,
                "email": item.email,
                "customer_type": item.customer_type,
                "region_code": item.region_code,
                "risk_tier": item.risk_tier,
                "synthetic": item.synthetic,
            }
            for item in sorted(dataset.customers, key=lambda row: row.customer_id)
        ],
        "support_cases": [
            {
                "case_id": item.case_id,
                "customer_id": item.customer_id,
                "assigned_principal_id": item.assigned_principal_id,
                "purpose": item.purpose,
                "status": item.status,
                "valid_from_offset_seconds": item.valid_from_offset_seconds,
                "valid_until_offset_seconds": item.valid_until_offset_seconds,
            }
            for item in sorted(dataset.support_cases, key=lambda row: row.case_id)
        ],
    }


def _database_dataset_snapshot_digest(connection: sqlite3.Connection) -> str:
    value = {
        "schema": "assurance-lab.financial-support-runtime-dataset/v1",
        "generator_version": None,
        "seed": None,
        "profile": None,
        "principals": [
            {
                "principal_id": str(row[0]),
                "role": str(row[1]),
                "status": str(row[2]),
                "entitlement_version": int(row[3]),
            }
            for row in connection.execute(
                """
                SELECT principal_id, role, status, entitlement_version
                FROM principals ORDER BY principal_id
                """
            )
        ],
        "customers": [
            {
                "customer_id": str(row[0]),
                "display_name": str(row[1]),
                "email": str(row[2]),
                "customer_type": str(row[3]),
                "region_code": str(row[4]),
                "risk_tier": str(row[5]),
                "synthetic": bool(row[6]),
            }
            for row in connection.execute(
                """
                SELECT customer_id, display_name, email, customer_type,
                       region_code, risk_tier, synthetic
                FROM customers ORDER BY customer_id
                """
            )
        ],
        "support_cases": [
            {
                "case_id": str(row[0]),
                "customer_id": str(row[1]),
                "assigned_principal_id": str(row[2]),
                "purpose": str(row[3]),
                "status": str(row[4]),
                "valid_from_offset_seconds": int(row[5]),
                "valid_until_offset_seconds": int(row[6]),
            }
            for row in connection.execute(
                """
                SELECT case_id, customer_id, assigned_principal_id, purpose,
                       status, valid_from_offset_seconds, valid_until_offset_seconds
                FROM support_cases ORDER BY case_id
                """
            )
        ],
    }
    return _sha256(canonical_json_bytes(value))


def runtime_database_snapshot_digest(dataset: SyntheticDataset) -> str:
    """Derive the runtime database digest before a connection exists."""

    snapshot = runtime_dataset_snapshot(dataset)
    normalized = {
        **snapshot,
        "generator_version": None,
        "seed": None,
        "profile": None,
    }
    return _sha256(canonical_json_bytes(normalized))


def _source_table_counts(connection: sqlite3.Connection) -> tuple[int, int, int]:
    return tuple(
        int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        for table in ("principals", "customers", "support_cases")
    )  # type: ignore[return-value]


def _persist_and_read_redeploy(
    connection: sqlite3.Connection,
    *,
    operation_id: str,
    requested: bool,
    performed: bool,
    before_identity: ResourceIdentityReceipt,
    after_identity: ResourceIdentityReceipt,
    before_counts: tuple[int, int, int],
    after_counts: tuple[int, int, int],
    previous_handle_closed: bool,
) -> RedeployOperationReceipt:
    connection.execute(
        "INSERT INTO redeploy_operations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            operation_id,
            int(requested),
            int(performed),
            before_identity.observed_runtime_instance_id,
            after_identity.observed_runtime_instance_id,
            before_identity.observed_dataset_snapshot_digest,
            after_identity.observed_dataset_snapshot_digest,
            before_counts[0],
            after_counts[0],
            before_counts[1],
            after_counts[1],
            before_counts[2],
            after_counts[2],
            int(previous_handle_closed),
        ),
    )
    connection.commit()
    row = connection.execute(
        """
        SELECT operation_id, requested, performed, before_runtime_instance_id,
               after_runtime_instance_id, before_dataset_snapshot_digest,
               after_dataset_snapshot_digest, before_principal_count,
               after_principal_count, before_customer_count, after_customer_count,
               before_support_case_count, after_support_case_count,
               previous_handle_closed
        FROM redeploy_operations WHERE operation_id = ?
        """,
        (operation_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError("redeploy operation was not persisted")
    return RedeployOperationReceipt(
        operation_id=str(row[0]),
        requested=bool(row[1]),
        performed=bool(row[2]),
        before_runtime_instance_id=str(row[3]),
        after_runtime_instance_id=str(row[4]),
        before_dataset_snapshot_digest=str(row[5]),
        after_dataset_snapshot_digest=str(row[6]),
        before_principal_count=int(row[7]),
        after_principal_count=int(row[8]),
        before_customer_count=int(row[9]),
        after_customer_count=int(row[10]),
        before_support_case_count=int(row[11]),
        after_support_case_count=int(row[12]),
        previous_handle_closed=bool(row[13]),
    )


def _persist_request(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    trace_id: str,
    action_digest: str,
    principal_id: str,
    requested_ids: tuple[str, ...],
) -> None:
    connection.execute(
        "INSERT INTO action_requests VALUES (?, ?, ?, ?, ?)",
        (request_id, trace_id, action_digest, principal_id, _ids_json(requested_ids)),
    )
    connection.commit()


def _request_receipt(
    connection: sqlite3.Connection,
    request_id: str,
) -> ActionRequestReceipt:
    row = connection.execute(
        """
        SELECT request_id, trace_id, action_digest, principal_id,
               requested_customer_ids_json
        FROM action_requests WHERE request_id = ?
        """,
        (request_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError("action request was not persisted")
    return ActionRequestReceipt(
        request_id=str(row[0]),
        trace_id=str(row[1]),
        action_digest=str(row[2]),
        principal_id=str(row[3]),
        requested_customer_ids=_ids_from_json(str(row[4])),
    )


def _persist_authorization(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    target_mode: str,
    authorization: AuthorizationDecision,
    allowed: bool,
    assigned_ids: tuple[str, ...],
    requested_ids: tuple[str, ...],
    requested_rows_found: int,
) -> None:
    connection.execute(
        "INSERT INTO authorization_decisions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            request_id,
            target_mode,
            authorization.value,
            int(allowed),
            _ids_json(assigned_ids),
            _ids_json(requested_ids),
            len(assigned_ids),
            requested_rows_found,
        ),
    )
    connection.commit()


def _authorization_receipt(
    connection: sqlite3.Connection,
    request_id: str,
) -> AuthorizationReceipt:
    row = connection.execute(
        "SELECT * FROM authorization_decisions WHERE request_id = ?",
        (request_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError("authorization decision was not persisted")
    return AuthorizationReceipt(
        request_id=str(row[0]),
        target_mode=str(row[1]),
        decision=AuthorizationDecision(str(row[2])),
        allowed=bool(row[3]),
        assigned_customer_ids=_ids_from_json(str(row[4])),
        requested_customer_ids=_ids_from_json(str(row[5])),
        assigned_rows_evaluated=int(row[6]),
        requested_rows_found=int(row[7]),
    )


def _persist_selection(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    selected_ids: tuple[str, ...],
) -> None:
    connection.execute(
        "INSERT INTO selection_receipts VALUES (?, ?, ?, ?)",
        (
            request_id,
            f"selection-{request_id}",
            _ids_json(selected_ids),
            len(selected_ids),
        ),
    )
    connection.commit()


def _selection_receipt(
    connection: sqlite3.Connection,
    request_id: str,
) -> SelectionReceipt:
    row = connection.execute(
        "SELECT * FROM selection_receipts WHERE request_id = ?",
        (request_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError("selection receipt was not persisted")
    return SelectionReceipt(
        request_id=str(row[0]),
        query_id=str(row[1]),
        selected_customer_ids=_ids_from_json(str(row[2])),
        row_count=int(row[3]),
    )


def _persist_guard(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    compensator_mode: str,
    reached: bool,
    decision: ReleaseDecision,
    selected_record_count: int,
    bulk_threshold_records: int,
) -> None:
    connection.execute(
        "INSERT INTO guard_decisions VALUES (?, ?, ?, ?, ?, ?)",
        (
            request_id,
            compensator_mode,
            int(reached),
            decision.value,
            selected_record_count,
            bulk_threshold_records,
        ),
    )
    connection.commit()


def _guard_receipt(
    connection: sqlite3.Connection,
    request_id: str,
) -> GuardDecisionReceipt:
    row = connection.execute(
        "SELECT * FROM guard_decisions WHERE request_id = ?",
        (request_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError("guard decision was not persisted")
    return GuardDecisionReceipt(
        request_id=str(row[0]),
        compensator_mode=str(row[1]),
        reached=bool(row[2]),
        decision=ReleaseDecision(str(row[3])),
        selected_record_count=int(row[4]),
        bulk_threshold_records=int(row[5]),
    )


def _persist_delivery_and_client_receipt(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    selected_ids: tuple[str, ...],
    delivered_ids: tuple[str, ...],
    payload_digest: str,
) -> None:
    connection.execute(
        "INSERT INTO delivery_receipts VALUES (?, ?, ?, ?)",
        (
            request_id,
            _ids_json(selected_ids),
            _ids_json(delivered_ids),
            payload_digest,
        ),
    )
    connection.execute(
        "INSERT INTO client_receipts VALUES (?, ?, ?)",
        (request_id, _ids_json(delivered_ids), payload_digest),
    )
    connection.commit()


def _delivery_receipt(
    connection: sqlite3.Connection,
    request_id: str,
) -> DeliveryReceipt:
    row = connection.execute(
        "SELECT * FROM delivery_receipts WHERE request_id = ?",
        (request_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError("delivery receipt was not persisted")
    return DeliveryReceipt(
        request_id=str(row[0]),
        selected_customer_ids=_ids_from_json(str(row[1])),
        delivered_customer_ids=_ids_from_json(str(row[2])),
        payload_digest=str(row[3]),
    )


def _client_receipt(
    connection: sqlite3.Connection,
    request_id: str,
) -> ClientReceipt:
    row = connection.execute(
        "SELECT * FROM client_receipts WHERE request_id = ?",
        (request_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError("client receipt was not persisted")
    return ClientReceipt(
        request_id=str(row[0]),
        received_customer_ids=_ids_from_json(str(row[1])),
        payload_digest=str(row[2]),
    )


def _resource_identity(connection: sqlite3.Connection) -> ResourceIdentityReceipt:
    rows = tuple(
        connection.execute(
            """
            SELECT clone_nonce, runner_resource_id, runtime_instance_id,
                   generation, dataset_snapshot_digest
            FROM runtime_identity ORDER BY clone_nonce
            """
        )
    )
    if len(rows) != 1:
        raise RuntimeError("runtime identity table must contain exactly one row")
    row = rows[0]
    return ResourceIdentityReceipt(
        requested_clone_nonce=str(row[0]),
        requested_runner_resource_id=str(row[1]),
        observed_clone_nonce=str(row[0]),
        observed_runner_resource_id=str(row[1]),
        observed_runtime_instance_id=str(row[2]),
        observed_generation=int(row[3]),
        observed_dataset_snapshot_digest=str(row[4]),
    )


def _principal_rows(
    connection: sqlite3.Connection,
    principal_id: str,
) -> tuple[PrincipalRow, ...]:
    return tuple(
        PrincipalRow(
            principal_id=str(row[0]),
            role=str(row[1]),
            status=str(row[2]),
            entitlement_version=int(row[3]),
        )
        for row in connection.execute(
            """
            SELECT principal_id, role, status, entitlement_version
            FROM principals WHERE principal_id = ? ORDER BY principal_id
            """,
            (principal_id,),
        )
    )


def _customer_rows(
    connection: sqlite3.Connection,
    customer_ids: tuple[str, ...],
) -> tuple[CustomerRow, ...]:
    placeholders = ",".join("?" for _ in customer_ids)
    return tuple(
        CustomerRow(
            customer_id=str(row[0]),
            display_name=str(row[1]),
            email=str(row[2]),
            customer_type=str(row[3]),
            region_code=str(row[4]),
            risk_tier=str(row[5]),
            synthetic=bool(row[6]),
        )
        for row in connection.execute(
            f"""
            SELECT customer_id, display_name, email, customer_type,
                   region_code, risk_tier, synthetic
            FROM customers WHERE customer_id IN ({placeholders})
            ORDER BY customer_id
            """,
            customer_ids,
        )
    )


def _assigned_support_case_rows(
    connection: sqlite3.Connection,
    principal_id: str,
) -> tuple[SupportCaseRow, ...]:
    return tuple(
        SupportCaseRow(
            case_id=str(row[0]),
            customer_id=str(row[1]),
            assigned_principal_id=str(row[2]),
            purpose=str(row[3]),
            status=str(row[4]),
            valid_from_offset_seconds=int(row[5]),
            valid_until_offset_seconds=int(row[6]),
        )
        for row in connection.execute(
            """
            SELECT case_id, customer_id, assigned_principal_id, purpose, status,
                   valid_from_offset_seconds, valid_until_offset_seconds
            FROM support_cases
            WHERE assigned_principal_id = ? AND status = 'active'
            ORDER BY case_id
            """,
            (principal_id,),
        )
    )


def _close_with_probe(
    connection: sqlite3.Connection,
    *,
    clone_nonce: str,
    runner_resource_id: str,
    runtime_instance_id: str,
) -> CleanupProbeReceipt:
    connection.close()
    try:
        connection.execute(
            "SELECT clone_nonce, runner_resource_id FROM runtime_identity"
        )
    except sqlite3.ProgrammingError:
        return CleanupProbeReceipt(
            clone_nonce=clone_nonce,
            runner_resource_id=runner_resource_id,
            runtime_instance_id=runtime_instance_id,
            probe_operation="select-runtime-identity-after-close",
            error_type="sqlite3.ProgrammingError",
            closed_handle_rejected_operation=True,
        )
    raise RuntimeError("closed SQLite handle unexpectedly accepted a query")


def _ids_json(values: tuple[str, ...]) -> str:
    return rfc8785.dumps(list(values)).decode("utf-8")


def _ids_from_json(value: str) -> tuple[str, ...]:
    parsed = json.loads(value)
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        raise RuntimeError("persisted customer-id list is malformed")
    return tuple(parsed)


def _string_level(value: object, name: str) -> str:
    if not isinstance(value, StringValue):
        raise ValueError(f"{name} selector must be a string value")
    return value.value


def _boolean_level(value: object, name: str) -> bool:
    if not isinstance(value, BooleanValue):
        raise ValueError(f"{name} selector must be a boolean value")
    return value.value


def _require_level(value: str, supported: set[str], name: str) -> None:
    if value not in supported:
        raise ValueError(f"unsupported {name} level: {value!r}")


def _validate_identifier(value: str, name: str) -> None:
    if _SAFE_ID.fullmatch(value) is None:
        raise ValueError(f"{name} must be a safe 1-192 character identifier")


def _validate_fixture(dataset: SyntheticDataset) -> None:
    active_support = {
        principal.principal_id
        for principal in dataset.principals
        if principal.role == "support" and principal.status == "active"
    }
    if "support-017" not in active_support:
        raise ValueError("fixture does not contain active principal support-017")
    assigned = {
        support_case.customer_id
        for support_case in dataset.support_cases
        if support_case.assigned_principal_id == "support-017"
        and support_case.status == "active"
    }
    if "SYNTH-CUSTOMER-000017" not in assigned:
        raise ValueError("fixture does not assign customer 000017 to support-017")
    customer_ids = {customer.customer_id for customer in dataset.customers}
    required = set(_required_text_list(action_descriptor(ATTACK), "requested_customer_ids"))
    required.update(_required_text_list(action_descriptor(BENIGN), "requested_customer_ids"))
    if not required.issubset(customer_ids):
        raise ValueError("fixture is missing a customer required by a fixed action")


def _required_text(action: dict[str, object], name: str) -> str:
    value = action.get(name)
    if not isinstance(value, str):
        raise ValueError(f"action field {name!r} is not text")
    return value


def _required_text_list(action: dict[str, object], name: str) -> tuple[str, ...]:
    value = action.get(name)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"action field {name!r} is not a text list")
    return tuple(value)


def _events(
    *,
    trace_id: str,
    action_digest: str,
    authorization: AuthorizationDecision,
    selected_outside: int,
    guard_reached: bool,
    release_decision: ReleaseDecision,
    delivered_outside: int,
    assigned_delivered: int,
    payload_digest: str,
    sham_redeploy: bool,
) -> tuple[RuntimeEvent, ...]:
    events = [
        RuntimeEvent(
            trace_id=trace_id,
            sequence=1,
            stage="input",
            component="support-client",
            event_type="action-issued",
            payload=(
                ("action_digest", action_digest),
                ("sham_redeploy", sham_redeploy),
            ),
        ),
        RuntimeEvent(
            trace_id=trace_id,
            sequence=2,
            stage="target",
            component="authorization-boundary",
            event_type="authorization-and-selection-observed",
            payload=(
                ("authorization_decision", authorization.value),
                ("out_of_scope_records_selected", selected_outside),
            ),
        ),
    ]
    if guard_reached:
        events.append(
            RuntimeEvent(
                trace_id=trace_id,
                sequence=3,
                stage="compensator",
                component="release-gateway",
                event_type="release-decision-observed",
                payload=(
                    ("release_guard_reached", True),
                    (
                        "unapproved_release_blocked",
                        release_decision == ReleaseDecision.BLOCK,
                    ),
                ),
            )
        )
    events.append(
        RuntimeEvent(
            trace_id=trace_id,
            sequence=4,
            stage="outcome",
            component="support-client",
            event_type="client-receipt-observed",
            payload=(
                ("out_of_scope_records_delivered", delivered_outside),
                ("assigned_case_records_delivered", assigned_delivered),
                ("delivered_payload_digest", payload_digest),
            ),
        )
    )
    return tuple(events)


def _sha256(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"
