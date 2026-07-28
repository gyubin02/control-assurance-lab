"""Executable reference environment for the financial support-export experiment.

This is the implementation under test.  It deliberately does not call the pure
oracle in ``financial_support.py``.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass

import rfc8785

from assurance_lab.contract import BooleanValue, CellSelector, StringValue
from assurance_lab.scenarios.financial_data import SyntheticDataset
from assurance_lab.scenarios.financial_support import (
    AuthorizationDecision,
    ReleaseDecision,
)
from assurance_lab.scenarios.financial_support_contract import (
    ATTACK,
    BENIGN,
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
    events: tuple[RuntimeEvent, ...]


class FinancialSupportRuntime:
    """Run one action against a fresh SQLite clone of the synthetic fixture."""

    def __init__(self, dataset: SyntheticDataset, *, bulk_threshold_records: int = 10):
        if bulk_threshold_records < 1:
            raise ValueError("bulk threshold must be positive")
        _validate_fixture(dataset)
        self._dataset = dataset
        self._bulk_threshold = bulk_threshold_records

    def execute(self, selector: CellSelector, *, trace_id: str) -> FinancialRuntimeResult:
        input_level = _string_level(selector.input, "input")
        target_level = _string_level(selector.target, "target")
        compensator_level = _string_level(selector.compensator, "compensator")
        sham_level = _boolean_level(selector.sham, "sham")
        if input_level not in {ATTACK.value, BENIGN.value}:
            raise ValueError(f"unsupported input level: {input_level!r}")
        if target_level not in {TARGET_INEFFECTIVE.value, TARGET_EFFECTIVE.value}:
            raise ValueError(f"unsupported target level: {target_level!r}")
        if compensator_level not in {COMPENSATOR_OFF.value, COMPENSATOR_ON.value}:
            raise ValueError(f"unsupported compensator level: {compensator_level!r}")
        if sham_level not in {SHAM_STEADY.value, SHAM_REDEPLOY.value}:
            raise ValueError(f"unsupported sham level: {sham_level!r}")

        action_level = ATTACK if input_level == ATTACK.value else BENIGN
        action = action_descriptor(action_level)
        action_digest = _sha256(rfc8785.dumps(action))
        principal_id = _required_text(action, "principal_id")
        requested_ids = tuple(_required_text_list(action, "requested_customer_ids"))

        connection = self._fresh_database()
        if sham_level:
            connection.close()
            connection = self._fresh_database()
        try:
            assigned_ids = _assigned_customers(connection, principal_id)
            wildcard = target_level == TARGET_INEFFECTIVE.value
            allowed = wildcard or set(requested_ids).issubset(assigned_ids)
            selected = (
                _select_customers(connection, requested_ids) if allowed else ()
            )
        finally:
            connection.close()

        outside_assignment = set(requested_ids).difference(assigned_ids)
        selected_outside = tuple(
            customer_id for customer_id in selected if customer_id in outside_assignment
        )
        target_blocks = not allowed
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
        delivered = () if release_blocked or target_blocks else selected
        delivered_outside = tuple(
            customer_id for customer_id in delivered if customer_id in outside_assignment
        )
        assigned_delivered = tuple(
            customer_id for customer_id in delivered if customer_id in assigned_ids
        )
        payload_digest = _sha256(
            rfc8785.dumps(
                {
                    "trace_id": trace_id,
                    "delivered_customer_ids": list(delivered),
                }
            )
        )
        authorization = (
            AuthorizationDecision.ALLOW if allowed else AuthorizationDecision.DENY
        )
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
            events=events,
        )

    def _fresh_database(self) -> sqlite3.Connection:
        connection = sqlite3.connect(":memory:")
        connection.execute(
            """
            CREATE TABLE customers (
                customer_id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                email TEXT NOT NULL,
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
        connection.executemany(
            "INSERT INTO customers VALUES (?, ?, ?, ?)",
            (
                (
                    customer.customer_id,
                    customer.display_name,
                    customer.email,
                    int(customer.synthetic),
                )
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
        connection.commit()
        return connection


def _string_level(value: object, name: str) -> str:
    if not isinstance(value, StringValue):
        raise ValueError(f"{name} selector must be a string value")
    return value.value


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


def _boolean_level(value: object, name: str) -> bool:
    if not isinstance(value, BooleanValue):
        raise ValueError(f"{name} selector must be a boolean value")
    return value.value


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


def _assigned_customers(connection: sqlite3.Connection, principal_id: str) -> set[str]:
    rows = connection.execute(
        """
        SELECT customer_id
        FROM support_cases
        WHERE assigned_principal_id = ? AND status = 'active'
        ORDER BY customer_id
        """,
        (principal_id,),
    )
    return {str(row[0]) for row in rows}


def _select_customers(
    connection: sqlite3.Connection,
    customer_ids: tuple[str, ...],
) -> tuple[str, ...]:
    placeholders = ",".join("?" for _ in customer_ids)
    rows = connection.execute(
        f"""
        SELECT customer_id
        FROM customers
        WHERE customer_id IN ({placeholders})
        ORDER BY customer_id
        """,
        customer_ids,
    )
    selected = tuple(str(row[0]) for row in rows)
    if len(selected) != len(customer_ids):
        raise ValueError("action references a customer outside the synthetic fixture")
    return selected


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
