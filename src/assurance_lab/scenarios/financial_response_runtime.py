"""Executable SQLite model for exact-session revocation and quarantine.

Each call receives a new identity/session database.  The target control may
revoke only the incident's exact old session.  The downstream compensator may
quarantine the principal, but is forbidden from editing session state.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Literal, cast

import rfc8785

from assurance_lab.contract import CellSelector, StringValue
from assurance_lab.scenarios.financial_response_contract import (
    ATTACK,
    ATTACK_ACTION_DIGEST,
    BENIGN,
    BENIGN_ACTION_DIGEST,
    COMPENSATOR_OFF,
    COMPENSATOR_ON,
    COMPROMISED_PRINCIPAL_ID,
    COMPROMISED_SESSION_ID,
    SHAM_RELOAD,
    SHAM_STEADY,
    SIBLING_SESSION_ID,
    TARGET_EFFECTIVE,
    TARGET_INEFFECTIVE,
    UNRELATED_PRINCIPAL_ID,
    UNRELATED_SESSION_ID,
    action_descriptor,
)

type Scalar = str | bool | int
type Payload = tuple[tuple[str, Scalar], ...]

_TRACE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
def responder_config_descriptor() -> dict[str, Any]:
    """Return the exact synthetic responder configuration exercised here.

    Its generation transition is persisted in SQLite.  It models configuration
    continuity across a responder replacement; it is not evidence that an
    operating-system process or production service was restarted.
    """

    return {
        "schema": "assurance-lab.financial-response-responder-config/v1",
        "component": "session-revoker",
        "model_boundary": (
            "synthetic persisted responder configuration generation transition; "
            "not a process restart"
        ),
        "attack_status": "reported-success",
        "benign_status": "not-triggered",
        "target_subject": {
            "principal_id": COMPROMISED_PRINCIPAL_ID,
            "session_id": COMPROMISED_SESSION_ID,
        },
    }


RESPONDER_CONFIG_DIGEST = (
    f"sha256:{hashlib.sha256(rfc8785.dumps(responder_config_descriptor())).hexdigest()}"
)


class ResponseActionStatus(StrEnum):
    NOT_TRIGGERED = "not-triggered"
    REPORTED_SUCCESS = "reported-success"


class BaselineVerdict(StrEnum):
    PASS = "pass"
    FAIL = "fail"


class ResponseResidualClassification(StrEnum):
    MASKED_REVOCATION_FAILURE = "masked_revocation_failure"
    EXPOSED_REPLAY = "exposed_replay"
    TARGET_EFFECTIVE = "target_effective"
    UNRESOLVED = "unresolved"


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
class SessionReadback:
    session_id: str
    principal_id: str
    active: bool


@dataclass(frozen=True, slots=True)
class PrincipalReadback:
    principal_id: str
    role: str
    quarantined: bool


@dataclass(frozen=True, slots=True)
class ResponderRuntimeReadback:
    clone_nonce: str
    instance_id: str
    generation: int
    config_digest: str


@dataclass(frozen=True, slots=True)
class ResponderShamReceipt:
    operation_id: str
    operation: Literal["steady-observation", "reload"]
    clone_nonce: str
    before_instance_id: str
    after_instance_id: str
    before_generation: int
    after_generation: int
    config_digest: str
    rows_affected: int


@dataclass(frozen=True, slots=True)
class ResponseActionReceipt:
    operation_id: str
    responder_instance_id: str
    trace_id: str
    action_digest: str
    target_mode: str
    principal_id: str
    session_id: str
    operation: Literal["not-triggered", "report-only", "revoke-exact"]
    status: ResponseActionStatus
    rows_affected: int


@dataclass(frozen=True, slots=True)
class MutationReceipt:
    component: Literal["session-revoker", "principal-quarantine"]
    operation: Literal["not-triggered", "report-only", "revoke-exact", "quarantine"]
    principal_id: str
    session_id: str | None
    rows_affected: int


@dataclass(frozen=True, slots=True)
class GatewayDecisionReceipt:
    query_id: str
    principal_id: str
    session_id: str
    session_found: bool
    principal_found: bool
    session_revoked: bool
    principal_quarantined: bool
    available: bool


@dataclass(frozen=True, slots=True)
class ResourceIdentityReceipt:
    requested_clone_nonce: str
    requested_runner_resource_id: str
    observed_clone_nonce: str
    observed_runner_resource_id: str


@dataclass(frozen=True, slots=True)
class CleanupProbeReceipt:
    clone_nonce: str
    runner_resource_id: str
    probe_operation: Literal["select-runtime-identity-after-close"]
    error_type: Literal["sqlite3.ProgrammingError"]
    closed_handle_rejected_operation: Literal[True]


@dataclass(frozen=True, slots=True)
class FinancialResponseRuntimeResult:
    trace_id: str
    action_digest: str
    response_action_status: ResponseActionStatus
    response_action_reported_success: bool
    exact_revocation_executed: bool
    compromised_session_active: bool
    non_target_sessions_active: bool
    compromised_principal_quarantined: bool
    compromised_session_replay_denied: bool
    unrelated_support_principal_available: bool
    target_modified_session_ids: tuple[str, ...]
    compensator_modified_session_ids: tuple[str, ...]
    session_readbacks: tuple[SessionReadback, ...]
    principal_readbacks: tuple[PrincipalReadback, ...]
    responder_before_sham: ResponderRuntimeReadback
    responder_after_sham: ResponderRuntimeReadback
    sham_operation: ResponderShamReceipt
    response_action_receipt: ResponseActionReceipt
    sessions_before_target: tuple[SessionReadback, ...]
    sessions_after_target: tuple[SessionReadback, ...]
    sessions_after_compensator: tuple[SessionReadback, ...]
    principals_before_target: tuple[PrincipalReadback, ...]
    principals_after_target: tuple[PrincipalReadback, ...]
    principals_after_compensator: tuple[PrincipalReadback, ...]
    target_mutation: MutationReceipt
    compensator_mutation: MutationReceipt
    gateway_decisions: tuple[GatewayDecisionReceipt, ...]
    resource_identity: ResourceIdentityReceipt
    cleanup_probe: CleanupProbeReceipt
    events: tuple[RuntimeEvent, ...]

    def session(self, session_id: str) -> SessionReadback:
        matches = tuple(
            readback
            for readback in self.session_readbacks
            if readback.session_id == session_id
        )
        if len(matches) != 1:
            raise KeyError(session_id)
        return matches[0]


@dataclass(frozen=True, slots=True)
class ResponseStatusAndReplayBaseline:
    name: Literal["response-status-and-replay-only"]
    verdict: BaselineVerdict
    response_action_reported_success: bool
    replay_denied: bool


@dataclass(frozen=True, slots=True)
class ResponseCaseAssessment:
    baseline: ResponseStatusAndReplayBaseline
    target_supported: bool
    compensator_supported: bool
    path_supported: bool
    benign_service_supported: bool
    residual_classification: ResponseResidualClassification


class FinancialResponseRuntime:
    """Execute one declared response cell against an isolated SQLite clone."""

    def execute(
        self,
        selector: CellSelector,
        *,
        trace_id: str,
        clone_nonce: str | None = None,
        runner_resource_id: str = "financial-response-sqlite-runner",
    ) -> FinancialResponseRuntimeResult:
        _validate_trace_id(trace_id)
        if clone_nonce is None:
            clone_nonce = f"runtime-clone-{trace_id}"
        _validate_resource_text(clone_nonce, "clone_nonce")
        _validate_resource_text(runner_resource_id, "runner_resource_id")
        input_level = _string_level(selector.input, "input")
        target_level = _string_level(selector.target, "target")
        compensator_level = _string_level(selector.compensator, "compensator")
        sham_level = _string_level(selector.sham, "sham")
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
        _require_level(sham_level, {SHAM_STEADY.value, SHAM_RELOAD.value}, "sham")

        action_level = ATTACK if input_level == ATTACK.value else BENIGN
        action = action_descriptor(action_level)
        action_digest = _sha256(rfc8785.dumps(action))
        if action_digest != (
            ATTACK_ACTION_DIGEST
            if action_level == ATTACK
            else BENIGN_ACTION_DIGEST
        ):
            raise RuntimeError("fixed action no longer matches its contracted digest")

        connection = self._fresh_database(
            clone_nonce=clone_nonce,
            runner_resource_id=runner_resource_id,
        )
        responder_before_sham = _responder_runtime(connection)
        sham_rows_affected = 0
        if sham_level == SHAM_RELOAD.value:
            sham_rows_affected = self._reload_responder(
                connection,
                clone_nonce=clone_nonce,
            )
        responder_after_sham = _responder_runtime(connection)
        sham_operation = _record_and_read_sham_operation(
            connection,
            operation=(
                "reload"
                if sham_level == SHAM_RELOAD.value
                else "steady-observation"
            ),
            before=responder_before_sham,
            after=responder_after_sham,
            rows_affected=sham_rows_affected,
        )
        _validate_sham_operation(
            sham_level=sham_level,
            before=responder_before_sham,
            after=responder_after_sham,
            receipt=sham_operation,
        )

        attack_triggered = input_level == ATTACK.value
        resource_identity = _resource_identity(
            connection,
            requested_clone_nonce=clone_nonce,
            requested_runner_resource_id=runner_resource_id,
        )
        if (
            resource_identity.observed_clone_nonce != clone_nonce
            or resource_identity.observed_runner_resource_id != runner_resource_id
        ):
            connection.close()
            raise RuntimeError(
                "runtime identity readback differs from the requested clone"
            )
        before_target = _session_states(connection)
        principals_before_target = _principal_states(connection)
        exact_revocation_executed = (
            attack_triggered and target_level == TARGET_EFFECTIVE.value
        )
        target_operation: Literal["not-triggered", "report-only", "revoke-exact"]
        target_rows_affected = 0
        if exact_revocation_executed:
            target_rows_affected = connection.execute(
                """
                UPDATE sessions
                SET revoked = 1
                WHERE session_id = ? AND principal_id = ?
                """,
                (COMPROMISED_SESSION_ID, COMPROMISED_PRINCIPAL_ID),
            ).rowcount
            if target_rows_affected != 1:
                connection.close()
                raise RuntimeError("exact-session revocation did not affect one session")
            connection.commit()
            target_operation = "revoke-exact"
        elif attack_triggered:
            target_operation = "report-only"
        else:
            target_operation = "not-triggered"
        expected_status = (
            ResponseActionStatus.REPORTED_SUCCESS
            if attack_triggered
            else ResponseActionStatus.NOT_TRIGGERED
        )
        response_action_receipt = _record_and_read_response_action(
            connection,
            responder=responder_after_sham,
            trace_id=trace_id,
            action_digest=action_digest,
            target_mode=target_level,
            operation=target_operation,
            status=expected_status,
            rows_affected=target_rows_affected,
        )
        if (
            response_action_receipt.operation_id
            != _expected_response_action_operation_id(
                trace_id=trace_id,
                action_digest=action_digest,
                target_mode=target_level,
                responder_instance_id=responder_after_sham.instance_id,
            )
            or response_action_receipt.responder_instance_id
            != responder_after_sham.instance_id
            or response_action_receipt.trace_id != trace_id
            or response_action_receipt.action_digest != action_digest
            or response_action_receipt.target_mode != target_level
            or response_action_receipt.principal_id
            != COMPROMISED_PRINCIPAL_ID
            or response_action_receipt.session_id != COMPROMISED_SESSION_ID
            or response_action_receipt.operation != target_operation
            or response_action_receipt.status != expected_status
            or response_action_receipt.rows_affected != target_rows_affected
        ):
            connection.close()
            raise RuntimeError(
                "response action readback differs from the executed operation"
            )
        status = response_action_receipt.status
        after_target = _session_states(connection)
        principals_after_target = _principal_states(connection)
        target_modified = _changed_session_ids(before_target, after_target)
        expected_target_modified = (
            (COMPROMISED_SESSION_ID,) if exact_revocation_executed else ()
        )
        if target_modified != expected_target_modified:
            connection.close()
            raise RuntimeError("target control changed a session outside its exact target")

        before_compensator = after_target
        quarantine_applied = (
            attack_triggered and compensator_level == COMPENSATOR_ON.value
        )
        compensator_rows_affected = 0
        if quarantine_applied:
            compensator_rows_affected = connection.execute(
                "UPDATE principals SET quarantined = 1 WHERE principal_id = ?",
                (COMPROMISED_PRINCIPAL_ID,),
            ).rowcount
            if compensator_rows_affected != 1:
                connection.close()
                raise RuntimeError("principal quarantine did not affect one principal")
            connection.commit()
        after_compensator = _session_states(connection)
        principals_after_compensator = _principal_states(connection)
        compensator_modified = _changed_session_ids(
            before_compensator,
            after_compensator,
        )
        if compensator_modified:
            connection.close()
            raise RuntimeError("principal quarantine modified session state")

        compromised_session_active = after_target[COMPROMISED_SESSION_ID][1]
        non_target_sessions_active = all(
            active
            for session_id, (_, active) in after_target.items()
            if session_id != COMPROMISED_SESSION_ID
        )
        compromised_principal_quarantined = _principal_quarantined(
            connection,
            COMPROMISED_PRINCIPAL_ID,
        )
        replay_decision = _request_decision(
            connection,
            query_id="probe-compromised-session-replay",
            principal_id=COMPROMISED_PRINCIPAL_ID,
            session_id=COMPROMISED_SESSION_ID,
        )
        unrelated_decision = _request_decision(
            connection,
            query_id="probe-unrelated-support-action",
            principal_id=UNRELATED_PRINCIPAL_ID,
            session_id=UNRELATED_SESSION_ID,
        )
        sessions_before_target = _session_readbacks(before_target)
        sessions_after_target = _session_readbacks(after_target)
        sessions_after_compensator = _session_readbacks(after_compensator)
        principals_before = _principal_readbacks(principals_before_target)
        principals_after_target_readback = _principal_readbacks(
            principals_after_target
        )
        principals_after_compensator_readback = _principal_readbacks(
            principals_after_compensator
        )
        cleanup_probe = _close_with_probe(
            connection,
            clone_nonce=clone_nonce,
            runner_resource_id=runner_resource_id,
        )

        events = _events(
            trace_id=trace_id,
            action_digest=action_digest,
            action_name=_required_text(action, "action"),
            sham_level=sham_level,
            target_level=target_level,
            status=status,
            exact_revocation_executed=exact_revocation_executed,
            compromised_session_active=compromised_session_active,
            non_target_sessions_active=non_target_sessions_active,
            target_modified_session_ids=target_modified,
            compensator_level=compensator_level,
            quarantine_applied=quarantine_applied,
            compromised_principal_quarantined=compromised_principal_quarantined,
            compensator_modified_session_ids=compensator_modified,
            replay_denied=not replay_decision.available,
            unrelated_available=unrelated_decision.available,
        )
        return FinancialResponseRuntimeResult(
            trace_id=trace_id,
            action_digest=action_digest,
            response_action_status=status,
            response_action_reported_success=(
                status == ResponseActionStatus.REPORTED_SUCCESS
            ),
            exact_revocation_executed=exact_revocation_executed,
            compromised_session_active=compromised_session_active,
            non_target_sessions_active=non_target_sessions_active,
            compromised_principal_quarantined=compromised_principal_quarantined,
            compromised_session_replay_denied=not replay_decision.available,
            unrelated_support_principal_available=unrelated_decision.available,
            target_modified_session_ids=target_modified,
            compensator_modified_session_ids=compensator_modified,
            session_readbacks=sessions_after_compensator,
            principal_readbacks=principals_after_compensator_readback,
            responder_before_sham=responder_before_sham,
            responder_after_sham=responder_after_sham,
            sham_operation=sham_operation,
            response_action_receipt=response_action_receipt,
            sessions_before_target=sessions_before_target,
            sessions_after_target=sessions_after_target,
            sessions_after_compensator=sessions_after_compensator,
            principals_before_target=principals_before,
            principals_after_target=principals_after_target_readback,
            principals_after_compensator=principals_after_compensator_readback,
            target_mutation=MutationReceipt(
                component="session-revoker",
                operation=target_operation,
                principal_id=COMPROMISED_PRINCIPAL_ID,
                session_id=COMPROMISED_SESSION_ID,
                rows_affected=target_rows_affected,
            ),
            compensator_mutation=MutationReceipt(
                component="principal-quarantine",
                operation=("quarantine" if quarantine_applied else "not-triggered"),
                principal_id=COMPROMISED_PRINCIPAL_ID,
                session_id=None,
                rows_affected=compensator_rows_affected,
            ),
            gateway_decisions=(replay_decision, unrelated_decision),
            resource_identity=resource_identity,
            cleanup_probe=cleanup_probe,
            events=events,
        )

    @staticmethod
    def _fresh_database(
        *,
        clone_nonce: str,
        runner_resource_id: str,
    ) -> sqlite3.Connection:
        connection = sqlite3.connect(":memory:")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            CREATE TABLE runtime_identity (
                clone_nonce TEXT PRIMARY KEY,
                runner_resource_id TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE principals (
                principal_id TEXT PRIMARY KEY,
                role TEXT NOT NULL,
                quarantined INTEGER NOT NULL CHECK (quarantined IN (0, 1))
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE sessions (
                session_id TEXT PRIMARY KEY,
                principal_id TEXT NOT NULL REFERENCES principals(principal_id),
                issued_at TEXT NOT NULL,
                revoked INTEGER NOT NULL CHECK (revoked IN (0, 1))
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE responder_runtime (
                slot TEXT PRIMARY KEY CHECK (slot = 'primary'),
                clone_nonce TEXT NOT NULL REFERENCES runtime_identity(clone_nonce),
                instance_id TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK (generation >= 0),
                config_digest TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE responder_sham_operations (
                operation_id TEXT PRIMARY KEY,
                operation TEXT NOT NULL
                    CHECK (operation IN ('steady-observation', 'reload')),
                clone_nonce TEXT NOT NULL REFERENCES runtime_identity(clone_nonce),
                before_instance_id TEXT NOT NULL,
                after_instance_id TEXT NOT NULL,
                before_generation INTEGER NOT NULL,
                after_generation INTEGER NOT NULL,
                config_digest TEXT NOT NULL,
                rows_affected INTEGER NOT NULL CHECK (rows_affected >= 0)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE response_actions (
                operation_id TEXT PRIMARY KEY,
                responder_instance_id TEXT NOT NULL,
                trace_id TEXT NOT NULL,
                action_digest TEXT NOT NULL,
                target_mode TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                operation TEXT NOT NULL
                    CHECK (
                        operation IN (
                            'not-triggered',
                            'report-only',
                            'revoke-exact'
                        )
                    ),
                status TEXT NOT NULL
                    CHECK (status IN ('not-triggered', 'reported-success')),
                rows_affected INTEGER NOT NULL CHECK (rows_affected >= 0)
            )
            """
        )
        connection.execute(
            "INSERT INTO runtime_identity VALUES (?, ?)",
            (clone_nonce, runner_resource_id),
        )
        connection.execute(
            "INSERT INTO responder_runtime VALUES ('primary', ?, ?, 0, ?)",
            (
                clone_nonce,
                _expected_responder_instance_id(clone_nonce, 0),
                RESPONDER_CONFIG_DIGEST,
            ),
        )
        connection.executemany(
            "INSERT INTO principals VALUES (?, ?, ?)",
            (
                (COMPROMISED_PRINCIPAL_ID, "support", 0),
                (UNRELATED_PRINCIPAL_ID, "support", 0),
            ),
        )
        connection.executemany(
            "INSERT INTO sessions VALUES (?, ?, ?, ?)",
            (
                (
                    COMPROMISED_SESSION_ID,
                    COMPROMISED_PRINCIPAL_ID,
                    "2026-07-01T00:00:00Z",
                    0,
                ),
                (
                    SIBLING_SESSION_ID,
                    COMPROMISED_PRINCIPAL_ID,
                    "2026-07-28T08:00:00Z",
                    0,
                ),
                (
                    UNRELATED_SESSION_ID,
                    UNRELATED_PRINCIPAL_ID,
                    "2026-07-28T08:30:00Z",
                    0,
                ),
            ),
        )
        connection.commit()
        return connection

    @staticmethod
    def _reload_responder(
        connection: sqlite3.Connection,
        *,
        clone_nonce: str,
    ) -> int:
        """Advance the persisted synthetic responder generation in the same clone."""

        before = _responder_runtime(connection)
        after_generation = before.generation + 1
        rows_affected = connection.execute(
            """
            UPDATE responder_runtime
            SET instance_id = ?, generation = ?
            WHERE slot = 'primary'
              AND clone_nonce = ?
              AND instance_id = ?
              AND generation = ?
              AND config_digest = ?
            """,
            (
                _expected_responder_instance_id(
                    clone_nonce,
                    after_generation,
                ),
                after_generation,
                clone_nonce,
                before.instance_id,
                before.generation,
                before.config_digest,
            ),
        ).rowcount
        connection.commit()
        return rows_affected


def assess_response_case(
    result: FinancialResponseRuntimeResult,
) -> ResponseCaseAssessment:
    """Compare the shallow operational signal with the exact control claim."""

    if result.action_digest != ATTACK_ACTION_DIGEST:
        raise ValueError("response assessment requires the fixed attack action")
    baseline_passes = (
        result.response_action_reported_success
        and result.compromised_session_replay_denied
    )
    target_supported = not result.compromised_session_active
    compensator_supported = result.compromised_principal_quarantined
    path_supported = result.compromised_session_replay_denied
    benign_supported = result.unrelated_support_principal_available
    if (
        not target_supported
        and compensator_supported
        and path_supported
        and benign_supported
    ):
        classification = ResponseResidualClassification.MASKED_REVOCATION_FAILURE
    elif not path_supported:
        classification = ResponseResidualClassification.EXPOSED_REPLAY
    elif target_supported and path_supported and benign_supported:
        classification = ResponseResidualClassification.TARGET_EFFECTIVE
    else:
        classification = ResponseResidualClassification.UNRESOLVED
    return ResponseCaseAssessment(
        baseline=ResponseStatusAndReplayBaseline(
            name="response-status-and-replay-only",
            verdict=(
                BaselineVerdict.PASS if baseline_passes else BaselineVerdict.FAIL
            ),
            response_action_reported_success=(
                result.response_action_reported_success
            ),
            replay_denied=result.compromised_session_replay_denied,
        ),
        target_supported=target_supported,
        compensator_supported=compensator_supported,
        path_supported=path_supported,
        benign_service_supported=benign_supported,
        residual_classification=classification,
    )


def _string_level(value: object, name: str) -> str:
    if not isinstance(value, StringValue):
        raise ValueError(f"{name} selector must be a string value")
    return value.value


def _require_level(value: str, supported: set[str], name: str) -> None:
    if value not in supported:
        raise ValueError(f"unsupported {name} level: {value!r}")


def _validate_trace_id(trace_id: str) -> None:
    if not _TRACE_ID.fullmatch(trace_id):
        raise ValueError("trace_id must be 1-128 safe identifier characters")


def _validate_resource_text(value: str, name: str) -> None:
    if not _TRACE_ID.fullmatch(value):
        raise ValueError(f"{name} must be 1-128 safe identifier characters")


def _required_text(action: dict[str, Any], name: str) -> str:
    value = action.get(name)
    if not isinstance(value, str):
        raise RuntimeError(f"fixed action field {name!r} is not text")
    return value


def _session_states(
    connection: sqlite3.Connection,
) -> dict[str, tuple[str, bool]]:
    rows = connection.execute(
        "SELECT session_id, principal_id, revoked FROM sessions ORDER BY session_id"
    )
    return {
        str(session_id): (str(principal_id), not bool(revoked))
        for session_id, principal_id, revoked in rows
    }


def _principal_states(
    connection: sqlite3.Connection,
) -> dict[str, tuple[str, bool]]:
    rows = connection.execute(
        "SELECT principal_id, role, quarantined FROM principals ORDER BY principal_id"
    )
    return {
        str(principal_id): (str(role), bool(quarantined))
        for principal_id, role, quarantined in rows
    }


def _session_readbacks(
    states: dict[str, tuple[str, bool]],
) -> tuple[SessionReadback, ...]:
    return tuple(
        SessionReadback(
            session_id=session_id,
            principal_id=principal_id,
            active=active,
        )
        for session_id, (principal_id, active) in sorted(states.items())
    )


def _principal_readbacks(
    states: dict[str, tuple[str, bool]],
) -> tuple[PrincipalReadback, ...]:
    return tuple(
        PrincipalReadback(
            principal_id=principal_id,
            role=role,
            quarantined=quarantined,
        )
        for principal_id, (role, quarantined) in sorted(states.items())
    )


def _expected_responder_instance_id(clone_nonce: str, generation: int) -> str:
    digest = hashlib.sha256(
        rfc8785.dumps(
            {
                "schema": "assurance-lab.responder-instance-id/v1",
                "clone_nonce": clone_nonce,
                "generation": generation,
                "config_digest": RESPONDER_CONFIG_DIGEST,
            }
        )
    ).hexdigest()
    return f"response-responder-{digest[:32]}-g{generation}"


def _expected_sham_operation_id(
    operation: Literal["steady-observation", "reload"],
    before: ResponderRuntimeReadback,
    after: ResponderRuntimeReadback,
) -> str:
    digest = hashlib.sha256(
        rfc8785.dumps(
            {
                "schema": "assurance-lab.responder-sham-operation-id/v1",
                "operation": operation,
                "clone_nonce": before.clone_nonce,
                "before_instance_id": before.instance_id,
                "after_instance_id": after.instance_id,
                "before_generation": before.generation,
                "after_generation": after.generation,
                "config_digest": before.config_digest,
            }
        )
    ).hexdigest()
    return f"response-sham-{digest[:32]}"


def _responder_runtime(
    connection: sqlite3.Connection,
) -> ResponderRuntimeReadback:
    rows = tuple(
        connection.execute(
            """
            SELECT clone_nonce, instance_id, generation, config_digest
            FROM responder_runtime
            WHERE slot = 'primary'
            """
        )
    )
    if len(rows) != 1:
        raise RuntimeError("responder runtime table must contain one primary row")
    clone_nonce, instance_id, generation, config_digest = rows[0]
    return ResponderRuntimeReadback(
        clone_nonce=str(clone_nonce),
        instance_id=str(instance_id),
        generation=int(generation),
        config_digest=str(config_digest),
    )


def _record_and_read_sham_operation(
    connection: sqlite3.Connection,
    *,
    operation: Literal["steady-observation", "reload"],
    before: ResponderRuntimeReadback,
    after: ResponderRuntimeReadback,
    rows_affected: int,
) -> ResponderShamReceipt:
    operation_id = _expected_sham_operation_id(operation, before, after)
    connection.execute(
        """
        INSERT INTO responder_sham_operations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            operation_id,
            operation,
            before.clone_nonce,
            before.instance_id,
            after.instance_id,
            before.generation,
            after.generation,
            before.config_digest,
            rows_affected,
        ),
    )
    connection.commit()
    rows = tuple(
        connection.execute(
            """
            SELECT operation_id, operation, clone_nonce,
                   before_instance_id, after_instance_id,
                   before_generation, after_generation,
                   config_digest, rows_affected
            FROM responder_sham_operations
            ORDER BY operation_id
            """
        )
    )
    if len(rows) != 1:
        raise RuntimeError("responder sham operation table must contain one row")
    row = rows[0]
    return ResponderShamReceipt(
        operation_id=str(row[0]),
        operation=row[1],
        clone_nonce=str(row[2]),
        before_instance_id=str(row[3]),
        after_instance_id=str(row[4]),
        before_generation=int(row[5]),
        after_generation=int(row[6]),
        config_digest=str(row[7]),
        rows_affected=int(row[8]),
    )


def _validate_sham_operation(
    *,
    sham_level: str,
    before: ResponderRuntimeReadback,
    after: ResponderRuntimeReadback,
    receipt: ResponderShamReceipt,
) -> None:
    expected_operation: Literal["steady-observation", "reload"] = (
        "reload" if sham_level == SHAM_RELOAD.value else "steady-observation"
    )
    expected_after_generation = (
        1 if expected_operation == "reload" else 0
    )
    expected_rows = 1 if expected_operation == "reload" else 0
    if (
        before.clone_nonce != after.clone_nonce
        or before.generation != 0
        or after.generation != expected_after_generation
        or before.config_digest != RESPONDER_CONFIG_DIGEST
        or after.config_digest != RESPONDER_CONFIG_DIGEST
        or before.instance_id
        != _expected_responder_instance_id(before.clone_nonce, 0)
        or after.instance_id
        != _expected_responder_instance_id(
            before.clone_nonce,
            expected_after_generation,
        )
        or receipt.operation
        != expected_operation
        or receipt.operation_id
        != _expected_sham_operation_id(expected_operation, before, after)
        or receipt.clone_nonce != before.clone_nonce
        or receipt.before_instance_id != before.instance_id
        or receipt.after_instance_id != after.instance_id
        or receipt.before_generation != before.generation
        or receipt.after_generation != after.generation
        or receipt.config_digest != before.config_digest
        or receipt.rows_affected != expected_rows
    ):
        raise RuntimeError(
            "responder sham operation differs from its persisted state transition"
        )


def _expected_response_action_operation_id(
    *,
    trace_id: str,
    action_digest: str,
    target_mode: str,
    responder_instance_id: str,
) -> str:
    digest = hashlib.sha256(
        rfc8785.dumps(
            {
                "schema": "assurance-lab.response-action-operation-id/v1",
                "trace_id": trace_id,
                "action_digest": action_digest,
                "target_mode": target_mode,
                "responder_instance_id": responder_instance_id,
            }
        )
    ).hexdigest()
    return f"response-action-{digest[:32]}"


def _record_and_read_response_action(
    connection: sqlite3.Connection,
    *,
    responder: ResponderRuntimeReadback,
    trace_id: str,
    action_digest: str,
    target_mode: str,
    operation: Literal["not-triggered", "report-only", "revoke-exact"],
    status: ResponseActionStatus,
    rows_affected: int,
) -> ResponseActionReceipt:
    operation_id = _expected_response_action_operation_id(
        trace_id=trace_id,
        action_digest=action_digest,
        target_mode=target_mode,
        responder_instance_id=responder.instance_id,
    )
    connection.execute(
        """
        INSERT INTO response_actions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            operation_id,
            responder.instance_id,
            trace_id,
            action_digest,
            target_mode,
            COMPROMISED_PRINCIPAL_ID,
            COMPROMISED_SESSION_ID,
            operation,
            status.value,
            rows_affected,
        ),
    )
    connection.commit()
    rows = tuple(
        connection.execute(
            """
            SELECT operation_id, responder_instance_id, trace_id,
                   action_digest, target_mode, principal_id, session_id,
                   operation, status, rows_affected
            FROM response_actions
            ORDER BY operation_id
            """
        )
    )
    if len(rows) != 1:
        raise RuntimeError("response action table must contain exactly one row")
    row = rows[0]
    operation_value = str(row[7])
    if operation_value not in {
        "not-triggered",
        "report-only",
        "revoke-exact",
    }:
        raise RuntimeError("response action row has an unknown operation")
    try:
        status_value = ResponseActionStatus(str(row[8]))
    except ValueError as error:
        raise RuntimeError("response action row has an unknown status") from error
    return ResponseActionReceipt(
        operation_id=str(row[0]),
        responder_instance_id=str(row[1]),
        trace_id=str(row[2]),
        action_digest=str(row[3]),
        target_mode=str(row[4]),
        principal_id=str(row[5]),
        session_id=str(row[6]),
        operation=cast(
            Literal["not-triggered", "report-only", "revoke-exact"],
            operation_value,
        ),
        status=status_value,
        rows_affected=int(row[9]),
    )


def _resource_identity(
    connection: sqlite3.Connection,
    *,
    requested_clone_nonce: str,
    requested_runner_resource_id: str,
) -> ResourceIdentityReceipt:
    rows = tuple(
        connection.execute(
            """
            SELECT clone_nonce, runner_resource_id
            FROM runtime_identity
            ORDER BY clone_nonce
            """
        )
    )
    if len(rows) != 1:
        raise RuntimeError("runtime identity table must contain exactly one row")
    clone_nonce, runner_resource_id = rows[0]
    return ResourceIdentityReceipt(
        requested_clone_nonce=requested_clone_nonce,
        requested_runner_resource_id=requested_runner_resource_id,
        observed_clone_nonce=str(clone_nonce),
        observed_runner_resource_id=str(runner_resource_id),
    )


def _changed_session_ids(
    before: dict[str, tuple[str, bool]],
    after: dict[str, tuple[str, bool]],
) -> tuple[str, ...]:
    if before.keys() != after.keys():
        raise RuntimeError("session identity set changed during response")
    return tuple(
        session_id
        for session_id in sorted(before)
        if before[session_id] != after[session_id]
    )


def _principal_quarantined(
    connection: sqlite3.Connection,
    principal_id: str,
) -> bool:
    row = connection.execute(
        "SELECT quarantined FROM principals WHERE principal_id = ?",
        (principal_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError(f"missing fixed principal: {principal_id}")
    return bool(row[0])


def _request_decision(
    connection: sqlite3.Connection,
    *,
    query_id: str,
    principal_id: str,
    session_id: str,
) -> GatewayDecisionReceipt:
    session_row = connection.execute(
        "SELECT principal_id, revoked FROM sessions WHERE session_id = ?",
        (session_id,),
    ).fetchone()
    principal_row = connection.execute(
        "SELECT quarantined FROM principals WHERE principal_id = ?",
        (principal_id,),
    ).fetchone()
    session_found = session_row is not None
    principal_found = principal_row is not None
    bound = session_found and str(session_row[0]) == principal_id
    revoked = bool(session_row[1]) if bound else False
    quarantined = bool(principal_row[0]) if principal_found else False
    available = bound and principal_found and not revoked and not quarantined
    return GatewayDecisionReceipt(
        query_id=query_id,
        principal_id=principal_id,
        session_id=session_id,
        session_found=session_found,
        principal_found=principal_found,
        session_revoked=revoked,
        principal_quarantined=quarantined,
        available=available,
    )


def _close_with_probe(
    connection: sqlite3.Connection,
    *,
    clone_nonce: str,
    runner_resource_id: str,
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
            probe_operation="select-runtime-identity-after-close",
            error_type="sqlite3.ProgrammingError",
            closed_handle_rejected_operation=True,
        )
    raise RuntimeError("closed SQLite handle unexpectedly accepted a query")


def _events(
    *,
    trace_id: str,
    action_digest: str,
    action_name: str,
    sham_level: str,
    target_level: str,
    status: ResponseActionStatus,
    exact_revocation_executed: bool,
    compromised_session_active: bool,
    non_target_sessions_active: bool,
    target_modified_session_ids: tuple[str, ...],
    compensator_level: str,
    quarantine_applied: bool,
    compromised_principal_quarantined: bool,
    compensator_modified_session_ids: tuple[str, ...],
    replay_denied: bool,
    unrelated_available: bool,
) -> tuple[RuntimeEvent, ...]:
    target_modified_canonical, target_modified_digest = _session_set_evidence(
        target_modified_session_ids
    )
    (
        compensator_modified_canonical,
        compensator_modified_digest,
    ) = _session_set_evidence(compensator_modified_session_ids)
    return (
        RuntimeEvent(
            trace_id=trace_id,
            sequence=1,
            stage="input",
            component="identity-gateway",
            event_type="action-issued",
            payload=(
                ("action", action_name),
                ("action_digest", action_digest),
                ("sham", sham_level),
            ),
        ),
        RuntimeEvent(
            trace_id=trace_id,
            sequence=2,
            stage="target",
            component="session-revoker",
            event_type="response-and-session-readback",
            payload=(
                ("target_mode", target_level),
                ("target_principal_id", COMPROMISED_PRINCIPAL_ID),
                ("target_session_id", COMPROMISED_SESSION_ID),
                ("response_action_status", status.value),
                (
                    "response_action_reported_success",
                    status == ResponseActionStatus.REPORTED_SUCCESS,
                ),
                ("exact_revocation_executed", exact_revocation_executed),
                ("compromised_session_active", compromised_session_active),
                ("non_target_sessions_active", non_target_sessions_active),
                (
                    "target_modified_session_count",
                    len(target_modified_session_ids),
                ),
                (
                    "target_modified_session_ids_canonical",
                    target_modified_canonical,
                ),
                (
                    "target_modified_session_ids_digest",
                    target_modified_digest,
                ),
            ),
        ),
        RuntimeEvent(
            trace_id=trace_id,
            sequence=3,
            stage="compensator",
            component="principal-quarantine",
            event_type="quarantine-readback",
            payload=(
                ("compensator_mode", compensator_level),
                ("quarantine_principal_id", COMPROMISED_PRINCIPAL_ID),
                ("quarantine_applied", quarantine_applied),
                (
                    "compromised_principal_quarantined",
                    compromised_principal_quarantined,
                ),
                (
                    "compensator_modified_session_count",
                    len(compensator_modified_session_ids),
                ),
                (
                    "compensator_modified_session_ids_canonical",
                    compensator_modified_canonical,
                ),
                (
                    "compensator_modified_session_ids_digest",
                    compensator_modified_digest,
                ),
            ),
        ),
        RuntimeEvent(
            trace_id=trace_id,
            sequence=4,
            stage="outcome",
            component="identity-gateway",
            event_type="availability-observed",
            payload=(
                ("compromised_session_replay_denied", replay_denied),
                (
                    "unrelated_support_principal_available",
                    unrelated_available,
                ),
            ),
        ),
    )


def _sha256(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _session_set_evidence(session_ids: tuple[str, ...]) -> tuple[str, str]:
    canonical = rfc8785.dumps(
        {
            "schema": "assurance-lab.modified-session-set/v1",
            "session_ids": list(session_ids),
        }
    )
    return canonical.decode("utf-8"), _sha256(canonical)
