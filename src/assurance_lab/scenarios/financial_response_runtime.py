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
from typing import Any, Literal

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
    ) -> FinancialResponseRuntimeResult:
        _validate_trace_id(trace_id)
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

        connection = self._fresh_database()
        if sham_level == SHAM_RELOAD.value:
            connection.close()
            connection = self._fresh_database()

        attack_triggered = input_level == ATTACK.value
        before_target = _session_states(connection)
        exact_revocation_executed = (
            attack_triggered and target_level == TARGET_EFFECTIVE.value
        )
        if exact_revocation_executed:
            affected = connection.execute(
                """
                UPDATE sessions
                SET revoked = 1
                WHERE session_id = ? AND principal_id = ?
                """,
                (COMPROMISED_SESSION_ID, COMPROMISED_PRINCIPAL_ID),
            ).rowcount
            if affected != 1:
                connection.close()
                raise RuntimeError("exact-session revocation did not affect one session")
            connection.commit()
        after_target = _session_states(connection)
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
        if quarantine_applied:
            affected = connection.execute(
                "UPDATE principals SET quarantined = 1 WHERE principal_id = ?",
                (COMPROMISED_PRINCIPAL_ID,),
            ).rowcount
            if affected != 1:
                connection.close()
                raise RuntimeError("principal quarantine did not affect one principal")
            connection.commit()
        after_compensator = _session_states(connection)
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
        replay_available = _request_available(
            connection,
            principal_id=COMPROMISED_PRINCIPAL_ID,
            session_id=COMPROMISED_SESSION_ID,
        )
        unrelated_available = _request_available(
            connection,
            principal_id=UNRELATED_PRINCIPAL_ID,
            session_id=UNRELATED_SESSION_ID,
        )
        readbacks = tuple(
            SessionReadback(
                session_id=session_id,
                principal_id=principal_id,
                active=active,
            )
            for session_id, (principal_id, active) in sorted(
                after_compensator.items()
            )
        )
        connection.close()

        status = (
            ResponseActionStatus.REPORTED_SUCCESS
            if attack_triggered
            else ResponseActionStatus.NOT_TRIGGERED
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
            replay_denied=not replay_available,
            unrelated_available=unrelated_available,
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
            compromised_session_replay_denied=not replay_available,
            unrelated_support_principal_available=unrelated_available,
            target_modified_session_ids=target_modified,
            compensator_modified_session_ids=compensator_modified,
            session_readbacks=readbacks,
            events=events,
        )

    @staticmethod
    def _fresh_database() -> sqlite3.Connection:
        connection = sqlite3.connect(":memory:")
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


def _request_available(
    connection: sqlite3.Connection,
    *,
    principal_id: str,
    session_id: str,
) -> bool:
    row = connection.execute(
        """
        SELECT s.revoked, p.quarantined
        FROM sessions AS s
        JOIN principals AS p ON p.principal_id = s.principal_id
        WHERE s.session_id = ? AND s.principal_id = ?
        """,
        (session_id, principal_id),
    ).fetchone()
    if row is None:
        raise RuntimeError("request references a missing principal/session binding")
    revoked, quarantined = row
    return not bool(revoked) and not bool(quarantined)


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
