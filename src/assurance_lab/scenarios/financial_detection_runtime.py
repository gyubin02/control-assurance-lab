"""Fresh-SQLite runtime for the financial exact-correlation experiment.

The runtime keeps three statements independent:

* the named exact-correlation rule produced a correctly bound alert;
* the fallback telemetry path forwarded the source and produced its broad alert;
* at least one alert reached the observer inside the two-second lab objective.

A missing named alert is not automatically a failure.  It becomes a supported
absence only when a content-addressed window-closure artifact still agrees with
the raw source sequence, source health, collector completion, and simulated
clock readbacks.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Literal

import rfc8785

from assurance_lab.contract import CellSelector, StringValue
from assurance_lab.scenarios.financial_detection_contract import (
    ALERT_SLO_MS,
    ATTACK,
    ATTACK_ACTION_DIGEST,
    BENIGN,
    BENIGN_ACTION_DIGEST,
    COMPENSATOR_OFF,
    COMPENSATOR_ON,
    FALLBACK_RULE_ID,
    NAMED_RULE_ID,
    SHAM_RELOAD,
    SHAM_STEADY,
    SIMULATED_CLOCK_ID,
    SOURCE_ID,
    TARGET_EFFECTIVE,
    TARGET_INEFFECTIVE,
    action_descriptor,
)

type Scalar = str | bool | int
type Payload = tuple[tuple[str, Scalar], ...]

_TRACE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CLOCK_SPEC: dict[str, Any] = {
    "schema": "assurance-lab.simulated-clock/v1",
    "clock_id": SIMULATED_CLOCK_ID,
    "epoch": "2026-07-29T00:00:00Z",
    "source_event_offsets_ms": [100, 200, 300],
    "named_alert_offset_ms": 800,
    "fallback_alert_offset_ms": 1_200,
    "alert_latency_origin": "latest-correlated-source-event",
    "alert_latency_objective_ms": ALERT_SLO_MS,
    "observation_window": {"opened_at_ms": 0, "closed_at_ms": ALERT_SLO_MS},
}
_CLOCK_SPEC_CANONICAL = rfc8785.dumps(_CLOCK_SPEC)
CLOCK_SPEC_DIGEST = (
    f"sha256:{hashlib.sha256(_CLOCK_SPEC_CANONICAL).hexdigest()}"
)
FALLBACK_ROUTE_ID = "SYNTH-ROUTE-FALLBACK-01"
DIRECT_SOURCE_ROUTE_ID = "SYNTH-ROUTE-DIRECT-SOURCE-01"


class AlertKind(StrEnum):
    NAMED_EXACT = "named-exact"
    BROAD_FALLBACK = "broad-fallback"


class BaselineVerdict(StrEnum):
    PASS = "pass"
    FAIL = "fail"


class DetectionClaimState(StrEnum):
    SUPPORTED = "supported"
    REFUTED = "refuted"
    INDETERMINATE = "indeterminate"


class NamedAlertAbsence(StrEnum):
    CONCLUDED = "concluded"
    PRESENT = "present"
    INDETERMINATE = "indeterminate"


class DetectionResidualClassification(StrEnum):
    MASKED_NAMED_DETECTION_FAILURE = "masked_named_detection_failure"
    EXPOSED_DETECTION_GAP = "exposed_detection_gap"
    NAMED_DETECTION_EFFECTIVE = "named_detection_effective"
    INDETERMINATE = "indeterminate"


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
class SourceEventRecord:
    event_id: str
    trace_id: str
    action_digest: str
    source_id: str
    source_sequence: int
    event_type: str
    observed_at_ms: int
    clock_id: str
    clock_spec_digest: str
    event_digest: str


@dataclass(frozen=True, slots=True)
class ForwardedEventRecord:
    event_id: str
    trace_id: str
    action_digest: str
    source_id: str
    source_sequence: int
    event_type: str
    source_event_digest: str
    route_id: str
    collector_run_id: str
    forwarding_digest: str


@dataclass(frozen=True, slots=True)
class AlertRecord:
    alert_id: str
    alert_kind: AlertKind
    rule_id: str
    trace_id: str
    action_digest: str
    source_id: str
    source_event_ids: tuple[str, ...]
    source_sequences: tuple[int, ...]
    triggered_at_ms: int
    clock_id: str
    clock_spec_digest: str
    correlation_evidence_canonical: str
    correlation_evidence_digest: str
    evidence_route_id: str
    forwarded_event_digests: tuple[str, ...]
    detector_run_id: str | None


@dataclass(frozen=True, slots=True)
class SimulatedClockReadback:
    clock_id: str
    current_time_ms: int
    transitions: tuple[tuple[int, int], ...]
    clock_spec_digest: str
    readback_canonical: str
    readback_digest: str


@dataclass(frozen=True, slots=True)
class DetectorRunReadback:
    detector_run_id: str
    trace_id: str
    rule_id: str
    rule_active: bool
    status: str
    started_at_ms: int
    evaluated_event_count: int
    source_high_watermark: int
    pending_event_count: int
    completed_at_ms: int | None
    processed_event_ids: tuple[str, ...]
    processed_source_sequences: tuple[int, ...]
    processed_source_event_digests: tuple[str, ...]
    observed_named_alert_ids: tuple[str, ...]
    clock_id: str
    clock_spec_digest: str
    readback_canonical: str
    readback_digest: str


@dataclass(frozen=True, slots=True)
class AlertQueryReadback:
    query_id: str
    trace_id: str
    completed: bool
    started_at_ms: int
    completed_at_ms: int | None
    as_of_ms: int
    observed_alert_ids: tuple[str, ...]
    clock_id: str
    clock_spec_digest: str
    readback_canonical: str
    readback_digest: str


@dataclass(frozen=True, slots=True)
class CollectorReloadAttestation:
    attestation_id: str
    reload_performed: bool
    pre_instance_id: str
    post_instance_id: str
    pre_config_digest: str
    post_config_digest: str
    instance_rows_canonical: str
    instance_rows_digest: str
    reload_operation_canonical: str
    reload_operation_digest: str
    attestation_canonical: str
    attestation_digest: str


@dataclass(frozen=True, slots=True)
class CollectorRunReadback:
    collector_run_id: str
    trace_id: str
    status: str
    healthy: bool
    collected_event_count: int
    source_id: str
    source_healthy: bool
    collected_event_ids: tuple[str, ...]
    collected_source_sequences: tuple[int, ...]
    clock_id: str
    clock_spec_digest: str
    readback_canonical: str
    readback_digest: str


@dataclass(frozen=True, slots=True)
class ObservationWindowClosure:
    trace_id: str
    action_digest: str
    source_id: str
    expected_event_ids: tuple[str, ...]
    observed_event_ids: tuple[str, ...]
    expected_source_sequences: tuple[int, ...]
    observed_source_sequences: tuple[int, ...]
    source_healthy: bool
    collector_run_id: str
    collector_healthy: bool
    collector_completed: bool
    collected_event_count: int
    collector_run_readback_digest: str
    opened_at_ms: int
    closed_at_ms: int
    clock_id: str
    clock_spec_digest: str
    clock_readback_digest: str
    detector_run_id: str
    detector_run_digest: str
    alert_query_id: str
    alert_query_digest: str
    reload_attestation_digest: str
    artifact_canonical: str
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class FinancialDetectionRuntimeResult:
    trace_id: str
    action_digest: str
    input_level: str
    target_level: str
    compensator_level: str
    sham_level: str
    source_trace_action_bound: bool
    source_sequence_coverage_complete: bool
    source_healthy: bool
    collector_healthy: bool
    collector_completed: bool
    observation_window_closed: bool
    simulated_clock_bound: bool
    detector_run_completed: bool
    alert_query_completed: bool
    named_rule_active: bool
    named_alert_identity_unique: bool
    named_alert_rule_identity_bound: bool
    named_alert_trace_source_action_bound: bool
    named_correlation_evidence_valid: bool
    named_exact_correlation_alert_proven: bool
    fallback_telemetry_forwarded: bool
    fallback_alert_binding_valid: bool
    any_alert_within_slo: bool
    first_alert_offset_from_window_open_ms: int | None
    first_alert_causal_latency_ms: int | None
    tested_benign_action_unalerted: bool
    forwarded_event_ids: tuple[str, ...]
    forwarded_events: tuple[ForwardedEventRecord, ...]
    source_events: tuple[SourceEventRecord, ...]
    alerts: tuple[AlertRecord, ...]
    clock_readback: SimulatedClockReadback
    detector_run: DetectorRunReadback
    alert_query: AlertQueryReadback
    reload_attestation: CollectorReloadAttestation
    collector_run_readback: CollectorRunReadback
    window_closure: ObservationWindowClosure
    events: tuple[RuntimeEvent, ...]


@dataclass(frozen=True, slots=True)
class AlertExistenceOnlyBaseline:
    name: Literal["alert-existence-only"]
    verdict: BaselineVerdict
    any_alert_within_slo: bool
    observed_alert_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DetectionCaseAssessment:
    baseline: AlertExistenceOnlyBaseline
    target_state: DetectionClaimState
    named_alert_absence: NamedAlertAbsence
    fallback_telemetry_supported: bool
    fallback_alert_supported: bool
    alert_path_supported: bool
    residual_classification: DetectionResidualClassification


class FinancialDetectionRuntime:
    """Execute one detection cell against an isolated in-memory event store."""

    def execute(
        self,
        selector: CellSelector,
        *,
        trace_id: str,
    ) -> FinancialDetectionRuntimeResult:
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
        contracted_digest = (
            ATTACK_ACTION_DIGEST if action_level == ATTACK else BENIGN_ACTION_DIGEST
        )
        if action_digest != contracted_digest:
            raise RuntimeError("fixed action no longer matches its contracted digest")
        source_plan = _source_plan(action)

        exact_rule_active = target_level == TARGET_EFFECTIVE.value
        expected_pre_instance_id = _collector_instance_id(trace_id, "pre")
        connection = self._fresh_database(
            exact_rule_active=exact_rule_active,
            collector_instance_id=expected_pre_instance_id,
        )
        if sham_level == SHAM_RELOAD.value:
            _perform_collector_reload(
                connection,
                trace_id=trace_id,
            )
        reload_attestation = _write_and_read_reload_attestation(
            connection,
            trace_id=trace_id,
        )
        reload_performed = reload_attestation.reload_performed

        collector_run_id = _collector_run_id(trace_id)
        connection.execute(
            """
            INSERT INTO collector_runs
                (collector_run_id, trace_id, status, healthy, clock_id,
                 clock_spec_digest, collected_event_count)
            VALUES (?, ?, 'running', 1, ?, ?, 0)
            """,
            (
                collector_run_id,
                trace_id,
                SIMULATED_CLOCK_ID,
                CLOCK_SPEC_DIGEST,
            ),
        )
        _write_source_events(
            connection,
            trace_id=trace_id,
            action_digest=action_digest,
            source_plan=source_plan,
        )
        source_events = _read_source_events(connection)
        suspicious = action_level == ATTACK

        named_rule_active = _rule_active(connection, NAMED_RULE_ID)
        detector_run_id = _start_detector_run(
            connection,
            trace_id=trace_id,
        )
        _enqueue_detector_source_events(
            connection,
            detector_run_id=detector_run_id,
            trace_id=trace_id,
        )
        _advance_clock(connection, 800)
        _process_named_detector_queue(
            connection,
            detector_run_id=detector_run_id,
        )
        detector_run = _read_detector_run(connection, detector_run_id)

        fallback_forward = compensator_level == COMPENSATOR_ON.value
        if fallback_forward:
            _write_forwarded_events(
                connection,
                source_events=source_events,
                route_id=FALLBACK_ROUTE_ID,
                collector_run_id=collector_run_id,
            )
        forwarded_events = _read_forwarded_events(connection)
        forwarding_valid = _forwarding_readback_valid(
            forwarded_events,
            source_events,
            trace_id=trace_id,
            action_digest=action_digest,
            route_id=FALLBACK_ROUTE_ID,
            collector_run_id=collector_run_id,
        )
        broad_forwarded = tuple(
            event
            for event in forwarded_events
            if event.event_type == "out-of-assignment-sensitive-read"
        )
        if suspicious and forwarding_valid and len(broad_forwarded) == 1:
            broad_source = _source_records_for_forwarded(
                broad_forwarded,
                source_events,
            )
            _advance_clock(connection, 1_200)
            _write_alert(
                connection,
                alert_kind=AlertKind.BROAD_FALLBACK,
                rule_id=FALLBACK_RULE_ID,
                trace_id=trace_id,
                action_digest=action_digest,
                source_events=broad_source,
                triggered_at_ms=1_200,
                evidence_route_id=FALLBACK_ROUTE_ID,
                forwarded_events=broad_forwarded,
                detector_run_id=None,
            )

        connection.execute(
            """
            UPDATE collector_runs
            SET status = 'complete', collected_event_count = ?
            WHERE collector_run_id = ?
            """,
            (len(source_events), collector_run_id),
        )
        connection.commit()
        collector_run_readback = _read_collector_run(
            connection,
            collector_run_id,
        )

        _advance_clock(connection, ALERT_SLO_MS)
        source_events = _read_source_events(connection)
        forwarded_events = _read_forwarded_events(connection)
        alerts = _read_alerts(connection)
        forwarded_event_ids = tuple(event.event_id for event in forwarded_events)
        clock_readback = _read_clock(connection)
        alert_query = _execute_and_read_alert_query(
            connection,
            trace_id=trace_id,
        )
        closure = _write_and_read_closure(
            connection,
            trace_id=trace_id,
            action_digest=action_digest,
            source_plan=source_plan,
            source_events=source_events,
            alerts=alerts,
            collector_run_id=collector_run_id,
            collector_run_readback=collector_run_readback,
            clock_readback=clock_readback,
            detector_run=detector_run,
            alert_query=alert_query,
            reload_attestation=reload_attestation,
        )
        connection.close()

        source_binding = _source_binding_valid(
            source_events,
            trace_id=trace_id,
            action_digest=action_digest,
        )
        sequence_coverage = _sequence_coverage_valid(
            source_events,
            source_plan,
        )
        clock_bound = _clock_bound(
            source_events,
            alerts,
            closure,
            clock_readback=clock_readback,
        )
        fallback_binding = _fallback_alert_binding_valid(
            alerts,
            source_events,
            forwarded_events,
            trace_id=trace_id,
            action_digest=action_digest,
            suspicious=suspicious,
            fallback_forward=fallback_forward,
        )
        (
            any_alert_within_slo,
            first_alert_offset,
            first_alert_causal_latency,
        ) = _alert_existence(alerts, source_events)
        closure_valid = _closure_valid_from_parts(
            closure,
            source_events=source_events,
            forwarded_events=forwarded_events,
            alerts=alerts,
            source_plan=source_plan,
            trace_id=trace_id,
            action_digest=action_digest,
            clock_readback=clock_readback,
            detector_run=detector_run,
            alert_query=alert_query,
            reload_attestation=reload_attestation,
            collector_run_readback=collector_run_readback,
            expected_named_rule_active=named_rule_active,
            expected_reload_performed=reload_performed,
        )
        named_proofs = _named_alert_proofs(
            alerts,
            source_events,
            source_plan=source_plan,
            trace_id=trace_id,
            action_digest=action_digest,
            detector_run=detector_run,
            alert_query=alert_query,
            clock_readback=clock_readback,
            closure_valid=closure_valid,
            named_rule_active=named_rule_active,
        )
        absence = _absence_from_parts(
            alerts=alerts,
            closure_valid=closure_valid,
        )
        detector_run_valid = _detector_run_valid(
            detector_run,
            source_events=source_events,
            alerts=alerts,
            trace_id=trace_id,
            named_rule_active=named_rule_active,
        )
        alert_query_valid = _alert_query_valid(
            alert_query,
            alerts=alerts,
            trace_id=trace_id,
            clock_readback=clock_readback,
        )
        events = _events(
            trace_id=trace_id,
            action_name=_required_text(action, "action"),
            action_digest=action_digest,
            sham_level=sham_level,
            source_events=source_events,
            source_binding=source_binding,
            sequence_coverage=sequence_coverage,
            target_level=target_level,
            named_rule_active=named_rule_active,
            named_proofs=named_proofs,
            compensator_level=compensator_level,
            forwarded_event_ids=forwarded_event_ids,
            fallback_telemetry_forwarded=forwarding_valid,
            fallback_binding=fallback_binding,
            alerts=alerts,
            any_alert_within_slo=any_alert_within_slo,
            first_alert_offset=first_alert_offset,
            first_alert_causal_latency=first_alert_causal_latency,
            tested_benign_action_unalerted=not suspicious and not alerts,
            closure=closure,
            closure_valid=closure_valid,
            absence=absence,
            clock_bound=clock_bound,
            detector_run=detector_run,
            detector_run_valid=detector_run_valid,
            alert_query=alert_query,
            alert_query_valid=alert_query_valid,
            reload_attestation=reload_attestation,
        )
        return FinancialDetectionRuntimeResult(
            trace_id=trace_id,
            action_digest=action_digest,
            input_level=input_level,
            target_level=target_level,
            compensator_level=compensator_level,
            sham_level=sham_level,
            source_trace_action_bound=source_binding,
            source_sequence_coverage_complete=sequence_coverage,
            source_healthy=closure.source_healthy,
            collector_healthy=closure.collector_healthy,
            collector_completed=closure.collector_completed,
            observation_window_closed=closure_valid,
            simulated_clock_bound=clock_bound,
            detector_run_completed=detector_run_valid,
            alert_query_completed=alert_query_valid,
            named_rule_active=named_rule_active,
            named_alert_identity_unique=named_proofs.identity_unique,
            named_alert_rule_identity_bound=named_proofs.rule_identity_bound,
            named_alert_trace_source_action_bound=named_proofs.source_binding,
            named_correlation_evidence_valid=named_proofs.correlation_valid,
            named_exact_correlation_alert_proven=named_proofs.full_claim,
            fallback_telemetry_forwarded=forwarding_valid,
            fallback_alert_binding_valid=fallback_binding,
            any_alert_within_slo=any_alert_within_slo,
            first_alert_offset_from_window_open_ms=first_alert_offset,
            first_alert_causal_latency_ms=first_alert_causal_latency,
            tested_benign_action_unalerted=not suspicious and not alerts,
            forwarded_event_ids=forwarded_event_ids,
            forwarded_events=forwarded_events,
            source_events=source_events,
            alerts=alerts,
            clock_readback=clock_readback,
            detector_run=detector_run,
            alert_query=alert_query,
            reload_attestation=reload_attestation,
            collector_run_readback=collector_run_readback,
            window_closure=closure,
            events=events,
        )

    @staticmethod
    def _fresh_database(
        *,
        exact_rule_active: bool,
        collector_instance_id: str,
    ) -> sqlite3.Connection:
        connection = sqlite3.connect(":memory:")
        connection.execute(
            """
            CREATE TABLE sources (
                source_id TEXT PRIMARY KEY,
                healthy INTEGER NOT NULL CHECK (healthy IN (0, 1))
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE rules (
                rule_id TEXT PRIMARY KEY,
                rule_kind TEXT NOT NULL,
                active INTEGER NOT NULL CHECK (active IN (0, 1))
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE collector_instances (
                collector_instance_id TEXT PRIMARY KEY,
                generation INTEGER NOT NULL UNIQUE,
                lifecycle_state TEXT NOT NULL
                    CHECK (lifecycle_state IN ('active', 'closed')),
                created_at_ms INTEGER NOT NULL,
                closed_at_ms INTEGER,
                config_digest TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE collector_reload_operations (
                operation_id TEXT PRIMARY KEY,
                trace_id TEXT NOT NULL,
                pre_instance_id TEXT NOT NULL
                    REFERENCES collector_instances(collector_instance_id),
                post_instance_id TEXT NOT NULL
                    REFERENCES collector_instances(collector_instance_id),
                status TEXT NOT NULL CHECK (status IN ('running', 'complete')),
                started_at_ms INTEGER NOT NULL,
                completed_at_ms INTEGER
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE reload_attestations (
                attestation_id TEXT PRIMARY KEY,
                attestation_canonical TEXT NOT NULL,
                attestation_digest TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE simulated_clock (
                clock_id TEXT PRIMARY KEY,
                current_time_ms INTEGER NOT NULL,
                clock_spec_digest TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE clock_transitions (
                transition_ordinal INTEGER PRIMARY KEY,
                from_ms INTEGER NOT NULL,
                to_ms INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE collector_runs (
                collector_run_id TEXT PRIMARY KEY,
                trace_id TEXT NOT NULL,
                status TEXT NOT NULL,
                healthy INTEGER NOT NULL CHECK (healthy IN (0, 1)),
                clock_id TEXT NOT NULL,
                clock_spec_digest TEXT NOT NULL,
                collected_event_count INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE source_events (
                event_id TEXT PRIMARY KEY,
                trace_id TEXT NOT NULL,
                action_digest TEXT NOT NULL,
                source_id TEXT NOT NULL REFERENCES sources(source_id),
                source_sequence INTEGER NOT NULL UNIQUE,
                event_type TEXT NOT NULL,
                observed_at_ms INTEGER NOT NULL,
                clock_id TEXT NOT NULL,
                clock_spec_digest TEXT NOT NULL,
                event_digest TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE forwarded_events (
                event_id TEXT PRIMARY KEY REFERENCES source_events(event_id),
                trace_id TEXT NOT NULL,
                action_digest TEXT NOT NULL,
                source_id TEXT NOT NULL,
                source_sequence INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                source_event_digest TEXT NOT NULL,
                route_id TEXT NOT NULL,
                collector_run_id TEXT NOT NULL,
                forwarding_digest TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE alerts (
                alert_id TEXT PRIMARY KEY,
                alert_kind TEXT NOT NULL,
                rule_id TEXT NOT NULL REFERENCES rules(rule_id),
                trace_id TEXT NOT NULL,
                action_digest TEXT NOT NULL,
                source_id TEXT NOT NULL,
                source_event_ids_json TEXT NOT NULL,
                source_sequences_json TEXT NOT NULL,
                triggered_at_ms INTEGER NOT NULL,
                clock_id TEXT NOT NULL,
                clock_spec_digest TEXT NOT NULL,
                correlation_evidence_canonical TEXT NOT NULL,
                correlation_evidence_digest TEXT NOT NULL,
                evidence_route_id TEXT NOT NULL,
                forwarded_event_digests_json TEXT NOT NULL,
                detector_run_id TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE detector_runs (
                detector_run_id TEXT PRIMARY KEY,
                trace_id TEXT NOT NULL,
                rule_id TEXT NOT NULL REFERENCES rules(rule_id),
                rule_active_at_start INTEGER NOT NULL
                    CHECK (rule_active_at_start IN (0, 1)),
                status TEXT NOT NULL CHECK (status IN ('running', 'complete')),
                started_at_ms INTEGER NOT NULL,
                completed_at_ms INTEGER,
                clock_id TEXT NOT NULL,
                clock_spec_digest TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE detector_queue (
                detector_run_id TEXT NOT NULL REFERENCES detector_runs(detector_run_id),
                event_id TEXT NOT NULL REFERENCES source_events(event_id),
                source_sequence INTEGER NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('pending', 'processed')),
                enqueued_at_ms INTEGER NOT NULL,
                processed_at_ms INTEGER,
                PRIMARY KEY (detector_run_id, event_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE alert_query_operations (
                query_id TEXT PRIMARY KEY,
                trace_id TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('running', 'complete')),
                started_at_ms INTEGER NOT NULL,
                completed_at_ms INTEGER,
                as_of_ms INTEGER,
                clock_id TEXT NOT NULL,
                clock_spec_digest TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE alert_query_results (
                query_id TEXT NOT NULL
                    REFERENCES alert_query_operations(query_id),
                result_ordinal INTEGER NOT NULL,
                alert_id TEXT NOT NULL REFERENCES alerts(alert_id),
                PRIMARY KEY (query_id, result_ordinal),
                UNIQUE (query_id, alert_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE observation_windows (
                trace_id TEXT PRIMARY KEY,
                artifact_canonical TEXT NOT NULL,
                artifact_digest TEXT NOT NULL
            )
            """
        )
        connection.execute("INSERT INTO sources VALUES (?, 1)", (SOURCE_ID,))
        connection.execute(
            "INSERT INTO simulated_clock VALUES (?, 0, ?)",
            (SIMULATED_CLOCK_ID, CLOCK_SPEC_DIGEST),
        )
        connection.executemany(
            "INSERT INTO rules VALUES (?, ?, ?)",
            (
                (NAMED_RULE_ID, AlertKind.NAMED_EXACT.value, int(exact_rule_active)),
                (FALLBACK_RULE_ID, AlertKind.BROAD_FALLBACK.value, 1),
            ),
        )
        connection.execute(
            """
            INSERT INTO collector_instances
                (collector_instance_id, generation, lifecycle_state,
                 created_at_ms, closed_at_ms, config_digest)
            VALUES (?, 1, 'active', 0, NULL, 'pending')
            """,
            (collector_instance_id,),
        )
        config_digest = _collector_config_digest(connection)
        connection.execute(
            """
            UPDATE collector_instances
            SET config_digest = ?
            WHERE collector_instance_id = ?
            """,
            (config_digest, collector_instance_id),
        )
        connection.commit()
        return connection


def conclude_named_alert_absence(
    result: FinancialDetectionRuntimeResult,
) -> NamedAlertAbsence:
    """Conclude absence only from a still-valid closed-window proof."""

    closure_valid = _result_closure_valid(result)
    return _absence_from_parts(alerts=result.alerts, closure_valid=closure_valid)


def _result_closure_valid(result: FinancialDetectionRuntimeResult) -> bool:
    if result.input_level not in {ATTACK.value, BENIGN.value}:
        return False
    if result.target_level not in {
        TARGET_INEFFECTIVE.value,
        TARGET_EFFECTIVE.value,
    }:
        return False
    if result.sham_level not in {SHAM_STEADY.value, SHAM_RELOAD.value}:
        return False
    action_level = ATTACK if result.input_level == ATTACK.value else BENIGN
    expected_action_digest = (
        ATTACK_ACTION_DIGEST
        if action_level == ATTACK
        else BENIGN_ACTION_DIGEST
    )
    if result.action_digest != expected_action_digest:
        return False
    try:
        source_plan = _source_plan(action_descriptor(action_level))
        return _closure_valid_from_parts(
            result.window_closure,
            source_events=result.source_events,
            forwarded_events=result.forwarded_events,
            alerts=result.alerts,
            source_plan=source_plan,
            trace_id=result.trace_id,
            action_digest=result.action_digest,
            clock_readback=result.clock_readback,
            detector_run=result.detector_run,
            alert_query=result.alert_query,
            reload_attestation=result.reload_attestation,
            collector_run_readback=result.collector_run_readback,
            expected_named_rule_active=(
                result.target_level == TARGET_EFFECTIVE.value
            ),
            expected_reload_performed=(result.sham_level == SHAM_RELOAD.value),
        )
    except (TypeError, ValueError):
        return False


def assess_detection_case(
    result: FinancialDetectionRuntimeResult,
) -> DetectionCaseAssessment:
    """Compare alert existence with the narrower named-rule claim."""

    if result.input_level != ATTACK.value:
        raise ValueError("detection case assessment requires the fixed suspicious action")

    fixed_action_bound = result.action_digest == ATTACK_ACTION_DIGEST
    alert_exists, _, _ = _alert_existence(result.alerts, result.source_events)
    source_plan = _source_plan(action_descriptor(ATTACK))
    closure_valid = _result_closure_valid(result)
    absence = _absence_from_parts(
        alerts=result.alerts,
        closure_valid=closure_valid,
    )
    named_proofs = _named_alert_proofs(
        result.alerts,
        result.source_events,
        source_plan=source_plan,
        trace_id=result.trace_id,
        action_digest=result.action_digest,
        detector_run=result.detector_run,
        alert_query=result.alert_query,
        clock_readback=result.clock_readback,
        closure_valid=closure_valid,
        named_rule_active=(
            result.target_level == TARGET_EFFECTIVE.value
        ),
    )
    if named_proofs.full_claim:
        target_state = DetectionClaimState.SUPPORTED
    elif absence == NamedAlertAbsence.CONCLUDED:
        target_state = DetectionClaimState.REFUTED
    else:
        target_state = DetectionClaimState.INDETERMINATE

    fallback_telemetry_supported = (
        fixed_action_bound
        and result.compensator_level == COMPENSATOR_ON.value
        and _collector_run_valid(
            result.collector_run_readback,
            source_events=result.source_events,
            trace_id=result.trace_id,
        )
        and _forwarding_readback_valid(
            result.forwarded_events,
            result.source_events,
            trace_id=result.trace_id,
            action_digest=result.action_digest,
            route_id=FALLBACK_ROUTE_ID,
            collector_run_id=_collector_run_id(result.trace_id),
        )
    )
    fallback_alert_supported = _fallback_alert_binding_valid(
        result.alerts,
        result.source_events,
        result.forwarded_events,
        trace_id=result.trace_id,
        action_digest=result.action_digest,
        suspicious=True,
        fallback_forward=fallback_telemetry_supported,
    )
    if (
        target_state == DetectionClaimState.REFUTED
        and fallback_telemetry_supported
        and fallback_alert_supported
        and alert_exists
    ):
        classification = (
            DetectionResidualClassification.MASKED_NAMED_DETECTION_FAILURE
        )
    elif target_state == DetectionClaimState.REFUTED and not alert_exists:
        classification = DetectionResidualClassification.EXPOSED_DETECTION_GAP
    elif target_state == DetectionClaimState.SUPPORTED:
        classification = DetectionResidualClassification.NAMED_DETECTION_EFFECTIVE
    else:
        classification = DetectionResidualClassification.INDETERMINATE

    return DetectionCaseAssessment(
        baseline=AlertExistenceOnlyBaseline(
            name="alert-existence-only",
            verdict=BaselineVerdict.PASS if alert_exists else BaselineVerdict.FAIL,
            any_alert_within_slo=alert_exists,
            observed_alert_ids=tuple(alert.alert_id for alert in result.alerts),
        ),
        target_state=target_state,
        named_alert_absence=absence,
        fallback_telemetry_supported=fallback_telemetry_supported,
        fallback_alert_supported=fallback_alert_supported,
        alert_path_supported=alert_exists,
        residual_classification=classification,
    )


@dataclass(frozen=True, slots=True)
class _NamedAlertProofs:
    identity_unique: bool
    rule_identity_bound: bool
    source_binding: bool
    correlation_valid: bool
    within_slo: bool
    full_claim: bool


def _collector_config_digest(connection: sqlite3.Connection) -> str:
    sources: list[dict[str, Any]] = [
        {"source_id": str(row[0]), "healthy": bool(row[1])}
        for row in connection.execute(
            "SELECT source_id, healthy FROM sources ORDER BY source_id"
        )
    ]
    rules: list[dict[str, Any]] = [
        {
            "rule_id": str(row[0]),
            "rule_kind": str(row[1]),
            "active": bool(row[2]),
        }
        for row in connection.execute(
            "SELECT rule_id, rule_kind, active FROM rules ORDER BY rule_id"
        )
    ]
    payload: dict[str, Any] = {
        "schema": "assurance-lab.collector-config/v1",
        "sources": sources,
        "rules": rules,
    }
    return _sha256(rfc8785.dumps(payload))


def _expected_collector_config_digest(*, exact_rule_active: bool) -> str:
    payload: dict[str, Any] = {
        "schema": "assurance-lab.collector-config/v1",
        "sources": [{"source_id": SOURCE_ID, "healthy": True}],
        "rules": [
            {
                "rule_id": NAMED_RULE_ID,
                "rule_kind": AlertKind.NAMED_EXACT.value,
                "active": exact_rule_active,
            },
            {
                "rule_id": FALLBACK_RULE_ID,
                "rule_kind": AlertKind.BROAD_FALLBACK.value,
                "active": True,
            },
        ],
    }
    return _sha256(rfc8785.dumps(payload))


def _perform_collector_reload(
    connection: sqlite3.Connection,
    *,
    trace_id: str,
) -> None:
    """Persist a real synthetic collector generation transition."""

    active_rows = tuple(
        connection.execute(
            """
            SELECT collector_instance_id, generation, config_digest
            FROM collector_instances
            WHERE lifecycle_state = 'active'
            """
        )
    )
    if len(active_rows) != 1:
        raise RuntimeError("collector reload requires exactly one active instance")
    pre_instance_id = str(active_rows[0][0])
    pre_generation = int(active_rows[0][1])
    pre_config_digest = str(active_rows[0][2])
    expected_config_digest = _collector_config_digest(connection)
    if pre_config_digest != expected_config_digest:
        raise RuntimeError("pre-reload collector config readback is inconsistent")

    post_instance_id = _collector_instance_id(trace_id, "post")
    operation_id = _reload_operation_id(trace_id)
    current_time_ms = _current_clock_ms(connection)
    connection.execute(
        """
        UPDATE collector_instances
        SET lifecycle_state = 'closed', closed_at_ms = ?
        WHERE collector_instance_id = ? AND lifecycle_state = 'active'
        """,
        (current_time_ms, pre_instance_id),
    )
    connection.execute(
        """
        INSERT INTO collector_instances
            (collector_instance_id, generation, lifecycle_state,
             created_at_ms, closed_at_ms, config_digest)
        VALUES (?, ?, 'active', ?, NULL, ?)
        """,
        (
            post_instance_id,
            pre_generation + 1,
            current_time_ms,
            expected_config_digest,
        ),
    )
    connection.execute(
        """
        INSERT INTO collector_reload_operations
            (operation_id, trace_id, pre_instance_id, post_instance_id,
             status, started_at_ms, completed_at_ms)
        VALUES (?, ?, ?, ?, 'running', ?, NULL)
        """,
        (
            operation_id,
            trace_id,
            pre_instance_id,
            post_instance_id,
            current_time_ms,
        ),
    )
    connection.execute(
        """
        UPDATE collector_reload_operations
        SET status = 'complete', completed_at_ms = ?
        WHERE operation_id = ? AND status = 'running'
        """,
        (current_time_ms, operation_id),
    )
    connection.commit()


def _collector_instance_rows_payload(
    connection: sqlite3.Connection,
) -> dict[str, Any]:
    rows = [
        {
            "collector_instance_id": str(row[0]),
            "generation": int(row[1]),
            "lifecycle_state": str(row[2]),
            "created_at_ms": int(row[3]),
            "closed_at_ms": int(row[4]) if row[4] is not None else None,
            "config_digest": str(row[5]),
        }
        for row in connection.execute(
            """
            SELECT collector_instance_id, generation, lifecycle_state,
                   created_at_ms, closed_at_ms, config_digest
            FROM collector_instances
            ORDER BY generation
            """
        )
    ]
    return {
        "schema": "assurance-lab.collector-instance-readback/v1",
        "rows": rows,
    }


def _collector_reload_operation_payload(
    connection: sqlite3.Connection,
) -> dict[str, Any]:
    rows = tuple(
        connection.execute(
            """
            SELECT operation_id, trace_id, pre_instance_id, post_instance_id,
                   status, started_at_ms, completed_at_ms
            FROM collector_reload_operations
            ORDER BY operation_id
            """
        )
    )
    if len(rows) > 1:
        raise RuntimeError("one cell cannot contain multiple collector reloads")
    operation: dict[str, Any] | None = None
    if rows:
        row = rows[0]
        operation = {
            "operation_id": str(row[0]),
            "trace_id": str(row[1]),
            "pre_instance_id": str(row[2]),
            "post_instance_id": str(row[3]),
            "status": str(row[4]),
            "started_at_ms": int(row[5]),
            "completed_at_ms": (
                int(row[6]) if row[6] is not None else None
            ),
        }
    return {
        "schema": "assurance-lab.collector-reload-operation-readback/v1",
        "operation": operation,
    }


def _write_and_read_reload_attestation(
    connection: sqlite3.Connection,
    *,
    trace_id: str,
) -> CollectorReloadAttestation:
    attestation_id = _reload_attestation_id(trace_id)
    instance_rows_payload = _collector_instance_rows_payload(connection)
    operation_payload = _collector_reload_operation_payload(connection)
    instance_rows_canonical = rfc8785.dumps(instance_rows_payload).decode("utf-8")
    operation_canonical = rfc8785.dumps(operation_payload).decode("utf-8")
    raw_rows = instance_rows_payload["rows"]
    if not isinstance(raw_rows, list) or not raw_rows:
        raise RuntimeError("collector instance readback is empty")
    operation = operation_payload["operation"]
    reload_performed = isinstance(operation, dict)
    if reload_performed:
        pre_instance_id = str(operation["pre_instance_id"])
        post_instance_id = str(operation["post_instance_id"])
    else:
        active = [
            item
            for item in raw_rows
            if isinstance(item, dict) and item.get("lifecycle_state") == "active"
        ]
        if len(active) != 1:
            raise RuntimeError("steady collector readback requires one active row")
        pre_instance_id = post_instance_id = str(
            active[0]["collector_instance_id"]
        )
    by_id = {
        str(item["collector_instance_id"]): item
        for item in raw_rows
        if isinstance(item, dict)
    }
    try:
        pre_config_digest = str(by_id[pre_instance_id]["config_digest"])
        post_config_digest = str(by_id[post_instance_id]["config_digest"])
    except KeyError as exc:
        raise RuntimeError("reload operation references a missing instance") from exc
    instance_rows_digest = _sha256(instance_rows_canonical.encode("utf-8"))
    operation_digest = _sha256(operation_canonical.encode("utf-8"))
    payload: dict[str, Any] = {
        "schema": "assurance-lab.collector-reload-attestation/v2",
        "attestation_id": attestation_id,
        "reload_performed": reload_performed,
        "pre_instance_id": pre_instance_id,
        "post_instance_id": post_instance_id,
        "pre_config_digest": pre_config_digest,
        "post_config_digest": post_config_digest,
        "instance_rows_digest": instance_rows_digest,
        "reload_operation_digest": operation_digest,
    }
    canonical = rfc8785.dumps(payload).decode("utf-8")
    digest = _sha256(canonical.encode("utf-8"))
    connection.execute(
        "INSERT INTO reload_attestations VALUES (?, ?, ?)",
        (attestation_id, canonical, digest),
    )
    row = connection.execute(
        """
        SELECT attestation_canonical, attestation_digest
        FROM reload_attestations
        WHERE attestation_id = ?
        """,
        (attestation_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError("reload attestation write was not readable")
    parsed = _json_object(str(row[0]), "reload attestation")
    return CollectorReloadAttestation(
        attestation_id=_object_text(parsed, "attestation_id"),
        reload_performed=_object_bool(parsed, "reload_performed"),
        pre_instance_id=_object_text(parsed, "pre_instance_id"),
        post_instance_id=_object_text(parsed, "post_instance_id"),
        pre_config_digest=_object_text(parsed, "pre_config_digest"),
        post_config_digest=_object_text(parsed, "post_config_digest"),
        instance_rows_canonical=instance_rows_canonical,
        instance_rows_digest=_object_text(parsed, "instance_rows_digest"),
        reload_operation_canonical=operation_canonical,
        reload_operation_digest=_object_text(
            parsed,
            "reload_operation_digest",
        ),
        attestation_canonical=str(row[0]),
        attestation_digest=str(row[1]),
    )


def _reload_attestation_valid(
    attestation: CollectorReloadAttestation,
    *,
    trace_id: str,
    expected_reload_performed: bool,
    expected_named_rule_active: bool,
) -> bool:
    payload: dict[str, Any] = {
        "schema": "assurance-lab.collector-reload-attestation/v2",
        "attestation_id": attestation.attestation_id,
        "reload_performed": attestation.reload_performed,
        "pre_instance_id": attestation.pre_instance_id,
        "post_instance_id": attestation.post_instance_id,
        "pre_config_digest": attestation.pre_config_digest,
        "post_config_digest": attestation.post_config_digest,
        "instance_rows_digest": attestation.instance_rows_digest,
        "reload_operation_digest": attestation.reload_operation_digest,
    }
    canonical = rfc8785.dumps(payload).decode("utf-8")
    try:
        instances = json.loads(attestation.instance_rows_canonical)
        operation_readback = json.loads(
            attestation.reload_operation_canonical
        )
    except (json.JSONDecodeError, TypeError):
        return False
    if not isinstance(instances, dict) or not isinstance(
        operation_readback,
        dict,
    ):
        return False
    expected_pre_instance_id = _collector_instance_id(trace_id, "pre")
    expected_post_instance_id = (
        _collector_instance_id(trace_id, "post")
        if expected_reload_performed
        else expected_pre_instance_id
    )
    expected_config_digest = _expected_collector_config_digest(
        exact_rule_active=expected_named_rule_active,
    )
    expected_rows = [
        {
            "collector_instance_id": expected_pre_instance_id,
            "generation": 1,
            "lifecycle_state": (
                "closed" if expected_reload_performed else "active"
            ),
            "created_at_ms": 0,
            "closed_at_ms": 0 if expected_reload_performed else None,
            "config_digest": expected_config_digest,
        }
    ]
    expected_operation: dict[str, Any] | None = None
    if expected_reload_performed:
        expected_rows.append(
            {
                "collector_instance_id": expected_post_instance_id,
                "generation": 2,
                "lifecycle_state": "active",
                "created_at_ms": 0,
                "closed_at_ms": None,
                "config_digest": expected_config_digest,
            }
        )
        expected_operation = {
            "operation_id": _reload_operation_id(trace_id),
            "trace_id": trace_id,
            "pre_instance_id": expected_pre_instance_id,
            "post_instance_id": expected_post_instance_id,
            "status": "complete",
            "started_at_ms": 0,
            "completed_at_ms": 0,
        }
    return all(
        (
            attestation.attestation_canonical == canonical,
            attestation.attestation_digest == _sha256(canonical.encode("utf-8")),
            attestation.pre_config_digest == attestation.post_config_digest,
            attestation.pre_config_digest == expected_config_digest,
            attestation.attestation_id == _reload_attestation_id(trace_id),
            attestation.reload_performed == expected_reload_performed,
            attestation.pre_instance_id == expected_pre_instance_id,
            attestation.post_instance_id == expected_post_instance_id,
            attestation.instance_rows_digest
            == _sha256(attestation.instance_rows_canonical.encode("utf-8")),
            attestation.reload_operation_digest
            == _sha256(
                attestation.reload_operation_canonical.encode("utf-8")
            ),
            instances
            == {
                "schema": "assurance-lab.collector-instance-readback/v1",
                "rows": expected_rows,
            },
            operation_readback
            == {
                "schema": (
                    "assurance-lab.collector-reload-operation-readback/v1"
                ),
                "operation": expected_operation,
            },
        )
    )


def _advance_clock(connection: sqlite3.Connection, to_ms: int) -> None:
    row = connection.execute(
        "SELECT current_time_ms FROM simulated_clock WHERE clock_id = ?",
        (SIMULATED_CLOCK_ID,),
    ).fetchone()
    if row is None:
        raise RuntimeError("simulated clock is missing")
    current = int(row[0])
    if to_ms < current:
        raise RuntimeError("simulated clock cannot move backwards")
    if to_ms == current:
        return
    ordinal_row = connection.execute(
        "SELECT COUNT(*) FROM clock_transitions"
    ).fetchone()
    if ordinal_row is None:
        raise RuntimeError("clock transition count is unavailable")
    connection.execute(
        "INSERT INTO clock_transitions VALUES (?, ?, ?)",
        (int(ordinal_row[0]) + 1, current, to_ms),
    )
    connection.execute(
        """
        UPDATE simulated_clock
        SET current_time_ms = ?
        WHERE clock_id = ?
        """,
        (to_ms, SIMULATED_CLOCK_ID),
    )
    connection.commit()


def _read_clock(connection: sqlite3.Connection) -> SimulatedClockReadback:
    row = connection.execute(
        """
        SELECT current_time_ms, clock_spec_digest
        FROM simulated_clock
        WHERE clock_id = ?
        """,
        (SIMULATED_CLOCK_ID,),
    ).fetchone()
    if row is None:
        raise RuntimeError("simulated clock readback is missing")
    transitions = tuple(
        (int(item[0]), int(item[1]))
        for item in connection.execute(
            "SELECT from_ms, to_ms FROM clock_transitions ORDER BY transition_ordinal"
        )
    )
    payload: dict[str, Any] = {
        "schema": "assurance-lab.simulated-clock-readback/v1",
        "clock_id": SIMULATED_CLOCK_ID,
        "current_time_ms": int(row[0]),
        "transitions": [
            {"from_ms": start, "to_ms": end} for start, end in transitions
        ],
        "clock_spec_digest": str(row[1]),
    }
    canonical = rfc8785.dumps(payload).decode("utf-8")
    return SimulatedClockReadback(
        clock_id=SIMULATED_CLOCK_ID,
        current_time_ms=int(row[0]),
        transitions=transitions,
        clock_spec_digest=str(row[1]),
        readback_canonical=canonical,
        readback_digest=_sha256(canonical.encode("utf-8")),
    )


def _clock_readback_valid(readback: SimulatedClockReadback) -> bool:
    payload: dict[str, Any] = {
        "schema": "assurance-lab.simulated-clock-readback/v1",
        "clock_id": readback.clock_id,
        "current_time_ms": readback.current_time_ms,
        "transitions": [
            {"from_ms": start, "to_ms": end}
            for start, end in readback.transitions
        ],
        "clock_spec_digest": readback.clock_spec_digest,
    }
    canonical = rfc8785.dumps(payload).decode("utf-8")
    contiguous = bool(readback.transitions)
    previous = 0
    for start, end in readback.transitions:
        if start != previous or end <= start:
            contiguous = False
            break
        previous = end
    return all(
        (
            readback.readback_canonical == canonical,
            readback.readback_digest == _sha256(canonical.encode("utf-8")),
            readback.clock_id == SIMULATED_CLOCK_ID,
            readback.clock_spec_digest == CLOCK_SPEC_DIGEST,
            readback.current_time_ms == ALERT_SLO_MS,
            contiguous,
            previous == ALERT_SLO_MS,
        )
    )


def _write_source_events(
    connection: sqlite3.Connection,
    *,
    trace_id: str,
    action_digest: str,
    source_plan: tuple[tuple[str, int, str], ...],
) -> tuple[SourceEventRecord, ...]:
    records = tuple(
        _source_record(
            event_id=event_id,
            trace_id=trace_id,
            action_digest=action_digest,
            source_sequence=source_sequence,
            event_type=event_type,
            observed_at_ms=(index + 1) * 100,
        )
        for index, (event_id, source_sequence, event_type) in enumerate(source_plan)
    )
    for event in records:
        _advance_clock(connection, event.observed_at_ms)
        connection.execute(
            """
            INSERT INTO source_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                event.trace_id,
                event.action_digest,
                event.source_id,
                event.source_sequence,
                event.event_type,
                event.observed_at_ms,
                event.clock_id,
                event.clock_spec_digest,
                event.event_digest,
            ),
        )
    connection.commit()
    return records


def _source_record(
    *,
    event_id: str,
    trace_id: str,
    action_digest: str,
    source_sequence: int,
    event_type: str,
    observed_at_ms: int,
) -> SourceEventRecord:
    payload = _source_event_payload(
        event_id=event_id,
        trace_id=trace_id,
        action_digest=action_digest,
        source_sequence=source_sequence,
        event_type=event_type,
        observed_at_ms=observed_at_ms,
    )
    return SourceEventRecord(
        event_id=event_id,
        trace_id=trace_id,
        action_digest=action_digest,
        source_id=SOURCE_ID,
        source_sequence=source_sequence,
        event_type=event_type,
        observed_at_ms=observed_at_ms,
        clock_id=SIMULATED_CLOCK_ID,
        clock_spec_digest=CLOCK_SPEC_DIGEST,
        event_digest=_sha256(rfc8785.dumps(payload)),
    )


def _source_event_payload(
    *,
    event_id: str,
    trace_id: str,
    action_digest: str,
    source_sequence: int,
    event_type: str,
    observed_at_ms: int,
) -> dict[str, Any]:
    return {
        "schema": "assurance-lab.source-event/v1",
        "event_id": event_id,
        "trace_id": trace_id,
        "action_digest": action_digest,
        "source_id": SOURCE_ID,
        "source_sequence": source_sequence,
        "event_type": event_type,
        "observed_at_ms": observed_at_ms,
        "clock_id": SIMULATED_CLOCK_ID,
        "clock_spec_digest": CLOCK_SPEC_DIGEST,
    }


def _read_source_events(
    connection: sqlite3.Connection,
) -> tuple[SourceEventRecord, ...]:
    rows = connection.execute(
        """
        SELECT event_id, trace_id, action_digest, source_id, source_sequence,
               event_type, observed_at_ms, clock_id, clock_spec_digest,
               event_digest
        FROM source_events
        ORDER BY source_sequence
        """
    )
    return tuple(
        SourceEventRecord(
            event_id=str(row[0]),
            trace_id=str(row[1]),
            action_digest=str(row[2]),
            source_id=str(row[3]),
            source_sequence=int(row[4]),
            event_type=str(row[5]),
            observed_at_ms=int(row[6]),
            clock_id=str(row[7]),
            clock_spec_digest=str(row[8]),
            event_digest=str(row[9]),
        )
        for row in rows
    )


def _write_forwarded_events(
    connection: sqlite3.Connection,
    *,
    source_events: tuple[SourceEventRecord, ...],
    route_id: str,
    collector_run_id: str,
) -> None:
    for source in source_events:
        payload = _forwarding_payload(
            source=source,
            route_id=route_id,
            collector_run_id=collector_run_id,
        )
        connection.execute(
            """
            INSERT INTO forwarded_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source.event_id,
                source.trace_id,
                source.action_digest,
                source.source_id,
                source.source_sequence,
                source.event_type,
                source.event_digest,
                route_id,
                collector_run_id,
                _sha256(rfc8785.dumps(payload)),
            ),
        )
    connection.commit()


def _read_forwarded_events(
    connection: sqlite3.Connection,
) -> tuple[ForwardedEventRecord, ...]:
    rows = connection.execute(
        """
        SELECT event_id, trace_id, action_digest, source_id, source_sequence,
               event_type, source_event_digest, route_id, collector_run_id,
               forwarding_digest
        FROM forwarded_events
        ORDER BY source_sequence
        """
    )
    return tuple(
        ForwardedEventRecord(
            event_id=str(row[0]),
            trace_id=str(row[1]),
            action_digest=str(row[2]),
            source_id=str(row[3]),
            source_sequence=int(row[4]),
            event_type=str(row[5]),
            source_event_digest=str(row[6]),
            route_id=str(row[7]),
            collector_run_id=str(row[8]),
            forwarding_digest=str(row[9]),
        )
        for row in rows
    )


def _forwarding_payload(
    *,
    source: SourceEventRecord,
    route_id: str,
    collector_run_id: str,
) -> dict[str, Any]:
    return {
        "schema": "assurance-lab.forwarded-event/v1",
        "event_id": source.event_id,
        "trace_id": source.trace_id,
        "action_digest": source.action_digest,
        "source_id": source.source_id,
        "source_sequence": source.source_sequence,
        "event_type": source.event_type,
        "source_event_digest": source.event_digest,
        "route_id": route_id,
        "collector_run_id": collector_run_id,
    }


def _forwarding_readback_valid(
    forwarded_events: tuple[ForwardedEventRecord, ...],
    source_events: tuple[SourceEventRecord, ...],
    *,
    trace_id: str,
    action_digest: str,
    route_id: str,
    collector_run_id: str,
) -> bool:
    if not forwarded_events or len(forwarded_events) != len(source_events):
        return False
    for forwarded, source in zip(forwarded_events, source_events, strict=True):
        expected_payload = _forwarding_payload(
            source=source,
            route_id=route_id,
            collector_run_id=collector_run_id,
        )
        if not all(
            (
                forwarded.event_id == source.event_id,
                forwarded.trace_id == source.trace_id == trace_id,
                forwarded.action_digest == source.action_digest == action_digest,
                forwarded.source_id == source.source_id == SOURCE_ID,
                forwarded.source_sequence == source.source_sequence,
                forwarded.event_type == source.event_type,
                forwarded.source_event_digest == source.event_digest,
                forwarded.route_id == route_id,
                forwarded.collector_run_id == collector_run_id,
                forwarded.forwarding_digest
                == _sha256(rfc8785.dumps(expected_payload)),
            )
        ):
            return False
    return True


def _alert_evidence_graph_valid(
    alerts: tuple[AlertRecord, ...],
    source_events: tuple[SourceEventRecord, ...],
    forwarded_events: tuple[ForwardedEventRecord, ...],
    *,
    trace_id: str,
    action_digest: str,
    collector_run_id: str,
    detector_run_id: str,
) -> bool:
    """Require every alert edge to resolve to the fixed raw evidence graph."""

    source_by_id = {event.event_id: event for event in source_events}
    if len(source_by_id) != len(source_events):
        return False
    if forwarded_events and not _forwarding_readback_valid(
        forwarded_events,
        source_events,
        trace_id=trace_id,
        action_digest=action_digest,
        route_id=FALLBACK_ROUTE_ID,
        collector_run_id=collector_run_id,
    ):
        return False
    forwarded_by_id = {event.event_id: event for event in forwarded_events}
    if len(forwarded_by_id) != len(forwarded_events):
        return False
    if len({alert.alert_id for alert in alerts}) != len(alerts):
        return False

    for alert in alerts:
        if (
            not alert.source_event_ids
            or len(set(alert.source_event_ids)) != len(alert.source_event_ids)
        ):
            return False
        try:
            correlated_sources = tuple(
                source_by_id[event_id] for event_id in alert.source_event_ids
            )
        except KeyError:
            return False
        if not all(
            (
                alert.trace_id == trace_id,
                alert.action_digest == action_digest,
                alert.source_id == SOURCE_ID,
                alert.source_sequences
                == tuple(
                    event.source_sequence for event in correlated_sources
                ),
                alert.clock_id == SIMULATED_CLOCK_ID,
                alert.clock_spec_digest == CLOCK_SPEC_DIGEST,
                _correlation_valid(alert, correlated_sources),
            )
        ):
            return False

        if alert.rule_id == NAMED_RULE_ID:
            if not all(
                (
                    alert.alert_kind == AlertKind.NAMED_EXACT,
                    alert.alert_id
                    == _alert_id(AlertKind.NAMED_EXACT, trace_id),
                    alert.source_event_ids
                    == tuple(event.event_id for event in source_events),
                    alert.evidence_route_id == DIRECT_SOURCE_ROUTE_ID,
                    not alert.forwarded_event_digests,
                    alert.detector_run_id == detector_run_id,
                )
            ):
                return False
            continue

        if alert.rule_id != FALLBACK_RULE_ID:
            return False
        try:
            correlated_forwarded = tuple(
                forwarded_by_id[event_id]
                for event_id in alert.source_event_ids
            )
        except KeyError:
            return False
        if not all(
            (
                alert.alert_kind == AlertKind.BROAD_FALLBACK,
                alert.alert_id
                == _alert_id(AlertKind.BROAD_FALLBACK, trace_id),
                len(correlated_sources) == 1,
                correlated_sources[0].event_type
                == "out-of-assignment-sensitive-read",
                alert.evidence_route_id == FALLBACK_ROUTE_ID,
                alert.forwarded_event_digests
                == tuple(
                    event.forwarding_digest
                    for event in correlated_forwarded
                ),
                alert.detector_run_id is None,
            )
        ):
            return False
    return True


def _source_records_for_forwarded(
    forwarded_events: tuple[ForwardedEventRecord, ...],
    source_events: tuple[SourceEventRecord, ...],
) -> tuple[SourceEventRecord, ...]:
    by_id = {event.event_id: event for event in source_events}
    try:
        return tuple(by_id[event.event_id] for event in forwarded_events)
    except KeyError as exc:
        raise RuntimeError("forwarded event has no bound source event") from exc


def _current_clock_ms(connection: sqlite3.Connection) -> int:
    row = connection.execute(
        "SELECT current_time_ms FROM simulated_clock WHERE clock_id = ?",
        (SIMULATED_CLOCK_ID,),
    ).fetchone()
    if row is None:
        raise RuntimeError("simulated clock is missing")
    return int(row[0])


def _start_detector_run(
    connection: sqlite3.Connection,
    *,
    trace_id: str,
) -> str:
    """Persist the running detector operation before any queue work begins."""

    detector_run_id = _detector_run_id(trace_id)
    rule_active = _rule_active(connection, NAMED_RULE_ID)
    connection.execute(
        """
        INSERT INTO detector_runs
            (detector_run_id, trace_id, rule_id, rule_active_at_start, status,
             started_at_ms, completed_at_ms, clock_id, clock_spec_digest)
        VALUES (?, ?, ?, ?, 'running', ?, NULL, ?, ?)
        """,
        (
            detector_run_id,
            trace_id,
            NAMED_RULE_ID,
            int(rule_active),
            _current_clock_ms(connection),
            SIMULATED_CLOCK_ID,
            CLOCK_SPEC_DIGEST,
        ),
    )
    connection.commit()
    return detector_run_id


def _enqueue_detector_source_events(
    connection: sqlite3.Connection,
    *,
    detector_run_id: str,
    trace_id: str,
) -> None:
    """Copy the source-store rows into a persisted pending detector queue."""

    enqueued_at_ms = _current_clock_ms(connection)
    connection.execute(
        """
        INSERT INTO detector_queue
            (detector_run_id, event_id, source_sequence, state,
             enqueued_at_ms, processed_at_ms)
        SELECT ?, event_id, source_sequence, 'pending', ?, NULL
        FROM source_events
        WHERE trace_id = ?
        ORDER BY source_sequence
        """,
        (detector_run_id, enqueued_at_ms, trace_id),
    )
    connection.commit()


def _read_queued_source_events(
    connection: sqlite3.Connection,
    *,
    detector_run_id: str,
    state: str,
) -> tuple[SourceEventRecord, ...]:
    rows = connection.execute(
        """
        SELECT source.event_id, source.trace_id, source.action_digest,
               source.source_id, source.source_sequence, source.event_type,
               source.observed_at_ms, source.clock_id,
               source.clock_spec_digest, source.event_digest
        FROM detector_queue AS queue
        JOIN source_events AS source ON source.event_id = queue.event_id
        WHERE queue.detector_run_id = ? AND queue.state = ?
        ORDER BY queue.source_sequence
        """,
        (detector_run_id, state),
    )
    return tuple(
        SourceEventRecord(
            event_id=str(row[0]),
            trace_id=str(row[1]),
            action_digest=str(row[2]),
            source_id=str(row[3]),
            source_sequence=int(row[4]),
            event_type=str(row[5]),
            observed_at_ms=int(row[6]),
            clock_id=str(row[7]),
            clock_spec_digest=str(row[8]),
            event_digest=str(row[9]),
        )
        for row in rows
    )


def _process_named_detector_queue(
    connection: sqlite3.Connection,
    *,
    detector_run_id: str,
) -> None:
    """Run the detector from persisted rule, queue, clock, and source rows."""

    run_row = connection.execute(
        """
        SELECT trace_id, rule_id, rule_active_at_start, status
        FROM detector_runs
        WHERE detector_run_id = ?
        """,
        (detector_run_id,),
    ).fetchone()
    if run_row is None:
        raise RuntimeError("detector run is missing")
    trace_id = str(run_row[0])
    rule_id = str(run_row[1])
    rule_active_at_start = bool(run_row[2])
    if rule_id != NAMED_RULE_ID or str(run_row[3]) != "running":
        raise RuntimeError("detector run is not a running named-rule operation")
    if _rule_active(connection, rule_id) != rule_active_at_start:
        raise RuntimeError("named rule changed while the detector run was active")

    pending = _read_queued_source_events(
        connection,
        detector_run_id=detector_run_id,
        state="pending",
    )
    current_time_ms = _current_clock_ms(connection)
    if (
        rule_active_at_start
        and pending
        and all(event.trace_id == trace_id for event in pending)
        and all(event.action_digest == ATTACK_ACTION_DIGEST for event in pending)
        and _exact_pattern_present(pending)
    ):
        _write_alert(
            connection,
            alert_kind=AlertKind.NAMED_EXACT,
            rule_id=rule_id,
            trace_id=trace_id,
            action_digest=ATTACK_ACTION_DIGEST,
            source_events=pending,
            triggered_at_ms=current_time_ms,
            evidence_route_id=DIRECT_SOURCE_ROUTE_ID,
            forwarded_events=(),
            detector_run_id=detector_run_id,
        )

    connection.execute(
        """
        UPDATE detector_queue
        SET state = 'processed', processed_at_ms = ?
        WHERE detector_run_id = ? AND state = 'pending'
        """,
        (current_time_ms, detector_run_id),
    )
    queue_state = connection.execute(
        """
        SELECT COUNT(*),
               SUM(CASE WHEN state = 'pending' THEN 1 ELSE 0 END)
        FROM detector_queue
        WHERE detector_run_id = ?
        """,
        (detector_run_id,),
    ).fetchone()
    if (
        queue_state is not None
        and int(queue_state[0]) > 0
        and int(queue_state[1] or 0) == 0
    ):
        connection.execute(
            """
            UPDATE detector_runs
            SET status = 'complete', completed_at_ms = ?
            WHERE detector_run_id = ? AND status = 'running'
            """,
            (current_time_ms, detector_run_id),
        )
    connection.commit()


def _detector_run_payload(run: DetectorRunReadback) -> dict[str, Any]:
    return {
        "schema": "assurance-lab.detector-run-readback/v2",
        "detector_run_id": run.detector_run_id,
        "trace_id": run.trace_id,
        "rule_id": run.rule_id,
        "rule_active": run.rule_active,
        "status": run.status,
        "started_at_ms": run.started_at_ms,
        "evaluated_event_count": run.evaluated_event_count,
        "source_high_watermark": run.source_high_watermark,
        "pending_event_count": run.pending_event_count,
        "completed_at_ms": run.completed_at_ms,
        "processed_event_ids": list(run.processed_event_ids),
        "processed_source_sequences": list(run.processed_source_sequences),
        "processed_source_event_digests": list(
            run.processed_source_event_digests
        ),
        "observed_named_alert_ids": list(run.observed_named_alert_ids),
        "clock_id": run.clock_id,
        "clock_spec_digest": run.clock_spec_digest,
    }


def _read_detector_run(
    connection: sqlite3.Connection,
    detector_run_id: str,
) -> DetectorRunReadback:
    """Reconstruct the readback from raw run, queue, source, and alert rows."""

    run_row = connection.execute(
        """
        SELECT trace_id, rule_id, rule_active_at_start, status, started_at_ms,
               completed_at_ms, clock_id, clock_spec_digest
        FROM detector_runs
        WHERE detector_run_id = ?
        """,
        (detector_run_id,),
    ).fetchone()
    if run_row is None:
        raise RuntimeError("detector run readback is missing")
    processed_rows = tuple(
        connection.execute(
            """
            SELECT queue.event_id, queue.source_sequence, source.event_digest
            FROM detector_queue AS queue
            JOIN source_events AS source ON source.event_id = queue.event_id
            WHERE queue.detector_run_id = ? AND queue.state = 'processed'
            ORDER BY queue.source_sequence
            """,
            (detector_run_id,),
        )
    )
    pending_row = connection.execute(
        """
        SELECT COUNT(*)
        FROM detector_queue
        WHERE detector_run_id = ? AND state = 'pending'
        """,
        (detector_run_id,),
    ).fetchone()
    named_alert_ids = tuple(
        str(row[0])
        for row in connection.execute(
            """
            SELECT alert_id
            FROM alerts
            WHERE detector_run_id = ? AND rule_id = ?
            ORDER BY alert_id
            """,
            (detector_run_id, NAMED_RULE_ID),
        )
    )
    processed_sequences = tuple(int(row[1]) for row in processed_rows)
    provisional = DetectorRunReadback(
        detector_run_id=detector_run_id,
        trace_id=str(run_row[0]),
        rule_id=str(run_row[1]),
        rule_active=bool(run_row[2]),
        status=str(run_row[3]),
        started_at_ms=int(run_row[4]),
        evaluated_event_count=len(processed_rows),
        source_high_watermark=max(processed_sequences, default=0),
        pending_event_count=int(pending_row[0]) if pending_row else 0,
        completed_at_ms=(
            int(run_row[5]) if run_row[5] is not None else None
        ),
        processed_event_ids=tuple(str(row[0]) for row in processed_rows),
        processed_source_sequences=processed_sequences,
        processed_source_event_digests=tuple(
            str(row[2]) for row in processed_rows
        ),
        observed_named_alert_ids=named_alert_ids,
        clock_id=str(run_row[6]),
        clock_spec_digest=str(run_row[7]),
        readback_canonical="pending",
        readback_digest="pending",
    )
    canonical = rfc8785.dumps(_detector_run_payload(provisional)).decode("utf-8")
    return replace(
        provisional,
        readback_canonical=canonical,
        readback_digest=_sha256(canonical.encode("utf-8")),
    )


def _detector_run_valid(
    run: DetectorRunReadback,
    *,
    source_events: tuple[SourceEventRecord, ...],
    alerts: tuple[AlertRecord, ...],
    trace_id: str,
    named_rule_active: bool,
) -> bool:
    if not source_events:
        return False
    canonical = rfc8785.dumps(_detector_run_payload(run)).decode("utf-8")
    expected_named_ids = tuple(
        alert.alert_id
        for alert in alerts
        if alert.rule_id == NAMED_RULE_ID
        and alert.detector_run_id == run.detector_run_id
    )
    source_sequences = tuple(event.source_sequence for event in source_events)
    return all(
        (
            run.readback_canonical == canonical,
            run.readback_digest == _sha256(canonical.encode("utf-8")),
            run.detector_run_id == _detector_run_id(trace_id),
            run.trace_id == trace_id,
            run.rule_id == NAMED_RULE_ID,
            run.rule_active == named_rule_active,
            run.status == "complete",
            run.started_at_ms == 300,
            run.evaluated_event_count == len(source_events),
            run.source_high_watermark
            == max(event.source_sequence for event in source_events),
            run.pending_event_count == 0,
            run.completed_at_ms == 800,
            run.processed_event_ids
            == tuple(event.event_id for event in source_events),
            run.processed_source_sequences == source_sequences,
            run.processed_source_event_digests
            == tuple(event.event_digest for event in source_events),
            run.observed_named_alert_ids == expected_named_ids,
            run.clock_id == SIMULATED_CLOCK_ID,
            run.clock_spec_digest == CLOCK_SPEC_DIGEST,
        )
    )


def _record_alert_query_results(
    connection: sqlite3.Connection,
    *,
    query_id: str,
    trace_id: str,
    as_of_ms: int,
) -> None:
    rows = tuple(
        connection.execute(
            """
            SELECT alert_id
            FROM alerts
            WHERE trace_id = ? AND triggered_at_ms <= ?
            ORDER BY triggered_at_ms, alert_id
            """,
            (trace_id, as_of_ms),
        )
    )
    connection.executemany(
        """
        INSERT INTO alert_query_results (query_id, result_ordinal, alert_id)
        VALUES (?, ?, ?)
        """,
        (
            (query_id, ordinal, str(row[0]))
            for ordinal, row in enumerate(rows, start=1)
        ),
    )


def _complete_alert_query(
    connection: sqlite3.Connection,
    *,
    query_id: str,
    as_of_ms: int,
) -> None:
    connection.execute(
        """
        UPDATE alert_query_operations
        SET status = 'complete', completed_at_ms = ?, as_of_ms = ?
        WHERE query_id = ? AND status = 'running'
        """,
        (as_of_ms, as_of_ms, query_id),
    )


def _alert_query_payload(query: AlertQueryReadback) -> dict[str, Any]:
    return {
        "schema": "assurance-lab.alert-query-readback/v2",
        "query_id": query.query_id,
        "trace_id": query.trace_id,
        "completed": query.completed,
        "started_at_ms": query.started_at_ms,
        "completed_at_ms": query.completed_at_ms,
        "as_of_ms": query.as_of_ms,
        "observed_alert_ids": list(query.observed_alert_ids),
        "clock_id": query.clock_id,
        "clock_spec_digest": query.clock_spec_digest,
    }


def _read_alert_query(
    connection: sqlite3.Connection,
    query_id: str,
) -> AlertQueryReadback:
    row = connection.execute(
        """
        SELECT trace_id, status, started_at_ms, completed_at_ms, as_of_ms,
               clock_id, clock_spec_digest
        FROM alert_query_operations
        WHERE query_id = ?
        """,
        (query_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError("alert query operation is missing")
    observed_alert_ids = tuple(
        str(item[0])
        for item in connection.execute(
            """
            SELECT alert_id
            FROM alert_query_results
            WHERE query_id = ?
            ORDER BY result_ordinal
            """,
            (query_id,),
        )
    )
    provisional = AlertQueryReadback(
        query_id=query_id,
        trace_id=str(row[0]),
        completed=str(row[1]) == "complete",
        started_at_ms=int(row[2]),
        completed_at_ms=(int(row[3]) if row[3] is not None else None),
        as_of_ms=(int(row[4]) if row[4] is not None else -1),
        observed_alert_ids=observed_alert_ids,
        clock_id=str(row[5]),
        clock_spec_digest=str(row[6]),
        readback_canonical="pending",
        readback_digest="pending",
    )
    canonical = rfc8785.dumps(_alert_query_payload(provisional)).decode("utf-8")
    return replace(
        provisional,
        readback_canonical=canonical,
        readback_digest=_sha256(canonical.encode("utf-8")),
    )


def _execute_and_read_alert_query(
    connection: sqlite3.Connection,
    *,
    trace_id: str,
) -> AlertQueryReadback:
    """Execute a persisted alert query and reconstruct its raw result rows."""

    query_id = _alert_query_id(trace_id)
    current_time_ms = _current_clock_ms(connection)
    connection.execute(
        """
        INSERT INTO alert_query_operations
            (query_id, trace_id, status, started_at_ms, completed_at_ms,
             as_of_ms, clock_id, clock_spec_digest)
        VALUES (?, ?, 'running', ?, NULL, NULL, ?, ?)
        """,
        (
            query_id,
            trace_id,
            current_time_ms,
            SIMULATED_CLOCK_ID,
            CLOCK_SPEC_DIGEST,
        ),
    )
    _record_alert_query_results(
        connection,
        query_id=query_id,
        trace_id=trace_id,
        as_of_ms=current_time_ms,
    )
    _complete_alert_query(
        connection,
        query_id=query_id,
        as_of_ms=current_time_ms,
    )
    connection.commit()
    return _read_alert_query(connection, query_id)


def _alert_query_valid(
    query: AlertQueryReadback,
    *,
    alerts: tuple[AlertRecord, ...],
    trace_id: str,
    clock_readback: SimulatedClockReadback,
) -> bool:
    canonical = rfc8785.dumps(_alert_query_payload(query)).decode("utf-8")
    return all(
        (
            query.readback_canonical == canonical,
            query.readback_digest == _sha256(canonical.encode("utf-8")),
            query.query_id == _alert_query_id(trace_id),
            query.trace_id == trace_id,
            query.completed,
            query.started_at_ms == ALERT_SLO_MS,
            query.completed_at_ms == ALERT_SLO_MS,
            query.as_of_ms == ALERT_SLO_MS == clock_readback.current_time_ms,
            query.observed_alert_ids
            == tuple(alert.alert_id for alert in alerts),
            query.clock_id == clock_readback.clock_id == SIMULATED_CLOCK_ID,
            query.clock_spec_digest
            == clock_readback.clock_spec_digest
            == CLOCK_SPEC_DIGEST,
        )
    )


def _write_alert(
    connection: sqlite3.Connection,
    *,
    alert_kind: AlertKind,
    rule_id: str,
    trace_id: str,
    action_digest: str,
    source_events: tuple[SourceEventRecord, ...],
    triggered_at_ms: int,
    evidence_route_id: str,
    forwarded_events: tuple[ForwardedEventRecord, ...],
    detector_run_id: str | None,
) -> None:
    alert_id = _alert_id(alert_kind, trace_id)
    correlation_payload = _correlation_payload(
        alert_id=alert_id,
        alert_kind=alert_kind,
        rule_id=rule_id,
        trace_id=trace_id,
        action_digest=action_digest,
        source_events=source_events,
        evidence_route_id=evidence_route_id,
        forwarded_event_digests=tuple(
            event.forwarding_digest for event in forwarded_events
        ),
        detector_run_id=detector_run_id,
    )
    canonical = rfc8785.dumps(correlation_payload)
    connection.execute(
        """
        INSERT INTO alerts VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            alert_id,
            alert_kind.value,
            rule_id,
            trace_id,
            action_digest,
            SOURCE_ID,
            _canonical_json([event.event_id for event in source_events]),
            _canonical_json([event.source_sequence for event in source_events]),
            triggered_at_ms,
            SIMULATED_CLOCK_ID,
            CLOCK_SPEC_DIGEST,
            canonical.decode("utf-8"),
            _sha256(canonical),
            evidence_route_id,
            _canonical_json(
                [event.forwarding_digest for event in forwarded_events]
            ),
            detector_run_id,
        ),
    )
    connection.commit()


def _read_alerts(connection: sqlite3.Connection) -> tuple[AlertRecord, ...]:
    rows = connection.execute(
        """
        SELECT alert_id, alert_kind, rule_id, trace_id, action_digest, source_id,
               source_event_ids_json, source_sequences_json, triggered_at_ms,
               clock_id, clock_spec_digest, correlation_evidence_canonical,
               correlation_evidence_digest, evidence_route_id,
               forwarded_event_digests_json, detector_run_id
        FROM alerts
        ORDER BY triggered_at_ms, alert_id
        """
    )
    return tuple(
        AlertRecord(
            alert_id=str(row[0]),
            alert_kind=AlertKind(str(row[1])),
            rule_id=str(row[2]),
            trace_id=str(row[3]),
            action_digest=str(row[4]),
            source_id=str(row[5]),
            source_event_ids=_json_text_tuple(str(row[6])),
            source_sequences=_json_int_tuple(str(row[7])),
            triggered_at_ms=int(row[8]),
            clock_id=str(row[9]),
            clock_spec_digest=str(row[10]),
            correlation_evidence_canonical=str(row[11]),
            correlation_evidence_digest=str(row[12]),
            evidence_route_id=str(row[13]),
            forwarded_event_digests=_json_text_tuple(str(row[14])),
            detector_run_id=(str(row[15]) if row[15] is not None else None),
        )
        for row in rows
    )


def _rule_active(connection: sqlite3.Connection, rule_id: str) -> bool:
    row = connection.execute(
        "SELECT active FROM rules WHERE rule_id = ?",
        (rule_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError(f"missing fixed detection rule: {rule_id}")
    return bool(row[0])


def _collector_run_payload(readback: CollectorRunReadback) -> dict[str, Any]:
    return {
        "schema": "assurance-lab.collector-run-readback/v1",
        "collector_run_id": readback.collector_run_id,
        "trace_id": readback.trace_id,
        "status": readback.status,
        "healthy": readback.healthy,
        "collected_event_count": readback.collected_event_count,
        "source_id": readback.source_id,
        "source_healthy": readback.source_healthy,
        "collected_event_ids": list(readback.collected_event_ids),
        "collected_source_sequences": list(
            readback.collected_source_sequences
        ),
        "clock_id": readback.clock_id,
        "clock_spec_digest": readback.clock_spec_digest,
    }


def _read_collector_run(
    connection: sqlite3.Connection,
    collector_run_id: str,
) -> CollectorRunReadback:
    """Join the raw collector, source-health, and collected source rows."""

    row = connection.execute(
        """
        SELECT trace_id, status, healthy, collected_event_count,
               clock_id, clock_spec_digest
        FROM collector_runs
        WHERE collector_run_id = ?
        """,
        (collector_run_id,),
    ).fetchone()
    source_row = connection.execute(
        "SELECT source_id, healthy FROM sources WHERE source_id = ?",
        (SOURCE_ID,),
    ).fetchone()
    if row is None or source_row is None:
        raise RuntimeError("collector run readback is missing")
    collected_rows = tuple(
        connection.execute(
            """
            SELECT event_id, source_sequence
            FROM source_events
            WHERE trace_id = ?
            ORDER BY source_sequence
            """,
            (str(row[0]),),
        )
    )
    provisional = CollectorRunReadback(
        collector_run_id=collector_run_id,
        trace_id=str(row[0]),
        status=str(row[1]),
        healthy=bool(row[2]),
        collected_event_count=int(row[3]),
        source_id=str(source_row[0]),
        source_healthy=bool(source_row[1]),
        collected_event_ids=tuple(str(item[0]) for item in collected_rows),
        collected_source_sequences=tuple(
            int(item[1]) for item in collected_rows
        ),
        clock_id=str(row[4]),
        clock_spec_digest=str(row[5]),
        readback_canonical="pending",
        readback_digest="pending",
    )
    canonical = rfc8785.dumps(_collector_run_payload(provisional)).decode(
        "utf-8"
    )
    return replace(
        provisional,
        readback_canonical=canonical,
        readback_digest=_sha256(canonical.encode("utf-8")),
    )


def _collector_run_valid(
    readback: CollectorRunReadback,
    *,
    source_events: tuple[SourceEventRecord, ...],
    trace_id: str,
) -> bool:
    canonical = rfc8785.dumps(_collector_run_payload(readback)).decode("utf-8")
    return all(
        (
            readback.readback_canonical == canonical,
            readback.readback_digest == _sha256(canonical.encode("utf-8")),
            readback.collector_run_id == _collector_run_id(trace_id),
            readback.trace_id == trace_id,
            readback.status == "complete",
            readback.healthy,
            readback.collected_event_count == len(source_events),
            readback.source_id == SOURCE_ID,
            readback.source_healthy,
            readback.collected_event_ids
            == tuple(event.event_id for event in source_events),
            readback.collected_source_sequences
            == tuple(event.source_sequence for event in source_events),
            readback.clock_id == SIMULATED_CLOCK_ID,
            readback.clock_spec_digest == CLOCK_SPEC_DIGEST,
        )
    )


def _write_and_read_closure(
    connection: sqlite3.Connection,
    *,
    trace_id: str,
    action_digest: str,
    source_plan: tuple[tuple[str, int, str], ...],
    source_events: tuple[SourceEventRecord, ...],
    alerts: tuple[AlertRecord, ...],
    collector_run_id: str,
    collector_run_readback: CollectorRunReadback,
    clock_readback: SimulatedClockReadback,
    detector_run: DetectorRunReadback,
    alert_query: AlertQueryReadback,
    reload_attestation: CollectorReloadAttestation,
) -> ObservationWindowClosure:
    if collector_run_id != collector_run_readback.collector_run_id:
        raise RuntimeError("closure collector run does not match its readback")
    closure_without_artifact = ObservationWindowClosure(
        trace_id=trace_id,
        action_digest=action_digest,
        source_id=SOURCE_ID,
        expected_event_ids=tuple(item[0] for item in source_plan),
        observed_event_ids=tuple(event.event_id for event in source_events),
        expected_source_sequences=tuple(item[1] for item in source_plan),
        observed_source_sequences=tuple(
            event.source_sequence for event in source_events
        ),
        source_healthy=collector_run_readback.source_healthy,
        collector_run_id=collector_run_id,
        collector_healthy=collector_run_readback.healthy,
        collector_completed=collector_run_readback.status == "complete",
        collected_event_count=collector_run_readback.collected_event_count,
        collector_run_readback_digest=collector_run_readback.readback_digest,
        opened_at_ms=0,
        closed_at_ms=clock_readback.current_time_ms,
        clock_id=collector_run_readback.clock_id,
        clock_spec_digest=collector_run_readback.clock_spec_digest,
        clock_readback_digest=clock_readback.readback_digest,
        detector_run_id=detector_run.detector_run_id,
        detector_run_digest=detector_run.readback_digest,
        alert_query_id=alert_query.query_id,
        alert_query_digest=alert_query.readback_digest,
        reload_attestation_digest=reload_attestation.attestation_digest,
        artifact_canonical="pending",
        artifact_digest="pending",
    )
    canonical = rfc8785.dumps(_closure_payload(closure_without_artifact)).decode(
        "utf-8"
    )
    digest = _sha256(canonical.encode("utf-8"))
    connection.execute(
        "INSERT INTO observation_windows VALUES (?, ?, ?)",
        (trace_id, canonical, digest),
    )
    connection.commit()
    row = connection.execute(
        """
        SELECT artifact_canonical, artifact_digest
        FROM observation_windows
        WHERE trace_id = ?
        """,
        (trace_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError("window closure write was not readable")
    return ObservationWindowClosure(
        trace_id=closure_without_artifact.trace_id,
        action_digest=closure_without_artifact.action_digest,
        source_id=closure_without_artifact.source_id,
        expected_event_ids=closure_without_artifact.expected_event_ids,
        observed_event_ids=closure_without_artifact.observed_event_ids,
        expected_source_sequences=(
            closure_without_artifact.expected_source_sequences
        ),
        observed_source_sequences=(
            closure_without_artifact.observed_source_sequences
        ),
        source_healthy=closure_without_artifact.source_healthy,
        collector_run_id=closure_without_artifact.collector_run_id,
        collector_healthy=closure_without_artifact.collector_healthy,
        collector_completed=closure_without_artifact.collector_completed,
        collected_event_count=closure_without_artifact.collected_event_count,
        collector_run_readback_digest=(
            closure_without_artifact.collector_run_readback_digest
        ),
        opened_at_ms=closure_without_artifact.opened_at_ms,
        closed_at_ms=closure_without_artifact.closed_at_ms,
        clock_id=closure_without_artifact.clock_id,
        clock_spec_digest=closure_without_artifact.clock_spec_digest,
        clock_readback_digest=closure_without_artifact.clock_readback_digest,
        detector_run_id=closure_without_artifact.detector_run_id,
        detector_run_digest=closure_without_artifact.detector_run_digest,
        alert_query_id=closure_without_artifact.alert_query_id,
        alert_query_digest=closure_without_artifact.alert_query_digest,
        reload_attestation_digest=(
            closure_without_artifact.reload_attestation_digest
        ),
        artifact_canonical=str(row[0]),
        artifact_digest=str(row[1]),
    )


def _closure_payload(closure: ObservationWindowClosure) -> dict[str, Any]:
    return {
        "schema": "assurance-lab.detection-window-closure/v1",
        "trace_id": closure.trace_id,
        "action_digest": closure.action_digest,
        "source_id": closure.source_id,
        "expected_event_ids": list(closure.expected_event_ids),
        "observed_event_ids": list(closure.observed_event_ids),
        "expected_source_sequences": list(closure.expected_source_sequences),
        "observed_source_sequences": list(closure.observed_source_sequences),
        "source_healthy": closure.source_healthy,
        "collector_run_id": closure.collector_run_id,
        "collector_healthy": closure.collector_healthy,
        "collector_completed": closure.collector_completed,
        "collected_event_count": closure.collected_event_count,
        "collector_run_readback_digest": (
            closure.collector_run_readback_digest
        ),
        "opened_at_ms": closure.opened_at_ms,
        "closed_at_ms": closure.closed_at_ms,
        "clock_id": closure.clock_id,
        "clock_spec_digest": closure.clock_spec_digest,
        "clock_readback_digest": closure.clock_readback_digest,
        "detector_run_id": closure.detector_run_id,
        "detector_run_digest": closure.detector_run_digest,
        "alert_query_id": closure.alert_query_id,
        "alert_query_digest": closure.alert_query_digest,
        "reload_attestation_digest": closure.reload_attestation_digest,
    }


def _closure_valid_from_parts(
    closure: ObservationWindowClosure,
    *,
    source_events: tuple[SourceEventRecord, ...],
    forwarded_events: tuple[ForwardedEventRecord, ...],
    alerts: tuple[AlertRecord, ...],
    source_plan: tuple[tuple[str, int, str], ...],
    trace_id: str,
    action_digest: str,
    clock_readback: SimulatedClockReadback,
    detector_run: DetectorRunReadback,
    alert_query: AlertQueryReadback,
    reload_attestation: CollectorReloadAttestation,
    collector_run_readback: CollectorRunReadback,
    expected_named_rule_active: bool,
    expected_reload_performed: bool,
) -> bool:
    try:
        canonical = rfc8785.dumps(_closure_payload(closure)).decode("utf-8")
    except (rfc8785.CanonicalizationError, UnicodeError, ValueError):
        return False
    expected_event_ids = tuple(item[0] for item in source_plan)
    expected_sequences = tuple(item[1] for item in source_plan)
    raw_event_ids = tuple(event.event_id for event in source_events)
    raw_sequences = tuple(event.source_sequence for event in source_events)
    return all(
        (
            closure.artifact_canonical == canonical,
            closure.artifact_digest == _sha256(canonical.encode("utf-8")),
            closure.trace_id == trace_id,
            closure.action_digest == action_digest,
            closure.source_id == SOURCE_ID,
            closure.expected_event_ids == expected_event_ids,
            closure.observed_event_ids == raw_event_ids == expected_event_ids,
            closure.expected_source_sequences == expected_sequences,
            closure.observed_source_sequences == raw_sequences == expected_sequences,
            closure.source_healthy,
            closure.collector_run_id == _collector_run_id(trace_id),
            closure.collector_run_id
            == collector_run_readback.collector_run_id,
            closure.collector_healthy,
            closure.collector_completed,
            closure.collected_event_count == len(source_events) == len(source_plan),
            closure.collector_run_readback_digest
            == collector_run_readback.readback_digest,
            closure.opened_at_ms == 0,
            closure.closed_at_ms == ALERT_SLO_MS,
            closure.clock_id == SIMULATED_CLOCK_ID,
            closure.clock_spec_digest == CLOCK_SPEC_DIGEST,
            closure.clock_readback_digest == clock_readback.readback_digest,
            closure.detector_run_id == detector_run.detector_run_id,
            closure.detector_run_digest == detector_run.readback_digest,
            closure.alert_query_id == alert_query.query_id,
            closure.alert_query_digest == alert_query.readback_digest,
            closure.reload_attestation_digest
            == reload_attestation.attestation_digest,
            _source_binding_valid(
                source_events,
                trace_id=trace_id,
                action_digest=action_digest,
            ),
            _sequence_coverage_valid(source_events, source_plan),
            _alert_evidence_graph_valid(
                alerts,
                source_events,
                forwarded_events,
                trace_id=trace_id,
                action_digest=action_digest,
                collector_run_id=_collector_run_id(trace_id),
                detector_run_id=detector_run.detector_run_id,
            ),
            _clock_bound(
                source_events,
                alerts,
                closure,
                clock_readback=clock_readback,
            ),
            _detector_run_valid(
                detector_run,
                source_events=source_events,
                alerts=alerts,
                trace_id=trace_id,
                named_rule_active=expected_named_rule_active,
            ),
            _alert_query_valid(
                alert_query,
                alerts=alerts,
                trace_id=trace_id,
                clock_readback=clock_readback,
            ),
            _reload_attestation_valid(
                reload_attestation,
                trace_id=trace_id,
                expected_reload_performed=expected_reload_performed,
                expected_named_rule_active=expected_named_rule_active,
            ),
            _collector_run_valid(
                collector_run_readback,
                source_events=source_events,
                trace_id=trace_id,
            ),
        )
    )


def _source_binding_valid(
    source_events: tuple[SourceEventRecord, ...],
    *,
    trace_id: str,
    action_digest: str,
) -> bool:
    if not source_events:
        return False
    for event in source_events:
        expected = _source_event_payload(
            event_id=event.event_id,
            trace_id=event.trace_id,
            action_digest=event.action_digest,
            source_sequence=event.source_sequence,
            event_type=event.event_type,
            observed_at_ms=event.observed_at_ms,
        )
        if not all(
            (
                event.trace_id == trace_id,
                event.action_digest == action_digest,
                event.source_id == SOURCE_ID,
                event.clock_id == SIMULATED_CLOCK_ID,
                event.clock_spec_digest == CLOCK_SPEC_DIGEST,
                event.event_digest == _sha256(rfc8785.dumps(expected)),
            )
        ):
            return False
    return True


def _sequence_coverage_valid(
    source_events: tuple[SourceEventRecord, ...],
    source_plan: tuple[tuple[str, int, str], ...],
) -> bool:
    observed = tuple(
        (event.event_id, event.source_sequence, event.event_type)
        for event in source_events
    )
    return observed == source_plan and len({item[1] for item in observed}) == len(
        observed
    )


def _clock_bound(
    source_events: tuple[SourceEventRecord, ...],
    alerts: tuple[AlertRecord, ...],
    closure: ObservationWindowClosure,
    *,
    clock_readback: SimulatedClockReadback,
) -> bool:
    source_times = tuple(event.observed_at_ms for event in source_events)
    alert_times = tuple(alert.triggered_at_ms for alert in alerts)
    alert_schedule_valid = all(
        alert.triggered_at_ms
        == (
            800
            if alert.alert_kind == AlertKind.NAMED_EXACT
            else 1_200
        )
        for alert in alerts
    )
    clock_records_valid = all(
        event.clock_id == SIMULATED_CLOCK_ID
        and event.clock_spec_digest == CLOCK_SPEC_DIGEST
        for event in source_events
    ) and all(
        alert.clock_id == SIMULATED_CLOCK_ID
        and alert.clock_spec_digest == CLOCK_SPEC_DIGEST
        for alert in alerts
    )
    transition_destinations = tuple(
        end for _, end in clock_readback.transitions
    )
    return all(
        (
            _clock_readback_valid(clock_readback),
            clock_records_valid,
            closure.clock_id == SIMULATED_CLOCK_ID,
            closure.clock_spec_digest == CLOCK_SPEC_DIGEST,
            closure.clock_readback_digest == clock_readback.readback_digest,
            closure.opened_at_ms == 0,
            closure.closed_at_ms
            == clock_readback.current_time_ms
            == ALERT_SLO_MS,
            source_times == tuple(sorted(source_times)),
            source_times == (100, 200, 300),
            alert_schedule_valid,
            all(item in transition_destinations for item in source_times),
            all(item in transition_destinations for item in alert_times),
            all(closure.opened_at_ms <= item <= closure.closed_at_ms for item in source_times),
            all(closure.opened_at_ms <= item <= closure.closed_at_ms for item in alert_times),
        )
    )


def _named_alert_proofs(
    alerts: tuple[AlertRecord, ...],
    source_events: tuple[SourceEventRecord, ...],
    *,
    source_plan: tuple[tuple[str, int, str], ...],
    trace_id: str,
    action_digest: str,
    detector_run: DetectorRunReadback,
    alert_query: AlertQueryReadback,
    clock_readback: SimulatedClockReadback,
    closure_valid: bool,
    named_rule_active: bool,
) -> _NamedAlertProofs:
    named = tuple(alert for alert in alerts if alert.rule_id == NAMED_RULE_ID)
    unique_global_ids = len({alert.alert_id for alert in alerts}) == len(alerts)
    identity_unique = len(named) == 1 and unique_global_ids
    if len(named) != 1:
        return _NamedAlertProofs(
            identity_unique=identity_unique,
            rule_identity_bound=False,
            source_binding=False,
            correlation_valid=False,
            within_slo=False,
            full_claim=False,
        )
    alert = named[0]
    rule_identity = (
        alert.alert_kind == AlertKind.NAMED_EXACT
        and alert.rule_id == NAMED_RULE_ID
        and alert.alert_id == _alert_id(AlertKind.NAMED_EXACT, trace_id)
        and alert.evidence_route_id == DIRECT_SOURCE_ROUTE_ID
        and not alert.forwarded_event_digests
        and alert.detector_run_id == detector_run.detector_run_id
    )
    source_binding = all(
        (
            alert.trace_id == trace_id,
            alert.action_digest == action_digest,
            alert.source_id == SOURCE_ID,
            alert.source_event_ids
            == tuple(event.event_id for event in source_events),
            alert.source_sequences
            == tuple(event.source_sequence for event in source_events),
        )
    )
    correlation_valid = _correlation_valid(alert, source_events)
    within_slo = bool(source_events) and (
        0 <= alert.triggered_at_ms <= ALERT_SLO_MS
        and alert.triggered_at_ms
        >= max(event.observed_at_ms for event in source_events)
        and alert.triggered_at_ms
        - max(event.observed_at_ms for event in source_events)
        <= ALERT_SLO_MS
    )
    full = all(
        (
            identity_unique,
            rule_identity,
            source_binding,
            correlation_valid,
            within_slo,
            _source_binding_valid(
                source_events,
                trace_id=trace_id,
                action_digest=action_digest,
            ),
            _sequence_coverage_valid(source_events, source_plan),
            _exact_pattern_present(source_events),
            named_rule_active,
            _clock_readback_valid(clock_readback),
            _detector_run_valid(
                detector_run,
                source_events=source_events,
                alerts=alerts,
                trace_id=trace_id,
                named_rule_active=named_rule_active,
            ),
            detector_run.observed_named_alert_ids == (alert.alert_id,),
            _alert_query_valid(
                alert_query,
                alerts=alerts,
                trace_id=trace_id,
                clock_readback=clock_readback,
            ),
            alert.alert_id in alert_query.observed_alert_ids,
            closure_valid,
        )
    )
    return _NamedAlertProofs(
        identity_unique=identity_unique,
        rule_identity_bound=rule_identity,
        source_binding=source_binding,
        correlation_valid=correlation_valid,
        within_slo=within_slo,
        full_claim=full,
    )


def _fallback_alert_binding_valid(
    alerts: tuple[AlertRecord, ...],
    source_events: tuple[SourceEventRecord, ...],
    forwarded_events: tuple[ForwardedEventRecord, ...],
    *,
    trace_id: str,
    action_digest: str,
    suspicious: bool,
    fallback_forward: bool,
) -> bool:
    fallback = tuple(alert for alert in alerts if alert.rule_id == FALLBACK_RULE_ID)
    if not suspicious:
        return False
    if not fallback_forward:
        return False
    broad_forwarded = tuple(
        event
        for event in forwarded_events
        if event.event_type == "out-of-assignment-sensitive-read"
    )
    if len(fallback) != 1 or len(broad_forwarded) != 1:
        return False
    try:
        broad_source = _source_records_for_forwarded(
            broad_forwarded,
            source_events,
        )
    except RuntimeError:
        return False
    alert = fallback[0]
    return all(
        (
            alert.alert_kind == AlertKind.BROAD_FALLBACK,
            alert.alert_id == _alert_id(AlertKind.BROAD_FALLBACK, trace_id),
            alert.trace_id == trace_id,
            alert.action_digest == action_digest,
            alert.source_id == SOURCE_ID,
            alert.evidence_route_id == FALLBACK_ROUTE_ID,
            alert.forwarded_event_digests
            == tuple(event.forwarding_digest for event in broad_forwarded),
            alert.source_event_ids == (broad_source[0].event_id,),
            alert.source_sequences == (broad_source[0].source_sequence,),
            _correlation_valid(alert, broad_source),
            0 <= alert.triggered_at_ms <= ALERT_SLO_MS,
            alert.triggered_at_ms >= broad_source[0].observed_at_ms,
            alert.triggered_at_ms - broad_source[0].observed_at_ms
            <= ALERT_SLO_MS,
        )
    )


def _correlation_valid(
    alert: AlertRecord,
    source_events: tuple[SourceEventRecord, ...],
) -> bool:
    expected = _correlation_payload(
        alert_id=alert.alert_id,
        alert_kind=alert.alert_kind,
        rule_id=alert.rule_id,
        trace_id=alert.trace_id,
        action_digest=alert.action_digest,
        source_events=source_events,
        evidence_route_id=alert.evidence_route_id,
        forwarded_event_digests=alert.forwarded_event_digests,
        detector_run_id=alert.detector_run_id,
    )
    try:
        canonical = rfc8785.dumps(expected).decode("utf-8")
    except (rfc8785.CanonicalizationError, UnicodeError, ValueError):
        return False
    return (
        alert.correlation_evidence_canonical == canonical
        and alert.correlation_evidence_digest
        == _sha256(canonical.encode("utf-8"))
    )


def _correlation_payload(
    *,
    alert_id: str,
    alert_kind: AlertKind,
    rule_id: str,
    trace_id: str,
    action_digest: str,
    source_events: tuple[SourceEventRecord, ...],
    evidence_route_id: str,
    forwarded_event_digests: tuple[str, ...],
    detector_run_id: str | None,
) -> dict[str, Any]:
    return {
        "schema": "assurance-lab.alert-correlation/v1",
        "alert_id": alert_id,
        "alert_kind": alert_kind.value,
        "rule_id": rule_id,
        "trace_id": trace_id,
        "action_digest": action_digest,
        "source_id": SOURCE_ID,
        "source_event_ids": [event.event_id for event in source_events],
        "source_sequences": [event.source_sequence for event in source_events],
        "source_event_digests": [event.event_digest for event in source_events],
        "evidence_route_id": evidence_route_id,
        "forwarded_event_digests": list(forwarded_event_digests),
        "detector_run_id": detector_run_id,
    }


def _alert_existence(
    alerts: tuple[AlertRecord, ...],
    source_events: tuple[SourceEventRecord, ...],
) -> tuple[bool, int | None, int | None]:
    source_by_id = {event.event_id: event for event in source_events}
    observations: list[tuple[int, int]] = []
    for alert in alerts:
        try:
            correlated = tuple(
                source_by_id[event_id] for event_id in alert.source_event_ids
            )
        except KeyError:
            continue
        if not correlated:
            continue
        offset = alert.triggered_at_ms
        causal_latency = offset - max(
            event.observed_at_ms for event in correlated
        )
        if all(
            (
                alert.clock_id == SIMULATED_CLOCK_ID,
                alert.clock_spec_digest == CLOCK_SPEC_DIGEST,
                0 <= offset <= ALERT_SLO_MS,
                0 <= causal_latency <= ALERT_SLO_MS,
            )
        ):
            observations.append((offset, causal_latency))
    if not observations:
        return False, None, None
    first_offset, first_causal_latency = min(observations)
    return True, first_offset, first_causal_latency


def _absence_from_parts(
    *,
    alerts: tuple[AlertRecord, ...],
    closure_valid: bool,
) -> NamedAlertAbsence:
    if any(alert.rule_id == NAMED_RULE_ID for alert in alerts):
        return NamedAlertAbsence.PRESENT
    return (
        NamedAlertAbsence.CONCLUDED
        if closure_valid
        else NamedAlertAbsence.INDETERMINATE
    )


def _events(
    *,
    trace_id: str,
    action_name: str,
    action_digest: str,
    sham_level: str,
    source_events: tuple[SourceEventRecord, ...],
    source_binding: bool,
    sequence_coverage: bool,
    target_level: str,
    named_rule_active: bool,
    named_proofs: _NamedAlertProofs,
    compensator_level: str,
    forwarded_event_ids: tuple[str, ...],
    fallback_telemetry_forwarded: bool,
    fallback_binding: bool,
    alerts: tuple[AlertRecord, ...],
    any_alert_within_slo: bool,
    first_alert_offset: int | None,
    first_alert_causal_latency: int | None,
    tested_benign_action_unalerted: bool,
    closure: ObservationWindowClosure,
    closure_valid: bool,
    absence: NamedAlertAbsence,
    clock_bound: bool,
    detector_run: DetectorRunReadback,
    detector_run_valid: bool,
    alert_query: AlertQueryReadback,
    alert_query_valid: bool,
    reload_attestation: CollectorReloadAttestation,
) -> tuple[RuntimeEvent, ...]:
    alert_ids_canonical = _canonical_json([alert.alert_id for alert in alerts])
    named_alert_ids_canonical = _canonical_json(
        [alert.alert_id for alert in alerts if alert.rule_id == NAMED_RULE_ID]
    )
    named_correlation_artifacts_canonical = _canonical_json(
        [
            alert.correlation_evidence_digest
            for alert in alerts
            if alert.rule_id == NAMED_RULE_ID
        ]
    )
    fallback_alert_ids_canonical = _canonical_json(
        [alert.alert_id for alert in alerts if alert.rule_id == FALLBACK_RULE_ID]
    )
    source_ids_canonical = _canonical_json(
        [event.event_id for event in source_events]
    )
    forwarded_ids_canonical = _canonical_json(list(forwarded_event_ids))
    forwarded_digests_canonical = _canonical_json(
        [
            list(alert.forwarded_event_digests)
            for alert in alerts
            if alert.rule_id == FALLBACK_RULE_ID
        ]
    )
    return (
        RuntimeEvent(
            trace_id=trace_id,
            sequence=1,
            stage="input",
            component="detection-observer",
            event_type="source-sequence-observed",
            payload=(
                ("action", action_name),
                ("action_digest", action_digest),
                ("source_id", SOURCE_ID),
                ("source_event_ids_canonical", source_ids_canonical),
                ("source_event_count", len(source_events)),
                ("source_trace_action_bound", source_binding),
                ("source_sequence_coverage_complete", sequence_coverage),
                ("sham", sham_level),
                (
                    "collector_reload_performed",
                    reload_attestation.reload_performed,
                ),
                (
                    "collector_pre_instance_id",
                    reload_attestation.pre_instance_id,
                ),
                (
                    "collector_post_instance_id",
                    reload_attestation.post_instance_id,
                ),
                (
                    "collector_config_preserved",
                    reload_attestation.pre_config_digest
                    == reload_attestation.post_config_digest,
                ),
                (
                    "collector_reload_attestation",
                    reload_attestation.attestation_digest,
                ),
            ),
        ),
        RuntimeEvent(
            trace_id=trace_id,
            sequence=2,
            stage="target",
            component="exact-correlation-detector",
            event_type="named-alert-readback",
            payload=(
                ("target_mode", target_level),
                ("named_rule_id", NAMED_RULE_ID),
                ("named_rule_active", named_rule_active),
                (
                    "named_alert_count",
                    sum(alert.rule_id == NAMED_RULE_ID for alert in alerts),
                ),
                ("named_alert_ids_canonical", named_alert_ids_canonical),
                ("named_alert_identity_unique", named_proofs.identity_unique),
                (
                    "named_alert_rule_identity_bound",
                    named_proofs.rule_identity_bound,
                ),
                (
                    "named_alert_trace_source_action_bound",
                    named_proofs.source_binding,
                ),
                (
                    "named_correlation_evidence_valid",
                    named_proofs.correlation_valid,
                ),
                (
                    "named_correlation_artifacts_canonical",
                    named_correlation_artifacts_canonical,
                ),
                (
                    "named_exact_correlation_alert_proven",
                    named_proofs.full_claim,
                ),
                ("detector_run_id", detector_run.detector_run_id),
                ("detector_run_completed", detector_run_valid),
                (
                    "detector_source_high_watermark",
                    detector_run.source_high_watermark,
                ),
                (
                    "detector_pending_event_count",
                    detector_run.pending_event_count,
                ),
                ("detector_run_readback", detector_run.readback_digest),
            ),
        ),
        RuntimeEvent(
            trace_id=trace_id,
            sequence=3,
            stage="compensator",
            component="fallback-telemetry-path",
            event_type="fallback-forwarding-readback",
            payload=(
                ("compensator_mode", compensator_level),
                ("fallback_rule_id", FALLBACK_RULE_ID),
                ("fallback_route_id", FALLBACK_ROUTE_ID),
                ("fallback_alert_ids_canonical", fallback_alert_ids_canonical),
                (
                    "fallback_alert_forwarding_digests_canonical",
                    forwarded_digests_canonical,
                ),
                ("forwarded_event_ids_canonical", forwarded_ids_canonical),
                ("forwarded_event_count", len(forwarded_event_ids)),
                (
                    "fallback_telemetry_forwarded",
                    fallback_telemetry_forwarded,
                ),
                ("fallback_alert_binding_valid", fallback_binding),
            ),
        ),
        RuntimeEvent(
            trace_id=trace_id,
            sequence=4,
            stage="outcome",
            component="detection-observer",
            event_type="closed-window-readback",
            payload=(
                ("alert_ids_canonical", alert_ids_canonical),
                ("alert_count", len(alerts)),
                ("any_alert_within_slo", any_alert_within_slo),
                (
                    "first_alert_offset_from_window_open_ms",
                    first_alert_offset if first_alert_offset is not None else -1,
                ),
                (
                    "first_alert_causal_latency_ms",
                    (
                        first_alert_causal_latency
                        if first_alert_causal_latency is not None
                        else -1
                    ),
                ),
                (
                    "tested_benign_action_unalerted",
                    tested_benign_action_unalerted,
                ),
                ("source_trace_action_binding_proven", source_binding),
                ("source_sequence_coverage_complete", sequence_coverage),
                ("source_healthy", closure.source_healthy),
                ("collector_healthy", closure.collector_healthy),
                ("collector_completed", closure.collector_completed),
                ("simulated_clock_bound", clock_bound),
                ("observation_window_closed", closure_valid),
                ("alert_query_completed", alert_query_valid),
                ("alert_query_as_of_ms", alert_query.as_of_ms),
                ("alert_query_readback", alert_query.readback_digest),
                ("named_alert_absence", absence.value),
                ("window_closure_artifact", closure.artifact_digest),
                ("window_closure_canonical", closure.artifact_canonical),
            ),
        ),
    )


def _exact_pattern_present(
    source_events: tuple[SourceEventRecord, ...],
) -> bool:
    return tuple(event.event_type for event in source_events) == (
        "session-authenticated",
        "revoked-session-replay-observed",
        "out-of-assignment-sensitive-read",
    )


def _source_plan(action: dict[str, Any]) -> tuple[tuple[str, int, str], ...]:
    raw = action.get("source_event_plan")
    if not isinstance(raw, list):
        raise ValueError("fixed action source_event_plan must be a list")
    parsed: list[tuple[str, int, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("fixed action source event must be an object")
        event_id = item.get("event_id")
        sequence = item.get("sequence")
        event_type = item.get("event_type")
        if (
            not isinstance(event_id, str)
            or isinstance(sequence, bool)
            or not isinstance(sequence, int)
            or not isinstance(event_type, str)
        ):
            raise ValueError("fixed action source event has invalid fields")
        parsed.append((event_id, sequence, event_type))
    if not parsed:
        raise ValueError("fixed action source sequence cannot be empty")
    return tuple(parsed)


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


def _validate_trace_id(trace_id: str) -> None:
    if not _TRACE_ID.fullmatch(trace_id):
        raise ValueError("trace_id must be 1-128 safe identifier characters")


def _alert_id(alert_kind: AlertKind, trace_id: str) -> str:
    suffix = hashlib.sha256(
        f"{alert_kind.value}\0{trace_id}".encode()
    ).hexdigest()[:16].upper()
    label = "NAMED" if alert_kind == AlertKind.NAMED_EXACT else "FALLBACK"
    return f"SYNTH-ALERT-{label}-{suffix}"


def _collector_run_id(trace_id: str) -> str:
    suffix = hashlib.sha256(f"collector\0{trace_id}".encode()).hexdigest()[:16]
    return f"SYNTH-COLLECTOR-{suffix.upper()}"


def _collector_instance_id(trace_id: str, phase: str) -> str:
    suffix = hashlib.sha256(
        f"collector-instance\0{phase}\0{trace_id}".encode()
    ).hexdigest()[:16]
    return f"SYNTH-COLLECTOR-INSTANCE-{suffix.upper()}"


def _reload_attestation_id(trace_id: str) -> str:
    suffix = hashlib.sha256(
        f"reload-attestation\0{trace_id}".encode()
    ).hexdigest()[:16]
    return f"SYNTH-RELOAD-{suffix.upper()}"


def _reload_operation_id(trace_id: str) -> str:
    suffix = hashlib.sha256(
        f"reload-operation\0{trace_id}".encode()
    ).hexdigest()[:16]
    return f"SYNTH-RELOAD-OP-{suffix.upper()}"


def _detector_run_id(trace_id: str) -> str:
    suffix = hashlib.sha256(
        f"detector-run\0{trace_id}".encode()
    ).hexdigest()[:16]
    return f"SYNTH-DETECTOR-RUN-{suffix.upper()}"


def _alert_query_id(trace_id: str) -> str:
    suffix = hashlib.sha256(
        f"alert-query\0{trace_id}".encode()
    ).hexdigest()[:16]
    return f"SYNTH-ALERT-QUERY-{suffix.upper()}"


def _canonical_json(value: Any) -> str:
    return rfc8785.dumps(value).decode("utf-8")


def _json_text_tuple(value: str) -> tuple[str, ...]:
    parsed = json.loads(value)
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        raise RuntimeError("stored alert event ids are not a text list")
    return tuple(parsed)


def _json_object(value: str, label: str) -> dict[str, Any]:
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise RuntimeError(f"stored {label} is not an object")
    return parsed


def _object_text(value: dict[str, Any], field: str) -> str:
    item = value.get(field)
    if not isinstance(item, str):
        raise RuntimeError(f"stored readback field {field!r} is not text")
    return item


def _object_bool(value: dict[str, Any], field: str) -> bool:
    item = value.get(field)
    if not isinstance(item, bool):
        raise RuntimeError(f"stored readback field {field!r} is not boolean")
    return item


def _object_int(value: dict[str, Any], field: str) -> int:
    item = value.get(field)
    if isinstance(item, bool) or not isinstance(item, int):
        raise RuntimeError(f"stored readback field {field!r} is not an integer")
    return item


def _object_text_tuple(
    value: dict[str, Any],
    field: str,
) -> tuple[str, ...]:
    item = value.get(field)
    if not isinstance(item, list) or not all(
        isinstance(element, str) for element in item
    ):
        raise RuntimeError(f"stored readback field {field!r} is not a text list")
    return tuple(item)


def _json_int_tuple(value: str) -> tuple[int, ...]:
    parsed = json.loads(value)
    if not isinstance(parsed, list) or not all(
        isinstance(item, int) and not isinstance(item, bool) for item in parsed
    ):
        raise RuntimeError("stored alert source sequences are not an integer list")
    return tuple(parsed)


def _sha256(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"
