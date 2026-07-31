from __future__ import annotations

import itertools
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import rfc8785

import assurance_lab.scenarios.financial_detection_runtime as detection_runtime
from assurance_lab.contract import (
    CellSelector,
    CompiledExperiment,
    EvidencePolicyRef,
    EvidenceWindow,
    ExperimentScope,
    StringValue,
    TrialPlan,
    compile_experiment,
)
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
    SCENARIO_ID,
    SHAM_RELOAD,
    SHAM_STEADY,
    SOURCE_ID,
    TARGET_EFFECTIVE,
    TARGET_INEFFECTIVE,
    action_descriptor,
    build_financial_detection_contract,
)
from assurance_lab.scenarios.financial_detection_runtime import (
    CLOCK_SPEC_DIGEST,
    AlertKind,
    AlertRecord,
    BaselineVerdict,
    CollectorRunReadback,
    DetectionClaimState,
    DetectionResidualClassification,
    DetectorRunReadback,
    FinancialDetectionRuntime,
    NamedAlertAbsence,
    ObservationWindowClosure,
    SourceEventRecord,
    assess_detection_case,
    conclude_named_alert_absence,
)


def _digest(fill: str) -> str:
    return f"sha256:{fill * 64}"


def _selector(
    *,
    suspicious: bool,
    exact_rule_active: bool,
    fallback_forward: bool,
    collector_reload: bool = False,
) -> CellSelector:
    return CellSelector(
        input=ATTACK if suspicious else BENIGN,
        target=TARGET_EFFECTIVE if exact_rule_active else TARGET_INEFFECTIVE,
        compensator=COMPENSATOR_ON if fallback_forward else COMPENSATOR_OFF,
        sham=SHAM_RELOAD if collector_reload else SHAM_STEADY,
    )


def _compiled() -> CompiledExperiment:
    start = datetime(2026, 7, 29, 0, 0, tzinfo=UTC)
    scope = ExperimentScope(
        scenario_id=SCENARIO_ID,
        build_digest=_digest("1"),
        dataset_digest=_digest("2"),
        fixture_digest=_digest("3"),
        assessment_as_of=start + timedelta(hours=1),
        evidence_window=EvidenceWindow(
            start=start,
            end=start + timedelta(hours=2),
        ),
        evidence_policy=EvidencePolicyRef(
            id="local-evidence-v1",
            version="1.0.0",
            digest=_digest("4"),
        ),
    )
    return compile_experiment(
        build_financial_detection_contract(
            scope=scope,
            plan=TrialPlan(
                blocks=("fresh-clone-a",),
                replicates=2,
                order_seed="financial-detection-published-seed",
            ),
        )
    )


def test_contract_compiles_the_owned_sixteen_cell_detection_plan() -> None:
    compiled = _compiled()

    assert len(compiled.cells) == 16
    assert len(compiled.planned_trials) == 32
    assert compiled.current_selector == _selector(
        suspicious=True,
        exact_rule_active=False,
        fallback_forward=True,
    )
    assert (
        compiled.contract.profile.input.attack_action_digest
        == ATTACK_ACTION_DIGEST
    )
    assert (
        compiled.contract.profile.input.benign_action_digest
        == BENIGN_ACTION_DIGEST
    )
    assert ATTACK_ACTION_DIGEST != BENIGN_ACTION_DIGEST
    assert _compiled().spec_digest == compiled.spec_digest

    obligations = {item.id: item for item in compiled.contract.obligations}
    active_rule = obligations["active-rule-detects-suspicious-replay"]
    benign = obligations["tested-benign-action-unalerted"]
    fallback_binding = obligations["current-fallback-alert-binding"]
    assert active_rule.selector == CellSelector(
        input=ATTACK,
        target=TARGET_EFFECTIVE,
    )
    assert (
        active_rule.predicate.metric_id
        == "named-exact-correlation-alert-proven"
    )
    assert benign.selector == CellSelector(input=BENIGN)
    assert (
        benign.predicate.metric_id
        == "tested-benign-action-unalerted"
    )
    assert (
        fallback_binding.predicate.metric_id
        == "fallback-alert-binding-valid"
    )
    coverage = {
        item.obligation_id: item.trial_keys for item in compiled.obligation_coverage
    }
    assert len(coverage[active_rule.id]) == 8
    assert len(coverage[benign.id]) == 16


def test_action_descriptors_fix_distinct_source_sequences() -> None:
    suspicious = action_descriptor(ATTACK)
    benign = action_descriptor(BENIGN)

    assert suspicious["source_id"] == SOURCE_ID
    assert benign["source_id"] == SOURCE_ID
    assert [item["sequence"] for item in suspicious["source_event_plan"]] == [
        7_301,
        7_302,
        7_303,
    ]
    assert [item["sequence"] for item in benign["source_event_plan"]] == [
        8_301,
        8_302,
        8_303,
    ]
    with pytest.raises(ValueError, match="unsupported"):
        action_descriptor(StringValue(value="invented-action"))


def test_all_sixteen_cells_execute_with_closed_observation_windows() -> None:
    runtime = FinancialDetectionRuntime()
    results = []
    for suspicious, exact_active, fallback_forward, reload in itertools.product(
        (False, True),
        repeat=4,
    ):
        result = runtime.execute(
            _selector(
                suspicious=suspicious,
                exact_rule_active=exact_active,
                fallback_forward=fallback_forward,
                collector_reload=reload,
            ),
            trace_id=(
                f"cell-{int(suspicious)}-{int(exact_active)}-"
                f"{int(fallback_forward)}-{int(reload)}"
            ),
        )
        results.append(result)

    assert len(results) == 16
    assert all(result.source_trace_action_bound for result in results)
    assert all(result.source_sequence_coverage_complete for result in results)
    assert all(result.source_healthy for result in results)
    assert all(result.collector_healthy for result in results)
    assert all(result.collector_completed for result in results)
    assert all(result.observation_window_closed for result in results)
    assert all(result.simulated_clock_bound for result in results)
    assert all(
        [event.sequence for event in result.events] == [1, 2, 3, 4]
        for result in results
    )


def test_all_sixteen_cells_match_the_predeclared_detection_semantics() -> None:
    runtime = FinancialDetectionRuntime()
    for suspicious, exact_active, fallback_forward, reload in itertools.product(
        (False, True),
        repeat=4,
    ):
        result = runtime.execute(
            _selector(
                suspicious=suspicious,
                exact_rule_active=exact_active,
                fallback_forward=fallback_forward,
                collector_reload=reload,
            ),
            trace_id=(
                f"semantic-cell-{int(suspicious)}-{int(exact_active)}-"
                f"{int(fallback_forward)}-{int(reload)}"
            ),
        )
        expected_named = suspicious and exact_active
        expected_fallback = suspicious and fallback_forward
        expected_alert_kinds = (
            ((AlertKind.NAMED_EXACT,) if expected_named else ())
            + ((AlertKind.BROAD_FALLBACK,) if expected_fallback else ())
        )

        assert result.action_digest == (
            ATTACK_ACTION_DIGEST if suspicious else BENIGN_ACTION_DIGEST
        )
        assert tuple(alert.alert_kind for alert in result.alerts) == (
            expected_alert_kinds
        )
        assert result.named_exact_correlation_alert_proven is expected_named
        assert result.fallback_telemetry_forwarded is fallback_forward
        assert result.fallback_alert_binding_valid is expected_fallback
        assert result.any_alert_within_slo is bool(expected_alert_kinds)
        assert result.tested_benign_action_unalerted is (not suspicious)
        assert result.reload_attestation.reload_performed is reload
        assert result.alert_query.observed_alert_ids == tuple(
            alert.alert_id for alert in result.alerts
        )
        assert result.observation_window_closed
        assert conclude_named_alert_absence(result) == (
            NamedAlertAbsence.PRESENT
            if expected_named
            else NamedAlertAbsence.CONCLUDED
        )

        if not suspicious:
            continue
        assessment = assess_detection_case(result)
        expected_classification = (
            DetectionResidualClassification.NAMED_DETECTION_EFFECTIVE
            if exact_active
            else (
                DetectionResidualClassification.MASKED_NAMED_DETECTION_FAILURE
                if fallback_forward
                else DetectionResidualClassification.EXPOSED_DETECTION_GAP
            )
        )
        assert assessment.residual_classification == expected_classification


@pytest.mark.parametrize("fallback_forward", (False, True))
@pytest.mark.parametrize("collector_reload", (False, True))
def test_named_rule_effect_is_independent_of_the_fallback_path(
    fallback_forward: bool,
    collector_reload: bool,
) -> None:
    runtime = FinancialDetectionRuntime()
    inactive = runtime.execute(
        _selector(
            suspicious=True,
            exact_rule_active=False,
            fallback_forward=fallback_forward,
            collector_reload=collector_reload,
        ),
        trace_id=f"inactive-{int(fallback_forward)}-{int(collector_reload)}",
    )
    active = runtime.execute(
        _selector(
            suspicious=True,
            exact_rule_active=True,
            fallback_forward=fallback_forward,
            collector_reload=collector_reload,
        ),
        trace_id=f"active-{int(fallback_forward)}-{int(collector_reload)}",
    )

    assert not inactive.named_exact_correlation_alert_proven
    assert not inactive.named_rule_active
    assert (
        conclude_named_alert_absence(inactive)
        == NamedAlertAbsence.CONCLUDED
    )
    assert active.named_exact_correlation_alert_proven
    assert active.named_rule_active
    assert conclude_named_alert_absence(active) == NamedAlertAbsence.PRESENT
    assert [alert.rule_id for alert in active.alerts].count(NAMED_RULE_ID) == 1


@pytest.mark.parametrize("exact_active", (False, True))
@pytest.mark.parametrize("collector_reload", (False, True))
def test_fallback_path_effect_is_independent_of_the_named_rule(
    exact_active: bool,
    collector_reload: bool,
) -> None:
    runtime = FinancialDetectionRuntime()
    dropped = runtime.execute(
        _selector(
            suspicious=True,
            exact_rule_active=exact_active,
            fallback_forward=False,
            collector_reload=collector_reload,
        ),
        trace_id=f"drop-{int(exact_active)}-{int(collector_reload)}",
    )
    forwarded = runtime.execute(
        _selector(
            suspicious=True,
            exact_rule_active=exact_active,
            fallback_forward=True,
            collector_reload=collector_reload,
        ),
        trace_id=f"forward-{int(exact_active)}-{int(collector_reload)}",
    )

    assert not dropped.fallback_telemetry_forwarded
    assert not any(
        alert.rule_id == FALLBACK_RULE_ID for alert in dropped.alerts
    )
    assert forwarded.fallback_telemetry_forwarded
    assert forwarded.forwarded_event_ids == tuple(
        event.event_id for event in forwarded.source_events
    )
    assert forwarded.fallback_alert_binding_valid
    assert [alert.rule_id for alert in forwarded.alerts].count(
        FALLBACK_RULE_ID
    ) == 1


@pytest.mark.parametrize(
    ("exact_active", "fallback_forward", "collector_reload"),
    tuple(itertools.product((False, True), repeat=3)),
)
def test_tested_benign_action_is_unalerted_in_all_eight_cells(
    exact_active: bool,
    fallback_forward: bool,
    collector_reload: bool,
) -> None:
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=False,
            exact_rule_active=exact_active,
            fallback_forward=fallback_forward,
            collector_reload=collector_reload,
        ),
        trace_id=(
            f"benign-{int(exact_active)}-"
            f"{int(fallback_forward)}-{int(collector_reload)}"
        ),
    )

    assert result.action_digest == BENIGN_ACTION_DIGEST
    assert result.tested_benign_action_unalerted
    assert not result.alerts
    assert not result.any_alert_within_slo
    assert result.first_alert_offset_from_window_open_ms is None
    assert result.first_alert_causal_latency_ms is None
    assert conclude_named_alert_absence(result) == NamedAlertAbsence.CONCLUDED
    assert result.fallback_telemetry_forwarded is fallback_forward


@pytest.mark.parametrize(
    ("suspicious", "exact_active", "fallback_forward"),
    tuple(itertools.product((False, True), repeat=3)),
)
def test_collector_reload_is_a_behavior_free_sham(
    suspicious: bool,
    exact_active: bool,
    fallback_forward: bool,
) -> None:
    runtime = FinancialDetectionRuntime()
    selector = {
        "suspicious": suspicious,
        "exact_rule_active": exact_active,
        "fallback_forward": fallback_forward,
    }
    steady = runtime.execute(
        _selector(**selector),
        trace_id="same-trace",
    )
    reloaded = runtime.execute(
        _selector(**selector, collector_reload=True),
        trace_id="same-trace",
    )

    assert (
        steady.action_digest,
        steady.source_trace_action_bound,
        steady.source_sequence_coverage_complete,
        steady.named_exact_correlation_alert_proven,
        steady.fallback_telemetry_forwarded,
        steady.fallback_alert_binding_valid,
        steady.any_alert_within_slo,
        steady.first_alert_offset_from_window_open_ms,
        steady.first_alert_causal_latency_ms,
        steady.tested_benign_action_unalerted,
        steady.forwarded_event_ids,
        steady.forwarded_events,
        steady.source_events,
        steady.alerts,
    ) == (
        reloaded.action_digest,
        reloaded.source_trace_action_bound,
        reloaded.source_sequence_coverage_complete,
        reloaded.named_exact_correlation_alert_proven,
        reloaded.fallback_telemetry_forwarded,
        reloaded.fallback_alert_binding_valid,
        reloaded.any_alert_within_slo,
        reloaded.first_alert_offset_from_window_open_ms,
        reloaded.first_alert_causal_latency_ms,
        reloaded.tested_benign_action_unalerted,
        reloaded.forwarded_event_ids,
        reloaded.forwarded_events,
        reloaded.source_events,
        reloaded.alerts,
    )
    assert not steady.reload_attestation.reload_performed
    assert (
        steady.reload_attestation.pre_instance_id
        == steady.reload_attestation.post_instance_id
    )
    assert reloaded.reload_attestation.reload_performed
    assert (
        reloaded.reload_attestation.pre_instance_id
        != reloaded.reload_attestation.post_instance_id
    )
    assert (
        reloaded.reload_attestation.pre_config_digest
        == reloaded.reload_attestation.post_config_digest
    )
    assert (
        steady.reload_attestation.attestation_digest
        != reloaded.reload_attestation.attestation_digest
    )


def test_current_cell_is_the_masked_named_detection_counterexample() -> None:
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=True,
            exact_rule_active=False,
            fallback_forward=True,
        ),
        trace_id="current-masked-detection",
    )
    assessment = assess_detection_case(result)

    assert not result.named_exact_correlation_alert_proven
    assert not result.named_rule_active
    assert result.fallback_telemetry_forwarded
    assert result.fallback_alert_binding_valid
    assert result.any_alert_within_slo
    assert result.first_alert_offset_from_window_open_ms == 1_200
    assert result.first_alert_causal_latency_ms == 900
    assert [alert.rule_id for alert in result.alerts] == [FALLBACK_RULE_ID]
    assert result.alerts[0].alert_kind == AlertKind.BROAD_FALLBACK
    assert assessment.baseline.name == "alert-existence-only"
    assert assessment.baseline.verdict == BaselineVerdict.PASS
    assert assessment.target_state == DetectionClaimState.REFUTED
    assert assessment.named_alert_absence == NamedAlertAbsence.CONCLUDED
    assert assessment.fallback_telemetry_supported
    assert assessment.fallback_alert_supported
    assert assessment.alert_path_supported
    assert (
        assessment.residual_classification
        == DetectionResidualClassification.MASKED_NAMED_DETECTION_FAILURE
    )


def test_fallback_alert_is_bound_to_the_forwarded_readback_route() -> None:
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=True,
            exact_rule_active=False,
            fallback_forward=True,
        ),
        trace_id="forwarded-route-binding",
    )

    assert len(result.forwarded_events) == len(result.source_events) == 3
    assert result.forwarded_event_ids == tuple(
        event.event_id for event in result.forwarded_events
    )
    assert all(
        forwarded.source_event_digest == source.event_digest
        and forwarded.trace_id == source.trace_id == result.trace_id
        and forwarded.action_digest == source.action_digest == result.action_digest
        and forwarded.collector_run_id == result.window_closure.collector_run_id
        for forwarded, source in zip(
            result.forwarded_events,
            result.source_events,
            strict=True,
        )
    )
    fallback = result.alerts[0]
    assert fallback.forwarded_event_digests == (
        result.forwarded_events[-1].forwarding_digest,
    )
    assert fallback.evidence_route_id == result.forwarded_events[-1].route_id

    damaged_forwarded = (
        *result.forwarded_events[:-1],
        replace(result.forwarded_events[-1], route_id="SYNTH-ROUTE-WRONG"),
    )
    damaged = replace(result, forwarded_events=damaged_forwarded)
    assessment = assess_detection_case(damaged)
    assert not assessment.fallback_telemetry_supported
    assert not assessment.fallback_alert_supported
    assert (
        assessment.residual_classification
        == DetectionResidualClassification.INDETERMINATE
    )


def test_invalid_forwarding_receipt_cannot_emit_a_true_metric(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = detection_runtime._write_forwarded_events

    def write_then_rebind(
        connection: sqlite3.Connection,
        *,
        source_events: tuple[SourceEventRecord, ...],
        route_id: str,
        collector_run_id: str,
    ) -> None:
        original(
            connection,
            source_events=source_events,
            route_id=route_id,
            collector_run_id=collector_run_id,
        )
        connection.execute(
            "UPDATE forwarded_events SET collector_run_id = ?",
            ("FORGED-COLLECTOR-RUN",),
        )
        connection.commit()

    monkeypatch.setattr(
        detection_runtime,
        "_write_forwarded_events",
        write_then_rebind,
    )
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=True,
            exact_rule_active=False,
            fallback_forward=True,
        ),
        trace_id="invalid-forwarding-metric",
    )

    assert not result.fallback_telemetry_forwarded
    assert result.events[2].value("fallback_telemetry_forwarded") is False
    assert not result.observation_window_closed
    assert (
        conclude_named_alert_absence(result)
        == NamedAlertAbsence.INDETERMINATE
    )


def test_absence_requires_clock_detector_query_and_reload_readbacks() -> None:
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=True,
            exact_rule_active=False,
            fallback_forward=True,
            collector_reload=True,
        ),
        trace_id="absence-raw-readbacks",
    )

    assert result.clock_readback.current_time_ms == ALERT_SLO_MS
    assert result.clock_readback.transitions[0] == (0, 100)
    assert result.clock_readback.transitions[-1][1] == ALERT_SLO_MS
    assert result.detector_run.status == "complete"
    assert result.detector_run.source_high_watermark == 7_303
    assert result.detector_run.pending_event_count == 0
    assert result.alert_query.completed
    assert result.alert_query.as_of_ms == ALERT_SLO_MS
    assert result.alert_query.observed_alert_ids == tuple(
        alert.alert_id for alert in result.alerts
    )
    assert result.reload_attestation.reload_performed
    assert conclude_named_alert_absence(result) == NamedAlertAbsence.CONCLUDED

    damaged_results = (
        replace(
            result,
            clock_readback=replace(
                result.clock_readback,
                current_time_ms=ALERT_SLO_MS - 1,
            ),
        ),
        replace(
            result,
            detector_run=replace(
                result.detector_run,
                pending_event_count=1,
            ),
        ),
        replace(
            result,
            alert_query=replace(
                result.alert_query,
                completed=False,
            ),
        ),
        replace(
            result,
            reload_attestation=replace(
                result.reload_attestation,
                post_config_digest="sha256:" + ("d" * 64),
            ),
        ),
    )
    assert all(
        conclude_named_alert_absence(damaged)
        == NamedAlertAbsence.INDETERMINATE
        for damaged in damaged_results
    )


def test_absence_rejects_target_or_sham_relabelling() -> None:
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=True,
            exact_rule_active=False,
            fallback_forward=True,
        ),
        trace_id="selector-readback-binding",
    )

    assert conclude_named_alert_absence(result) == NamedAlertAbsence.CONCLUDED
    assert (
        conclude_named_alert_absence(
            replace(result, target_level=TARGET_EFFECTIVE.value)
        )
        == NamedAlertAbsence.INDETERMINATE
    )
    assert (
        conclude_named_alert_absence(
            replace(result, sham_level=SHAM_RELOAD.value)
        )
        == NamedAlertAbsence.INDETERMINATE
    )


def test_inactive_named_rule_without_fallback_exposes_the_gap() -> None:
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=True,
            exact_rule_active=False,
            fallback_forward=False,
        ),
        trace_id="exposed-detection-gap",
    )
    assessment = assess_detection_case(result)

    assert not result.alerts
    assert assessment.baseline.verdict == BaselineVerdict.FAIL
    assert assessment.target_state == DetectionClaimState.REFUTED
    assert (
        assessment.residual_classification
        == DetectionResidualClassification.EXPOSED_DETECTION_GAP
    )


def test_active_named_rule_produces_exact_bound_correlation_evidence() -> None:
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=True,
            exact_rule_active=True,
            fallback_forward=False,
        ),
        trace_id="exact-alert-proof",
    )
    assessment = assess_detection_case(result)

    assert len(result.alerts) == 1
    alert = result.alerts[0]
    assert alert.alert_kind == AlertKind.NAMED_EXACT
    assert alert.rule_id == NAMED_RULE_ID
    assert alert.trace_id == result.trace_id
    assert alert.action_digest == ATTACK_ACTION_DIGEST
    assert alert.source_id == SOURCE_ID
    assert alert.source_event_ids == tuple(
        event.event_id for event in result.source_events
    )
    assert alert.source_sequences == (7_301, 7_302, 7_303)
    assert alert.triggered_at_ms == 800
    assert alert.triggered_at_ms <= ALERT_SLO_MS
    assert result.first_alert_offset_from_window_open_ms == 800
    assert result.first_alert_causal_latency_ms == 500
    assert alert.correlation_evidence_digest.startswith("sha256:")
    assert result.named_alert_identity_unique
    assert result.named_alert_rule_identity_bound
    assert result.named_alert_trace_source_action_bound
    assert result.named_correlation_evidence_valid
    assert result.named_exact_correlation_alert_proven
    target_event = result.events[1]
    assert target_event.value("named_rule_id") == NAMED_RULE_ID
    assert target_event.value("named_rule_active") is True
    assert target_event.value("named_alert_ids_canonical") == (
        f'["{alert.alert_id}"]'
    )
    assert (
        target_event.value("named_correlation_artifacts_canonical")
        == f'["{alert.correlation_evidence_digest}"]'
    )
    assert assessment.target_state == DetectionClaimState.SUPPORTED
    assert (
        assessment.residual_classification
        == DetectionResidualClassification.NAMED_DETECTION_EFFECTIVE
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("alert_id", "SYNTH-ALERT-NAMED-WRONG"),
        ("trace_id", "other-trace"),
        ("action_digest", "sha256:" + ("a" * 64)),
        ("source_id", "SYNTH-SOURCE-WRONG"),
        ("correlation_evidence_digest", "sha256:" + ("b" * 64)),
    ),
)
def test_named_claim_is_not_supported_by_a_misbound_alert(
    field: str,
    value: str,
) -> None:
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=True,
            exact_rule_active=True,
            fallback_forward=False,
        ),
        trace_id=f"misbound-named-alert-{field}",
    )
    assert len(result.alerts) == 1
    damaged = replace(
        result,
        alerts=(_misbind_alert(result.alerts[0], field, value),),
    )
    assessment = assess_detection_case(damaged)

    assert assessment.baseline.verdict == BaselineVerdict.PASS
    assert assessment.target_state == DetectionClaimState.INDETERMINATE
    assert (
        assessment.residual_classification
        == DetectionResidualClassification.INDETERMINATE
    )


def _misbind_alert(
    alert: AlertRecord,
    field: str,
    value: str,
) -> AlertRecord:
    if field == "alert_id":
        return replace(alert, alert_id=value)
    if field == "trace_id":
        return replace(alert, trace_id=value)
    if field == "action_digest":
        return replace(alert, action_digest=value)
    if field == "source_id":
        return replace(alert, source_id=value)
    if field == "correlation_evidence_digest":
        return replace(alert, correlation_evidence_digest=value)
    raise AssertionError(f"unsupported alert mutation field: {field}")


def test_each_execution_starts_from_a_fresh_sqlite_store() -> None:
    runtime = FinancialDetectionRuntime()
    first = runtime.execute(
        _selector(
            suspicious=True,
            exact_rule_active=True,
            fallback_forward=True,
        ),
        trace_id="first-has-two-alerts",
    )
    second = runtime.execute(
        _selector(
            suspicious=True,
            exact_rule_active=False,
            fallback_forward=False,
        ),
        trace_id="second-is-empty",
    )

    assert len(first.alerts) == 2
    assert not second.alerts
    assert not second.forwarded_event_ids
    assert first.alert_query.observed_alert_ids != (
        second.alert_query.observed_alert_ids
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("source_healthy", False),
        ("collector_healthy", False),
        ("collector_completed", False),
        ("collected_event_count", 2),
        ("closed_at_ms", ALERT_SLO_MS - 1),
        ("clock_spec_digest", "sha256:" + ("f" * 64)),
        ("artifact_digest", "sha256:" + ("e" * 64)),
    ),
)
def test_absence_becomes_indeterminate_if_window_proof_is_damaged(
    field: str,
    value: bool | int | str,
) -> None:
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=True,
            exact_rule_active=False,
            fallback_forward=True,
        ),
        trace_id=f"damaged-closure-{field}",
    )
    damaged = replace(
        result,
        window_closure=_damage_closure(
            result.window_closure,
            field,
            value,
        ),
    )

    assert (
        conclude_named_alert_absence(damaged)
        == NamedAlertAbsence.INDETERMINATE
    )
    assessment = assess_detection_case(damaged)
    assert assessment.baseline.verdict == BaselineVerdict.PASS
    assert assessment.target_state == DetectionClaimState.INDETERMINATE
    assert (
        assessment.residual_classification
        == DetectionResidualClassification.INDETERMINATE
    )


def _damage_closure(
    closure: ObservationWindowClosure,
    field: str,
    value: bool | int | str,
) -> ObservationWindowClosure:
    if field == "source_healthy":
        assert isinstance(value, bool)
        return replace(closure, source_healthy=value)
    if field == "collector_healthy":
        assert isinstance(value, bool)
        return replace(closure, collector_healthy=value)
    if field == "collector_completed":
        assert isinstance(value, bool)
        return replace(closure, collector_completed=value)
    if field == "collected_event_count":
        assert isinstance(value, int) and not isinstance(value, bool)
        return replace(closure, collected_event_count=value)
    if field == "closed_at_ms":
        assert isinstance(value, int) and not isinstance(value, bool)
        return replace(closure, closed_at_ms=value)
    if field == "clock_spec_digest":
        assert isinstance(value, str)
        return replace(closure, clock_spec_digest=value)
    if field == "artifact_digest":
        assert isinstance(value, str)
        return replace(closure, artifact_digest=value)
    raise AssertionError(f"unsupported closure mutation field: {field}")


def test_absence_becomes_indeterminate_if_raw_sequence_loses_coverage() -> None:
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=True,
            exact_rule_active=False,
            fallback_forward=True,
        ),
        trace_id="damaged-source-sequence",
    )
    damaged = replace(
        result,
        source_events=result.source_events[:-1],
    )

    assert (
        conclude_named_alert_absence(damaged)
        == NamedAlertAbsence.INDETERMINATE
    )


def test_window_artifact_binds_alert_readback_and_simulated_clock() -> None:
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=True,
            exact_rule_active=False,
            fallback_forward=True,
            collector_reload=True,
        ),
        trace_id="window-bindings",
    )
    closure = result.window_closure
    outcome = result.events[3]

    assert closure.observed_event_ids == tuple(
        event.event_id for event in result.source_events
    )
    assert closure.observed_source_sequences == (7_301, 7_302, 7_303)
    assert result.alert_query.observed_alert_ids == tuple(
        alert.alert_id for alert in result.alerts
    )
    assert closure.clock_spec_digest == CLOCK_SPEC_DIGEST
    assert closure.closed_at_ms == ALERT_SLO_MS
    assert closure.clock_readback_digest == result.clock_readback.readback_digest
    assert closure.detector_run_digest == result.detector_run.readback_digest
    assert result.detector_run.source_high_watermark == 7_303
    assert result.detector_run.pending_event_count == 0
    assert closure.alert_query_digest == result.alert_query.readback_digest
    assert result.alert_query.as_of_ms == ALERT_SLO_MS
    assert (
        closure.reload_attestation_digest
        == result.reload_attestation.attestation_digest
    )
    assert outcome.value("window_closure_artifact") == closure.artifact_digest
    assert outcome.value("source_trace_action_binding_proven") is True
    assert outcome.value("source_sequence_coverage_complete") is True
    assert outcome.value("observation_window_closed") is True
    assert outcome.value("simulated_clock_bound") is True
    assert outcome.value("named_alert_absence") == NamedAlertAbsence.CONCLUDED.value


def test_detector_noop_leaves_real_pending_work_and_claim_indeterminate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        detection_runtime,
        "_process_named_detector_queue",
        lambda connection, *, detector_run_id: None,
    )

    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=True,
            exact_rule_active=True,
            fallback_forward=False,
        ),
        trace_id="detector-noop",
    )

    assert result.detector_run.status == "running"
    assert result.detector_run.evaluated_event_count == 0
    assert result.detector_run.pending_event_count == 3
    assert result.detector_run.completed_at_ms is None
    assert not result.detector_run_completed
    assert not result.observation_window_closed
    assert not result.named_exact_correlation_alert_proven
    assert conclude_named_alert_absence(result) == NamedAlertAbsence.INDETERMINATE


def test_detector_lag_cannot_be_hidden_by_marking_the_run_complete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def lagging_processor(
        connection: sqlite3.Connection,
        *,
        detector_run_id: str,
    ) -> None:
        first = connection.execute(
            """
            SELECT event_id
            FROM detector_queue
            WHERE detector_run_id = ? AND state = 'pending'
            ORDER BY source_sequence
            LIMIT 1
            """,
            (detector_run_id,),
        ).fetchone()
        assert first is not None
        connection.execute(
            """
            UPDATE detector_queue
            SET state = 'processed', processed_at_ms = 800
            WHERE detector_run_id = ? AND event_id = ?
            """,
            (detector_run_id, str(first[0])),
        )
        connection.execute(
            """
            UPDATE detector_runs
            SET status = 'complete', completed_at_ms = 800
            WHERE detector_run_id = ?
            """,
            (detector_run_id,),
        )
        connection.commit()

    monkeypatch.setattr(
        detection_runtime,
        "_process_named_detector_queue",
        lagging_processor,
    )
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=True,
            exact_rule_active=True,
            fallback_forward=False,
        ),
        trace_id="detector-lag",
    )

    assert result.detector_run.status == "complete"
    assert result.detector_run.evaluated_event_count == 1
    assert result.detector_run.pending_event_count == 2
    assert not result.detector_run_completed
    assert not result.observation_window_closed
    assert (
        assess_detection_case(result).target_state
        == DetectionClaimState.INDETERMINATE
    )


def test_alert_query_noop_is_visible_in_operation_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        detection_runtime,
        "_complete_alert_query",
        lambda connection, *, query_id, as_of_ms: None,
    )
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=True,
            exact_rule_active=False,
            fallback_forward=False,
        ),
        trace_id="alert-query-noop",
    )

    assert not result.alert_query.completed
    assert result.alert_query.completed_at_ms is None
    assert result.alert_query.as_of_ms == -1
    assert not result.alert_query_completed
    assert not result.observation_window_closed
    assert conclude_named_alert_absence(result) == NamedAlertAbsence.INDETERMINATE


def test_alert_query_result_omission_refutes_a_positive_named_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        detection_runtime,
        "_record_alert_query_results",
        lambda connection, *, query_id, trace_id, as_of_ms: None,
    )
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=True,
            exact_rule_active=True,
            fallback_forward=False,
        ),
        trace_id="alert-query-result-omission",
    )

    assert len(result.alerts) == 1
    assert result.alert_query.completed
    assert result.alert_query.observed_alert_ids == ()
    assert not result.alert_query_completed
    assert not result.named_exact_correlation_alert_proven
    assert (
        assess_detection_case(result).target_state
        == DetectionClaimState.INDETERMINATE
    )


def test_coherent_source_alert_and_receipt_rewrite_cannot_change_fixed_action() -> None:
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=True,
            exact_rule_active=True,
            fallback_forward=False,
        ),
        trace_id="coherent-source-rewrite",
    )
    rewritten_sources = []
    for source in result.source_events:
        event_id = f"{source.event_id}-REBOUND"
        payload = detection_runtime._source_event_payload(
            event_id=event_id,
            trace_id=source.trace_id,
            action_digest=source.action_digest,
            source_sequence=source.source_sequence,
            event_type=source.event_type,
            observed_at_ms=source.observed_at_ms,
        )
        rewritten_sources.append(
            replace(
                source,
                event_id=event_id,
                event_digest=detection_runtime._sha256(
                    rfc8785.dumps(payload)
                ),
            )
        )
    source_events = tuple(rewritten_sources)

    old_alert = result.alerts[0]
    correlation_payload = detection_runtime._correlation_payload(
        alert_id=old_alert.alert_id,
        alert_kind=old_alert.alert_kind,
        rule_id=old_alert.rule_id,
        trace_id=old_alert.trace_id,
        action_digest=old_alert.action_digest,
        source_events=source_events,
        evidence_route_id=old_alert.evidence_route_id,
        forwarded_event_digests=old_alert.forwarded_event_digests,
        detector_run_id=old_alert.detector_run_id,
    )
    alert_canonical = rfc8785.dumps(correlation_payload).decode("utf-8")
    alerts = (
        replace(
            old_alert,
            source_event_ids=tuple(item.event_id for item in source_events),
            correlation_evidence_canonical=alert_canonical,
            correlation_evidence_digest=detection_runtime._sha256(
                alert_canonical.encode("utf-8")
            ),
        ),
    )

    detector_run = replace(
        result.detector_run,
        processed_event_ids=tuple(item.event_id for item in source_events),
        processed_source_event_digests=tuple(
            item.event_digest for item in source_events
        ),
        readback_canonical="pending",
        readback_digest="pending",
    )
    detector_canonical = rfc8785.dumps(
        detection_runtime._detector_run_payload(detector_run)
    ).decode("utf-8")
    detector_run = replace(
        detector_run,
        readback_canonical=detector_canonical,
        readback_digest=detection_runtime._sha256(
            detector_canonical.encode("utf-8")
        ),
    )
    collector_run = replace(
        result.collector_run_readback,
        collected_event_ids=tuple(item.event_id for item in source_events),
        readback_canonical="pending",
        readback_digest="pending",
    )
    collector_canonical = rfc8785.dumps(
        detection_runtime._collector_run_payload(collector_run)
    ).decode("utf-8")
    collector_run = replace(
        collector_run,
        readback_canonical=collector_canonical,
        readback_digest=detection_runtime._sha256(
            collector_canonical.encode("utf-8")
        ),
    )
    closure = replace(
        result.window_closure,
        expected_event_ids=tuple(item.event_id for item in source_events),
        observed_event_ids=tuple(item.event_id for item in source_events),
        detector_run_digest=detector_run.readback_digest,
        collector_run_readback_digest=collector_run.readback_digest,
        artifact_canonical="pending",
        artifact_digest="pending",
    )
    closure_canonical = rfc8785.dumps(
        detection_runtime._closure_payload(closure)
    ).decode("utf-8")
    closure = replace(
        closure,
        artifact_canonical=closure_canonical,
        artifact_digest=detection_runtime._sha256(
            closure_canonical.encode("utf-8")
        ),
    )
    damaged = replace(
        result,
        source_events=source_events,
        alerts=alerts,
        detector_run=detector_run,
        collector_run_readback=collector_run,
        window_closure=closure,
    )

    assert (
        assess_detection_case(damaged).target_state
        == DetectionClaimState.INDETERMINATE
    )


def _rehash_detector_run(run: DetectorRunReadback) -> DetectorRunReadback:
    provisional = replace(
        run,
        readback_canonical="pending",
        readback_digest="pending",
    )
    canonical = rfc8785.dumps(
        detection_runtime._detector_run_payload(provisional)
    ).decode("utf-8")
    return replace(
        provisional,
        readback_canonical=canonical,
        readback_digest=detection_runtime._sha256(canonical.encode("utf-8")),
    )


def _rehash_collector_run(
    run: CollectorRunReadback,
) -> CollectorRunReadback:
    provisional = replace(
        run,
        readback_canonical="pending",
        readback_digest="pending",
    )
    canonical = rfc8785.dumps(
        detection_runtime._collector_run_payload(provisional)
    ).decode("utf-8")
    return replace(
        provisional,
        readback_canonical=canonical,
        readback_digest=detection_runtime._sha256(canonical.encode("utf-8")),
    )


def _rehash_closure(
    closure: ObservationWindowClosure,
) -> ObservationWindowClosure:
    provisional = replace(
        closure,
        artifact_canonical="pending",
        artifact_digest="pending",
    )
    canonical = rfc8785.dumps(
        detection_runtime._closure_payload(provisional)
    ).decode("utf-8")
    return replace(
        provisional,
        artifact_canonical=canonical,
        artifact_digest=detection_runtime._sha256(canonical.encode("utf-8")),
    )


@pytest.mark.parametrize("suspicious", (False, True))
def test_fully_rehashed_alternate_action_digest_is_indeterminate(
    suspicious: bool,
) -> None:
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=suspicious,
            exact_rule_active=False,
            fallback_forward=False,
        ),
        trace_id=f"coherent-action-digest-rebind-{int(suspicious)}",
    )
    alternate_digest = "sha256:" + ("a" * 64)
    rewritten_sources = tuple(
        replace(
            source,
            action_digest=alternate_digest,
            event_digest=detection_runtime._sha256(
                rfc8785.dumps(
                    detection_runtime._source_event_payload(
                        event_id=source.event_id,
                        trace_id=source.trace_id,
                        action_digest=alternate_digest,
                        source_sequence=source.source_sequence,
                        event_type=source.event_type,
                        observed_at_ms=source.observed_at_ms,
                    )
                )
            ),
        )
        for source in result.source_events
    )
    detector_run = _rehash_detector_run(
        replace(
            result.detector_run,
            processed_source_event_digests=tuple(
                source.event_digest for source in rewritten_sources
            ),
        )
    )
    closure = _rehash_closure(
        replace(
            result.window_closure,
            action_digest=alternate_digest,
            detector_run_digest=detector_run.readback_digest,
        )
    )
    forged = replace(
        result,
        action_digest=alternate_digest,
        source_events=rewritten_sources,
        detector_run=detector_run,
        window_closure=closure,
    )

    assert (
        conclude_named_alert_absence(forged)
        == NamedAlertAbsence.INDETERMINATE
    )
    if suspicious:
        assessment = assess_detection_case(forged)
        assert assessment.target_state == DetectionClaimState.INDETERMINATE
        assert (
            assessment.residual_classification
            == DetectionResidualClassification.INDETERMINATE
        )


def test_fully_rebound_collector_identity_invalidates_fallback_claims() -> None:
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=True,
            exact_rule_active=False,
            fallback_forward=True,
        ),
        trace_id="coherent-collector-identity-rebind",
    )
    forged_run_id = "FORGED-COLLECTOR-RUN"
    forwarded_events = tuple(
        replace(
            forwarded,
            collector_run_id=forged_run_id,
            forwarding_digest=detection_runtime._sha256(
                rfc8785.dumps(
                    detection_runtime._forwarding_payload(
                        source=source,
                        route_id=forwarded.route_id,
                        collector_run_id=forged_run_id,
                    )
                )
            ),
        )
        for forwarded, source in zip(
            result.forwarded_events,
            result.source_events,
            strict=True,
        )
    )
    original_alert = result.alerts[0]
    broad_source = (result.source_events[-1],)
    correlation = detection_runtime._correlation_payload(
        alert_id=original_alert.alert_id,
        alert_kind=original_alert.alert_kind,
        rule_id=original_alert.rule_id,
        trace_id=original_alert.trace_id,
        action_digest=original_alert.action_digest,
        source_events=broad_source,
        evidence_route_id=original_alert.evidence_route_id,
        forwarded_event_digests=(forwarded_events[-1].forwarding_digest,),
        detector_run_id=original_alert.detector_run_id,
    )
    alert_canonical = rfc8785.dumps(correlation).decode("utf-8")
    alert = replace(
        original_alert,
        forwarded_event_digests=(forwarded_events[-1].forwarding_digest,),
        correlation_evidence_canonical=alert_canonical,
        correlation_evidence_digest=detection_runtime._sha256(
            alert_canonical.encode("utf-8")
        ),
    )
    collector_run = _rehash_collector_run(
        replace(
            result.collector_run_readback,
            collector_run_id=forged_run_id,
        )
    )
    closure = _rehash_closure(
        replace(
            result.window_closure,
            collector_run_id=forged_run_id,
            collector_run_readback_digest=collector_run.readback_digest,
        )
    )
    forged = replace(
        result,
        forwarded_events=forwarded_events,
        alerts=(alert,),
        collector_run_readback=collector_run,
        window_closure=closure,
    )

    assessment = assess_detection_case(forged)
    assert not assessment.fallback_telemetry_supported
    assert not assessment.fallback_alert_supported
    assert assessment.target_state == DetectionClaimState.INDETERMINATE
    assert (
        assessment.residual_classification
        == DetectionResidualClassification.INDETERMINATE
    )


def test_orphan_alert_source_makes_the_whole_assessment_indeterminate() -> None:
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=True,
            exact_rule_active=False,
            fallback_forward=True,
        ),
        trace_id="orphan-alert-source",
    )
    orphan = replace(
        result,
        alerts=(
            replace(
                result.alerts[0],
                source_event_ids=("SYNTH-SOURCE-ORPHAN",),
            ),
        ),
    )

    assessment = assess_detection_case(orphan)
    assert (
        conclude_named_alert_absence(orphan)
        == NamedAlertAbsence.INDETERMINATE
    )
    assert assessment.target_state == DetectionClaimState.INDETERMINATE
    assert not assessment.fallback_alert_supported
    assert (
        assessment.residual_classification
        == DetectionResidualClassification.INDETERMINATE
    )


def test_orphan_forwarded_event_makes_the_whole_assessment_indeterminate() -> None:
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=True,
            exact_rule_active=False,
            fallback_forward=True,
        ),
        trace_id="orphan-forwarded-event",
    )
    orphan = replace(
        result,
        forwarded_events=(
            *result.forwarded_events[:-1],
            replace(
                result.forwarded_events[-1],
                event_id="SYNTH-SOURCE-ORPHAN",
            ),
        ),
    )

    assessment = assess_detection_case(orphan)
    assert (
        conclude_named_alert_absence(orphan)
        == NamedAlertAbsence.INDETERMINATE
    )
    assert assessment.target_state == DetectionClaimState.INDETERMINATE
    assert not assessment.fallback_telemetry_supported
    assert not assessment.fallback_alert_supported
    assert (
        assessment.residual_classification
        == DetectionResidualClassification.INDETERMINATE
    )


def test_incomplete_alert_set_makes_the_whole_assessment_indeterminate() -> None:
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=True,
            exact_rule_active=False,
            fallback_forward=True,
        ),
        trace_id="incomplete-alert-set",
    )
    incomplete = replace(result, alerts=())

    assessment = assess_detection_case(incomplete)
    assert (
        conclude_named_alert_absence(incomplete)
        == NamedAlertAbsence.INDETERMINATE
    )
    assert assessment.target_state == DetectionClaimState.INDETERMINATE
    assert (
        assessment.residual_classification
        == DetectionResidualClassification.INDETERMINATE
    )


def test_old_style_coherent_sham_relabel_lacks_a_reload_operation_receipt() -> None:
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=True,
            exact_rule_active=False,
            fallback_forward=True,
        ),
        trace_id="coherent-sham-relabel",
    )
    forged = replace(
        result.reload_attestation,
        reload_performed=True,
        post_instance_id=detection_runtime._collector_instance_id(
            result.trace_id,
            "post",
        ),
        attestation_canonical="pending",
        attestation_digest="pending",
    )
    payload: dict[str, Any] = {
        "schema": "assurance-lab.collector-reload-attestation/v2",
        "attestation_id": forged.attestation_id,
        "reload_performed": forged.reload_performed,
        "pre_instance_id": forged.pre_instance_id,
        "post_instance_id": forged.post_instance_id,
        "pre_config_digest": forged.pre_config_digest,
        "post_config_digest": forged.post_config_digest,
        "instance_rows_digest": forged.instance_rows_digest,
        "reload_operation_digest": forged.reload_operation_digest,
    }
    attestation_canonical = rfc8785.dumps(payload).decode("utf-8")
    forged = replace(
        forged,
        attestation_canonical=attestation_canonical,
        attestation_digest=detection_runtime._sha256(
            attestation_canonical.encode("utf-8")
        ),
    )
    closure = replace(
        result.window_closure,
        reload_attestation_digest=forged.attestation_digest,
        artifact_canonical="pending",
        artifact_digest="pending",
    )
    closure_canonical = rfc8785.dumps(
        detection_runtime._closure_payload(closure)
    ).decode("utf-8")
    closure = replace(
        closure,
        artifact_canonical=closure_canonical,
        artifact_digest=detection_runtime._sha256(
            closure_canonical.encode("utf-8")
        ),
    )
    damaged = replace(
        result,
        sham_level=SHAM_RELOAD.value,
        reload_attestation=forged,
        window_closure=closure,
    )

    assert conclude_named_alert_absence(damaged) == NamedAlertAbsence.INDETERMINATE


def test_coherent_reload_to_steady_relabel_keeps_disqualifying_raw_rows() -> None:
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=True,
            exact_rule_active=False,
            fallback_forward=True,
            collector_reload=True,
        ),
        trace_id="coherent-reload-to-steady-relabel",
    )
    forged = replace(
        result.reload_attestation,
        reload_performed=False,
        post_instance_id=result.reload_attestation.pre_instance_id,
        post_config_digest=result.reload_attestation.pre_config_digest,
        attestation_canonical="pending",
        attestation_digest="pending",
    )
    payload: dict[str, Any] = {
        "schema": "assurance-lab.collector-reload-attestation/v2",
        "attestation_id": forged.attestation_id,
        "reload_performed": forged.reload_performed,
        "pre_instance_id": forged.pre_instance_id,
        "post_instance_id": forged.post_instance_id,
        "pre_config_digest": forged.pre_config_digest,
        "post_config_digest": forged.post_config_digest,
        "instance_rows_digest": forged.instance_rows_digest,
        "reload_operation_digest": forged.reload_operation_digest,
    }
    attestation_canonical = rfc8785.dumps(payload).decode("utf-8")
    forged = replace(
        forged,
        attestation_canonical=attestation_canonical,
        attestation_digest=detection_runtime._sha256(
            attestation_canonical.encode("utf-8")
        ),
    )
    closure = _rehash_closure(
        replace(
            result.window_closure,
            reload_attestation_digest=forged.attestation_digest,
        )
    )
    damaged = replace(
        result,
        sham_level=SHAM_STEADY.value,
        reload_attestation=forged,
        window_closure=closure,
    )

    assert conclude_named_alert_absence(damaged) == NamedAlertAbsence.INDETERMINATE


def test_forged_collector_run_id_cannot_be_hidden_in_rehashed_closure() -> None:
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=True,
            exact_rule_active=False,
            fallback_forward=True,
        ),
        trace_id="forged-collector-run",
    )
    closure = replace(
        result.window_closure,
        collector_run_id="FORGED-COLLECTOR-RUN",
        artifact_canonical="pending",
        artifact_digest="pending",
    )
    canonical = rfc8785.dumps(
        detection_runtime._closure_payload(closure)
    ).decode("utf-8")
    closure = replace(
        closure,
        artifact_canonical=canonical,
        artifact_digest=detection_runtime._sha256(canonical.encode("utf-8")),
    )

    assert (
        conclude_named_alert_absence(
            replace(result, window_closure=closure)
        )
        == NamedAlertAbsence.INDETERMINATE
    )


def test_missing_source_evidence_returns_indeterminate_instead_of_raising() -> None:
    result = FinancialDetectionRuntime().execute(
        _selector(
            suspicious=True,
            exact_rule_active=False,
            fallback_forward=True,
        ),
        trace_id="missing-source-evidence",
    )

    damaged = replace(result, source_events=())
    assessment = assess_detection_case(damaged)

    assert conclude_named_alert_absence(damaged) == NamedAlertAbsence.INDETERMINATE
    assert assessment.target_state == DetectionClaimState.INDETERMINATE
    assert (
        assessment.residual_classification
        == DetectionResidualClassification.INDETERMINATE
    )


def test_runtime_rejects_partial_wrong_typed_and_unknown_cells() -> None:
    runtime = FinancialDetectionRuntime()
    with pytest.raises(ValueError, match="input selector"):
        runtime.execute(
            CellSelector(
                target=TARGET_INEFFECTIVE,
                compensator=COMPENSATOR_OFF,
                sham=SHAM_STEADY,
            ),
            trace_id="missing-input",
        )
    with pytest.raises(ValueError, match="sham selector"):
        runtime.execute(
            CellSelector(
                input=ATTACK,
                target=TARGET_INEFFECTIVE,
                compensator=COMPENSATOR_OFF,
                sham=None,
            ),
            trace_id="wrong-type",
        )
    with pytest.raises(ValueError, match="unsupported target"):
        runtime.execute(
            CellSelector(
                input=ATTACK,
                target=StringValue(value="match-everything"),
                compensator=COMPENSATOR_OFF,
                sham=SHAM_STEADY,
            ),
            trace_id="unknown-target",
        )
    with pytest.raises(ValueError, match="trace_id"):
        runtime.execute(
            _selector(
                suspicious=True,
                exact_rule_active=False,
                fallback_forward=False,
            ),
            trace_id="../unsafe",
        )
