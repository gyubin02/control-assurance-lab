from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from assurance_lab.controls.alert_window import (
    AlertWindowEvaluation,
    AlertWindowEvaluationError,
    AlertWindowProfile,
    ContainsPredicate,
    Criterion,
    DefenderAlertSource,
    ElasticAlertSource,
    EqualsPredicate,
    MatchingRecordCount,
    TotalRecordCount,
    evaluate_alert_window,
    parse_alert_window_profile,
)
from assurance_lab.evidence.canonical import canonical_json_bytes, canonical_jsonl_bytes

START = datetime(2026, 7, 29, 1, 0, tzinfo=UTC)
END = datetime(2026, 7, 29, 1, 5, tzinfo=UTC)
RULE = "12345678-1234-4234-9234-123456789abc"


def elastic_profile(*criteria: Criterion) -> AlertWindowProfile:
    return AlertWindowProfile(
        profile_id="endpoint-detection-window",
        profile_version="1.0.0",
        title="Endpoint detection window",
        source=ElasticAlertSource(
            fields=(
                "@timestamp",
                "kibana.alert.rule.uuid",
                "kibana.alert.severity",
            ),
            rule_uuids=(RULE,),
        ),
        criteria=criteria
        or (
            Criterion(
                criterion_id="expected-rule-observed",
                description="The exact detection rule produced an alert.",
                metric=MatchingRecordCount(
                    all=(
                        ContainsPredicate(
                            field="kibana.alert.rule.uuid",
                            value=RULE,
                        ),
                    )
                ),
                comparison="ge",
                expected_count=1,
            ),
        ),
    )


def elastic_records(*fields: dict[str, object]) -> bytes:
    return canonical_jsonl_bytes(
        [
            {
                "cursor": [f"2026-07-29T01:00:{index:02d}Z", index],
                "fields": item,
                "id": f"elastic-alert:{index:012d}",
            }
            for index, item in enumerate(fields)
        ]
    )


def defender_profile(*criteria: Criterion) -> AlertWindowProfile:
    return AlertWindowProfile(
        profile_id="defender-severity-window",
        profile_version="1.0.0",
        title="Defender severity window",
        source=DefenderAlertSource(),
        criteria=criteria
        or (
            Criterion(
                criterion_id="high-severity-observed",
                description="At least one high severity alert was observed.",
                metric=MatchingRecordCount(
                    all=(EqualsPredicate(field="Severity", value="High"),)
                ),
                comparison="ge",
                expected_count=1,
            ),
        ),
    )


def defender_records(*fields: dict[str, object]) -> bytes:
    return canonical_jsonl_bytes(
        [
            {
                "fields": item,
                "id": f"defender-xdr-alert:{index:012d}",
            }
            for index, item in enumerate(fields)
        ]
    )


def run(
    profile: AlertWindowProfile,
    records: bytes,
) -> AlertWindowEvaluation:
    return evaluate_alert_window(
        profile=profile,
        expected_profile_digest=profile.digest,
        source_kind=profile.source_kind,
        records_jsonl=records,
        window_start=START,
        window_end=END,
    )


def test_profile_round_trips_only_as_exact_canonical_bytes() -> None:
    profile = elastic_profile()
    parsed = parse_alert_window_profile(
        profile.canonical_bytes(),
        expected_profile_id=profile.profile_id,
        expected_profile_digest=profile.digest,
    )
    assert parsed == profile
    assert parsed.digest == profile.digest


@pytest.mark.parametrize(
    ("value", "profile_id", "digest"),
    [
        (b"", "endpoint-detection-window", f"sha256:{'0' * 64}"),
        (b"{}", "endpoint-detection-window", f"sha256:{'0' * 64}"),
        (
            b'{ "profile_id": "endpoint-detection-window" }',
            "endpoint-detection-window",
            f"sha256:{'0' * 64}",
        ),
    ],
)
def test_profile_parser_rejects_absent_invalid_or_noncanonical_bytes(
    value: bytes,
    profile_id: str,
    digest: str,
) -> None:
    with pytest.raises(AlertWindowEvaluationError):
        parse_alert_window_profile(
            value,
            expected_profile_id=profile_id,
            expected_profile_digest=digest,
        )


def test_profile_parser_rejects_external_id_or_digest_substitution() -> None:
    profile = elastic_profile()
    with pytest.raises(AlertWindowEvaluationError):
        parse_alert_window_profile(
            profile.canonical_bytes(),
            expected_profile_id="another-profile",
            expected_profile_digest=profile.digest,
        )
    with pytest.raises(AlertWindowEvaluationError):
        parse_alert_window_profile(
            profile.canonical_bytes(),
            expected_profile_id=profile.profile_id,
            expected_profile_digest=f"sha256:{'0' * 64}",
        )


def test_known_elastic_match_supports_lower_bound() -> None:
    profile = elastic_profile()
    result = run(
        profile,
        elastic_records(
            {
                "@timestamp": ["2026-07-29T01:00:00Z"],
                "kibana.alert.rule.uuid": [RULE],
                "kibana.alert.severity": ["high"],
            }
        ),
    )
    assert result.decision == "supported"
    assert result.criteria[0].observed_lower_bound == 1
    assert result.criteria[0].observed_upper_bound == 1


def test_known_nonmatch_refutes_lower_bound_without_missing_evidence() -> None:
    profile = elastic_profile()
    result = run(
        profile,
        elastic_records(
            {
                "@timestamp": ["2026-07-29T01:00:00Z"],
                "kibana.alert.rule.uuid": [
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
                ],
            }
        ),
    )
    assert result.decision == "refuted"
    assert result.criteria[0].reason_code == "comparison-refuted"


def test_missing_field_yields_interval_and_unresolved_lower_bound() -> None:
    profile = elastic_profile()
    result = run(
        profile,
        elastic_records({"@timestamp": ["2026-07-29T01:00:00Z"]}),
    )
    criterion = result.criteria[0]
    assert result.decision == "unresolved"
    assert criterion.observed_lower_bound == 0
    assert criterion.observed_upper_bound == 1
    assert criterion.indeterminate_record_count == 1


def test_known_match_is_enough_for_monotone_lower_bound_despite_missing_row() -> None:
    profile = elastic_profile()
    result = run(
        profile,
        elastic_records(
            {
                "@timestamp": ["2026-07-29T01:00:00Z"],
                "kibana.alert.rule.uuid": [RULE],
            },
            {"@timestamp": ["2026-07-29T01:00:01Z"]},
        ),
    )
    assert result.decision == "supported"
    assert result.criteria[0].observed_lower_bound == 1
    assert result.criteria[0].observed_upper_bound == 2


@pytest.mark.parametrize(
    ("comparison", "expected", "lower_fields", "decision"),
    [
        ("le", 0, ({"@timestamp": ["2026-07-29T01:00:00Z"]},), "unresolved"),
        (
            "le",
            0,
            (
                {
                    "@timestamp": ["2026-07-29T01:00:00Z"],
                    "kibana.alert.rule.uuid": [RULE],
                },
            ),
            "refuted",
        ),
        ("eq", 1, ({"@timestamp": ["2026-07-29T01:00:00Z"]},), "unresolved"),
        (
            "eq",
            0,
            (
                {
                    "@timestamp": ["2026-07-29T01:00:00Z"],
                    "kibana.alert.rule.uuid": [RULE],
                },
            ),
            "refuted",
        ),
    ],
)
def test_interval_logic_is_fail_closed_for_upper_and_exact_comparisons(
    comparison: str,
    expected: int,
    lower_fields: tuple[dict[str, object], ...],
    decision: str,
) -> None:
    profile = elastic_profile(
        Criterion(
            criterion_id="bounded-rule-count",
            description="Bound the exact rule alert count.",
            metric=MatchingRecordCount(
                all=(
                    ContainsPredicate(
                        field="kibana.alert.rule.uuid",
                        value=RULE,
                    ),
                )
            ),
            comparison=comparison,  # type: ignore[arg-type]
            expected_count=expected,
        )
    )
    assert run(profile, elastic_records(*lower_fields)).decision == decision


def test_total_record_count_has_no_field_uncertainty() -> None:
    profile = elastic_profile(
        Criterion(
            criterion_id="window-is-empty",
            description="No alert records were present.",
            metric=TotalRecordCount(),
            comparison="eq",
            expected_count=0,
        )
    )
    result = run(profile, elastic_records())
    assert result.decision == "supported"
    assert result.criteria[0].observed_lower_bound == 0
    assert result.criteria[0].observed_upper_bound == 0


def test_defender_uses_exact_scalar_matching() -> None:
    profile = defender_profile()
    result = run(
        profile,
        defender_records(
            {
                "AlertId": "a-1",
                "Severity": "High",
                "Timestamp": "2026-07-29T01:00:00.0000000Z",
            }
        ),
    )
    assert result.decision == "supported"


def test_defender_contains_predicates_are_rejected() -> None:
    with pytest.raises(ValidationError):
        AlertWindowProfile(
            profile_id="bad-defender-profile",
            profile_version="1.0.0",
            title="Bad profile",
            source=DefenderAlertSource(),
            criteria=(
                Criterion(
                    criterion_id="bad",
                    description="Bad list semantics.",
                    metric=MatchingRecordCount(
                        all=(ContainsPredicate(field="Severity", value="High"),)
                    ),
                    comparison="ge",
                    expected_count=1,
                ),
            ),
        )


def test_profile_rejects_predicate_field_not_collected_by_source() -> None:
    with pytest.raises(ValidationError):
        elastic_profile(
            Criterion(
                criterion_id="hidden-field",
                description="Field was not selected.",
                metric=MatchingRecordCount(
                    all=(EqualsPredicate(field="host.name", value="server-1"),)
                ),
                comparison="ge",
                expected_count=1,
            )
        )


def test_duplicate_or_unsorted_profile_criteria_are_rejected() -> None:
    first = Criterion(
        criterion_id="z-last",
        description="Last.",
        metric=TotalRecordCount(),
        comparison="ge",
        expected_count=0,
    )
    second = Criterion(
        criterion_id="a-first",
        description="First.",
        metric=TotalRecordCount(),
        comparison="ge",
        expected_count=0,
    )
    with pytest.raises(ValidationError):
        elastic_profile(first, second)
    with pytest.raises(ValidationError):
        elastic_profile(first, first)


def test_profile_requires_sorted_unique_source_parameters() -> None:
    with pytest.raises(ValidationError):
        ElasticAlertSource(fields=("kibana.alert.severity", "@timestamp"))
    with pytest.raises(ValidationError):
        ElasticAlertSource(fields=("@timestamp", "@timestamp"))
    with pytest.raises(ValidationError):
        ElasticAlertSource(
            fields=("@timestamp",),
            workflow_statuses=("open", "closed"),
        )


def test_records_reject_noncanonical_jsonl_unknown_envelopes_and_fields() -> None:
    profile = elastic_profile()
    pretty = (
        json.dumps(
            {
                "cursor": ["2026-07-29T01:00:00Z", 0],
                "fields": {"@timestamp": ["2026-07-29T01:00:00Z"]},
                "id": "elastic-alert:000000000000",
            },
            indent=2,
        ).encode()
        + b"\n"
    )
    with pytest.raises(AlertWindowEvaluationError):
        run(profile, pretty)
    extra = canonical_jsonl_bytes(
        [
            {
                "cursor": ["2026-07-29T01:00:00Z", 0],
                "extra": True,
                "fields": {"@timestamp": ["2026-07-29T01:00:00Z"]},
                "id": "elastic-alert:000000000000",
            }
        ]
    )
    with pytest.raises(AlertWindowEvaluationError):
        run(profile, extra)
    unselected = elastic_records(
        {
            "@timestamp": ["2026-07-29T01:00:00Z"],
            "host.name": ["server-1"],
        }
    )
    with pytest.raises(AlertWindowEvaluationError):
        run(profile, unselected)


def test_evaluation_rejects_source_profile_digest_or_window_substitution() -> None:
    profile = elastic_profile()
    records = elastic_records()
    with pytest.raises(AlertWindowEvaluationError):
        evaluate_alert_window(
            profile=profile,
            expected_profile_digest=f"sha256:{'0' * 64}",
            source_kind="elastic-security",
            records_jsonl=records,
            window_start=START,
            window_end=END,
        )
    with pytest.raises(AlertWindowEvaluationError):
        evaluate_alert_window(
            profile=profile,
            expected_profile_digest=profile.digest,
            source_kind="defender-xdr",
            records_jsonl=records,
            window_start=START,
            window_end=END,
        )
    with pytest.raises(AlertWindowEvaluationError):
        evaluate_alert_window(
            profile=profile,
            expected_profile_digest=profile.digest,
            source_kind="elastic-security",
            records_jsonl=records,
            window_start=END,
            window_end=START,
        )


def test_evaluation_is_deterministic_and_content_addressed() -> None:
    profile = elastic_profile()
    records = elastic_records(
        {
            "@timestamp": ["2026-07-29T01:00:00Z"],
            "kibana.alert.rule.uuid": [RULE],
        }
    )
    first = run(profile, records)
    second = run(profile, records)
    assert first.canonical_bytes() == second.canonical_bytes()
    assert first.digest == second.digest
    assert first.records_digest == (
        "sha256:"
        + hashlib.sha256(records).hexdigest()
    )


def test_scalar_comparison_does_not_coerce_bool_integer_or_text() -> None:
    profile = AlertWindowProfile(
        profile_id="typed-defender-profile",
        profile_version="1.0.0",
        title="Typed matching",
        source=DefenderAlertSource(),
        criteria=(
            Criterion(
                criterion_id="string-one",
                description="String one only.",
                metric=MatchingRecordCount(
                    all=(EqualsPredicate(field="Severity", value="1"),)
                ),
                comparison="eq",
                expected_count=0,
            ),
        ),
    )
    result = run(
        profile,
        defender_records(
            {
                "AlertId": "a-1",
                "Severity": 1,
                "Timestamp": "2026-07-29T01:00:00.0000000Z",
            }
        ),
    )
    assert result.decision == "supported"


def test_profile_canonical_bytes_do_not_embed_their_own_digest() -> None:
    profile = elastic_profile()
    assert profile.digest.encode() not in profile.canonical_bytes()
    assert canonical_json_bytes(profile.model_dump(mode="json")) == profile.canonical_bytes()
