"""Recomputable, source-window control criteria for SIEM and EDR evidence.

This profile is deliberately narrower than the experiment evaluator.  It can
establish facts about one complete, half-open alert window, such as "at least
one alert from this exact rule was observed."  It cannot establish that an
attack happened, that a control caused the alert, or that the control is
effective in production.

Missing or shape-incompatible fields are not silently treated as non-matches.
For every matching-count criterion the evaluator computes a closed interval:

* the lower bound is the number of records that definitely match; and
* the upper bound also includes records that might match if their missing
  evidence were available.

A comparison is supported or refuted only when the whole interval permits that
conclusion.  Otherwise the result is unresolved.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Annotated, Any, Final, Literal, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
    strict_jsonl_loads,
)

ALERT_WINDOW_PROFILE_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.alert-window-profile.v1+json"]
] = "application/vnd.control-assurance.alert-window-profile.v1+json"
ALERT_WINDOW_EVALUATION_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.alert-window-evaluation.v1+json"]
] = "application/vnd.control-assurance.alert-window-evaluation.v1+json"
ALERT_WINDOW_CLAIM_BOUNDARY: Final[
    Literal["observed-source-window-only"]
] = "observed-source-window-only"

_ID_RE = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_FIELD_RE = re.compile(r"^(?:@timestamp|[A-Za-z][A-Za-z0-9_.]{0,127})$")
_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

_MAX_RECORDS = 100_000
_MAX_FIELDS = 32
_MAX_CRITERIA = 64
_MAX_PREDICATES = 16
_MAX_LITERAL_TEXT = 4_096
_MAX_FIELD_VALUE_BYTES = 1024 * 1024

_PROFILE_LIMITS = JSONLimits(
    max_bytes=1024 * 1024,
    max_line_bytes=1024 * 1024,
    max_depth=24,
    max_collection_items=16_384,
    max_string_length=256 * 1024,
)
_RECORD_LIMITS = JSONLimits(
    max_bytes=64 * 1024 * 1024,
    max_line_bytes=2 * 1024 * 1024,
    max_depth=16,
    max_collection_items=200_000,
    max_string_length=_MAX_FIELD_VALUE_BYTES,
)

PortableId = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9._-]{0,127}$",
    ),
]
Digest = Annotated[
    str,
    StringConstraints(
        min_length=71,
        max_length=71,
        pattern=r"^sha256:[a-f0-9]{64}$",
    ),
]
FieldName = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^(?:@timestamp|[A-Za-z][A-Za-z0-9_.]{0,127})$",
    ),
]
Scalar = str | int | bool
Decision = Literal["supported", "refuted", "unresolved"]
Comparison = Literal["eq", "ge", "le"]

_DEFENDER_FIELDS: Final = frozenset(
    {
        "AlertId",
        "AttackTechniques",
        "Category",
        "DetectionSource",
        "ServiceSource",
        "Severity",
        "Timestamp",
        "Title",
    }
)
_ELASTIC_ALERT_STATUSES: Final = frozenset({"active", "recovered"})
_ELASTIC_WORKFLOW_STATUSES: Final = frozenset(
    {"acknowledged", "closed", "open"}
)


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _utc_second(value: datetime, *, label: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
    converted = value.astimezone(UTC)
    if converted.microsecond:
        raise ValueError(f"{label} must use whole UTC seconds")
    return converted


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class ExistsPredicate(_FrozenModel):
    kind: Literal["exists"] = "exists"
    field: FieldName


class EqualsPredicate(_FrozenModel):
    kind: Literal["equals"] = "equals"
    field: FieldName
    value: Scalar

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: Scalar) -> Scalar:
        if type(value) is str and len(value.encode("utf-8")) > _MAX_LITERAL_TEXT:
            raise ValueError("predicate text exceeds the profile limit")
        return value


class ContainsPredicate(_FrozenModel):
    kind: Literal["contains"] = "contains"
    field: FieldName
    value: Scalar

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: Scalar) -> Scalar:
        if type(value) is str and len(value.encode("utf-8")) > _MAX_LITERAL_TEXT:
            raise ValueError("predicate text exceeds the profile limit")
        return value


FieldPredicate = Annotated[
    ExistsPredicate | EqualsPredicate | ContainsPredicate,
    Field(discriminator="kind"),
]


class TotalRecordCount(_FrozenModel):
    kind: Literal["total-record-count"] = "total-record-count"


class MatchingRecordCount(_FrozenModel):
    kind: Literal["matching-record-count"] = "matching-record-count"
    all: tuple[FieldPredicate, ...] = Field(
        min_length=1,
        max_length=_MAX_PREDICATES,
    )

    @model_validator(mode="after")
    def unique_predicates(self) -> MatchingRecordCount:
        canonical = tuple(
            canonical_json_bytes(predicate.model_dump(mode="json"))
            for predicate in self.all
        )
        if len(set(canonical)) != len(canonical):
            raise ValueError("matching criterion contains duplicate predicates")
        return self


Metric = Annotated[
    TotalRecordCount | MatchingRecordCount,
    Field(discriminator="kind"),
]


class Criterion(_FrozenModel):
    criterion_id: PortableId
    description: Annotated[str, StringConstraints(min_length=1, max_length=512)]
    metric: Metric
    comparison: Comparison
    expected_count: int = Field(ge=0, le=_MAX_RECORDS)


class ElasticAlertSource(_FrozenModel):
    kind: Literal["elastic-security"] = "elastic-security"
    fields: tuple[FieldName, ...] = Field(min_length=1, max_length=_MAX_FIELDS)
    rule_uuids: tuple[str, ...] = Field(default=(), max_length=256)
    workflow_statuses: tuple[str, ...] = Field(default=(), max_length=3)
    alert_statuses: tuple[str, ...] = Field(default=(), max_length=2)

    @field_validator("fields")
    @classmethod
    def validate_fields(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if "@timestamp" not in value:
            raise ValueError("Elastic profile fields must include @timestamp")
        if len(set(value)) != len(value) or tuple(sorted(value)) != value:
            raise ValueError("Elastic profile fields must be unique and sorted")
        return value

    @field_validator("rule_uuids")
    @classmethod
    def validate_rule_uuids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if (
            any(type(item) is not str or _UUID_RE.fullmatch(item) is None for item in value)
            or len(set(value)) != len(value)
            or tuple(sorted(value)) != value
        ):
            raise ValueError("Elastic rule UUIDs must be unique sorted canonical UUIDs")
        return value

    @field_validator("workflow_statuses")
    @classmethod
    def validate_workflow_statuses(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if (
            any(item not in _ELASTIC_WORKFLOW_STATUSES for item in value)
            or len(set(value)) != len(value)
            or tuple(sorted(value)) != value
        ):
            raise ValueError("Elastic workflow statuses are invalid")
        return value

    @field_validator("alert_statuses")
    @classmethod
    def validate_alert_statuses(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if (
            any(item not in _ELASTIC_ALERT_STATUSES for item in value)
            or len(set(value)) != len(value)
            or tuple(sorted(value)) != value
        ):
            raise ValueError("Elastic alert statuses are invalid")
        return value


class DefenderAlertSource(_FrozenModel):
    kind: Literal["defender-xdr"] = "defender-xdr"


AlertSource = Annotated[
    ElasticAlertSource | DefenderAlertSource,
    Field(discriminator="kind"),
]


class AlertWindowProfile(_FrozenModel):
    """Canonical criteria distributed independently of captured evidence."""

    media_type: Literal[
        "application/vnd.control-assurance.alert-window-profile.v1+json"
    ] = ALERT_WINDOW_PROFILE_MEDIA_TYPE
    schema_version: Literal["1.0.0"] = "1.0.0"
    profile_id: PortableId
    profile_version: Annotated[
        str,
        StringConstraints(
            min_length=1,
            max_length=64,
            pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$",
        ),
    ]
    title: Annotated[str, StringConstraints(min_length=1, max_length=160)]
    claim_boundary: Literal["observed-source-window-only"] = (
        ALERT_WINDOW_CLAIM_BOUNDARY
    )
    source: AlertSource
    criteria: tuple[Criterion, ...] = Field(
        min_length=1,
        max_length=_MAX_CRITERIA,
    )

    @model_validator(mode="after")
    def validate_profile(self) -> AlertWindowProfile:
        criterion_ids = tuple(item.criterion_id for item in self.criteria)
        if len(set(criterion_ids)) != len(criterion_ids):
            raise ValueError("control profile criterion ids must be unique")
        if tuple(sorted(criterion_ids)) != criterion_ids:
            raise ValueError("control profile criteria must be sorted by id")

        allowed_fields = (
            frozenset(self.source.fields)
            if isinstance(self.source, ElasticAlertSource)
            else _DEFENDER_FIELDS
        )
        for criterion in self.criteria:
            if not isinstance(criterion.metric, MatchingRecordCount):
                continue
            for predicate in criterion.metric.all:
                if predicate.field not in allowed_fields:
                    raise ValueError(
                        "criterion field is not supplied by the selected source"
                    )
                if (
                    isinstance(self.source, DefenderAlertSource)
                    and isinstance(predicate, ContainsPredicate)
                ):
                    raise ValueError(
                        "Defender AlertInfo fields are scalar; contains is invalid"
                    )
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            self.model_dump(mode="json"),
            limits=_PROFILE_LIMITS,
        )

    @property
    def digest(self) -> str:
        return _sha256(self.canonical_bytes())

    @property
    def source_kind(self) -> Literal["elastic-security", "defender-xdr"]:
        return self.source.kind


class CriterionEvaluation(_FrozenModel):
    criterion_id: PortableId
    comparison: Comparison
    expected_count: int = Field(ge=0, le=_MAX_RECORDS)
    observed_lower_bound: int = Field(ge=0, le=_MAX_RECORDS)
    observed_upper_bound: int = Field(ge=0, le=_MAX_RECORDS)
    indeterminate_record_count: int = Field(ge=0, le=_MAX_RECORDS)
    matched_record_ids_digest: Digest
    indeterminate_record_ids_digest: Digest
    decision: Decision
    reason_code: Literal[
        "comparison-satisfied",
        "comparison-refuted",
        "insufficient-field-evidence",
    ]

    @model_validator(mode="after")
    def validate_interval(self) -> CriterionEvaluation:
        if self.observed_upper_bound < self.observed_lower_bound:
            raise ValueError("criterion evaluation interval is reversed")
        if (
            self.observed_upper_bound - self.observed_lower_bound
            != self.indeterminate_record_count
        ):
            raise ValueError("criterion interval does not close over uncertainty")
        expected_reason = {
            "supported": "comparison-satisfied",
            "refuted": "comparison-refuted",
            "unresolved": "insufficient-field-evidence",
        }[self.decision]
        if self.reason_code != expected_reason:
            raise ValueError("criterion decision and reason disagree")
        return self


class AlertWindowEvaluation(_FrozenModel):
    """Canonical result recomputed from a profile and exact record bytes."""

    media_type: Literal[
        "application/vnd.control-assurance.alert-window-evaluation.v1+json"
    ] = ALERT_WINDOW_EVALUATION_MEDIA_TYPE
    schema_version: Literal["1.0.0"] = "1.0.0"
    profile_id: PortableId
    profile_digest: Digest
    source_kind: Literal["elastic-security", "defender-xdr"]
    records_digest: Digest
    record_count: int = Field(ge=0, le=_MAX_RECORDS)
    window_start: datetime
    window_end: datetime
    claim_boundary: Literal["observed-source-window-only"] = (
        ALERT_WINDOW_CLAIM_BOUNDARY
    )
    criteria: tuple[CriterionEvaluation, ...] = Field(
        min_length=1,
        max_length=_MAX_CRITERIA,
    )
    decision: Decision

    @field_validator("window_start", "window_end")
    @classmethod
    def validate_times(cls, value: datetime) -> datetime:
        return _utc_second(value, label="evaluation window")

    @model_validator(mode="after")
    def validate_result(self) -> AlertWindowEvaluation:
        if self.window_end <= self.window_start:
            raise ValueError("evaluation window must be non-empty")
        ids = tuple(item.criterion_id for item in self.criteria)
        if len(set(ids)) != len(ids) or tuple(sorted(ids)) != ids:
            raise ValueError("evaluation criteria must be unique and sorted")
        expected = (
            "refuted"
            if any(item.decision == "refuted" for item in self.criteria)
            else (
                "unresolved"
                if any(item.decision == "unresolved" for item in self.criteria)
                else "supported"
            )
        )
        if self.decision != expected:
            raise ValueError("overall decision does not follow criterion decisions")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"))

    @property
    def digest(self) -> str:
        return _sha256(self.canonical_bytes())


class AlertWindowEvaluationError(ValueError):
    """The profile or evidence cannot enter the evaluation boundary."""


def parse_alert_window_profile(
    value: bytes,
    *,
    expected_profile_id: str,
    expected_profile_digest: str,
) -> AlertWindowProfile:
    """Parse one exact canonical profile under external id and digest anchors."""

    if type(value) is not bytes or not value:
        raise AlertWindowEvaluationError("control profile is absent")
    if type(expected_profile_id) is not str or _ID_RE.fullmatch(expected_profile_id) is None:
        raise AlertWindowEvaluationError("expected control profile id is invalid")
    if (
        type(expected_profile_digest) is not str
        or _DIGEST_RE.fullmatch(expected_profile_digest) is None
    ):
        raise AlertWindowEvaluationError("expected control profile digest is invalid")
    try:
        strict_json_loads(value, limits=_PROFILE_LIMITS)
        # ``model_validate_json`` applies strict JSON semantics: JSON arrays
        # are the wire representation of immutable tuple fields.  Calling
        # ``model_validate`` on the intermediate Python lists would reject
        # that valid wire representation under strict mode.
        profile = AlertWindowProfile.model_validate_json(value)
        canonical = profile.canonical_bytes()
    except (StrictJSONError, TypeError, ValueError) as exc:
        raise AlertWindowEvaluationError("control profile is invalid") from exc
    if canonical != value:
        raise AlertWindowEvaluationError("control profile is not canonical JSON")
    if profile.profile_id != expected_profile_id:
        raise AlertWindowEvaluationError("control profile id differs from its reference")
    if profile.digest != expected_profile_digest:
        raise AlertWindowEvaluationError("control profile digest differs from its reference")
    return profile


def _predicate_result(
    predicate: FieldPredicate,
    fields: dict[str, Any],
) -> bool | None:
    if predicate.field not in fields:
        return None
    observed = fields[predicate.field]
    if isinstance(predicate, ExistsPredicate):
        return True
    if isinstance(predicate, EqualsPredicate):
        # Exact type equality prevents bool/int coercion and silent string
        # normalization across products.
        return type(observed) is type(predicate.value) and observed == predicate.value
    assert isinstance(predicate, ContainsPredicate)
    if not isinstance(observed, list):
        return None
    return any(
        type(item) is type(predicate.value) and item == predicate.value
        for item in observed
    )


def _records(
    value: bytes,
    *,
    profile: AlertWindowProfile,
) -> list[tuple[str, dict[str, Any]]]:
    if type(value) is not bytes:
        raise AlertWindowEvaluationError("source records must be immutable bytes")
    try:
        parsed = strict_jsonl_loads(
            value,
            limits=_RECORD_LIMITS,
            require_sorted_ids=True,
        )
    except StrictJSONError as exc:
        raise AlertWindowEvaluationError(
            "source records are not canonical sorted JSONL"
        ) from exc
    if len(parsed) > _MAX_RECORDS:
        raise AlertWindowEvaluationError("source record count exceeds the profile")
    allowed_fields = (
        frozenset(profile.source.fields)
        if isinstance(profile.source, ElasticAlertSource)
        else _DEFENDER_FIELDS
    )
    expected_keys = (
        frozenset({"cursor", "fields", "id"})
        if isinstance(profile.source, ElasticAlertSource)
        else frozenset({"fields", "id"})
    )
    result: list[tuple[str, dict[str, Any]]] = []
    for item in parsed:
        if not isinstance(item, dict) or frozenset(item) != expected_keys:
            raise AlertWindowEvaluationError(
                "source record has an unexpected envelope"
            )
        record_id = item.get("id")
        fields = item.get("fields")
        if (
            type(record_id) is not str
            or not record_id
            or len(record_id) > 256
            or not isinstance(fields, dict)
            or any(type(name) is not str or name not in allowed_fields for name in fields)
        ):
            raise AlertWindowEvaluationError(
                "source record fields are outside the control profile"
            )
        result.append((record_id, cast(dict[str, Any], fields)))
    return result


def _ids_digest(values: list[str]) -> str:
    return _sha256(canonical_json_bytes(values))


def _comparison_decision(
    comparison: Comparison,
    *,
    expected: int,
    lower: int,
    upper: int,
) -> Decision:
    if comparison == "ge":
        if lower >= expected:
            return "supported"
        if upper < expected:
            return "refuted"
        return "unresolved"
    if comparison == "le":
        if upper <= expected:
            return "supported"
        if lower > expected:
            return "refuted"
        return "unresolved"
    if lower == upper == expected:
        return "supported"
    if expected < lower or expected > upper:
        return "refuted"
    return "unresolved"


def _evaluate_criterion(
    criterion: Criterion,
    records: list[tuple[str, dict[str, Any]]],
) -> CriterionEvaluation:
    matched: list[str] = []
    indeterminate: list[str] = []
    if isinstance(criterion.metric, TotalRecordCount):
        matched = [record_id for record_id, _ in records]
    else:
        assert isinstance(criterion.metric, MatchingRecordCount)
        for record_id, fields in records:
            outcomes = tuple(
                _predicate_result(predicate, fields)
                for predicate in criterion.metric.all
            )
            if all(outcome is True for outcome in outcomes):
                matched.append(record_id)
            elif not any(outcome is False for outcome in outcomes):
                indeterminate.append(record_id)
    lower = len(matched)
    upper = lower + len(indeterminate)
    decision = _comparison_decision(
        criterion.comparison,
        expected=criterion.expected_count,
        lower=lower,
        upper=upper,
    )
    if decision == "supported":
        reason: Literal[
            "comparison-satisfied",
            "comparison-refuted",
            "insufficient-field-evidence",
        ] = "comparison-satisfied"
    elif decision == "refuted":
        reason = "comparison-refuted"
    else:
        reason = "insufficient-field-evidence"
    return CriterionEvaluation(
        criterion_id=criterion.criterion_id,
        comparison=criterion.comparison,
        expected_count=criterion.expected_count,
        observed_lower_bound=lower,
        observed_upper_bound=upper,
        indeterminate_record_count=len(indeterminate),
        matched_record_ids_digest=_ids_digest(matched),
        indeterminate_record_ids_digest=_ids_digest(indeterminate),
        decision=decision,
        reason_code=reason,
    )


def evaluate_alert_window(
    *,
    profile: AlertWindowProfile,
    expected_profile_digest: str,
    source_kind: Literal["elastic-security", "defender-xdr"],
    records_jsonl: bytes,
    window_start: datetime,
    window_end: datetime,
) -> AlertWindowEvaluation:
    """Recompute all declared criteria from exact canonical connector records."""

    if type(profile) is not AlertWindowProfile:
        raise TypeError("profile must be an exact AlertWindowProfile")
    if (
        type(expected_profile_digest) is not str
        or _DIGEST_RE.fullmatch(expected_profile_digest) is None
        or profile.digest != expected_profile_digest
    ):
        raise AlertWindowEvaluationError("profile digest does not match its external anchor")
    if source_kind != profile.source_kind:
        raise AlertWindowEvaluationError("profile and connector source kinds differ")
    try:
        start = _utc_second(window_start, label="evaluation window start")
        end = _utc_second(window_end, label="evaluation window end")
    except ValueError as exc:
        raise AlertWindowEvaluationError("evaluation window is invalid") from exc
    if end <= start:
        raise AlertWindowEvaluationError("evaluation window must be non-empty")
    records = _records(records_jsonl, profile=profile)
    criteria = tuple(
        _evaluate_criterion(criterion, records)
        for criterion in profile.criteria
    )
    decision: Decision = (
        "refuted"
        if any(item.decision == "refuted" for item in criteria)
        else (
            "unresolved"
            if any(item.decision == "unresolved" for item in criteria)
            else "supported"
        )
    )
    return AlertWindowEvaluation(
        profile_id=profile.profile_id,
        profile_digest=profile.digest,
        source_kind=source_kind,
        records_digest=_sha256(records_jsonl),
        record_count=len(records),
        window_start=start,
        window_end=end,
        criteria=criteria,
        decision=decision,
    )
