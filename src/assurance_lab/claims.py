"""Claim-level evaluation without score-based masking."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field, model_validator


class Applicability(StrEnum):
    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"
    UNDETERMINED = "undetermined"


class ExecutionState(StrEnum):
    COMPLETED = "completed"
    NOT_RUN = "not_run"
    INCONCLUSIVE = "inconclusive"
    HARNESS_ERROR = "harness_error"


class SupportState(StrEnum):
    SUPPORTED = "supported"
    REFUTED = "refuted"
    CONFLICTING = "conflicting"
    INSUFFICIENT = "insufficient"


class DisplayState(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"
    NOT_TESTED = "not_tested"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


class QualityState(StrEnum):
    MET = "met"
    NOT_MET = "not_met"
    UNKNOWN = "unknown"
    NOT_REQUIRED = "not_required"


class DefeaterEffect(StrEnum):
    BLOCKS_ATTRIBUTION = "blocks_attribution"
    REBUTS_CLAIM = "rebuts_claim"
    LIMITS_SCOPE = "limits_scope"
    INVALIDATES_RUN = "invalidates_run"


class EvidenceReference(BaseModel):
    id: str
    path: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    captured_at: datetime
    source: str
    run_id: str
    fresh_until: datetime | None = None

    def is_fresh(self, at: datetime | None = None) -> bool:
        if self.fresh_until is None:
            return True
        checked_at = at or datetime.now(tz=UTC)
        return checked_at <= self.fresh_until


class EvidenceQuality(BaseModel):
    provenance: QualityState
    scope_coverage: QualityState
    temporal_alignment: QualityState
    freshness: QualityState
    integrity_verifiability: QualityState
    reproduction_consistency: QualityState
    minimization: QualityState

    def unmet(self, required: set[str]) -> list[str]:
        failures: list[str] = []
        for name in sorted(required):
            value = getattr(self, name, None)
            if value is None:
                raise ValueError(f"unknown evidence-quality dimension: {name}")
            if value != QualityState.MET:
                failures.append(name)
        return failures


class Defeater(BaseModel):
    id: str
    statement: str
    effect: DefeaterEffect
    active: bool
    evidence_ids: list[str] = Field(default_factory=list)


class ClaimEvaluation(BaseModel):
    claim_id: str
    statement: str
    applicability: Applicability
    execution: ExecutionState
    support: SupportState
    evidence_quality: EvidenceQuality | None = None
    required_quality: set[str] = Field(default_factory=set)
    evidence_ids: list[str] = Field(default_factory=list)
    defeaters: list[Defeater] = Field(default_factory=list)
    not_applicable_rationale: str | None = None

    @model_validator(mode="after")
    def validate_rationale(self) -> ClaimEvaluation:
        if (
            self.applicability == Applicability.NOT_APPLICABLE
            and not self.not_applicable_rationale
        ):
            raise ValueError("not_applicable requires a rationale")
        return self

    def quality_failures(self) -> list[str]:
        if not self.required_quality:
            return []
        if self.evidence_quality is None:
            return sorted(self.required_quality)
        return self.evidence_quality.unmet(self.required_quality)

    def display_state(self) -> DisplayState:
        if self.applicability == Applicability.NOT_APPLICABLE:
            return DisplayState.NOT_APPLICABLE
        if self.execution == ExecutionState.HARNESS_ERROR:
            return DisplayState.ERROR
        if self.execution == ExecutionState.NOT_RUN:
            return DisplayState.NOT_TESTED
        if self.applicability == Applicability.UNDETERMINED:
            return DisplayState.UNKNOWN
        if self.execution == ExecutionState.INCONCLUSIVE:
            return DisplayState.UNKNOWN

        active = [defeater for defeater in self.defeaters if defeater.active]
        if any(d.effect == DefeaterEffect.INVALIDATES_RUN for d in active):
            return DisplayState.ERROR
        if any(d.effect == DefeaterEffect.BLOCKS_ATTRIBUTION for d in active):
            return DisplayState.UNKNOWN
        if self.quality_failures():
            return DisplayState.UNKNOWN
        if self.support == SupportState.CONFLICTING:
            return DisplayState.CONFLICT
        if any(d.effect == DefeaterEffect.REBUTS_CLAIM for d in active):
            if self.support == SupportState.REFUTED:
                return DisplayState.FAIL
            return DisplayState.CONFLICT
        if self.support == SupportState.REFUTED:
            return DisplayState.FAIL
        if self.support == SupportState.INSUFFICIENT:
            return DisplayState.UNKNOWN
        if self.support == SupportState.SUPPORTED:
            return DisplayState.PASS
        raise AssertionError(f"unhandled support state: {self.support}")


class ClaimDependency(BaseModel):
    parent_id: str
    child_id: str
    required: bool = True


def enforce_required_children(
    parent: ClaimEvaluation,
    children: list[tuple[ClaimDependency, ClaimEvaluation]],
) -> ClaimEvaluation:
    """Apply the non-masking invariant to a parent evaluation.

    Optional/compensating children remain visible but do not rewrite the parent.
    A required child that is not a pass prevents the parent from passing.
    """

    if parent.display_state() != DisplayState.PASS:
        return parent

    blocking = [
        child
        for dependency, child in children
        if dependency.required and child.display_state() != DisplayState.PASS
    ]
    if not blocking:
        return parent

    copied = parent.model_copy(deep=True)
    copied.support = SupportState.CONFLICTING
    copied.defeaters.append(
        Defeater(
            id=f"{parent.claim_id}:required-child",
            statement="Required child claims are not all supported: "
            + ", ".join(child.claim_id for child in blocking),
            effect=DefeaterEffect.REBUTS_CLAIM,
            active=True,
            evidence_ids=[
                evidence_id for child in blocking for evidence_id in child.evidence_ids
            ],
        )
    )
    return copied

