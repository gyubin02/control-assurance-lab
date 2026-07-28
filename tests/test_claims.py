from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from assurance_lab.claims import (
    Applicability,
    ClaimDependency,
    ClaimEvaluation,
    Defeater,
    DefeaterEffect,
    DisplayState,
    EvidenceQuality,
    EvidenceReference,
    ExecutionState,
    QualityState,
    SupportState,
    enforce_required_children,
)


def quality(**overrides: QualityState) -> EvidenceQuality:
    values = {
        "provenance": QualityState.MET,
        "scope_coverage": QualityState.MET,
        "temporal_alignment": QualityState.MET,
        "freshness": QualityState.MET,
        "integrity_verifiability": QualityState.MET,
        "reproduction_consistency": QualityState.MET,
        "minimization": QualityState.MET,
    }
    values.update(overrides)
    return EvidenceQuality(**values)


def evaluation(claim_id: str, support: SupportState) -> ClaimEvaluation:
    return ClaimEvaluation(
        claim_id=claim_id,
        statement=claim_id,
        applicability=Applicability.APPLICABLE,
        execution=ExecutionState.COMPLETED,
        support=support,
        evidence_quality=quality(),
        required_quality={"provenance", "freshness"},
        evidence_ids=[f"ev:{claim_id}"],
    )


def test_downstream_control_does_not_mask_failed_authorization() -> None:
    authorization = evaluation("application-authorization", SupportState.REFUTED)
    egress = evaluation("egress-prevention", SupportState.SUPPORTED)
    end_impact = evaluation("no-final-exfiltration", SupportState.SUPPORTED)

    assert authorization.display_state() == DisplayState.FAIL
    assert egress.display_state() == DisplayState.PASS
    assert end_impact.display_state() == DisplayState.PASS


def test_required_failed_child_prevents_parent_pass() -> None:
    parent = evaluation("customer-data-protected", SupportState.SUPPORTED)
    child = evaluation("application-authorization", SupportState.REFUTED)
    dependency = ClaimDependency(parent_id=parent.claim_id, child_id=child.claim_id)

    result = enforce_required_children(parent, [(dependency, child)])

    assert result.display_state() == DisplayState.CONFLICT
    assert result.support == SupportState.CONFLICTING
    assert parent.display_state() == DisplayState.PASS


def test_stale_evidence_cannot_pass() -> None:
    result = evaluation("detect-bulk-export", SupportState.SUPPORTED)
    result.evidence_quality = quality(freshness=QualityState.NOT_MET)

    assert result.display_state() == DisplayState.UNKNOWN
    assert result.quality_failures() == ["freshness"]


def test_attribution_defeater_yields_unknown_not_pass() -> None:
    result = evaluation("authorization-blocked-request", SupportState.SUPPORTED)
    result.defeaters.append(
        Defeater(
            id="waf-masked-app",
            statement="The WAF rejected the request before application authorization ran.",
            effect=DefeaterEffect.BLOCKS_ATTRIBUTION,
            active=True,
        )
    )

    assert result.display_state() == DisplayState.UNKNOWN


def test_scope_defeater_yields_unknown_not_pass() -> None:
    result = evaluation("export-access-protected", SupportState.SUPPORTED)
    result.defeaters.append(
        Defeater(
            id="only-one-endpoint-tested",
            statement="Only the CSV endpoint was tested; the claim includes PDF export.",
            effect=DefeaterEffect.LIMITS_SCOPE,
            active=True,
        )
    )

    assert result.display_state() == DisplayState.UNKNOWN


def test_supported_claim_without_evidence_cannot_pass() -> None:
    result = evaluation("detect-bulk-export", SupportState.SUPPORTED)
    result.evidence_ids = []

    assert result.display_state() == DisplayState.UNKNOWN


def test_evidence_timestamps_must_be_timezone_aware() -> None:
    with pytest.raises(ValidationError):
        EvidenceReference(
            id="ev-1",
            path="evidence/log.json",
            sha256="a" * 64,
            captured_at=datetime(2026, 7, 29),
            source="audit-log",
            run_id="run-1",
        )

    reference = EvidenceReference(
        id="ev-2",
        path="evidence/log.json",
        sha256="b" * 64,
        captured_at=datetime(2026, 7, 29, tzinfo=UTC),
        source="audit-log",
        run_id="run-1",
        fresh_until=datetime(2026, 7, 31, tzinfo=UTC),
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        reference.is_fresh(datetime(2026, 7, 30))


def test_not_applicable_requires_rationale() -> None:
    result = ClaimEvaluation(
        claim_id="ot-safety",
        statement="OT safety control applies",
        applicability=Applicability.NOT_APPLICABLE,
        execution=ExecutionState.NOT_RUN,
        support=SupportState.INSUFFICIENT,
        not_applicable_rationale="This profile contains no real OT devices.",
    )

    assert result.display_state() == DisplayState.NOT_APPLICABLE
