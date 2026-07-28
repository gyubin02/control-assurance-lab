from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from assurance_lab.claim_spec import (
    ClaimPredicate,
    ClaimQuantifier,
    ClaimSpec,
    ClaimSubject,
    EnvironmentScope,
    EvidencePolicyRef,
    ExactTolerance,
    InputDomain,
    QuantifierKind,
    SubjectKind,
    TemporalScope,
)


def scoped_claim() -> ClaimSpec:
    return ClaimSpec(
        id="fin.scope-selection",
        subject=ClaimSubject(
            kind=SubjectKind.DATA_FLOW,
            identifier="support-customer-export",
            component="customer-data-api",
        ),
        predicate=ClaimPredicate(
            name="selects_no_out_of_scope_records",
            statement="A support request selects no customer outside its active case.",
        ),
        input_domain=InputDomain(
            id="fixed-out-of-case-bulk-v1",
            description="Two synthetic customers outside support-017's active case.",
            fixture_digest="1" * 64,
        ),
        environment=EnvironmentScope(
            scenario_id="financial-support-export",
            scenario_version="0.1.0",
            build_digest="2" * 64,
            dataset_digest="3" * 64,
        ),
        temporal=TemporalScope(as_of=datetime(2026, 7, 29, 1, 0, tzinfo=UTC)),
        quantifier=ClaimQuantifier(
            kind=QuantifierKind.ALL_TESTED,
            minimum_trials=2,
        ),
        tolerance=ExactTolerance(),
        evidence_policy=EvidencePolicyRef(id="runtime-correlated-v1", version="1"),
    )


def test_claim_scope_is_serializable_and_explicit() -> None:
    claim = scoped_claim()
    payload = claim.model_dump(mode="json")

    assert payload["temporal"]["as_of"] == "2026-07-29T01:00:00Z"
    assert payload["quantifier"]["minimum_trials"] == 2
    assert payload["tolerance"] == {"kind": "exact"}


def test_rate_quantifier_cannot_omit_threshold() -> None:
    with pytest.raises(ValidationError):
        ClaimQuantifier(
            kind=QuantifierKind.AT_LEAST_RATE,
            minimum_trials=20,
        )


def test_temporal_scope_rejects_implicit_or_incoherent_window() -> None:
    with pytest.raises(ValidationError):
        TemporalScope(
            as_of=datetime(2026, 7, 29, 1, 0, tzinfo=UTC),
            window_start=datetime(2026, 7, 29, 0, 0, tzinfo=UTC),
        )
