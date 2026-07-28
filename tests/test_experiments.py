from assurance_lab.experiments import (
    Assertion,
    CheckRole,
    ControlExperimentSpec,
    InterventionalWitnessEvaluator,
    Relation,
    RelationOperator,
    RunRecord,
    RunRole,
    WitnessState,
)


def spec() -> ControlExperimentSpec:
    return ControlExperimentSpec(
        id="authz-001",
        claim_id="application-authorization",
        validity_assertions=[
            Assertion(
                id="baseline-reaches-data",
                role=RunRole.ATTACK_BASELINE,
                observation="unauthorized_read",
                expected=True,
                purpose="the broken baseline demonstrates reachability",
            ),
        ],
        support_assertions=[
            Assertion(
                id="treatment-blocks-at-authz",
                role=RunRole.ATTACK_TREATMENT,
                observation="authorization_denied",
                expected=True,
                purpose="the target enforcement point denies the request",
            ),
            Assertion(
                id="mechanism-observed",
                role=RunRole.ATTACK_TREATMENT,
                observation="target_control_engaged",
                expected=True,
                purpose="the target control emitted its decision",
            ),
            Assertion(
                id="legitimate-still-works",
                role=RunRole.BENIGN_TREATMENT,
                observation="legitimate_read",
                expected=True,
                purpose="the treatment preserves the legitimate path",
            ),
        ],
        refutation_assertions=[
            Assertion(
                id="treatment-allows-unauthorized",
                role=RunRole.ATTACK_TREATMENT,
                observation="unauthorized_read",
                expected=True,
                purpose="the treated system still permits unauthorized access",
            )
        ],
        relations=[
            Relation(
                id="attack-contrast",
                left_role=RunRole.ATTACK_BASELINE,
                right_role=RunRole.ATTACK_TREATMENT,
                observation="unauthorized_read",
                operator=RelationOperator.TRUE_TO_FALSE,
                purpose="unauthorized access disappears under the target control",
            ),
            Relation(
                id="benign-invariance",
                left_role=RunRole.BENIGN_BASELINE,
                right_role=RunRole.BENIGN_TREATMENT,
                observation="legitimate_read",
                operator=RelationOperator.EQUAL,
                check_role=CheckRole.VALIDITY,
                purpose="legitimate access remains available",
            ),
            Relation(
                id="unrelated-invariance",
                left_role=RunRole.ATTACK_BASELINE,
                right_role=RunRole.UNRELATED_INTERVENTION,
                observation="unauthorized_read",
                operator=RelationOperator.EQUAL,
                check_role=CheckRole.VALIDITY,
                purpose="an unrelated change does not explain the result",
            ),
        ],
    )


def records(
    *,
    treated_unauthorized_read: bool = False,
    treated_legitimate_read: bool = True,
    treatment_verified: bool = True,
    treatment_environment: str = "env:one",
    unrelated_unauthorized_read: bool = True,
) -> list[RunRecord]:
    common = {
        "pair_id": "pair-01",
        "environment_fingerprint": "env:one",
        "intervention_verified": True,
        "cleanup_verified": True,
        "evidence_ids": ["evidence:pair-01"],
    }
    return [
        RunRecord(
            id="attack-baseline",
            role=RunRole.ATTACK_BASELINE,
            observations={
                "unauthorized_read": True,
                "authorization_denied": False,
                "target_control_engaged": False,
            },
            **common,
        ),
        RunRecord(
            id="attack-treatment",
            role=RunRole.ATTACK_TREATMENT,
            pair_id="pair-01",
            environment_fingerprint=treatment_environment,
            intervention_verified=treatment_verified,
            cleanup_verified=True,
            observations={
                "unauthorized_read": treated_unauthorized_read,
                "authorization_denied": not treated_unauthorized_read,
                "target_control_engaged": True,
            },
            evidence_ids=["evidence:pair-01"],
        ),
        RunRecord(
            id="benign-baseline",
            role=RunRole.BENIGN_BASELINE,
            observations={"legitimate_read": True},
            **common,
        ),
        RunRecord(
            id="benign-treatment",
            role=RunRole.BENIGN_TREATMENT,
            observations={"legitimate_read": treated_legitimate_read},
            **common,
        ),
        RunRecord(
            id="unrelated",
            role=RunRole.UNRELATED_INTERVENTION,
            observations={"unauthorized_read": unrelated_unauthorized_read},
            **common,
        ),
    ]


def test_valid_contrast_supports_scoped_claim() -> None:
    result = InterventionalWitnessEvaluator().evaluate(spec(), records())

    assert result.state == WitnessState.SUPPORTED
    assert result.attributable is True
    assert all(check.passed for check in result.checks)


def test_outage_is_not_accepted_as_prevention() -> None:
    result = InterventionalWitnessEvaluator().evaluate(
        spec(), records(treated_legitimate_read=False)
    )

    assert result.state == WitnessState.INCONCLUSIVE
    assert result.attributable is False
    assert any(
        check.id == "assertion:legitimate-still-works" and not check.passed
        for check in result.checks
    )


def test_unverified_intervention_blocks_attribution() -> None:
    result = InterventionalWitnessEvaluator().evaluate(
        spec(), records(treatment_verified=False)
    )

    assert result.state == WitnessState.INCONCLUSIVE
    assert result.attributable is False
    assert "not attributable" in result.reasons[0]


def test_environment_drift_blocks_attribution() -> None:
    result = InterventionalWitnessEvaluator().evaluate(
        spec(), records(treatment_environment="env:different")
    )

    assert result.state == WitnessState.INCONCLUSIVE
    assert any(
        check.id == "environment:pair-01" and not check.passed for check in result.checks
    )


def test_unrelated_change_detects_harness_sensitivity() -> None:
    result = InterventionalWitnessEvaluator().evaluate(
        spec(), records(unrelated_unauthorized_read=False)
    )

    assert result.state == WitnessState.INCONCLUSIVE
    assert any(
        check.id == "relation:unrelated-invariance" and not check.passed
        for check in result.checks
    )


def test_valid_failed_treatment_refutes_claim() -> None:
    result = InterventionalWitnessEvaluator().evaluate(
        spec(), records(treated_unauthorized_read=True)
    )

    assert result.state == WitnessState.REFUTED
    assert result.attributable is True
