from copy import deepcopy

from assurance_lab.experiments import CheckRole, RelationOperator, WitnessState
from assurance_lab.factorial import (
    CellSelector,
    FactorContrast,
    FactorialExperimentSpec,
    FactorialWitnessEvaluator,
    FactorKind,
    FactorSpec,
    PointAssertion,
    TrialRecord,
    expand_full_factorial,
)


def design() -> FactorialExperimentSpec:
    factors = [
        FactorSpec(
            name="traffic",
            kind=FactorKind.INPUT,
            levels=["attack", "benign"],
            description="replayed request class",
        ),
        FactorSpec(
            name="authorization",
            kind=FactorKind.CONTROL,
            levels=["broken", "correct"],
            description="application object-scope authorization",
        ),
        FactorSpec(
            name="egress",
            kind=FactorKind.CONTROL,
            levels=["off", "block_bulk"],
            description="downstream bulk-export prevention",
        ),
        FactorSpec(
            name="detection",
            kind=FactorKind.CONTROL,
            levels=["off", "on"],
            description="unrelated detection pipeline for the preventive claim",
        ),
    ]
    return FactorialExperimentSpec(
        id="fin-authz-factorial",
        claim_id="application-authorization",
        factors=factors,
        cells=expand_full_factorial(factors),
        point_assertions=[
            PointAssertion(
                id="baseline-reachability",
                selector=CellSelector(
                    where={
                        "traffic": "attack",
                        "authorization": "broken",
                        "egress": "off",
                    }
                ),
                observation="unauthorized_read",
                expected=True,
                check_role=CheckRole.VALIDITY,
                purpose="the broken baseline reaches customer data",
            ),
            PointAssertion(
                id="target-mechanism",
                selector=CellSelector(
                    where={"traffic": "attack", "authorization": "correct"}
                ),
                observation="authorization_denied",
                expected=True,
                check_role=CheckRole.SUPPORT,
                purpose="the target enforcement point denies the request",
            ),
            PointAssertion(
                id="treated-unauthorized-read",
                selector=CellSelector(
                    where={"traffic": "attack", "authorization": "correct"}
                ),
                observation="unauthorized_read",
                expected=True,
                check_role=CheckRole.REFUTATION,
                purpose="the treated system still permits the read",
            ),
        ],
        contrasts=[
            FactorContrast(
                id="authorization-attack-effect",
                factor="authorization",
                from_level="broken",
                to_level="correct",
                where={"traffic": "attack"},
                observation="unauthorized_read",
                operator=RelationOperator.TRUE_TO_FALSE,
                check_role=CheckRole.SUPPORT,
                purpose="authorization removes the unauthorized read at both egress levels",
            ),
            FactorContrast(
                id="benign-invariance",
                factor="authorization",
                from_level="broken",
                to_level="correct",
                where={"traffic": "benign"},
                observation="legitimate_read",
                operator=RelationOperator.EQUAL,
                check_role=CheckRole.VALIDITY,
                purpose="authorization preserves legitimate reads",
            ),
            FactorContrast(
                id="detection-unrelated",
                factor="detection",
                from_level="off",
                to_level="on",
                where={"traffic": "attack"},
                observation="unauthorized_read",
                operator=RelationOperator.EQUAL,
                check_role=CheckRole.VALIDITY,
                purpose="the unrelated detector does not cause prevention",
            ),
        ],
    )


def trials(spec: FactorialExperimentSpec, replicates: int = 2) -> list[TrialRecord]:
    records: list[TrialRecord] = []
    sequence = 0
    for replicate in range(replicates):
        for cell in spec.cells:
            sequence += 1
            attack = cell.factors["traffic"] == "attack"
            authorization_correct = cell.factors["authorization"] == "correct"
            egress_on = cell.factors["egress"] == "block_bulk"
            unauthorized_read = attack and not authorization_correct
            legitimate_read = not attack
            final_exfiltration = unauthorized_read and not egress_on
            records.append(
                TrialRecord(
                    id=f"trial-{replicate:02d}-{cell.id}",
                    cell_id=cell.id,
                    block_id="block-a",
                    replicate=replicate,
                    sequence=sequence,
                    environment_fingerprint=f"env:replicate-{replicate}",
                    observed_factors=cell.factors,
                    cleanup_verified=True,
                    observations={
                        "unauthorized_read": unauthorized_read,
                        "authorization_denied": attack and authorization_correct,
                        "legitimate_read": legitimate_read,
                        "final_exfiltration": final_exfiltration,
                    },
                    evidence_ids=[f"evidence:{replicate}:{cell.id}"],
                )
            )
    return records


def test_factorial_witness_supports_target_control_without_masking() -> None:
    experiment = design()
    result = FactorialWitnessEvaluator().evaluate(experiment, trials(experiment))

    assert result.state == WitnessState.SUPPORTED
    assert result.attributable is True
    assert all(
        check.passed
        for check in result.checks
        if check.id != "assertion:treated-unauthorized-read"
    )


def test_masked_cell_keeps_component_failure_visible() -> None:
    experiment = design()
    records = trials(experiment)
    masked = [
        trial
        for trial in records
        if trial.observed_factors["traffic"] == "attack"
        and trial.observed_factors["authorization"] == "broken"
        and trial.observed_factors["egress"] == "block_bulk"
    ]

    assert masked
    assert all(trial.observations["unauthorized_read"] is True for trial in masked)
    assert all(trial.observations["final_exfiltration"] is False for trial in masked)


def test_environment_drift_in_one_pair_blocks_attribution() -> None:
    experiment = design()
    records = trials(experiment)
    target = next(
        trial
        for trial in records
        if trial.replicate == 0
        and trial.observed_factors
        == {
            "traffic": "attack",
            "authorization": "correct",
            "egress": "off",
            "detection": "off",
        }
    )
    target.environment_fingerprint = "env:drifted"

    result = FactorialWitnessEvaluator().evaluate(experiment, records)

    assert result.state == WitnessState.INCONCLUSIVE
    assert result.attributable is False
    assert any(
        check.id.startswith("environment:") and not check.passed
        for check in result.checks
    )


def test_observed_factor_mismatch_blocks_attribution() -> None:
    experiment = design()
    records = trials(experiment)
    records[0].observed_factors = {
        **records[0].observed_factors,
        "authorization": "correct",
    }

    result = FactorialWitnessEvaluator().evaluate(experiment, records)

    assert result.state == WitnessState.INCONCLUSIVE
    assert any(
        check.id == f"factor:{records[0].id}" and not check.passed
        for check in result.checks
    )


def test_missing_paired_trial_is_not_silently_ignored() -> None:
    experiment = design()
    records = trials(experiment)
    omitted = deepcopy(records)
    omitted.pop(3)

    result = FactorialWitnessEvaluator().evaluate(experiment, omitted)

    assert result.state == WitnessState.INCONCLUSIVE
    assert any(
        check.id.startswith("contrast:") and not check.passed for check in result.checks
    )


def test_outage_breaks_benign_invariance() -> None:
    experiment = design()
    records = trials(experiment)
    for trial in records:
        if (
            trial.observed_factors["traffic"] == "benign"
            and trial.observed_factors["authorization"] == "correct"
        ):
            trial.observations["legitimate_read"] = False

    result = FactorialWitnessEvaluator().evaluate(experiment, records)

    assert result.state == WitnessState.INCONCLUSIVE
    assert any(
        check.id == "contrast:benign-invariance" and not check.passed
        for check in result.checks
    )
