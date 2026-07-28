from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from pydantic import ValidationError

import assurance_lab.contract as contract_module
from assurance_lab.contract import (
    I_JSON_MAX_INTEGER,
    MAX_BLOCKS,
    MAX_REPLICATES,
    AllTested,
    AtLeastRate,
    BooleanValue,
    CellSelector,
    CompensatorControlAxis,
    ContractCompileError,
    DecimalValue,
    EvidencePolicyRef,
    EvidenceWindow,
    Exists,
    ExperimentContract,
    ExperimentScope,
    InputAxis,
    IntegerValue,
    MetricContract,
    MetricRelation,
    MetricValueType,
    Obligation,
    ObligationScope,
    Predicate,
    PredicateOperator,
    PreventiveNonMaskingProfile,
    RelationOperator,
    ShamAxis,
    Stage,
    StringValue,
    Subject,
    TargetControlAxis,
    TrialPlan,
    compile_experiment,
)


def text(value: str) -> StringValue:
    return StringValue(value=value)


def boolean(value: bool) -> BooleanValue:
    return BooleanValue(value=value)


def current_selector() -> CellSelector:
    return CellSelector(
        input=text("malicious"),
        target=text("wildcard-misgrant"),
        compensator=text("enforce"),
        sham=boolean(False),
    )


def benign_envelope_selector() -> CellSelector:
    return CellSelector(input=text("assigned-case"))


def metric(
    identifier: str,
    component: str,
    stage: Stage,
) -> MetricContract:
    return MetricContract(
        id=identifier,
        component=component,
        stage=stage,
        value_type=MetricValueType.BOOLEAN,
        extractor_id=f"{identifier}.extractor",
        evidence_class="signed-event",
    )


def obligation(
    identifier: str,
    component: str,
    scope: ObligationScope,
    metric_id: str,
    expected: bool,
    *,
    selector: CellSelector | None = None,
    min_trials: int = 2,
) -> Obligation:
    return Obligation(
        id=identifier,
        subject=Subject(identifier=component, component=component),
        scope=scope,
        selector=selector or current_selector(),
        predicate=Predicate(
            metric_id=metric_id,
            operator=PredicateOperator.EQUAL,
            expected=boolean(expected),
        ),
        quantifier=AllTested(min_trials=min_trials),
    )


def valid_contract() -> ExperimentContract:
    now = datetime(2026, 7, 29, 12, tzinfo=UTC)
    digest = "sha256:" + "1" * 64
    target_metric = metric(
        "out-of-scope-records-selected",
        "authorization-policy",
        Stage.TARGET,
    )
    compensator_metric = metric(
        "unapproved-release-blocked",
        "release-gateway",
        Stage.COMPENSATOR,
    )
    outcome_metric = metric(
        "final-exfiltration",
        "client-receipt",
        Stage.OUTCOME,
    )
    benign_metric = metric(
        "assigned-case-available",
        "client-receipt",
        Stage.OUTCOME,
    )
    return ExperimentContract(
        id="financial-support-export",
        version="3.0.0",
        scope=ExperimentScope(
            scenario_id="financial-support-export",
            build_digest=digest,
            dataset_digest="sha256:" + "2" * 64,
            fixture_digest="sha256:" + "3" * 64,
            assessment_as_of=now,
            evidence_window=EvidenceWindow(
                start=now - timedelta(minutes=10),
                end=now + timedelta(minutes=10),
            ),
            evidence_policy=EvidencePolicyRef(
                id="lab-evidence",
                version="1",
                digest="sha256:" + "4" * 64,
            ),
        ),
        metrics=(
            target_metric,
            compensator_metric,
            outcome_metric,
            benign_metric,
        ),
        obligations=(
            obligation(
                "entitlement-current",
                "authorization-policy",
                ObligationScope.TARGET_LOCAL,
                target_metric.id,
                False,
            ),
            obligation(
                "release-guard-current",
                "release-gateway",
                ObligationScope.COMPENSATOR_LOCAL,
                compensator_metric.id,
                True,
            ),
            obligation(
                "tested-path-current",
                "client-receipt",
                ObligationScope.PATH,
                outcome_metric.id,
                False,
            ),
            obligation(
                "normal-support-current",
                "client-receipt",
                ObligationScope.PATH,
                benign_metric.id,
                True,
                    selector=benign_envelope_selector(),
            ),
        ),
        profile=PreventiveNonMaskingProfile(
            input=InputAxis(
                component="support-client",
                attack=text("malicious"),
                benign=text("assigned-case"),
                attack_action_digest="sha256:" + "8" * 64,
                benign_action_digest="sha256:" + "9" * 64,
            ),
            target=TargetControlAxis(
                component="authorization-policy",
                ineffective=text("wildcard-misgrant"),
                effective=text("case-scoped"),
                current=text("wildcard-misgrant"),
            ),
            compensator=CompensatorControlAxis(
                component="release-gateway",
                off=text("monitor-only"),
                on=text("enforce"),
                current=text("enforce"),
            ),
            sham=ShamAxis(steady=boolean(False), redeploy=boolean(True)),
            outcome_component="client-receipt",
            target_metric_id=target_metric.id,
            compensator_metric_id=compensator_metric.id,
            outcome_metric_id=outcome_metric.id,
            benign_outcome_metric_id=benign_metric.id,
            target_safe_value=boolean(False),
            compensator_safe_value=boolean(True),
            outcome_safe_value=boolean(False),
            benign_safe_value=boolean(True),
            primary_target_obligation_id="entitlement-current",
            primary_compensator_obligation_id="release-guard-current",
            primary_path_obligation_id="tested-path-current",
            primary_benign_obligation_id="normal-support-current",
            target_attack_relation=MetricRelation(operator=RelationOperator.TRUE_TO_FALSE),
            target_benign_relation=MetricRelation(operator=RelationOperator.EQUAL),
            sham_relation=MetricRelation(operator=RelationOperator.EQUAL),
            compensator_attack_relation=MetricRelation(operator=RelationOperator.TRUE_TO_FALSE),
        ),
        plan=TrialPlan(
            blocks=("fresh-clone-a",),
            replicates=2,
            order_seed="published-seed-2026-07-29",
        ),
    )


def replace_obligation(
    contract: ExperimentContract,
    replacement: Obligation,
) -> ExperimentContract:
    obligations = tuple(
        replacement if item.id == replacement.id else item for item in contract.obligations
    )
    return contract.model_copy(update={"obligations": obligations})


def test_compiler_owns_full_factorial_current_state_and_contrast_names() -> None:
    compiled = compile_experiment(valid_contract())

    assert len(compiled.cells) == 16
    assert len({cell.key for cell in compiled.cells}) == 16
    assert compiled.current_selector == current_selector()
    assert [contrast.id.value for contrast in compiled.contrasts] == [
        "target-attack-effect",
        "target-benign-invariance",
        "compensator-benign-invariance",
        "sham-invariance",
        "compensator-attack-effect",
    ]
    assert len(compiled.planned_trials) == 32
    assert [trial.ordinal for trial in compiled.planned_trials] == list(range(1, 33))
    assert len({trial.key for trial in compiled.planned_trials}) == 32


def test_each_generated_contrast_pair_changes_only_its_owned_axis() -> None:
    compiled = compile_experiment(valid_contract())
    cells = {cell.key: cell.selector for cell in compiled.cells}

    for contrast in compiled.contrasts:
        pair = contrast.pairs[0]
        reference = cells[pair.reference_cell_key]
        comparison = cells[pair.comparison_cell_key]
        changed = {
            axis
            for axis in ("input", "target", "compensator", "sham")
            if getattr(reference, axis) != getattr(comparison, axis)
        }
        assert changed == {contrast.varied_axis}


def test_target_local_obligation_cannot_be_wired_to_outcome() -> None:
    contract = valid_contract()
    original = contract.obligations[0]
    bad = original.model_copy(
        update={
            "predicate": original.predicate.model_copy(update={"metric_id": "final-exfiltration"})
        }
    )

    with pytest.raises(
        ContractCompileError,
        match="target_local obligation entitlement-current cannot use outcome metric",
    ):
        compile_experiment(replace_obligation(contract, bad))


@pytest.mark.parametrize("reserved_field", ["cells", "contrasts"])
def test_author_cannot_omit_cells_or_relabel_contrasts(reserved_field: str) -> None:
    payload = valid_contract().model_dump(mode="python")
    payload[reserved_field] = ()

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ExperimentContract.model_validate(payload, strict=True)


def test_primary_obligations_must_use_exact_generated_current_selector() -> None:
    contract = valid_contract()
    original = contract.obligations[0]
    bad = original.model_copy(
        update={
            "selector": original.selector.model_copy(
                update={"input": contract.profile.input.benign}
            )
        }
    )

    with pytest.raises(
        ContractCompileError,
        match="primary target obligation has the wrong exact selector",
    ):
        compile_experiment(replace_obligation(contract, bad))


def test_every_obligation_must_have_planned_coverage() -> None:
    contract = valid_contract()
    unplanned = obligation(
        "impossible-selector",
        "client-receipt",
        ObligationScope.PATH,
        "final-exfiltration",
        False,
        selector=CellSelector(input=text("not-a-declared-level")),
        min_trials=1,
    )
    bad = contract.model_copy(update={"obligations": (*contract.obligations, unplanned)})

    with pytest.raises(
        ContractCompileError,
        match="selector has undeclared input level",
    ):
        compile_experiment(bad)


def test_minimum_trials_cannot_exceed_the_generated_plan() -> None:
    contract = valid_contract()
    original = contract.obligations[2]
    bad = original.model_copy(update={"quantifier": AllTested(min_trials=3)})

    with pytest.raises(
        ContractCompileError,
        match="requires 3 trials but the plan contains 2",
    ):
        compile_experiment(replace_obligation(contract, bad))


def test_typo_fields_are_rejected_on_creation_and_assignment_is_validated() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        MetricContract(
            id="decision",
            component="authorization-policy",
            stage=Stage.TARGET,
            value_type=MetricValueType.BOOLEAN,
            extractor_id="decision.extractor",
            evidence_class="signed-event",
            compnent="misspelled",  # type: ignore[call-arg]
        )

    contract = valid_contract()
    with pytest.raises(ValidationError):
        contract.plan.replicates = 0


@pytest.mark.parametrize(
    "value",
    [
        0.5,
        float("nan"),
        float("inf"),
        "NaN",
        "Infinity",
        Decimal("NaN"),
    ],
)
def test_decimal_values_reject_float_nan_and_infinity(value: object) -> None:
    with pytest.raises(ValidationError):
        DecimalValue(value=value)  # type: ignore[arg-type]


def test_integer_values_do_not_coerce_float_or_boolean() -> None:
    with pytest.raises(ValidationError):
        IntegerValue(value=1.0)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        IntegerValue(value=True)


def test_decimal_serialization_and_spec_digest_are_semantic() -> None:
    assert DecimalValue.model_validate(
        {"value": "1.25"},
        strict=True,
    ).model_dump(mode="json") == {
        "type": "decimal",
        "value": "1.25",
    }
    assert DecimalValue(value=Decimal("1.2500")).model_dump(mode="json") == {
        "type": "decimal",
        "value": "1.25",
    }

    first = valid_contract()
    reordered = first.model_copy(
        update={
            "metrics": tuple(reversed(first.metrics)),
            "obligations": tuple(reversed(first.obligations)),
        }
    )
    assert compile_experiment(first).spec_digest == compile_experiment(reordered).spec_digest

    changed = first.model_copy(
        update={"plan": first.plan.model_copy(update={"order_seed": "different-published-seed"})}
    )
    assert compile_experiment(first).spec_digest != compile_experiment(changed).spec_digest


@pytest.mark.parametrize(
    "field",
    ["target_attack_relation", "compensator_attack_relation"],
)
def test_effect_relations_must_be_directional(field: str) -> None:
    contract = valid_contract()
    profile = contract.profile.model_copy(
        update={
            field: MetricRelation(operator=RelationOperator.EQUAL),
        }
    )

    with pytest.raises(ContractCompileError, match="directional relation"):
        compile_experiment(contract.model_copy(update={"profile": profile}))


def test_direction_must_match_metric_type() -> None:
    contract = valid_contract()
    profile = contract.profile.model_copy(
        update={"target_attack_relation": MetricRelation(operator=RelationOperator.DECREASES)}
    )

    with pytest.raises(ContractCompileError, match="incompatible with boolean"):
        compile_experiment(contract.model_copy(update={"profile": profile}))


def test_boolean_effect_direction_must_end_at_the_declared_safe_value() -> None:
    contract = valid_contract()
    profile = contract.profile.model_copy(
        update={
            "target_safe_value": boolean(True),
            "target_attack_relation": MetricRelation(
                operator=RelationOperator.TRUE_TO_FALSE
            ),
        }
    )

    with pytest.raises(ContractCompileError, match="moves away"):
        compile_experiment(contract.model_copy(update={"profile": profile}))


def test_attack_and_benign_actions_need_distinct_semantic_digests() -> None:
    contract = valid_contract()
    input_axis = contract.profile.input.model_copy(
        update={
            "benign_action_digest": contract.profile.input.attack_action_digest,
        }
    )
    profile = contract.profile.model_copy(update={"input": input_axis})

    with pytest.raises(ContractCompileError, match="distinct digests"):
        compile_experiment(contract.model_copy(update={"profile": profile}))


def test_primary_obligations_are_bound_to_safe_meaning() -> None:
    contract = valid_contract()
    path = contract.obligations[2]
    inverted = path.model_copy(
        update={"predicate": path.predicate.model_copy(update={"expected": boolean(True)})}
    )
    with pytest.raises(ContractCompileError, match="declared safe value"):
        compile_experiment(replace_obligation(contract, inverted))

    weakened = path.model_copy(update={"quantifier": Exists(min_trials=1)})
    with pytest.raises(ContractCompileError, match="must use all_tested"):
        compile_experiment(replace_obligation(contract, weakened))

    with pytest.raises(ValidationError, match="rate must be in"):
        AtLeastRate(rate=DecimalValue(value=Decimal("0")), min_trials=1)


def test_benign_primary_and_distinct_semantic_roles_are_required() -> None:
    contract = valid_contract()
    without_benign = contract.model_copy(update={"obligations": contract.obligations[:-1]})
    with pytest.raises(ContractCompileError, match="benign path obligation does not exist"):
        compile_experiment(without_benign)

    aliased = contract.profile.model_copy(
        update={"benign_outcome_metric_id": contract.profile.outcome_metric_id}
    )
    with pytest.raises(ContractCompileError, match="metrics must be distinct"):
        compile_experiment(contract.model_copy(update={"profile": aliased}))

    collapsed = contract.profile.model_copy(
        update={
            "compensator": contract.profile.compensator.model_copy(
                update={"component": contract.profile.target.component}
            )
        }
    )
    with pytest.raises(ContractCompileError, match="components must be distinct"):
        compile_experiment(contract.model_copy(update={"profile": collapsed}))


def test_compiled_contract_graph_is_frozen() -> None:
    compiled = compile_experiment(valid_contract())

    with pytest.raises(ValidationError, match="frozen"):
        compiled.spec_digest = "sha256:" + "0" * 64
    with pytest.raises(ValidationError, match="frozen"):
        compiled.contract.profile.target.ineffective.value = "case-scoped"


@pytest.mark.parametrize(
    "update",
    [
        {"version": "999"},
        {"id": "different-scenario"},
    ],
)
def test_contract_version_and_scenario_identity_are_exact(
    update: dict[str, str],
) -> None:
    contract = valid_contract().model_copy(update=update)

    with pytest.raises(ContractCompileError, match="revalidation failed"):
        compile_experiment(contract)


def test_numeric_and_factorial_resources_are_bounded() -> None:
    with pytest.raises(ValidationError):
        IntegerValue(value=I_JSON_MAX_INTEGER + 1)

    contract = valid_contract()
    plan = TrialPlan(
        blocks=tuple(f"block-{index}" for index in range(MAX_BLOCKS)),
        replicates=MAX_REPLICATES,
        order_seed="bounded-seed",
    )
    with pytest.raises(ContractCompileError, match="trial plan expands"):
        compile_experiment(contract.model_copy(update={"plan": plan}))


def test_canonicalization_errors_use_the_contract_error_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_canonicalization(_: object) -> bytes:
        raise contract_module.rfc8785.CanonicalizationError("invalid canonical value")

    monkeypatch.setattr(contract_module.rfc8785, "dumps", fail_canonicalization)
    with pytest.raises(ContractCompileError, match="canonicalization failed"):
        compile_experiment(valid_contract())
