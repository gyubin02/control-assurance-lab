from __future__ import annotations

from datetime import UTC, datetime, timedelta

from assurance_lab.contract import (
    CellSelector,
    ContrastId,
    EvidencePolicyRef,
    EvidenceWindow,
    ExperimentScope,
    TrialPlan,
    compile_experiment,
)
from assurance_lab.scenarios.financial_support_contract import (
    ATTACK,
    ATTACK_ACTION_DIGEST,
    BENIGN,
    BENIGN_ACTION_DIGEST,
    COMPENSATOR_OFF,
    COMPENSATOR_ON,
    SCENARIO_ID,
    SHAM_STEADY,
    TARGET_EFFECTIVE,
    TARGET_INEFFECTIVE,
    build_financial_support_contract,
)


def _digest(fill: str) -> str:
    return f"sha256:{fill * 64}"


def _compiled():
    start = datetime(2026, 7, 28, 0, 0, tzinfo=UTC)
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
    contract = build_financial_support_contract(
        scope=scope,
        plan=TrialPlan(
            blocks=("fresh-clone-a",),
            replicates=2,
            order_seed="financial-support-published-seed",
        ),
    )
    return compile_experiment(contract)


def test_financial_contract_compiles_to_the_owned_factorial() -> None:
    compiled = _compiled()

    assert len(compiled.cells) == 16
    assert len(compiled.planned_trials) == 32
    assert compiled.current_selector == CellSelector(
        input=ATTACK,
        target=TARGET_INEFFECTIVE,
        compensator=COMPENSATOR_ON,
        sham=SHAM_STEADY,
    )
    assert [contrast.id for contrast in compiled.contrasts] == [
        ContrastId.TARGET_ATTACK_EFFECT,
        ContrastId.TARGET_BENIGN_INVARIANCE,
        ContrastId.COMPENSATOR_BENIGN_INVARIANCE,
        ContrastId.SHAM_INVARIANCE,
        ContrastId.COMPENSATOR_ATTACK_EFFECT,
    ]


def test_financial_contract_states_the_non_masking_comparisons() -> None:
    compiled = _compiled()
    cells = {cell.key: cell.selector for cell in compiled.cells}
    contrasts = {contrast.id: contrast for contrast in compiled.contrasts}

    target_pair = contrasts[ContrastId.TARGET_ATTACK_EFFECT].pairs[0]
    assert cells[target_pair.reference_cell_key] == CellSelector(
        input=ATTACK,
        target=TARGET_INEFFECTIVE,
        compensator=COMPENSATOR_OFF,
        sham=SHAM_STEADY,
    )
    assert cells[target_pair.comparison_cell_key] == CellSelector(
        input=ATTACK,
        target=TARGET_EFFECTIVE,
        compensator=COMPENSATOR_OFF,
        sham=SHAM_STEADY,
    )

    guard_pair = contrasts[ContrastId.COMPENSATOR_ATTACK_EFFECT].pairs[0]
    assert cells[guard_pair.reference_cell_key] == CellSelector(
        input=ATTACK,
        target=TARGET_INEFFECTIVE,
        compensator=COMPENSATOR_OFF,
        sham=SHAM_STEADY,
    )
    assert cells[guard_pair.comparison_cell_key] == CellSelector(
        input=ATTACK,
        target=TARGET_INEFFECTIVE,
        compensator=COMPENSATOR_ON,
        sham=SHAM_STEADY,
    )


def test_financial_contract_digest_is_reproducible() -> None:
    first = _compiled()
    second = _compiled()

    assert first.spec_digest == second.spec_digest
    assert first.canonical_spec == second.canonical_spec
    assert tuple(trial.key for trial in first.planned_trials) == tuple(
        trial.key for trial in second.planned_trials
    )
    assert first.contract.profile.input.attack_action_digest == ATTACK_ACTION_DIGEST
    assert first.contract.profile.input.benign_action_digest == BENIGN_ACTION_DIGEST
    assert ATTACK_ACTION_DIGEST != BENIGN_ACTION_DIGEST


def test_primary_obligations_are_current_and_do_not_hide_service_loss() -> None:
    compiled = _compiled()
    by_id = {item.id: item for item in compiled.contract.obligations}
    profile = compiled.contract.profile

    assert by_id[profile.primary_target_obligation_id].selector == compiled.current_selector
    assert by_id[profile.primary_compensator_obligation_id].selector == (
        compiled.current_selector
    )
    assert by_id[profile.primary_path_obligation_id].selector == compiled.current_selector
    assert by_id[profile.primary_benign_obligation_id].selector == CellSelector(
        input=BENIGN
    )
    coverage = {
        item.obligation_id: item.trial_keys for item in compiled.obligation_coverage
    }
    assert len(coverage[profile.primary_benign_obligation_id]) == 16
