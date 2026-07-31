from __future__ import annotations

import re
from pathlib import Path

import pytest

from assurance_lab.contract import CellSelector
from assurance_lab.scenarios.financial_data import (
    DatasetProfile,
    generate_dataset,
)
from assurance_lab.scenarios.financial_recovery_contract import (
    ATTACK,
    COMPENSATOR_ON,
    SHAM_STEADY,
    TARGET_INEFFECTIVE,
)
from assurance_lab.scenarios.financial_recovery_e2e import (
    write_reference_recovery_lifecycle_bundle,
)
from assurance_lab.scenarios.financial_recovery_runtime import (
    FinancialRecoveryRuntime,
)


@pytest.fixture
def runtime(tmp_path: Path) -> FinancialRecoveryRuntime:
    evidence = write_reference_recovery_lifecycle_bundle(tmp_path / "lifecycle.cab")
    return FinancialRecoveryRuntime(
        generate_dataset(seed=2907, profile=DatasetProfile.DEFAULT),
        cutover_fixtures=evidence.cutover_fixtures(),
    )


def _selector() -> CellSelector:
    return CellSelector(
        input=ATTACK,
        target=TARGET_INEFFECTIVE,
        compensator=COMPENSATOR_ON,
        sham=SHAM_STEADY,
    )


def test_default_clone_nonce_remains_fresh_and_valid(
    runtime: FinancialRecoveryRuntime,
) -> None:
    first = runtime.execute(_selector(), trace_id="default-nonce-a")
    second = runtime.execute(_selector(), trace_id="default-nonce-b")

    assert re.fullmatch(r"[a-f0-9]{32}", first.clone_nonce)
    assert re.fullmatch(r"[a-f0-9]{32}", second.clone_nonce)
    assert first.clone_nonce != second.clone_nonce


def test_injected_clone_nonce_is_exact_and_repeatable(
    runtime: FinancialRecoveryRuntime,
) -> None:
    nonce = "0123456789abcdef0123456789abcdef"
    first = runtime.execute(
        _selector(),
        trace_id="deterministic-nonce",
        clone_nonce=nonce,
    )
    second = runtime.execute(
        _selector(),
        trace_id="deterministic-nonce",
        clone_nonce=nonce,
    )

    assert first == second
    assert first.clone_nonce == nonce
    assert first.clone_id == second.clone_id


@pytest.mark.parametrize(
    "invalid",
    (
        "",
        "0" * 31,
        "0" * 33,
        "ABCDEF0123456789ABCDEF0123456789",
        "g" * 32,
        "\uff10" * 32,
    ),
)
def test_injected_clone_nonce_rejects_noncanonical_values(
    runtime: FinancialRecoveryRuntime,
    invalid: str,
) -> None:
    with pytest.raises(
        ValueError,
        match="exactly 32 lowercase hexadecimal",
    ):
        runtime.execute(
            _selector(),
            trace_id="invalid-nonce",
            clone_nonce=invalid,
        )
