from __future__ import annotations

from pathlib import Path

import pytest

from assurance_lab._version import __version__
from assurance_lab.baseline import BaselineVerdict
from assurance_lab.cli import main
from assurance_lab.contract import BooleanValue, IntegerValue, Stage
from assurance_lab.evaluation import ResidualClassification, TruthValue
from assurance_lab.evidence.canonical import (
    canonical_json_bytes,
    strict_json_loads,
)
from assurance_lab.exhibit import (
    CaseLimitation,
    CurrentRequestSummary,
    FinancialSupportCaseResult,
    GuardState,
    recompute_case,
)
from assurance_lab.scenarios.financial_support_contract import (
    ATTACK,
    ATTACK_ACTION_DIGEST,
    COMPENSATOR_OFF,
    COMPENSATOR_ON,
    TARGET_EFFECTIVE,
    TARGET_INEFFECTIVE,
)


def test_cli_run_then_verify_recomputes_one_bundle_derived_case(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle_root = tmp_path / "case-bundle"

    assert main(["run", str(bundle_root)]) == 0
    run_output = capsys.readouterr().out
    assert "Nothing left the system. The first control still failed." in run_output
    assert (
        "Request               out-of-case-bulk-export · support-017 · 10 customers x 1 record"
    ) in run_output
    assert "Entitlement boundary  10 out-of-scope records selected    REFUTED" in run_output
    assert "Release guard         release blocked" in run_output
    assert "Outside boundary      0 out-of-scope records delivered   SUPPORTED" in run_output
    assert "Benign service        1 assigned record · 8/8 runs" in run_output
    assert "Control-specific     MASKED TARGET FAILURE" in run_output

    result = recompute_case(bundle_root)
    assert result.comparison.baseline.verdict == BaselineVerdict.PASS
    assert result.comparison.v3.target_truth == TruthValue.REFUTED
    assert (
        result.comparison.v3.residual_classification == ResidualClassification.MASKED_TARGET_FAILURE
    )
    assert result.invariant.holds
    assert result.current.selected_records == 10
    assert result.current.guard_blocked
    assert result.current.delivered_records == 0
    assert result.current_request.action == ATTACK.value
    assert result.current_request.action_digest == ATTACK_ACTION_DIGEST
    assert result.current_request.principal_id == "support-017"
    assert result.current_request.role == "support"
    assert result.current_request.data_class == "customer_confidential"
    assert result.current_request.requested_customer_count == 10
    assert result.current_request.records_per_customer == 1
    assert result.current_request.requested_customer_ids == tuple(
        f"SYNTH-CUSTOMER-{index:06d}" for index in range(21, 31)
    )
    tampered_request = result.current_request.model_dump()
    requested_customer_ids = list(tampered_request["requested_customer_ids"])
    requested_customer_ids[0] = "SYNTH-CUSTOMER-000031"
    tampered_request["requested_customer_ids"] = tuple(requested_customer_ids)
    with pytest.raises(
        ValueError,
        match="current request summary differs from its action digest",
    ):
        CurrentRequestSummary.model_validate(tampered_request, strict=True)
    assert len(result.benign_outcomes) == 8
    assert {observation.assigned_records_delivered for observation in result.benign_outcomes} == {1}
    assert result.profile == "integrity-only"
    assert result.time_basis == "simulated"
    assert set(result.limitations) == {
        CaseLimitation.SIMULATED_TIME,
        CaseLimitation.INTEGRITY_ONLY,
        CaseLimitation.SINGLE_SYNTHETIC_SCENARIO,
    }

    matrix = {
        (item.target_level, item.compensator_level): item for item in result.steady_attack_matrix
    }
    assert len(matrix) == 4
    assert matrix[(TARGET_INEFFECTIVE.value, COMPENSATOR_OFF.value)].selected_records == 10
    assert (
        matrix[(TARGET_INEFFECTIVE.value, COMPENSATOR_OFF.value)].guard_state
        == GuardState.EXECUTED_ALLOWED
    )
    assert matrix[(TARGET_INEFFECTIVE.value, COMPENSATOR_OFF.value)].delivered_records == 10
    assert (
        matrix[(TARGET_INEFFECTIVE.value, COMPENSATOR_ON.value)].guard_state
        == GuardState.EXECUTED_BLOCKED
    )
    assert matrix[(TARGET_INEFFECTIVE.value, COMPENSATOR_ON.value)].delivered_records == 0
    for compensator in (COMPENSATOR_OFF.value, COMPENSATOR_ON.value):
        effective = matrix[(TARGET_EFFECTIVE.value, compensator)]
        assert effective.selected_records == 0
        assert effective.guard_state == GuardState.SKIPPED_BY_TARGET
        assert effective.compensator_artifact_digest is None
        assert effective.delivered_records == 0

    claims = {item.role: item for item in result.primary_claims}
    assert set(claims) == {"target", "guard", "path", "benign"}
    assert claims["target"].truth == TruthValue.REFUTED
    assert claims["guard"].truth == TruthValue.SUPPORTED
    assert claims["path"].truth == TruthValue.SUPPORTED
    assert claims["benign"].truth == TruthValue.SUPPORTED
    assert all(item.evidence_ids for item in claims.values())

    artifact_coordinates = {(item.trial_key, item.stage) for item in result.stage_artifacts}
    assert len(result.stage_artifacts) == 60
    assert len({item.artifact_digest for item in result.stage_artifacts}) == 60
    assert all(
        (observation.trial_key, observation.stage) in artifact_coordinates
        for observation in result.comparison.raw_observations
    )
    current_raw = {
        (observation.stage, observation.metric_id): observation.value
        for observation in result.comparison.raw_observations
        if observation.trial_key == result.current.trial_key
    }
    profile = result.evaluation.compiled_experiment.contract.profile
    assert current_raw[(Stage.TARGET, profile.target_metric_id)] == IntegerValue(value=10)
    assert current_raw[(Stage.COMPENSATOR, profile.compensator_metric_id)] == BooleanValue(
        value=True
    )
    assert current_raw[(Stage.OUTCOME, profile.outcome_metric_id)] == IntegerValue(value=0)
    assert result.comparison.spec_digest == (result.evaluation.compiled_experiment.spec_digest)

    assert main(["verify", str(bundle_root)]) == 0
    verify_output = capsys.readouterr().out
    assert f"Evidence             {result.bundle_id}" in verify_output
    assert "Scope                synthetic · simulated clock · integrity-only" in verify_output

    assert main(["verify", str(bundle_root), "--json"]) == 0
    json_output = capsys.readouterr().out.encode("utf-8")
    parsed = strict_json_loads(json_output)
    assert canonical_json_bytes(parsed) == json_output
    from_cli = FinancialSupportCaseResult.model_validate_json(
        json_output,
        strict=True,
    )
    assert from_cli == result


def test_checked_in_case_view_is_exactly_recomputed_from_the_example_bundle() -> None:
    repository_root = Path(__file__).parents[1]
    result = recompute_case(repository_root / "examples" / "masked-export.cab")
    checked_in = (repository_root / "web" / "case.json").read_bytes()

    assert canonical_json_bytes(result.model_dump(mode="json")) == checked_in


def test_cli_reports_the_installed_package_version(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])

    assert exit_info.value.code == 0
    assert capsys.readouterr().out == f"assurance-lab {__version__}\n"
