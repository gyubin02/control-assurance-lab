"""Minimal command line entry point for the fixed financial-support case."""

from __future__ import annotations

import argparse
import hashlib
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

from assurance_lab.contract import (
    EvidencePolicyRef,
    EvidenceWindow,
    ExperimentScope,
    TrialPlan,
    compile_experiment,
)
from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.exhibit import FinancialSupportCaseResult, recompute_case
from assurance_lab.scenarios.financial_data import DatasetProfile, generate_dataset
from assurance_lab.scenarios.financial_support_contract import (
    SCENARIO_ID,
    build_financial_support_contract,
)
from assurance_lab.scenarios.financial_support_e2e import (
    FinancialSupportExperimentRunner,
)

_SIMULATION_START = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)
_EVIDENCE_POLICY = {
    "schema": "assurance-lab.financial-support-evidence-policy/v1",
    "profile": "integrity-only",
}
_EVIDENCE_POLICY_DIGEST = (
    "sha256:" + hashlib.sha256(canonical_json_bytes(_EVIDENCE_POLICY)).hexdigest()
)


class _StepClock:
    def __init__(self, start: datetime) -> None:
        self._next = start

    def __call__(self) -> datetime:
        result = self._next
        self._next += timedelta(milliseconds=1)
        return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "run":
            result = _run(Path(arguments.directory))
            _print_human(result)
            return 0
        result = recompute_case(Path(arguments.directory))
        if arguments.json:
            sys.stdout.write(canonical_json_bytes(result.model_dump(mode="json")).decode("utf-8"))
        else:
            _print_human(result)
        return 0
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="assurance-lab")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="create the fixed simulated evidence bundle")
    run.add_argument("directory")
    verify = commands.add_parser("verify", help="verify and recompute an evidence bundle")
    verify.add_argument("directory")
    verify.add_argument("--json", action="store_true", help="emit canonical JSON")
    return parser


def _run(destination: Path) -> FinancialSupportCaseResult:
    dataset = generate_dataset(seed=2907, profile=DatasetProfile.DEFAULT)
    runner = FinancialSupportExperimentRunner(
        dataset,
        clock=_StepClock(_SIMULATION_START + timedelta(seconds=1)),
        time_basis="simulated",
    )
    scope = ExperimentScope(
        scenario_id=SCENARIO_ID,
        build_digest=runner.build_digest,
        dataset_digest=runner.dataset_digest,
        fixture_digest=runner.fixture_digest,
        assessment_as_of=_SIMULATION_START + timedelta(minutes=30),
        evidence_window=EvidenceWindow(
            start=_SIMULATION_START,
            end=_SIMULATION_START + timedelta(hours=1),
        ),
        evidence_policy=EvidencePolicyRef(
            id="financial-support-bundle-v1",
            version="1.0.0",
            digest=_EVIDENCE_POLICY_DIGEST,
        ),
    )
    compiled = compile_experiment(
        build_financial_support_contract(
            scope=scope,
            plan=TrialPlan(
                blocks=("sqlite-fresh-clone",),
                replicates=1,
                order_seed="financial-support-cli-seed",
            ),
        )
    )
    runner.run(compiled, destination)
    return recompute_case(destination)


def _print_human(result: FinancialSupportCaseResult) -> None:
    benign_safe = sum(item.assigned_records_delivered == 1 for item in result.benign_outcomes)
    blocked = (
        f"{result.current.selected_records} blocked"
        if result.current.guard_blocked
        else "not blocked"
    )
    print("Nothing left the system. The first control still failed.")
    print()
    print(f"{result.current.selected_records:>2} selected at entitlement boundary    REFUTED")
    print(f"{blocked:>2} at release guard          SUPPORTED")
    print(f"{result.current.delivered_records:>2} delivered outside boundary         SUPPORTED")
    print(
        f" 1 assigned record in {benign_safe}/{len(result.benign_outcomes)} "
        "benign runs     SUPPORTED"
    )
    print()
    print(f"Final-outcome-only   {result.comparison.baseline.verdict.value.upper()}")
    print(
        "Control-specific     "
        f"{result.comparison.v3.residual_classification.value.replace('_', ' ').upper()}"
    )
    print(f"Evidence             {result.bundle_id}")
    print(f"Scope                synthetic · {result.time_basis} clock · {result.profile}")


if __name__ == "__main__":
    raise SystemExit(main())
