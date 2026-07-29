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
from assurance_lab.offline_cli import (
    run_cab_snapshot_create,
    run_cab_snapshot_verify,
    run_dsse_verify,
)
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
        if arguments.command == "dsse":
            return run_dsse_verify(
                envelope_path=Path(arguments.envelope),
                policy_path=Path(arguments.policy),
                payload_path=Path(arguments.payload),
                payload_type=arguments.payload_type,
                admission_time=arguments.admission_time,
                json_output=arguments.json,
            )
        if arguments.command == "cab":
            if arguments.snapshot_command == "create":
                return run_cab_snapshot_create(
                    source=Path(arguments.source),
                    output=Path(arguments.output),
                )
            return run_cab_snapshot_verify(
                snapshot_path=Path(arguments.snapshot),
                json_output=arguments.json,
            )
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

    dsse = commands.add_parser("dsse", help="offline DSSE operations")
    dsse_commands = dsse.add_subparsers(dest="dsse_command", required=True)
    dsse_verify = dsse_commands.add_parser(
        "verify",
        help="verify exact expected bytes under an external trust policy",
    )
    dsse_verify.add_argument("--envelope", required=True)
    dsse_verify.add_argument("--policy", required=True)
    dsse_verify.add_argument("--payload", required=True)
    dsse_verify.add_argument("--payload-type", required=True)
    dsse_verify.add_argument(
        "--at",
        dest="admission_time",
        required=True,
        metavar="RFC3339",
        help="caller-trusted verification instant",
    )
    dsse_verify.add_argument("--json", action="store_true", help="emit canonical JSON")

    cab = commands.add_parser("cab", help="offline CAB operations")
    cab_commands = cab.add_subparsers(dest="cab_command", required=True)
    snapshot = cab_commands.add_parser("snapshot", help="seal or verify exact CAB bytes")
    snapshot_commands = snapshot.add_subparsers(dest="snapshot_command", required=True)
    snapshot_create = snapshot_commands.add_parser(
        "create",
        help="capture and self-verify a CAB directory",
    )
    snapshot_create.add_argument("source")
    snapshot_create.add_argument("--out", dest="output", required=True)
    snapshot_verify = snapshot_commands.add_parser(
        "verify",
        help="verify a sealed CAB snapshot",
    )
    snapshot_verify.add_argument("snapshot")
    snapshot_verify.add_argument("--json", action="store_true", help="emit canonical JSON")
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
    claims = {item.role: item.truth.value.upper() for item in result.primary_claims}
    guard_value = "release blocked" if result.current.guard_blocked else "release allowed"
    print("Nothing left the system. The first control still failed.")
    print()
    print(
        f"Request               {result.current_request.action} · "
        f"{result.current_request.principal_id} · "
        f"{result.current_request.requested_customer_count} customers x "
        f"{result.current_request.records_per_customer} record"
    )
    print(
        f"Entitlement boundary  {result.current.selected_records} "
        f"out-of-scope records selected    {claims['target']}"
    )
    print(f"Release guard         {guard_value:<31}{claims['guard']}")
    print(
        f"Outside boundary      {result.current.delivered_records} "
        f"out-of-scope records delivered   {claims['path']}"
    )
    print(
        f"Benign service        1 assigned record · "
        f"{benign_safe}/{len(result.benign_outcomes)} runs         {claims['benign']}"
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
