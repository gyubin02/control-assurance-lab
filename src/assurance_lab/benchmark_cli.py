"""CLI plumbing for building and independently reopening public benchmarks."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Literal

from assurance_lab.benchmark.release_builder import (
    VerifiedPublicRelease,
    build_public_release,
    verify_public_release,
)
from assurance_lab.evidence.canonical import canonical_json_bytes


def add_benchmark_parser(
    commands: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register the public benchmark release command tree."""

    benchmark = commands.add_parser(
        "benchmark",
        help="build and independently verify the public benchmark release",
    )
    benchmark_areas = benchmark.add_subparsers(
        dest="benchmark_area",
        required=True,
    )
    release = benchmark_areas.add_parser(
        "release",
        help="operate on a content-closed public benchmark release",
    )
    release_actions = release.add_subparsers(
        dest="benchmark_release_action",
        required=True,
    )
    build = release_actions.add_parser(
        "build",
        help="build, verify, and atomically publish a new release directory",
    )
    build.add_argument(
        "directory",
        metavar="RELEASE_DIR",
        help="new destination directory; an existing path is never replaced",
    )
    build.add_argument("--json", action="store_true", help="emit canonical JSON")

    verify = release_actions.add_parser(
        "verify",
        help="reopen and independently verify an existing release directory",
    )
    verify.add_argument(
        "directory",
        metavar="RELEASE_DIR",
        help="existing release directory; verification never modifies it",
    )
    verify.add_argument("--json", action="store_true", help="emit canonical JSON")


def run_benchmark_release(arguments: argparse.Namespace) -> int:
    """Run one release action and emit output only after full verification."""

    requested = Path(arguments.directory)
    result: VerifiedPublicRelease
    if arguments.benchmark_release_action == "build":
        operation: Literal["build", "verify"] = "build"
        result = build_public_release(requested)
    elif arguments.benchmark_release_action == "verify":
        operation = "verify"
        result = verify_public_release(requested)
    else:
        raise ValueError("unsupported benchmark release action")

    if arguments.json:
        sys.stdout.write(canonical_json_bytes(_result_document(result, operation)).decode("utf-8"))
    else:
        _print_human(result, operation)
    return 0


def _result_document(
    result: VerifiedPublicRelease,
    operation: Literal["build", "verify"],
) -> dict[str, Any]:
    return {
        "schema": "assurance-lab.benchmark.release-cli-result/v1",
        "operation": operation,
        "status": "verified",
        "release_digest": result.release_digest,
        "release_manifest_digest": result.release_manifest_digest,
        "index_digest": result.index_digest,
        "corpus_digest": result.corpus_digest,
        "semantic_verification_receipt_digest": (result.semantic_verification_receipt_digest),
        "corruptions": {
            "rejected": result.rejected_count,
            "indeterminate": result.indeterminate_count,
            "conflicting": result.conflicting_count,
        },
    }


def _print_human(
    result: VerifiedPublicRelease,
    operation: Literal["build", "verify"],
) -> None:
    action = "BUILT AND VERIFIED" if operation == "build" else "VERIFIED"
    print(f"Benchmark release  {action}")
    print(f"Release digest     {result.release_digest}")
    print(f"Manifest digest    {result.release_manifest_digest}")
    print(f"Index digest       {result.index_digest}")
    print(f"Corpus digest      {result.corpus_digest}")
    print(f"Semantic receipt   {result.semantic_verification_receipt_digest}")
    print(
        "Corruptions        "
        f"{result.rejected_count} rejected · "
        f"{result.indeterminate_count} indeterminate · "
        f"{result.conflicting_count} conflicting"
    )
    print(f"Directory          {result.root}")


__all__ = ["add_benchmark_parser", "run_benchmark_release"]
