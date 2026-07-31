from __future__ import annotations

import json
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from assurance_lab.evidence.bundle import (
    BundleStatus,
    EvaluationRef,
    EvaluatorRef,
    ExperimentRef,
    Sensitivity,
    verify_bundle,
)
from assurance_lab.evidence.canonical import canonical_json_bytes, canonical_jsonl_bytes
from assurance_lab.evidence.writer import BundleMetadata, PayloadFile, write_bundle

PROJECT_ROOT = Path(__file__).resolve().parents[1]
NODE_VERIFIER = PROJECT_ROOT / "verifier-js" / "src" / "cli.js"
EXAMPLE_BUNDLE = PROJECT_ROOT / "examples" / "masked-export.cab"


def _node() -> str:
    executable = shutil.which("node")
    if executable is None:
        pytest.skip("Node.js is required for cross-language verifier conformance")
    return executable


def _verify_with_node(bundle: Path) -> tuple[int, dict[str, Any]]:
    completed = subprocess.run(
        (_node(), str(NODE_VERIFIER), str(bundle)),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if not completed.stdout:
        pytest.fail(f"Node verifier produced no JSON: {completed.stderr}")
    return completed.returncode, json.loads(completed.stdout)


def _metadata() -> BundleMetadata:
    as_of = datetime(2026, 7, 29, 5, 0, tzinfo=UTC)
    return BundleMetadata(
        created_at=as_of + timedelta(seconds=1),
        as_of=as_of,
        experiment=ExperimentRef(
            id="cross-language-canonical-boundary",
            spec_version="1.0.0",
            spec_digest="sha256:" + "1" * 64,
        ),
        evaluation=EvaluationRef(
            policy_id="integrity-only-v1",
            policy_digest="sha256:" + "2" * 64,
            evaluator=EvaluatorRef(
                name="python-conformance-writer",
                version="1.0.0",
                source_revision="test-fixture",
                image_digest=None,
            ),
        ),
    )


def test_checked_in_example_has_one_cross_language_content_address() -> None:
    python_result = verify_bundle(EXAMPLE_BUNDLE)
    return_code, node_result = _verify_with_node(EXAMPLE_BUNDLE)

    assert python_result.status == BundleStatus.INTEGRITY_VERIFIED
    assert return_code == 0
    assert node_result["status"] == python_result.status.value
    assert node_result["bundle_id"] == python_result.bundle_id
    assert node_result["issues"] == []


def test_python_writer_and_node_verifier_share_canonical_unicode_boundaries(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "unicode-boundary.cab"
    json_payload = canonical_json_bytes(
        {
            "id": "canonical-edge",
            "numbers": [333333333.3333333, 4.5, 0.002, 1e-27],
            "supplementary_plane": "\U00010000",
            "private_use": "\ue000",
        }
    )
    jsonl_payload = canonical_jsonl_bytes(
        (
            {"id": "\U00010000", "value": "supplementary-plane"},
            {"id": "\ue000", "value": "private-use"},
        )
    )
    python_written = write_bundle(
        bundle,
        metadata=_metadata(),
        payloads=(
            PayloadFile(
                path="records/unicode-order.jsonl",
                content=jsonl_payload,
                media_type="application/x-ndjson",
                role="cross-language Unicode ordering boundary",
                sensitivity=Sensitivity.SYNTHETIC,
                required_for=("canonical-conformance",),
            ),
            PayloadFile(
                path="spec/canonical-values.json",
                content=json_payload,
                media_type="application/json",
                role="cross-language RFC 8785 value boundary",
                sensitivity=Sensitivity.SYNTHETIC,
                required_for=("canonical-conformance",),
            ),
        ),
    )

    return_code, node_result = _verify_with_node(bundle)

    assert python_written.status == BundleStatus.INTEGRITY_VERIFIED
    assert python_written.bundle_id is not None
    assert return_code == 0
    assert node_result["status"] == python_written.status.value
    assert node_result["bundle_id"] == python_written.bundle_id
    assert node_result["observed"] == {
        "manifest_sha256": python_written.bundle_id.removeprefix("cab:sha256:"),
        "payload_bytes": len(json_payload) + len(jsonl_payload),
        "payload_count": 2,
    }


def test_both_verifiers_reject_the_same_payload_corruption(tmp_path: Path) -> None:
    bundle = tmp_path / "corrupt.cab"
    write_bundle(
        bundle,
        metadata=_metadata(),
        payloads=(
            PayloadFile(
                path="records/value.json",
                content=canonical_json_bytes({"id": "before", "value": 1}),
                media_type="application/json",
                role="corruption parity fixture",
                sensitivity=Sensitivity.SYNTHETIC,
                required_for=("integrity",),
            ),
        ),
    )
    (bundle / "records" / "value.json").write_bytes(
        canonical_json_bytes({"id": "after", "value": 2})
    )

    python_result = verify_bundle(bundle)
    return_code, node_result = _verify_with_node(bundle)

    assert python_result.status == BundleStatus.CORRUPT
    assert return_code == 1
    assert node_result["status"] == python_result.status.value
    assert node_result["bundle_id"] == python_result.bundle_id
    assert {issue["code"] for issue in node_result["issues"]} >= {
        "digest-mismatch",
        "size-mismatch",
    }


def test_both_verifiers_prioritize_future_selector_over_mixed_shape_errors(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "future.cab"
    shutil.copytree(EXAMPLE_BUNDLE, bundle)
    manifest_path = bundle / "bundle.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["schema_version"] = "2.0.0"
    manifest["profile"] = None
    manifest["future_extension"] = {"introduced_in": "2.0.0"}
    manifest_path.write_bytes(canonical_json_bytes(manifest))

    python_result = verify_bundle(bundle)
    return_code, node_result = _verify_with_node(bundle)

    assert python_result.status == BundleStatus.UNSUPPORTED
    assert return_code == 1
    assert node_result["status"] == python_result.status.value
    assert node_result["bundle_id"] == python_result.bundle_id
    assert {issue["code"] for issue in node_result["issues"]} == {
        "unsupported-schema-version"
    }
