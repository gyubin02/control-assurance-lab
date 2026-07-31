from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any

import yaml

_ROOT = Path(__file__).resolve().parents[1]
_DOCKERFILE = (_ROOT / "Dockerfile").read_text(encoding="utf-8")
_RELEASE_WORKFLOW = (_ROOT / ".github" / "workflows" / "release-container.yml").read_text(
    encoding="utf-8"
)
_RELEASE = yaml.safe_load(_RELEASE_WORKFLOW)
_CHECKS_WORKFLOW = (_ROOT / ".github" / "workflows" / "checks.yml").read_text(encoding="utf-8")
_CHECKS = yaml.safe_load(_CHECKS_WORKFLOW)
_DIGEST_PIN = re.compile(
    r"^ARG PYTHON_IMAGE=python:3[.]12-alpine3[.]23@"
    r"sha256:[a-f0-9]{64}$",
    re.MULTILINE,
)


def test_container_build_is_digest_and_dependency_pinned() -> None:
    assert _DIGEST_PIN.search(_DOCKERFILE)
    assert not _DOCKERFILE.startswith("# syntax=")
    assert _DOCKERFILE.count("--require-hashes") == 2
    assert _DOCKERFILE.count("--only-binary=:all:") == 2
    assert "requirements/container-build.lock" in _DOCKERFILE
    assert "requirements/runtime.lock" in _DOCKERFILE
    assert "ARG SOURCE_DATE_EPOCH=0" in _DOCKERFILE
    assert "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" in _DOCKERFILE
    assert "COPY . " not in _DOCKERFILE
    assert ":latest" not in _DOCKERFILE


def test_runtime_image_has_a_non_privileged_secret_free_default() -> None:
    assert "USER 10000:10000" in _DOCKERFILE
    assert "groupadd" not in _DOCKERFILE
    assert "useradd" not in _DOCKERFILE
    assert 'CMD ["assurance-lab", "--help"]' in _DOCKERFILE
    assert "ENTRYPOINT" not in _DOCKERFILE
    assert "ARG SECRET" not in _DOCKERFILE
    assert "ENV SECRET" not in _DOCKERFILE
    assert "/opt/control-assurance/bin/pip" in _DOCKERFILE
    assert "/usr/local/lib/python3.12/site-packages/pip" in _DOCKERFILE
    assert "/usr/local/lib/python3.12/ensurepip" in _DOCKERFILE
    assert "! command -v pip" in _DOCKERFILE
    assert "! python -m pip --version" in _DOCKERFILE
    assert "! python -m ensurepip --version" in _DOCKERFILE


def _release_step(job: str, name: str) -> dict[str, Any]:
    matches = [
        step
        for step in _RELEASE["jobs"][job]["steps"]
        if isinstance(step, dict) and step.get("name") == name
    ]
    assert len(matches) == 1
    return matches[0]


def test_release_actions_are_immutable_and_jobs_are_least_privilege() -> None:
    action_refs = re.findall(r"^\s*uses:\s*[^@\s]+@([^\s#]+)", _RELEASE_WORKFLOW, re.MULTILINE)
    assert action_refs
    assert all(re.fullmatch(r"[a-f0-9]{40}", reference) for reference in action_refs)
    assert _RELEASE["permissions"] == {}
    jobs = _RELEASE["jobs"]
    assert set(jobs) == {"quality", "build-scan", "publish"}
    assert jobs["quality"]["permissions"] == {"contents": "read"}
    assert jobs["build-scan"]["permissions"] == {"contents": "read"}
    assert jobs["build-scan"]["needs"] == "quality"
    assert set(jobs["publish"]["needs"]) == {"quality", "build-scan"}
    assert jobs["publish"]["permissions"] == {
        "attestations": "write",
        "contents": "read",
        "id-token": "write",
        "packages": "write",
    }
    for job in ("quality", "build-scan"):
        serialized = yaml.safe_dump(jobs[job])
        assert "packages: write" not in serialized
        assert "id-token: write" not in serialized
        assert "attestations: write" not in serialized
    publish_uses = {
        str(step.get("uses", "")).split("@", maxsplit=1)[0]
        for step in jobs["publish"]["steps"]
        if isinstance(step, dict)
    }
    assert "actions/checkout" not in publish_uses


def test_release_repeats_every_source_and_distribution_gate_on_the_tag() -> None:
    audit = _release_step("quality", "Audit every Python dependency lock")["run"]
    for lock in ("runtime.lock", "container-build.lock", "ci.lock"):
        assert f"requirements/{lock}" in audit
    for option in ("--require-hashes", "--disable-pip", "--strict"):
        assert option in audit
    source_gate = _release_step(
        "quality", "Run source, unit, static, and independent JavaScript checks"
    )["run"]
    for command in (
        "ruff check .",
        "mypy src tests",
        "pytest -q",
        "npm test --prefix verifier-js",
        "node --test web/app.test.js",
        "node --test src/assurance_lab/control_plane/static/model.test.mjs",
    ):
        assert command in source_gate
    distribution_gate = _release_step("quality", "Build and smoke-test the release distributions")[
        "run"
    ]
    assert "hatchling build --target wheel --target sdist" in distribution_gate
    assert "scripts/check-distributions.py dist" in distribution_gate
    assert "dist/*.whl" in distribution_gate


def test_release_scans_the_exact_unpublished_layout_on_both_platforms() -> None:
    build = _release_step("build-scan", "Build the unpublished multi-platform OCI layout")
    canonicalize = _release_step(
        "build-scan", "Canonicalize the BuildKit content-store layout"
    )
    close = _release_step(
        "build-scan", "Close the layout over both images and both attestations"
    )
    assert build["with"]["push"] is False
    assert build["with"]["platforms"] == "linux/amd64,linux/arm64"
    assert "type=oci" in build["with"]["outputs"]
    assert "tar=false" in build["with"]["outputs"]
    assert "oci-artifact=false" in build["with"]["outputs"]
    assert build["with"]["provenance"] == "mode=max"
    assert build["with"]["sbom"] == (
        "generator=docker/buildkit-syft-scanner@"
        "sha256:79e7b013cbec16bbb436f312819a49a4a57752b2270c1a9332ae1a10fcc82a68"
    )
    assert canonicalize["env"]["LAYOUT"] == "${{ runner.temp }}/control-assurance-oci"
    assert (
        'python scripts/canonicalize-buildkit-layout.py "$LAYOUT"'
        in canonicalize["run"]
    )
    step_names = [
        step.get("name")
        for step in _RELEASE["jobs"]["build-scan"]["steps"]
        if isinstance(step, dict)
    ]
    assert step_names.index(build["name"]) < step_names.index(canonicalize["name"])
    assert step_names.index(canonicalize["name"]) < step_names.index(close["name"])
    assert "docker/login-action@" not in yaml.safe_dump(_RELEASE["jobs"]["build-scan"])
    assert _RELEASE_WORKFLOW.count("TRIVY_PLATFORM: linux/amd64") == 1
    assert _RELEASE_WORKFLOW.count("TRIVY_PLATFORM: linux/arm64") == 1
    assert _RELEASE_WORKFLOW.count("version: v0.69.3") == 2
    assert "ignore-unfixed" not in _RELEASE_WORKFLOW
    for platform in ("amd64", "arm64"):
        step = _release_step(
            "build-scan", f"Reject known high-impact vulnerabilities on {platform}"
        )
        assert step["with"]["input"] == "${{ runner.temp }}/control-assurance-oci"
        select = _release_step("build-scan", f"Select the exact {platform} scan view")
        assert shlex.split(select["run"]) == [
            "cp",
            f"$RUNNER_TEMP/control-assurance-platform-indexes/linux-{platform}.json",
            "$RUNNER_TEMP/control-assurance-oci/index.json",
        ]
    restore = _release_step("build-scan", "Restore and re-verify the scanned release index")["run"]
    assert "verify-container-layout.py" in restore
    assert "cmp" in restore
    assert _RELEASE_WORKFLOW.count('--source-date-epoch "$SOURCE_DATE_EPOCH"') == 3
    package = _release_step("build-scan", "Package the exact scanned layout")["run"]
    assert "--sort=name" in package
    assert "--source-date-epoch" in package
    assert 'archive_sha256="$(sha256sum' in package
    upload = _release_step("build-scan", "Hand the exact OCI tar to the privileged job")
    assert upload["with"]["archive"] is False
    artifact_binding = _release_step(
        "build-scan", "Bind the artifact service digest to the scanned tar"
    )
    assert artifact_binding["run"] == 'test "$UPLOADED" = "$EXPECTED"'


def test_release_signs_attests_and_promotes_only_the_gated_digest() -> None:
    download = _release_step(
        "publish", "Download the exact scanned OCI tar without re-archiving it"
    )
    assert download["with"]["skip-decompress"] is True
    assert download["with"]["digest-mismatch"] == "error"
    downloaded_binding = _release_step("publish", "Rebind the downloaded bytes to the scan job")[
        "run"
    ]
    assert 'observed="$(sha256sum' in downloaded_binding
    assert 'test "$observed" = "$EXPECTED"' in downloaded_binding
    assert (
        "oras resolve"
        in _release_step("publish", "Verify the local OCI subject before registry access")["run"]
    )
    publish = _release_step(
        "publish", "Publish the exact scanned index under a run-unique candidate tag"
    )["run"]
    assert "--from-oci-layout" in publish
    assert "candidate-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${GITHUB_SHA}" in publish
    assert "oras resolve --platform linux/amd64" in publish
    assert "oras resolve --platform linux/arm64" in publish
    assert "cosign sign --yes" in _RELEASE_WORKFLOW
    assert "actions/attest@" in _RELEASE_WORKFLOW
    assert "gh attestation verify" in _RELEASE_WORKFLOW
    provenance_verify = _release_step("publish", "Verify the published GitHub provenance")["run"]
    for constraint in (
        "--bundle-from-oci",
        "--signer-workflow",
        "${GITHUB_REPOSITORY}/.github/workflows/release-container.yml",
        '--source-ref "${GITHUB_REF}"',
        '--source-digest "${GITHUB_SHA}"',
    ):
        assert constraint in provenance_verify
    promote = _RELEASE_WORKFLOW.index("Promote the verified digest without rewriting a version")
    for prerequisite in (
        "Publish the exact scanned index under a run-unique candidate tag",
        "Sign the immutable image index",
        "Publish GitHub build provenance",
        "Verify the published signature identity",
        "Verify the published GitHub provenance",
    ):
        assert _RELEASE_WORKFLOW.index(prerequisite) < promote
    promotion = _release_step("publish", "Promote the verified digest without rewriting a version")[
        "run"
    ]
    assert 'test "$existing" = "$INDEX_DIGEST"' in promotion
    assert 'oras cp "${IMAGE}@${INDEX_DIGEST}" "$version_ref"' in promotion
    assert 'test "$(oras resolve "$version_ref")" = "$INDEX_DIGEST"' in promotion
    assert ":latest" not in _RELEASE_WORKFLOW


def test_runtime_workloads_preserve_the_image_security_contract() -> None:
    pods: list[dict[str, Any]] = []
    for path in sorted((_ROOT / "deploy" / "kubernetes").glob("*.yaml")):
        for document in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if not isinstance(document, dict):
                continue
            kind = document.get("kind")
            if kind == "Deployment" or kind == "Job":
                pods.append(document["spec"]["template"]["spec"])

    assert pods
    for pod in pods:
        assert pod["securityContext"]["runAsNonRoot"] is True
        assert pod["securityContext"]["runAsUser"] == 10000
        assert pod["securityContext"]["runAsGroup"] == 10000
        assert pod["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
        assert pod["automountServiceAccountToken"] is False
        for container in (*pod.get("initContainers", ()), *pod["containers"]):
            context = container["securityContext"]
            assert context["allowPrivilegeEscalation"] is False
            assert context["capabilities"]["drop"] == ["ALL"]
            assert context["readOnlyRootFilesystem"] is True


def test_pull_request_checks_build_and_confine_the_real_image() -> None:
    assert "Build the exact production Dockerfile" in _CHECKS_WORKFLOW
    assert "load: true" in _CHECKS_WORKFLOW
    assert "--read-only" in _CHECKS_WORKFLOW
    assert "--network none" in _CHECKS_WORKFLOW
    assert "--cap-drop ALL" in _CHECKS_WORKFLOW
    assert "--security-opt no-new-privileges" in _CHECKS_WORKFLOW
    assert "the runtime image exposes a pip executable" in _CHECKS_WORKFLOW
    assert "the runtime image still contains the pip module" in _CHECKS_WORKFLOW
    assert "the runtime image can recreate pip with ensurepip" in _CHECKS_WORKFLOW
    assert (
        "docker image inspect control-assurance:ci --format '{{.Config.User}}'" in _CHECKS_WORKFLOW
    )
    for entrypoint in (
        "assurance-lab",
        "assurance-control-plane",
        "assurance-runtime-worker",
        "assurance-deployment-reconciler",
    ):
        assert f'"${{runtime[@]}}" {entrypoint} --help' in _CHECKS_WORKFLOW or (
            f'"${{runtime[@]}}" {entrypoint} --version' in _CHECKS_WORKFLOW
        )


def test_pull_request_checks_scan_the_built_image_before_a_release_tag_exists() -> None:
    steps = _CHECKS["jobs"]["container-contract"]["steps"]
    matches = [
        step
        for step in steps
        if step.get("name") == "Reject known high-impact vulnerabilities before tagging"
    ]
    assert len(matches) == 1
    scan = matches[0]
    assert scan["uses"] == (
        "aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25"
    )
    assert scan["with"] == {
        "scan-type": "image",
        "image-ref": "control-assurance:ci",
        "scanners": "vuln,secret",
        "format": "table",
        "severity": "HIGH,CRITICAL",
        "exit-code": "1",
        "version": "v0.69.3",
    }
    build_index = next(
        index
        for index, step in enumerate(steps)
        if step.get("name") == "Build the exact production Dockerfile"
    )
    scan_index = steps.index(scan)
    exercise_index = next(
        index
        for index, step in enumerate(steps)
        if step.get("name") == "Exercise the immutable non-root runtime"
    )
    assert build_index < scan_index < exercise_index
