from __future__ import annotations

import base64
from pathlib import Path
from typing import Any, cast

import yaml

from assurance_lab.controls.alert_window import parse_alert_window_profile
from assurance_lab.runtime.profile_registrar import (
    RuntimeProfileRegistrationManifest,
)
from assurance_lab.runtime.service_config import (
    ElasticRuntimeSettings,
    RuntimeWorkerServiceConfig,
)

_ROOT = Path(__file__).resolve().parents[1]
_DEPLOY = _ROOT / "deploy" / "kubernetes"
_CONFIG_DIGEST = (
    "sha256:b704eef000feda61016990c6f0454eb749f5cc5f1b1e433509f5d282fc0d3748"
)
_MANIFEST_DIGEST = (
    "sha256:e298279144319a96e9284783de26664bb39b503ca2bf0e88d00bd817fa4b8e77"
)


def _yaml_documents(name: str) -> list[dict[str, Any]]:
    documents = yaml.safe_load_all((_DEPLOY / name).read_text())
    return [cast(dict[str, Any], document) for document in documents]


def test_release_assets_reopen_under_the_documented_content_identities() -> None:
    configuration = RuntimeWorkerServiceConfig.model_validate_json(
        (_DEPLOY / "runtime-worker-config.example.json").read_bytes()
    )
    manifest = RuntimeProfileRegistrationManifest.model_validate_json(
        (_DEPLOY / "profile-registration-manifest.example.json").read_bytes()
    )
    assert configuration.digest == _CONFIG_DIGEST
    assert manifest.digest == _MANIFEST_DIGEST

    runtime_release = _yaml_documents("runtime-release.example.yaml")[0]
    assert runtime_release["metadata"]["annotations"][
        "control-assurance.io/config-digest"
    ] == _CONFIG_DIGEST
    embedded_configuration = RuntimeWorkerServiceConfig.model_validate_json(
        runtime_release["data"]["runtime-worker.json"]
    )
    assert embedded_configuration == configuration

    profile_release = _yaml_documents("profile-release.example.yaml")[0]
    assert profile_release["metadata"]["annotations"][
        "control-assurance.io/profile-manifest-digest"
    ] == _MANIFEST_DIGEST
    embedded_manifest = RuntimeProfileRegistrationManifest.model_validate_json(
        profile_release["data"]["profile-registration-manifest.json"]
    )
    assert embedded_manifest == manifest

    profile_bytes = base64.b64decode(
        profile_release["binaryData"][
            "elastic-high-severity-alerts-v1.json"
        ],
        validate=True,
    )
    artifact = manifest.profiles[0]
    profile = parse_alert_window_profile(
        profile_bytes,
        expected_profile_id=artifact.profile_id,
        expected_profile_digest=artifact.expected_digest,
    )
    assert profile.canonical_bytes() == profile_bytes


def test_worker_manifest_preserves_ha_drain_and_explicit_identity_boundaries() -> None:
    documents = _yaml_documents("runtime-worker.yaml")
    deployment = next(item for item in documents if item["kind"] == "Deployment")
    pod = deployment["spec"]["template"]["spec"]
    worker = next(
        item for item in pod["containers"] if item["name"] == "runtime-worker"
    )
    init = {item["name"]: item for item in pod["initContainers"]}

    assert deployment["spec"]["replicas"] == 2
    assert deployment["spec"]["strategy"]["rollingUpdate"]["maxUnavailable"] == 0
    assert pod["terminationGracePeriodSeconds"] == 900
    assert pod["automountServiceAccountToken"] is False
    assert "vault-token-agent" in init
    assert init["vault-token-agent"]["restartPolicy"] == "Always"
    assert "initialize-shared-work-root" in init
    assert pod["securityContext"]["runAsUser"] == 10000
    assert pod["securityContext"]["runAsGroup"] == 10000
    trust_materializer = init["materialize-pinned-trust"]
    trust_script = trust_materializer["args"][0]
    assert 'test "$(id -u)" = "10000"' in trust_script
    assert 'chmod 0400 "/trust/runtime/.${file}.new"' in trust_script
    assert "chmod 0500 /trust/runtime" in trust_script
    assert worker["startupProbe"]["httpGet"]["path"] == "/livez"
    assert worker["readinessProbe"]["httpGet"]["path"] == "/readyz"
    assert worker["securityContext"]["readOnlyRootFilesystem"] is True
    assert "@sha256:" in worker["image"]
    assert {
        volume["name"] for volume in pod["volumes"]
    } >= {"azure-token", "aws-token", "vault-login-token", "shared-work"}
    configuration = RuntimeWorkerServiceConfig.model_validate_json(
        (_DEPLOY / "runtime-worker-config.example.json").read_bytes()
    )
    source_runtime = configuration.registrations[0].source_runtime
    assert type(source_runtime) is ElasticRuntimeSettings
    pinned = (
        configuration.database.ca_bundle.file,
        source_runtime.ca_bundle.file,
        configuration.registrations[
            0
        ].custody_runtime.vault_transit.ca_bundle.file,
    )
    assert all(
        item.owner_uid == 10000
        and item.group_gid == 10000
        and item.mode == 0o400
        and item.mount_root == "/trust/runtime"
        for item in pinned
    )

    pdb = next(
        item for item in documents if item["kind"] == "PodDisruptionBudget"
    )
    assert pdb["spec"]["minAvailable"] == 1


def test_profile_registrar_is_a_separate_nonretrying_release_identity() -> None:
    documents = _yaml_documents("profile-registrar-job.yaml")
    service_account = next(
        item for item in documents if item["kind"] == "ServiceAccount"
    )
    job = next(item for item in documents if item["kind"] == "Job")
    pod = job["spec"]["template"]["spec"]
    registrar = pod["containers"][0]

    assert service_account["metadata"]["name"] == (
        "control-assurance-profile-registrar"
    )
    assert job["spec"]["backoffLimit"] == 0
    assert pod["restartPolicy"] == "Never"
    assert pod["securityContext"]["runAsUser"] == 10000
    assert pod["securityContext"]["runAsGroup"] == 10000
    trust_materializer = pod["initContainers"][0]
    assert trust_materializer["name"] == (
        "materialize-pinned-postgres-trust"
    )
    assert "chmod 0400 /trust/runtime/.postgres-ca.pem.new" in (
        trust_materializer["args"][0]
    )
    assert registrar["command"][1] == "register-profiles"
    secret_names = {
        entry["valueFrom"]["secretKeyRef"]["name"]
        for entry in registrar["env"]
        if "secretKeyRef" in entry.get("valueFrom", {})
    }
    assert "control-assurance-profile-registrar-database" in secret_names
    assert "control-assurance-runtime-database" not in secret_names
    manifest = RuntimeProfileRegistrationManifest.model_validate_json(
        (_DEPLOY / "profile-registration-manifest.example.json").read_bytes()
    )
    database_ca = manifest.database.ca_bundle.file
    assert database_ca.owner_uid == 10000
    assert database_ca.group_gid == 10000
    assert database_ca.mode == 0o400
    assert database_ca.path == "/trust/runtime/postgres-ca.pem"
