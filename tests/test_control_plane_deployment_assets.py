from __future__ import annotations

import base64
import hashlib
import json
import re
import runpy
import subprocess
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import yaml

from assurance_lab.control_plane.service_config import (
    ControlPlaneServiceConfig,
)

_ROOT = Path(__file__).resolve().parents[1]
_DEPLOY = _ROOT / "deploy" / "kubernetes"
_CONFIG_DIGEST = (
    "sha256:d1f33835c7b121c8d6689571fb9162de4818b90a6a86864031c18c7be1cea906"
)
_IMAGE = re.compile(r"^[^\s]+@sha256:[a-f0-9]{64}$")
_APPLICATION_IMAGE = (
    "ghcr.io/gyubin02/control-assurance-lab@sha256:"
    "0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef"
)
_VAULT_IMAGE = (
    "hashicorp/vault@sha256:"
    "fedcba9876543210fedcba9876543210"
    "fedcba9876543210fedcba9876543210"
)
_PUBLIC_INPUTS = (
    "control/key-vault-ca.pem",
    "control/oidc-ca.pem",
    "control/oidc-client.der",
    "control/postgres-ca.pem",
    "runtime/elastic-ca.pem",
    "runtime/postgres-ca.pem",
    "runtime/vault-ca.pem",
)


def _site_egress_contract(tmp_path: Path) -> Path:
    path = tmp_path / "site-egress-contract.json"
    document = {
        "cilium": {
            "bpf_masquerade": True,
            "cilium_endpoint_slice_enabled": False,
            "cluster_mesh_enabled": False,
            "egress_gateway_enabled": True,
            "endpoint_policy_overflow_lockdown_enabled": True,
            "identity_allocation_mode": "crd",
            "ipv6_enabled": False,
            "kube_proxy_replacement": True,
            "l7_proxy_enabled": True,
            "minimum_version": "1.20.0",
            "required_identity_labels": [
                "app.kubernetes.io/component",
                "app.kubernetes.io/name",
                "control-assurance.io/egress-contract",
                "io.kubernetes.pod.namespace",
            ],
        },
        "cluster_dns": {
            "namespace": "kube-system",
            "pod_selector": {"k8s-app": "kube-dns"},
        },
        "site_perimeter_enforcement": {
            "allowed_gateway_source_ips": [
                "10.255.0.10",
                "10.255.0.11",
            ],
            "change_reference": "CHG-2026-0042",
            "contracted_destination_cidrs": [
                "10.60.0.10/32",
                "10.60.0.11/32",
                "10.60.0.30/32",
                "20.190.128.1/32",
            ],
            "deny_all_direct_external_pod_and_node_egress": True,
            "deny_gateway_sources_outside_contracted_destinations": True,
            "direct_denied_node_source_cidrs": ["10.50.0.0/16"],
            "direct_denied_pod_source_cidrs": ["10.244.0.0/16"],
            "gateway_allow_exception_precedes_direct_deny": True,
            "perimeter_ipv6_external_egress_disabled": True,
        },
        "gateways": [
            {
                "egress_ip": "10.255.0.10",
                "node_selector": {
                    "kubernetes.io/hostname": "egress-a"
                },
            },
            {
                "egress_ip": "10.255.0.11",
                "node_selector": {
                    "kubernetes.io/hostname": "egress-b"
                },
            },
        ],
        "profile": "cilium-egress-gateway/1.20",
        "schema": "control-assurance/site-egress-contract/v3",
        "workloads": {
            "control-plane": [
                {
                    "cidrs": ["10.60.0.10/32"],
                    "fqdn": "postgres.security.internal",
                    "name": "control-postgres",
                    "port": 5432,
                },
                {
                    "cidrs": ["20.190.128.1/32"],
                    "fqdn": "login.microsoftonline.com",
                    "name": "entra-oidc",
                    "port": 443,
                },
            ],
            "deployment-reconciler": [
                {
                    "cidrs": ["10.60.0.10/32"],
                    "fqdn": "postgres.security.internal",
                    "name": "control-postgres",
                    "port": 5432,
                },
                {
                    "cidrs": ["10.60.0.11/32"],
                    "fqdn": "runtime-postgres.security.internal",
                    "name": "runtime-postgres",
                    "port": 5432,
                },
            ],
            "profile-registrar": [
                {
                    "cidrs": ["10.60.0.11/32"],
                    "fqdn": "runtime-postgres.security.internal",
                    "name": "runtime-postgres",
                    "port": 5432,
                }
            ],
            "runtime-worker": [
                {
                    "cidrs": ["10.60.0.11/32"],
                    "fqdn": "runtime-postgres.security.internal",
                    "name": "runtime-postgres",
                    "port": 5432,
                },
                {
                    "cidrs": ["10.60.0.30/32"],
                    "fqdn": "elastic.security.internal",
                    "name": "elastic-security",
                    "port": 443,
                },
            ],
        },
    }
    path.write_bytes(
        json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    path.chmod(0o444)
    return path


def _documents(name: str) -> list[dict[str, Any]]:
    return [
        cast(dict[str, Any], document)
        for document in yaml.safe_load_all(
            (_DEPLOY / name).read_text(encoding="utf-8")
        )
    ]


def _deployment(name: str) -> dict[str, Any]:
    return next(
        document
        for document in _documents(name)
        if document["kind"] == "Deployment"
    )


def _public_input_directory(tmp_path: Path) -> Path:
    directory = tmp_path / "public-inputs"
    for reference in _PUBLIC_INPUTS:
        target = directory / reference
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(f"test-only-public-input:{reference}".encode())
        target.chmod(0o444)
    return directory


def _render_command(
    *,
    script: Path,
    output: Path,
    public_inputs: Path,
    site_egress_contract: Path,
) -> list[str]:
    return [
        sys.executable,
        str(script),
        "render",
        "--source-dir",
        str(_DEPLOY),
        "--public-input-dir",
        str(public_inputs),
        "--site-egress-contract",
        str(site_egress_contract),
        "--output-dir",
        str(output),
        "--application-image",
        _APPLICATION_IMAGE,
        "--vault-image",
        _VAULT_IMAGE,
    ]


def test_control_plane_release_is_secret_free_and_digest_pinned() -> None:
    configuration = ControlPlaneServiceConfig.model_validate_json(
        (_DEPLOY / "control-plane-config.example.json").read_bytes()
    )
    assert configuration.digest == _CONFIG_DIGEST
    assert configuration.database.control_dsn.kind == "environment"
    assert configuration.database.auth_dsn.kind == "environment"
    assert (
        configuration.database.control_dsn.name
        != configuration.database.auth_dsn.name
    )
    assert len(
        {
            configuration.database.control_role,
            configuration.database.auth_role,
            configuration.database.migration_owner_role,
        }
    ) == 3
    assert configuration.database.require_tls_verify_full is True
    assert configuration.database.require_read_write_primary is True
    assert re.fullmatch(
        r"[a-f0-9]{32}",
        configuration.key_management.pkce_wrapping_key.key_version,
    )
    assert re.fullmatch(
        r"[a-f0-9]{32}",
        configuration.key_management.oidc_client_signing_key.key_version,
    )
    assert configuration.key_management.csrf_key_secret_ref.startswith(
        "azure-keyvault://"
    )
    pinned_files = (
        configuration.database.ca_bundle.file,
        configuration.oidc.jwks_ca_bundle.file,
        configuration.key_management.key_vault_ca_bundle.file,
        configuration.key_management.oidc_client_certificate.file,
    )
    assert all(
        item.owner_uid == 0
        and item.group_gid == 2000
        and item.mode == 0o440
        for item in pinned_files
    )
    raw = (_DEPLOY / "control-plane-config.example.json").read_text(
        encoding="utf-8"
    )
    assert "client_secret" not in raw
    assert "password" not in raw
    assert "private_key" not in raw


def test_control_plane_manifest_preserves_ha_and_no_migration_authority() -> None:
    documents = _documents("control-plane.yaml")
    assert not {
        document["kind"] for document in documents
    } & {"Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"}
    deployment = next(
        document for document in documents if document["kind"] == "Deployment"
    )
    pod = deployment["spec"]["template"]["spec"]
    container = pod["containers"][0]
    assert deployment["spec"]["replicas"] == 2
    assert deployment["spec"]["minReadySeconds"] == 15
    assert deployment["spec"]["progressDeadlineSeconds"] == 600
    assert (
        deployment["spec"]["strategy"]["rollingUpdate"]["maxUnavailable"]
        == 0
    )
    assert pod["automountServiceAccountToken"] is False
    assert pod["enableServiceLinks"] is False
    assert not pod.get("initContainers")
    assert _IMAGE.fullmatch(container["image"])
    assert container["command"] == ["assurance-control-plane"]
    assert container["args"][:2] == ["run", "--config"]
    assert container["startupProbe"]["httpGet"]["path"] == "/health/ready"
    assert container["readinessProbe"]["httpGet"]["path"] == "/health/ready"
    assert container["livenessProbe"]["httpGet"]["path"] == "/health/live"
    digest = next(
        entry
        for entry in container["env"]
        if entry["name"] == "ASSURANCE_CONTROL_PLANE_CONFIG_DIGEST"
    )
    assert digest["value"] == _CONFIG_DIGEST
    environment = {entry["name"]: entry for entry in container["env"]}
    assert "ASSURANCE_CONTROL_PLANE_DSN" not in environment
    control_dsn = environment["ASSURANCE_CONTROL_PLANE_CONTROL_DSN"][
        "valueFrom"
    ]["secretKeyRef"]
    auth_dsn = environment["ASSURANCE_CONTROL_PLANE_AUTH_DSN"][
        "valueFrom"
    ]["secretKeyRef"]
    assert control_dsn == {
        "name": "control-assurance-control-plane-postgres",
        "key": "control-dsn",
    }
    assert auth_dsn == {
        "name": "control-assurance-control-plane-postgres",
        "key": "auth-dsn",
    }
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    volumes = {item["name"]: item for item in pod["volumes"]}
    assert volumes["config"]["configMap"]["defaultMode"] == 0o440
    assert volumes["trust"]["projected"]["defaultMode"] == 0o440
    assert (
        volumes["oidc-client-identity"]["projected"]["defaultMode"]
        == 0o440
    )
    pdb = next(
        document
        for document in documents
        if document["kind"] == "PodDisruptionBudget"
    )
    assert pdb["spec"]["minAvailable"] == 1
    assert pdb["spec"]["unhealthyPodEvictionPolicy"] == "IfHealthyBudget"


def test_reconciler_is_two_replica_database_fenced_and_least_privileged() -> None:
    documents = _documents("deployment-reconciler.yaml")
    assert not {
        document["kind"] for document in documents
    } & {"Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"}
    deployment = _deployment("deployment-reconciler.yaml")
    pod = deployment["spec"]["template"]["spec"]
    container = pod["containers"][0]
    assert deployment["spec"]["replicas"] == 2
    assert (
        deployment["spec"]["strategy"]["rollingUpdate"]["maxUnavailable"]
        == 0
    )
    assert pod["automountServiceAccountToken"] is False
    assert pod["securityContext"]["runAsUser"] == 10000
    assert pod["securityContext"]["runAsGroup"] == 10000
    assert _IMAGE.fullmatch(container["image"])
    assert container["command"] == ["assurance-deployment-reconciler"]
    assert container["args"][:2] == ["run", "--runtime-config"]
    assert container["startupProbe"]["httpGet"]["path"] == "/livez"
    assert container["readinessProbe"]["httpGet"]["path"] == "/readyz"
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    environment = {entry["name"]: entry for entry in container["env"]}
    assert "EXECUTION_DATABASE_DSN" not in environment
    assert "PAM_DATABASE_DSN" not in environment
    assert environment[
        "ASSURANCE_DEPLOYMENT_RECONCILER_DSN"
    ]["valueFrom"]["secretKeyRef"]["name"] == (
        "control-assurance-deployment-reconciler-database"
    )
    assert environment[
        "RUNTIME_DATABASE_DSN"
    ]["valueFrom"]["secretKeyRef"]["name"] == (
        "control-assurance-deployment-reconciler-database"
    )
    assert environment[
        "ASSURANCE_DEPLOYMENT_RECONCILER_DSN"
    ]["valueFrom"]["secretKeyRef"]["key"] == "control-plane-dsn"
    assert environment[
        "RUNTIME_DATABASE_DSN"
    ]["valueFrom"]["secretKeyRef"]["key"] == "runtime-catalog-dsn"
    assert environment[
        "ASSURANCE_DEPLOYMENT_RECONCILER_EXPECTED_ROLE"
    ]["value"] == "assurance_reconciler_runtime"
    assert environment[
        "ASSURANCE_DEPLOYMENT_RECONCILER_RUNTIME_ROLE"
    ]["value"] == "assurance_runtime_reconciler"
    assert environment[
        "ASSURANCE_CONTROL_PLANE_MIGRATION_OWNER_ROLE"
    ]["value"] == "assurance_migration_owner"
    for name, key in (
        (
            "ASSURANCE_DEPLOYMENT_RECONCILER_CONTROL_CA_DIGEST",
            "control-postgres-ca-digest",
        ),
        (
            "ASSURANCE_DEPLOYMENT_RECONCILER_RUNTIME_CA_DIGEST",
            "runtime-postgres-ca-digest",
        ),
    ):
        reference = environment[name]["valueFrom"]["secretKeyRef"]
        assert reference == {
            "name": "control-assurance-deployment-reconciler-release-pins-v1",
            "key": key,
        }
    trust_materializer = pod["initContainers"][0]
    trust_script = trust_materializer["args"][0]
    assert "chmod 0400 /trust/runtime/.control-postgres-ca.pem.new" in (
        trust_script
    )
    assert "chmod 0400 /trust/runtime/.postgres-ca.pem.new" in trust_script
    assert not any("projected" in volume for volume in pod["volumes"])
    assert {
        init["name"] for init in pod["initContainers"]
    } == {"materialize-pinned-database-trust"}
    pdb = next(
        document
        for document in documents
        if document["kind"] == "PodDisruptionBudget"
    )
    assert pdb["spec"]["minAvailable"] == 1


def test_base_network_policy_denies_egress_without_claiming_routing() -> None:
    documents = _documents("network-policies.yaml")
    assert all(
        document["apiVersion"] == "networking.k8s.io/v1"
        and document["kind"] == "NetworkPolicy"
        and document["metadata"]["namespace"] == "control-assurance"
        for document in documents
    )
    policies = {document["metadata"]["name"]: document for document in documents}
    assert set(policies) == {
        "control-assurance-default-deny",
        "control-assurance-control-plane-ingress",
        "control-assurance-reconciler-health-ingress",
        "control-assurance-runtime-health-ingress",
    }
    default_deny = policies["control-assurance-default-deny"]["spec"]
    assert default_deny == {
        "podSelector": {},
        "policyTypes": ["Ingress", "Egress"],
    }
    control_selector = {
        "app.kubernetes.io/name": "control-assurance",
        "app.kubernetes.io/component": "control-plane",
    }
    reconciler_selector = {
        "app.kubernetes.io/name": "control-assurance",
        "app.kubernetes.io/component": "deployment-reconciler",
    }
    runtime_selector = {
        "app.kubernetes.io/name": "control-assurance-runtime",
        "app.kubernetes.io/component": "runtime-worker",
    }
    expected_policy_selectors = {
        "control-assurance-control-plane-ingress": control_selector,
        "control-assurance-reconciler-health-ingress": reconciler_selector,
        "control-assurance-runtime-health-ingress": runtime_selector,
    }
    for name, selector in expected_policy_selectors.items():
        assert policies[name]["spec"]["podSelector"]["matchLabels"] == selector

    ingress_expectations = {
        "control-assurance-control-plane-ingress": [
            (
                "control-assurance.io/ingress-namespace",
                "control-assurance.io/ingress-client",
            ),
            (
                "control-assurance.io/monitoring-namespace",
                "control-assurance.io/health-client",
            ),
        ],
        "control-assurance-reconciler-health-ingress": [
            (
                "control-assurance.io/monitoring-namespace",
                "control-assurance.io/health-client",
            )
        ],
        "control-assurance-runtime-health-ingress": [
            (
                "control-assurance.io/monitoring-namespace",
                "control-assurance.io/health-client",
            )
        ],
    }
    for name, source_labels in ingress_expectations.items():
        spec = policies[name]["spec"]
        assert spec["policyTypes"] == ["Ingress"]
        assert len(spec["ingress"]) == len(source_labels)
        for rule, (namespace_label, pod_label) in zip(
            spec["ingress"],
            source_labels,
            strict=True,
        ):
            assert rule["from"] == [
                {
                    "namespaceSelector": {
                        "matchLabels": {namespace_label: "true"}
                    },
                    "podSelector": {
                        "matchLabels": {pod_label: "true"}
                    },
                }
            ]
            assert rule["ports"] == [{"protocol": "TCP", "port": 8080}]

    raw_policy = (_DEPLOY / "network-policies.yaml").read_text(
        encoding="utf-8"
    )
    assert "control-assurance-dns" not in raw_policy
    assert "egress-gateway" not in raw_policy
    assert "toFQDNs" not in raw_policy
    assert "ipBlock:" not in raw_policy
    assert "0.0.0.0/0" not in raw_policy

    runbook = (_ROOT / "docs" / "control-plane-deployment.md").read_text(
        encoding="utf-8"
    )
    for required_statement in (
        "control-assurance/site-egress-contract/v3",
        "Cilium stable 1.20",
        "BPF masquerading",
        "kube-proxy replacement",
        "L7 proxy",
        "enable-lockdown-endpoint-on-policy-overflow=true",
        "identity allocation mode `crd`",
        "`control-assurance.io/egress-contract`,",
        "Cilium security identity에서 제외되지 않음",
        "Cluster Mesh 비활성화",
        "CiliumEndpointSlice 비활성화",
        "짧은 적용 지연",
        "site_perimeter_enforcement.change_reference",
        "대신 증명하지 않는다",
        "exact `toFQDNs.matchName`과 TCP",
        "pod/node의 모든",
        "direct external egress",
        "`direct_denied_pod_source_cidrs`",
        "`direct_denied_node_source_cidrs`",
        "`gateway_allow_exception_precedes_direct_deny=true`",
        "`cilium.ipv6_enabled=false`",
        "`site_perimeter_enforcement.perimeter_ipv6_external_egress_disabled=true`",
        "`deny_all_direct_external_pod_and_node_egress`",
        "`toFQDNs`도 TLS/SNI를 검사하는 기능은 아니다",
        "같은 IP의 다른",
        "virtual host를 구별하지 못하고",
        "즉시 session",
        "revocation으로 간주하지 않는다",
        "자동 추출해 계약 FQDN과",
        "비교하지는 않는다",
        "live firewall rule의 존재, 순서",
        "증명하지 않으며",
    ):
        assert required_statement in runbook


def test_kubernetes_release_render_and_verify_are_fail_closed(
    tmp_path: Path,
) -> None:
    script = _ROOT / "scripts" / "render-kubernetes-release.py"
    output = tmp_path / "release"
    public_inputs = _public_input_directory(tmp_path)
    site_egress_contract = _site_egress_contract(tmp_path)
    rendered = subprocess.run(
        _render_command(
            script=script,
            output=output,
            public_inputs=public_inputs,
            site_egress_contract=site_egress_contract,
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    assert rendered.returncode == 0, rendered.stderr
    lock_digest = rendered.stdout.strip()
    assert re.fullmatch(r"sha256:[a-f0-9]{64}", lock_digest)

    verified = subprocess.run(
        [
            sys.executable,
            str(script),
            "verify",
            "--release-dir",
            str(output),
            "--expected-lock-digest",
            lock_digest,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert verified.returncode == 0, verified.stderr

    emitted = subprocess.run(
        [
            sys.executable,
            str(script),
            "verify",
            "--release-dir",
            str(output),
            "--expected-lock-digest",
            lock_digest,
            "--emit-manifests",
        ],
        check=False,
        capture_output=True,
    )
    assert emitted.returncode == 0, emitted.stderr.decode()
    expected_emitted = b"".join(
        (output / "manifests" / name).read_bytes()
        for name in (
            "control-plane.yaml",
            "deployment-reconciler.yaml",
            "runtime-worker.yaml",
            "profile-registrar-job.yaml",
            "network-policies.yaml",
            "release-material.yaml",
            "site-egress-policy.yaml",
        )
    )
    assert emitted.stdout == expected_emitted
    emitted_documents = list(yaml.safe_load_all(emitted.stdout))
    assert len(emitted_documents) == 34
    assert all(isinstance(item, dict) for item in emitted_documents)

    lock = json.loads((output / "release-lock.json").read_bytes())
    assert lock["schema"] == "control-assurance/kubernetes-release-lock/v3"
    assert set(lock["public_inputs"]) == set(_PUBLIC_INPUTS)
    assert set(lock["configurations"]) == {
        "control-plane",
        "profile-registration",
        "runtime-worker",
        "site-egress",
    }
    material = [
        cast(dict[str, Any], item)
        for item in yaml.safe_load_all(
            (output / "manifests" / "release-material.yaml").read_bytes()
        )
    ]
    assert len(material) == 8
    assert all(item["immutable"] is True for item in material)
    by_kind = {
        item["metadata"]["labels"][
            "control-assurance.io/material-kind"
        ]: item
        for item in material
    }
    assert set(by_kind) == {
        "control-config",
        "control-identity",
        "control-trust",
        "profile-release",
        "reconciler-trust",
        "runtime-config",
        "runtime-trust",
        "site-egress-contract",
    }
    material_names = {
        kind: item["metadata"]["name"] for kind, item in by_kind.items()
    }
    for item in material:
        metadata = item["metadata"]
        material_digest = metadata["annotations"][
            "control-assurance.io/material-digest"
        ]
        digest_hex = material_digest.removeprefix("sha256:")
        digest_base32 = (
            base64.b32encode(bytes.fromhex(digest_hex))
            .decode("ascii")
            .rstrip("=")
            .lower()
        )
        assert metadata["name"].endswith(digest_hex[:20])
        assert metadata["labels"][
            "control-assurance.io/material-digest-prefix"
        ] == digest_hex[:20]
        assert metadata["labels"][
            "control-assurance.io/material-digest-base32"
        ] == digest_base32
    rendered_control = next(
        cast(dict[str, Any], item)
        for item in yaml.safe_load_all(
            (output / "manifests" / "control-plane.yaml").read_bytes()
        )
        if item["kind"] == "Deployment"
    )
    control_pod = rendered_control["spec"]["template"]["spec"]
    control_container = control_pod["containers"][0]
    control_environment = {
        item["name"]: item for item in control_container["env"]
    }
    assert control_environment[
        "ASSURANCE_CONTROL_PLANE_CONFIG_DIGEST"
    ] == {
        "name": "ASSURANCE_CONTROL_PLANE_CONFIG_DIGEST",
        "value": lock["configurations"]["control-plane"],
    }
    control_volumes = {
        item["name"]: item for item in control_pod["volumes"]
    }
    assert control_volumes["config"]["configMap"]["name"] == (
        material_names["control-config"]
    )
    assert control_volumes["trust"]["projected"]["sources"][0][
        "configMap"
    ]["name"] == material_names["control-trust"]
    assert control_volumes["oidc-client-identity"]["projected"][
        "sources"
    ][0]["configMap"]["name"] == material_names["control-identity"]
    egress_digest = lock["configurations"]["site-egress"]
    egress_selector = (
        base64.b32encode(
            bytes.fromhex(egress_digest.removeprefix("sha256:"))
        )
        .decode("ascii")
        .rstrip("=")
        .lower()
    )
    assert len(egress_selector) == 52
    for pod in (control_pod,):
        template = rendered_control["spec"]["template"]
        assert template["metadata"]["labels"][
            "control-assurance.io/egress-contract"
        ] == egress_selector
        assert template["metadata"]["annotations"][
            "control-assurance.io/egress-contract-digest"
        ] == egress_digest
        assert pod["dnsPolicy"] == "ClusterFirst"
        assert pod["dnsConfig"] == {
            "options": [{"name": "ndots", "value": "1"}]
        }

    rendered_runtime = next(
        cast(dict[str, Any], item)
        for item in yaml.safe_load_all(
            (output / "manifests" / "runtime-worker.yaml").read_bytes()
        )
        if item["kind"] == "Deployment"
    )
    runtime_pod = rendered_runtime["spec"]["template"]["spec"]
    runtime_worker = next(
        item
        for item in runtime_pod["containers"]
        if item["name"] == "runtime-worker"
    )
    runtime_environment = {
        item["name"]: item for item in runtime_worker["env"]
    }
    assert runtime_environment["ASSURANCE_RUNTIME_CONFIG_DIGEST"] == {
        "name": "ASSURANCE_RUNTIME_CONFIG_DIGEST",
        "value": lock["configurations"]["runtime-worker"],
    }
    runtime_volumes = {
        item["name"]: item for item in runtime_pod["volumes"]
    }
    assert runtime_volumes["runtime-config"]["configMap"]["name"] == (
        material_names["runtime-config"]
    )
    assert runtime_volumes["trust-inputs"]["configMap"]["name"] == (
        material_names["runtime-trust"]
    )

    rendered_reconciler = next(
        cast(dict[str, Any], item)
        for item in yaml.safe_load_all(
            (
                output
                / "manifests"
                / "deployment-reconciler.yaml"
            ).read_bytes()
        )
        if item["kind"] == "Deployment"
    )
    reconciler_pod = rendered_reconciler["spec"]["template"]["spec"]
    reconciler_environment = {
        item["name"]: item
        for item in reconciler_pod["containers"][0]["env"]
    }
    assert reconciler_environment[
        "ASSURANCE_DEPLOYMENT_RECONCILER_CONTROL_CA_DIGEST"
    ]["value"] == lock["public_inputs"]["control/postgres-ca.pem"]
    assert reconciler_environment[
        "ASSURANCE_DEPLOYMENT_RECONCILER_RUNTIME_CA_DIGEST"
    ]["value"] == lock["public_inputs"]["runtime/postgres-ca.pem"]
    reconciler_volumes = {
        item["name"]: item for item in reconciler_pod["volumes"]
    }
    assert reconciler_volumes["trust-inputs"]["configMap"]["name"] == (
        material_names["reconciler-trust"]
    )

    rendered_profile = next(
        cast(dict[str, Any], item)
        for item in yaml.safe_load_all(
            (
                output / "manifests" / "profile-registrar-job.yaml"
            ).read_bytes()
        )
        if item["kind"] == "Job"
    )
    profile_pod = rendered_profile["spec"]["template"]["spec"]
    profile_digest = lock["configurations"]["profile-registration"]
    profile_digest_hex = profile_digest.removeprefix("sha256:")
    assert rendered_profile["metadata"]["name"].endswith(
        profile_digest_hex[:20]
    )
    assert rendered_profile["metadata"]["labels"][
        "control-assurance.io/profile-manifest-digest-prefix"
    ] == profile_digest_hex[:20]
    assert rendered_profile["metadata"]["labels"][
        "control-assurance.io/profile-manifest-digest-base32"
    ] == (
        base64.b32encode(bytes.fromhex(profile_digest_hex))
        .decode("ascii")
        .rstrip("=")
        .lower()
    )
    assert rendered_profile["metadata"]["annotations"][
        "control-assurance.io/profile-manifest-digest"
    ] == profile_digest
    profile_environment = {
        item["name"]: item
        for item in profile_pod["containers"][0]["env"]
    }
    assert profile_environment[
        "ASSURANCE_PROFILE_REGISTRATION_MANIFEST_DIGEST"
    ] == {
        "name": "ASSURANCE_PROFILE_REGISTRATION_MANIFEST_DIGEST",
        "value": lock["configurations"]["profile-registration"],
    }
    profile_volumes = {
        item["name"]: item for item in profile_pod["volumes"]
    }
    assert profile_volumes["profile-manifest"]["configMap"]["name"] == (
        material_names["profile-release"]
    )
    assert profile_volumes["trust-inputs"]["configMap"]["name"] == (
        material_names["runtime-trust"]
    )
    for workload, pod in (
        (rendered_runtime, runtime_pod),
        (rendered_reconciler, reconciler_pod),
        (rendered_profile, profile_pod),
    ):
        template = workload["spec"]["template"]
        assert template["metadata"]["labels"][
            "control-assurance.io/egress-contract"
        ] == egress_selector
        assert template["metadata"]["annotations"][
            "control-assurance.io/egress-contract-digest"
        ] == egress_digest
        assert pod["dnsConfig"] == {
            "options": [{"name": "ndots", "value": "1"}]
        }

    embedded_egress_contract = base64.b64decode(
        by_kind["site-egress-contract"]["binaryData"][
            "site-egress-contract.json"
        ],
        validate=True,
    )
    assert embedded_egress_contract == site_egress_contract.read_bytes()
    assert lock["configurations"]["site-egress"] == (
        f"sha256:{hashlib.sha256(embedded_egress_contract).hexdigest()}"
    )
    site_policy = [
        cast(dict[str, Any], item)
        for item in yaml.safe_load_all(
            (
                output / "manifests" / "site-egress-policy.yaml"
            ).read_bytes()
        )
    ]
    cnp = [item for item in site_policy if item["kind"] == "CiliumNetworkPolicy"]
    assert len(cnp) == 4
    for policy in cnp:
        assert policy["metadata"]["namespace"] == "control-assurance"
        assert policy["metadata"]["annotations"][
            "control-assurance.io/egress-contract-digest"
        ] == egress_digest
        dns_rule = policy["spec"]["egress"][0]
        dns_entries = dns_rule["toPorts"][0]["rules"]["dns"]
        assert dns_entries
        assert all(set(entry) == {"matchName"} for entry in dns_entries)
        assert not any("*" in entry["matchName"] for entry in dns_entries)
        network_rules = policy["spec"]["egress"][1:]
        assert network_rules
        assert all(
            set(rule) == {"toFQDNs", "toPorts"}
            and all(
                set(item) == {"matchName"}
                and "*" not in item["matchName"]
                for item in rule["toFQDNs"]
            )
            and all(
                port["protocol"] == "TCP"
                for group in rule["toPorts"]
                for port in group["ports"]
            )
            for rule in network_rules
        )
        assert "toCIDRSet" not in json.dumps(policy)
    gateway = next(
        item
        for item in site_policy
        if item["kind"] == "CiliumEgressGatewayPolicy"
    )
    assert "namespace" not in gateway["metadata"]
    assert len(gateway["spec"]["selectors"]) == 4
    assert all(
        selector["podSelector"]["matchLabels"][
            "io.kubernetes.pod.namespace"
        ] == "control-assurance"
        for selector in gateway["spec"]["selectors"]
    )
    assert gateway["spec"]["destinationCIDRs"] == [
        "10.60.0.10/32",
        "10.60.0.11/32",
        "10.60.0.30/32",
        "20.190.128.1/32",
    ]
    assert len(gateway["spec"]["egressGateways"]) == 2
    assert all(
        set(item) == {"nodeSelector", "egressIP"}
        and "interface" not in item
        for item in gateway["spec"]["egressGateways"]
    )
    runtime_ca = base64.b64decode(
        by_kind["runtime-trust"]["binaryData"]["postgres-ca.pem"],
        validate=True,
    )
    assert runtime_ca == (
        public_inputs / "runtime" / "postgres-ca.pem"
    ).read_bytes()
    assert lock["public_inputs"]["runtime/postgres-ca.pem"] == (
        f"sha256:{hashlib.sha256(runtime_ca).hexdigest()}"
    )

    for manifest in (output / "manifests").glob("*.yaml"):
        raw = manifest.read_text(encoding="utf-8")
        assert "@sha256:" in raw or manifest.name in {
            "network-policies.yaml",
            "release-material.yaml",
            "site-egress-policy.yaml",
        }
        assert f"sha256:{'0' * 64}" not in raw
        assert f"sha256:{'1' * 64}" not in raw
        assert "ghcr.io/example/" not in raw

    control_plane = output / "manifests" / "control-plane.yaml"
    control_plane.write_text(
        control_plane.read_text(encoding="utf-8") + "\n# tampered\n",
        encoding="utf-8",
    )
    rejected = subprocess.run(
        [
            sys.executable,
            str(script),
            "verify",
            "--release-dir",
            str(output),
            "--expected-lock-digest",
            lock_digest,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected.returncode == 2
    assert "release-manifest-digest-mismatch:control-plane.yaml" in (
        rejected.stderr
    )


def test_kubernetes_release_renderer_rejects_placeholder_release_image(
    tmp_path: Path,
) -> None:
    script = _ROOT / "scripts" / "render-kubernetes-release.py"
    public_inputs = _public_input_directory(tmp_path)
    site_egress_contract = _site_egress_contract(tmp_path)
    rejected = subprocess.run(
        [
            sys.executable,
            str(script),
            "render",
            "--source-dir",
            str(_DEPLOY),
            "--public-input-dir",
            str(public_inputs),
            "--site-egress-contract",
            str(site_egress_contract),
            "--output-dir",
            str(tmp_path / "release"),
            "--application-image",
            (
                "ghcr.io/gyubin02/control-assurance-lab@sha256:"
                + ("0" * 64)
            ),
            "--vault-image",
            _VAULT_IMAGE,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected.returncode == 2
    assert "application-image-placeholder-digest" in rejected.stderr
    assert not (tmp_path / "release").exists()


def test_release_identity_names_do_not_collapse_after_shared_8_hex() -> None:
    namespace = runpy.run_path(
        str(_ROOT / "scripts" / "render-kubernetes-release.py")
    )
    digest_prefix = cast(
        Callable[[str], str],
        namespace["_digest_prefix"],
    )
    first = "sha256:12345678" + ("a" * 56)
    second = "sha256:12345678" + ("b" * 56)
    assert first[:15] == second[:15]
    assert digest_prefix(first) == "12345678" + ("a" * 12)
    assert digest_prefix(second) == "12345678" + ("b" * 12)
    assert digest_prefix(first) != digest_prefix(second)


def test_kubernetes_release_is_deterministic_and_rejects_rewritten_trust_lock(
    tmp_path: Path,
) -> None:
    script = _ROOT / "scripts" / "render-kubernetes-release.py"
    public_inputs = _public_input_directory(tmp_path)
    site_egress_contract = _site_egress_contract(tmp_path)
    first = tmp_path / "first"
    second = tmp_path / "second"

    first_result = subprocess.run(
        _render_command(
            script=script,
            output=first,
            public_inputs=public_inputs,
            site_egress_contract=site_egress_contract,
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    second_result = subprocess.run(
        _render_command(
            script=script,
            output=second,
            public_inputs=public_inputs,
            site_egress_contract=site_egress_contract,
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    assert first_result.returncode == second_result.returncode == 0
    assert first_result.stdout == second_result.stdout
    for relative in (
        "release-lock.json",
        "manifests/control-plane.yaml",
        "manifests/deployment-reconciler.yaml",
        "manifests/network-policies.yaml",
        "manifests/profile-registrar-job.yaml",
        "manifests/release-material.yaml",
        "manifests/runtime-worker.yaml",
        "manifests/site-egress-policy.yaml",
    ):
        assert (first / relative).read_bytes() == (
            second / relative
        ).read_bytes()

    lock_path = first / "release-lock.json"
    lock = json.loads(lock_path.read_bytes())
    lock["public_inputs"]["runtime/postgres-ca.pem"] = (
        f"sha256:{'f' * 64}"
    )
    rewritten = (
        json.dumps(
            lock,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    lock_path.write_bytes(rewritten)
    rewritten_digest = f"sha256:{hashlib.sha256(rewritten).hexdigest()}"

    rejected = subprocess.run(
        [
            sys.executable,
            str(script),
            "verify",
            "--release-dir",
            str(first),
            "--expected-lock-digest",
            rewritten_digest,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected.returncode == 2
    assert "release-public-input-binding-mismatch" in rejected.stderr


def test_kubernetes_release_rejects_unapproved_site_egress_contract_file(
    tmp_path: Path,
) -> None:
    script = _ROOT / "scripts" / "render-kubernetes-release.py"
    public_inputs = _public_input_directory(tmp_path)
    contract = _site_egress_contract(tmp_path)
    contract.chmod(0o664)

    writable = subprocess.run(
        _render_command(
            script=script,
            output=tmp_path / "writable-release",
            public_inputs=public_inputs,
            site_egress_contract=contract,
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    assert writable.returncode == 2
    assert "site-egress-contract-input-invalid" in writable.stderr
    assert not (tmp_path / "writable-release").exists()

    contract.chmod(0o444)
    link = tmp_path / "site-egress-link.json"
    link.symlink_to(contract)
    symlinked = subprocess.run(
        _render_command(
            script=script,
            output=tmp_path / "symlinked-release",
            public_inputs=public_inputs,
            site_egress_contract=link,
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    assert symlinked.returncode == 2
    assert "site-egress-contract-input-invalid" in symlinked.stderr
    assert not (tmp_path / "symlinked-release").exists()


def test_kubernetes_release_rejects_noncanonical_site_egress_contract(
    tmp_path: Path,
) -> None:
    script = _ROOT / "scripts" / "render-kubernetes-release.py"
    public_inputs = _public_input_directory(tmp_path)
    contract = _site_egress_contract(tmp_path)
    document = json.loads(contract.read_bytes())
    contract.chmod(0o644)
    contract.write_text(
        json.dumps(document, indent=2) + "\n",
        encoding="utf-8",
    )
    contract.chmod(0o444)

    rejected = subprocess.run(
        _render_command(
            script=script,
            output=tmp_path / "noncanonical-release",
            public_inputs=public_inputs,
            site_egress_contract=contract,
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected.returncode == 2
    assert (
        "release-json-not-canonical:site-egress-contract.json"
        in rejected.stderr
    )
    assert not (tmp_path / "noncanonical-release").exists()


def test_kubernetes_release_rejects_rehashed_site_egress_policy_tamper(
    tmp_path: Path,
) -> None:
    script = _ROOT / "scripts" / "render-kubernetes-release.py"
    public_inputs = _public_input_directory(tmp_path)
    contract = _site_egress_contract(tmp_path)
    output = tmp_path / "release"
    rendered = subprocess.run(
        _render_command(
            script=script,
            output=output,
            public_inputs=public_inputs,
            site_egress_contract=contract,
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    assert rendered.returncode == 0, rendered.stderr

    policy_path = output / "manifests" / "site-egress-policy.yaml"
    documents = [
        cast(dict[str, Any], item)
        for item in yaml.safe_load_all(policy_path.read_bytes())
    ]
    gateway = next(
        item
        for item in documents
        if item["kind"] == "CiliumEgressGatewayPolicy"
    )
    gateway["spec"]["destinationCIDRs"].append("8.8.8.8/32")
    tampered_policy = yaml.safe_dump_all(
        documents,
        explicit_start=True,
        sort_keys=False,
    ).encode()
    policy_path.write_bytes(tampered_policy)

    lock_path = output / "release-lock.json"
    lock = json.loads(lock_path.read_bytes())
    lock["manifests"]["site-egress-policy.yaml"] = (
        f"sha256:{hashlib.sha256(tampered_policy).hexdigest()}"
    )
    rewritten_lock = (
        json.dumps(
            lock,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    lock_path.write_bytes(rewritten_lock)
    rewritten_digest = (
        f"sha256:{hashlib.sha256(rewritten_lock).hexdigest()}"
    )

    rejected = subprocess.run(
        [
            sys.executable,
            str(script),
            "verify",
            "--release-dir",
            str(output),
            "--expected-lock-digest",
            rewritten_digest,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected.returncode == 2
    assert "release-site-egress-policy-mismatch" in rejected.stderr


def test_kubernetes_release_rejects_rehashed_noncanonical_manifest(
    tmp_path: Path,
) -> None:
    script = _ROOT / "scripts" / "render-kubernetes-release.py"
    public_inputs = _public_input_directory(tmp_path)
    contract = _site_egress_contract(tmp_path)
    output = tmp_path / "release"
    rendered = subprocess.run(
        _render_command(
            script=script,
            output=output,
            public_inputs=public_inputs,
            site_egress_contract=contract,
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    assert rendered.returncode == 0, rendered.stderr

    manifest_path = output / "manifests" / "network-policies.yaml"
    noncanonical = manifest_path.read_bytes() + b"\n"
    manifest_path.write_bytes(noncanonical)

    lock_path = output / "release-lock.json"
    lock = json.loads(lock_path.read_bytes())
    lock["manifests"]["network-policies.yaml"] = (
        f"sha256:{hashlib.sha256(noncanonical).hexdigest()}"
    )
    rewritten_lock = (
        json.dumps(
            lock,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    lock_path.write_bytes(rewritten_lock)
    rewritten_digest = (
        f"sha256:{hashlib.sha256(rewritten_lock).hexdigest()}"
    )

    rejected = subprocess.run(
        [
            sys.executable,
            str(script),
            "verify",
            "--release-dir",
            str(output),
            "--expected-lock-digest",
            rewritten_digest,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected.returncode == 2
    assert (
        "release-manifest-not-canonical:network-policies.yaml"
        in rejected.stderr
    )


def test_kubernetes_release_rejects_symlinked_or_extra_public_input(
    tmp_path: Path,
) -> None:
    script = _ROOT / "scripts" / "render-kubernetes-release.py"
    public_inputs = _public_input_directory(tmp_path)
    site_egress_contract = _site_egress_contract(tmp_path)
    target = public_inputs / "runtime" / "elastic-ca.pem"
    target.unlink()
    target.symlink_to(public_inputs / "runtime" / "postgres-ca.pem")

    rejected = subprocess.run(
        _render_command(
            script=script,
            output=tmp_path / "symlink-release",
            public_inputs=public_inputs,
            site_egress_contract=site_egress_contract,
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected.returncode == 2
    assert "public-input-unavailable:runtime/elastic-ca.pem" in (
        rejected.stderr
    )

    target.unlink()
    target.write_bytes(b"test-only-public-input:runtime/elastic-ca.pem")
    target.chmod(0o444)
    extra = public_inputs / "runtime" / "unbound-ca.pem"
    extra.write_bytes(b"must-not-enter-the-release")
    extra.chmod(0o444)
    rejected = subprocess.run(
        _render_command(
            script=script,
            output=tmp_path / "extra-release",
            public_inputs=public_inputs,
            site_egress_contract=site_egress_contract,
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected.returncode == 2
    assert "public-input-file-set-mismatch" in rejected.stderr


def test_web_server_runtime_excludes_unused_standard_extras() -> None:
    project = tomllib.loads(
        (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    dependencies = project["project"]["optional-dependencies"][
        "control-plane"
    ]
    assert "uvicorn>=0.52,<0.53" in dependencies
    assert not any(item.startswith("uvicorn[") for item in dependencies)
    lock = (_ROOT / "requirements" / "runtime.lock").read_text(
        encoding="utf-8"
    )
    assert "\nuvloop==" not in lock
    assert "\nwatchfiles==" not in lock
    assert "\nwebsockets==" not in lock
    assert "\nhttptools==" not in lock
