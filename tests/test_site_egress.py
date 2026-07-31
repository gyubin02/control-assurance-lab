from __future__ import annotations

import base64
import copy
from typing import Any

import pytest

from assurance_lab.site_egress import (
    SITE_EGRESS_DIGEST_ANNOTATION,
    SITE_EGRESS_DIGEST_LABEL,
    SiteEgressContractError,
    bind_workload_to_site_egress,
    parse_site_egress_contract,
    render_site_egress_documents,
)

_DIGEST = "sha256:" + ("a" * 64)


def _contract() -> dict[str, Any]:
    return {
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


def _rejected(document: object, code: str) -> None:
    with pytest.raises(SiteEgressContractError, match=f"^{code}$"):
        parse_site_egress_contract(document)


def test_site_egress_renders_exact_fqdn_ports_and_cidr_gateway_route() -> None:
    contract = parse_site_egress_contract(_contract())
    assert contract.as_document() == _contract()
    documents = render_site_egress_documents(contract, digest=_DIGEST)
    selector_digest = (
        base64.b32encode(bytes.fromhex("a" * 64))
        .decode("ascii")
        .rstrip("=")
        .lower()
    )
    assert len(selector_digest) == 52
    policies = {
        item["metadata"]["name"]: item
        for item in documents
    }
    assert len(policies) == 5
    expected_fqdns = {
        "control-assurance-control-plane-egress": {
            443: ["login.microsoftonline.com"],
            5432: ["postgres.security.internal"],
        },
        "control-assurance-deployment-reconciler-egress": {
            5432: [
                "postgres.security.internal",
                "runtime-postgres.security.internal",
            ],
        },
        "control-assurance-profile-registrar-egress": {
            5432: ["runtime-postgres.security.internal"],
        },
        "control-assurance-runtime-worker-egress": {
            443: ["elastic.security.internal"],
            5432: ["runtime-postgres.security.internal"],
        },
    }

    for policy_name, policy in policies.items():
        assert policy["metadata"]["annotations"][
            SITE_EGRESS_DIGEST_ANNOTATION
        ] == _DIGEST
        assert policy["metadata"]["labels"][
            SITE_EGRESS_DIGEST_LABEL
        ] == selector_digest
        if policy["kind"] != "CiliumNetworkPolicy":
            continue
        assert policy["metadata"]["namespace"] == "control-assurance"
        assert policy["spec"]["endpointSelector"]["matchLabels"][
            SITE_EGRESS_DIGEST_LABEL
        ] == selector_digest
        dns = policy["spec"]["egress"][0]
        assert dns["toEndpoints"] == [
            {
                "matchLabels": {
                    "k8s:io.kubernetes.pod.namespace": "kube-system",
                    "k8s:k8s-app": "kube-dns",
                }
            }
        ]
        dns_names = dns["toPorts"][0]["rules"]["dns"]
        assert dns_names
        assert all(set(item) == {"matchName"} for item in dns_names)
        assert "matchPattern" not in str(dns_names)
        observed_fqdns: dict[int, list[str]] = {}
        for rule in policy["spec"]["egress"][1:]:
            assert set(rule) == {"toFQDNs", "toPorts"}
            assert rule["toFQDNs"]
            assert all(
                set(item) == {"matchName"}
                and "*" not in item["matchName"]
                for item in rule["toFQDNs"]
            )
            assert all(
                item["protocol"] == "TCP"
                for group in rule["toPorts"]
                for item in group["ports"]
            )
            ports = [
                int(item["port"])
                for group in rule["toPorts"]
                for item in group["ports"]
            ]
            assert len(ports) == 1
            observed_fqdns[ports[0]] = [
                item["matchName"] for item in rule["toFQDNs"]
            ]
        assert observed_fqdns == expected_fqdns[policy_name]
        assert "toCIDRSet" not in str(policy["spec"]["egress"])

    gateway = policies["control-assurance-egress-gateway"]
    assert gateway["kind"] == "CiliumEgressGatewayPolicy"
    assert "namespace" not in gateway["metadata"]
    assert gateway["spec"]["destinationCIDRs"] == [
        "10.60.0.10/32",
        "10.60.0.11/32",
        "10.60.0.30/32",
        "20.190.128.1/32",
    ]
    assert len(gateway["spec"]["selectors"]) == 4
    assert all(
        item["podSelector"]["matchLabels"][
            "io.kubernetes.pod.namespace"
        ] == "control-assurance"
        for item in gateway["spec"]["selectors"]
    )
    assert all(
        item["podSelector"]["matchLabels"][
            SITE_EGRESS_DIGEST_LABEL
        ] == selector_digest
        for item in gateway["spec"]["selectors"]
    )
    assert gateway["spec"]["egressGateways"] == [
        {
            "nodeSelector": {
                "matchLabels": {
                    "kubernetes.io/hostname": "egress-a"
                }
            },
            "egressIP": "10.255.0.10",
        },
        {
            "nodeSelector": {
                "matchLabels": {
                    "kubernetes.io/hostname": "egress-b"
                }
            },
            "egressIP": "10.255.0.11",
        },
    ]


def test_site_egress_accepts_the_broadest_supported_cidr_boundary() -> None:
    document = _contract()
    document["workloads"]["control-plane"][1]["cidrs"] = [
        "20.190.128.0/24"
    ]
    document["site_perimeter_enforcement"][
        "contracted_destination_cidrs"
    ][-1] = "20.190.128.0/24"
    contract = parse_site_egress_contract(document)
    assert contract.destination_cidrs[-1] == "20.190.128.0/24"


def test_site_egress_rejects_a_gateway_route_map_above_256_cidrs() -> None:
    document = _contract()
    document["workloads"]["control-plane"] = [
        {
            "cidrs": [
                f"10.70.{index // 256}.{index % 256}/32"
                for index in range(offset, offset + 64)
            ],
            "fqdn": f"bulk-{offset}.security.internal",
            "name": f"bulk-{offset}",
            "port": 443,
        }
        for offset in range(0, 320, 64)
    ]
    _rejected(document, "site-egress-cidr-budget-exceeded")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("minimum_version", "1.19.0"),
        ("egress_gateway_enabled", False),
        ("bpf_masquerade", False),
        ("kube_proxy_replacement", False),
        ("l7_proxy_enabled", False),
        ("endpoint_policy_overflow_lockdown_enabled", False),
        ("identity_allocation_mode", "kvstore"),
        ("ipv6_enabled", True),
        ("cluster_mesh_enabled", True),
        ("cilium_endpoint_slice_enabled", True),
        (
            "required_identity_labels",
            [
                "app.kubernetes.io/component",
                "app.kubernetes.io/name",
                "io.kubernetes.pod.namespace",
            ],
        ),
    ],
)
def test_site_egress_rejects_every_unsupported_cilium_mode(
    field: str,
    value: object,
) -> None:
    document = _contract()
    document["cilium"][field] = value
    _rejected(document, "site-egress-cilium-requirements-invalid")


@pytest.mark.parametrize(
    ("fqdn", "cidr", "port", "code"),
    [
        (
            "*.microsoftonline.com",
            "20.190.128.1/32",
            443,
            "site-egress-fqdn-invalid",
        ),
        (
            "login.microsoftonline.com",
            "0.0.0.0/0",
            443,
            "site-egress-cidr-invalid",
        ),
        (
            "login.microsoftonline.com",
            "20.190.128.1/32",
            80,
            "site-egress-workload-port-invalid",
        ),
        (
            "login.microsoftonline.com",
            "10.0.0.0/8",
            443,
            "site-egress-cidr-invalid",
        ),
        (
            "login.microsoftonline.com",
            "10.60.0.0/16",
            443,
            "site-egress-cidr-invalid",
        ),
        (
            "login.microsoftonline.com",
            "20.190.128.0/23",
            443,
            "site-egress-cidr-invalid",
        ),
    ],
)
def test_site_egress_rejects_broad_or_ambiguous_destination(
    fqdn: str,
    cidr: str,
    port: int,
    code: str,
) -> None:
    document = _contract()
    destination = document["workloads"]["control-plane"][1]
    destination["fqdn"] = fqdn
    destination["cidrs"] = [cidr]
    destination["port"] = port
    _rejected(document, code)


def test_site_egress_requires_two_distinct_exact_gateway_nodes_and_ips() -> None:
    document = _contract()
    document["gateways"] = document["gateways"][:1]
    document["site_perimeter_enforcement"][
        "allowed_gateway_source_ips"
    ] = ["10.255.0.10"]
    _rejected(document, "site-egress-gateway-count-invalid")

    document = _contract()
    document["gateways"][1]["node_selector"] = {
        "kubernetes.io/hostname": "egress-a"
    }
    _rejected(document, "site-egress-gateway-duplicate")

    document = _contract()
    document["gateways"][1]["egress_ip"] = "10.255.0.10"
    _rejected(document, "site-egress-gateway-duplicate")

    document = _contract()
    document["gateways"][0]["interface"] = "eth0"
    _rejected(document, "site-egress-gateway-shape")

    document = _contract()
    document["gateways"][0] = {
        "interface": "eth0",
        "node_selector": {
            "kubernetes.io/hostname": "egress-a"
        },
    }
    _rejected(document, "site-egress-gateway-shape")


def test_site_egress_requires_perimeter_to_bind_sources_and_destinations() -> None:
    document = _contract()
    document["site_perimeter_enforcement"][
        "allowed_gateway_source_ips"
    ].reverse()
    _rejected(document, "site-egress-perimeter-source-mismatch")

    document = _contract()
    document["site_perimeter_enforcement"][
        "deny_all_direct_external_pod_and_node_egress"
    ] = False
    _rejected(document, "site-egress-perimeter-contract-invalid")

    document = _contract()
    document["site_perimeter_enforcement"][
        "deny_gateway_sources_outside_contracted_destinations"
    ] = False
    _rejected(document, "site-egress-perimeter-contract-invalid")

    document = _contract()
    document["site_perimeter_enforcement"][
        "gateway_allow_exception_precedes_direct_deny"
    ] = False
    _rejected(document, "site-egress-perimeter-contract-invalid")

    document = _contract()
    document["site_perimeter_enforcement"][
        "perimeter_ipv6_external_egress_disabled"
    ] = False
    _rejected(document, "site-egress-perimeter-contract-invalid")

    document = _contract()
    document["site_perimeter_enforcement"][
        "change_reference"
    ] = "replace-me"
    _rejected(document, "site-egress-perimeter-contract-invalid")

    document = _contract()
    document["site_perimeter_enforcement"][
        "contracted_destination_cidrs"
    ].pop()
    _rejected(document, "site-egress-perimeter-destination-mismatch")


@pytest.mark.parametrize(
    ("source_class", "cidrs", "code"),
    [
        (
            "pod",
            [],
            "site-egress-pod-source-cidrs-invalid",
        ),
        (
            "node",
            ["10.0.0.0/7"],
            "site-egress-perimeter-source-cidr-invalid",
        ),
        (
            "pod",
            ["10.244.0.1/16"],
            "site-egress-perimeter-source-cidr-invalid",
        ),
        (
            "node",
            ["10.51.0.0/16", "10.50.0.0/16"],
            "site-egress-node-source-cidrs-not-canonical",
        ),
        (
            "pod",
            ["10.244.0.0/16", "10.244.0.0/16"],
            "site-egress-pod-source-cidrs-not-canonical",
        ),
    ],
)
def test_site_egress_requires_canonical_bounded_direct_source_cidrs(
    source_class: str,
    cidrs: list[str],
    code: str,
) -> None:
    document = _contract()
    document["site_perimeter_enforcement"][
        f"direct_denied_{source_class}_source_cidrs"
    ] = cidrs
    _rejected(document, code)


def test_site_egress_rejects_overlapping_direct_source_cidrs() -> None:
    document = _contract()
    document["site_perimeter_enforcement"][
        "direct_denied_node_source_cidrs"
    ] = ["10.244.1.0/24"]
    _rejected(document, "site-egress-perimeter-source-cidr-overlap")


def test_site_egress_rejects_more_than_64_direct_source_cidrs_per_class() -> None:
    document = _contract()
    document["site_perimeter_enforcement"][
        "direct_denied_node_source_cidrs"
    ] = [f"10.80.{index}.0/24" for index in range(65)]
    _rejected(document, "site-egress-node-source-cidrs-invalid")


def test_site_egress_allows_gateway_ip_inside_denied_node_range() -> None:
    document = _contract()
    document["site_perimeter_enforcement"][
        "direct_denied_node_source_cidrs"
    ] = ["10.255.0.0/24"]
    contract = parse_site_egress_contract(document)
    assert contract.gateways[0].egress_ip == "10.255.0.10"


def test_site_egress_selector_retains_digest_bits_after_shared_prefix() -> None:
    first = "sha256:" + ("a" * 64)
    second = "sha256:" + ("a" * 12) + ("b" * 52)
    contract = parse_site_egress_contract(_contract())
    first_policy = render_site_egress_documents(
        contract,
        digest=first,
    )[0]
    second_policy = render_site_egress_documents(
        contract,
        digest=second,
    )[0]
    first_label = first_policy["metadata"]["labels"][
        SITE_EGRESS_DIGEST_LABEL
    ]
    second_label = second_policy["metadata"]["labels"][
        SITE_EGRESS_DIGEST_LABEL
    ]
    assert first[:19] == second[:19]
    assert first_label != second_label
    assert len(first_label) == len(second_label) == 52

    first_workload: dict[str, Any] = {
        "spec": {"template": {"metadata": {}, "spec": {}}}
    }
    second_workload = copy.deepcopy(first_workload)
    bind_workload_to_site_egress(first_workload, digest=first)
    bind_workload_to_site_egress(second_workload, digest=second)
    assert (
        first_workload["spec"]["template"]["metadata"]["labels"][
            SITE_EGRESS_DIGEST_LABEL
        ]
        != second_workload["spec"]["template"]["metadata"]["labels"][
            SITE_EGRESS_DIGEST_LABEL
        ]
    )


def test_site_egress_requires_all_four_nonempty_workload_mappings() -> None:
    document = _contract()
    del document["workloads"]["profile-registrar"]
    _rejected(document, "site-egress-workload-set-invalid")

    document = _contract()
    document["workloads"]["runtime-worker"] = []
    _rejected(document, "site-egress-destination-count-invalid")

    document = _contract()
    duplicate = copy.deepcopy(
        document["workloads"]["runtime-worker"][0]
    )
    document["workloads"]["runtime-worker"].append(duplicate)
    _rejected(document, "site-egress-destination-duplicate")
