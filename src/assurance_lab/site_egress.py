"""Strict, release-bound Cilium egress contract rendering.

This module deliberately supports one network architecture.  Kubernetes
NetworkPolicy supplies the namespace default deny and ingress boundary.
CiliumNetworkPolicy supplies exact DNS-query and FQDN/port allowlisting.
CiliumEgressGatewayPolicy routes a separately approved static CIDR envelope
through explicit gateway nodes and egress addresses.  The site perimeter
must deny every direct external path from workload pods and ordinary nodes,
so a DNS answer outside that routing envelope fails closed.

The contract is public release material, not a credential.  Its digest is
attached to every selected pod and every generated policy so a release review
can identify the exact network authority that was admitted.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final, NoReturn, cast

SITE_EGRESS_SCHEMA: Final = "control-assurance/site-egress-contract/v3"
SITE_EGRESS_PROFILE: Final = "cilium-egress-gateway/1.20"
SITE_EGRESS_LOCK_IDENTITY: Final = "site-egress"
SITE_EGRESS_MANIFEST: Final = "site-egress-policy.yaml"
SITE_EGRESS_MATERIAL_KIND: Final = "site-egress-contract"
SITE_EGRESS_CONTRACT_KEY: Final = "site-egress-contract.json"
SITE_EGRESS_DIGEST_LABEL: Final = "control-assurance.io/egress-contract"
SITE_EGRESS_DIGEST_ANNOTATION: Final = (
    "control-assurance.io/egress-contract-digest"
)
NAMESPACE: Final = "control-assurance"

_REQUIRED_IDENTITY_LABELS: Final = (
    "app.kubernetes.io/component",
    "app.kubernetes.io/name",
    "control-assurance.io/egress-contract",
    "io.kubernetes.pod.namespace",
)
_CILIUM_REQUIREMENTS = {
    "minimum_version": "1.20.0",
    "egress_gateway_enabled": True,
    "bpf_masquerade": True,
    "kube_proxy_replacement": True,
    "l7_proxy_enabled": True,
    "endpoint_policy_overflow_lockdown_enabled": True,
    "identity_allocation_mode": "crd",
    "ipv6_enabled": False,
    "cluster_mesh_enabled": False,
    "cilium_endpoint_slice_enabled": False,
}
_WORKLOAD_LABELS: Final[dict[str, dict[str, str]]] = {
    "control-plane": {
        "app.kubernetes.io/name": "control-assurance",
        "app.kubernetes.io/component": "control-plane",
    },
    "deployment-reconciler": {
        "app.kubernetes.io/name": "control-assurance",
        "app.kubernetes.io/component": "deployment-reconciler",
    },
    "runtime-worker": {
        "app.kubernetes.io/name": "control-assurance-runtime",
        "app.kubernetes.io/component": "runtime-worker",
    },
    "profile-registrar": {
        "app.kubernetes.io/name": "control-assurance-runtime",
        "app.kubernetes.io/component": "profile-registrar",
    },
}
_WORKLOAD_PORTS: Final[dict[str, frozenset[int]]] = {
    "control-plane": frozenset({443, 5432}),
    "deployment-reconciler": frozenset({5432}),
    "runtime-worker": frozenset({443, 5432}),
    "profile-registrar": frozenset({5432}),
}
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_KUBERNETES_LABEL_NAME = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$"
)
_DESTINATION_NAME = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
_CHANGE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{2,127}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_PLACEHOLDER_WORDS = frozenset(
    {"change-me", "changeme", "example", "placeholder", "replace-me"}
)
_MAX_DESTINATIONS_PER_WORKLOAD = 64
_MAX_CIDRS_PER_DESTINATION = 64
_MAX_TOTAL_DESTINATION_CIDRS = 256
_MAX_DIRECT_SOURCE_CIDRS_PER_CLASS = 64


class SiteEgressContractError(ValueError):
    """The site egress contract cannot authorize a production release."""


def _fail(code: str) -> NoReturn:
    raise SiteEgressContractError(code)


def _cilium_requirements_document() -> dict[str, object]:
    return {
        **_CILIUM_REQUIREMENTS,
        "required_identity_labels": list(_REQUIRED_IDENTITY_LABELS),
    }


def _exact_mapping(
    value: object,
    *,
    keys: set[str],
    code: str,
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        _fail(code)
    return cast(dict[str, Any], value)


def _string(value: object, *, code: str, maximum: int = 253) -> str:
    if (
        type(value) is not str
        or not value
        or len(value.encode("utf-8")) > maximum
        or "\x00" in value
        or "\r" in value
        or "\n" in value
    ):
        _fail(code)
    return value


def _label_name(value: str, *, code: str) -> str:
    if _KUBERNETES_LABEL_NAME.fullmatch(value) is None:
        _fail(code)
    return value


def _label_key(value: object, *, code: str) -> str:
    key = _string(value, code=code)
    if "/" not in key:
        return _label_name(key, code=code)
    prefix, name = key.split("/", 1)
    if (
        not prefix
        or len(prefix) > 253
        or not _valid_fqdn(prefix)
    ):
        _fail(code)
    return f"{prefix}/{_label_name(name, code=code)}"


def _label_value(value: object, *, code: str) -> str:
    text = _string(value, code=code, maximum=63)
    return _label_name(text, code=code)


def _valid_fqdn(value: str) -> bool:
    return (
        3 <= len(value) <= 253
        and "." in value
        and not value.startswith(".")
        and not value.endswith(".")
        and all(_DNS_LABEL.fullmatch(label) is not None for label in value.split("."))
    )


def _fqdn(value: object) -> str:
    name = _string(value, code="site-egress-fqdn-invalid").lower()
    if (
        value != name
        or not _valid_fqdn(name)
        or "*" in name
        or name.endswith(
            (
                ".example",
                ".example.com",
                ".example.net",
                ".example.org",
                ".invalid",
                ".localhost",
                ".test",
            )
        )
    ):
        _fail("site-egress-fqdn-invalid")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    _fail("site-egress-fqdn-invalid")


def _network(value: object) -> str:
    text = _string(value, code="site-egress-cidr-invalid", maximum=64)
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError:
        _fail("site-egress-cidr-invalid")
    if (
        type(network) is not ipaddress.IPv4Network
        or str(network) != text
        or network.prefixlen < 24
        or network.is_loopback
        or network.is_link_local
        or network.is_multicast
        or network.is_reserved
        or network.is_unspecified
    ):
        _fail("site-egress-cidr-invalid")
    return text


def _direct_source_network(value: object) -> str:
    text = _string(
        value,
        code="site-egress-perimeter-source-cidr-invalid",
        maximum=64,
    )
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError:
        _fail("site-egress-perimeter-source-cidr-invalid")
    if (
        type(network) is not ipaddress.IPv4Network
        or str(network) != text
        or network.prefixlen < 8
        or network.is_loopback
        or network.is_link_local
        or network.is_multicast
        or network.is_reserved
        or network.is_unspecified
    ):
        _fail("site-egress-perimeter-source-cidr-invalid")
    return text


def _network_sort_key(value: str) -> tuple[int, int]:
    network = ipaddress.ip_network(value)
    return int(network.network_address), network.prefixlen


def _direct_source_networks(
    value: object,
    *,
    source_class: str,
) -> tuple[str, ...]:
    cidrs = tuple(
        _direct_source_network(item)
        for item in _sequence(
            value,
            minimum=1,
            maximum=_MAX_DIRECT_SOURCE_CIDRS_PER_CLASS,
            code=f"site-egress-{source_class}-source-cidrs-invalid",
        )
    )
    if cidrs != tuple(sorted(set(cidrs), key=_network_sort_key)):
        _fail(f"site-egress-{source_class}-source-cidrs-not-canonical")
    return cidrs


def _address(value: object) -> str:
    text = _string(value, code="site-egress-gateway-ip-invalid", maximum=45)
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        _fail("site-egress-gateway-ip-invalid")
    if (
        type(address) is not ipaddress.IPv4Address
        or str(address) != text
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        _fail("site-egress-gateway-ip-invalid")
    return text


def _sequence(
    value: object,
    *,
    minimum: int,
    maximum: int,
    code: str,
) -> Sequence[object]:
    if (
        type(value) is not list
        or not minimum <= len(value) <= maximum
    ):
        _fail(code)
    return cast(list[object], value)


@dataclass(frozen=True, slots=True)
class SiteEgressDestination:
    name: str
    fqdn: str
    cidrs: tuple[str, ...]
    port: int

    def as_document(self) -> dict[str, object]:
        return {
            "cidrs": list(self.cidrs),
            "fqdn": self.fqdn,
            "name": self.name,
            "port": self.port,
        }


@dataclass(frozen=True, slots=True)
class SiteEgressGateway:
    node_name: str
    egress_ip: str

    def as_document(self) -> dict[str, object]:
        return {
            "egress_ip": self.egress_ip,
            "node_selector": {"kubernetes.io/hostname": self.node_name},
        }


@dataclass(frozen=True, slots=True)
class SiteEgressContract:
    dns_namespace: str
    dns_pod_selector: tuple[tuple[str, str], ...]
    direct_denied_node_source_cidrs: tuple[str, ...]
    direct_denied_pod_source_cidrs: tuple[str, ...]
    gateways: tuple[SiteEgressGateway, ...]
    workloads: tuple[tuple[str, tuple[SiteEgressDestination, ...]], ...]
    perimeter_change_reference: str

    @property
    def workload_map(self) -> dict[str, tuple[SiteEgressDestination, ...]]:
        return dict(self.workloads)

    @property
    def destination_cidrs(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    cidr
                    for _, destinations in self.workloads
                    for destination in destinations
                    for cidr in destination.cidrs
                },
                key=lambda value: (
                    int(ipaddress.ip_network(value).network_address),
                    ipaddress.ip_network(value).prefixlen,
                ),
            )
        )

    def as_document(self) -> dict[str, object]:
        gateway_ips = [gateway.egress_ip for gateway in self.gateways]
        return {
            "cilium": _cilium_requirements_document(),
            "cluster_dns": {
                "namespace": self.dns_namespace,
                "pod_selector": dict(self.dns_pod_selector),
            },
            "site_perimeter_enforcement": {
                "allowed_gateway_source_ips": gateway_ips,
                "change_reference": self.perimeter_change_reference,
                "contracted_destination_cidrs": list(
                    self.destination_cidrs
                ),
                "deny_all_direct_external_pod_and_node_egress": True,
                "deny_gateway_sources_outside_contracted_destinations": True,
                "direct_denied_node_source_cidrs": list(
                    self.direct_denied_node_source_cidrs
                ),
                "direct_denied_pod_source_cidrs": list(
                    self.direct_denied_pod_source_cidrs
                ),
                "gateway_allow_exception_precedes_direct_deny": True,
                "perimeter_ipv6_external_egress_disabled": True,
            },
            "gateways": [gateway.as_document() for gateway in self.gateways],
            "profile": SITE_EGRESS_PROFILE,
            "schema": SITE_EGRESS_SCHEMA,
            "workloads": {
                name: [
                    destination.as_document()
                    for destination in destinations
                ]
                for name, destinations in self.workloads
            },
        }


def _parse_destination(
    value: object,
    *,
    workload: str,
) -> SiteEgressDestination:
    document = _exact_mapping(
        value,
        keys={"name", "fqdn", "cidrs", "port"},
        code="site-egress-destination-shape",
    )
    name = _string(
        document["name"],
        code="site-egress-destination-name-invalid",
        maximum=63,
    )
    if _DESTINATION_NAME.fullmatch(name) is None:
        _fail("site-egress-destination-name-invalid")
    port = document["port"]
    if (
        type(port) is not int
        or port not in _WORKLOAD_PORTS[workload]
    ):
        _fail("site-egress-workload-port-invalid")
    cidrs = tuple(
        _network(item)
        for item in _sequence(
            document["cidrs"],
            minimum=1,
            maximum=_MAX_CIDRS_PER_DESTINATION,
            code="site-egress-cidrs-invalid",
        )
    )
    if len(cidrs) != len(set(cidrs)):
        _fail("site-egress-cidr-duplicate")
    return SiteEgressDestination(
        name=name,
        fqdn=_fqdn(document["fqdn"]),
        cidrs=cidrs,
        port=port,
    )


def _parse_gateway(value: object) -> SiteEgressGateway:
    document = _exact_mapping(
        value,
        keys={"node_selector", "egress_ip"},
        code="site-egress-gateway-shape",
    )
    selector = _exact_mapping(
        document["node_selector"],
        keys={"kubernetes.io/hostname"},
        code="site-egress-gateway-selector-invalid",
    )
    node_name = _label_value(
        selector["kubernetes.io/hostname"],
        code="site-egress-gateway-selector-invalid",
    )
    return SiteEgressGateway(
        node_name=node_name,
        egress_ip=_address(document["egress_ip"]),
    )


def parse_site_egress_contract(value: object) -> SiteEgressContract:
    """Parse one strict canonicalizable production site contract."""

    document = _exact_mapping(
        value,
        keys={
            "cilium",
            "cluster_dns",
            "gateways",
            "profile",
            "schema",
            "site_perimeter_enforcement",
            "workloads",
        },
        code="site-egress-contract-shape",
    )
    if document["schema"] != SITE_EGRESS_SCHEMA:
        _fail("site-egress-schema-unsupported")
    if document["profile"] != SITE_EGRESS_PROFILE:
        _fail("site-egress-profile-unsupported")
    cilium = _exact_mapping(
        document["cilium"],
        keys=set(_cilium_requirements_document()),
        code="site-egress-cilium-requirements-invalid",
    )
    if cilium != _cilium_requirements_document():
        _fail("site-egress-cilium-requirements-invalid")

    dns = _exact_mapping(
        document["cluster_dns"],
        keys={"namespace", "pod_selector"},
        code="site-egress-dns-identity-invalid",
    )
    namespace = _string(
        dns["namespace"],
        code="site-egress-dns-identity-invalid",
        maximum=63,
    )
    if _DNS_LABEL.fullmatch(namespace) is None:
        _fail("site-egress-dns-identity-invalid")
    raw_selector = dns["pod_selector"]
    if type(raw_selector) is not dict or not 1 <= len(raw_selector) <= 4:
        _fail("site-egress-dns-identity-invalid")
    selector = tuple(
        sorted(
            (
                _label_key(
                    key,
                    code="site-egress-dns-identity-invalid",
                ),
                _label_value(
                    label_value,
                    code="site-egress-dns-identity-invalid",
                ),
            )
            for key, label_value in raw_selector.items()
        )
    )

    gateways = tuple(
        _parse_gateway(item)
        for item in _sequence(
            document["gateways"],
            minimum=2,
            maximum=8,
            code="site-egress-gateway-count-invalid",
        )
    )
    if (
        len({gateway.node_name for gateway in gateways}) != len(gateways)
        or len({gateway.egress_ip for gateway in gateways}) != len(gateways)
    ):
        _fail("site-egress-gateway-duplicate")

    raw_workloads = _exact_mapping(
        document["workloads"],
        keys=set(_WORKLOAD_LABELS),
        code="site-egress-workload-set-invalid",
    )
    workloads: list[
        tuple[str, tuple[SiteEgressDestination, ...]]
    ] = []
    destination_by_name: dict[str, SiteEgressDestination] = {}
    for workload in _WORKLOAD_LABELS:
        destinations = tuple(
            _parse_destination(item, workload=workload)
            for item in _sequence(
                raw_workloads[workload],
                minimum=1,
                maximum=_MAX_DESTINATIONS_PER_WORKLOAD,
                code="site-egress-destination-count-invalid",
            )
        )
        if len({item.name for item in destinations}) != len(destinations):
            _fail("site-egress-destination-duplicate")
        for destination in destinations:
            previous = destination_by_name.setdefault(
                destination.name,
                destination,
            )
            if previous != destination:
                _fail("site-egress-destination-name-conflict")
        workloads.append((workload, destinations))

    destination_networks = [
        ipaddress.ip_network(cidr)
        for _, destinations in workloads
        for destination in destinations
        for cidr in destination.cidrs
    ]
    if (
        len({str(network) for network in destination_networks})
        > _MAX_TOTAL_DESTINATION_CIDRS
    ):
        _fail("site-egress-cidr-budget-exceeded")
    for gateway in gateways:
        address = ipaddress.ip_address(gateway.egress_ip)
        if any(address in network for network in destination_networks):
            _fail("site-egress-gateway-destination-overlap")

    perimeter = _exact_mapping(
        document["site_perimeter_enforcement"],
        keys={
            "allowed_gateway_source_ips",
            "change_reference",
            "contracted_destination_cidrs",
            "deny_all_direct_external_pod_and_node_egress",
            "deny_gateway_sources_outside_contracted_destinations",
            "direct_denied_node_source_cidrs",
            "direct_denied_pod_source_cidrs",
            "gateway_allow_exception_precedes_direct_deny",
            "perimeter_ipv6_external_egress_disabled",
        },
        code="site-egress-perimeter-contract-invalid",
    )
    change_reference = _string(
        perimeter["change_reference"],
        code="site-egress-perimeter-contract-invalid",
        maximum=128,
    )
    deny_all_direct = perimeter[
        "deny_all_direct_external_pod_and_node_egress"
    ]
    deny_gateway_outside = perimeter[
        "deny_gateway_sources_outside_contracted_destinations"
    ]
    gateway_exception_first = perimeter[
        "gateway_allow_exception_precedes_direct_deny"
    ]
    ipv6_external_egress_disabled = perimeter[
        "perimeter_ipv6_external_egress_disabled"
    ]
    if (
        _CHANGE_REFERENCE.fullmatch(change_reference) is None
        or change_reference.lower() in _PLACEHOLDER_WORDS
        or deny_all_direct is not True
        or deny_gateway_outside is not True
        or gateway_exception_first is not True
        or ipv6_external_egress_disabled is not True
    ):
        _fail("site-egress-perimeter-contract-invalid")
    direct_denied_node_source_cidrs = _direct_source_networks(
        perimeter["direct_denied_node_source_cidrs"],
        source_class="node",
    )
    direct_denied_pod_source_cidrs = _direct_source_networks(
        perimeter["direct_denied_pod_source_cidrs"],
        source_class="pod",
    )
    direct_source_networks = [
        ipaddress.ip_network(cidr)
        for cidr in (
            *direct_denied_node_source_cidrs,
            *direct_denied_pod_source_cidrs,
        )
    ]
    if any(
        left.overlaps(right)
        for index, left in enumerate(direct_source_networks)
        for right in direct_source_networks[index + 1 :]
    ):
        _fail("site-egress-perimeter-source-cidr-overlap")
    allowed_sources = tuple(
        _address(item)
        for item in _sequence(
            perimeter["allowed_gateway_source_ips"],
            minimum=2,
            maximum=8,
            code="site-egress-perimeter-contract-invalid",
        )
    )
    if allowed_sources != tuple(
        gateway.egress_ip for gateway in gateways
    ):
        _fail("site-egress-perimeter-source-mismatch")
    contracted_cidrs = tuple(
        _network(item)
        for item in _sequence(
            perimeter["contracted_destination_cidrs"],
            minimum=1,
            maximum=_MAX_TOTAL_DESTINATION_CIDRS,
            code="site-egress-perimeter-contract-invalid",
        )
    )
    if contracted_cidrs != tuple(
        sorted(
            {str(network) for network in destination_networks},
            key=lambda value: (
                int(ipaddress.ip_network(value).network_address),
                ipaddress.ip_network(value).prefixlen,
            ),
        )
    ):
        _fail("site-egress-perimeter-destination-mismatch")

    return SiteEgressContract(
        dns_namespace=namespace,
        dns_pod_selector=selector,
        direct_denied_node_source_cidrs=(
            direct_denied_node_source_cidrs
        ),
        direct_denied_pod_source_cidrs=direct_denied_pod_source_cidrs,
        gateways=gateways,
        workloads=tuple(workloads),
        perimeter_change_reference=change_reference,
    )


def _digest_label_value(digest: str) -> str:
    """Return a Kubernetes-label-safe value retaining all 256 digest bits."""

    if _DIGEST.fullmatch(digest) is None:
        _fail("site-egress-digest-invalid")
    digest_bytes = bytes.fromhex(digest.removeprefix("sha256:"))
    return base64.b32encode(digest_bytes).decode("ascii").rstrip("=").lower()


def _policy_metadata(
    *,
    name: str,
    component: str,
    digest: str,
    namespaced: bool,
) -> dict[str, Any]:
    selector_digest = _digest_label_value(digest)
    metadata: dict[str, Any] = {
        "name": name,
        "labels": {
            "app.kubernetes.io/name": "control-assurance",
            "app.kubernetes.io/component": component,
            SITE_EGRESS_DIGEST_LABEL: selector_digest,
        },
        "annotations": {SITE_EGRESS_DIGEST_ANNOTATION: digest},
    }
    if namespaced:
        metadata["namespace"] = NAMESPACE
    return metadata


def _cilium_network_policy(
    *,
    workload: str,
    destinations: Sequence[SiteEgressDestination],
    contract: SiteEgressContract,
    digest: str,
) -> dict[str, Any]:
    fqdn_names = sorted({item.fqdn for item in destinations})
    egress: list[dict[str, object]] = [
        {
            "toEndpoints": [
                {
                    "matchLabels": {
                        "k8s:io.kubernetes.pod.namespace": (
                            contract.dns_namespace
                        ),
                        **{
                            f"k8s:{key}": value
                            for key, value in contract.dns_pod_selector
                        },
                    }
                }
            ],
            "toPorts": [
                {
                    "ports": [{"port": "53", "protocol": "ANY"}],
                    "rules": {
                        "dns": [
                            {"matchName": fqdn}
                            for fqdn in fqdn_names
                        ]
                    },
                }
            ],
        }
    ]
    for port in sorted({item.port for item in destinations}):
        names = sorted(
            {
                item.fqdn
                for item in destinations
                if item.port == port
            }
        )
        egress.append(
            {
                "toFQDNs": [{"matchName": name} for name in names],
                "toPorts": [
                    {
                        "ports": [
                            {"port": str(port), "protocol": "TCP"}
                        ]
                    }
                ],
            }
        )
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": _policy_metadata(
            name=f"control-assurance-{workload}-egress",
            component=workload,
            digest=digest,
            namespaced=True,
        ),
        "spec": {
            "endpointSelector": {
                "matchLabels": {
                    **_WORKLOAD_LABELS[workload],
                    SITE_EGRESS_DIGEST_LABEL: _digest_label_value(digest),
                }
            },
            "egress": egress,
        },
    }


def render_site_egress_documents(
    contract: SiteEgressContract,
    *,
    digest: str,
) -> list[dict[str, Any]]:
    """Render exact Cilium allow and transparent routing policies."""

    if type(contract) is not SiteEgressContract:
        raise TypeError("contract must be an exact SiteEgressContract")
    documents = [
        _cilium_network_policy(
            workload=workload,
            destinations=destinations,
            contract=contract,
            digest=digest,
        )
        for workload, destinations in contract.workloads
    ]
    selector_digest = _digest_label_value(digest)
    documents.append(
        {
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumEgressGatewayPolicy",
            "metadata": _policy_metadata(
                name="control-assurance-egress-gateway",
                component="egress-gateway",
                digest=digest,
                namespaced=False,
            ),
            "spec": {
                "selectors": [
                    {
                        "podSelector": {
                            "matchLabels": {
                                "io.kubernetes.pod.namespace": NAMESPACE,
                                **_WORKLOAD_LABELS[workload],
                                SITE_EGRESS_DIGEST_LABEL: selector_digest,
                            }
                        }
                    }
                    for workload in _WORKLOAD_LABELS
                ],
                "destinationCIDRs": list(contract.destination_cidrs),
                "egressGateways": [
                    {
                        "nodeSelector": {
                            "matchLabels": {
                                "kubernetes.io/hostname": gateway.node_name
                            }
                        },
                        "egressIP": gateway.egress_ip,
                    }
                    for gateway in contract.gateways
                ],
            },
        }
    )
    return documents


def bind_workload_to_site_egress(
    document: dict[str, Any],
    *,
    digest: str,
) -> None:
    """Bind one rendered Deployment/Job pod template to its policy digest."""

    selector_digest = _digest_label_value(digest)
    try:
        template = document["spec"]["template"]
        metadata = template["metadata"]
        pod = template["spec"]
        labels = metadata.setdefault("labels", {})
        annotations = metadata.setdefault("annotations", {})
        if not isinstance(labels, dict) or not isinstance(annotations, dict):
            raise KeyError
    except (KeyError, TypeError):
        _fail("site-egress-workload-binding-invalid")
    labels[SITE_EGRESS_DIGEST_LABEL] = selector_digest
    annotations[SITE_EGRESS_DIGEST_ANNOTATION] = digest
    pod["dnsPolicy"] = "ClusterFirst"
    pod["dnsConfig"] = {
        "options": [{"name": "ndots", "value": "1"}]
    }
