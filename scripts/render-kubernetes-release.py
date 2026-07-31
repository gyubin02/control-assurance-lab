#!/usr/bin/env python3
"""Render and verify one content-addressed Kubernetes release.

Template configuration files intentionally contain non-deployable digest
placeholders.  Rendering reads the exact public trust/identity bytes, injects
their SHA-256 identities into canonical configuration, embeds the bytes in
immutable ConfigMaps, patches every workload reference, and binds the result
to one out-of-band release-lock digest.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn, cast

import yaml

from assurance_lab.site_egress import (
    SITE_EGRESS_CONTRACT_KEY,
    SITE_EGRESS_LOCK_IDENTITY,
    SITE_EGRESS_MANIFEST,
    SITE_EGRESS_MATERIAL_KIND,
    SiteEgressContractError,
    bind_workload_to_site_egress,
    parse_site_egress_contract,
    render_site_egress_documents,
)

_SCHEMA = "control-assurance/kubernetes-release-lock/v3"
_WORKLOAD_FILES = (
    "control-plane.yaml",
    "deployment-reconciler.yaml",
    "runtime-worker.yaml",
    "profile-registrar-job.yaml",
    "network-policies.yaml",
)
_CONFIGURATION_FILES = (
    "control-plane-config.example.json",
    "runtime-worker-config.example.json",
    "profile-registration-manifest.example.json",
)
_PROFILE_RELEASE_SOURCE = "profile-release.example.yaml"
_SOURCE_FILES = (
    *_WORKLOAD_FILES,
    *_CONFIGURATION_FILES,
    _PROFILE_RELEASE_SOURCE,
)
_MATERIAL_MANIFEST = "release-material.yaml"
_MANIFEST_FILES = (
    *_WORKLOAD_FILES,
    _MATERIAL_MANIFEST,
    SITE_EGRESS_MANIFEST,
)
_EXPECTED_IMAGE_COUNTS = {
    "control-plane.yaml": 1,
    "deployment-reconciler.yaml": 2,
    "runtime-worker.yaml": 4,
    "profile-registrar-job.yaml": 2,
    "network-policies.yaml": 0,
    _MATERIAL_MANIFEST: 0,
    SITE_EGRESS_MANIFEST: 0,
}
_CONFIGURATION_IDENTITIES = {
    "control-plane": "control-plane-config.example.json",
    "runtime-worker": "runtime-worker-config.example.json",
    "profile-registration": "profile-registration-manifest.example.json",
}
_REQUIRED_PUBLIC_INPUTS = {
    "control/key-vault-ca.pem",
    "control/oidc-ca.pem",
    "control/oidc-client.der",
    "control/postgres-ca.pem",
    "runtime/elastic-ca.pem",
    "runtime/postgres-ca.pem",
    "runtime/vault-ca.pem",
}
_MATERIAL_KINDS = {
    "control-config",
    "control-identity",
    "control-trust",
    "profile-release",
    "reconciler-trust",
    "runtime-config",
    "runtime-trust",
    SITE_EGRESS_MATERIAL_KIND,
}
_APPLICATION_PLACEHOLDER_DIGEST = "0" * 64
_VAULT_PLACEHOLDER_DIGEST = "1" * 64
_IMAGE = re.compile(
    r"^(?P<repository>[a-z0-9][a-z0-9._:/-]*)"
    r"@sha256:(?P<digest>[a-f0-9]{64})$"
)
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_MAX_FILE_BYTES = 8 * 1024 * 1024
_MAX_PUBLIC_INPUT_BYTES = 256 * 1024
_MAX_SITE_EGRESS_CONTRACT_BYTES = 128 * 1024
_MAX_CONFIG_MAP_BINARY_BYTES = 700 * 1024
_NAMESPACE = "control-assurance"
_MIN_NAME_DIGEST_HEX = 20


class ReleaseError(ValueError):
    """A stable, secret-free release validation failure."""


def _fail(message: str) -> NoReturn:
    raise ReleaseError(message)


def _sha256(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _digest_prefix(
    digest: str,
    length: int = _MIN_NAME_DIGEST_HEX,
) -> str:
    if (
        _DIGEST.fullmatch(digest) is None
        or type(length) is not int
        or not _MIN_NAME_DIGEST_HEX <= length <= 64
    ):
        _fail("release-identity-digest-invalid")
    return digest.removeprefix("sha256:")[:length]


def _digest_label_value(digest: str) -> str:
    """Encode every digest bit in one Kubernetes-label-safe value."""

    if _DIGEST.fullmatch(digest) is None:
        _fail("release-identity-digest-invalid")
    raw = bytes.fromhex(digest.removeprefix("sha256:"))
    return base64.b32encode(raw).decode("ascii").rstrip("=").lower()


def _metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_regular_file(path: Path) -> bytes:
    """Read one bounded single-link file through a stable no-follow fd."""

    descriptor = -1
    try:
        before_path = path.lstat()
        if (
            not stat.S_ISREG(before_path.st_mode)
            or before_path.st_nlink != 1
            or not 0 < before_path.st_size <= _MAX_FILE_BYTES
        ):
            _fail(f"release-file-not-regular:{path.name}")
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        if _metadata_identity(before) != _metadata_identity(before_path):
            _fail(f"release-file-changed:{path.name}")
        content = bytearray()
        while len(content) <= _MAX_FILE_BYTES:
            chunk = os.read(
                descriptor,
                min(64 * 1024, _MAX_FILE_BYTES + 1 - len(content)),
            )
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        after_path = path.lstat()
        if (
            len(content) != after.st_size
            or len(content) > _MAX_FILE_BYTES
            or _metadata_identity(before) != _metadata_identity(after)
            or _metadata_identity(before_path)
            != _metadata_identity(after_path)
        ):
            _fail(f"release-file-changed:{path.name}")
        return bytes(content)
    except ReleaseError:
        raise
    except OSError as error:
        raise ReleaseError(
            f"release-file-unavailable:{path.name}"
        ) from error
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)


def _read_approved_input(path: Path, *, label: str, maximum: int) -> bytes:
    """Read one operator-approved input with a strict pathname and mode."""

    try:
        before = path.lstat()
        if (
            not path.is_absolute()
            or path.resolve(strict=True) != path
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_mode & 0o022
            or not 0 < before.st_size <= maximum
        ):
            raise OSError
        content = _read_regular_file(path)
        after = path.lstat()
        if (
            _metadata_identity(before) != _metadata_identity(after)
            or len(content) > maximum
        ):
            _fail(f"{label}-changed")
        return content
    except ReleaseError:
        raise
    except (OSError, RuntimeError) as error:
        raise ReleaseError(f"{label}-input-invalid") from error


def _read_public_input(root: Path, reference: str) -> bytes:
    """Read ``scope/name`` without following either directory component."""

    parts = PurePosixPath(reference).parts
    if (
        len(parts) != 2
        or parts[0] not in {"control", "runtime"}
        or any(
            item in {"", ".", ".."} or "/" in item or "\x00" in item
            for item in parts
        )
    ):
        _fail("public-input-reference-invalid")
    descriptors: list[int] = []
    try:
        root_fd = os.open(
            root,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_DIRECTORY", 0),
        )
        descriptors.append(root_fd)
        scope_fd = os.open(
            parts[0],
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_DIRECTORY", 0),
            dir_fd=root_fd,
        )
        descriptors.append(scope_fd)
        descriptor = os.open(
            parts[1],
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=scope_fd,
        )
        descriptors.append(descriptor)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_mode & 0o022
            or not 0 < before.st_size <= _MAX_PUBLIC_INPUT_BYTES
        ):
            _fail(f"public-input-policy:{reference}")
        content = bytearray()
        while len(content) <= _MAX_PUBLIC_INPUT_BYTES:
            chunk = os.read(
                descriptor,
                min(
                    64 * 1024,
                    _MAX_PUBLIC_INPUT_BYTES + 1 - len(content),
                ),
            )
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        if (
            _metadata_identity(before) != _metadata_identity(after)
            or len(content) != after.st_size
            or len(content) > _MAX_PUBLIC_INPUT_BYTES
        ):
            _fail(f"public-input-changed:{reference}")
        return bytes(content)
    except ReleaseError:
        raise
    except OSError as error:
        raise ReleaseError(
            f"public-input-unavailable:{reference}"
        ) from error
    finally:
        for descriptor in reversed(descriptors):
            with suppress(OSError):
                os.close(descriptor)


def _assert_exact_public_input_tree(
    directory: Path,
    expected: set[str],
) -> None:
    try:
        root = directory.lstat()
        if not stat.S_ISDIR(root.st_mode) or directory.resolve() != directory:
            raise OSError
        observed: set[str] = set()
        scopes: set[str] = set()
        for scope in directory.iterdir():
            metadata = scope.lstat()
            if not stat.S_ISDIR(metadata.st_mode):
                raise OSError
            scopes.add(scope.name)
            for item in scope.iterdir():
                child = item.lstat()
                if (
                    not stat.S_ISREG(child.st_mode)
                    or child.st_nlink != 1
                    or child.st_mode & 0o022
                ):
                    raise OSError
                observed.add(f"{scope.name}/{item.name}")
    except (OSError, RuntimeError) as error:
        raise ReleaseError("public-input-directory-invalid") from error
    if scopes != {PurePosixPath(item).parts[0] for item in expected}:
        _fail("public-input-file-set-mismatch")
    if observed != expected:
        _fail("public-input-file-set-mismatch")


def _canonical_document(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _canonical_lock(value: object) -> bytes:
    return _canonical_document(value) + b"\n"


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("release-json-duplicate-key")
        result[key] = value
    return result


def _parse_json_document(
    data: bytes,
    *,
    name: str,
    canonical: bool,
) -> dict[str, Any]:
    try:
        value = json.loads(data, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseError(f"release-json-invalid:{name}") from error
    if not isinstance(value, dict):
        _fail(f"release-json-invalid-shape:{name}")
    result = cast(dict[str, Any], value)
    if canonical:
        expected = _canonical_document(result)
        if data not in {expected, expected + b"\n"}:
            _fail(f"release-json-not-canonical:{name}")
    return result


def _parse_lock(data: bytes) -> dict[str, Any]:
    result = _parse_json_document(
        data.removesuffix(b"\n"),
        name="release-lock.json",
        canonical=True,
    )
    if _canonical_lock(result) != data:
        _fail("release-lock-not-canonical")
    return result


def _validated_image(value: str, *, label: str) -> str:
    match = _IMAGE.fullmatch(value)
    if match is None:
        _fail(f"{label}-image-not-digest-pinned")
    repository = match.group("repository")
    digest = match.group("digest")
    final_segment = repository.rsplit("/", 1)[-1]
    if ":" in final_segment:
        _fail(f"{label}-image-tag-not-allowed")
    if repository.endswith(".invalid") or "/example/" in f"/{repository}/":
        _fail(f"{label}-image-placeholder-repository")
    if len(set(digest)) == 1:
        _fail(f"{label}-image-placeholder-digest")
    return value


def _yaml_documents(data: bytes, *, name: str) -> list[dict[str, Any]]:
    try:
        raw_documents = list(yaml.safe_load_all(data))
    except yaml.YAMLError as error:
        raise ReleaseError(f"manifest-invalid-yaml:{name}") from error
    if not raw_documents or any(
        not isinstance(item, dict) for item in raw_documents
    ):
        _fail(f"manifest-invalid-document:{name}")
    return [cast(dict[str, Any], item) for item in raw_documents]


def _pod_spec(document: Mapping[str, Any]) -> dict[str, Any] | None:
    kind = document.get("kind")
    try:
        if kind in {"Deployment", "Job"}:
            return cast(
                dict[str, Any],
                document["spec"]["template"]["spec"],
            )
    except (KeyError, TypeError):
        _fail("workload-missing-pod-spec")
    return None


def _container_sets(
    pod: Mapping[str, Any],
) -> Sequence[list[dict[str, Any]]]:
    result: list[list[dict[str, Any]]] = []
    for field in ("initContainers", "containers"):
        value = pod.get(field, [])
        if not isinstance(value, list) or any(
            not isinstance(item, dict) for item in value
        ):
            _fail("workload-invalid-container-list")
        result.append(cast(list[dict[str, Any]], value))
    return result


def _render_images(
    documents: list[dict[str, Any]],
    *,
    application_image: str,
    vault_image: str,
) -> None:
    observed = 0
    for document in documents:
        pod = _pod_spec(document)
        if pod is None:
            continue
        for containers in _container_sets(pod):
            for container in containers:
                name = container.get("name")
                image = container.get("image")
                if not isinstance(name, str) or not isinstance(image, str):
                    _fail("workload-container-name-or-image-missing")
                match = _IMAGE.fullmatch(image)
                if match is None:
                    _fail("source-image-not-digest-pinned")
                repository = match.group("repository")
                digest = match.group("digest")
                if name == "vault-token-agent":
                    if (
                        repository != "hashicorp/vault"
                        or digest != _VAULT_PLACEHOLDER_DIGEST
                    ):
                        _fail("source-vault-placeholder-drift")
                    container["image"] = vault_image
                else:
                    if (
                        not repository.endswith("/control-assurance-lab")
                        or digest != _APPLICATION_PLACEHOLDER_DIGEST
                    ):
                        _fail("source-application-placeholder-drift")
                    container["image"] = application_image
                observed += 1
    if observed == 0 and any(
        document.get("kind") in {"Deployment", "Job"}
        for document in documents
    ):
        _fail("workload-has-no-images")


def _verify_images(
    documents: list[dict[str, Any]],
    *,
    application_image: str,
    vault_image: str,
) -> int:
    observed = 0
    for document in documents:
        pod = _pod_spec(document)
        if pod is None:
            continue
        for containers in _container_sets(pod):
            for container in containers:
                name = container.get("name")
                image = container.get("image")
                if not isinstance(name, str) or not isinstance(image, str):
                    _fail("workload-container-name-or-image-missing")
                expected = (
                    vault_image
                    if name == "vault-token-agent"
                    else application_image
                )
                if image != expected:
                    _fail("rendered-image-does-not-match-release-lock")
                observed += 1
    return observed


def _dump_documents(documents: list[dict[str, Any]]) -> bytes:
    return yaml.safe_dump_all(
        documents,
        allow_unicode=True,
        explicit_start=True,
        sort_keys=False,
    ).encode()


def _public_reference(path_value: object) -> str:
    if type(path_value) is not str:
        _fail("public-input-configured-path-invalid")
    path = PurePosixPath(path_value)
    if (
        not path.is_absolute()
        or path.name in {"", ".", ".."}
        or len(path.parts) < 2
    ):
        _fail("public-input-configured-path-invalid")
    if path.parent == PurePosixPath("/etc/control-assurance/trust"):
        return f"control/{path.name}"
    if path.parent == PurePosixPath("/etc/control-assurance/identity"):
        return f"control/{path.name}"
    if path.parent == PurePosixPath("/trust/runtime"):
        return f"runtime/{path.name}"
    _fail("public-input-configured-path-unapproved")


def _inject_public_inputs(
    value: object,
    *,
    public_input_directory: Path,
    content: dict[str, bytes],
) -> None:
    if isinstance(value, list):
        for item in value:
            _inject_public_inputs(
                item,
                public_input_directory=public_input_directory,
                content=content,
            )
        return
    if not isinstance(value, dict):
        return
    if "file" in value and "sha256_digest" in value:
        file_settings = value.get("file")
        if not isinstance(file_settings, dict):
            _fail("pinned-public-file-invalid")
        reference = _public_reference(file_settings.get("path"))
        data = content.get(reference)
        if data is None:
            data = _read_public_input(public_input_directory, reference)
            content[reference] = data
        value["sha256_digest"] = _sha256(data)
    for child in value.values():
        _inject_public_inputs(
            child,
            public_input_directory=public_input_directory,
            content=content,
        )


def _inspect_public_inputs(value: object) -> dict[str, str]:
    result: dict[str, str] = {}

    def inspect(item: object) -> None:
        if isinstance(item, list):
            for child in item:
                inspect(child)
            return
        if not isinstance(item, dict):
            return
        if "file" in item and "sha256_digest" in item:
            file_settings = item.get("file")
            digest = item.get("sha256_digest")
            if (
                not isinstance(file_settings, dict)
                or type(digest) is not str
                or _DIGEST.fullmatch(digest) is None
            ):
                _fail("pinned-public-file-invalid")
            reference = _public_reference(file_settings.get("path"))
            previous = result.setdefault(reference, digest)
            if previous != digest:
                _fail("pinned-public-file-conflicting-digest")
        for child in item.values():
            inspect(child)

    inspect(value)
    return result


def _combined_digest(digests: Mapping[str, str]) -> str:
    return _sha256(_canonical_document(dict(sorted(digests.items()))))


def _binary_data(content: Mapping[str, bytes]) -> dict[str, str]:
    return {
        name: base64.b64encode(value).decode("ascii")
        for name, value in sorted(content.items())
    }


def _config_map(
    *,
    name: str,
    component: str,
    material_kind: str,
    material_digest: str,
    content: Mapping[str, bytes],
) -> dict[str, Any]:
    if (
        not content
        or sum(len(name.encode()) + len(value) for name, value in content.items())
        > _MAX_CONFIG_MAP_BINARY_BYTES
    ):
        _fail(f"release-config-map-size-invalid:{material_kind}")
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": name,
            "namespace": _NAMESPACE,
            "labels": {
                "app.kubernetes.io/name": "control-assurance",
                "app.kubernetes.io/component": component,
                "control-assurance.io/material-kind": material_kind,
                "control-assurance.io/material-digest-prefix": (
                    _digest_prefix(material_digest)
                ),
                "control-assurance.io/material-digest-base32": (
                    _digest_label_value(material_digest)
                ),
            },
            "annotations": {
                "control-assurance.io/material-digest": material_digest
            },
        },
        "immutable": True,
        "binaryData": _binary_data(content),
    }


def _profile_artifacts(
    *,
    source_data: bytes,
    source_manifest: bytes,
) -> dict[str, bytes]:
    documents = _yaml_documents(
        source_data,
        name=_PROFILE_RELEASE_SOURCE,
    )
    if len(documents) != 1:
        _fail("profile-release-source-invalid")
    document = documents[0]
    if (
        document.get("kind") != "ConfigMap"
        or document.get("immutable") is not True
    ):
        _fail("profile-release-source-invalid")
    data = document.get("data")
    encoded = document.get("binaryData")
    if (
        not isinstance(data, dict)
        or data.get("profile-registration-manifest.json")
        != source_manifest.decode("utf-8")
        or not isinstance(encoded, dict)
        or not encoded
    ):
        _fail("profile-release-source-invalid")
    result: dict[str, bytes] = {}
    for name, value in encoded.items():
        if type(name) is not str or type(value) is not str:
            _fail("profile-release-source-invalid")
        try:
            result[name] = base64.b64decode(
                value,
                validate=True,
            )
        except ValueError:
            _fail("profile-release-source-invalid")
    return result


def _validate_profile_artifacts(
    manifest: Mapping[str, Any],
    artifacts: Mapping[str, bytes],
) -> None:
    profiles = manifest.get("profiles")
    if not isinstance(profiles, list) or not profiles:
        _fail("profile-release-artifacts-invalid")
    expected: set[str] = set()
    for profile in profiles:
        if not isinstance(profile, dict):
            _fail("profile-release-artifacts-invalid")
        file_settings = profile.get("file")
        digest = profile.get("expected_digest")
        if not isinstance(file_settings, dict) or type(digest) is not str:
            _fail("profile-release-artifacts-invalid")
        path_value = file_settings.get("path")
        if type(path_value) is not str:
            _fail("profile-release-artifacts-invalid")
        path = PurePosixPath(path_value)
        if path.parent != PurePosixPath("/profiles"):
            _fail("profile-release-artifacts-invalid")
        name = path.name
        artifact = artifacts.get(name)
        if artifact is None or _sha256(artifact) != digest:
            _fail("profile-release-artifacts-invalid")
        expected.add(name)
    if expected != set(artifacts):
        _fail("profile-release-artifacts-invalid")


def _material_documents(
    *,
    configurations: Mapping[str, bytes],
    public_content: Mapping[str, bytes],
    profile_artifacts: Mapping[str, bytes],
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    identities = {
        name: _sha256(value) for name, value in configurations.items()
    }
    control_trust_content = {
        PurePosixPath(reference).name: value
        for reference, value in public_content.items()
        if reference.startswith("control/") and reference.endswith("-ca.pem")
    }
    control_identity_content = {
        PurePosixPath(reference).name: value
        for reference, value in public_content.items()
        if reference.startswith("control/")
        and not reference.endswith("-ca.pem")
    }
    runtime_trust_content = {
        PurePosixPath(reference).name: value
        for reference, value in public_content.items()
        if reference.startswith("runtime/")
    }
    reconciler_trust_content = {
        "control-postgres-ca.pem": public_content[
            "control/postgres-ca.pem"
        ],
        "runtime-postgres-ca.pem": public_content[
            "runtime/postgres-ca.pem"
        ],
    }
    control_trust_digest = _combined_digest(
        {
            name: _sha256(value)
            for name, value in control_trust_content.items()
        }
    )
    control_identity_digest = _combined_digest(
        {
            name: _sha256(value)
            for name, value in control_identity_content.items()
        }
    )
    runtime_trust_digest = _combined_digest(
        {
            name: _sha256(value)
            for name, value in runtime_trust_content.items()
        }
    )
    reconciler_trust_digest = _combined_digest(
        {
            name: _sha256(value)
            for name, value in reconciler_trust_content.items()
        }
    )
    profile_content = {
        "profile-registration-manifest.json": configurations[
            "profile-registration"
        ],
        **dict(profile_artifacts),
    }
    bindings = {
        "control_config": (
            "control-assurance-control-plane-config-"
            f"{_digest_prefix(identities['control-plane'])}"
        ),
        "control_identity": (
            "control-assurance-control-plane-identity-"
            f"{_digest_prefix(control_identity_digest)}"
        ),
        "control_trust": (
            "control-assurance-control-plane-trust-"
            f"{_digest_prefix(control_trust_digest)}"
        ),
        "profile_release": (
            "control-assurance-profile-release-"
            f"{_digest_prefix(identities['profile-registration'])}"
        ),
        "reconciler_trust": (
            "control-assurance-deployment-reconciler-trust-"
            f"{_digest_prefix(reconciler_trust_digest)}"
        ),
        "runtime_config": (
            "control-assurance-runtime-release-"
            f"{_digest_prefix(identities['runtime-worker'])}"
        ),
        "runtime_pins": (
            "control-assurance-runtime-release-pins-"
            f"{_digest_prefix(identities['runtime-worker'])}"
        ),
        "runtime_trust": (
            "control-assurance-runtime-trust-"
            f"{_digest_prefix(runtime_trust_digest)}"
        ),
        "site_egress": (
            "control-assurance-site-egress-"
            f"{_digest_prefix(identities[SITE_EGRESS_LOCK_IDENTITY])}"
        ),
    }
    documents = [
        _config_map(
            name=bindings["control_config"],
            component="control-plane",
            material_kind="control-config",
            material_digest=identities["control-plane"],
            content={"service.json": configurations["control-plane"]},
        ),
        _config_map(
            name=bindings["control_trust"],
            component="control-plane",
            material_kind="control-trust",
            material_digest=control_trust_digest,
            content=control_trust_content,
        ),
        _config_map(
            name=bindings["control_identity"],
            component="control-plane",
            material_kind="control-identity",
            material_digest=control_identity_digest,
            content=control_identity_content,
        ),
        _config_map(
            name=bindings["runtime_config"],
            component="runtime-worker",
            material_kind="runtime-config",
            material_digest=identities["runtime-worker"],
            content={
                "runtime-worker.json": configurations["runtime-worker"]
            },
        ),
        _config_map(
            name=bindings["runtime_trust"],
            component="runtime-worker",
            material_kind="runtime-trust",
            material_digest=runtime_trust_digest,
            content=runtime_trust_content,
        ),
        _config_map(
            name=bindings["reconciler_trust"],
            component="deployment-reconciler",
            material_kind="reconciler-trust",
            material_digest=reconciler_trust_digest,
            content=reconciler_trust_content,
        ),
        _config_map(
            name=bindings["profile_release"],
            component="profile-registrar",
            material_kind="profile-release",
            material_digest=identities["profile-registration"],
            content=profile_content,
        ),
        _config_map(
            name=bindings["site_egress"],
            component="egress-policy",
            material_kind=SITE_EGRESS_MATERIAL_KIND,
            material_digest=identities[SITE_EGRESS_LOCK_IDENTITY],
            content={
                SITE_EGRESS_CONTRACT_KEY: configurations[
                    SITE_EGRESS_LOCK_IDENTITY
                ]
            },
        ),
    ]
    return documents, bindings


def _workload(
    documents: Sequence[dict[str, Any]],
    *,
    kind: str,
    name: str,
) -> dict[str, Any]:
    selected = [
        item
        for item in documents
        if item.get("kind") == kind
        and isinstance(item.get("metadata"), dict)
        and item["metadata"].get("name") == name
    ]
    if len(selected) != 1:
        _fail("release-workload-composition-drift")
    return selected[0]


def _named_item(
    items: object,
    *,
    name: str,
    label: str,
) -> dict[str, Any]:
    if not isinstance(items, list):
        _fail(f"release-binding-invalid:{label}")
    selected = [
        item
        for item in items
        if isinstance(item, dict) and item.get("name") == name
    ]
    if len(selected) != 1:
        _fail(f"release-binding-invalid:{label}")
    return cast(dict[str, Any], selected[0])


def _set_environment_value(
    container: dict[str, Any],
    *,
    name: str,
    value: str,
) -> None:
    entry = _named_item(
        container.get("env"),
        name=name,
        label=f"environment-{name}",
    )
    entry.clear()
    entry.update({"name": name, "value": value})


def _set_secret_name(
    container: dict[str, Any],
    *,
    environment_name: str,
    secret_name: str,
) -> None:
    entry = _named_item(
        container.get("env"),
        name=environment_name,
        label=f"environment-{environment_name}",
    )
    try:
        reference = entry["valueFrom"]["secretKeyRef"]
        if not isinstance(reference, dict):
            raise KeyError
    except (KeyError, TypeError):
        _fail(f"release-binding-invalid:{environment_name}")
    reference["name"] = secret_name


def _apply_release_bindings(
    name: str,
    documents: list[dict[str, Any]],
    *,
    bindings: Mapping[str, str],
    configuration_digests: Mapping[str, str],
    public_digests: Mapping[str, str],
) -> None:
    if name == "control-plane.yaml":
        deployment = _workload(
            documents,
            kind="Deployment",
            name="control-assurance-control-plane",
        )
        bind_workload_to_site_egress(
            deployment,
            digest=configuration_digests[SITE_EGRESS_LOCK_IDENTITY],
        )
        pod = cast(dict[str, Any], deployment["spec"]["template"]["spec"])
        container = _named_item(
            pod.get("containers"),
            name="control-plane",
            label="control-plane-container",
        )
        _set_environment_value(
            container,
            name="ASSURANCE_CONTROL_PLANE_CONFIG_DIGEST",
            value=configuration_digests["control-plane"],
        )
        _named_item(
            pod.get("volumes"),
            name="config",
            label="control-config-volume",
        )["configMap"]["name"] = bindings["control_config"]
        trust = _named_item(
            pod.get("volumes"),
            name="trust",
            label="control-trust-volume",
        )
        trust["projected"]["sources"][0]["configMap"]["name"] = bindings[
            "control_trust"
        ]
        identity = _named_item(
            pod.get("volumes"),
            name="oidc-client-identity",
            label="control-identity-volume",
        )
        identity["projected"]["sources"] = [
            {
                "configMap": {
                    "name": bindings["control_identity"],
                    "items": [
                        {
                            "key": "oidc-client.der",
                            "path": "oidc-client.der",
                        }
                    ],
                }
            }
        ]
        return
    if name == "runtime-worker.yaml":
        deployment = _workload(
            documents,
            kind="Deployment",
            name="control-assurance-runtime-worker",
        )
        bind_workload_to_site_egress(
            deployment,
            digest=configuration_digests[SITE_EGRESS_LOCK_IDENTITY],
        )
        pod = cast(dict[str, Any], deployment["spec"]["template"]["spec"])
        initializer = _named_item(
            pod.get("initContainers"),
            name="initialize-shared-work-root",
            label="runtime-initializer",
        )
        worker = _named_item(
            pod.get("containers"),
            name="runtime-worker",
            label="runtime-worker",
        )
        for container in (initializer, worker):
            _set_environment_value(
                container,
                name="ASSURANCE_RUNTIME_CONFIG_DIGEST",
                value=configuration_digests["runtime-worker"],
            )
        for environment_name in (
            "RUNTIME_WORKER_CREDENTIAL_DIGEST",
            "RUNTIME_SOURCE_REVISION",
        ):
            _set_secret_name(
                worker,
                environment_name=environment_name,
                secret_name=bindings["runtime_pins"],
            )
        _named_item(
            pod.get("volumes"),
            name="runtime-config",
            label="runtime-config-volume",
        )["configMap"]["name"] = bindings["runtime_config"]
        _named_item(
            pod.get("volumes"),
            name="trust-inputs",
            label="runtime-trust-volume",
        )["configMap"]["name"] = bindings["runtime_trust"]
        return
    if name == "deployment-reconciler.yaml":
        deployment = _workload(
            documents,
            kind="Deployment",
            name="control-assurance-deployment-reconciler",
        )
        bind_workload_to_site_egress(
            deployment,
            digest=configuration_digests[SITE_EGRESS_LOCK_IDENTITY],
        )
        pod = cast(dict[str, Any], deployment["spec"]["template"]["spec"])
        container = _named_item(
            pod.get("containers"),
            name="deployment-reconciler",
            label="reconciler-container",
        )
        _set_environment_value(
            container,
            name="ASSURANCE_RUNTIME_CONFIG_DIGEST",
            value=configuration_digests["runtime-worker"],
        )
        _set_environment_value(
            container,
            name="ASSURANCE_DEPLOYMENT_RECONCILER_CONTROL_CA_DIGEST",
            value=public_digests["control/postgres-ca.pem"],
        )
        _set_environment_value(
            container,
            name="ASSURANCE_DEPLOYMENT_RECONCILER_RUNTIME_CA_DIGEST",
            value=public_digests["runtime/postgres-ca.pem"],
        )
        _named_item(
            pod.get("volumes"),
            name="runtime-config",
            label="reconciler-runtime-config-volume",
        )["configMap"]["name"] = bindings["runtime_config"]
        _named_item(
            pod.get("volumes"),
            name="trust-inputs",
            label="reconciler-trust-volume",
        )["configMap"]["name"] = bindings["reconciler_trust"]
        return
    if name == "profile-registrar-job.yaml":
        job = _workload(
            documents,
            kind="Job",
            name=cast(str, documents[1]["metadata"]["name"]),
        )
        bind_workload_to_site_egress(
            job,
            digest=configuration_digests[SITE_EGRESS_LOCK_IDENTITY],
        )
        manifest_digest = configuration_digests["profile-registration"]
        job["metadata"]["name"] = (
            "control-assurance-profile-registrar-"
            f"{_digest_prefix(manifest_digest)}"
        )
        job["metadata"]["labels"][
            "control-assurance.io/profile-manifest-digest-prefix"
        ] = _digest_prefix(manifest_digest)
        job["metadata"]["labels"][
            "control-assurance.io/profile-manifest-digest-base32"
        ] = _digest_label_value(manifest_digest)
        annotations = job["metadata"].setdefault("annotations", {})
        if not isinstance(annotations, dict):
            _fail("profile-registrar-metadata-invalid")
        annotations[
            "control-assurance.io/profile-manifest-digest"
        ] = manifest_digest
        pod = cast(dict[str, Any], job["spec"]["template"]["spec"])
        registrar = _named_item(
            pod.get("containers"),
            name="profile-registrar",
            label="profile-registrar-container",
        )
        _set_environment_value(
            registrar,
            name="ASSURANCE_PROFILE_REGISTRATION_MANIFEST_DIGEST",
            value=manifest_digest,
        )
        for volume_name in ("profile-manifest", "control-profiles"):
            _named_item(
                pod.get("volumes"),
                name=volume_name,
                label=f"{volume_name}-volume",
            )["configMap"]["name"] = bindings["profile_release"]
        _named_item(
            pod.get("volumes"),
            name="trust-inputs",
            label="profile-trust-volume",
        )["configMap"]["name"] = bindings["runtime_trust"]
        return
    if name != "network-policies.yaml":
        _fail(f"release-source-unsupported:{name}")


def _assert_exact_entries(directory: Path, expected: set[str]) -> None:
    try:
        observed = {entry.name for entry in directory.iterdir()}
    except OSError as error:
        raise ReleaseError("release-directory-unavailable") from error
    if observed != expected:
        _fail("release-file-set-mismatch")


def _decode_binary_data(document: Mapping[str, Any]) -> dict[str, bytes]:
    encoded = document.get("binaryData")
    if (
        document.get("apiVersion") != "v1"
        or document.get("kind") != "ConfigMap"
        or document.get("immutable") is not True
        or "data" in document
        or not isinstance(encoded, dict)
        or not encoded
    ):
        _fail("release-material-invalid")
    result: dict[str, bytes] = {}
    for name, value in encoded.items():
        if type(name) is not str or type(value) is not str:
            _fail("release-material-invalid")
        try:
            result[name] = base64.b64decode(
                value,
                validate=True,
            )
        except ValueError:
            _fail("release-material-invalid")
    return result


def _material_by_kind(
    documents: Sequence[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for document in documents:
        try:
            labels = document["metadata"]["labels"]
            kind = labels["control-assurance.io/material-kind"]
        except (KeyError, TypeError):
            _fail("release-material-invalid")
        if type(kind) is not str or kind in result:
            _fail("release-material-invalid")
        result[kind] = document
    if set(result) != _MATERIAL_KINDS:
        _fail("release-material-invalid")
    return result


def _digest_map(
    value: Any,
    *,
    field: str,
    expected: set[str] | None = None,
) -> dict[str, str]:
    if not isinstance(value, dict):
        _fail(f"release-lock-invalid-{field}")
    if expected is not None and set(value) != expected:
        _fail(f"release-lock-invalid-{field}")
    result: dict[str, str] = {}
    for key, digest in value.items():
        if (
            not isinstance(key, str)
            or not isinstance(digest, str)
            or _DIGEST.fullmatch(digest) is None
        ):
            _fail(f"release-lock-invalid-{field}")
        result[key] = digest
    return result


def render_release(
    *,
    source_directory: Path,
    public_input_directory: Path,
    site_egress_contract_path: Path,
    output_directory: Path,
    application_image: str,
    vault_image: str,
) -> str:
    application_image = _validated_image(
        application_image,
        label="application",
    )
    vault_image = _validated_image(vault_image, label="vault")
    if output_directory.exists():
        _fail("release-output-already-exists")

    source_data = {
        name: _read_regular_file(source_directory / name)
        for name in _SOURCE_FILES
    }
    site_egress_raw = _read_approved_input(
        site_egress_contract_path,
        label="site-egress-contract",
        maximum=_MAX_SITE_EGRESS_CONTRACT_BYTES,
    )
    site_egress_document = _parse_json_document(
        site_egress_raw,
        name=SITE_EGRESS_CONTRACT_KEY,
        canonical=True,
    )
    try:
        site_egress_contract = parse_site_egress_contract(
            site_egress_document
        )
    except SiteEgressContractError as error:
        raise ReleaseError(str(error)) from error
    if site_egress_contract.as_document() != site_egress_document:
        _fail("site-egress-contract-not-canonical")
    configurations: dict[str, bytes] = {}
    configuration_documents: dict[str, dict[str, Any]] = {}
    public_content: dict[str, bytes] = {}
    for identity, filename in _CONFIGURATION_IDENTITIES.items():
        document = _parse_json_document(
            source_data[filename],
            name=filename,
            canonical=True,
        )
        _inject_public_inputs(
            document,
            public_input_directory=public_input_directory,
            content=public_content,
        )
        configuration_documents[identity] = document
        configurations[identity] = _canonical_document(document)
    configurations[SITE_EGRESS_LOCK_IDENTITY] = _canonical_document(
        site_egress_contract.as_document()
    )
    if set(public_content) != _REQUIRED_PUBLIC_INPUTS:
        _fail("public-input-configuration-set-mismatch")
    _assert_exact_public_input_tree(
        public_input_directory,
        set(public_content),
    )
    profile_artifacts = _profile_artifacts(
        source_data=source_data[_PROFILE_RELEASE_SOURCE],
        source_manifest=source_data[
            "profile-registration-manifest.example.json"
        ].removesuffix(b"\n"),
    )
    _validate_profile_artifacts(
        configuration_documents["profile-registration"],
        profile_artifacts,
    )
    material_documents, bindings = _material_documents(
        configurations=configurations,
        public_content=public_content,
        profile_artifacts=profile_artifacts,
    )
    configuration_digests = {
        name: _sha256(value) for name, value in configurations.items()
    }
    public_digests = {
        name: _sha256(value) for name, value in public_content.items()
    }

    output_directory.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(
        tempfile.mkdtemp(
            prefix=f".{output_directory.name}.",
            dir=output_directory.parent,
        )
    )
    stage.chmod(0o755)
    try:
        manifest_directory = stage / "manifests"
        manifest_directory.mkdir(mode=0o755)
        manifest_digests: dict[str, str] = {}
        for name in _WORKLOAD_FILES:
            documents = _yaml_documents(source_data[name], name=name)
            _render_images(
                documents,
                application_image=application_image,
                vault_image=vault_image,
            )
            _apply_release_bindings(
                name,
                documents,
                bindings=bindings,
                configuration_digests=configuration_digests,
                public_digests=public_digests,
            )
            rendered = _dump_documents(documents)
            observed_images = _verify_images(
                _yaml_documents(rendered, name=name),
                application_image=application_image,
                vault_image=vault_image,
            )
            if observed_images != _EXPECTED_IMAGE_COUNTS[name]:
                _fail(f"release-workload-composition-drift:{name}")
            (manifest_directory / name).write_bytes(rendered)
            manifest_digests[name] = _sha256(rendered)
        site_egress = _dump_documents(
            render_site_egress_documents(
                site_egress_contract,
                digest=configuration_digests[
                    SITE_EGRESS_LOCK_IDENTITY
                ],
            )
        )
        (manifest_directory / SITE_EGRESS_MANIFEST).write_bytes(
            site_egress
        )
        manifest_digests[SITE_EGRESS_MANIFEST] = _sha256(site_egress)
        material = _dump_documents(material_documents)
        (manifest_directory / _MATERIAL_MANIFEST).write_bytes(material)
        manifest_digests[_MATERIAL_MANIFEST] = _sha256(material)
        lock = {
            "application_image": application_image,
            "configurations": configuration_digests,
            "manifests": manifest_digests,
            "public_inputs": public_digests,
            "schema": _SCHEMA,
            "sources": {
                name: _sha256(value) for name, value in source_data.items()
            },
            "vault_image": vault_image,
        }
        lock_data = _canonical_lock(lock)
        (stage / "release-lock.json").write_bytes(lock_data)
        os.replace(stage, output_directory)
        return _sha256(lock_data)
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def verify_release(
    *,
    release_directory: Path,
    expected_lock_digest: str,
) -> bytes:
    if _DIGEST.fullmatch(expected_lock_digest) is None:
        _fail("expected-release-lock-digest-invalid")
    _assert_exact_entries(
        release_directory,
        {"manifests", "release-lock.json"},
    )
    lock_data = _read_regular_file(release_directory / "release-lock.json")
    if _sha256(lock_data) != expected_lock_digest:
        _fail("release-lock-digest-mismatch")
    lock = _parse_lock(lock_data)
    if set(lock) != {
        "application_image",
        "configurations",
        "manifests",
        "public_inputs",
        "schema",
        "sources",
        "vault_image",
    }:
        _fail("release-lock-fields-mismatch")
    if lock["schema"] != _SCHEMA:
        _fail("release-lock-schema-unsupported")
    application_raw = lock["application_image"]
    vault_raw = lock["vault_image"]
    if not isinstance(application_raw, str) or not isinstance(vault_raw, str):
        _fail("release-lock-image-invalid")
    application_image = _validated_image(application_raw, label="application")
    vault_image = _validated_image(vault_raw, label="vault")
    _digest_map(
        lock["sources"],
        field="sources",
        expected=set(_SOURCE_FILES),
    )
    manifests = _digest_map(
        lock["manifests"],
        field="manifests",
        expected=set(_MANIFEST_FILES),
    )
    configuration_digests = _digest_map(
        lock["configurations"],
        field="configurations",
        expected={
            *set(_CONFIGURATION_IDENTITIES),
            SITE_EGRESS_LOCK_IDENTITY,
        },
    )
    public_digests = _digest_map(
        lock["public_inputs"],
        field="public-inputs",
        expected=_REQUIRED_PUBLIC_INPUTS,
    )

    manifest_directory = release_directory / "manifests"
    if manifest_directory.is_symlink() or not manifest_directory.is_dir():
        _fail("release-manifest-directory-invalid")
    _assert_exact_entries(manifest_directory, set(_MANIFEST_FILES))
    parsed: dict[str, list[dict[str, Any]]] = {}
    verified_manifests: list[bytes] = []
    observed_images = 0
    for name in _MANIFEST_FILES:
        data = _read_regular_file(manifest_directory / name)
        if _sha256(data) != manifests[name]:
            _fail(f"release-manifest-digest-mismatch:{name}")
        documents = _yaml_documents(data, name=name)
        if data != _dump_documents(documents):
            _fail(f"release-manifest-not-canonical:{name}")
        parsed[name] = documents
        manifest_images = _verify_images(
            documents,
            application_image=application_image,
            vault_image=vault_image,
        )
        if manifest_images != _EXPECTED_IMAGE_COUNTS[name]:
            _fail(f"release-workload-composition-drift:{name}")
        observed_images += manifest_images
        verified_manifests.append(data)
    if observed_images == 0:
        _fail("release-has-no-workload-images")

    material = _material_by_kind(parsed[_MATERIAL_MANIFEST])
    material_content = {
        name: _decode_binary_data(document)
        for name, document in material.items()
    }
    configurations = {
        "control-plane": material_content["control-config"]["service.json"],
        "runtime-worker": material_content["runtime-config"][
            "runtime-worker.json"
        ],
        "profile-registration": material_content["profile-release"][
            "profile-registration-manifest.json"
        ],
        SITE_EGRESS_LOCK_IDENTITY: material_content[
            SITE_EGRESS_MATERIAL_KIND
        ][SITE_EGRESS_CONTRACT_KEY],
    }
    configuration_documents: dict[str, dict[str, Any]] = {}
    observed_public: dict[str, str] = {}
    for identity, data in configurations.items():
        if _sha256(data) != configuration_digests[identity]:
            _fail("release-configuration-digest-mismatch")
        document = _parse_json_document(
            data,
            name=identity,
            canonical=True,
        )
        configuration_documents[identity] = document
        pins = _inspect_public_inputs(document)
        for reference, digest in pins.items():
            previous = observed_public.setdefault(reference, digest)
            if previous != digest:
                _fail("pinned-public-file-conflicting-digest")
    if observed_public != public_digests:
        _fail("release-public-input-binding-mismatch")
    try:
        site_egress_contract = parse_site_egress_contract(
            configuration_documents[SITE_EGRESS_LOCK_IDENTITY]
        )
    except SiteEgressContractError as error:
        raise ReleaseError(str(error)) from error
    if (
        site_egress_contract.as_document()
        != configuration_documents[SITE_EGRESS_LOCK_IDENTITY]
    ):
        _fail("site-egress-contract-not-canonical")

    public_content = {
        **{
            f"control/{name}": value
            for name, value in material_content["control-trust"].items()
        },
        **{
            f"control/{name}": value
            for name, value in material_content["control-identity"].items()
        },
        **{
            f"runtime/{name}": value
            for name, value in material_content["runtime-trust"].items()
        },
    }
    if set(public_content) != set(public_digests) or any(
        _sha256(value) != public_digests[name]
        for name, value in public_content.items()
    ):
        _fail("release-public-input-content-mismatch")
    if material_content["reconciler-trust"] != {
        "control-postgres-ca.pem": public_content[
            "control/postgres-ca.pem"
        ],
        "runtime-postgres-ca.pem": public_content[
            "runtime/postgres-ca.pem"
        ],
    }:
        _fail("release-reconciler-trust-mismatch")
    profile_artifacts = {
        name: value
        for name, value in material_content["profile-release"].items()
        if name != "profile-registration-manifest.json"
    }
    _validate_profile_artifacts(
        configuration_documents["profile-registration"],
        profile_artifacts,
    )
    expected_material, bindings = _material_documents(
        configurations=configurations,
        public_content=public_content,
        profile_artifacts=profile_artifacts,
    )
    if expected_material != parsed[_MATERIAL_MANIFEST]:
        _fail("release-material-identity-mismatch")
    expected_site_egress = render_site_egress_documents(
        site_egress_contract,
        digest=configuration_digests[SITE_EGRESS_LOCK_IDENTITY],
    )
    if expected_site_egress != parsed[SITE_EGRESS_MANIFEST]:
        _fail("release-site-egress-policy-mismatch")

    for name in _WORKLOAD_FILES:
        expected = copy.deepcopy(parsed[name])
        _apply_release_bindings(
            name,
            expected,
            bindings=bindings,
            configuration_digests=configuration_digests,
            public_digests=public_digests,
        )
        if expected != parsed[name]:
            _fail(f"release-binding-mismatch:{name}")
    return b"".join(verified_manifests)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render or verify immutable Kubernetes release manifests",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    render = commands.add_parser("render")
    render.add_argument(
        "--source-dir",
        type=Path,
        default=Path("deploy/kubernetes"),
    )
    render.add_argument(
        "--public-input-dir",
        type=Path,
        required=True,
        help="directory containing exact control/ and runtime/ public files",
    )
    render.add_argument(
        "--site-egress-contract",
        type=Path,
        required=True,
        help="absolute canonical site egress contract JSON path",
    )
    render.add_argument("--output-dir", type=Path, required=True)
    render.add_argument("--application-image", required=True)
    render.add_argument("--vault-image", required=True)

    verify = commands.add_parser("verify")
    verify.add_argument("--release-dir", type=Path, required=True)
    verify.add_argument("--expected-lock-digest", required=True)
    verify.add_argument(
        "--emit-manifests",
        action="store_true",
        help="write the already-verified manifest bytes to stdout",
    )
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        if arguments.command == "render":
            digest = render_release(
                source_directory=arguments.source_dir,
                public_input_directory=arguments.public_input_dir,
                site_egress_contract_path=arguments.site_egress_contract,
                output_directory=arguments.output_dir,
                application_image=arguments.application_image,
                vault_image=arguments.vault_image,
            )
            print(digest)
        else:
            manifests = verify_release(
                release_directory=arguments.release_dir,
                expected_lock_digest=arguments.expected_lock_digest,
            )
            if arguments.emit_manifests:
                sys.stdout.buffer.write(manifests)
            else:
                print(f"release verified: {arguments.expected_lock_digest}")
    except ReleaseError as error:
        print(f"release rejected: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
