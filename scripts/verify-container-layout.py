#!/usr/bin/env python3
"""Verify the exact multi-platform OCI layout used by the release workflow."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import IO, Any, cast

OCI_INDEX = "application/vnd.oci.image.index.v1+json"
DOCKER_INDEX = "application/vnd.docker.distribution.manifest.list.v2+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
DOCKER_CONFIG = "application/vnd.docker.container.image.v1+json"
IN_TOTO = "application/vnd.in-toto+json"
ATTESTATION_TYPE = "attestation-manifest"
ATTESTATION_DIGEST = "vnd.docker.reference.digest"
ATTESTATION_KIND = "vnd.docker.reference.type"
REFERENCE_NAME = "org.opencontainers.image.ref.name"
PREDICATE_TYPE = "in-toto.io/predicate-type"
SPDX_PREDICATE = "https://spdx.dev/Document"
SLSA_PREDICATE = "https://slsa.dev/provenance/v1"
BUILDKIT_BUILD_TYPE = (
    "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md"
)
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar"
OCI_LAYER_GZIP = "application/vnd.oci.image.layer.v1.tar+gzip"
DOCKER_LAYER_GZIP = "application/vnd.docker.image.rootfs.diff.tar.gzip"
LAYER_ENCODINGS = {
    OCI_LAYER: "identity",
    OCI_LAYER_GZIP: "gzip",
    DOCKER_LAYER_GZIP: "gzip",
}
SHA256 = re.compile(r"^sha256:([a-f0-9]{64})$")
BLOB_NAME = re.compile(r"^blobs/sha256/([a-f0-9]{64})$")
EXPECTED_PLATFORMS = ("linux/amd64", "linux/arm64")
MAX_CONTROL_BYTES = 4 * 1024 * 1024
MAX_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_LAYER_MEMBERS = 1_000_000
MAX_UNCOMPRESSED_LAYER_BYTES = 8 * 1024 * 1024 * 1024
READ_CHUNK_BYTES = 1024 * 1024


class ContractError(ValueError):
    """The layout does not meet the release contract."""


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be a JSON object")
    return value


def _sequence(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ContractError(f"{label} must be a JSON array")
    return value


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON member: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ContractError(f"non-finite JSON number: {value}")


def _json_document(data: bytes, label: str, *, limit: int = MAX_DOCUMENT_BYTES) -> Any:
    if len(data) > limit:
        raise ContractError(f"{label} exceeds its byte limit")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ContractError(f"{label} is not UTF-8") from error
    try:
        return json.loads(
            text,
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, ContractError) as error:
        if isinstance(error, ContractError):
            raise
        raise ContractError(f"{label} is not strict JSON") from error


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )


def _descriptor(value: Any, label: str) -> dict[str, Any]:
    descriptor = _mapping(value, label)
    digest = descriptor.get("digest")
    size = descriptor.get("size")
    media_type = descriptor.get("mediaType")
    if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
        raise ContractError(f"{label}.digest is not a sha256 digest")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ContractError(f"{label}.size is invalid")
    if not isinstance(media_type, str) or not media_type:
        raise ContractError(f"{label}.mediaType is invalid")
    if "urls" in descriptor or "data" in descriptor:
        raise ContractError(f"{label} is not self-contained in the OCI layout")
    return descriptor


def _platform(value: Any, label: str) -> str:
    platform = _mapping(value, label)
    operating_system = platform.get("os")
    architecture = platform.get("architecture")
    variant = platform.get("variant")
    if not isinstance(operating_system, str) or not isinstance(architecture, str):
        raise ContractError(f"{label} is missing os or architecture")
    if variant not in (None, ""):
        raise ContractError(f"{label} has an unsupported variant")
    return f"{operating_system}/{architecture}"


def _relative_name(name: str) -> str:
    if "\x00" in name:
        raise ContractError("layout member contains NUL")
    while name.startswith("./"):
        name = name[2:]
    if name in ("", "."):
        return "."
    path = PurePosixPath(name)
    if path.is_absolute() or any(component in ("", ".", "..") for component in path.parts):
        raise ContractError(f"layout member has an unsafe name: {name!r}")
    return path.as_posix()


@dataclass(frozen=True)
class LayoutMember:
    name: str
    size: int


class LayoutReader:
    """Read one closed OCI layout directory or tar without extracting it."""

    def __init__(self, source: Path, *, source_date_epoch: int | None) -> None:
        self.source = source
        self.source_date_epoch = source_date_epoch
        self._tar: tarfile.TarFile | None = None
        self._tar_members: dict[str, tarfile.TarInfo] = {}
        self.files: dict[str, LayoutMember] = {}
        self.directories: set[str] = set()
        self._blob_cache: dict[str, bytes | None] = {}
        metadata = source.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ContractError("layout source may not be a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            self._load_directory()
        elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
            self._load_tar()
        else:
            raise ContractError("layout source must be a directory or single-link tar")
        expected_directories = {".", "blobs", "blobs/sha256"}
        if self.directories != expected_directories:
            raise ContractError(
                "layout directory set differs from '.', 'blobs', and 'blobs/sha256'"
            )
        if "oci-layout" not in self.files or "index.json" not in self.files:
            raise ContractError("layout control files are missing")
        foreign = {
            name
            for name in self.files
            if name not in {"oci-layout", "index.json"} and BLOB_NAME.fullmatch(name) is None
        }
        if foreign:
            raise ContractError(f"layout contains foreign files: {sorted(foreign)!r}")

    def close(self) -> None:
        if self._tar is not None:
            self._tar.close()

    def __enter__(self) -> LayoutReader:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _load_directory(self) -> None:
        self.directories.add(".")
        for directory, directory_names, file_names in os.walk(
            self.source, topdown=True, followlinks=False
        ):
            directory_path = Path(directory)
            relative_directory = _relative_name(directory_path.relative_to(self.source).as_posix())
            self.directories.add(relative_directory)
            for name in directory_names:
                child = directory_path / name
                metadata = child.lstat()
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                    raise ContractError(f"layout directory is not a real directory: {name!r}")
            for name in file_names:
                child = directory_path / name
                relative = _relative_name(child.relative_to(self.source).as_posix())
                if relative in self.files:
                    raise ContractError(f"duplicate layout member: {relative!r}")
                metadata = child.lstat()
                if (
                    stat.S_ISLNK(metadata.st_mode)
                    or not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                ):
                    raise ContractError(
                        f"layout file is not a single-link regular file: {relative!r}"
                    )
                self.files[relative] = LayoutMember(relative, metadata.st_size)

    def _load_tar(self) -> None:
        try:
            # The reader owns this handle until its own context manager exits.
            archive = tarfile.open(self.source, mode="r:*")  # noqa: SIM115
        except (tarfile.TarError, OSError) as error:
            raise ContractError("layout archive cannot be opened") from error
        self._tar = archive
        self.directories.add(".")
        try:
            for member in archive.getmembers():
                name = _relative_name(member.name)
                if self.source_date_epoch is not None and int(member.mtime) != (
                    self.source_date_epoch
                ):
                    raise ContractError(f"archive member {name!r} has an unstable timestamp")
                if member.isdir():
                    self.directories.add(name)
                    continue
                if not member.isreg():
                    raise ContractError(f"archive member {name!r} is not a regular file")
                if name in self.files:
                    raise ContractError(f"duplicate archive member: {name!r}")
                self._tar_members[name] = member
                self.files[name] = LayoutMember(name, member.size)
        except Exception:
            archive.close()
            self._tar = None
            raise

    def _open(self, name: str) -> IO[bytes]:
        if name not in self.files:
            raise ContractError(f"referenced layout member is missing: {name!r}")
        if self._tar is None:
            return (self.source / name).open("rb")
        extracted = self._tar.extractfile(self._tar_members[name])
        if extracted is None:
            raise ContractError(f"archive member cannot be read: {name!r}")
        return extracted

    def read(self, name: str, *, limit: int) -> bytes:
        member = self.files.get(name)
        if member is None:
            raise ContractError(f"layout member is missing: {name!r}")
        if member.size > limit:
            raise ContractError(f"layout member {name!r} exceeds its byte limit")
        with self._open(name) as stream:
            data = stream.read(limit + 1)
            if len(data) != member.size:
                raise ContractError(f"layout member {name!r} changed while it was read")
            return data

    def blob(self, descriptor: Mapping[str, Any], label: str, *, load: bool) -> bytes | None:
        digest = str(descriptor["digest"])
        match = SHA256.fullmatch(digest)
        assert match is not None
        name = f"blobs/sha256/{match.group(1)}"
        member = self.files.get(name)
        if member is None:
            raise ContractError(f"{label} blob is missing")
        if member.size != descriptor["size"]:
            raise ContractError(f"{label} descriptor size does not match its blob")
        if digest in self._blob_cache:
            cached = self._blob_cache[digest]
            if load and cached is None:
                return self.read(name, limit=MAX_DOCUMENT_BYTES)
            return cached
        hasher = hashlib.sha256()
        chunks: list[bytes] | None = [] if load else None
        observed_size = 0
        with self._open(name) as stream:
            while True:
                chunk = stream.read(READ_CHUNK_BYTES)
                if not chunk:
                    break
                observed_size += len(chunk)
                hasher.update(chunk)
                if chunks is not None:
                    if observed_size > MAX_DOCUMENT_BYTES:
                        raise ContractError(f"{label} document exceeds its byte limit")
                    chunks.append(chunk)
        if observed_size != member.size:
            raise ContractError(f"{label} blob changed while it was read")
        if hasher.hexdigest() != match.group(1):
            raise ContractError(f"{label} digest does not match its blob")
        data = b"".join(chunks) if chunks is not None else None
        self._blob_cache[digest] = data
        return data

    def open_blob(self, descriptor: Mapping[str, Any], label: str) -> IO[bytes]:
        digest = str(descriptor["digest"])
        match = SHA256.fullmatch(digest)
        assert match is not None
        name = f"blobs/sha256/{match.group(1)}"
        member = self.files.get(name)
        if member is None:
            raise ContractError(f"{label} blob is missing")
        if member.size != descriptor["size"]:
            raise ContractError(f"{label} descriptor size does not match its blob")
        return self._open(name)

    @property
    def observed_blob_names(self) -> set[str]:
        return {f"blobs/sha256/{digest.removeprefix('sha256:')}" for digest in self._blob_cache}


class _DigestingReader(io.RawIOBase):
    """Bound and hash the uncompressed bytes consumed by a streaming tar reader."""

    def __init__(self, stream: IO[bytes], label: str) -> None:
        super().__init__()
        self.stream = stream
        self.label = label
        self.size = 0
        self.hasher = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        remaining = MAX_UNCOMPRESSED_LAYER_BYTES - self.size
        if remaining < 0:
            raise ContractError(f"{self.label} exceeds its uncompressed byte limit")
        if size < 0 or size > remaining + 1:
            size = remaining + 1
        data = self.stream.read(size)
        self.size += len(data)
        if self.size > MAX_UNCOMPRESSED_LAYER_BYTES:
            raise ContractError(f"{self.label} exceeds its uncompressed byte limit")
        self.hasher.update(data)
        return data

    def readable(self) -> bool:
        return True

    @property
    def digest(self) -> str:
        return f"sha256:{self.hasher.hexdigest()}"


def _manifest_document(
    reader: LayoutReader,
    descriptor: Mapping[str, Any],
    label: str,
) -> dict[str, Any]:
    if descriptor["mediaType"] not in {OCI_MANIFEST, DOCKER_MANIFEST}:
        raise ContractError(f"{label} has an unsupported manifest media type")
    data = reader.blob(descriptor, label, load=True)
    assert data is not None
    manifest = _mapping(_json_document(data, label), label)
    if manifest.get("schemaVersion") != 2:
        raise ContractError(f"{label}.schemaVersion must be 2")
    if manifest.get("mediaType") not in {None, descriptor["mediaType"]}:
        raise ContractError(f"{label}.mediaType disagrees with its descriptor")
    return manifest


def _verify_layer(
    reader: LayoutReader,
    descriptor: Mapping[str, Any],
    *,
    label: str,
) -> str:
    encoding = LAYER_ENCODINGS.get(str(descriptor["mediaType"]))
    if encoding is None:
        raise ContractError(f"{label} has an unsupported layer media type")
    reader.blob(descriptor, label, load=False)
    with reader.open_blob(descriptor, label) as compressed:
        decoded: IO[bytes] = compressed
        if encoding == "gzip":
            decoded = cast(IO[bytes], gzip.GzipFile(fileobj=compressed, mode="rb"))
        digesting = _DigestingReader(decoded, label)
        try:
            with tarfile.open(fileobj=digesting, mode="r|") as layer:
                for index, member in enumerate(layer, start=1):
                    if index > MAX_LAYER_MEMBERS:
                        raise ContractError(f"{label} exceeds its member limit")
                    _relative_name(member.name)
            while digesting.read(READ_CHUNK_BYTES):
                pass
        except (gzip.BadGzipFile, EOFError, OSError, tarfile.TarError) as error:
            raise ContractError(f"{label} is not a valid {encoding} tar stream") from error
        finally:
            if decoded is not compressed:
                decoded.close()
    return digesting.digest


def _required_string(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise ContractError(f"{label} must be a non-empty string")
    return value


def _verify_spdx_predicate(value: Any, *, platform: str) -> None:
    label = f"{platform} SPDX predicate"
    predicate = _mapping(value, label)
    if predicate.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise ContractError(f"{label} does not identify an SPDX document")
    if predicate.get("spdxVersion") not in {"SPDX-2.2", "SPDX-2.3"}:
        raise ContractError(f"{label} has an unsupported SPDX version")
    if predicate.get("dataLicense") != "CC0-1.0":
        raise ContractError(f"{label} has an unexpected data license")
    _required_string(predicate.get("name"), f"{label}.name")
    namespace = _required_string(predicate.get("documentNamespace"), f"{label}.documentNamespace")
    if not namespace.startswith(("https://", "http://")):
        raise ContractError(f"{label}.documentNamespace is not an absolute HTTP URI")
    creation = _mapping(predicate.get("creationInfo"), f"{label}.creationInfo")
    _required_string(creation.get("created"), f"{label}.creationInfo.created")
    creators = _sequence(creation.get("creators"), f"{label}.creationInfo.creators")
    if not creators or any(not isinstance(creator, str) or not creator for creator in creators):
        raise ContractError(f"{label}.creationInfo.creators is empty or invalid")

    packages = _sequence(predicate.get("packages"), f"{label}.packages")
    if not packages:
        raise ContractError(f"{label} contains no packages")
    identifiers = {"SPDXRef-DOCUMENT"}
    for index, value in enumerate(packages):
        package = _mapping(value, f"{label}.packages[{index}]")
        identifier = _required_string(package.get("SPDXID"), f"{label}.packages[{index}].SPDXID")
        if not identifier.startswith("SPDXRef-") or identifier in identifiers:
            raise ContractError(f"{label} has an invalid or duplicate package SPDXID")
        identifiers.add(identifier)
        _required_string(package.get("name"), f"{label}.packages[{index}].name")
        _required_string(
            package.get("downloadLocation"),
            f"{label}.packages[{index}].downloadLocation",
        )

    relationships = _sequence(predicate.get("relationships"), f"{label}.relationships")
    if not relationships:
        raise ContractError(f"{label} contains no relationships")
    describes_package = False
    for index, value in enumerate(relationships):
        relationship = _mapping(value, f"{label}.relationships[{index}]")
        for field in ("spdxElementId", "relationshipType", "relatedSpdxElement"):
            _required_string(relationship.get(field), f"{label}.relationships[{index}].{field}")
        if (
            relationship["spdxElementId"] == "SPDXRef-DOCUMENT"
            and relationship["relationshipType"] == "DESCRIBES"
            and relationship["relatedSpdxElement"] in identifiers
            and relationship["relatedSpdxElement"] != "SPDXRef-DOCUMENT"
        ):
            describes_package = True
    if not describes_package:
        raise ContractError(f"{label} does not describe any declared package")


def _verify_slsa_predicate(
    value: Any,
    *,
    platform: str,
    version: str,
    revision: str,
    source: str,
    source_date_epoch: int | None,
) -> None:
    label = f"{platform} SLSA predicate"
    predicate = _mapping(value, label)
    definition = _mapping(predicate.get("buildDefinition"), f"{label}.buildDefinition")
    if definition.get("buildType") != BUILDKIT_BUILD_TYPE:
        raise ContractError(f"{label} was not emitted by the pinned BuildKit build type")

    external = _mapping(
        definition.get("externalParameters"),
        f"{label}.buildDefinition.externalParameters",
    )
    config_source = _mapping(
        external.get("configSource"),
        f"{label}.buildDefinition.externalParameters.configSource",
    )
    if config_source.get("path") != "Dockerfile":
        raise ContractError(f"{label} does not name the release Dockerfile")
    request = _mapping(
        external.get("request"),
        f"{label}.buildDefinition.externalParameters.request",
    )
    if request.get("frontend") != "dockerfile.v0":
        raise ContractError(f"{label} does not use the Dockerfile frontend")
    local_names = {
        _required_string(
            _mapping(item, f"{label}.request.locals[{index}]").get("name"),
            f"{label}.request.locals[{index}].name",
        )
        for index, item in enumerate(_sequence(request.get("locals"), f"{label}.request.locals"))
    }
    if local_names != {"context", "dockerfile"}:
        raise ContractError(f"{label} does not close over context and Dockerfile inputs")
    if request.get("secrets", []) not in (None, []) or request.get("ssh", []) not in (
        None,
        [],
    ):
        raise ContractError(f"{label} records an unapproved secret or SSH build input")
    args = _mapping(request.get("args"), f"{label}.request.args")
    expected_args = {
        "build-arg:IMAGE_VERSION": version,
        "build-arg:SOURCE_REVISION": revision,
        "build-arg:SOURCE_URL": source,
    }
    if source_date_epoch is not None:
        expected_args["build-arg:SOURCE_DATE_EPOCH"] = str(source_date_epoch)
    observed_build_args = {
        name: value
        for name, value in args.items()
        if isinstance(name, str) and name.startswith("build-arg:")
    }
    if observed_build_args != expected_args:
        raise ContractError(f"{label} build arguments are not exactly release-bound")

    internal = _mapping(
        definition.get("internalParameters"),
        f"{label}.buildDefinition.internalParameters",
    )
    _required_string(
        internal.get("builderPlatform"),
        f"{label}.buildDefinition.internalParameters.builderPlatform",
    )
    build_config = _mapping(
        internal.get("buildConfig"),
        f"{label}.buildDefinition.internalParameters.buildConfig",
    )
    llb = _sequence(
        build_config.get("llbDefinition"),
        f"{label}.buildDefinition.internalParameters.buildConfig.llbDefinition",
    )
    if not llb:
        raise ContractError(f"{label} is not mode=max provenance")
    llb_ids: set[str] = set()
    for index, value in enumerate(llb):
        step = _mapping(value, f"{label}.llbDefinition[{index}]")
        identifier = _required_string(step.get("id"), f"{label}.llbDefinition[{index}].id")
        if identifier in llb_ids:
            raise ContractError(f"{label} has duplicate LLB step identifiers")
        llb_ids.add(identifier)

    dependencies = _sequence(
        definition.get("resolvedDependencies"),
        f"{label}.buildDefinition.resolvedDependencies",
    )
    if not dependencies:
        raise ContractError(f"{label} contains no resolved dependencies")
    for index, value in enumerate(dependencies):
        dependency = _mapping(value, f"{label}.resolvedDependencies[{index}]")
        _required_string(dependency.get("uri"), f"{label}.resolvedDependencies[{index}].uri")
        digests = _mapping(
            dependency.get("digest"),
            f"{label}.resolvedDependencies[{index}].digest",
        )
        sha256 = digests.get("sha256")
        if not isinstance(sha256, str) or re.fullmatch(r"[a-f0-9]{64}", sha256) is None:
            raise ContractError(f"{label}.resolvedDependencies[{index}] has no sha256 digest")

    run_details = _mapping(predicate.get("runDetails"), f"{label}.runDetails")
    builder = _mapping(run_details.get("builder"), f"{label}.runDetails.builder")
    _required_string(builder.get("id"), f"{label}.runDetails.builder.id", allow_empty=True)
    metadata = _mapping(run_details.get("metadata"), f"{label}.runDetails.metadata")
    for field in ("invocationId", "startedOn", "finishedOn"):
        _required_string(metadata.get(field), f"{label}.runDetails.metadata.{field}")
    completeness = _mapping(
        metadata.get("buildkit_completeness"),
        f"{label}.runDetails.metadata.buildkit_completeness",
    )
    if completeness.get("request") is not True:
        raise ContractError(
            f"{label}.runDetails.metadata.buildkit_completeness.request must be true"
        )
    if not isinstance(completeness.get("resolvedDependencies"), bool):
        raise ContractError(
            f"{label}.runDetails.metadata.buildkit_completeness."
            "resolvedDependencies must be boolean"
        )
    _mapping(
        metadata.get("buildkit_metadata"),
        f"{label}.runDetails.metadata.buildkit_metadata",
    )


def _verify_image(
    reader: LayoutReader,
    descriptor: Mapping[str, Any],
    *,
    platform: str,
    version: str,
    revision: str,
    source: str,
) -> None:
    manifest = _manifest_document(reader, descriptor, f"{platform} image manifest")
    config_descriptor = _descriptor(manifest.get("config"), f"{platform} image config")
    if config_descriptor["mediaType"] not in {OCI_CONFIG, DOCKER_CONFIG}:
        raise ContractError(f"{platform} image config has an unsupported media type")
    config_data = reader.blob(config_descriptor, f"{platform} image config", load=True)
    assert config_data is not None
    config = _mapping(_json_document(config_data, f"{platform} image config"), "image config")
    expected_os, expected_architecture = platform.split("/", maxsplit=1)
    if config.get("os") != expected_os or config.get("architecture") != expected_architecture:
        raise ContractError(f"{platform} config identity does not match its descriptor")
    runtime = _mapping(config.get("config"), f"{platform} runtime config")
    if runtime.get("User") != "10000:10000":
        raise ContractError(f"{platform} image is not pinned to UID/GID 10000")
    if runtime.get("WorkingDir") != "/var/lib/control-assurance":
        raise ContractError(f"{platform} image has the wrong working directory")
    if runtime.get("Cmd") != ["assurance-lab", "--help"]:
        raise ContractError(f"{platform} image has an unsafe default command")
    if runtime.get("Entrypoint") not in (None, []):
        raise ContractError(f"{platform} image has an unexpected entrypoint")
    labels = _mapping(runtime.get("Labels"), f"{platform} image labels")
    expected_labels = {
        "org.opencontainers.image.licenses": "Apache-2.0",
        "org.opencontainers.image.revision": revision,
        "org.opencontainers.image.source": source,
        "org.opencontainers.image.version": version,
    }
    for name, expected in expected_labels.items():
        if labels.get(name) != expected:
            raise ContractError(f"{platform} image label {name!r} is not release-bound")
    environment = runtime.get("Env", [])
    for entry in _sequence(environment, f"{platform} environment"):
        if not isinstance(entry, str) or "=" not in entry:
            raise ContractError(f"{platform} image has an invalid environment entry")
        name = entry.split("=", maxsplit=1)[0].upper()
        if any(term in name for term in ("SECRET", "TOKEN", "PASSWORD", "PRIVATE_KEY")):
            raise ContractError(f"{platform} image embeds a secret-shaped environment value")
    rootfs = _mapping(config.get("rootfs"), f"{platform} rootfs")
    if rootfs.get("type") != "layers":
        raise ContractError(f"{platform} rootfs type is not layers")
    diff_ids = _sequence(rootfs.get("diff_ids"), f"{platform} rootfs diff_ids")
    layers = _sequence(manifest.get("layers"), f"{platform} image layers")
    if len(diff_ids) != len(layers) or any(
        not isinstance(digest, str) or SHA256.fullmatch(digest) is None for digest in diff_ids
    ):
        raise ContractError(f"{platform} rootfs does not account for every image layer")
    for index, value in enumerate(layers):
        label = f"{platform} image layer {index}"
        layer = _descriptor(value, label)
        observed_diff_id = _verify_layer(reader, layer, label=label)
        if observed_diff_id != diff_ids[index]:
            raise ContractError(f"{label} does not match rootfs.diff_ids[{index}]")


def _verify_attestation(
    reader: LayoutReader,
    descriptor: Mapping[str, Any],
    *,
    target_digest: str,
    platform: str,
    version: str,
    revision: str,
    source: str,
    source_date_epoch: int | None,
) -> tuple[str, ...]:
    manifest = _manifest_document(reader, descriptor, f"{platform} attestation manifest")
    config_descriptor = _descriptor(manifest.get("config"), f"{platform} attestation config")
    if config_descriptor["mediaType"] not in {OCI_CONFIG, DOCKER_CONFIG}:
        raise ContractError(f"{platform} attestation config has an unsupported media type")
    config_data = reader.blob(config_descriptor, f"{platform} attestation config", load=True)
    assert config_data is not None
    config = _mapping(
        _json_document(config_data, f"{platform} attestation config"),
        f"{platform} attestation config",
    )
    if config.get("architecture") != "unknown" or config.get("os") != "unknown":
        raise ContractError(f"{platform} attestation config is not unknown/unknown")
    if config.get("config") not in ({}, None):
        raise ContractError(f"{platform} attestation config has runtime settings")
    rootfs = _mapping(config.get("rootfs"), f"{platform} attestation rootfs")
    if rootfs.get("type") != "layers":
        raise ContractError(f"{platform} attestation rootfs is not layers")
    attestation_diff_ids = _sequence(
        rootfs.get("diff_ids"), f"{platform} attestation rootfs diff_ids"
    )

    predicates: list[str] = []
    layer_digests: list[str] = []
    for index, value in enumerate(_sequence(manifest.get("layers"), f"{platform} attestations")):
        layer = _descriptor(value, f"{platform} attestation {index}")
        if layer["mediaType"] != IN_TOTO:
            raise ContractError(f"{platform} attestation {index} is not in-toto JSON")
        annotations = _mapping(
            layer.get("annotations"), f"{platform} attestation {index} annotations"
        )
        predicate_type = annotations.get(PREDICATE_TYPE)
        if not isinstance(predicate_type, str) or not predicate_type:
            raise ContractError(f"{platform} attestation {index} has no predicate type")
        data = reader.blob(layer, f"{platform} attestation {index}", load=True)
        assert data is not None
        statement = _mapping(
            _json_document(data, f"{platform} attestation {index}"),
            f"{platform} attestation {index}",
        )
        if statement.get("_type") not in {
            "https://in-toto.io/Statement/v0.1",
            "https://in-toto.io/Statement/v1",
        }:
            raise ContractError(f"{platform} attestation {index} has an unknown statement type")
        if statement.get("predicateType") != predicate_type:
            raise ContractError(
                f"{platform} attestation {index} predicate annotation is inconsistent"
            )
        target_hex = target_digest.removeprefix("sha256:")
        subjects = _sequence(statement.get("subject"), f"{platform} attestation {index} subjects")
        if not subjects or any(
            not isinstance(subject, dict)
            or not isinstance(subject.get("name"), str)
            or not subject["name"]
            or subject.get("digest") != {"sha256": target_hex}
            for subject in subjects
        ):
            raise ContractError(
                f"{platform} attestation {index} is not bound to its image manifest"
            )
        if predicate_type == SPDX_PREDICATE:
            _verify_spdx_predicate(statement.get("predicate"), platform=platform)
        elif predicate_type == SLSA_PREDICATE:
            _verify_slsa_predicate(
                statement.get("predicate"),
                platform=platform,
                version=version,
                revision=revision,
                source=source,
                source_date_epoch=source_date_epoch,
            )
        else:
            raise ContractError(f"{platform} attestation {index} has an unsupported predicate type")
        predicates.append(predicate_type)
        layer_digests.append(str(layer["digest"]))
    if attestation_diff_ids != layer_digests:
        raise ContractError(
            f"{platform} attestation config does not account for every statement layer"
        )
    if sorted(predicates) != sorted((SPDX_PREDICATE, SLSA_PREDICATE)):
        raise ContractError(
            f"{platform} image must have exactly one SPDX SBOM and one SLSA v1 "
            "provenance attestation"
        )
    return tuple(sorted(set(predicates)))


def _platform_index(descriptor: Mapping[str, Any]) -> bytes:
    return _canonical_json(
        {
            "manifests": [descriptor],
            "mediaType": OCI_INDEX,
            "schemaVersion": 2,
        }
    )


def verify_layout(
    reader: LayoutReader,
    *,
    reference: str,
    version: str,
    revision: str,
    source: str,
    source_date_epoch: int | None,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    layout = _mapping(
        _json_document(
            reader.read("oci-layout", limit=MAX_CONTROL_BYTES),
            "oci-layout",
            limit=MAX_CONTROL_BYTES,
        ),
        "oci-layout",
    )
    if layout != {"imageLayoutVersion": "1.0.0"}:
        raise ContractError("oci-layout version is not exactly 1.0.0")
    top = _mapping(
        _json_document(
            reader.read("index.json", limit=MAX_CONTROL_BYTES),
            "index.json",
            limit=MAX_CONTROL_BYTES,
        ),
        "index.json",
    )
    if top.get("schemaVersion") != 2 or top.get("mediaType") not in {
        None,
        OCI_INDEX,
    }:
        raise ContractError("index.json is not an OCI v1 index")
    roots = _sequence(top.get("manifests"), "index.json manifests")
    if len(roots) != 1:
        raise ContractError("index.json must name exactly one release index")
    root_descriptor = _descriptor(roots[0], "release index descriptor")
    root_annotations = _mapping(root_descriptor.get("annotations"), "release index annotations")
    if root_annotations.get(REFERENCE_NAME) != reference:
        raise ContractError("release index reference does not match the expected local reference")
    if root_descriptor["mediaType"] not in {OCI_INDEX, DOCKER_INDEX}:
        raise ContractError("release root is not a multi-platform image index")
    root_data = reader.blob(root_descriptor, "release image index", load=True)
    assert root_data is not None
    root = _mapping(_json_document(root_data, "release image index"), "release image index")
    if root.get("schemaVersion") != 2 or root.get("mediaType") not in {
        None,
        root_descriptor["mediaType"],
    }:
        raise ContractError("release image index metadata is inconsistent")
    image_descriptors: dict[str, dict[str, Any]] = {}
    attestation_descriptors: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(_sequence(root.get("manifests"), "release manifests")):
        descriptor = _descriptor(value, f"release manifest {index}")
        platform = _platform(descriptor.get("platform"), f"release manifest {index} platform")
        annotations = descriptor.get("annotations", {})
        if not isinstance(annotations, dict):
            raise ContractError(f"release manifest {index} annotations must be an object")
        if annotations.get(ATTESTATION_KIND) == ATTESTATION_TYPE:
            target = annotations.get(ATTESTATION_DIGEST)
            if platform != "unknown/unknown":
                raise ContractError("attestation manifest must use unknown/unknown platform")
            if not isinstance(target, str) or SHA256.fullmatch(target) is None:
                raise ContractError("attestation manifest does not name an image digest")
            if target in attestation_descriptors:
                raise ContractError("an image has multiple attestation manifests")
            attestation_descriptors[target] = descriptor
            continue
        if platform not in EXPECTED_PLATFORMS:
            raise ContractError(f"release contains an unexpected runnable platform: {platform}")
        if platform in image_descriptors:
            raise ContractError(f"release contains duplicate platform: {platform}")
        image_descriptors[platform] = descriptor
    if tuple(sorted(image_descriptors)) != tuple(sorted(EXPECTED_PLATFORMS)):
        raise ContractError("release does not contain exactly amd64 and arm64 images")
    image_digests = {str(value["digest"]) for value in image_descriptors.values()}
    if set(attestation_descriptors) != image_digests:
        raise ContractError("each platform must have exactly one attached attestation manifest")
    platform_metadata: list[dict[str, Any]] = []
    views: dict[str, bytes] = {}
    for platform in EXPECTED_PLATFORMS:
        image = image_descriptors[platform]
        _verify_image(
            reader,
            image,
            platform=platform,
            version=version,
            revision=revision,
            source=source,
        )
        predicates = _verify_attestation(
            reader,
            attestation_descriptors[str(image["digest"])],
            target_digest=str(image["digest"]),
            platform=platform,
            version=version,
            revision=revision,
            source=source,
            source_date_epoch=source_date_epoch,
        )
        platform_metadata.append(
            {
                "attestation_digest": attestation_descriptors[str(image["digest"])]["digest"],
                "manifest_digest": image["digest"],
                "platform": platform,
                "predicates": list(predicates),
            }
        )
        views[platform] = _platform_index(image)
    blob_files = {name for name in reader.files if BLOB_NAME.fullmatch(name) is not None}
    if reader.observed_blob_names != blob_files:
        extras = sorted(blob_files - reader.observed_blob_names)
        missing = sorted(reader.observed_blob_names - blob_files)
        raise ContractError(
            f"layout is not closed over its reachable blobs; extra={extras!r}, missing={missing!r}"
        )
    metadata = {
        "index_digest": root_descriptor["digest"],
        "platforms": platform_metadata,
        "reference": reference,
        "revision": revision,
        "schema": "control-assurance.release-container-layout/v1",
        "source": source,
        "version": version,
    }
    return metadata, views


def _arguments(arguments: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify the exact multi-platform OCI layout promoted by release CI."
    )
    parser.add_argument("layout", type=Path)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--metadata", type=Path)
    parser.add_argument("--platform-index-directory", type=Path)
    parser.add_argument("--source-date-epoch", type=int)
    return parser.parse_args(arguments)


def _write_new(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(data)
    except FileExistsError as error:
        raise ContractError(f"refusing to replace output: {path}") from error


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = _arguments(sys.argv[1:] if arguments is None else arguments)
    try:
        with LayoutReader(parsed.layout, source_date_epoch=parsed.source_date_epoch) as reader:
            metadata, views = verify_layout(
                reader,
                reference=parsed.reference,
                version=parsed.version,
                revision=parsed.revision,
                source=parsed.source,
                source_date_epoch=parsed.source_date_epoch,
            )
        encoded_metadata = _canonical_json(metadata)
        if parsed.metadata is None:
            sys.stdout.buffer.write(encoded_metadata)
        else:
            _write_new(parsed.metadata, encoded_metadata)
        if parsed.platform_index_directory is not None:
            for platform, data in views.items():
                name = platform.replace("/", "-") + ".json"
                _write_new(parsed.platform_index_directory / name, data)
    except (ContractError, OSError, tarfile.TarError) as error:
        print(f"container layout rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
