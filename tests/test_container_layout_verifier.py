from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_VERIFIER = _ROOT / "scripts" / "verify-container-layout.py"
_REFERENCE = "sha-deadbeef"
_VERSION = "0.1.0"
_REVISION = "d" * 40
_SOURCE = "https://github.com/gyubin02/control-assurance-lab"
_EPOCH = 1_700_000_000
_BUILDKIT_BUILD_TYPE = (
    "https://github.com/moby/buildkit/blob/master/"
    "docs/attestations/slsa-definitions.md"
)


def _json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _store(root: Path, data: bytes) -> dict[str, Any]:
    digest = hashlib.sha256(data).hexdigest()
    (root / "blobs" / "sha256" / digest).write_bytes(data)
    return {"digest": f"sha256:{digest}", "size": len(data)}


def _descriptor(
    stored: dict[str, Any],
    media_type: str,
    **extra: Any,
) -> dict[str, Any]:
    return {"mediaType": media_type, **stored, **extra}


def _gzip_layer() -> tuple[bytes, str]:
    uncompressed = io.BytesIO()
    with tarfile.open(
        fileobj=uncompressed, mode="w", format=tarfile.USTAR_FORMAT
    ) as archive:
        data = b"release-boundary-fixture\n"
        member = tarfile.TarInfo("opt/control-assurance/fixture.txt")
        member.mode = 0o644
        member.mtime = _EPOCH
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
    tar_bytes = uncompressed.getvalue()
    return (
        gzip.compress(tar_bytes, compresslevel=9, mtime=0),
        f"sha256:{hashlib.sha256(tar_bytes).hexdigest()}",
    )


def _spdx_predicate(*, orphan_relationship: bool = False) -> dict[str, Any]:
    package_id = "SPDXRef-Package-control-assurance"
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": "2026-01-01T00:00:00Z",
            "creators": ["Tool: release-boundary-fixture-1.0"],
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": "https://example.invalid/spdx/control-assurance",
        "name": "control-assurance",
        "packages": [
            {
                "SPDXID": package_id,
                "downloadLocation": "NOASSERTION",
                "name": "control-assurance",
                "versionInfo": _VERSION,
            }
        ],
        "relationships": [
            {
                "relatedSpdxElement": package_id,
                "relationshipType": (
                    "CONTAINS" if orphan_relationship else "DESCRIBES"
                ),
                "spdxElementId": "SPDXRef-DOCUMENT",
            }
        ],
        "spdxVersion": "SPDX-2.3",
    }


def _slsa_predicate(
    architecture: str,
    *,
    extra_build_arg: bool = False,
    incomplete_request: bool = False,
    revision: str = _REVISION,
) -> dict[str, Any]:
    build_args = {
        "build-arg:IMAGE_VERSION": _VERSION,
        "build-arg:SOURCE_DATE_EPOCH": str(_EPOCH),
        "build-arg:SOURCE_REVISION": revision,
        "build-arg:SOURCE_URL": _SOURCE,
    }
    if extra_build_arg:
        build_args["build-arg:UNREVIEWED_INPUT"] = "present"
    return {
        "buildDefinition": {
            "buildType": _BUILDKIT_BUILD_TYPE,
            "externalParameters": {
                "configSource": {"path": "Dockerfile"},
                "request": {
                    "args": build_args,
                    "frontend": "dockerfile.v0",
                    "locals": [{"name": "context"}, {"name": "dockerfile"}],
                },
            },
            "internalParameters": {
                "buildConfig": {"llbDefinition": [{"id": "step0"}]},
                "builderPlatform": "linux/amd64",
            },
            "resolvedDependencies": [
                {
                    "digest": {"sha256": architecture[0] * 64},
                    "uri": f"pkg:docker/python@fixture?platform=linux%2F{architecture}",
                }
            ],
        },
        "runDetails": {
            "builder": {"id": ""},
            "metadata": {
                "buildkit_completeness": {
                    "request": not incomplete_request,
                    "resolvedDependencies": True,
                },
                "buildkit_metadata": {},
                "finishedOn": "2026-01-01T00:00:01Z",
                "invocationId": f"fixture-{architecture}",
                "startedOn": "2026-01-01T00:00:00Z",
            },
        },
    }


def _release_layout(
    root: Path,
    *,
    include_arm_attestation: bool = True,
    empty_spdx: bool = False,
    empty_slsa: bool = False,
    extra_slsa_build_arg: bool = False,
    incomplete_slsa_request: bool = False,
    malformed_layer: bool = False,
    orphan_spdx_relationship: bool = False,
    wrong_slsa_revision: bool = False,
    wrong_diff_id: bool = False,
) -> dict[str, str]:
    (root / "blobs" / "sha256").mkdir(parents=True)
    (root / "oci-layout").write_bytes(_json({"imageLayoutVersion": "1.0.0"}))
    layer_bytes, diff_id = _gzip_layer()
    if malformed_layer:
        layer_bytes = b"not-a-gzip-stream"
    layer_blob = _store(root, layer_bytes)
    if wrong_diff_id:
        diff_id = f"sha256:{'0' * 64}"
    platform_manifests: dict[str, dict[str, Any]] = {}
    attestations: dict[str, dict[str, Any]] = {}
    for architecture in ("amd64", "arm64"):
        platform = f"linux/{architecture}"
        config = _store(
            root,
            _json(
                {
                    "architecture": architecture,
                    "config": {
                        "Cmd": ["assurance-lab", "--help"],
                        "Entrypoint": None,
                        "Env": [
                            "HOME=/tmp",
                            "PATH=/opt/control-assurance/bin:/usr/local/bin:/usr/bin:/bin",
                        ],
                        "Labels": {
                            "org.opencontainers.image.licenses": "Apache-2.0",
                            "org.opencontainers.image.revision": _REVISION,
                            "org.opencontainers.image.source": _SOURCE,
                            "org.opencontainers.image.version": _VERSION,
                        },
                        "User": "10000:10000",
                        "WorkingDir": "/var/lib/control-assurance",
                    },
                    "os": "linux",
                    "rootfs": {
                        "diff_ids": [diff_id],
                        "type": "layers",
                    },
                }
            ),
        )
        manifest = _store(
            root,
            _json(
                {
                    "config": _descriptor(
                        config, "application/vnd.oci.image.config.v1+json"
                    ),
                    "layers": [
                        _descriptor(
                            layer_blob,
                            "application/vnd.oci.image.layer.v1.tar+gzip",
                        )
                    ],
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "schemaVersion": 2,
                }
            ),
        )
        image_descriptor = _descriptor(
            manifest,
            "application/vnd.oci.image.manifest.v1+json",
            platform={"architecture": architecture, "os": "linux"},
        )
        platform_manifests[platform] = image_descriptor
        target_hex = str(manifest["digest"]).removeprefix("sha256:")
        attestation_layers: list[dict[str, Any]] = []
        for predicate in (
            "https://spdx.dev/Document",
            "https://slsa.dev/provenance/v1",
        ):
            predicate_body = (
                _spdx_predicate(orphan_relationship=orphan_spdx_relationship)
                if predicate == "https://spdx.dev/Document"
                else _slsa_predicate(
                    architecture,
                    extra_build_arg=extra_slsa_build_arg,
                    incomplete_request=incomplete_slsa_request,
                    revision="e" * 40 if wrong_slsa_revision else _REVISION,
                )
            )
            if empty_spdx and predicate == "https://spdx.dev/Document":
                predicate_body = {}
            if empty_slsa and predicate == "https://slsa.dev/provenance/v1":
                predicate_body = {}
            statement = _store(
                root,
                _json(
                    {
                        "_type": "https://in-toto.io/Statement/v1",
                        "predicate": predicate_body,
                        "predicateType": predicate,
                        "subject": [
                            {
                                "digest": {"sha256": target_hex},
                                "name": "_",
                            }
                        ],
                    }
                ),
            )
            attestation_layers.append(
                _descriptor(
                    statement,
                    "application/vnd.in-toto+json",
                    annotations={"in-toto.io/predicate-type": predicate},
                )
            )
        attestation_config = _store(
            root,
            _json(
                {
                    "architecture": "unknown",
                    "config": {},
                    "os": "unknown",
                    "rootfs": {
                        "diff_ids": [
                            str(layer["digest"]) for layer in attestation_layers
                        ],
                        "type": "layers",
                    },
                }
            ),
        )
        attestation_manifest = _store(
            root,
            _json(
                {
                    "config": _descriptor(
                        attestation_config,
                        "application/vnd.oci.image.config.v1+json",
                    ),
                    "layers": attestation_layers,
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "schemaVersion": 2,
                }
            ),
        )
        attestations[platform] = _descriptor(
            attestation_manifest,
            "application/vnd.oci.image.manifest.v1+json",
            annotations={
                "vnd.docker.reference.digest": manifest["digest"],
                "vnd.docker.reference.type": "attestation-manifest",
            },
            platform={"architecture": "unknown", "os": "unknown"},
        )
    manifests = [
        platform_manifests["linux/amd64"],
        attestations["linux/amd64"],
        platform_manifests["linux/arm64"],
    ]
    if include_arm_attestation:
        manifests.append(attestations["linux/arm64"])
    else:
        missing = attestations["linux/arm64"]["digest"].removeprefix("sha256:")
        (root / "blobs" / "sha256" / missing).unlink()
    release_index = _store(
        root,
        _json(
            {
                "manifests": manifests,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "schemaVersion": 2,
            }
        ),
    )
    (root / "index.json").write_bytes(
        _json(
            {
                "manifests": [
                    _descriptor(
                        release_index,
                        "application/vnd.oci.image.index.v1+json",
                        annotations={"org.opencontainers.image.ref.name": _REFERENCE},
                    )
                ],
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "schemaVersion": 2,
            }
        )
    )
    return {
        platform: str(descriptor["digest"])
        for platform, descriptor in platform_manifests.items()
    }


def _command(layout: Path, *extra: str) -> list[str]:
    return [
        sys.executable,
        str(_VERIFIER),
        str(layout),
        "--reference",
        _REFERENCE,
        "--version",
        _VERSION,
        "--revision",
        _REVISION,
        "--source",
        _SOURCE,
        "--source-date-epoch",
        str(_EPOCH),
        *extra,
    ]


def _deterministic_tar(source: Path, target: Path) -> None:
    with tarfile.open(target, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name in (".", "blobs", "blobs/sha256"):
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.mtime = _EPOCH
            archive.addfile(info)
        for path in sorted(item for item in source.rglob("*") if item.is_file()):
            data = path.read_bytes()
            info = tarfile.TarInfo(path.relative_to(source).as_posix())
            info.mode = 0o644
            info.mtime = _EPOCH
            info.size = len(data)
            archive.addfile(info, fileobj=__import__("io").BytesIO(data))


def test_verifier_emits_exact_platform_views(tmp_path: Path) -> None:
    layout = tmp_path / "layout"
    expected = _release_layout(layout)
    metadata = tmp_path / "metadata.json"
    views = tmp_path / "views"

    subprocess.run(
        _command(
            layout,
            "--metadata",
            str(metadata),
            "--platform-index-directory",
            str(views),
        ),
        check=True,
    )

    result = json.loads(metadata.read_text(encoding="utf-8"))
    assert {
        entry["platform"]: entry["manifest_digest"] for entry in result["platforms"]
    } == expected
    for platform in ("linux-amd64", "linux-arm64"):
        view = json.loads((views / f"{platform}.json").read_text(encoding="utf-8"))
        assert len(view["manifests"]) == 1


def test_verifier_accepts_the_deterministic_release_tar(tmp_path: Path) -> None:
    layout = tmp_path / "layout"
    _release_layout(layout)
    archive = tmp_path / "release.oci.tar"
    _deterministic_tar(layout, archive)

    completed = subprocess.run(
        _command(archive),
        check=True,
        capture_output=True,
        text=True,
    )

    assert json.loads(completed.stdout)["schema"] == (
        "control-assurance.release-container-layout/v1"
    )


def test_verifier_rejects_a_tampered_reachable_blob(tmp_path: Path) -> None:
    layout = tmp_path / "layout"
    _release_layout(layout)
    blob = next((layout / "blobs" / "sha256").iterdir())
    blob.write_bytes(blob.read_bytes() + b"tampered")

    completed = subprocess.run(
        _command(layout),
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "descriptor size does not match" in completed.stderr


def test_verifier_rejects_a_platform_without_attestations(tmp_path: Path) -> None:
    layout = tmp_path / "layout"
    _release_layout(layout, include_arm_attestation=False)

    completed = subprocess.run(
        _command(layout),
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "each platform must have exactly one" in completed.stderr


def test_verifier_rejects_an_empty_spdx_predicate(tmp_path: Path) -> None:
    layout = tmp_path / "layout"
    _release_layout(layout, empty_spdx=True)

    completed = subprocess.run(
        _command(layout),
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "SPDX predicate" in completed.stderr


def test_verifier_rejects_an_empty_slsa_predicate(tmp_path: Path) -> None:
    layout = tmp_path / "layout"
    _release_layout(layout, empty_slsa=True)

    completed = subprocess.run(
        _command(layout),
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "SLSA predicate" in completed.stderr


def test_verifier_rejects_unbound_slsa_build_arguments(tmp_path: Path) -> None:
    layout = tmp_path / "layout"
    _release_layout(layout, wrong_slsa_revision=True)

    completed = subprocess.run(
        _command(layout),
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "build arguments are not exactly release-bound" in completed.stderr


def test_verifier_rejects_additional_slsa_build_arguments(tmp_path: Path) -> None:
    layout = tmp_path / "layout"
    _release_layout(layout, extra_slsa_build_arg=True)

    completed = subprocess.run(
        _command(layout),
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "build arguments are not exactly release-bound" in completed.stderr


def test_verifier_rejects_incomplete_slsa_requests(tmp_path: Path) -> None:
    layout = tmp_path / "layout"
    _release_layout(layout, incomplete_slsa_request=True)

    completed = subprocess.run(
        _command(layout),
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "buildkit_completeness.request must be true" in completed.stderr


def test_verifier_rejects_spdx_without_a_described_package(
    tmp_path: Path,
) -> None:
    layout = tmp_path / "layout"
    _release_layout(layout, orphan_spdx_relationship=True)

    completed = subprocess.run(
        _command(layout),
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "does not describe any declared package" in completed.stderr


def test_verifier_rejects_a_malformed_compressed_layer(tmp_path: Path) -> None:
    layout = tmp_path / "layout"
    _release_layout(layout, malformed_layer=True)

    completed = subprocess.run(
        _command(layout),
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "valid gzip tar stream" in completed.stderr


def test_verifier_rejects_a_layer_diff_id_mismatch(tmp_path: Path) -> None:
    layout = tmp_path / "layout"
    _release_layout(layout, wrong_diff_id=True)

    completed = subprocess.run(
        _command(layout),
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "rootfs.diff_ids" in completed.stderr


def test_verifier_rejects_symlinks_and_unreachable_blobs(tmp_path: Path) -> None:
    if not hasattr(os, "symlink"):
        pytest.skip("symlink support is required")
    layout = tmp_path / "layout"
    _release_layout(layout)
    os.symlink(layout / "oci-layout", layout / "foreign")

    completed = subprocess.run(
        _command(layout),
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "single-link regular file" in completed.stderr
