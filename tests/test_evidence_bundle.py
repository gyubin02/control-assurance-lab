import hashlib
import os
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from assurance_lab.evidence import bundle as bundle_module
from assurance_lab.evidence.bundle import (
    PROFILE,
    ROOT_MEDIA_TYPE,
    SCHEMA_VERSION,
    BundleFile,
    BundleLimits,
    BundleManifest,
    BundleStatus,
    EvaluationRef,
    EvaluatorRef,
    ExperimentRef,
    Sensitivity,
    validate_payload_path,
    verify_bundle,
)
from assurance_lab.evidence.canonical import canonical_json_bytes


def _manifest(
    payload: bytes,
    *,
    path: str = "records/events.jsonl",
    media_type: str = "application/x-ndjson",
) -> BundleManifest:
    return BundleManifest(
        media_type=ROOT_MEDIA_TYPE,
        schema_version=SCHEMA_VERSION,
        profile=PROFILE,
        created_at="2026-07-29T03:15:00.000000Z",
        as_of="2026-07-29T03:14:00.000000Z",
        experiment=ExperimentRef(
            id="fin-entitlement-release-001",
            spec_version="1.0.0",
            spec_digest=f"sha256:{'1' * 64}",
        ),
        evaluation=EvaluationRef(
            policy_id="policy:financial-reference:v1",
            policy_digest=f"sha256:{'2' * 64}",
            evaluator=EvaluatorRef(
                name="assurance-lab",
                version="0.1.0",
                source_revision="test-revision",
                image_digest=None,
            ),
        ),
        parent_bundles=[],
        files=[
            BundleFile(
                path=path,
                sha256=hashlib.sha256(payload).hexdigest(),
                size=len(payload),
                media_type=media_type,
                role="test-artifact",
                sensitivity=Sensitivity.SYNTHETIC,
                required_for=["integrity"],
            )
        ],
    )


def _write_bundle(
    root: Path,
    payload: bytes,
    *,
    path: str = "records/events.jsonl",
    media_type: str = "application/x-ndjson",
) -> tuple[BundleManifest, bytes]:
    destination = root / path
    destination.parent.mkdir(parents=True)
    destination.write_bytes(payload)
    manifest = _manifest(payload, path=path, media_type=media_type)
    raw_manifest = manifest.canonical_bytes()
    (root / "bundle.json").write_bytes(raw_manifest)
    return manifest, raw_manifest


def _write_manifest_dict(root: Path, manifest: dict[str, object]) -> None:
    (root / "bundle.json").write_bytes(canonical_json_bytes(manifest))


def test_verified_bundle_hashes_the_exact_canonical_root(tmp_path: Path) -> None:
    payload = b'{"id":"event:1","value":true}\n'
    manifest, raw_manifest = _write_bundle(tmp_path, payload)

    first = verify_bundle(tmp_path)
    second = verify_bundle(tmp_path)

    assert first.status == BundleStatus.INTEGRITY_VERIFIED
    assert not first.issues
    assert first.bundle_id == (
        f"cab:sha256:{hashlib.sha256(raw_manifest).hexdigest()}"
    )
    assert first.bundle_id == manifest.bundle_id() == second.bundle_id


def test_one_changed_byte_is_corruption(tmp_path: Path) -> None:
    original = b'{"id":"event:1","value":true}\n'
    _write_bundle(tmp_path, original)
    (tmp_path / "records/events.jsonl").write_bytes(
        b'{"id":"event:1","value":false}\n'
    )

    result = verify_bundle(tmp_path)

    assert result.status == BundleStatus.CORRUPT
    assert {issue.code for issue in result.issues} == {
        "size-mismatch",
        "digest-mismatch",
    }


def test_root_manifest_must_be_exact_rfc8785_bytes(tmp_path: Path) -> None:
    payload = b'{"id":"event:1"}\n'
    _, raw_manifest = _write_bundle(tmp_path, payload)
    (tmp_path / "bundle.json").write_bytes(raw_manifest + b"\n")

    result = verify_bundle(tmp_path)

    assert result.status == BundleStatus.CORRUPT
    assert [issue.code for issue in result.issues] == [
        "noncanonical-root-manifest"
    ]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "1.0.1"),
        ("profile", "full-synthetic"),
        ("media_type", "application/vnd.example.bundle+json"),
    ],
)
def test_unknown_root_version_profile_or_media_type_is_unsupported(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    payload = b'{"id":"event:1"}\n'
    manifest, _ = _write_bundle(tmp_path, payload)
    document = manifest.model_dump(mode="json")
    document[field] = value
    _write_manifest_dict(tmp_path, document)

    result = verify_bundle(tmp_path)

    assert result.status == BundleStatus.UNSUPPORTED
    assert result.issues[0].code == f"unsupported-{field.replace('_', '-')}"


@pytest.mark.parametrize("missing", ["media_type", "profile", "parent_bundles"])
def test_required_root_fields_must_be_explicit(
    tmp_path: Path,
    missing: str,
) -> None:
    payload = b'{"id":"event:1"}\n'
    manifest, _ = _write_bundle(tmp_path, payload)
    document = manifest.model_dump(mode="json")
    del document[missing]
    _write_manifest_dict(tmp_path, document)

    result = verify_bundle(tmp_path)

    assert result.status == BundleStatus.CORRUPT
    assert result.issues[0].code == "invalid-root-manifest"


def test_models_forbid_extensions_and_integer_coercion(tmp_path: Path) -> None:
    payload = b'{"id":"event:1"}\n'
    manifest, _ = _write_bundle(tmp_path, payload)
    document = manifest.model_dump(mode="json")
    document["extension"] = True
    _write_manifest_dict(tmp_path, document)

    result = verify_bundle(tmp_path)
    assert result.status == BundleStatus.CORRUPT
    assert result.issues[0].code == "invalid-root-manifest"

    descriptor = manifest.files[0].model_dump()
    descriptor["size"] = "1"
    with pytest.raises(ValidationError) as caught:
        BundleFile.model_validate(descriptor)
    assert caught.value.errors()[0]["loc"] == ("size",)


@pytest.mark.parametrize(
    ("location", "value"),
    [
        (("files", 0, "role"), "role\nforged"),
        (("files", 0, "required_for", 0), "integrity\tforged"),
        (("experiment", "id"), "experiment:\u202eforged"),
        (("evaluation", "evaluator", "name"), "assurance\u2066lab"),
    ],
)
def test_manifest_display_strings_reject_controls_and_bidi(
    tmp_path: Path,
    location: tuple[str | int, ...],
    value: str,
) -> None:
    payload = b'{"id":"event:1"}\n'
    manifest, _ = _write_bundle(tmp_path, payload)
    document = manifest.model_dump(mode="json")
    target: object = document
    for component in location[:-1]:
        target = target[component]  # type: ignore[index]
    target[location[-1]] = value  # type: ignore[index]
    _write_manifest_dict(tmp_path, document)

    result = verify_bundle(tmp_path)

    assert result.status == BundleStatus.CORRUPT
    assert result.issues[0].code == "invalid-root-manifest"


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-07-29T03:15:00Z",
        "2026-07-29T03:15:00.00000Z",
        "2026-07-29T03:15:00.000000+00:00",
        "2026-02-30T03:15:00.000000Z",
    ],
)
def test_timestamps_require_exact_utc_microsecond_form(
    tmp_path: Path,
    timestamp: str,
) -> None:
    payload = b'{"id":"event:1"}\n'
    manifest, _ = _write_bundle(tmp_path, payload)
    document = manifest.model_dump(mode="json")
    document["created_at"] = timestamp
    _write_manifest_dict(tmp_path, document)

    result = verify_bundle(tmp_path)

    assert result.status == BundleStatus.CORRUPT
    assert result.issues[0].code == "invalid-root-manifest"


@pytest.mark.parametrize(
    "path",
    [
        "/records/events.jsonl",
        "records/../events.jsonl",
        "records//events.jsonl",
        "records/events\\copy.jsonl",
        "records/\x1fevents.jsonl",
        "records/\u202eevents.jsonl",
        "records/café.jsonl",
        "records/.events.jsonl",
        f"records/{'a' * 256}.jsonl",
    ],
)
def test_payload_paths_are_portable_ascii_and_bounded(path: str) -> None:
    with pytest.raises(ValueError):
        validate_payload_path(path)


def test_unlisted_file_symlink_and_sidecar_are_rejected(tmp_path: Path) -> None:
    payload = b'{"id":"event:1"}\n'
    _write_bundle(tmp_path, payload)
    (tmp_path / "records/extra.json").write_text("{}")
    (tmp_path / "records/link").symlink_to(tmp_path / "bundle.json")
    (tmp_path / "verification").mkdir()
    (tmp_path / "verification/producer.json").write_text("{}")

    result = verify_bundle(tmp_path)
    codes = {issue.code for issue in result.issues}

    assert result.status == BundleStatus.CORRUPT
    assert {
        "unlisted-file",
        "unlisted-directory",
        "unsafe-symlink",
    }.issubset(codes)


def test_hardlinked_payload_is_rejected(tmp_path: Path) -> None:
    payload = b'{"id":"event:1"}\n'
    _write_bundle(tmp_path, payload)
    os.link(
        tmp_path / "records/events.jsonl",
        tmp_path / "records/copy.jsonl",
    )

    result = verify_bundle(tmp_path)

    assert result.status == BundleStatus.CORRUPT
    assert "unsafe-hardlink" in {issue.code for issue in result.issues}


def test_duplicate_or_traversal_manifest_paths_are_rejected(tmp_path: Path) -> None:
    payload = b'{"id":"event:1"}\n'
    manifest = _manifest(payload).model_dump(mode="json")
    files = manifest["files"]
    assert isinstance(files, list)
    first = files[0]
    assert isinstance(first, dict)
    first["path"] = "records/../outside.json"
    _write_manifest_dict(tmp_path, manifest)

    result = verify_bundle(tmp_path)

    assert result.status == BundleStatus.CORRUPT
    assert result.issues[0].code == "invalid-root-manifest"


@pytest.mark.parametrize(
    ("payload", "path", "media_type"),
    [
        (
            b'{"id":"event:2"}\n{"id":"event:1"}\n',
            "records/events.jsonl",
            "application/x-ndjson",
        ),
        (
            b'{"id": "event:1"}\n',
            "records/events.jsonl",
            "application/x-ndjson",
        ),
        (
            b'{"id":"event:1"}\r\n',
            "records/events.jsonl",
            "application/jsonl",
        ),
        (
            b'{ "id": "event:1" }',
            "derived/result.json",
            "application/json",
        ),
    ],
)
def test_declared_json_artifacts_must_use_canonical_representation(
    tmp_path: Path,
    payload: bytes,
    path: str,
    media_type: str,
) -> None:
    _write_bundle(tmp_path, payload, path=path, media_type=media_type)

    result = verify_bundle(tmp_path)

    assert result.status == BundleStatus.CORRUPT
    assert "invalid-canonical-artifact" in {
        issue.code for issue in result.issues
    }


def test_canonical_json_artifact_is_accepted(tmp_path: Path) -> None:
    payload = b'{"id":"result:1","measurement":"1.2500"}'
    _write_bundle(
        tmp_path,
        payload,
        path="derived/result.json",
        media_type="application/json",
    )

    result = verify_bundle(tmp_path)

    assert result.status == BundleStatus.INTEGRITY_VERIFIED


def test_resource_limits_stop_tree_processing(tmp_path: Path) -> None:
    payload = b'{"id":"event:1"}\n'
    _write_bundle(tmp_path, payload)

    result = verify_bundle(tmp_path, limits=BundleLimits(max_files=1))

    assert result.status == BundleStatus.CORRUPT
    assert "resource-limit" in {issue.code for issue in result.issues}


def test_manifest_size_is_checked_before_read(tmp_path: Path) -> None:
    payload = b'{"id":"event:1"}\n'
    _, raw_manifest = _write_bundle(tmp_path, payload)

    result = verify_bundle(
        tmp_path,
        limits=BundleLimits(max_manifest_bytes=len(raw_manifest) - 1),
    )

    assert result.status == BundleStatus.CORRUPT
    assert result.issues[0].code == "resource-limit"


def test_same_inode_payload_overwrite_after_hash_is_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = b'{"id":"event:1","value":"safe"}\n'
    replacement = b'{"id":"event:1","value":"evil"}\n'
    assert len(original) == len(replacement)
    _write_bundle(tmp_path, original)
    target = tmp_path / "records/events.jsonl"
    before = target.stat()
    real_hash_payload = bundle_module._hash_payload
    overwritten = False

    def overwrite_after_hash(
        *args: Any,
        **kwargs: Any,
    ) -> tuple[str, int, bytes | None]:
        nonlocal overwritten
        result = real_hash_payload(*args, **kwargs)
        if not overwritten:
            target.write_bytes(replacement)
            overwritten = True
        return result

    monkeypatch.setattr(bundle_module, "_hash_payload", overwrite_after_hash)

    result = bundle_module.verify_bundle(tmp_path)

    assert target.stat().st_ino == before.st_ino
    assert result.status == BundleStatus.CORRUPT
    assert {
        "entry-changed",
        "digest-mismatch",
    } & {issue.code for issue in result.issues}
