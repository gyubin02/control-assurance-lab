from __future__ import annotations

import json

import pytest

from assurance_lab.evidence.canonical import canonical_json_bytes
from assurance_lab.runtime.execution_identity import (
    EXECUTION_ENVIRONMENT_IDENTITY_MEDIA_TYPE,
    ExecutionEnvironmentIdentity,
    ExecutionEnvironmentIdentityError,
    parse_execution_environment_identity,
)
from assurance_lab.runtime.models import sha256_digest

_RUN = f"sha256:{'1' * 64}"
_CONFIGURATION = f"sha256:{'2' * 64}"
_PLAN = f"sha256:{'3' * 64}"
_PROFILE = f"sha256:{'4' * 64}"


def _source() -> bytes:
    return canonical_json_bytes(
        {
            "kind": "elastic-runtime-identity",
            "media_type": (
                "application/vnd.control-assurance."
                "elastic-runtime-identity.v1+json"
            ),
            "schema_version": "1.0.0",
            "endpoint_origin_digest": f"sha256:{'5' * 64}",
        }
    )


def _custody(*, run_id: str = _RUN) -> bytes:
    return canonical_json_bytes(
        {
            "configuration_digest": _CONFIGURATION,
            "control_id": "alert-completeness",
            "deployment_profile_digest": _PROFILE,
            "execution_plan_digest": _PLAN,
            "media_type": (
                "application/vnd.control-assurance."
                "custody-runtime-identity.v1+json"
            ),
            "run_id": run_id,
            "schema_version": "1.0.0",
            "tenant_id": "acme-bank",
        }
    )


def _identity(
    *,
    source: bytes | None = None,
    custody: bytes | None = None,
) -> ExecutionEnvironmentIdentity:
    source = source or _source()
    custody = custody or _custody()
    return ExecutionEnvironmentIdentity(
        run_id=_RUN,
        tenant_id="acme-bank",
        control_id="alert-completeness",
        configuration_digest=_CONFIGURATION,
        execution_plan_digest=_PLAN,
        source_revision="oci:sha256:0123456789abcdef",
        source_kind="elastic-security",
        source_identity_media_type=(
            "application/vnd.control-assurance."
            "elastic-runtime-identity.v1+json"
        ),
        source_identity_bytes=source,
        source_identity_digest=sha256_digest(source),
        custody_identity_media_type=(
            "application/vnd.control-assurance."
            "custody-runtime-identity.v1+json"
        ),
        custody_identity_bytes=custody,
        custody_identity_digest=sha256_digest(custody),
        custody_deployment_profile_digest=_PROFILE,
    )


def test_execution_environment_identity_round_trips_exact_public_bytes() -> None:
    identity = _identity()
    encoded = identity.canonical_bytes()

    reopened = parse_execution_environment_identity(encoded)

    assert reopened == identity
    assert reopened.digest == sha256_digest(encoded)
    assert (
        json.loads(encoded)["media_type"]
        == EXECUTION_ENVIRONMENT_IDENTITY_MEDIA_TYPE
    )
    assert "https://" not in encoded.decode()
    assert "password" not in encoded.decode()


def test_execution_environment_identity_binds_nested_source_bytes() -> None:
    original = _identity()
    changed_source = canonical_json_bytes(
        {
            **json.loads(_source()),
            "endpoint_origin_digest": f"sha256:{'6' * 64}",
        }
    )

    changed = _identity(source=changed_source)

    assert changed.digest != original.digest
    assert changed.source_identity_digest != original.source_identity_digest


def test_execution_environment_identity_rejects_cross_run_custody() -> None:
    with pytest.raises(
        ExecutionEnvironmentIdentityError,
        match="cross",
    ):
        _identity(custody=_custody(run_id=f"sha256:{'9' * 64}"))


def test_execution_environment_identity_rejects_nested_digest_substitution() -> None:
    source = _source()
    with pytest.raises(
        ExecutionEnvironmentIdentityError,
        match="digest",
    ):
        ExecutionEnvironmentIdentity(
            run_id=_RUN,
            tenant_id="acme-bank",
            control_id="alert-completeness",
            configuration_digest=_CONFIGURATION,
            execution_plan_digest=_PLAN,
            source_revision="git:0123456789abcdef",
            source_kind="elastic-security",
            source_identity_media_type=(
                "application/vnd.control-assurance."
                "elastic-runtime-identity.v1+json"
            ),
            source_identity_bytes=source,
            source_identity_digest=f"sha256:{'0' * 64}",
            custody_identity_media_type=(
                "application/vnd.control-assurance."
                "custody-runtime-identity.v1+json"
            ),
            custody_identity_bytes=_custody(),
            custody_identity_digest=sha256_digest(_custody()),
            custody_deployment_profile_digest=_PROFILE,
        )


def test_execution_environment_identity_rejects_noncanonical_outer_bytes() -> None:
    encoded = _identity().canonical_bytes()
    noncanonical = json.dumps(
        json.loads(encoded),
        indent=2,
        sort_keys=False,
    ).encode()

    with pytest.raises(
        ExecutionEnvironmentIdentityError,
        match="canonical",
    ):
        parse_execution_environment_identity(noncanonical)


def test_execution_environment_identity_repr_has_no_nested_documents() -> None:
    rendered = repr(_identity())

    assert "endpoint_origin_digest" not in rendered
    assert "custody-runtime" not in rendered
    assert "sha256:" in rendered
