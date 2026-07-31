"""Canonical public identity for one fully composed runtime execution.

An execution plan fixes *what* will be collected and retained.  This document
fixes *which* public source, PAM, custody, and signing identities were selected
to carry that plan out.  Credential bytes and private endpoint strings never
enter this boundary; the source and custody identity documents are themselves
canonical, secret-free objects produced by their runtime composition layers.

The exact bytes are journaled before a connector, PAM broker, signer, or S3
writer may perform a side effect.  Recovery either reconstructs these same
bytes or fails closed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Final, Literal, cast

from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)
from assurance_lab.runtime.models import sha256_digest

EXECUTION_ENVIRONMENT_IDENTITY_MEDIA_TYPE: Final = (
    "application/vnd.control-assurance.execution-environment-identity.v1+json"
)
EXECUTION_ENVIRONMENT_IDENTITY_SCHEMA_VERSION: Final = "1.0.0"
MAX_EXECUTION_ENVIRONMENT_IDENTITY_BYTES: Final = 512 * 1024

SourceRuntimeKind = Literal["elastic-security", "defender-xdr"]

_LIMITS = JSONLimits(
    max_bytes=MAX_EXECUTION_ENVIRONMENT_IDENTITY_BYTES,
    max_line_bytes=MAX_EXECUTION_ENVIRONMENT_IDENTITY_BYTES,
    max_depth=24,
    max_collection_items=16_384,
    max_string_length=256 * 1024,
)
_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_PORTABLE_ID_RE = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_MEDIA_TYPE_RE = re.compile(
    r"^application/(?:json|[a-z0-9!#$&^_.+-]+[+]json)$"
)
_SOURCE_REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+/@:-]{0,255}$")
_SOURCE_DOCUMENT_KIND: Final[dict[SourceRuntimeKind, str]] = {
    "elastic-security": "elastic-runtime-identity",
    "defender-xdr": "defender-runtime-identity",
}
_FIELDS = frozenset(
    {
        "configuration_digest",
        "control_id",
        "custody_deployment_profile_digest",
        "custody_identity",
        "custody_identity_digest",
        "custody_identity_media_type",
        "execution_plan_digest",
        "media_type",
        "run_id",
        "schema_version",
        "source_identity",
        "source_identity_digest",
        "source_identity_media_type",
        "source_kind",
        "source_revision",
        "tenant_id",
    }
)


class ExecutionEnvironmentIdentityError(ValueError):
    """The public execution identity is malformed or crosses a boundary."""


def _digest(value: object, *, label: str) -> str:
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        raise ExecutionEnvironmentIdentityError(f"{label} is not a canonical digest")
    return value


def _portable_id(value: object, *, label: str) -> str:
    if type(value) is not str or _PORTABLE_ID_RE.fullmatch(value) is None:
        raise ExecutionEnvironmentIdentityError(f"{label} is not portable")
    return value


def _media_type(value: object, *, label: str) -> str:
    if type(value) is not str or _MEDIA_TYPE_RE.fullmatch(value) is None:
        raise ExecutionEnvironmentIdentityError(f"{label} is invalid")
    return value


def _canonical_object(value: bytes, *, label: str) -> dict[str, object]:
    if (
        type(value) is not bytes
        or not value
        or len(value) > MAX_EXECUTION_ENVIRONMENT_IDENTITY_BYTES
    ):
        raise ExecutionEnvironmentIdentityError(
            f"{label} is absent or exceeds its bound"
        )
    try:
        parsed = strict_json_loads(value, limits=_LIMITS)
        encoded = canonical_json_bytes(parsed, limits=_LIMITS)
    except StrictJSONError:
        raise ExecutionEnvironmentIdentityError(
            f"{label} is not bounded strict JSON"
        ) from None
    if not isinstance(parsed, dict) or encoded != value:
        raise ExecutionEnvironmentIdentityError(
            f"{label} is not one canonical JSON object"
        )
    return cast(dict[str, object], parsed)


@dataclass(frozen=True, slots=True, repr=False)
class ExecutionEnvironmentIdentity:
    """Exact public source and custody composition for one frozen run."""

    run_id: str
    tenant_id: str
    control_id: str
    configuration_digest: str
    execution_plan_digest: str
    source_revision: str
    source_kind: SourceRuntimeKind
    source_identity_media_type: str
    source_identity_bytes: bytes = field(repr=False)
    source_identity_digest: str
    custody_identity_media_type: str
    custody_identity_bytes: bytes = field(repr=False)
    custody_identity_digest: str
    custody_deployment_profile_digest: str

    def __post_init__(self) -> None:
        _digest(self.run_id, label="run id")
        _portable_id(self.tenant_id, label="tenant id")
        _portable_id(self.control_id, label="control id")
        _digest(self.configuration_digest, label="configuration digest")
        _digest(self.execution_plan_digest, label="execution plan digest")
        if (
            type(self.source_revision) is not str
            or _SOURCE_REVISION_RE.fullmatch(self.source_revision) is None
        ):
            raise ExecutionEnvironmentIdentityError("source revision is invalid")
        if self.source_kind not in _SOURCE_DOCUMENT_KIND:
            raise ExecutionEnvironmentIdentityError("source kind is unsupported")
        _media_type(
            self.source_identity_media_type,
            label="source identity media type",
        )
        _media_type(
            self.custody_identity_media_type,
            label="custody identity media type",
        )
        _digest(self.source_identity_digest, label="source identity digest")
        _digest(self.custody_identity_digest, label="custody identity digest")
        _digest(
            self.custody_deployment_profile_digest,
            label="custody deployment profile digest",
        )
        source = _canonical_object(
            self.source_identity_bytes,
            label="source identity",
        )
        custody = _canonical_object(
            self.custody_identity_bytes,
            label="custody identity",
        )
        if (
            sha256_digest(self.source_identity_bytes)
            != self.source_identity_digest
            or sha256_digest(self.custody_identity_bytes)
            != self.custody_identity_digest
        ):
            raise ExecutionEnvironmentIdentityError(
                "nested identity digest differs from its bytes"
            )
        if (
            source.get("kind") != _SOURCE_DOCUMENT_KIND[self.source_kind]
            or source.get("media_type") != self.source_identity_media_type
            or custody.get("media_type") != self.custody_identity_media_type
            or custody.get("run_id") != self.run_id
            or custody.get("tenant_id") != self.tenant_id
            or custody.get("control_id") != self.control_id
            or custody.get("configuration_digest")
            != self.configuration_digest
            or custody.get("execution_plan_digest")
            != self.execution_plan_digest
            or custody.get("deployment_profile_digest")
            != self.custody_deployment_profile_digest
        ):
            raise ExecutionEnvironmentIdentityError(
                "nested runtime identities cross the execution boundary"
            )
        if len(self.canonical_bytes()) > MAX_EXECUTION_ENVIRONMENT_IDENTITY_BYTES:
            raise ExecutionEnvironmentIdentityError(
                "execution environment identity exceeds its bound"
            )

    def __repr__(self) -> str:
        return (
            "ExecutionEnvironmentIdentity("
            f"run_id={self.run_id!r}, source_kind={self.source_kind!r}, "
            f"digest={self.digest!r})"
        )

    def as_json(self) -> dict[str, object]:
        return {
            "configuration_digest": self.configuration_digest,
            "control_id": self.control_id,
            "custody_deployment_profile_digest": (
                self.custody_deployment_profile_digest
            ),
            "custody_identity": _canonical_object(
                self.custody_identity_bytes,
                label="custody identity",
            ),
            "custody_identity_digest": self.custody_identity_digest,
            "custody_identity_media_type": self.custody_identity_media_type,
            "execution_plan_digest": self.execution_plan_digest,
            "media_type": EXECUTION_ENVIRONMENT_IDENTITY_MEDIA_TYPE,
            "run_id": self.run_id,
            "schema_version": EXECUTION_ENVIRONMENT_IDENTITY_SCHEMA_VERSION,
            "source_identity": _canonical_object(
                self.source_identity_bytes,
                label="source identity",
            ),
            "source_identity_digest": self.source_identity_digest,
            "source_identity_media_type": self.source_identity_media_type,
            "source_kind": self.source_kind,
            "source_revision": self.source_revision,
            "tenant_id": self.tenant_id,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.as_json(), limits=_LIMITS)

    @property
    def digest(self) -> str:
        return sha256_digest(self.canonical_bytes())


def parse_execution_environment_identity(
    value: bytes,
) -> ExecutionEnvironmentIdentity:
    """Reopen and independently rederive one canonical identity document."""

    document = _canonical_object(value, label="execution environment identity")
    if set(document) != _FIELDS:
        raise ExecutionEnvironmentIdentityError(
            "execution environment identity fields are invalid"
        )
    if (
        document.get("media_type")
        != EXECUTION_ENVIRONMENT_IDENTITY_MEDIA_TYPE
        or document.get("schema_version")
        != EXECUTION_ENVIRONMENT_IDENTITY_SCHEMA_VERSION
    ):
        raise ExecutionEnvironmentIdentityError(
            "execution environment identity version is unsupported"
        )
    source = document.get("source_identity")
    custody = document.get("custody_identity")
    if not isinstance(source, dict) or not isinstance(custody, dict):
        raise ExecutionEnvironmentIdentityError(
            "execution environment nested identities are invalid"
        )
    source_kind = document.get("source_kind")
    if source_kind not in _SOURCE_DOCUMENT_KIND:
        raise ExecutionEnvironmentIdentityError("source kind is unsupported")
    try:
        identity = ExecutionEnvironmentIdentity(
            run_id=_digest(document.get("run_id"), label="run id"),
            tenant_id=_portable_id(document.get("tenant_id"), label="tenant id"),
            control_id=_portable_id(
                document.get("control_id"),
                label="control id",
            ),
            configuration_digest=_digest(
                document.get("configuration_digest"),
                label="configuration digest",
            ),
            execution_plan_digest=_digest(
                document.get("execution_plan_digest"),
                label="execution plan digest",
            ),
            source_revision=cast(str, document.get("source_revision")),
            source_kind=source_kind,
            source_identity_media_type=_media_type(
                document.get("source_identity_media_type"),
                label="source identity media type",
            ),
            source_identity_bytes=canonical_json_bytes(source, limits=_LIMITS),
            source_identity_digest=_digest(
                document.get("source_identity_digest"),
                label="source identity digest",
            ),
            custody_identity_media_type=_media_type(
                document.get("custody_identity_media_type"),
                label="custody identity media type",
            ),
            custody_identity_bytes=canonical_json_bytes(custody, limits=_LIMITS),
            custody_identity_digest=_digest(
                document.get("custody_identity_digest"),
                label="custody identity digest",
            ),
            custody_deployment_profile_digest=_digest(
                document.get("custody_deployment_profile_digest"),
                label="custody deployment profile digest",
            ),
        )
    except (TypeError, ValueError):
        raise ExecutionEnvironmentIdentityError(
            "execution environment identity is invalid"
        ) from None
    if identity.canonical_bytes() != value:
        raise ExecutionEnvironmentIdentityError(
            "execution environment identity did not round-trip"
        )
    return identity


__all__ = [
    "EXECUTION_ENVIRONMENT_IDENTITY_MEDIA_TYPE",
    "EXECUTION_ENVIRONMENT_IDENTITY_SCHEMA_VERSION",
    "MAX_EXECUTION_ENVIRONMENT_IDENTITY_BYTES",
    "ExecutionEnvironmentIdentity",
    "ExecutionEnvironmentIdentityError",
    "SourceRuntimeKind",
    "parse_execution_environment_identity",
]
