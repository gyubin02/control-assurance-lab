"""Secret-document profiles consumed by connector PAM boundaries.

Secret managers store opaque bytes.  The runtime must not guess what those
bytes mean, silently accept extra fields, or let parsing failures echo secret
material.  These decoders accept one canonical document shape and immediately
turn it into an opaque connector credential.
"""

from __future__ import annotations

from typing import Final

from assurance_lab.connectors.elastic_pam import ElasticParentCredential
from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)

ELASTIC_PARENT_CREDENTIAL_CONTENT_TYPE: Final = (
    "application/vnd.control-assurance.elastic-parent-credential.v1+json"
)
ELASTIC_PARENT_CREDENTIAL_SCHEMA_VERSION: Final = "1.0.0"

_MAX_DOCUMENT_BYTES: Final = 32 * 1024
_DOCUMENT_LIMITS = JSONLimits(
    max_bytes=_MAX_DOCUMENT_BYTES,
    max_line_bytes=_MAX_DOCUMENT_BYTES,
    max_depth=3,
    max_collection_items=16,
    max_string_length=16 * 1024,
)


class ConnectorSecretProfileError(ValueError):
    """Credential-free secret profile failure."""


def decode_elastic_parent_credential(value: bytes) -> ElasticParentCredential:
    """Decode one canonical Basic or Bearer parent credential document."""

    if type(value) is not bytes or not value or len(value) > _MAX_DOCUMENT_BYTES:
        raise ConnectorSecretProfileError(
            "Elastic parent credential document is absent or exceeds its limit"
        )
    try:
        parsed = strict_json_loads(value, limits=_DOCUMENT_LIMITS)
        if not isinstance(parsed, dict):
            raise ConnectorSecretProfileError("Elastic parent credential document is not an object")
        if canonical_json_bytes(parsed, limits=_DOCUMENT_LIMITS) != value:
            raise ConnectorSecretProfileError(
                "Elastic parent credential document is not canonical JSON"
            )
    except StrictJSONError:
        raise ConnectorSecretProfileError(
            "Elastic parent credential document is not strict bounded JSON"
        ) from None

    common = {"kind", "schema_version", "scheme"}
    if (
        parsed.get("kind") != "elastic-parent-credential"
        or parsed.get("schema_version") != ELASTIC_PARENT_CREDENTIAL_SCHEMA_VERSION
        or parsed.get("scheme") not in {"basic", "bearer"}
    ):
        raise ConnectorSecretProfileError("Elastic parent credential profile identity is invalid")
    try:
        if parsed["scheme"] == "basic":
            if set(parsed) != common | {"password", "username"}:
                raise ConnectorSecretProfileError("Elastic Basic credential fields are invalid")
            username = parsed["username"]
            password = parsed["password"]
            if (
                type(username) is not str
                or type(password) is not str
                or not username
                or len(username.encode("utf-8")) > 4_096
                or len(password.encode("utf-8")) > 12_000
            ):
                raise ConnectorSecretProfileError("Elastic Basic credential values are invalid")
            return ElasticParentCredential.basic(username, password)

        if set(parsed) != common | {"token"}:
            raise ConnectorSecretProfileError("Elastic Bearer credential fields are invalid")
        token = parsed["token"]
        if type(token) is not str or not token or len(token) > 16_384:
            raise ConnectorSecretProfileError("Elastic Bearer credential value is invalid")
        return ElasticParentCredential(
            "Bearer",
            token.encode("ascii", errors="strict"),
        )
    except ConnectorSecretProfileError:
        raise
    except (UnicodeEncodeError, ValueError):
        raise ConnectorSecretProfileError(
            "Elastic parent credential values are outside the approved profile"
        ) from None


__all__ = [
    "ELASTIC_PARENT_CREDENTIAL_CONTENT_TYPE",
    "ELASTIC_PARENT_CREDENTIAL_SCHEMA_VERSION",
    "ConnectorSecretProfileError",
    "decode_elastic_parent_credential",
]
