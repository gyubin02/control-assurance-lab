from __future__ import annotations

import pytest

from assurance_lab.connectors.elastic_pam import ElasticParentCredential
from assurance_lab.connectors.secret_profiles import (
    ConnectorSecretProfileError,
    decode_elastic_parent_credential,
)
from assurance_lab.evidence.canonical import canonical_json_bytes


def _document(**changes: object) -> bytes:
    document: dict[str, object] = {
        "kind": "elastic-parent-credential",
        "password": "private-password",
        "schema_version": "1.0.0",
        "scheme": "basic",
        "username": "collector",
    }
    document.update(changes)
    return canonical_json_bytes(document)


def test_basic_profile_returns_only_an_opaque_parent_credential() -> None:
    credential = decode_elastic_parent_credential(_document())

    assert type(credential) is ElasticParentCredential
    assert credential.scheme == "Basic"
    assert str(credential) == "<redacted>"
    assert "private-password" not in repr(credential)
    assert credential._authorization_header().startswith("Basic ")
    assert "private-password" not in credential._authorization_header()


def test_bearer_profile_returns_redacted_exact_token() -> None:
    document = canonical_json_bytes(
        {
            "kind": "elastic-parent-credential",
            "schema_version": "1.0.0",
            "scheme": "bearer",
            "token": "opaque-parent-token",
        }
    )

    credential = decode_elastic_parent_credential(document)

    assert credential.scheme == "Bearer"
    assert credential._authorization_header() == "Bearer opaque-parent-token"
    assert "opaque-parent-token" not in repr(credential)


@pytest.mark.parametrize(
    "document",
    [
        b"",
        b'{ "kind":"elastic-parent-credential"}',
        canonical_json_bytes(
            {
                "kind": "elastic-parent-credential",
                "password": "private-password",
                "schema_version": "1.0.0",
                "scheme": "basic",
                "unexpected": True,
                "username": "collector",
            }
        ),
        _document(schema_version="2.0.0"),
        _document(scheme="digest"),
        _document(username=""),
        _document(username="name:with-colon"),
        canonical_json_bytes(
            {
                "kind": "elastic-parent-credential",
                "schema_version": "1.0.0",
                "scheme": "bearer",
                "token": "contains whitespace",
            }
        ),
    ],
)
def test_malformed_or_ambiguous_profiles_fail_closed(document: bytes) -> None:
    with pytest.raises(ConnectorSecretProfileError) as raised:
        decode_elastic_parent_credential(document)

    assert "private-password" not in str(raised.value)
    assert "contains whitespace" not in str(raised.value)


def test_duplicate_json_member_is_rejected() -> None:
    document = (
        b'{"kind":"elastic-parent-credential","password":"one",'
        b'"password":"two","schema_version":"1.0.0","scheme":"basic",'
        b'"username":"collector"}'
    )

    with pytest.raises(ConnectorSecretProfileError, match="strict bounded JSON"):
        decode_elastic_parent_credential(document)


def test_oversized_document_is_rejected_before_json_parsing() -> None:
    with pytest.raises(ConnectorSecretProfileError, match="exceeds"):
        decode_elastic_parent_credential(b"x" * (32 * 1024 + 1))
