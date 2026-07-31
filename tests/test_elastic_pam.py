from __future__ import annotations

import base64
import hashlib
import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from assurance_lab.connectors.contract import (
    ConnectorCapture,
    ConnectorCaptureError,
    ConnectorDescriptor,
    ConnectorWindow,
)
from assurance_lab.connectors.elastic_pam import (
    ElasticJitApiKeyBroker,
    ElasticPamError,
    ElasticPamPolicy,
    ElasticParentCredential,
    SQLiteElasticLeaseJournal,
    _PamHTTPResponse,
    verify_elastic_pam_receipt,
)
from assurance_lab.connectors.elastic_security import (
    ElasticApiKey,
    ElasticSecurityRequest,
)
from assurance_lab.evidence.canonical import canonical_json_bytes, strict_json_loads

_NOW = 1_785_300_000_000
_LEASE_ID = "ab" * 32
_KEY_ID = "key-id_0123456789"
_RAW_KEY = "child-secret-value"
_ENCODED_KEY = base64.b64encode(f"{_KEY_ID}:{_RAW_KEY}".encode()).decode()
_HEADERS = (
    ("content-type", "application/json"),
    ("x-elastic-product", "Elasticsearch"),
)


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _request() -> ElasticSecurityRequest:
    return ElasticSecurityRequest(
        capture_id="pam-capture",
        capture_nonce="cd" * 32,
        window=ConnectorWindow(
            start=datetime(2026, 7, 29, 0, 0, tzinfo=UTC),
            end=datetime(2026, 7, 29, 0, 5, tzinfo=UTC),
        ),
        page_size=10,
        max_hits=100,
    )


def _capture() -> ConnectorCapture:
    receipt = canonical_json_bytes({"capture": "complete"})
    records = b""
    return ConnectorCapture(
        descriptor=ConnectorDescriptor(
            connector_id="elastic-security-readonly",
            connector_version="test",
            capture_media_type="application/test+json",
        ),
        receipt_bytes=receipt,
        receipt_digest=_digest(receipt),
        records_jsonl=records,
        records_digest=_digest(records),
        record_count=0,
    )


def _json_response(value: dict[str, Any], *, status: int = 200) -> _PamHTTPResponse:
    return _PamHTTPResponse(
        status=status,
        headers=_HEADERS,
        body=canonical_json_bytes(value),
    )


def _create_response(
    *,
    expiration: int = _NOW + 900_000,
    key_id: str = _KEY_ID,
    key_name: str = f"control-assurance-{_LEASE_ID[:32]}",
    raw_key: str = _RAW_KEY,
    encoded: str = _ENCODED_KEY,
) -> _PamHTTPResponse:
    return _json_response(
        {
            "api_key": raw_key,
            "encoded": encoded,
            "expiration": expiration,
            "id": key_id,
            "name": key_name,
        }
    )


def _revoke_response(
    *,
    invalidated: list[str] | None = None,
    previous: list[str] | None = None,
) -> _PamHTTPResponse:
    return _json_response(
        {
            "error_count": 0,
            "invalidated_api_keys": invalidated if invalidated is not None else [_KEY_ID],
            "previously_invalidated_api_keys": previous if previous is not None else [],
        }
    )


@dataclass
class _Call:
    method: str
    target: str
    body: bytes
    headers: tuple[tuple[str, str], ...]


class _FakeTransport:
    def __init__(
        self,
        responses: list[_PamHTTPResponse | BaseException | Callable[[_Call], _PamHTTPResponse]],
    ) -> None:
        self.responses = list(responses)
        self.calls: list[_Call] = []

    def request(
        self,
        *,
        method: str,
        target: str,
        body: bytes,
        headers: tuple[tuple[str, str], ...],
        deadline: float,
    ) -> _PamHTTPResponse:
        del deadline
        call = _Call(method=method, target=target, body=body, headers=headers)
        self.calls.append(call)
        if not self.responses:
            raise AssertionError("unexpected PAM request")
        result = self.responses.pop(0)
        if isinstance(result, BaseException):
            raise result
        if callable(result):
            return result(call)
        return result


class _StubConnector:
    def __init__(
        self,
        result: ConnectorCapture | BaseException,
        seen_keys: list[ElasticApiKey],
        key: ElasticApiKey,
    ) -> None:
        self._result = result
        self._seen_keys = seen_keys
        self._key = key

    def capture(self, request: object) -> ConnectorCapture:
        assert request == _request()
        self._seen_keys.append(self._key)
        if isinstance(self._result, BaseException):
            raise self._result
        return self._result


def _broker(
    tmp_path: Path,
    transport: _FakeTransport,
    *,
    capture_result: ConnectorCapture | BaseException | None = None,
    parent: ElasticParentCredential | None = None,
) -> tuple[ElasticJitApiKeyBroker, SQLiteElasticLeaseJournal, list[ElasticApiKey]]:
    journal = SQLiteElasticLeaseJournal(tmp_path / "leases.sqlite3")
    seen_keys: list[ElasticApiKey] = []
    result = capture_result if capture_result is not None else _capture()
    broker = ElasticJitApiKeyBroker(
        "https://elastic.example",
        parent or ElasticParentCredential("Bearer", b"parent-token-value"),
        journal,
        _transport=transport,
        _connector_factory=lambda key: _StubConnector(result, seen_keys, key),
        _nonce=lambda: _LEASE_ID,
        _now=lambda: _NOW,
    )
    return broker, journal, seen_keys


def test_parent_credential_is_opaque_and_api_key_parent_is_rejected() -> None:
    credential = ElasticParentCredential.basic("broker", "correct horse battery staple")
    assert str(credential) == "<redacted>"
    assert "correct horse" not in repr(credential)
    assert credential.scheme == "Basic"
    assert credential._authorization_header().startswith("Basic ")

    with pytest.raises(ValueError, match="Basic or Bearer"):
        ElasticParentCredential("ApiKey", b"derived")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="whitespace"):
        ElasticParentCredential("Bearer", b"secret with space")


def test_policy_is_exact_read_only_and_content_addressed() -> None:
    policy = ElasticPamPolicy(".alerts-security.alerts-default", ttl_seconds=900)
    assert policy.role_descriptor() == {
        "capture": {
            "cluster": [],
            "indices": [
                {
                    "allow_restricted_indices": True,
                    "names": [
                        ".alerts-security.alerts-default",
                        ".internal.alerts-security.alerts-default-*",
                    ],
                    "privileges": ["read"],
                }
            ],
        }
    }
    assert policy.role_descriptor_digest == _digest(
        canonical_json_bytes(policy.role_descriptor())
    )
    with pytest.raises(ValueError, match="exact"):
        ElasticPamPolicy(".alerts-security.alerts-*")
    with pytest.raises(ValueError, match="lifetime"):
        ElasticPamPolicy(".alerts-security.alerts-default", ttl_seconds=60)


def test_capture_uses_one_jit_key_revokes_it_and_emits_secret_free_receipt(
    tmp_path: Path,
) -> None:
    transport = _FakeTransport([_create_response(), _revoke_response()])
    broker, journal, seen_keys = _broker(tmp_path, transport)

    managed = broker.capture(_request())

    assert len(seen_keys) == 1
    assert str(seen_keys[0]) == "<redacted>"
    assert _RAW_KEY.encode() not in managed.pam_receipt_bytes
    assert _ENCODED_KEY.encode() not in managed.pam_receipt_bytes
    assert _KEY_ID.encode() not in managed.pam_receipt_bytes
    assert f"control-assurance-{_LEASE_ID[:32]}".encode() not in managed.pam_receipt_bytes
    assert b"parent-token-value" not in managed.pam_receipt_bytes
    assert [call.method for call in transport.calls] == ["POST", "DELETE"]
    assert all(call.target == "/_security/api_key" for call in transport.calls)

    create_body = strict_json_loads(transport.calls[0].body)
    assert create_body["expiration"] == "900s"
    assert create_body["role_descriptors"] == ElasticPamPolicy(
        _request().index_alias
    ).role_descriptor()
    assert "authorization" not in dict(transport.calls[0].headers)
    assert strict_json_loads(transport.calls[1].body) == {"ids": [_KEY_ID]}

    record = journal.get(_LEASE_ID)
    assert record.state == "revoked"
    assert record.revoke_attempts == 1
    assert record.key_id == _KEY_ID
    receipt = strict_json_loads(managed.pam_receipt_bytes)
    verified = verify_elastic_pam_receipt(
        managed.pam_receipt_bytes,
        expected_request_digest=receipt["lease"]["request_digest"],
        expected_endpoint_origin_digest=broker.endpoint_origin_digest,
        expected_role_descriptor_digest=ElasticPamPolicy(
            _request().index_alias
        ).role_descriptor_digest,
        expected_capture_receipt_digest=managed.capture.receipt_digest,
        expected_capture_records_digest=managed.capture.records_digest,
    )
    assert verified.lease_id == _LEASE_ID
    assert verified.receipt_digest == managed.pam_receipt_digest


def test_connector_failure_is_returned_only_after_key_revocation(tmp_path: Path) -> None:
    transport = _FakeTransport([_create_response(), _revoke_response()])
    failure = ConnectorCaptureError("search", "exact hit count changed")
    broker, journal, _ = _broker(tmp_path, transport, capture_result=failure)

    with pytest.raises(ConnectorCaptureError, match="exact hit count changed"):
        broker.capture(_request())

    assert journal.get(_LEASE_ID).state == "revoked"
    assert [call.method for call in transport.calls] == ["POST", "DELETE"]
    assert journal.get(_LEASE_ID).last_error is None


def test_capture_is_withheld_when_revocation_is_not_confirmed(tmp_path: Path) -> None:
    transport = _FakeTransport(
        [
            _create_response(),
            ElasticPamError("transport", "revocation endpoint unavailable"),
        ]
    )
    broker, journal, _ = _broker(tmp_path, transport)

    with pytest.raises(ElasticPamError, match="capture is withheld"):
        broker.capture(_request())

    record = journal.get(_LEASE_ID)
    assert record.state == "revoke-pending"
    assert record.revoke_attempts == 1


def test_ambiguous_create_is_cleaned_up_by_unique_name(tmp_path: Path) -> None:
    malformed = _json_response(
        {
            "api_key": _RAW_KEY,
            "encoded": _ENCODED_KEY,
            "expiration": _NOW + 900_000,
            "id": _KEY_ID,
            "name": "wrong-name",
        }
    )
    transport = _FakeTransport(
        [
            malformed,
            _revoke_response(invalidated=[], previous=[]),
        ]
    )
    broker, journal, _ = _broker(tmp_path, transport)

    with pytest.raises(ElasticPamError, match="different lease"):
        broker.capture(_request())

    assert strict_json_loads(transport.calls[1].body) == {
        "name": f"control-assurance-{_LEASE_ID[:32]}",
        "owner": True,
    }
    assert journal.get(_LEASE_ID).state == "revoked"


def test_prepared_intent_survives_restart_and_recovery_never_reissues(
    tmp_path: Path,
) -> None:
    journal = SQLiteElasticLeaseJournal(tmp_path / "leases.sqlite3")
    policy = ElasticPamPolicy(_request().index_alias)
    journal.prepare(
        lease_id=_LEASE_ID,
        key_name=f"control-assurance-{_LEASE_ID[:32]}",
        policy=policy,
        request_digest=_digest(canonical_json_bytes(_request().as_json())),
        endpoint_origin_digest=_digest(b"https://elastic.example"),
        now_epoch_millis=_NOW,
    )
    transport = _FakeTransport([_revoke_response(invalidated=[], previous=[])])
    broker = ElasticJitApiKeyBroker(
        "https://elastic.example",
        ElasticParentCredential("Bearer", b"parent-token-value"),
        SQLiteElasticLeaseJournal(tmp_path / "leases.sqlite3"),
        _transport=transport,
        _now=lambda: _NOW,
    )

    results = broker.recover_unsettled()

    assert len(results) == 1
    assert results[0].final_state == "revoked"
    assert results[0].revocation_outcome == "not-created"
    assert [call.method for call in transport.calls] == ["DELETE"]
    assert strict_json_loads(transport.calls[0].body)["name"].startswith(
        "control-assurance-"
    )


def test_request_scoped_recovery_does_not_revoke_another_run(
    tmp_path: Path,
) -> None:
    journal = SQLiteElasticLeaseJournal(tmp_path / "scoped-leases.sqlite3")
    policy = ElasticPamPolicy(_request().index_alias)
    first_request_digest = _digest(b"first connector request")
    second_request_digest = _digest(b"second connector request")
    second_lease_id = "f" * 64
    journal.prepare(
        lease_id=_LEASE_ID,
        key_name=f"control-assurance-{_LEASE_ID[:32]}",
        policy=policy,
        request_digest=first_request_digest,
        endpoint_origin_digest=_digest(b"https://elastic.example"),
        now_epoch_millis=_NOW,
    )
    journal.prepare(
        lease_id=second_lease_id,
        key_name=f"control-assurance-{second_lease_id[:32]}",
        policy=policy,
        request_digest=second_request_digest,
        endpoint_origin_digest=_digest(b"https://elastic.example"),
        now_epoch_millis=_NOW + 1,
    )
    transport = _FakeTransport([_revoke_response(invalidated=[], previous=[])])
    broker = ElasticJitApiKeyBroker(
        "https://elastic.example",
        ElasticParentCredential("Bearer", b"parent-token-value"),
        journal,
        _transport=transport,
        _now=lambda: _NOW + 2,
    )

    recovered = broker.recover_request_digest(first_request_digest)

    assert [result.lease_id for result in recovered] == [_LEASE_ID]
    assert len(transport.calls) == 1
    assert strict_json_loads(transport.calls[0].body) == {
        "name": f"control-assurance-{_LEASE_ID[:32]}",
        "owner": True,
    }
    assert journal.get(_LEASE_ID).state == "revoked"
    assert journal.get(second_lease_id).state == "prepared"


def test_active_intent_recovery_uses_exact_key_id_and_accepts_idempotent_result(
    tmp_path: Path,
) -> None:
    journal = SQLiteElasticLeaseJournal(tmp_path / "leases.sqlite3")
    policy = ElasticPamPolicy(_request().index_alias)
    prepared = journal.prepare(
        lease_id=_LEASE_ID,
        key_name=f"control-assurance-{_LEASE_ID[:32]}",
        policy=policy,
        request_digest=_digest(canonical_json_bytes(_request().as_json())),
        endpoint_origin_digest=_digest(b"https://elastic.example"),
        now_epoch_millis=_NOW,
    )
    journal.activate(
        lease_id=_LEASE_ID,
        expected_revision=prepared.revision,
        key_id=_KEY_ID,
        expiration_epoch_millis=_NOW + 900_000,
        now_epoch_millis=_NOW,
    )
    transport = _FakeTransport(
        [_revoke_response(invalidated=[], previous=[_KEY_ID])]
    )
    broker = ElasticJitApiKeyBroker(
        "https://elastic.example",
        ElasticParentCredential("Bearer", b"parent-token-value"),
        journal,
        _transport=transport,
        _now=lambda: _NOW,
    )

    result = broker.recover_unsettled()

    assert result[0].revocation_outcome == "previously-invalidated"
    assert strict_json_loads(transport.calls[0].body) == {"ids": [_KEY_ID]}
    assert journal.get(_LEASE_ID).state == "revoked"


def test_parent_secret_reflection_fails_closed_but_still_runs_name_cleanup(
    tmp_path: Path,
) -> None:
    reflected = _PamHTTPResponse(
        status=200,
        headers=_HEADERS,
        body=b'{"error":"parent-token-value"}',
    )
    transport = _FakeTransport(
        [reflected, _revoke_response(invalidated=[], previous=[])]
    )
    broker, journal, _ = _broker(tmp_path, transport)

    with pytest.raises(ElasticPamError, match="reflected parent credentials"):
        broker.capture(_request())

    assert journal.get(_LEASE_ID).state == "revoked"
    assert [call.method for call in transport.calls] == ["POST", "DELETE"]


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (
            _create_response(
                encoded=base64.b64encode(b"different:value").decode()
            ),
            "encodings do not agree",
        ),
        (
            _create_response(expiration=_NOW + 2_000_000),
            "outside the lease window",
        ),
        (
            _PamHTTPResponse(
                status=200,
                headers=(("content-type", "application/json"),),
                body=b"{}",
            ),
            "product marker",
        ),
    ],
)
def test_invalid_create_responses_fail_closed_and_are_recovered_by_name(
    tmp_path: Path,
    response: _PamHTTPResponse,
    message: str,
) -> None:
    transport = _FakeTransport(
        [response, _revoke_response(invalidated=[], previous=[])]
    )
    broker, journal, _ = _broker(tmp_path, transport)

    with pytest.raises(ElasticPamError, match=message):
        broker.capture(_request())

    assert journal.get(_LEASE_ID).state == "revoked"


def test_receipt_tamper_and_wrong_external_anchor_are_rejected(tmp_path: Path) -> None:
    transport = _FakeTransport([_create_response(), _revoke_response()])
    broker, _, _ = _broker(tmp_path, transport)
    managed = broker.capture(_request())
    parsed = strict_json_loads(managed.pam_receipt_bytes)

    with pytest.raises(ElasticPamError, match="external anchor"):
        verify_elastic_pam_receipt(
            managed.pam_receipt_bytes,
            expected_request_digest=_digest(b"wrong"),
            expected_endpoint_origin_digest=broker.endpoint_origin_digest,
            expected_role_descriptor_digest=ElasticPamPolicy(
                _request().index_alias
            ).role_descriptor_digest,
            expected_capture_receipt_digest=managed.capture.receipt_digest,
            expected_capture_records_digest=managed.capture.records_digest,
        )

    parsed["mutations"]["revocation_outcome"] = "not-created"
    tampered = canonical_json_bytes(parsed)
    with pytest.raises(ElasticPamError, match="issued key was revoked"):
        verify_elastic_pam_receipt(
            tampered,
            expected_request_digest=parsed["lease"]["request_digest"],
            expected_endpoint_origin_digest=broker.endpoint_origin_digest,
            expected_role_descriptor_digest=parsed["lease"][
                "role_descriptor_digest"
            ],
            expected_capture_receipt_digest=managed.capture.receipt_digest,
            expected_capture_records_digest=managed.capture.records_digest,
        )

    noncanonical = b'{ "broker": ' + managed.pam_receipt_bytes.split(
        b'"broker":', 1
    )[1]
    with pytest.raises(ElasticPamError, match="canonical"):
        verify_elastic_pam_receipt(
            noncanonical,
            expected_request_digest=parsed["lease"]["request_digest"],
            expected_endpoint_origin_digest=broker.endpoint_origin_digest,
            expected_role_descriptor_digest=parsed["lease"][
                "role_descriptor_digest"
            ],
            expected_capture_receipt_digest=managed.capture.receipt_digest,
            expected_capture_records_digest=managed.capture.records_digest,
        )


def test_journal_rejects_symlink_and_permissive_existing_file(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"")
    os.chmod(target, 0o600)
    link = tmp_path / "link.sqlite3"
    link.symlink_to(target)
    with pytest.raises(ElasticPamError, match="owner-only"):
        SQLiteElasticLeaseJournal(link)

    permissive = tmp_path / "permissive.sqlite3"
    permissive.write_bytes(b"")
    os.chmod(permissive, 0o644)
    with pytest.raises(ElasticPamError, match="owner-only"):
        SQLiteElasticLeaseJournal(permissive)
