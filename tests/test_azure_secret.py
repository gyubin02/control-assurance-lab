from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any

import pytest

from assurance_lab.evidence.canonical import canonical_json_bytes, strict_json_loads
from assurance_lab.key_management import azure_secret as azs
from assurance_lab.key_management.azure_key_vault import (
    AZURE_KEY_VAULT_SCOPE,
    AzureKeyVaultBearerToken,
)

_REFERENCE = azs.AzureKeyVaultSecretReference(
    vault_name="assurance-prod",
    secret_name="elastic-parent",
    secret_version="a" * 32,
)
_TOKEN = b"workload-token-private"
_SECRET = b'{"password":"not-for-logs","scheme":"basic","username":"collector"}'
_PROFILE = "application/vnd.control-assurance.elastic-parent-credential.v1+json"
_NOW = datetime(2026, 7, 29, 6, 0, tzinfo=UTC)


class _TokenProvider:
    def __init__(self, *, valid_until: float = 10_000.0) -> None:
        self.valid_until = valid_until
        self.calls: list[tuple[str, float]] = []

    def get_token(
        self,
        *,
        scope: str,
        deadline: float,
    ) -> AzureKeyVaultBearerToken:
        self.calls.append((scope, deadline))
        return AzureKeyVaultBearerToken(
            _TOKEN,
            valid_until_monotonic=self.valid_until,
        )


class _Transport:
    def __init__(self, response: azs._SecretHTTPResponse) -> None:
        self.response = response
        self.calls: list[tuple[str, str, float]] = []
        self.lock = threading.Lock()

    def get(
        self,
        *,
        target: str,
        token: AzureKeyVaultBearerToken,
        deadline: float,
    ) -> azs._SecretHTTPResponse:
        with self.lock:
            self.calls.append((target, token._authorization_header(), deadline))
        return self.response


def _response(
    *,
    secret: bytes = _SECRET,
    secret_id: str = _REFERENCE.secret_uri,
    status: int = 200,
    enabled: bool = True,
    not_before: int | None = None,
    expires: int | None = None,
    content_type: str | None = _PROFILE,
    extra: dict[str, Any] | None = None,
    response_content_type: str = "application/json; charset=utf-8",
) -> azs._SecretHTTPResponse:
    attributes: dict[str, object] = {"enabled": enabled}
    if not_before is not None:
        attributes["nbf"] = not_before
    if expires is not None:
        attributes["exp"] = expires
    document: dict[str, object] = {
        "attributes": attributes,
        "id": secret_id,
        "value": secret.decode(),
    }
    if content_type is not None:
        document["contentType"] = content_type
    if extra:
        document.update(extra)
    return azs._SecretHTTPResponse(
        status=status,
        headers=(("content-type", response_content_type),),
        body=canonical_json_bytes(document),
    )


def _client(
    response: azs._SecretHTTPResponse,
    *,
    monotonic: float = 100.0,
    provider: _TokenProvider | None = None,
) -> tuple[azs.AzureKeyVaultSecretClient, _TokenProvider, _Transport]:
    selected_provider = provider or _TokenProvider()
    transport = _Transport(response)
    client = azs.AzureKeyVaultSecretClient(
        selected_provider,
        _REFERENCE,
        _transport=transport,
        _monotonic=lambda: monotonic,
        _now=lambda: _NOW,
    )
    return client, selected_provider, transport


def test_reference_requires_exact_vault_name_secret_and_version() -> None:
    text = f"azure-keyvault://assurance-prod/secrets/elastic-parent/{'a' * 32}"

    parsed = azs.AzureKeyVaultSecretReference.parse(text)

    assert parsed == _REFERENCE
    assert parsed.configuration_reference == text
    assert parsed.secret_uri == (
        f"https://assurance-prod.vault.azure.net/secrets/elastic-parent/{'a' * 32}"
    )
    assert parsed.reference_digest.startswith("sha256:")


@pytest.mark.parametrize(
    "reference",
    [
        "azure-keyvault://assurance-prod/secrets/elastic-parent/latest",
        f"azure-keyvault://Assurance-prod/secrets/elastic-parent/{'a' * 32}",
        f"azure-keyvault://assurance-prod:443/secrets/elastic-parent/{'a' * 32}",
        f"azure-keyvault://assurance-prod/keys/elastic-parent/{'a' * 32}",
        f"azure-keyvault://assurance-prod/secrets/elastic-parent/{'A' * 32}",
        f"azure-keyvault://user@assurance-prod/secrets/elastic-parent/{'a' * 32}",
        f"azure-keyvault://assurance-prod/secrets/elastic-parent/{'a' * 32}?x=1",
    ],
)
def test_reference_rejects_mutable_or_ambiguous_forms(reference: str) -> None:
    with pytest.raises(ValueError):
        azs.AzureKeyVaultSecretReference.parse(reference)


def test_exact_version_read_is_redacted_and_decoded_under_content_profile() -> None:
    client, provider, transport = _client(_response())

    secret = client.get()
    decoded = secret.consume(
        strict_json_loads,
        expected_content_type=_PROFILE,
    )

    assert decoded == {
        "password": "not-for-logs",
        "scheme": "basic",
        "username": "collector",
    }
    assert secret.reference_digest == _REFERENCE.reference_digest
    assert secret.content_type == _PROFILE
    assert secret.retrieved_at == _NOW
    assert str(secret) == "<redacted>"
    assert _SECRET.decode() not in repr(secret)
    assert b"not-for-logs".decode() not in repr(client)
    assert provider.calls[0][0] == AZURE_KEY_VAULT_SCOPE
    assert transport.calls == [
        (
            (f"/secrets/elastic-parent/{'a' * 32}?api-version=2025-07-01"),
            f"Bearer {_TOKEN.decode()}",
            160.0,
        )
    ]


def test_secret_decoder_failure_never_copies_secret_into_the_exception() -> None:
    client, _provider, _transport = _client(_response())
    secret = client.get()

    with pytest.raises(azs.AzureKeyVaultSecretError) as raised:
        secret.consume(lambda value: (_ for _ in ()).throw(ValueError(value.decode())))

    assert raised.value.stage == "decode"
    assert b"not-for-logs".decode() not in str(raised.value)
    assert b"not-for-logs".decode() not in repr(raised.value)


def test_wrong_content_profile_fails_before_decoder_runs() -> None:
    client, _provider, _transport = _client(_response())
    secret = client.get()
    called = False

    def decoder(value: bytes) -> object:
        nonlocal called
        called = True
        return value

    with pytest.raises(azs.AzureKeyVaultSecretError, match="content type"):
        secret.consume(
            decoder,
            expected_content_type="application/pem-certificate-chain",
        )

    assert called is False


@pytest.mark.parametrize(
    ("response", "stage"),
    [
        (_response(secret_id="https://other.vault.azure.net/secrets/x/" + "b" * 32), "response"),
        (_response(enabled=False), "policy"),
        (
            _response(not_before=int(_NOW.timestamp()) + 1),
            "policy",
        ),
        (
            _response(expires=int(_NOW.timestamp())),
            "policy",
        ),
        (
            _response(
                extra={"unexpected": "member"},
            ),
            "response",
        ),
        (
            _response(response_content_type="text/html"),
            "response",
        ),
    ],
)
def test_response_must_bind_exact_enabled_current_secret(
    response: azs._SecretHTTPResponse,
    stage: str,
) -> None:
    client, _provider, _transport = _client(response)

    with pytest.raises(azs.AzureKeyVaultSecretError) as raised:
        client.get()

    assert raised.value.stage == stage


def test_bearer_token_reflection_is_rejected_on_remote_error() -> None:
    response = azs._SecretHTTPResponse(
        status=401,
        headers=(("content-type", "application/json"),),
        body=canonical_json_bytes({"error": _TOKEN.decode()}),
    )
    client, _provider, _transport = _client(response)

    with pytest.raises(azs.AzureKeyVaultSecretError, match="credential material"):
        client.get()


def test_bearer_token_reflection_in_selected_header_is_rejected() -> None:
    response = _response()
    reflected = azs._SecretHTTPResponse(
        status=response.status,
        headers=(
            ("content-type", "application/json"),
            ("request-id", _TOKEN.decode()),
        ),
        body=response.body,
    )
    client, _provider, _transport = _client(reflected)

    with pytest.raises(azs.AzureKeyVaultSecretError, match="credential material"):
        client.get()


def test_expired_token_fails_before_network() -> None:
    provider = _TokenProvider(valid_until=99.0)
    client, _provider, transport = _client(
        _response(),
        monotonic=100.0,
        provider=provider,
    )

    with pytest.raises(azs.AzureKeyVaultSecretError) as raised:
        client.get()

    assert raised.value.stage == "authentication"
    assert transport.calls == []


@pytest.mark.parametrize(
    "clock",
    [
        lambda: float("nan"),
        lambda: -1.0,
        lambda: "100",
    ],
)
def test_invalid_monotonic_clock_fails_closed(clock: Any) -> None:
    transport = _Transport(_response())
    client = azs.AzureKeyVaultSecretClient(
        _TokenProvider(),
        _REFERENCE,
        _transport=transport,
        _monotonic=clock,
        _now=lambda: _NOW,
    )

    with pytest.raises(azs.AzureKeyVaultSecretError) as raised:
        client.get()

    assert raised.value.stage == "clock"
    assert transport.calls == []


def test_naive_wall_clock_fails_without_returning_secret() -> None:
    transport = _Transport(_response())
    client = azs.AzureKeyVaultSecretClient(
        _TokenProvider(),
        _REFERENCE,
        _transport=transport,
        _monotonic=lambda: 100.0,
        _now=lambda: datetime(2026, 7, 29, 6, 0),
    )

    with pytest.raises(azs.AzureKeyVaultSecretError) as raised:
        client.get()

    assert raised.value.stage == "clock"


class _FailingTransport:
    calls = 0

    def get(self, **kwargs: object) -> azs._SecretHTTPResponse:
        del kwargs
        self.calls += 1
        raise OSError("contains private infrastructure detail")


def test_transport_failure_is_sanitized_and_never_retried() -> None:
    provider = _TokenProvider()
    transport = _FailingTransport()
    client = azs.AzureKeyVaultSecretClient(
        provider,
        _REFERENCE,
        _transport=transport,
        _monotonic=lambda: 100.0,
        _now=lambda: _NOW,
    )

    with pytest.raises(azs.AzureKeyVaultSecretError) as raised:
        client.get()

    assert raised.value.stage == "transport"
    assert "private infrastructure" not in str(raised.value)
    assert transport.calls == 1


def test_concurrent_reads_each_revalidate_the_exact_pinned_version() -> None:
    client, provider, transport = _client(_response())

    with ThreadPoolExecutor(max_workers=8) as executor:
        values = tuple(
            executor.map(
                lambda _: client.get().consume(lambda value: bytes(value)),
                range(16),
            )
        )

    assert values == (_SECRET,) * 16
    assert len(provider.calls) == 16
    assert len(transport.calls) == 16
    assert len({call[0] for call in transport.calls}) == 1


def test_secret_value_constructor_rejects_empty_and_oversized_values() -> None:
    for value in (b"", b"x" * (128 * 1024 + 1)):
        with pytest.raises(ValueError):
            azs.AzureKeyVaultSecretValue(
                value,
                reference=_REFERENCE,
                content_type=None,
                retrieved_at=_NOW,
            )
