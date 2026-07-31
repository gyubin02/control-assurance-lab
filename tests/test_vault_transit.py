from __future__ import annotations

import base64
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from assurance_lab.evidence.admission import DetachedSignature, ReceiptSigner
from assurance_lab.evidence.vault_transit import (
    MAX_SIGNING_MESSAGE_BYTES,
    VaultToken,
    VaultTokenProvider,
    VaultTransitEd25519ReceiptSigner,
    VaultTransitError,
    _HTTPResponse,
    _HTTPTransport,
    vault_endpoint_origin_digest,
)

_TOKEN = b"hvs.unit-test-secret-token"
_HEADERS = (("content-type", "application/json"),)


class _TokenProvider:
    def __init__(self, value: bytes = _TOKEN) -> None:
        self.value = value
        self.calls = 0
        self._lock = threading.Lock()

    def get_token(self, *, deadline: float) -> VaultToken:
        with self._lock:
            self.calls += 1
        return VaultToken(
            self.value,
            valid_until_monotonic=max(deadline, time.monotonic() + 1),
        )


class _FailingProvider:
    def __init__(self, secret: str) -> None:
        self.secret = secret

    def get_token(self, *, deadline: float) -> VaultToken:
        del deadline
        raise RuntimeError(self.secret)


def _pem(private_key: Ed25519PrivateKey) -> str:
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _raw_public_key_base64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def _key_document(
    private_key: Ed25519PrivateKey,
    *,
    latest_version: int = 1,
    **overrides: object,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "derived": False,
        "keys": {
            str(latest_version): {
                "creation_time": "2026-07-29T00:00:00Z",
                "name": "Ed25519",
                "public_key": _raw_public_key_base64(private_key),
            }
        },
        "latest_version": latest_version,
        "min_encryption_version": 0,
        "name": "receipt",
        "supports_signing": True,
        "type": "ed25519",
    }
    data.update(overrides)
    return {"data": data}


def _response(document: object, *, status: int = 200) -> _HTTPResponse:
    return _HTTPResponse(
        status=status,
        headers=_HEADERS,
        body=json.dumps(document, separators=(",", ":")).encode(),
    )


class _SigningTransport:
    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        *,
        key_document: object | None = None,
        response_version: int = 1,
        malformed_signature: str | None = None,
    ) -> None:
        self.private_key = private_key
        self.key_document = (
            key_document if key_document is not None else _key_document(private_key)
        )
        self.response_version = response_version
        self.malformed_signature = malformed_signature
        self.calls: list[dict[str, object]] = []
        self._lock = threading.Lock()

    def request(
        self,
        *,
        method: str,
        target: str,
        body: bytes,
        headers: tuple[tuple[str, str], ...],
        token: VaultToken,
        deadline: float,
    ) -> _HTTPResponse:
        del token, deadline
        with self._lock:
            self.calls.append(
                {
                    "body": body,
                    "headers": headers,
                    "method": method,
                    "target": target,
                }
            )
        if method == "GET":
            return _response(self.key_document)
        request = json.loads(body)
        message = base64.b64decode(request["input"], validate=True)
        signature = self.private_key.sign(message)
        encoded = base64.b64encode(signature).decode()
        value = (
            self.malformed_signature
            if self.malformed_signature is not None
            else f"vault:v{self.response_version}:{encoded}"
        )
        return _response({"data": {"signature": value}})


def _signer(
    private_key: Ed25519PrivateKey,
    *,
    provider: VaultTokenProvider | None = None,
    transport: _HTTPTransport | None = None,
    endpoint: str = "https://vault.example:8200",
    allow_insecure_loopback: bool = False,
    sign_timeout_seconds: int = 30,
) -> VaultTransitEd25519ReceiptSigner:
    return VaultTransitEd25519ReceiptSigner(
        provider if provider is not None else _TokenProvider(),
        endpoint=endpoint,
        mount_path="control/transit",
        key_name="receipt",
        key_id="vault:control-assurance:receipt:v1",
        allow_insecure_loopback=allow_insecure_loopback,
        _transport=(
            transport
            if transport is not None
            else _SigningTransport(private_key)
        ),
        sign_timeout_seconds=sign_timeout_seconds,
    )


def test_signer_pins_version_and_public_key_and_verifies_locally() -> None:
    private_key = Ed25519PrivateKey.generate()
    provider = _TokenProvider()
    transport = _SigningTransport(private_key)
    signer = _signer(private_key, provider=provider, transport=transport)

    protocol_signer: ReceiptSigner = signer
    signature = protocol_signer.sign(b"canonical receipt bytes")

    assert signature.key_id == "vault:control-assurance:receipt:v1"
    assert signature.algorithm == "ed25519"
    assert signer.key_version == 1
    assert signer.public_key_bytes == private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    assert signer.endpoint_origin_digest == vault_endpoint_origin_digest(
        "https://vault.example:8200"
    )
    assert signer.verify(b"canonical receipt bytes", signature)
    assert not signer.verify(b"different", signature)
    assert provider.calls == 2
    assert transport.calls[0] == {
        "body": b"",
        "headers": (
            ("accept", "application/json"),
            ("content-type", "application/json"),
            ("x-vault-request", "true"),
        ),
        "method": "GET",
        "target": "/v1/control/transit/keys/receipt",
    }
    signing_request = json.loads(transport.calls[1]["body"])  # type: ignore[arg-type]
    assert signing_request == {
        "input": base64.b64encode(b"canonical receipt bytes").decode(),
        "key_version": 1,
    }
    assert transport.calls[1]["target"] == "/v1/control/transit/sign/receipt"
    assert "secret" not in repr(signer)
    assert signer.public_key_fingerprint in repr(signer)


def test_enterprise_namespace_is_an_exact_non_secret_header() -> None:
    private_key = Ed25519PrivateKey.generate()
    transport = _SigningTransport(private_key)
    VaultTransitEd25519ReceiptSigner(
        _TokenProvider(),
        endpoint="https://vault.example:8200",
        namespace="admin/security",
        mount_path="transit",
        key_name="receipt",
        key_id="vault:receipt:v1",
        _transport=transport,
    )
    assert transport.calls[0]["headers"] == (
        ("accept", "application/json"),
        ("content-type", "application/json"),
        ("x-vault-namespace", "admin/security"),
        ("x-vault-request", "true"),
    )


def test_rotation_after_initialization_does_not_change_requested_version() -> None:
    private_key = Ed25519PrivateKey.generate()
    transport = _SigningTransport(private_key)
    signer = _signer(private_key, transport=transport)

    signature = signer.sign(b"still version one")

    request = json.loads(transport.calls[-1]["body"])  # type: ignore[arg-type]
    assert request["key_version"] == 1
    assert signer.verify(b"still version one", signature)


def test_returned_signature_version_must_match_pinned_version() -> None:
    private_key = Ed25519PrivateKey.generate()
    signer = _signer(
        private_key,
        transport=_SigningTransport(private_key, response_version=2),
    )

    with pytest.raises(VaultTransitError, match="pinned version") as raised:
        signer.sign(b"receipt")

    assert raised.value.stage == "sign"


@pytest.mark.parametrize(
    "malformed",
    [
        "vault:v1:not-base64",
        "vault:v01:" + ("A" * 86) + "==",
        "vault:v1:" + base64.b64encode(b"x" * 63).decode(),
        "vault:v1:" + base64.b64encode(b"x" * 65).decode(),
        "other:v1:" + base64.b64encode(b"x" * 64).decode(),
    ],
)
def test_signature_wire_format_is_exact(malformed: str) -> None:
    private_key = Ed25519PrivateKey.generate()
    signer = _signer(
        private_key,
        transport=_SigningTransport(
            private_key,
            malformed_signature=malformed,
        ),
    )

    with pytest.raises(VaultTransitError, match="malformed"):
        signer.sign(b"receipt")


def test_signature_must_verify_before_it_is_returned() -> None:
    pinned = Ed25519PrivateKey.generate()
    signing = Ed25519PrivateKey.generate()
    transport = _SigningTransport(
        signing,
        key_document=_key_document(pinned),
    )
    signer = _signer(pinned, transport=transport)

    with pytest.raises(VaultTransitError, match="local Ed25519 verification"):
        signer.sign(b"receipt")


@pytest.mark.parametrize(
    ("override", "detail"),
    [
        ({"type": "ecdsa-p256"}, "incompatible"),
        ({"derived": True}, "incompatible"),
        ({"supports_signing": False}, "incompatible"),
        ({"name": "other"}, "incompatible"),
        ({"latest_version": True}, "incompatible"),
        ({"latest_version": 0}, "incompatible"),
        ({"min_encryption_version": 2}, "incompatible"),
        ({"keys": {}}, "incompatible"),
        ({"keys": {"01": {}}}, "version map"),
        ({"keys": {"2": {}}}, "version map"),
    ],
)
def test_key_metadata_is_fail_closed(
    override: dict[str, object],
    detail: str,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    document = _key_document(private_key)
    document["data"].update(override)

    with pytest.raises(VaultTransitError, match=detail):
        _signer(
            private_key,
            transport=_SigningTransport(private_key, key_document=document),
        )


def test_latest_key_entry_and_canonical_public_key_encoding_are_required() -> None:
    private_key = Ed25519PrivateKey.generate()
    missing = _key_document(private_key, latest_version=2)
    missing["data"]["keys"] = {"1": missing["data"]["keys"]["2"]}
    with pytest.raises(VaultTransitError, match="omits the latest"):
        _signer(
            private_key,
            transport=_SigningTransport(private_key, key_document=missing),
        )

    noncanonical = _key_document(private_key)
    noncanonical["data"]["keys"]["1"]["public_key"] = (
        _raw_public_key_base64(private_key).rstrip("=")
    )
    with pytest.raises(VaultTransitError, match="canonical Ed25519 raw/SPKI"):
        _signer(
            private_key,
            transport=_SigningTransport(private_key, key_document=noncanonical),
        )


@pytest.mark.parametrize("encoding", ["pem", "der"])
def test_exact_spki_encodings_are_accepted(encoding: str) -> None:
    private_key = Ed25519PrivateKey.generate()
    document = _key_document(private_key)
    if encoding == "pem":
        public_key = _pem(private_key)
    else:
        der = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        public_key = base64.b64encode(der).decode("ascii")
    document["data"]["keys"]["1"]["public_key"] = public_key
    signer = _signer(
        private_key,
        transport=_SigningTransport(private_key, key_document=document),
    )
    assert signer.public_key_bytes == private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def test_noncanonical_spki_pem_is_rejected() -> None:
    private_key = Ed25519PrivateKey.generate()
    document = _key_document(private_key)
    document["data"]["keys"]["1"]["public_key"] = _pem(private_key).replace(
        "\n", "\r\n"
    )
    with pytest.raises(VaultTransitError, match="canonical Ed25519 raw/SPKI"):
        _signer(
            private_key,
            transport=_SigningTransport(private_key, key_document=document),
        )


@pytest.mark.parametrize(
    "response",
    [
        _HTTPResponse(200, _HEADERS, b'{"data":{},"data":{}}'),
        _HTTPResponse(200, (("content-type", "text/plain"),), b"{}"),
        _HTTPResponse(
            200,
            (
                ("content-encoding", "gzip"),
                ("content-type", "application/json"),
            ),
            b"{}",
        ),
        _HTTPResponse(200, (), b"{}"),
        _HTTPResponse(503, _HEADERS, b'{"errors":["sealed"]}'),
    ],
)
def test_malformed_or_unsuccessful_key_response_is_rejected(
    response: _HTTPResponse,
) -> None:
    private_key = Ed25519PrivateKey.generate()

    class _OneResponse:
        def request(self, **kwargs: object) -> _HTTPResponse:
            del kwargs
            return response

    with pytest.raises(VaultTransitError):
        _signer(private_key, transport=_OneResponse())


def test_token_and_provider_representations_are_redacted() -> None:
    token = VaultToken(
        _TOKEN,
        valid_until_monotonic=time.monotonic() + 10,
    )
    assert str(token) == "<redacted>"
    assert repr(token) == "VaultToken(<redacted>)"
    assert _TOKEN.decode() not in str(token)
    assert _TOKEN.decode() not in repr(token)

    private_key = Ed25519PrivateKey.generate()
    secret = "hvs.provider-exception-secret"
    with pytest.raises(VaultTransitError) as raised:
        _signer(private_key, provider=_FailingProvider(secret))
    assert secret not in str(raised.value)
    assert secret not in repr(raised.value)
    assert raised.value.__context__ is None
    assert raised.value.__cause__ is None


def test_transport_exceptions_do_not_escape_with_credentials() -> None:
    private_key = Ed25519PrivateKey.generate()
    secret = "hvs.transport-exception-secret"

    class _ExplodingTransport:
        def request(self, **kwargs: object) -> _HTTPResponse:
            del kwargs
            raise RuntimeError(secret)

    with pytest.raises(VaultTransitError) as raised:
        _signer(
            private_key,
            provider=_TokenProvider(secret.encode()),
            transport=_ExplodingTransport(),
        )
    assert secret not in str(raised.value)
    assert secret not in repr(raised.value)
    assert raised.value.__context__ is None
    assert raised.value.__cause__ is None


def test_expired_token_is_rejected_before_transport() -> None:
    private_key = Ed25519PrivateKey.generate()

    class _ExpiredProvider:
        def get_token(self, *, deadline: float) -> VaultToken:
            del deadline
            return VaultToken(
                _TOKEN,
                valid_until_monotonic=time.monotonic() - 1,
            )

    with pytest.raises(VaultTransitError, match="currently valid"):
        _signer(private_key, provider=_ExpiredProvider())


def test_whole_call_deadline_is_checked_after_transport_returns() -> None:
    private_key = Ed25519PrivateKey.generate()

    class _SlowSigningTransport(_SigningTransport):
        def request(self, **kwargs: object) -> _HTTPResponse:
            if kwargs["method"] == "POST":
                time.sleep(1.05)
            return super().request(**kwargs)  # type: ignore[arg-type]

    signer = _signer(
        private_key,
        transport=_SlowSigningTransport(private_key),
        sign_timeout_seconds=1,
    )
    with pytest.raises(VaultTransitError, match="deadline"):
        signer.sign(b"receipt")


def test_concurrent_signing_has_no_shared_request_or_token_state() -> None:
    private_key = Ed25519PrivateKey.generate()
    provider = _TokenProvider()
    transport = _SigningTransport(private_key)
    signer = _signer(private_key, provider=provider, transport=transport)
    messages = [f"receipt-{index}".encode() for index in range(32)]

    with ThreadPoolExecutor(max_workers=8) as executor:
        signatures = tuple(executor.map(signer.sign, messages))

    assert all(
        signer.verify(message, signature)
        for message, signature in zip(messages, signatures, strict=True)
    )
    assert provider.calls == 33


def test_wrong_key_id_and_non_bytes_do_not_verify() -> None:
    private_key = Ed25519PrivateKey.generate()
    signer = _signer(private_key)
    signature = signer.sign(b"receipt")
    other = DetachedSignature(
        key_id="vault:other:v1",
        algorithm="ed25519",
        signature=signature.signature,
    )
    assert not signer.verify(b"receipt", other)
    assert not signer.verify("receipt", signature)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        signer.sign(bytearray(b"receipt"))  # type: ignore[arg-type]
    with pytest.raises(VaultTransitError, match="exceeds"):
        signer.sign(b"x" * (MAX_SIGNING_MESSAGE_BYTES + 1))


@pytest.mark.parametrize(
    ("endpoint", "allow_insecure"),
    [
        ("http://vault.example:8200", True),
        ("http://localhost:8200", True),
        ("http://127.0.0.1:8200", False),
        ("https://VAULT.example:8200", False),
        ("https://vault.example:443", False),
        ("https://vault.example:8200/", False),
        ("https://user@vault.example:8200", False),
        ("https://vault.example:8200/path", False),
        ("https://vault.example:8200?x=1", False),
    ],
)
def test_endpoint_origin_is_exact_and_plain_http_is_lab_only(
    endpoint: str,
    allow_insecure: bool,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError):
        _signer(
            private_key,
            endpoint=endpoint,
            allow_insecure_loopback=allow_insecure,
        )


@pytest.mark.parametrize(
    ("mount_path", "key_name"),
    [
        ("/transit", "receipt"),
        ("transit/", "receipt"),
        ("transit//nested", "receipt"),
        ("transit/../secret", "receipt"),
        ("transit", "../receipt"),
        ("transit", "nested/receipt"),
        ("transit", "receipt?version=2"),
        ("transit.", "receipt"),
        ("transit", "receipt."),
    ],
)
def test_mount_and_key_paths_are_canonical(
    mount_path: str,
    key_name: str,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError):
        VaultTransitEd25519ReceiptSigner(
            _TokenProvider(),
            endpoint="https://vault.example:8200",
            mount_path=mount_path,
            key_name=key_name,
            key_id="vault:receipt:v1",
            _transport=_SigningTransport(private_key),
        )


@pytest.mark.parametrize("namespace", ["/admin", "admin/", "admin//security", "admin."])
def test_namespace_path_is_canonical(namespace: str) -> None:
    private_key = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError):
        VaultTransitEd25519ReceiptSigner(
            _TokenProvider(),
            endpoint="https://vault.example:8200",
            namespace=namespace,
            mount_path="transit",
            key_name="receipt",
            key_id="vault:receipt:v1",
            _transport=_SigningTransport(private_key),
        )


class _WireServer:
    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        *,
        mode: str,
        token: bytes = _TOKEN,
    ) -> None:
        self.private_key = private_key
        self.mode = mode
        self.token = token
        self.paths: list[str] = []
        self.authorization_values: list[str | None] = []
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: object) -> None:
                del format, args

            def do_GET(self) -> None:
                outer.paths.append(self.path)
                outer.authorization_values.append(self.headers.get("X-Vault-Token"))
                if outer.mode == "redirect":
                    body = b"redirect"
                    self.send_response(302)
                    self.send_header("Location", "/credential-sink")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self._json(_key_document(outer.private_key))

            def do_POST(self) -> None:
                outer.paths.append(self.path)
                outer.authorization_values.append(self.headers.get("X-Vault-Token"))
                content_length = int(self.headers.get("Content-Length", "0"))
                request = json.loads(self.rfile.read(content_length))
                message = base64.b64decode(request["input"], validate=True)
                if outer.mode == "reflect":
                    self._json({"data": {"error": outer.token.decode()}})
                    return
                signature = outer.private_key.sign(message)
                self._json(
                    {
                        "data": {
                            "signature": (
                                "vault:v1:"
                                + base64.b64encode(signature).decode()
                            )
                        }
                    }
                )

            def _json(self, document: object) -> None:
                body = json.dumps(document, separators=(",", ":")).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self) -> _WireServer:
        self.thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        del args
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def test_real_http_sends_token_on_wire_but_rejects_reflection() -> None:
    private_key = Ed25519PrivateKey.generate()
    with _WireServer(private_key, mode="reflect") as wire:
        signer = VaultTransitEd25519ReceiptSigner(
            _TokenProvider(),
            endpoint=wire.endpoint,
            mount_path="transit",
            key_name="receipt",
            key_id="vault:receipt:v1",
            allow_insecure_loopback=True,
            request_timeout_seconds=2,
        )
        with pytest.raises(VaultTransitError, match="configured origin") as raised:
            signer.sign(b"receipt")

    assert _TOKEN.decode() not in str(raised.value)
    assert wire.authorization_values == [_TOKEN.decode(), _TOKEN.decode()]
    assert wire.paths == [
        "/v1/transit/keys/receipt",
        "/v1/transit/sign/receipt",
    ]


def test_real_http_redirect_is_not_followed_and_token_is_not_forwarded() -> None:
    private_key = Ed25519PrivateKey.generate()
    with (
        _WireServer(private_key, mode="redirect") as wire,
        pytest.raises(VaultTransitError, match="HTTP 302"),
    ):
        VaultTransitEd25519ReceiptSigner(
            _TokenProvider(b"hvs.redirect-never-forward"),
            endpoint=wire.endpoint,
            mount_path="transit",
            key_name="receipt",
            key_id="vault:receipt:v1",
            allow_insecure_loopback=True,
            request_timeout_seconds=2,
        )

    assert wire.paths == ["/v1/transit/keys/receipt"]
    assert wire.authorization_values == ["hvs.redirect-never-forward"]


def test_custom_ca_file_must_not_be_a_symlink(tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    target = tmp_path / "ca.pem"
    target.write_text("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n")
    link = tmp_path / "ca-link.pem"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="safely"):
        VaultTransitEd25519ReceiptSigner(
            _TokenProvider(),
            endpoint="https://vault.example:8200",
            mount_path="transit",
            key_name="receipt",
            key_id="vault:receipt:v1",
            ca_file=link,
            _transport=_SigningTransport(private_key),
        )


def test_opt_in_live_vault_transit_signing() -> None:
    """Operator-owned smoke test; this repository makes no live-tested claim."""

    if os.environ.get("CONTROL_ASSURANCE_VAULT_LIVE") != "1":
        pytest.skip("set CONTROL_ASSURANCE_VAULT_LIVE=1 for an operator Vault")
    endpoint = os.environ["CONTROL_ASSURANCE_VAULT_ENDPOINT"]
    mount = os.environ.get("CONTROL_ASSURANCE_VAULT_MOUNT", "transit")
    key_name = os.environ["CONTROL_ASSURANCE_VAULT_KEY"]
    token_file = Path(os.environ["CONTROL_ASSURANCE_VAULT_TOKEN_FILE"])
    token_value = token_file.read_bytes().strip()

    class _LiveTokenProvider:
        def get_token(self, *, deadline: float) -> VaultToken:
            return VaultToken(token_value, valid_until_monotonic=deadline)

    signer = VaultTransitEd25519ReceiptSigner(
        _LiveTokenProvider(),
        endpoint=endpoint,
        namespace=os.environ.get("CONTROL_ASSURANCE_VAULT_NAMESPACE"),
        mount_path=mount,
        key_name=key_name,
        key_id=os.environ["CONTROL_ASSURANCE_VAULT_KEY_ID"],
        ca_file=(
            Path(os.environ["CONTROL_ASSURANCE_VAULT_CA_FILE"])
            if "CONTROL_ASSURANCE_VAULT_CA_FILE" in os.environ
            else None
        ),
    )
    message = b"control-assurance-vault-transit-live-smoke-v1"
    assert signer.verify(message, signer.sign(message))
