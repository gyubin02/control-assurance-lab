from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TypedDict

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

import assurance_lab.evidence.reference_adapters as adapters
from assurance_lab.evidence.admission import (
    CustodyStore,
    DetachedSignature,
    ReceiptSigner,
    TrustPolicyResolver,
)
from assurance_lab.evidence.attestation import (
    TRUST_POLICY_MEDIA_TYPE,
    TRUST_POLICY_SCHEMA_VERSION,
    KeyStatus,
    TrustedKey,
    TrustPolicy,
)
from assurance_lab.evidence.reference_adapters import (
    AtomicFilesystemCustodyStore,
    CustodyStoreError,
    DigestDirectoryTrustPolicyResolver,
    Ed25519PEMReceiptSigner,
    PolicyResolutionError,
    ReferenceAdapterError,
    policy_relative_path,
)


class _CustodyInputs(TypedDict):
    receipt_bytes: bytes
    envelope_bytes: bytes
    cab_snapshot_bytes: bytes
    trust_policy_bytes: bytes
    expected_receipt_digest: str
    expected_envelope_digest: str
    expected_cab_snapshot_digest: str
    expected_trust_policy_digest: str


def _digest(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _private_root(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _private_pem(
    key: Ed25519PrivateKey,
    *,
    password: bytes | None = None,
) -> bytes:
    encryption: serialization.KeySerializationEncryption
    if password is None:
        encryption = serialization.NoEncryption()
    else:
        encryption = serialization.BestAvailableEncryption(password)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption,
    )


def _signer(
    seed: int = 7,
    *,
    key_id: str = "key:receipt-reference",
    password: bytes | None = None,
) -> tuple[Ed25519PEMReceiptSigner, bytes]:
    key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    pem = _private_pem(key, password=password)
    return (
        Ed25519PEMReceiptSigner(
            pem,
            key_id=key_id,
            password=password,
        ),
        pem,
    )


def _policy_bytes(
    policy_id: str = "policy:collector/prod",
    *,
    seed: int = 21,
) -> bytes:
    public_key = (
        Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
        .public_key()
        .public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )
    policy = TrustPolicy(
        media_type=TRUST_POLICY_MEDIA_TYPE,
        schema_version=TRUST_POLICY_SCHEMA_VERSION,
        policy_id=policy_id,
        threshold=1,
        trusted_keys=(
            TrustedKey(
                key_id="key:collector-a",
                identity="collector:seoul-a",
                algorithm="ed25519",
                public_key=base64.b64encode(public_key).decode("ascii"),
                allowed_payload_types=(
                    "application/vnd.control-assurance.collection-statement.v2+json",
                ),
                valid_from="2026-01-01T00:00:00.000000Z",
                valid_until=None,
                status=KeyStatus.ACTIVE,
                revocation_effective_at=None,
            ),
        ),
    )
    return policy.canonical_bytes()


def _provision_policy(
    root: Path,
    *,
    policy_id: str,
    revision: int,
    policy_bytes: bytes,
    locator_digest: str | None = None,
) -> Path:
    digest = locator_digest or _digest(policy_bytes)
    path = root / policy_relative_path(policy_id, revision, digest)
    path.parent.mkdir(parents=True, mode=0o700)
    path.parent.chmod(0o700)
    path.parent.parent.chmod(0o700)
    path.write_bytes(policy_bytes)
    path.chmod(0o600)
    return path


def _custody_inputs(
    *,
    receipt: bytes = b'{"receipt":"one"}',
    envelope: bytes = b'{"envelope":"one"}',
    snapshot: bytes = b"CAB-SNAPSHOT-ONE",
    policy: bytes = b'{"policy":"one"}',
) -> _CustodyInputs:
    return {
        "receipt_bytes": receipt,
        "envelope_bytes": envelope,
        "cab_snapshot_bytes": snapshot,
        "trust_policy_bytes": policy,
        "expected_receipt_digest": _digest(receipt),
        "expected_envelope_digest": _digest(envelope),
        "expected_cab_snapshot_digest": _digest(snapshot),
        "expected_trust_policy_digest": _digest(policy),
    }


def _persist(
    store: AtomicFilesystemCustodyStore,
    object_id: str,
    inputs: _CustodyInputs,
) -> str:
    return store.persist(
        custody_object_id=object_id,
        custody_reference=store.reference_for(object_id),
        receipt_bytes=inputs["receipt_bytes"],
        envelope_bytes=inputs["envelope_bytes"],
        cab_snapshot_bytes=inputs["cab_snapshot_bytes"],
        trust_policy_bytes=inputs["trust_policy_bytes"],
        expected_envelope_digest=inputs["expected_envelope_digest"],
        expected_cab_snapshot_digest=inputs["expected_cab_snapshot_digest"],
        expected_trust_policy_digest=inputs["expected_trust_policy_digest"],
        expected_receipt_digest=inputs["expected_receipt_digest"],
    )


def _verify(
    store: AtomicFilesystemCustodyStore,
    object_id: str,
    inputs: _CustodyInputs,
) -> bool:
    return store.verify(
        custody_object_id=object_id,
        custody_reference=store.reference_for(object_id),
        receipt_digest=inputs["expected_receipt_digest"],
        envelope_digest=inputs["expected_envelope_digest"],
        cab_snapshot_digest=inputs["expected_cab_snapshot_digest"],
        trust_policy_digest=inputs["expected_trust_policy_digest"],
    )


def test_pem_signer_loads_encrypted_pkcs8_and_emits_canonical_signature() -> None:
    password = b"caller-owned-password"
    signer, _pem = _signer(password=password)
    message = b"canonical admission receipt bytes"
    signature = signer.sign(message)
    protocol_signer: ReceiptSigner = signer

    assert len(signer.public_key_bytes) == 32
    assert signer.public_key_bytes == protocol_signer.public_key_bytes
    assert signature.algorithm == "ed25519"
    assert signature.key_id == "key:receipt-reference"
    assert len(base64.b64decode(signature.signature, validate=True)) == 64
    assert base64.b64encode(base64.b64decode(signature.signature)).decode() == (
        signature.signature
    )
    assert signer.verify(message, signature)
    assert not signer.verify(message + b"!", signature)
    assert not signer.verify(
        message,
        DetachedSignature(
            key_id="key:other",
            algorithm="ed25519",
            signature=signature.signature,
        ),
    )


def test_pem_signer_never_renders_private_pem_or_password() -> None:
    password = b"DO-NOT-RENDER-THIS-PASSWORD"
    signer, pem = _signer(password=password)
    rendered = repr(signer)
    pem_body_fragment = pem.splitlines()[1][:24].decode("ascii")

    assert "PRIVATE KEY" not in rendered
    assert password.decode() not in rendered
    assert pem_body_fragment not in rendered
    assert signer.key_fingerprint in rendered

    with pytest.raises(ValueError) as captured:
        Ed25519PEMReceiptSigner(
            pem,
            key_id="key:receipt-reference",
            password=b"WRONG-SECRET-PASSWORD",
        )
    failure = repr(captured.value)
    assert password.decode() not in failure
    assert "WRONG-SECRET-PASSWORD" not in failure
    assert pem_body_fragment not in failure


def test_pem_signer_rejects_non_pkcs8_and_non_ed25519_without_key_details() -> None:
    ed25519 = Ed25519PrivateKey.generate()
    openssh = ed25519.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    with pytest.raises(ValueError, match="PKCS#8 PEM"):
        Ed25519PEMReceiptSigner(openssh, key_id="key:test")

    rsa_pem = generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with pytest.raises(ValueError, match="not Ed25519") as captured:
        Ed25519PEMReceiptSigner(rsa_pem, key_id="key:test")
    assert rsa_pem.splitlines()[1][:24].decode("ascii") not in repr(captured.value)


def test_pem_signer_rejects_ambiguous_or_appended_key_material() -> None:
    first = _private_pem(Ed25519PrivateKey.generate())
    second = _private_pem(Ed25519PrivateKey.generate())
    mixed_footer = first.replace(
        b"-----END PRIVATE KEY-----",
        b"-----END ENCRYPTED PRIVATE KEY-----",
    )
    invalid_documents = (
        first + second,
        first + b"TRAILING-JUNK",
        b"LEADING-JUNK" + first,
        mixed_footer,
    )

    for document in invalid_documents:
        with pytest.raises(ValueError, match="PKCS#8 PEM"):
            Ed25519PEMReceiptSigner(document, key_id="key:test")

    signer = Ed25519PEMReceiptSigner(
        first + b" \t\r\n",
        key_id="key:test",
    )
    assert signer.verify(b"message", signer.sign(b"message"))
    with pytest.raises(ValueError, match="exactly one"):
        Ed25519PEMReceiptSigner(
            first + b"\n" * 65,
            key_id="key:test",
        )


def test_policy_mapping_is_portable_and_resolves_exact_canonical_bytes(
    tmp_path: Path,
) -> None:
    root = _private_root(tmp_path / "policies")
    policy_id = "policy:finance/prod+서울"
    # The public policy profile is visible ASCII; mapping rejects the Unicode
    # identifier before it can become a filesystem ambiguity.
    with pytest.raises(ValueError, match="visible ASCII"):
        policy_relative_path(policy_id, 1, f"sha256:{'0' * 64}")

    policy_id = "policy:finance/prod+kr"
    policy_bytes = _policy_bytes(policy_id)
    digest = _digest(policy_bytes)
    path = _provision_policy(
        root,
        policy_id=policy_id,
        revision=17,
        policy_bytes=policy_bytes,
    )
    relative = path.relative_to(root)

    assert len(relative.parts) == 3
    assert relative.parts[0] == hashlib.sha256(policy_id.encode("ascii")).hexdigest()
    assert relative.parts[1] == "00000000000000000017"
    assert relative.parts[2] == f"{digest.removeprefix('sha256:')}.json"
    with DigestDirectoryTrustPolicyResolver(root) as resolver:
        protocol_resolver: TrustPolicyResolver = resolver
        assert resolver.policy_path(policy_id, 17, digest) == path
        assert protocol_resolver.resolve(policy_id, 17, digest) == policy_bytes


def test_policy_resolver_rejects_wrong_digest_even_at_requested_location(
    tmp_path: Path,
) -> None:
    root = _private_root(tmp_path / "policies")
    policy_id = "policy:collector/prod"
    policy_bytes = _policy_bytes(policy_id)
    wrong_digest = f"sha256:{'a' * 64}"
    _provision_policy(
        root,
        policy_id=policy_id,
        revision=1,
        policy_bytes=policy_bytes,
        locator_digest=wrong_digest,
    )

    with (
        DigestDirectoryTrustPolicyResolver(root) as resolver,
        pytest.raises(PolicyResolutionError, match="requested digest"),
    ):
        resolver.resolve(policy_id, 1, wrong_digest)


def test_policy_resolver_rejects_noncanonical_and_misbound_policy(
    tmp_path: Path,
) -> None:
    root = _private_root(tmp_path / "policies")
    policy_id = "policy:collector/prod"
    canonical = _policy_bytes(policy_id)
    noncanonical = json.dumps(
        json.loads(canonical),
        indent=2,
        sort_keys=False,
    ).encode()
    noncanonical_digest = _digest(noncanonical)
    _provision_policy(
        root,
        policy_id=policy_id,
        revision=1,
        policy_bytes=noncanonical,
    )
    other_policy = _policy_bytes("policy:other")
    other_digest = _digest(other_policy)
    _provision_policy(
        root,
        policy_id=policy_id,
        revision=2,
        policy_bytes=other_policy,
    )

    with DigestDirectoryTrustPolicyResolver(root) as resolver:
        with pytest.raises(PolicyResolutionError, match="canonical policy"):
            resolver.resolve(policy_id, 1, noncanonical_digest)
        with pytest.raises(PolicyResolutionError, match="id does not match"):
            resolver.resolve(policy_id, 2, other_digest)


def test_policy_resolver_rejects_symlink_hardlink_and_root_path_swap(
    tmp_path: Path,
) -> None:
    root = _private_root(tmp_path / "policies")
    policy_id = "policy:collector/prod"
    policy_bytes = _policy_bytes(policy_id)
    digest = _digest(policy_bytes)
    path = _provision_policy(
        root,
        policy_id=policy_id,
        revision=1,
        policy_bytes=policy_bytes,
    )
    resolver = DigestDirectoryTrustPolicyResolver(root)

    outside = tmp_path / "outside-policy.json"
    outside.write_bytes(policy_bytes)
    outside.chmod(0o600)
    path.unlink()
    path.symlink_to(outside)
    with pytest.raises(PolicyResolutionError, match="unavailable or unsafe"):
        resolver.resolve(policy_id, 1, digest)

    path.unlink()
    path.write_bytes(policy_bytes)
    path.chmod(0o600)
    hardlink = tmp_path / "policy-hardlink.json"
    os.link(path, hardlink)
    with pytest.raises(PolicyResolutionError, match="unavailable or unsafe"):
        resolver.resolve(policy_id, 1, digest)
    hardlink.unlink()

    moved = tmp_path / "moved-policies"
    root.rename(moved)
    root.symlink_to(moved, target_is_directory=True)
    with pytest.raises(ReferenceAdapterError, match="symbolic-link ancestry"):
        resolver.resolve(policy_id, 1, digest)
    resolver.close()


def test_policy_read_stays_on_pinned_fd_and_rejects_mid_read_root_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _private_root(tmp_path / "policies")
    policy_id = "policy:collector/prod"
    policy_bytes = _policy_bytes(policy_id)
    digest = _digest(policy_bytes)
    _provision_policy(
        root,
        policy_id=policy_id,
        revision=1,
        policy_bytes=policy_bytes,
    )
    resolver = DigestDirectoryTrustPolicyResolver(root)
    moved = tmp_path / "original-policies"
    real_reader = adapters._read_private_file
    swapped = False

    def swap_then_read(
        parent_fd: int,
        name: str,
        *,
        maximum: int,
        label: str,
    ) -> bytes:
        nonlocal swapped
        if not swapped:
            root.rename(moved)
            replacement = _private_root(root)
            _provision_policy(
                replacement,
                policy_id=policy_id,
                revision=1,
                policy_bytes=_policy_bytes(policy_id, seed=88),
                locator_digest=digest,
            )
            swapped = True
        return real_reader(parent_fd, name, maximum=maximum, label=label)

    monkeypatch.setattr(adapters, "_read_private_file", swap_then_read)
    with pytest.raises(ReferenceAdapterError, match="different directory"):
        resolver.resolve(policy_id, 1, digest)
    resolver.close()

    assert swapped
    assert (
        moved / policy_relative_path(policy_id, 1, digest)
    ).read_bytes() == policy_bytes


def test_custody_publishes_one_private_exact_object_and_retries_idempotently(
    tmp_path: Path,
) -> None:
    root = _private_root(tmp_path / "custody")
    object_id = "1" * 64
    inputs = _custody_inputs()
    with AtomicFilesystemCustodyStore(root) as store:
        protocol_store: CustodyStore = store
        reference = protocol_store.reference_for(object_id)
        assert _persist(store, object_id, inputs) == reference
        assert _persist(store, object_id, inputs) == reference
        assert _verify(store, object_id, inputs)

    object_path = root / object_id
    assert set(path.name for path in object_path.iterdir()) == {
        "cab.snapshot",
        "envelope.dsse.json",
        "receipt.json",
        "trust-policy.json",
    }
    assert stat.S_IMODE(object_path.stat().st_mode) & 0o077 == 0
    for path in object_path.iterdir():
        selected = path.stat()
        assert stat.S_ISREG(selected.st_mode)
        assert selected.st_nlink == 1
        assert stat.S_IMODE(selected.st_mode) & 0o077 == 0


def test_custody_exact_retry_establishes_durability_before_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _private_root(tmp_path / "custody")
    object_id = "a" * 64
    inputs = _custody_inputs()
    object_path = root / object_id
    object_path.mkdir(mode=0o700)
    payloads = {
        "cab.snapshot": inputs["cab_snapshot_bytes"],
        "envelope.dsse.json": inputs["envelope_bytes"],
        "receipt.json": inputs["receipt_bytes"],
        "trust-policy.json": inputs["trust_policy_bytes"],
    }
    for name, payload in payloads.items():
        path = object_path / name
        path.write_bytes(payload)
        path.chmod(0o600)

    real_fsync = os.fsync
    synced: list[tuple[int, int]] = []

    def record_fsync(descriptor: int) -> None:
        selected = os.fstat(descriptor)
        synced.append((selected.st_dev, selected.st_ino))
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", record_fsync)
    with AtomicFilesystemCustodyStore(root) as store:
        assert _persist(store, object_id, inputs) == store.reference_for(object_id)
        assert _verify(store, object_id, inputs)

    expected_synced = {
        (path.stat().st_dev, path.stat().st_ino)
        for path in (object_path, root, *(object_path / name for name in payloads))
    }
    assert expected_synced <= set(synced)


def test_custody_rejects_wrong_digest_without_creating_an_object(
    tmp_path: Path,
) -> None:
    root = _private_root(tmp_path / "custody")
    object_id = "2" * 64
    inputs = _custody_inputs()
    inputs["expected_receipt_digest"] = f"sha256:{'0' * 64}"

    with (
        AtomicFilesystemCustodyStore(root) as store,
        pytest.raises(CustodyStoreError, match="expected digest"),
    ):
        _persist(store, object_id, inputs)

    assert list(root.iterdir()) == []


def test_custody_never_overwrites_same_object_id_with_different_bytes(
    tmp_path: Path,
) -> None:
    root = _private_root(tmp_path / "custody")
    object_id = "3" * 64
    first = _custody_inputs()
    second = _custody_inputs(receipt=b'{"receipt":"different"}')

    with AtomicFilesystemCustodyStore(root) as store:
        _persist(store, object_id, first)
        original = (root / object_id / "receipt.json").read_bytes()
        with pytest.raises(CustodyStoreError, match="different bytes"):
            _persist(store, object_id, second)
        assert (root / object_id / "receipt.json").read_bytes() == original
        assert _verify(store, object_id, first)


def test_custody_does_not_replace_a_preexisting_empty_object_directory(
    tmp_path: Path,
) -> None:
    root = _private_root(tmp_path / "custody")
    object_id = "4" * 64
    existing = root / object_id
    existing.mkdir(mode=0o700)

    with (
        AtomicFilesystemCustodyStore(root) as store,
        pytest.raises(CustodyStoreError, match="different bytes"),
    ):
        _persist(store, object_id, _custody_inputs())

    assert existing.is_dir()
    assert list(existing.iterdir()) == []


def test_custody_cleans_partial_pending_write_after_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _private_root(tmp_path / "custody")
    object_id = "5" * 64
    real_writer = adapters._write_new_private_file
    written: list[str] = []

    def crash_after_second_file(parent_fd: int, name: str, payload: bytes) -> None:
        real_writer(parent_fd, name, payload)
        written.append(name)
        if len(written) == 2:
            raise OSError("simulated power-loss boundary")

    monkeypatch.setattr(adapters, "_write_new_private_file", crash_after_second_file)
    with (
        AtomicFilesystemCustodyStore(root) as store,
        pytest.raises(CustodyStoreError, match="published atomically"),
    ):
        _persist(store, object_id, _custody_inputs())

    assert len(written) == 2
    assert list(root.iterdir()) == []


def test_custody_observes_but_does_not_delete_interrupted_pending_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _private_root(tmp_path / "custody")
    object_id = "c" * 64
    real_writer = adapters._write_new_private_file
    writes = 0

    def interrupt_after_first_file(
        parent_fd: int,
        name: str,
        payload: bytes,
    ) -> None:
        nonlocal writes
        real_writer(parent_fd, name, payload)
        writes += 1
        raise KeyboardInterrupt

    monkeypatch.setattr(adapters, "_write_new_private_file", interrupt_after_first_file)
    with AtomicFilesystemCustodyStore(root) as store:
        with pytest.raises(KeyboardInterrupt):
            _persist(store, object_id, _custody_inputs())
        observations = store.list_pending()

    assert writes == 1
    assert len(observations) == 1
    assert observations[0].custody_object_id == object_id
    assert observations[0].constituent_files == ("cab.snapshot",)
    pending_path = root / observations[0].pending_name
    assert pending_path.is_dir()
    with AtomicFilesystemCustodyStore(root) as reopened:
        assert reopened.list_pending() == observations
    assert pending_path.is_dir()
    assert not (root / object_id).exists()


def test_custody_pending_observation_rejects_unsafe_names_and_links(
    tmp_path: Path,
) -> None:
    root = _private_root(tmp_path / "custody")
    with AtomicFilesystemCustodyStore(root) as store:
        malformed = root / ".pending-not-a-valid-generated-name"
        malformed.mkdir(mode=0o700)
        with pytest.raises(CustodyStoreError, match="invalid pending name"):
            store.list_pending()
        malformed.rmdir()

        object_id = "d" * 64
        outside = _private_root(tmp_path / "outside-pending")
        pending = root / f".pending-{object_id}-{'1' * 32}"
        pending.symlink_to(outside, target_is_directory=True)
        with pytest.raises(CustodyStoreError, match="unavailable or unsafe"):
            store.list_pending()


def test_custody_constructor_defers_filesystem_rename_capability_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _private_root(tmp_path / "custody")
    object_id = "e" * 64

    def unsupported_rename(
        _source_parent_fd: int,
        _source_name: str,
        _destination_parent_fd: int,
        _destination_name: str,
    ) -> None:
        raise OSError(errno.EINVAL, "filesystem does not support RENAME_NOREPLACE")

    # Construction verifies the libc surface and root safety; it does not
    # mutate the root to probe a filesystem-specific operation.
    store = AtomicFilesystemCustodyStore(root)
    monkeypatch.setattr(adapters, "_rename_noreplace", unsupported_rename)
    with pytest.raises(CustodyStoreError, match="published atomically"):
        _persist(store, object_id, _custody_inputs())
    assert not (root / object_id).exists()
    assert store.list_pending() == ()
    store.close()


def test_custody_constructor_defers_directory_fsync_capability_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _private_root(tmp_path / "custody")
    object_id = "f" * 64
    real_fsync = os.fsync

    def reject_directory_fsync(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError(errno.EINVAL, "directory fsync is unsupported")
        real_fsync(descriptor)

    store = AtomicFilesystemCustodyStore(root)
    monkeypatch.setattr(os, "fsync", reject_directory_fsync)
    with pytest.raises(CustodyStoreError, match="published atomically"):
        _persist(store, object_id, _custody_inputs())
    assert not (root / object_id).exists()
    observations = store.list_pending()
    assert len(observations) == 1
    assert observations[0].custody_object_id == object_id
    assert observations[0].constituent_files == ()
    store.close()


def test_custody_rejects_mid_write_root_swap_without_publishing_elsewhere(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _private_root(tmp_path / "custody")
    object_id = "8" * 64
    moved = tmp_path / "original-custody"
    real_writer = adapters._write_new_private_file
    writes = 0

    def swap_after_first_file(parent_fd: int, name: str, payload: bytes) -> None:
        nonlocal writes
        real_writer(parent_fd, name, payload)
        writes += 1
        if writes == 1:
            root.rename(moved)
            _private_root(root)

    monkeypatch.setattr(adapters, "_write_new_private_file", swap_after_first_file)
    with (
        AtomicFilesystemCustodyStore(root) as store,
        pytest.raises(CustodyStoreError, match="published atomically"),
    ):
        _persist(store, object_id, _custody_inputs())

    assert writes == 4
    assert list(root.iterdir()) == []
    assert list(moved.iterdir()) == []


def test_custody_rejects_verified_pending_directory_identity_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _private_root(tmp_path / "custody")
    object_id = "b" * 64
    inputs = _custody_inputs()
    real_rename = adapters._rename_noreplace
    identities: dict[str, tuple[int, int]] = {}

    def swap_exact_directory_before_rename(
        source_parent_fd: int,
        source_name: str,
        destination_parent_fd: int,
        destination_name: str,
    ) -> None:
        staged = os.stat(
            source_name,
            dir_fd=source_parent_fd,
            follow_symlinks=False,
        )
        identities["staged"] = (staged.st_dev, staged.st_ino)
        os.rename(
            source_name,
            ".held-verified-staging",
            src_dir_fd=source_parent_fd,
            dst_dir_fd=source_parent_fd,
        )
        os.mkdir(source_name, mode=0o700, dir_fd=source_parent_fd)
        replacement_fd = os.open(
            source_name,
            adapters._DIRECTORY_FLAGS,
            dir_fd=source_parent_fd,
        )
        try:
            payloads = {
                "cab.snapshot": inputs["cab_snapshot_bytes"],
                "envelope.dsse.json": inputs["envelope_bytes"],
                "receipt.json": inputs["receipt_bytes"],
                "trust-policy.json": inputs["trust_policy_bytes"],
            }
            for name, payload in payloads.items():
                adapters._write_new_private_file(replacement_fd, name, payload)
            os.fsync(replacement_fd)
        finally:
            os.close(replacement_fd)
        replacement = os.stat(
            source_name,
            dir_fd=source_parent_fd,
            follow_symlinks=False,
        )
        identities["replacement"] = (replacement.st_dev, replacement.st_ino)
        real_rename(
            source_parent_fd,
            source_name,
            destination_parent_fd,
            destination_name,
        )

    monkeypatch.setattr(adapters, "_rename_noreplace", swap_exact_directory_before_rename)
    with (
        AtomicFilesystemCustodyStore(root) as store,
        pytest.raises(CustodyStoreError, match="unavailable or unsafe"),
    ):
        _persist(store, object_id, inputs)

    published = (root / object_id).stat()
    assert identities["staged"] != identities["replacement"]
    assert (published.st_dev, published.st_ino) == identities["replacement"]


def test_custody_concurrent_exact_publish_has_one_object_and_no_pending_names(
    tmp_path: Path,
) -> None:
    root = _private_root(tmp_path / "custody")
    object_id = "6" * 64
    inputs = _custody_inputs()
    with AtomicFilesystemCustodyStore(root) as store:
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = tuple(
                executor.map(
                    lambda _index: _persist(store, object_id, inputs),
                    range(8),
                )
            )
        assert results == (store.reference_for(object_id),) * 8
        assert _verify(store, object_id, inputs)

    assert [path.name for path in root.iterdir()] == [object_id]


def test_custody_detects_early_file_mutation_while_later_file_is_hashed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _private_root(tmp_path / "custody")
    object_id = "9" * 64
    inputs = _custody_inputs()
    store = AtomicFilesystemCustodyStore(root)
    _persist(store, object_id, inputs)
    real_reader = adapters._read_pinned_file
    reads = 0

    def mutate_after_first_digest(
        descriptor: int,
        opened: os.stat_result,
        *,
        maximum: int,
        label: str,
    ) -> bytes:
        nonlocal reads
        payload = real_reader(
            descriptor,
            opened,
            maximum=maximum,
            label=label,
        )
        reads += 1
        if reads == 2:
            cab = root / object_id / "cab.snapshot"
            cab.write_bytes(b"X" * len(inputs["cab_snapshot_bytes"]))
            cab.chmod(0o600)
        return payload

    monkeypatch.setattr(adapters, "_read_pinned_file", mutate_after_first_digest)
    with pytest.raises(CustodyStoreError, match="unavailable or unsafe"):
        _verify(store, object_id, inputs)
    store.close()

    # Metadata may catch the overwrite after the first pass.  On a
    # coarse-timestamp filesystem, the reverse rehash either raises before the
    # hook increments for cab or reads and rejects the changed bytes.
    assert reads in {4, 7, 8}


def test_custody_rejects_symlink_hardlink_corruption_and_root_swap(
    tmp_path: Path,
) -> None:
    root = _private_root(tmp_path / "custody")
    object_id = "7" * 64
    inputs = _custody_inputs()
    store = AtomicFilesystemCustodyStore(root)
    _persist(store, object_id, inputs)

    receipt = root / object_id / "receipt.json"
    hardlink = tmp_path / "receipt-hardlink.json"
    os.link(receipt, hardlink)
    with pytest.raises(CustodyStoreError, match="unavailable or unsafe"):
        _verify(store, object_id, inputs)
    hardlink.unlink()

    receipt.unlink()
    outside = tmp_path / "outside-receipt.json"
    outside.write_bytes(inputs["receipt_bytes"])
    outside.chmod(0o600)
    receipt.symlink_to(outside)
    with pytest.raises(CustodyStoreError, match="unavailable or unsafe"):
        _verify(store, object_id, inputs)
    receipt.unlink()
    receipt.write_bytes(inputs["receipt_bytes"])
    receipt.chmod(0o600)

    moved = tmp_path / "moved-custody"
    root.rename(moved)
    root.symlink_to(moved, target_is_directory=True)
    with pytest.raises(ReferenceAdapterError, match="symbolic-link ancestry"):
        _verify(store, object_id, inputs)
    store.close()


def test_filesystem_adapters_reject_nonprivate_roots(tmp_path: Path) -> None:
    policy_root = _private_root(tmp_path / "policies")
    policy_root.chmod(0o755)
    with pytest.raises(ReferenceAdapterError, match="absent, unsafe"):
        DigestDirectoryTrustPolicyResolver(policy_root)

    custody_root = _private_root(tmp_path / "custody")
    custody_root.chmod(0o750)
    with pytest.raises(ReferenceAdapterError, match="absent, unsafe"):
        AtomicFilesystemCustodyStore(custody_root)
