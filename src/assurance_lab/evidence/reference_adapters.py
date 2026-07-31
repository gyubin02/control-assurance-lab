"""Linux reference adapters for signing, policy resolution, and local custody.

These adapters make the admission boundary usable without asking an integrator
to invent its three security-sensitive I/O implementations:

* :class:`Ed25519PublicKeyLeaseVerifier` verifies lease signatures from a raw
  or SubjectPublicKeyInfo PEM Ed25519 public key; it cannot issue leases.
* :class:`Ed25519PEMReceiptSigner` loads one PKCS#8 Ed25519 private key from
  caller-supplied PEM bytes for receipt signing.
* :class:`DigestDirectoryTrustPolicyResolver` resolves one exact immutable
  ``(policy id, revision, digest)`` from an owner-private directory.
* :class:`AtomicFilesystemCustodyStore` publishes one content-addressed object
  directory only after every constituent file is durable.

The filesystem adapters deliberately require Linux ``openat``/``O_NOFOLLOW``
semantics and ``renameat2(RENAME_NOREPLACE)``.  They are single-host reference
adapters, not a KMS, HSM, replicated object store, transparency log, retention
lock, or WORM system.  In particular, the operating-system account that owns a
custody root can still alter or delete it outside this process.
"""

from __future__ import annotations

import base64
import binascii
import ctypes
import errno
import hashlib
import os
import re
import secrets
import stat
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from assurance_lab.evidence.admission import DetachedSignature
from assurance_lab.evidence.attestation import (
    MAX_ENVELOPE_BYTES,
    MAX_TRUST_POLICY_BYTES,
    parse_trust_policy,
)
from assurance_lab.evidence.snapshot import MAX_CAB_SNAPSHOT_BYTES

MAX_PRIVATE_KEY_PEM_BYTES = 64 * 1024
MAX_PUBLIC_KEY_PEM_BYTES = 64 * 1024
MAX_CUSTODY_RECEIPT_BYTES = 1024 * 1024

_SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_OBJECT_ID_RE = re.compile(r"^[a-f0-9]{64}$")
_PENDING_NAME_RE = re.compile(r"^\.pending-([a-f0-9]{64})-[a-f0-9]{32}$")
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,255}$")
_VISIBLE_ASCII_RE = re.compile(r"^[\x21-\x7e]{1,256}$")
_PKCS8_PEM_HEADERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
)
_PKCS8_PEM_FOOTERS = {
    b"-----BEGIN PRIVATE KEY-----": b"-----END PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----": (b"-----END ENCRYPTED PRIVATE KEY-----"),
}
_PUBLIC_KEY_PEM_HEADER = b"-----BEGIN PUBLIC KEY-----"
_PUBLIC_KEY_PEM_FOOTER = b"-----END PUBLIC KEY-----"
_PEM_TRAILING_WHITESPACE = b" \t\r\n"
_MAX_PEM_TRAILING_WHITESPACE_BYTES = 64
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_READ_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_FILE_WRITE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_CHUNK_SIZE = 1024 * 1024
_RENAME_NOREPLACE = 1
_CUSTODY_FILENAMES = (
    "cab.snapshot",
    "envelope.dsse.json",
    "receipt.json",
    "trust-policy.json",
)


class ReferenceAdapterError(RuntimeError):
    """A reference adapter could not complete a fail-closed operation."""


class PolicyResolutionError(ReferenceAdapterError):
    """An exact trust-policy revision was absent, unsafe, or corrupt."""


class CustodyStoreError(ReferenceAdapterError):
    """A custody object was unsafe, conflicting, corrupt, or unavailable."""


def _sha256(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _require_exact_bytes(value: bytes, *, label: str, maximum: int) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{label} must be immutable bytes")
    if len(value) > maximum:
        raise ValueError(f"{label} exceeds its profile byte limit")
    return value


def _validate_digest(value: str, *, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be lowercase sha256:<64 hex>")
    return value


def _validate_object_id(value: str) -> str:
    if type(value) is not str or _OBJECT_ID_RE.fullmatch(value) is None:
        raise ValueError("custody object id must be exactly 64 lowercase hex characters")
    return value


def _validate_policy_locator(
    policy_id: str,
    policy_revision: int,
    policy_digest: str,
) -> tuple[str, int, str]:
    if type(policy_id) is not str or _VISIBLE_ASCII_RE.fullmatch(policy_id) is None:
        raise ValueError("policy id must be non-empty visible ASCII up to 256 bytes")
    if type(policy_revision) is not int or policy_revision < 1 or policy_revision > (2**63 - 1):
        raise ValueError("policy revision must be an integer from 1 through 2^63-1")
    return (
        policy_id,
        policy_revision,
        _validate_digest(policy_digest, label="policy digest"),
    )


def _require_single_pkcs8_pem(private_key_pem: bytes) -> None:
    header = next(
        (candidate for candidate in _PKCS8_PEM_HEADERS if private_key_pem.startswith(candidate)),
        None,
    )
    if header is None:
        raise ValueError("private key must use PKCS#8 PEM encoding")
    footer = _PKCS8_PEM_FOOTERS[header]
    footer_offset = private_key_pem.find(footer, len(header))
    if footer_offset < 0:
        raise ValueError("private key must contain one matching PKCS#8 PEM block")
    trailing = private_key_pem[footer_offset + len(footer) :]
    if len(trailing) > _MAX_PEM_TRAILING_WHITESPACE_BYTES or trailing.strip(
        _PEM_TRAILING_WHITESPACE
    ):
        raise ValueError("private key must contain exactly one PKCS#8 PEM block")


def _require_single_public_key_pem(public_key_pem: bytes) -> None:
    if not public_key_pem.startswith(_PUBLIC_KEY_PEM_HEADER):
        raise ValueError("public key must use SubjectPublicKeyInfo PEM encoding")
    footer_offset = public_key_pem.find(
        _PUBLIC_KEY_PEM_FOOTER,
        len(_PUBLIC_KEY_PEM_HEADER),
    )
    if footer_offset < 0:
        raise ValueError("public key must contain one matching PEM block")
    trailing = public_key_pem[footer_offset + len(_PUBLIC_KEY_PEM_FOOTER) :]
    if len(trailing) > _MAX_PEM_TRAILING_WHITESPACE_BYTES or trailing.strip(
        _PEM_TRAILING_WHITESPACE
    ):
        raise ValueError("public key must contain exactly one PEM block")


def policy_relative_path(
    policy_id: str,
    policy_revision: int,
    policy_digest: str,
) -> Path:
    """Map an exact policy tuple to portable, non-secret path components.

    The policy id is hashed rather than escaped.  This prevents ``/``, ``..``,
    platform-reserved names, Unicode normalization, or a long human identifier
    from changing the directory topology.
    """

    policy_id, policy_revision, policy_digest = _validate_policy_locator(
        policy_id,
        policy_revision,
        policy_digest,
    )
    identifier_hash = hashlib.sha256(policy_id.encode("ascii")).hexdigest()
    digest_hex = policy_digest.removeprefix("sha256:")
    return Path(identifier_hash, f"{policy_revision:020d}", f"{digest_hex}.json")


class Ed25519PublicKeyLeaseVerifier:
    """Public-key-only lease verifier for the admission data plane."""

    __slots__ = ("_key_id", "_public_key", "_public_key_bytes")

    def __init__(self, public_key: bytes, *, key_id: str) -> None:
        if type(public_key) is not bytes:
            raise TypeError("lease-authority public key must be immutable bytes")
        if (
            not public_key
            or len(public_key) > MAX_PUBLIC_KEY_PEM_BYTES
            or type(key_id) is not str
            or _KEY_ID_RE.fullmatch(key_id) is None
        ):
            raise ValueError("lease-authority public key or key id is invalid")
        try:
            if len(public_key) == 32:
                loaded: object = Ed25519PublicKey.from_public_bytes(public_key)
            else:
                _require_single_public_key_pem(public_key)
                loaded = serialization.load_pem_public_key(public_key)
        except (TypeError, ValueError):
            raise ValueError("lease-authority public key could not be loaded") from None
        if not isinstance(loaded, Ed25519PublicKey):
            raise ValueError("lease-authority public key is not Ed25519")
        self._key_id = key_id
        self._public_key = loaded
        self._public_key_bytes = loaded.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(key_id={self._key_id!r}, "
            f"public_key_fingerprint={self.key_fingerprint!r})"
        )

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_key_bytes(self) -> bytes:
        return self._public_key_bytes

    @property
    def key_fingerprint(self) -> str:
        return _sha256(self._public_key_bytes)

    def verify(self, message: bytes, signature: DetachedSignature) -> bool:
        if (
            type(message) is not bytes
            or not isinstance(signature, DetachedSignature)
            or signature.key_id != self._key_id
            or signature.algorithm != "ed25519"
        ):
            return False
        try:
            encoded = signature.signature.encode("ascii", errors="strict")
            decoded = base64.b64decode(encoded, validate=True)
            if len(decoded) != 64 or base64.b64encode(decoded) != encoded:
                return False
            self._public_key.verify(decoded, message)
        except (
            InvalidSignature,
            UnicodeEncodeError,
            ValueError,
            binascii.Error,
        ):
            return False
        return True


class Ed25519PEMReceiptSigner:
    """A small PKCS#8 PEM-backed implementation of ``ReceiptSigner``.

    PEM bytes and passwords are consumed during construction and are never
    retained.  The loaded private-key object remains in process memory; this is
    not a hardware-backed or remotely isolated signing boundary.
    """

    __slots__ = ("_key_id", "_private_key", "_public_key", "_public_key_bytes")

    def __init__(
        self,
        private_key_pem: bytes,
        *,
        key_id: str,
        password: bytes | None = None,
    ) -> None:
        if type(private_key_pem) is not bytes:
            raise TypeError("private key PEM must be immutable bytes")
        if not private_key_pem or len(private_key_pem) > MAX_PRIVATE_KEY_PEM_BYTES:
            raise ValueError("private key PEM is empty or exceeds the byte limit")
        _require_single_pkcs8_pem(private_key_pem)
        if type(key_id) is not str or _KEY_ID_RE.fullmatch(key_id) is None:
            raise ValueError("key id is not portable or exceeds 256 characters")
        if password is not None and type(password) is not bytes:
            raise TypeError("PEM password must be immutable bytes or None")
        try:
            loaded = serialization.load_pem_private_key(
                private_key_pem,
                password=password,
            )
        except (TypeError, ValueError):
            # Do not chain the parser exception: backend messages are not part
            # of this adapter's public error surface.
            raise ValueError("PKCS#8 Ed25519 private key could not be loaded") from None
        if not isinstance(loaded, Ed25519PrivateKey):
            raise ValueError("PKCS#8 private key is not Ed25519")
        public_key = loaded.public_key()
        self._key_id = key_id
        self._private_key = loaded
        self._public_key = public_key
        self._public_key_bytes = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(key_id={self._key_id!r}, "
            f"public_key_fingerprint={self.key_fingerprint!r})"
        )

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_key_bytes(self) -> bytes:
        """Return the canonical raw 32-byte Ed25519 public key."""

        return self._public_key_bytes

    @property
    def key_fingerprint(self) -> str:
        return _sha256(self._public_key_bytes)

    def sign(self, message: bytes) -> DetachedSignature:
        if type(message) is not bytes:
            raise TypeError("message must be immutable bytes")
        signature = self._private_key.sign(message)
        return DetachedSignature(
            key_id=self._key_id,
            algorithm="ed25519",
            signature=base64.b64encode(signature).decode("ascii"),
        )

    def verify(self, message: bytes, signature: DetachedSignature) -> bool:
        if (
            type(message) is not bytes
            or not isinstance(signature, DetachedSignature)
            or signature.key_id != self._key_id
            or signature.algorithm != "ed25519"
        ):
            return False
        try:
            encoded = signature.signature.encode("ascii", errors="strict")
            decoded = base64.b64decode(encoded, validate=True)
            if len(decoded) != 64 or base64.b64encode(decoded) != encoded:
                return False
            self._public_key.verify(decoded, message)
        except (
            InvalidSignature,
            UnicodeEncodeError,
            ValueError,
            binascii.Error,
        ):
            return False
        return True


def _require_linux_primitives() -> None:
    if (
        os.name != "posix"
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or not Path("/proc/self/fd").is_dir()
    ):
        raise ReferenceAdapterError("filesystem adapters require Linux no-follow openat semantics")


def _open_absolute_directory(path: Path) -> int:
    if not path.is_absolute():
        raise ReferenceAdapterError("adapter root must resolve to an absolute path")
    descriptor = os.open("/", _DIRECTORY_FLAGS)
    try:
        for component in path.parts[1:]:
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _validate_private_directory(selected: os.stat_result, *, label: str) -> None:
    if (
        not stat.S_ISDIR(selected.st_mode)
        or selected.st_uid != os.geteuid()
        or stat.S_IMODE(selected.st_mode) & 0o077
    ):
        raise ReferenceAdapterError(
            f"{label} must be an owner-controlled directory with mode 0700 or stricter"
        )


def _validate_private_file(selected: os.stat_result, *, label: str) -> None:
    if (
        not stat.S_ISREG(selected.st_mode)
        or selected.st_nlink != 1
        or selected.st_uid != os.geteuid()
        or stat.S_IMODE(selected.st_mode) & 0o077
    ):
        raise ReferenceAdapterError(
            f"{label} must be a single-link owner-controlled regular file "
            "with mode 0600 or stricter"
        )


def _same_object(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        stat.S_IFMT(left.st_mode),
    ) == (
        right.st_dev,
        right.st_ino,
        stat.S_IFMT(right.st_mode),
    )


def _stable_file(left: os.stat_result, right: os.stat_result) -> bool:
    return _same_object(left, right) and (
        left.st_size,
        left.st_nlink,
        left.st_uid,
        stat.S_IMODE(left.st_mode),
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_size,
        right.st_nlink,
        right.st_uid,
        stat.S_IMODE(right.st_mode),
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _open_private_child_directory(parent_fd: int, name: str, *, label: str) -> int:
    listed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    _validate_private_directory(listed, label=label)
    descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    opened = os.fstat(descriptor)
    try:
        _validate_private_directory(opened, label=label)
        if not _same_object(listed, opened):
            raise ReferenceAdapterError(f"{label} changed before it was opened")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _read_private_file(
    parent_fd: int,
    name: str,
    *,
    maximum: int,
    label: str,
) -> bytes:
    descriptor, opened = _open_private_file(
        parent_fd,
        name,
        maximum=maximum,
        label=label,
    )
    try:
        payload = _read_pinned_file(
            descriptor,
            opened,
            maximum=maximum,
            label=label,
        )
        _assert_pinned_file_unchanged(
            parent_fd,
            name,
            descriptor,
            opened,
            label=label,
        )
        return payload
    finally:
        os.close(descriptor)


def _open_private_file(
    parent_fd: int,
    name: str,
    *,
    maximum: int,
    label: str,
) -> tuple[int, os.stat_result]:
    listed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    _validate_private_file(listed, label=label)
    if listed.st_size > maximum:
        raise ReferenceAdapterError(f"{label} exceeds its profile byte limit")
    descriptor = os.open(name, _FILE_READ_FLAGS, dir_fd=parent_fd)
    try:
        opened = os.fstat(descriptor)
        _validate_private_file(opened, label=label)
        if not _stable_file(listed, opened):
            raise ReferenceAdapterError(f"{label} changed before it was opened")
        return descriptor, opened
    except Exception:
        os.close(descriptor)
        raise


def _read_pinned_file(
    descriptor: int,
    opened: os.stat_result,
    *,
    maximum: int,
    label: str,
) -> bytes:
    output = bytearray()
    while len(output) <= maximum:
        remaining = maximum + 1 - len(output)
        chunk = os.read(descriptor, min(_CHUNK_SIZE, remaining))
        if not chunk:
            break
        output.extend(chunk)
    after = os.fstat(descriptor)
    if len(output) > maximum:
        raise ReferenceAdapterError(f"{label} exceeds its profile byte limit")
    if not _stable_file(opened, after) or len(output) != after.st_size:
        raise ReferenceAdapterError(f"{label} changed while it was read")
    return bytes(output)


def _assert_pinned_file_unchanged(
    parent_fd: int,
    name: str,
    descriptor: int,
    opened: os.stat_result,
    *,
    label: str,
) -> None:
    listed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    after = os.fstat(descriptor)
    _validate_private_file(listed, label=label)
    _validate_private_file(after, label=label)
    if not _stable_file(opened, after) or not _stable_file(listed, after):
        raise ReferenceAdapterError(f"{label} changed during the complete verification")


class _PinnedPrivateRoot:
    __slots__ = ("_closed", "_root", "_root_fd", "_root_identity")

    def __init__(self, root: Path) -> None:
        _require_linux_primitives()
        self._root = Path(os.path.abspath(os.fspath(root)))
        if self._root == Path("/"):
            raise ReferenceAdapterError("adapter root cannot be the filesystem root")
        self._closed = False
        try:
            self._root_fd = _open_absolute_directory(self._root)
            selected = os.fstat(self._root_fd)
            _validate_private_directory(selected, label="adapter root")
        except (OSError, ReferenceAdapterError) as exc:
            raise ReferenceAdapterError(
                "adapter root is absent, unsafe, or has symbolic-link ancestry"
            ) from exc
        self._root_identity = (selected.st_dev, selected.st_ino)

    @property
    def root(self) -> Path:
        return self._root

    def _assert_pinned_root(self) -> None:
        if self._closed:
            raise ReferenceAdapterError("adapter root is closed")
        pinned = os.fstat(self._root_fd)
        _validate_private_directory(pinned, label="adapter root")
        if (pinned.st_dev, pinned.st_ino) != self._root_identity:
            raise ReferenceAdapterError("pinned adapter root identity changed")
        reopened = -1
        try:
            reopened = _open_absolute_directory(self._root)
            selected = os.fstat(reopened)
            _validate_private_directory(selected, label="adapter root")
            if (selected.st_dev, selected.st_ino) != self._root_identity:
                raise ReferenceAdapterError("adapter root path now names a different directory")
        except OSError as exc:
            raise ReferenceAdapterError(
                "adapter root path changed or acquired symbolic-link ancestry"
            ) from exc
        finally:
            if reopened >= 0:
                os.close(reopened)

    def close(self) -> None:
        if not self._closed:
            os.close(self._root_fd)
            self._closed = True

    def __enter__(self) -> Self:
        self._assert_pinned_root()
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        descriptor = getattr(self, "_root_fd", -1)
        closed = getattr(self, "_closed", True)
        if descriptor >= 0 and not closed:
            with suppress(OSError):
                os.close(descriptor)
            self._closed = True


class DigestDirectoryTrustPolicyResolver(_PinnedPrivateRoot):
    """Resolve immutable canonical policies through a digest-derived layout.

    Provision policy bytes at ``root / policy_relative_path(...)``.  The two
    intermediate directories must be owned by the service and mode 0700 (or
    stricter); the policy file must be a single-link regular file with mode
    0600 (or stricter).
    """

    def policy_path(
        self,
        policy_id: str,
        policy_revision: int,
        policy_digest: str,
    ) -> Path:
        return self.root / policy_relative_path(
            policy_id,
            policy_revision,
            policy_digest,
        )

    def resolve(
        self,
        policy_id: str,
        policy_revision: int,
        policy_digest: str,
    ) -> bytes:
        relative = policy_relative_path(
            policy_id,
            policy_revision,
            policy_digest,
        )
        components = relative.parts
        self._assert_pinned_root()
        current = os.dup(self._root_fd)
        try:
            for index, component in enumerate(components[:-1]):
                child = _open_private_child_directory(
                    current,
                    component,
                    label=f"policy directory level {index + 1}",
                )
                os.close(current)
                current = child
            policy_bytes = _read_private_file(
                current,
                components[-1],
                maximum=MAX_TRUST_POLICY_BYTES,
                label="trust policy",
            )
        except (OSError, ReferenceAdapterError) as exc:
            raise PolicyResolutionError(
                "exact trust-policy revision is unavailable or unsafe"
            ) from exc
        finally:
            os.close(current)
        self._assert_pinned_root()
        if _sha256(policy_bytes) != policy_digest:
            raise PolicyResolutionError("trust-policy bytes do not match the requested digest")
        try:
            policy = parse_trust_policy(policy_bytes)
        except Exception as exc:
            raise PolicyResolutionError(
                "trust-policy bytes are not the canonical policy profile"
            ) from exc
        if policy.policy_id != policy_id:
            raise PolicyResolutionError("trust-policy id does not match the requested id")
        return policy_bytes


@dataclass(frozen=True, slots=True)
class CustodyLimits:
    """Profile ceilings enforced again at the filesystem boundary."""

    max_receipt_bytes: int = MAX_CUSTODY_RECEIPT_BYTES
    max_envelope_bytes: int = MAX_ENVELOPE_BYTES
    max_cab_snapshot_bytes: int = MAX_CAB_SNAPSHOT_BYTES
    max_trust_policy_bytes: int = MAX_TRUST_POLICY_BYTES

    def __post_init__(self) -> None:
        configured = (
            (self.max_receipt_bytes, MAX_CUSTODY_RECEIPT_BYTES),
            (self.max_envelope_bytes, MAX_ENVELOPE_BYTES),
            (self.max_cab_snapshot_bytes, MAX_CAB_SNAPSHOT_BYTES),
            (self.max_trust_policy_bytes, MAX_TRUST_POLICY_BYTES),
        )
        if any(
            type(value) is not int or value <= 0 or value > maximum for value, maximum in configured
        ):
            raise ValueError("custody limits must be positive and no larger than profile limits")


@dataclass(frozen=True, slots=True)
class PendingCustodyObservation:
    """One point-in-time observation of an unpublished staging directory.

    An observation is deliberately not a deletion capability or proof that a
    writer is dead.  Operators must quiesce every writer using the custody root
    before investigating or removing an interrupted staging directory.
    """

    custody_object_id: str
    pending_name: str
    constituent_files: tuple[str, ...]


def _write_new_private_file(parent_fd: int, name: str, payload: bytes) -> None:
    descriptor = os.open(name, _FILE_WRITE_FLAGS, 0o600, dir_fd=parent_fd)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("custody file write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        selected = os.fstat(descriptor)
        _validate_private_file(selected, label="new custody file")
        if selected.st_size != len(payload):
            raise OSError("custody file size differs after write")
    finally:
        os.close(descriptor)


def _rename_noreplace(
    source_parent_fd: int,
    source_name: str,
    destination_parent_fd: int,
    destination_name: str,
) -> None:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
    except (AttributeError, OSError) as exc:
        raise CustodyStoreError(
            "atomic custody publication requires renameat2(RENAME_NOREPLACE)"
        ) from exc
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        source_parent_fd,
        os.fsencode(source_name),
        destination_parent_fd,
        os.fsencode(destination_name),
        _RENAME_NOREPLACE,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), destination_name)


def _cleanup_pending_directory(root_fd: int, name: str, identity: tuple[int, int]) -> None:
    descriptor = -1
    try:
        descriptor = _open_private_child_directory(
            root_fd,
            name,
            label="pending custody directory",
        )
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != identity:
            raise CustodyStoreError("pending custody directory identity changed")
        entries = os.listdir(descriptor)
        if any(entry not in _CUSTODY_FILENAMES for entry in entries):
            raise CustodyStoreError("pending custody directory contains an unexpected entry")
        for entry in entries:
            listed = os.stat(entry, dir_fd=descriptor, follow_symlinks=False)
            _validate_private_file(listed, label="pending custody file")
            os.unlink(entry, dir_fd=descriptor)
        os.fsync(descriptor)
        current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != identity:
            raise CustodyStoreError("pending custody path changed during cleanup")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    os.rmdir(name, dir_fd=root_fd)
    os.fsync(root_fd)


class AtomicFilesystemCustodyStore(_PinnedPrivateRoot):
    """Atomic, non-overwriting, exact-retry local custody.

    A completed object is a directory named by its 64-hex custody object id and
    contains exactly four owner-private files.  Publication is atomic and never
    replaces an existing name.  A retry succeeds only if all four existing
    files still match the requested digests.

    Durability is the local filesystem's ``fsync`` contract.  This class makes
    no WORM, retention, replication, availability, backup, or operator
    non-equivocation claim.  Process death can leave an unpublished
    ``.pending-*`` directory.  :meth:`list_pending` observes such directories
    but never removes them because a different process may still be writing.
    Construction checks for the Linux API; the first publish remains the
    filesystem-specific capability check for ``RENAME_NOREPLACE`` and
    directory ``fsync``.
    """

    __slots__ = ("_limits",)

    def __init__(self, root: Path, *, limits: CustodyLimits | None = None) -> None:
        super().__init__(root)
        self._limits = limits or CustodyLimits()
        # Reject a missing libc API during configuration.  Filesystem-specific
        # support is necessarily exercised by the first real publication.
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            _renameat2 = libc.renameat2
        except (AttributeError, OSError) as exc:
            self.close()
            raise CustodyStoreError(
                "atomic custody publication requires renameat2(RENAME_NOREPLACE)"
            ) from exc

    def reference_for(self, custody_object_id: str) -> str:
        object_id = _validate_object_id(custody_object_id)
        return f"local-custody:v1:{object_id}"

    def list_pending(self) -> tuple[PendingCustodyObservation, ...]:
        """Inspect safe pending names without guessing writer liveness.

        This read-only snapshot may immediately become stale.  It intentionally
        exposes no automatic scavenger: safe deletion requires an external
        maintenance window that has stopped every writer sharing this root.
        """

        self._assert_pinned_root()
        try:
            names = sorted(os.listdir(self._root_fd))
        except OSError as exc:
            raise CustodyStoreError("cannot list pending custody objects") from exc
        observations: list[PendingCustodyObservation] = []
        for name in names:
            if not name.startswith(".pending-"):
                continue
            match = _PENDING_NAME_RE.fullmatch(name)
            if match is None:
                raise CustodyStoreError("custody root contains an invalid pending name")
            descriptor = -1
            try:
                descriptor = _open_private_child_directory(
                    self._root_fd,
                    name,
                    label="pending custody directory",
                )
                entries = tuple(sorted(os.listdir(descriptor)))
                if any(entry not in _CUSTODY_FILENAMES for entry in entries):
                    raise CustodyStoreError(
                        "pending custody directory contains an unexpected entry"
                    )
                for entry in entries:
                    selected = os.stat(
                        entry,
                        dir_fd=descriptor,
                        follow_symlinks=False,
                    )
                    _validate_private_file(selected, label="pending custody file")
                listed = os.stat(
                    name,
                    dir_fd=self._root_fd,
                    follow_symlinks=False,
                )
                opened = os.fstat(descriptor)
                _validate_private_directory(
                    listed,
                    label="pending custody directory",
                )
                _validate_private_directory(
                    opened,
                    label="pending custody directory",
                )
                if not _same_object(listed, opened):
                    raise CustodyStoreError("pending custody path changed during observation")
                observations.append(
                    PendingCustodyObservation(
                        custody_object_id=match.group(1),
                        pending_name=name,
                        constituent_files=entries,
                    )
                )
            except (OSError, ReferenceAdapterError) as exc:
                raise CustodyStoreError("pending custody object is unavailable or unsafe") from exc
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        self._assert_pinned_root()
        return tuple(observations)

    def _validated_inputs(
        self,
        *,
        custody_object_id: str,
        custody_reference: str,
        receipt_bytes: bytes,
        envelope_bytes: bytes,
        cab_snapshot_bytes: bytes,
        trust_policy_bytes: bytes,
        expected_envelope_digest: str,
        expected_cab_snapshot_digest: str,
        expected_trust_policy_digest: str,
        expected_receipt_digest: str,
    ) -> tuple[str, dict[str, bytes], dict[str, str]]:
        object_id = _validate_object_id(custody_object_id)
        if custody_reference != self.reference_for(object_id):
            raise CustodyStoreError("custody reference does not match the deterministic object")
        payloads = {
            "cab.snapshot": _require_exact_bytes(
                cab_snapshot_bytes,
                label="CAB snapshot",
                maximum=self._limits.max_cab_snapshot_bytes,
            ),
            "envelope.dsse.json": _require_exact_bytes(
                envelope_bytes,
                label="DSSE envelope",
                maximum=self._limits.max_envelope_bytes,
            ),
            "receipt.json": _require_exact_bytes(
                receipt_bytes,
                label="admission receipt",
                maximum=self._limits.max_receipt_bytes,
            ),
            "trust-policy.json": _require_exact_bytes(
                trust_policy_bytes,
                label="trust policy",
                maximum=self._limits.max_trust_policy_bytes,
            ),
        }
        expected = {
            "cab.snapshot": _validate_digest(
                expected_cab_snapshot_digest,
                label="CAB snapshot digest",
            ),
            "envelope.dsse.json": _validate_digest(
                expected_envelope_digest,
                label="DSSE envelope digest",
            ),
            "receipt.json": _validate_digest(
                expected_receipt_digest,
                label="admission receipt digest",
            ),
            "trust-policy.json": _validate_digest(
                expected_trust_policy_digest,
                label="trust policy digest",
            ),
        }
        if any(_sha256(payloads[name]) != expected[name] for name in _CUSTODY_FILENAMES):
            raise CustodyStoreError("custody payload does not match its expected digest")
        return object_id, payloads, expected

    def persist(
        self,
        *,
        custody_object_id: str,
        custody_reference: str,
        receipt_bytes: bytes,
        envelope_bytes: bytes,
        cab_snapshot_bytes: bytes,
        trust_policy_bytes: bytes,
        expected_envelope_digest: str,
        expected_cab_snapshot_digest: str,
        expected_trust_policy_digest: str,
        expected_receipt_digest: str,
    ) -> str:
        object_id, payloads, expected = self._validated_inputs(
            custody_object_id=custody_object_id,
            custody_reference=custody_reference,
            receipt_bytes=receipt_bytes,
            envelope_bytes=envelope_bytes,
            cab_snapshot_bytes=cab_snapshot_bytes,
            trust_policy_bytes=trust_policy_bytes,
            expected_envelope_digest=expected_envelope_digest,
            expected_cab_snapshot_digest=expected_cab_snapshot_digest,
            expected_trust_policy_digest=expected_trust_policy_digest,
            expected_receipt_digest=expected_receipt_digest,
        )
        self._assert_pinned_root()
        try:
            existing = os.stat(
                object_id,
                dir_fd=self._root_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            raise CustodyStoreError("cannot inspect the custody object name") from exc
        if existing is not None:
            if self._verify_object(
                object_id,
                expected,
                establish_durability=True,
            ):
                return custody_reference
            raise CustodyStoreError("custody object id already exists with different bytes")

        pending_name = f".pending-{object_id}-{secrets.token_hex(16)}"
        pending_fd = -1
        pending_identity = (-1, -1)
        published = False
        try:
            os.mkdir(pending_name, mode=0o700, dir_fd=self._root_fd)
            pending_fd = _open_private_child_directory(
                self._root_fd,
                pending_name,
                label="pending custody directory",
            )
            pending_stat = os.fstat(pending_fd)
            pending_identity = (pending_stat.st_dev, pending_stat.st_ino)
            for name in _CUSTODY_FILENAMES:
                _write_new_private_file(pending_fd, name, payloads[name])
            os.fsync(pending_fd)
            if not self._verify_open_directory_contents(pending_fd, expected):
                raise CustodyStoreError(
                    "staged custody files differ from the requested exact bytes"
                )
            self._assert_pinned_root()
            try:
                _rename_noreplace(
                    self._root_fd,
                    pending_name,
                    self._root_fd,
                    object_id,
                )
                published = True
            except OSError as exc:
                if exc.errno != errno.EEXIST:
                    raise
            if published:
                os.fsync(self._root_fd)
            else:
                os.close(pending_fd)
                pending_fd = -1
                _cleanup_pending_directory(
                    self._root_fd,
                    pending_name,
                    pending_identity,
                )
            self._assert_pinned_root()
            if not self._verify_object(
                object_id,
                expected,
                establish_durability=True,
                required_identity=(pending_identity if published else None),
            ):
                raise CustodyStoreError(
                    "published custody object does not contain the requested exact bytes"
                )
            return custody_reference
        except Exception as exc:
            if not published and pending_identity != (-1, -1):
                if pending_fd >= 0:
                    os.close(pending_fd)
                    pending_fd = -1
                with suppress(Exception):
                    _cleanup_pending_directory(
                        self._root_fd,
                        pending_name,
                        pending_identity,
                    )
            if isinstance(exc, CustodyStoreError):
                raise
            raise CustodyStoreError("custody object could not be published atomically") from exc
        finally:
            if pending_fd >= 0:
                os.close(pending_fd)

    def _verify_open_directory_contents(
        self,
        descriptor: int,
        expected: dict[str, str],
        *,
        durable_checkpoint: Callable[[], None] | None = None,
    ) -> bool:
        if set(os.listdir(descriptor)) != set(_CUSTODY_FILENAMES):
            return False
        maximums = {
            "cab.snapshot": self._limits.max_cab_snapshot_bytes,
            "envelope.dsse.json": self._limits.max_envelope_bytes,
            "receipt.json": self._limits.max_receipt_bytes,
            "trust-policy.json": self._limits.max_trust_policy_bytes,
        }
        pinned: dict[str, tuple[int, os.stat_result]] = {}
        try:
            # Pin all four inodes before reading any payload.  A later
            # pathname substitution cannot redirect one constituent to a
            # different file while the object is being checked.
            for name in _CUSTODY_FILENAMES:
                pinned[name] = _open_private_file(
                    descriptor,
                    name,
                    maximum=maximums[name],
                    label=f"custody file {name}",
                )
            for name in _CUSTODY_FILENAMES:
                file_descriptor, opened = pinned[name]
                payload = _read_pinned_file(
                    file_descriptor,
                    opened,
                    maximum=maximums[name],
                    label=f"custody file {name}",
                )
                if _sha256(payload) != expected[name]:
                    return False

            def assert_paths_unchanged(*, operation: str) -> None:
                for name in _CUSTODY_FILENAMES:
                    file_descriptor, opened = pinned[name]
                    _assert_pinned_file_unchanged(
                        descriptor,
                        name,
                        file_descriptor,
                        opened,
                        label=f"custody file {name}",
                    )
                if set(os.listdir(descriptor)) != set(_CUSTODY_FILENAMES):
                    raise CustodyStoreError(f"custody directory entries changed during {operation}")

            def rehash_pinned_contents(*, operation: str) -> None:
                # The reverse pass closes the longest window for files read
                # earliest above.  Re-reading is required because ctime/mtime
                # can have coarser granularity than a same-size overwrite.
                for name in reversed(_CUSTODY_FILENAMES):
                    file_descriptor, opened = pinned[name]
                    os.lseek(file_descriptor, 0, os.SEEK_SET)
                    payload = _read_pinned_file(
                        file_descriptor,
                        opened,
                        maximum=maximums[name],
                        label=f"custody file {name}",
                    )
                    if _sha256(payload) != expected[name]:
                        raise CustodyStoreError(f"custody file changed during {operation}")

            # Keep every descriptor open until every digest is known, then
            # check the path and exact bytes again.  Metadata alone is not an
            # integrity proof on filesystems with coarse timestamp granularity.
            assert_paths_unchanged(operation="verification")
            rehash_pinned_contents(operation="verification")
            assert_paths_unchanged(operation="verification")
            if durable_checkpoint is not None:
                # Hashing proves equality, not durability.  Exact retries may
                # encounter an owner-private object that this process did not
                # create, so establish the filesystem contract explicitly.
                for file_descriptor, _opened in pinned.values():
                    os.fsync(file_descriptor)
                os.fsync(descriptor)
                durable_checkpoint()
                # Keep every pinned FD open across all fsync calls and check
                # both the bytes and pathname again afterwards.  Metadata
                # timestamps alone are not a content proof on filesystems with
                # coarse timestamp granularity.
                rehash_pinned_contents(operation="durability establishment")
                assert_paths_unchanged(operation="durability establishment")
            return True
        finally:
            for file_descriptor, _opened in pinned.values():
                os.close(file_descriptor)

    def _verify_object(
        self,
        object_id: str,
        expected: dict[str, str],
        *,
        establish_durability: bool = False,
        required_identity: tuple[int, int] | None = None,
    ) -> bool:
        self._assert_pinned_root()
        descriptor = -1
        try:
            descriptor = _open_private_child_directory(
                self._root_fd,
                object_id,
                label="custody object directory",
            )

            def validate_object_path() -> None:
                listed = os.stat(
                    object_id,
                    dir_fd=self._root_fd,
                    follow_symlinks=False,
                )
                opened = os.fstat(descriptor)
                _validate_private_directory(listed, label="custody object directory")
                _validate_private_directory(opened, label="custody object directory")
                if not _same_object(listed, opened):
                    raise CustodyStoreError("custody object path changed during verification")
                if (
                    required_identity is not None
                    and (
                        opened.st_dev,
                        opened.st_ino,
                    )
                    != required_identity
                ):
                    raise CustodyStoreError(
                        "published custody object is not the verified staged directory"
                    )

            def durable_checkpoint() -> None:
                validate_object_path()
                os.fsync(self._root_fd)
                self._assert_pinned_root()

            if not self._verify_open_directory_contents(
                descriptor,
                expected,
                durable_checkpoint=(durable_checkpoint if establish_durability else None),
            ):
                return False
            validate_object_path()
        except (OSError, ReferenceAdapterError) as exc:
            raise CustodyStoreError("custody object is unavailable or unsafe") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        self._assert_pinned_root()
        return True

    def verify(
        self,
        *,
        custody_object_id: str,
        custody_reference: str,
        receipt_digest: str,
        envelope_digest: str,
        cab_snapshot_digest: str,
        trust_policy_digest: str,
    ) -> bool:
        object_id = _validate_object_id(custody_object_id)
        if custody_reference != self.reference_for(object_id):
            return False
        expected = {
            "cab.snapshot": _validate_digest(
                cab_snapshot_digest,
                label="CAB snapshot digest",
            ),
            "envelope.dsse.json": _validate_digest(
                envelope_digest,
                label="DSSE envelope digest",
            ),
            "receipt.json": _validate_digest(
                receipt_digest,
                label="admission receipt digest",
            ),
            "trust-policy.json": _validate_digest(
                trust_policy_digest,
                label="trust policy digest",
            ),
        }
        return self._verify_object(object_id, expected)


__all__ = [
    "MAX_CUSTODY_RECEIPT_BYTES",
    "MAX_PRIVATE_KEY_PEM_BYTES",
    "MAX_PUBLIC_KEY_PEM_BYTES",
    "AtomicFilesystemCustodyStore",
    "CustodyLimits",
    "CustodyStoreError",
    "DigestDirectoryTrustPolicyResolver",
    "Ed25519PEMReceiptSigner",
    "Ed25519PublicKeyLeaseVerifier",
    "PendingCustodyObservation",
    "PolicyResolutionError",
    "ReferenceAdapterError",
    "policy_relative_path",
]
