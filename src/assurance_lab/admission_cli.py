"""Operational CLI for the single-node evidence-admission reference boundary.

The command surface is intentionally split by authority:

* configuration can be validated without creating the admission database;
* an immutable trust-policy revision can be installed without replacing bytes;
* a signed lease can be registered before a collector submits evidence;
* admission and crash reconciliation use the same durable ledger and custody root;
* unpublished custody staging directories can be observed, never scavenged.

Private-key material and optional PEM passwords are read only from owner-private
files named by the configuration document.  They are never accepted as command
line arguments.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import os
import secrets
import stat
import sys
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from assurance_lab.evidence.admission import (
    AdmissionOutcome,
    AdmissionRejected,
    AdmissionService,
    SignedJobLease,
)
from assurance_lab.evidence.attestation import (
    MAX_ENVELOPE_BYTES,
    MAX_TRUST_POLICY_BYTES,
    TrustPolicy,
    parse_trust_policy,
)
from assurance_lab.evidence.canonical import (
    JSONLimits,
    canonical_json_bytes,
    strict_json_loads,
)
from assurance_lab.evidence.reference_adapters import (
    MAX_PRIVATE_KEY_PEM_BYTES,
    AtomicFilesystemCustodyStore,
    DigestDirectoryTrustPolicyResolver,
    Ed25519PEMReceiptSigner,
    ReferenceAdapterError,
    policy_relative_path,
)

CONFIG_MEDIA_TYPE = "application/vnd.control-assurance.admission-config.v1+json"
RESULT_MEDIA_TYPE = "application/vnd.control-assurance.admission-cli-result.v1+json"
MAX_CONFIG_BYTES = 64 * 1024
MAX_PASSWORD_BYTES = 4 * 1024
MAX_SIGNED_LEASE_BYTES = 1024 * 1024

_CONFIG_LIMITS = JSONLimits(
    max_bytes=MAX_CONFIG_BYTES,
    max_line_bytes=MAX_CONFIG_BYTES,
    max_depth=12,
    max_collection_items=64,
    max_string_length=4096,
)
_DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
_SAFE_IDENTIFIER_PATTERN = r"^[\x21-\x7e]{1,256}$"
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_WRITE_FLAGS = (
    os.O_RDWR
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_RENAME_NOREPLACE = 1


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class PrivateKeyFileConfig(_StrictFrozenModel):
    """One signer role backed by a caller-provisioned PKCS#8 PEM file."""

    key_id: str = Field(pattern=_SAFE_IDENTIFIER_PATTERN)
    private_key_file: str = Field(min_length=1, max_length=4096)
    password_file: str | None = Field(default=None, min_length=1, max_length=4096)

    @field_validator("private_key_file", "password_file")
    @classmethod
    def paths_are_absolute(cls, value: str | None) -> str | None:
        if value is None:
            return None
        path = Path(value)
        if not path.is_absolute() or path.name in {"", ".", ".."}:
            raise ValueError("signer file paths must be absolute file paths")
        return value


class AdmissionCLIConfig(_StrictFrozenModel):
    """Non-secret configuration for one single-node admission service."""

    media_type: Literal[
        "application/vnd.control-assurance.admission-config.v1+json"
    ] = Field(alias="schema")
    ledger_file: str = Field(min_length=1, max_length=4096)
    policy_root: str = Field(min_length=1, max_length=4096)
    custody_root: str = Field(min_length=1, max_length=4096)
    expected_audience: str = Field(pattern=_SAFE_IDENTIFIER_PATTERN)
    expected_capability_digest: str = Field(pattern=_DIGEST_PATTERN)
    lease_authority: PrivateKeyFileConfig
    receipt_signer: PrivateKeyFileConfig

    @field_validator("ledger_file", "policy_root", "custody_root")
    @classmethod
    def service_paths_are_absolute(cls, value: str) -> str:
        path = Path(value)
        if not path.is_absolute():
            raise ValueError("service paths must be absolute")
        return value

    @model_validator(mode="after")
    def paths_and_roles_are_distinct(self) -> AdmissionCLIConfig:
        files = [
            self.ledger_file,
            self.lease_authority.private_key_file,
            self.receipt_signer.private_key_file,
        ]
        for key in (self.lease_authority, self.receipt_signer):
            if key.password_file is not None:
                files.append(key.password_file)
        if len(set(files)) != len(files):
            raise ValueError("ledger, private-key, and password files must be distinct")
        if self.policy_root == self.custody_root:
            raise ValueError("policy and custody roots must be distinct")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            limits=_CONFIG_LIMITS,
        )


def _sha256(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _command_path(arguments: argparse.Namespace) -> str:
    parts = ["admission"]
    for attribute in (
        "admission_area",
        "admission_action",
    ):
        value = getattr(arguments, attribute, None)
        if value:
            parts.append(str(value))
    return " ".join(parts)


def _absolute_cli_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = Path.cwd() / path
    return Path(os.path.abspath(os.fspath(path)))


def _open_absolute_directory(path: Path) -> int:
    if not path.is_absolute():
        raise ValueError("internal path must be absolute")
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
        raise ValueError(f"{label} must be owner-controlled and mode 0700 or stricter")


def _validate_regular_file(
    selected: os.stat_result,
    *,
    label: str,
    private: bool,
) -> None:
    if not stat.S_ISREG(selected.st_mode) or selected.st_nlink != 1:
        raise ValueError(f"{label} must be a single-link regular file")
    if private and (
        selected.st_uid != os.geteuid() or stat.S_IMODE(selected.st_mode) & 0o077
    ):
        raise ValueError(f"{label} must be owner-controlled and mode 0600 or stricter")


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
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
    return _same_file(left, right) and (
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


def _read_descriptor(descriptor: int, *, maximum: int, label: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > maximum:
            raise ValueError(f"{label} exceeds its byte limit")
        chunks.append(chunk)


def _read_exact_file(
    path: Path,
    *,
    maximum: int,
    label: str,
    private: bool,
    require_private_parent: bool = False,
) -> bytes:
    """Read one stable inode twice without following any path component."""

    parent = -1
    descriptor = -1
    try:
        parent = _open_absolute_directory(path.parent)
        parent_stat = os.fstat(parent)
        if require_private_parent:
            _validate_private_directory(parent_stat, label=f"{label} parent directory")
        descriptor = os.open(path.name, _READ_FLAGS, dir_fd=parent)
        opened = os.fstat(descriptor)
        _validate_regular_file(opened, label=label, private=private)
        if opened.st_size < 0 or opened.st_size > maximum:
            raise ValueError(f"{label} exceeds its byte limit")
        first = _read_descriptor(descriptor, maximum=maximum, label=label)
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = _read_descriptor(descriptor, maximum=maximum, label=label)
        after = os.fstat(descriptor)
        listed = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        _validate_regular_file(listed, label=label, private=private)
        if (
            first != second
            or not _stable_file(opened, after)
            or not _same_file(opened, listed)
        ):
            raise ValueError(f"{label} changed while it was being read")
        return first
    except (OSError, ValueError) as exc:
        if isinstance(exc, ValueError):
            raise
        raise ValueError(f"{label} is unavailable or has unsafe path ancestry") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent >= 0:
            os.close(parent)


def _load_config(path: Path) -> AdmissionCLIConfig:
    payload = _read_exact_file(
        path,
        maximum=MAX_CONFIG_BYTES,
        label="admission configuration",
        private=True,
        require_private_parent=True,
    )
    document = strict_json_loads(payload, limits=_CONFIG_LIMITS)
    if not isinstance(document, dict):
        raise ValueError("admission configuration root must be a JSON object")
    return AdmissionCLIConfig.model_validate(document)


def _load_signer(specification: PrivateKeyFileConfig) -> Ed25519PEMReceiptSigner:
    key_bytes = _read_exact_file(
        Path(specification.private_key_file),
        maximum=MAX_PRIVATE_KEY_PEM_BYTES,
        label="private key",
        private=True,
        require_private_parent=True,
    )
    password: bytes | None = None
    if specification.password_file is not None:
        password = _read_exact_file(
            Path(specification.password_file),
            maximum=MAX_PASSWORD_BYTES,
            label="private-key password",
            private=True,
            require_private_parent=True,
        )
        if not password:
            raise ValueError("private-key password file must not be empty")
    return Ed25519PEMReceiptSigner(
        key_bytes,
        key_id=specification.key_id,
        password=password,
    )


def _validate_ledger_location(path: Path) -> None:
    parent = -1
    descriptor = -1
    try:
        parent = _open_absolute_directory(path.parent)
        _validate_private_directory(
            os.fstat(parent),
            label="admission ledger directory",
        )
        try:
            descriptor = os.open(path.name, _READ_FLAGS, dir_fd=parent)
        except FileNotFoundError:
            return
        opened = os.fstat(descriptor)
        _validate_regular_file(
            opened,
            label="admission ledger",
            private=True,
        )
        listed = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if not _same_file(opened, listed):
            raise ValueError("admission ledger path changed during validation")
    except (OSError, ValueError) as exc:
        if isinstance(exc, ValueError):
            raise
        raise ValueError("admission ledger location is absent or unsafe") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent >= 0:
            os.close(parent)


@contextmanager
def _configured_adapters(
    configuration: AdmissionCLIConfig,
) -> Iterator[
    tuple[
        Ed25519PEMReceiptSigner,
        Ed25519PEMReceiptSigner,
        DigestDirectoryTrustPolicyResolver,
        AtomicFilesystemCustodyStore,
    ]
]:
    authority = _load_signer(configuration.lease_authority)
    receipt = _load_signer(configuration.receipt_signer)
    if authority.key_fingerprint == receipt.key_fingerprint:
        raise ValueError("lease authority and receipt signer require distinct key material")
    _validate_ledger_location(Path(configuration.ledger_file))
    with (
        DigestDirectoryTrustPolicyResolver(Path(configuration.policy_root)) as resolver,
        AtomicFilesystemCustodyStore(Path(configuration.custody_root)) as custody,
    ):
        yield authority, receipt, resolver, custody


@contextmanager
def _configured_service(
    configuration: AdmissionCLIConfig,
) -> Iterator[AdmissionService]:
    with _configured_adapters(configuration) as (
        authority,
        receipt,
        resolver,
        custody,
    ):
        yield AdmissionService(
            Path(configuration.ledger_file),
            lease_authority=authority,
            receipt_signer=receipt,
            policy_resolver=resolver,
            custody=custody,
            expected_audience=configuration.expected_audience,
            expected_capability_digest=configuration.expected_capability_digest,
        )


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("policy write made no progress")
        view = view[written:]


def _rename_noreplace(
    source_parent: int,
    source_name: str,
    destination_parent: int,
    destination_name: str,
) -> None:
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except (AttributeError, OSError) as exc:
        raise ValueError(
            "atomic trust-policy installation requires renameat2(RENAME_NOREPLACE)"
        ) from exc
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        source_parent,
        os.fsencode(source_name),
        destination_parent,
        os.fsencode(destination_name),
        _RENAME_NOREPLACE,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), destination_name)


def _unlink_pinned_name(parent: int, name: str, identity: tuple[int, int]) -> None:
    selected = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (
        not stat.S_ISREG(selected.st_mode)
        or (selected.st_dev, selected.st_ino) != identity
    ):
        raise ValueError("staged trust-policy path changed before cleanup")
    os.unlink(name, dir_fd=parent)
    os.fsync(parent)


def _open_or_create_private_directory(parent: int, component: str) -> tuple[int, bool]:
    created = False
    try:
        child = os.open(component, _DIRECTORY_FLAGS, dir_fd=parent)
    except FileNotFoundError:
        try:
            os.mkdir(component, mode=0o700, dir_fd=parent)
        except FileExistsError:
            pass
        else:
            os.fsync(parent)
            created = True
        child = os.open(component, _DIRECTORY_FLAGS, dir_fd=parent)
    _validate_private_directory(os.fstat(child), label="trust-policy directory")
    return child, created


def _install_policy(
    *,
    configuration: AdmissionCLIConfig,
    policy_path: Path,
    revision: int,
) -> tuple[TrustPolicy, str, str, bool]:
    policy_bytes = _read_exact_file(
        policy_path,
        maximum=MAX_TRUST_POLICY_BYTES,
        label="trust policy input",
        private=False,
    )
    policy = parse_trust_policy(policy_bytes)
    digest = _sha256(policy_bytes)
    relative = policy_relative_path(policy.policy_id, revision, digest)
    root = -1
    current = -1
    descriptor = -1
    pending_name: str | None = None
    pending_identity = (-1, -1)
    published = False
    created = False
    try:
        root = _open_absolute_directory(Path(configuration.policy_root))
        _validate_private_directory(os.fstat(root), label="trust-policy root")
        current = os.dup(root)
        for component in relative.parts[:-1]:
            child, _created_directory = _open_or_create_private_directory(
                current,
                component,
            )
            os.close(current)
            current = child
        pending_name = (
            f".pending-policy-{digest.removeprefix('sha256:')}-"
            f"{secrets.token_hex(16)}"
        )
        descriptor = os.open(pending_name, _WRITE_FLAGS, 0o600, dir_fd=current)
        selected = os.fstat(descriptor)
        _validate_regular_file(
            selected,
            label="staged trust policy",
            private=True,
        )
        pending_identity = (selected.st_dev, selected.st_ino)
        _write_all(descriptor, policy_bytes)
        os.fsync(descriptor)
        selected = os.fstat(descriptor)
        _validate_regular_file(
            selected,
            label="staged trust policy",
            private=True,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        if _read_descriptor(
            descriptor,
            maximum=MAX_TRUST_POLICY_BYTES,
            label="staged trust policy",
        ) != policy_bytes:
            raise ValueError("staged trust-policy bytes changed before publication")
        listed = os.stat(pending_name, dir_fd=current, follow_symlinks=False)
        _validate_regular_file(
            listed,
            label="staged trust policy",
            private=True,
        )
        if not _same_file(selected, listed):
            raise ValueError("staged trust-policy path changed before publication")
        os.close(descriptor)
        descriptor = -1
        os.fsync(current)
        try:
            _rename_noreplace(
                current,
                pending_name,
                current,
                relative.name,
            )
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
            _unlink_pinned_name(current, pending_name, pending_identity)
            pending_name = None
            installed = _read_exact_file(
                Path(configuration.policy_root) / relative,
                maximum=MAX_TRUST_POLICY_BYTES,
                label="installed trust policy",
                private=True,
                require_private_parent=True,
            )
            if installed != policy_bytes:
                raise ValueError(
                    "trust-policy revision already exists with different bytes"
                ) from None
        else:
            published = True
            created = True
            pending_name = None
            os.fsync(current)
            os.fsync(root)
        with DigestDirectoryTrustPolicyResolver(
            Path(configuration.policy_root)
        ) as resolver:
            if resolver.resolve(policy.policy_id, revision, digest) != policy_bytes:
                raise ValueError("installed trust-policy bytes did not verify")
        return policy, digest, relative.as_posix(), created
    except (OSError, ReferenceAdapterError, ValueError) as exc:
        if isinstance(exc, ValueError):
            raise
        raise ValueError("trust policy could not be installed safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if (
            pending_name is not None
            and not published
            and current >= 0
            and pending_identity != (-1, -1)
        ):
            with suppress(OSError, ValueError):
                _unlink_pinned_name(current, pending_name, pending_identity)
        if current >= 0:
            os.close(current)
        if root >= 0:
            os.close(root)


def _config_result(
    configuration: AdmissionCLIConfig,
    authority: Ed25519PEMReceiptSigner,
    receipt: Ed25519PEMReceiptSigner,
) -> dict[str, Any]:
    return {
        "command": "config-validate",
        "config_digest": _sha256(configuration.canonical_bytes()),
        "lease_authority_key_fingerprint": authority.key_fingerprint,
        "media_type": RESULT_MEDIA_TYPE,
        "receipt_signer_key_fingerprint": receipt.key_fingerprint,
        "status": "valid",
    }


def _lease_result(grant: SignedJobLease) -> dict[str, Any]:
    lease = grant.lease
    return {
        "command": "lease-register",
        "epoch": lease.epoch,
        "job_id": lease.job_id,
        "lease_digest": lease.lease_digest(),
        "media_type": RESULT_MEDIA_TYPE,
        "sequence": lease.sequence,
        "status": "registered",
        "tenant_id": lease.tenant_id,
    }


def _admission_result(outcome: AdmissionOutcome) -> dict[str, Any]:
    return {
        "command": "admit",
        "custody_acknowledgement": outcome.custody_acknowledgement.model_dump(
            mode="json"
        ),
        "disposition": outcome.disposition.value,
        "media_type": RESULT_MEDIA_TYPE,
        "receipt": outcome.receipt.model_dump(mode="json"),
        "status": "durable",
    }


def _emit_success(
    document: dict[str, Any],
    *,
    json_output: bool,
    human: str,
) -> None:
    if json_output:
        sys.stdout.buffer.write(canonical_json_bytes(document))
    else:
        print(human)


def _emit_error(
    *,
    command: str,
    code: str,
    message: str,
    json_output: bool,
) -> int:
    if json_output:
        sys.stderr.buffer.write(
            canonical_json_bytes(
                {
                    "command": command,
                    "error": {
                        "code": code,
                        "message": message,
                    },
                    "media_type": RESULT_MEDIA_TYPE,
                    "status": "error",
                }
            )
        )
    else:
        print(f"admission error [{code}]: {message}", file=sys.stderr)
    return 2


def _execute(arguments: argparse.Namespace) -> None:
    configuration = _load_config(_absolute_cli_path(arguments.config))
    area = arguments.admission_area
    action = arguments.admission_action
    json_output = bool(arguments.json)

    if (area, action) == ("config", "validate"):
        with _configured_adapters(configuration) as (
            authority,
            receipt,
            _resolver,
            _custody,
        ):
            result = _config_result(configuration, authority, receipt)
        _emit_success(
            result,
            json_output=json_output,
            human=(
                "admission configuration valid "
                f"config={result['config_digest']} "
                f"authority={result['lease_authority_key_fingerprint']} "
                f"receipt={result['receipt_signer_key_fingerprint']}"
            ),
        )
        return

    if (area, action) == ("policy", "install"):
        # Validate every configured trust boundary before provisioning one
        # immutable policy revision.
        with _configured_adapters(configuration):
            policy, digest, relative, created = _install_policy(
                configuration=configuration,
                policy_path=_absolute_cli_path(arguments.policy),
                revision=arguments.revision,
            )
        result = {
            "command": "policy-install",
            "disposition": "installed" if created else "exact-retry",
            "media_type": RESULT_MEDIA_TYPE,
            "policy_digest": digest,
            "policy_id": policy.policy_id,
            "policy_revision": arguments.revision,
            "relative_path": relative,
            "status": "ready",
        }
        _emit_success(
            result,
            json_output=json_output,
            human=(
                f"policy {result['disposition']} "
                f"id={policy.policy_id} revision={arguments.revision} digest={digest}"
            ),
        )
        return

    if (area, action) == ("lease", "register"):
        grant_bytes = _read_exact_file(
            _absolute_cli_path(arguments.grant),
            maximum=MAX_SIGNED_LEASE_BYTES,
            label="signed lease",
            private=False,
        )
        with _configured_service(configuration) as service:
            grant = service.register_lease(grant_bytes)
        result = _lease_result(grant)
        _emit_success(
            result,
            json_output=json_output,
            human=(
                f"lease registered tenant={result['tenant_id']} "
                f"job={result['job_id']} epoch={result['epoch']} "
                f"sequence={result['sequence']} digest={result['lease_digest']}"
            ),
        )
        return

    if (area, action) == ("bundle", "admit"):
        envelope_bytes = _read_exact_file(
            _absolute_cli_path(arguments.envelope),
            maximum=MAX_ENVELOPE_BYTES,
            label="DSSE envelope",
            private=False,
        )
        with _configured_service(configuration) as service:
            outcome = service.admit(
                envelope_bytes=envelope_bytes,
                cab_source=_absolute_cli_path(arguments.cab),
            )
        result = _admission_result(outcome)
        body = outcome.receipt.body
        _emit_success(
            result,
            json_output=json_output,
            human=(
                f"{outcome.disposition.value} tenant={body.tenant_id} "
                f"job={body.job_id} epoch={body.epoch} sequence={body.sequence} "
                f"receipt={outcome.receipt.receipt_digest()} "
                f"custody={outcome.custody_reference}"
            ),
        )
        return

    if (area, action) == ("ledger", "reconcile"):
        with _configured_service(configuration) as service:
            completed = service.reconcile_pending(limit=arguments.limit)
        result = {
            "command": "reconcile",
            "completed": completed,
            "limit": arguments.limit,
            "media_type": RESULT_MEDIA_TYPE,
            "status": "complete",
        }
        _emit_success(
            result,
            json_output=json_output,
            human=f"reconciliation complete completed={completed} limit={arguments.limit}",
        )
        return

    if (area, action) == ("custody", "pending"):
        with _configured_adapters(configuration) as (
            _authority,
            _receipt,
            _resolver,
            custody,
        ):
            pending = custody.list_pending()
        result = {
            "command": "custody-pending",
            "count": len(pending),
            "media_type": RESULT_MEDIA_TYPE,
            "objects": [
                {
                    "constituent_files": list(item.constituent_files),
                    "custody_object_id": item.custody_object_id,
                    "pending_name": item.pending_name,
                }
                for item in pending
            ],
            "status": "observed",
        }
        _emit_success(
            result,
            json_output=json_output,
            human=f"pending custody staging directories={len(pending)}",
        )
        return

    raise ValueError("unknown admission command")


def run_admission(arguments: argparse.Namespace) -> int:
    """Execute one parsed admission command with a stable fail-closed surface."""

    try:
        _execute(arguments)
    except AdmissionRejected as exc:
        return _emit_error(
            command=_command_path(arguments),
            code=exc.reason.value,
            message=exc.detail,
            json_output=bool(arguments.json),
        )
    except (OSError, ReferenceAdapterError, RuntimeError, ValueError) as exc:
        return _emit_error(
            command=_command_path(arguments),
            code="operation-invalid",
            message=str(exc),
            json_output=bool(arguments.json),
        )
    return 0


def _add_json_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="emit canonical JSON")


def _add_config_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config",
        required=True,
        help="owner-private admission configuration file",
    )


def add_admission_parser(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the admission command tree on the project CLI parser."""

    admission = commands.add_parser(
        "admission",
        help="single-node signed evidence admission and custody",
    )
    areas = admission.add_subparsers(dest="admission_area", required=True)

    config = areas.add_parser("config", help="validate service configuration")
    config_actions = config.add_subparsers(dest="admission_action", required=True)
    config_validate = config_actions.add_parser(
        "validate",
        help="validate private files, signer roles, roots, and ledger location",
    )
    _add_config_flag(config_validate)
    _add_json_flag(config_validate)

    policy = areas.add_parser("policy", help="manage immutable trust-policy revisions")
    policy_actions = policy.add_subparsers(dest="admission_action", required=True)
    policy_install = policy_actions.add_parser(
        "install",
        help="atomically install or exactly retry one canonical policy revision",
    )
    _add_config_flag(policy_install)
    policy_install.add_argument("--policy", required=True)
    policy_install.add_argument("--revision", required=True, type=int)
    _add_json_flag(policy_install)

    lease = areas.add_parser("lease", help="register signed one-time leases")
    lease_actions = lease.add_subparsers(dest="admission_action", required=True)
    lease_register = lease_actions.add_parser(
        "register",
        help="verify and durably register one exact signed lease",
    )
    _add_config_flag(lease_register)
    lease_register.add_argument("--grant", required=True)
    _add_json_flag(lease_register)

    bundle = areas.add_parser("bundle", help="admit a signed exact CAB")
    bundle_actions = bundle.add_subparsers(dest="admission_action", required=True)
    bundle_admit = bundle_actions.add_parser(
        "admit",
        help="verify, consume the lease, seal the CAB, and establish custody",
    )
    _add_config_flag(bundle_admit)
    bundle_admit.add_argument("--envelope", required=True)
    bundle_admit.add_argument("--cab", required=True)
    _add_json_flag(bundle_admit)

    ledger = areas.add_parser("ledger", help="reconcile committed custody work")
    ledger_actions = ledger.add_subparsers(dest="admission_action", required=True)
    ledger_reconcile = ledger_actions.add_parser(
        "reconcile",
        help="finish durable custody for committed pending admissions",
    )
    _add_config_flag(ledger_reconcile)
    ledger_reconcile.add_argument("--limit", type=int, default=100, choices=range(1, 1001))
    _add_json_flag(ledger_reconcile)

    custody = areas.add_parser("custody", help="observe local custody state")
    custody_actions = custody.add_subparsers(dest="admission_action", required=True)
    custody_pending = custody_actions.add_parser(
        "pending",
        help="observe unpublished staging directories without deleting them",
    )
    _add_config_flag(custody_pending)
    _add_json_flag(custody_pending)


__all__ = [
    "AdmissionCLIConfig",
    "PrivateKeyFileConfig",
    "add_admission_parser",
    "run_admission",
]
