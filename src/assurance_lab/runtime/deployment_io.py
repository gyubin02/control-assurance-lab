"""Owner-controlled file and shared-volume boundaries for worker deployment."""

from __future__ import annotations

import hashlib
import math
import os
import secrets
import stat
import threading
import time
from contextlib import suppress
from pathlib import Path
from typing import Final

from assurance_lab.connectors.defender_pam import (
    FEDERATED_ASSERTION_AUDIENCE,
    FederatedClientAssertion,
)
from assurance_lab.evidence.vault_transit import VaultToken
from assurance_lab.runtime.service_config import (
    PinnedPublicFileSettings,
    ProjectedFederatedAssertionSettings,
    ProtectedFileSettings,
    RuntimeServiceConfigurationError,
    SharedWorkRootSettings,
)

_MAX_CREDENTIAL_FILE_BYTES: Final = 128 * 1024
_MAX_PUBLIC_TRUST_FILE_BYTES: Final = 8 * 1024 * 1024
_MAX_PROTECTED_FILE_BYTES: Final = _MAX_PUBLIC_TRUST_FILE_BYTES
_WORK_ROOT_MARKER_NAME: Final = ".control-assurance-shared-work-root-v1"
_WORK_ROOT_PROBE_PREFIX: Final = ".control-assurance-write-probe-"


def _open_flags(*, directory: bool = False) -> int:
    value = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os,
        "O_NOFOLLOW",
        0,
    )
    if directory:
        value |= getattr(os, "O_DIRECTORY", 0)
    return value


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _matches_policy(
    metadata: os.stat_result,
    settings: ProtectedFileSettings,
    *,
    maximum_bytes: int,
) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_nlink == 1
        and metadata.st_uid == settings.owner_uid
        and (
            settings.group_gid is None
            or metadata.st_gid == settings.group_gid
        )
        and stat.S_IMODE(metadata.st_mode) == settings.mode
        and 0 < metadata.st_size <= maximum_bytes
    )


def read_protected_file(
    settings: ProtectedFileSettings,
    *,
    maximum_bytes: int = _MAX_CREDENTIAL_FILE_BYTES,
) -> bytes:
    """Read a direct or atomic-writer file without allowing mount escape.

    The configured path may be a Kubernetes projected-volume symlink.  Its
    resolved target must stay below the exact mount root, whose path itself may
    not be a symlink.  The final path is then opened component by component
    with ``O_NOFOLLOW`` and checked before and after the bounded read.
    """

    if type(settings) is not ProtectedFileSettings:
        raise TypeError("protected file settings must be exact")
    if (
        type(maximum_bytes) is not int
        or not 1 <= maximum_bytes <= _MAX_PROTECTED_FILE_BYTES
    ):
        raise ValueError("protected file size limit is invalid")
    configured = Path(settings.path)
    mount_root = Path(settings.mount_root)
    try:
        root_lstat_before = mount_root.lstat()
        if not stat.S_ISDIR(root_lstat_before.st_mode):
            raise OSError
        resolved_root = mount_root.resolve(strict=True)
        if resolved_root != mount_root:
            raise OSError
        configured_lstat_before = configured.lstat()
        resolved_file = configured.resolve(strict=True)
        relative = resolved_file.relative_to(resolved_root)
        if not relative.parts:
            raise OSError
    except (OSError, RuntimeError, ValueError):
        raise RuntimeServiceConfigurationError(
            "protected file path is unavailable or escaped its mount"
        ) from None

    descriptors: list[int] = []
    try:
        parent = os.open(resolved_root, _open_flags(directory=True))
        descriptors.append(parent)
        for component in relative.parts[:-1]:
            child = os.open(
                component,
                _open_flags(directory=True),
                dir_fd=parent,
            )
            descriptors.append(child)
            parent = child
        descriptor = os.open(
            relative.parts[-1],
            _open_flags(),
            dir_fd=parent,
        )
        descriptors.append(descriptor)
        before = os.fstat(descriptor)
        if not _matches_policy(
            before,
            settings,
            maximum_bytes=maximum_bytes,
        ):
            raise OSError
        content = bytearray()
        while True:
            chunk = os.read(
                descriptor,
                min(
                    64 * 1024,
                    maximum_bytes + 1 - len(content),
                ),
            )
            if not chunk:
                break
            content.extend(chunk)
            if len(content) > maximum_bytes:
                raise OSError
        after = os.fstat(descriptor)
        if _identity(before) != _identity(after):
            raise OSError
    except OSError:
        raise RuntimeServiceConfigurationError(
            "protected file failed ownership, mode, or stability checks"
        ) from None
    finally:
        for descriptor in reversed(descriptors):
            with suppress(OSError):
                os.close(descriptor)

    try:
        if (
            _identity(mount_root.lstat()) != _identity(root_lstat_before)
            or _identity(configured.lstat())
            != _identity(configured_lstat_before)
            or mount_root.resolve(strict=True) != resolved_root
            or configured.resolve(strict=True) != resolved_file
        ):
            raise OSError
    except (OSError, RuntimeError):
        raise RuntimeServiceConfigurationError(
            "protected file path changed while it was read"
        ) from None
    return bytes(content)


def read_pinned_public_file(
    settings: PinnedPublicFileSettings,
    *,
    maximum_bytes: int = _MAX_PUBLIC_TRUST_FILE_BYTES,
) -> bytes:
    """Read one stable public file and require its release-pinned SHA-256."""

    if type(settings) is not PinnedPublicFileSettings:
        raise TypeError("pinned public file settings must be exact")
    value = read_protected_file(
        settings.file,
        maximum_bytes=maximum_bytes,
    )
    observed = f"sha256:{hashlib.sha256(value).hexdigest()}"
    if not secrets.compare_digest(observed, settings.sha256_digest):
        raise RuntimeServiceConfigurationError(
            "pinned public file digest differs"
        )
    return value


def _credential_bytes(settings: ProtectedFileSettings) -> bytes:
    value = read_protected_file(settings)
    if value.endswith(b"\n"):
        value = value[:-1]
    if not value or b"\r" in value or b"\n" in value:
        raise RuntimeServiceConfigurationError(
            "protected credential file framing is invalid"
        )
    return value


class SecureFileVaultTokenProvider:
    """Read a rotating Vault Agent sink under an exact local validity bound."""

    __slots__ = ("_lock", "_settings", "_validity_seconds")

    def __init__(
        self,
        settings: ProtectedFileSettings,
        *,
        validity_seconds: int,
    ) -> None:
        if type(settings) is not ProtectedFileSettings:
            raise TypeError("Vault token file settings must be exact")
        if (
            type(validity_seconds) is not int
            or not 5 <= validity_seconds <= 300
        ):
            raise ValueError("Vault token local validity bound is invalid")
        self._settings = settings
        self._validity_seconds = validity_seconds
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return "SecureFileVaultTokenProvider(<protected-file>)"

    def get_token(self, *, deadline: float) -> VaultToken:
        now = time.monotonic()
        if (
            type(deadline) is not float
            or not math.isfinite(deadline)
            or deadline <= now
        ):
            raise RuntimeServiceConfigurationError(
                "Vault token acquisition deadline is invalid"
            )
        remaining = deadline - now
        if not self._lock.acquire(timeout=remaining):
            raise RuntimeServiceConfigurationError(
                "Vault token acquisition deadline expired"
            )
        try:
            value = _credential_bytes(self._settings)
        finally:
            self._lock.release()
        now = time.monotonic()
        valid_until = min(
            deadline,
            now + float(self._validity_seconds),
        )
        if valid_until <= now:
            raise RuntimeServiceConfigurationError(
                "Vault token acquisition deadline expired"
            )
        try:
            return VaultToken(value, valid_until_monotonic=valid_until)
        except ValueError:
            raise RuntimeServiceConfigurationError(
                "Vault token file does not contain a bounded header token"
            ) from None


class ProjectedFederatedAssertionSource:
    """Read one exact Kubernetes ServiceAccount assertion at point of use."""

    __slots__ = ("_settings",)

    def __init__(
        self,
        settings: ProjectedFederatedAssertionSettings,
    ) -> None:
        if type(settings) is not ProjectedFederatedAssertionSettings:
            raise TypeError("federated assertion settings must be exact")
        self._settings = settings

    def __repr__(self) -> str:
        return (
            "ProjectedFederatedAssertionSource("
            f"source_reference={self.source_reference!r}, value=<protected-file>)"
        )

    @property
    def source_reference(self) -> str:
        return self._settings.source_reference

    def get_assertion(
        self,
        *,
        audience: str,
        deadline: float,
    ) -> FederatedClientAssertion:
        if audience != FEDERATED_ASSERTION_AUDIENCE:
            raise RuntimeServiceConfigurationError(
                "federated assertion audience is not approved"
            )
        if (
            type(deadline) is not float
            or not math.isfinite(deadline)
            or deadline <= time.monotonic()
        ):
            raise RuntimeServiceConfigurationError(
                "federated assertion deadline is invalid"
            )
        value = _credential_bytes(self._settings.token)
        if time.monotonic() >= deadline:
            raise RuntimeServiceConfigurationError(
                "federated assertion deadline expired"
            )
        try:
            return FederatedClientAssertion(value)
        except ValueError:
            raise RuntimeServiceConfigurationError(
                "projected assertion is not one bounded compact JWT"
            ) from None


def _work_root_marker_path(settings: SharedWorkRootSettings) -> Path:
    return Path(settings.path) / _WORK_ROOT_MARKER_NAME


def _require_work_root_directory(settings: SharedWorkRootSettings) -> Path:
    path = Path(settings.path)
    try:
        metadata = path.lstat()
    except OSError:
        raise RuntimeServiceConfigurationError(
            "shared work root does not exist"
        ) from None
    if not stat.S_ISDIR(metadata.st_mode) or path.resolve(strict=True) != path:
        raise RuntimeServiceConfigurationError(
            "shared work root is not one direct directory"
        )
    return path


def _validate_work_root_marker(settings: SharedWorkRootSettings) -> None:
    marker = _work_root_marker_path(settings)
    flags = _open_flags()
    descriptor = -1
    try:
        descriptor = os.open(marker, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != settings.marker_owner_uid
            or (
                settings.marker_group_gid is not None
                and before.st_gid != settings.marker_group_gid
            )
            or stat.S_IMODE(before.st_mode) != settings.marker_mode
            or before.st_size != len(settings.marker_bytes)
        ):
            raise OSError
        value = os.read(descriptor, len(settings.marker_bytes) + 1)
        after = os.fstat(descriptor)
        if value != settings.marker_bytes or _identity(before) != _identity(after):
            raise OSError
    except OSError:
        raise RuntimeServiceConfigurationError(
            "shared work root marker is absent or differs"
        ) from None
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)


def _probe_work_root(path: Path) -> None:
    probe = path / f"{_WORK_ROOT_PROBE_PREFIX}{secrets.token_hex(16)}"
    descriptor = -1
    try:
        descriptor = os.open(
            probe,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        value = secrets.token_bytes(32)
        if os.write(descriptor, value) != len(value):
            raise OSError
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise OSError
    except OSError:
        raise RuntimeServiceConfigurationError(
            "shared work root failed its atomic write probe"
        ) from None
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        try:
            probe.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            raise RuntimeServiceConfigurationError(
                "shared work root probe could not be removed"
            ) from None


def initialize_shared_work_root(settings: SharedWorkRootSettings) -> None:
    """Idempotently create only the public marker on a mounted RWX volume."""

    if type(settings) is not SharedWorkRootSettings:
        raise TypeError("shared work root settings must be exact")
    path = _require_work_root_directory(settings)
    if (
        settings.marker_owner_uid != os.geteuid()
        or (
            settings.marker_group_gid is not None
            and settings.marker_group_gid != os.getegid()
        )
    ):
        raise RuntimeServiceConfigurationError(
            "work root initializer identity differs from marker policy"
        )
    marker = _work_root_marker_path(settings)
    descriptor = -1
    try:
        descriptor = os.open(
            marker,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError:
        # Another replica's init container can win the same O_EXCL race.
        for _ in range(50):
            try:
                _validate_work_root_marker(settings)
                break
            except RuntimeServiceConfigurationError:
                time.sleep(0.1)
        else:
            raise RuntimeServiceConfigurationError(
                "existing shared work root marker never became valid"
            ) from None
    except OSError:
        raise RuntimeServiceConfigurationError(
            "shared work root marker could not be initialized"
        ) from None
    else:
        try:
            os.fchmod(descriptor, settings.marker_mode)
            if os.write(descriptor, settings.marker_bytes) != len(
                settings.marker_bytes
            ):
                raise OSError
            os.fsync(descriptor)
        except OSError:
            with suppress(OSError):
                marker.unlink()
            raise RuntimeServiceConfigurationError(
                "shared work root marker could not be committed"
            ) from None
        finally:
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
    _validate_work_root_marker(settings)
    _probe_work_root(path)


def validate_shared_work_root(settings: SharedWorkRootSettings) -> Path:
    """Require the pre-created shared-volume marker and write semantics."""

    if type(settings) is not SharedWorkRootSettings:
        raise TypeError("shared work root settings must be exact")
    path = _require_work_root_directory(settings)
    _validate_work_root_marker(settings)
    _probe_work_root(path)
    return path


__all__ = [
    "ProjectedFederatedAssertionSource",
    "SecureFileVaultTokenProvider",
    "initialize_shared_work_root",
    "read_pinned_public_file",
    "read_protected_file",
    "validate_shared_work_root",
]
