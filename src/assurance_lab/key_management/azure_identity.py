"""Azure Workload Identity token provider for the Key Vault boundary.

The provider exchanges one externally issued, projected OIDC assertion for an
Azure Key Vault access token.  It has no client-secret input, no ambient
credential discovery, and no environment-controlled authority or scope.

The projected token is treated as a credential boundary in its own right:

* the configured path and mount root are absolute and immutable;
* Kubernetes atomic-writer symlinks are accepted only when they resolve inside
  that exact mount root;
* the resolved file is opened component-by-component with ``O_NOFOLLOW``;
* owner, optional group, exact read-only mode, link count, type, and size are
  checked before and after a bounded read; and
* the JWT is locally checked for strict syntax, RS256, exact issuer, subject,
  audience, and a short freshness window before it is sent to Microsoft Entra.

Local JWT checks do not authenticate the external issuer's signature.  Entra
performs that verification against the configured federated identity
credential.  This module merely refuses obviously wrong or unsafe assertion
material before it crosses the network boundary.
"""

from __future__ import annotations

import base64
import binascii
import http.client
import math
import os
import re
import ssl
import stat
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, cast

from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    strict_json_loads,
)
from assurance_lab.key_management.azure_key_vault import (
    AZURE_KEY_VAULT_SCOPE,
    AzureKeyVaultBearerToken,
)

AZURE_WORKLOAD_IDENTITY_AUDIENCE: Final = "api://AzureADTokenExchange"
AZURE_PUBLIC_AUTHORITY_ORIGIN: Final = "https://login.microsoftonline.com"
CLIENT_ASSERTION_TYPE: Final = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

_FORM_HEADERS: Final = (
    ("accept", "application/json"),
    ("accept-encoding", "identity"),
    ("content-type", "application/x-www-form-urlencoded"),
)
_RECORDED_RESPONSE_HEADERS: Final = (
    "client-request-id",
    "content-encoding",
    "content-type",
    "request-id",
)
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_JWT_RE = re.compile(rb"^[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+[.][A-Za-z0-9_-]+$")
_TOKEN_RE = re.compile(rb"^[\x21-\x7e]+$")

_MIN_TIMEOUT_SECONDS: Final = 1
_MAX_TIMEOUT_SECONDS: Final = 120
_MIN_TOKEN_TTL_SECONDS: Final = 60
_MAX_TOKEN_TTL_SECONDS: Final = 3_900
_DEFAULT_REFRESH_SKEW_SECONDS: Final = 120
_MAX_REFRESH_SKEW_SECONDS: Final = 900
_MAX_CLOCK_SKEW_SECONDS: Final = 60
_MAX_ASSERTION_AGE_SECONDS: Final = 3_900
_MAX_ASSERTION_TTL_SECONDS: Final = 3_900
_MIN_ASSERTION_REMAINING_SECONDS: Final = 60
_MIN_ASSERTION_BYTES: Final = 32
_MAX_ASSERTION_BYTES: Final = 128 * 1024
_MAX_TOKEN_BYTES: Final = 32 * 1024
_MAX_FORM_BYTES: Final = 192 * 1024
_MAX_RESPONSE_BYTES: Final = 256 * 1024
_MAX_PATH_BYTES: Final = 4_096

_JWT_LIMITS = JSONLimits(
    max_bytes=64 * 1024,
    max_line_bytes=64 * 1024,
    max_depth=12,
    max_collection_items=128,
    max_string_length=16 * 1024,
)
_RESPONSE_LIMITS = JSONLimits(
    max_bytes=_MAX_RESPONSE_BYTES,
    max_line_bytes=_MAX_RESPONSE_BYTES,
    max_depth=8,
    max_collection_items=64,
    max_string_length=_MAX_RESPONSE_BYTES,
)


class AzureWorkloadIdentityError(RuntimeError):
    """Stable credential-free error from the workload identity boundary."""

    __slots__ = ("stage",)

    def __init__(self, stage: str, detail: str) -> None:
        self.stage = stage
        super().__init__(detail)


class _ProjectedAssertion:
    """Opaque projected assertion with deliberately redacted representations."""

    __slots__ = ("__value",)

    def __init__(self, value: bytes) -> None:
        if (
            type(value) is not bytes
            or not _MIN_ASSERTION_BYTES <= len(value) <= _MAX_ASSERTION_BYTES
            or _JWT_RE.fullmatch(value) is None
        ):
            raise AzureWorkloadIdentityError(
                "assertion",
                "projected assertion has invalid compact JWT syntax",
            )
        self.__value = value

    def __repr__(self) -> str:
        return "_ProjectedAssertion(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"

    def _text(self) -> str:
        return self.__value.decode("ascii", errors="strict")

    def _appears_in(self, payload: bytes) -> bool:
        return self.__value in payload

    def _encoded_appears_in(self, payload: bytes) -> bool:
        encoded = urllib.parse.quote_from_bytes(self.__value, safe="").encode("ascii")
        return encoded in payload


@dataclass(frozen=True, slots=True)
class _TokenHTTPResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


class _TokenHTTPTransport(Protocol):
    def request(
        self,
        *,
        endpoint: str,
        body: bytes,
        headers: tuple[tuple[str, str], ...],
        deadline: float,
    ) -> _TokenHTTPResponse: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


class _UrllibTokenTransport:
    """One-shot HTTPS transport with no proxy, redirect, compression, or retry."""

    __slots__ = ("_endpoint", "_opener", "_timeout_seconds")

    def __init__(
        self,
        *,
        endpoint: str,
        timeout_seconds: int,
        ssl_context: ssl.SSLContext,
    ) -> None:
        self._endpoint = endpoint
        self._timeout_seconds = timeout_seconds
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl_context),
        )

    def request(
        self,
        *,
        endpoint: str,
        body: bytes,
        headers: tuple[tuple[str, str], ...],
        deadline: float,
    ) -> _TokenHTTPResponse:
        if endpoint != self._endpoint:
            raise AzureWorkloadIdentityError(
                "transport",
                "token request endpoint departed from the pinned endpoint",
            )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AzureWorkloadIdentityError(
                "deadline",
                "workload token request deadline expired",
            )
        request = urllib.request.Request(
            endpoint,
            data=body,
            headers=dict(headers),
            method="POST",
        )
        response: Any
        try:
            response = self._opener.open(
                request,
                timeout=min(float(self._timeout_seconds), remaining),
            )
        except urllib.error.HTTPError as exc:
            response = exc
        except (
            TimeoutError,
            urllib.error.URLError,
            http.client.HTTPException,
            OSError,
        ):
            raise AzureWorkloadIdentityError(
                "transport",
                "Microsoft Entra token request failed",
            ) from None

        try:
            declared_lengths = response.headers.get_all("Content-Length", [])
            if len(declared_lengths) > 1:
                raise AzureWorkloadIdentityError(
                    "response",
                    "token response contains duplicate length headers",
                )
            if declared_lengths:
                try:
                    declared = int(declared_lengths[0])
                except (TypeError, ValueError):
                    raise AzureWorkloadIdentityError(
                        "response",
                        "token response length is invalid",
                    ) from None
                if declared < 0 or declared > _MAX_RESPONSE_BYTES:
                    raise AzureWorkloadIdentityError(
                        "response",
                        "token response exceeds the byte limit",
                    )

            content = bytearray()
            reader = getattr(response, "read1", response.read)
            while True:
                if time.monotonic() >= deadline:
                    raise AzureWorkloadIdentityError(
                        "deadline",
                        "token response deadline expired",
                    )
                chunk = reader(min(64 * 1024, _MAX_RESPONSE_BYTES + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > _MAX_RESPONSE_BYTES:
                    raise AzureWorkloadIdentityError(
                        "response",
                        "token response exceeds the byte limit",
                    )

            selected: list[tuple[str, str]] = []
            for name in _RECORDED_RESPONSE_HEADERS:
                values = response.headers.get_all(name, [])
                if len(values) > 1:
                    raise AzureWorkloadIdentityError(
                        "response",
                        "token response contains duplicate security headers",
                    )
                if values:
                    selected.append((name, values[0]))
            return _TokenHTTPResponse(
                status=int(response.status),
                headers=tuple(selected),
                body=bytes(content),
            )
        except (OSError, http.client.HTTPException):
            raise AzureWorkloadIdentityError(
                "response",
                "token response could not be read completely",
            ) from None
        finally:
            response.close()


def _require_uuid(value: str, *, label: str) -> str:
    if type(value) is not str or _UUID_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a canonical lowercase UUID")
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError
    except ValueError as exc:
        raise ValueError(f"{label} must be a canonical lowercase UUID") from exc
    return value


def _require_https_issuer(value: str) -> str:
    if type(value) is not str or not value or len(value) > 600:
        raise ValueError("expected issuer must be one bounded HTTPS URL")
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in {None, 443}
        or parsed.query
        or parsed.fragment
        or any(character in value for character in "\r\n")
    ):
        raise ValueError("expected issuer must be one bounded HTTPS URL")
    return value


def _require_subject(value: str) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > 600
        or any(character in value for character in "\r\n")
    ):
        raise ValueError("expected subject is invalid")
    return value


def _require_absolute_path(value: Path, *, label: str) -> Path:
    if not isinstance(value, Path) or not value.is_absolute():
        raise ValueError(f"{label} must be an absolute pathlib.Path")
    if (
        "\x00" in str(value)
        or len(os.fsencode(value)) > _MAX_PATH_BYTES
        or any(part in {".", ".."} for part in value.parts)
    ):
        raise ValueError(f"{label} is not a bounded canonical path")
    return value


def _decode_b64url(value: bytes, *, label: str, maximum: int) -> bytes:
    maximum_encoded = 4 * ((maximum + 2) // 3)
    if not value or len(value) > maximum_encoded:
        raise AzureWorkloadIdentityError(
            "assertion",
            f"{label} is absent or exceeds its limit",
        )
    if b"=" in value or re.fullmatch(rb"[A-Za-z0-9_-]+", value) is None:
        raise AzureWorkloadIdentityError(
            "assertion",
            f"{label} is not canonical base64url",
        )
    try:
        decoded = base64.urlsafe_b64decode(value + (b"=" * (-len(value) % 4)))
    except (ValueError, binascii.Error):
        raise AzureWorkloadIdentityError(
            "assertion",
            f"{label} is not canonical base64url",
        ) from None
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=")
    if len(decoded) > maximum or canonical != value:
        raise AzureWorkloadIdentityError(
            "assertion",
            f"{label} is not canonical base64url",
        )
    return decoded


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return path != root


def _secure_open_resolved(path: Path) -> int:
    """Open a resolved absolute file without following any path component."""

    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY
    file_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)

    directory = os.open("/", directory_flags)
    try:
        for component in path.parts[1:-1]:
            next_directory = os.open(
                component,
                directory_flags,
                dir_fd=directory,
            )
            os.close(directory)
            directory = next_directory
        return os.open(path.name, file_flags, dir_fd=directory)
    finally:
        os.close(directory)


def _same_file_state(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_nlink,
        left.st_uid,
        left.st_gid,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_nlink,
        right.st_uid,
        right.st_gid,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _read_projected_file(
    *,
    token_file: Path,
    mount_root: Path,
    expected_owner_uid: int,
    expected_group_gid: int | None,
    expected_mode: int,
) -> bytes:
    """Read one stable projected file, allowing only in-root atomic symlinks."""

    try:
        if not _within(token_file, mount_root):
            raise AzureWorkloadIdentityError(
                "file",
                "projected token path is outside its configured mount root",
            )
        root_before = mount_root.resolve(strict=True)
        resolved_before = token_file.resolve(strict=True)
        if not root_before.is_dir() or not _within(resolved_before, root_before):
            raise AzureWorkloadIdentityError(
                "file",
                "projected token symlink escapes its configured mount root",
            )
        path_state_before = token_file.stat()
        descriptor = _secure_open_resolved(resolved_before)
    except AzureWorkloadIdentityError:
        raise
    except (OSError, RuntimeError):
        raise AzureWorkloadIdentityError(
            "file",
            "projected token path could not be opened safely",
        ) from None

    try:
        before = os.fstat(descriptor)
        if not _same_file_state(path_state_before, before):
            raise AzureWorkloadIdentityError(
                "file",
                "projected token path changed before it was opened",
            )
        if not stat.S_ISREG(before.st_mode):
            raise AzureWorkloadIdentityError(
                "file",
                "projected token is not a regular file",
            )
        if before.st_nlink != 1:
            raise AzureWorkloadIdentityError(
                "file",
                "projected token has an unsafe hard-link count",
            )
        if before.st_uid != expected_owner_uid:
            raise AzureWorkloadIdentityError(
                "file",
                "projected token owner does not match policy",
            )
        if expected_group_gid is not None and before.st_gid != expected_group_gid:
            raise AzureWorkloadIdentityError(
                "file",
                "projected token group does not match policy",
            )
        if stat.S_IMODE(before.st_mode) != expected_mode:
            raise AzureWorkloadIdentityError(
                "file",
                "projected token mode does not match policy",
            )
        if not _MIN_ASSERTION_BYTES <= before.st_size <= _MAX_ASSERTION_BYTES:
            raise AzureWorkloadIdentityError(
                "file",
                "projected token size is outside policy",
            )

        content = bytearray()
        while True:
            chunk = os.read(
                descriptor,
                min(64 * 1024, _MAX_ASSERTION_BYTES + 1 - len(content)),
            )
            if not chunk:
                break
            content.extend(chunk)
            if len(content) > _MAX_ASSERTION_BYTES:
                raise AzureWorkloadIdentityError(
                    "file",
                    "projected token exceeds the byte limit",
                )
        after = os.fstat(descriptor)
        if len(content) != before.st_size or not _same_file_state(before, after):
            raise AzureWorkloadIdentityError(
                "file",
                "projected token changed while it was read",
            )
    except AzureWorkloadIdentityError:
        raise
    except OSError:
        raise AzureWorkloadIdentityError(
            "file",
            "projected token could not be read completely",
        ) from None
    finally:
        os.close(descriptor)

    try:
        root_after = mount_root.resolve(strict=True)
        resolved_after = token_file.resolve(strict=True)
        path_state_after = token_file.stat()
    except (OSError, RuntimeError):
        raise AzureWorkloadIdentityError(
            "file",
            "projected token path changed after it was read",
        ) from None
    if (
        root_after != root_before
        or resolved_after != resolved_before
        or not _same_file_state(after, path_state_after)
    ):
        raise AzureWorkloadIdentityError(
            "file",
            "projected token path changed while it was consumed",
        )
    return bytes(content)


@dataclass(frozen=True, slots=True)
class _RefreshFailure:
    generation: int
    stage: str
    detail: str


class AzureWorkloadIdentityTokenProvider:
    """Exchange a pinned projected assertion for a cached Key Vault token."""

    __slots__ = (
        "_cached",
        "_client_id",
        "_condition",
        "_epoch_seconds",
        "_expected_group_gid",
        "_expected_issuer",
        "_expected_mode",
        "_expected_owner_uid",
        "_expected_subject",
        "_generation",
        "_last_failure",
        "_monotonic",
        "_mount_root",
        "_refresh_skew_seconds",
        "_refreshing",
        "_tenant_id",
        "_timeout_seconds",
        "_token_endpoint",
        "_token_file",
        "_transport",
    )

    def __init__(
        self,
        *,
        tenant_id: str,
        client_id: str,
        token_file: Path,
        token_mount_root: Path,
        expected_issuer: str,
        expected_subject: str,
        expected_file_owner_uid: int,
        expected_file_mode: int,
        expected_file_group_gid: int | None = None,
        refresh_skew_seconds: int = _DEFAULT_REFRESH_SKEW_SECONDS,
        timeout_seconds: int = 30,
        _transport: _TokenHTTPTransport | None = None,
        _monotonic: Callable[[], float] = time.monotonic,
        _epoch_seconds: Callable[[], int] = lambda: time.time_ns() // 1_000_000_000,
    ) -> None:
        self._tenant_id = _require_uuid(tenant_id, label="tenant ID")
        self._client_id = _require_uuid(client_id, label="client ID")
        self._token_file = _require_absolute_path(token_file, label="token file")
        self._mount_root = _require_absolute_path(
            token_mount_root,
            label="token mount root",
        )
        if not _within(self._token_file, self._mount_root):
            raise ValueError("token file must be below the exact token mount root")
        self._expected_issuer = _require_https_issuer(expected_issuer)
        self._expected_subject = _require_subject(expected_subject)
        if type(expected_file_owner_uid) is not int or expected_file_owner_uid < 0:
            raise ValueError("expected token owner UID is invalid")
        if expected_file_group_gid is not None and (
            type(expected_file_group_gid) is not int or expected_file_group_gid < 0
        ):
            raise ValueError("expected token group GID is invalid")
        if type(expected_file_mode) is not int or expected_file_mode not in {0o400, 0o440}:
            raise ValueError("expected token mode must be exactly 0400 or 0440")
        if (
            type(refresh_skew_seconds) is not int
            or not 30 <= refresh_skew_seconds <= _MAX_REFRESH_SKEW_SECONDS
        ):
            raise ValueError("token refresh skew is outside policy")
        if (
            type(timeout_seconds) is not int
            or not _MIN_TIMEOUT_SECONDS <= timeout_seconds <= _MAX_TIMEOUT_SECONDS
        ):
            raise ValueError("token timeout is outside policy")
        if not callable(_monotonic) or not callable(_epoch_seconds):
            raise TypeError("clock sources must be callable")

        self._expected_owner_uid = expected_file_owner_uid
        self._expected_group_gid = expected_file_group_gid
        self._expected_mode = expected_file_mode
        self._refresh_skew_seconds = refresh_skew_seconds
        self._timeout_seconds = timeout_seconds
        self._monotonic = _monotonic
        self._epoch_seconds = _epoch_seconds
        self._token_endpoint = (
            f"{AZURE_PUBLIC_AUTHORITY_ORIGIN}/{self._tenant_id}/oauth2/v2.0/token"
        )
        if _transport is None:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            self._transport: _TokenHTTPTransport = _UrllibTokenTransport(
                endpoint=self._token_endpoint,
                timeout_seconds=timeout_seconds,
                ssl_context=context,
            )
        else:
            self._transport = _transport

        self._condition = threading.Condition()
        self._cached: AzureKeyVaultBearerToken | None = None
        self._refreshing = False
        self._generation = 0
        self._last_failure: _RefreshFailure | None = None

    def __repr__(self) -> str:
        return "AzureWorkloadIdentityTokenProvider(<configured>)"

    @property
    def token_endpoint(self) -> str:
        return self._token_endpoint

    @property
    def client_id(self) -> str:
        return self._client_id

    def get_token(
        self,
        *,
        scope: str,
        deadline: float,
    ) -> AzureKeyVaultBearerToken:
        """Return one current token, sharing a single refresh across callers."""

        if scope != AZURE_KEY_VAULT_SCOPE:
            raise AzureWorkloadIdentityError(
                "scope",
                "only the exact Azure Key Vault scope is permitted",
            )
        if (
            type(deadline) is not float
            or not math.isfinite(deadline)
            or deadline <= self._monotonic()
        ):
            raise AzureWorkloadIdentityError(
                "deadline",
                "workload token deadline is invalid or expired",
            )

        with self._condition:
            observed_generation = self._generation
            while True:
                now = self._monotonic()
                if now >= deadline:
                    raise AzureWorkloadIdentityError(
                        "deadline",
                        "workload token deadline expired",
                    )
                if (
                    self._cached is not None
                    and now + self._refresh_skew_seconds < self._cached.valid_until_monotonic
                ):
                    return self._cached
                if not self._refreshing:
                    self._refreshing = True
                    break
                remaining = deadline - now
                if remaining <= 0:
                    raise AzureWorkloadIdentityError(
                        "deadline",
                        "workload token deadline expired while awaiting refresh",
                    )
                self._condition.wait(timeout=remaining)
                if self._generation > observed_generation:
                    wait_failure = self._last_failure
                    if wait_failure is not None and wait_failure.generation == self._generation:
                        raise AzureWorkloadIdentityError(
                            wait_failure.stage,
                            wait_failure.detail,
                        )
                    observed_generation = self._generation

        try:
            token = self._acquire(deadline=deadline)
        except Exception as exc:
            if isinstance(exc, AzureWorkloadIdentityError):
                acquisition_failure = exc
            else:
                acquisition_failure = AzureWorkloadIdentityError(
                    "internal",
                    "workload token acquisition failed safely",
                )
            with self._condition:
                self._refreshing = False
                self._generation += 1
                self._last_failure = _RefreshFailure(
                    generation=self._generation,
                    stage=acquisition_failure.stage,
                    detail=str(acquisition_failure),
                )
                self._condition.notify_all()
            raise acquisition_failure from None
        except BaseException:
            with self._condition:
                self._refreshing = False
                self._generation += 1
                self._last_failure = _RefreshFailure(
                    generation=self._generation,
                    stage="internal",
                    detail="workload token refresh was interrupted",
                )
                self._condition.notify_all()
            raise

        with self._condition:
            self._cached = token
            self._refreshing = False
            self._generation += 1
            self._last_failure = None
            self._condition.notify_all()
            return token

    def _acquire(self, *, deadline: float) -> AzureKeyVaultBearerToken:
        start = self._monotonic()
        if start >= deadline:
            raise AzureWorkloadIdentityError(
                "deadline",
                "workload token deadline expired before assertion acquisition",
            )
        raw = _read_projected_file(
            token_file=self._token_file,
            mount_root=self._mount_root,
            expected_owner_uid=self._expected_owner_uid,
            expected_group_gid=self._expected_group_gid,
            expected_mode=self._expected_mode,
        )
        assertion = self._validate_assertion(raw)
        body = urllib.parse.urlencode(
            (
                ("client_id", self._client_id),
                ("scope", AZURE_KEY_VAULT_SCOPE),
                ("grant_type", "client_credentials"),
                ("client_assertion_type", CLIENT_ASSERTION_TYPE),
                ("client_assertion", assertion._text()),
            ),
            encoding="utf-8",
            errors="strict",
        ).encode("ascii")
        if len(body) > _MAX_FORM_BYTES:
            raise AzureWorkloadIdentityError(
                "request",
                "workload token form exceeds the byte limit",
            )
        if self._monotonic() >= deadline:
            raise AzureWorkloadIdentityError(
                "deadline",
                "workload token deadline expired before token exchange",
            )
        try:
            response = self._transport.request(
                endpoint=self._token_endpoint,
                body=body,
                headers=_FORM_HEADERS,
                deadline=deadline,
            )
        except AzureWorkloadIdentityError:
            raise
        except Exception:
            raise AzureWorkloadIdentityError(
                "transport",
                "workload token transport failed safely",
            ) from None

        if (
            type(response) is not _TokenHTTPResponse
            or type(response.status) is not int
            or not 100 <= response.status <= 599
            or type(response.headers) is not tuple
            or len(response.headers) > len(_RECORDED_RESPONSE_HEADERS)
            or type(response.body) is not bytes
            or len(response.body) > _MAX_RESPONSE_BYTES
        ):
            raise AzureWorkloadIdentityError(
                "response",
                "token transport returned a malformed response",
            )
        for item in response.headers:
            if (
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or type(item[1]) is not str
                or not item[0]
                or len(item[0]) > 64
                or len(item[1]) > 4_096
            ):
                raise AzureWorkloadIdentityError(
                    "response",
                    "token transport returned malformed response headers",
                )
        if self._monotonic() >= deadline:
            raise AzureWorkloadIdentityError(
                "deadline",
                "workload token deadline expired after token exchange",
            )
        reflected = (
            response.body
            + b"\x00"
            + b"\x00".join(
                f"{name}:{value}".encode("utf-8", errors="replace")
                for name, value in response.headers
            )
        )
        if assertion._appears_in(reflected) or assertion._encoded_appears_in(reflected):
            raise AzureWorkloadIdentityError(
                "response",
                "token endpoint reflected client assertion material",
            )
        if response.status != 200:
            raise AzureWorkloadIdentityError(
                "response",
                f"Microsoft Entra returned HTTP {response.status}",
            )

        token_bytes, expires_in = self._parse_success(response)
        try:
            token = AzureKeyVaultBearerToken(
                token_bytes,
                valid_until_monotonic=start + float(expires_in),
            )
        except ValueError:
            raise AzureWorkloadIdentityError(
                "response",
                "token response contained invalid access token material",
            ) from None
        header_wire = b"\x00".join(
            f"{name}:{value}".encode("utf-8", errors="replace") for name, value in response.headers
        )
        if token._appears_in(header_wire):
            raise AzureWorkloadIdentityError(
                "response",
                "token endpoint reflected access token material in headers",
            )
        if self._monotonic() + self._refresh_skew_seconds >= token.valid_until_monotonic:
            raise AzureWorkloadIdentityError(
                "response",
                "issued access token is already inside the refresh window",
            )
        return token

    def _validate_assertion(self, raw: bytes) -> _ProjectedAssertion:
        assertion = _ProjectedAssertion(raw)
        header_segment, claims_segment, signature_segment = raw.split(b".")
        header_bytes = _decode_b64url(
            header_segment,
            label="JWT header",
            maximum=16 * 1024,
        )
        claims_bytes = _decode_b64url(
            claims_segment,
            label="JWT claims",
            maximum=64 * 1024,
        )
        _decode_b64url(
            signature_segment,
            label="JWT signature",
            maximum=64 * 1024,
        )
        try:
            header = strict_json_loads(header_bytes, limits=_JWT_LIMITS)
            claims = strict_json_loads(claims_bytes, limits=_JWT_LIMITS)
        except StrictJSONError:
            raise AzureWorkloadIdentityError(
                "assertion",
                "projected assertion is not strict bounded JSON",
            ) from None
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise AzureWorkloadIdentityError(
                "assertion",
                "projected assertion header or claims are not objects",
            )
        if header.get("alg") != "RS256" or header.get("typ", "JWT") != "JWT":
            raise AzureWorkloadIdentityError(
                "assertion",
                "projected assertion must use RS256 and JWT type",
            )
        if frozenset(header) - frozenset({"alg", "kid", "typ", "x5t"}):
            raise AzureWorkloadIdentityError(
                "assertion",
                "projected assertion header has unsupported members",
            )
        for name in ("kid", "x5t"):
            if name in header and (
                type(header[name]) is not str
                or not header[name]
                or len(header[name]) > 512
                or any(character in header[name] for character in "\r\n")
            ):
                raise AzureWorkloadIdentityError(
                    "assertion",
                    "projected assertion key identifier is invalid",
                )

        required = frozenset({"aud", "exp", "iat", "iss", "nbf", "sub"})
        if not required <= frozenset(claims):
            raise AzureWorkloadIdentityError(
                "assertion",
                "projected assertion lacks required claims",
            )
        audience = claims["aud"]
        if not (
            audience == AZURE_WORKLOAD_IDENTITY_AUDIENCE
            or (
                isinstance(audience, list)
                and len(audience) == 1
                and audience[0] == AZURE_WORKLOAD_IDENTITY_AUDIENCE
            )
        ):
            raise AzureWorkloadIdentityError(
                "assertion",
                "projected assertion audience is not exactly bound",
            )
        if claims["iss"] != self._expected_issuer or claims["sub"] != self._expected_subject:
            raise AzureWorkloadIdentityError(
                "assertion",
                "projected assertion identity binding is wrong",
            )
        if any(type(claims[name]) is not int for name in ("exp", "iat", "nbf")):
            raise AzureWorkloadIdentityError(
                "assertion",
                "projected assertion times are invalid",
            )
        now_value = self._epoch_seconds()
        if type(now_value) is not int or now_value < 0:
            raise AzureWorkloadIdentityError(
                "clock",
                "epoch clock returned an invalid value",
            )
        issued = cast(int, claims["iat"])
        not_before = cast(int, claims["nbf"])
        expires = cast(int, claims["exp"])
        if (
            issued > now_value + _MAX_CLOCK_SKEW_SECONDS
            or not_before > now_value + _MAX_CLOCK_SKEW_SECONDS
            or issued < now_value - _MAX_ASSERTION_AGE_SECONDS
            or expires <= now_value + _MIN_ASSERTION_REMAINING_SECONDS
            or expires <= max(issued, not_before)
            or expires - min(issued, not_before) > _MAX_ASSERTION_TTL_SECONDS
        ):
            raise AzureWorkloadIdentityError(
                "assertion",
                "projected assertion is outside the freshness window",
            )
        return assertion

    @staticmethod
    def _parse_success(response: _TokenHTTPResponse) -> tuple[bytes, int]:
        headers: dict[str, str] = {}
        previous = ""
        for name, value in response.headers:
            if (
                type(name) is not str
                or type(value) is not str
                or name != name.lower()
                or name <= previous
                or any(character in value for character in "\r\n")
                or len(value) > 4_096
            ):
                raise AzureWorkloadIdentityError(
                    "response",
                    "token response headers are not canonical",
                )
            headers[name] = value
            previous = name
        content_type = headers.get("content-type", "")
        if content_type.split(";", 1)[0].strip().lower() != "application/json":
            raise AzureWorkloadIdentityError(
                "response",
                "token response is not application/json",
            )
        if headers.get("content-encoding", "identity").lower() != "identity":
            raise AzureWorkloadIdentityError(
                "response",
                "compressed token responses are forbidden",
            )
        try:
            parsed = strict_json_loads(response.body, limits=_RESPONSE_LIMITS)
        except StrictJSONError:
            raise AzureWorkloadIdentityError(
                "response",
                "token response is not strict bounded JSON",
            ) from None
        if not isinstance(parsed, dict):
            raise AzureWorkloadIdentityError(
                "response",
                "token response JSON is not an object",
            )
        required = frozenset({"access_token", "expires_in", "token_type"})
        allowed = required | frozenset({"ext_expires_in"})
        if not required <= frozenset(parsed) or not frozenset(parsed) <= allowed:
            raise AzureWorkloadIdentityError(
                "response",
                "token response has missing or unexpected members",
            )
        if parsed["token_type"] != "Bearer":
            raise AzureWorkloadIdentityError(
                "response",
                "token response type is not Bearer",
            )
        expires_in = parsed["expires_in"]
        if (
            type(expires_in) is not int
            or not _MIN_TOKEN_TTL_SECONDS <= expires_in <= _MAX_TOKEN_TTL_SECONDS
        ):
            raise AzureWorkloadIdentityError(
                "response",
                "access token lifetime is outside policy",
            )
        if "ext_expires_in" in parsed and (
            type(parsed["ext_expires_in"]) is not int
            or parsed["ext_expires_in"] < expires_in
            or parsed["ext_expires_in"] > 86_400
        ):
            raise AzureWorkloadIdentityError(
                "response",
                "extended access token lifetime is invalid",
            )
        access_token = parsed["access_token"]
        if type(access_token) is not str:
            raise AzureWorkloadIdentityError(
                "response",
                "access token is not text",
            )
        try:
            token_bytes = access_token.encode("ascii", errors="strict")
        except UnicodeEncodeError:
            raise AzureWorkloadIdentityError(
                "response",
                "access token is not ASCII",
            ) from None
        if (
            not token_bytes
            or len(token_bytes) > _MAX_TOKEN_BYTES
            or _TOKEN_RE.fullmatch(token_bytes) is None
            or b" " in token_bytes
        ):
            raise AzureWorkloadIdentityError(
                "response",
                "access token has invalid opaque syntax",
            )
        return token_bytes, expires_in
