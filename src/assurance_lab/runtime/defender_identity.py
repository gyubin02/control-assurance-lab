"""Resolve and bind the exact Microsoft Defender runtime identity.

This module is the composition boundary between an approved Defender source
configuration and the existing Entra workload-token broker.  It deliberately
does not accept a client secret, private key, refresh token, or stored
federated assertion.

The credential profile is read through one exact-version secret client,
decoded by :mod:`assurance_lab.connectors.defender_credentials`, and converted
to one of the existing Defender PAM credentials:

* a certificate assertion signed by one exact Azure Key Vault key version; or
* a federated assertion obtained from one exact Kubernetes ServiceAccount
  source.

The returned public runtime identity binds tenant, client, sovereign cloud,
permission, endpoint identities, the version-pinned secret reference, and the
complete canonical public credential authorization profile.  The broker is
kept out of object representations and no secret value is copied into the
identity document.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, Protocol, cast, runtime_checkable

from assurance_lab.connectors.defender_credentials import (
    DEFENDER_CREDENTIAL_PROFILE_CONTENT_TYPE,
    CertificatePS256CredentialPlan,
    DefenderCredentialProfileError,
    FederatedRS256CredentialPlan,
    decode_defender_credential_profile,
)
from assurance_lab.connectors.defender_pam import (
    CertificateAssertionCredential,
    CloudName,
    DefenderTokenJournal,
    DefenderWorkloadIdentityBroker,
    FederatedAssertionCredential,
    FederatedAssertionSource,
)
from assurance_lab.control_plane.models import DefenderSourceConfiguration
from assurance_lab.evidence.canonical import (
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)
from assurance_lab.key_management.azure_key_vault import (
    AzureKeyVaultCryptoClient,
    AzureKeyVaultPS256Signer,
    AzureKeyVaultTokenProvider,
)
from assurance_lab.key_management.azure_secret import (
    AzureKeyVaultSecretError,
    AzureKeyVaultSecretReference,
    AzureKeyVaultSecretValue,
)

DEFENDER_RUNTIME_IDENTITY_MEDIA_TYPE: Final = (
    "application/vnd.control-assurance.defender-runtime-identity.v1+json"
)
DEFENDER_RUNTIME_IDENTITY_SCHEMA_VERSION: Final = "1.0.0"

DefenderRuntimeCredentialMode = Literal[
    "certificate-ps256",
    "federated-rs256",
]

_DIGEST_RE: Final = re.compile(r"^sha256:[a-f0-9]{64}$")
_MIN_TIMEOUT_SECONDS: Final = 1
_MAX_TIMEOUT_SECONDS: Final = 120


class DefenderRuntimeIdentityError(RuntimeError):
    """A stable composition failure that never includes secret profile values."""

    __slots__ = ("stage",)

    def __init__(self, stage: str, detail: str) -> None:
        if (
            type(stage) is not str
            or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", stage) is None
        ):
            raise ValueError("runtime identity failure stage is invalid")
        if type(detail) is not str or not detail or len(detail) > 256:
            raise ValueError("runtime identity failure detail is invalid")
        self.stage = stage
        super().__init__(detail)


@runtime_checkable
class DefenderCredentialSecretClient(Protocol):
    """Return one secret value already bound to an exact configuration ref."""

    @property
    def reference_digest(self) -> str: ...

    def get(self) -> AzureKeyVaultSecretValue: ...


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _wall_time(clock: Callable[[], datetime]) -> datetime:
    try:
        value = clock()
    except Exception:
        raise DefenderRuntimeIdentityError(
            "clock",
            "Defender runtime identity clock failed",
        ) from None
    if type(value) is not datetime or value.tzinfo is None:
        raise DefenderRuntimeIdentityError(
            "clock",
            "Defender runtime identity clock returned an invalid instant",
        )
    try:
        return value.astimezone(UTC)
    except (OverflowError, ValueError):
        raise DefenderRuntimeIdentityError(
            "clock",
            "Defender runtime identity clock returned an invalid instant",
        ) from None


def _timeout(value: int, *, label: str) -> int:
    if (
        type(value) is not int
        or not _MIN_TIMEOUT_SECONDS <= value <= _MAX_TIMEOUT_SECONDS
    ):
        raise ValueError(f"{label} is outside the supported range")
    return value


def _load_credential_plan(
    configuration: DefenderSourceConfiguration,
    secret_client: DefenderCredentialSecretClient,
) -> tuple[
    AzureKeyVaultSecretReference,
    CertificatePS256CredentialPlan | FederatedRS256CredentialPlan,
]:
    try:
        reference = AzureKeyVaultSecretReference.parse(
            configuration.client_credential_ref
        )
    except ValueError:
        raise DefenderRuntimeIdentityError(
            "credential-reference",
            "Defender credential reference is not one exact Azure Key Vault secret version",
        ) from None
    if not isinstance(secret_client, DefenderCredentialSecretClient):
        raise TypeError("secret client does not implement the exact secret protocol")
    if (
        type(secret_client.reference_digest) is not str
        or _DIGEST_RE.fullmatch(secret_client.reference_digest) is None
        or secret_client.reference_digest != reference.reference_digest
    ):
        raise DefenderRuntimeIdentityError(
            "credential-reference",
            "Defender secret client differs from the deployed credential reference",
        )
    try:
        secret_value = secret_client.get()
    except Exception:
        raise DefenderRuntimeIdentityError(
            "credential-secret",
            "Defender credential secret could not be resolved safely",
        ) from None
    if (
        type(secret_value) is not AzureKeyVaultSecretValue
        or secret_value.reference_digest != reference.reference_digest
    ):
        raise DefenderRuntimeIdentityError(
            "credential-secret",
            "Defender credential secret crossed its exact-version boundary",
        )
    try:
        plan = secret_value.consume(
            decode_defender_credential_profile,
            expected_content_type=DEFENDER_CREDENTIAL_PROFILE_CONTENT_TYPE,
        )
    except (AzureKeyVaultSecretError, DefenderCredentialProfileError):
        raise DefenderRuntimeIdentityError(
            "credential-profile",
            "Defender credential profile could not be decoded safely",
        ) from None
    if type(plan) not in {
        CertificatePS256CredentialPlan,
        FederatedRS256CredentialPlan,
    }:
        raise DefenderRuntimeIdentityError(
            "credential-profile",
            "Defender credential decoder returned an unsupported plan",
        )
    return reference, plan


def _credential_authorization_object(
    plan: CertificatePS256CredentialPlan | FederatedRS256CredentialPlan,
) -> dict[str, object]:
    if (
        type(plan.authorization_profile_bytes) is not bytes
        or not plan.authorization_profile_bytes
        or type(plan.authorization_profile_digest) is not str
        or _DIGEST_RE.fullmatch(plan.authorization_profile_digest) is None
        or _sha256(plan.authorization_profile_bytes)
        != plan.authorization_profile_digest
    ):
        raise DefenderRuntimeIdentityError(
            "authorization-profile",
            "credential authorization profile identity is invalid",
        )
    try:
        parsed = strict_json_loads(plan.authorization_profile_bytes)
    except StrictJSONError:
        raise DefenderRuntimeIdentityError(
            "authorization-profile",
            "credential authorization profile is not strict JSON",
        ) from None
    if (
        not isinstance(parsed, dict)
        or canonical_json_bytes(parsed) != plan.authorization_profile_bytes
    ):
        raise DefenderRuntimeIdentityError(
            "authorization-profile",
            "credential authorization profile is not canonical",
        )
    return cast(dict[str, object], parsed)


@dataclass(frozen=True, slots=True, repr=False)
class PreparedDefenderRuntimeIdentity:
    """One broker and the complete public identity under which it may operate."""

    tenant_id: str = field(repr=False)
    client_id: str = field(repr=False)
    cloud: CloudName
    permission: Literal["ThreatHunting.Read.All"]
    table: Literal["AlertInfo"]
    credential_mode: DefenderRuntimeCredentialMode
    credential_secret_reference_digest: str
    credential_authorization_profile_bytes: bytes = field(repr=False)
    credential_authorization_profile_digest: str
    credential_reference_digest: str
    token_endpoint_digest: str
    graph_origin_digest: str
    scope_digest: str
    runtime_identity_bytes: bytes = field(repr=False)
    runtime_identity_digest: str
    broker: DefenderWorkloadIdentityBroker = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        for value in (
            self.credential_secret_reference_digest,
            self.credential_authorization_profile_digest,
            self.credential_reference_digest,
            self.token_endpoint_digest,
            self.graph_origin_digest,
            self.scope_digest,
            self.runtime_identity_digest,
        ):
            if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
                raise ValueError("prepared Defender identity contains an invalid digest")
        if (
            _sha256(self.credential_authorization_profile_bytes)
            != self.credential_authorization_profile_digest
            or _sha256(self.runtime_identity_bytes) != self.runtime_identity_digest
        ):
            raise ValueError("prepared Defender identity digest differs from its bytes")
        if type(self.broker) is not DefenderWorkloadIdentityBroker:
            raise TypeError("prepared Defender identity broker is invalid")
        if (
            self.broker.token_endpoint_digest != self.token_endpoint_digest
            or self.broker.graph_origin_digest != self.graph_origin_digest
            or self.broker.scope_digest != self.scope_digest
            or self.broker.credential_reference_digest
            != self.credential_reference_digest
        ):
            raise ValueError("prepared Defender broker differs from its public identity")
        try:
            credential_profile = strict_json_loads(
                self.credential_authorization_profile_bytes
            )
            runtime_identity = strict_json_loads(self.runtime_identity_bytes)
        except StrictJSONError as exc:
            raise ValueError("prepared Defender identity is not strict JSON") from exc
        if (
            not isinstance(credential_profile, dict)
            or canonical_json_bytes(credential_profile)
            != self.credential_authorization_profile_bytes
            or not isinstance(runtime_identity, dict)
            or canonical_json_bytes(runtime_identity) != self.runtime_identity_bytes
        ):
            raise ValueError("prepared Defender identity is not canonical JSON")
        expected_runtime_identity = {
            "client_id": self.client_id,
            "cloud": self.cloud,
            "credential_authorization_profile": credential_profile,
            "credential_authorization_profile_digest": (
                self.credential_authorization_profile_digest
            ),
            "credential_mode": self.credential_mode,
            "credential_reference_digest": self.credential_reference_digest,
            "credential_secret_reference_digest": (
                self.credential_secret_reference_digest
            ),
            "graph_origin_digest": self.graph_origin_digest,
            "kind": "defender-runtime-identity",
            "media_type": DEFENDER_RUNTIME_IDENTITY_MEDIA_TYPE,
            "permission": self.permission,
            "schema_version": DEFENDER_RUNTIME_IDENTITY_SCHEMA_VERSION,
            "scope_digest": self.scope_digest,
            "table": self.table,
            "tenant_id": self.tenant_id,
            "token_endpoint_digest": self.token_endpoint_digest,
        }
        if runtime_identity != expected_runtime_identity:
            raise ValueError(
                "prepared Defender runtime identity differs from its fields"
            )

    def __repr__(self) -> str:
        return (
            "PreparedDefenderRuntimeIdentity("
            f"cloud={self.cloud!r}, permission={self.permission!r}, "
            f"credential_mode={self.credential_mode!r}, "
            f"credential_authorization_profile_digest="
            f"{self.credential_authorization_profile_digest!r}, "
            f"runtime_identity_digest={self.runtime_identity_digest!r})"
        )

    def assert_runtime_identity(
        self,
        *,
        expected_bytes: bytes,
        expected_digest: str,
    ) -> None:
        """Fail closed when an approved public identity differs at execution."""

        if (
            type(expected_bytes) is not bytes
            or type(expected_digest) is not str
            or _DIGEST_RE.fullmatch(expected_digest) is None
            or _sha256(expected_bytes) != expected_digest
        ):
            raise DefenderRuntimeIdentityError(
                "identity-binding",
                "expected Defender runtime identity is invalid",
            )
        if (
            expected_bytes != self.runtime_identity_bytes
            or expected_digest != self.runtime_identity_digest
        ):
            raise DefenderRuntimeIdentityError(
                "identity-binding",
                "Defender runtime identity differs from the approved identity",
            )


def prepare_defender_runtime_identity(
    configuration: DefenderSourceConfiguration,
    *,
    credential_secret_client: DefenderCredentialSecretClient,
    journal: DefenderTokenJournal,
    key_vault_token_provider: AzureKeyVaultTokenProvider | None = None,
    federated_assertion_source: FederatedAssertionSource | None = None,
    key_vault_ca_file: Path | None = None,
    entra_ca_file: Path | None = None,
    request_timeout_seconds: int = 30,
    key_vault_operation_timeout_seconds: int = 60,
    wall_clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> PreparedDefenderRuntimeIdentity:
    """Resolve one exact credential profile and construct its Entra broker."""

    if type(configuration) is not DefenderSourceConfiguration:
        raise TypeError("configuration must be an exact Defender source configuration")
    if not isinstance(journal, DefenderTokenJournal):
        raise TypeError("journal does not implement the Defender token protocol")
    if not callable(wall_clock):
        raise TypeError("Defender runtime wall clock must be callable")
    request_timeout = _timeout(
        request_timeout_seconds,
        label="Defender request timeout",
    )
    key_vault_timeout = _timeout(
        key_vault_operation_timeout_seconds,
        label="Key Vault operation timeout",
    )
    if key_vault_ca_file is not None and not isinstance(key_vault_ca_file, Path):
        raise TypeError("Key Vault CA file must be a pathlib.Path")
    if entra_ca_file is not None and not isinstance(entra_ca_file, Path):
        raise TypeError("Entra CA file must be a pathlib.Path")

    reference, plan = _load_credential_plan(
        configuration,
        credential_secret_client,
    )
    now = _wall_time(wall_clock)
    credential: CertificateAssertionCredential | FederatedAssertionCredential
    if type(plan) is CertificatePS256CredentialPlan:
        if key_vault_token_provider is None:
            raise DefenderRuntimeIdentityError(
                "credential-composition",
                "certificate mode requires an explicit Key Vault token provider",
            )
        if federated_assertion_source is not None:
            raise DefenderRuntimeIdentityError(
                "credential-composition",
                "certificate mode cannot use a federated assertion source",
            )
        try:
            plan.assert_valid_at(now)
            crypto_client = AzureKeyVaultCryptoClient(
                key_vault_token_provider,
                vault_name=plan.vault_name,
                key_name=plan.key_name,
                key_version=plan.key_version,
                ca_file=key_vault_ca_file,
                request_timeout_seconds=request_timeout,
                operation_timeout_seconds=key_vault_timeout,
            )
            signer = AzureKeyVaultPS256Signer(
                crypto_client,
                certificate_der=plan.certificate_der,
            )
            if signer.key_reference != plan.key_reference:
                raise DefenderCredentialProfileError(
                    "remote signer reference differs from the credential profile"
                )
            credential = CertificateAssertionCredential(
                plan.certificate_der,
                signer,
            )
        except (DefenderCredentialProfileError, OSError, TypeError, ValueError):
            raise DefenderRuntimeIdentityError(
                "credential-composition",
                "certificate credential could not be composed safely",
            ) from None
    else:
        federated_plan = cast(FederatedRS256CredentialPlan, plan)
        if key_vault_token_provider is not None:
            raise DefenderRuntimeIdentityError(
                "credential-composition",
                "federated mode cannot use a signing token provider",
            )
        if (
            federated_assertion_source is None
            or not isinstance(
                federated_assertion_source,
                FederatedAssertionSource,
            )
        ):
            raise DefenderRuntimeIdentityError(
                "credential-composition",
                "federated mode requires an exact assertion source",
            )
        try:
            if (
                federated_assertion_source.source_reference
                != federated_plan.source_reference
            ):
                raise ValueError
            credential = FederatedAssertionCredential(
                federated_assertion_source,
                expected_issuer=federated_plan.issuer,
                expected_subject=federated_plan.subject,
            )
        except (AttributeError, TypeError, ValueError):
            raise DefenderRuntimeIdentityError(
                "credential-composition",
                "federated assertion source differs from the credential profile",
            ) from None

    try:
        broker = DefenderWorkloadIdentityBroker(
            tenant_id=configuration.tenant_id,
            client_id=configuration.client_id,
            cloud=configuration.cloud,
            credential=credential,
            journal=journal,
            ca_file=entra_ca_file,
            timeout_seconds=request_timeout,
        )
    except (OSError, TypeError, ValueError):
        raise DefenderRuntimeIdentityError(
            "broker-composition",
            "Defender workload identity broker could not be constructed",
        ) from None

    credential_authorization = _credential_authorization_object(plan)
    runtime_identity_bytes = canonical_json_bytes(
        {
            "client_id": configuration.client_id,
            "cloud": configuration.cloud,
            "credential_authorization_profile": credential_authorization,
            "credential_authorization_profile_digest": (
                plan.authorization_profile_digest
            ),
            "credential_mode": plan.mode,
            "credential_reference_digest": (
                broker.credential_reference_digest
            ),
            "credential_secret_reference_digest": reference.reference_digest,
            "graph_origin_digest": broker.graph_origin_digest,
            "kind": "defender-runtime-identity",
            "media_type": DEFENDER_RUNTIME_IDENTITY_MEDIA_TYPE,
            "permission": configuration.permission,
            "schema_version": DEFENDER_RUNTIME_IDENTITY_SCHEMA_VERSION,
            "scope_digest": broker.scope_digest,
            "table": configuration.table,
            "tenant_id": configuration.tenant_id,
            "token_endpoint_digest": broker.token_endpoint_digest,
        }
    )
    return PreparedDefenderRuntimeIdentity(
        tenant_id=configuration.tenant_id,
        client_id=configuration.client_id,
        cloud=configuration.cloud,
        permission=configuration.permission,
        table=configuration.table,
        credential_mode=plan.mode,
        credential_secret_reference_digest=reference.reference_digest,
        credential_authorization_profile_bytes=(
            plan.authorization_profile_bytes
        ),
        credential_authorization_profile_digest=(
            plan.authorization_profile_digest
        ),
        credential_reference_digest=broker.credential_reference_digest,
        token_endpoint_digest=broker.token_endpoint_digest,
        graph_origin_digest=broker.graph_origin_digest,
        scope_digest=broker.scope_digest,
        runtime_identity_bytes=runtime_identity_bytes,
        runtime_identity_digest=_sha256(runtime_identity_bytes),
        broker=broker,
    )


__all__ = [
    "DEFENDER_RUNTIME_IDENTITY_MEDIA_TYPE",
    "DEFENDER_RUNTIME_IDENTITY_SCHEMA_VERSION",
    "DefenderCredentialSecretClient",
    "DefenderRuntimeIdentityError",
    "PreparedDefenderRuntimeIdentity",
    "prepare_defender_runtime_identity",
]
