"""Identity-bound recovery authority for an abandoned publishing attempt.

A database lease expiring does not prove that the former worker can no longer
call a source, signer, or custody service.  Recovery therefore requires four
content-addressed records:

* a maker's exact old-attempt/new-lease request;
* a hard compute-fence attestation;
* a run-scoped PAM credential-drain attestation; and
* a checker-approved, short-lived, single-use authorization.

The final authorization embeds and binds the first three records.  A dedicated
authority signs its RFC 8785 canonical bytes with Ed25519.  Runtime code parses
strict JSON, verifies against pinned local key material, compares the document
with an exact journal expectation, and atomically claims the authorization
through a caller-supplied one-time-use registry.

This module deliberately does not mutate the execution journal or PAM store.
Its records contain the exact digests and timestamps those durable stores need
to perform one fail-closed compare-and-swap.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Annotated, Final, Literal, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from assurance_lab.evidence.admission import (
    DetachedSignature,
    LeaseAuthorityVerifier,
    ReceiptSigner,
)
from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)
from assurance_lab.runtime.models import sha256_digest, utc_second

RECOVERY_SCHEMA_VERSION: Final[Literal["2.0.0"]] = "2.0.0"
PUBLISHING_RECOVERY_SCHEMA_VERSION: Final[Literal["2.0.0"]] = RECOVERY_SCHEMA_VERSION
RECOVERY_ACTOR_ACTION_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.recovery-actor-action.v2+json"]
] = "application/vnd.control-assurance.recovery-actor-action.v2+json"
SIGNED_RECOVERY_ACTOR_ACTION_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.signed-recovery-actor-action.v2+json"]
] = "application/vnd.control-assurance.signed-recovery-actor-action.v2+json"
PUBLISHING_RECOVERY_REQUEST_INTENT_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.publishing-recovery-request-intent.v2+json"]
] = "application/vnd.control-assurance.publishing-recovery-request-intent.v2+json"
PUBLISHING_RECOVERY_APPROVAL_INTENT_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.publishing-recovery-approval-intent.v2+json"]
] = "application/vnd.control-assurance.publishing-recovery-approval-intent.v2+json"
PUBLISHING_RECOVERY_REQUEST_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.publishing-recovery-request.v2+json"]
] = "application/vnd.control-assurance.publishing-recovery-request.v2+json"
COMPUTE_FENCE_ATTESTATION_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.compute-fence-attestation.v2+json"]
] = "application/vnd.control-assurance.compute-fence-attestation.v2+json"
SIGNED_COMPUTE_FENCE_ATTESTATION_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.signed-compute-fence-attestation.v2+json"]
] = "application/vnd.control-assurance.signed-compute-fence-attestation.v2+json"
CREDENTIAL_DRAIN_ATTESTATION_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.credential-drain-attestation.v2+json"]
] = "application/vnd.control-assurance.credential-drain-attestation.v2+json"
SIGNED_CREDENTIAL_DRAIN_ATTESTATION_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.signed-credential-drain-attestation.v2+json"]
] = "application/vnd.control-assurance.signed-credential-drain-attestation.v2+json"
PAM_LIFECYCLE_SNAPSHOT_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.pam-lifecycle-snapshot.v2+json"]
] = "application/vnd.control-assurance.pam-lifecycle-snapshot.v2+json"
PAM_RECOVERY_SCOPE_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.pam-recovery-scope.v2+json"]
] = "application/vnd.control-assurance.pam-recovery-scope.v2+json"
PUBLISHING_RECOVERY_AUTHORIZATION_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.publishing-recovery-authorization.v2+json"]
] = "application/vnd.control-assurance.publishing-recovery-authorization.v2+json"
SIGNED_PUBLISHING_RECOVERY_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.signed-publishing-recovery.v2+json"]
] = "application/vnd.control-assurance.signed-publishing-recovery.v2+json"
PUBLISHING_RECOVERY_EXPECTATION_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.publishing-recovery-expectation.v2+json"]
] = "application/vnd.control-assurance.publishing-recovery-expectation.v2+json"
PUBLISHING_RECOVERY_USE_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.publishing-recovery-use.v2+json"]
] = "application/vnd.control-assurance.publishing-recovery-use.v2+json"
PUBLISHING_RECOVERY_EXECUTION_BINDING_MEDIA_TYPE: Final[
    Literal["application/vnd.control-assurance.publishing-recovery-execution-binding.v2+json"]
] = "application/vnd.control-assurance.publishing-recovery-execution-binding.v2+json"
PUBLISHING_RECOVERY_SIGNATURE_DOMAIN: Final[
    Literal["control-assurance:publishing-recovery-authorization:v2"]
] = "control-assurance:publishing-recovery-authorization:v2"
COMPUTE_FENCE_SIGNATURE_DOMAIN: Final[Literal["control-assurance:compute-fence-attestation:v2"]] = (
    "control-assurance:compute-fence-attestation:v2"
)
CREDENTIAL_DRAIN_SIGNATURE_DOMAIN: Final[
    Literal["control-assurance:credential-drain-attestation:v2"]
] = "control-assurance:credential-drain-attestation:v2"
RECOVERY_MAKER_ACTION_SIGNATURE_DOMAIN: Final[
    Literal["control-assurance:publishing-recovery-maker-request:v2"]
] = "control-assurance:publishing-recovery-maker-request:v2"
RECOVERY_CHECKER_ACTION_SIGNATURE_DOMAIN: Final[
    Literal["control-assurance:publishing-recovery-checker-approval:v2"]
] = "control-assurance:publishing-recovery-checker-approval:v2"

MAX_SIGNED_PUBLISHING_RECOVERY_BYTES: Final = 128 * 1024
MAX_RECOVERY_AUTHORIZATION_LIFETIME: Final = timedelta(minutes=15)
MAX_RECOVERY_REQUEST_LIFETIME: Final = timedelta(hours=24)
MAX_ACTOR_AUTHENTICATION_AGE: Final = timedelta(minutes=5)
MAX_ACTOR_ACTION_LIFETIME: Final = MAX_RECOVERY_REQUEST_LIFETIME

_AUTHORIZATION_SIGNATURE_PREFIX = PUBLISHING_RECOVERY_SIGNATURE_DOMAIN.encode("ascii") + b"\x00"
_COMPUTE_FENCE_SIGNATURE_PREFIX = COMPUTE_FENCE_SIGNATURE_DOMAIN.encode("ascii") + b"\x00"
_CREDENTIAL_DRAIN_SIGNATURE_PREFIX = CREDENTIAL_DRAIN_SIGNATURE_DOMAIN.encode("ascii") + b"\x00"
_MAKER_ACTION_SIGNATURE_PREFIX = RECOVERY_MAKER_ACTION_SIGNATURE_DOMAIN.encode("ascii") + b"\x00"
_CHECKER_ACTION_SIGNATURE_PREFIX = (
    RECOVERY_CHECKER_ACTION_SIGNATURE_DOMAIN.encode("ascii") + b"\x00"
)
_LIMITS = JSONLimits(
    max_bytes=MAX_SIGNED_PUBLISHING_RECOVERY_BYTES,
    max_line_bytes=MAX_SIGNED_PUBLISHING_RECOVERY_BYTES,
    max_depth=16,
    max_collection_items=512,
    max_string_length=16 * 1024,
)
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,255}$")
_PORTABLE_ID_RE = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_MEDIA_TYPE_RE = re.compile(r"^application/(?:json|[a-z0-9!#$&^_.+-]+[+]json)$")
_NONCE_RE = re.compile(r"^[a-f0-9]{64}$")

Digest = Annotated[
    str,
    StringConstraints(pattern=r"^sha256:[a-f0-9]{64}$"),
]
AuthorityClass = Literal["custody", "signing", "source"]
HardFenceMethod = Literal[
    "egress-deny-fenced",
    "node-power-fenced",
    "pod-runtime-terminated",
]
PAMLifecycleState = Literal["expired", "never-issued", "revoked"]
PAMExpiryBasis = Literal[
    "confirmed-revocation",
    "not-issued",
    "observed-expiry",
    "policy-upper-bound",
]


class PublishingRecoveryError(RuntimeError):
    """Bounded, secret-free rejection at the recovery trust boundary."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        if (
            type(code) is not str
            or re.fullmatch(
                r"^[a-z][a-z0-9-]{0,63}$",
                code,
            )
            is None
        ):
            raise ValueError("publishing recovery error code is invalid")
        self.code = code
        super().__init__(code)


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )


class _CanonicalModel(_FrozenModel):
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json"), limits=_LIMITS)

    @property
    def digest(self) -> str:
        return sha256_digest(self.canonical_bytes())


def _validate_safe_id(value: str) -> str:
    if _SAFE_ID_RE.fullmatch(value) is None:
        raise ValueError("identity must use bounded visible portable ASCII")
    return value


def _validate_portable_id(value: str) -> str:
    if _PORTABLE_ID_RE.fullmatch(value) is None:
        raise ValueError("runtime identity is not portable")
    return value


def _validate_media_type(value: str) -> str:
    if _MEDIA_TYPE_RE.fullmatch(value) is None:
        raise ValueError("evidence media type must identify JSON")
    return value


def _validate_time(value: datetime, *, label: str) -> datetime:
    return utc_second(value, label=label)


def _json_time(value: datetime, *, label: str) -> str:
    return _validate_time(value, label=label).isoformat().replace("+00:00", "Z")


def _validate_nonce(value: str) -> str:
    if _NONCE_RE.fullmatch(value) is None:
        raise ValueError("nonce must be 32 bytes encoded as lowercase hexadecimal")
    return value


class RecoveryActorAssertion(_CanonicalModel):
    """Legacy unsigned actor assertion accepted only by the v2 migration helper.

    A v2 recovery request or authorization never accepts this object directly.
    It must first be converted into an exact action-bound payload and signed by
    a pinned IdP key.
    """

    subject_id: str = Field(min_length=1, max_length=256)
    session_digest: Digest
    role: Literal["checker", "maker"]
    authenticated_at: datetime
    mfa_verified_at: datetime

    _subject_is_safe = field_validator("subject_id")(_validate_safe_id)

    @field_validator("authenticated_at", "mfa_verified_at")
    @classmethod
    def validate_actor_time(cls, value: datetime) -> datetime:
        return _validate_time(value, label="recovery actor authentication time")

    @model_validator(mode="after")
    def validate_authentication_order(self) -> RecoveryActorAssertion:
        if self.mfa_verified_at < self.authenticated_at:
            raise ValueError("MFA cannot precede actor authentication")
        return self

    def require_fresh_at(self, action_at: datetime) -> None:
        if (
            self.mfa_verified_at > action_at
            or action_at - self.mfa_verified_at > MAX_ACTOR_AUTHENTICATION_AGE
        ):
            raise ValueError("recovery actor MFA is not fresh for the action")


ActorRole = Literal["checker", "maker"]
ActorAction = Literal["approve", "request"]


class RecoveryActorVerificationPolicy(_FrozenModel):
    """Pinned human-identity namespace expected at the recovery boundary."""

    audience: str = Field(min_length=1, max_length=256)
    maker_issuer_id: str = Field(min_length=1, max_length=256)
    checker_issuer_id: str = Field(min_length=1, max_length=256)

    _audience_is_safe = field_validator("audience")(_validate_safe_id)
    _maker_issuer_is_safe = field_validator("maker_issuer_id")(_validate_safe_id)
    _checker_issuer_is_safe = field_validator("checker_issuer_id")(_validate_safe_id)

    @model_validator(mode="after")
    def validate_independent_issuers(self) -> RecoveryActorVerificationPolicy:
        if self.maker_issuer_id == self.checker_issuer_id:
            raise ValueError("maker and checker IdP issuers must be independent")
        return self


class RecoveryActorAction(_CanonicalModel):
    """One IdP-authenticated human action over one exact recovery intent."""

    media_type: Literal["application/vnd.control-assurance.recovery-actor-action.v2+json"] = (
        RECOVERY_ACTOR_ACTION_MEDIA_TYPE
    )
    schema_version: Literal["2.0.0"] = RECOVERY_SCHEMA_VERSION
    issuer_id: str = Field(min_length=1, max_length=256)
    audience: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=128)
    run_id: Digest
    subject_id: str = Field(min_length=1, max_length=256)
    session_digest: Digest
    role: ActorRole
    action: ActorAction
    action_digest: Digest
    authenticated_at: datetime
    mfa_verified_at: datetime
    acted_at: datetime
    expires_at: datetime
    action_nonce: str = Field(min_length=64, max_length=64)
    idp_key_fingerprint: Digest

    _issuer_is_safe = field_validator("issuer_id")(_validate_safe_id)
    _audience_is_safe = field_validator("audience")(_validate_safe_id)
    _tenant_is_portable = field_validator("tenant_id")(_validate_portable_id)
    _subject_is_safe = field_validator("subject_id")(_validate_safe_id)
    _nonce_is_canonical = field_validator("action_nonce")(_validate_nonce)

    @field_validator(
        "authenticated_at",
        "mfa_verified_at",
        "acted_at",
        "expires_at",
    )
    @classmethod
    def validate_actor_time(cls, value: datetime) -> datetime:
        return _validate_time(value, label="recovery actor action time")

    @model_validator(mode="after")
    def validate_action(self) -> RecoveryActorAction:
        if (self.role, self.action) not in {
            ("maker", "request"),
            ("checker", "approve"),
        }:
            raise ValueError("recovery actor role and action are inconsistent")
        if not (self.authenticated_at <= self.mfa_verified_at <= self.acted_at < self.expires_at):
            raise ValueError("recovery actor action timeline is invalid")
        if self.acted_at - self.mfa_verified_at > MAX_ACTOR_AUTHENTICATION_AGE:
            raise ValueError("recovery actor MFA is not fresh for the action")
        if self.expires_at - self.acted_at > MAX_ACTOR_ACTION_LIFETIME:
            raise ValueError("recovery actor action lifetime is invalid")
        return self


class SignedRecoveryActorAction(_CanonicalModel):
    """One exact actor action plus an independent IdP signature."""

    media_type: Literal[
        "application/vnd.control-assurance.signed-recovery-actor-action.v2+json"
    ] = SIGNED_RECOVERY_ACTOR_ACTION_MEDIA_TYPE
    schema_version: Literal["2.0.0"] = RECOVERY_SCHEMA_VERSION
    actor_action_digest: Digest
    idp_key_fingerprint: Digest
    actor_action: RecoveryActorAction
    authority_signature: DetachedSignature

    @model_validator(mode="after")
    def validate_envelope(self) -> SignedRecoveryActorAction:
        if (
            self.actor_action_digest != self.actor_action.digest
            or self.idp_key_fingerprint != self.actor_action.idp_key_fingerprint
        ):
            raise ValueError("signed recovery actor action envelope is inconsistent")
        return self


def migrate_recovery_actor_assertion(
    assertion: RecoveryActorAssertion,
    *,
    issuer_id: str,
    audience: str,
    tenant_id: str,
    run_id: str,
    action: ActorAction,
    action_digest: str,
    acted_at: datetime,
    expires_at: datetime,
    action_nonce: str,
    idp_key_fingerprint: str,
) -> RecoveryActorAction:
    """Convert legacy actor facts into a v2 payload that still requires signing."""

    if type(assertion) is not RecoveryActorAssertion:
        raise TypeError("legacy recovery actor assertion must be exact")
    return RecoveryActorAction(
        issuer_id=issuer_id,
        audience=audience,
        tenant_id=tenant_id,
        run_id=run_id,
        subject_id=assertion.subject_id,
        session_digest=assertion.session_digest,
        role=assertion.role,
        action=action,
        action_digest=action_digest,
        authenticated_at=assertion.authenticated_at,
        mfa_verified_at=assertion.mfa_verified_at,
        acted_at=acted_at,
        expires_at=expires_at,
        action_nonce=action_nonce,
        idp_key_fingerprint=idp_key_fingerprint,
    )


class AbandonedPublishingAttempt(_CanonicalModel):
    """Exact identity-bound journal tuple that became stuck in publishing."""

    lease_fence: int = Field(ge=1, le=2**63 - 2)
    attempt_count: int = Field(ge=1, le=32)
    attempt_revision: Literal[1] = 1
    worker_id: str = Field(min_length=1, max_length=128)
    worker_credential_digest: Digest
    lease_token_digest: Digest
    leased_at: datetime
    lease_expires_at: datetime
    publishing_at: datetime

    _worker_is_portable = field_validator("worker_id")(_validate_portable_id)

    @field_validator("leased_at", "lease_expires_at", "publishing_at")
    @classmethod
    def validate_attempt_time(cls, value: datetime) -> datetime:
        return _validate_time(value, label="abandoned publishing attempt time")

    @model_validator(mode="after")
    def validate_attempt(self) -> AbandonedPublishingAttempt:
        if (
            self.attempt_count > self.lease_fence
            or self.lease_expires_at <= self.leased_at
            or self.publishing_at < self.leased_at
            or self.publishing_at >= self.lease_expires_at
        ):
            raise ValueError("abandoned publishing attempt tuple is inconsistent")
        return self


class SuccessorLeaseClaim(_CanonicalModel):
    """Exact scheduler claim allowed to adopt the abandoned publication."""

    lease_fence: int = Field(ge=2, le=2**63 - 1)
    attempt_count: int = Field(ge=2, le=32)
    attempt_revision: Literal[1] = 1
    worker_id: str = Field(min_length=1, max_length=128)
    worker_credential_digest: Digest
    lease_token_digest: Digest
    leased_at: datetime
    lease_expires_at: datetime

    _worker_is_portable = field_validator("worker_id")(_validate_portable_id)

    @field_validator("leased_at", "lease_expires_at")
    @classmethod
    def validate_claim_time(cls, value: datetime) -> datetime:
        return _validate_time(value, label="successor lease claim time")

    @model_validator(mode="after")
    def validate_claim(self) -> SuccessorLeaseClaim:
        if self.lease_expires_at <= self.leased_at:
            raise ValueError("successor lease claim expires before it starts")
        return self


class PAMRecoveryScope(_CanonicalModel):
    """One exact authority/connector/request tuple derived from the frozen plan."""

    authority_class: AuthorityClass
    connector_id: str = Field(min_length=1, max_length=128)
    connector_request_digest: Digest

    _connector_is_portable = field_validator("connector_id")(_validate_portable_id)

    @property
    def sort_key(self) -> tuple[str, str, str]:
        return (
            self.authority_class,
            self.connector_id,
            self.connector_request_digest,
        )


def migrate_legacy_pam_recovery_scopes(
    *,
    authority_classes: tuple[AuthorityClass, ...],
    connector_ids: tuple[str, ...],
    connector_request_digests: tuple[str, ...],
) -> tuple[PAMRecoveryScope, ...]:
    """Pair legacy parallel arrays explicitly; never infer a missing mapping."""

    if not (len(authority_classes) == len(connector_ids) == len(connector_request_digests)):
        raise ValueError("legacy PAM recovery scope arrays differ in length")
    scopes = tuple(
        PAMRecoveryScope(
            authority_class=authority_class,
            connector_id=connector_id,
            connector_request_digest=connector_request_digest,
        )
        for authority_class, connector_id, connector_request_digest in zip(
            authority_classes,
            connector_ids,
            connector_request_digests,
            strict=True,
        )
    )
    return tuple(sorted(scopes, key=lambda scope: scope.sort_key))


def publishing_recovery_pam_scope_digest(
    scopes: tuple[PAMRecoveryScope, ...],
) -> str:
    """Content-address one ordered, mapped recovery scope."""

    document = {
        "media_type": PAM_RECOVERY_SCOPE_MEDIA_TYPE,
        "schema_version": RECOVERY_SCHEMA_VERSION,
        "scopes": [scope.model_dump(mode="json") for scope in scopes],
    }
    return sha256_digest(canonical_json_bytes(document, limits=_LIMITS))


def publishing_recovery_execution_binding_digest(
    *,
    tenant_id: str,
    run_id: str,
    execution_plan_digest: str,
    execution_identity_digest: str,
    abandoned_lease_fence: int,
    pam_scope_digest: str,
) -> str:
    """Derive the run-scoped binding every PAM lifecycle row must carry."""

    document = {
        "media_type": PUBLISHING_RECOVERY_EXECUTION_BINDING_MEDIA_TYPE,
        "schema_version": RECOVERY_SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "run_id": run_id,
        "execution_plan_digest": execution_plan_digest,
        "execution_identity_digest": execution_identity_digest,
        "abandoned_lease_fence": abandoned_lease_fence,
        "pam_scope_digest": pam_scope_digest,
    }
    return sha256_digest(canonical_json_bytes(document, limits=_LIMITS))


class PublishingRecoveryRequestIntent(_CanonicalModel):
    """Exact request body signed independently by the maker's IdP."""

    media_type: Literal[
        "application/vnd.control-assurance.publishing-recovery-request-intent.v2+json"
    ] = PUBLISHING_RECOVERY_REQUEST_INTENT_MEDIA_TYPE
    schema_version: Literal["2.0.0"] = RECOVERY_SCHEMA_VERSION
    tenant_id: str = Field(min_length=1, max_length=128)
    run_id: Digest
    control_id: str = Field(min_length=1, max_length=128)
    configuration_digest: Digest
    execution_plan_digest: Digest
    execution_identity_digest: Digest
    abandoned_attempt: AbandonedPublishingAttempt
    successor_claim: SuccessorLeaseClaim
    pam_scopes: tuple[PAMRecoveryScope, ...] = Field(min_length=1, max_length=32)
    pam_scope_digest: Digest
    pam_execution_binding_digest: Digest
    reason: Literal[
        "node-loss",
        "old-worker-terminated",
        "old-worker-unreachable",
        "operator-recovery",
    ]
    incident_reference_digest: Digest
    requested_at: datetime
    request_expires_at: datetime
    request_nonce: str = Field(min_length=64, max_length=64)

    _tenant_is_portable = field_validator("tenant_id")(_validate_portable_id)
    _control_is_portable = field_validator("control_id")(_validate_portable_id)
    _nonce_is_canonical = field_validator("request_nonce")(_validate_nonce)

    @field_validator("requested_at", "request_expires_at")
    @classmethod
    def validate_request_time(cls, value: datetime) -> datetime:
        return _validate_time(value, label="publishing recovery request time")

    @model_validator(mode="after")
    def validate_intent(self) -> PublishingRecoveryRequestIntent:
        old = self.abandoned_attempt
        new = self.successor_claim
        scopes = tuple(self.pam_scopes)
        scope_keys = tuple(scope.sort_key for scope in scopes)
        if (
            new.lease_fence != old.lease_fence + 1
            or new.attempt_count != old.attempt_count + 1
            or new.leased_at < old.lease_expires_at
            or self.requested_at < new.leased_at
            or new.worker_id == old.worker_id
            or new.worker_credential_digest == old.worker_credential_digest
            or new.lease_token_digest == old.lease_token_digest
        ):
            raise ValueError("old and successor recovery tuples are inconsistent")
        if (
            self.request_expires_at <= self.requested_at
            or self.request_expires_at - self.requested_at > MAX_RECOVERY_REQUEST_LIFETIME
        ):
            raise ValueError("publishing recovery request lifetime is invalid")
        if scope_keys != tuple(sorted(scope_keys)) or len(set(scope_keys)) != len(scope_keys):
            raise ValueError("PAM recovery scopes must be sorted and unique")
        expected_scope_digest = publishing_recovery_pam_scope_digest(scopes)
        if self.pam_scope_digest != expected_scope_digest:
            raise ValueError("PAM recovery scope digest is inconsistent")
        expected_binding = publishing_recovery_execution_binding_digest(
            tenant_id=self.tenant_id,
            run_id=self.run_id,
            execution_plan_digest=self.execution_plan_digest,
            execution_identity_digest=self.execution_identity_digest,
            abandoned_lease_fence=old.lease_fence,
            pam_scope_digest=self.pam_scope_digest,
        )
        if self.pam_execution_binding_digest != expected_binding:
            raise ValueError("PAM execution binding digest is inconsistent")
        return self


class PublishingRecoveryRequest(_CanonicalModel):
    """Maker-IdP-signed request binding one old attempt to one successor."""

    media_type: Literal["application/vnd.control-assurance.publishing-recovery-request.v2+json"] = (
        PUBLISHING_RECOVERY_REQUEST_MEDIA_TYPE
    )
    schema_version: Literal["2.0.0"] = RECOVERY_SCHEMA_VERSION
    intent_digest: Digest
    intent: PublishingRecoveryRequestIntent
    signed_maker_action: SignedRecoveryActorAction

    @model_validator(mode="after")
    def validate_request(self) -> PublishingRecoveryRequest:
        action = self.signed_maker_action.actor_action
        if (
            self.intent_digest != self.intent.digest
            or action.role != "maker"
            or action.action != "request"
            or action.tenant_id != self.intent.tenant_id
            or action.run_id != self.intent.run_id
            or action.action_digest != self.intent.digest
            or action.acted_at != self.intent.requested_at
            or action.expires_at != self.intent.request_expires_at
        ):
            raise ValueError("publishing recovery maker action does not bind the request")
        return self

    @property
    def tenant_id(self) -> str:
        return self.intent.tenant_id

    @property
    def run_id(self) -> str:
        return self.intent.run_id

    @property
    def control_id(self) -> str:
        return self.intent.control_id

    @property
    def configuration_digest(self) -> str:
        return self.intent.configuration_digest

    @property
    def execution_plan_digest(self) -> str:
        return self.intent.execution_plan_digest

    @property
    def execution_identity_digest(self) -> str:
        return self.intent.execution_identity_digest

    @property
    def abandoned_attempt(self) -> AbandonedPublishingAttempt:
        return self.intent.abandoned_attempt

    @property
    def successor_claim(self) -> SuccessorLeaseClaim:
        return self.intent.successor_claim

    @property
    def pam_scopes(self) -> tuple[PAMRecoveryScope, ...]:
        return self.intent.pam_scopes

    @property
    def pam_scope_digest(self) -> str:
        return self.intent.pam_scope_digest

    @property
    def pam_execution_binding_digest(self) -> str:
        return self.intent.pam_execution_binding_digest

    @property
    def requested_at(self) -> datetime:
        return self.intent.requested_at

    @property
    def request_expires_at(self) -> datetime:
        return self.intent.request_expires_at

    @property
    def requester(self) -> RecoveryActorAction:
        """Read-only migration view; v2 constructors require the signed envelope."""

        return self.signed_maker_action.actor_action


class WorkloadFenceLocator(_CanonicalModel):
    """Immutable workload coordinates captured before destructive fencing."""

    cluster_uid: str = Field(min_length=1, max_length=256)
    namespace: str = Field(min_length=1, max_length=128)
    service_account_uid: str = Field(min_length=1, max_length=256)
    pod_uid: str = Field(min_length=1, max_length=256)
    node_uid: str = Field(min_length=1, max_length=256)
    container_image_digest: Digest
    worker_id: str = Field(min_length=1, max_length=128)
    worker_credential_digest: Digest

    _cluster_is_safe = field_validator("cluster_uid")(_validate_safe_id)
    _namespace_is_portable = field_validator("namespace")(_validate_portable_id)
    _service_account_is_safe = field_validator("service_account_uid")(_validate_safe_id)
    _pod_is_safe = field_validator("pod_uid")(_validate_safe_id)
    _node_is_safe = field_validator("node_uid")(_validate_safe_id)
    _worker_is_portable = field_validator("worker_id")(_validate_portable_id)


class ComputeFenceAttestation(_CanonicalModel):
    """Hard proof that the old workload is absent or externally isolated."""

    media_type: Literal["application/vnd.control-assurance.compute-fence-attestation.v2+json"] = (
        COMPUTE_FENCE_ATTESTATION_MEDIA_TYPE
    )
    schema_version: Literal["2.0.0"] = RECOVERY_SCHEMA_VERSION
    recovery_request_digest: Digest
    tenant_id: str = Field(min_length=1, max_length=128)
    run_id: Digest
    abandoned_attempt_digest: Digest
    workload: WorkloadFenceLocator
    method: HardFenceMethod
    authority_classes_fenced: tuple[AuthorityClass, ...] = (
        "custody",
        "signing",
        "source",
    )
    old_process_absent: bool
    old_workload_egress_denied: bool
    node_reachable_at_observation: bool
    kubernetes_delete_operation_digest: Digest | None = None
    node_power_fence_operation_digest: Digest | None = None
    egress_policy_digest: Digest | None = None
    proof_media_type: str = Field(min_length=16, max_length=128)
    proof_digest: Digest
    relaunch_fence_operation_digest: Digest
    relaunch_fence_effective_at: datetime
    relaunch_fence_valid_until: datetime
    all_matching_workloads_fenced: Literal[True] = True
    relaunch_denied: Literal[True] = True
    fencing_controller_id: str = Field(min_length=1, max_length=256)
    fencing_controller_credential_digest: Digest
    fencing_authority_key_fingerprint: Digest
    fence_requested_at: datetime
    fence_effective_at: datetime
    isolation_observed_at: datetime
    attested_at: datetime

    _tenant_is_portable = field_validator("tenant_id")(_validate_portable_id)
    _proof_type_is_json = field_validator("proof_media_type")(_validate_media_type)
    _controller_is_safe = field_validator("fencing_controller_id")(_validate_safe_id)

    @field_validator(
        "fence_requested_at",
        "fence_effective_at",
        "relaunch_fence_effective_at",
        "relaunch_fence_valid_until",
        "isolation_observed_at",
        "attested_at",
    )
    @classmethod
    def validate_fence_time(cls, value: datetime) -> datetime:
        return _validate_time(value, label="compute fence time")

    @model_validator(mode="after")
    def validate_fence(self) -> ComputeFenceAttestation:
        if self.authority_classes_fenced != ("custody", "signing", "source"):
            raise ValueError("hard fence must cover every external authority class")
        if not (
            self.fence_requested_at
            <= self.relaunch_fence_effective_at
            <= self.fence_effective_at
            <= self.isolation_observed_at
            <= self.attested_at
            < self.relaunch_fence_valid_until
        ):
            raise ValueError("compute fence timeline is invalid")
        method_digests = (
            self.kubernetes_delete_operation_digest,
            self.node_power_fence_operation_digest,
            self.egress_policy_digest,
        )
        if sum(value is not None for value in method_digests) != 1:
            raise ValueError("hard fence must contain exactly one method proof")
        if self.method == "pod-runtime-terminated":
            valid = (
                self.kubernetes_delete_operation_digest is not None
                and self.node_reachable_at_observation
                and self.old_process_absent
                and self.node_power_fence_operation_digest is None
                and self.egress_policy_digest is None
            )
        elif self.method == "node-power-fenced":
            valid = (
                self.node_power_fence_operation_digest is not None
                and self.old_process_absent
                and self.kubernetes_delete_operation_digest is None
                and self.egress_policy_digest is None
            )
        else:
            valid = (
                self.egress_policy_digest is not None
                and self.old_workload_egress_denied
                and self.kubernetes_delete_operation_digest is None
                and self.node_power_fence_operation_digest is None
            )
        if not valid:
            raise ValueError("hard fence proof does not satisfy its method")
        return self


class PAMDrainAnchor(_CanonicalModel):
    """One exact run-scoped PAM lifecycle row included in the drain snapshot."""

    authority_class: AuthorityClass
    connector_id: str = Field(min_length=1, max_length=128)
    connector_request_digest: Digest
    scope_digest: Digest
    execution_binding_digest: Digest
    lifecycle_record_id: str = Field(min_length=1, max_length=256)
    lifecycle_record_digest: Digest
    lifecycle_sequence: int = Field(ge=1, le=2**53 - 1)
    lifecycle_revision: int = Field(ge=0, le=2**53 - 1)
    credential_reference_digest: Digest | None = None
    state: PAMLifecycleState
    expiry_basis: PAMExpiryBasis
    created_at: datetime
    issued_at: datetime | None = None
    expires_at: datetime | None = None
    revocation_confirmed_at: datetime | None = None
    maximum_residual_exposure_ends_at: datetime
    settled_at: datetime

    _connector_is_portable = field_validator("connector_id")(_validate_portable_id)
    _record_is_safe = field_validator("lifecycle_record_id")(_validate_safe_id)

    @field_validator(
        "created_at",
        "issued_at",
        "expires_at",
        "revocation_confirmed_at",
        "maximum_residual_exposure_ends_at",
        "settled_at",
    )
    @classmethod
    def validate_anchor_time(
        cls,
        value: datetime | None,
    ) -> datetime | None:
        if value is None:
            return None
        return _validate_time(value, label="PAM drain lifecycle time")

    @model_validator(mode="after")
    def validate_anchor(self) -> PAMDrainAnchor:
        optional_times = (
            self.issued_at,
            self.expires_at,
            self.revocation_confirmed_at,
        )
        if any(value is not None and value < self.created_at for value in optional_times):
            raise ValueError("PAM lifecycle event precedes record creation")
        if (
            self.maximum_residual_exposure_ends_at < self.created_at
            or self.settled_at < self.maximum_residual_exposure_ends_at
        ):
            raise ValueError("PAM residual exposure timeline is invalid")
        if any(value is not None and value > self.settled_at for value in optional_times):
            raise ValueError("PAM lifecycle event follows record settlement")
        if self.state == "revoked":
            valid = (
                self.expiry_basis == "confirmed-revocation"
                and self.credential_reference_digest is not None
                and self.issued_at is not None
                and self.revocation_confirmed_at is not None
                and self.issued_at
                <= self.revocation_confirmed_at
                <= self.maximum_residual_exposure_ends_at
            )
        elif self.state == "expired":
            valid = (
                self.expiry_basis in {"observed-expiry", "policy-upper-bound"}
                and self.credential_reference_digest is not None
                and self.issued_at is not None
                and self.expires_at is not None
                and self.revocation_confirmed_at is None
                and self.issued_at <= self.expires_at <= self.maximum_residual_exposure_ends_at
            )
        else:
            valid = (
                self.expiry_basis == "not-issued"
                and self.credential_reference_digest is None
                and self.issued_at is None
                and self.expires_at is None
                and self.revocation_confirmed_at is None
                and self.maximum_residual_exposure_ends_at == self.created_at
            )
        if not valid:
            raise ValueError("PAM lifecycle state lacks its required drain proof")
        return self

    @property
    def scope_key(self) -> tuple[str, str, str]:
        return (
            self.authority_class,
            self.connector_id,
            self.connector_request_digest,
        )

    @property
    def sort_key(self) -> tuple[str, str, str, int, str]:
        return (
            self.authority_class,
            self.connector_id,
            self.connector_request_digest,
            self.lifecycle_sequence,
            self.lifecycle_record_id,
        )


def credential_drain_lifecycle_snapshot_digest(
    *,
    scope_digest: str,
    execution_binding_digest: str,
    snapshot_high_watermark: int,
    anchors: tuple[PAMDrainAnchor, ...],
) -> str:
    """Content-address the exact ordered PAM rows used for the drain decision."""

    document = {
        "media_type": PAM_LIFECYCLE_SNAPSHOT_MEDIA_TYPE,
        "schema_version": RECOVERY_SCHEMA_VERSION,
        "scope_digest": scope_digest,
        "execution_binding_digest": execution_binding_digest,
        "snapshot_high_watermark": snapshot_high_watermark,
        "matching_record_count": len(anchors),
        "anchors": [anchor.model_dump(mode="json") for anchor in anchors],
    }
    return sha256_digest(canonical_json_bytes(document, limits=_LIMITS))


class CredentialDrainAttestation(_CanonicalModel):
    """Complete run-scoped PAM row set and conservative drain boundary."""

    media_type: Literal[
        "application/vnd.control-assurance.credential-drain-attestation.v2+json"
    ] = CREDENTIAL_DRAIN_ATTESTATION_MEDIA_TYPE
    schema_version: Literal["2.0.0"] = RECOVERY_SCHEMA_VERSION
    recovery_request_digest: Digest
    compute_fence_attestation_digest: Digest
    tenant_id: str = Field(min_length=1, max_length=128)
    run_id: Digest
    abandoned_attempt_digest: Digest
    scope_digest: Digest
    execution_binding_digest: Digest
    anchors: tuple[PAMDrainAnchor, ...] = Field(min_length=1, max_length=128)
    lifecycle_snapshot_digest: Digest
    lifecycle_record_count: int = Field(ge=1, le=128)
    snapshot_high_watermark: int = Field(ge=1, le=2**53 - 1)
    all_matching_records_settled: Literal[True] = True
    maximum_residual_exposure_ends_at: datetime
    fence_effective_at: datetime
    maximum_inflight_seconds: int = Field(ge=0, le=3600)
    clock_skew_seconds: int = Field(ge=0, le=300)
    post_fence_inflight_deadline: datetime
    drain_not_before: datetime
    checked_at: datetime
    attested_at: datetime
    issuance_fence_operation_digest: Digest
    issuance_fence_effective_at: datetime
    issuance_fence_valid_until: datetime
    issuance_fence_high_watermark: int = Field(ge=1, le=2**53 - 1)
    no_new_issuance: Literal[True] = True
    drain_controller_id: str = Field(min_length=1, max_length=256)
    drain_controller_credential_digest: Digest
    drain_authority_key_fingerprint: Digest
    pam_query_evidence_media_type: str = Field(min_length=16, max_length=128)
    pam_query_evidence_digest: Digest

    _tenant_is_portable = field_validator("tenant_id")(_validate_portable_id)
    _controller_is_safe = field_validator("drain_controller_id")(_validate_safe_id)
    _proof_type_is_json = field_validator("pam_query_evidence_media_type")(_validate_media_type)

    @field_validator(
        "maximum_residual_exposure_ends_at",
        "fence_effective_at",
        "post_fence_inflight_deadline",
        "drain_not_before",
        "checked_at",
        "attested_at",
        "issuance_fence_effective_at",
        "issuance_fence_valid_until",
    )
    @classmethod
    def validate_drain_time(cls, value: datetime) -> datetime:
        return _validate_time(value, label="credential drain time")

    @model_validator(mode="after")
    def validate_drain(self) -> CredentialDrainAttestation:
        anchors = tuple(self.anchors)
        keys = tuple(anchor.sort_key for anchor in anchors)
        if keys != tuple(sorted(keys)) or len(set(keys)) != len(keys):
            raise ValueError("PAM drain anchors must be sorted and unique")
        record_ids = tuple(anchor.lifecycle_record_id for anchor in anchors)
        record_digests = tuple(anchor.lifecycle_record_digest for anchor in anchors)
        sequences = tuple(anchor.lifecycle_sequence for anchor in anchors)
        if (
            len(set(record_ids)) != len(record_ids)
            or len(set(record_digests)) != len(record_digests)
            or len(set(sequences)) != len(sequences)
        ):
            raise ValueError("PAM drain lifecycle records must be globally unique")
        if self.lifecycle_record_count != len(anchors):
            raise ValueError("PAM lifecycle snapshot count is inconsistent")
        expected_snapshot_digest = credential_drain_lifecycle_snapshot_digest(
            scope_digest=self.scope_digest,
            execution_binding_digest=self.execution_binding_digest,
            snapshot_high_watermark=self.snapshot_high_watermark,
            anchors=anchors,
        )
        if self.lifecycle_snapshot_digest != expected_snapshot_digest:
            raise ValueError("PAM lifecycle snapshot digest is not content-derived")
        if any(
            anchor.scope_digest != self.scope_digest
            or anchor.execution_binding_digest != self.execution_binding_digest
            or anchor.lifecycle_sequence > self.snapshot_high_watermark
            or anchor.settled_at > self.checked_at
            for anchor in anchors
        ):
            raise ValueError("PAM anchor is outside the run execution binding")
        if (
            self.issuance_fence_high_watermark != self.snapshot_high_watermark
            or self.issuance_fence_effective_at > self.checked_at
            or self.attested_at >= self.issuance_fence_valid_until
        ):
            raise ValueError("PAM issuance fence does not seal the lifecycle snapshot")
        maximum_residual = max(anchor.maximum_residual_exposure_ends_at for anchor in anchors)
        expected_inflight_deadline = self.fence_effective_at + timedelta(
            seconds=self.maximum_inflight_seconds + self.clock_skew_seconds
        )
        expected_drain = max(maximum_residual, expected_inflight_deadline)
        if (
            self.maximum_residual_exposure_ends_at != maximum_residual
            or self.post_fence_inflight_deadline != expected_inflight_deadline
            or self.drain_not_before != expected_drain
            or self.checked_at < self.drain_not_before
            or self.attested_at < self.checked_at
        ):
            raise ValueError("credential drain boundary is inconsistent")
        return self


class SignedComputeFenceAttestation(_CanonicalModel):
    """Fence-controller signature over one exact hard-fence attestation."""

    media_type: Literal[
        "application/vnd.control-assurance.signed-compute-fence-attestation.v2+json"
    ] = SIGNED_COMPUTE_FENCE_ATTESTATION_MEDIA_TYPE
    schema_version: Literal["2.0.0"] = RECOVERY_SCHEMA_VERSION
    attestation_digest: Digest
    fencing_authority_key_fingerprint: Digest
    attestation: ComputeFenceAttestation
    authority_signature: DetachedSignature

    @model_validator(mode="after")
    def validate_envelope(self) -> SignedComputeFenceAttestation:
        if (
            self.attestation_digest != self.attestation.digest
            or self.fencing_authority_key_fingerprint
            != self.attestation.fencing_authority_key_fingerprint
        ):
            raise ValueError("signed compute fence envelope is inconsistent")
        return self


class SignedCredentialDrainAttestation(_CanonicalModel):
    """PAM-controller signature over one exact run-scoped drain snapshot."""

    media_type: Literal[
        "application/vnd.control-assurance.signed-credential-drain-attestation.v2+json"
    ] = SIGNED_CREDENTIAL_DRAIN_ATTESTATION_MEDIA_TYPE
    schema_version: Literal["2.0.0"] = RECOVERY_SCHEMA_VERSION
    attestation_digest: Digest
    drain_authority_key_fingerprint: Digest
    attestation: CredentialDrainAttestation
    authority_signature: DetachedSignature

    @model_validator(mode="after")
    def validate_envelope(self) -> SignedCredentialDrainAttestation:
        if (
            self.attestation_digest != self.attestation.digest
            or self.drain_authority_key_fingerprint
            != self.attestation.drain_authority_key_fingerprint
        ):
            raise ValueError("signed credential drain envelope is inconsistent")
        return self


def publishing_recovery_checker_action_digest(
    *,
    tenant_id: str,
    run_id: str,
    recovery_request_digest: str,
    signed_compute_fence_attestation_digest: str,
    signed_credential_drain_attestation_digest: str,
    abandoned_attempt_digest: str,
    successor_claim_digest: str,
    change_approval_digest: str,
    approved_at: datetime,
    not_before: datetime,
    issued_at: datetime,
    expires_at: datetime,
    authorization_nonce: str,
    recovery_authority_id: str,
    recovery_authority_key_fingerprint: str,
) -> str:
    """Content-address every security-relevant fact approved by the checker."""

    document = {
        "media_type": PUBLISHING_RECOVERY_APPROVAL_INTENT_MEDIA_TYPE,
        "schema_version": RECOVERY_SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "run_id": run_id,
        "recovery_request_digest": recovery_request_digest,
        "signed_compute_fence_attestation_digest": (signed_compute_fence_attestation_digest),
        "signed_credential_drain_attestation_digest": (signed_credential_drain_attestation_digest),
        "abandoned_attempt_digest": abandoned_attempt_digest,
        "successor_claim_digest": successor_claim_digest,
        "change_approval_digest": change_approval_digest,
        "approved_at": _json_time(
            approved_at,
            label="publishing recovery approval time",
        ),
        "not_before": _json_time(
            not_before,
            label="publishing recovery not-before time",
        ),
        "issued_at": _json_time(
            issued_at,
            label="publishing recovery issuance time",
        ),
        "expires_at": _json_time(
            expires_at,
            label="publishing recovery expiry time",
        ),
        "authorization_nonce": authorization_nonce,
        "recovery_authority_id": recovery_authority_id,
        "recovery_authority_key_fingerprint": recovery_authority_key_fingerprint,
    }
    return sha256_digest(canonical_json_bytes(document, limits=_LIMITS))


class PublishingRecoveryAuthorization(_CanonicalModel):
    """Checker-approved, one-time recovery right for one exact journal CAS."""

    media_type: Literal[
        "application/vnd.control-assurance.publishing-recovery-authorization.v2+json"
    ] = PUBLISHING_RECOVERY_AUTHORIZATION_MEDIA_TYPE
    schema_version: Literal["2.0.0"] = RECOVERY_SCHEMA_VERSION
    tenant_id: str = Field(min_length=1, max_length=128)
    run_id: Digest
    control_id: str = Field(min_length=1, max_length=128)
    configuration_digest: Digest
    execution_plan_digest: Digest
    execution_identity_digest: Digest
    recovery_request_digest: Digest
    recovery_request: PublishingRecoveryRequest
    compute_fence_attestation_digest: Digest
    signed_compute_fence_attestation_digest: Digest
    signed_compute_fence_attestation: SignedComputeFenceAttestation
    credential_drain_attestation_digest: Digest
    signed_credential_drain_attestation_digest: Digest
    signed_credential_drain_attestation: SignedCredentialDrainAttestation
    abandoned_attempt: AbandonedPublishingAttempt
    successor_claim: SuccessorLeaseClaim
    signed_checker_action_digest: Digest
    signed_checker_action: SignedRecoveryActorAction
    change_approval_digest: Digest
    approved_at: datetime
    not_before: datetime
    issued_at: datetime
    expires_at: datetime
    use_policy: Literal["single-use"] = "single-use"
    authorization_nonce: str = Field(min_length=64, max_length=64)
    recovery_authority_id: str = Field(min_length=1, max_length=256)
    recovery_authority_key_fingerprint: Digest

    _tenant_is_portable = field_validator("tenant_id")(_validate_portable_id)
    _control_is_portable = field_validator("control_id")(_validate_portable_id)
    _authority_is_safe = field_validator("recovery_authority_id")(_validate_safe_id)
    _nonce_is_canonical = field_validator("authorization_nonce")(_validate_nonce)

    @field_validator("approved_at", "not_before", "issued_at", "expires_at")
    @classmethod
    def validate_authorization_time(cls, value: datetime) -> datetime:
        return _validate_time(value, label="publishing recovery authorization time")

    @model_validator(mode="after")
    def validate_authorization(self) -> PublishingRecoveryAuthorization:
        request = self.recovery_request
        signed_fence = self.signed_compute_fence_attestation
        signed_drain = self.signed_credential_drain_attestation
        fence = signed_fence.attestation
        drain = signed_drain.attestation
        maker = request.signed_maker_action.actor_action
        checker = self.signed_checker_action.actor_action
        root_binding = (
            self.tenant_id,
            self.run_id,
            self.control_id,
            self.configuration_digest,
            self.execution_plan_digest,
            self.execution_identity_digest,
        )
        request_binding = (
            request.tenant_id,
            request.run_id,
            request.control_id,
            request.configuration_digest,
            request.execution_plan_digest,
            request.execution_identity_digest,
        )
        if root_binding != request_binding:
            raise ValueError("authorization and recovery request bindings differ")
        if (
            self.recovery_request_digest != request.digest
            or self.compute_fence_attestation_digest != fence.digest
            or self.signed_compute_fence_attestation_digest != signed_fence.digest
            or self.credential_drain_attestation_digest != drain.digest
            or self.signed_credential_drain_attestation_digest != signed_drain.digest
            or self.abandoned_attempt != request.abandoned_attempt
            or self.successor_claim != request.successor_claim
            or self.signed_checker_action_digest != self.signed_checker_action.digest
        ):
            raise ValueError("authorization embeds a substituted recovery object")
        old = self.abandoned_attempt
        new = self.successor_claim
        if (
            fence.recovery_request_digest != request.digest
            or fence.tenant_id != self.tenant_id
            or fence.run_id != self.run_id
            or fence.abandoned_attempt_digest != old.digest
            or fence.workload.worker_id != old.worker_id
            or fence.workload.worker_credential_digest != old.worker_credential_digest
        ):
            raise ValueError("compute fence does not identify the abandoned workload")
        if (
            drain.recovery_request_digest != request.digest
            or drain.compute_fence_attestation_digest != fence.digest
            or drain.tenant_id != self.tenant_id
            or drain.run_id != self.run_id
            or drain.abandoned_attempt_digest != old.digest
            or drain.scope_digest != request.pam_scope_digest
            or drain.execution_binding_digest != request.pam_execution_binding_digest
            or drain.fence_effective_at != fence.fence_effective_at
        ):
            raise ValueError("credential drain is outside the recovery binding")
        observed_scopes = {anchor.scope_key for anchor in drain.anchors}
        expected_scopes = {scope.sort_key for scope in request.pam_scopes}
        if observed_scopes != expected_scopes:
            raise ValueError("credential drain does not cover the exact PAM scope")
        expected_checker_action_digest = publishing_recovery_checker_action_digest(
            tenant_id=self.tenant_id,
            run_id=self.run_id,
            recovery_request_digest=self.recovery_request_digest,
            signed_compute_fence_attestation_digest=(self.signed_compute_fence_attestation_digest),
            signed_credential_drain_attestation_digest=(
                self.signed_credential_drain_attestation_digest
            ),
            abandoned_attempt_digest=self.abandoned_attempt.digest,
            successor_claim_digest=self.successor_claim.digest,
            change_approval_digest=self.change_approval_digest,
            approved_at=self.approved_at,
            not_before=self.not_before,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            authorization_nonce=self.authorization_nonce,
            recovery_authority_id=self.recovery_authority_id,
            recovery_authority_key_fingerprint=(self.recovery_authority_key_fingerprint),
        )
        if (
            maker.role != "maker"
            or maker.action != "request"
            or checker.role != "checker"
            or checker.action != "approve"
            or checker.tenant_id != self.tenant_id
            or checker.run_id != self.run_id
            or checker.action_digest != expected_checker_action_digest
            or checker.acted_at != self.approved_at
            or checker.expires_at < self.expires_at
        ):
            raise ValueError("recovery requires explicit maker and checker roles")
        if (
            maker.subject_id == checker.subject_id
            or maker.session_digest == checker.session_digest
            or maker.idp_key_fingerprint == checker.idp_key_fingerprint
        ):
            raise ValueError("maker and checker must use different people, sessions, and IdP keys")
        non_human_identities = {
            old.worker_id,
            new.worker_id,
            fence.fencing_controller_id,
            drain.drain_controller_id,
            self.recovery_authority_id,
        }
        if (
            len(non_human_identities) != 5
            or len(
                {
                    fence.fencing_authority_key_fingerprint,
                    drain.drain_authority_key_fingerprint,
                    self.recovery_authority_key_fingerprint,
                }
            )
            != 3
            or maker.subject_id in non_human_identities
            or checker.subject_id in non_human_identities
            or maker.idp_key_fingerprint
            in {
                fence.fencing_authority_key_fingerprint,
                drain.drain_authority_key_fingerprint,
                self.recovery_authority_key_fingerprint,
            }
            or checker.idp_key_fingerprint
            in {
                fence.fencing_authority_key_fingerprint,
                drain.drain_authority_key_fingerprint,
                self.recovery_authority_key_fingerprint,
            }
            or fence.fencing_controller_credential_digest
            in {
                old.worker_credential_digest,
                new.worker_credential_digest,
                drain.drain_controller_credential_digest,
            }
            or drain.drain_controller_credential_digest
            in {
                old.worker_credential_digest,
                new.worker_credential_digest,
            }
        ):
            raise ValueError("recovery duties or workload credentials are not separated")
        required_not_before = max(
            old.lease_expires_at,
            fence.isolation_observed_at,
            drain.drain_not_before,
        )
        if (
            fence.fence_requested_at < request.requested_at
            or fence.attested_at > drain.attested_at
            or drain.attested_at > self.approved_at
            or self.approved_at < required_not_before
            or self.not_before != required_not_before
            or self.issued_at < self.approved_at
            or self.expires_at <= self.issued_at
            or self.expires_at - self.issued_at > MAX_RECOVERY_AUTHORIZATION_LIFETIME
            or self.issued_at >= request.request_expires_at
            or self.expires_at > request.request_expires_at
            or self.not_before >= new.lease_expires_at
            or self.expires_at > new.lease_expires_at
            or fence.relaunch_fence_valid_until < new.lease_expires_at
            or drain.issuance_fence_valid_until < new.lease_expires_at
        ):
            raise ValueError("publishing recovery timeline or lifetime is invalid")
        return self

    @property
    def compute_fence_attestation(self) -> ComputeFenceAttestation:
        return self.signed_compute_fence_attestation.attestation

    @property
    def credential_drain_attestation(self) -> CredentialDrainAttestation:
        return self.signed_credential_drain_attestation.attestation

    @property
    def maker(self) -> RecoveryActorAction:
        return self.recovery_request.signed_maker_action.actor_action

    @property
    def checker(self) -> RecoveryActorAction:
        return self.signed_checker_action.actor_action

    @property
    def authorization_id(self) -> str:
        """Content address used as the durable one-time consumption key."""

        return self.digest


class SignedPublishingRecoveryAuthorization(_CanonicalModel):
    """Canonical authorization plus a detached dedicated-authority signature."""

    media_type: Literal["application/vnd.control-assurance.signed-publishing-recovery.v2+json"] = (
        SIGNED_PUBLISHING_RECOVERY_MEDIA_TYPE
    )
    schema_version: Literal["2.0.0"] = RECOVERY_SCHEMA_VERSION
    authorization_id: Digest
    recovery_authority_key_fingerprint: Digest
    authorization: PublishingRecoveryAuthorization
    authority_signature: DetachedSignature

    @model_validator(mode="after")
    def validate_envelope(self) -> SignedPublishingRecoveryAuthorization:
        if (
            self.authorization_id != self.authorization.authorization_id
            or self.recovery_authority_key_fingerprint
            != self.authorization.recovery_authority_key_fingerprint
        ):
            raise ValueError("signed recovery envelope is inconsistent")
        return self


class PublishingRecoveryJournalExpectation(_CanonicalModel):
    """Journal-backed fields plus the successor CAS inputs checked at use time.

    The execution journal does not currently persist worker credential digests
    or scheduler lease timestamps.  Those remain signed scheduler/recovery
    authority facts in :class:`PublishingRecoveryRequest`; this expectation
    intentionally contains only values the current journal row or the
    successor CAS call can independently supply.
    """

    media_type: Literal[
        "application/vnd.control-assurance.publishing-recovery-expectation.v2+json"
    ] = PUBLISHING_RECOVERY_EXPECTATION_MEDIA_TYPE
    schema_version: Literal["2.0.0"] = RECOVERY_SCHEMA_VERSION
    tenant_id: str = Field(min_length=1, max_length=128)
    run_id: Digest
    control_id: str = Field(min_length=1, max_length=128)
    configuration_digest: Digest
    execution_plan_digest: Digest
    execution_identity_digest: Digest
    recovery_request_digest: Digest
    pam_scope_digest: Digest
    pam_execution_binding_digest: Digest
    pam_snapshot_high_watermark: int = Field(ge=1, le=2**53 - 1)
    pam_lifecycle_record_count: int = Field(ge=1, le=128)
    relaunch_fence_operation_digest: Digest
    issuance_fence_operation_digest: Digest
    abandoned_lease_fence: int = Field(ge=1, le=2**63 - 2)
    abandoned_attempt_count: int = Field(ge=1, le=32)
    abandoned_attempt_revision: Literal[1] = 1
    abandoned_worker_id: str = Field(min_length=1, max_length=128)
    abandoned_lease_token_digest: Digest
    abandoned_publishing_at: datetime
    successor_lease_fence: int = Field(ge=2, le=2**63 - 1)
    successor_attempt_count: int = Field(ge=2, le=32)
    successor_worker_id: str = Field(min_length=1, max_length=128)
    successor_lease_token_digest: Digest

    _tenant_is_portable = field_validator("tenant_id")(_validate_portable_id)
    _control_is_portable = field_validator("control_id")(_validate_portable_id)
    _old_worker_is_portable = field_validator("abandoned_worker_id")(_validate_portable_id)
    _new_worker_is_portable = field_validator("successor_worker_id")(_validate_portable_id)

    @field_validator("abandoned_publishing_at")
    @classmethod
    def validate_publishing_time(cls, value: datetime) -> datetime:
        return _validate_time(value, label="journal publishing time")

    @model_validator(mode="after")
    def validate_fence_progression(self) -> PublishingRecoveryJournalExpectation:
        if (
            self.successor_lease_fence != self.abandoned_lease_fence + 1
            or self.successor_attempt_count != self.abandoned_attempt_count + 1
        ):
            raise ValueError("journal recovery expectation does not advance once")
        return self


class PublishingRecoveryUseClaim(_CanonicalModel):
    """Value passed to an atomic registry before the journal transition commits."""

    media_type: Literal["application/vnd.control-assurance.publishing-recovery-use.v2+json"] = (
        PUBLISHING_RECOVERY_USE_MEDIA_TYPE
    )
    schema_version: Literal["2.0.0"] = RECOVERY_SCHEMA_VERSION
    authorization_id: Digest
    tenant_id: str = Field(min_length=1, max_length=128)
    run_id: Digest
    recovery_request_digest: Digest
    abandoned_attempt_digest: Digest
    successor_claim_digest: Digest
    execution_plan_digest: Digest
    execution_identity_digest: Digest
    pam_scope_digest: Digest
    pam_snapshot_high_watermark: int = Field(ge=1, le=2**53 - 1)
    pam_lifecycle_record_count: int = Field(ge=1, le=128)
    relaunch_fence_operation_digest: Digest
    issuance_fence_operation_digest: Digest
    consumed_at: datetime
    authorization_expires_at: datetime

    _tenant_is_portable = field_validator("tenant_id")(_validate_portable_id)

    @field_validator("consumed_at", "authorization_expires_at")
    @classmethod
    def validate_use_time(cls, value: datetime) -> datetime:
        return _validate_time(value, label="publishing recovery use time")

    @model_validator(mode="after")
    def validate_use_window(self) -> PublishingRecoveryUseClaim:
        if self.consumed_at >= self.authorization_expires_at:
            raise ValueError("recovery use occurs after authorization expiry")
        return self


class PublishingRecoveryUseRegistry(Protocol):
    """Atomic replay boundary implemented by the journal transaction."""

    def consume_once(self, claim: PublishingRecoveryUseClaim) -> bool:
        """Return true only for the first durable use of ``authorization_id``."""
        ...


@dataclass(frozen=True, slots=True)
class VerifiedPublishingRecoveryAuthorization:
    """Pinned-key verified, context-bound, atomically consumed authorization."""

    envelope: SignedPublishingRecoveryAuthorization
    envelope_bytes: bytes
    journal_expectation: PublishingRecoveryJournalExpectation
    use_claim: PublishingRecoveryUseClaim

    def __post_init__(self) -> None:
        if (
            type(self.envelope) is not SignedPublishingRecoveryAuthorization
            or type(self.envelope_bytes) is not bytes
            or type(self.journal_expectation) is not PublishingRecoveryJournalExpectation
            or type(self.use_claim) is not PublishingRecoveryUseClaim
            or self.envelope.canonical_bytes() != self.envelope_bytes
            or self.use_claim.authorization_id != self.envelope.authorization_id
        ):
            raise TypeError("verified publishing recovery state is invalid")

    @property
    def authorization(self) -> PublishingRecoveryAuthorization:
        return self.envelope.authorization

    @property
    def digest(self) -> str:
        return self.envelope.digest


def _verifier_material(
    verifier: LeaseAuthorityVerifier,
) -> tuple[str, bytes, str]:
    try:
        key_id = verifier.key_id
        public_key = verifier.public_key_bytes
    except Exception:
        raise PublishingRecoveryError("authority-unavailable") from None
    if (
        type(key_id) is not str
        or _SAFE_ID_RE.fullmatch(key_id) is None
        or type(public_key) is not bytes
        or len(public_key) != 32
    ):
        raise PublishingRecoveryError("authority-invalid")
    return key_id, public_key, sha256_digest(public_key)


def _sign_payload(
    payload: bytes,
    *,
    expected_fingerprint: str,
    signature_prefix: bytes,
    signer: ReceiptSigner,
) -> DetachedSignature:
    before = _verifier_material(signer)
    if expected_fingerprint != before[2]:
        raise PublishingRecoveryError("authority-mismatch")
    try:
        signature = signer.sign(signature_prefix + payload)
    except Exception:
        raise PublishingRecoveryError("signing-failed") from None
    if type(signature) is not DetachedSignature:
        raise PublishingRecoveryError("signature-invalid")
    if _verifier_material(signer) != before:
        raise PublishingRecoveryError("authority-changed")
    return signature


def _verify_payload_signature(
    payload: bytes,
    signature: DetachedSignature,
    *,
    expected_fingerprint: str,
    signature_prefix: bytes,
    verifier: LeaseAuthorityVerifier,
    invalid_code: str,
) -> None:
    before = _verifier_material(verifier)
    try:
        encoded = signature.signature.encode("ascii", errors="strict")
        decoded = base64.b64decode(encoded, validate=True)
        if (
            signature.key_id != before[0]
            or signature.algorithm != "ed25519"
            or len(decoded) != 64
            or base64.b64encode(decoded) != encoded
            or expected_fingerprint != before[2]
        ):
            raise ValueError
        Ed25519PublicKey.from_public_bytes(before[1]).verify(
            decoded,
            signature_prefix + payload,
        )
    except (
        InvalidSignature,
        UnicodeEncodeError,
        ValueError,
        TypeError,
        binascii.Error,
    ):
        raise PublishingRecoveryError(invalid_code) from None
    if _verifier_material(verifier) != before:
        raise PublishingRecoveryError("authority-changed")


def _verify_compute_fence_signature(
    envelope: SignedComputeFenceAttestation,
    *,
    verifier: LeaseAuthorityVerifier,
) -> None:
    _verify_payload_signature(
        envelope.attestation.canonical_bytes(),
        envelope.authority_signature,
        expected_fingerprint=envelope.fencing_authority_key_fingerprint,
        signature_prefix=_COMPUTE_FENCE_SIGNATURE_PREFIX,
        verifier=verifier,
        invalid_code="fence-signature-invalid",
    )


def _verify_credential_drain_signature(
    envelope: SignedCredentialDrainAttestation,
    *,
    verifier: LeaseAuthorityVerifier,
) -> None:
    _verify_payload_signature(
        envelope.attestation.canonical_bytes(),
        envelope.authority_signature,
        expected_fingerprint=envelope.drain_authority_key_fingerprint,
        signature_prefix=_CREDENTIAL_DRAIN_SIGNATURE_PREFIX,
        verifier=verifier,
        invalid_code="drain-signature-invalid",
    )


def _verify_authorization_signature(
    envelope: SignedPublishingRecoveryAuthorization,
    *,
    verifier: LeaseAuthorityVerifier,
) -> None:
    _verify_payload_signature(
        envelope.authorization.canonical_bytes(),
        envelope.authority_signature,
        expected_fingerprint=envelope.recovery_authority_key_fingerprint,
        signature_prefix=_AUTHORIZATION_SIGNATURE_PREFIX,
        verifier=verifier,
        invalid_code="signature-invalid",
    )


def _actor_signature_prefix(action: RecoveryActorAction) -> bytes:
    if (action.role, action.action) == ("maker", "request"):
        return _MAKER_ACTION_SIGNATURE_PREFIX
    if (action.role, action.action) == ("checker", "approve"):
        return _CHECKER_ACTION_SIGNATURE_PREFIX
    raise PublishingRecoveryError("actor-action-invalid")


def _verify_actor_action_signature(
    envelope: SignedRecoveryActorAction,
    *,
    verifier: LeaseAuthorityVerifier,
    invalid_code: str,
) -> None:
    _verify_payload_signature(
        envelope.actor_action.canonical_bytes(),
        envelope.authority_signature,
        expected_fingerprint=envelope.idp_key_fingerprint,
        signature_prefix=_actor_signature_prefix(envelope.actor_action),
        verifier=verifier,
        invalid_code=invalid_code,
    )


def _assert_actor_action_context(
    envelope: SignedRecoveryActorAction,
    *,
    expected_role: ActorRole,
    expected_action: ActorAction,
    expected_action_digest: str,
    tenant_id: str,
    run_id: str,
    expected_issuer_id: str,
    expected_audience: str,
    observed_at: datetime,
    invalid_code: str,
) -> None:
    action = envelope.actor_action
    if (
        action.role != expected_role
        or action.action != expected_action
        or action.action_digest != expected_action_digest
        or action.tenant_id != tenant_id
        or action.run_id != run_id
        or action.issuer_id != expected_issuer_id
        or action.audience != expected_audience
        or observed_at < action.acted_at
        or observed_at >= action.expires_at
    ):
        raise PublishingRecoveryError(invalid_code)


def issue_recovery_actor_action(
    action: RecoveryActorAction,
    *,
    signer: ReceiptSigner,
) -> SignedRecoveryActorAction:
    """Sign one exact maker/checker action with its independent IdP key."""

    if type(action) is not RecoveryActorAction:
        raise TypeError("recovery actor action must be exact")
    signature = _sign_payload(
        action.canonical_bytes(),
        expected_fingerprint=action.idp_key_fingerprint,
        signature_prefix=_actor_signature_prefix(action),
        signer=signer,
    )
    try:
        envelope = SignedRecoveryActorAction(
            actor_action_digest=action.digest,
            idp_key_fingerprint=action.idp_key_fingerprint,
            actor_action=action,
            authority_signature=signature,
        )
    except (TypeError, ValueError):
        raise PublishingRecoveryError("envelope-invalid") from None
    _verify_actor_action_signature(
        envelope,
        verifier=signer,
        invalid_code="actor-signature-invalid",
    )
    return envelope


def issue_compute_fence_attestation(
    attestation: ComputeFenceAttestation,
    *,
    signer: ReceiptSigner,
) -> SignedComputeFenceAttestation:
    """Sign one hard-fence proof with the dedicated fencing controller key."""

    if type(attestation) is not ComputeFenceAttestation:
        raise TypeError("compute fence attestation must be exact")
    signature = _sign_payload(
        attestation.canonical_bytes(),
        expected_fingerprint=attestation.fencing_authority_key_fingerprint,
        signature_prefix=_COMPUTE_FENCE_SIGNATURE_PREFIX,
        signer=signer,
    )
    try:
        envelope = SignedComputeFenceAttestation(
            attestation_digest=attestation.digest,
            fencing_authority_key_fingerprint=(attestation.fencing_authority_key_fingerprint),
            attestation=attestation,
            authority_signature=signature,
        )
    except (TypeError, ValueError):
        raise PublishingRecoveryError("envelope-invalid") from None
    _verify_compute_fence_signature(envelope, verifier=signer)
    return envelope


def issue_credential_drain_attestation(
    attestation: CredentialDrainAttestation,
    *,
    signer: ReceiptSigner,
) -> SignedCredentialDrainAttestation:
    """Sign one complete PAM drain snapshot with its controller key."""

    if type(attestation) is not CredentialDrainAttestation:
        raise TypeError("credential drain attestation must be exact")
    signature = _sign_payload(
        attestation.canonical_bytes(),
        expected_fingerprint=attestation.drain_authority_key_fingerprint,
        signature_prefix=_CREDENTIAL_DRAIN_SIGNATURE_PREFIX,
        signer=signer,
    )
    try:
        envelope = SignedCredentialDrainAttestation(
            attestation_digest=attestation.digest,
            drain_authority_key_fingerprint=(attestation.drain_authority_key_fingerprint),
            attestation=attestation,
            authority_signature=signature,
        )
    except (TypeError, ValueError):
        raise PublishingRecoveryError("envelope-invalid") from None
    _verify_credential_drain_signature(envelope, verifier=signer)
    return envelope


def issue_publishing_recovery_authorization(
    authorization: PublishingRecoveryAuthorization,
    *,
    signer: ReceiptSigner,
    fence_verifier: LeaseAuthorityVerifier,
    drain_verifier: LeaseAuthorityVerifier,
    maker_verifier: LeaseAuthorityVerifier,
    checker_verifier: LeaseAuthorityVerifier,
    actor_policy: RecoveryActorVerificationPolicy,
) -> SignedPublishingRecoveryAuthorization:
    """Sign one fully validated recovery authorization."""

    if type(authorization) is not PublishingRecoveryAuthorization:
        raise TypeError("publishing recovery authorization must be exact")
    if type(actor_policy) is not RecoveryActorVerificationPolicy:
        raise TypeError("recovery actor verification policy must be exact")
    _verify_actor_action_signature(
        authorization.recovery_request.signed_maker_action,
        verifier=maker_verifier,
        invalid_code="maker-signature-invalid",
    )
    _verify_actor_action_signature(
        authorization.signed_checker_action,
        verifier=checker_verifier,
        invalid_code="checker-signature-invalid",
    )
    expected_checker_action_digest = publishing_recovery_checker_action_digest(
        tenant_id=authorization.tenant_id,
        run_id=authorization.run_id,
        recovery_request_digest=authorization.recovery_request_digest,
        signed_compute_fence_attestation_digest=(
            authorization.signed_compute_fence_attestation_digest
        ),
        signed_credential_drain_attestation_digest=(
            authorization.signed_credential_drain_attestation_digest
        ),
        abandoned_attempt_digest=authorization.abandoned_attempt.digest,
        successor_claim_digest=authorization.successor_claim.digest,
        change_approval_digest=authorization.change_approval_digest,
        approved_at=authorization.approved_at,
        not_before=authorization.not_before,
        issued_at=authorization.issued_at,
        expires_at=authorization.expires_at,
        authorization_nonce=authorization.authorization_nonce,
        recovery_authority_id=authorization.recovery_authority_id,
        recovery_authority_key_fingerprint=(authorization.recovery_authority_key_fingerprint),
    )
    _assert_actor_action_context(
        authorization.recovery_request.signed_maker_action,
        expected_role="maker",
        expected_action="request",
        expected_action_digest=authorization.recovery_request.intent_digest,
        tenant_id=authorization.tenant_id,
        run_id=authorization.run_id,
        expected_issuer_id=actor_policy.maker_issuer_id,
        expected_audience=actor_policy.audience,
        observed_at=authorization.issued_at,
        invalid_code="maker-action-invalid",
    )
    _assert_actor_action_context(
        authorization.signed_checker_action,
        expected_role="checker",
        expected_action="approve",
        expected_action_digest=expected_checker_action_digest,
        tenant_id=authorization.tenant_id,
        run_id=authorization.run_id,
        expected_issuer_id=actor_policy.checker_issuer_id,
        expected_audience=actor_policy.audience,
        observed_at=authorization.issued_at,
        invalid_code="checker-action-invalid",
    )
    _verify_compute_fence_signature(
        authorization.signed_compute_fence_attestation,
        verifier=fence_verifier,
    )
    _verify_credential_drain_signature(
        authorization.signed_credential_drain_attestation,
        verifier=drain_verifier,
    )
    signature = _sign_payload(
        authorization.canonical_bytes(),
        expected_fingerprint=authorization.recovery_authority_key_fingerprint,
        signature_prefix=_AUTHORIZATION_SIGNATURE_PREFIX,
        signer=signer,
    )
    try:
        envelope = SignedPublishingRecoveryAuthorization(
            authorization_id=authorization.authorization_id,
            recovery_authority_key_fingerprint=(authorization.recovery_authority_key_fingerprint),
            authorization=authorization,
            authority_signature=signature,
        )
    except (TypeError, ValueError):
        raise PublishingRecoveryError("envelope-invalid") from None
    _verify_authorization_signature(envelope, verifier=signer)
    return envelope


def _assert_journal_binding(
    authorization: PublishingRecoveryAuthorization,
    expectation: PublishingRecoveryJournalExpectation,
) -> None:
    request = authorization.recovery_request
    old = authorization.abandoned_attempt
    new = authorization.successor_claim
    observed = (
        authorization.tenant_id,
        authorization.run_id,
        authorization.control_id,
        authorization.configuration_digest,
        authorization.execution_plan_digest,
        authorization.execution_identity_digest,
        authorization.recovery_request_digest,
        request.pam_scope_digest,
        request.pam_execution_binding_digest,
        authorization.credential_drain_attestation.snapshot_high_watermark,
        authorization.credential_drain_attestation.lifecycle_record_count,
        authorization.compute_fence_attestation.relaunch_fence_operation_digest,
        authorization.credential_drain_attestation.issuance_fence_operation_digest,
        old.lease_fence,
        old.attempt_count,
        old.attempt_revision,
        old.worker_id,
        old.lease_token_digest,
        old.publishing_at,
        new.lease_fence,
        new.attempt_count,
        new.worker_id,
        new.lease_token_digest,
    )
    expected = (
        expectation.tenant_id,
        expectation.run_id,
        expectation.control_id,
        expectation.configuration_digest,
        expectation.execution_plan_digest,
        expectation.execution_identity_digest,
        expectation.recovery_request_digest,
        expectation.pam_scope_digest,
        expectation.pam_execution_binding_digest,
        expectation.pam_snapshot_high_watermark,
        expectation.pam_lifecycle_record_count,
        expectation.relaunch_fence_operation_digest,
        expectation.issuance_fence_operation_digest,
        expectation.abandoned_lease_fence,
        expectation.abandoned_attempt_count,
        expectation.abandoned_attempt_revision,
        expectation.abandoned_worker_id,
        expectation.abandoned_lease_token_digest,
        expectation.abandoned_publishing_at,
        expectation.successor_lease_fence,
        expectation.successor_attempt_count,
        expectation.successor_worker_id,
        expectation.successor_lease_token_digest,
    )
    if observed != expected:
        raise PublishingRecoveryError("journal-binding-mismatch")


def verify_publishing_recovery_authorization(
    value: bytes,
    *,
    verifier: LeaseAuthorityVerifier,
    fence_verifier: LeaseAuthorityVerifier,
    drain_verifier: LeaseAuthorityVerifier,
    maker_verifier: LeaseAuthorityVerifier,
    checker_verifier: LeaseAuthorityVerifier,
    actor_policy: RecoveryActorVerificationPolicy,
    now: datetime,
    journal_expectation: PublishingRecoveryJournalExpectation,
    use_registry: PublishingRecoveryUseRegistry,
) -> VerifiedPublishingRecoveryAuthorization:
    """Verify, context-bind, and atomically consume one signed authorization."""

    observed_at = utc_second(now, label="publishing recovery verification time")
    if type(journal_expectation) is not PublishingRecoveryJournalExpectation:
        raise TypeError("publishing recovery journal expectation must be exact")
    if type(actor_policy) is not RecoveryActorVerificationPolicy:
        raise TypeError("recovery actor verification policy must be exact")
    if type(value) is not bytes or not value or len(value) > MAX_SIGNED_PUBLISHING_RECOVERY_BYTES:
        raise PublishingRecoveryError("document-invalid")
    try:
        document = strict_json_loads(value, limits=_LIMITS)
        envelope = SignedPublishingRecoveryAuthorization.model_validate_json(
            value,
            strict=True,
        )
        canonical = envelope.canonical_bytes()
    except (StrictJSONError, TypeError, ValueError):
        raise PublishingRecoveryError("document-invalid") from None
    if not isinstance(document, dict) or canonical != value:
        raise PublishingRecoveryError("document-noncanonical")
    _verify_authorization_signature(envelope, verifier=verifier)
    authorization = envelope.authorization
    _verify_actor_action_signature(
        authorization.recovery_request.signed_maker_action,
        verifier=maker_verifier,
        invalid_code="maker-signature-invalid",
    )
    _verify_actor_action_signature(
        authorization.signed_checker_action,
        verifier=checker_verifier,
        invalid_code="checker-signature-invalid",
    )
    _verify_compute_fence_signature(
        authorization.signed_compute_fence_attestation,
        verifier=fence_verifier,
    )
    _verify_credential_drain_signature(
        authorization.signed_credential_drain_attestation,
        verifier=drain_verifier,
    )
    if observed_at < authorization.not_before or observed_at < authorization.issued_at:
        raise PublishingRecoveryError("authorization-not-yet-valid")
    if observed_at >= authorization.recovery_request.request_expires_at:
        raise PublishingRecoveryError("recovery-request-expired")
    if observed_at >= authorization.successor_claim.lease_expires_at:
        raise PublishingRecoveryError("successor-lease-expired")
    if observed_at >= authorization.expires_at:
        raise PublishingRecoveryError("authorization-expired")
    if observed_at >= authorization.compute_fence_attestation.relaunch_fence_valid_until:
        raise PublishingRecoveryError("compute-fence-expired")
    if observed_at >= authorization.credential_drain_attestation.issuance_fence_valid_until:
        raise PublishingRecoveryError("issuance-fence-expired")
    expected_checker_action_digest = publishing_recovery_checker_action_digest(
        tenant_id=authorization.tenant_id,
        run_id=authorization.run_id,
        recovery_request_digest=authorization.recovery_request_digest,
        signed_compute_fence_attestation_digest=(
            authorization.signed_compute_fence_attestation_digest
        ),
        signed_credential_drain_attestation_digest=(
            authorization.signed_credential_drain_attestation_digest
        ),
        abandoned_attempt_digest=authorization.abandoned_attempt.digest,
        successor_claim_digest=authorization.successor_claim.digest,
        change_approval_digest=authorization.change_approval_digest,
        approved_at=authorization.approved_at,
        not_before=authorization.not_before,
        issued_at=authorization.issued_at,
        expires_at=authorization.expires_at,
        authorization_nonce=authorization.authorization_nonce,
        recovery_authority_id=authorization.recovery_authority_id,
        recovery_authority_key_fingerprint=(authorization.recovery_authority_key_fingerprint),
    )
    _assert_actor_action_context(
        authorization.recovery_request.signed_maker_action,
        expected_role="maker",
        expected_action="request",
        expected_action_digest=authorization.recovery_request.intent_digest,
        tenant_id=authorization.tenant_id,
        run_id=authorization.run_id,
        expected_issuer_id=actor_policy.maker_issuer_id,
        expected_audience=actor_policy.audience,
        observed_at=observed_at,
        invalid_code="maker-action-invalid",
    )
    _assert_actor_action_context(
        authorization.signed_checker_action,
        expected_role="checker",
        expected_action="approve",
        expected_action_digest=expected_checker_action_digest,
        tenant_id=authorization.tenant_id,
        run_id=authorization.run_id,
        expected_issuer_id=actor_policy.checker_issuer_id,
        expected_audience=actor_policy.audience,
        observed_at=observed_at,
        invalid_code="checker-action-invalid",
    )
    _assert_journal_binding(authorization, journal_expectation)
    use_claim = PublishingRecoveryUseClaim(
        authorization_id=envelope.authorization_id,
        tenant_id=authorization.tenant_id,
        run_id=authorization.run_id,
        recovery_request_digest=authorization.recovery_request_digest,
        abandoned_attempt_digest=authorization.abandoned_attempt.digest,
        successor_claim_digest=authorization.successor_claim.digest,
        execution_plan_digest=authorization.execution_plan_digest,
        execution_identity_digest=authorization.execution_identity_digest,
        pam_scope_digest=authorization.recovery_request.pam_scope_digest,
        pam_snapshot_high_watermark=(
            authorization.credential_drain_attestation.snapshot_high_watermark
        ),
        pam_lifecycle_record_count=(
            authorization.credential_drain_attestation.lifecycle_record_count
        ),
        relaunch_fence_operation_digest=(
            authorization.compute_fence_attestation.relaunch_fence_operation_digest
        ),
        issuance_fence_operation_digest=(
            authorization.credential_drain_attestation.issuance_fence_operation_digest
        ),
        consumed_at=observed_at,
        authorization_expires_at=authorization.expires_at,
    )
    try:
        consumed = use_registry.consume_once(use_claim)
    except Exception:
        raise PublishingRecoveryError("consumption-unavailable") from None
    if type(consumed) is not bool:
        raise PublishingRecoveryError("consumption-invalid")
    if not consumed:
        raise PublishingRecoveryError("authorization-consumed")
    return VerifiedPublishingRecoveryAuthorization(
        envelope=envelope,
        envelope_bytes=value,
        journal_expectation=journal_expectation,
        use_claim=use_claim,
    )


__all__ = [
    "COMPUTE_FENCE_ATTESTATION_MEDIA_TYPE",
    "COMPUTE_FENCE_SIGNATURE_DOMAIN",
    "CREDENTIAL_DRAIN_ATTESTATION_MEDIA_TYPE",
    "CREDENTIAL_DRAIN_SIGNATURE_DOMAIN",
    "MAX_ACTOR_ACTION_LIFETIME",
    "MAX_RECOVERY_AUTHORIZATION_LIFETIME",
    "MAX_RECOVERY_REQUEST_LIFETIME",
    "MAX_SIGNED_PUBLISHING_RECOVERY_BYTES",
    "PAM_LIFECYCLE_SNAPSHOT_MEDIA_TYPE",
    "PAM_RECOVERY_SCOPE_MEDIA_TYPE",
    "PUBLISHING_RECOVERY_APPROVAL_INTENT_MEDIA_TYPE",
    "PUBLISHING_RECOVERY_AUTHORIZATION_MEDIA_TYPE",
    "PUBLISHING_RECOVERY_EXECUTION_BINDING_MEDIA_TYPE",
    "PUBLISHING_RECOVERY_EXPECTATION_MEDIA_TYPE",
    "PUBLISHING_RECOVERY_REQUEST_INTENT_MEDIA_TYPE",
    "PUBLISHING_RECOVERY_REQUEST_MEDIA_TYPE",
    "PUBLISHING_RECOVERY_SCHEMA_VERSION",
    "PUBLISHING_RECOVERY_SIGNATURE_DOMAIN",
    "PUBLISHING_RECOVERY_USE_MEDIA_TYPE",
    "RECOVERY_ACTOR_ACTION_MEDIA_TYPE",
    "RECOVERY_CHECKER_ACTION_SIGNATURE_DOMAIN",
    "RECOVERY_MAKER_ACTION_SIGNATURE_DOMAIN",
    "RECOVERY_SCHEMA_VERSION",
    "SIGNED_COMPUTE_FENCE_ATTESTATION_MEDIA_TYPE",
    "SIGNED_CREDENTIAL_DRAIN_ATTESTATION_MEDIA_TYPE",
    "SIGNED_PUBLISHING_RECOVERY_MEDIA_TYPE",
    "SIGNED_RECOVERY_ACTOR_ACTION_MEDIA_TYPE",
    "AbandonedPublishingAttempt",
    "ActorAction",
    "ActorRole",
    "AuthorityClass",
    "ComputeFenceAttestation",
    "CredentialDrainAttestation",
    "PAMDrainAnchor",
    "PAMRecoveryScope",
    "PublishingRecoveryAuthorization",
    "PublishingRecoveryError",
    "PublishingRecoveryJournalExpectation",
    "PublishingRecoveryRequest",
    "PublishingRecoveryRequestIntent",
    "PublishingRecoveryUseClaim",
    "PublishingRecoveryUseRegistry",
    "RecoveryActorAction",
    "RecoveryActorAssertion",
    "RecoveryActorVerificationPolicy",
    "SignedComputeFenceAttestation",
    "SignedCredentialDrainAttestation",
    "SignedPublishingRecoveryAuthorization",
    "SignedRecoveryActorAction",
    "SuccessorLeaseClaim",
    "VerifiedPublishingRecoveryAuthorization",
    "WorkloadFenceLocator",
    "credential_drain_lifecycle_snapshot_digest",
    "issue_compute_fence_attestation",
    "issue_credential_drain_attestation",
    "issue_publishing_recovery_authorization",
    "issue_recovery_actor_action",
    "migrate_legacy_pam_recovery_scopes",
    "migrate_recovery_actor_assertion",
    "publishing_recovery_checker_action_digest",
    "publishing_recovery_execution_binding_digest",
    "publishing_recovery_pam_scope_digest",
    "verify_publishing_recovery_authorization",
]
