from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from assurance_lab.evidence.admission import DetachedSignature
from assurance_lab.runtime.execution_recovery import (
    PUBLISHING_RECOVERY_SIGNATURE_DOMAIN,
    RECOVERY_MAKER_ACTION_SIGNATURE_DOMAIN,
    AbandonedPublishingAttempt,
    ActorAction,
    ComputeFenceAttestation,
    CredentialDrainAttestation,
    PAMDrainAnchor,
    PublishingRecoveryAuthorization,
    PublishingRecoveryError,
    PublishingRecoveryJournalExpectation,
    PublishingRecoveryRequest,
    PublishingRecoveryRequestIntent,
    PublishingRecoveryUseClaim,
    RecoveryActorAction,
    RecoveryActorAssertion,
    RecoveryActorVerificationPolicy,
    SignedComputeFenceAttestation,
    SignedCredentialDrainAttestation,
    SignedPublishingRecoveryAuthorization,
    SignedRecoveryActorAction,
    SuccessorLeaseClaim,
    VerifiedPublishingRecoveryAuthorization,
    WorkloadFenceLocator,
    credential_drain_lifecycle_snapshot_digest,
    issue_compute_fence_attestation,
    issue_credential_drain_attestation,
    issue_recovery_actor_action,
    migrate_legacy_pam_recovery_scopes,
    migrate_recovery_actor_assertion,
    publishing_recovery_checker_action_digest,
    publishing_recovery_execution_binding_digest,
    publishing_recovery_pam_scope_digest,
)
from assurance_lab.runtime.execution_recovery import (
    issue_publishing_recovery_authorization as _issue_final_authorization,
)
from assurance_lab.runtime.execution_recovery import (
    verify_publishing_recovery_authorization as _verify_final_authorization,
)
from assurance_lab.runtime.models import sha256_digest

_OLD_LEASED = datetime(2026, 7, 30, 1, 0, tzinfo=UTC)
_OLD_PUBLISHING = datetime(2026, 7, 30, 1, 1, tzinfo=UTC)
_OLD_EXPIRES = datetime(2026, 7, 30, 1, 5, tzinfo=UTC)
_NEW_LEASED = _OLD_EXPIRES
_NEW_EXPIRES = datetime(2026, 7, 30, 1, 30, tzinfo=UTC)
_REQUESTED = datetime(2026, 7, 30, 1, 6, tzinfo=UTC)
_FENCE_EFFECTIVE = datetime(2026, 7, 30, 1, 7, tzinfo=UTC)
_FENCE_OBSERVED = datetime(2026, 7, 30, 1, 8, tzinfo=UTC)
_FENCE_ATTESTED = datetime(2026, 7, 30, 1, 9, tzinfo=UTC)
_DRAIN_NOT_BEFORE = datetime(2026, 7, 30, 1, 12, tzinfo=UTC)
_DRAIN_CHECKED = datetime(2026, 7, 30, 1, 13, tzinfo=UTC)
_DRAIN_ATTESTED = datetime(2026, 7, 30, 1, 14, tzinfo=UTC)
_APPROVED = datetime(2026, 7, 30, 1, 15, tzinfo=UTC)
_EXPIRES = datetime(2026, 7, 30, 1, 25, tzinfo=UTC)


def _digest(character: str) -> str:
    return f"sha256:{character * 64}"


_RUN_ID = _digest("1")
_CONFIGURATION_DIGEST = _digest("2")
_PLAN_DIGEST = _digest("3")
_IDENTITY_DIGEST = _digest("4")
_OLD_CREDENTIAL_DIGEST = _digest("5")
_OLD_TOKEN_DIGEST = _digest("6")
_NEW_CREDENTIAL_DIGEST = _digest("7")
_NEW_TOKEN_DIGEST = _digest("8")
_CONNECTOR_REQUEST_DIGESTS = (_digest("a"), _digest("b"), _digest("c"))
_PAM_SCOPES = migrate_legacy_pam_recovery_scopes(
    authority_classes=("custody", "signing", "source"),
    connector_ids=("vault-custody", "kms-signing", "elastic-security"),
    connector_request_digests=_CONNECTOR_REQUEST_DIGESTS,
)
_PAM_SCOPE_DIGEST = publishing_recovery_pam_scope_digest(_PAM_SCOPES)
_SNAPSHOT_HIGH_WATERMARK = 103


class _Signer:
    def __init__(self, seed: bytes, *, key_id: str = "recovery-authority-v2") -> None:
        self._private = Ed25519PrivateKey.from_private_bytes(seed)
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_key_bytes(self) -> bytes:
        return self._private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, message: bytes) -> DetachedSignature:
        return DetachedSignature(
            key_id=self.key_id,
            algorithm="ed25519",
            signature=base64.b64encode(self._private.sign(message)).decode("ascii"),
        )


_FENCE_SIGNER = _Signer(b"\xf1" * 32, key_id="fence-authority-v2")
_DRAIN_SIGNER = _Signer(b"\xf2" * 32, key_id="drain-authority-v2")
_MAKER_SIGNER = _Signer(b"\xf3" * 32, key_id="maker-idp-v2")
_CHECKER_SIGNER = _Signer(b"\xf4" * 32, key_id="checker-idp-v2")
_ACTOR_POLICY = RecoveryActorVerificationPolicy(
    audience="control-assurance-recovery",
    maker_issuer_id="idp:maker",
    checker_issuer_id="idp:checker",
)


class _UseRegistry:
    def __init__(self) -> None:
        self._authorization_ids: set[str] = set()
        self.claims: list[PublishingRecoveryUseClaim] = []

    def consume_once(self, claim: PublishingRecoveryUseClaim) -> bool:
        if claim.authorization_id in self._authorization_ids:
            return False
        self._authorization_ids.add(claim.authorization_id)
        self.claims.append(claim)
        return True


def issue_publishing_recovery_authorization(
    authorization: PublishingRecoveryAuthorization,
    *,
    signer: _Signer,
    maker_verifier: Any = _MAKER_SIGNER,
    checker_verifier: Any = _CHECKER_SIGNER,
) -> SignedPublishingRecoveryAuthorization:
    return _issue_final_authorization(
        authorization,
        signer=signer,
        fence_verifier=_FENCE_SIGNER,
        drain_verifier=_DRAIN_SIGNER,
        maker_verifier=maker_verifier,
        checker_verifier=checker_verifier,
        actor_policy=_ACTOR_POLICY,
    )


def verify_publishing_recovery_authorization(
    value: bytes,
    *,
    verifier: Any,
    now: datetime,
    journal_expectation: PublishingRecoveryJournalExpectation,
    use_registry: Any,
    maker_verifier: Any = _MAKER_SIGNER,
    checker_verifier: Any = _CHECKER_SIGNER,
) -> VerifiedPublishingRecoveryAuthorization:
    return _verify_final_authorization(
        value,
        verifier=verifier,
        fence_verifier=_FENCE_SIGNER,
        drain_verifier=_DRAIN_SIGNER,
        maker_verifier=maker_verifier,
        checker_verifier=checker_verifier,
        actor_policy=_ACTOR_POLICY,
        now=now,
        journal_expectation=journal_expectation,
        use_registry=use_registry,
    )


def _sign_final_without_nested_verification(
    authorization: PublishingRecoveryAuthorization,
    signer: _Signer,
) -> SignedPublishingRecoveryAuthorization:
    message = (
        PUBLISHING_RECOVERY_SIGNATURE_DOMAIN.encode("ascii")
        + b"\x00"
        + authorization.canonical_bytes()
    )
    return SignedPublishingRecoveryAuthorization(
        authorization_id=authorization.authorization_id,
        recovery_authority_key_fingerprint=(authorization.recovery_authority_key_fingerprint),
        authorization=authorization,
        authority_signature=signer.sign(message),
    )


def _rebuild(
    model_type: type[Any],
    model: Any,
    **updates: object,
) -> Any:
    values = model.model_dump(mode="python")
    values.update(updates)
    return model_type.model_validate(values)


def _old_attempt(**updates: object) -> AbandonedPublishingAttempt:
    values: dict[str, object] = {
        "lease_fence": 3,
        "attempt_count": 3,
        "worker_id": "worker-old",
        "worker_credential_digest": _OLD_CREDENTIAL_DIGEST,
        "lease_token_digest": _OLD_TOKEN_DIGEST,
        "leased_at": _OLD_LEASED,
        "lease_expires_at": _OLD_EXPIRES,
        "publishing_at": _OLD_PUBLISHING,
    }
    values.update(updates)
    return AbandonedPublishingAttempt.model_validate(values)


def _successor(**updates: object) -> SuccessorLeaseClaim:
    values: dict[str, object] = {
        "lease_fence": 4,
        "attempt_count": 4,
        "worker_id": "worker-new",
        "worker_credential_digest": _NEW_CREDENTIAL_DIGEST,
        "lease_token_digest": _NEW_TOKEN_DIGEST,
        "leased_at": _NEW_LEASED,
        "lease_expires_at": _NEW_EXPIRES,
    }
    values.update(updates)
    return SuccessorLeaseClaim.model_validate(values)


def _maker() -> RecoveryActorAssertion:
    return RecoveryActorAssertion(
        subject_id="user:maker",
        session_digest=_digest("d"),
        role="maker",
        authenticated_at=_REQUESTED - timedelta(minutes=2),
        mfa_verified_at=_REQUESTED - timedelta(minutes=1),
    )


def _checker(**updates: object) -> RecoveryActorAssertion:
    values: dict[str, object] = {
        "subject_id": "user:checker",
        "session_digest": _digest("e"),
        "role": "checker",
        "authenticated_at": _APPROVED - timedelta(minutes=2),
        "mfa_verified_at": _APPROVED - timedelta(minutes=1),
    }
    values.update(updates)
    return RecoveryActorAssertion.model_validate(values)


def _signed_actor_action(
    assertion: RecoveryActorAssertion,
    *,
    action: ActorAction,
    action_digest: str,
    tenant_id: str,
    run_id: str,
    acted_at: datetime,
    expires_at: datetime,
    signer: _Signer,
    issuer_id: str,
    nonce: str,
    **updates: object,
) -> SignedRecoveryActorAction:
    payload = migrate_recovery_actor_assertion(
        assertion,
        issuer_id=issuer_id,
        audience=_ACTOR_POLICY.audience,
        tenant_id=tenant_id,
        run_id=run_id,
        action=action,
        action_digest=action_digest,
        acted_at=acted_at,
        expires_at=expires_at,
        action_nonce=nonce,
        idp_key_fingerprint=sha256_digest(signer.public_key_bytes),
    )
    if updates:
        payload = _rebuild(RecoveryActorAction, payload, **updates)
    return issue_recovery_actor_action(payload, signer=signer)


def _request(
    *,
    old: AbandonedPublishingAttempt | None = None,
    successor: SuccessorLeaseClaim | None = None,
    **updates: object,
) -> PublishingRecoveryRequest:
    abandoned = old or _old_attempt()
    next_claim = successor or _successor()
    execution_binding = publishing_recovery_execution_binding_digest(
        tenant_id="bank-a",
        run_id=_RUN_ID,
        execution_plan_digest=_PLAN_DIGEST,
        execution_identity_digest=_IDENTITY_DIGEST,
        abandoned_lease_fence=abandoned.lease_fence,
        pam_scope_digest=_PAM_SCOPE_DIGEST,
    )
    values: dict[str, object] = {
        "tenant_id": "bank-a",
        "run_id": _RUN_ID,
        "control_id": "edr-alert-recovery",
        "configuration_digest": _CONFIGURATION_DIGEST,
        "execution_plan_digest": _PLAN_DIGEST,
        "execution_identity_digest": _IDENTITY_DIGEST,
        "abandoned_attempt": abandoned,
        "successor_claim": next_claim,
        "pam_scopes": _PAM_SCOPES,
        "pam_scope_digest": _PAM_SCOPE_DIGEST,
        "pam_execution_binding_digest": execution_binding,
        "reason": "old-worker-unreachable",
        "incident_reference_digest": _digest("f"),
        "requested_at": _REQUESTED,
        "request_expires_at": _REQUESTED + timedelta(hours=1),
        "request_nonce": "0" * 64,
    }
    signed_maker_action = cast(
        SignedRecoveryActorAction | None,
        updates.pop("signed_maker_action", None),
    )
    values.update(updates)
    intent = PublishingRecoveryRequestIntent.model_validate(values)
    if signed_maker_action is None:
        signed_maker_action = _signed_actor_action(
            _maker(),
            action="request",
            action_digest=intent.digest,
            tenant_id=intent.tenant_id,
            run_id=intent.run_id,
            acted_at=intent.requested_at,
            expires_at=intent.request_expires_at,
            signer=_MAKER_SIGNER,
            issuer_id=_ACTOR_POLICY.maker_issuer_id,
            nonce="a" * 64,
        )
    return PublishingRecoveryRequest(
        intent_digest=intent.digest,
        intent=intent,
        signed_maker_action=signed_maker_action,
    )


def _fence(
    request: PublishingRecoveryRequest,
    **updates: object,
) -> ComputeFenceAttestation:
    old = request.abandoned_attempt
    values: dict[str, object] = {
        "recovery_request_digest": request.digest,
        "tenant_id": request.tenant_id,
        "run_id": request.run_id,
        "abandoned_attempt_digest": old.digest,
        "workload": WorkloadFenceLocator(
            cluster_uid="cluster:prod-1",
            namespace="assurance-runtime",
            service_account_uid="service-account:worker",
            pod_uid="pod:4e32",
            node_uid="node:91af",
            container_image_digest=_digest("9"),
            worker_id=old.worker_id,
            worker_credential_digest=old.worker_credential_digest,
        ),
        "method": "pod-runtime-terminated",
        "old_process_absent": True,
        "old_workload_egress_denied": False,
        "node_reachable_at_observation": True,
        "kubernetes_delete_operation_digest": _digest("a"),
        "proof_media_type": ("application/vnd.control-assurance.kubernetes-fence-proof.v1+json"),
        "proof_digest": _digest("b"),
        "relaunch_fence_operation_digest": _digest("0"),
        "relaunch_fence_effective_at": _FENCE_EFFECTIVE,
        "relaunch_fence_valid_until": request.successor_claim.lease_expires_at,
        "fencing_controller_id": "system:fence-controller",
        "fencing_controller_credential_digest": _digest("c"),
        "fencing_authority_key_fingerprint": sha256_digest(_FENCE_SIGNER.public_key_bytes),
        "fence_requested_at": _REQUESTED,
        "fence_effective_at": _FENCE_EFFECTIVE,
        "isolation_observed_at": _FENCE_OBSERVED,
        "attested_at": _FENCE_ATTESTED,
    }
    values.update(updates)
    return ComputeFenceAttestation.model_validate(values)


def _anchors(request: PublishingRecoveryRequest) -> tuple[PAMDrainAnchor, ...]:
    return (
        PAMDrainAnchor(
            authority_class="custody",
            connector_id="vault-custody",
            connector_request_digest=_CONNECTOR_REQUEST_DIGESTS[0],
            scope_digest=request.pam_scope_digest,
            execution_binding_digest=request.pam_execution_binding_digest,
            lifecycle_record_id="pam:custody:1",
            lifecycle_record_digest=_digest("1"),
            lifecycle_sequence=101,
            lifecycle_revision=1,
            state="never-issued",
            expiry_basis="not-issued",
            created_at=_REQUESTED,
            maximum_residual_exposure_ends_at=_REQUESTED,
            settled_at=_REQUESTED,
        ),
        PAMDrainAnchor(
            authority_class="signing",
            connector_id="kms-signing",
            connector_request_digest=_CONNECTOR_REQUEST_DIGESTS[1],
            scope_digest=request.pam_scope_digest,
            execution_binding_digest=request.pam_execution_binding_digest,
            lifecycle_record_id="pam:signing:1",
            lifecycle_record_digest=_digest("2"),
            lifecycle_sequence=102,
            lifecycle_revision=2,
            credential_reference_digest=_digest("3"),
            state="expired",
            expiry_basis="policy-upper-bound",
            created_at=_OLD_LEASED - timedelta(minutes=10),
            issued_at=_OLD_LEASED - timedelta(minutes=9),
            expires_at=datetime(2026, 7, 30, 1, 11, tzinfo=UTC),
            maximum_residual_exposure_ends_at=datetime(
                2026,
                7,
                30,
                1,
                11,
                tzinfo=UTC,
            ),
            settled_at=datetime(2026, 7, 30, 1, 11, tzinfo=UTC),
        ),
        PAMDrainAnchor(
            authority_class="source",
            connector_id="elastic-security",
            connector_request_digest=_CONNECTOR_REQUEST_DIGESTS[2],
            scope_digest=request.pam_scope_digest,
            execution_binding_digest=request.pam_execution_binding_digest,
            lifecycle_record_id="pam:source:1",
            lifecycle_record_digest=_digest("4"),
            lifecycle_sequence=103,
            lifecycle_revision=3,
            credential_reference_digest=_digest("5"),
            state="revoked",
            expiry_basis="confirmed-revocation",
            created_at=_OLD_LEASED - timedelta(minutes=10),
            issued_at=_OLD_LEASED - timedelta(minutes=9),
            revocation_confirmed_at=datetime(2026, 7, 30, 1, 9, tzinfo=UTC),
            maximum_residual_exposure_ends_at=_DRAIN_NOT_BEFORE,
            settled_at=_DRAIN_NOT_BEFORE,
        ),
    )


def _drain(
    request: PublishingRecoveryRequest,
    fence: ComputeFenceAttestation,
    *,
    anchors: tuple[PAMDrainAnchor, ...] | None = None,
    **updates: object,
) -> CredentialDrainAttestation:
    rows = anchors or _anchors(request)
    values: dict[str, object] = {
        "recovery_request_digest": request.digest,
        "compute_fence_attestation_digest": fence.digest,
        "tenant_id": request.tenant_id,
        "run_id": request.run_id,
        "abandoned_attempt_digest": request.abandoned_attempt.digest,
        "scope_digest": request.pam_scope_digest,
        "execution_binding_digest": request.pam_execution_binding_digest,
        "anchors": rows,
        "lifecycle_snapshot_digest": credential_drain_lifecycle_snapshot_digest(
            scope_digest=request.pam_scope_digest,
            execution_binding_digest=request.pam_execution_binding_digest,
            snapshot_high_watermark=_SNAPSHOT_HIGH_WATERMARK,
            anchors=rows,
        ),
        "lifecycle_record_count": len(rows),
        "snapshot_high_watermark": _SNAPSHOT_HIGH_WATERMARK,
        "maximum_residual_exposure_ends_at": _DRAIN_NOT_BEFORE,
        "fence_effective_at": fence.fence_effective_at,
        "maximum_inflight_seconds": 60,
        "clock_skew_seconds": 60,
        "post_fence_inflight_deadline": _FENCE_EFFECTIVE + timedelta(seconds=120),
        "drain_not_before": _DRAIN_NOT_BEFORE,
        "checked_at": _DRAIN_CHECKED,
        "attested_at": _DRAIN_ATTESTED,
        "issuance_fence_operation_digest": _digest("6"),
        "issuance_fence_effective_at": _FENCE_EFFECTIVE,
        "issuance_fence_valid_until": request.successor_claim.lease_expires_at,
        "issuance_fence_high_watermark": _SNAPSHOT_HIGH_WATERMARK,
        "drain_controller_id": "system:drain-controller",
        "drain_controller_credential_digest": _digest("d"),
        "drain_authority_key_fingerprint": sha256_digest(_DRAIN_SIGNER.public_key_bytes),
        "pam_query_evidence_media_type": (
            "application/vnd.control-assurance.pam-drain-proof.v1+json"
        ),
        "pam_query_evidence_digest": _digest("8"),
    }
    values.update(updates)
    return CredentialDrainAttestation.model_validate(values)


def _authorization(
    signer: _Signer,
    *,
    request: PublishingRecoveryRequest | None = None,
    fence: ComputeFenceAttestation | None = None,
    drain: CredentialDrainAttestation | None = None,
    signed_fence: SignedComputeFenceAttestation | None = None,
    signed_drain: SignedCredentialDrainAttestation | None = None,
    checker: RecoveryActorAssertion | None = None,
    signed_checker_action: SignedRecoveryActorAction | None = None,
    **updates: object,
) -> PublishingRecoveryAuthorization:
    recovery_request = request or _request()
    compute_fence = fence or _fence(recovery_request)
    credential_drain = drain or _drain(recovery_request, compute_fence)
    compute_fence_envelope = signed_fence or issue_compute_fence_attestation(
        compute_fence,
        signer=_FENCE_SIGNER,
    )
    credential_drain_envelope = signed_drain or issue_credential_drain_attestation(
        credential_drain,
        signer=_DRAIN_SIGNER,
    )
    values: dict[str, object] = {
        "tenant_id": recovery_request.tenant_id,
        "run_id": recovery_request.run_id,
        "control_id": recovery_request.control_id,
        "configuration_digest": recovery_request.configuration_digest,
        "execution_plan_digest": recovery_request.execution_plan_digest,
        "execution_identity_digest": recovery_request.execution_identity_digest,
        "recovery_request_digest": recovery_request.digest,
        "recovery_request": recovery_request,
        "compute_fence_attestation_digest": compute_fence.digest,
        "signed_compute_fence_attestation_digest": (compute_fence_envelope.digest),
        "signed_compute_fence_attestation": compute_fence_envelope,
        "credential_drain_attestation_digest": credential_drain.digest,
        "signed_credential_drain_attestation_digest": (credential_drain_envelope.digest),
        "signed_credential_drain_attestation": credential_drain_envelope,
        "abandoned_attempt": recovery_request.abandoned_attempt,
        "successor_claim": recovery_request.successor_claim,
        "change_approval_digest": _digest("9"),
        "approved_at": _APPROVED,
        "not_before": _DRAIN_NOT_BEFORE,
        "issued_at": _APPROVED,
        "expires_at": _EXPIRES,
        "authorization_nonce": "f" * 64,
        "recovery_authority_id": "system:recovery-authority",
        "recovery_authority_key_fingerprint": sha256_digest(signer.public_key_bytes),
    }
    values.update(updates)
    checker_action_digest = publishing_recovery_checker_action_digest(
        tenant_id=str(values["tenant_id"]),
        run_id=str(values["run_id"]),
        recovery_request_digest=str(values["recovery_request_digest"]),
        signed_compute_fence_attestation_digest=str(
            values["signed_compute_fence_attestation_digest"]
        ),
        signed_credential_drain_attestation_digest=str(
            values["signed_credential_drain_attestation_digest"]
        ),
        abandoned_attempt_digest=recovery_request.abandoned_attempt.digest,
        successor_claim_digest=recovery_request.successor_claim.digest,
        change_approval_digest=str(values["change_approval_digest"]),
        approved_at=cast(datetime, values["approved_at"]),
        not_before=cast(datetime, values["not_before"]),
        issued_at=cast(datetime, values["issued_at"]),
        expires_at=cast(datetime, values["expires_at"]),
        authorization_nonce=str(values["authorization_nonce"]),
        recovery_authority_id=str(values["recovery_authority_id"]),
        recovery_authority_key_fingerprint=str(values["recovery_authority_key_fingerprint"]),
    )
    if signed_checker_action is None:
        signed_checker_action = _signed_actor_action(
            checker or _checker(),
            action="approve",
            action_digest=checker_action_digest,
            tenant_id=str(values["tenant_id"]),
            run_id=str(values["run_id"]),
            acted_at=cast(datetime, values["approved_at"]),
            expires_at=cast(datetime, values["expires_at"]),
            signer=_CHECKER_SIGNER,
            issuer_id=_ACTOR_POLICY.checker_issuer_id,
            nonce="b" * 64,
        )
    values["signed_checker_action_digest"] = signed_checker_action.digest
    values["signed_checker_action"] = signed_checker_action
    return PublishingRecoveryAuthorization.model_validate(values)


def _expectation(
    authorization: PublishingRecoveryAuthorization,
    **updates: object,
) -> PublishingRecoveryJournalExpectation:
    request = authorization.recovery_request
    values: dict[str, object] = {
        "tenant_id": authorization.tenant_id,
        "run_id": authorization.run_id,
        "control_id": authorization.control_id,
        "configuration_digest": authorization.configuration_digest,
        "execution_plan_digest": authorization.execution_plan_digest,
        "execution_identity_digest": authorization.execution_identity_digest,
        "recovery_request_digest": authorization.recovery_request_digest,
        "pam_scope_digest": request.pam_scope_digest,
        "pam_execution_binding_digest": request.pam_execution_binding_digest,
        "pam_snapshot_high_watermark": (
            authorization.credential_drain_attestation.snapshot_high_watermark
        ),
        "pam_lifecycle_record_count": (
            authorization.credential_drain_attestation.lifecycle_record_count
        ),
        "relaunch_fence_operation_digest": (
            authorization.compute_fence_attestation.relaunch_fence_operation_digest
        ),
        "issuance_fence_operation_digest": (
            authorization.credential_drain_attestation.issuance_fence_operation_digest
        ),
        "abandoned_lease_fence": authorization.abandoned_attempt.lease_fence,
        "abandoned_attempt_count": authorization.abandoned_attempt.attempt_count,
        "abandoned_attempt_revision": (authorization.abandoned_attempt.attempt_revision),
        "abandoned_worker_id": authorization.abandoned_attempt.worker_id,
        "abandoned_lease_token_digest": (authorization.abandoned_attempt.lease_token_digest),
        "abandoned_publishing_at": (authorization.abandoned_attempt.publishing_at),
        "successor_lease_fence": authorization.successor_claim.lease_fence,
        "successor_attempt_count": authorization.successor_claim.attempt_count,
        "successor_worker_id": authorization.successor_claim.worker_id,
        "successor_lease_token_digest": (authorization.successor_claim.lease_token_digest),
    }
    values.update(updates)
    return PublishingRecoveryJournalExpectation.model_validate(values)


def test_four_record_authorization_round_trips_and_is_consumed_once() -> None:
    signer = _Signer(b"\x11" * 32)
    authorization = _authorization(signer)
    envelope = issue_publishing_recovery_authorization(
        authorization,
        signer=signer,
    )
    encoded = envelope.canonical_bytes()
    registry = _UseRegistry()

    verified = verify_publishing_recovery_authorization(
        encoded,
        verifier=signer,
        now=_APPROVED,
        journal_expectation=_expectation(authorization),
        use_registry=registry,
    )

    assert verified.envelope == envelope
    assert verified.envelope_bytes == encoded
    assert verified.authorization == authorization
    assert verified.use_claim == registry.claims[0]
    assert verified.use_claim.authorization_id == authorization.authorization_id
    assert verified.digest == sha256_digest(encoded)

    with pytest.raises(PublishingRecoveryError, match="authorization-consumed"):
        verify_publishing_recovery_authorization(
            encoded,
            verifier=signer,
            now=_APPROVED,
            journal_expectation=_expectation(authorization),
            use_registry=registry,
        )


def test_authorization_is_not_valid_before_issue_and_expires_exclusively() -> None:
    signer = _Signer(b"\x12" * 32)
    authorization = _authorization(signer)
    encoded = issue_publishing_recovery_authorization(
        authorization,
        signer=signer,
    ).canonical_bytes()

    with pytest.raises(
        PublishingRecoveryError,
        match="authorization-not-yet-valid",
    ):
        verify_publishing_recovery_authorization(
            encoded,
            verifier=signer,
            now=_APPROVED - timedelta(seconds=1),
            journal_expectation=_expectation(authorization),
            use_registry=_UseRegistry(),
        )
    with pytest.raises(PublishingRecoveryError, match="authorization-expired"):
        verify_publishing_recovery_authorization(
            encoded,
            verifier=signer,
            now=_EXPIRES,
            journal_expectation=_expectation(authorization),
            use_registry=_UseRegistry(),
        )


def test_correctly_signed_cross_run_or_successor_substitution_is_rejected() -> None:
    signer = _Signer(b"\x13" * 32)
    authorization = _authorization(signer)
    encoded = issue_publishing_recovery_authorization(
        authorization,
        signer=signer,
    ).canonical_bytes()
    registry = _UseRegistry()

    wrong_run = _expectation(authorization, run_id=_digest("0"))
    with pytest.raises(PublishingRecoveryError, match="journal-binding-mismatch"):
        verify_publishing_recovery_authorization(
            encoded,
            verifier=signer,
            now=_APPROVED,
            journal_expectation=wrong_run,
            use_registry=registry,
        )
    assert registry.claims == []

    wrong_successor = _expectation(
        authorization,
        successor_worker_id="worker-substitute",
        successor_lease_token_digest=_digest("b"),
    )
    with pytest.raises(PublishingRecoveryError, match="journal-binding-mismatch"):
        verify_publishing_recovery_authorization(
            encoded,
            verifier=signer,
            now=_APPROVED,
            journal_expectation=wrong_successor,
            use_registry=registry,
        )
    assert registry.claims == []


def test_semantically_valid_tampering_still_breaks_signature() -> None:
    signer = _Signer(b"\x14" * 32)
    authorization = _authorization(signer)
    envelope = issue_publishing_recovery_authorization(
        authorization,
        signer=signer,
    )
    substituted = _authorization(signer, change_approval_digest=_digest("0"))
    tampered = SignedPublishingRecoveryAuthorization(
        authorization_id=substituted.authorization_id,
        recovery_authority_key_fingerprint=(substituted.recovery_authority_key_fingerprint),
        authorization=substituted,
        authority_signature=envelope.authority_signature,
    ).canonical_bytes()

    with pytest.raises(PublishingRecoveryError, match="signature-invalid"):
        verify_publishing_recovery_authorization(
            tampered,
            verifier=signer,
            now=_APPROVED,
            journal_expectation=_expectation(authorization),
            use_registry=_UseRegistry(),
        )


def test_noncanonical_or_duplicate_json_never_reaches_signature_verification() -> None:
    signer = _Signer(b"\x15" * 32)
    authorization = _authorization(signer)
    encoded = issue_publishing_recovery_authorization(
        authorization,
        signer=signer,
    ).canonical_bytes()

    with pytest.raises(PublishingRecoveryError, match="document-noncanonical"):
        verify_publishing_recovery_authorization(
            b" " + encoded,
            verifier=signer,
            now=_APPROVED,
            journal_expectation=_expectation(authorization),
            use_registry=_UseRegistry(),
        )
    duplicate = encoded[:-1] + b',"media_type":"application/json"}'
    with pytest.raises(PublishingRecoveryError, match="document-invalid"):
        verify_publishing_recovery_authorization(
            duplicate,
            verifier=signer,
            now=_APPROVED,
            journal_expectation=_expectation(authorization),
            use_registry=_UseRegistry(),
        )


def test_authority_key_substitution_and_rotation_during_verify_fail_closed() -> None:
    signer = _Signer(b"\x16" * 32)
    authorization = _authorization(signer)
    encoded = issue_publishing_recovery_authorization(
        authorization,
        signer=signer,
    ).canonical_bytes()

    with pytest.raises(PublishingRecoveryError, match="signature-invalid"):
        verify_publishing_recovery_authorization(
            encoded,
            verifier=_Signer(b"\x17" * 32),
            now=_APPROVED,
            journal_expectation=_expectation(authorization),
            use_registry=_UseRegistry(),
        )

    class _ChangingVerifier:
        key_id = signer.key_id

        def __init__(self) -> None:
            self._calls = 0

        @property
        def public_key_bytes(self) -> bytes:
            self._calls += 1
            if self._calls == 1:
                return signer.public_key_bytes
            return _Signer(b"\x18" * 32).public_key_bytes

    with pytest.raises(PublishingRecoveryError, match="authority-changed"):
        verify_publishing_recovery_authorization(
            encoded,
            verifier=_ChangingVerifier(),
            now=_APPROVED,
            journal_expectation=_expectation(authorization),
            use_registry=_UseRegistry(),
        )


def test_final_authority_cannot_bless_forged_fence_or_drain_attestations() -> None:
    final_signer = _Signer(b"\x23" * 32)
    rogue = _Signer(b"\x24" * 32, key_id="rogue-controller")
    request = _request()
    fence = _fence(request)
    drain = _drain(request, fence)

    forged_fence = SignedComputeFenceAttestation(
        attestation_digest=fence.digest,
        fencing_authority_key_fingerprint=fence.fencing_authority_key_fingerprint,
        attestation=fence,
        authority_signature=rogue.sign(b"forged-fence"),
    )
    forged_fence_authorization = _authorization(
        final_signer,
        request=request,
        fence=fence,
        drain=drain,
        signed_fence=forged_fence,
    )
    with pytest.raises(PublishingRecoveryError, match="fence-signature-invalid"):
        issue_publishing_recovery_authorization(
            forged_fence_authorization,
            signer=final_signer,
        )
    final_envelope = _sign_final_without_nested_verification(
        forged_fence_authorization,
        final_signer,
    )
    with pytest.raises(PublishingRecoveryError, match="fence-signature-invalid"):
        verify_publishing_recovery_authorization(
            final_envelope.canonical_bytes(),
            verifier=final_signer,
            now=_APPROVED,
            journal_expectation=_expectation(forged_fence_authorization),
            use_registry=_UseRegistry(),
        )

    valid_fence = issue_compute_fence_attestation(fence, signer=_FENCE_SIGNER)
    forged_drain = SignedCredentialDrainAttestation(
        attestation_digest=drain.digest,
        drain_authority_key_fingerprint=drain.drain_authority_key_fingerprint,
        attestation=drain,
        authority_signature=rogue.sign(b"forged-drain"),
    )
    forged_drain_authorization = _authorization(
        final_signer,
        request=request,
        fence=fence,
        drain=drain,
        signed_fence=valid_fence,
        signed_drain=forged_drain,
    )
    with pytest.raises(PublishingRecoveryError, match="drain-signature-invalid"):
        issue_publishing_recovery_authorization(
            forged_drain_authorization,
            signer=final_signer,
        )
    final_envelope = _sign_final_without_nested_verification(
        forged_drain_authorization,
        final_signer,
    )
    with pytest.raises(PublishingRecoveryError, match="drain-signature-invalid"):
        verify_publishing_recovery_authorization(
            final_envelope.canonical_bytes(),
            verifier=final_signer,
            now=_APPROVED,
            journal_expectation=_expectation(forged_drain_authorization),
            use_registry=_UseRegistry(),
        )


def test_final_authority_cannot_bless_a_forged_maker_action_signature() -> None:
    final_signer = _Signer(b"\x26" * 32)
    rogue_idp = _Signer(b"\x27" * 32, key_id=_MAKER_SIGNER.key_id)
    request = _request()
    maker_envelope = request.signed_maker_action
    forged_signature = rogue_idp.sign(
        RECOVERY_MAKER_ACTION_SIGNATURE_DOMAIN.encode("ascii")
        + b"\x00"
        + maker_envelope.actor_action.canonical_bytes()
    )
    forged_maker = _rebuild(
        SignedRecoveryActorAction,
        maker_envelope,
        authority_signature=forged_signature,
    )
    forged_request = _request(signed_maker_action=forged_maker)
    authorization = _authorization(final_signer, request=forged_request)

    with pytest.raises(PublishingRecoveryError, match="maker-signature-invalid"):
        issue_publishing_recovery_authorization(
            authorization,
            signer=final_signer,
        )

    registry = _UseRegistry()
    envelope = _sign_final_without_nested_verification(
        authorization,
        final_signer,
    )
    with pytest.raises(PublishingRecoveryError, match="maker-signature-invalid"):
        verify_publishing_recovery_authorization(
            envelope.canonical_bytes(),
            verifier=final_signer,
            now=_APPROVED,
            journal_expectation=_expectation(authorization),
            use_registry=registry,
        )
    assert registry.claims == []


def test_actor_action_replay_and_context_substitution_are_rejected() -> None:
    request = _request()

    changed_intent = _rebuild(
        PublishingRecoveryRequestIntent,
        request.intent,
        request_nonce="1" * 64,
    )
    with pytest.raises(ValidationError, match="maker action"):
        PublishingRecoveryRequest(
            intent_digest=changed_intent.digest,
            intent=changed_intent,
            signed_maker_action=request.signed_maker_action,
        )

    for context_update in (
        {"tenant_id": "bank-b"},
        {"run_id": _digest("0")},
    ):
        substituted_action = _rebuild(
            RecoveryActorAction,
            request.signed_maker_action.actor_action,
            **context_update,
        )
        substituted_envelope = issue_recovery_actor_action(
            substituted_action,
            signer=_MAKER_SIGNER,
        )
        with pytest.raises(ValidationError, match="maker action"):
            PublishingRecoveryRequest(
                intent_digest=request.intent_digest,
                intent=request.intent,
                signed_maker_action=substituted_envelope,
            )

    substituted_action = _rebuild(
        RecoveryActorAction,
        request.signed_maker_action.actor_action,
        role="checker",
        action="approve",
    )
    substituted_envelope = issue_recovery_actor_action(
        substituted_action,
        signer=_MAKER_SIGNER,
    )
    with pytest.raises(ValidationError, match="maker action"):
        PublishingRecoveryRequest(
            intent_digest=request.intent_digest,
            intent=request.intent,
            signed_maker_action=substituted_envelope,
        )


def test_actor_issuer_audience_and_pinned_key_substitution_fail_closed() -> None:
    final_signer = _Signer(b"\x28" * 32)
    request = _request()

    bad_authorizations: list[PublishingRecoveryAuthorization] = []
    for context_update in (
        {"issuer_id": "idp:untrusted"},
        {"audience": "different-recovery-service"},
    ):
        substituted_action = _rebuild(
            RecoveryActorAction,
            request.signed_maker_action.actor_action,
            **context_update,
        )
        substituted_envelope = issue_recovery_actor_action(
            substituted_action,
            signer=_MAKER_SIGNER,
        )
        substituted_request = PublishingRecoveryRequest(
            intent_digest=request.intent_digest,
            intent=request.intent,
            signed_maker_action=substituted_envelope,
        )
        authorization = _authorization(
            final_signer,
            request=substituted_request,
        )
        bad_authorizations.append(authorization)
        with pytest.raises(PublishingRecoveryError, match="maker-action-invalid"):
            issue_publishing_recovery_authorization(
                authorization,
                signer=final_signer,
            )

    registry = _UseRegistry()
    bypassed = _sign_final_without_nested_verification(
        bad_authorizations[0],
        final_signer,
    )
    with pytest.raises(PublishingRecoveryError, match="maker-action-invalid"):
        verify_publishing_recovery_authorization(
            bypassed.canonical_bytes(),
            verifier=final_signer,
            now=_APPROVED,
            journal_expectation=_expectation(bad_authorizations[0]),
            use_registry=registry,
        )
    assert registry.claims == []

    valid_authorization = _authorization(final_signer)
    encoded = issue_publishing_recovery_authorization(
        valid_authorization,
        signer=final_signer,
    ).canonical_bytes()
    substituted_key = _Signer(b"\x29" * 32, key_id=_MAKER_SIGNER.key_id)
    with pytest.raises(PublishingRecoveryError, match="maker-signature-invalid"):
        verify_publishing_recovery_authorization(
            encoded,
            verifier=final_signer,
            maker_verifier=substituted_key,
            now=_APPROVED,
            journal_expectation=_expectation(valid_authorization),
            use_registry=registry,
        )
    assert registry.claims == []


def test_maker_and_checker_idp_keys_must_be_independent() -> None:
    final_signer = _Signer(b"\x2a" * 32)
    authorization = _authorization(final_signer)
    checker_action = _rebuild(
        RecoveryActorAction,
        authorization.signed_checker_action.actor_action,
        idp_key_fingerprint=sha256_digest(_MAKER_SIGNER.public_key_bytes),
    )
    same_key_checker = issue_recovery_actor_action(
        checker_action,
        signer=_MAKER_SIGNER,
    )
    values = authorization.model_dump(mode="python")
    values["signed_checker_action_digest"] = same_key_checker.digest
    values["signed_checker_action"] = same_key_checker

    with pytest.raises(ValidationError, match="different people, sessions, and IdP keys"):
        PublishingRecoveryAuthorization.model_validate(values)
    with pytest.raises(ValidationError, match="issuers must be independent"):
        RecoveryActorVerificationPolicy(
            audience="control-assurance-recovery",
            maker_issuer_id="idp:shared",
            checker_issuer_id="idp:shared",
        )


def test_maker_checker_and_non_human_duties_must_be_separated() -> None:
    signer = _Signer(b"\x19" * 32)
    maker = _maker()
    same_person = _checker(subject_id=maker.subject_id)
    with pytest.raises(ValidationError, match="maker and checker"):
        _authorization(signer, checker=same_person)

    same_session = _checker(session_digest=maker.session_digest)
    with pytest.raises(ValidationError, match="maker and checker"):
        _authorization(signer, checker=same_session)

    request = _request()
    fence = _fence(request, fencing_controller_id="worker-new")
    drain = _drain(request, fence)
    with pytest.raises(ValidationError, match="duties"):
        _authorization(signer, request=request, fence=fence, drain=drain)


def test_pod_fence_requires_reachable_node_and_confirmed_process_absence() -> None:
    request = _request()
    with pytest.raises(ValidationError, match="hard fence proof"):
        _fence(request, node_reachable_at_observation=False)
    with pytest.raises(ValidationError, match="hard fence proof"):
        _fence(request, old_process_absent=False)
    with pytest.raises(ValidationError, match="exactly one method proof"):
        _fence(request, node_power_fence_operation_digest=_digest("d"))


def test_drain_rejects_partial_or_cross_run_pam_row_sets() -> None:
    signer = _Signer(b"\x20" * 32)
    request = _request()
    fence = _fence(request)
    rows = _anchors(request)

    with pytest.raises(ValidationError, match="exact PAM scope"):
        partial = _drain(request, fence, anchors=rows[1:])
        _authorization(
            signer,
            request=request,
            fence=fence,
            drain=partial,
        )

    foreign_anchor = _rebuild(
        PAMDrainAnchor,
        rows[2],
        execution_binding_digest=_digest("0"),
    )
    with pytest.raises(ValidationError, match="outside the run"):
        _drain(request, fence, anchors=(*rows[:2], foreign_anchor))


def test_drain_boundary_and_authorization_ttl_are_exact_and_bounded() -> None:
    signer = _Signer(b"\x21" * 32)
    request = _request()
    fence = _fence(request)

    with pytest.raises(ValidationError, match="drain boundary"):
        _drain(
            request,
            fence,
            drain_not_before=_DRAIN_NOT_BEFORE - timedelta(seconds=1),
        )
    with pytest.raises(ValidationError, match="content-derived"):
        _drain(
            request,
            fence,
            lifecycle_snapshot_digest=_digest("0"),
        )
    with pytest.raises(ValidationError, match="timeline or lifetime"):
        _authorization(
            signer,
            expires_at=_APPROVED + timedelta(minutes=15, seconds=1),
        )


def test_authorization_cannot_outlive_or_adopt_an_expired_successor_lease() -> None:
    signer = _Signer(b"\x25" * 32)
    short_successor = _successor(lease_expires_at=_EXPIRES)
    request = _request(successor=short_successor)
    authorization = _authorization(signer, request=request)
    encoded = issue_publishing_recovery_authorization(
        authorization,
        signer=signer,
    ).canonical_bytes()

    with pytest.raises(PublishingRecoveryError, match="successor-lease-expired"):
        verify_publishing_recovery_authorization(
            encoded,
            verifier=signer,
            now=_EXPIRES,
            journal_expectation=_expectation(authorization),
            use_registry=_UseRegistry(),
        )

    with pytest.raises(ValidationError, match="timeline or lifetime"):
        _authorization(
            signer,
            request=request,
            expires_at=_EXPIRES + timedelta(seconds=1),
        )


def test_relaunch_and_issuance_fences_cover_the_full_successor_lease() -> None:
    signer = _Signer(b"\x2b" * 32)
    request = _request()
    stale_at = request.successor_claim.lease_expires_at - timedelta(seconds=1)

    with pytest.raises(ValidationError, match="compute fence timeline"):
        _fence(
            request,
            relaunch_fence_effective_at=_FENCE_EFFECTIVE + timedelta(seconds=1),
        )

    stale_fence = _fence(
        request,
        relaunch_fence_valid_until=stale_at,
    )
    stale_fence_drain = _drain(request, stale_fence)
    with pytest.raises(ValidationError, match="timeline or lifetime"):
        _authorization(
            signer,
            request=request,
            fence=stale_fence,
            drain=stale_fence_drain,
        )

    fence = _fence(request)
    stale_drain = _drain(
        request,
        fence,
        issuance_fence_valid_until=stale_at,
    )
    with pytest.raises(ValidationError, match="timeline or lifetime"):
        _authorization(
            signer,
            request=request,
            fence=fence,
            drain=stale_drain,
        )


def test_duplicate_lifecycle_digest_and_active_row_omission_fail_closed() -> None:
    signer = _Signer(b"\x2c" * 32)
    request = _request()
    fence = _fence(request)
    rows = _anchors(request)
    duplicate_digest_row = _rebuild(
        PAMDrainAnchor,
        rows[2],
        lifecycle_record_digest=rows[1].lifecycle_record_digest,
    )
    with pytest.raises(ValidationError, match="globally unique"):
        _drain(
            request,
            fence,
            anchors=(*rows[:2], duplicate_digest_row),
        )

    authorization = _authorization(
        signer,
        request=request,
        fence=fence,
    )
    encoded = issue_publishing_recovery_authorization(
        authorization,
        signer=signer,
    ).canonical_bytes()
    registry = _UseRegistry()

    # A fourth active lifecycle row can share a connector request digest with
    # an included settled row. The authoritative count prevents set-based
    # request-digest deduplication from hiding that omitted row.
    expectation = _expectation(
        authorization,
        pam_lifecycle_record_count=4,
    )
    with pytest.raises(PublishingRecoveryError, match="journal-binding-mismatch"):
        verify_publishing_recovery_authorization(
            encoded,
            verifier=signer,
            now=_APPROVED,
            journal_expectation=expectation,
            use_registry=registry,
        )
    assert registry.claims == []


def test_future_issued_pam_anchor_cannot_enter_an_earlier_snapshot() -> None:
    request = _request()
    fence = _fence(request)
    rows = _anchors(request)

    with pytest.raises(ValidationError, match="follows record settlement"):
        _rebuild(
            PAMDrainAnchor,
            rows[2],
            issued_at=_DRAIN_CHECKED + timedelta(seconds=1),
        )

    future_issued_at = _DRAIN_CHECKED + timedelta(seconds=1)
    future_settled_at = future_issued_at + timedelta(seconds=1)
    future_row = _rebuild(
        PAMDrainAnchor,
        rows[2],
        issued_at=future_issued_at,
        revocation_confirmed_at=future_settled_at,
        maximum_residual_exposure_ends_at=future_settled_at,
        settled_at=future_settled_at,
    )
    with pytest.raises(ValidationError, match="outside the run execution binding"):
        _drain(
            request,
            fence,
            anchors=(*rows[:2], future_row),
        )


def test_request_expiry_is_exclusive_and_checked_before_consumption() -> None:
    signer = _Signer(b"\x2d" * 32)
    request = _request(request_expires_at=_EXPIRES)
    authorization = _authorization(
        signer,
        request=request,
        expires_at=_EXPIRES,
    )
    encoded = issue_publishing_recovery_authorization(
        authorization,
        signer=signer,
    ).canonical_bytes()
    registry = _UseRegistry()

    with pytest.raises(PublishingRecoveryError, match="recovery-request-expired"):
        verify_publishing_recovery_authorization(
            encoded,
            verifier=signer,
            now=request.request_expires_at,
            journal_expectation=_expectation(authorization),
            use_registry=registry,
        )
    assert registry.claims == []


def test_execution_binding_is_derived_from_exact_run_and_request_digests() -> None:
    request = _request()
    changed = publishing_recovery_execution_binding_digest(
        tenant_id=request.tenant_id,
        run_id=_digest("0"),
        execution_plan_digest=request.execution_plan_digest,
        execution_identity_digest=request.execution_identity_digest,
        abandoned_lease_fence=request.abandoned_attempt.lease_fence,
        pam_scope_digest=request.pam_scope_digest,
    )
    assert changed != request.pam_execution_binding_digest

    with pytest.raises(ValidationError, match="binding digest"):
        _request(pam_execution_binding_digest=changed)


def test_replay_registry_failure_or_non_boolean_result_fails_closed() -> None:
    signer = _Signer(b"\x22" * 32)
    authorization = _authorization(signer)
    encoded = issue_publishing_recovery_authorization(
        authorization,
        signer=signer,
    ).canonical_bytes()

    class _Unavailable:
        def consume_once(self, claim: PublishingRecoveryUseClaim) -> bool:
            del claim
            raise OSError("database unavailable")

    with pytest.raises(PublishingRecoveryError, match="consumption-unavailable"):
        verify_publishing_recovery_authorization(
            encoded,
            verifier=signer,
            now=_APPROVED,
            journal_expectation=_expectation(authorization),
            use_registry=_Unavailable(),
        )

    class _Invalid:
        def consume_once(self, claim: PublishingRecoveryUseClaim) -> Any:
            del claim
            return 1

    with pytest.raises(PublishingRecoveryError, match="consumption-invalid"):
        verify_publishing_recovery_authorization(
            encoded,
            verifier=signer,
            now=_APPROVED,
            journal_expectation=_expectation(authorization),
            use_registry=_Invalid(),
        )
