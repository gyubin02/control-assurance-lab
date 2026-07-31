import base64
import hashlib
import json
from datetime import UTC, datetime, tzinfo
from typing import Any, Literal

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import ValidationError

import assurance_lab.evidence.attestation as attestation_module
from assurance_lab.evidence.attestation import (
    ATTESTATION_VERIFIER_ID,
    DSSE_PROFILE,
    MAX_ALLOWED_PAYLOAD_TYPES,
    MAX_DECODED_PAYLOAD_BYTES,
    MAX_ENVELOPE_BYTES,
    MAX_ENVELOPE_SIGNATURES,
    MAX_TRUST_POLICY_BYTES,
    MAX_TRUSTED_KEYS,
    TRUST_POLICY_MEDIA_TYPE,
    TRUST_POLICY_SCHEMA_VERSION,
    AttestationReason,
    AttestationVerification,
    DSSEEnvelope,
    DSSESignature,
    KeyStatus,
    TrustedKey,
    TrustPolicy,
    canonical_payload_bytes,
    dsse_pae,
    parse_dsse_envelope,
    parse_trust_policy,
    verify_dsse_attestation,
)
from assurance_lab.evidence.canonical import (
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)

PAYLOAD_TYPE = "application/vnd.control-assurance.bundle-manifest.v1+json"
OTHER_PAYLOAD_TYPE = "application/vnd.control-assurance.other.v1+json"
ADMISSION_TIME = datetime(2026, 7, 29, 3, 15, tzinfo=UTC)
VALID_FROM = "2026-01-01T00:00:00.000000Z"
VALID_UNTIL = "2027-01-01T00:00:00.000000Z"


def _private_key(marker: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([marker]) * 32)


def _public_key_base64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def _trusted_key(
    private_key: Ed25519PrivateKey,
    *,
    key_id: str,
    identity: str,
    algorithm: Literal["ed25519"] = "ed25519",
    allowed_payload_types: tuple[str, ...] = (PAYLOAD_TYPE,),
    valid_from: str = VALID_FROM,
    valid_until: str | None = VALID_UNTIL,
    status: KeyStatus = KeyStatus.ACTIVE,
    revocation_effective_at: str | None = None,
    public_key: str | None = None,
) -> TrustedKey:
    return TrustedKey(
        key_id=key_id,
        identity=identity,
        algorithm=algorithm,
        public_key=public_key or _public_key_base64(private_key),
        allowed_payload_types=allowed_payload_types,
        valid_from=valid_from,
        valid_until=valid_until,
        status=status,
        revocation_effective_at=revocation_effective_at,
    )


def _policy(
    *trusted_keys: TrustedKey,
    threshold: int = 1,
) -> TrustPolicy:
    return TrustPolicy(
        media_type=TRUST_POLICY_MEDIA_TYPE,
        schema_version=TRUST_POLICY_SCHEMA_VERSION,
        policy_id="policy:financial-evidence-admission:v1",
        threshold=threshold,
        trusted_keys=trusted_keys,
    )


def _signature(
    private_key: Ed25519PrivateKey,
    *,
    key_id: str,
    payload_type: str,
    payload: bytes,
) -> DSSESignature:
    signed = private_key.sign(dsse_pae(payload_type, payload))
    return DSSESignature(
        keyid=key_id,
        sig=base64.b64encode(signed).decode("ascii"),
    )


def _envelope(
    payload: bytes,
    *signers: tuple[str, Ed25519PrivateKey],
    payload_type: str = PAYLOAD_TYPE,
) -> DSSEEnvelope:
    return DSSEEnvelope(
        payloadType=payload_type,
        payload=base64.b64encode(payload).decode("ascii"),
        signatures=tuple(
            _signature(
                private_key,
                key_id=key_id,
                payload_type=payload_type,
                payload=payload,
            )
            for key_id, private_key in signers
        ),
    )


def _verify(
    envelope: DSSEEnvelope | bytes,
    *,
    policy: TrustPolicy,
    expected_payload: bytes,
    expected_payload_type: str = PAYLOAD_TYPE,
    admission_time: datetime = ADMISSION_TIME,
) -> AttestationReason:
    envelope_bytes = (
        envelope if isinstance(envelope, bytes) else envelope.canonical_bytes()
    )
    result = verify_dsse_attestation(
        envelope_bytes,
        policy=policy,
        expected_payload_type=expected_payload_type,
        expected_payload=expected_payload,
        admission_time=admission_time,
    )
    return result.reason_code


def _replace_envelope_field(
    envelope: DSSEEnvelope,
    field: str,
    value: Any,
) -> bytes:
    document = strict_json_loads(envelope.canonical_bytes())
    assert isinstance(document, dict)
    document[field] = value
    return canonical_json_bytes(document)


def test_fixed_ed25519_dsse_vector_is_stable_for_other_verifiers() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    payload = canonical_payload_bytes(
        {
            "profile": "integrity-only",
            "bundle_id": f"cab:sha256:{'ab' * 32}",
        }
    )
    envelope = _envelope(
        payload,
        ("collector-finops-2026q3", private_key),
    )
    trusted_key = _trusted_key(
        private_key,
        key_id="collector-finops-2026q3",
        identity="spiffe://assurance.example/collector/finops",
    )
    policy = _policy(trusted_key)

    assert _public_key_base64(private_key) == (
        "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="
    )
    assert envelope.canonical_bytes() == (
        b'{"payload":"eyJidW5kbGVfaWQiOiJjYWI6c2hhMjU2OmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJ'
        b'hYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWIiLCJwcm9maWxlIjoiaW'
        b'50ZWdyaXR5LW9ubHkifQ==","payloadType":"application/vnd.control-assurance.bu'
        b'ndle-manifest.v1+json","signatures":[{"keyid":"collector-finops-2026q3","si'
        b'g":"NyFCsg6i+0Q82hFLQadB22m0AvCOgHrq7FRethMboXTI2PQu/CJB+kLmgDC6ubDLbb/LRPd'
        b'Mo5HQvCZdspuqCA=="}]}'
    )

    result = verify_dsse_attestation(
        envelope.canonical_bytes(),
        policy=policy,
        expected_payload_type=PAYLOAD_TYPE,
        expected_payload=payload,
        admission_time=ADMISSION_TIME,
    )

    assert result.verified is True
    assert result.reason_code == AttestationReason.VERIFIED
    assert result.accepted_key_ids == ("collector-finops-2026q3",)
    assert result.accepted_identities == (
        "spiffe://assurance.example/collector/finops",
    )
    assert result.profile == DSSE_PROFILE
    assert result.verifier_id == ATTESTATION_VERIFIER_ID
    assert result.raw_envelope_sha256 == hashlib.sha256(
        envelope.canonical_bytes()
    ).hexdigest()
    assert result.expected_payload_sha256 == hashlib.sha256(payload).hexdigest()
    assert result.expected_payload_type == PAYLOAD_TYPE
    assert result.trust_policy_sha256 == hashlib.sha256(
        policy.canonical_bytes()
    ).hexdigest()
    assert result.policy_id == policy.policy_id
    assert result.admission_time == "2026-07-29T03:15:00.000000Z"


def test_pae_uses_utf8_byte_lengths_exactly_as_dsse_v1_requires() -> None:
    assert dsse_pae("type/\N{LATIN SMALL LETTER E WITH ACUTE}", b"\x00\xff") == (
        b"DSSEv1 7 type/\xc3\xa9 2 \x00\xff"
    )


def test_canonical_payload_helper_uses_rfc8785() -> None:
    assert canonical_payload_bytes({"z": 2, "a": [True, None]}) == (
        b'{"a":[true,null],"z":2}'
    )


def test_threshold_counts_two_distinct_trusted_identities() -> None:
    first = _private_key(1)
    second = _private_key(2)
    payload = canonical_payload_bytes({"bundle_id": "cab:two-party"})
    envelope = _envelope(payload, ("key:a", first), ("key:b", second))
    policy = _policy(
        _trusted_key(first, key_id="key:a", identity="collector:a"),
        _trusted_key(second, key_id="key:b", identity="collector:b"),
        threshold=2,
    )

    result = verify_dsse_attestation(
        envelope.canonical_bytes(),
        policy=policy,
        expected_payload_type=PAYLOAD_TYPE,
        expected_payload=payload,
        admission_time=ADMISSION_TIME,
    )

    assert result.verified is True
    assert result.accepted_key_ids == ("key:a", "key:b")
    assert result.accepted_identities == ("collector:a", "collector:b")


def test_signature_removal_fails_the_required_threshold() -> None:
    first = _private_key(1)
    second = _private_key(2)
    payload = canonical_payload_bytes({"bundle_id": "cab:threshold"})
    original = _envelope(payload, ("key:a", first), ("key:b", second))
    reduced = DSSEEnvelope(
        payloadType=original.payload_type,
        payload=original.payload,
        signatures=(original.signatures[0],),
    )
    policy = _policy(
        _trusted_key(first, key_id="key:a", identity="collector:a"),
        _trusted_key(second, key_id="key:b", identity="collector:b"),
        threshold=2,
    )

    assert _verify(reduced, policy=policy, expected_payload=payload) == (
        AttestationReason.THRESHOLD_NOT_MET
    )


def test_authentic_coherent_rewrite_is_not_the_expected_payload() -> None:
    private_key = _private_key(3)
    original = canonical_payload_bytes({"bundle_id": "cab:expected"})
    rewritten = canonical_payload_bytes({"bundle_id": "cab:rewritten"})
    envelope = _envelope(rewritten, ("key:a", private_key))
    policy = _policy(
        _trusted_key(private_key, key_id="key:a", identity="collector:a")
    )

    assert _verify(envelope, policy=policy, expected_payload=original) == (
        AttestationReason.PAYLOAD_MISMATCH
    )


def test_payload_type_substitution_is_rejected_before_signature_admission() -> None:
    private_key = _private_key(3)
    payload = canonical_payload_bytes({"bundle_id": "cab:expected"})
    envelope = _envelope(
        payload,
        ("key:a", private_key),
        payload_type=OTHER_PAYLOAD_TYPE,
    )
    policy = _policy(
        _trusted_key(
            private_key,
            key_id="key:a",
            identity="collector:a",
            allowed_payload_types=(OTHER_PAYLOAD_TYPE,),
        )
    )

    assert _verify(envelope, policy=policy, expected_payload=payload) == (
        AttestationReason.PAYLOAD_TYPE_MISMATCH
    )


def test_unknown_signer_is_not_trusted_by_key_material_in_the_envelope() -> None:
    trusted = _private_key(1)
    outsider = _private_key(9)
    payload = canonical_payload_bytes({"bundle_id": "cab:unknown"})
    envelope = _envelope(payload, ("key:outsider", outsider))
    policy = _policy(
        _trusted_key(trusted, key_id="key:trusted", identity="collector:trusted")
    )

    assert _verify(envelope, policy=policy, expected_payload=payload) == (
        AttestationReason.UNKNOWN_SIGNER
    )


def test_wrong_private_key_under_a_trusted_key_id_has_invalid_signature() -> None:
    trusted = _private_key(1)
    outsider = _private_key(9)
    payload = canonical_payload_bytes({"bundle_id": "cab:forged"})
    envelope = _envelope(payload, ("key:trusted", outsider))
    policy = _policy(
        _trusted_key(trusted, key_id="key:trusted", identity="collector:trusted")
    )

    assert _verify(envelope, policy=policy, expected_payload=payload) == (
        AttestationReason.INVALID_SIGNATURE
    )


def test_duplicate_signature_key_id_is_rejected() -> None:
    private_key = _private_key(1)
    payload = canonical_payload_bytes({"bundle_id": "cab:duplicate-signature"})
    signature = _signature(
        private_key,
        key_id="key:a",
        payload_type=PAYLOAD_TYPE,
        payload=payload,
    )
    envelope = DSSEEnvelope(
        payloadType=PAYLOAD_TYPE,
        payload=base64.b64encode(payload).decode("ascii"),
        signatures=(signature, signature),
    )
    policy = _policy(
        _trusted_key(private_key, key_id="key:a", identity="collector:a")
    )

    assert _verify(envelope, policy=policy, expected_payload=payload) == (
        AttestationReason.DUPLICATE_SIGNER
    )


def test_two_rotation_keys_for_one_identity_are_one_signer_not_two() -> None:
    first = _private_key(1)
    second = _private_key(2)
    payload = canonical_payload_bytes({"bundle_id": "cab:rotation-overlap"})
    envelope = _envelope(payload, ("key:old", first), ("key:new", second))
    policy = _policy(
        _trusted_key(first, key_id="key:old", identity="collector:a"),
        _trusted_key(second, key_id="key:new", identity="collector:a"),
        threshold=2,
    )

    assert _verify(envelope, policy=policy, expected_payload=payload) == (
        AttestationReason.DUPLICATE_SIGNER
    )


def test_duplicate_key_id_in_external_policy_is_rejected() -> None:
    private_key = _private_key(1)
    payload = canonical_payload_bytes({"bundle_id": "cab:duplicate-policy"})
    envelope = _envelope(payload, ("key:a", private_key))
    trusted_key = _trusted_key(
        private_key,
        key_id="key:a",
        identity="collector:a",
    )

    with pytest.raises(ValidationError, match="key ids must be unique"):
        _policy(trusted_key, trusted_key)

    valid_policy = _policy(trusted_key)
    constructed_policy = valid_policy.model_copy(
        update={"trusted_keys": (trusted_key, trusted_key)}
    )
    assert _verify(
        envelope,
        policy=constructed_policy,
        expected_payload=payload,
    ) == AttestationReason.MALFORMED_POLICY


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("payload", "YQ"),
        ("payload", "%%%="),
        ("payload", "YR=="),
        ("signature", "YQ"),
        ("signature", "_w=="),
    ],
)
def test_malformed_or_noncanonical_base64_is_explicitly_rejected(
    field: str,
    value: str,
) -> None:
    private_key = _private_key(1)
    payload = canonical_payload_bytes({"bundle_id": "cab:base64"})
    envelope = _envelope(payload, ("key:a", private_key))
    document = strict_json_loads(envelope.canonical_bytes())
    assert isinstance(document, dict)
    if field == "payload":
        document["payload"] = value
    else:
        signatures = document["signatures"]
        assert isinstance(signatures, list)
        signature = signatures[0]
        assert isinstance(signature, dict)
        signature["sig"] = value
    policy = _policy(
        _trusted_key(private_key, key_id="key:a", identity="collector:a")
    )

    assert _verify(
        canonical_json_bytes(document),
        policy=policy,
        expected_payload=payload,
    ) == AttestationReason.MALFORMED_BASE64


@pytest.mark.parametrize(
    ("trusted_key_overrides", "expected_reason"),
    [
        (
            {"valid_from": "2026-08-01T00:00:00.000000Z"},
            AttestationReason.KEY_NOT_YET_VALID,
        ),
        (
            {"valid_until": "2026-07-01T00:00:00.000000Z"},
            AttestationReason.KEY_EXPIRED,
        ),
        (
            {"status": KeyStatus.DISABLED},
            AttestationReason.KEY_DISABLED,
        ),
        (
            {
                "status": KeyStatus.REVOKED,
                "revocation_effective_at": "2026-07-01T00:00:00.000000Z",
            },
            AttestationReason.KEY_REVOKED,
        ),
    ],
)
def test_key_state_is_evaluated_at_trusted_admission_time(
    trusted_key_overrides: dict[str, Any],
    expected_reason: AttestationReason,
) -> None:
    private_key = _private_key(1)
    payload = canonical_payload_bytes({"bundle_id": "cab:key-state"})
    envelope = _envelope(payload, ("key:a", private_key))
    trusted_key = _trusted_key(
        private_key,
        key_id="key:a",
        identity="collector:a",
        **trusted_key_overrides,
    )

    assert _verify(
        envelope,
        policy=_policy(trusted_key),
        expected_payload=payload,
    ) == expected_reason


def test_revoked_key_can_verify_a_trusted_admission_before_revocation() -> None:
    private_key = _private_key(1)
    payload = canonical_payload_bytes({"bundle_id": "cab:historical"})
    envelope = _envelope(payload, ("key:a", private_key))
    trusted_key = _trusted_key(
        private_key,
        key_id="key:a",
        identity="collector:a",
        status=KeyStatus.REVOKED,
        revocation_effective_at="2026-07-01T00:00:00.000000Z",
    )

    assert _verify(
        envelope,
        policy=_policy(trusted_key),
        expected_payload=payload,
        admission_time=datetime(2026, 6, 30, 23, 59, 59, tzinfo=UTC),
    ) == AttestationReason.VERIFIED


def test_naive_admission_time_is_rejected_instead_of_assuming_a_timezone() -> None:
    private_key = _private_key(1)
    payload = canonical_payload_bytes({"bundle_id": "cab:naive-time"})
    envelope = _envelope(payload, ("key:a", private_key))
    policy = _policy(
        _trusted_key(private_key, key_id="key:a", identity="collector:a")
    )

    assert _verify(
        envelope,
        policy=policy,
        expected_payload=payload,
        admission_time=datetime(2026, 7, 29, 3, 15),
    ) == AttestationReason.INVALID_ADMISSION_TIME


@pytest.mark.parametrize("year", [1, 9, 99, 999])
def test_early_admission_years_have_a_canonical_four_digit_timestamp(
    year: int,
) -> None:
    private_key = _private_key(1)
    payload = canonical_payload_bytes({"bundle_id": "cab:early-time"})
    envelope = _envelope(payload, ("key:a", private_key))
    policy = _policy(
        _trusted_key(
            private_key,
            key_id="key:a",
            identity="collector:a",
            valid_from="0001-01-01T00:00:00.000000Z",
            valid_until=None,
        )
    )

    result = verify_dsse_attestation(
        envelope.canonical_bytes(),
        policy=policy,
        expected_payload_type=PAYLOAD_TYPE,
        expected_payload=payload,
        admission_time=datetime(year, 1, 2, 3, 4, 5, 6, tzinfo=UTC),
    )

    assert result.reason_code == AttestationReason.VERIFIED
    assert result.admission_time == f"{year:04d}-01-02T03:04:05.000006Z"


def test_hostile_datetime_behavior_is_an_invalid_time_not_an_exception() -> None:
    class HostileDateTime(datetime):
        def utcoffset(self) -> None:
            raise RuntimeError("must not run subclass code")

    class HostileTimezone(tzinfo):
        def utcoffset(self, value: datetime | None) -> None:
            raise RuntimeError("hostile timezone")

        def dst(self, value: datetime | None) -> None:
            return None

        def tzname(self, value: datetime | None) -> str:
            return "hostile"

    private_key = _private_key(1)
    payload = canonical_payload_bytes({"bundle_id": "cab:hostile-time"})
    envelope = _envelope(payload, ("key:a", private_key))
    policy = _policy(
        _trusted_key(private_key, key_id="key:a", identity="collector:a")
    )

    for admission_time in (
        HostileDateTime(2026, 7, 29, tzinfo=UTC),
        datetime(2026, 7, 29, tzinfo=HostileTimezone()),
    ):
        assert _verify(
            envelope,
            policy=policy,
            expected_payload=payload,
            admission_time=admission_time,
        ) == AttestationReason.INVALID_ADMISSION_TIME


def test_key_that_does_not_allow_exact_payload_type_is_rejected() -> None:
    private_key = _private_key(1)
    payload = canonical_payload_bytes({"bundle_id": "cab:denied-type"})
    envelope = _envelope(payload, ("key:a", private_key))
    policy = _policy(
        _trusted_key(
            private_key,
            key_id="key:a",
            identity="collector:a",
            allowed_payload_types=(OTHER_PAYLOAD_TYPE,),
        )
    )

    assert _verify(envelope, policy=policy, expected_payload=payload) == (
        AttestationReason.PAYLOAD_TYPE_NOT_ALLOWED
    )


def test_profile_rejects_unknown_key_algorithm_without_fallback() -> None:
    private_key = _private_key(1)
    payload = canonical_payload_bytes({"bundle_id": "cab:algorithm"})
    envelope = _envelope(payload, ("key:a", private_key))
    trusted_key = _trusted_key(
        private_key,
        key_id="key:a",
        identity="collector:a",
    )
    document = trusted_key.model_dump(mode="json")
    document["algorithm"] = "ed25519ph"
    with pytest.raises(ValidationError):
        TrustedKey.model_validate(document)

    invalid_key = trusted_key.model_copy(update={"algorithm": "ed25519ph"})
    invalid_policy = _policy(trusted_key).model_copy(
        update={"trusted_keys": (invalid_key,)}
    )
    assert _verify(
        envelope,
        policy=invalid_policy,
        expected_payload=payload,
    ) == AttestationReason.MALFORMED_POLICY


def test_invalid_public_key_length_is_rejected_at_the_policy_boundary() -> None:
    private_key = _private_key(1)
    payload = canonical_payload_bytes({"bundle_id": "cab:public-key"})
    envelope = _envelope(payload, ("key:a", private_key))
    with pytest.raises(ValidationError):
        _trusted_key(
            private_key,
            key_id="key:a",
            identity="collector:a",
            public_key=base64.b64encode(b"too-short").decode("ascii"),
        )

    trusted_key = _trusted_key(
        private_key,
        key_id="key:a",
        identity="collector:a",
    )
    invalid_key = trusted_key.model_copy(
        update={"public_key": base64.b64encode(b"too-short").decode("ascii")}
    )
    invalid_policy = _policy(trusted_key).model_copy(
        update={"trusted_keys": (invalid_key,)}
    )
    assert _verify(
        envelope,
        policy=invalid_policy,
        expected_payload=payload,
    ) == AttestationReason.MALFORMED_POLICY


def test_empty_external_policy_denies_unsigned_envelope() -> None:
    payload = canonical_payload_bytes({"bundle_id": "cab:deny-default"})
    envelope = _envelope(payload)

    assert _verify(
        envelope,
        policy=_policy(),
        expected_payload=payload,
    ) == AttestationReason.THRESHOLD_NOT_MET


def test_malformed_json_and_unknown_fields_fail_closed() -> None:
    private_key = _private_key(1)
    payload = canonical_payload_bytes({"bundle_id": "cab:strict-wire"})
    envelope = _envelope(payload, ("key:a", private_key))
    policy = _policy(
        _trusted_key(private_key, key_id="key:a", identity="collector:a")
    )
    duplicate_member = (
        b'{"payload":"","payload":"","payloadType":"'
        + PAYLOAD_TYPE.encode("ascii")
        + b'","signatures":[]}'
    )
    with_extension = _replace_envelope_field(envelope, "public_key", "forged")

    assert _verify(
        duplicate_member,
        policy=policy,
        expected_payload=payload,
    ) == AttestationReason.MALFORMED_ENVELOPE
    assert _verify(
        with_extension,
        policy=policy,
        expected_payload=payload,
    ) == AttestationReason.MALFORMED_ENVELOPE


def test_wire_models_are_frozen_and_do_not_accept_coercion() -> None:
    private_key = _private_key(1)
    payload = canonical_payload_bytes({"bundle_id": "cab:immutable"})
    envelope = _envelope(payload, ("key:a", private_key))
    policy = _policy(
        _trusted_key(private_key, key_id="key:a", identity="collector:a")
    )

    with pytest.raises(ValidationError):
        envelope.payload = ""
    with pytest.raises(ValidationError):
        TrustPolicy(
            media_type=TRUST_POLICY_MEDIA_TYPE,
            schema_version=TRUST_POLICY_SCHEMA_VERSION,
            policy_id="policy:test",
            threshold="1",  # type: ignore[arg-type]
            trusted_keys=policy.trusted_keys,
        )
    with pytest.raises(ValidationError):
        DSSEEnvelope.model_validate(
            {
                "payload_type": PAYLOAD_TYPE,
                "payload": envelope.payload,
                "signatures": envelope.signatures,
            }
        )


def test_policy_requires_explicit_canonical_wire_document() -> None:
    private_key = _private_key(1)
    policy = _policy(
        _trusted_key(private_key, key_id="key:a", identity="collector:a")
    )
    encoded = policy.canonical_bytes()

    assert parse_trust_policy(encoded) == policy
    with pytest.raises(ValueError, match="RFC 8785"):
        parse_trust_policy(encoded + b"\n")
    document = strict_json_loads(encoded)
    assert isinstance(document, dict)
    del document["media_type"]
    with pytest.raises(ValidationError):
        TrustPolicy.model_validate(document)


def test_envelope_json_layout_is_not_confused_with_signed_payload_bytes() -> None:
    private_key = _private_key(1)
    payload = canonical_payload_bytes({"bundle_id": "cab:json-layout"})
    envelope = _envelope(payload, ("key:a", private_key))
    policy = _policy(
        _trusted_key(private_key, key_id="key:a", identity="collector:a")
    )
    noncanonical_layout = (
        b'{ "signatures" : '
        + canonical_json_bytes(
            [
                signature.model_dump(mode="json")
                for signature in envelope.signatures
            ]
        )
        + b', "payload" : '
        + canonical_json_bytes(envelope.payload)
        + b', "payloadType" : '
        + canonical_json_bytes(envelope.payload_type)
        + b" }"
    )

    assert parse_dsse_envelope(noncanonical_layout) == envelope
    assert _verify(
        noncanonical_layout,
        policy=policy,
        expected_payload=payload,
    ) == AttestationReason.VERIFIED


def test_model_copy_cannot_remove_revocation_semantics_at_verify_boundary() -> None:
    private_key = _private_key(1)
    payload = canonical_payload_bytes({"bundle_id": "cab:copied-policy"})
    envelope = _envelope(payload, ("key:a", private_key))
    trusted_key = _trusted_key(
        private_key,
        key_id="key:a",
        identity="collector:a",
    )
    invalid_key = trusted_key.model_copy(
        update={
            "status": KeyStatus.REVOKED,
            "revocation_effective_at": None,
        }
    )
    invalid_policy = _policy(trusted_key).model_copy(
        update={"trusted_keys": (invalid_key,)}
    )

    result = verify_dsse_attestation(
        envelope.canonical_bytes(),
        policy=invalid_policy,
        expected_payload_type=PAYLOAD_TYPE,
        expected_payload=payload,
        admission_time=ADMISSION_TIME,
    )

    assert result.verified is False
    assert result.reason_code == AttestationReason.MALFORMED_POLICY
    assert result.threshold_required is None
    assert result.trust_policy_sha256 is None


def test_model_construct_cannot_bypass_policy_threshold_validation() -> None:
    private_key = _private_key(1)
    payload = canonical_payload_bytes({"bundle_id": "cab:constructed-policy"})
    envelope = _envelope(payload, ("key:a", private_key))
    trusted_key = _trusted_key(
        private_key,
        key_id="key:a",
        identity="collector:a",
    )
    invalid_policy = TrustPolicy.model_construct(
        media_type=TRUST_POLICY_MEDIA_TYPE,
        schema_version=TRUST_POLICY_SCHEMA_VERSION,
        policy_id="policy:constructed",
        threshold=0,
        trusted_keys=(trusted_key,),
    )

    assert _verify(
        envelope,
        policy=invalid_policy,
        expected_payload=payload,
    ) == AttestationReason.MALFORMED_POLICY


def test_hostile_programmatic_policy_container_fails_closed() -> None:
    class HostileList(list[TrustedKey]):
        def __len__(self) -> int:
            raise RuntimeError("hostile container")

        def __iter__(self) -> Any:
            raise RuntimeError("hostile container")

    private_key = _private_key(1)
    payload = canonical_payload_bytes({"bundle_id": "cab:hostile-policy"})
    envelope = _envelope(payload, ("key:a", private_key))
    trusted_key = _trusted_key(
        private_key,
        key_id="key:a",
        identity="collector:a",
    )
    invalid_policy = TrustPolicy.model_construct(
        media_type=TRUST_POLICY_MEDIA_TYPE,
        schema_version=TRUST_POLICY_SCHEMA_VERSION,
        policy_id="policy:hostile-container",
        threshold=1,
        trusted_keys=HostileList([trusted_key]),
    )

    result = verify_dsse_attestation(
        envelope.canonical_bytes(),
        policy=invalid_policy,
        expected_payload_type=PAYLOAD_TYPE,
        expected_payload=payload,
        admission_time=ADMISSION_TIME,
    )

    assert result.reason_code == AttestationReason.MALFORMED_POLICY
    assert result.threshold_required is None
    assert result.trust_policy_sha256 is None


def test_one_raw_public_key_cannot_impersonate_two_threshold_identities() -> None:
    first = _private_key(1)
    second = _private_key(2)
    payload = canonical_payload_bytes({"bundle_id": "cab:one-key-two-identities"})
    envelope = _envelope(payload, ("key:a", first), ("key:b", first))
    first_key = _trusted_key(first, key_id="key:a", identity="collector:a")
    second_key = _trusted_key(second, key_id="key:b", identity="collector:b")
    duplicate_material = second_key.model_copy(
        update={"public_key": first_key.public_key}
    )

    with pytest.raises(ValidationError, match="public-key material must be unique"):
        _policy(first_key, duplicate_material, threshold=2)

    valid_policy = _policy(first_key, second_key, threshold=2)
    constructed_policy = valid_policy.model_copy(
        update={"trusted_keys": (first_key, duplicate_material)}
    )
    assert _verify(
        envelope,
        policy=constructed_policy,
        expected_payload=payload,
    ) == AttestationReason.MALFORMED_POLICY


@pytest.mark.parametrize("signature_length", [0, 63, 65])
def test_profile_requires_exactly_64_signature_bytes(
    signature_length: int,
) -> None:
    with pytest.raises(ValidationError):
        DSSESignature(
            keyid="key:a",
            sig=base64.b64encode(b"x" * signature_length).decode("ascii"),
        )


def test_profile_requires_keyid_even_though_general_dsse_makes_it_optional() -> None:
    payload = canonical_payload_bytes({"bundle_id": "cab:keyid-required"})
    document = {
        "payload": base64.b64encode(payload).decode("ascii"),
        "payloadType": PAYLOAD_TYPE,
        "signatures": [
            {"sig": base64.b64encode(b"x" * 64).decode("ascii")}
        ],
    }

    with pytest.raises(ValidationError):
        parse_dsse_envelope(canonical_json_bytes(document))


def test_envelope_byte_limit_is_checked_before_json_or_policy_work() -> None:
    payload = canonical_payload_bytes({"bundle_id": "cab:oversized-envelope"})
    result = verify_dsse_attestation(
        b" " * (MAX_ENVELOPE_BYTES + 1),
        policy=_policy(),
        expected_payload_type=PAYLOAD_TYPE,
        expected_payload=payload,
        admission_time=ADMISSION_TIME,
    )

    assert result.reason_code == AttestationReason.RESOURCE_LIMIT_EXCEEDED
    assert result.raw_envelope_sha256 is None
    assert result.threshold_required is None


def test_signature_count_limit_precedes_signature_base64_traversal() -> None:
    payload = canonical_payload_bytes({"bundle_id": "cab:too-many-signatures"})
    document = {
        "payload": base64.b64encode(payload).decode("ascii"),
        "payloadType": PAYLOAD_TYPE,
        "signatures": [
            {"keyid": f"key:{index}", "sig": "%%%="}
            for index in range(MAX_ENVELOPE_SIGNATURES + 1)
        ],
    }

    assert _verify(
        canonical_json_bytes(document),
        policy=_policy(),
        expected_payload=payload,
    ) == AttestationReason.RESOURCE_LIMIT_EXCEEDED


def test_envelope_depth_limit_precedes_model_validation() -> None:
    payload = canonical_payload_bytes({"bundle_id": "cab:deep-envelope"})
    document = {
        "payload": base64.b64encode(payload).decode("ascii"),
        "payloadType": PAYLOAD_TYPE,
        "signatures": [],
        "extension": {"a": {"b": {"c": {"d": "too-deep"}}}},
    }

    assert _verify(
        canonical_json_bytes(document),
        policy=_policy(),
        expected_payload=payload,
    ) == AttestationReason.RESOURCE_LIMIT_EXCEEDED


def test_huge_raw_json_integer_is_normalized_by_parser_and_verifier() -> None:
    private_key = _private_key(1)
    payload = canonical_payload_bytes({"bundle_id": "cab:huge-integer"})
    envelope = _envelope(payload, ("key:a", private_key))
    document_prefix = envelope.canonical_bytes()[:-1]
    hostile = document_prefix + b',"unused":' + (b"9" * 4_301) + b"}"
    policy = _policy(
        _trusted_key(private_key, key_id="key:a", identity="collector:a")
    )

    with pytest.raises(StrictJSONError, match="integer exceeds"):
        strict_json_loads(b'{"unused":' + (b"9" * 4_301) + b"}")
    with pytest.raises(StrictJSONError, match="integer exceeds"):
        parse_dsse_envelope(hostile)

    result = verify_dsse_attestation(
        hostile,
        policy=policy,
        expected_payload_type=PAYLOAD_TYPE,
        expected_payload=payload,
        admission_time=ADMISSION_TIME,
    )
    assert result.reason_code == AttestationReason.RESOURCE_LIMIT_EXCEEDED


def test_decoded_payload_limit_is_preflighted_before_json_materialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    parser = strict_json_loads

    def observed_parser(
        value: bytes,
        *,
        limits: Any,
    ) -> Any:
        calls.append(len(value))
        return parser(value, limits=limits)

    monkeypatch.setattr(attestation_module, "strict_json_loads", observed_parser)

    exact_payload = b"x" * MAX_DECODED_PAYLOAD_BYTES
    exact_document = {
        "payload": base64.b64encode(exact_payload).decode("ascii"),
        "payloadType": PAYLOAD_TYPE,
        "signatures": [],
    }
    exact_wire = json.dumps(
        exact_document,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    assert parse_dsse_envelope(exact_wire).payload_bytes() == exact_payload
    assert calls == [len(exact_wire)]

    calls.clear()
    oversized_payload = b"x" * (MAX_DECODED_PAYLOAD_BYTES + 1)
    document = {
        "payload": base64.b64encode(oversized_payload).decode("ascii"),
        "payloadType": PAYLOAD_TYPE,
        "signatures": [],
    }
    oversized_wire = json.dumps(
        document,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    with pytest.raises(ValueError, match="decoded payload exceeds"):
        parse_dsse_envelope(oversized_wire)
    assert calls == []

    assert _verify(
        oversized_wire,
        policy=_policy(),
        expected_payload=b"different",
    ) == AttestationReason.RESOURCE_LIMIT_EXCEEDED
    assert calls == []

    escaped_member_wire = oversized_wire.replace(
        b'"payload"',
        b'"pay\\u006coad"',
        1,
    )
    with pytest.raises(ValueError, match="decoded payload exceeds"):
        parse_dsse_envelope(escaped_member_wire)
    assert calls == []


def test_allowed_payload_type_limit_is_preflighted_before_json_materialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    parser = strict_json_loads

    def observed_parser(
        value: bytes,
        *,
        limits: Any,
    ) -> Any:
        calls.append(len(value))
        return parser(value, limits=limits)

    monkeypatch.setattr(attestation_module, "strict_json_loads", observed_parser)
    private_key = _private_key(1)
    exact_types = tuple(
        f"application/vnd.example.type-{index:02d}+json"
        for index in range(MAX_ALLOWED_PAYLOAD_TYPES)
    )
    trusted_key = _trusted_key(
        private_key,
        key_id="key:a",
        identity="collector:a",
        allowed_payload_types=exact_types,
    )
    exact_policy = _policy(trusted_key)

    assert parse_trust_policy(exact_policy.canonical_bytes()) == exact_policy
    assert calls == [len(exact_policy.canonical_bytes())]

    calls.clear()
    oversized_document = exact_policy.model_dump(mode="json")
    oversized_key = oversized_document["trusted_keys"][0]
    oversized_key["allowed_payload_types"] = [
        *exact_types,
        "application/vnd.example.type-16+json",
    ]
    oversized_wire = canonical_json_bytes(oversized_document)
    with pytest.raises(ValueError, match="allowed payload type count exceeds"):
        parse_trust_policy(oversized_wire)
    assert calls == []

    escaped_member_wire = oversized_wire.replace(
        b'"allowed_payload_types"',
        b'"allowed_payload_\\u0074ypes"',
        1,
    )
    with pytest.raises(ValueError, match="allowed payload type count exceeds"):
        parse_trust_policy(escaped_member_wire)
    assert calls == []


def test_trust_policy_profile_limits_keys_types_and_wire_bytes() -> None:
    private_key = _private_key(1)
    trusted_key = _trusted_key(
        private_key,
        key_id="key:a",
        identity="collector:a",
    )
    with pytest.raises(ValidationError):
        TrustedKey(
            **{
                **trusted_key.model_dump(mode="python"),
                "allowed_payload_types": tuple(
                    f"application/vnd.example.type-{index}+json"
                    for index in range(MAX_ALLOWED_PAYLOAD_TYPES + 1)
                ),
            }
        )

    oversized_policy = TrustPolicy.model_construct(
        media_type=TRUST_POLICY_MEDIA_TYPE,
        schema_version=TRUST_POLICY_SCHEMA_VERSION,
        policy_id="policy:too-many-keys",
        threshold=1,
        trusted_keys=tuple(
            trusted_key for _ in range(MAX_TRUSTED_KEYS + 1)
        ),
    )
    payload = canonical_payload_bytes({"bundle_id": "cab:bounded-policy"})
    assert _verify(
        _envelope(payload),
        policy=oversized_policy,
        expected_payload=payload,
    ) == AttestationReason.MALFORMED_POLICY

    with pytest.raises(ValueError):
        parse_trust_policy(b" " * (MAX_TRUST_POLICY_BYTES + 1))


def test_verification_decision_rejects_contradictory_states() -> None:
    with pytest.raises(ValidationError):
        AttestationVerification(
            verified=True,
            reason_code=AttestationReason.INVALID_SIGNATURE,
            threshold_required=1,
        )
    with pytest.raises(ValidationError):
        AttestationVerification(
            verified=False,
            reason_code=AttestationReason.VERIFIED,
            threshold_required=1,
        )
    with pytest.raises(ValidationError, match="complete provenance"):
        AttestationVerification(
            verified=True,
            reason_code=AttestationReason.VERIFIED,
            threshold_required=1,
            accepted_key_ids=("key:a",),
            accepted_identities=("collector:a",),
        )

    private_key = _private_key(1)
    payload = canonical_payload_bytes({"bundle_id": "cab:decision-coherence"})
    result = verify_dsse_attestation(
        _envelope(payload, ("key:a", private_key)).canonical_bytes(),
        policy=_policy(
            _trusted_key(
                private_key,
                key_id="key:a",
                identity="collector:a",
            )
        ),
        expected_payload_type=PAYLOAD_TYPE,
        expected_payload=payload,
        admission_time=ADMISSION_TIME,
    )
    assert strict_json_loads(result.canonical_bytes())["verified"] is True

    forged = result.model_copy(
        update={"reason_code": AttestationReason.INVALID_SIGNATURE}
    )
    with pytest.raises(ValidationError):
        AttestationVerification.model_validate(forged)
    with pytest.raises(ValidationError):
        forged.canonical_bytes()
