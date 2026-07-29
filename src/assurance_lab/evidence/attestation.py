"""The fail-closed Control Assurance DSSE Profile v1 trust boundary.

The profile uses in-toto DSSE v1 PAE, but deliberately narrows the wire format:
standard canonical RFC 4648 base64, a required ``keyid``, Ed25519 signatures,
bounded JSON, and an external canonical trust policy.  It is not a claim to
accept every envelope permitted by the general DSSE protocol.

That is deliberately narrower than provenance as a whole.  A successful result
does not prove that the producer process was honest, that the admission
timestamp is true, that private keys were well protected, that storage is WORM,
that an otherwise valid envelope is fresh rather than replayed, or that a
signature has legal non-repudiation effect.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, ClassVar, Literal, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)

DSSE_PAE_VERSION = b"DSSEv1"
DSSE_PROFILE: Literal["control-assurance-dsse-profile-v1"] = (
    "control-assurance-dsse-profile-v1"
)
ATTESTATION_VERIFIER_ID: Literal[
    "control-assurance-lab/python-attestation-v1"
] = "control-assurance-lab/python-attestation-v1"
TRUST_POLICY_MEDIA_TYPE: Literal[
    "application/vnd.control-assurance.trust-policy.v1+json"
] = "application/vnd.control-assurance.trust-policy.v1+json"
TRUST_POLICY_SCHEMA_VERSION: Literal["1.0.0"] = "1.0.0"

MAX_ENVELOPE_BYTES = 4 * 1024 * 1024
MAX_TRUST_POLICY_BYTES = 1 * 1024 * 1024
MAX_DECODED_PAYLOAD_BYTES = 2 * 1024 * 1024
MAX_ENCODED_PAYLOAD_LENGTH = 4 * ((MAX_DECODED_PAYLOAD_BYTES + 2) // 3)
MAX_ENVELOPE_SIGNATURES = 64
MAX_TRUSTED_KEYS = 256
MAX_ALLOWED_PAYLOAD_TYPES = 16
MAX_KEY_ID_LENGTH = 256
MAX_IDENTITY_LENGTH = 512
MAX_PAYLOAD_TYPE_LENGTH = 512
ED25519_PUBLIC_KEY_BYTES = 32
ED25519_PUBLIC_KEY_BASE64_LENGTH = 44
ED25519_SIGNATURE_BYTES = 64
ED25519_SIGNATURE_BASE64_LENGTH = 88

ENVELOPE_JSON_LIMITS = JSONLimits(
    max_bytes=MAX_ENVELOPE_BYTES,
    max_line_bytes=MAX_ENVELOPE_BYTES,
    max_depth=4,
    max_collection_items=MAX_ENVELOPE_SIGNATURES,
    max_string_length=MAX_ENCODED_PAYLOAD_LENGTH,
)
TRUST_POLICY_JSON_LIMITS = JSONLimits(
    max_bytes=MAX_TRUST_POLICY_BYTES,
    max_line_bytes=MAX_TRUST_POLICY_BYTES,
    max_depth=5,
    max_collection_items=MAX_TRUSTED_KEYS,
    max_string_length=MAX_IDENTITY_LENGTH,
)

_CANONICAL_TIMESTAMP_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$"
)
_KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,255}$")
_VISIBLE_ASCII_PATTERN = re.compile(r"^[\x21-\x7e]+$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class _FrozenStrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        revalidate_instances="always",
        strict=True,
    )


def _tuple_from_array(value: object) -> object:
    if isinstance(value, tuple):
        return value
    if isinstance(value, list):
        return tuple(value)
    raise ValueError("value must be an array")


def _canonical_base64_decode(
    value: str,
    *,
    max_encoded_length: int,
    expected_decoded_length: int | None = None,
) -> bytes:
    if len(value) > max_encoded_length:
        raise ValueError("base64 value exceeds the configured length limit")
    try:
        encoded = value.encode("ascii", errors="strict")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ValueError("value is not canonical RFC 4648 base64") from exc
    if base64.b64encode(decoded) != encoded:
        raise ValueError("value is not canonical RFC 4648 base64")
    if expected_decoded_length is not None and len(decoded) != expected_decoded_length:
        raise ValueError(
            f"decoded value must be exactly {expected_decoded_length} bytes"
        )
    return decoded


def _validate_payload_base64(value: str) -> str:
    decoded = _canonical_base64_decode(
        value,
        max_encoded_length=MAX_ENCODED_PAYLOAD_LENGTH,
    )
    if len(decoded) > MAX_DECODED_PAYLOAD_BYTES:
        raise ValueError("decoded payload exceeds the configured byte limit")
    return value


def _validate_signature_base64(value: str) -> str:
    _canonical_base64_decode(
        value,
        max_encoded_length=ED25519_SIGNATURE_BASE64_LENGTH,
        expected_decoded_length=ED25519_SIGNATURE_BYTES,
    )
    return value


def _validate_public_key_base64(value: str) -> str:
    _canonical_base64_decode(
        value,
        max_encoded_length=ED25519_PUBLIC_KEY_BASE64_LENGTH,
        expected_decoded_length=ED25519_PUBLIC_KEY_BYTES,
    )
    return value


def _validate_payload_type(value: str) -> str:
    if (
        not value
        or len(value) > MAX_PAYLOAD_TYPE_LENGTH
        or _VISIBLE_ASCII_PATTERN.fullmatch(value) is None
    ):
        raise ValueError("payload type must be non-empty visible ASCII")
    return value


def _validate_identity(value: str) -> str:
    if (
        not value
        or len(value) > MAX_IDENTITY_LENGTH
        or _VISIBLE_ASCII_PATTERN.fullmatch(value) is None
    ):
        raise ValueError("signer identity must be non-empty visible ASCII")
    return value


def _validate_algorithm(value: str) -> str:
    if not value or len(value) > 64 or _VISIBLE_ASCII_PATTERN.fullmatch(value) is None:
        raise ValueError("algorithm must be non-empty visible ASCII")
    return value


def _validate_policy_id(value: str) -> str:
    if not value or len(value) > 256 or _VISIBLE_ASCII_PATTERN.fullmatch(value) is None:
        raise ValueError("policy id must be non-empty visible ASCII")
    return value


def _validate_key_id(value: str) -> str:
    if _KEY_ID_PATTERN.fullmatch(value) is None:
        raise ValueError("key id is not portable or exceeds the length limit")
    return value


def _parse_canonical_timestamp(value: str) -> datetime:
    if _CANONICAL_TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise ValueError("timestamp must use YYYY-MM-DDTHH:MM:SS.ffffffZ")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise ValueError("timestamp is not a valid UTC date and time") from exc
    return parsed.replace(tzinfo=UTC)


def _canonical_admission_time(value: datetime) -> datetime | None:
    if type(value) is not datetime or value.tzinfo is None:
        return None
    try:
        offset = value.utcoffset()
    except Exception:
        return None
    if offset is None:
        return None
    try:
        return value.astimezone(UTC)
    except Exception:
        return None


def _format_canonical_timestamp(value: datetime) -> str:
    return (
        f"{value.year:04d}-{value.month:02d}-{value.day:02d}T"
        f"{value.hour:02d}:{value.minute:02d}:{value.second:02d}."
        f"{value.microsecond:06d}Z"
    )


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class DSSESignature(_FrozenStrictModel):
    """One profile signature; ``keyid`` is required and the key stays external."""

    keyid: str = Field(min_length=1, max_length=MAX_KEY_ID_LENGTH)
    sig: str = Field(
        min_length=ED25519_SIGNATURE_BASE64_LENGTH,
        max_length=ED25519_SIGNATURE_BASE64_LENGTH,
    )

    _key_id_is_safe = field_validator("keyid")(_validate_key_id)
    _signature_is_canonical_base64 = field_validator("sig")(_validate_signature_base64)


class DSSEEnvelope(_FrozenStrictModel):
    """Strict immutable Control Assurance DSSE Profile v1 envelope."""

    payload_type: str = Field(alias="payloadType")
    payload: str = Field(max_length=MAX_ENCODED_PAYLOAD_LENGTH)
    signatures: tuple[DSSESignature, ...] = Field(
        max_length=MAX_ENVELOPE_SIGNATURES
    )

    _payload_type_is_safe = field_validator("payload_type")(_validate_payload_type)
    _payload_is_canonical_base64 = field_validator("payload")(_validate_payload_base64)
    _signatures_are_immutable = field_validator("signatures", mode="before")(
        _tuple_from_array
    )

    def payload_bytes(self) -> bytes:
        return _canonical_base64_decode(
            self.payload,
            max_encoded_length=MAX_ENCODED_PAYLOAD_LENGTH,
        )

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            limits=ENVELOPE_JSON_LIMITS,
        )


class KeyStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    REVOKED = "revoked"


class TrustedKey(_FrozenStrictModel):
    """An externally administered public key and its admission constraints.

    ``valid_until`` is exclusive.  ``revocation_effective_at`` is time-aware:
    a historically trusted admission before that instant can still verify.
    ``disabled`` is an unconditional deny, independent of admission time.
    """

    key_id: str = Field(min_length=1, max_length=MAX_KEY_ID_LENGTH)
    identity: str = Field(min_length=1, max_length=MAX_IDENTITY_LENGTH)
    algorithm: Literal["ed25519"]
    public_key: str = Field(
        min_length=ED25519_PUBLIC_KEY_BASE64_LENGTH,
        max_length=ED25519_PUBLIC_KEY_BASE64_LENGTH,
    )
    allowed_payload_types: tuple[str, ...] = Field(
        max_length=MAX_ALLOWED_PAYLOAD_TYPES
    )
    valid_from: str
    valid_until: str | None = None
    status: KeyStatus
    revocation_effective_at: str | None = None

    _key_id_is_safe = field_validator("key_id")(_validate_key_id)
    _identity_is_safe = field_validator("identity")(_validate_identity)
    _algorithm_is_safe = field_validator("algorithm")(_validate_algorithm)
    _public_key_is_canonical_base64 = field_validator("public_key")(
        _validate_public_key_base64
    )
    _payload_types_are_immutable = field_validator(
        "allowed_payload_types", mode="before"
    )(_tuple_from_array)

    @field_validator("status", mode="before")
    @classmethod
    def status_uses_exact_wire_value(cls, value: object) -> object:
        if isinstance(value, KeyStatus):
            return value
        if type(value) is str:
            try:
                return KeyStatus(value)
            except ValueError as exc:
                raise ValueError("unknown trusted-key status") from exc
        return value

    @field_validator("allowed_payload_types")
    @classmethod
    def payload_types_are_explicit(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        for value in values:
            _validate_payload_type(value)
        if len(set(values)) != len(values):
            raise ValueError("allowed payload types must be unique")
        if values != tuple(sorted(values)):
            raise ValueError("allowed payload types must be sorted")
        return values

    @field_validator("valid_from", "valid_until", "revocation_effective_at")
    @classmethod
    def timestamps_are_canonical(cls, value: str | None) -> str | None:
        if value is not None:
            _parse_canonical_timestamp(value)
        return value

    @model_validator(mode="after")
    def validity_window_is_coherent(self) -> TrustedKey:
        valid_from = _parse_canonical_timestamp(self.valid_from)
        if (
            self.valid_until is not None
            and _parse_canonical_timestamp(self.valid_until) <= valid_from
        ):
            raise ValueError("valid_until must be later than valid_from")
        if self.status == KeyStatus.REVOKED and self.revocation_effective_at is None:
            raise ValueError("revoked keys require revocation_effective_at")
        return self

    def public_key_bytes(self) -> bytes:
        return _canonical_base64_decode(
            self.public_key,
            max_encoded_length=ED25519_PUBLIC_KEY_BASE64_LENGTH,
            expected_decoded_length=ED25519_PUBLIC_KEY_BYTES,
        )


class TrustPolicy(_FrozenStrictModel):
    """Deny-by-default trust input supplied independently of the envelope."""

    media_type: Literal[
        "application/vnd.control-assurance.trust-policy.v1+json"
    ]
    schema_version: Literal["1.0.0"]
    policy_id: str = Field(min_length=1, max_length=256)
    threshold: int = Field(ge=1, le=MAX_TRUSTED_KEYS)
    trusted_keys: tuple[TrustedKey, ...] = Field(max_length=MAX_TRUSTED_KEYS)

    _trusted_keys_are_immutable = field_validator("trusted_keys", mode="before")(
        _tuple_from_array
    )
    _policy_id_is_safe = field_validator("policy_id")(_validate_policy_id)

    @model_validator(mode="after")
    def trusted_key_material_is_unambiguous(self) -> TrustPolicy:
        key_ids = [trusted_key.key_id for trusted_key in self.trusted_keys]
        if len(set(key_ids)) != len(key_ids):
            raise ValueError("trusted key ids must be unique")
        public_keys = [
            trusted_key.public_key_bytes() for trusted_key in self.trusted_keys
        ]
        if len(set(public_keys)) != len(public_keys):
            raise ValueError("trusted Ed25519 public-key material must be unique")
        return self

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            self.model_dump(mode="json"),
            limits=TRUST_POLICY_JSON_LIMITS,
        )


class AttestationReason(StrEnum):
    VERIFIED = "verified"
    INVALID_EXPECTATION = "invalid-expectation"
    INVALID_ADMISSION_TIME = "invalid-admission-time"
    MALFORMED_POLICY = "malformed-policy"
    MALFORMED_ENVELOPE = "malformed-envelope"
    MALFORMED_BASE64 = "malformed-base64"
    RESOURCE_LIMIT_EXCEEDED = "resource-limit-exceeded"
    PAYLOAD_TYPE_MISMATCH = "payload-type-mismatch"
    PAYLOAD_MISMATCH = "payload-mismatch"
    DUPLICATE_TRUSTED_KEY = "duplicate-trusted-key"
    DUPLICATE_SIGNER = "duplicate-signer"
    UNKNOWN_SIGNER = "unknown-signer"
    UNKNOWN_ALGORITHM = "unknown-algorithm"
    PAYLOAD_TYPE_NOT_ALLOWED = "payload-type-not-allowed"
    KEY_NOT_YET_VALID = "key-not-yet-valid"
    KEY_EXPIRED = "key-expired"
    KEY_DISABLED = "key-disabled"
    KEY_REVOKED = "key-revoked"
    INVALID_PUBLIC_KEY = "invalid-public-key"
    INVALID_SIGNATURE = "invalid-signature"
    THRESHOLD_NOT_MET = "threshold-not-met"


class AttestationVerification(_FrozenStrictModel):
    """A coherent decision bound to the exact inputs used by the verifier."""

    profile: Literal["control-assurance-dsse-profile-v1"] = DSSE_PROFILE
    verifier_id: Literal[
        "control-assurance-lab/python-attestation-v1"
    ] = ATTESTATION_VERIFIER_ID
    verified: bool
    reason_code: AttestationReason
    threshold_required: int | None = Field(default=None, ge=1, le=MAX_TRUSTED_KEYS)
    accepted_key_ids: tuple[str, ...] = ()
    accepted_identities: tuple[str, ...] = ()
    raw_envelope_sha256: str | None = None
    expected_payload_sha256: str | None = None
    expected_payload_type: str | None = None
    trust_policy_sha256: str | None = None
    policy_id: str | None = None
    admission_time: str | None = None

    _accepted_arrays_are_immutable = field_validator(
        "accepted_key_ids",
        "accepted_identities",
        mode="before",
    )(_tuple_from_array)

    @field_validator("reason_code", mode="before")
    @classmethod
    def reason_uses_exact_wire_value(cls, value: object) -> object:
        if isinstance(value, AttestationReason):
            return value
        if type(value) is str:
            try:
                return AttestationReason(value)
            except ValueError as exc:
                raise ValueError("unknown attestation reason") from exc
        return value

    @field_validator(
        "raw_envelope_sha256",
        "expected_payload_sha256",
        "trust_policy_sha256",
    )
    @classmethod
    def digests_are_lowercase_sha256(cls, value: str | None) -> str | None:
        if value is not None and _SHA256_PATTERN.fullmatch(value) is None:
            raise ValueError("digest must be 64 lowercase hexadecimal SHA-256 digits")
        return value

    @field_validator("expected_payload_type")
    @classmethod
    def expected_type_is_profile_safe(cls, value: str | None) -> str | None:
        if value is not None:
            _validate_payload_type(value)
        return value

    @field_validator("policy_id")
    @classmethod
    def result_policy_id_is_safe(cls, value: str | None) -> str | None:
        if value is not None:
            _validate_policy_id(value)
        return value

    @field_validator("admission_time")
    @classmethod
    def result_time_is_canonical(cls, value: str | None) -> str | None:
        if value is not None:
            _parse_canonical_timestamp(value)
        return value

    @model_validator(mode="after")
    def decision_is_coherent(self) -> AttestationVerification:
        key_ids = self.accepted_key_ids
        identities = self.accepted_identities
        if key_ids != tuple(sorted(set(key_ids))):
            raise ValueError("accepted key ids must be unique and sorted")
        if identities != tuple(sorted(set(identities))):
            raise ValueError("accepted identities must be unique and sorted")
        if self.verified:
            if self.reason_code != AttestationReason.VERIFIED:
                raise ValueError("verified decisions require the verified reason code")
            required = (
                self.threshold_required,
                self.raw_envelope_sha256,
                self.expected_payload_sha256,
                self.expected_payload_type,
                self.trust_policy_sha256,
                self.policy_id,
                self.admission_time,
            )
            if any(value is None for value in required):
                raise ValueError("verified decisions require complete provenance")
            if self.threshold_required is None or len(identities) < self.threshold_required:
                raise ValueError("verified decisions must satisfy their identity threshold")
            if len(key_ids) != len(identities):
                raise ValueError("verified decisions require one key per accepted identity")
        else:
            if self.reason_code == AttestationReason.VERIFIED:
                raise ValueError("failed decisions cannot use the verified reason code")
            if key_ids or identities:
                raise ValueError("failed decisions cannot retain accepted signers")
        return self

    def canonical_bytes(self) -> bytes:
        """Revalidate before producing bytes suitable for receipt construction."""

        primitive = self.model_dump(mode="json", warnings="error")
        revalidated = AttestationVerification.model_validate(primitive, strict=True)
        return canonical_json_bytes(revalidated.model_dump(mode="json"))


def canonical_payload_bytes(value: Any) -> bytes:
    """Serialize a JSON-compatible attestation payload with RFC 8785."""

    return canonical_json_bytes(value)


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """Return in-toto DSSE v1 pre-authentication encoding (PAE).

    The decimal lengths are byte lengths, not Unicode code-point counts.
    """

    if not isinstance(payload_type, str):
        raise TypeError("payload_type must be a string")
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    try:
        encoded_type = payload_type.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError("payload_type is not valid Unicode") from exc
    return b" ".join(
        (
            DSSE_PAE_VERSION,
            str(len(encoded_type)).encode("ascii"),
            encoded_type,
            str(len(payload)).encode("ascii"),
            payload,
        )
    )


class _ResourceLimitError(ValueError):
    pass


@dataclass(slots=True)
class _RawJSONContainer:
    items: int = 0


@dataclass(frozen=True, slots=True)
class _RawJSONString:
    decoded_length: int
    captured: str | None
    final_characters: tuple[str, ...]


class _RawJSONPreflight:
    """Validate bounded JSON syntax without constructing its object graph."""

    _WHITESPACE = frozenset((0x20, 0x09, 0x0A, 0x0D))
    _STRING_SPECIAL = re.compile(br'["\\\x00-\x1f\x80-\xff]')
    _SIMPLE_ESCAPES: ClassVar[dict[int, str]] = {
        0x22: '"',
        0x5C: "\\",
        0x2F: "/",
        0x62: "\b",
        0x66: "\f",
        0x6E: "\n",
        0x72: "\r",
        0x74: "\t",
    }
    _MEMBER_CAPTURE_LIMIT = max(len("payload"), len("allowed_payload_types"))

    def __init__(
        self,
        payload: bytes,
        *,
        max_containers: int,
        max_collection_items: int,
        enforce_envelope_payload_limit: bool,
        enforce_policy_payload_types_limit: bool,
    ) -> None:
        self._payload = payload
        self._index = 0
        self._max_containers = max_containers
        self._max_collection_items = max_collection_items
        self._enforce_envelope_payload_limit = enforce_envelope_payload_limit
        self._enforce_policy_payload_types_limit = (
            enforce_policy_payload_types_limit
        )

    def run(self) -> None:
        self._skip_whitespace()
        self._parse_value(container_depth=0)
        self._skip_whitespace()
        if self._index != len(self._payload):
            raise ValueError("JSON document has trailing content")

    def _skip_whitespace(self) -> None:
        while (
            self._index < len(self._payload)
            and self._payload[self._index] in self._WHITESPACE
        ):
            self._index += 1

    def _parse_value(
        self,
        *,
        container_depth: int,
        payload_string: bool = False,
        array_item_limit: int | None = None,
    ) -> None:
        self._skip_whitespace()
        if self._index >= len(self._payload):
            raise ValueError("JSON document is incomplete")
        byte = self._payload[self._index]
        if byte == 0x7B:
            self._parse_object(container_depth=container_depth + 1)
            return
        if byte == 0x5B:
            self._parse_array(
                container_depth=container_depth + 1,
                item_limit=array_item_limit,
            )
            return
        if byte == 0x22:
            string = self._parse_string(
                capture_limit=0,
                retain_final_characters=payload_string,
            )
            if payload_string:
                self._check_decoded_payload_limit(string)
            return
        if byte in (0x74, 0x66, 0x6E):
            self._parse_literal()
            return
        if byte == 0x2D or 0x30 <= byte <= 0x39:
            self._parse_number()
            return
        raise ValueError("JSON value has invalid syntax")

    def _parse_object(self, *, container_depth: int) -> None:
        self._enter_container(container_depth)
        self._index += 1
        self._skip_whitespace()
        if self._consume_if(0x7D):
            return
        container = _RawJSONContainer()
        while True:
            container.items += 1
            self._check_collection_limit(container.items)
            if self._index >= len(self._payload) or self._payload[self._index] != 0x22:
                raise ValueError("JSON object member name must be a string")
            member = self._parse_string(
                capture_limit=self._MEMBER_CAPTURE_LIMIT,
                retain_final_characters=False,
            ).captured
            self._skip_whitespace()
            if not self._consume_if(0x3A):
                raise ValueError("JSON object member is missing a colon")
            payload_string = (
                self._enforce_envelope_payload_limit
                and container_depth == 1
                and member == "payload"
            )
            allowed_types_limit = (
                MAX_ALLOWED_PAYLOAD_TYPES
                if self._enforce_policy_payload_types_limit
                and member == "allowed_payload_types"
                else None
            )
            self._parse_value(
                container_depth=container_depth,
                payload_string=payload_string,
                array_item_limit=allowed_types_limit,
            )
            self._skip_whitespace()
            if self._consume_if(0x7D):
                return
            if not self._consume_if(0x2C):
                raise ValueError("JSON object members must be comma separated")
            self._skip_whitespace()

    def _parse_array(
        self,
        *,
        container_depth: int,
        item_limit: int | None,
    ) -> None:
        self._enter_container(container_depth)
        self._index += 1
        self._skip_whitespace()
        if self._consume_if(0x5D):
            return
        container = _RawJSONContainer()
        while True:
            container.items += 1
            self._check_collection_limit(container.items)
            if item_limit is not None and container.items > item_limit:
                raise _ResourceLimitError(
                    "allowed payload type count exceeds the profile limit"
                )
            self._parse_value(container_depth=container_depth)
            self._skip_whitespace()
            if self._consume_if(0x5D):
                return
            if not self._consume_if(0x2C):
                raise ValueError("JSON array items must be comma separated")
            self._skip_whitespace()

    def _enter_container(self, depth: int) -> None:
        if depth > self._max_containers:
            raise _ResourceLimitError(
                "JSON nesting exceeds the profile depth limit"
            )

    def _check_collection_limit(self, items: int) -> None:
        if items > self._max_collection_items:
            raise _ResourceLimitError(
                "JSON collection exceeds the profile item limit"
            )

    def _consume_if(self, expected: int) -> bool:
        if (
            self._index < len(self._payload)
            and self._payload[self._index] == expected
        ):
            self._index += 1
            return True
        return False

    def _parse_string(
        self,
        *,
        capture_limit: int,
        retain_final_characters: bool,
    ) -> _RawJSONString:
        if not self._consume_if(0x22):
            raise ValueError("JSON string is missing its opening quote")
        captured: list[str] | None = []
        final_characters: list[str] = []
        decoded_length = 0
        while self._index < len(self._payload):
            special = self._STRING_SPECIAL.search(self._payload, self._index)
            if special is None:
                raise ValueError("JSON string is incomplete")
            segment_end = special.start()
            segment_length = segment_end - self._index
            if segment_length:
                decoded_length += segment_length
                if captured is not None:
                    if decoded_length <= capture_limit:
                        captured.extend(
                            chr(byte)
                            for byte in self._payload[self._index : segment_end]
                        )
                    else:
                        captured = None
                if retain_final_characters:
                    for byte in self._payload[max(self._index, segment_end - 2) : segment_end]:
                        final_characters.append(chr(byte))
                        if len(final_characters) > 2:
                            del final_characters[0]
                self._index = segment_end
            byte = self._payload[self._index]
            if byte == 0x22:
                self._index += 1
                return _RawJSONString(
                    decoded_length=decoded_length,
                    captured=(
                        "".join(captured)
                        if captured is not None and decoded_length <= capture_limit
                        else None
                    ),
                    final_characters=tuple(final_characters),
                )
            character = self._next_string_character()
            decoded_length += 1
            if captured is not None:
                if decoded_length <= capture_limit:
                    captured.append(character)
                else:
                    captured = None
            if retain_final_characters:
                final_characters.append(character)
                if len(final_characters) > 2:
                    del final_characters[0]
        raise ValueError("JSON string is incomplete")

    def _next_string_character(self) -> str:
        byte = self._payload[self._index]
        if byte < 0x20:
            raise ValueError("JSON string contains an unescaped control byte")
        if byte == 0x5C:
            return self._parse_escape()
        if byte < 0x80:
            self._index += 1
            return chr(byte)
        if byte & 0xE0 == 0xC0:
            width = 2
        elif byte & 0xF0 == 0xE0:
            width = 3
        elif byte & 0xF8 == 0xF0:
            width = 4
        else:
            raise ValueError("JSON string is not valid UTF-8")
        encoded = self._payload[self._index : self._index + width]
        if len(encoded) != width:
            raise ValueError("JSON string is not valid UTF-8")
        try:
            character = encoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError("JSON string is not valid UTF-8") from exc
        if len(character) != 1:
            raise ValueError("JSON string is not valid UTF-8")
        self._index += width
        return character

    def _parse_escape(self) -> str:
        self._index += 1
        if self._index >= len(self._payload):
            raise ValueError("JSON escape is incomplete")
        escape = self._payload[self._index]
        self._index += 1
        if escape in self._SIMPLE_ESCAPES:
            return self._SIMPLE_ESCAPES[escape]
        if escape != 0x75:
            raise ValueError("JSON string contains an invalid escape")
        digits = self._payload[self._index : self._index + 4]
        if len(digits) != 4:
            raise ValueError("JSON Unicode escape is incomplete")
        try:
            code_point = int(digits.decode("ascii"), 16)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("JSON Unicode escape is invalid") from exc
        self._index += 4
        return chr(code_point)

    def _parse_literal(self) -> None:
        literals = {
            0x74: b"true",
            0x66: b"false",
            0x6E: b"null",
        }
        literal = literals[self._payload[self._index]]
        if self._payload[self._index : self._index + len(literal)] != literal:
            raise ValueError("JSON literal is invalid")
        self._index += len(literal)

    def _parse_number(self) -> None:
        if self._consume_if(0x2D) and self._index >= len(self._payload):
            raise ValueError("JSON number is incomplete")
        if self._consume_if(0x30):
            pass
        else:
            if not self._consume_digit(first_nonzero=True):
                raise ValueError("JSON number has an invalid integer part")
            while self._consume_digit():
                pass
        if self._consume_if(0x2E):
            if not self._consume_digit():
                raise ValueError("JSON number has an invalid fraction")
            while self._consume_digit():
                pass
        if self._index < len(self._payload) and self._payload[self._index] in (
            0x65,
            0x45,
        ):
            self._index += 1
            if self._index < len(self._payload) and self._payload[self._index] in (
                0x2B,
                0x2D,
            ):
                self._index += 1
            if not self._consume_digit():
                raise ValueError("JSON number has an invalid exponent")
            while self._consume_digit():
                pass

    def _consume_digit(self, *, first_nonzero: bool = False) -> bool:
        if self._index >= len(self._payload):
            return False
        byte = self._payload[self._index]
        lower = 0x31 if first_nonzero else 0x30
        if lower <= byte <= 0x39:
            self._index += 1
            return True
        return False

    @staticmethod
    def _check_decoded_payload_limit(value: _RawJSONString) -> None:
        if value.decoded_length > MAX_ENCODED_PAYLOAD_LENGTH:
            raise _ResourceLimitError("encoded payload exceeds the profile limit")
        if value.decoded_length % 4 != 0:
            return
        final = value.final_characters
        padding = 0
        if final and final[-1] == "=":
            padding = 2 if len(final) > 1 and final[-2] == "=" else 1
        decoded_length = (value.decoded_length // 4) * 3 - padding
        if decoded_length > MAX_DECODED_PAYLOAD_BYTES:
            raise _ResourceLimitError("decoded payload exceeds the profile limit")


def _preflight_json_structure(
    payload: bytes,
    *,
    max_containers: int,
    max_collection_items: int,
    enforce_envelope_payload_limit: bool = False,
    enforce_policy_payload_types_limit: bool = False,
) -> None:
    """Bound JSON containers before ``json.loads`` materializes the document."""

    _RawJSONPreflight(
        payload,
        max_containers=max_containers,
        max_collection_items=max_collection_items,
        enforce_envelope_payload_limit=enforce_envelope_payload_limit,
        enforce_policy_payload_types_limit=enforce_policy_payload_types_limit,
    ).run()


def parse_dsse_envelope(envelope_bytes: bytes) -> DSSEEnvelope:
    """Parse a bounded, duplicate-safe profile envelope.

    JSON member ordering and whitespace are not security relevant in DSSE; PAE
    binds the decoded payload type and payload bytes.  This profile requires
    canonical standard base64 and explicit signer key ids.
    """

    if type(envelope_bytes) is not bytes:
        raise TypeError("DSSE envelope must be bytes")
    if len(envelope_bytes) > MAX_ENVELOPE_BYTES:
        raise _ResourceLimitError("DSSE envelope exceeds the profile byte limit")
    _preflight_json_structure(
        envelope_bytes,
        max_containers=4,
        max_collection_items=MAX_ENVELOPE_SIGNATURES,
        enforce_envelope_payload_limit=True,
    )
    document = strict_json_loads(envelope_bytes, limits=ENVELOPE_JSON_LIMITS)
    if not isinstance(document, dict):
        raise ValueError("DSSE envelope root must be an object")
    _validate_raw_envelope_shape(document)
    return DSSEEnvelope.model_validate(document)


def parse_trust_policy(policy_bytes: bytes) -> TrustPolicy:
    """Parse a bounded external policy and require exact RFC 8785 wire form."""

    if type(policy_bytes) is not bytes:
        raise TypeError("trust policy must be bytes")
    if len(policy_bytes) > MAX_TRUST_POLICY_BYTES:
        raise _ResourceLimitError("trust policy exceeds the profile byte limit")
    _preflight_json_structure(
        policy_bytes,
        max_containers=5,
        max_collection_items=MAX_TRUSTED_KEYS,
        enforce_policy_payload_types_limit=True,
    )
    document = strict_json_loads(policy_bytes, limits=TRUST_POLICY_JSON_LIMITS)
    if not isinstance(document, dict):
        raise ValueError("trust policy root must be an object")
    policy = TrustPolicy.model_validate(document)
    if policy.canonical_bytes() != policy_bytes:
        raise ValueError("trust policy must use exact RFC 8785 canonical JSON")
    return policy


def _validate_raw_envelope_shape(document: dict[str, Any]) -> None:
    payload = document.get("payload")
    if isinstance(payload, str) and len(payload) > MAX_ENCODED_PAYLOAD_LENGTH:
        raise _ResourceLimitError("encoded payload exceeds the profile limit")
    if isinstance(payload, str) and len(payload) % 4 == 0:
        padding = 2 if payload.endswith("==") else int(payload.endswith("="))
        decoded_length = (len(payload) // 4) * 3 - padding
        if decoded_length > MAX_DECODED_PAYLOAD_BYTES:
            raise _ResourceLimitError("decoded payload exceeds the profile limit")
    signatures = document.get("signatures")
    if not isinstance(signatures, list):
        raise ValueError("DSSE signatures must be an array")
    if len(signatures) > MAX_ENVELOPE_SIGNATURES:
        raise _ResourceLimitError("signature count exceeds the profile limit")
    for signature in signatures:
        if not isinstance(signature, dict):
            raise ValueError("each DSSE signature must be an object")
        encoded = signature.get("sig")
        if (
            isinstance(encoded, str)
            and len(encoded) > ED25519_SIGNATURE_BASE64_LENGTH
        ):
            raise _ResourceLimitError("encoded signature exceeds the profile limit")


def _bounded_programmatic_policy_primitive(
    policy: object,
) -> dict[str, Any] | None:
    """Copy only bounded built-in values from a possibly constructed model."""

    if type(policy) is not TrustPolicy:
        return None
    media_type = getattr(policy, "media_type", None)
    schema_version = getattr(policy, "schema_version", None)
    policy_id = getattr(policy, "policy_id", None)
    threshold = getattr(policy, "threshold", None)
    trusted_keys = getattr(policy, "trusted_keys", None)
    if (
        type(media_type) is not str
        or len(media_type) > 128
        or type(schema_version) is not str
        or len(schema_version) > 32
        or type(policy_id) is not str
        or len(policy_id) > 256
        or type(threshold) is not int
        or not 1 <= threshold <= MAX_TRUSTED_KEYS
        or type(trusted_keys) not in (list, tuple)
    ):
        return None
    trusted_key_values = cast(list[object] | tuple[object, ...], trusted_keys)
    if len(trusted_key_values) > MAX_TRUSTED_KEYS:
        return None

    primitive_keys: list[dict[str, Any]] = []
    for trusted_key in trusted_key_values:
        if type(trusted_key) is not TrustedKey:
            return None
        key_id = getattr(trusted_key, "key_id", None)
        identity = getattr(trusted_key, "identity", None)
        algorithm = getattr(trusted_key, "algorithm", None)
        public_key = getattr(trusted_key, "public_key", None)
        allowed_types = getattr(trusted_key, "allowed_payload_types", None)
        valid_from = getattr(trusted_key, "valid_from", None)
        valid_until = getattr(trusted_key, "valid_until", None)
        status = getattr(trusted_key, "status", None)
        revocation_effective_at = getattr(
            trusted_key,
            "revocation_effective_at",
            None,
        )
        bounded_text_fields = (
            (key_id, MAX_KEY_ID_LENGTH),
            (identity, MAX_IDENTITY_LENGTH),
            (algorithm, 64),
            (public_key, ED25519_PUBLIC_KEY_BASE64_LENGTH),
            (valid_from, 27),
        )
        if any(
            type(value) is not str or len(value) > maximum
            for value, maximum in bounded_text_fields
        ):
            return None
        if any(
            value is not None and (type(value) is not str or len(value) > 27)
            for value in (valid_until, revocation_effective_at)
        ):
            return None
        if type(allowed_types) not in (list, tuple):
            return None
        allowed_type_values = cast(
            list[object] | tuple[object, ...],
            allowed_types,
        )
        if len(allowed_type_values) > MAX_ALLOWED_PAYLOAD_TYPES or any(
            type(value) is not str or len(value) > MAX_PAYLOAD_TYPE_LENGTH
            for value in allowed_type_values
        ):
            return None
        if type(status) is KeyStatus:
            status_value = status.value
        elif type(status) is str and len(status) <= 16:
            status_value = status
        else:
            return None
        primitive_keys.append(
            {
                "key_id": key_id,
                "identity": identity,
                "algorithm": algorithm,
                "public_key": public_key,
                "allowed_payload_types": list(allowed_type_values),
                "valid_from": valid_from,
                "valid_until": valid_until,
                "status": status_value,
                "revocation_effective_at": revocation_effective_at,
            }
        )
    return {
        "media_type": media_type,
        "schema_version": schema_version,
        "policy_id": policy_id,
        "threshold": threshold,
        "trusted_keys": primitive_keys,
    }


def _revalidate_programmatic_policy(policy: TrustPolicy) -> TrustPolicy | None:
    try:
        primitive = _bounded_programmatic_policy_primitive(policy)
        if primitive is None:
            return None
        revalidated = TrustPolicy.model_validate(primitive, strict=True)
        revalidated.canonical_bytes()
    except Exception:
        # This is the public trust boundary.  Invalid constructed models and
        # serializer failures deny admission rather than escaping verification.
        return None
    return revalidated


@dataclass(frozen=True, slots=True)
class _VerificationProvenance:
    raw_envelope_sha256: str | None = None
    expected_payload_sha256: str | None = None
    expected_payload_type: str | None = None
    trust_policy_sha256: str | None = None
    policy_id: str | None = None
    admission_time: str | None = None


def _failed(
    reason: AttestationReason,
    *,
    threshold: int | None,
    provenance: _VerificationProvenance,
) -> AttestationVerification:
    return AttestationVerification(
        verified=False,
        reason_code=reason,
        threshold_required=threshold,
        raw_envelope_sha256=provenance.raw_envelope_sha256,
        expected_payload_sha256=provenance.expected_payload_sha256,
        expected_payload_type=provenance.expected_payload_type,
        trust_policy_sha256=provenance.trust_policy_sha256,
        policy_id=provenance.policy_id,
        admission_time=provenance.admission_time,
    )


def _verified(
    *,
    threshold: int,
    key_ids: set[str],
    identities: set[str],
    provenance: _VerificationProvenance,
) -> AttestationVerification:
    return AttestationVerification(
        verified=True,
        reason_code=AttestationReason.VERIFIED,
        threshold_required=threshold,
        accepted_key_ids=tuple(sorted(key_ids)),
        accepted_identities=tuple(sorted(identities)),
        raw_envelope_sha256=provenance.raw_envelope_sha256,
        expected_payload_sha256=provenance.expected_payload_sha256,
        expected_payload_type=provenance.expected_payload_type,
        trust_policy_sha256=provenance.trust_policy_sha256,
        policy_id=provenance.policy_id,
        admission_time=provenance.admission_time,
    )


def _looks_like_malformed_base64(document: object) -> bool:
    if not isinstance(document, dict):
        return False
    candidates: list[tuple[object, int, int | None]] = [
        (document.get("payload"), MAX_ENCODED_PAYLOAD_LENGTH, None)
    ]
    signatures = document.get("signatures")
    if isinstance(signatures, list):
        if len(signatures) > MAX_ENVELOPE_SIGNATURES:
            return False
        for signature in signatures:
            if isinstance(signature, dict):
                candidates.append(
                    (
                        signature.get("sig"),
                        ED25519_SIGNATURE_BASE64_LENGTH,
                        ED25519_SIGNATURE_BYTES,
                    )
                )
    for candidate, maximum, exact_length in candidates:
        if not isinstance(candidate, str):
            continue
        try:
            _canonical_base64_decode(
                candidate,
                max_encoded_length=maximum,
                expected_decoded_length=exact_length,
            )
        except ValueError:
            return True
    return False


def verify_dsse_attestation(
    envelope_bytes: bytes,
    *,
    policy: TrustPolicy,
    expected_payload_type: str,
    expected_payload: bytes,
    admission_time: datetime,
) -> AttestationVerification:
    """Verify exact bytes under revalidated trust at a caller-trusted timestamp.

    Every signature present must be known, eligible, and valid.  The threshold
    counts distinct policy identities, so two overlapping rotation keys for one
    producer cannot impersonate two independent signers.  Every return value is
    bound to the inputs available at the point of the decision.
    """

    provenance = _VerificationProvenance()
    if type(envelope_bytes) is not bytes:
        return _failed(
            AttestationReason.MALFORMED_ENVELOPE,
            threshold=None,
            provenance=provenance,
        )
    if len(envelope_bytes) > MAX_ENVELOPE_BYTES:
        return _failed(
            AttestationReason.RESOURCE_LIMIT_EXCEEDED,
            threshold=None,
            provenance=provenance,
        )
    provenance = replace(
        provenance,
        raw_envelope_sha256=_sha256(envelope_bytes),
    )

    if type(expected_payload_type) is not str or type(expected_payload) is not bytes:
        return _failed(
            AttestationReason.INVALID_EXPECTATION,
            threshold=None,
            provenance=provenance,
        )
    try:
        _validate_payload_type(expected_payload_type)
    except ValueError:
        return _failed(
            AttestationReason.INVALID_EXPECTATION,
            threshold=None,
            provenance=provenance,
        )
    if len(expected_payload) > MAX_DECODED_PAYLOAD_BYTES:
        return _failed(
            AttestationReason.RESOURCE_LIMIT_EXCEEDED,
            threshold=None,
            provenance=provenance,
        )
    provenance = replace(
        provenance,
        expected_payload_sha256=_sha256(expected_payload),
        expected_payload_type=expected_payload_type,
    )

    revalidated_policy = _revalidate_programmatic_policy(policy)
    if revalidated_policy is None:
        return _failed(
            AttestationReason.MALFORMED_POLICY,
            threshold=None,
            provenance=provenance,
        )
    policy = revalidated_policy
    threshold = policy.threshold
    provenance = replace(
        provenance,
        trust_policy_sha256=_sha256(policy.canonical_bytes()),
        policy_id=policy.policy_id,
    )

    admitted_at = _canonical_admission_time(admission_time)
    if admitted_at is None:
        return _failed(
            AttestationReason.INVALID_ADMISSION_TIME,
            threshold=threshold,
            provenance=provenance,
        )
    provenance = replace(
        provenance,
        admission_time=_format_canonical_timestamp(admitted_at),
    )

    try:
        _preflight_json_structure(
            envelope_bytes,
            max_containers=4,
            max_collection_items=MAX_ENVELOPE_SIGNATURES,
            enforce_envelope_payload_limit=True,
        )
    except _ResourceLimitError:
        return _failed(
            AttestationReason.RESOURCE_LIMIT_EXCEEDED,
            threshold=threshold,
            provenance=provenance,
        )
    except ValueError:
        return _failed(
            AttestationReason.MALFORMED_ENVELOPE,
            threshold=threshold,
            provenance=provenance,
        )

    try:
        document = strict_json_loads(envelope_bytes, limits=ENVELOPE_JSON_LIMITS)
    except StrictJSONError as exc:
        reason = (
            AttestationReason.RESOURCE_LIMIT_EXCEEDED
            if "exceed" in str(exc) or "limit" in str(exc)
            else AttestationReason.MALFORMED_ENVELOPE
        )
        return _failed(reason, threshold=threshold, provenance=provenance)
    try:
        if not isinstance(document, dict):
            raise ValueError("DSSE envelope root must be an object")
        _validate_raw_envelope_shape(document)
    except _ResourceLimitError:
        return _failed(
            AttestationReason.RESOURCE_LIMIT_EXCEEDED,
            threshold=threshold,
            provenance=provenance,
        )
    except (ValueError, TypeError):
        return _failed(
            AttestationReason.MALFORMED_ENVELOPE,
            threshold=threshold,
            provenance=provenance,
        )
    if _looks_like_malformed_base64(document):
        return _failed(
            AttestationReason.MALFORMED_BASE64,
            threshold=threshold,
            provenance=provenance,
        )
    try:
        envelope = DSSEEnvelope.model_validate(document)
    except (ValueError, TypeError):
        return _failed(
            AttestationReason.MALFORMED_ENVELOPE,
            threshold=threshold,
            provenance=provenance,
        )

    if envelope.payload_type != expected_payload_type:
        return _failed(
            AttestationReason.PAYLOAD_TYPE_MISMATCH,
            threshold=threshold,
            provenance=provenance,
        )
    payload = envelope.payload_bytes()
    if payload != expected_payload:
        return _failed(
            AttestationReason.PAYLOAD_MISMATCH,
            threshold=threshold,
            provenance=provenance,
        )

    key_ids = [trusted_key.key_id for trusted_key in policy.trusted_keys]
    if len(set(key_ids)) != len(key_ids):
        return _failed(
            AttestationReason.DUPLICATE_TRUSTED_KEY,
            threshold=threshold,
            provenance=provenance,
        )
    key_by_id = {trusted_key.key_id: trusted_key for trusted_key in policy.trusted_keys}

    signature_key_ids = [signature.keyid for signature in envelope.signatures]
    if len(set(signature_key_ids)) != len(signature_key_ids):
        return _failed(
            AttestationReason.DUPLICATE_SIGNER,
            threshold=threshold,
            provenance=provenance,
        )

    if any(key_id not in key_by_id for key_id in signature_key_ids):
        return _failed(
            AttestationReason.UNKNOWN_SIGNER,
            threshold=threshold,
            provenance=provenance,
        )

    selected_keys = [key_by_id[key_id] for key_id in signature_key_ids]
    identities = [trusted_key.identity for trusted_key in selected_keys]
    if len(set(identities)) != len(identities):
        return _failed(
            AttestationReason.DUPLICATE_SIGNER,
            threshold=threshold,
            provenance=provenance,
        )

    if any(trusted_key.algorithm != "ed25519" for trusted_key in selected_keys):
        return _failed(
            AttestationReason.UNKNOWN_ALGORITHM,
            threshold=threshold,
            provenance=provenance,
        )
    if any(
        expected_payload_type not in trusted_key.allowed_payload_types
        for trusted_key in selected_keys
    ):
        return _failed(
            AttestationReason.PAYLOAD_TYPE_NOT_ALLOWED,
            threshold=threshold,
            provenance=provenance,
        )

    for trusted_key in selected_keys:
        if trusted_key.status == KeyStatus.DISABLED:
            return _failed(
                AttestationReason.KEY_DISABLED,
                threshold=threshold,
                provenance=provenance,
            )
        if (
            trusted_key.revocation_effective_at is not None
            and admitted_at
            >= _parse_canonical_timestamp(trusted_key.revocation_effective_at)
        ):
            return _failed(
                AttestationReason.KEY_REVOKED,
                threshold=threshold,
                provenance=provenance,
            )
        if admitted_at < _parse_canonical_timestamp(trusted_key.valid_from):
            return _failed(
                AttestationReason.KEY_NOT_YET_VALID,
                threshold=threshold,
                provenance=provenance,
            )
        if (
            trusted_key.valid_until is not None
            and admitted_at >= _parse_canonical_timestamp(trusted_key.valid_until)
        ):
            return _failed(
                AttestationReason.KEY_EXPIRED,
                threshold=threshold,
                provenance=provenance,
            )

    encoded = dsse_pae(envelope.payload_type, payload)
    accepted_key_ids: set[str] = set()
    accepted_identities: set[str] = set()
    for signature, trusted_key in zip(
        envelope.signatures,
        selected_keys,
        strict=True,
    ):
        public_key_bytes = trusted_key.public_key_bytes()
        if len(public_key_bytes) != 32:
            return _failed(
                AttestationReason.INVALID_PUBLIC_KEY,
                threshold=threshold,
                provenance=provenance,
            )
        try:
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        except ValueError:
            return _failed(
                AttestationReason.INVALID_PUBLIC_KEY,
                threshold=threshold,
                provenance=provenance,
            )
        try:
            public_key.verify(
                _canonical_base64_decode(
                    signature.sig,
                    max_encoded_length=ED25519_SIGNATURE_BASE64_LENGTH,
                    expected_decoded_length=ED25519_SIGNATURE_BYTES,
                ),
                encoded,
            )
        except (InvalidSignature, ValueError):
            return _failed(
                AttestationReason.INVALID_SIGNATURE,
                threshold=threshold,
                provenance=provenance,
            )
        accepted_key_ids.add(trusted_key.key_id)
        accepted_identities.add(trusted_key.identity)

    if len(accepted_identities) < threshold:
        return _failed(
            AttestationReason.THRESHOLD_NOT_MET,
            threshold=threshold,
            provenance=provenance,
        )
    return _verified(
        threshold=threshold,
        key_ids=accepted_key_ids,
        identities=accepted_identities,
        provenance=provenance,
    )


__all__ = [
    "ATTESTATION_VERIFIER_ID",
    "DSSE_PAE_VERSION",
    "DSSE_PROFILE",
    "ENVELOPE_JSON_LIMITS",
    "MAX_ALLOWED_PAYLOAD_TYPES",
    "MAX_DECODED_PAYLOAD_BYTES",
    "MAX_ENVELOPE_BYTES",
    "MAX_ENVELOPE_SIGNATURES",
    "MAX_TRUSTED_KEYS",
    "MAX_TRUST_POLICY_BYTES",
    "TRUST_POLICY_JSON_LIMITS",
    "TRUST_POLICY_MEDIA_TYPE",
    "TRUST_POLICY_SCHEMA_VERSION",
    "AttestationReason",
    "AttestationVerification",
    "DSSEEnvelope",
    "DSSESignature",
    "KeyStatus",
    "TrustPolicy",
    "TrustedKey",
    "canonical_payload_bytes",
    "dsse_pae",
    "parse_dsse_envelope",
    "parse_trust_policy",
    "verify_dsse_attestation",
]
