"""Strict, secret-safe credential profiles for Microsoft Defender XDR.

The secret manager returns opaque bytes.  This module gives those bytes one
small, explicit meaning without ever accepting a private key, client secret,
refresh token, or cached workload assertion.

Two profiles are supported:

``certificate-ps256``
    A public X.509 certificate and an exact-version Azure Key Vault signing
    key URI.  The private key remains behind the remote signing boundary.

``federated-rs256``
    The exact OIDC issuer, Kubernetes ServiceAccount subject, and a canonical
    reference to the projected assertion source.  The assertion itself is
    obtained only when it is needed.

Successful decoding produces immutable plans plus a canonical authorization
profile containing only public identity anchors.  The certificate plan
deliberately checks validity against a caller-provided clock at *use* time:
decoding configuration is not evidence that a certificate remains valid.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
import urllib.parse
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Final, Literal, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from assurance_lab.evidence.canonical import (
    JSONLimits,
    StrictJSONError,
    canonical_json_bytes,
    strict_json_loads,
)

DEFENDER_CREDENTIAL_PROFILE_CONTENT_TYPE: Final = (
    "application/vnd.control-assurance.defender-credential-profile.v1+json"
)
DEFENDER_CREDENTIAL_PROFILE_SCHEMA_VERSION: Final = "1.0.0"
DEFENDER_AUTHORIZATION_PROFILE_CONTENT_TYPE: Final = (
    "application/vnd.control-assurance.defender-authorization-profile.v1+json"
)
DEFENDER_AUTHORIZATION_PROFILE_SCHEMA_VERSION: Final = "1.0.0"

CertificateCredentialMode = Literal["certificate-ps256"]
FederatedCredentialMode = Literal["federated-rs256"]
type CredentialMode = CertificateCredentialMode | FederatedCredentialMode

_MAX_DOCUMENT_BYTES: Final = 128 * 1024
_MAX_CERTIFICATE_BYTES: Final = 64 * 1024
_MAX_ISSUER_BYTES: Final = 2_048
_MAX_SUBJECT_BYTES: Final = 512
_MAX_SOURCE_REFERENCE_BYTES: Final = 1_024
_DOCUMENT_LIMITS = JSONLimits(
    max_bytes=_MAX_DOCUMENT_BYTES,
    max_line_bytes=_MAX_DOCUMENT_BYTES,
    max_depth=3,
    max_collection_items=24,
    max_string_length=96 * 1024,
)

_VAULT_NAME_RE: Final = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,22}[a-z0-9])$")
_KEY_NAME_RE: Final = re.compile(r"^[A-Za-z0-9-]{1,127}$")
_KEY_VERSION_RE: Final = re.compile(r"^[a-f0-9]{32}$")
_DNS_LABEL_RE: Final = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_DNS_SUBDOMAIN_RE: Final = re.compile(
    r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$"
)
_SHA256_RE: Final = re.compile(r"^sha256:[a-f0-9]{64}$")

_COMMON_FIELDS: Final = frozenset({"kind", "mode", "schema_version"})
_CERTIFICATE_FIELDS: Final = _COMMON_FIELDS | frozenset(
    {
        "algorithm",
        "certificate_der",
        "certificate_not_after",
        "certificate_not_before",
        "signing_key_uri",
    }
)
_FEDERATED_FIELDS: Final = _COMMON_FIELDS | frozenset(
    {
        "algorithm",
        "issuer",
        "source_reference",
        "subject",
    }
)


class DefenderCredentialProfileError(ValueError):
    """A stable profile failure that never includes supplied profile values."""


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _canonical_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise DefenderCredentialProfileError("certificate validity metadata is invalid")
    converted = value.astimezone(UTC)
    if converted.microsecond != 0:
        raise DefenderCredentialProfileError("certificate validity metadata is invalid")
    return converted.strftime("%Y-%m-%dT%H:%M:%SZ")


def _decode_base64_certificate(value: object) -> bytes:
    if (
        type(value) is not str
        or not value
        or len(value) > 4 * ((_MAX_CERTIFICATE_BYTES + 2) // 3)
    ):
        raise DefenderCredentialProfileError(
            "certificate DER is absent or exceeds its limit"
        )
    try:
        encoded = value.encode("ascii", errors="strict")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, ValueError):
        raise DefenderCredentialProfileError(
            "certificate DER is not canonical base64"
        ) from None
    if (
        not decoded
        or len(decoded) > _MAX_CERTIFICATE_BYTES
        or base64.b64encode(decoded) != encoded
    ):
        raise DefenderCredentialProfileError(
            "certificate DER is not canonical base64"
        )
    return decoded


def _parse_key_vault_key_uri(value: object) -> tuple[str, str, str, str]:
    if type(value) is not str or not value or len(value) > 2_048:
        raise DefenderCredentialProfileError("remote signing key URI is invalid")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError:
        raise DefenderCredentialProfileError("remote signing key URI is invalid") from None
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
        or parsed.hostname is None
        or parsed.netloc != parsed.hostname
        or "\\" in value
        or "%" in value
        or any(character.isspace() for character in value)
    ):
        raise DefenderCredentialProfileError("remote signing key URI is invalid")
    suffix = ".vault.azure.net"
    if not parsed.hostname.endswith(suffix):
        raise DefenderCredentialProfileError("remote signing key URI is invalid")
    vault_name = parsed.hostname[: -len(suffix)]
    segments = parsed.path.split("/")
    if (
        _VAULT_NAME_RE.fullmatch(vault_name) is None
        or len(segments) != 4
        or segments[0] != ""
        or segments[1] != "keys"
        or _KEY_NAME_RE.fullmatch(segments[2]) is None
        or _KEY_VERSION_RE.fullmatch(segments[3]) is None
    ):
        raise DefenderCredentialProfileError(
            "remote signing key URI must identify one exact Key Vault key version"
        )
    canonical = (
        f"https://{vault_name}.vault.azure.net/keys/{segments[2]}/{segments[3]}"
    )
    if canonical != value:
        raise DefenderCredentialProfileError("remote signing key URI is not canonical")
    return canonical, vault_name, segments[2], segments[3]


def _valid_dns_name(value: str) -> bool:
    if (
        not value
        or len(value) > 253
        or value.endswith(".")
        or _DNS_SUBDOMAIN_RE.fullmatch(value) is None
    ):
        return False
    return all(_DNS_LABEL_RE.fullmatch(label) is not None for label in value.split("."))


def _parse_https_issuer(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or len(value.encode("utf-8")) > _MAX_ISSUER_BYTES
    ):
        raise DefenderCredentialProfileError("federated issuer URL is invalid")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except (UnicodeError, ValueError):
        raise DefenderCredentialProfileError("federated issuer URL is invalid") from None
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or hostname is None
        or not _valid_dns_name(hostname)
        or parsed.netloc != hostname
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
        or "\\" in value
        or "%" in value
        or any(character.isspace() for character in value)
        or "//" in parsed.path
        or any(segment in {".", ".."} for segment in parsed.path.split("/"))
    ):
        raise DefenderCredentialProfileError("federated issuer URL is invalid")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise DefenderCredentialProfileError("federated issuer URL is invalid")
    canonical = f"https://{hostname}{parsed.path}"
    if canonical != value:
        raise DefenderCredentialProfileError("federated issuer URL is not canonical")
    return canonical


def _parse_kubernetes_source_reference(value: object) -> tuple[str, str, str, str]:
    if (
        type(value) is not str
        or not value
        or len(value.encode("utf-8")) > _MAX_SOURCE_REFERENCE_BYTES
    ):
        raise DefenderCredentialProfileError(
            "workload assertion source reference is invalid"
        )
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except (UnicodeError, ValueError):
        raise DefenderCredentialProfileError(
            "workload assertion source reference is invalid"
        ) from None
    cluster = parsed.hostname
    segments = parsed.path.split("/")
    if (
        parsed.scheme != "kubernetes"
        or cluster is None
        or not _valid_dns_name(cluster)
        or parsed.netloc != cluster
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
        or "\\" in value
        or "%" in value
        or any(character.isspace() for character in value)
        or len(segments) != 3
        or segments[0] != ""
        or _DNS_LABEL_RE.fullmatch(segments[1]) is None
        or not _valid_dns_name(segments[2])
    ):
        raise DefenderCredentialProfileError(
            "workload assertion source reference must identify one Kubernetes ServiceAccount"
        )
    canonical = f"kubernetes://{cluster}/{segments[1]}/{segments[2]}"
    if canonical != value:
        raise DefenderCredentialProfileError(
            "workload assertion source reference is not canonical"
        )
    return canonical, cluster, segments[1], segments[2]


def _authorization_profile(
    document: dict[str, object],
) -> tuple[bytes, str]:
    encoded = canonical_json_bytes(document)
    return encoded, _sha256(encoded)


@dataclass(frozen=True, slots=True, repr=False)
class CertificatePS256CredentialPlan:
    """Public certificate identity plus one non-exportable signing-key anchor."""

    mode: CertificateCredentialMode
    certificate_der: bytes = field(repr=False)
    signing_key_uri: str = field(repr=False)
    vault_name: str = field(repr=False)
    key_name: str = field(repr=False)
    key_version: str = field(repr=False)
    certificate_not_before: datetime = field(repr=False)
    certificate_not_after: datetime = field(repr=False)
    certificate_sha256: str
    certificate_spki_sha256: str
    certificate_thumbprint_s256: str
    authorization_profile_bytes: bytes = field(repr=False)
    authorization_profile_digest: str

    def __repr__(self) -> str:
        return (
            "CertificatePS256CredentialPlan("
            f"mode={self.mode!r}, "
            f"certificate_sha256={self.certificate_sha256!r}, "
            f"certificate_spki_sha256={self.certificate_spki_sha256!r}, "
            f"authorization_profile_digest={self.authorization_profile_digest!r})"
        )

    @property
    def key_reference(self) -> str:
        """Return the exact HTTPS reference expected from the remote signer."""

        return self.signing_key_uri

    def assert_valid_at(self, instant: datetime) -> None:
        """Fail unless the certificate is valid at the caller's actual use time."""

        if type(instant) is not datetime or instant.tzinfo is None:
            raise DefenderCredentialProfileError(
                "certificate use time must be timezone-aware"
            )
        try:
            current = instant.astimezone(UTC)
        except (OverflowError, ValueError):
            raise DefenderCredentialProfileError(
                "certificate use time is outside the supported range"
            ) from None
        if not self.certificate_not_before <= current < self.certificate_not_after:
            raise DefenderCredentialProfileError(
                "certificate is not valid at the requested use time"
            )

    def assert_remote_public_key(self, public_key: rsa.RSAPublicKey) -> None:
        """Bind a remotely read Key Vault public key to the profile certificate."""

        if not isinstance(public_key, rsa.RSAPublicKey):
            raise DefenderCredentialProfileError("remote signing public key is invalid")
        try:
            encoded = public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except (TypeError, ValueError):
            raise DefenderCredentialProfileError(
                "remote signing public key is invalid"
            ) from None
        self.assert_remote_public_key_fingerprint(_sha256(encoded))

    def assert_remote_public_key_der(self, public_key_der: bytes) -> None:
        """Check one canonical DER SubjectPublicKeyInfo returned by a key service."""

        if type(public_key_der) is not bytes or not public_key_der:
            raise DefenderCredentialProfileError("remote signing public key is invalid")
        try:
            public_key = serialization.load_der_public_key(public_key_der)
        except (TypeError, ValueError):
            raise DefenderCredentialProfileError(
                "remote signing public key is invalid"
            ) from None
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise DefenderCredentialProfileError("remote signing public key is invalid")
        canonical = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if canonical != public_key_der:
            raise DefenderCredentialProfileError(
                "remote signing public key DER is not canonical"
            )
        self.assert_remote_public_key(public_key)

    def assert_remote_public_key_fingerprint(self, fingerprint: str) -> None:
        """Compare a caller-computed SPKI SHA-256 digest without key material."""

        if type(fingerprint) is not str or _SHA256_RE.fullmatch(fingerprint) is None:
            raise DefenderCredentialProfileError(
                "remote signing public key fingerprint is invalid"
            )
        if fingerprint != self.certificate_spki_sha256:
            raise DefenderCredentialProfileError(
                "remote signing key does not match the registered certificate"
            )


@dataclass(frozen=True, slots=True, repr=False)
class FederatedRS256CredentialPlan:
    """Exact public workload identity anchors; no assertion or token is stored."""

    mode: FederatedCredentialMode
    issuer: str = field(repr=False)
    subject: str = field(repr=False)
    source_reference: str = field(repr=False)
    cluster: str = field(repr=False)
    namespace: str = field(repr=False)
    service_account: str = field(repr=False)
    authorization_profile_bytes: bytes = field(repr=False)
    authorization_profile_digest: str

    def __repr__(self) -> str:
        return (
            "FederatedRS256CredentialPlan("
            f"mode={self.mode!r}, "
            f"authorization_profile_digest={self.authorization_profile_digest!r})"
        )


type DefenderCredentialPlan = (
    CertificatePS256CredentialPlan | FederatedRS256CredentialPlan
)


def _decode_certificate_profile(
    profile: dict[str, object],
) -> CertificatePS256CredentialPlan:
    if frozenset(profile) != _CERTIFICATE_FIELDS:
        raise DefenderCredentialProfileError(
            "certificate credential profile fields are invalid"
        )
    if profile.get("algorithm") != "PS256":
        raise DefenderCredentialProfileError(
            "certificate credential algorithm is invalid"
        )
    certificate_der = _decode_base64_certificate(profile.get("certificate_der"))
    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
    except ValueError:
        raise DefenderCredentialProfileError(
            "certificate DER is not one valid X.509 certificate"
        ) from None
    if (
        certificate.public_bytes(serialization.Encoding.DER) != certificate_der
    ):
        raise DefenderCredentialProfileError("certificate DER is not canonical")
    public_key = certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 2_048:
        raise DefenderCredentialProfileError(
            "certificate must contain an RSA public key of at least 2048 bits"
        )
    try:
        key_usage = certificate.extensions.get_extension_for_class(
            x509.KeyUsage
        ).value
    except x509.ExtensionNotFound:
        pass
    else:
        if not key_usage.digital_signature:
            raise DefenderCredentialProfileError(
                "certificate key usage does not allow digital signatures"
            )
    try:
        basic_constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound:
        pass
    else:
        if basic_constraints.ca:
            raise DefenderCredentialProfileError(
                "certificate must be an end-entity certificate"
            )

    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    if not_before >= not_after:
        raise DefenderCredentialProfileError(
            "certificate validity interval is invalid"
        )
    not_before_text = _canonical_timestamp(not_before)
    not_after_text = _canonical_timestamp(not_after)
    if (
        profile.get("certificate_not_before") != not_before_text
        or profile.get("certificate_not_after") != not_after_text
    ):
        raise DefenderCredentialProfileError(
            "certificate validity metadata does not match the certificate"
        )

    key_uri, vault_name, key_name, key_version = _parse_key_vault_key_uri(
        profile.get("signing_key_uri")
    )
    spki_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    certificate_digest = _sha256(certificate_der)
    spki_digest = _sha256(spki_der)
    thumbprint = _base64url(certificate.fingerprint(hashes.SHA256()))
    authorization_bytes, authorization_digest = _authorization_profile(
        {
            "algorithm": "PS256",
            "certificate_not_after": not_after_text,
            "certificate_not_before": not_before_text,
            "certificate_sha256": certificate_digest,
            "certificate_spki_sha256": spki_digest,
            "certificate_thumbprint_s256": thumbprint,
            "content_type": DEFENDER_AUTHORIZATION_PROFILE_CONTENT_TYPE,
            "kind": "defender-authorization-profile",
            "mode": "certificate-ps256",
            "schema_version": DEFENDER_AUTHORIZATION_PROFILE_SCHEMA_VERSION,
            "signing_key_uri": key_uri,
        }
    )
    return CertificatePS256CredentialPlan(
        mode="certificate-ps256",
        certificate_der=certificate_der,
        signing_key_uri=key_uri,
        vault_name=vault_name,
        key_name=key_name,
        key_version=key_version,
        certificate_not_before=not_before,
        certificate_not_after=not_after,
        certificate_sha256=certificate_digest,
        certificate_spki_sha256=spki_digest,
        certificate_thumbprint_s256=thumbprint,
        authorization_profile_bytes=authorization_bytes,
        authorization_profile_digest=authorization_digest,
    )


def _decode_federated_profile(
    profile: dict[str, object],
) -> FederatedRS256CredentialPlan:
    if frozenset(profile) != _FEDERATED_FIELDS:
        raise DefenderCredentialProfileError(
            "federated credential profile fields are invalid"
        )
    if profile.get("algorithm") != "RS256":
        raise DefenderCredentialProfileError("federated credential algorithm is invalid")
    issuer = _parse_https_issuer(profile.get("issuer"))
    source_reference, cluster, namespace, service_account = (
        _parse_kubernetes_source_reference(profile.get("source_reference"))
    )
    subject = profile.get("subject")
    expected_subject = f"system:serviceaccount:{namespace}:{service_account}"
    if (
        type(subject) is not str
        or not subject
        or len(subject.encode("utf-8")) > _MAX_SUBJECT_BYTES
        or subject != expected_subject
    ):
        raise DefenderCredentialProfileError(
            "federated subject does not match the assertion source identity"
        )
    authorization_bytes, authorization_digest = _authorization_profile(
        {
            "algorithm": "RS256",
            "content_type": DEFENDER_AUTHORIZATION_PROFILE_CONTENT_TYPE,
            "issuer": issuer,
            "kind": "defender-authorization-profile",
            "mode": "federated-rs256",
            "schema_version": DEFENDER_AUTHORIZATION_PROFILE_SCHEMA_VERSION,
            "source_reference": source_reference,
            "subject": subject,
        }
    )
    return FederatedRS256CredentialPlan(
        mode="federated-rs256",
        issuer=issuer,
        subject=subject,
        source_reference=source_reference,
        cluster=cluster,
        namespace=namespace,
        service_account=service_account,
        authorization_profile_bytes=authorization_bytes,
        authorization_profile_digest=authorization_digest,
    )


def decode_defender_credential_profile(value: bytes) -> DefenderCredentialPlan:
    """Decode one exact canonical profile without reflecting supplied values."""

    if type(value) is not bytes or not value or len(value) > _MAX_DOCUMENT_BYTES:
        raise DefenderCredentialProfileError(
            "Defender credential profile is absent or exceeds its limit"
        )
    try:
        decoded = strict_json_loads(value, limits=_DOCUMENT_LIMITS)
        if not isinstance(decoded, dict):
            raise DefenderCredentialProfileError(
                "Defender credential profile is not an object"
            )
        if canonical_json_bytes(decoded, limits=_DOCUMENT_LIMITS) != value:
            raise DefenderCredentialProfileError(
                "Defender credential profile is not canonical JSON"
            )
    except StrictJSONError:
        raise DefenderCredentialProfileError(
            "Defender credential profile is not strict bounded JSON"
        ) from None
    profile = cast(dict[str, object], decoded)
    if (
        profile.get("kind") != "defender-credential-profile"
        or profile.get("schema_version")
        != DEFENDER_CREDENTIAL_PROFILE_SCHEMA_VERSION
    ):
        raise DefenderCredentialProfileError(
            "Defender credential profile identity is invalid"
        )
    mode = profile.get("mode")
    if mode == "certificate-ps256":
        return _decode_certificate_profile(profile)
    if mode == "federated-rs256":
        return _decode_federated_profile(profile)
    raise DefenderCredentialProfileError("Defender credential mode is invalid")


__all__ = [
    "DEFENDER_AUTHORIZATION_PROFILE_CONTENT_TYPE",
    "DEFENDER_AUTHORIZATION_PROFILE_SCHEMA_VERSION",
    "DEFENDER_CREDENTIAL_PROFILE_CONTENT_TYPE",
    "DEFENDER_CREDENTIAL_PROFILE_SCHEMA_VERSION",
    "CertificatePS256CredentialPlan",
    "DefenderCredentialPlan",
    "DefenderCredentialProfileError",
    "FederatedRS256CredentialPlan",
    "decode_defender_credential_profile",
]
