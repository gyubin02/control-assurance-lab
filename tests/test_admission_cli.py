from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import assurance_lab.admission_cli as admission_cli
from assurance_lab.admission_cli import CONFIG_MEDIA_TYPE, AdmissionCLIConfig
from assurance_lab.evidence.admission import (
    ADMISSION_SCHEMA_VERSION,
    COLLECTION_STATEMENT_MEDIA_TYPE,
    CollectionStatement,
    issue_signed_job_lease,
)
from assurance_lab.evidence.attestation import (
    TRUST_POLICY_MEDIA_TYPE,
    TRUST_POLICY_SCHEMA_VERSION,
    KeyStatus,
    TrustedKey,
    TrustPolicy,
    dsse_pae,
)
from assurance_lab.evidence.bundle import (
    PROFILE,
    ROOT_MEDIA_TYPE,
    SCHEMA_VERSION,
    BundleFile,
    BundleManifest,
    EvaluationRef,
    EvaluatorRef,
    ExperimentRef,
    Sensitivity,
)
from assurance_lab.evidence.canonical import canonical_json_bytes, strict_json_loads
from assurance_lab.evidence.reference_adapters import (
    Ed25519PEMReceiptSigner,
    policy_relative_path,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
AUDIENCE = "admission:reference"
CAPABILITY_DIGEST = f"sha256:{'c' * 64}"
POLICY_ID = "policy:collector-reference"
POLICY_REVISION = 7
LEASE_PASSWORD = b"lease-authority-test-password"
RECEIPT_PASSWORD = b"receipt-service-test-password"


def _digest(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _private_pem(key: Ed25519PrivateKey, password: bytes) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password),
    )


def _public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _write(path: Path, payload: bytes, mode: int) -> None:
    path.write_bytes(payload)
    path.chmod(mode)


def _mkdir(path: Path, mode: int = 0o700) -> None:
    path.mkdir(parents=True)
    path.chmod(mode)


def _manifest(payload: bytes) -> BundleManifest:
    return BundleManifest(
        media_type=ROOT_MEDIA_TYPE,
        schema_version=SCHEMA_VERSION,
        profile=PROFILE,
        created_at="2026-07-29T09:00:00.000000Z",
        as_of="2026-07-29T08:59:00.000000Z",
        experiment=ExperimentRef(
            id="admission-cli-e2e",
            spec_version="1.0.0",
            spec_digest=f"sha256:{'1' * 64}",
        ),
        evaluation=EvaluationRef(
            policy_id="policy:admission-cli-e2e",
            policy_digest=f"sha256:{'2' * 64}",
            evaluator=EvaluatorRef(
                name="assurance-lab-test",
                version="0.0.1",
                source_revision="fresh-process-test",
                image_digest=None,
            ),
        ),
        parent_bundles=[],
        files=[
            BundleFile(
                path="records/observation.json",
                sha256=hashlib.sha256(payload).hexdigest(),
                size=len(payload),
                media_type="application/json",
                role="control-observation",
                sensitivity=Sensitivity.SYNTHETIC,
                required_for=["admission-cli-e2e"],
            )
        ],
    )


def _write_cab(path: Path) -> BundleManifest:
    payload = canonical_json_bytes(
        {
            "control": "entitlement-boundary",
            "observed": "blocked",
            "synthetic": True,
        }
    )
    (path / "records").mkdir(parents=True)
    (path / "records/observation.json").write_bytes(payload)
    manifest = _manifest(payload)
    (path / "bundle.json").write_bytes(manifest.canonical_bytes())
    return manifest


def _trust_policy(
    collector: Ed25519PrivateKey,
) -> TrustPolicy:
    return TrustPolicy(
        media_type=TRUST_POLICY_MEDIA_TYPE,
        schema_version=TRUST_POLICY_SCHEMA_VERSION,
        policy_id=POLICY_ID,
        threshold=1,
        trusted_keys=(
            TrustedKey(
                key_id="key:collector-e2e",
                identity="collector:e2e",
                algorithm="ed25519",
                public_key=base64.b64encode(_public_bytes(collector)).decode("ascii"),
                allowed_payload_types=(COLLECTION_STATEMENT_MEDIA_TYPE,),
                valid_from="2026-01-01T00:00:00.000000Z",
                valid_until="2030-01-01T00:00:00.000000Z",
                status=KeyStatus.ACTIVE,
                revocation_effective_at=None,
            ),
        ),
    )


@dataclass(frozen=True, slots=True)
class _CLISetup:
    private_root: Path
    config_file: Path
    config: dict[str, Any]
    policy_file: Path
    policy_bytes: bytes
    policy_digest: str
    grant_file: Path
    envelope_file: Path
    cab: Path
    custody_root: Path
    authority_key_file: Path
    receipt_key_file: Path

    def write_config(self, document: dict[str, Any] | None = None) -> None:
        _write(
            self.config_file,
            canonical_json_bytes(document or self.config),
            0o600,
        )


def _setup(tmp_path: Path, *, job_id: str = "job:e2e-0001") -> _CLISetup:
    private_root = tmp_path / "admission"
    _mkdir(private_root)
    policy_root = private_root / "policies"
    custody_root = private_root / "custody"
    ledger_root = private_root / "state"
    key_root = private_root / "keys"
    for directory in (policy_root, custody_root, ledger_root, key_root):
        _mkdir(directory)

    authority_key = Ed25519PrivateKey.generate()
    receipt_key = Ed25519PrivateKey.generate()
    collector_key = Ed25519PrivateKey.generate()
    authority_key_file = key_root / "lease-authority.pem"
    receipt_key_file = key_root / "receipt-service.pem"
    authority_password_file = key_root / "lease-authority.password"
    receipt_password_file = key_root / "receipt-service.password"
    _write(authority_key_file, _private_pem(authority_key, LEASE_PASSWORD), 0o600)
    _write(receipt_key_file, _private_pem(receipt_key, RECEIPT_PASSWORD), 0o600)
    _write(authority_password_file, LEASE_PASSWORD, 0o600)
    _write(receipt_password_file, RECEIPT_PASSWORD, 0o600)

    config: dict[str, Any] = {
        "schema": CONFIG_MEDIA_TYPE,
        "custody_root": str(custody_root),
        "expected_audience": AUDIENCE,
        "expected_capability_digest": CAPABILITY_DIGEST,
        "lease_authority": {
            "key_id": "key:lease-authority-e2e",
            "password_file": str(authority_password_file),
            "private_key_file": str(authority_key_file),
        },
        "ledger_file": str(ledger_root / "admission.sqlite3"),
        "policy_root": str(policy_root),
        "receipt_signer": {
            "key_id": "key:receipt-service-e2e",
            "password_file": str(receipt_password_file),
            "private_key_file": str(receipt_key_file),
        },
    }
    config_file = private_root / "admission-config.json"
    _write(config_file, canonical_json_bytes(config), 0o600)
    # The parsed config itself is part of this fixture's contract.
    AdmissionCLIConfig.model_validate(config)

    policy = _trust_policy(collector_key)
    policy_bytes = policy.canonical_bytes()
    policy_digest = _digest(policy_bytes)
    policy_file = tmp_path / "collector-policy.json"
    _write(policy_file, policy_bytes, 0o644)

    cab = tmp_path / "candidate.cab"
    manifest = _write_cab(cab)
    manifest_digest = _digest(manifest.canonical_bytes())
    now = datetime.now(UTC)
    authority_signer = Ed25519PEMReceiptSigner(
        authority_key_file.read_bytes(),
        key_id="key:lease-authority-e2e",
        password=LEASE_PASSWORD,
    )
    grant = issue_signed_job_lease(
        signer=authority_signer,
        tenant_id="tenant:reference-bank",
        collector_id="collector:e2e",
        audience=AUDIENCE,
        job_id=job_id,
        capability_digest=CAPABILITY_DIGEST,
        policy_id=POLICY_ID,
        policy_revision=POLICY_REVISION,
        policy_digest=policy_digest,
        epoch=1,
        sequence=1,
        cab_id=f"cab:{manifest_digest}",
        manifest_digest=manifest_digest,
        issued_at=now - timedelta(minutes=2),
        expires_at=now + timedelta(minutes=30),
    )
    grant_file = tmp_path / "signed-lease.json"
    _write(grant_file, grant.canonical_bytes(), 0o644)

    lease = grant.lease
    statement = CollectionStatement(
        media_type=COLLECTION_STATEMENT_MEDIA_TYPE,
        schema_version=ADMISSION_SCHEMA_VERSION,
        lease_digest=lease.lease_digest(),
        tenant_id=lease.tenant_id,
        collector_id=lease.collector_id,
        audience=lease.audience,
        job_id=lease.job_id,
        capability_digest=lease.capability_digest,
        policy_id=lease.policy_id,
        policy_revision=lease.policy_revision,
        policy_digest=lease.policy_digest,
        epoch=lease.epoch,
        sequence=lease.sequence,
        previous_epoch=lease.previous_epoch,
        previous_epoch_final_sequence=lease.previous_epoch_final_sequence,
        previous_epoch_final_receipt_digest=lease.previous_epoch_final_receipt_digest,
        cab_id=lease.cab_id,
        manifest_digest=lease.manifest_digest,
        job_nonce=lease.job_nonce,
        collected_at=now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    )
    payload = statement.canonical_bytes()
    signature = collector_key.sign(dsse_pae(COLLECTION_STATEMENT_MEDIA_TYPE, payload))
    envelope_bytes = canonical_json_bytes(
        {
            "payload": base64.b64encode(payload).decode("ascii"),
            "payloadType": COLLECTION_STATEMENT_MEDIA_TYPE,
            "signatures": [
                {
                    "keyid": "key:collector-e2e",
                    "sig": base64.b64encode(signature).decode("ascii"),
                }
            ],
        }
    )
    envelope_file = tmp_path / "collection.dsse.json"
    _write(envelope_file, envelope_bytes, 0o644)
    return _CLISetup(
        private_root=private_root,
        config_file=config_file,
        config=config,
        policy_file=policy_file,
        policy_bytes=policy_bytes,
        policy_digest=policy_digest,
        grant_file=grant_file,
        envelope_file=envelope_file,
        cab=cab,
        custody_root=custody_root,
        authority_key_file=authority_key_file,
        receipt_key_file=receipt_key_file,
    )


def _run(*arguments: str) -> subprocess.CompletedProcess[bytes]:
    command = [sys.executable, "-m", "assurance_lab.cli", *arguments]
    assert LEASE_PASSWORD.decode() not in command
    assert RECEIPT_PASSWORD.decode() not in command
    return subprocess.run(
        command,
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
    )


def _json_output(completed: subprocess.CompletedProcess[bytes]) -> dict[str, Any]:
    assert completed.returncode == 0, completed.stderr.decode()
    assert completed.stderr == b""
    document = strict_json_loads(completed.stdout)
    assert isinstance(document, dict)
    assert canonical_json_bytes(document) == completed.stdout
    return document


def _json_error(completed: subprocess.CompletedProcess[bytes]) -> dict[str, Any]:
    assert completed.returncode == 2
    assert completed.stdout == b""
    document = strict_json_loads(completed.stderr)
    assert isinstance(document, dict)
    assert canonical_json_bytes(document) == completed.stderr
    return document


def _install_and_register(setup: _CLISetup) -> None:
    installed = _json_output(
        _run(
            "admission",
            "policy",
            "install",
            "--config",
            str(setup.config_file),
            "--policy",
            str(setup.policy_file),
            "--revision",
            str(POLICY_REVISION),
            "--json",
        )
    )
    assert installed["disposition"] == "installed"
    assert installed["policy_digest"] == setup.policy_digest
    registered = _json_output(
        _run(
            "admission",
            "lease",
            "register",
            "--config",
            str(setup.config_file),
            "--grant",
            str(setup.grant_file),
            "--json",
        )
    )
    assert registered["status"] == "registered"


def _admit(setup: _CLISetup) -> subprocess.CompletedProcess[bytes]:
    return _run(
        "admission",
        "bundle",
        "admit",
        "--config",
        str(setup.config_file),
        "--envelope",
        str(setup.envelope_file),
        "--cab",
        str(setup.cab),
        "--json",
    )


def test_fresh_process_roundtrip_and_exact_retry_use_real_custody(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    validated = _json_output(
        _run(
            "admission",
            "config",
            "validate",
            "--config",
            str(setup.config_file),
            "--json",
        )
    )
    assert validated["status"] == "valid"
    assert validated["lease_authority_key_fingerprint"] != (
        validated["receipt_signer_key_fingerprint"]
    )

    _install_and_register(setup)
    retry_install = _json_output(
        _run(
            "admission",
            "policy",
            "install",
            "--config",
            str(setup.config_file),
            "--policy",
            str(setup.policy_file),
            "--revision",
            str(POLICY_REVISION),
            "--json",
        )
    )
    assert retry_install["disposition"] == "exact-retry"

    admitted = _json_output(_admit(setup))
    assert admitted["disposition"] == "admitted"
    assert admitted["status"] == "durable"
    receipt = admitted["receipt"]
    acknowledgement = admitted["custody_acknowledgement"]
    assert acknowledgement["body"]["receipt_digest"] == _digest(
        canonical_json_bytes(receipt)
    )

    object_id = receipt["body"]["custody_object_id"]
    object_root = setup.custody_root / object_id
    assert sorted(path.name for path in object_root.iterdir()) == [
        "cab.snapshot",
        "envelope.dsse.json",
        "receipt.json",
        "trust-policy.json",
    ]
    assert (object_root / "envelope.dsse.json").read_bytes() == (
        setup.envelope_file.read_bytes()
    )
    assert (object_root / "trust-policy.json").read_bytes() == setup.policy_bytes
    assert (object_root / "receipt.json").read_bytes() == canonical_json_bytes(receipt)

    retried = _json_output(_admit(setup))
    assert retried == {
        **admitted,
        "disposition": "exact-retry",
    }
    pending = _json_output(
        _run(
            "admission",
            "custody",
            "pending",
            "--config",
            str(setup.config_file),
            "--json",
        )
    )
    assert pending["count"] == 0
    assert pending["objects"] == []


def test_committed_admission_is_reconciled_after_custody_outage(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    _install_and_register(setup)
    setup.custody_root.chmod(0o500)
    rejected = _json_error(_admit(setup))
    assert rejected["error"]["code"] == "custody-unavailable"
    setup.custody_root.chmod(0o700)

    reconciled = _json_output(
        _run(
            "admission",
            "ledger",
            "reconcile",
            "--config",
            str(setup.config_file),
            "--limit",
            "10",
            "--json",
        )
    )
    assert reconciled["completed"] == 1
    retried = _json_output(_admit(setup))
    assert retried["disposition"] == "exact-retry"
    assert retried["status"] == "durable"


@pytest.mark.parametrize(
    ("target", "expected_message"),
    [
        ("config", "admission configuration must be owner-controlled"),
        ("authority-key", "private key must be owner-controlled"),
        ("receipt-key", "private key must be owner-controlled"),
    ],
)
def test_private_file_permissions_fail_closed(
    tmp_path: Path,
    target: str,
    expected_message: str,
) -> None:
    setup = _setup(tmp_path)
    selected = {
        "config": setup.config_file,
        "authority-key": setup.authority_key_file,
        "receipt-key": setup.receipt_key_file,
    }[target]
    selected.chmod(0o644)
    failed = _json_error(
        _run(
            "admission",
            "config",
            "validate",
            "--config",
            str(setup.config_file),
            "--json",
        )
    )
    assert failed["error"]["code"] == "operation-invalid"
    assert expected_message in failed["error"]["message"]


def test_changed_lease_authority_cannot_reopen_existing_ledger(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    _install_and_register(setup)
    replacement = Ed25519PrivateKey.generate()
    _write(
        setup.authority_key_file,
        _private_pem(replacement, LEASE_PASSWORD),
        0o600,
    )
    failed = _json_error(
        _run(
            "admission",
            "lease",
            "register",
            "--config",
            str(setup.config_file),
            "--grant",
            str(setup.grant_file),
            "--json",
        )
    )
    assert failed["error"]["code"] == "operation-invalid"
    assert "admission ledger" in failed["error"]["message"]


def test_unsafe_installed_policy_is_unavailable_at_admission(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    _install_and_register(setup)
    relative = policy_relative_path(POLICY_ID, POLICY_REVISION, setup.policy_digest)
    installed = Path(setup.config["policy_root"]) / relative
    installed.chmod(0o644)
    failed = _json_error(_admit(setup))
    assert failed["error"]["code"] == "policy-unavailable"


def test_symbolic_link_root_is_rejected_without_following_it(tmp_path: Path) -> None:
    setup = _setup(tmp_path)
    linked = setup.private_root / "linked-custody"
    linked.symlink_to(setup.custody_root, target_is_directory=True)
    changed = {**setup.config, "custody_root": str(linked)}
    setup.write_config(changed)
    failed = _json_error(
        _run(
            "admission",
            "config",
            "validate",
            "--config",
            str(setup.config_file),
            "--json",
        )
    )
    assert failed["error"]["code"] == "operation-invalid"
    assert "symbolic-link ancestry" in failed["error"]["message"]


def test_policy_install_never_replaces_existing_bytes(tmp_path: Path) -> None:
    setup = _setup(tmp_path)
    first = _json_output(
        _run(
            "admission",
            "policy",
            "install",
            "--config",
            str(setup.config_file),
            "--policy",
            str(setup.policy_file),
            "--revision",
            str(POLICY_REVISION),
            "--json",
        )
    )
    installed = Path(setup.config["policy_root"]) / first["relative_path"]
    original = installed.read_bytes()
    installed.write_bytes(b"not the same policy bytes")
    installed.chmod(0o600)
    failed = _json_error(
        _run(
            "admission",
            "policy",
            "install",
            "--config",
            str(setup.config_file),
            "--policy",
            str(setup.policy_file),
            "--revision",
            str(POLICY_REVISION),
            "--json",
        )
    )
    assert failed["error"]["code"] == "operation-invalid"
    assert "different bytes" in failed["error"]["message"]
    assert installed.read_bytes() != original
    assert installed.read_bytes() == b"not the same policy bytes"


def test_interrupted_policy_write_never_publishes_partial_final_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup = _setup(tmp_path)
    configuration = AdmissionCLIConfig.model_validate(setup.config)

    def interrupt_after_prefix(descriptor: int, payload: bytes) -> None:
        assert os.write(descriptor, payload[:11]) == 11
        raise OSError("simulated interrupted policy write")

    monkeypatch.setattr(admission_cli, "_write_all", interrupt_after_prefix)
    with pytest.raises(ValueError, match="could not be installed safely"):
        admission_cli._install_policy(
            configuration=configuration,
            policy_path=setup.policy_file,
            revision=POLICY_REVISION,
        )

    relative = policy_relative_path(POLICY_ID, POLICY_REVISION, setup.policy_digest)
    assert not (Path(setup.config["policy_root"]) / relative).exists()
    revision_root = (Path(setup.config["policy_root"]) / relative).parent
    assert not any(
        path.name.startswith(".pending-policy-")
        for path in revision_root.iterdir()
    )
