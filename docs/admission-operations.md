# Running the single-node admission boundary

The reference admission service accepts one exact, signed CAB under a
pre-registered one-time lease. A successful command means the receipt, DSSE
envelope, sealed CAB snapshot, and trust policy were all written to local
custody and read back byte-for-byte.

This is a Linux, single-node reference boundary. It is not a substitute for a
KMS or HSM, replicated object storage, WORM retention, or an external
transparency log.

## Prepare the private paths

Create these paths before running the CLI. The CLI does not generate keys or
guess a storage layout.

```bash
sudo install -d -m 700 -o "$USER" -g "$(id -gn)" \
  /srv/assurance-lab \
  /srv/assurance-lab/keys \
  /srv/assurance-lab/state \
  /srv/assurance-lab/policies \
  /srv/assurance-lab/custody
```

Provision two different Ed25519 PKCS#8 private keys: one for lease-authority
verification and one for admission receipts. An encrypted PEM is supported by
setting `password_file` in the configuration. Create password files through
your normal secret-delivery process; do not put a password on the command line.

Every private key, password, and configuration file must be owned by the
service account with mode `0600` or stricter. Its immediate directory must be
owned by that account with mode `0700` or stricter. Policy, custody, and ledger
paths must be absolute and must not contain symbolic links.

## Configuration

The configuration contains locations and public identifiers, not passwords:

```json
{
  "schema": "application/vnd.control-assurance.admission-config.v1+json",
  "ledger_file": "/srv/assurance-lab/state/admission.sqlite3",
  "policy_root": "/srv/assurance-lab/policies",
  "custody_root": "/srv/assurance-lab/custody",
  "expected_audience": "admission:production",
  "expected_capability_digest": "sha256:REPLACE_WITH_64_LOWERCASE_HEX",
  "lease_authority": {
    "key_id": "key:lease-authority-2026q3",
    "private_key_file": "/srv/assurance-lab/keys/lease-authority.pem",
    "password_file": "/srv/assurance-lab/keys/lease-authority.password"
  },
  "receipt_signer": {
    "key_id": "key:admission-receipts-2026q3",
    "private_key_file": "/srv/assurance-lab/keys/admission-receipts.pem",
    "password_file": "/srv/assurance-lab/keys/admission-receipts.password"
  }
}
```

Use `null` for `password_file` only when the corresponding PKCS#8 PEM is
unencrypted. The two signer roles must use different key material.

Validate the paths, permissions, key formats, and role separation without
creating the ledger:

```bash
assurance-lab admission config validate \
  --config /srv/assurance-lab/admission.json
```

## Admit one CAB

Install the exact canonical trust-policy revision used by the collector. The
command computes the digest-derived location, creates only private
intermediate directories, and never replaces an existing revision.

```bash
assurance-lab admission policy install \
  --config /srv/assurance-lab/admission.json \
  --policy /secure-transfer/collector-policy.json \
  --revision 1
```

The control plane issues a canonical signed lease and transfers the grant as a
file. The collector separately creates a DSSE envelope whose payload is the
canonical collection statement bound to that lease and CAB. Neither signature
nor secret key is accepted on the command line.

Register the grant before accepting the evidence:

```bash
assurance-lab admission lease register \
  --config /srv/assurance-lab/admission.json \
  --grant /secure-transfer/job-0001.signed-lease.json
```

Then admit the collector's envelope and CAB directory:

```bash
assurance-lab admission bundle admit \
  --config /srv/assurance-lab/admission.json \
  --envelope /secure-transfer/job-0001.dsse.json \
  --cab /secure-transfer/job-0001.cab
```

Add `--json` to any leaf command for canonical JSON. A successful admission
returns the signed admission receipt and signed custody acknowledgement. An
identical retry returns `exact-retry` and the same receipt bytes.

## Recover after a custody interruption

Admission first commits the verified receipt to the private ledger, then
establishes custody. If the second step fails, the lease is already consumed;
do not issue a replacement lease for the same evidence. Restore the custody
backend and reconcile:

```bash
assurance-lab admission ledger reconcile \
  --config /srv/assurance-lab/admission.json \
  --limit 100
```

`custody pending` reports filesystem staging directories left by an interrupted
publisher:

```bash
assurance-lab admission custody pending \
  --config /srv/assurance-lab/admission.json
```

It is observation only. It does not prove a writer is dead and does not delete
anything. Stop every writer sharing the custody root before investigating or
removing a staging directory.
