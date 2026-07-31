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

Keep the lease-authority Ed25519 private key in the separate control plane that
issues leases. Never copy that private key to the admission host. Export only
its SubjectPublicKeyInfo PEM public key for admission-side verification. For
example, run this in the lease-issuing environment:

```bash
openssl pkey -in lease-authority-private.pem -pubout \
  -out lease-authority-public.pem
```

Provision a different Ed25519 PKCS#8 private key on the admission host for
signing receipts. An encrypted receipt-signing PEM is supported by setting
`password_file` in the configuration. Create its password file through your
normal secret-delivery process; do not put a password on the command line.

Every private key, public verification key, password, and configuration file
must be owned by the service account with mode `0600` or stricter. The public
key is not confidential, but its integrity is authorization-critical. Each
immediate directory must be owned by that account with mode `0700` or stricter.
Policy, custody, and ledger paths must be absolute and must not contain symbolic
links.

## Configuration

The configuration contains locations and public identifiers, not passwords:

```json
{
  "schema": "application/vnd.control-assurance.admission-config.v2+json",
  "ledger_file": "/srv/assurance-lab/state/admission.sqlite3",
  "policy_root": "/srv/assurance-lab/policies",
  "custody_root": "/srv/assurance-lab/custody",
  "expected_audience": "admission:production",
  "expected_capability_digest": "sha256:REPLACE_WITH_64_LOWERCASE_HEX",
  "lease_authority": {
    "key_id": "key:lease-authority-2026q3",
    "public_key_file": "/srv/assurance-lab/keys/lease-authority-public.pem"
  },
  "receipt_signer": {
    "key_id": "key:admission-receipts-2026q3",
    "private_key_file": "/srv/assurance-lab/keys/admission-receipts.pem",
    "password_file": "/srv/assurance-lab/keys/admission-receipts.password"
  }
}
```

Use `null` for the receipt signer's `password_file` only when its PKCS#8 PEM is
unencrypted. The lease-authority public key and receipt-signing key must
identify different key material. Version 1 configurations that placed a lease
authority `private_key_file` on the admission host are rejected; migrate them
by exporting the public key and using the version 2 schema above.

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
identical retry of an already finalized receipt returns `exact-retry` and the
same receipt bytes. Resuming an unsigned preparation returns `admitted` when it
wins the first finalization.

## What is durable while a signer is unavailable

Receipt signing is split into three steps:

1. A short SQLite transaction reserves the next tenant and collector sequence
   and stores the exact unsigned receipt body and evidence bytes.
2. The transaction ends before the receipt signer is called.
3. A second short transaction accepts the signature only if that exact
   preparation still owns the reserved chain position, then consumes the lease
   and advances the receipt heads atomically.

Custody acknowledgements use the same prepare, sign, and compare-and-finalize
shape. No receipt or acknowledgement signing call is made while SQLite holds
its `BEGIN IMMEDIATE` writer lock. A slow remote signer therefore does not stop
an unrelated tenant from writing. The tenant whose next receipt is being
signed remains intentionally blocked: allowing a successor to pass it would
make receipt order depend on network timing.

If receipt signing fails, the lease remains unconsumed but reserved by the
stored preparation. Retry the same envelope, CAB, policy revision, and custody
binding. A changed request cannot take over the reservation. If the process
stops after signing but before finalization, the signature may be requested
again on restart, but only over the same canonical body. The reconciliation
command can also finish this preparation from the verified bytes already in
the ledger; it does not need the original CAB directory or a live policy
resolver.

If acknowledgement signing fails, the receipt is already committed and its
lease is already consumed. The verified custody object and exact unsigned
acknowledgement remain recoverable through reconciliation.

## Recover after signing or custody interruption

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

## Ledger upgrade boundary

The signing preparation tables are part of internal ledger schema version 3
and its SQLite schema fingerprint. A ledger created by an earlier build does
not have those tables, so this build rejects it instead of silently altering
evidence history. There is no supported in-place migration in this release.

Before upgrading an existing deployment, stop every writer and preserve a
byte-for-byte backup of the database and its custody objects. Start this build
with a new ledger and issue new leases. Keep the old ledger with the matching
old binary as read-only audit material. Do not copy rows between databases by
hand. If uninterrupted receipt-chain continuity is a requirement, wait for a
signed export/import migration rather than starting a new chain.

This internal change does not change the public admission receipt,
acknowledgement, or lease media types. It does change which service build can
open an existing ledger.

## Remaining production boundary

The reference service still uses one SQLite node and one process-local
connection lock. It does not provide replicated consensus or automatic signer
failover. Each remote signer client must impose a bounded request deadline;
the ledger deliberately cannot cancel a signer call on its behalf.

Different tenants may reach the signer concurrently. A signer adapter must
therefore be thread-safe as well as deadline-bounded. Signature verification
inside ledger transactions uses only the public key pinned when the ledger was
opened; it never calls the remote signer adapter.

After a crash, the service can prove which canonical body remains to be signed,
but the current signer interface has no durable external operation id. A retry
can therefore create more than one KMS or HSM audit entry for the same body.
Only the signature that wins compare-and-finalize becomes authoritative in the
ledger. Deployments that require exactly one external signing operation need
an idempotent signer API keyed by the stored body digest.
