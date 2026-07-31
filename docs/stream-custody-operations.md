# Signed custody for streamed evidence

Large Elastic and EDR captures use the v2 stream snapshot:

```text
snapshot/
├── snapshot.json
└── blobs/
    ├── <sha256>
    └── <sha256>
```

`snapshot.json` identifies every CAB path, byte size, and SHA-256 digest.
Duplicate CAB files share one blob. That is enough to verify a local snapshot,
but it does not prove that every member reached durable storage.

`seal_streamed_cab_snapshot` closes that operational gap. It publishes the
descriptor, every unique blob, and one signed closure through
`S3ObjectLockCustody`.

## What “closed” means

The workflow does these steps in order:

1. verify the complete local v2 snapshot against a caller-supplied snapshot
   digest;
2. conditionally write and reopen `snapshot.json`;
3. conditionally write and reopen every unique descriptor-listed blob;
4. verify the complete local snapshot again;
5. construct one canonical receipt covering the exact descriptor-derived
   object set;
6. sign a domain-separated SHA-256 digest of that receipt with a
   `ReceiptSigner`; and
7. conditionally write and reopen the signed closure under the same S3 Object
   Lock scope and retention instant.

The receipt records, for every component:

- semantic role (`snapshot-descriptor` or `cab-blob`);
- content digest and exact byte size;
- every CAB path represented by a deduplicated blob; and
- the complete canonical S3 custody acknowledgement, including its exact
  `VersionId`.

It also requires all acknowledgements to share one:

- tenant scope digest;
- CAB scope digest;
- bucket ARN digest;
- KMS key ARN digest;
- SSE-KMS or DSSE-KMS algorithm;
- COMPLIANCE mode; and
- whole-second retain-until instant.

The descriptor object comes first. Blob objects are sorted by digest. Paths
within a deduplicated blob are sorted and unique. Omitted, repeated,
substituted, or size-altered members therefore change the canonical receipt
or fail exact-set verification.

## Signature boundary

The signature input is not arbitrary JSON and is not the S3 acknowledgement.
It is:

```text
UTF8("control-assurance:stream-custody-receipt:v1")
00
uint16_be(32)
raw_sha256(canonical_receipt)
```

The domain and fixed-length digest framing prevent a signature from being
reinterpreted as another protocol message.

The signer must implement the existing `ReceiptSigner` contract:

```python
signer.key_id
signer.public_key_bytes  # exact 32-byte Ed25519 public key
signer.sign(message)
```

`VaultTransitEd25519ReceiptSigner` is compatible. Its returned signature is
verified locally before the signed closure is allowed into S3. The closure
stores the signer key ID and SHA-256 fingerprint of the pinned public key, not
Vault credentials or a private key.

Key rotation is an explicit trust-policy event. Keep the old raw public key
and key ID available for at least as long as any closure signed by that key
must remain verifiable.

## Sealing example

The snapshot digest must come from a separate trusted state transition, job
record, or admission decision. Discovering it from the directory immediately
before sealing does not provide an external anchor.

```python
from datetime import UTC, datetime, timedelta
from pathlib import Path

from assurance_lab.evidence.stream_custody import seal_streamed_cab_snapshot

retain_until = datetime.now(UTC).replace(microsecond=0) + timedelta(days=365)

sealed = seal_streamed_cab_snapshot(
    Path("/var/lib/control-assurance/staging/cab-42"),
    expected_snapshot_digest="sha256:<externally-recorded-digest>",
    tenant_id="tenant:bank-a",
    retain_until=retain_until,
    custody=s3_object_lock_custody,
    receipt_signer=vault_transit_signer,
)

persist_atomically(
    sealed.closure_bytes,
    sealed.closure_acknowledgement.to_canonical_bytes(),
)
```

The caller must atomically persist both returned byte strings, or place them
in a compare-and-commit ledger transition. The final acknowledgement cannot
be embedded inside the closure it acknowledges without creating a circular
digest.

Do not recalculate `retain_until` on retry. The exact value is part of every
component acknowledgement and the signed receipt.

## Offline verification

Offline verification needs:

- canonical signed closure bytes;
- the final closure acknowledgement;
- canonical `snapshot.json` bytes;
- the externally trusted snapshot digest;
- expected tenant ID;
- the pinned custody configuration; and
- expected signer key ID plus raw Ed25519 public key.

```python
from assurance_lab.evidence.stream_custody import (
    verify_stream_custody_closure,
)

result = verify_stream_custody_closure(
    closure_bytes,
    closure_acknowledgement,
    descriptor_bytes,
    expected_snapshot_digest=expected_snapshot_digest,
    tenant_id="tenant:bank-a",
    custody=s3_object_lock_custody,
    receipt_signer=pinned_public_key_verifier,
)
```

The default path:

- parses strict, bounded JSON;
- requires exact canonical serialization;
- derives the unique blob set from the descriptor;
- compares that set byte-for-byte with the signed receipt claims;
- checks every acknowledgement against the configured tenant/CAB and
  bucket/KMS scope; and
- verifies Ed25519 locally.

It does not call the signer. `S3ObjectLockCustody.verify_acknowledgement_scope`
is a local calculation and does not call AWS.

The final result says `exact_versions_reverified=False`. That wording matters:
offline verification proves receipt integrity and the client’s earlier
claims, not current S3 availability.

## Exact-version online verification

For an audit sample, restore drill, or incident investigation:

```python
result = verify_stream_custody_closure(
    closure_bytes,
    closure_acknowledgement,
    descriptor_bytes,
    expected_snapshot_digest=expected_snapshot_digest,
    tenant_id="tenant:bank-a",
    custody=s3_object_lock_custody,
    receipt_signer=pinned_public_key_verifier,
    online_reverify=True,
)

assert result.exact_versions_reverified is True
```

This performs `HeadObject` and `GetObject` for every component and for the
signed closure. Every request includes the acknowledged `VersionId`. Every
returned body is streamed through SHA-256 and must reproduce its original
canonical acknowledgement.

Online verification is intentionally expensive. Run it on a documented
sampling schedule and during recovery exercises; do not silently replace it
with a “latest object” metadata check.

## Crash and retry behavior

Every S3 object key is derived from:

```text
tenant scope + CAB scope + object SHA-256
```

Every write uses `If-None-Match: *`. If the process stops after S3 accepted a
component, a retry reaches the same key. `S3ObjectLockCustody` then reopens the
existing exact version and continues only when its bytes, scope, checksum,
retention, encryption, and KMS identity match.

The same applies if the final closure PUT succeeded but its response was lost.
Ed25519 signing is deterministic for the same key and message, so the rebuilt
closure has the same digest. With the same explicit retention instant, retry
reconciles the already locked closure instead of creating a new logical
result.

Fail closed on:

- `collision`: a content-addressed key contains different bytes or metadata;
- `ambiguous_put`: no exact committed outcome can be recovered;
- signer unavailability or a signature that fails local verification;
- local snapshot change during component writes; or
- any closure/descriptor/object-set mismatch.

Do not delete a conflicting object, choose a new CAB identifier, or accept a
later retention date merely to make the job complete. Preserve the failed job
record and investigate the conflict.

## What the acknowledgement does not prove

`S3CustodyAcknowledgement` is canonical output produced by this client after
PUT/HEAD/GET closure. **AWS does not sign it.**

The signed stream-custody receipt authenticates which acknowledgements the
receipt signer accepted. It does not independently prove:

- CloudTrail delivery;
- replication completion;
- KMS key availability for the full retention period;
- legal or regulatory compliance;
- correct IAM, SCP, bucket-policy, or key-policy deployment; or
- availability of the object at a later time unless online verification was
  run then.

Use CloudTrail data events, AWS Config/Security Hub controls, KMS monitoring,
replication alarms, independent ledger anchoring, and restore drills as
separate controls. The base bucket, policy, IAM, KMS, and replication boundary
is documented in [S3 Object Lock custody](s3-object-lock-operations.md).

## Production qualification checklist

Before calling this path production-ready in an organization-owned account:

- run a real SDK interoperability test against a dedicated Object Lock bucket;
- inject socket loss before and after actual `PutObject` commit;
- verify conditional-write enforcement in bucket policy;
- exercise exact-version reads under the final IAM/SCP/KMS policies;
- rotate the Vault Transit signing key and verify old closures offline;
- verify KMS rotation and disabled-key alerting;
- measure large-object upload, audit-sample, and recovery throughput;
- prove replica retention and byte equality if cross-Region recovery is in
  scope; and
- record a restore drill that reconstructs a CAB from descriptor-listed exact
  versions and verifies it independently.

The repository tests prove deterministic closure logic and adversarial
handling with local test doubles. They do not claim a live AWS or Vault
deployment unless the operator-owned live procedures were run and their
results were retained.
