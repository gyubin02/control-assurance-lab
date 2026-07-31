# 0009 — A valid signature is not an admission

Status: accepted

## The failure we are preventing

An Ed25519 signature can answer a useful question:

> Did a key trusted under this policy sign these exact bytes?

It cannot answer whether the bytes belong to a job we issued, whether the same
envelope was already used yesterday, whether an earlier result was skipped, or
whether the evidence reached durable custody before the sender received an
acknowledgement.

Treating “signature valid” as “evidence accepted” would leave a signed replay as
a valid experiment run.

## Decision

Admission is a state transition, not a pure signature check.

1. The control plane issues a 256-bit random job nonce once. The durable lease
   binds it to one tenant, collector identity, audience, capability digest,
   epoch, sequence, and expiry. It also binds the immutable trust-policy
   coordinate: policy ID, monotonically increasing revision, and the SHA-256
   digest of the exact canonical policy bytes.
2. The collector signs a canonical collection statement. The statement binds
   the lease coordinates to the exact CAB manifest digest.
3. The admission service accepts the raw DSSE envelope and a CAB directory. It
   does not accept a caller-made “verified” object. The service reads its own
   clock once, obtains policy from its configured resolver, and performs the
   DSSE and CAB checks itself.
4. Before opening a transaction, the service seals the CAB into one bounded,
   deterministic binary snapshot. The snapshot has no timestamps, ownership
   metadata, links, or source pathname. The bytes checked are therefore the
   bytes committed and later sent to custody.
5. One transaction consumes the lease, advances the collector sequence, stores
   the original envelope, sealed CAB, and exact trust-policy bytes, and appends
   an acceptance receipt to the tenant's receipt chain. Stored reads rerun the
   DSSE decision instead of trusting a serialized “verified” flag. The same
   transaction advances a policy-revision high-water mark. A lower revision is
   a rollback; a second digest for an existing revision is a fork. Both fail
   closed.
6. The sender is acknowledged only after the configured custody store confirms
   the expected content-addressed object and the service commits a signed
   custody acknowledgement. A pending custody record is the tail of that
   tenant's ledger: no successor can be admitted, and no later receipt can be
   acknowledged, until reconciliation makes the predecessor durable.

An exact retry after a lost acknowledgement returns the original receipt. Its
fingerprint includes the raw envelope, sealed CAB, policy, verifier result,
configured audience and capability, accepted signer set, and custody
destination. It does not create a second admission. A different request using
the same lease is rejected.

## What the receipt must bind

- trusted admission time;
- tenant, collector, job, audience, epoch, and sequence;
- the signed predecessor when a collector starts a new epoch;
- lease nonce digest rather than the nonce itself;
- CAB ID, manifest digest, and sealed-snapshot digest;
- envelope and signed-payload digests;
- trust-policy digest and accepted signer identities/key IDs;
- trust-policy ID and immutable monotonic revision;
- SHA-256 public-key fingerprints, derived by admission from canonical raw
  Ed25519 public keys, for both the lease authority and receipt signer;
- the preceding receipt digest; and
- deterministic custody object and reference; and
- a receipt signer whose public-key material, not merely key label, is distinct
  from the lease authority.

The receipt does not copy source credentials or raw customer data.

## Consequences

- An envelope can be cryptographically valid and still be rejected as stale,
  out of sequence, unexpected, or replayed.
- A later collector epoch begins at sequence one and must carry the
  authority-signed final head of the preceding epoch. Restarting a process does
  not reset sequence state.
- Offline DSSE verification remains useful, but it cannot prove freshness.
- The R1 ledger is a private, quota-bound SQLite database with strict schema and
  file checks. Every database-path component is opened without following
  symbolic links. The service opens the main database once with `O_NOFOLLOW`,
  retains that descriptor for its lifetime, and gives SQLite
  `/proc/self/fd/<dbfd>` rather than reopening the pathname. One serialized
  SQLite connection is retained with it; the parent, published pathname,
  pinned descriptor, SQLite-reported inode, and WAL/SHM files are checked at
  transaction boundaries. The reference implementation therefore requires
  Linux `openat`/`O_NOFOLLOW` and `/proc/self/fd` semantics and fails closed
  when they are unavailable.
- Startup validates every stored receipt signature and every tenant and
  collector predecessor link up to an exact head. Normal appends validate a
  cached, previously closed head and its immediate predecessor. A
  `PRAGMA data_version` change from another SQLite connection triggers the
  bounded full validation again before work continues. Count/min/max checks
  reject gaps cheaply; the signed walk also rejects a forged replacement that
  preserves those aggregates. The work is bounded by the tenant admission
  and database byte quotas rather than growing without limit on every normal
  append.
- The reference ledger demonstrates transaction, retry, and crash semantics on
  one node. Its private mode-0700 directory excludes other UIDs, and stable
  symlink, hard-link, pathname, inode, and sidecar substitutions are rejected.
  It does not treat a process with the same effective UID, or a privileged
  process able to manipulate its file descriptors and `/proc` view, as a
  hostile security boundary. Nor does it claim to detect privileged rollback of
  the complete valid database plus sidecars, host cloning, or equivocation
  between verifiers. A production deployment still needs an independently
  witnessed, signed receipt-head anchor or transparency service, an HA ledger,
  a KMS signer latency contract, and independently operated WORM custody.
- Key revocation history, lease state, sequence state, and receipt-chain heads
  are part of disaster recovery. Restoring only the CAB files is insufficient.
