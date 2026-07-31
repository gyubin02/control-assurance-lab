# Custody and signing runtime identity

`custody_ref` and `signing_key_ref` are selectors. They are not cloud
connection strings and they do not prove which bucket, retention policy, or
key version handled a run.

The runtime closes that gap with one canonical public document before it makes
a connector call:

```text
frozen run + frozen execution plan
             │
             ▼
exact deployment-profile registry
             │
             ├── pinned S3 Object Lock adapter
             ├── pinned Vault Transit Ed25519 signer
             └── canonical custody-runtime-identity bytes
```

The identity includes the run, configuration and execution-plan digests; the
exact S3 bucket ARN, AWS account, Region, customer-managed KMS key, encryption
mode, Object Lock mode, retention bounds and object-size bound; and the Vault
origin, namespace, Transit mount and key as non-reversible digests together
with the exact key version and public-key fingerprint.

It never contains a Vault endpoint string, namespace, mount path, key name,
token, AWS credential, client object, CA path, or private key.

## Bootstrap

Bootstrap code owns cloud authentication. It constructs
`S3ObjectLockCustody` and `VaultTransitEd25519ReceiptSigner` through the
documented adapters, then creates the public profile from those live pinned
objects:

```python
profile = CustodySigningDeploymentProfile.from_runtime(
    profile_id="bank-a-custody-v1",
    configuration=configuration,
    custody=s3_custody,
    signer=vault_signer,
)
registration = RegisteredCustodySigningRuntime(
    profile_bytes=profile.canonical_bytes(),
    custody=s3_custody,
    signer=vault_signer,
)
registry = ExactCustodyRuntimeProfileRegistry((registration,))
```

The registry key is the exact tuple of tenant, control, configuration digest,
custody reference and signing-key reference. There is no DNS, AWS, Vault,
secret-manager or naming-convention discovery in this lookup. Duplicate
entries are rejected.

The registration re-derives the public S3 and Vault identities from the
adapters. A profile copied from another bucket, account, KMS key, retention
policy, Vault origin, namespace, mount, key version or public key is rejected
before it can enter the registry.

## First execution and retry

Prepare the runtime only after the execution plan has been durably frozen:

```python
prepared = prepare_custody_signing_runtime(
    request,
    execution_plan,
    registry=registry,
)
execution_journal.store_runtime_identity(
    run_id=request.run_id,
    identity_bytes=prepared.identity_bytes,
    identity_digest=prepared.identity_digest,
)
```

The identity write must commit before PAM acquisition, connector collection,
signing, or S3 writes. A process crash before that commit has made no external
evidence side effect.

On retry, reopen the journaled bytes and require the current bootstrap to
reproduce them:

```python
prepared = prepare_custody_signing_runtime(
    request,
    execution_plan,
    registry=registry,
    expected_identity_bytes=journaled_identity_bytes,
)
```

Any profile rollout, bucket substitution, retention change, KMS change, Vault
key rotation or public-key change produces `runtime-identity-drift`. The
executor must stop; it must not silently publish a second interpretation of
the same run.

`attempt_count` does not decide whether expected bytes are required. A later
worker may be the first worker to reach the identity bind if an earlier lease
expired before making any external side effect. The journal decides:

- when no identity is bound, workers may prepare a candidate, but only the
  compare-and-set winner may proceed to PAM, collection, signing or custody;
- when an identity is already bound, the worker supplies those exact bytes as
  `expected_identity_bytes`; and
- a worker that loses the bind reopens the winner and prepares again against
  those bytes.

## Rotation and change control

A new bucket policy or key version is a new deployment profile:

1. construct and independently verify the new adapters;
2. issue a new opaque profile ID;
3. change the control's versioned custody and/or signing reference;
4. approve and deploy the resulting new control-configuration digest;
5. retain the old registry entry for all unfinished old runs; and
6. remove it only after those runs and their verification obligations close.

Do not replace a registry entry in place. An in-place change cannot be
distinguished from substitution after a restart unless the previously
journaled runtime identity is supplied.

The runtime identity stores only a digest of `key_id`. Signed receipts still
need the original key ID to select a verification key, so choose an opaque
value and do not encode Vault paths or organizational secrets in it.

## Retention and legal hold

The control's `retention_days` must fit inside the adapter's exact local
minimum and maximum retention bounds. The run-specific `custody_retain_until`
must remain exactly the execution plan's whole-second value.

`S3ObjectLockCustody` currently writes COMPLIANCE retention but does not set an
S3 legal hold. A configuration with `legal_hold=true` therefore fails with
`legal-hold-unsupported`. It is not treated as equivalent to COMPLIANCE
retention.

The S3 bucket policy and KMS policy remain independent enforcement boundaries.
The public identity records what this process selected; it does not prove that
an organization SCP, bucket policy, key policy, Vault policy, TLS route or
disaster-recovery procedure is correct. Those require operator-owned live
conformance tests.

## Logging boundary

`CustodyRuntimeIdentityError` exposes only bounded error codes. Registry
exceptions are replaced without their text. Runtime registrations and prepared
objects have custom representations containing digests only.

The canonical public identity intentionally contains S3 ARNs and the AWS
account number. Treat it as internal operational evidence. Vault location
components are digested even there so ordinary evidence readers do not learn
the signer network topology.
