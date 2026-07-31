# S3 Object Lock custody

The executor's exact bucket, KMS and retention selection is frozen before
collection as described in
[Custody and signing runtime identity](custody-runtime-identity.md).

`S3ObjectLockCustody` is the write-once boundary for evidence that has already
been verified. It does not turn an unverified file into evidence, and an S3
success response is not itself a custody acknowledgement.

For each file, or for bounded immutable canonical bytes supplied through
`put_bytes`, the adapter:

1. opens one non-symlink, single-link regular file;
2. streams it once to calculate SHA-256;
3. derives a key from the tenant scope, CAB scope, and object digest;
4. sends one conditional `PutObject` with explicit COMPLIANCE retention and a
   pinned customer-managed KMS key;
5. validates the returned version ID, SHA-256 checksum, and KMS identity;
6. performs `HeadObject` against that exact version;
7. performs `GetObject` against that exact version and hashes the returned
   bytes; and
8. emits a small canonical acknowledgement only after all checks close.

The source file, S3 response body, and retrieved object are processed in
bounded chunks. The adapter does not build a second in-memory copy of the
object. `put_bytes` is reserved for already-bounded receipts and closure
documents; it applies the same conditional write and exact-version checks.

## Why a version ID is part of the acknowledgement

Object Lock protects object *versions*. A later write can create another
version under the same key without changing the retention of the earlier
version. The acknowledgement therefore names the exact `VersionId` that was
reopened and checked. It never treats “the current object at this key” as a
stable identity.

AWS describes this version-specific WORM behavior and the difference between
GOVERNANCE and COMPLIANCE mode in
[Locking objects with Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html).
In COMPLIANCE mode, the retention period cannot be shortened and the protected
version cannot be deleted, including by the account root user.

## Bucket prerequisites

Use a general-purpose S3 bucket. Directory buckets do not support Object Lock.
Before the adapter accepts work, and again before and after every write, it
requires:

- `GetBucketVersioning` to return `Status: Enabled`; and
- `GetObjectLockConfiguration` to return
  `ObjectLockEnabled: Enabled`.

Those are exact AWS API contracts:

- [GetBucketVersioning](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketVersioning.html)
- [GetObjectLockConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectLockConfiguration.html)

Object Lock cannot be disabled after it is enabled, and AWS does not permit
versioning to be suspended on such a bucket. The repeated checks are still
intentional: a substituted client, wrong bucket, access point, emulator, or
test double must not silently weaken this boundary.

Configure Block Public Access at both account and bucket level, disable ACLs
with bucket-owner-enforced object ownership, and deny non-TLS requests. The
adapter never sends an ACL.

## Retention policy

The caller supplies one explicit, whole-second UTC `retain_until` value. A
local `S3RetentionPolicy` rejects values below its minimum or above its
maximum. The same range must be enforced independently in the bucket policy
with `s3:object-lock-remaining-retention-days`, and the policy must require
`s3:object-lock-mode` to be `COMPLIANCE`.

This is two different protection layers:

- the application bound catches a bad request before a write; and
- the bucket-policy bound rejects a compromised or replaced application.

AWS documents the retention condition key and the fact that an individual
object retention value can be set independently of the bucket default in
[Locking objects with Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html).

Do not use a short production retention simply to make a smoke test convenient.
COMPLIANCE retention is deliberately irreversible. Use a dedicated
non-production Object Lock bucket whose retention period has been approved for
conformance tests.

## Conditional, content-addressed writes

The object key has this shape:

```text
control-assurance/custody/v1/
  tenants/<tenant-scope-sha256>/
  cabs/<cab-scope-sha256>/
  objects/sha256/<object-sha256>
```

Raw tenant and CAB identifiers are not placed in S3 keys or acknowledgements.
Their scope digests use domain-separated, length-framed UTF-8 input, so a
tenant digest cannot be reinterpreted as a CAB digest.

Every write sends `If-None-Match: *`. Current S3 `PutObject` returns
`412 Precondition Failed` when the key already exists and can return
`409 ConditionalRequestConflict` for a concurrent conflicting write. See:

- [PutObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html)
- [How to prevent object overwrites with conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)
- [Enforce conditional writes on S3 buckets](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes-enforce.html)

The bucket policy should deny `PutObject` when the `s3:if-none-match` condition
key is absent. This turns the application's conditional-write convention into
a storage-side requirement.

An old SDK that rejects `IfNoneMatch` is not given an unconditional fallback.
Upgrade the SDK. Creating another locked version would defeat exact retry
semantics.

## SHA-256 closure

The adapter sends both:

```text
ChecksumAlgorithm = SHA256
ChecksumSHA256    = <canonical RFC 4648 base64>
```

and checks the same checksum in `PutObject`, `HeadObject`, and `GetObject`
responses. It also hashes every byte returned by `GetObject`. ETag is not used
as a content digest: AWS explicitly notes that ETag is not the MD5 of objects
encrypted with SSE-KMS and is not generally a full-object checksum. See
[Checking object integrity](https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html).

`HeadObject` and `GetObject` use `ChecksumMode=ENABLED`. For a KMS-encrypted
object, the workload therefore needs permission to decrypt the encrypted
checksum as well as the object.

## SSE-KMS and DSSE-KMS

Construction accepts only:

- `aws:kms` (SSE-KMS), or
- `aws:kms:dsse` (DSSE-KMS).

A full customer-managed KMS key ARN is mandatory. Aliases, bare key IDs, and
the AWS-managed `aws/s3` key are rejected. The KMS key partition and account
must match the configured bucket owner, and the S3 response must repeat the
exact pinned ARN.

AWS recommends a fully qualified key ARN because an alias can resolve in the
requester's account. AWS also requires the KMS key to be in the same Region as
the bucket. Permissions for ordinary SSE-KMS uploads and downloads include
`kms:GenerateDataKey` and `kms:Decrypt`. See
[Using server-side encryption with AWS KMS keys](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html).

DSSE-KMS must be used only with an SDK version whose S3 model supports
`aws:kms:dsse`. The adapter fails closed if the injected SDK rejects that
parameter; it never downgrades to SSE-KMS or SSE-S3.

## Workload identity and minimum API surface

Use an IAM role delivered by the compute platform. Do not put AWS access keys
in application configuration.

The injected client protocol exposes only:

```text
GetBucketVersioning
GetObjectLockConfiguration
PutObject
HeadObject
GetObject
```

It has no delete operation, no `PutObjectRetention`, no legal-hold mutation,
and no governance-retention bypass operation. The application role should not
have any of those permissions.

A starting identity policy needs these S3 actions, scoped to the one bucket
and custody prefix:

```text
s3:GetBucketVersioning
s3:GetBucketObjectLockConfiguration
s3:PutObject
s3:PutObjectRetention
s3:GetObject
s3:GetObjectVersion
s3:GetObjectRetention
```

and these KMS actions, scoped to the one customer-managed key:

```text
kms:GenerateDataKey
kms:Decrypt
```

`s3:PutObjectRetention` is needed because the COMPLIANCE date is supplied with
the object write. `s3:GetObjectRetention` is needed so HEAD/GET can return the
mode and retain-until date. A version-specific GET requires
`s3:GetObjectVersion`; AWS documents that distinction in
[GetObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html).

The bucket and KMS key policies should additionally:

- allow only the workload role and designated read/audit roles;
- require the exact KMS key ARN and selected encryption algorithm;
- require `COMPLIANCE`;
- bound remaining retention days;
- require `If-None-Match`;
- deny insecure transport; and
- deny access outside the custody prefix.

Validate the final policies with IAM Access Analyzer and an operator-owned
staging account. A prose permission list is not a substitute for testing the
actual organization SCPs, permission boundaries, session policies, bucket
policy, and KMS key policy together.

## Boto3 construction

Boto3 is intentionally not a base package dependency. A deployment that uses
AWS installs and pins Boto3 separately, then constructs a client with:

```python
from assurance_lab.evidence.s3_object_lock import create_boto3_s3_client

client = create_boto3_s3_client(region_name="ap-northeast-2")
```

The helper accepts no endpoint override, selects Signature Version 4, uses
virtual-hosted S3 addressing, ignores ambient proxy configuration, and
disables SDK retries. Disabling retries is important because a socket timeout
after S3 committed a PUT is ambiguous. Credential acquisition remains in the
standard AWS SDK credential provider chain; use workload identity and its
normal refresh path.

The injected-client design also supports a centrally constructed,
organization-hardened Boto3 client. That client is part of the production
boundary and must pin the AWS Region, enforce TLS certificate validation, set
finite connect/read timeouts, and keep request/response bodies and
authorization headers out of logs.

## Acknowledgement

The canonical acknowledgement contains:

- digest of the bucket ARN;
- tenant and CAB scope digests;
- digest of the object key;
- exact S3 version ID;
- COMPLIANCE retain-until date;
- S3 SHA-256 checksum;
- object SHA-256 digest;
- encryption algorithm; and
- digest of the pinned KMS key ARN.

It intentionally contains no bucket name, bucket ARN, object key, AWS
endpoint, role ARN, access key, session token, or raw tenant/CAB identifier.
Store its canonical bytes and acknowledgement digest in the custody ledger.

An acknowledgement proves what this client independently reopened at that
time. It is not AWS-signed, is not proof that CloudTrail was delivered, and
does not prove that a replica completed.

`reverify_acknowledgement` accepts an externally known byte size and reopens
only the acknowledgement's exact `VersionId`. It reproduces and compares the
entire canonical acknowledgement after hashing the returned bytes. Streamed
CAB exact-set signing and audit use this path; see
[Signed custody for streamed evidence](stream-custody-operations.md).

## Ambiguous PUT recovery

A timeout can occur after S3 has committed the object but before the client
receives the response. The adapter handles this without an unconditional
second write:

1. `HeadObject` the current object at the exact content-addressed key;
2. obtain its version ID;
3. validate all custody metadata;
4. `GetObject` that exact version;
5. hash every returned byte; and
6. return an acknowledgement only if it is identical to the intended write.

The same reconciliation runs after a 409 or 412 response. A retry must reuse
the same:

- tenant ID;
- CAB ID;
- object digest;
- explicit retain-until instant;
- bucket and KMS pins; and
- encryption algorithm.

Do not recalculate a later retain-until date on retry. That is a different
operation, not an exact retry.

If no object can be reconciled, the result remains `ambiguous_put`. If the key
is occupied but any byte or metadata field differs, the result is `collision`.
Treat a collision as an integrity incident. Do not delete the object, change
the key, or accept the latest version merely to make the workflow continue.

## KMS rotation

Automatic rotation of the same customer-managed KMS key keeps the key ARN
stable and does not change the adapter pin. Replacing the key is a controlled
rollout:

1. create and policy the new customer-managed key;
2. deploy a new custody configuration pinned to its ARN;
3. record the new KMS ARN digest in configuration history;
4. write new objects through the new configuration;
5. retain decrypt access to the old key for every object and acknowledgement
   that still has to be verified; and
6. do not schedule deletion of the old key before all retention, audit, and
   recovery obligations expire.

Disabling or deleting a KMS key can make a correctly retained S3 object
unreadable. Object Lock protects the object version, not the availability of
its KMS key.

## Replication and regional recovery

S3 stores data redundantly across Availability Zones in a Region, but a
separate regional recovery requirement needs an explicit replication design.
S3 Replication can copy locked versions and their retention metadata. Both
source and destination buckets must have versioning and Object Lock enabled.
SSE-KMS and DSSE-KMS objects need explicit replication configuration and KMS
permissions. See:

- [Object Lock considerations](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html)
- [Replication requirements](https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-requirements.html)
- [Replicating KMS-encrypted objects](https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-config-for-kms-objects.html)

Replication is asynchronous. This adapter's acknowledgement covers the source
version only. Do not call the system regionally recoverable until a separate
monitor verifies the destination version, retention metadata, encryption key,
bytes, replication status, lag objective, and a restore drill.

## Monitoring and audit

Enable CloudTrail data events for the custody prefix and alert on:

- any `DeleteObject`, `DeleteObjectVersion`, `PutObjectRetention`,
  `PutObjectLegalHold`, or `BypassGovernanceRetention` attempt by the workload;
- `PutObject` without the expected KMS key, COMPLIANCE mode, retention range,
  checksum, or conditional header;
- changes to bucket versioning, Object Lock, bucket policy, replication, or
  default encryption;
- changes to the KMS key policy, disable state, deletion schedule, or grants;
- repeated `ambiguous_put` or any `collision`;
- acknowledgement failures during independent replay; and
- replication lag or failed replication when CRR/SRR is required.

Keep S3 request logging and SDK wire logging from recording object content or
authorization material. `S3ObjectLockError` intentionally replaces client
exception text with stable messages; the client and token provider must apply
the same discipline below this adapter.

## Verification status and residual boundary

The repository test suite uses a deterministic, thread-safe in-memory S3
client. It covers:

- exact PUT/HEAD/GET closure;
- SSE-KMS and DSSE-KMS pins;
- malicious response substitution;
- exact retry and content collision;
- timeout before and after server commit;
- retention and configuration drift;
- tenant/CAB scope substitution;
- immutable-byte receipt upload and exact-version re-verification;
- source symlink and hardlink rejection; and
- concurrent writers converging on one version.

It has **not** written to an operator-owned AWS account. No live AWS
interoperability or regulatory-compliance claim is made. A production
qualification still needs a staging Object Lock bucket, real IAM/SCP/bucket
and KMS policies, CloudTrail evidence, fault injection around an actual
`PutObject`, replication checks where required, cost/throughput testing, and a
documented recovery drill.
