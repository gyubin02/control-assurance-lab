# Runtime environment composition

The scheduler decides **which frozen control run is due**. The execution plan
decides **which exact vendor query, nonce, code revision, and retention
deadline belong to that run**. Neither one identifies the deployed
credentials, PAM broker, custody bucket, KMS key, or receipt-signing key.

`assurance_lab.runtime.environment` closes that gap without placing secrets in
the journal.

## What is bound

For each run, the provider reconstructs one canonical public document that
binds:

- the run, tenant, control, configuration, execution plan, and code revision;
- the complete secret-free Elastic or Defender runtime identity;
- the run-specific S3 Object Lock and Vault Transit runtime identity; and
- the exact custody deployment-profile digest.

The resulting media type is
`application/vnd.control-assurance.execution-environment-identity.v1+json`.
Its bytes and SHA-256 digest are stored by the execution journal before source
capture or evidence publication.

The nested identities expose authority boundaries, not credentials. They
contain content addresses, permission profiles, endpoint-origin digests,
version-pinned key facts, retention policy, bucket and KMS identities, and
public-key fingerprints. Parent credentials, bearer tokens, private keys,
assertions, CA file paths, and Vault tokens are never serialized.

## Deployment registry

The deployment bootstrap creates:

1. a `PinnedElasticSourceRuntimeProvider` or
   `PinnedDefenderSourceRuntimeProvider` for every deployed source;
2. an `ExactSourceRuntimeRegistry` keyed by the canonical source-configuration
   digest;
3. an `ExactCustodyRuntimeProfileRegistry` keyed by tenant, control,
   configuration digest, and exact custody/signing references; and
4. one `ExactExecutionEnvironmentProvider` from those two registries.

Source selection is content-addressed. A hostname, tenant id, or friendly name
is not sufficient to select a runtime. Duplicate source digests are rejected
at bootstrap, and a provider that returns a different digest than the one
under which it was registered is rejected at execution.

In production, each pinned provider receives a resolver backed by the
dedicated Elastic or Defender identity module. The resolver reads the same
exact-version Azure Key Vault reference and reconstructs the public identity
on every attempt. That makes an immutable-secret violation, certificate
expiry, CA change, or dependency substitution visible before the retry can
continue. A precomposed identity can be registered for a deliberately static
runtime, but it does not provide that repeated credential-boundary check.

Neither resolver acquires a short-lived Elastic API key or Entra access token.
Those actions remain inside the PAM broker at capture time.

## First attempt and retry

On the first attempt:

1. validate the request and reopen the frozen execution plan;
2. select the exact source runtime by source-configuration digest;
3. prepare the managed source without calling the vendor;
4. select the exact custody/signing runtime without writing custody;
5. build the composite execution identity; and
6. return both the handles and identity bytes to the durable executor.

On a retry, the executor supplies the previously journaled composite identity.
The provider parses it before composition, passes each nested identity to its
source and custody boundary, reconstructs the complete document, and requires
byte-for-byte equality. A credential-profile change, CA change, broker change,
Vault key rotation, custody policy rollout, registry substitution, source
configuration change, or cross-run replay therefore fails closed.

This comparison is deliberately byte-exact. Semantic similarity is not enough
for a run whose external request and retention decision have already been
frozen.

## Side-effect boundary

`ExactExecutionEnvironmentProvider.prepare` may perform the bounded credential
reads required to reconstruct a pinned runtime identity and may construct
local clients. It does not:

- acquire or revoke a PAM lease;
- request an Entra access token;
- query Elastic Security or Defender XDR;
- sign a receipt;
- upload, read, or reverify an Object Lock object; or
- extend a frozen retention deadline.

The first source-side effect remains `PreparedManagedSource.capture()`. Custody
and signing effects remain in managed evidence publication after the composite
identity has been durably journaled.

## Operator checks

Before enabling a configuration:

- register the exact canonical source configuration used by the deployed
  control;
- register a custody deployment profile whose configuration digest and
  retention range match that control;
- use an immutable image digest or full Git revision as
  `source_revision`; and
- ensure every HA worker receives the same registry snapshot and journal
  connection, while credential material remains available only through the
  dedicated identity resolvers.

After a source credential, CA bundle, KMS policy, Vault key, or retention
policy changes, create a new deployment registration. Do not silently replace
an entry needed by an in-flight run. Existing journaled runs must either
reconstruct their original public identity or stop for operator recovery.
