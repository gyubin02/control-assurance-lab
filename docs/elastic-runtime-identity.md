# Elastic runtime identity boundary

The Elastic runtime does not receive a password or bearer token from ordinary
configuration. Its production composition path accepts:

- one exact-version `azure-keyvault://.../secrets/.../<32-lowercase-hex>`
  parent-credential reference;
- an `AzureKeyVaultSecretClient` already authenticated by workload identity;
- the canonical
  `application/vnd.control-assurance.elastic-parent-credential.v1+json`
  secret profile;
- a shared PostgreSQL pool and an explicit, secret-free journal namespace
  digest;
- one prevalidated PEM trust-bundle path; and
- the approved Elastic endpoint, alert alias, child-key TTL, and JIT PAM mode.

`prepare_elastic_runtime_identity` resolves the secret once, decodes it
directly into an opaque `ElasticParentCredential`, constructs
`PostgresElasticLeaseJournal` and `ElasticJitApiKeyBroker`, and emits canonical
public identity bytes. Those bytes include the exact endpoint digest, alert
alias, TTL, least-privilege role descriptor and digest, parent-reference
digests, CA-bundle digest, journal namespace, connector and broker identities,
and request timeout. They do not contain the parent secret, Key Vault URI, or
local CA path.

`prepare_elastic_managed_source_from_identity` reopens the frozen execution
configuration, requires its complete Elastic source model to have the same
digest, rechecks the CA bytes, and only then calls
`prepare_elastic_managed_source`. A different endpoint, alias, TTL, PAM mode,
parent reference, CA reference, or CA file fails before Elastic is contacted.

## CA bootstrap boundary

The existing Elastic PAM and capture clients accept TLS trust as a
`pathlib.Path`. They do not accept an already-built `SSLContext` or an
in-memory, digest-addressed CA bundle. The runtime therefore cannot honestly
prove, by itself, that a file was materialized from the configured Key Vault
CA reference.

The implemented boundary does not weaken TLS or silently fall back to ambient
system trust. `PrevalidatedElasticCATrust` requires:

- an absolute path with no symlink traversal;
- an operator-controlled, non-writable parent directory;
- a regular, single-link file owned by the runtime uid;
- no group or other file permissions;
- a bounded, stable read;
- a PEM bundle accepted by an enforcing TLS client context; and
- the same SHA-256 content digest at identity creation, managed-source
  preparation, and child-connector construction.

The deployment bootstrap still has one explicit responsibility: retrieve the
exact CA secret version, write it atomically to that owner-only path, and
provide the path together with the same configured reference. Production
packaging should run that materializer in a separate init container or
privileged bootstrap unit, publish by same-filesystem `rename(2)`, and remove
write permission before the runtime starts. Until a first-class
secret-to-`SSLContext` interface exists, this provenance step remains an
operator boundary and is not represented as cryptographic Key Vault
attestation.

## Rotation

Parent credentials and CA bundles rotate by configuration revision:

1. create a new Key Vault secret version;
2. submit the new exact reference through maker-checker approval;
3. materialize and validate the new CA path when applicable;
4. construct a new public runtime identity and compare its exact bytes during
   deployment;
5. stop assigning work to the old identity; and
6. run JIT-lease recovery for the old journal namespace before retiring it.

Never overwrite a referenced secret version or replace the CA file underneath
a running identity. Both operations are treated as drift.
