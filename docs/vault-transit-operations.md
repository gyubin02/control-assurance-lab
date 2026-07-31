# Vault Transit receipt signing

The executor binds the pinned origin, namespace, mount, key version and public
key to each frozen run as described in
[Custody and signing runtime identity](custody-runtime-identity.md).

This adapter moves the receipt-signing private key out of the admission
process. HashiCorp Vault Transit holds the key; Control Assurance sends bytes
to sign and keeps only a pinned Ed25519 public key.

That sentence is the useful part. The rest of this document describes the
boundary needed to make it true.

## What is pinned

`VaultTransitEd25519ReceiptSigner` performs one read when it starts:

```text
GET /v1/<mount>/keys/<key>
```

It accepts the key only when Vault reports all of the following:

- `type` is exactly `ed25519`;
- `derived` is `false`;
- `supports_signing` is `true`;
- `name` matches the configured key name;
- `latest_version` is a positive integer; and
- that version contains one canonical Ed25519 public-key representation.

Current Vault releases represent an Ed25519 key as standard RFC 4648 base64 of
the 32 raw public-key bytes (unlike the SPKI PEM used for ECDSA and RSA).
The adapter accepts that exact form. It also accepts a canonical base64 SPKI
DER value or one canonical SPKI PEM block for compatible/imported response
formats. Every form is decoded, re-serialized where applicable, loaded as
Ed25519, and exposed to the admission verifier as exactly 32 raw bytes. The
origin, public key, and key version do not change for the life of the signer.

Every signing call then sends:

```json
{"input":"<canonical RFC 4648 base64>","key_version":1}
```

to:

```text
POST /v1/<mount>/sign/<key>
```

The response must be `vault:v1:<canonical base64>`. The returned version must
match the startup pin, the decoded signature must be exactly 64 bytes, and the
signature must verify locally before it is returned. `verify()` is entirely
local and continues to work during a Vault outage.

Vault documents the read-key and sign-data contracts in the
[Transit HTTP API](https://developer.hashicorp.com/vault/api-docs/secret/transit).

## Vault setup

Use a dedicated mount and a non-derived Ed25519 key. Do not make the key
exportable and do not enable plaintext backup.

```sh
vault secrets enable -path=control-assurance-transit transit

vault write control-assurance-transit/keys/receipt \
  type=ed25519 \
  derived=false \
  exportable=false \
  allow_plaintext_backup=false
```

Give the workload only the two operations the adapter uses:

```hcl
path "control-assurance-transit/keys/receipt" {
  capabilities = ["read"]
}

path "control-assurance-transit/sign/receipt" {
  capabilities = ["update"]
}
```

It does not need key creation, rotation, export, backup, deletion, remote
verification, encryption, or decryption rights.

For Vault Enterprise or HCP Vault Dedicated, configure the exact namespace.
The adapter sends it as `X-Vault-Namespace`; HCP's top-level namespace is
normally `admin`. HashiCorp describes namespace routing in the
[Vault HTTP API](https://developer.hashicorp.com/vault/api-docs#namespaces).
The adapter also sends `X-Vault-Request: true`, which is required by Vault
Proxy when `require_request_header` is enabled.

## Endpoint and TLS

The endpoint is an exact origin, for example:

```text
https://vault.security.example:8200
```

It may not contain credentials, a path, query, fragment, non-canonical host
spelling, or an explicit default port. Redirects and environment proxy
settings are disabled. The adapter never discovers another Vault address.

Production endpoints must use HTTPS. Certificate-chain and hostname
verification are always enabled, and TLS versions below 1.2 are disabled. A
private CA bundle may be supplied as a single-link regular file; it is opened
without following symlinks, bounded to 8 MiB, checked for changes while being
read, and loaded from the captured bytes. Plain HTTP is available only when
all three conditions are true:

1. the host is a literal loopback address;
2. `allow_insecure_loopback=True`; and
3. the operator is running a local lab or conformance test.

For an HA Vault cluster, put a stable, certificate-authenticated load-balancer
origin in front of the active nodes. Redirect-based failover is intentionally
not accepted because it can forward the Vault token to an unpinned origin.

## Token provider

The signer never reads `VAULT_TOKEN`, performs a login, renews a lease, or
stores a token after a request. It receives a `VaultToken` from a
`VaultTokenProvider`.

The provider is the authentication boundary. In production it should:

- use workload identity such as Kubernetes auth, AppRole with wrapped
  SecretID delivery, or a local Vault Agent;
- return a narrowly scoped, short-lived token;
- derive `valid_until_monotonic` from the token lease with safety margin;
- honor the supplied monotonic deadline;
- be safe when called by concurrent worker threads; and
- keep login responses and token values out of its logs and exceptions.

`VaultToken.__str__` and `__repr__` are always redacted. The HTTP transport
also rejects a Vault response that reflects the raw, JSON slash-escaped, or
percent-encoded token. Provider and transport exceptions are replaced outside
their exception handlers so a secret-bearing exception is not chained into
the public failure.

The token validity horizon is a local fail-closed bound, not proof that Vault
has not revoked the token.

## Timeouts, concurrency, and retries

There are three independent bounds:

- `request_timeout_seconds` limits each socket operation;
- `initialization_timeout_seconds` bounds token acquisition plus key read; and
- `sign_timeout_seconds` bounds token acquisition plus one signing operation.

The production transport creates an isolated opener for each call. It has no
cookie jar, redirect state, proxy state, or mutable request body shared across
threads. Token-provider calls are serialized so a provider that rotates a
single local credential is not entered concurrently.

The adapter does not retry `POST /sign`. A timeout after the server receives a
request is ambiguous. Ed25519 signing of the same bytes with the same key is
deterministic, so an upper layer may repeat the same logical operation after
reconciliation, but it must not silently create a new receipt identity.

Do not hold a global database writer lock while waiting for a remote signer.
The admission layer should prepare and hash the exact receipt candidate,
perform the bounded remote signature, then use a compare-and-commit or
reservation protocol to ensure that the signed candidate is still current.
The Transit adapter's timeout does not make an oversized transaction safe.

## Rotation runbook

The signer deliberately does not follow `latest_version` after startup.
Rotation is therefore an operator-visible rollout:

1. rotate the Transit key under change control;
2. start a new signer instance;
3. record its `key_version`, `public_key_fingerprint`, and
   `endpoint_origin_digest`;
4. add the new public key and a new, unique `key_id` to the external trust
   policy;
5. admit traffic through the new instance;
6. retain the previous public key for the receipt-retention period; and
7. retire the old key only after its verification and retention obligations
   end.

An old process continues to request its pinned version. If Vault no longer
permits that version, signing fails. If a response claims a different version,
the adapter rejects it. Rotation never becomes an unnoticed key substitution.

## Audit and monitoring

Enable Vault audit devices before production use. Alert on:

- denied reads or signs for the workload identity;
- key rotation or configuration changes outside the change window;
- attempts to call export, backup, delete, or key-management paths;
- repeated signing timeouts;
- signer startup with a new public-key fingerprint; and
- a sustained increase in Transit latency.

The adapter itself does not emit tokens, request bodies, or response bodies to
logs. The receipt bytes sent as `input` can still contain business metadata;
Vault audit-device handling and downstream access controls must match that
classification.

## FIPS boundary

HashiCorp currently documents Ed25519 as not certified in Vault FIPS 140-3
mode. This adapter implements the repository's Ed25519-only
`ReceiptSigner` contract; it must not be described as a FIPS signing path. A
future algorithm-agile receipt profile and signer are required where a
validated FIPS algorithm/module is mandatory. See
[Transit key types](https://developer.hashicorp.com/vault/docs/secrets/transit#key-types).

## Operator-owned live smoke test

The unit suite uses fake transports plus a real loopback HTTP server. It proves
wire-level token placement, redirect refusal, reflection rejection, strict
response parsing, deadline behavior, version pinning, concurrency, and local
verification. It does **not** prove interoperability with an operator's Vault
cluster.

An opt-in smoke test is included in `tests/test_vault_transit.py`. Supply a
token through an owner-private file, not a command-line argument:

```sh
export CONTROL_ASSURANCE_VAULT_LIVE=1
export CONTROL_ASSURANCE_VAULT_ENDPOINT=https://vault.security.example:8200
export CONTROL_ASSURANCE_VAULT_NAMESPACE=admin
export CONTROL_ASSURANCE_VAULT_MOUNT=control-assurance-transit
export CONTROL_ASSURANCE_VAULT_KEY=receipt
export CONTROL_ASSURANCE_VAULT_KEY_ID=vault:prod:receipt:v1
export CONTROL_ASSURANCE_VAULT_TOKEN_FILE=/run/secrets/vault-token
export CONTROL_ASSURANCE_VAULT_CA_FILE=/etc/ssl/private/vault-ca.pem

pytest -q tests/test_vault_transit.py -k opt_in_live
```

The smoke-test file provider is intentionally minimal and is not a production
authentication implementation. Until that test is run against an
operator-owned cluster, the project must say “live-test available,” not
“live-tested with Vault.”
