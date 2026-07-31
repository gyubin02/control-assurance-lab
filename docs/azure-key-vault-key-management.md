# Azure Key Vault key-management boundary

This adapter exists to keep two long-lived private-key operations out of the
control-plane process:

- signing the Microsoft Entra PS256 client assertion used for Defender XDR;
- wrapping the short-lived AES key that encrypts an OIDC PKCE verifier.

It is intentionally smaller than a general Key Vault client. It accepts one
public-cloud vault, one key name, and one immutable 32-hex key version. It can
call only `sign`, `wrapkey`, and `unwrapkey`. There is no “latest” alias, secret
API, key creation, deletion, rotation, or permission-management API.

## What crosses the boundary

For Defender, the process hashes the JWS signing input and sends that SHA-256
digest to Key Vault with `PS256`. The RSA private key never leaves Key Vault.
The returned signature is not trusted on receipt: the adapter verifies it
locally against the exact X.509 certificate registered on the Entra
application. A Key Vault key substitution therefore fails before a client
assertion is used.

For OIDC, the process generates a fresh 256-bit AES key and 96-bit nonce. It
encrypts the PKCE verifier locally with AES-GCM and binds the ciphertext to the
authorization transaction digest as additional authenticated data. Key Vault
wraps only the ephemeral AES key with `RSA-OAEP-256`. The database stores:

- the authenticated ciphertext;
- the wrapped AES key;
- the nonce;
- the exact transaction digest;
- a digest of the pinned Key Vault key URI;
- the exact versioned key reference and algorithm profile.

The plaintext PKCE verifier is recovered only after the PostgreSQL state store
has atomically burned the one-time authorization transaction. A failed
decrypt cannot make the browser state reusable.

The ephemeral AES key necessarily exists briefly in process memory during
encrypt and decrypt. Python does not provide a reliable guarantee that every
copy is zeroized. This design protects the durable database and the
long-lived RSA private key; it is not a claim of confidential-computing or
memory-forensics resistance.

## Required Azure configuration

Create separate version-pinned RSA or RSA-HSM keys when operational ownership
or rotation cadence differs:

| Use | Minimum data-plane operations |
|---|---|
| Defender client assertion | `keys/sign` |
| OIDC PKCE envelope | `keys/wrapKey`, `keys/unwrapKey` |

The application identity should have no key create, import, rotate, backup,
restore, release, delete, purge, secret, or certificate-management permission.
Use a private endpoint and deny public network access where the deployment
supports it. Key Vault firewall, private DNS, RBAC assignment, HSM tier,
diagnostic logging, and Azure Policy are deployment controls; this Python
adapter cannot prove them by itself.

Authentication is supplied through `AzureKeyVaultTokenProvider`. The provider
must return a short-lived token for exactly:

```text
https://vault.azure.net/.default
```

The adapter has no client-secret constructor. A production deployment should
bind this protocol to managed identity or workload identity. The token is
opaque, never persisted, omitted from `repr`, and rejected if it has expired
before the operation starts.

## Network and response contract

The built-in transport:

- permits only `https://<vault>.vault.azure.net`;
- disables environment proxies;
- refuses redirects;
- requests `identity` content encoding;
- performs no automatic retry;
- accepts only bounded strict JSON;
- requires the returned `kid` to equal the complete configured key URI;
- never includes an upstream response body in an exception.

Not retrying is deliberate. A timeout after an HSM operation can make the
remote outcome unknowable. Defender assertions are disposable and get a new
JTI on the next broker attempt. OIDC envelope creation happens before the
database transaction, so a failed wrap leaves no durable authorization state.
Unwrap is safe to retry only as part of consuming an already-burned
transaction; it cannot resurrect that transaction.

## Rotation without an alias race

1. Create a new Key Vault key version.
2. For Defender, register the matching certificate on the Entra application.
3. Deploy configuration containing the new **versioned** key URI and
   certificate.
4. Run the live conformance checks and one synthetic Defender capture.
5. Move new OIDC transactions to the new version.
6. Keep the previous OIDC key version enabled for `unwrapKey` until every
   transaction encrypted under it has expired and its burn-retention window
   has elapsed.
7. Remove the old Entra certificate and old signing permission only after the
   maximum access-token and assertion exposure windows have closed.

Never configure `/keys/<name>` without a version. An alias can move between
local validation and the remote operation, defeating the certificate/key
binding and making old OIDC envelopes undecryptable.

## Failure interpretation

| Stage | Meaning | Safe operator action |
|---|---|---|
| `authentication` | no current Key Vault token | restore workload identity; do not add a static secret |
| `transport` | pinned vault could not be reached | check private DNS, endpoint and egress policy |
| `remote` | Key Vault rejected the exact operation | inspect Azure audit logs and RBAC outside the application |
| `response` | key ID, encoding, JSON, or result was unsafe | treat as integrity failure; do not retry blindly |
| `verification` | PS256 result did not match the registered certificate | stop Defender token issuance and reconcile key/certificate versions |
| `envelope` | OIDC binding or AES-GCM authentication failed | keep the transaction burned and require a new login |

## What has and has not been demonstrated

The repository tests use a real RSA implementation behind a fake Key Vault
transport. They exercise exact REST request bodies, PS256 pre-hash semantics,
local certificate verification, RSA-OAEP-256 wrapping, AES-GCM authentication,
concurrent signing, malformed responses, redirects, compression, key
substitution, token reflection, transport ambiguity, ciphertext modification,
and transaction substitution.

No live Azure tenant or HSM operation is claimed until the opt-in conformance
test is run against an operator-owned vault. The REST contracts and algorithm
choices follow Microsoft’s Key Vault documentation:

- [Sign operation](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/sign/sign)
- [Wrap key operation](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/wrap-key/wrap-key)
- [Unwrap key operation](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/unwrap-key/unwrap-key)
- [Supported key algorithms](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details)
- [Key Vault authentication](https://learn.microsoft.com/en-us/azure/key-vault/general/authentication-requests-and-responses)
