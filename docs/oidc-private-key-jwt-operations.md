# OIDC without an application secret

The control plane uses the authorization-code flow with server-side state,
PKCE S256, nonce validation, and an HTTP-only session cookie. The browser
never receives the PKCE verifier, ID token, access token, or client
credential.

This document covers the remaining server-to-server boundary: redeeming the
authorization code and obtaining the signing keys used to verify the ID
token.

## Deployment profile

`PinnedOIDCHTTPClient` is created from one immutable `OIDCConfiguration`.
That configuration fixes:

- issuer;
- authorization endpoint;
- token endpoint;
- JWKS URI;
- client ID;
- redirect URI;
- requested scopes; and
- group-to-tenant role mappings.

The default scopes are `openid profile`. `groups` is deliberately absent:
Microsoft Entra emits group membership as a configured token claim, not as an
OAuth scope. The app registration must be configured to place the exact group
identifiers used by the entitlement map in the ID token. If Entra emits a
group-overage indication instead of the `groups` array, login is denied. This
adapter does not turn the discarded access token into an unreviewed Microsoft
Graph lookup.

Endpoints are credential-free HTTPS URLs. Redirects, URL user information,
environment proxies, compressed responses, and automatic retries are not
part of this profile.

The token endpoint authenticates the control plane with
`private_key_jwt`. There is no client-secret argument or environment-variable
fallback. `CertificatePrivateKeyJWT` builds a five-minute PS256 assertion and
asks an injected `PS256AssertionSigner` to sign it. In production that signer
can be `AzureKeyVaultPS256Signer`, pinned to one immutable Key Vault key
version.

The assertion contains:

| Field | Binding |
| --- | --- |
| `iss`, `sub` | exact OIDC client ID |
| `aud` | exact token endpoint URL |
| `iat`, `nbf`, `exp` | current time and a five-minute lifetime |
| `jti` | fresh canonical UUID |
| `x5t#S256` | SHA-256 thumbprint of the registered DER certificate |

The returned RSA-PSS signature is verified locally with the registered
certificate before the assertion is sent. A Key Vault response signed by a
different key version therefore fails at the application boundary even if
the remote request itself succeeded.

Microsoft Entra documents certificate assertions and the use of
`client_assertion` in an authorization-code exchange:

- <https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials>
- <https://www.rfc-editor.org/rfc/rfc7523>

## One-shot code redemption

The exact form sent to the token endpoint is:

```text
client_id
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
client_assertion
code
code_verifier
grant_type=authorization_code
redirect_uri
```

`client_secret`, `refresh_token`, and `offline_access` are absent.

Authorization codes are single-use. If the HTTP request fails after it may
have left the process, the outcome is marked ambiguous and the request is not
retried. The browser must start a new login transaction. This trades a small
availability cost for a clear replay boundary.

On success the transport applies the OAuth 2.0 success-response rules from
RFC 6749 section 5.1 under local resource bounds:

- `access_token`, `token_type`, and the OIDC `id_token` are required;
- `Bearer` is compared case-insensitively;
- `expires_in` and `scope` are optional and, when present, bounded and
  syntax-checked;
- a standards-permitted `refresh_token` is bounded, syntax-checked, and
  immediately discarded because this component has no refresh flow; and
- bounded extension members are ignored, as RFC 6749 requires.

The access token and any refresh token are never returned to the control
plane, written to the database, logged, or used for a user-info call. Python
strings cannot be reliably zeroized, so the meaningful guarantee here is
minimal lifetime and no persistence—not a claim of in-memory erasure. The ID
token is the only token that leaves the HTTP adapter.

At the injectable HTTP boundary, duplicate singleton headers, simultaneous
`Content-Length` and `Transfer-Encoding`, a body whose observable length does
not match `Content-Length`, and unsupported transfer codings are rejected.
An exact `Transfer-Encoding: chunked` response remains interoperable after the
transport has decoded its framing.

The OIDC core then verifies the ID-token signature, issuer, audience,
authorized party, nonce, issue and authentication times, MFA evidence, and
entitlements before it creates a local session.

## JWKS custody and rotation

The JWKS request goes to the exact configured URI over the same hardened HTTP
transport. Only a bounded strict JWK Set with at least one key is admitted.
The full per-key algorithm and key-shape checks still happen in the ID-token
verifier.

Valid JWKS bytes are cached in process for 60 seconds by default. The cache:

- admits one in-flight retrieval at a time while keeping network I/O outside
  the state mutex;
- lets concurrent callers join that retrieval using deadlines measured from
  each caller's own `fetch()` entry;
- never serves an entry after its local monotonic expiry;
- never serves stale data when refresh fails; and
- can be disabled by setting the TTL to zero.

When a verified token header names a `kid` absent from the cached set, the
coordinator sends both that `kid` and the digest of the key-set generation it
observed. Concurrent misses from the same generation join one forced JWKS GET;
if another caller already installed a newer generation, late callers use that
generation without another GET. The coordinator then verifies once more.

The GET is not retried, a failed refresh invalidates the old set instead of
falling back to it, duplicate matching keys are malformed rather than a
rotation signal, and signature failure under a known `kid` never triggers a
network refresh. A failed retrieval also creates a short fail-fast bound, so
an identity-provider outage does not become a request loop.

An unchanged generation receives a five-second refresh-rate bound by default.
Missing `(generation, kid)` results are kept in a bounded 128-entry negative
cache, and generation bounds are capped at 16 entries.
`jwks_negative_cache_seconds` is configurable from one to 30 seconds. This
limits arbitrary-`kid` traffic at the cost of denying a newly published key
for at most that short interval after a negative refresh. It admits normal
signing-key publication without turning attacker-chosen token headers into an
unbounded identity-provider workload.

Removing an existing compromised key still has the configured cache window:
tokens naming that known key do not force a refresh. Shorten the TTL during a
planned emergency removal instead of weakening signature verification.

## MFA claim contract and the Entra live gate

The default `MFAPolicy` requires the literal `mfa` value in the ID token's
`amr` array. That is a fail-closed, provider-neutral default; it is **not** a
claim that every Entra v2 tenant emits that shape. `acr` and `amr` behavior can
depend on tenant policy, token version, authentication method, and optional
claim configuration.

Before production login is enabled, the deployment owner must:

1. enforce the intended Microsoft Entra Conditional Access policy;
2. capture a real ID token from that tenant through this exact authorization
   flow without logging the raw token;
3. record the bounded `acr`/`amr`, `auth_time`, and `groups` shapes as a
   conformance result;
4. configure `accepted_acr` and `required_amr` to that reviewed contract; and
5. prove that a session not satisfying the policy is denied.

Setting `required=False` is not an MFA bypass label: sessions only receive
`mfa=True` when at least one evidence condition is configured and all such
conditions match. An empty optional policy therefore remains non-MFA and
cannot silently satisfy mutation routes that require MFA.

Relevant provider references:

- <https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference>
- <https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims>
- <https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles>

## Network controls outside the process

The adapter enforces the application protocol, not the surrounding network.
Production deployment still needs:

1. egress allow-listing for the exact identity-provider origins;
2. trusted DNS and TLS interception policy;
3. an explicit CA bundle when enterprise trust differs from the host store;
4. workload identity and Key Vault RBAC scoped to `sign` on the pinned key;
5. private endpoints or equivalent egress controls where policy requires
   them; and
6. identity-provider logs joined to the control-plane audit stream.

Do not add a forward proxy through `HTTPS_PROXY`. The implementation ignores
environment proxy settings deliberately. If an enterprise proxy is mandatory,
provide a reviewed transport implementation that preserves the exact endpoint,
TLS, redirect, decompression, size, and no-retry invariants.

## Failure semantics

Application errors expose a stable stage, never an authorization code, PKCE
verifier, client assertion, access token, ID token, response body, or nested
transport exception.

| Stage family | Operator meaning |
| --- | --- |
| `assertion-*` | certificate, clock, UUID source, KMS signing, or local signature verification failed |
| `token-request-profile` | the caller attempted to change an immutable token binding |
| `token-transport-ambiguous` | the code may have reached the token endpoint; do not retry |
| `token-response*` | status, framing headers, media type, encoding, required OAuth fields, syntax bounds, or reflection check failed |
| `jwks-request-profile` | issuer or JWKS URI did not match the deployment profile |
| `jwks-transport` / `jwks-response` | the fresh key set could not be obtained or admitted |

Repeated failures should be investigated with identity-provider request logs
and network telemetry. Do not log the form body or raw token response to make
diagnosis easier.

## What the repository proves

The automated suite covers:

- exact assertion claims, certificate thumbprint, PS256 padding, and local
  verification;
- exact form and endpoint bindings with no client secret;
- redirect, compression, ambiguous HTTP framing, duplicate singleton header,
  content-type, malformed scope/token, and malformed-JSON rejection;
- RFC 6749-compatible optional expiry/scope, case-insensitive bearer type,
  bounded refresh-token discard, and extension-member handling;
- code, PKCE verifier, and assertion reflection rejection;
- no retry and no nested-error disclosure after an ambiguous POST failure;
- exact bounded JWKS retrieval;
- 50 concurrent misses for one generation and `kid` joining one forced GET;
- bounded repeated arbitrary-`kid` misses, bounded negative-cache memory, and
  caller-relative waiter deadlines;
- network retrieval outside the cache state mutex and no stale fallback after
  a failed refresh; and
- one refresh path for an unknown `kid`, with no refresh for duplicate keys or
  bad signatures under a known key.

Those tests prove the local protocol behavior. They do not prove that a
particular Entra tenant, certificate registration, Key Vault, private
endpoint, CA chain, group assignment, or conditional-access policy is
configured correctly. That claim requires an opt-in live conformance run in
the deployment tenant.
