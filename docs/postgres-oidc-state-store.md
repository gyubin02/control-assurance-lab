# PostgreSQL OIDC state boundary

The OIDC state store uses `control_assurance_auth`, not the tenant-scoped
`control_assurance` tables.

That separation is intentional. At the authorization callback there is no
trusted tenant yet. Likewise, an opaque session cookie must be resolved before
the application can learn which tenant it belongs to. Disabling or weakening
row-level security on the control-plane tables to accommodate either lookup
would turn an authentication concern into a tenant-isolation exception.

## Database roles

Production uses separate control and authentication DSNs and separate
connection pools. Both connect to one database bound to exactly one deployment
tenant, but their login roles and privileges are disjoint. The auth pool login
has only `USAGE` on `control_assurance_auth` and `EXECUTE` on these eight
public entry points:

```sql
control_assurance_auth.runtime_identity()
control_assurance_auth.reserve_login_admission(...)
control_assurance_auth.finalize_login_admission(...)
control_assurance_auth.cancel_login_admission(text)
control_assurance_auth.consume_ready_authorization_transaction(...)
control_assurance_auth.create_browser_session(...)
control_assurance_auth.read_browser_session(text, timestamptz)
control_assurance_auth.revoke_browser_session(text)
```

It has no privilege on auth base tables, `control_assurance`, or
`control_assurance_boundary`; it cannot read either migration table directly.
The control role has no auth-schema privilege. Authentication startup learns
its independent append-only lineage through the security-definer identity
entry point and requires exactly `[2, 5, 6]`. The migration-5 implementations
are private `_v5` routines with no runtime `EXECUTE`; migration 6 exposes
tenant-bound wrappers under the original public signatures.

Do not install these grants by hand. A dedicated migration login must own the
database and every object in `control_assurance`, `control_assurance_auth`, and
`control_assurance_boundary`. After applying
`deploy/postgres/control-plane-schema.sql`, that exact login calls:

```sql
SELECT control_assurance_boundary.configure_runtime_roles(
  'acme-bank',
  'assurance_control_runtime'::name,
  'assurance_auth_runtime'::name,
  'assurance_reconciler_runtime'::name
);
```

The function rejects a second tenant and rejects roles with inheritance,
memberships, role settings, ownership, elevated role attributes, role-specific
or public parameter `SET` ACLs, database `CREATE`/`TEMPORARY`, or any schema
`CREATE`.
It revokes public database temporary-object creation and installs the exact
grants. Applying the schema again removes runtime grants by design, so run
`configure_runtime_roles` again after every schema application.

Tenant identity is derived from immutable `session_user` binding, not a
caller-controlled GUC. `SET ROLE`, a spoofed
`control_assurance.tenant_id`, a tenant from another deployment, or a DSN whose
login does not exactly match the configured auth role fails closed.

## Login admission, browser handles, and PKCE

Raw transaction cookies, `state` values, nonces, and session cookies are not
database fields. The coordinator hashes them before calling the store.

`GET /auth/login` is public, so PKCE protection cannot itself be the admission
gate. Each request follows this order:

1. Derive a keyed `hmac-sha256:` digest for the source.
2. Atomically reserve one PostgreSQL admission slot after checking both the
   global active limit and the source active limit.
3. Call the KMS/Vault-backed `CodeVerifierProtector` outside a database
   transaction.
4. Atomically replace the reservation with a `ready` slot and its encrypted
   authorization transaction.
5. Return the browser redirect and transaction cookie only after step 4.

A protector failure cancels its reservation. A process crash leaves only a
short reservation, which expires without becoming callback-visible. A slow
protector that outlives the reservation cannot finalize it. Ready
transactions continue to consume the same admission slot until callback
consumption or transaction expiry, so a fast protector cannot evade the
active limit.

The callback routine joins the transaction to an admission whose phase is
exactly `ready`. It can never consume a bare reservation. For a ready
transaction it:

1. Atomically deletes the authorization transaction and its active slot.
2. Appends the one-time burn marker and commits.
3. Compares callback state and time.
4. Decrypts only for a valid callback, after the database transaction is over.

A KMS outage after callback consumption fails the login and the transaction
remains burned.
The user starts a new login. The system never reopens a one-time callback to
improve availability.

The database role has no KMS permission. The application workload identity has
decrypt permission only for the dedicated OIDC PKCE key and required
encryption context. Key material must not be placed in configuration revisions
or PostgreSQL.

### Source identity and trusted proxies

The digest is an HMAC derived with domain separation from the protected
control-plane CSRF key. PostgreSQL never receives a raw address.

With `oidc.login_admission.trusted_proxy_cidrs: []`, the direct ASGI socket peer
is authoritative and every `X-Forwarded-For` value is ignored. To use a reverse
proxy, list its canonical CIDR explicitly. A matching trusted peer must
**replace** the header with exactly one `X-Forwarded-For` field containing
exactly one IP address. Duplicate fields, comma-separated chains, a missing
field, or malformed input fail closed. A forwarding header from a peer outside
the configured CIDRs is ignored.

This is deliberately a single-hop overwrite contract. Do not configure a
load balancer that appends an untrusted client-supplied chain.

### Response contract

An exhausted global or source admission quota returns a generic HTTP `429`
with `Retry-After`. Database, source-contract, protector, or finalization
failures return a generic HTTP `503`. Neither response identifies which quota,
source, database routine, or KMS operation failed.

## HA and cleanup

All reserve decisions take one fixed transaction-scoped advisory lock. The
count and insertion are therefore one serial decision across replicas.
Finalization, cancellation, one-time consumption, and exact session revocation
use digest-scoped transaction advisory locks inside `SECURITY DEFINER`
routines.

Expired admission and burn cleanup uses bounded batches with
`FOR UPDATE SKIP LOCKED`. Active admission rows cannot exceed the configured
global limit. The replay ledger has a separate configured `burn_capacity`; if
it fills before records expire, login/consume fails closed instead of adding
unbounded durable state.

These active-state limits are not a request-rate control. The public ingress
must separately rate-limit `/auth/login` by a deployment-appropriate,
spoof-resistant client signal and bound concurrent upstream connections.
Ingress limiting reduces HTTP/worker/DB pressure; PostgreSQL admission remains
mandatory because edge instances and application replicas do not share local
counters.

The opt-in live test is enabled with:

```bash
CONTROL_ASSURANCE_POSTGRES_MIGRATION_DSN='postgresql://migration-owner@…/db' \
CONTROL_ASSURANCE_POSTGRES_CONTROL_DSN='postgresql://control-role@…/db' \
CONTROL_ASSURANCE_POSTGRES_AUTH_DSN='postgresql://auth-role@…/db' \
CONTROL_ASSURANCE_POSTGRES_RECONCILER_DSN='postgresql://reconciler-role@…/db' \
CONTROL_ASSURANCE_POSTGRES_TENANT='acme-bank' \
CONTROL_ASSURANCE_POSTGRES_CONTROL_ROLE='assurance_control_runtime' \
CONTROL_ASSURANCE_POSTGRES_AUTH_ROLE='assurance_auth_runtime' \
CONTROL_ASSURANCE_POSTGRES_RECONCILER_ROLE='assurance_reconciler_runtime' \
  pytest -q tests/integration/test_postgres_oidc_store_live.py
```

The test database must be disposable: the live suite drops and recreates the
three managed schemas for isolation. It covers two independent auth pools
racing one global slot, verifies that only the winner invokes protection,
proves reservations are not consumable, checks cancellation and expiry, and
retains the one-time consume/session coverage. The separate tenant/role attack
suite also requires the admin DSN and migration-role name:

```bash
CONTROL_ASSURANCE_POSTGRES_ADMIN_DSN='postgresql://cluster-admin@…/db' \
CONTROL_ASSURANCE_POSTGRES_MIGRATION_ROLE='assurance_migration_owner' \
  pytest -q tests/integration/test_postgres_tenant_role_boundary_live.py
```

Neither test simulates a database-cluster promotion or network partition.

## Residual trust

The boundary assumes the PostgreSQL host and cluster administrator are trusted,
the migration/database owner is protected and absent from runtime pods, DSNs
are routed to the intended database, and `verify-full` CA material is delivered
through the pinned release path. A database owner or cluster administrator can
change bindings, ownership, RLS, routines, or ACLs and therefore remains inside
the trusted computing base.

Startup and readiness recheck exact login identity, tenant binding, owner,
lineage, role posture, and raw schema/table/column/function ACLs. Operational
controls must prevent membership, role-attribute, ownership, or grant changes
between checks; the application cannot make a malicious database
administrator safe.
