# Runtime catalog and scheduling

The control plane says what an authorized person wants deployed. The runtime
catalog says what a worker actually accepted. Those are deliberately separate
facts.

`PostgresRuntimeCatalog` is the first concrete deployment target. It receives
the exact `DeploymentApplyRequest` already emitted by the deployment
reconciler, validates the canonical `ControlConfiguration` again, and writes
two records in one PostgreSQL transaction:

- an immutable deployment-history row and content-addressed receipt;
- the current applied runtime pointer for that tenant and control.

The desired pointer in `control_assurance.active_deployments` is not read or
rewritten by this component. A pending or failed deployment therefore cannot
masquerade as runtime state.

## Profiles are content, not labels

A `ControlConfiguration` names a profile id and digest, but that pair alone is
not enough to execute a control. Before deployment, an authorized registrar
must append the exact RFC 8785 JSON bytes to `control_profiles`.

`register_control_profile()` independently checks the canonical JSON and its
SHA-256 digest. Registration is content-idempotent: the same tenant, id,
digest, media type, and bytes reopen the original audit row. An attempt to
reuse the digest under another id is rejected. Rows cannot be updated or
deleted.

Deployment then resolves the profile by the exact tenant, id, and digest. A
missing or malformed profile stops the deployment before it can become
current. Foreign keys carry that binding into immutable deployment history and
every materialized run. Immediately before execution, the scheduler reopens
and validates the profile bytes again.

Profiles are control logic, not a credential store. They may contain
secret-manager references but must never contain tokens, passwords, private
keys, session material, or connector response bodies. Registry write access is
therefore a separate workload privilege, not a convenience granted to every
scheduler.

## Deployment idempotency and fencing

`operation_id` is the target-side idempotency key. A retry with the same
operation id must name the same tenant, control, revision, operation sequence,
configuration digest, and canonical configuration bytes. Any difference is an
identity collision and is terminal.

Each operation has a separate monotonically increasing fence:

1. The first successful call stores `lease_fence_at_commit`.
2. A retry after a lost acknowledgement may present a higher fence.
3. The catalog verifies the already stored receipt, advances only the fence
   ledger, and returns the same receipt digest.
4. A lower fence is rejected.
5. An operation sequence older than the current deployed control can never
   become current again.

Database exceptions that could include a failed COMMIT are reported as
`DeploymentOutcomeUnknown`. The adapter never turns an ambiguous commit into a
success response. The deployment reconciler eventually calls the same
operation id again and observes the durable row if the first transaction did
commit.

The deployment receipt includes the prior operation id and prior receipt
digest. Its SHA-256 digest is both the target acknowledgement and a
content-addressed link in the per-control deployment chain. PostgreSQL checks
the raw configuration and receipt hashes independently and compares the JSON
identity fields with their relational columns.

## Which windows become runs

Schedules use UTC Unix-epoch boundaries. For a deployment applied at `A`, with
interval `I`, window width `W`, and collection lag `L`, a candidate window is:

```text
[E - W, E)       due at E + L
```

where `E` is an exact multiple of `I` seconds from the Unix epoch.

A window is materialized only when all of the following are true:

- the deployed configuration is enabled;
- `E - W >= A`;
- its due time is not later than the materialization horizon;
- if another deployment superseded it at `S`, then `E <= S`.

The entire half-open window therefore belongs to one deployment. A window that
crosses a configuration change is omitted instead of being silently assigned
to either version. A disabled configuration is still a valid deployed state,
but it produces no runs.

`run_id` is the SHA-256 digest of the canonical run request. The request binds
the tenant, control, deployment operation and receipt, revision,
configuration and control-profile digests, half-open window, and due time.
Re-running materialization is safe: PostgreSQL's primary key and exact-window
uniqueness make it append-only and idempotent. A future horizon is rejected;
operators may backfill up to a known database time but cannot pre-create work
that a later deployment might invalidate.

## HA claims and crash recovery

Workers claim due work with `FOR UPDATE SKIP LOCKED`. The transaction:

1. selects one eligible run;
2. increments its attempt count and lease fence;
3. records a digest of the lease token, never the token;
4. appends an immutable claim-ledger row.

Other workers either claim different runs or receive no work. They do not wait
behind the selected row. If a process dies, the lease expires and another
worker claims the same stable run id with a higher fence. The abandoned claim
remains visible and has no outcome row, which is useful evidence rather than
garbage to erase.

Retry delay is bounded exponential backoff in `RuntimeScheduler`. Executor
errors reach durable state only as canonical category digests; exception text,
URLs, headers, and credentials are never persisted. The scheduler and store
must use the same attempt limit. At the limit, a failure is terminal. An
expired final lease is also closed as a terminal, secret-free failure rather
than remaining forever in a misleading `leased` state.

PostgreSQL triggers enforce legal state transitions and exact fence increments
even if application code sends a malformed update.

## What a successful run proves

The scheduler does not treat an executor's `"ok"` string as success. The
executor returns:

- the exact run id and current fence;
- a digest for the immutable evidence object;
- a digest for the executor/custody receipt.

The catalog builds a canonical `ControlRunClosure` that joins those values to
the deployment receipt, configuration digest, profile digest, and collection
window. It stores the closure bytes and digest in an immutable outcome ledger
before changing the run to `succeeded`. PostgreSQL recomputes the closure hash
and compares its JSON fields with the current leased run.

`run_closure()` reopens and verifies the canonical bytes. This closure proves
which digests were accepted for which run; independent evidence admission and
custody verification remain separate checks.

## Executor integration seam

`ControlRunExecutor.ensure_executed()` is intentionally the only vendor-facing
runtime boundary. Its request contains the exact canonical configuration,
control profile, and original run-request bytes. The executor can therefore
recompute `run_id` itself instead of trusting an opaque caller-supplied label.
An implementation must:

- verify and use `request.run_id` as its logical idempotency key;
- reject lower stale fences;
- obtain short-lived access through the configured PAM boundary;
- call the connector for exactly `[window_start, window_end)`;
- write, sign, admit, and retain evidence through the configured custody
  boundary;
- after an ambiguous retry, return the same evidence and receipt digests.

`ProductionRuntimeWorkerFactory` now supplies that composition. For each pinned
source it builds either the Elastic Security JIT API-key path or the Defender
XDR workload-identity path, backed by the tenant-bound PostgreSQL PAM journal.
It then joins the connector to the managed-evidence writer, durable execution
journal, S3 Object Lock stream custody, and Vault Transit receipt signer behind
`DurableControlRunExecutor`. The catalog and scheduler do not import vendor
clients or resolve secret references themselves.

This is an implemented bootstrap path, not evidence that an operator-owned
Elastic or Defender tenant, Azure Key Vault, Vault cluster, S3 bucket, KMS key,
or PostgreSQL HA service has been provisioned correctly. Startup preflight and
the opt-in connector conformance tests establish narrower contracts; the live
deployment still owns endpoint policy, identity grants, retention, recovery,
and external audit.

## PostgreSQL installation and privileges

Apply [`deploy/postgres/runtime-schema.sql`](../deploy/postgres/runtime-schema.sql)
with a migration owner. Application roles must not own the schema or tables.
The migration:

- revokes all access from `PUBLIC`;
- forces row-level security on every tenant table;
- derives the one admitted tenant from PostgreSQL `session_user`, not from a
  caller-set session variable;
- makes deployment history, claim rows, and outcome rows immutable;
- checks raw SHA-256 digests and JSON-to-column identity at the database
  boundary.

Use a different LOGIN credential for every tenant and capability. Do not put a
workload role in a group role: role membership would reintroduce a `SET ROLE`
path, so startup rejects both sides of every membership. A credential admitted
to this store must have no entitlement or object privilege in the execution or
PAM stores.

Create the roles, then authenticate directly as the database, schema, and
function migration owner and call the owner-only provisioning function. It
removes stale grants in this schema, writes the insert-once entitlement, and
installs the exact privilege matrix:

```sql
CREATE ROLE assurance_bank_prod_worker
  LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
  NOINHERIT NOREPLICATION;
CREATE ROLE assurance_bank_prod_registrar
  LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
  NOINHERIT NOREPLICATION;
CREATE ROLE assurance_bank_prod_reconciler
  LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
  NOINHERIT NOREPLICATION;

SELECT control_assurance_runtime.configure_login_role(
  'bank-prod', 'assurance_bank_prod_worker', 'worker'
);
SELECT control_assurance_runtime.configure_login_role(
  'bank-prod', 'assurance_bank_prod_registrar', 'registrar'
);
SELECT control_assurance_runtime.configure_login_role(
  'bank-prod', 'assurance_bank_prod_reconciler', 'reconciler'
);
```

These are exact privilege sets, not a starting point for broader grants. The
provisioning call itself fails for a superuser, a `BYPASSRLS` role, either side
of role membership, a role with per-role settings, object ownership, database
temporary/create permission, schema create permission, direct column grants,
or any execution/PAM-store entitlement or ACL. It refuses to remap an existing
credential to another tenant or capability.

Startup calls `assert_session_principal` and refuses a mismatched role or
tenant, a missing or additional table/routine privilege, `SUPERUSER`,
`BYPASSRLS`, database temporary/create permission, schema creation, direct
column grants, role settings or membership, object ownership, `PUBLIC` access,
or cross-store reuse. The owner-only entitlement table is never granted to the
application. Changing a credential to another tenant therefore requires an
explicit migration-owner operation and a new deployment review.

Run both the runtime behavior test and the adversarial identity-boundary test
against disposable PostgreSQL 17 databases:

```bash
CONTROL_ASSURANCE_POSTGRES_RUNTIME_MIGRATION_DSN='postgresql://migration@...' \
CONTROL_ASSURANCE_POSTGRES_RUNTIME_REGISTRAR_DSN='postgresql://registrar@...' \
CONTROL_ASSURANCE_POSTGRES_RUNTIME_RECONCILER_DSN='postgresql://reconciler@...' \
CONTROL_ASSURANCE_POSTGRES_RUNTIME_WORKER_DSN='postgresql://worker@...' \
CONTROL_ASSURANCE_POSTGRES_RUNTIME_TENANT='bank-prod' \
  pytest -q tests/integration/test_postgres_runtime_live.py

CONTROL_ASSURANCE_POSTGRES_BOUNDARY_ADMIN_DSN='postgresql://...' \
  pytest -q \
    tests/integration/test_postgres_runtime_tenant_boundary_live.py
```

The first test covers idempotency, fences, HA claims, crash reclaim, and exact
closure. The second creates real LOGIN credentials for two tenants and proves
that GUC spoofing, cross-tenant writes, both directions of role membership,
object ownership, `SUPERUSER`, `BYPASSRLS`, role settings, cross-store reuse,
owner-table access, and excess table/column/view/sequence/routine grants fail
closed. Neither is a PostgreSQL promotion or network-partition test; those
belong in the deployment environment's HA/DR exercise.
