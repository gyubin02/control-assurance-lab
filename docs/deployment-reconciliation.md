# Deployment reconciliation

Selecting an approved revision and applying it to a runtime are different
facts. The control plane stores both, and does not collapse the first into the
second.

`active_deployments` is the desired-selection pointer retained by the existing
control-plane API. In the same database transaction, activation appends a
`deployment_operations` row. That row is initially `pending`. Only a fenced
worker lease followed by an exact target acknowledgement can move it to
`applied`.

An operator can therefore answer two separate questions:

1. Which revision did an authorized deployer select?
2. Which exact configuration digest did a runtime acknowledge?

The second answer comes from the latest applied deployment operation, not from
the selection pointer.

## State machine

| State | Meaning | Next state |
| --- | --- | --- |
| `pending` | Durable intent exists; no worker owns it. | `leased` |
| `leased` | One tenant-scoped worker owns an expiring lease and fence. | `applied`, `failed`, or `leased` after expiry |
| `failed` with `retry_at` | A secret-free failure digest was recorded; retry is delayed. | `leased` at or after `retry_at` |
| `failed` without `retry_at` | Terminal failure; operator action is required. | none |
| `applied` | The target acknowledged the exact requested configuration digest and returned a receipt digest. | none |

Request fields never change. State changes use compare-and-swap versions.
PostgreSQL triggers independently enforce request immutability, contiguous
operation sequence, maker-checker separation, legal transitions, exact
configuration acknowledgement, and monotonically increasing fences. SQLite
provides the same state model for single-node exercises.

There can be only one unresolved operation per tenant and control. This avoids
silently skipping an intermediate desired state when a later change is
approved faster than a runtime can apply the first.

## Fencing and ambiguous outcomes

Every lease increments both `attempt_count` and `lease_fence`. A worker must
present all of the following to close a lease:

- tenant-scoped workload identity;
- operation id;
- lease owner;
- lease token digest;
- current fence;
- a time before lease expiry.

The target adapter receives the operation id as its stable idempotency key and
the fence as its ordering token. It must reject stale lower fences. Calling it
again for the same operation must observe or finish that logical application,
not create another one.

This is important when the target commits but the worker loses its database
connection before recording the acknowledgement:

1. The first lease eventually expires.
2. Another worker claims the same operation with a higher fence.
3. The adapter queries or idempotently reapplies the same operation id.
4. The target returns the observed configuration and receipt digests.
5. The new worker closes its current lease.

No code can make an arbitrary external API transactional with PostgreSQL. The
operation id, target-side idempotency, and fencing contract are the explicit
recovery boundary.

## Retries and failures

`DeploymentReconciler` stores a canonical digest of a bounded error category;
it never persists exception text because transport errors frequently contain
headers, URLs, or credentials. Retry delay uses bounded exponential backoff.
The default eighth failed attempt is terminal.

A privileged manual retry does not reopen that terminal row. It appends a new
`apply` operation only when the failed operation is still the latest intent and
its exact approved revision is still the desired selection. The new operation's
immutable `retry_of_operation_id` points to that terminal failure. This keeps
the retry lineage available when operations are exported independently of the
audit log; `predecessor_operation_id` remains reserved for the latest
successfully applied state. The old failure and all of its attempts remain
immutable.

An `adapter-unhandled` result should be investigated: it means an adapter
raised an exception outside its declared `DeploymentApplyError` categories.
`target-outcome-unknown` is retryable by design and must use the same
idempotency key on the next attempt.

Recommended alerts:

- oldest eligible `pending` operation exceeds two schedule intervals;
- any lease remains past expiry;
- terminal `failed` operation exists;
- retry count grows across consecutive operations for one control;
- desired revision digest differs from the latest applied operation digest.

## Rollback

Rollback never rewrites an applied operation. A fresh `rollback` operation
references:

- a retired revision with an immutable approval decision;
- the current applied operation as its predecessor;
- the authenticated deployer and session digest;
- a new contiguous operation sequence.

The deployer still needs a fresh MFA session and cannot be the revision maker.
If applied state changes after the operator reads it, predecessor compare and
swap rejects the rollback request.

## Authentication and tenancy boundary

Human requests pass through `ControlPlaneService`, including deployer RBAC,
fresh MFA, tenant isolation, and maker-checker checks. Reconciler methods take a
`DeploymentWorkerIdentity`; production ingress must derive that object from a
verified workload credential such as mTLS or a short-lived workload identity.
The digest in the model is an audit binding, not a bearer secret.

The control-plane database is bound to one deployment tenant. PostgreSQL forces
row-level security on every tenant table and derives the tenant from a
`session_user`-to-tenant binding installed by the migration owner. The store
does not set or trust a tenant GUC. An actor or worker tenant that differs from
the deployment binding is rejected before a pool lease; a spoofed GUC or
`SET ROLE` does not change the binding.

The reconciler control-plane DSN uses a dedicated `LOGIN NOINHERIT` role. That
role can read revisions, operations, and audit history; append audit events;
and update only the operation state/fence/lease/result columns. It cannot
create deployment intent, alter immutable operation request fields, read auth
state, create temporary objects, or own managed objects. The human control role
can append deployment intent but cannot perform reconciler state transitions.
The auth role is separate from both.

At startup the reconciler requires the DSN login to equal its configured role
and verifies actual TLS, tenant and role-kind binding, exact control lineage
`[1, 2, 3, 4, 5, 6]`, exact database/object migration owner, unprivileged role
posture, and the complete raw ACL set. Extra privilege is a startup failure,
not merely a warning. The runtime-catalog DSN has its own role and independent
boundary.

## What the acknowledgement proves

An applied row proves that the configured adapter returned:

- the same operation id;
- the current fence;
- the exact requested configuration digest;
- a digest for the target's durable receipt.

It does not, by itself, prove the target receipt was signed, independently
available, or correct. A production adapter must define that receipt, keep it
in the target or evidence custody, and make its digest independently
verifiable. The generic reconciler deliberately does not invent those
target-specific guarantees.

The opt-in PostgreSQL integration test exercises real PostgreSQL concurrency,
process-style pool close/reopen, expired-lease reclaim, stale-worker rejection,
exact acknowledgement, and audit-chain verification:

```bash
CONTROL_ASSURANCE_POSTGRES_MIGRATION_DSN='postgresql://migration-owner@…/db' \
CONTROL_ASSURANCE_POSTGRES_CONTROL_DSN='postgresql://control-role@…/db' \
CONTROL_ASSURANCE_POSTGRES_AUTH_DSN='postgresql://auth-role@…/db' \
CONTROL_ASSURANCE_POSTGRES_RECONCILER_DSN='postgresql://reconciler-role@…/db' \
CONTROL_ASSURANCE_POSTGRES_TENANT='acme-bank' \
CONTROL_ASSURANCE_POSTGRES_CONTROL_ROLE='assurance_control_runtime' \
CONTROL_ASSURANCE_POSTGRES_AUTH_ROLE='assurance_auth_runtime' \
CONTROL_ASSURANCE_POSTGRES_RECONCILER_ROLE='assurance_reconciler_runtime' \
  pytest -q tests/integration/test_postgres_deployment_outbox_live.py
```

The database must be disposable because the live test recreates the managed
schemas. It does not claim a multi-node PostgreSQL promotion or
network-partition test.

The remaining trust boundary is explicit: the PostgreSQL host/administrator,
dedicated migration/database owner, DSN routing, and pinned TLS CA are trusted.
Runtime pods must never receive the migration credential. Admission and
database administration controls must prevent later membership, role-setting,
ownership, RLS, or ACL mutation. Readiness periodically repeats the exact
preflight, but it cannot neutralize an administrator who can rewrite the
database between checks.
