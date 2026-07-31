# Tenant runtime worker

`TenantRuntimeWorker` is the long-lived boundary between the durable runtime
catalog and `RuntimeScheduler`. One process instance serves exactly one tenant;
the PostgreSQL tenant context and the scheduler worker identity remain the
authorization boundary underneath it.

## Loop and time authority

The worker materializes due windows immediately on startup and periodically
thereafter. It always calls:

```python
catalog.materialize_due_runs(tenant_id=tenant_id, through=None)
```

`through=None` is intentional. PostgreSQL's transaction clock, not a worker
host clock, decides which windows are due. A bounded burst of `run_once()` calls
follows each cadence check. Re-entering the outer loop after every burst keeps
materialization timely even while the queue stays busy.

The production defaults are 32 runs per burst, a 30-second materialization
cadence, and a 2-second idle poll. They are constructor policy, not ambient
environment settings.

## Failure boundary

Only catalog availability failures and `RuntimeCatalogOutcomeUnknown` are
retried. Backoff is exponential and capped. A successful catalog operation
resets the consecutive-failure backoff.

These errors stop the process immediately and remain visible to the supervisor:

- catalog conflict or stale-fence rejection;
- missing tenant-scoped identity;
- persisted-state or digest integrity failure;
- any unclassified/programmer exception.

This is deliberate: retrying corrupt or contradictory state can hide an
operator-significant control failure.

## Shutdown

`request_stop()` is thread-safe and interrupts idle or backoff waits. If a
`run_once()` call is already active, that one call is allowed to return. The
stop flag is checked before the next call, so shutdown never claims another
run. If the process is terminated rather than drained, the database lease and
executor journal remain authoritative. A crash after publication identity is
bound can require the operator reconciliation described in the deployment
runbook; it is not advertised as automatic recovery.

## Telemetry

`status()` returns an immutable lock-consistent snapshot containing only the
tenant id, state, counters, fixed event codes, and the current backoff. It never
stores an exception message, URL, credential reference, query, or token.

The optional event callback receives the same bounded vocabulary. Sink
exceptions are counted and swallowed because telemetry is non-authoritative;
they cannot stop evidence execution. A production adapter should translate
these events to metrics/logs without adding caught exception text.

## Production process boundary

`TenantRuntimeWorker` remains free of environment and credential construction.
The production composition is now a separate, non-interactive process
boundary: `assurance-runtime-worker` loads one digest-pinned, secret-free
configuration, builds the PostgreSQL catalogs and journals, composes exact
source and custody identities, serves `/livez` and `/readyz`, and drains one
active call on SIGTERM.

Profile writes are deliberately absent from the long-running worker identity.
The same entry point exposes a one-shot `register-profiles` command intended
for a separate deployment credential and a read-only
`custody-profile-digests` command for two-pass release pinning. Kubernetes
assets, release ordering, token projection, RWX storage requirements, and the
conservative stuck-publication recovery boundary are documented in
[Runtime worker deployment](runtime-worker-deployment.md).
