# Recovery does not retest the session cutover

Date: 2026-07-29

Status: accepted

## The mistake in the first design

The first recovery sketch varied two things at once:

- whether the old compromised session had been replaced correctly; and
- whether the restored entitlement snapshot was safe.

That made an attractive story, but a poor experiment. If a request failed, the
result could be explained by a revoked session, a bad replacement session, or the
restored entitlement boundary. The experiment would not identify which control
actually changed the outcome.

It also assigned the same transition to two owners. The incident lifecycle already
checks that the old session moves from active to revoked, that the replacement is a
different session, and that the replacement is usable after restore. Repeating that
transition as a recovery factor would let the experiment and the incident history
disagree about which state is current.

## Decision

The recovery experiment starts after a fixed cutover:

```text
old compromised session     revoked
replacement session         active and distinct
replacement entitlement     bound to the selected snapshot digest
```

Those facts are fixture requirements. The lifecycle verifier owns the transition
that produced them.

The recovery experiment varies only:

```text
malicious / legitimate retest
× stale wildcard / approved case-scoped snapshot
× monitor-only / enforcing release guard
× steady / snapshot reapply
```

Its named target is the restored entitlement boundary. The release guard is a
separate downstream control.

## Why this matters

The seeded current state restores the stale wildcard snapshot. It selects ten
out-of-scope customers. The enforcing release guard then blocks delivery.

Both of these statements are true:

```text
final delivery                       0
restored entitlement boundary        failed
```

Varying the snapshot while holding the cutover fixed isolates that failure. Varying
the release guard separately shows why an outcome-only recovery check would miss it.

The legitimate retest is deliberately narrow: it proves that the one declared
assigned-case action still works in every tested cell. It is not a general
availability or false-positive claim.

## Consequences

- A recovery result cannot be used as evidence that session rotation occurred.
- A lifecycle result cannot be used as evidence that the restored entitlement set
  was safe.
- The recovery bundle must bind the exact old and replacement session identities,
  their read-back states, and the replacement-to-entitlement digest.
- Prior disclosure remains lifecycle history. Recovery may carry an exact reference
  to that history, but a clean retest cannot erase or rewrite it.
- The web case must show “service restored” beside, not instead of, the failed
  restored control.
