# Quarantine is not session revocation

Date: 2026-07-29

Status: accepted

## The misleading success

The response case starts with one known compromised session. The responder reports
success, a principal-level quarantine is applied, and replay through the gateway is
denied.

An operational check can reasonably call that contained. It still does not answer
the narrower question: was the exact compromised session revoked in the session
store?

If the session remains active, the quarantine is carrying the whole result. Removing
the quarantine, reaching a service that does not consult it, or later releasing the
principal can expose the still-valid session again.

## Decision

The response experiment names two different controls:

```text
target control       revoke the exact incident session
compensator          quarantine the compromised principal
```

The target mutation is valid only if the session-store read-back changes the named
old session from active to revoked and leaves every other session unchanged.

The compensator is valid only if the principal-store read-back changes the named
principal to quarantined and does not modify session rows.

Gateway replay denial is the path result. It may be caused by either control, so it
cannot identify which one worked.

## Required evidence

Summary Booleans are not treated as raw database evidence. Each run carries:

- the exact before and after session rows;
- the exact before and after principal rows;
- mutation receipts with affected-row counts;
- gateway query and decision receipts bound to the requested principal and session;
- a clone identity read back from the SQLite fixture; and
- a close probe that fails on the closed handle.

The bundle verifier derives the target, compensator, and path values from those
records. Rewriting a summary and rebuilding the manifest is not enough.

## Consequences

- `reported success + replay denied` remains visible as the shallow baseline.
- `old session still active + principal quarantined + replay denied` is classified
  as a masked revocation failure.
- Principal quarantine receives credit for containment without receiving credit for
  exact-session revocation.
- The tested non-target sessions must remain active when exact revocation is
  enabled. This is a scoped specificity check, not a claim about every session in a
  production identity system.
- Bundle metadata and executable source-set identity are part of provenance. A
  rewriter cannot substitute its own evaluator metadata and retain admission.
