# Incident history is not an experiment log

Date: 2026-07-29

Status: accepted

## The problem

The first case ends with a useful contradiction:

```text
entitlement boundary failed
release guard worked
zero records left the system
```

Once detection, response, and recovery are added, it becomes tempting to turn that
into one long success story. An alert appears, a session is contained, the system is
restored, the final retest is green, and the page says “recovered.”

That would discard the most important facts. A fallback alert cannot repair a failed
named detector. Quarantine cannot prove that the old session was revoked. A clean
retest cannot undo a delivery that was already observed.

There is a second trap. The fixed and broken variants in the lab are both observed
runs. Calling one of them *the counterfactual* makes the experimental claim sound
stronger than it is.

## Decision

The incident record and the experiment corpus are different objects.

- The incident record is a content-addressed chain of actual state snapshots.
- A separately executed matched comparison may help test a declared factor, but it
  is labelled `matched-comparison` and can never become current-state evidence.
- Detection, response, and recovery are three independent 16-cell experiments. Their
  cells are not appended to the incident record as though all 48 executions happened
  to one live system.
- A lifecycle transition points to its own event artifacts, attestation bundle, and
  cleanup bundle. Post-fork evidence cannot be reused between the actual and matched
  comparison branches.
- A prior delivery enters the disclosure ledger only when an exact receipt is
  admitted. The verifier then forbids removal or rewriting of that entry.
- Operational access, service restoration, and prior disclosure remain separate
  state. “The replacement session works” and “a delivery happened earlier” may both
  be true.

The disclosure ledger is append-only under these verifier rules. It is not an
externally immutable log, and a receipt establishes delivery—not who kept a copy.

## Why this shape

The experiment answers a narrow mechanism question by comparing controlled runs. The
incident chain answers a different question: what state can be treated as current,
and what history must still be carried forward?

Keeping them separate prevents a good comparison run from silently replacing an
unfavorable actual state. It also lets the project publish every experimental cell
without pretending that a synthetic benchmark is a production incident chronology.

## Rejected alternatives

**One final incident status.**

Too much disappears behind a green word. It cannot preserve local control failure,
downstream containment, current service, and prior disclosure at once.

**One 48-step incident timeline.**

The cells start from fresh fixtures and contain mutually exclusive interventions.
Presenting them as consecutive incident actions would be false.

**Promote the fixed branch after a successful retest.**

That would confuse an observed comparison with the system's actual current state.

**Delete disclosure history after restore.**

Restore changes current state. It cannot rewrite an already admitted delivery event.

## Consequences

The interface must resist a single “incident passed” badge. It should show the state
that is current, the comparison that supports a scoped mechanism claim, and any prior
delivery side by side.

The lifecycle verifier is intentionally strict about lineage, evidence reuse,
replacement-session identity, entitlement changes, and disclosure monotonicity. It
does not decide whether every operational action was wise; the three experiment
evaluators own those control-specific verdicts.
