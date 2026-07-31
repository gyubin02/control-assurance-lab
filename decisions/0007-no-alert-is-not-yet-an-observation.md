# “No alert” is not yet an observation

Date: 2026-07-29

Status: accepted

## The tempting shortcut

The detection case has two possible alert paths:

- a named rule that should correlate the exact three-event replay sequence; and
- a broader fallback rule that notices the final sensitive read.

When the named rule produces no row, it is tempting to record `false` immediately.
That is not enough. The collector may still be processing, an event may be missing,
the detector may not have reached the last source sequence, or the alert query may
have run before the declared window ended.

An empty query result says only what was visible at that query instant.

## Decision

The evaluator may conclude that the named alert is absent only when one closure
record binds all of the following:

```text
expected source-event identities and sequence range
observed source-event identities and sequence range
healthy source
healthy, completed collector run
named detector watermark at the final source sequence
empty pending detector queue
simulated clock read-back at the declared window close
alert-store query completed as of that close
exact alert identities returned by the query
```

If any part is missing or inconsistent, the named detection result is
`INDETERMINATE`, not `REFUTED`.

The two-second bound is a deterministic objective of this synthetic lab. It is not a
NIST requirement, a production service-level objective, or a performance result.

## Why the fallback does not settle it

A broad fallback alert can be real and useful while the named rule is broken. It
must be traced through the forwarded-event read-back that actually fed the fallback
detector. Merely showing that the original source event existed does not prove that
the forwarding path delivered it.

The shallow question and the control-specific question therefore remain separate:

```text
Did any alert appear in the window?          yes
Did the named exact-correlation rule alert?  no, after closure proof
```

That combination is the detection masking case. The fallback deserves credit for
its own alert; it cannot lend its identity to the named rule.

## Consequences

- Missing evidence never becomes a negative detection result by default.
- A fallback alert is bound to forwarded records, not directly to source records.
- Alert time is reported as an offset from the window origin unless a separate
  causal-latency calculation is made.
- The legitimate check is described only as “the tested benign action was
  unalerted.” One fixed action is not a false-positive rate.
- A restart sham needs its own pre/post instance and configuration receipt. Closing
  an unused database and opening another one is not evidence that a collector
  restart occurred.
