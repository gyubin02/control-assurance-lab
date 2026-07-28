# 0003 — Separate mechanism effect, current operation, and path outcome

Status: accepted.

## Problem

The first factorial result exposed one `state` and one `attributable` Boolean for an
entire experiment. That collapses different estimands:

- whether a mechanism can change a local outcome in a controlled laboratory contrast;
- whether the currently deployed instance is in the intended state and operating;
- whether the final impact occurred on one tested path; and
- whether the test suite detects an intentionally seeded fault.

A successful mutation contrast cannot be reused as a current operating-control pass.

## Decision

The canonical report contains three independent result families.

1. **Protocol validity** — whether the declared design was actually executed with
   admissible, paired evidence.
2. **Contrast results** — the named estimand and observed effect direction
   (`beneficial`, `null`, `harmful`, `heterogeneous`, or `unresolved`).
3. **Point claim assessments** — support and rebuttal evidence for a scoped claim at
   one current or historical state.

`attributable: bool` is removed. A contrast may be valid while showing no beneficial
effect. A current claim may be refuted while a compensating-control path claim is
supported.

## Non-masking consequence

The masking scenario must produce at least these separate point assessments:

```text
application authorization (local)  = refuted
bulk-egress prevention (local)      = supported or not_exercised
tested final-impact path            = supported
```

No result is copied from one row to another. A compensation relation is recorded as
risk context, not as inheritance between claim truth values.
