# Benchmark protocol

Status: pre-result draft

Freeze target: before the detection and recovery reference bundles are generated

This file fixes the questions the first public benchmark must answer. It is written
before looking at the completed 48-cell result so that a pleasant demo cannot quietly
become the success criterion.

## Corpus

The lifecycle corpus contains three independent deterministic experiments:

```text
detection  2 inputs × 2 named-control states × 2 fallback states × 2 sham states
response   2 inputs × 2 named-control states × 2 fallback states × 2 sham states
recovery   2 inputs × 2 named-control states × 2 fallback states × 2 sham states
```

That is 48 distinct cells. The benchmark plan runs three fresh-clone replicates per
cell, for 144 planned executions. These are not 144 consecutive actions against one
incident.

The earlier preventive case remains the incident source and a worked example of the
same non-masking rule. It is not counted again in the 48-cell lifecycle result.

All inputs, fixture rows, action descriptors, factor labels, expected directions,
sham operations, freshness limits, and lab timing bounds are fixed in the compiled
contracts. The benchmark contains no production data and no live attack target.

## Primary questions

For each seeded masking cell:

1. Does the evaluator expose the failed named control?
2. Does it preserve the supported fallback or downstream outcome beside that failure?
3. Does it avoid calling an unrelated or compensating control the target control?
4. Does a legitimate action still satisfy its declared service envelope?

For each invalid-evidence case:

1. Does the verifier refuse a positive conclusion?
2. Does it identify the broken evidence or protocol boundary?
3. Does it avoid silently substituting another artifact?

For incident history:

1. Can any accepted transition remove or rewrite an admitted delivery?
2. Can matched-comparison evidence be promoted to the current state?
3. Can post-fork evidence, replacement sessions, or transition bundles be reused?

## Deliberately shallow baselines

The comparison is not against a straw-man “always pass” program. Each baseline uses
a signal that an operations team could plausibly watch:

| Experiment | Shallow baseline |
|---|---|
| prevention | final delivery count only |
| detection | existence of any in-window alert |
| response | responder success status plus replay denial |
| recovery | final delivery count plus legitimate-service success |

Each baseline must misclassify at least one predeclared masking cell. The typed
evaluator must keep the baseline's true observation visible while refusing its
control-specific conclusion.

## Predeclared evidence corruptions

Corruptions are applied to a valid bundle and, where stated, the manifest is rebuilt.
That distinction matters: a changed file with an old hash tests byte integrity; a
changed file with internally updated hashes tests semantic verification.

| ID | Mutation | Required result |
|---|---|---|
| C01 | change one raw byte without updating the manifest | reject bundle integrity |
| C02 | remove one declared cell and rebuild the manifest | reject protocol coverage |
| C03 | duplicate a trial key or fresh-clone identity | reject trial lineage |
| C04 | relabel a selector while preserving its observations | reject selector binding |
| C05 | swap the fixed attack and benign action digests | reject action binding |
| C06 | reuse a trace or event artifact across two trials in the same benchmark bundle | reject provenance |
| C07 | move required evidence outside its freshness window | return no positive verdict |
| C08 | introduce a source sequence gap in a closed detection window | do not conclude absence |
| C09 | omit collector completion or clock-bound evidence | do not conclude absence |
| C10 | replace the named target's subject with a different session, rule, or snapshot | reject subject binding |
| C11 | present fallback evidence as the named control's local readback | keep the named control unsupported |
| C12 | remove or fail cleanup for a fresh-clone trial | reject that trial; v1 makes no descendant-run claim |
| C13 | add contradictory target-local observations | return `CONFLICTING` |
| C14 | remove or rewrite an admitted disclosure entry | reject lifecycle |
| C15 | select a matched-comparison snapshot as current | reject lifecycle |
| C16 | reuse the compromised session as its replacement | reject lifecycle |
| C17 | change evaluator identity, evaluation time, parent bundle, or file roles and rebuild the manifest | reject provenance |
| C18 | rewrite a derived stage value and every dependent digest without changing its lower-level database or query receipt | reject semantic reconstruction |
| C19 | claim that fallback telemetry was forwarded while disconnecting the forwarded read-back from the alert input | reject causal path binding |
| C20 | label a run as reload/reapply while omitting the persisted pre/post operation receipt | reject sham attestation |

The released corruption generator must be deterministic and must record whether it
rebuilt the manifest.

Fresh-clone identities remain unique, but benchmark generation injects a deterministic
nonce source so that two releases from the frozen inputs are byte-identical. Production
or ad-hoc runtime defaults may still use operating-system randomness.

## Measures

The first release reports counts and exact fractions; it does not attach confidence
intervals to a deterministic corpus.

```text
masked-failure recall
exact fault-localization accuracy
false-supported rate
invalid-evidence rejection rate
disclosure-monotonicity violations
cross-verifier semantic agreement
```

`false-supported rate` is primary. A system that catches every seeded failure by
calling every case unknown is not useful, so valid fixed cells and all benign service
cells must also reach their predeclared positive conclusions.

## Independent verification

The second verifier must not import the evaluator's verdict functions. It may share
the public schema and canonicalization rules. Starting with only a bundle, it must
recompute:

- manifest and file integrity;
- declared 16-cell coverage;
- fixed action and selector bindings;
- the named-control, fallback, path, and benign results;
- the shallow baseline result; and
- the residual classification.

The recovery bundle therefore vendors the lifecycle parent manifest and every payload
needed to verify the cutover and disclosure ledger. An absolute path or a parent bundle
ID by itself is not portable evidence.

Agreement means semantic equality of these outputs, not byte-for-byte equality of
two programs' internal objects.

## Stop conditions

The benchmark is not ready for release if any of the following is true:

- a seeded fault is detectable only through a hard-coded expected verdict;
- the verifier trusts a derived case file over raw events;
- a missing or stale artifact still produces `SUPPORTED`;
- one experiment's evidence is reused as another experiment's observed result;
- the current state can come from a matched comparison;
- the disclosed-history ledger can shrink; or
- the README describes a stronger result than the released corpus establishes.
