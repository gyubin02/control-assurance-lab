# Evaluation questions

These questions define what would count as useful evidence for the project. They
are intentionally narrower than “does the platform look complete?”

## RQ1 — Masked control failures

When a target control is defective but a compensating control prevents the final
business impact, can the evaluator:

- fail the target-control claim;
- support the compensating-control claim only from its own evidence;
- report the tested end-impact path as protected; and
- retain the residual path created by the target failure?

### Ground-truth design

Use a two-factor experiment:

| Cell | Target control | Compensating control |
|---|---|---|
| A | broken | off |
| B | broken | on |
| C | correct | off |
| D | correct | on |

Replay the same attack and a legitimate transaction in every cell. Cell B is the
masking case. It must not become a target-control pass merely because its final
impact matches cells C and D.

## RQ2 — Remediation attribution

After a control change, can the evaluator distinguish:

- evidence that the target mechanism changed the relevant outcome;
- a coincidental outcome change caused by environment drift;
- a service outage mistaken for prevention; and
- a change caused by an unrelated control?

The claimed contribution is a scoped interventional witness, not universal causal
proof. An attribution is counted only when manipulation, environment, mechanism,
attack-contrast, benign-invariance, unrelated-invariance, repetition, and evidence
checks satisfy their declared rules.

## RQ3 — Unsafe certainty

When evidence is stale, missing, weakly attributed, temporally uncorrelated,
contradictory, or contaminated by failed cleanup, does the evaluator abstain instead
of returning a pass?

This is evaluated separately from defect detection. A tool that catches faults but
silently passes on missing evidence is still unsafe for assurance work.

## RQ4 — Defect localization

Given a multi-step path with one or more seeded faults, how accurately does the
evaluator identify the failed claim and enforcement point?

The benchmark must include:

- authorization logic bypass;
- policy deployed to the wrong scope;
- downstream masking;
- telemetry collection loss;
- delayed alert outside the stated objective;
- stale access-review evidence;
- response action that records success without changing state;
- corrupt or incomplete restore;
- benign-traffic regression;
- cleanup contamination.

## RQ5 — Independent recalculation

Can a second process, using only the portable bundle and public verifier, reproduce:

- artifact integrity checks;
- claim verdicts;
- active defeaters;
- residual paths; and
- the reason for every abstention?

Byte-identical bundles are not required because timestamps and archive ordering can
differ. Canonical records and derived verdicts must match.

## Baselines

1. **Configuration-only:** compares declared state with desired state.
2. **Final-outcome-only:** passes when the business impact does not occur.
3. **Single-run claim-aware:** observes each enforcement point but has no matched
   intervention or remediation attribution.
4. **Interventional claim-aware:** the proposed evaluator.

These are reference evaluators implemented in the repository, not caricatures of
named commercial products.

## Primary metrics

| Metric | Definition |
|---|---|
| False-assurance rate | defective applicable claims reported as pass / defective applicable claims |
| Fault-localization precision and recall | claim/control-level seeded defects versus reported failures |
| Masking error rate | masked target failures incorrectly reported as pass / masking cases |
| Safe-abstention rate | inadequate-evidence cases reported as unknown/conflict/error/not-tested rather than pass |
| Attribution precision | valid attributions / all reported attributions |
| Benign-regression recall | seeded legitimate-flow regressions detected / seeded regressions |
| Verdict reproducibility | matching canonical claim states across independent recalculations |
| Evidence trace completeness | derived verdict inputs with resolvable evidence pointers / all derived verdict inputs |
| Runtime and storage overhead | paired against the same scenario set and environment |

False-assurance rate is primary. A high unknown rate can trivially reduce false
assurance, so coverage and safe-abstention are reported beside it.

## Statistical plan

- Deterministic reference-model cases run at least three times to expose hidden state.
- Containerized deterministic cases start with five paired repetitions; the pilot
  decides whether that is sufficient.
- Timing, queueing, and alert-delay cases use at least thirty seeded paired trials.
- Trial order is randomized or counterbalanced. Seeds and order are recorded.
- Binary paired outcomes use paired counts and confidence intervals; timing results
  report paired effect sizes and bootstrap intervals.
- Thresholds and exclusions are written before the final benchmark run.
- Failed harness runs remain in the run ledger and are reported separately from
  security failures.

## What would disconfirm the contribution

The central claim should be narrowed or abandoned if:

- a public tool already implements the same portable interventional semantics and
  non-masking rule;
- the proposed evaluator does not reduce false assurance over the baselines on seeded
  masked defects;
- correct attribution depends on hand-written scenario knowledge unavailable to an
  independent evaluator;
- evidence bundles cannot be independently recalculated; or
- the overhead makes repeated control testing impractical even in the defined lab scope.

