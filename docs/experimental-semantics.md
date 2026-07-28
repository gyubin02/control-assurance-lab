# Experimental semantics

Status: design draft. Terms and thresholds may change after the first two scenario
implementations.

## 1. Objects

### Claim

A falsifiable predicate with an explicit subject, threat context, scope, and time.

Bad:

> Access control is secure.

Testable:

> For the customer-export endpoint in build `b`, a caller authenticated as a
> retail customer cannot read another customer's transaction export.

Claims form a directed acyclic argument graph. A parent claim is not evaluated
by averaging its children.

### Control

A mechanism intended to change a security-relevant outcome. It identifies:

- its enforcement or observation point;
- intended mechanism;
- protected claim;
- lifecycle role: preventive, detective, responsive, or recovery;
- required configuration and dependencies;
- observable signals expected when it operates;
- known bypasses and compensating controls.

### Scenario

A graph of actions with preconditions, postconditions, cleanup actions, and
business-impact nodes. An action result and a claim verdict are different data.

### Intervention

A deliberate, recorded change to one factor in the experiment. Examples include:

- enabling the intended authorization policy;
- replacing a vulnerable package with its fixed version;
- disabling alert forwarding;
- corrupting one backup generation before a restore test.

Every intervention needs a manipulation check: independent evidence that the
requested state change actually occurred.

### Observation and evidence

An observation is a typed fact produced by a collector. Evidence is an immutable
artifact or excerpt that supports the observation and carries:

- source identity and collector version;
- collection time and clock information;
- scenario, run, and correlation identifiers;
- content digest;
- scope and sensitivity label;
- retention and freshness policy;
- redaction or minimization record;
- optional signature or external attestation.

A SHA-256 digest detects later byte changes when a trusted digest is available. It
does not, on its own, prove who produced the artifact.

### Assumption and defeater

An assumption is a condition required for an inference. A defeater is observed or
credible counterevidence that blocks or weakens it.

Examples:

- the compared images differ beyond the named intervention;
- the target service was unavailable;
- a downstream WAF blocked a request before the authorization control saw it;
- clocks were too far apart to correlate the alert;
- the cleanup step failed and contaminated the next run;
- the evidence expired under its declared freshness policy.

Active defeaters are never hidden by a numeric score.

## 2. Four separate effectiveness questions

| Dimension | Question | Typical evidence |
|---|---|---|
| Design | Could the specified mechanism cover this threat at the stated enforcement point? | architecture, policy relation, path and dependency analysis |
| Operating | Was the intended control deployed, configured, reachable, and active for this run? | configuration snapshot, health check, manipulation check |
| Outcome | What happened to the attack, detection, response, or recovery objective? | endpoint decision, action trace, alert, containment event, restore validation |
| Evidence quality | Is the evidence sufficiently attributable, complete, fresh, correlated, and reproducible for the claim? | provenance, clock check, coverage, digest/signature, repeated run consistency |

A control can be well designed but not operating. It can be operating while its
evidence pipeline is broken. The business impact can be prevented while the target
control fails.

## 3. Evaluation state

Applicability, execution, and verdict are stored independently.

```text
applicability = applicable | not_applicable | undetermined
execution     = completed | not_run | inconclusive | harness_error
support       = supported | refuted | conflicting | insufficient
```

The interface derives a display state:

| Display state | Required condition |
|---|---|
| `PASS` | applicable, completed, supported, evidence threshold met, no active critical defeater |
| `FAIL` | applicable and refuted |
| `CONFLICT` | credible supporting and rebutting evidence coexist |
| `UNKNOWN` | applicability or support cannot be established |
| `NOT_TESTED` | applicable but no current completed experiment exists |
| `NOT_APPLICABLE` | an approved scope rationale establishes non-applicability |
| `ERROR` | the harness failed before a security conclusion could be made |

`ERROR`, `UNKNOWN`, and `NOT_TESTED` are not passes. `NOT_APPLICABLE` requires a
recorded rationale and owner.

## 4. Interventional witness

An interventional witness is a set of matched executions, not one log line.

### Minimum deterministic matrix

| Run family | Target control | Input | Expected purpose |
|---|---|---|---|
| `attack-baseline` | absent or intentionally broken | fixed malicious action | show the action can reach the protected condition |
| `attack-treatment` | intended state | same malicious action | measure the target-control contrast |
| `benign-baseline` | absent or broken | fixed legitimate action | establish normal behavior |
| `benign-treatment` | intended state | same legitimate action | detect functional regression or total outage |
| `unrelated-intervention` | unrelated control changed | same malicious action | detect harness or environment sensitivity |

Plausible control mutations add stronger tests. Repeated runs and randomized or
alternating order are required when any outcome is nondeterministic.

### Required checks

1. **Reachability:** the baseline action reaches the relevant precondition.
2. **Manipulation:** the target control differs exactly as declared.
3. **Environment equivalence:** immutable inputs match and mutable differences are listed.
4. **Mechanism observation:** evidence exists at the named enforcement/observation point.
5. **Attack contrast:** the protected outcome changes in the expected direction.
6. **Benign invariance:** legitimate behavior remains within its allowed envelope.
7. **Unrelated invariance:** the unrelated intervention does not explain the contrast.
8. **Repeatability:** repeated paired results satisfy the declared rule.
9. **Cleanup:** the environment returns to the declared baseline or is destroyed.

If checks 2 or 3 fail, the system may report an observed difference but must not
attribute it to the target control.

### Claim strength

The witness supports only the scoped claim under the tested environment and inputs.
It does not automatically establish production effectiveness or protection against
untested variants.

## 5. Non-masking rule

Every enforcement or observation point has its own claim.

Example path:

```text
request
  -> application authorization
  -> data access
  -> egress filter
  -> final exfiltration impact
```

If application authorization permits an unauthorized read but the egress filter
blocks exfiltration:

- application-authorization claim: `FAIL`;
- egress-prevention claim: evaluated from its own evidence;
- end-impact claim: `PASS` for this path and experiment;
- residual risk: access succeeded before the compensating control and alternative
  egress paths remain to be tested.

No `max`, majority vote, weighted average, or “best product result wins” operation
may replace these claim-level verdicts.

## 6. Evidence-quality gate

Evidence quality is a vector, not a decorative confidence percentage:

```text
provenance
scope_coverage
temporal_alignment
freshness
integrity_verifiability
reproduction_consistency
minimization
```

Each claim declares hard minimums. Failure of a hard minimum produces `UNKNOWN`
or `CONFLICT`, even if the raw outcome looks favorable.

## 7. Formal sketch

For environment snapshot `e`, fixed action `a`, control treatment `t`, and outcome
predicate `Y`, a paired contrast is:

```text
delta(e, a) = Y(e, a, t=1) - Y(e, a, t=0)
```

Attribution requires more than `delta != 0`:

```text
attributable =
    manipulation_verified
    and environment_equivalent
    and mechanism_observed
    and expected_attack_contrast
    and benign_invariant
    and unrelated_invariant
    and evidence_gate_passed
```

For stochastic systems, the evaluator estimates a paired treatment effect with a
declared uncertainty method rather than applying this Boolean shortcut. The first
benchmark will determine the default repetition count and interval/test.

## 8. Invariants for the implementation

1. No verdict exists without evidence pointers or an explicit insufficiency reason.
2. Raw action status is never reused as a claim verdict.
3. A parent claim cannot pass while a required child is failed, unknown, conflicting,
   or stale.
4. A compensating control can reduce path risk but cannot rewrite another control's result.
5. A missing collector cannot produce a successful detective-control verdict.
6. Expired evidence cannot silently remain current.
7. Failed cleanup invalidates subsequent reused-environment runs until reset.
8. Secret-bearing evidence is rejected or redacted before bundle finalization.
9. A bundle verifier can recompute every derived verdict from included canonical inputs.
10. Unsupported framework mappings are omitted rather than guessed.

