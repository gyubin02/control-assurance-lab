# 0002 — Replace fixed run roles with an experimental design matrix

Status: accepted for the next implementation change.

## Context

The first evaluator used five fixed roles:

- attack baseline;
- attack treatment;
- benign baseline;
- benign treatment;
- unrelated intervention.

That was enough to encode the first counterexample. It is not enough for the intended
platform. It cannot cleanly represent:

- target-control × compensating-control interactions;
- three or more configuration levels;
- telemetry and response interventions in the same experiment;
- randomized order and repeated blocks;
- recovery tests with fault severity as a factor; or
- a scenario-specific factor without changing core enums.

Adding more role names would hard-code one research design into the engine.

## Decision

Represent an experiment as:

- named factors;
- allowed levels for each factor;
- cells containing a complete assignment of factors;
- trial blocks and repetitions;
- typed observations;
- selectors over cells;
- assertions and contrasts between selected cells.

The minimum witness remains a template that expands into this general model. It is
not the core storage shape.

## Consequences

- The initial fixed-role code becomes a documented discarded prototype.
- Scenario authors can express a 2×2 masking experiment without new Python enums.
- The evaluator must validate balanced comparisons and make unmatched cells explicit.
- Selectors and contrast rules become a security boundary; they need a small,
  non-Turing-complete grammar rather than arbitrary Python evaluation.
- The web interface can render an actual experimental matrix instead of a linear
  checklist.

## Migration test

The original authorization witness must produce the same verdict after translation
to factors:

```text
traffic = attack | benign
target_control = broken | correct
compensating_control = off | on
unrelated_control = baseline | changed
```

