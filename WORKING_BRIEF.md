# Working brief

The repository name is provisional. This file is not a launch README.

## The question

Security tools can show that:

- a configuration value exists,
- an attack step ran,
- an alert appeared, or
- the final business impact did not occur.

Those observations do not necessarily identify which control worked.

This project asks a narrower question first:

> When a control is changed and the same security-relevant action is replayed, what changed, where did it change, and is the evidence strong enough to attribute that difference to the control?

The larger system will use that answer to connect technical tests to control claims, evidence quality, unresolved attack paths, remediation, and retest.

## What must be demonstrated

1. A target control can fail even when a downstream control prevents the final impact.
2. A passing end-to-end test must not hide that failed control.
3. A changed outcome is not attributed to the target control unless the intervention was verified and the compared environments were equivalent enough.
4. Legitimate behavior is tested alongside the attack behavior. A total outage is not a successful preventive control.
5. Missing, stale, contradictory, or poorly sourced evidence produces an explicit non-pass result.
6. Another person can rerun the experiment and verify the evidence bundle without receiving a real secret.

## Full intended scope

The finished work is intended to contain:

- a declarative claim and experiment format;
- an isolated experiment runner with setup, intervention, replay, observation, rollback, and cleanup;
- a claim-level evidence graph;
- preventive, detective, response, and recovery control tests;
- financial-services and manufacturing/R&D scenario packs;
- deliberate control defects with ground-truth labels;
- baselines for configuration-only and single-run attack testing;
- a benchmark for false assurance, defect localization, masking, evidence adequacy, and reproducibility;
- a practical web interface and a command-line interface;
- portable evidence bundles, verification, and optional OSCAL export;
- a Korean study trail that explains the system from first principles.

## Claims deliberately not made

- A laboratory contrast automatically proves production effectiveness.
- A checksum makes evidence tamper-proof.
- ATT&CK or compliance mappings prove a control works.
- One successful run establishes causality.
- A single score can safely summarize every control.
- This project replaces a pentest, audit, incident-response exercise, or human judgment.

## Release gate

There will be no public “complete” release until the benchmark contains at least one
case where each baseline produces false assurance and the proposed evaluator identifies
the seeded defect for a reason visible in the raw evidence.

