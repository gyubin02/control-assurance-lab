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

## First public result

The first release earns one claim before it grows:

> A downstream release guard stopped all 10 records, but the upstream entitlement
> check still selected all 10. The evaluator exposes the upstream failure instead of
> reporting one green end-to-end result.

That result must be produced by a real replay over a disposable synthetic financial
dataset. A second process must be able to verify the bundle, extract the observations,
and recalculate the same decision. Reusing evidence from another trial, changing the
scope, breaking the benign request, or failing cleanup must prevent a positive result.

The public surface for this result is deliberately small:

- the experiment contract;
- the runner and raw evidence bundle;
- the independent verifier and decision;
- one comparison with a final-outcome-only baseline; and
- one short explanation of what the raw records show.

Other scenario packs, compliance export, broad control libraries, and a general
dashboard wait until this result survives the benchmark. They are not release
checklist items.

## Claims deliberately not made

- A laboratory contrast automatically proves production effectiveness.
- A checksum makes evidence tamper-proof.
- ATT&CK or compliance mappings prove a control works.
- One successful run establishes causality.
- A single score can safely summarize every control.
- This project replaces a pentest, audit, incident-response exercise, or human judgment.

## Release gate

There will be no first public release until the final-outcome-only baseline produces
false assurance on the masked case and the proposed evaluator identifies the upstream
defect for a reason visible in the raw evidence.
