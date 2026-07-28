# Support export scenario contract

Status: pre-implementation contract. If the implementation disagrees with this
document, the implementation does not silently redefine the experiment.

## Why this scenario exists

A support employee has a valid session. A mistaken entitlement gives that employee
access to every customer instead of the customer attached to the assigned case. A
release guard may still prevent a large response from reaching the employee.

This creates the exact ambiguity the evaluator must preserve:

- the entitlement can be wrong;
- the runtime policy can correctly enforce that wrong entitlement;
- data can be selected inside the service;
- a later guard can stop final delivery; and
- the absence of final delivery does not repair the entitlement failure.

This is a synthetic financial-service reference environment, not a copy of a bank.
It does not model a core ledger, payment settlement, a real SOC, or a regulated
production network.

## Protected path

```text
support client
  -> release gateway
  -> customer-data API
  -> authorization policy
  -> PostgreSQL
  -> release decision
  -> client receipt
```

The experiment runner has a separate control path for setup, read-back, evidence
collection, and teardown. Application services do not receive the Docker socket.

## Actors and data

`support-017` owns an active case for `SYNTH-CUSTOMER-000017`. The attack action asks
for a bulk export outside that case. The normal support action asks for the assigned
customer. A separate `compliance-002` action presents a short-lived, scoped release
approval and performs a legitimate bulk export.

All generated records are visibly synthetic. Names use the
`SYNTH-CUSTOMER-<number>` form and email addresses use `example.invalid`. The
generator does not emit real-format national identifiers, payment-card numbers, or
bank-account numbers.

## Interventions

### Target: effective support entitlement

- `case_scoped`: the effective scope contains only the customer on the active case.
- `wildcard_misgrant`: the effective scope is `*`.

The policy engine is unchanged between these two states. In the second state it may
faithfully enforce a bad entitlement. Calling that an authorization-engine defect
would be incorrect.

The runner verifies the effective entitlement through an audit-only read path. A
setup command reporting success is not a manipulation check.

### Compensating control: release guard

- `monitor_only`: parse and record the release decision but do not block.
- `enforce`: block an unapproved sensitive bulk response.

Both states execute the same parsing path. This makes the enforcement difference
observable without treating a disabled process as a valid baseline.

### Sham

The sham performs the same deployment lifecycle without changing entitlement or
release semantics. It exists to catch restart, cache, ordering, and harness effects.

## Primary malicious 2 x 2

| Cell | Entitlement | Release guard | Out-of-scope rows selected | Final delivery | Required interpretation |
|---|---|---|---:|---:|---|
| A | wildcard | monitor | yes | yes | target fail; path fail |
| B | wildcard | enforce | yes | no | target fail; guard pass; path pass |
| C | case-scoped | monitor | no | no | target pass; guard not exercised |
| D | case-scoped | enforce | no | no | target pass; guard not exercised |

Cell B is the non-masking regression case. Cell D prevents a different false
positive: a configured guard is not a tested guard when the request never reaches it.

## Claims

The implementation will assign versioned structured scopes. The short IDs below are
only readable labels.

| ID | Local subject and predicate | Input scope | Result source |
|---|---|---|---|
| `entitlement-current` | `support-017` has only active-case customer scope | current entitlement read-back | identity audit read |
| `scope-selection` | an out-of-case support request selects zero customer rows | fixed malicious bulk request | policy decision plus DB audit |
| `release-guard` | an unapproved sensitive bulk response is not released | only when the guard is reached | gateway decision plus client receipt |
| `tested-path` | the fixed malicious request delivers no out-of-case records | named request, build, and seed only | client receipt |
| `normal-support` | assigned-case summary lookup remains available | fixed benign support fixture | client response and DB audit |
| `approved-bulk` | a valid scoped compliance release remains available | signed lab approval fixture | gateway and client receipt |

`tested-path` is not a claim that every exfiltration route is closed.

## Observations kept separate

- `effective_scope_digest`
- `authorization_reached`
- `authorization_decision`
- `out_of_scope_records_selected`
- `release_guard_reached`
- `release_guard_decision`
- `delivered_record_count`
- `delivered_payload_digest`
- `final_exfiltration`

The phrase “the user read the records” is reserved for data received by the client.
If the service selected rows and the gateway blocked the response, the report says
exactly that.

Every action uses one trace identifier across the client, gateway, policy decision,
database audit, and collector receipts. A component's success log is not enough to
establish a downstream postcondition.

## Benign checks

Each intervention state runs more than a health check:

1. assigned-case support lookup succeeds;
2. out-of-case single-customer lookup is denied under `case_scoped`; and
3. an approved, bounded compliance export succeeds even under `enforce`.

A guard that prevents every bulk operation is a service regression, not a successful
security control.

## Follow-on lifecycle experiments

The prevention experiment observes detection but does not trigger response, because
revoking the session mid-matrix would contaminate later cells. Separate experiments
then test:

1. detection from the required source events and its delay;
2. response by revoking the exact session and quarantining the principal;
3. independent replay of the old session;
4. restoration from the last approved entitlement snapshot;
5. issuance of a new constrained session; and
6. normal and malicious retests.

The recovery claim is limited to restoring an approved access state and normal
service. Confidentiality already lost in cell A cannot be recovered.

## First residual-risk probes

- repeated small reads below the bulk threshold;
- a role-only policy that ignores resource scope;
- missing or delayed database audit events;
- a responder returning success without changing session state;
- a stale entitlement snapshot that restores the wildcard;
- cleanup residue affecting the next trial.

These are separate seeded faults. Combining them in one run would make localization
ambiguous.

## Safety boundary

- no real credentials or personal data;
- no internet egress from scenario networks;
- host ports bind only to loopback;
- non-root containers, read-only roots, and dropped capabilities;
- no privileged containers or Docker socket mounts;
- payload contents discarded after count and digest in a tmpfs sink;
- per-run lab keys, short-lived tokens, hard timeouts, and a kill switch;
- fresh project, network, and volume per replicate;
- teardown followed by host-side residue inspection.

Cleanup failure is recorded as an experiment failure. The next run does not reuse the
same lineage.
