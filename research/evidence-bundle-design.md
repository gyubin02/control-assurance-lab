# Evidence bundle, provenance, and admissibility design

Status: design proposal. This document is intentionally stricter than the first
implementation needs to be. Fields may be removed after the financial scenario has
produced a real bundle, but the trust boundaries should not be weakened silently.

## 1. What the bundle is for

The bundle is the portable input to a second evaluator. It should let that evaluator
answer four different questions without trusting a screenshot or the first evaluator's
summary:

1. Are all declared bytes present and unchanged?
2. Where did each observation come from, and how was it transformed?
3. Was each piece of evidence admissible for one particular inference at the declared
   `as_of` time?
4. Do the included specifications, observations, and policies reproduce the reported
   claim and contrast results?

Those questions are narrower than "is the evidence true?" A valid digest can cover a
fabricated log. A valid signature can come from a compromised but trusted collector.
A complete laboratory bundle does not establish that production has the same controls
or behavior.

The design follows the existing separation between:

- protocol validity;
- contrast results;
- point claim assessments; and
- cleanup or experiment hygiene.

The bundle must preserve those result families. It must not introduce a new aggregate
confidence score that hides one of them.

## 2. Threat model

The verifier should detect or expose:

- a payload file changed after the bundle was finalized;
- a listed payload that is missing, truncated, duplicated, or replaced;
- a reference to an unknown evidence, trial, source, or claim identifier;
- a result that cannot be recomputed from the declared inputs;
- an event moved into another trial, cell, or replicate;
- a source sequence gap, replay, or impossible clock relation;
- evidence that is stale at the fixed evaluation time;
- a claimed observation whose extractor inputs or version are unavailable;
- contradictory evidence hidden from the final report;
- path traversal, duplicate archive entries, symlinks, decompression bombs, and hostile
  JSON intended to confuse different parsers; and
- a signature that is valid cryptographically but does not satisfy the verifier's
  externally supplied identity policy.

The verifier cannot, from the bundle alone, detect:

- a source that lied before collection;
- a compromised collector that fabricated a complete, internally consistent history;
- an operator who omitted an entire counterexample before bundle construction;
- clock manipulation that remains within every recorded uncertainty bound;
- a stolen signing key that still satisfies an unchanged trust policy; or
- a gap between the synthetic reference environment and a real organization.

These are not edge cases. They determine the words used in the report.

## 3. Financial reference path

The first bundle profile is tied to the synthetic financial-service reference
environment. One test path is:

```text
entitlement misgrant
  -> out-of-scope record selection
  -> release guard
  -> detector
  -> session revocation or quarantine
  -> entitlement restoration
  -> clean retest
```

This is a software reference environment, not a model of one named bank or securities
company. All people, accounts, products, hosts, and network locations are synthetic.
Examples use the reserved `.invalid` namespace and visibly synthetic identifiers.

The arrows describe one control lifecycle, not one long trial. The prevention matrix
may observe detection, but it does not revoke a session mid-matrix and contaminate later
cells. Detection, response, restoration, and clean retest are linked but separate
experiments with their own trial and reset lineage.

The domain event vocabulary starts with:

```text
identity.token_issued
identity.entitlement_resolved
authz.decision
data.query_completed
release.decision
client.payload_received
detection.alert_created
response.session_revocation_requested
response.session_revocation_state_verified
recovery.entitlement_restored
harness.factor_observed
harness.cleanup_verified
```

Not every event is expected in every cell. For example, a correct authorization
decision can prevent the query and therefore leave the release guard unexercised.
Expected events are conditional on the path and claim; their absence is not
automatically a pass or a failure.

The masking cell should be legible from raw events:

```text
identity.entitlement_resolved          wildcard misgrant
authz.decision                         allow
data.query_completed                   out_of_scope_records_selected > 0
release.decision                       block
client.payload_received                out_of_scope_records_received = 0
```

Those facts produce separate results:

```text
effective-entitlement current claim    refuted
out-of-case selection local claim      refuted
release-guard local claim              supported
tested final-delivery path claim       supported
residual risk                          unauthorized selection occurred before release
```

The policy engine can faithfully enforce the bad wildcard entitlement. The evidence
therefore does not label this an authorization-engine defect. The final-delivery result
cannot overwrite the entitlement and selection results. If the case-scoped entitlement
causes the request to be denied before a query occurs, the release guard is
`NOT_EXERCISED`, not supported.

## 4. Bundle shape

The canonical object is a directory tree, not an archive byte stream. A `.cabundle`
archive is only a transport. Repacking it must not change the semantic bundle identity.

```text
bundle.json
spec/
  experiment.json
  claims.jsonl
  evidence-policy.json
  event-contracts.json
records/
  sources.jsonl
  activities.jsonl
  artifacts.jsonl
  clock-assessments.jsonl
  stream-checkpoints.jsonl
  trials.jsonl
  events.jsonl
  observations.jsonl
  links.jsonl
  evidence-uses.jsonl
  defeaters.jsonl
  omissions.jsonl
artifacts/
  sha256/4a/4a...f2
derived/
  admission-results.jsonl
  protocol-report.json
  semantic-result.json
  decision-trace.jsonl
  extraction-results.jsonl
attestations/
  <signer-id>.dsse.json
verification/
  producer-verification.json
```

`bundle.json` is both the root metadata record and the payload manifest. It lists every
payload under `spec/`, `records/`, `artifacts/`, and `derived/`. It does not list itself,
`attestations/`, or `verification/`; including its own digest would create a cycle.

The semantic bundle identifier is:

```text
sha256(JCS(bundle.json))
```

It is displayed as `cab:sha256:<hex>` but is not embedded in `bundle.json`. Detached
attestations sign this canonical root. Adding another signature therefore does not
change the semantic bundle identifier.

`verification/producer-verification.json` is optional diagnostic output from the
producer. A verifier always writes its own verification report elsewhere. It must not
mistake the producer's report for fresh verification.

The only entries allowed outside the manifest are `bundle.json`, signature envelopes
that match the attestation schema, and the one producer diagnostic file. "Unlisted
archive entry" below means any other entry. An attacker cannot smuggle a second report,
schema, or executable into an ignored path.

### 4.1 Root manifest

Illustrative root:

```json
{
  "media_type": "application/vnd.control-assurance.bundle.v1+json",
  "schema_version": "1.0.0",
  "profile": "full-synthetic",
  "created_at": "2026-07-29T03:14:15.000000Z",
  "as_of": "2026-07-29T03:14:00.000000Z",
  "experiment": {
    "id": "fin-entitlement-release-001",
    "spec_version": "1.0.0",
    "spec_digest": "sha256:<hex>"
  },
  "evaluation": {
    "policy_id": "policy:financial-reference:v1",
    "policy_digest": "sha256:<hex>",
    "evaluator": {
      "name": "assurance-lab",
      "version": "0.1.0",
      "source_revision": "<git-commit>",
      "image_digest": "sha256:<hex>"
    }
  },
  "parent_bundles": [],
  "files": [
    {
      "path": "records/events.jsonl",
      "sha256": "<hex>",
      "size": 12345,
      "media_type": "application/x-ndjson",
      "role": "domain-events",
      "sensitivity": "synthetic",
      "required_for": ["integrity", "verdict-recomputation"]
    }
  ]
}
```

`as_of` is the time at which freshness and temporal admissibility were evaluated.
Re-running the verifier tomorrow with the same bundle must produce the same historical
result. A current-state check tomorrow requires a new `as_of` and therefore a new
bundle.

`created_at` may be later than `as_of`, because finalization takes time. A policy sets
the maximum allowed delay. Neither field may be filled from an untrusted event source.

`parent_bundles` is used for a late-evidence supplement, redacted derivative, or
schema-migrated derivative. A published bundle is not edited in place.

### 4.2 File descriptors

The `files` array is sorted by Unicode code point order of `path`. Paths:

- use `/` separators;
- are relative, normalized UTF-8 NFC strings;
- contain no empty, `.` or `..` component;
- do not begin with `/`;
- cannot differ only by case or Unicode normalization; and
- cannot point into `attestations/` or `verification/`.

Every payload file has exactly one descriptor. Unlisted archive entries are rejected.
A listed file that is absent or has the wrong size or digest makes the bundle corrupt,
not merely partial.

The descriptor hashes the exact stored bytes. It does not claim that those bytes are a
truthful representation of the source.

### 4.3 Identifiers

Logical record identifiers are lower-case ASCII strings in typed namespaces such as:

```text
trial:003
event:authz:trial-003:000004
observation:trial-003:release-blocked
activity:extract-authz:trial-003:01
```

They are unique within the bundle and stable across deterministic re-serialization.
They are locators, not integrity checks. A verifier does not trust a record because its
ID contains the word `authz`.

Artifact identifiers are content-derived:

```text
artifact:sha256:<hex>
```

The suffix must equal the digest of the artifact bytes. The semantic bundle ID is
content-derived as described above. Other records are not content-addressed when that
would introduce a cycle through parent, chain, or derivation references.

## 5. Canonical serialization

JSON objects used in digest or signature operations are serialized with the
[JSON Canonicalization Scheme (RFC 8785)](https://www.rfc-editor.org/rfc/rfc8785.html).
`bundle.json` and other single-object JSON payloads are stored as the exact JCS bytes,
without a trailing newline. A separate CLI can pretty-print them for inspection; a
pretty copy is not another signed source of truth.
The implementation still needs a strict parser in front of JCS:

- UTF-8 only, without a byte-order mark;
- duplicate object keys rejected before ordinary JSON decoding;
- invalid Unicode and lone surrogates rejected;
- no `NaN`, positive or negative infinity, or negative zero;
- integer values restricted to the I-JSON interoperable range when encoded as JSON
  numbers;
- exact large values, decimal measurements, and nanosecond counters encoded as typed
  decimal strings; and
- bounded nesting, string length, object members, array length, and total input bytes.

The current protocol's finite `number` type can be represented by JCS. Measurements
that require decimal exactness should not silently pass through a binary float.

Canonical timestamps use UTC and exactly six fractional digits:

```text
YYYY-MM-DDTHH:MM:SS.ffffffZ
```

The original source timestamp string may be retained in a raw synthetic artifact, but
comparisons use the parsed canonical value and the recorded clock uncertainty.

Canonical JSONL is:

- one JCS object per line;
- UTF-8 without BOM;
- LF line endings;
- no blank lines; and
- one final LF.

Record sets such as sources, claims, and observations are sorted by record ID. Domain
events are sorted by:

```text
(trial_id, producer_id, source_epoch, source_sequence, event_id)
```

`received_at` remains a field and is not rewritten to fit that order. Sorting makes
re-serialization deterministic; it does not pretend that independent source clocks
have one global event order.

Archive bytes are not canonical. A deterministic packing profile may sort paths, use
fixed metadata, prohibit symlinks, and use fixed compression settings for release
artifacts, but the verifier identifies the bundle from `bundle.json`, not the ZIP
digest.

## 6. Core record types

The records borrow the useful distinction in W3C PROV between entity, activity, and
agent, but remain plain JSON rather than requiring RDF or an ontology runtime. W3C
[PROV-O](https://www.w3.org/TR/prov-o/) is an export target, not the storage engine.

### 6.1 Source identity

One "source" field is too vague. Four identities are kept separate:

| Identity | Meaning |
|---|---|
| producer | service, policy engine, detector, or harness component that emitted a fact |
| collector | process that received or queried the producer's data |
| extractor | code that converted collected bytes into typed observations |
| signer | identity that signed the finalized bundle root |

A source record contains:

```json
{
  "id": "source:authz-engine:instance-01",
  "record_type": "source",
  "schema_version": "1.0.0",
  "kind": "service",
  "logical_name": "authz-engine",
  "instance": "synthetic-instance-01",
  "software_version": "1.2.3",
  "image_digest": "sha256:<hex>",
  "environment": "financial-reference",
  "identity_basis": {
    "method": "mutual-tls-peer",
    "peer_certificate_sha256": "<hex>",
    "verification_evidence_ids": ["evidence:peer-check:01"]
  },
  "clock_id": "clock:authz-engine:01"
}
```

The `identity_basis` says how the collector associated bytes with a producer. It is
not a declaration that the producer was uncompromised. Bearer credentials,
certificates containing private keys, and raw authentication headers are never stored.

For each collector and extractor, record:

- package or executable version;
- source revision when available;
- image or executable digest;
- configuration digest;
- launch identity and isolation boundary;
- input and output record identifiers; and
- stdout, stderr, and exit status for a transformation when relevant.

An extractor executing inside the target service is not treated as an independent
probe merely because it has a different process name. Independence is an
inference-specific property established from deployment boundaries and evidence.

### 6.2 Artifact descriptors

An artifact record connects content-addressed bytes to their origin without putting
source claims in the filename:

```json
{
  "id": "artifact:sha256:<hex>",
  "record_type": "artifact",
  "schema_version": "1.0.0",
  "path": "artifacts/sha256/4a/4a...f2",
  "sha256": "<hex>",
  "size": 816,
  "media_type": "application/x-ndjson",
  "evidence_class": "source-native-minimized-log",
  "generated_by": "activity:collect-authz:trial-003:01",
  "sensitivity": "synthetic",
  "contains_raw_secret": false,
  "contains_payload_rows": false
}
```

The Boolean minimization declarations are checked by the publication gate; they are
not accepted as proof on their own. "Source-native" means the first representation
accepted from that producer, not an untouched memory or packet capture. The reference
environment minimizes tokens, addresses, and payloads before evidence leaves the
producer.

### 6.3 Collection and transformation activities

An activity record links inputs, code, configuration, and outputs:

```json
{
  "id": "activity:extract-authz:trial-003:01",
  "record_type": "activity",
  "schema_version": "1.0.0",
  "activity_type": "extract",
  "started_at": "2026-07-29T03:12:01.000000Z",
  "ended_at": "2026-07-29T03:12:01.120000Z",
  "actor_id": "extractor:event-normalizer:01",
  "used_ids": ["artifact:sha256:<hex>"],
  "generated_ids": ["event:authz:trial-003:000004"],
  "code_digest": "sha256:<hex>",
  "configuration_digest": "sha256:<hex>",
  "deterministic": true,
  "exit_status": 0
}
```

Derived data is never allowed to overwrite its input. A normalized event, excerpt,
redacted artifact, migration, and verdict each gets a new identifier and a
`derived_from` link.

### 6.4 Domain event envelope

All required financial domain events use one envelope:

```json
{
  "id": "event:authz:trial-003:000004",
  "record_type": "domain_event",
  "schema_version": "1.0.0",
  "event_type": "authz.decision",
  "occurred_at": "2026-07-29T03:12:01.010000Z",
  "received_at": "2026-07-29T03:12:01.024000Z",
  "source_epoch": "boot-01",
  "source_sequence": 44,
  "collector_sequence": 81,
  "producer": {
    "source_id": "source:authz-engine:instance-01",
    "software_version": "1.2.3",
    "image_digest": "sha256:<hex>"
  },
  "collector_id": "collector:event-gateway:01",
  "experiment": {
    "experiment_id": "fin-entitlement-release-001",
    "trial_id": "trial-003",
    "cell_id": "target-broken__detector-on",
    "block_id": "block-01",
    "replicate": 0
  },
  "correlation": {
    "trace_id": "trace:trial-003:request-01",
    "request_id": "request:trial-003:01",
    "parent_event_ids": ["event:identity:trial-003:000003"]
  },
  "attributes": {
    "decision": "allow",
    "requested_scope_digest": "sha256:<hex>",
    "effective_scope_digest": "sha256:<hex>",
    "policy_revision": "synthetic-policy-v1"
  },
  "artifact_ids": ["artifact:sha256:<hex>"],
  "previous_event_digest": "sha256:<hex>"
}
```

The event stores counts and decisions, not selected records. The synthetic token may be
represented by a digest if correlation requires it, but the token bytes are excluded.
Addresses, request or response bodies, and customer-like payloads are excluded.

The parent IDs express the producer's or extractor's proposed lineage. The verifier
still checks that the linked events share the declared trial and permitted correlation
scope.

### 6.5 Event-specific minimum attributes

| Event type | Minimum synthetic attributes |
|---|---|
| `identity.token_issued` | token digest, synthetic subject ID, session digest, entitlement-set digest, expiry |
| `identity.entitlement_resolved` | subject ID, requested scope digest, resolved scope digest, resolution decision |
| `authz.decision` | action, resource-scope digest, allow/deny, policy revision, reason code |
| `data.query_completed` | selected record count, out-of-scope records selected, query-plan digest, success/failure |
| `release.decision` | candidate record count, out-of-scope records selected, allow/block, rule revision |
| `client.payload_received` | delivered record count, out-of-scope records received, payload digest, no payload bytes |
| `detection.alert_created` | alert class, severity, trace/request link, detection rule revision |
| `response.session_revocation_requested` | session digest, requested action, triggering alert ID |
| `response.session_revocation_state_verified` | session digest, observed active/revoked state, probe source |
| `recovery.entitlement_restored` | subject ID, before/after entitlement-set digests, restoration revision |
| `harness.factor_observed` | factor, expected level, observed level, probe source, intervention digest |
| `harness.cleanup_verified` | reset lineage, reset epoch, residual-state count, probe source |

The `state_verified` response event is deliberately separate from
`revocation_requested`. A request log is not evidence that the session stopped working.
The same rule applies to recovery: `recovery.entitlement_restored` shows a state change,
not a successful recovery outcome. That outcome needs a linked clean retest with a new
session and the expected entitlement, authorization, query, release, and client
observations.

### 6.6 Observations

An observation is a typed value extracted from one or more events or artifacts:

```json
{
  "id": "observation:trial-003:release-blocked",
  "record_type": "observation",
  "schema_version": "1.0.0",
  "name": "release_blocked",
  "value": {"type": "boolean", "value": true},
  "unit": null,
  "observed_at": "2026-07-29T03:12:01.024000Z",
  "received_at": "2026-07-29T03:12:01.024000Z",
  "source_event_ids": ["event:release:trial-003:000007"],
  "generated_by": "activity:extract-release:trial-003:01",
  "trial_id": "trial-003",
  "correlation_id": "trace:trial-003:request-01"
}
```

Observations cannot cite only another observation unless the deriving activity and the
full upstream lineage are present. Raw action success and claim truth remain different
types.

## 7. Time and freshness

Five time concepts must not be collapsed:

| Field | Meaning |
|---|---|
| `occurred_at` | producer's claim about when the event happened |
| `observed_at` | time a direct probe or collector sampled the represented state |
| `received_at` | collector's clock when it accepted the event |
| `valid_from` / `valid_until` | optional interval for a snapshot or policy state |
| `as_of` | fixed time at which the evaluator judged relevance and freshness |

`occurred_at`, `observed_at`, and `received_at` are recorded even when they disagree.
An observation derived from an event must state how its `observed_at` was selected; it
cannot silently copy an untrusted producer time into a collector-time field. The system
does not "fix" the producer timestamp in place.

Each clock record has:

```json
{
  "id": "clock:authz-engine:01",
  "record_type": "clock_assessment",
  "schema_version": "1.0.0",
  "measured_at": "2026-07-29T03:10:00.000000Z",
  "reference": "collector-monotonic-plus-utc",
  "estimated_offset_microseconds": "2400",
  "uncertainty_microseconds": "10000",
  "evidence_ids": ["evidence:clock-check:authz:01"]
}
```

Offset and uncertainty are decimal strings because they are exact quantities. A clock
assessment has its own freshness rule. If it has expired, fine-grained temporal
correlation may become unknown even though file integrity remains valid.

Freshness is not a producer-supplied `fresh=true` flag. A claim's evidence policy
declares:

- which timestamp is authoritative for that evidence class;
- maximum age at `as_of`;
- permitted future skew;
- required valid interval overlap;
- permitted collection delay; and
- behavior when clock uncertainty exceeds the correlation window.

The evaluator returns one of:

```text
current | stale | future_dated | temporally_unresolved | not_required
```

Stale evidence stays in the bundle and can still establish a historical fact. It is
excluded from a current operating claim if that claim requires fresh evidence. The
verifier never reads the local wall clock to change an existing bundle's verdict.

## 8. Correlation, coverage, and lineage

### 8.1 Correlation strength

The runner creates `trace_id` and `request_id` before the action begins and propagates
them when the tested components permit it. A correlation link records both the
relation and its basis:

```text
exact_token       same injected unguessable test correlation value
deterministic     documented one-way derivation from the test value
explicit_parent   producer emitted a resolvable parent event ID
tuple_window      source, subject digest, action digest, and bounded time window
heuristic         analyst or probabilistic match
```

`exact_token`, `deterministic`, and a verified `explicit_parent` can satisfy the
default mechanism-correlation requirement. `tuple_window` may be allowed by a named
policy with collision analysis. `heuristic` is visible context and cannot be the sole
basis for a strong mechanism attribution.

A matching string is not sufficient if it was replayed from a prior trial. The
verifier also checks experiment, trial, reset lineage, request, and allowed time
intervals.

### 8.2 Per-source sequence and chain

There is no invented global sequence across services. Each producer has a monotonically
increasing `source_sequence` for one declared boot or stream epoch. The collector has a
separate sequence for accepted records; it does not overwrite the producer's sequence.
A stream checkpoint records:

- producer and epoch;
- first and last sequence;
- expected and observed event counts;
- gaps and duplicates;
- collection filter and time window;
- collector health evidence;
- terminal event digest; and
- any externally retained terminal digest or signed checkpoint reference.

Each event may contain the digest of the prior canonical event in that source epoch.
The first accepted event uses `null`; a chain never crosses an epoch boundary.
This chain exposes reordering or deletion only relative to a trusted checkpoint. If an
attacker can rewrite all events and `bundle.json`, the attacker can recompute the whole
chain. The chain is described as tamper-evident only when a terminal digest was retained
outside the bundle before the suspected modification. It is never described as
immutable or nonrepudiable.

### 8.3 Absence is evidence only with coverage

"No alert event was found" is not the same as "the detector did not alert." An absence
observation is admissible only when the bundle includes:

- the exact query/filter and closed time window;
- collector and source health for the full window;
- stream checkpoint or query-completeness evidence;
- no unexplained sequence gap;
- the expected event contract for this exercised path;
- sufficient post-action waiting time under the declared alert objective; and
- a correlated triggering action known to have reached the detector's input boundary.

If any of these is missing, the detective claim is `UNKNOWN` or `NOT_EXERCISED`, not
`PASS` or `FAIL` inferred from silence.

### 8.4 Reset and cleanup lineage

Every trial carries the protocol fields:

```text
trial_id, cell_id, block_id, replicate
reset_lineage, reset_epoch
declared_intervention_digest
covariate_snapshot_digest
input_seed, action_digest
```

`harness.factor_observed` must come from the declared independent probe for control or
fault factors. A runner's command echo does not prove the new state.

`harness.cleanup_verified` belongs to the trial and reset lineage it checked. A cleanup
failure contaminates only later trials that reuse the affected lineage; it does not
erase historical evidence from unrelated disposable environments.

## 9. Evidence use and admissibility

Evidence does not have an intrinsic `supports` or `rebuts` label. The same event can
support a path-outcome claim and rebut a local authorization claim. Polarity belongs to
an evidence-use edge:

```json
{
  "id": "use:selection-rebuts-local-claim:trial-003",
  "record_type": "evidence_use",
  "schema_version": "1.0.0",
  "target": {
    "type": "point_assertion",
    "id": "assertion:scope-selection-zero-out-of-case"
  },
  "evidence_ids": [
    "event:authz:trial-003:000004",
    "event:query:trial-003:000005",
    "observation:trial-003:out-of-scope-selected"
  ],
  "polarity": "rebuts",
  "inference_rule_id": "rule:authz-local-decision:v1",
  "admission_policy_id": "policy:financial-reference:v1",
  "as_of": "2026-07-29T03:14:00.000000Z"
}
```

Admissibility is evaluated per evidence-use edge, not once per artifact. The result is
a vector:

```text
structural_integrity
provenance
source_independence
scope_coverage
temporal_alignment
freshness
correlation
reproduction_consistency
minimization
```

Each dimension is:

```text
met | not_met | unknown | not_required
```

The policy declares hard requirements for each inference rule. It also records the
reason and input evidence for every dimension. There is no percentage that turns five
unknown dimensions into "83% confidence."

The admission result is:

```text
admitted | rejected | unresolved
```

- `admitted`: every hard requirement is `met` or `not_required`;
- `rejected`: at least one hard requirement is `not_met`;
- `unresolved`: no requirement is known false, but at least one is `unknown`.

Rejected or unresolved support cannot produce a supported claim. Rejected or unresolved
rebuttal cannot produce a refuted claim. It may still appear as visible context.

An integrity failure is about the evidence path, not automatically about the security
control. A corrupt log produces an evidence or harness error unless another admissible
source independently establishes the control result.

## 10. Counterevidence and defeaters

Supporting records are never deleted when rebutting records arrive. Point claim truth
uses the existing four-state representation:

```text
neither     support=0, rebut=0
supported   support=1, rebut=0
refuted     support=0, rebut=1
conflicting support=1, rebut=1
```

Defeaters are separate records:

| Type | Effect |
|---|---|
| rebutter | adds admissible rebuttal to a claim |
| undercutter | blocks one evidence-to-inference edge without asserting the opposite claim |
| scope defeater | shows that a narrower claim is required |
| run invalidator | removes one run from a contrast or point assertion |

Examples in the financial path:

- the release guard prevented delivery, but the wildcard entitlement led to an
  out-of-case selection: rebutter for entitlement and scope-selection claims, support
  for release-path prevention, and not an authorization-engine defect;
- detector timestamps cannot be correlated because clock uncertainty exceeds the
  objective: undercutter for the alert inference;
- only one synthetic product class was tested: scope defeater for an all-products claim;
- factor observation disagrees with the declared intervention: run invalidator for the
  control contrast.

A defeater has its own evidence, status, activation rule, owner when manually entered,
and lifecycle:

```text
asserted | active | resolved | superseded
```

Resolution creates a new record linked to the old one. It does not rewrite the old
decision trace. A late event creates a supplemental bundle with the original bundle ID
as a parent.

## 11. Independent recomputation

"Reproducible" is too broad unless the level is named.

### Level 0 — structural verification

- strict parsing;
- safe path and archive checks;
- file size and digest verification;
- schema validation;
- reference and provenance-graph validation.

### Level 1 — admission recomputation

- time and clock-window calculations;
- source, correlation, coverage, and freshness checks;
- evidence-use admission decisions;
- active defeaters.

### Level 2 — verdict recomputation

- point assertion predicates;
- Belnap support/rebut aggregation;
- protocol validity;
- paired contrast matching and direction;
- exercise state and non-masking result rows;
- semantic result and reason codes.

### Level 3 — observation reconstruction

- re-run every deterministic extractor from included raw artifacts;
- compare regenerated events or observations with bundled records;
- verify extractor binary or image, configuration, and declared output.

A `full-synthetic` release should target Level 3 because no real secrets are needed.
A bundle with an opaque SaaS query or intentionally withheld input may support only
Levels 0–2. The UI and report state that limitation instead of displaying the same
"verified" badge.

A digest is not a runnable extractor. The full profile either includes the exact
extractor package plus a locked execution description, or names a locally installed
trusted implementation with the same digest. The verifier never executes code merely
because it arrived inside a bundle. Level 3 is an explicit opt-in sandbox operation
with no network, read-only inputs, an empty writable directory, and CPU, memory, output,
and wall-time limits.

The bundled `derived/protocol-report.json` and `derived/semantic-result.json` are
expected outputs, not trusted inputs. The verifier recomputes them and compares:

- all canonical enum states;
- claim, assertion, contrast, and check identifiers;
- admitted support and rebuttal evidence IDs;
- active defeaters;
- exercise states;
- residual paths;
- effect direction; and
- machine-readable reason codes.

Human prose, display ordering, creation timestamps, and UI labels are excluded from the
semantic result hash.

The bundle pins:

- experiment and claim specifications;
- evidence policy and event contracts;
- evaluator version, source revision, and image digest;
- extractor versions and digests;
- schema major versions; and
- random seeds and trial ordering.

The public verifier should also support a clean-room mode using its locally trusted
schemas and policy implementation. A malicious bundle cannot replace the verifier's
schema or executable merely by including another file with a plausible name.

## 12. Partial, withheld, unsupported, and corrupt bundles

These states are different:

| State | Meaning |
|---|---|
| complete | every file required by the declared profile is present and valid |
| intentionally_withheld | a descriptor says an item was omitted under a named sharing policy |
| unsupported | the verifier does not implement the declared schema major or algorithm |
| corrupt | listed bytes are absent, changed, duplicated, unsafe, or unparsable |

An intentionally withheld item appears in `records/omissions.jsonl` with:

- stable metadata ID;
- evidence class and role;
- omission reason;
- whether a content digest was also withheld;
- affected claims, inferences, and recomputation level; and
- approving sharing-policy version.

The manifest does not list a nonexistent path. Required evidence withheld for privacy
forces the affected inference to unresolved. It cannot be replaced with a green
"metadata verified" result.

Missing listed bytes are corruption, not an approved omission. An unknown schema major
is unsupported, not evidence that the control failed. A verifier may salvage and show
independently valid records from a corrupt bundle for diagnosis, but it cannot issue a
normal control verdict from the quarantined bundle.

## 13. Digests, signatures, and external anchors

SHA-256 is used for content addressing and integrity checks. If an attacker changes a
payload and recomputes `bundle.json`, hashes alone do not expose the rewrite.

Signatures use a detached
[DSSE](https://github.com/in-toto/attestation/blob/main/spec/v1/envelope.md) envelope
over the canonical `bundle.json` bytes with a project-specific payload type. DSSE
separates payload type from payload bytes and avoids ambiguous signing formats. An
optional in-toto Statement may name the root digest as its subject when integration
with supply-chain tooling is useful.

For public releases, a
[Sigstore bundle](https://docs.sigstore.dev/about/bundle/) can carry the certificate,
transparency-log material, and signed timestamp needed for offline signature
verification. This is an adapter, not a custom signature system.

Trust policy is supplied outside the evidence bundle:

- accepted issuer and subject identity;
- accepted public keys or Sigstore identities;
- required signature threshold;
- permitted algorithms;
- signing-time policy; and
- revocation or trust-root update policy.

This matters because the bundle cannot securely declare, "trust the key included in
this same bundle." A removed signature is caught only when external policy requires
one. A cryptographically valid signature from an untrusted identity is not accepted.

Shared-key HMAC is not used for public independent verification because every holder
can create an indistinguishable signature.

A verified signature proves that a matching key authorized the canonical root under
the verifier's policy. It does not prove:

- that a source event was honest;
- that collection was complete;
- that the signer personally reviewed the evidence;
- that the source or signing key was uncompromised;
- legal chain of custody or legal admissibility; or
- nonrepudiation in the general sense.

An externally retained terminal digest, signed checkpoint, transparency-log entry, or
trusted timestamp can strengthen evidence that a particular root existed before a
later time. It still does not make the evidence immutable.

## 14. Privacy, redaction, and publication

Version one accepts only synthetic scenario evidence. The publication gate rejects:

- raw access, refresh, session, API, or registry tokens;
- raw authorization headers, cookies, or credentials;
- street, email, IP, MAC, or account-like addresses;
- payload rows or record contents;
- realistic personal identifiers; and
- private keys or reusable certificates.

Allowed records use:

- synthetic IDs such as `syn:person:analyst-01`;
- reserved names such as `authz.fin-lab.example.invalid`;
- record counts;
- policy, query-plan, payload, token, and entitlement-set digests; and
- categorical decisions and reason codes.

A digest is not automatically safe. Hashing a low-entropy address, employee number, or
small payload can permit guessing. Public bundles omit both the value and its digest
when membership disclosure is a concern.

Redaction is a derivation:

```text
raw synthetic artifact
  -> named redactor version and configuration
  -> redacted artifact with new digest
  -> redaction record linked to the input
```

The redacted artifact is never labeled raw. A public derivative receives a new bundle
ID and links to its parent only when that link does not reveal sensitive information.

Automated secret and identifier scanning is a release gate, not a proof that no
sensitive data remains. It is backed by manual inspection for the small reference
dataset. The project does not claim to be a general data-loss-prevention product.

Encryption of bundle payloads is deferred from the public v1 format. Hashing ciphertext
would permit structural verification without decryption but not verdict recomputation;
hashing plaintext in a public manifest can leak information. Synthetic-only bundles
avoid pretending that this trade-off has already been solved.

## 15. Schema evolution and migration

Bundle, event, observation, and policy schemas have independent semantic versions:

- major: incompatible meaning or representation;
- minor: additive fields or record types with unchanged existing meaning;
- patch: clarification or stricter validation that does not reinterpret accepted data.

The verifier rejects an unknown major version. It may preserve unknown namespaced
extension fields, but an extension cannot satisfy a core required check unless a
locally trusted plugin understands it.

Migration never rewrites signed source bytes:

1. verify the old bundle with the old schema;
2. run a named migrator with pinned code and configuration;
3. emit new records linked with `derived_from`;
4. include a migration report and old semantic bundle ID;
5. recompute with the new schema; and
6. finalize and optionally sign a new bundle.

A signature on the old root remains a signature on the old representation. It is not
copied onto the migrated root.

Each supported migration has golden vectors covering:

- canonical byte output;
- preserved identifiers and typed values;
- explicitly changed semantics;
- unknown extension handling;
- round trips where promised; and
- refusal cases where lossless migration is impossible.

## 16. Verification order

The verifier fails closed in this order:

1. Apply archive size, file count, per-file size, compression-ratio, nesting, and
   processing-time limits.
2. Reject absolute paths, traversal, symlinks, hardlinks, duplicate entries, and
   normalization or case-fold collisions without extracting them.
3. Strictly parse `bundle.json`; reject duplicate JSON keys and unsupported root media
   types.
4. Canonicalize the root and compute the semantic bundle ID.
5. Verify every payload size and SHA-256 digest while streaming.
6. Enforce the external signature policy when one was requested.
7. Validate trusted schemas and reject dangling or type-invalid references.
8. Validate provenance DAGs, activity inputs/outputs, source epochs, sequences, and
   trial lineage.
9. Recompute clock intervals, coverage, correlation, freshness, and evidence admission
   at the bundled `as_of`.
10. Recompute point claims, contrasts, protocol checks, defeaters, residual paths, and
    semantic result.
11. Compare recomputed outputs with bundled derived outputs.
12. Report structural verification, admission recomputation, verdict recomputation,
    and observation reconstruction as separate levels.

The verifier emits diagnostics even when it abstains, but it never converts a parser,
integrity, or harness error into a security-control failure or pass.

## 17. Adversarial and regression tests

The evidence subsystem is not ready when it serializes a happy-path bundle. At minimum,
the test corpus must include:

### Canonicalization and parser cases

- object keys reordered, whitespace changed, and semantically identical JSON producing
  the same JCS digest;
- duplicate keys including escaped-equivalent names;
- invalid UTF-8, lone surrogates, non-normalized paths, and case collisions;
- `NaN`, infinity, negative zero, unsafe integers, and ambiguous numeric coercions;
- a deeply nested object, huge string, huge array, and overlong JSONL line; and
- record and file ordering permutations that preserve the semantic result.

### Archive and integrity cases

- one changed byte, truncated file, missing listed file, unlisted file, duplicate
  filename, traversal path, symlink, and decompression bomb;
- a file and root manifest both rewritten with no external signature, demonstrating
  that hashes alone cannot identify the rewrite;
- a stripped signature when external policy requires one;
- a valid signature from the wrong identity;
- a DSSE payload-type substitution; and
- a source hash chain rewritten with and without an externally retained terminal
  digest, proving the precise boundary of the chain.

### Provenance and lineage cases

- unknown producer, collector, extractor, artifact, event, or trial reference;
- provenance cycle and transformation output that overwrites an input ID;
- runner self-report mislabeled as an independent factor probe;
- event copied across cells or replicates;
- duplicate, missing, decreasing, or replayed source sequence;
- reset lineage contamination after failed cleanup; and
- extractor version changed without a new activity record.

### Time and correlation cases

- stale snapshot, future-dated event, late arrival, expired clock assessment, and clock
  uncertainty wider than the alert objective;
- reused trace ID from an earlier reset epoch;
- guessed or duplicated correlation token;
- only a heuristic link where exact correlation is required; and
- event timestamps that appear ordered but whose uncertainty intervals overlap.

### Admission and counterevidence cases

- support with no evidence;
- rebuttal with no evidence;
- support and rebuttal together yielding conflict;
- stale support that remains in history but cannot pass a current claim;
- alert absence with a healthy complete stream versus alert absence with an unexplained
  gap;
- requested session revocation without verified state change;
- entitlement and scope-selection failure masked by release guard success;
- downstream control not reached and therefore `NOT_EXERCISED`;
- an integrity-defective collector record plus independent admissible runtime evidence;
  and
- evidence-use duplication that does not strengthen a verdict.

### Recalculation and privacy cases

- bundled derived report altered while canonical inputs remain unchanged;
- local wall clock, file iteration order, locale, and timezone changed without changing
  the recomputed result;
- Level 2 success with an explicitly unavailable Level 3 extractor input;
- malicious bundled schema or executable ignored by clean-room verification;
- migration that loses a typed distinction and is therefore rejected;
- secret, token, realistic address, personal identifier, and low-entropy digest seeded
  into a release candidate; and
- a redacted derivative that accidentally retains the raw artifact or old digest.

Several tests should be negative demonstrations rather than expected successes. In
particular, rewriting an unsigned bundle and recomputing every digest should pass
internal integrity while failing external-origin policy. That result teaches the
actual boundary better than a broad "tamper-proof" claim.

## 18. Honest non-claims

Public documentation and UI must not say that the bundle:

- is tamper-proof, immutable, or automatically nonrepudiable;
- establishes legal admissibility or a forensic chain of custody;
- proves that a signed source event was true;
- proves collection completeness without coverage evidence;
- proves production effectiveness from a synthetic experiment;
- is current after its declared `as_of`;
- proves protection against an untested input, product, path, or environment;
- certifies ISMS-P, an electronic-finance regulation, or any other framework;
- contains no sensitive data merely because a scanner passed;
- reproduces raw observations when its declared verification level stops at Level 2;
  or
- turns a missing event into evidence of a missing action.

The strongest accurate sentence is narrower:

> Given the included synthetic inputs, the pinned schemas and policies, and the stated
> trust assumptions, an independent verifier reproduced these admissibility and
> control-assessment results as of the recorded time.

## 19. First implementation slice

The first implementation should not begin with signatures. It should produce one
unsigned, full-synthetic bundle that supports Level 3 reconstruction and catches its
own false-assurance cases.

Order:

1. Strict canonical JSON and JSONL writer plus hostile parser tests.
2. Root manifest, content-addressed artifacts, and safe directory verifier.
3. Source, activity, financial event, observation, and provenance-link schemas.
4. Fixed `as_of`, clock assessments, source sequence, and coverage checkpoints.
5. Evidence-use admission with explicit support, rebuttal, and undercutting.
6. Independent semantic-result recomputation from observations.
7. Raw-artifact extraction replay for the synthetic event producers.
8. Privacy release gate and redacted-derivative test.
9. Deterministic transport archive.
10. DSSE and optional Sigstore adapter under an external trust policy.

This order is deliberate. Signing an evaluator output before the evidence graph can
expose a masked entitlement and scope-selection failure would preserve the wrong
conclusion more reliably; it would not improve the assurance model.
