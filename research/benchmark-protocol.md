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

The released corruption generator must be deterministic and must prove whether it
rebuilt the manifest. A `KEEP` case must retain the exact source manifest and fail
CAB integrity. A `REBUILD` case must carry a changed manifest and pass CAB integrity.

### Frozen corruption representation

The first release freezes one representation instead of claiming a generic
mutation engine. A source is a bounded deterministic CAB snapshot. Mutation
targets are either one canonical JSON object or canonical JSONL records with
unique, lexically sorted string `id` fields. Each C01–C20 entry fixes:

- the source scenario and CAB member path;
- the exact record selector (`$` for the single root object of a `.json`
  member, or the producer-owned `id` of one `.jsonl` record) and JSON Pointer;
- one complete operation and all of its operands;
- `KEEP` or `REBUILD`; and
- the required negative verifier result.

The operation set is limited to replacement, removal, array-item removal,
copy-from-record, and swap-with-record. The replay engine extracts the real
before value, performs that exact operation, canonicalizes the target member,
and encodes the complete CAB. It does not accept a collaborator-authored
“execution” object. Archives, binary databases, protobufs, and other production
representations are outside this profile until they define an equally precise
canonical locator and replay contract.

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

### Release admission boundary

The common benchmark package does not accept a result model as proof of its own
contents. `admit_benchmark_release` resolves the source corpus once and then
admits the semantic and corruption corpora against that same resolution:

- parses canonical bytes with duplicate-key and resource limits;
- resolves every source CAB by the snapshot digest in the index and verifies its
  manifest;
- loads the exact compiled specification, recompiles its ordinary experiment
  contract and benchmark plan, and byte-compares the result with the supplied
  frozen plan;
- recomputes the corpus digest over every index edge and the exact three
  recompiled plan digests;
- binds the index to the exact three raw trial sets and rejects any lineage or
  runtime-artifact reuse across all 144 executions;
- resolves every action and runtime artifact by content digest from that same
  CAB, checks its declared schema, and requires a CAB member for every
  attestation digest before invoking the scenario-specific verifier;
- requires every semantic trial and aggregate to equal that independent
  recomputation; and
- binds both the per-scenario and top-level semantic result bytes to the index.

C01–C20 follow the same rule. Their mutation type, source scenario, locator,
complete recipe, manifest policy, and expected verifier result are frozen. A
release verifier replays each mutation against the already admitted source CAB,
compares the complete corrupted bytes, verifies before/after witnesses, and
proves the manifest policy. The independent verifier must return a typed receipt
that binds its pinned identity, the source and corrupted digests, the mutation
specification digest, the normalized negative issues, and the result. The outer
corruption receipt addresses that exact verifier receipt. A bare verdict or a
receipt alone is never accepted as evidence that the mutation happened.

The final public corpus still depends on scenario-specific artifact semantics
and an independent second verifier. Resolver/verifier authentication, signature
trust, freshness, custody, and external immutability remain outside this
benchmark model.

## Stop conditions

The benchmark is not ready for release if any of the following is true:

- a seeded fault is detectable only through a hard-coded expected verdict;
- the verifier trusts a derived case file over raw events;
- a missing or stale artifact still produces `SUPPORTED`;
- one experiment's evidence is reused as another experiment's observed result;
- the current state can come from a matched comparison;
- the disclosed-history ledger can shrink; or
- the README describes a stronger result than the released corpus establishes.
