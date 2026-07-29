# 0010 — Benchmark results are recomputed, not asserted

Status: accepted

## The failure we are preventing

A strict result schema can still describe a fiction.

An evaluator could publish 144 internally consistent `SUPPORTED` trials, point
each scenario at a digest-shaped string, and never supply the raw observations
behind those conclusions. Likewise, twenty internally consistent corruption
receipts do not prove that twenty different mutations were applied to real
bundle bytes.

Content addresses close this gap only when a verifier resolves and checks the
addressed bytes. A receipt that merely repeats an address is not that check.

## Decision

Release admission begins with bytes, not already-instantiated model objects.

1. Benchmark JSON is parsed under one byte, depth, collection, and string
   profile. Duplicate keys and non-canonical wire encodings are rejected.
2. Typed values returned by collaborators are dumped to JSON primitives and
   revalidated. `model_copy` and `model_construct` never confer admission.
3. A raw benchmark admission resolves each indexed source CAB by its exact
   snapshot digest. The CAB contains the compiled specification, frozen plan,
   and raw trial set. Admission recompiles the ordinary experiment contract
   and the benchmark plan from the compiled specification, then byte-compares
   that result with the supplied plan. The corpus digest is recomputed over
   every index edge plus those three recompiled plans; it is never accepted as
   a caller-authored label.
4. The combined corpus checks the exact 16 × 3 compiler order and global
   uniqueness of all 144 trace, clone, readback, attestation, and runtime
   artifact identities.
5. A semantic admission resolves every action and runtime artifact from the
   same verified source CAB by content digest, checks the schema named by each
   reference, and proves that every attestation digest has a manifested CAB
   member. It then invokes the scenario verifier directly. Every result
   lineage field and semantic vector must equal the independent recomputation.
   The index binds the exact top-level and per-scenario result bytes.
6. C01–C20 are frozen specifications, not caller-selected labels. Corruption
   admission locates an exact record and JSON Pointer in the admitted source
   CAB, applies the frozen mutation recipe, and deterministically encodes the
   result. It proves that `KEEP` leaves a stale manifest and that `REBUILD`
   produces a new integrity-verified CAB. It then compares the complete
   corrupted bytes and before/after witnesses with the index and requires a
   verifier receipt bound to the exact inputs, mutation, result, and pinned
   verifier identity.
7. `admit_benchmark_release` resolves the three source CABs once and admits the
   raw corpus, semantic result, and twenty corruptions against that one
   in-memory resolution. Separate convenience entry points repeat the same
   source admission; they do not accept a pre-admitted index or corpus.

There is no public “verified” Boolean or DTO that a caller can inject. The
admission functions perform the work themselves and return the ordinary parsed
model only after all checks succeed.

## Resource contract

Nested issues have aggregate cell, scenario, and benchmark limits. The largest
valid semantic result remains below the same 16 MiB canonical JSON limit used
by the parser and content-addressing path.

This is an admission limit, not a recommendation to publish multi-megabyte
diagnostics. Compact normalized issues remain the expected form.

## Supported corruption wire profile

The first release deliberately supports one concrete representation:

- a deterministic, bounded CAB snapshot with an integrity-verified
  `bundle.json`;
- exact compiled-specification, frozen-plan, and raw-trial-set members;
- canonical JSON object targets or canonical JSONL targets whose records have
  unique, lexically sorted string `id` values; and
- the frozen `replace`, `remove`, `remove-array-item`, `copy-from-record`, and
  `swap-with-record` recipes used by C01–C20.

This is not a claim to mutate arbitrary archives, databases, protobufs, or
production evidence formats. A future representation needs its own canonical
locator and replay profile before it can enter release admission.

## External responsibilities

The source-CAB resolver and verifier implementation must be pinned and
authenticated by release policy. Scenario verifiers still own the semantic
meaning of their declared action and runtime schemas and must derive that
meaning from raw observations. The corruption verifier must independently
evaluate the concrete corrupted CAB; returning a verdict enum is insufficient.

This decision does not authenticate any resolver, verifier, or producer. It
does not establish freshness, signature trust, durable custody, WORM retention,
or external immutability. Those remain separate admission and institutional
policy responsibilities.

## Consequences

- A digest-shaped string without resolvable bytes cannot support a positive
  benchmark result.
- Rebuilding every dependent digest does not make a forged semantic result
  admissible.
- Reusing one experiment's runtime artifacts in another experiment fails the
  combined-corpus boundary.
- A corruption receipt with an invented before/after digest, an absent or
  ambiguous locator, a no-op replay, a substituted corrupted CAB, the wrong
  C02/C17/C18 manifest policy, or an unbound verifier result is rejected.
- The framework can replay C01–C20 over the canonical benchmark CAB profile.
  Publishing the final public corpus still requires the scenario-specific
  semantic verifiers, an independent corruption verifier, and release-policy
  authentication of those implementations.
