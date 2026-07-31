# CAB integrity verifier

This directory contains a second implementation of the Control Assurance Bundle
integrity boundary. It uses Node's standard library only: it does not import the
Python evaluator, invoke a subprocess, or consume a verdict produced by Python.

```bash
cd verifier-js
npm test
npm run verify:example
```

The verifier starts from one bundle directory and checks:

- strict UTF-8 JSON parsing, including duplicate keys and trailing data;
- canonical JSON and canonical, ID-sorted JSONL payloads;
- the supported v1 manifest shape and `cab:sha256:<manifest bytes>` identifier;
- an exact, portable tree with no symlinks, hard links, traversal, extras, or gaps;
- each declared byte length and SHA-256 digest; and
- a stable root, manifest, and payload observation during the call.

Result schema `1.1.0` keeps the diagnostic surface bounded. Issues are deduplicated
and sorted by `(path, code, detail)`, then constrained by both a count budget and a
canonical-byte budget. `issue_summary` records the total, reported, and suppressed
counts, per-code counts, and a SHA-256 commitment to the complete canonical sorted
issue set. A different filesystem enumeration order therefore cannot change the
reported prefix or the commitment when the observed issue set is the same. The
entire serialized result has a separate 1 MiB hard limit.

The CLI exits `0` only for `integrity_verified`, `1` for a completed negative or
unsupported verdict, `2` for command-line usage, and `3` when verification or
serialization itself did not complete. Exit `3` still emits one small fixed
`verifier_error` JSON object to standard output and does not expose an exception
or host path.

The JSON result says `claim_scope: "integrity-only"` deliberately. Replacing a
payload and coherently rebuilding `bundle.json` produces a new valid bundle ID and
passes this layer. There is no signature, trusted timestamp, transparency log, or
externally pinned digest here, so this verifier does not identify the producer or
make the mutable directory immutable. It also does not evaluate scenario verdicts.

## Independent benchmark semantics

`benchmark-verify` is a separate, standard-library-only verifier for the fixed
three-scenario lifecycle benchmark. It does not invoke Python or accept the
producer's verdict as an input to its decision. Starting from the release index,
the claimed semantic result, and three CAB snapshot byte strings, it:

- rebuilds the compiler's 3 × 16 × 3 trial coordinates and frozen action bindings;
- resolves actions, runtime observations, clone attestations, and the recovery
  matched-pair proof by their manifested byte digests;
- recomputes detection, response, and recovery semantics from the raw runtime
  rows and embedded lifecycle documents;
- requires all three replicates to agree without voting; and
- compares one normalized semantic projection with the claimed result.

```bash
cd verifier-js
RELEASE=../path/to/built-release
node ./src/benchmark-cli.js \
  --index "$RELEASE/index.json" \
  --semantic "$RELEASE/semantic/primary.json" \
  --source "financial-entitlement-recovery=$RELEASE/sources/financial-entitlement-recovery.cab.snapshot" \
  --source "financial-exact-correlation-detection=$RELEASE/sources/financial-exact-correlation-detection.cab.snapshot" \
  --source "financial-exact-session-response=$RELEASE/sources/financial-exact-session-response.cab.snapshot"
```

`RELEASE` must point to the completed directory returned by Python's
`assurance_lab.benchmark.release_builder.build_public_release`; the verifier
does not invent or download a release tree.

Exit `0` means the independent projection agreed, `1` means it completed with a
negative result, `4` means the runtime schema is not supported, and `3` means the
verification call itself did not complete. Unknown runtime schemas never become a
positive result. The receipt is canonical JSON and content-addresses its inputs,
both semantic projections, the verifier source identity, and the receipt body
itself.

The public-source profile is closed rather than merely well-formed. Each source
must carry the pinned v1 manifest, its one embedded producer snapshot, the exact
producer witnesses used by the frozen corruption corpus, the three benchmark
core documents, and only the expected number of content-addressed object
members. Every object member must be resolved while validating the 48 trials;
an extra, unreachable object is rejected even if an attacker rebuilds every
surrounding digest.

The CLI does not accept a caller-selected implementation identity. Before reading
benchmark inputs it hashes raw `package.json` bytes and every sorted regular
`src/*.js` file into a canonical source-set manifest, then records that digest and
the pinned implementation ID in the receipt. Source files and benchmark inputs
are opened with `O_NOFOLLOW`, must have one hard link, and are bound to the same
opened inode, size, mode, link count, and timestamps before and after each read.
This makes a receipt bind the complete on-disk verifier source set observed for
the call before benchmark inputs are read. It is not execution attestation: Node
loads these modules before the identity pass, and the receipt does not identify
the already-loaded module bytes, the Node binary, or the host.
All package, source, and directory handles remain open through a final global
identity and name-binding pass. The source directory entry set is enumerated
again, every file is restatted and reopened without following links, and the
package and source directories are rebound before a receipt can be emitted.
Reviewers should still pin that digest from a reviewed release and reproduce the
call in a controlled, immutable checkout. The verifier does not add an author
signature, trusted time, software provenance, or authority to the underlying
CABs.

## Elastic Security capture verification

`elastic-capture-verify` is a third, independent path for the read-only Elastic
Security connector receipt. It receives three values from outside the receipt:
the exact connector request, the expected endpoint-origin digest, and the
expected connector version. That separation matters. Rewriting the request in a
receipt and then repairing every request body and digest does not change what the
reviewer intended to collect.

```bash
cd verifier-js
node ./src/elastic-security-cli.js \
  --receipt ../capture/receipt.json \
  --expected-request ../capture/expected-request.json \
  --expected-endpoint-origin-digest sha256:... \
  --expected-connector-version 0.1.0 \
  --records-output ../capture/records.jsonl
```

The expected request is canonical JSON and includes a fresh 256-bit
`capture_nonce`. The endpoint digest should be computed by a trusted caller from
the normalized Elastic origin; the origin itself does not have to enter the
receipt. The output file must not already exist.

The verifier rebuilds the open-PIT target, every search body, and the final close
body. It checks strict total and shard accounting, changing PIT identifiers,
`search_after` lineage, globally increasing cursors, the required final empty
page, and closure of the latest PIT. Each hit must fall inside the requested
half-open time window, and its one `fields.@timestamp` value must equal its sort
timestamp. The capture's microsecond duration must exactly connect its canonical
start and finish instants. The canonical record JSONL, count, and digest are
derived from those exchanges; no producer-supplied verdict or record summary is
consumed.

The canonical CLI summary commits to the expected-request digest, endpoint-origin
digest, connector version, a fixed Elastic verifier ID, and the source-set digest
of the Node package observed immediately before and after verification. As with
the benchmark verifier, that on-disk source identity is useful for reproduction;
it is not execution attestation for the modules or Node binary already loaded.

This is deliberately a receipt-consistency claim, not server attestation. A
party able to replace all response bytes coherently can still construct a
different internally consistent receipt. TLS validation protects the live
transport, while an outer signature or attestation must bind the captured bytes
to an authorized collector and reviewed verifier. The CLI reports
`source_authenticity: "not-established"` and `source_version: null` instead of
inventing either fact.

## Microsoft Defender XDR capture verification

`defender-xdr-capture-verify` independently verifies the fixed-profile Microsoft
Graph `security/runHuntingQuery` receipt produced for Defender XDR `AlertInfo`.
It accepts the intended request, endpoint-origin digest, and connector version
from outside the receipt:

```bash
cd verifier-js
node ./src/defender-xdr-cli.js \
  --receipt ../capture/receipt.json \
  --expected-request ../capture/expected-request.json \
  --expected-endpoint-origin-digest sha256:... \
  --expected-connector-version 0.1.0 \
  --records-output ../capture/records.jsonl
```

The expected-request file must be canonical JSON and contains the exact UTC
half-open window, fixed request profile, safety limit, capture identifier, and a
fresh 256-bit nonce. The verifier reconstructs both the KQL and canonical Graph
request body rather than accepting a query from the receipt. It then checks the
single-exchange lifecycle, safe header allowlists, response media type, exact
`AlertInfo` schema, the leading server-side count row, count closure, safety-limit
non-saturation, seven-digit UTC timestamps, deterministic row ordering, and the
requested half-open time boundary.

The output records and their digest are derived again as canonical JSONL. The
Node test suite also feeds the same receipt to the Python and Node verifiers and
requires byte-identical record streams and digests. Neither implementation
treats internal consistency as Microsoft attestation: a coherent replacement of
the captured response remains possible outside a separately authenticated
collector boundary. Accordingly, the summary says
`source_authenticity: "not-established"` and leaves `source_version` null.

## Supported JSON domain

Canonicalization follows RFC 8785's ECMAScript serialization and UTF-16 property
ordering for JSON values representable by Node. This profile additionally rejects
non-finite values, negative zero, binary64 underflow to zero, integral values
outside the I-JSON safe-integer range, unpaired Unicode surrogates, oversized input,
deep nesting, and oversized collections. Canonical JSONL is LF-terminated, contains
one canonical object per line, and has no more than 100,000 unique string `id`
values in Python Unicode code-point order. That last rule deliberately matches the
Python CAB writer; RFC 8785's UTF-16 rule still applies to object property names.

Each file is opened with `O_NOFOLLOW`, then inspected, read, and inspected again
through the same `FileHandle`. Binary payloads are hashed through a fixed 64 KiB
buffer; only canonical JSON/JSONL bytes are retained, after their JSON byte limit
has been checked from the open handle. Directory entries are consumed with
`opendir` rather than materializing an unbounded directory first. File, directory,
entry, per-file byte, total-byte, and depth limits stop the verification before
payload I/O once a complete tree snapshot cannot be obtained. Caller-supplied
limits must have the exact supported shape, use positive safe integers, and satisfy
the documented nested byte relationships; malformed configuration fails closed.
A platform without `O_NOFOLLOW` fails closed.

Node does not expose the descriptor-relative `openat(O_NOFOLLOW)` directory
traversal used by the hardened Python verifier, however, so callers must still
provide a bundle whose parent directories cannot be swapped by an untrusted
concurrent writer while verification is in progress. In deployment, copy or
extract an untrusted CAB into a private local-filesystem snapshot, close every
writer, and verify that snapshot. A mutable shared workspace or an SMB/NFS mount is
outside this verifier's race-resistance claim. Service deployments must also bound
worker concurrency and wall-clock time; the byte limits do not make a slow or
hostile filesystem responsive.
