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
