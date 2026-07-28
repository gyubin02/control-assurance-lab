# 0004 — The case note must earn its own numbers

Status: accepted for Case Note 01.

## Problem

The web page is a static exhibit. If it merely reads `case.json`, a changed label or
hand-edited number can tell a different story from the checked-in evidence while the
page still looks authoritative.

Copying the Python evaluator into JavaScript would create a second, slowly diverging
implementation of the experiment semantics. That is not a useful kind of
independence.

## Decision

The page fails closed until the browser has:

- hashed the raw `bundle.json` bytes and matched the case bundle ID;
- checked the size and SHA-256 digest of every listed bundle file;
- tied each displayed value to the exact hashed JSONL line that contains it;
- tied the matrix labels and normal-service cells to their attested interventions;
- tied the initiating request to the fixture and verified experiment contract; and
- recalculated the four current point claims and the masked-failure classification
  from the verified safe values.

The browser does **not** claim to recompute protocol completeness or the full
interventional contrasts. The page tells the reader to run the CLI for that result.

## Why this boundary

The browser now checks the parts it presents, so it cannot silently turn into a
screenshot of stale or relabelled facts. The CLI remains the only semantic evaluator,
so there is still one definition of a complete 16-cell experiment.

Two mutations are part of the release check: changing a byte in a listed artifact
must stop the page at the digest gate, and changing only a matrix factor label must
stop it at the attested-selector gate.

## Limit

This establishes consistency inside an integrity-only bundle. It does not authenticate
the publisher or provide an external trusted digest. Someone able to replace the
entire site and bundle can publish a different internally consistent case; that
requires a separate origin-signing design.
