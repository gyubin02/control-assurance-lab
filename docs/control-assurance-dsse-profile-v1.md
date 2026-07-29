# Control Assurance DSSE Profile v1

This profile uses the DSSE v1 pre-authentication encoding:

```text
DSSEv1 SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload
```

It deliberately accepts less than the general DSSE protocol. The narrower
wire contract is part of the trust boundary, not an accidental parser choice.

## Wire contract

- The envelope is UTF-8 JSON with no duplicate object members.
- `payloadType`, `payload`, and `signatures` are the only envelope members.
- Every signature has a required `keyid` and `sig`.
- Payload, signature, and public-key values use padded, canonical **standard**
  RFC 4648 base64. URL-safe base64 is not accepted.
- Signatures are Ed25519 only: a 32-byte public key and a 64-byte signature.
- The verifier compares the decoded payload type and payload bytes with the
  caller's exact expected values before admitting any signature.
- Trust comes only from the external policy. An envelope cannot introduce its
  own key.
- Every signature present must resolve to a known, eligible policy key with a
  distinct signer identity and must verify successfully. Unlike a general DSSE
  threshold verifier, this profile does not skip an unknown, ineligible, or
  invalid signature and count only the remaining valid signatures.

These rules mean that a valid general DSSE envelope with an omitted `keyid` or
URL-safe base64 may be rejected by this profile.

## Resource contract

| Input | Limit |
|---|---:|
| Envelope JSON | 4 MiB |
| Decoded payload | 2 MiB |
| Signatures | 64 |
| Envelope JSON depth | 4 |
| Canonical trust-policy JSON | 1 MiB |
| Trusted keys | 256 |
| Allowed payload types per key | 16 |
| Trust-policy JSON depth | 5 |

The envelope and policy byte caps, decoded-payload cap, container depths, and
collection counts listed above are preflighted before JSON materialization,
Pydantic validation, or signature base64 traversal. A programmatically supplied
policy is bounded, copied into built-in primitive containers, and fully
reconstructed at the verification boundary.
`model_copy()` and `model_construct()` therefore do not confer trust.

Key ids, signer identity labels, and raw Ed25519 public keys must be unique
where they contribute to threshold admission. Two labels backed by one private
key are one authority, not two.

## Decision provenance

`AttestationVerification` binds a successful decision to:

- the raw envelope SHA-256;
- the expected payload SHA-256 and payload type;
- the canonical external policy SHA-256 and policy id;
- the normalized trusted admission time;
- this profile and verifier implementation id; and
- the accepted key ids, identities, and required threshold.

Receipt construction should consume `AttestationVerification.canonical_bytes()`,
which revalidates decision coherence before serialization.

The object is an input to an admission receipt, not the receipt itself. The
admission ledger still has to bind the job/lease identity, collector epoch and
sequence, replay checkpoint, verifier artifact deployed by the institution,
raw-envelope custody location, ledger sequence, and previous receipt digest in
one durable transaction. Signature verification does not establish freshness,
trusted time, private-key custody, immutable storage, or regulatory compliance.
