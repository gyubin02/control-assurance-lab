# Offline DSSE verification fixture

This directory is a complete synthetic fixture for the repository's narrow
Control Assurance DSSE Profile v1. The envelope signs the exact bytes in
`payload.json` as `application/json`. The independently supplied policy contains
only the corresponding synthetic public key.

From the repository root:

```bash
assurance-lab dsse verify \
  --envelope examples/dsse-v1/envelope.json \
  --policy examples/dsse-v1/trust-policy.json \
  --payload examples/dsse-v1/payload.json \
  --payload-type application/json \
  --at 2026-07-29T12:00:00Z \
  --json
```

The result must exactly match `expected-verification.json`. Changing the payload,
payload type, policy, envelope, or caller-trusted verification instant can
change the decision.

The key and content are synthetic. A successful result establishes an exact
signature decision under the supplied policy and time. It does not establish
freshness, consume a job lease, create durable custody, or prove that a
production control operated effectively.
