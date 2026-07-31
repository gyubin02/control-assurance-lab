# Microsoft Defender XDR operations and live conformance

The Defender connector has one read-only purpose: collect `AlertInfo` rows from
Microsoft Graph `POST /v1.0/security/runHuntingQuery` for an exact half-open UTC
window. It requires the application permission `ThreatHunting.Read.All`.

The connector does not accept arbitrary KQL, change alerts, isolate devices, or
call a beta endpoint. Its fixed query projects a bounded column set, adds a
server-side count row, sorts deterministically, and requests one row beyond the
configured safety limit. A saturated, truncated, malformed, redirected, or
compressed response fails closed.

## Production identity boundary

`ProductionRuntimeWorkerFactory` supports two client-credential modes:

- an Entra client assertion signed with one exact Azure Key Vault RSA key
  version and checked against the registered public certificate; or
- a projected federated RS256 assertion bound to the configured issuer,
  subject, audience, and source file.

The exact-version credential profile is resolved through Azure workload
identity. Token acquisition is journaled in the tenant-bound PostgreSQL PAM
store before the token is exposed to one connector call. Token bytes are not
written to the journal, connector receipt, evidence bundle, or object
representation.

Microsoft does not provide per-token attenuation below the application
permission. Use a dedicated application registration, grant only
`ThreatHunting.Read.All`, and review its assignment outside this program. Key
Vault roles, private endpoints, conditional access, Entra audit retention, and
certificate rotation remain deployment controls. See
[Azure workload identity](azure-workload-identity.md) and
[Azure Key Vault key management](azure-key-vault-key-management.md).

## Opt-in live connector test

`tests/integration/test_defender_xdr_live.py` calls a real Defender XDR tenant.
Ordinary CI has no tenant credential and skips the test. Choose a closed window
whose expected `AlertInfo` count was established independently; the test must
not learn its expected answer from the response it is evaluating.

Deliver a short-lived Graph bearer token as exact bytes in a private regular
file with no trailing newline. The test refuses a symlink, a hard-linked file,
group/world permissions, an empty token, an oversized token, or a file that
changes while read. Do not place the token in a command-line argument, shell
history, repository file, or test output.

Set:

| Variable | Meaning |
|---|---|
| `CONTROL_ASSURANCE_DEFENDER_XDR_TOKEN_FILE` | Absolute path to the owner-only bearer-token file |
| `CONTROL_ASSURANCE_DEFENDER_XDR_START` | Inclusive whole-second UTC start, `YYYY-MM-DDTHH:MM:SSZ` |
| `CONTROL_ASSURANCE_DEFENDER_XDR_END` | Exclusive whole-second UTC end |
| `CONTROL_ASSURANCE_DEFENDER_XDR_EXPECTED_COUNT` | Independently reviewed number of rows in the window |
| `CONTROL_ASSURANCE_DEFENDER_XDR_MAX_HITS` | Optional safety limit; defaults to at least the expected count |
| `CONTROL_ASSURANCE_DEFENDER_XDR_ENDPOINT` | Optional official Graph origin; defaults to `https://graph.microsoft.com` |

Then run:

```bash
.venv/bin/pytest -q -rs tests/integration/test_defender_xdr_live.py
```

A pass means the real Graph response matched the fixed request, exact count,
schema, ordering, half-open window, and receipt-integrity rules. Remove the
token file through the same secret-delivery boundary that created it and review
Entra sign-in/audit records for the test application.

## What the test does not prove

The opt-in test uses a pre-issued bearer token. It exercises the live Graph
connector, not the production Key Vault/federated assertion broker, PostgreSQL
PAM journal, S3 Object Lock publication, or Vault Transit signer. It keeps the
capture in process and does not create a durable evidence artifact.

The dependency-free Node verifier separately recomputes Defender receipt
structure and canonical records, and the test suite requires Python/Node
agreement on shared fixtures. The current live test does not invoke that Node
verifier. A production acceptance exercise must run the full worker path,
retain the signed custody closure, verify the external request and source
anchors, test token/key rotation, and exercise ambiguous transport recovery.
A successful run is not Microsoft attestation of the captured bytes.
