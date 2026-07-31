# Real Elastic Security connector conformance

`scripts/run-elastic-live-conformance.sh` is an opt-in test against an actual
Elasticsearch 9.4.2 process. It does not replace Elasticsearch with an HTTP
stub.

The run creates a temporary, loopback-only single node, a two-shard hidden
backing index, and the exact `.alerts-security.alerts-default` query alias. It
inserts four alerts inside `[2026-07-29, 2026-07-30)` and one alert exactly at
the exclusive end. The connector must return the first four and must not return
the fifth. The resulting receipt is then recalculated by the independent Node
verifier, including a byte-for-byte comparison of the derived canonical JSONL.
The same capture is then written as a CAB containing the externally authorized
request, exact REST receipt, canonical records, and recomputed verification
statement. That CAB is sealed and reopened against the same out-of-band request
and source-origin anchor before the test succeeds.

## Run it

Use an unpacked official distribution:

```bash
CONTROL_ASSURANCE_ELASTIC_HOME=/opt/elasticsearch-9.4.2 \
  scripts/run-elastic-live-conformance.sh
```

Or point at the official Linux x86-64 archive:

```bash
CONTROL_ASSURANCE_ELASTIC_ARCHIVE=~/Downloads/elasticsearch-9.4.2-linux-x86_64.tar.gz \
  scripts/run-elastic-live-conformance.sh
```

The script also recognizes
`~/.cache/control-assurance-elastic/elasticsearch-9.4.2` and its adjacent
archive. If neither exists, an explicit
`CONTROL_ASSURANCE_ELASTIC_DOWNLOAD=1` downloads the official archive and
checks its pinned SHA-512 before use.

The Python environment must contain this project and its test dependencies.
`.venv/bin/python` is selected automatically; override it with
`CONTROL_ASSURANCE_PYTHON=/path/to/python`. Node.js 20.11 or newer is required
for the independent verifier.

## Security boundary of the harness

- The built-in `elastic` principal exists only to seed the disposable node and
  mint the test key.
- The connector receives a 15-minute API key with no cluster privileges and
  only `read` on the exact alias and backing index. The harness proves that a
  cluster-health read and a document write both return `403`.
- Neither credential is passed as a command-line argument. The connector key
  is read from an owner-only, single-link temporary file.
- The API key is revoked during cleanup, the node is stopped with a bounded
  grace period, and the entire owner-only work directory is removed.
- Every network operation is loopback-only and time-bounded. Plain HTTP is
  allowed here solely because the process is isolated on loopback; production
  connectors require TLS verification.

This harness establishes connector behavior against the real Elasticsearch
REST implementation. It does not claim that a captured receipt authenticates
the source system by itself; source authenticity belongs to the outer signed
attestation and deployment trust boundary.
