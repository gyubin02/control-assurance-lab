import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { executeDefenderXDRVerification } from "../src/defender-xdr-cli.js";
import {
  DefenderXDRCaptureVerificationError,
  verifyDefenderXDRCapture,
} from "../src/defender-xdr-verifier.js";
import {
  canonicalize,
  parseStrictJson,
  verifyCanonicalJsonLines,
} from "../src/strict-json.js";

const CONNECTOR_VERSION = "0.1.0";
const ENDPOINT_DIGEST = digest(Buffer.from("http://127.0.0.1:8787"));
const REQUEST = {
  capture_id: "defender-xdr-conformance",
  capture_nonce:
    "71c934e89a46d9d52d52b560975b8128627f4781452e6fe54def16fcf0c74bc9",
  max_hits: 10,
  profile: "microsoft-graph-v1.0-alertinfo-exact-count-v1",
  window: {
    end_exclusive: "2026-07-30T00:00:00Z",
    start_inclusive: "2026-07-29T00:00:00Z",
  },
};
const RESULT_COLUMNS = [
  "ControlAssuranceKind",
  "ControlAssuranceTotal",
  "Timestamp",
  "AlertId",
  "Title",
  "Category",
  "Severity",
  "ServiceSource",
  "DetectionSource",
  "AttackTechniques",
];
const REQUEST_HEADERS = [
  ["accept", "application/json"],
  ["accept-encoding", "identity"],
  ["content-type", "application/json"],
];
const RESPONSE_HEADERS = [
  ["content-type", "application/json; charset=utf-8"],
  ["request-id", "12345678-1234-1234-1234-123456789abc"],
];

function digest(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function fixedQuery(request = REQUEST) {
  const start = request.window.start_inclusive;
  const end = request.window.end_exclusive;
  return (
    "let _ca_rows = materialize(\n" +
    "    AlertInfo\n" +
    `    | where Timestamp >= datetime(${start}) and Timestamp < datetime(${end})\n` +
    '    | project ControlAssuranceKind = "record", ' +
    'ControlAssuranceTotal = "", ' +
    "Timestamp = strcat(" +
    'format_datetime(Timestamp, "yyyy-MM-dd"), "T", ' +
    'format_datetime(Timestamp, "HH:mm:ss.fffffff"), "Z"), ' +
    "AlertId = tostring(AlertId), " +
    "Title = tostring(Title), " +
    "Category = tostring(Category), " +
    "Severity = tostring(Severity), " +
    "ServiceSource = tostring(ServiceSource), " +
    "DetectionSource = tostring(DetectionSource), " +
    "AttackTechniques = tostring(AttackTechniques)\n" +
    ");\n" +
    "let _ca_total = toscalar(_ca_rows | count);\n" +
    "union _ca_rows,\n" +
    '    (print ControlAssuranceKind = "control", ' +
    "ControlAssuranceTotal = tostring(_ca_total), " +
    'Timestamp = "", AlertId = "", Title = "", Category = "", ' +
    'Severity = "", ServiceSource = "", DetectionSource = "", ' +
    'AttackTechniques = "")\n' +
    "| order by ControlAssuranceKind asc, Timestamp asc, AlertId asc, " +
    "Title asc, Category asc, Severity asc, ServiceSource asc, " +
    "DetectionSource asc, AttackTechniques asc\n" +
    `| take ${request.max_hits + 2}`
  );
}

function requestBody(request = REQUEST) {
  return canonicalize({
    Query: fixedQuery(request),
    Timespan:
      `${request.window.start_inclusive}/${request.window.end_exclusive}`,
  });
}

function control(total) {
  return {
    AlertId: "",
    AttackTechniques: "",
    Category: "",
    ControlAssuranceKind: "control",
    ControlAssuranceTotal: String(total),
    DetectionSource: "",
    ServiceSource: "",
    Severity: "",
    Timestamp: "",
    Title: "",
  };
}

function alert(timestamp, alertId, title, severity) {
  return {
    AlertId: alertId,
    AttackTechniques: "T1059",
    Category: "Execution",
    ControlAssuranceKind: "record",
    ControlAssuranceTotal: "",
    DetectionSource: "Microsoft Defender for Endpoint",
    ServiceSource: "Microsoft Defender for Endpoint",
    Severity: severity,
    Timestamp: timestamp,
    Title: title,
  };
}

function graphResponse(
  results = [
    control(2),
    alert(
      "2026-07-29T00:00:01.0000000Z",
      "alert-a",
      "Credential access signal",
      "High",
    ),
    alert(
      "2026-07-29T00:00:02.0000000Z",
      "alert-b",
      "Suspicious process",
      "Medium",
    ),
  ],
) {
  return canonicalize({
    "@odata.context":
      "https://graph.microsoft.com/v1.0/$metadata" +
      "#microsoft.graph.security.huntingQueryResults",
    results,
    // The Graph schema is a set, not an order anchor. This deliberately differs
    // from the KQL projection order and must still verify.
    schema: [...RESULT_COLUMNS]
      .reverse()
      .map((name) => ({ name, type: "String" })),
  });
}

function exchange(request = REQUEST, responseBody = graphResponse()) {
  const body = requestBody(request);
  return {
    operation: "run-hunting-query",
    request: {
      body_base64: body.toString("base64"),
      body_digest: digest(body),
      headers: REQUEST_HEADERS,
      method: "POST",
      target: "/v1.0/security/runHuntingQuery",
    },
    response: {
      body_base64: responseBody.toString("base64"),
      body_digest: digest(responseBody),
      headers: RESPONSE_HEADERS,
      status: 200,
    },
    sequence: 0,
  };
}

function fixtureReceipt(request = REQUEST, responseBody = graphResponse()) {
  return canonicalize({
    connector: {
      id: "microsoft-defender-xdr-readonly",
      version: CONNECTOR_VERSION,
    },
    endpoint_origin_digest: ENDPOINT_DIGEST,
    exchanges: [exchange(request, responseBody)],
    media_type:
      "application/vnd.control-assurance.defender-xdr-capture.v1+json",
    request,
    schema_version: "1.0.0",
    source_profile: {
      api: "Microsoft Graph v1.0",
      permission: "ThreatHunting.Read.All",
      table: "AlertInfo",
    },
    timing: {
      elapsed_microseconds: 125000,
      finished_at: "2026-07-29T00:00:00.125000Z",
      started_at: "2026-07-29T00:00:00.000000Z",
    },
  });
}

function verify(receipt = fixtureReceipt(), request = REQUEST) {
  return verifyDefenderXDRCapture(receipt, {
    expectedConnectorVersion: CONNECTOR_VERSION,
    expectedEndpointOriginDigest: ENDPOINT_DIGEST,
    expectedRequest: canonicalize(request),
  });
}

function mutateReceipt(receipt, mutate) {
  const parsed = parseStrictJson(receipt);
  mutate(parsed);
  return canonicalize(parsed);
}

function replaceResponseBody(receipt, mutate) {
  const response = receipt.exchanges[0].response;
  const parsed = parseStrictJson(
    Buffer.from(response.body_base64, "base64"),
  );
  mutate(parsed);
  const bytes = canonicalize(parsed);
  response.body_base64 = bytes.toString("base64");
  response.body_digest = digest(bytes);
}

function replaceRequestBody(receipt, body) {
  const request = receipt.exchanges[0].request;
  request.body_base64 = body.toString("base64");
  request.body_digest = digest(body);
}

test("independently rebuilds canonical AlertInfo records", () => {
  const result = verify();
  assert.equal(result.recordCount, 2);
  assert.equal(result.claimScope, "receipt-internal-consistency");
  assert.equal(result.sourceAuthenticity, "not-established");
  assert.equal(result.sourceVersion, null);
  assert.equal(result.sourceLocatorDigest, ENDPOINT_DIGEST);
  assert.equal(result.expectedRequestDigest, digest(canonicalize(REQUEST)));
  assert.equal(result.receiptDigest, digest(fixtureReceipt()));
  assert.equal(result.recordsDigest, digest(result.recordsJsonl));
  verifyCanonicalJsonLines(result.recordsJsonl, {
    maxBytes: 64 * 1024 * 1024,
    maxDepth: 16,
    maxCollectionItems: 100_000,
    maxStringLength: 256 * 1024,
    maxLineBytes: 2 * 1024 * 1024,
  });
  const rows = result.recordsJsonl
    .toString("utf8")
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.deepEqual(
    rows.map((row) => row.id),
    [
      "defender-xdr-alert:000000000000",
      "defender-xdr-alert:000000000001",
    ],
  );
  assert.equal(rows[0].fields.AlertId, "alert-a");
  assert.equal(rows[1].fields.Timestamp, "2026-07-29T00:00:02.0000000Z");
});

test("uses Python code-point order for equal-timestamp row keys", () => {
  const response = graphResponse([
    control(2),
    alert(
      "2026-07-29T00:00:01.0000000Z",
      "\ue000",
      "first by code point",
      "High",
    ),
    alert(
      "2026-07-29T00:00:01.0000000Z",
      "😀",
      "second by code point",
      "High",
    ),
  ]);
  // JavaScript's native UTF-16 comparison gives the opposite answer here.
  assert.equal("😀" < "\ue000", true);
  assert.equal(verify(fixtureReceipt(REQUEST, response)).recordCount, 2);
});

test("pins origin, nonce-bearing request, and implementation version externally", () => {
  assert.throws(
    () =>
      verifyDefenderXDRCapture(fixtureReceipt(), {
        expectedConnectorVersion: CONNECTOR_VERSION,
        expectedEndpointOriginDigest: `sha256:${"0".repeat(64)}`,
        expectedRequest: canonicalize(REQUEST),
      }),
    (error) =>
      error instanceof DefenderXDRCaptureVerificationError &&
      error.code === "endpoint_origin_mismatch",
  );
  assert.throws(
    () =>
      verifyDefenderXDRCapture(fixtureReceipt(), {
        expectedConnectorVersion: "forged-version",
        expectedEndpointOriginDigest: ENDPOINT_DIGEST,
        expectedRequest: canonicalize(REQUEST),
      }),
    /connector_identity/,
  );
  const changed = structuredClone(REQUEST);
  changed.capture_nonce = "0".repeat(64);
  assert.throws(() => verify(fixtureReceipt(), changed), /receipt_request_mismatch/);
});

test("rebuilds the one permitted KQL body instead of trusting repaired digests", () => {
  const mutations = [
    (receipt) => {
      receipt.exchanges[0].request.target = "/beta/security/runHuntingQuery";
    },
    (receipt) => {
      receipt.exchanges[0].request.headers.push([
        "authorization",
        "Bearer should-never-be-recorded",
      ]);
    },
    (receipt) => {
      const body = parseStrictJson(requestBody());
      body.Query = "AlertInfo | take 1";
      replaceRequestBody(receipt, canonicalize(body));
    },
    (receipt) => {
      const body = parseStrictJson(requestBody());
      body.Timespan =
        "2026-07-29T00:00:00Z/2026-07-31T00:00:00Z";
      replaceRequestBody(receipt, canonicalize(body));
    },
  ];
  for (const mutate of mutations) {
    const corrupted = mutateReceipt(fixtureReceipt(), mutate);
    assert.throws(() => verify(corrupted));
  }
});

test("rejects missing, forged, saturated, and non-closing exact counts", () => {
  const mutations = [
    (body) => body.results.shift(),
    (body) => {
      body.results[0].ControlAssuranceTotal = "1";
    },
    (body) => {
      body.results[0].ControlAssuranceTotal = "01";
    },
    (body) => {
      body.results[0].ControlAssuranceTotal = "11";
    },
    (body) => {
      body.results[0].AlertId = "source-data-in-control";
    },
  ];
  for (const mutate of mutations) {
    const corrupted = mutateReceipt(fixtureReceipt(), (receipt) => {
      replaceResponseBody(receipt, mutate);
    });
    assert.throws(() => verify(corrupted));
  }
});

test("rejects schema substitution, row reordering, and half-open boundary drift", () => {
  const mutations = [
    (body) => body.schema.pop(),
    (body) => {
      body.schema[0].type = "Int64";
    },
    (body) => {
      body.schema[0].name = body.schema[1].name;
    },
    (body) => body.results.reverse(),
    (body) => {
      body.results[1].Timestamp = "2026-07-30T00:00:00.0000000Z";
    },
    (body) => {
      body.results[1].Timestamp = "2026-07-29T00:00:01.000000Z";
    },
    (body) => {
      body["@odata.context"] =
        "https://attacker.invalid/v1.0/$metadata" +
        "#microsoft.graph.security.huntingQueryResults";
    },
  ];
  for (const mutate of mutations) {
    const corrupted = mutateReceipt(fixtureReceipt(), (receipt) => {
      replaceResponseBody(receipt, mutate);
    });
    assert.throws(() => verify(corrupted));
  }
});

test("checks exact media metadata, timing closure, and source profile", () => {
  const mutations = [
    (receipt) => {
      receipt.exchanges[0].response.headers = [
        ["content-type", "text/html"],
      ];
    },
    (receipt) => {
      receipt.exchanges[0].response.headers = [
        ["content-encoding", "gzip"],
        ["content-type", "application/json"],
      ];
    },
    (receipt) => {
      receipt.timing.elapsed_microseconds += 1;
    },
    (receipt) => {
      receipt.timing.finished_at = receipt.timing.started_at;
    },
    (receipt) => {
      receipt.source_profile.permission = "SecurityEvents.Read.All";
    },
  ];
  for (const mutate of mutations) {
    assert.throws(() => verify(mutateReceipt(fixtureReceipt(), mutate)));
  }
});

test("rejects duplicate-key and merely equivalent non-canonical receipts", () => {
  const receipt = fixtureReceipt();
  assert.throws(
    () => verify(Buffer.concat([Buffer.from(" "), receipt])),
    /receipt_not_canonical/,
  );
  const text = receipt.toString("utf8");
  const duplicate = Buffer.from(
    text.replace(
      '{"connector":',
      '{"connector":{"id":"forged","version":"0.1.0"},"connector":',
    ),
  );
  assert.throws(() => verify(duplicate), /receipt_not_canonical/);
});

test("does not turn coherent Graph field replacement into source authenticity", () => {
  const rewritten = mutateReceipt(fixtureReceipt(), (receipt) => {
    replaceResponseBody(receipt, (body) => {
      body.results[1].Severity = "Low";
    });
  });
  const result = verify(rewritten);
  assert.equal(result.sourceAuthenticity, "not-established");
  assert.notEqual(result.recordsDigest, verify().recordsDigest);
});

test("CLI emits a bounded summary and creates records without overwriting", async () => {
  const directory = await mkdtemp(join(tmpdir(), "defender-xdr-verifier-"));
  try {
    const receipt = join(directory, "receipt.json");
    const request = join(directory, "request.json");
    const records = join(directory, "records.jsonl");
    await writeFile(receipt, fixtureReceipt(), { mode: 0o600 });
    await writeFile(request, canonicalize(REQUEST), { mode: 0o600 });
    const arguments_ = [
      "--receipt",
      receipt,
      "--expected-request",
      request,
      "--expected-endpoint-origin-digest",
      ENDPOINT_DIGEST,
      "--expected-connector-version",
      CONNECTOR_VERSION,
      "--records-output",
      records,
    ];
    const outcome = await executeDefenderXDRVerification(arguments_);
    assert.equal(outcome.exitCode, 0);
    const summary = JSON.parse(outcome.stdout.toString("utf8"));
    assert.equal(summary.status, "verified");
    assert.equal(summary.source_authenticity, "not-established");
    assert.equal(summary.source_version, null);
    assert.equal(
      summary.verifier_id,
      "control-assurance/defender-xdr-capture-verifier-js",
    );
    assert.equal(summary.verifier_package_version, "0.2.0");
    assert.match(
      summary.verifier_source_set_digest,
      /^sha256:[a-f0-9]{64}$/,
    );
    assert.equal(digest(await readFile(records)), summary.records_digest);

    const overwrite = await executeDefenderXDRVerification(arguments_);
    assert.equal(overwrite.exitCode, 1);
    assert.deepEqual(
      overwrite.stdout,
      Buffer.from('{"status":"verification_error"}\n'),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("Python and Node independently derive byte-identical records", async () => {
  const directory = await mkdtemp(join(tmpdir(), "defender-crosscheck-"));
  try {
    const receiptPath = join(directory, "receipt.json");
    const requestPath = join(directory, "request.json");
    await writeFile(receiptPath, fixtureReceipt(), { mode: 0o600 });
    await writeFile(requestPath, canonicalize(REQUEST), { mode: 0o600 });
    const program = String.raw`
import json
import pathlib
import sys
from datetime import UTC, datetime
from assurance_lab.connectors.contract import ConnectorWindow
from assurance_lab.connectors.defender_xdr import DefenderXDRRequest, verify_defender_xdr_capture

request_value = json.loads(pathlib.Path(sys.argv[2]).read_bytes())
request = DefenderXDRRequest(
    capture_id=request_value["capture_id"],
    capture_nonce=request_value["capture_nonce"],
    max_hits=request_value["max_hits"],
    window=ConnectorWindow(
        start=datetime.strptime(request_value["window"]["start_inclusive"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC),
        end=datetime.strptime(request_value["window"]["end_exclusive"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC),
    ),
)
verified = verify_defender_xdr_capture(
    pathlib.Path(sys.argv[1]).read_bytes(),
    expected_endpoint_origin_digest=sys.argv[3],
    expected_request=request,
    expected_connector_version=sys.argv[4],
)
print(json.dumps({
    "record_count": verified.record_count,
    "records_digest": verified.records_digest,
    "records_hex": verified.records_jsonl.hex(),
    "receipt_digest": verified.receipt_digest,
}, sort_keys=True, separators=(",", ":")))
`;
    const repositoryRoot = join(import.meta.dirname, "..", "..");
    const repositoryPython = join(repositoryRoot, ".venv", "bin", "python");
    const executed = spawnSync(
      process.env.PYTHON ??
        (existsSync(repositoryPython) ? repositoryPython : "python"),
      [
        "-c",
        program,
        receiptPath,
        requestPath,
        ENDPOINT_DIGEST,
        CONNECTOR_VERSION,
      ],
      {
        cwd: repositoryRoot,
        encoding: "utf8",
        timeout: 30_000,
      },
    );
    assert.equal(executed.status, 0, executed.stderr);
    const python = JSON.parse(executed.stdout);
    const node = verify();
    assert.equal(python.record_count, node.recordCount);
    assert.equal(python.records_digest, node.recordsDigest);
    assert.equal(python.records_hex, node.recordsJsonl.toString("hex"));
    assert.equal(python.receipt_digest, node.receiptDigest);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
