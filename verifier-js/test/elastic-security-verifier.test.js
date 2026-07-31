import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { executeElasticVerification } from "../src/elastic-security-cli.js";
import {
  ElasticCaptureVerificationError,
  verifyElasticSecurityCapture,
} from "../src/elastic-security-verifier.js";
import {
  canonicalize,
  parseStrictJson,
  verifyCanonicalJsonLines,
} from "../src/strict-json.js";

const ENDPOINT = "https://elastic.example:9200";
const ENDPOINT_DIGEST = digest(Buffer.from(ENDPOINT));
const CONNECTOR_VERSION = "0.1.0";
const REQUEST = {
  alert_statuses: ["active"],
  capture_id: "elastic-conformance",
  capture_nonce: "71c934e89a46d9d52d52b560975b8128627f4781452e6fe54def16fcf0c74bc9",
  fields: ["@timestamp", "kibana.alert.severity"],
  index_alias: ".alerts-security.alerts-default",
  keep_alive_seconds: 60,
  max_hits: 10,
  page_size: 2,
  rule_uuids: [],
  window: {
    end_exclusive: "2026-07-30T00:00:00Z",
    start_inclusive: "2026-07-29T00:00:00Z",
  },
  workflow_statuses: [],
};
const JSON_HEADERS = [
  ["accept", "application/json"],
  ["accept-encoding", "identity"],
  ["content-type", "application/json"],
];
const RESPONSE_HEADERS = [
  ["content-type", "application/json; charset=UTF-8"],
  ["x-elastic-product", "Elasticsearch"],
];
const SHARDS = { failed: 0, skipped: 0, successful: 1, total: 1 };
const SEARCH_TARGET =
  "/_search?filter_path=pit_id%2Ctimed_out%2C_shards%2Chits.total%2Chits.hits.sort%2Chits.hits.fields";

function digest(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function hit(timestamp, shardDoc, severity) {
  return {
    fields: {
      "@timestamp": [timestamp],
      "kibana.alert.severity": [severity],
    },
    sort: [timestamp, shardDoc],
  };
}

function searchBody(pitId, searchAfter = null, request = REQUEST) {
  const filters = [
    {
      range: {
        "@timestamp": {
          format: "strict_date_optional_time",
          gte: request.window.start_inclusive,
          lt: request.window.end_exclusive,
        },
      },
    },
  ];
  if (request.rule_uuids.length > 0) {
    filters.push({ terms: { "kibana.alert.rule.uuid": request.rule_uuids } });
  }
  if (request.workflow_statuses.length > 0) {
    filters.push({
      terms: { "kibana.alert.workflow_status": request.workflow_statuses },
    });
  }
  if (request.alert_statuses.length > 0) {
    filters.push({ terms: { "kibana.alert.status": request.alert_statuses } });
  }
  const body = {
    _source: false,
    fields: request.fields,
    pit: { id: pitId, keep_alive: `${request.keep_alive_seconds}s` },
    query: { bool: { filter: filters } },
    size: request.page_size,
    sort: [
      {
        "@timestamp": {
          format: "strict_date_optional_time_nanos",
          numeric_type: "date_nanos",
          order: "asc",
        },
      },
      { _shard_doc: "asc" },
    ],
    track_total_hits: true,
  };
  if (searchAfter !== null) body.search_after = searchAfter;
  return canonicalize(body);
}

function searchResponse(pitId, hits, total = 3, { omitHits = false } = {}) {
  const hitsRoot = { total: { relation: "eq", value: total } };
  if (!omitHits) hitsRoot.hits = hits;
  return canonicalize({
    _shards: SHARDS,
    hits: hitsRoot,
    pit_id: pitId,
    timed_out: false,
  });
}

function exchange(sequence, operation, method, target, requestBody, responseBody) {
  return {
    operation,
    request: {
      body_base64: requestBody.toString("base64"),
      body_digest: digest(requestBody),
      headers: JSON_HEADERS,
      method,
      target,
    },
    response: {
      body_base64: responseBody.toString("base64"),
      body_digest: digest(responseBody),
      headers: RESPONSE_HEADERS,
      status: 200,
    },
    sequence,
  };
}

function fixtureReceipt() {
  const firstTimestamp = "2026-07-29T00:00:01.000000000Z";
  const secondTimestamp = "2026-07-29T00:00:02.000000000Z";
  const thirdTimestamp = "2026-07-29T00:00:03.000000000Z";
  return canonicalize({
    connector: { id: "elastic-security-readonly", version: CONNECTOR_VERSION },
    endpoint_origin_digest: ENDPOINT_DIGEST,
    exchanges: [
      exchange(
        0,
        "open-pit",
        "POST",
        "/.alerts-security.alerts-default/_pit?allow_partial_search_results=false&filter_path=id%2C_shards&keep_alive=60s",
        Buffer.alloc(0),
        canonicalize({ _shards: SHARDS, id: "pit-0" }),
      ),
      exchange(
        1,
        "search-page",
        "POST",
        SEARCH_TARGET,
        searchBody("pit-0"),
        searchResponse("pit-1", [
          hit(firstTimestamp, 10, "high"),
          hit(secondTimestamp, 11, "medium"),
        ]),
      ),
      exchange(
        2,
        "search-page",
        "POST",
        SEARCH_TARGET,
        searchBody("pit-1", [secondTimestamp, 11]),
        searchResponse("pit-2", [hit(thirdTimestamp, 12, "critical")]),
      ),
      exchange(
        3,
        "search-page",
        "POST",
        SEARCH_TARGET,
        searchBody("pit-2", [thirdTimestamp, 12]),
        searchResponse("pit-3", [], 3, { omitHits: true }),
      ),
      exchange(
        4,
        "close-pit",
        "DELETE",
        "/_pit?filter_path=succeeded%2Cnum_freed",
        canonicalize({ id: "pit-3" }),
        canonicalize({ num_freed: 1, succeeded: true }),
      ),
    ],
    media_type:
      "application/vnd.control-assurance.elastic-security-capture.v1+json",
    request: REQUEST,
    schema_version: "1.0.0",
    timing: {
      elapsed_microseconds: 125000,
      finished_at: "2026-07-29T00:00:00.125000Z",
      started_at: "2026-07-29T00:00:00.000000Z",
    },
  });
}

function verify(receipt = fixtureReceipt(), request = REQUEST) {
  return verifyElasticSecurityCapture(receipt, {
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

function replaceBody(receipt, exchangeIndex, side, mutate) {
  const member = receipt.exchanges[exchangeIndex][side];
  const value = parseStrictJson(Buffer.from(member.body_base64, "base64"));
  mutate(value);
  const bytes = canonicalize(value);
  member.body_base64 = bytes.toString("base64");
  member.body_digest = digest(bytes);
}

test("rebuilds the canonical record stream from exact REST exchanges", () => {
  const result = verify();
  assert.equal(result.recordCount, 3);
  assert.equal(result.claimScope, "receipt-internal-consistency");
  assert.equal(result.sourceAuthenticity, "not-established");
  assert.equal(result.sourceLocatorDigest, ENDPOINT_DIGEST);
  assert.equal(
    result.expectedRequestDigest,
    digest(canonicalize(REQUEST)),
  );
  assert.equal(result.sourceVersion, null);
  assert.equal(result.receiptDigest, digest(fixtureReceipt()));
  assert.equal(result.recordsDigest, digest(result.recordsJsonl));
  verifyCanonicalJsonLines(result.recordsJsonl, {
    maxBytes: 64 * 1024 * 1024,
    maxDepth: 16,
    maxCollectionItems: 200_000,
    maxStringLength: 1024 * 1024,
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
      "elastic-alert:000000000000",
      "elastic-alert:000000000001",
      "elastic-alert:000000000002",
    ],
  );
  assert.deepEqual(rows[2].cursor, [
    "2026-07-29T00:00:03.000000000Z",
    12,
  ]);
});

test("pins endpoint, connector version, and expected request outside the receipt", () => {
  assert.throws(
    () =>
      verifyElasticSecurityCapture(fixtureReceipt(), {
        expectedConnectorVersion: CONNECTOR_VERSION,
        expectedEndpointOriginDigest: `sha256:${"1".repeat(64)}`,
        expectedRequest: canonicalize(REQUEST),
      }),
    (error) =>
      error instanceof ElasticCaptureVerificationError &&
      error.code === "endpoint_origin_mismatch",
  );
  assert.throws(
    () =>
      verifyElasticSecurityCapture(fixtureReceipt(), {
        expectedConnectorVersion: "9.9.9",
        expectedEndpointOriginDigest: ENDPOINT_DIGEST,
        expectedRequest: canonicalize(REQUEST),
      }),
    /connector_identity/,
  );

  const changed = structuredClone(REQUEST);
  changed.max_hits = 9;
  assert.throws(
    () => verify(fixtureReceipt(), changed),
    /receipt_request_mismatch/,
  );
});

test("rejects a coherently rewritten embedded request and all search bodies", () => {
  const corrupted = mutateReceipt(fixtureReceipt(), (receipt) => {
    receipt.request.page_size = 3;
    const rewritten = { ...REQUEST, page_size: 3 };
    replaceBody(receipt, 1, "request", (body) => {
      Object.assign(body, parseStrictJson(searchBody("pit-0", null, rewritten)));
    });
    replaceBody(receipt, 2, "request", (body) => {
      Object.assign(
        body,
        parseStrictJson(
          searchBody(
            "pit-1",
            ["2026-07-29T00:00:02.000000000Z", 11],
            rewritten,
          ),
        ),
      );
    });
    replaceBody(receipt, 3, "request", (body) => {
      Object.assign(
        body,
        parseStrictJson(
          searchBody(
            "pit-2",
            ["2026-07-29T00:00:03.000000000Z", 12],
            rewritten,
          ),
        ),
      );
    });
  });
  assert.throws(() => verify(corrupted), /receipt_request_mismatch/);
});

test("rejects PIT, cursor, total, final-empty, and close lineage substitutions", () => {
  const mutations = [
    (receipt) =>
      replaceBody(receipt, 2, "request", (body) => {
        body.pit.id = "pit-substituted";
      }),
    (receipt) =>
      replaceBody(receipt, 2, "request", (body) => {
        body.search_after = ["2026-07-29T00:00:01.000000000Z", 10];
      }),
    (receipt) =>
      replaceBody(receipt, 2, "response", (body) => {
        body.hits.total.value = 4;
      }),
    (receipt) => {
      receipt.exchanges.splice(3, 1);
      receipt.exchanges[3].sequence = 3;
    },
    (receipt) =>
      replaceBody(receipt, 4, "request", (body) => {
        body.id = "pit-2";
      }),
  ];
  for (const mutate of mutations) {
    const corrupted = mutateReceipt(fixtureReceipt(), mutate);
    assert.throws(() => verify(corrupted));
  }
});

test("rejects records outside the half-open window and timestamp-field drift", () => {
  const outside = mutateReceipt(fixtureReceipt(), (receipt) => {
    replaceBody(receipt, 1, "response", (body) => {
      const timestamp = "2026-07-28T23:59:59.999999999Z";
      body.hits.hits[0].sort[0] = timestamp;
      body.hits.hits[0].fields["@timestamp"] = [timestamp];
    });
  });
  assert.throws(() => verify(outside), /record_outside_half_open_window/);

  const mismatch = mutateReceipt(fixtureReceipt(), (receipt) => {
    replaceBody(receipt, 1, "response", (body) => {
      body.hits.hits[0].fields["@timestamp"] = [
        "2026-07-29T00:00:01.000000001Z",
      ];
    });
  });
  assert.throws(() => verify(mismatch), /timestamp_field_cursor_mismatch/);
});

test("accepts only terminal omission of filter_path hits.hits", () => {
  assert.equal(verify().recordCount, 3);
  const premature = mutateReceipt(fixtureReceipt(), (receipt) => {
    replaceBody(receipt, 1, "response", (body) => {
      delete body.hits.hits;
    });
  });
  assert.throws(() => verify(premature), /premature_empty_page/);
});

test("rejects canonical digest repair around a failed shard or timeout", () => {
  for (const mutate of [
    (body) => {
      body._shards.failed = 1;
      body._shards.successful = 0;
    },
    (body) => {
      body.timed_out = true;
    },
  ]) {
    const corrupted = mutateReceipt(fixtureReceipt(), (receipt) => {
      replaceBody(receipt, 1, "response", mutate);
    });
    assert.throws(() => verify(corrupted));
  }
});

test("requires exact capture timing and a nonce anchored by the expected request", () => {
  const timingMutations = [
    (timing) => {
      timing.elapsed_microseconds = 124999;
    },
    (timing) => {
      timing.finished_at = "2026-07-28T23:59:59.999999Z";
    },
    (timing) => {
      timing.finished_at = "2026-07-29T00:00:00.125Z";
    },
    (timing) => {
      timing.untrusted_clock = true;
    },
  ];
  for (const mutate of timingMutations) {
    const corrupted = mutateReceipt(fixtureReceipt(), (receipt) => {
      mutate(receipt.timing);
    });
    assert.throws(() => verify(corrupted), /capture_timing/);
  }

  const changedNonce = mutateReceipt(fixtureReceipt(), (receipt) => {
    receipt.request.capture_nonce = "0".repeat(64);
  });
  assert.throws(() => verify(changedNonce), /receipt_request_mismatch/);
});

test("does not overclaim authenticity of coherently substituted server fields", () => {
  const substituted = mutateReceipt(fixtureReceipt(), (receipt) => {
    replaceBody(receipt, 1, "response", (body) => {
      body.hits.hits[0].fields["kibana.alert.severity"] = ["low"];
    });
  });
  const result = verify(substituted);
  assert.equal(result.sourceAuthenticity, "not-established");
  assert.notEqual(result.recordsDigest, verify().recordsDigest);
});

test("CLI emits a bounded summary and writes records only to a new file", async () => {
  const directory = await mkdtemp(join(tmpdir(), "elastic-verifier-"));
  try {
    const receipt = join(directory, "receipt.json");
    const request = join(directory, "request.json");
    const records = join(directory, "records.jsonl");
    await writeFile(receipt, fixtureReceipt(), { mode: 0o600 });
    await writeFile(request, canonicalize(REQUEST), { mode: 0o600 });
    const outcome = await executeElasticVerification([
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
    ]);
    assert.equal(outcome.exitCode, 0);
    const summary = JSON.parse(outcome.stdout.toString("utf8"));
    assert.equal(summary.status, "verified");
    assert.equal(summary.source_version, null);
    assert.equal(summary.source_authenticity, "not-established");
    assert.match(summary.expected_request_digest, /^sha256:[a-f0-9]{64}$/);
    assert.equal(
      summary.verifier_id,
      "control-assurance/elastic-security-capture-verifier-js",
    );
    assert.equal(summary.verifier_package_version, "0.2.0");
    assert.match(
      summary.verifier_source_set_digest,
      /^sha256:[a-f0-9]{64}$/,
    );
    assert.equal(digest(await readFile(records)), summary.records_digest);

    const second = await executeElasticVerification([
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
    ]);
    assert.equal(second.exitCode, 1);
    assert.deepEqual(
      second.stdout,
      Buffer.from('{"status":"verification_error"}\n'),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
