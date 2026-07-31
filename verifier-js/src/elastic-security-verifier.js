import { createHash } from "node:crypto";

import {
  canonicalize,
  parseStrictJson,
  verifyCanonicalJson,
} from "./strict-json.js";

export const ELASTIC_CAPTURE_MEDIA_TYPE =
  "application/vnd.control-assurance.elastic-security-capture.v1+json";
export const ELASTIC_CAPTURE_SCHEMA_VERSION = "1.0.0";
export const ELASTIC_CONNECTOR_ID = "elastic-security-readonly";
export const ELASTIC_VERIFIER_ID =
  "control-assurance/elastic-security-capture-verifier-js";

const MAX_FIELDS = 32;
const MAX_FILTER_VALUES = 256;
const MAX_PAGE_SIZE = 1_000;
const MAX_HITS = 100_000;
const MAX_PAGES = 10_001;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_TOTAL_RESPONSE_BYTES = 64 * 1024 * 1024;
const MAX_RECEIPT_BYTES = 96 * 1024 * 1024;
const MAX_RECORD_BYTES = 64 * 1024 * 1024;
const MAX_FIELD_VALUE_BYTES = 1024 * 1024;
const MIN_KEEP_ALIVE_SECONDS = 15;
const MAX_KEEP_ALIVE_SECONDS = 300;

export const ELASTIC_RECEIPT_LIMITS = Object.freeze({
  maxBytes: MAX_RECEIPT_BYTES,
  maxDepth: 32,
  maxCollectionItems: 200_000,
  maxStringLength: MAX_RESPONSE_BYTES * 2,
  maxLineBytes: MAX_RECEIPT_BYTES,
});

const RESPONSE_LIMITS = Object.freeze({
  maxBytes: MAX_RESPONSE_BYTES,
  maxDepth: 16,
  maxCollectionItems: 100_000,
  maxStringLength: MAX_FIELD_VALUE_BYTES,
  maxLineBytes: MAX_RESPONSE_BYTES,
});

const REQUEST_LIMITS = Object.freeze({
  maxBytes: 1024 * 1024,
  maxDepth: 16,
  maxCollectionItems: 2_048,
  maxStringLength: 32_768,
  maxLineBytes: 1024 * 1024,
});

const RECORD_LIMITS = Object.freeze({
  maxBytes: MAX_RECORD_BYTES,
  maxDepth: 16,
  maxCollectionItems: 200_000,
  maxStringLength: MAX_FIELD_VALUE_BYTES,
  maxLineBytes: 2 * 1024 * 1024,
});

const JSON_HEADERS = Object.freeze([
  Object.freeze(["accept", "application/json"]),
  Object.freeze(["accept-encoding", "identity"]),
  Object.freeze(["content-type", "application/json"]),
]);
const RECORDED_RESPONSE_HEADERS = new Set([
  "content-type",
  "x-elastic-product",
]);
const SEARCH_TARGET =
  "/_search?filter_path=pit_id%2Ctimed_out%2C_shards%2Chits.total%2Chits.hits.sort%2Chits.hits.fields";
const CLOSE_TARGET = "/_pit?filter_path=succeeded%2Cnum_freed";

const ALERT_INDEX =
  /^[.]alerts-security[.]alerts-[a-z0-9][a-z0-9_-]{0,63}$/;
const FIELD = /^(?:@timestamp|[A-Za-z][A-Za-z0-9_.]{0,127})$/;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CAPTURE_ID = /^[a-z][a-z0-9._-]{0,127}$/;
const CAPTURE_NONCE = /^[a-f0-9]{64}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const UTC_SECONDS =
  /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$/;
const UTC_NANOS =
  /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:[.]([0-9]{1,9}))?Z$/;
const UTC_MICROSECONDS =
  /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})[.]([0-9]{6})Z$/;
const WORKFLOW_STATUSES = new Set(["acknowledged", "closed", "open"]);
const ALERT_STATUSES = new Set(["active", "recovered"]);

export class ElasticCaptureVerificationError extends Error {
  constructor(code) {
    super(code);
    this.name = "ElasticCaptureVerificationError";
    this.code = code;
  }
}

function reject(code) {
  throw new ElasticCaptureVerificationError(code);
}

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactObject(value, required, optional = [], code = "invalid_shape") {
  if (!isObject(value)) reject(code);
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(value);
  if (
    keys.length < required.length ||
    required.some((name) => !Object.hasOwn(value, name)) ||
    keys.some((name) => !allowed.has(name))
  ) {
    reject(code);
  }
  return value;
}

function exactArray(value, maximum, code = "invalid_array") {
  if (!Array.isArray(value) || value.length > maximum) reject(code);
  return value;
}

function exactInteger(value, minimum, maximum, code = "invalid_integer") {
  if (
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    reject(code);
  }
  return value;
}

function exactText(value, maximum, code = "invalid_text") {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
    reject(code);
  }
  return value;
}

function exactDigest(value, code = "invalid_digest") {
  if (typeof value !== "string" || !DIGEST.test(value)) reject(code);
  return value;
}

function equalBytes(left, right) {
  return Buffer.isBuffer(left) && Buffer.isBuffer(right) && left.equals(right);
}

function canonicalBase64(value, maximum, code) {
  if (
    typeof value !== "string" ||
    value.length > 4 * Math.ceil(maximum / 3) ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value,
    )
  ) {
    reject(code);
  }
  const decoded = Buffer.from(value, "base64");
  if (
    decoded.length > maximum ||
    decoded.toString("base64") !== value
  ) {
    reject(code);
  }
  return decoded;
}

function canonicalHeaders(value, code) {
  const raw = exactArray(value, 8, code);
  const headers = [];
  let previous = "";
  for (const pair of raw) {
    if (
      !Array.isArray(pair) ||
      pair.length !== 2 ||
      typeof pair[0] !== "string" ||
      typeof pair[1] !== "string"
    ) {
      reject(code);
    }
    const [name, content] = pair;
    if (
      name.length === 0 ||
      name !== name.toLowerCase() ||
      name <= previous ||
      content.length > 512 ||
      content.includes("\r") ||
      content.includes("\n")
    ) {
      reject(code);
    }
    headers.push([name, content]);
    previous = name;
  }
  return headers;
}

function sameHeaders(left, right) {
  return (
    left.length === right.length &&
    left.every(
      (pair, index) =>
        pair[0] === right[index][0] && pair[1] === right[index][1],
    )
  );
}

function isLeapYear(year) {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function daysInMonth(year, month) {
  if (month === 2) return isLeapYear(year) ? 29 : 28;
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

// Gregorian civil date to days since 1970-01-01. The arithmetic remains exact
// for the connector's four-digit year domain.
function daysFromCivil(year, month, day) {
  const adjustedYear = year - (month <= 2 ? 1 : 0);
  const era = Math.floor(adjustedYear / 400);
  const yearOfEra = adjustedYear - era * 400;
  const adjustedMonth = month + (month > 2 ? -3 : 9);
  const dayOfYear =
    Math.floor((153 * adjustedMonth + 2) / 5) + day - 1;
  const dayOfEra =
    yearOfEra * 365 +
    Math.floor(yearOfEra / 4) -
    Math.floor(yearOfEra / 100) +
    dayOfYear;
  return era * 146097 + dayOfEra - 719468;
}

function parseUtc(value, pattern, code) {
  if (typeof value !== "string") reject(code);
  const match = pattern.exec(value);
  if (match === null) reject(code);
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  if (
    year < 1 ||
    year > 9999 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > daysInMonth(year, month) ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    reject(code);
  }
  const epochSeconds =
    BigInt(daysFromCivil(year, month, day)) * 86_400n +
    BigInt(hour * 3600 + minute * 60 + second);
  const fraction = (match[7] ?? "").padEnd(9, "0");
  return epochSeconds * 1_000_000_000n + BigInt(fraction || "0");
}

function parseWholeSecond(value, code) {
  return parseUtc(value, UTC_SECONDS, code);
}

function parseNanoseconds(value, code) {
  return parseUtc(value, UTC_NANOS, code);
}

function sortedUniqueText(value, maximum, pattern, code) {
  const values = exactArray(value, maximum, code);
  let previous = null;
  for (const item of values) {
    if (
      typeof item !== "string" ||
      !pattern.test(item) ||
      (previous !== null && item <= previous)
    ) {
      reject(code);
    }
    previous = item;
  }
  return values;
}

function sortedEnum(value, allowed, code) {
  const values = exactArray(value, allowed.size, code);
  let previous = null;
  for (const item of values) {
    if (
      typeof item !== "string" ||
      !allowed.has(item) ||
      (previous !== null && item <= previous)
    ) {
      reject(code);
    }
    previous = item;
  }
  return values;
}

function validateExpectedRequest(value) {
  const request = exactObject(
    value,
    [
      "alert_statuses",
      "capture_id",
      "capture_nonce",
      "fields",
      "index_alias",
      "keep_alive_seconds",
      "max_hits",
      "page_size",
      "rule_uuids",
      "window",
      "workflow_statuses",
    ],
    [],
    "request_outside_profile",
  );
  if (typeof request.capture_id !== "string" || !CAPTURE_ID.test(request.capture_id)) {
    reject("request_outside_profile");
  }
  if (
    typeof request.capture_nonce !== "string" ||
    !CAPTURE_NONCE.test(request.capture_nonce)
  ) {
    reject("request_outside_profile");
  }
  if (
    typeof request.index_alias !== "string" ||
    !ALERT_INDEX.test(request.index_alias)
  ) {
    reject("request_outside_profile");
  }
  const fields = sortedUniqueText(
    request.fields,
    MAX_FIELDS,
    FIELD,
    "request_outside_profile",
  );
  if (!fields.includes("@timestamp")) reject("request_outside_profile");
  sortedUniqueText(
    request.rule_uuids,
    MAX_FILTER_VALUES,
    UUID,
    "request_outside_profile",
  );
  sortedEnum(
    request.workflow_statuses,
    WORKFLOW_STATUSES,
    "request_outside_profile",
  );
  sortedEnum(request.alert_statuses, ALERT_STATUSES, "request_outside_profile");
  const pageSize = exactInteger(
    request.page_size,
    1,
    MAX_PAGE_SIZE,
    "request_outside_profile",
  );
  exactInteger(
    request.max_hits,
    pageSize,
    MAX_HITS,
    "request_outside_profile",
  );
  exactInteger(
    request.keep_alive_seconds,
    MIN_KEEP_ALIVE_SECONDS,
    MAX_KEEP_ALIVE_SECONDS,
    "request_outside_profile",
  );
  const window = exactObject(
    request.window,
    ["end_exclusive", "start_inclusive"],
    [],
    "request_outside_profile",
  );
  const start = parseWholeSecond(
    window.start_inclusive,
    "request_outside_profile",
  );
  const end = parseWholeSecond(window.end_exclusive, "request_outside_profile");
  if (start >= end) reject("request_outside_profile");
  return { request, start, end, fields: new Set(fields) };
}

function openTarget(request) {
  const query =
    "allow_partial_search_results=false&filter_path=id%2C_shards&keep_alive=" +
    `${request.keep_alive_seconds}s`;
  return `/${encodeURIComponent(request.index_alias)}/_pit?${query}`;
}

function queryObject(request) {
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
      terms: {
        "kibana.alert.workflow_status": request.workflow_statuses,
      },
    });
  }
  if (request.alert_statuses.length > 0) {
    filters.push({ terms: { "kibana.alert.status": request.alert_statuses } });
  }
  return { bool: { filter: filters } };
}

function searchBody(request, pitId, searchAfter) {
  const body = {
    _source: false,
    fields: request.fields,
    pit: {
      id: pitId,
      keep_alive: `${request.keep_alive_seconds}s`,
    },
    query: queryObject(request),
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
  return canonicalize(body, RESPONSE_LIMITS);
}

function parseRequestExchange(value, sequence) {
  const request = exactObject(
    value,
    ["body_base64", "body_digest", "headers", "method", "target"],
    [],
    "exchange_request_shape",
  );
  const body = canonicalBase64(
    request.body_base64,
    MAX_RESPONSE_BYTES,
    "request_body_base64",
  );
  if (
    exactDigest(request.body_digest, "request_body_digest") !== sha256(body)
  ) {
    reject("request_body_digest");
  }
  const headers = canonicalHeaders(
    request.headers,
    "request_headers",
  );
  if (headers.some(([name]) => name === "authorization")) {
    reject("secret_in_receipt");
  }
  return {
    body,
    headers,
    method: exactText(request.method, 16, `exchange_${sequence}_method`),
    target: exactText(request.target, 32_768, `exchange_${sequence}_target`),
  };
}

function parseResponseExchange(value) {
  const response = exactObject(
    value,
    ["body_base64", "body_digest", "headers", "status"],
    [],
    "exchange_response_shape",
  );
  const body = canonicalBase64(
    response.body_base64,
    MAX_RESPONSE_BYTES,
    "response_body_base64",
  );
  if (
    exactDigest(response.body_digest, "response_body_digest") !== sha256(body)
  ) {
    reject("response_body_digest");
  }
  const headers = canonicalHeaders(response.headers, "response_headers");
  if (headers.some(([name]) => !RECORDED_RESPONSE_HEADERS.has(name))) {
    reject("unapproved_response_header");
  }
  return {
    body,
    headers,
    status: exactInteger(response.status, 100, 599, "response_status"),
  };
}

function requireJsonResponse(response, stage) {
  const headers = new Map(response.headers);
  if (headers.get("x-elastic-product") !== "Elasticsearch") {
    reject(`${stage}_product_marker`);
  }
  const contentType = headers.get("content-type") ?? "";
  if (contentType.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    reject(`${stage}_content_type`);
  }
  if (response.status !== 200) reject(`${stage}_http_status`);
  let value;
  try {
    value = parseStrictJson(response.body, RESPONSE_LIMITS);
  } catch {
    reject(`${stage}_response_json`);
  }
  if (!isObject(value)) reject(`${stage}_response_shape`);
  return value;
}

function parseShards(value, stage) {
  const shards = exactObject(
    value,
    ["failed", "successful", "total"],
    ["failures", "skipped"],
    `${stage}_shards`,
  );
  const total = exactInteger(
    shards.total,
    0,
    1_000_000_000,
    `${stage}_shards`,
  );
  const successful = exactInteger(
    shards.successful,
    0,
    total,
    `${stage}_shards`,
  );
  const failed = exactInteger(shards.failed, 0, total, `${stage}_shards`);
  const skipped = exactInteger(
    Object.hasOwn(shards, "skipped") ? shards.skipped : 0,
    0,
    total,
    `${stage}_shards`,
  );
  if (
    failed !== 0 ||
    Object.hasOwn(shards, "failures") ||
    successful + skipped !== total
  ) {
    reject(`${stage}_shards`);
  }
}

function parseOpen(response) {
  const root = exactObject(
    requireJsonResponse(response, "open_pit"),
    ["_shards", "id"],
    [],
    "open_pit_response_shape",
  );
  parseShards(root._shards, "open_pit");
  return exactText(root.id, 16_384, "open_pit_id");
}

function parseSearch(response, profile) {
  const root = exactObject(
    requireJsonResponse(response, "search"),
    ["_shards", "hits", "timed_out"],
    ["pit_id"],
    "search_response_shape",
  );
  if (typeof root.timed_out !== "boolean" || root.timed_out) {
    reject("search_timed_out");
  }
  parseShards(root._shards, "search");
  const hitsRoot = exactObject(
    root.hits,
    ["total"],
    ["hits"],
    "search_hits_shape",
  );
  const totalRoot = exactObject(
    hitsRoot.total,
    ["relation", "value"],
    [],
    "search_total_shape",
  );
  if (totalRoot.relation !== "eq") reject("search_total_inexact");
  const total = exactInteger(
    totalRoot.value,
    0,
    MAX_HITS + 1,
    "search_total",
  );
  const hits = exactArray(
    Object.hasOwn(hitsRoot, "hits") ? hitsRoot.hits : [],
    profile.request.page_size,
    "search_page_size",
  );
  let pagePrevious = null;
  for (const hitValue of hits) {
    const hit = exactObject(
      hitValue,
      ["sort"],
      ["fields"],
      "search_hit_shape",
    );
    const cursor = exactArray(hit.sort, 2, "search_cursor_shape");
    if (cursor.length !== 2) reject("search_cursor_shape");
    const timestamp = parseNanoseconds(cursor[0], "search_cursor_timestamp");
    const shardDoc = exactInteger(
      cursor[1],
      0,
      Number.MAX_SAFE_INTEGER,
      "search_cursor_shard",
    );
    const key = [timestamp, shardDoc];
    if (
      pagePrevious !== null &&
      (timestamp < pagePrevious[0] ||
        (timestamp === pagePrevious[0] && shardDoc <= pagePrevious[1]))
    ) {
      reject("search_cursor_order");
    }
    pagePrevious = key;
    const fields = Object.hasOwn(hit, "fields") ? hit.fields : Object.create(null);
    if (!isObject(fields)) reject("search_fields_shape");
    if (Object.keys(fields).some((name) => !profile.fields.has(name))) {
      reject("search_field_outside_allowlist");
    }
    try {
      canonicalize(fields, RESPONSE_LIMITS);
    } catch {
      reject("search_fields_bounds");
    }
  }
  const pitId = Object.hasOwn(root, "pit_id")
    ? exactText(root.pit_id, 16_384, "search_pit_id")
    : null;
  return { hits, pitId, total };
}

function parseClose(response) {
  const root = exactObject(
    requireJsonResponse(response, "close_pit"),
    ["num_freed", "succeeded"],
    [],
    "close_pit_response_shape",
  );
  if (typeof root.succeeded !== "boolean" || !root.succeeded) {
    reject("close_pit_not_confirmed");
  }
  exactInteger(root.num_freed, 0, 1_000_000_000, "close_pit_num_freed");
}

function compareCursor(leftTimestamp, leftShard, right) {
  if (right === null) return 1;
  if (leftTimestamp < right[0]) return -1;
  if (leftTimestamp > right[0]) return 1;
  return leftShard === right[1] ? 0 : leftShard < right[1] ? -1 : 1;
}

function canonicalRecords(records) {
  const chunks = [];
  let total = 0;
  for (const record of records) {
    const line = canonicalize(record, RECORD_LIMITS);
    if (line.length > RECORD_LIMITS.maxLineBytes) reject("record_line_too_large");
    total += line.length + 1;
    if (total > RECORD_LIMITS.maxBytes) reject("records_too_large");
    chunks.push(line, Buffer.from("\n"));
  }
  return Buffer.concat(chunks, total);
}

function expectedRequestValue(expectedRequest) {
  if (Buffer.isBuffer(expectedRequest)) {
    let parsed;
    try {
      parsed = verifyCanonicalJson(expectedRequest, REQUEST_LIMITS);
    } catch {
      reject("expected_request_not_canonical");
    }
    return parsed;
  }
  if (!isObject(expectedRequest)) reject("expected_request_missing");
  return expectedRequest;
}

export function verifyElasticSecurityCapture(
  receiptBytes,
  {
    expectedEndpointOriginDigest,
    expectedRequest,
    expectedConnectorVersion,
  } = {},
) {
  if (!Buffer.isBuffer(receiptBytes) || receiptBytes.length === 0) {
    reject("receipt_missing");
  }
  exactDigest(
    expectedEndpointOriginDigest,
    "expected_endpoint_origin_digest_missing",
  );
  if (
    typeof expectedConnectorVersion !== "string" ||
    expectedConnectorVersion.length === 0 ||
    expectedConnectorVersion.length > 64 ||
    !/^[\x20-\x7e]+$/.test(expectedConnectorVersion)
  ) {
    reject("expected_connector_version_missing");
  }
  const expectedValue = expectedRequestValue(expectedRequest);
  const profile = validateExpectedRequest(expectedValue);
  const expectedRequestBytes = canonicalize(expectedValue, REQUEST_LIMITS);

  let receipt;
  try {
    receipt = verifyCanonicalJson(receiptBytes, ELASTIC_RECEIPT_LIMITS);
  } catch {
    reject("receipt_not_canonical");
  }
  const root = exactObject(
    receipt,
    [
      "connector",
      "endpoint_origin_digest",
      "exchanges",
      "media_type",
      "request",
      "schema_version",
      "timing",
    ],
    [],
    "receipt_shape",
  );
  if (
    root.media_type !== ELASTIC_CAPTURE_MEDIA_TYPE ||
    root.schema_version !== ELASTIC_CAPTURE_SCHEMA_VERSION
  ) {
    reject("receipt_profile_identity");
  }
  const timing = exactObject(
    root.timing,
    ["elapsed_microseconds", "finished_at", "started_at"],
    [],
    "capture_timing",
  );
  const startedAt = parseUtc(
    timing.started_at,
    UTC_MICROSECONDS,
    "capture_timing",
  );
  const finishedAt = parseUtc(
    timing.finished_at,
    UTC_MICROSECONDS,
    "capture_timing",
  );
  const elapsedMicroseconds = exactInteger(
    timing.elapsed_microseconds,
    0,
    3_615_000_000,
    "capture_timing",
  );
  if (
    finishedAt < startedAt ||
    finishedAt - startedAt !== BigInt(elapsedMicroseconds) * 1_000n
  ) {
    reject("capture_timing");
  }
  const connector = exactObject(
    root.connector,
    ["id", "version"],
    [],
    "connector_identity",
  );
  if (
    connector.id !== ELASTIC_CONNECTOR_ID ||
    connector.version !== expectedConnectorVersion
  ) {
    reject("connector_identity");
  }
  if (
    exactDigest(root.endpoint_origin_digest, "endpoint_origin_digest") !==
    expectedEndpointOriginDigest
  ) {
    reject("endpoint_origin_mismatch");
  }
  let embeddedRequestBytes;
  try {
    embeddedRequestBytes = canonicalize(root.request, REQUEST_LIMITS);
  } catch {
    reject("receipt_request_invalid");
  }
  if (!equalBytes(embeddedRequestBytes, expectedRequestBytes)) {
    reject("receipt_request_mismatch");
  }
  // Revalidate the embedded form, rather than relying on a structurally similar
  // caller object that happened to canonicalize to unsupported values.
  validateExpectedRequest(root.request);

  const exchanges = exactArray(
    root.exchanges,
    MAX_PAGES + 3,
    "exchange_count",
  );
  if (exchanges.length < 3) reject("lifecycle_incomplete");

  const records = [];
  let currentPit = null;
  let previousSearchAfter = null;
  let previousCursor = null;
  let exactTotal = null;
  let foundEmptyPage = false;
  let totalResponseBytes = 0;

  for (let sequence = 0; sequence < exchanges.length; sequence += 1) {
    const exchange = exactObject(
      exchanges[sequence],
      ["operation", "request", "response", "sequence"],
      [],
      "exchange_shape",
    );
    if (exchange.sequence !== sequence) reject("exchange_sequence");
    const operation = exactText(
      exchange.operation,
      32,
      "exchange_operation",
    );
    const request = parseRequestExchange(exchange.request, sequence);
    const response = parseResponseExchange(exchange.response);
    totalResponseBytes += response.body.length;
    if (totalResponseBytes > MAX_TOTAL_RESPONSE_BYTES) {
      reject("total_response_bytes");
    }

    if (sequence === 0) {
      if (
        operation !== "open-pit" ||
        request.method !== "POST" ||
        request.target !== openTarget(profile.request) ||
        !sameHeaders(request.headers, JSON_HEADERS) ||
        request.body.length !== 0
      ) {
        reject("open_pit_request_substituted");
      }
      currentPit = parseOpen(response);
      continue;
    }

    const last = sequence === exchanges.length - 1;
    if (last) {
      if (
        operation !== "close-pit" ||
        request.method !== "DELETE" ||
        request.target !== CLOSE_TARGET ||
        !sameHeaders(request.headers, JSON_HEADERS)
      ) {
        reject("close_pit_request_substituted");
      }
      if (
        currentPit === null ||
        !equalBytes(
          request.body,
          canonicalize({ id: currentPit }, RESPONSE_LIMITS),
        )
      ) {
        reject("close_pit_lineage");
      }
      parseClose(response);
      if (!foundEmptyPage) reject("final_empty_page_missing");
      continue;
    }

    if (foundEmptyPage) reject("search_after_empty_page");
    if (
      operation !== "search-page" ||
      request.method !== "POST" ||
      request.target !== SEARCH_TARGET ||
      !sameHeaders(request.headers, JSON_HEADERS) ||
      currentPit === null ||
      !equalBytes(
        request.body,
        searchBody(profile.request, currentPit, previousSearchAfter),
      )
    ) {
      reject("search_request_substituted");
    }

    const page = parseSearch(response, profile);
    if (exactTotal === null) {
      exactTotal = page.total;
      if (exactTotal > profile.request.max_hits) reject("max_hits_exceeded");
    } else if (page.total !== exactTotal) {
      reject("exact_total_changed");
    }
    if (page.pitId !== null) currentPit = page.pitId;

    if (page.hits.length === 0) {
      if (records.length !== exactTotal) reject("premature_empty_page");
      foundEmptyPage = true;
      previousSearchAfter = null;
      continue;
    }

    for (const rawHit of page.hits) {
      const timestampText = rawHit.sort[0];
      const timestamp = parseNanoseconds(
        timestampText,
        "record_cursor_timestamp",
      );
      const shardDoc = rawHit.sort[1];
      if (timestamp < profile.start || timestamp >= profile.end) {
        reject("record_outside_half_open_window");
      }
      if (compareCursor(timestamp, shardDoc, previousCursor) <= 0) {
        reject("cursor_repeated_or_reversed");
      }
      previousCursor = [timestamp, shardDoc];
      const fields = Object.hasOwn(rawHit, "fields")
        ? rawHit.fields
        : Object.create(null);
      const timestampField = fields["@timestamp"];
      if (
        !Array.isArray(timestampField) ||
        timestampField.length !== 1 ||
        timestampField[0] !== timestampText
      ) {
        reject("timestamp_field_cursor_mismatch");
      }
      records.push({
        cursor: [timestampText, shardDoc],
        fields,
        id: `elastic-alert:${String(records.length).padStart(12, "0")}`,
      });
      if (records.length > profile.request.max_hits) reject("max_hits_exceeded");
    }
    const finalHit = page.hits.at(-1);
    previousSearchAfter = [finalHit.sort[0], finalHit.sort[1]];
  }

  if (exactTotal === null || records.length !== exactTotal) {
    reject("record_total_not_closed");
  }
  const recordsJsonl = canonicalRecords(records);
  return Object.freeze({
    captureMediaType: ELASTIC_CAPTURE_MEDIA_TYPE,
    claimScope: "receipt-internal-consistency",
    connectorId: ELASTIC_CONNECTOR_ID,
    connectorVersion: expectedConnectorVersion,
    expectedRequestDigest: sha256(expectedRequestBytes),
    recordCount: records.length,
    recordsDigest: sha256(recordsJsonl),
    recordsJsonl,
    receiptDigest: sha256(receiptBytes),
    sourceAuthenticity: "not-established",
    sourceLocatorDigest: expectedEndpointOriginDigest,
    sourceProduct: "Elasticsearch",
    sourceVersion: null,
    verifierId: ELASTIC_VERIFIER_ID,
  });
}

export function elasticVerificationSummary(
  verification,
  {
    verifierPackageVersion = null,
    verifierSourceSetDigest = null,
  } = {},
) {
  return {
    capture_media_type: verification.captureMediaType,
    claim_scope: verification.claimScope,
    connector_id: verification.connectorId,
    connector_version: verification.connectorVersion,
    expected_request_digest: verification.expectedRequestDigest,
    record_count: verification.recordCount,
    records_digest: verification.recordsDigest,
    receipt_digest: verification.receiptDigest,
    source_authenticity: verification.sourceAuthenticity,
    source_locator_digest: verification.sourceLocatorDigest,
    source_product: verification.sourceProduct,
    source_version: verification.sourceVersion,
    status: "verified",
    verifier_id: verification.verifierId,
    verifier_package_version: verifierPackageVersion,
    verifier_source_set_digest: verifierSourceSetDigest,
  };
}
