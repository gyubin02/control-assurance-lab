import { createHash } from "node:crypto";

import {
  canonicalize,
  parseStrictJson,
  verifyCanonicalJson,
} from "./strict-json.js";

export const DEFENDER_XDR_CAPTURE_MEDIA_TYPE =
  "application/vnd.control-assurance.defender-xdr-capture.v1+json";
export const DEFENDER_XDR_CAPTURE_SCHEMA_VERSION = "1.0.0";
export const DEFENDER_XDR_CONNECTOR_ID = "microsoft-defender-xdr-readonly";
export const DEFENDER_XDR_REQUEST_PROFILE =
  "microsoft-graph-v1.0-alertinfo-exact-count-v1";
export const DEFENDER_XDR_VERIFIER_ID =
  "control-assurance/defender-xdr-capture-verifier-js";

const MAX_RESPONSE_BYTES = 65 * 1024 * 1024;
const MAX_RECEIPT_BYTES = 90 * 1024 * 1024;
const MAX_RECORD_BYTES = 64 * 1024 * 1024;
const MAX_FIELD_VALUE_LENGTH = 256 * 1024;
const MAX_SERVICE_ROWS = 100_000;
const MAX_HITS = MAX_SERVICE_ROWS - 2;
const MAX_WINDOW_SECONDS = 30 * 24 * 60 * 60;
const MAX_TIMING_MICROSECONDS = 900 * 1_000_000;
const REQUEST_BODY_MAX_BYTES = 64 * 1024;

export const DEFENDER_XDR_RECEIPT_LIMITS = Object.freeze({
  maxBytes: MAX_RECEIPT_BYTES,
  maxDepth: 32,
  maxCollectionItems: MAX_SERVICE_ROWS + 128,
  maxStringLength: MAX_RESPONSE_BYTES * 2,
  maxLineBytes: MAX_RECEIPT_BYTES,
});

const RESPONSE_LIMITS = Object.freeze({
  maxBytes: MAX_RESPONSE_BYTES,
  maxDepth: 16,
  maxCollectionItems: MAX_SERVICE_ROWS + 32,
  maxStringLength: MAX_FIELD_VALUE_LENGTH,
  maxLineBytes: MAX_RESPONSE_BYTES,
});

const EXPECTED_REQUEST_LIMITS = Object.freeze({
  maxBytes: REQUEST_BODY_MAX_BYTES,
  maxDepth: 16,
  maxCollectionItems: 64,
  maxStringLength: REQUEST_BODY_MAX_BYTES,
  maxLineBytes: REQUEST_BODY_MAX_BYTES,
});

const RECORD_LIMITS = Object.freeze({
  maxBytes: MAX_RECORD_BYTES,
  maxDepth: 16,
  maxCollectionItems: MAX_SERVICE_ROWS,
  maxStringLength: MAX_FIELD_VALUE_LENGTH,
  maxLineBytes: 2 * 1024 * 1024,
});

const REQUEST_HEADERS = Object.freeze([
  Object.freeze(["accept", "application/json"]),
  Object.freeze(["accept-encoding", "identity"]),
  Object.freeze(["content-type", "application/json"]),
]);
const RECORDED_RESPONSE_HEADERS = new Set([
  "content-encoding",
  "content-type",
  "request-id",
]);
const ALLOWED_ODATA_CONTEXTS = new Set(
  [
    "https://dod-graph.microsoft.us",
    "https://graph.microsoft.com",
    "https://graph.microsoft.us",
  ].map(
    (origin) =>
      `${origin}/v1.0/$metadata#microsoft.graph.security.huntingQueryResults`,
  ),
);
const HUNTING_TARGET = "/v1.0/security/runHuntingQuery";
const SOURCE_PROFILE = Object.freeze({
  api: "Microsoft Graph v1.0",
  permission: "ThreatHunting.Read.All",
  table: "AlertInfo",
});

const RESULT_COLUMNS = Object.freeze([
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
]);
const ALERT_COLUMNS = Object.freeze(RESULT_COLUMNS.slice(2));
const RESULT_KEYS = new Set(RESULT_COLUMNS);

const CAPTURE_ID = /^[a-z][a-z0-9._-]{0,127}$/;
const CAPTURE_NONCE = /^[a-f0-9]{64}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const WHOLE_SECOND_UTC =
  /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$/;
const MICROSECOND_UTC =
  /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})[.]([0-9]{6})Z$/;
const SEVEN_DIGIT_UTC =
  /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})[.]([0-9]{7})Z$/;
const EXACT_TOTAL = /^(?:0|[1-9][0-9]{0,18})$/;

export class DefenderXDRCaptureVerificationError extends Error {
  constructor(code) {
    super(code);
    this.name = "DefenderXDRCaptureVerificationError";
    this.code = code;
  }
}

function reject(code) {
  throw new DefenderXDRCaptureVerificationError(code);
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
    required.some((name) => !Object.hasOwn(value, name)) ||
    keys.some((name) => !allowed.has(name))
  ) {
    reject(code);
  }
  return value;
}

function exactArray(value, maximum, code) {
  if (!Array.isArray(value) || value.length > maximum) reject(code);
  return value;
}

function exactInteger(value, minimum, maximum, code) {
  if (
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    reject(code);
  }
  return value;
}

function exactText(value, maximum, code, { allowEmpty = false } = {}) {
  if (
    typeof value !== "string" ||
    (!allowEmpty && value.length === 0) ||
    [...value].length > maximum
  ) {
    reject(code);
  }
  return value;
}

function exactDigest(value, code) {
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
  if (decoded.length > maximum || decoded.toString("base64") !== value) {
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

function leapYear(year) {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function daysInMonth(year, month) {
  if (month === 2) return leapYear(year) ? 29 : 28;
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

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

function parseUtc(value, pattern, scale, code) {
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
  const fraction = match[7] ?? "";
  return epochSeconds * scale + BigInt(fraction || "0");
}

function parseWholeSeconds(value, code) {
  return parseUtc(value, WHOLE_SECOND_UTC, 1n, code);
}

function parseMicroseconds(value, code) {
  return parseUtc(value, MICROSECOND_UTC, 1_000_000n, code);
}

function parseHundredNanoseconds(value, code) {
  return parseUtc(value, SEVEN_DIGIT_UTC, 10_000_000n, code);
}

function compareCodePoints(left, right) {
  const leftIterator = left[Symbol.iterator]();
  const rightIterator = right[Symbol.iterator]();
  for (;;) {
    const leftPoint = leftIterator.next();
    const rightPoint = rightIterator.next();
    if (leftPoint.done || rightPoint.done) {
      if (leftPoint.done && rightPoint.done) return 0;
      return leftPoint.done ? -1 : 1;
    }
    const leftValue = leftPoint.value.codePointAt(0);
    const rightValue = rightPoint.value.codePointAt(0);
    if (leftValue < rightValue) return -1;
    if (leftValue > rightValue) return 1;
  }
}

function compareTextTuple(left, right) {
  for (let index = 0; index < left.length; index += 1) {
    const order = compareCodePoints(left[index], right[index]);
    if (order !== 0) return order;
  }
  return 0;
}

function validateRequest(value) {
  const request = exactObject(
    value,
    ["capture_id", "capture_nonce", "max_hits", "profile", "window"],
    [],
    "request_outside_profile",
  );
  if (
    typeof request.capture_id !== "string" ||
    !CAPTURE_ID.test(request.capture_id) ||
    typeof request.capture_nonce !== "string" ||
    !CAPTURE_NONCE.test(request.capture_nonce) ||
    request.profile !== DEFENDER_XDR_REQUEST_PROFILE
  ) {
    reject("request_outside_profile");
  }
  exactInteger(request.max_hits, 1, MAX_HITS, "request_outside_profile");
  const window = exactObject(
    request.window,
    ["end_exclusive", "start_inclusive"],
    [],
    "request_outside_profile",
  );
  const startSeconds = parseWholeSeconds(
    window.start_inclusive,
    "request_outside_profile",
  );
  const endSeconds = parseWholeSeconds(
    window.end_exclusive,
    "request_outside_profile",
  );
  if (
    startSeconds >= endSeconds ||
    endSeconds - startSeconds > BigInt(MAX_WINDOW_SECONDS)
  ) {
    reject("request_outside_profile");
  }
  return {
    endTicks: endSeconds * 10_000_000n,
    request,
    startTicks: startSeconds * 10_000_000n,
  };
}

function queryText(request) {
  const start = request.window.start_inclusive;
  const end = request.window.end_exclusive;
  const take = request.max_hits + 2;
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
    `| take ${take}`
  );
}

function requestBody(request) {
  return canonicalize(
    {
      Query: queryText(request),
      Timespan:
        `${request.window.start_inclusive}/${request.window.end_exclusive}`,
    },
    RESPONSE_LIMITS,
  );
}

function expectedRequestValue(expectedRequest) {
  if (Buffer.isBuffer(expectedRequest)) {
    try {
      return verifyCanonicalJson(expectedRequest, EXPECTED_REQUEST_LIMITS);
    } catch {
      reject("expected_request_not_canonical");
    }
  }
  if (!isObject(expectedRequest)) reject("expected_request_missing");
  return expectedRequest;
}

function parseExchangeRequest(value) {
  const request = exactObject(
    value,
    ["body_base64", "body_digest", "headers", "method", "target"],
    [],
    "exchange_request_shape",
  );
  const body = canonicalBase64(
    request.body_base64,
    REQUEST_BODY_MAX_BYTES,
    "request_body_base64",
  );
  if (exactDigest(request.body_digest, "request_body_digest") !== sha256(body)) {
    reject("request_body_digest");
  }
  const headers = canonicalHeaders(request.headers, "request_headers");
  if (headers.some(([name]) => name === "authorization")) {
    reject("secret_in_receipt");
  }
  return {
    body,
    headers,
    method: exactText(request.method, 16, "request_method"),
    target: exactText(request.target, 2_048, "request_target"),
  };
}

function parseExchangeResponse(value) {
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

function parseTiming(value) {
  const timing = exactObject(
    value,
    ["elapsed_microseconds", "finished_at", "started_at"],
    [],
    "capture_timing",
  );
  const started = parseMicroseconds(timing.started_at, "capture_timing");
  const finished = parseMicroseconds(timing.finished_at, "capture_timing");
  const elapsed = exactInteger(
    timing.elapsed_microseconds,
    0,
    MAX_TIMING_MICROSECONDS,
    "capture_timing",
  );
  if (
    finished < started ||
    finished - started !== BigInt(elapsed)
  ) {
    reject("capture_timing");
  }
}

function requireGraphJson(response) {
  const headers = new Map(response.headers);
  const encoding = (headers.get("content-encoding") ?? "").trim().toLowerCase();
  if (encoding !== "" && encoding !== "identity") {
    reject("response_content_encoding");
  }
  const contentType = headers.get("content-type") ?? "";
  if (contentType.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    reject("response_content_type");
  }
  if (response.status !== 200) reject("response_http_status");
  try {
    const parsed = parseStrictJson(response.body, RESPONSE_LIMITS);
    if (!isObject(parsed)) reject("response_shape");
    return parsed;
  } catch (error) {
    if (error instanceof DefenderXDRCaptureVerificationError) throw error;
    reject("response_json");
  }
}

function parseSchema(value) {
  const schema = exactArray(value, RESULT_COLUMNS.length, "schema_shape");
  if (schema.length !== RESULT_COLUMNS.length) reject("schema_incomplete");
  const names = new Set();
  for (const raw of schema) {
    const member = exactObject(
      raw,
      ["name", "type"],
      ["@odata.type"],
      "schema_member_shape",
    );
    const name = exactText(member.name, 64, "schema_member_name");
    const type = exactText(member.type, 32, "schema_member_type");
    if (
      !RESULT_KEYS.has(name) ||
      names.has(name) ||
      type !== "String" ||
      (Object.hasOwn(member, "@odata.type") &&
        member["@odata.type"] !==
          "#microsoft.graph.security.singlePropertySchema")
    ) {
      reject("schema_substituted");
    }
    names.add(name);
  }
  if (names.size !== RESULT_KEYS.size) reject("schema_incomplete");
}

function parseResults(response, profile) {
  const root = exactObject(
    requireGraphJson(response),
    ["results", "schema"],
    ["@odata.context"],
    "hunting_response_shape",
  );
  if (
    Object.hasOwn(root, "@odata.context") &&
    !ALLOWED_ODATA_CONTEXTS.has(root["@odata.context"])
  ) {
    reject("odata_context_substituted");
  }
  parseSchema(root.schema);
  const results = exactArray(
    root.results,
    MAX_SERVICE_ROWS,
    "results_shape",
  );
  if (results.length === 0) reject("control_row_missing");
  const control = exactObject(
    results[0],
    RESULT_COLUMNS,
    [],
    "control_row_shape",
  );
  if (control.ControlAssuranceKind !== "control") {
    reject("control_row_missing_or_unordered");
  }
  if (
    typeof control.ControlAssuranceTotal !== "string" ||
    !EXACT_TOTAL.test(control.ControlAssuranceTotal)
  ) {
    reject("control_total_invalid");
  }
  for (const name of ALERT_COLUMNS) {
    if (control[name] !== "") reject("control_row_contains_source_data");
  }
  const exactTotal = BigInt(control.ControlAssuranceTotal);
  if (exactTotal > BigInt(profile.request.max_hits)) {
    reject("max_hits_exceeded");
  }
  if (BigInt(results.length) !== exactTotal + 1n) {
    reject("record_total_not_closed");
  }

  const records = [];
  let previousKey = null;
  for (let index = 1; index < results.length; index += 1) {
    const row = exactObject(
      results[index],
      RESULT_COLUMNS,
      [],
      "alert_row_shape",
    );
    if (
      row.ControlAssuranceKind !== "record" ||
      row.ControlAssuranceTotal !== ""
    ) {
      reject("alert_control_fields");
    }
    const fields = Object.create(null);
    for (const name of ALERT_COLUMNS) {
      fields[name] = exactText(
        row[name],
        MAX_FIELD_VALUE_LENGTH,
        "alert_field",
        { allowEmpty: name !== "Timestamp" && name !== "AlertId" },
      );
    }
    const timestamp = parseHundredNanoseconds(
      fields.Timestamp,
      "alert_timestamp",
    );
    if (timestamp < profile.startTicks || timestamp >= profile.endTicks) {
      reject("record_outside_half_open_window");
    }
    const key = ALERT_COLUMNS.map((name) => fields[name]);
    if (previousKey !== null && compareTextTuple(key, previousKey) < 0) {
      reject("record_order");
    }
    previousKey = key;
    records.push({
      fields,
      id: `defender-xdr-alert:${String(records.length).padStart(12, "0")}`,
    });
  }
  return records;
}

function canonicalRecords(records) {
  const chunks = [];
  let size = 0;
  for (const record of records) {
    let line;
    try {
      line = canonicalize(record, RECORD_LIMITS);
    } catch {
      reject("records_outside_profile");
    }
    if (line.length > RECORD_LIMITS.maxLineBytes) {
      reject("records_outside_profile");
    }
    size += line.length + 1;
    if (size > RECORD_LIMITS.maxBytes) reject("records_outside_profile");
    chunks.push(line, Buffer.from("\n"));
  }
  return Buffer.concat(chunks, size);
}

export function verifyDefenderXDRCapture(
  receiptBytes,
  {
    expectedConnectorVersion,
    expectedEndpointOriginDigest,
    expectedRequest,
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
    [...expectedConnectorVersion].some(
      (character) => character.codePointAt(0) > 0x7f,
    )
  ) {
    reject("expected_connector_version_missing");
  }

  const externalRequest = expectedRequestValue(expectedRequest);
  const profile = validateRequest(externalRequest);
  let expectedRequestBytes;
  try {
    expectedRequestBytes = canonicalize(
      externalRequest,
      EXPECTED_REQUEST_LIMITS,
    );
  } catch {
    reject("expected_request_not_canonical");
  }

  let receipt;
  try {
    receipt = verifyCanonicalJson(
      receiptBytes,
      DEFENDER_XDR_RECEIPT_LIMITS,
    );
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
      "source_profile",
      "timing",
    ],
    [],
    "receipt_shape",
  );
  if (
    root.media_type !== DEFENDER_XDR_CAPTURE_MEDIA_TYPE ||
    root.schema_version !== DEFENDER_XDR_CAPTURE_SCHEMA_VERSION
  ) {
    reject("receipt_profile_identity");
  }
  if (
    exactDigest(root.endpoint_origin_digest, "endpoint_origin_digest") !==
    expectedEndpointOriginDigest
  ) {
    reject("endpoint_origin_mismatch");
  }
  const connector = exactObject(
    root.connector,
    ["id", "version"],
    [],
    "connector_identity",
  );
  if (
    connector.id !== DEFENDER_XDR_CONNECTOR_ID ||
    connector.version !== expectedConnectorVersion
  ) {
    reject("connector_identity");
  }
  const sourceProfile = exactObject(
    root.source_profile,
    ["api", "permission", "table"],
    [],
    "source_profile",
  );
  if (
    sourceProfile.api !== SOURCE_PROFILE.api ||
    sourceProfile.permission !== SOURCE_PROFILE.permission ||
    sourceProfile.table !== SOURCE_PROFILE.table
  ) {
    reject("source_profile_substituted");
  }
  parseTiming(root.timing);

  let embeddedRequestBytes;
  try {
    embeddedRequestBytes = canonicalize(
      root.request,
      EXPECTED_REQUEST_LIMITS,
    );
  } catch {
    reject("receipt_request_invalid");
  }
  if (!equalBytes(embeddedRequestBytes, expectedRequestBytes)) {
    reject("receipt_request_mismatch");
  }
  const embeddedProfile = validateRequest(root.request);

  const exchanges = exactArray(root.exchanges, 1, "exchange_count");
  if (exchanges.length !== 1) reject("exchange_count");
  const exchange = exactObject(
    exchanges[0],
    ["operation", "request", "response", "sequence"],
    [],
    "exchange_shape",
  );
  if (exchange.operation !== "run-hunting-query" || exchange.sequence !== 0) {
    reject("exchange_lifecycle");
  }
  const request = parseExchangeRequest(exchange.request);
  if (
    request.method !== "POST" ||
    request.target !== HUNTING_TARGET ||
    !sameHeaders(request.headers, REQUEST_HEADERS) ||
    !equalBytes(request.body, requestBody(embeddedProfile.request))
  ) {
    reject("hunting_request_substituted");
  }
  const response = parseExchangeResponse(exchange.response);
  const records = parseResults(response, embeddedProfile);
  const recordsJsonl = canonicalRecords(records);

  return Object.freeze({
    captureMediaType: DEFENDER_XDR_CAPTURE_MEDIA_TYPE,
    claimScope: "receipt-internal-consistency",
    connectorId: DEFENDER_XDR_CONNECTOR_ID,
    connectorVersion: expectedConnectorVersion,
    expectedRequestDigest: sha256(expectedRequestBytes),
    recordCount: records.length,
    recordsDigest: sha256(recordsJsonl),
    recordsJsonl,
    receiptDigest: sha256(receiptBytes),
    sourceAuthenticity: "not-established",
    sourceLocatorDigest: expectedEndpointOriginDigest,
    sourceProduct: "Microsoft Defender XDR",
    sourceVersion: null,
    verifierId: DEFENDER_XDR_VERIFIER_ID,
  });
}

export function defenderXDRVerificationSummary(
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
