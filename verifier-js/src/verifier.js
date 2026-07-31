import { createHash } from "node:crypto";
import { constants as fileConstants } from "node:fs";
import fsPromises from "node:fs/promises";
import path from "node:path";

import {
  canonicalize,
  DEFAULT_JSON_LIMITS,
  StrictJsonError,
  verifyCanonicalJson,
  verifyCanonicalJsonLines,
} from "./strict-json.js";

const ROOT_MEDIA_TYPE = "application/vnd.control-assurance.bundle.v1+json";
const SCHEMA_VERSION = "1.0.0";
const PROFILE = "integrity-only";
const PAYLOAD_ROOTS = new Set(["spec", "records", "artifacts", "derived"]);
const JSONL_MEDIA_TYPES = new Set(["application/x-ndjson", "application/jsonl"]);
const SAFE_COMPONENT = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const SHA256 = /^[a-f0-9]{64}$/;
const PREFIXED_SHA256 = /^sha256:[a-f0-9]{64}$/;
const TIMESTAMP =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;
const NO_FOLLOW = fileConstants.O_NOFOLLOW;
const READ_FLAGS =
  typeof NO_FOLLOW === "number"
    ? fileConstants.O_RDONLY | (fileConstants.O_CLOEXEC ?? 0) | NO_FOLLOW
    : null;
const READ_CHUNK_BYTES = 64 * 1024;
export const VERIFIER_VERSION = "0.2.0";
export const ISSUE_REPORT_COUNT_LIMIT = 1_024;
export const ISSUE_REPORT_BYTE_LIMIT = 512 * 1024;
export const RESULT_BYTE_LIMIT = 1024 * 1024;
const RESULT_JSON_LIMITS = Object.freeze({
  ...DEFAULT_JSON_LIMITS,
  maxBytes: RESULT_BYTE_LIMIT,
});

// Generated from Python 3.12's Unicode 15.0 database. This is the exact
// category/bidirectional boundary used by evidence.bundle._safe_display_text:
// Cc, Cf, Cs, R, AL, AN, RLE, RLO, LRE, LRO, PDF, LRI, RLI, FSI, and PDI.
const PYTHON_PROHIBITED_DISPLAY = new RegExp(
  "[" +
    "\\u{0}-\\u{1F}\\u{7F}-\\u{9F}\\u{AD}\\u{5BE}\\u{5C0}\\u{5C3}\\u{5C6}" +
    "\\u{5D0}-\\u{5EA}\\u{5EF}-\\u{5F4}\\u{600}-\\u{605}\\u{608}\\u{60B}\\u{60D}" +
    "\\u{61B}-\\u{64A}\\u{660}-\\u{669}\\u{66B}-\\u{66F}\\u{671}-\\u{6D5}\\u{6DD}" +
    "\\u{6E5}-\\u{6E6}\\u{6EE}-\\u{6EF}\\u{6FA}-\\u{70D}\\u{70F}-\\u{710}" +
    "\\u{712}-\\u{72F}\\u{74D}-\\u{7A5}\\u{7B1}\\u{7C0}-\\u{7EA}\\u{7F4}-\\u{7F5}" +
    "\\u{7FA}\\u{7FE}-\\u{815}\\u{81A}\\u{824}\\u{828}\\u{830}-\\u{83E}" +
    "\\u{840}-\\u{858}\\u{85E}\\u{860}-\\u{86A}\\u{870}-\\u{88E}\\u{890}-\\u{891}" +
    "\\u{8A0}-\\u{8C9}\\u{8E2}\\u{180E}\\u{200B}-\\u{200F}\\u{202A}-\\u{202E}" +
    "\\u{2060}-\\u{2064}\\u{2066}-\\u{206F}\\u{D800}-\\u{DFFF}\\u{FB1D}" +
    "\\u{FB1F}-\\u{FB28}\\u{FB2A}-\\u{FB36}\\u{FB38}-\\u{FB3C}\\u{FB3E}" +
    "\\u{FB40}-\\u{FB41}\\u{FB43}-\\u{FB44}\\u{FB46}-\\u{FBC2}\\u{FBD3}-\\u{FD3D}" +
    "\\u{FD50}-\\u{FD8F}\\u{FD92}-\\u{FDC7}\\u{FDF0}-\\u{FDFC}\\u{FE70}-\\u{FE74}" +
    "\\u{FE76}-\\u{FEFC}\\u{FEFF}\\u{FFF9}-\\u{FFFB}\\u{10800}-\\u{10805}\\u{10808}" +
    "\\u{1080A}-\\u{10835}\\u{10837}-\\u{10838}\\u{1083C}\\u{1083F}-\\u{10855}" +
    "\\u{10857}-\\u{1089E}\\u{108A7}-\\u{108AF}\\u{108E0}-\\u{108F2}" +
    "\\u{108F4}-\\u{108F5}\\u{108FB}-\\u{1091B}\\u{10920}-\\u{10939}\\u{1093F}" +
    "\\u{10980}-\\u{109B7}\\u{109BC}-\\u{109CF}\\u{109D2}-\\u{10A00}" +
    "\\u{10A10}-\\u{10A13}\\u{10A15}-\\u{10A17}\\u{10A19}-\\u{10A35}" +
    "\\u{10A40}-\\u{10A48}\\u{10A50}-\\u{10A58}\\u{10A60}-\\u{10A9F}" +
    "\\u{10AC0}-\\u{10AE4}\\u{10AEB}-\\u{10AF6}\\u{10B00}-\\u{10B35}" +
    "\\u{10B40}-\\u{10B55}\\u{10B58}-\\u{10B72}\\u{10B78}-\\u{10B91}" +
    "\\u{10B99}-\\u{10B9C}\\u{10BA9}-\\u{10BAF}\\u{10C00}-\\u{10C48}" +
    "\\u{10C80}-\\u{10CB2}\\u{10CC0}-\\u{10CF2}\\u{10CFA}-\\u{10D23}" +
    "\\u{10D30}-\\u{10D39}\\u{10E60}-\\u{10E7E}\\u{10E80}-\\u{10EA9}\\u{10EAD}" +
    "\\u{10EB0}-\\u{10EB1}\\u{10F00}-\\u{10F27}\\u{10F30}-\\u{10F45}" +
    "\\u{10F51}-\\u{10F59}\\u{10F70}-\\u{10F81}\\u{10F86}-\\u{10F89}" +
    "\\u{10FB0}-\\u{10FCB}\\u{10FE0}-\\u{10FF6}\\u{110BD}\\u{110CD}" +
    "\\u{13430}-\\u{1343F}\\u{1BCA0}-\\u{1BCA3}\\u{1D173}-\\u{1D17A}" +
    "\\u{1E800}-\\u{1E8C4}\\u{1E8C7}-\\u{1E8CF}\\u{1E900}-\\u{1E943}\\u{1E94B}" +
    "\\u{1E950}-\\u{1E959}\\u{1E95E}-\\u{1E95F}\\u{1EC71}-\\u{1ECB4}" +
    "\\u{1ED01}-\\u{1ED3D}\\u{1EE00}-\\u{1EE03}\\u{1EE05}-\\u{1EE1F}" +
    "\\u{1EE21}-\\u{1EE22}\\u{1EE24}\\u{1EE27}\\u{1EE29}-\\u{1EE32}" +
    "\\u{1EE34}-\\u{1EE37}\\u{1EE39}\\u{1EE3B}\\u{1EE42}\\u{1EE47}\\u{1EE49}" +
    "\\u{1EE4B}\\u{1EE4D}-\\u{1EE4F}\\u{1EE51}-\\u{1EE52}\\u{1EE54}\\u{1EE57}" +
    "\\u{1EE59}\\u{1EE5B}\\u{1EE5D}\\u{1EE5F}\\u{1EE61}-\\u{1EE62}\\u{1EE64}" +
    "\\u{1EE67}-\\u{1EE6A}\\u{1EE6C}-\\u{1EE72}\\u{1EE74}-\\u{1EE77}" +
    "\\u{1EE79}-\\u{1EE7C}\\u{1EE7E}\\u{1EE80}-\\u{1EE89}\\u{1EE8B}-\\u{1EE9B}" +
    "\\u{1EEA1}-\\u{1EEA3}\\u{1EEA5}-\\u{1EEA9}\\u{1EEAB}-\\u{1EEBB}" +
    "\\u{E0001}\\u{E0020}-\\u{E007F}" +
    "]",
  "u",
);

export const DEFAULT_BUNDLE_LIMITS = Object.freeze({
  maxManifestBytes: 2 * 1024 * 1024,
  maxFiles: 10_001,
  maxDirectories: 2_048,
  maxDepth: 32,
  maxFileBytes: 1024 * 1024 * 1024,
  maxTotalBytes: 8 * 1024 * 1024 * 1024,
  maxPathBytes: 1_024,
  maxComponentBytes: 255,
  json: DEFAULT_JSON_LIMITS,
});

export class VerifierConfigurationError extends Error {
  constructor(message) {
    super(message);
    this.name = "VerifierConfigurationError";
  }
}

class TraversalLimitError extends Error {
  constructor(detail) {
    super(detail);
    this.name = "TraversalLimitError";
  }
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function issue(code, detail, filePath = null) {
  return { code, detail, path: filePath };
}

function lexicalCompare(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function compareIssues(left, right) {
  return (
    lexicalCompare(left.path ?? "", right.path ?? "") ||
    lexicalCompare(left.code, right.code) ||
    lexicalCompare(left.detail, right.detail)
  );
}

function canonicalIssueArrayDigest(issues) {
  const hash = createHash("sha256");
  hash.update("[");
  for (let index = 0; index < issues.length; index += 1) {
    if (index > 0) hash.update(",");
    hash.update(canonicalize(issues[index]));
  }
  hash.update("]");
  return `sha256:${hash.digest("hex")}`;
}

function canonicalArrayByteLength(encodedItems) {
  if (encodedItems.length === 0) return 2;
  return (
    2 +
    encodedItems.reduce((total, encoded) => total + encoded.length, 0) +
    encodedItems.length -
    1
  );
}

export function summarizeIssues(issues) {
  const unique = new Map();
  for (const entry of issues) {
    const normalized = {
      code: entry.code,
      detail: entry.detail,
      path: entry.path ?? null,
    };
    unique.set(
      JSON.stringify([normalized.path, normalized.code, normalized.detail]),
      normalized,
    );
  }
  const ordered = [...unique.values()].sort(compareIssues);
  const byCode = new Map();
  for (const entry of ordered) {
    byCode.set(entry.code, (byCode.get(entry.code) ?? 0) + 1);
  }

  const reported = [];
  const encodedReported = [];
  let reportedBytes = 2;
  for (const entry of ordered) {
    if (reported.length >= ISSUE_REPORT_COUNT_LIMIT) break;
    const encoded = canonicalize(entry);
    const candidateBytes =
      reported.length === 0
        ? 2 + encoded.length
        : reportedBytes + 1 + encoded.length;
    if (candidateBytes > ISSUE_REPORT_BYTE_LIMIT) break;
    reported.push(entry);
    encodedReported.push(encoded);
    reportedBytes = candidateBytes;
  }
  reportedBytes = canonicalArrayByteLength(encodedReported);
  return {
    issues: reported,
    summary: {
      by_code: [...byCode.entries()]
        .sort(([left], [right]) => lexicalCompare(left, right))
        .map(([code, count]) => ({ code, count })),
      canonical_set_digest: canonicalIssueArrayDigest(ordered),
      report_byte_limit: ISSUE_REPORT_BYTE_LIMIT,
      report_count_limit: ISSUE_REPORT_COUNT_LIMIT,
      reported: reported.length,
      reported_canonical_bytes: reportedBytes,
      suppressed: ordered.length - reported.length,
      total_unique: ordered.length,
    },
  };
}

function result(status, bundleId, issues, observed = null) {
  const report = summarizeIssues(issues);
  return {
    schema_version: "1.1.0",
    verifier: { name: "cab-integrity-verifier", version: VERIFIER_VERSION },
    claim_scope: "integrity-only",
    status,
    bundle_id: bundleId,
    observed,
    issue_summary: report.summary,
    issues: report.issues,
  };
}

export function verifierErrorResult() {
  return result("verifier_error", null, [
    issue("verifier-error", "verification did not complete"),
  ]);
}

function exactKeys(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new Error(`${label} has missing or unknown fields`);
  }
}

function validateLimitObject(value, expectedKeys, label) {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new VerifierConfigurationError(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new VerifierConfigurationError(
      `${label} must contain exactly the supported limit fields`,
    );
  }
  for (const key of expectedKeys) {
    if (!Number.isSafeInteger(value[key]) || value[key] <= 0) {
      throw new VerifierConfigurationError(
        `${label}.${key} must be a positive safe integer`,
      );
    }
  }
}

function validateLimits(limits) {
  const bundleKeys = [
    "maxManifestBytes",
    "maxFiles",
    "maxDirectories",
    "maxDepth",
    "maxFileBytes",
    "maxTotalBytes",
    "maxPathBytes",
    "maxComponentBytes",
  ];
  const jsonKeys = [
    "maxBytes",
    "maxDepth",
    "maxCollectionItems",
    "maxStringLength",
    "maxLineBytes",
  ];
  if (limits === null || Array.isArray(limits) || typeof limits !== "object") {
    throw new VerifierConfigurationError("bundle limits must be an object");
  }
  const actualTopLevel = Object.keys(limits).sort();
  const expectedTopLevel = [...bundleKeys, "json"].sort();
  if (
    actualTopLevel.length !== expectedTopLevel.length ||
    actualTopLevel.some((key, index) => key !== expectedTopLevel[index])
  ) {
    throw new VerifierConfigurationError(
      "bundle limits must contain exactly the supported limit fields",
    );
  }
  validateLimitObject(
    Object.fromEntries(bundleKeys.map((key) => [key, limits[key]])),
    bundleKeys,
    "bundle limits",
  );
  validateLimitObject(limits.json, jsonKeys, "JSON limits");
  if (!Number.isSafeInteger(limits.maxFiles + limits.maxDirectories)) {
    throw new VerifierConfigurationError(
      "combined file and directory entry limit exceeds the safe-integer range",
    );
  }
  if (limits.maxComponentBytes > limits.maxPathBytes) {
    throw new VerifierConfigurationError(
      "component byte limit cannot exceed the path byte limit",
    );
  }
  if (limits.json.maxLineBytes > limits.json.maxBytes) {
    throw new VerifierConfigurationError(
      "JSON line byte limit cannot exceed the JSON payload byte limit",
    );
  }
  return Object.freeze({
    ...Object.fromEntries(bundleKeys.map((key) => [key, limits[key]])),
    json: Object.freeze(Object.fromEntries(jsonKeys.map((key) => [key, limits.json[key]]))),
  });
}

function codePointLength(value) {
  let length = 0;
  for (const _character of value) length += 1;
  return length;
}

function boundedText(value, label, maximum) {
  if (typeof value !== "string") {
    throw new Error(`${label} must be a non-empty bounded string`);
  }
  const length = codePointLength(value);
  if (length < 1 || length > maximum) {
    throw new Error(`${label} must be a non-empty bounded string`);
  }
}

function safeDisplayText(value, label) {
  if (typeof value !== "string") {
    throw new Error(`${label} entries must be strings`);
  }
  if (PYTHON_PROHIBITED_DISPLAY.test(value)) {
    throw new Error(`${label} contains a control or bidirectional character`);
  }
}

function safeText(value, label, maximum) {
  boundedText(value, label, maximum);
  safeDisplayText(value, label);
}

function payloadPath(value, limits) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.startsWith("/") ||
    value.includes("\\") ||
    !/^[\x20-\x7e]+$/.test(value) ||
    Buffer.byteLength(value, "ascii") > limits.maxPathBytes
  ) {
    throw new Error("payload path must be a bounded relative ASCII POSIX path");
  }
  const parts = value.split("/");
  if (
    !PAYLOAD_ROOTS.has(parts[0]) ||
    parts.some(
      (part) =>
        part === "" ||
        part === "." ||
        part === ".." ||
        part.startsWith(".") ||
        Buffer.byteLength(part, "ascii") > limits.maxComponentBytes ||
        !SAFE_COMPONENT.test(part),
    )
  ) {
    throw new Error("payload path contains traversal or a non-portable component");
  }
}

function timestamp(value, label) {
  if (typeof value !== "string" || !TIMESTAMP.test(value)) {
    throw new Error(`${label} is not a canonical UTC timestamp`);
  }
  const [datePart, timePart] = value.slice(0, -1).split("T");
  const [year, month, day] = datePart.split("-").map(Number);
  const [hour, minute, secondAndFraction] = timePart.split(":");
  const second = Number(secondAndFraction.slice(0, 2));
  const lastDay = new Date(Date.UTC(year, month, 0)).getUTCDate();
  if (
    year < 1 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > lastDay ||
    Number(hour) > 23 ||
    Number(minute) > 59 ||
    second > 59
  ) {
    throw new Error(`${label} is not a valid date and time`);
  }
}

function validateStringArray(value, label, maximum = 1_000) {
  if (!Array.isArray(value) || value.length > maximum) {
    throw new Error(`${label} must be a bounded array`);
  }
  for (const item of value) safeDisplayText(item, label);
  if (new Set(value).size !== value.length) {
    throw new Error(`${label} entries must be unique`);
  }
}

function unsupportedSelectorIssues(manifest) {
  if (manifest === null || Array.isArray(manifest) || typeof manifest !== "object") {
    return [];
  }
  const expected = {
    media_type: ROOT_MEDIA_TYPE,
    schema_version: SCHEMA_VERSION,
    profile: PROFILE,
  };
  const issues = [];
  for (const [field, supported] of Object.entries(expected)) {
    const received = manifest[field];
    if (typeof received === "string" && received !== supported) {
      issues.push(
        issue(
          `unsupported-${field.replaceAll("_", "-")}`,
          `supported value is ${JSON.stringify(supported)}; received ${JSON.stringify(received)}`,
          "bundle.json",
        ),
      );
    }
  }
  return issues;
}

function validateManifest(manifest, limits) {
  exactKeys(
    manifest,
    [
      "media_type",
      "schema_version",
      "profile",
      "created_at",
      "as_of",
      "experiment",
      "evaluation",
      "parent_bundles",
      "files",
    ],
    "manifest",
  );
  for (const field of ["media_type", "schema_version", "profile"]) {
    if (typeof manifest[field] !== "string") {
      throw new Error(`manifest ${field} must be a string`);
    }
  }
  if (
    manifest.media_type !== ROOT_MEDIA_TYPE ||
    manifest.schema_version !== SCHEMA_VERSION ||
    manifest.profile !== PROFILE
  ) {
    throw new Error("manifest selector validation was not completed");
  }
  timestamp(manifest.created_at, "created_at");
  timestamp(manifest.as_of, "as_of");
  if (manifest.created_at < manifest.as_of) {
    throw new Error("bundle cannot be created before its evaluation time");
  }

  exactKeys(manifest.experiment, ["id", "spec_version", "spec_digest"], "experiment");
  safeText(manifest.experiment.id, "experiment.id", 256);
  safeText(manifest.experiment.spec_version, "experiment.spec_version", 64);
  if (!PREFIXED_SHA256.test(manifest.experiment.spec_digest)) {
    throw new Error("experiment.spec_digest must be a prefixed SHA-256");
  }

  exactKeys(manifest.evaluation, ["policy_id", "policy_digest", "evaluator"], "evaluation");
  safeText(manifest.evaluation.policy_id, "evaluation.policy_id", 256);
  if (!PREFIXED_SHA256.test(manifest.evaluation.policy_digest)) {
    throw new Error("evaluation.policy_digest must be a prefixed SHA-256");
  }
  exactKeys(
    manifest.evaluation.evaluator,
    ["name", "version", "source_revision", "image_digest"],
    "evaluator",
  );
  safeText(manifest.evaluation.evaluator.name, "evaluator.name", 128);
  safeText(manifest.evaluation.evaluator.version, "evaluator.version", 64);
  safeText(manifest.evaluation.evaluator.source_revision, "evaluator.source_revision", 256);
  if (
    manifest.evaluation.evaluator.image_digest !== null &&
    !PREFIXED_SHA256.test(manifest.evaluation.evaluator.image_digest)
  ) {
    throw new Error("evaluator.image_digest must be null or a prefixed SHA-256");
  }

  validateStringArray(manifest.parent_bundles, "parent_bundles");
  if (!Array.isArray(manifest.files) || manifest.files.length > 10_000) {
    throw new Error("files must be a bounded array");
  }
  const paths = [];
  for (const descriptor of manifest.files) {
    exactKeys(
      descriptor,
      ["path", "sha256", "size", "media_type", "role", "sensitivity", "required_for"],
      "file descriptor",
    );
    payloadPath(descriptor.path, limits);
    paths.push(descriptor.path);
    if (!SHA256.test(descriptor.sha256)) {
      throw new Error("file descriptor sha256 is invalid");
    }
    if (!Number.isSafeInteger(descriptor.size) || descriptor.size < 0) {
      throw new Error("file descriptor size is invalid");
    }
    boundedText(descriptor.media_type, "file media_type", 255);
    safeText(descriptor.role, "file role", 128);
    if (!["synthetic", "lab-internal"].includes(descriptor.sensitivity)) {
      throw new Error("file sensitivity is unsupported");
    }
    validateStringArray(descriptor.required_for, "required_for", 128);
  }
  if (paths.some((entry, index) => index > 0 && entry < paths[index - 1])) {
    throw new Error("file descriptors must be sorted by path");
  }
  if (new Set(paths).size !== paths.length) {
    throw new Error("file descriptor paths must be unique");
  }
  if (new Set(paths.map((entry) => entry.toLowerCase())).size !== paths.length) {
    throw new Error("file descriptor paths collide after ASCII case folding");
  }
}

function stable(before, after) {
  return (
    before.dev === after.dev &&
    before.ino === after.ino &&
    before.mode === after.mode &&
    before.nlink === after.nlink &&
    before.size === after.size &&
    before.mtimeNs === after.mtimeNs &&
    before.ctimeNs === after.ctimeNs
  );
}

function readFailureDetail(error, fallback) {
  if (error !== null && typeof error === "object" && typeof error.code === "string") {
    if (error.code === "ENOENT") return "entry is absent";
    if (error.code === "ELOOP") return "entry is a symbolic link";
    if (error.code === "EACCES" || error.code === "EPERM") return "entry is not readable";
    if (error.code === "ENOTDIR") return "a parent entry is not a directory";
    return fallback;
  }
  return error instanceof Error ? error.message : fallback;
}

async function stableRead(
  filePath,
  { maximum, captureMaximum = null },
) {
  if (READ_FLAGS === null) {
    throw new Error("platform cannot open bundle files without following symbolic links");
  }
  const handle = await fsPromises.open(filePath, READ_FLAGS);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile()) {
      throw new Error("entry is not a regular non-symlink file");
    }
    if (before.nlink !== 1n) {
      throw new Error("bundle files must have exactly one hard link");
    }
    if (before.size > BigInt(maximum)) {
      throw new Error("file exceeds its configured byte limit");
    }
    if (captureMaximum !== null && before.size > BigInt(captureMaximum)) {
      throw new Error("canonical artifact exceeds the JSON byte limit");
    }
    const effectiveMaximum =
      captureMaximum === null ? maximum : Math.min(maximum, captureMaximum);
    const buffer = Buffer.allocUnsafe(
      Math.min(READ_CHUNK_BYTES, Math.max(1, effectiveMaximum + 1)),
    );
    const hash = createHash("sha256");
    const chunks = captureMaximum === null ? null : [];
    let size = 0;
    for (;;) {
      const remaining = effectiveMaximum - size;
      const readLength = Math.min(buffer.length, remaining + 1);
      const { bytesRead } = await handle.read(buffer, 0, readLength, null);
      if (bytesRead === 0) break;
      if (size + bytesRead > effectiveMaximum) {
        throw new Error(
          captureMaximum === null
            ? "file exceeds its configured byte limit"
            : "canonical artifact exceeds the JSON byte limit",
        );
      }
      const observed = buffer.subarray(0, bytesRead);
      hash.update(observed);
      if (chunks !== null) chunks.push(Buffer.from(observed));
      size += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    if (
      !stable(before, after) ||
      BigInt(size) !== after.size
    ) {
      throw new Error("file changed while it was read");
    }
    return {
      bytes: chunks === null ? null : Buffer.concat(chunks, size),
      sha256: hash.digest("hex"),
      size,
      stat: after,
    };
  } finally {
    await handle.close();
  }
}

function portableTreePath(relative, limits) {
  if (
    !/^[\x20-\x7e]+$/.test(relative) ||
    Buffer.byteLength(relative, "ascii") > limits.maxPathBytes
  ) {
    return false;
  }
  return relative.split("/").every(
    (component) =>
      component.length > 0 &&
      !component.startsWith(".") &&
      Buffer.byteLength(component, "ascii") <= limits.maxComponentBytes &&
      SAFE_COMPONENT.test(component),
  );
}

async function scanTree(root, limits) {
  const files = new Map();
  const directories = new Map();
  const issues = [];
  const folded = new Map();
  let entries = 0;
  let fileCount = 0;
  let directoryCount = 0;
  let bytes = 0n;
  let complete = true;

  async function visit(directory, parentParts) {
    let directoryHandle;
    try {
      directoryHandle = await fsPromises.opendir(directory);
    } catch (error) {
      complete = false;
      issues.push(
        issue(
          "unreadable-subtree",
          readFailureDetail(error, "subtree could not be opened"),
          parentParts.length === 0 ? null : parentParts.join("/"),
        ),
      );
      return;
    }
    try {
      for await (const child of directoryHandle) {
        entries += 1;
        if (entries > limits.maxFiles + limits.maxDirectories) {
          throw new TraversalLimitError(
            "directory entry count exceeds the configured limit",
          );
        }
        const parts = [...parentParts, child.name];
        const relative = parts.join("/");
        const absolute = path.join(root, ...parts);
        let metadata;
        try {
          metadata = await fsPromises.lstat(absolute, { bigint: true });
        } catch (error) {
          complete = false;
          issues.push(
            issue(
              "unreadable-entry",
              readFailureDetail(error, "entry could not be inspected"),
              relative,
            ),
          );
          continue;
        }
        if (!portableTreePath(relative, limits)) {
          issues.push(issue("unsafe-path", "filesystem path is not portable", relative));
        }
        const lower = relative.toLowerCase();
        if (folded.has(lower) && folded.get(lower) !== relative) {
          const previous = folded.get(lower);
          const survivor = lexicalCompare(previous, relative) <= 0 ? previous : relative;
          const collision = survivor === previous ? relative : previous;
          folded.set(lower, survivor);
          issues.push(
            issue(
              "path-collision",
              "paths collide after ASCII case folding",
              collision,
            ),
          );
        } else {
          folded.set(lower, relative);
        }
        if (metadata.isSymbolicLink()) {
          fileCount += 1;
          if (fileCount > limits.maxFiles) {
            throw new TraversalLimitError("file count exceeds the configured limit");
          }
          issues.push(
            issue("unsafe-symlink", "bundle trees cannot contain symbolic links", relative),
          );
        } else if (metadata.isDirectory()) {
          directoryCount += 1;
          if (directoryCount > limits.maxDirectories) {
            throw new TraversalLimitError(
              "directory count exceeds the configured limit",
            );
          }
          directories.set(relative, metadata);
          if (parts.length >= limits.maxDepth) {
            complete = false;
            issues.push(
              issue(
                "resource-limit",
                "directory depth exceeds the configured limit",
              ),
            );
          } else {
            await visit(absolute, parts);
          }
        } else if (metadata.isFile()) {
          fileCount += 1;
          if (fileCount > limits.maxFiles) {
            throw new TraversalLimitError("file count exceeds the configured limit");
          }
          if (metadata.size > BigInt(limits.maxFileBytes)) {
            throw new TraversalLimitError(
              "file exceeds the configured per-file byte limit",
            );
          }
          files.set(relative, metadata);
          bytes += metadata.size;
          if (metadata.nlink !== 1n) {
            issues.push(issue("unsafe-hardlink", "bundle files must have one hard link", relative));
          }
          if (bytes > BigInt(limits.maxTotalBytes)) {
            throw new TraversalLimitError(
              "total bundle bytes exceed the configured limit",
            );
          }
        } else {
          fileCount += 1;
          if (fileCount > limits.maxFiles) {
            throw new TraversalLimitError("file count exceeds the configured limit");
          }
          issues.push(issue("unsafe-entry", "entry is not a regular file or directory", relative));
        }
      }
    } catch (error) {
      if (error instanceof TraversalLimitError) throw error;
      if (
        error === null ||
        typeof error !== "object" ||
        typeof error.code !== "string"
      ) {
        throw error;
      }
      complete = false;
      issues.push(
        issue(
          "unreadable-subtree",
          readFailureDetail(error, "subtree iteration failed"),
          parentParts.length === 0 ? null : parentParts.join("/"),
        ),
      );
    } finally {
      try {
        await directoryHandle.close();
      } catch (error) {
        if (error?.code !== "ERR_DIR_CLOSED") throw error;
      }
    }
  }

  try {
    await visit(root, []);
  } catch (error) {
    if (!(error instanceof TraversalLimitError)) throw error;
    complete = false;
    issues.length = 0;
    issues.push(
      issue(
        "resource-limit",
        "bundle traversal exceeded a configured resource limit",
      ),
    );
  }
  return { files, directories, issues, totalBytes: bytes, complete };
}

function treeChanged(before, after) {
  const changes = [...after.issues];
  for (const [kind, left, right] of [
    ["file", before.files, after.files],
    ["directory", before.directories, after.directories],
  ]) {
    for (const entryPath of left.keys()) {
      if (!right.has(entryPath)) {
        changes.push(issue("tree-changed", `${kind} disappeared during verification`, entryPath));
      } else if (!stable(left.get(entryPath), right.get(entryPath))) {
        changes.push(issue("entry-changed", `${kind} changed during verification`, entryPath));
      }
    }
    for (const entryPath of right.keys()) {
      if (!left.has(entryPath)) {
        changes.push(issue("tree-changed", `${kind} appeared during verification`, entryPath));
      }
    }
  }
  return changes;
}

function mediaKind(mediaType) {
  if (JSONL_MEDIA_TYPES.has(mediaType)) return "jsonl";
  if (
    mediaType === "application/json" ||
    (mediaType.startsWith("application/") && mediaType.endsWith("+json"))
  ) {
    return "json";
  }
  return null;
}

export async function verifyBundle(rootInput, limits = DEFAULT_BUNDLE_LIMITS) {
  limits = validateLimits(limits);
  const root = path.resolve(rootInput);
  let rootBefore;
  try {
    rootBefore = await fsPromises.lstat(root, { bigint: true });
    if (rootBefore.isSymbolicLink() || !rootBefore.isDirectory()) {
      return result("corrupt", null, [
        issue("unsafe-root", "bundle root must be a real directory"),
      ]);
    }
  } catch {
    return result("corrupt", null, [issue("unsafe-root", "bundle root cannot be inspected")]);
  }

  let manifestRead;
  try {
    manifestRead = await stableRead(path.join(root, "bundle.json"), {
      maximum: limits.maxManifestBytes,
      captureMaximum: Math.min(limits.maxManifestBytes, limits.json.maxBytes),
    });
  } catch (error) {
    return result("corrupt", null, [
      issue(
        "invalid-root-manifest",
        readFailureDetail(error, "root manifest could not be read"),
        "bundle.json",
      ),
    ]);
  }
  let manifest;
  try {
    manifest = verifyCanonicalJson(manifestRead.bytes, limits.json);
  } catch (error) {
    return result("corrupt", null, [
      issue("invalid-root-manifest", error.message, "bundle.json"),
    ]);
  }
  const bundleId = `cab:sha256:${manifestRead.sha256}`;
  const unsupported = unsupportedSelectorIssues(manifest);
  if (unsupported.length > 0) {
    return result("unsupported", bundleId, unsupported);
  }
  try {
    validateManifest(manifest, limits);
  } catch (error) {
    return result("corrupt", bundleId, [
      issue("invalid-root-manifest", error.message, "bundle.json"),
    ]);
  }

  const tree = await scanTree(root, limits);
  const issues = [...tree.issues];
  if (
    tree.files.has("bundle.json") &&
    !stable(manifestRead.stat, tree.files.get("bundle.json"))
  ) {
    issues.push(
      issue(
        "root-manifest-changed",
        "bundle.json did not remain the file whose bytes were parsed",
        "bundle.json",
      ),
    );
  }
  if (!tree.complete) {
    return result("corrupt", bundleId, issues, {
      manifest_sha256: manifestRead.sha256,
      payload_count: manifest.files.length,
      payload_bytes: 0,
    });
  }
  const expectedFiles = new Set(manifest.files.map((descriptor) => descriptor.path));
  const actualFiles = new Set([...tree.files.keys()].filter((entry) => entry !== "bundle.json"));
  const expectedDirectories = new Set();
  for (const filePath of expectedFiles) {
    const parts = filePath.split("/");
    for (let index = 1; index < parts.length; index += 1) {
      expectedDirectories.add(parts.slice(0, index).join("/"));
    }
  }
  for (const filePath of actualFiles) {
    if (!expectedFiles.has(filePath)) {
      issues.push(issue("unlisted-file", "file is not declared by bundle.json", filePath));
    }
  }
  for (const filePath of expectedFiles) {
    if (!actualFiles.has(filePath)) {
      issues.push(issue("missing-file", "manifested payload is absent", filePath));
    }
  }
  for (const directory of tree.directories.keys()) {
    if (!expectedDirectories.has(directory)) {
      issues.push(
        issue("unlisted-directory", "directory is not required by a payload", directory),
      );
    }
  }

  let verifiedBytes = 0;
  for (const descriptor of manifest.files) {
    if (!tree.files.has(descriptor.path)) continue;
    let payload;
    try {
      const kind = mediaKind(descriptor.media_type);
      payload = await stableRead(
        path.join(root, ...descriptor.path.split("/")),
        {
          maximum: limits.maxFileBytes,
          captureMaximum: kind === null ? null : limits.json.maxBytes,
        },
      );
    } catch (error) {
      issues.push(
        issue(
          "unreadable-payload",
          readFailureDetail(error, "payload could not be read"),
          descriptor.path,
        ),
      );
      continue;
    }
    if (!stable(tree.files.get(descriptor.path), payload.stat)) {
      issues.push(
        issue(
          "entry-changed",
          "payload read did not come from the enumerated file",
          descriptor.path,
        ),
      );
    }
    verifiedBytes += payload.size;
    if (payload.size !== descriptor.size) {
      issues.push(issue("size-mismatch", "payload size does not match manifest", descriptor.path));
    }
    if (payload.sha256 !== descriptor.sha256) {
      issues.push(issue("digest-mismatch", "payload digest does not match manifest", descriptor.path));
    }
    try {
      const kind = mediaKind(descriptor.media_type);
      if (kind === "json") verifyCanonicalJson(payload.bytes, limits.json);
      if (kind === "jsonl") verifyCanonicalJsonLines(payload.bytes, limits.json);
    } catch (error) {
      if (error instanceof StrictJsonError) {
        issues.push(issue("invalid-canonical-artifact", error.message, descriptor.path));
      } else {
        throw error;
      }
    }
  }

  try {
    const finalTree = await scanTree(root, limits);
    issues.push(...treeChanged(tree, finalTree));
    const finalManifest = await stableRead(path.join(root, "bundle.json"), {
      maximum: limits.maxManifestBytes,
      captureMaximum: Math.min(limits.maxManifestBytes, limits.json.maxBytes),
    });
    const rootAfter = await fsPromises.lstat(root, { bigint: true });
    if (
      !finalManifest.bytes.equals(manifestRead.bytes) ||
      !stable(manifestRead.stat, finalManifest.stat)
    ) {
      issues.push(issue("root-manifest-changed", "bundle.json changed during verification"));
    }
    if (!stable(rootBefore, rootAfter)) {
      issues.push(issue("root-changed", "bundle root changed during verification"));
    }
  } catch {
    issues.push(issue("root-changed", "bundle root could not be rechecked"));
  }

  return result(
    issues.length === 0 ? "integrity_verified" : "corrupt",
    bundleId,
    issues,
    {
      manifest_sha256: manifestRead.sha256,
      payload_count: manifest.files.length,
      payload_bytes: verifiedBytes,
    },
  );
}

export function canonicalResult(verification) {
  return canonicalize(verification, RESULT_JSON_LIMITS);
}
