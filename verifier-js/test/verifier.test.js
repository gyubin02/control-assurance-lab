import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { constants as fileConstants } from "node:fs";
import {
  copyFile,
  link,
  mkdtemp,
  mkdir,
  readFile,
  rename,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import fsPromises from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { executeVerification } from "../src/cli.js";
import { canonicalize, parseStrictJson } from "../src/strict-json.js";
import {
  canonicalResult,
  DEFAULT_BUNDLE_LIMITS,
  ISSUE_REPORT_BYTE_LIMIT,
  ISSUE_REPORT_COUNT_LIMIT,
  RESULT_BYTE_LIMIT,
  summarizeIssues,
  VERIFIER_VERSION,
  verifyBundle,
} from "../src/verifier.js";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

test("reports the package version used to ship this verifier", async () => {
  const packageDocument = JSON.parse(
    await readFile(new URL("../package.json", import.meta.url), "utf8"),
  );

  assert.equal(packageDocument.version, VERIFIER_VERSION);
});

function manifestFor(descriptors) {
  return {
    as_of: "2026-07-29T00:00:00.000000Z",
    created_at: "2026-07-29T00:00:01.000000Z",
    evaluation: {
      evaluator: {
        image_digest: null,
        name: "independent-test",
        source_revision: "test-fixture",
        version: "1.0.0",
      },
      policy_digest: `sha256:${"2".repeat(64)}`,
      policy_id: "integrity-fixture",
    },
    experiment: {
      id: "minimal",
      spec_digest: `sha256:${"1".repeat(64)}`,
      spec_version: "1.0.0",
    },
    files: descriptors,
    media_type: "application/vnd.control-assurance.bundle.v1+json",
    parent_bundles: [],
    profile: "integrity-only",
    schema_version: "1.0.0",
  };
}

async function fixture(payload = canonicalize({ id: "a", value: 1 }), mediaType = "application/json") {
  const root = await mkdtemp(path.join(os.tmpdir(), "cab-js-"));
  await mkdir(path.join(root, "records"));
  await writeFile(path.join(root, "records", "event.json"), payload);
  const descriptor = {
    media_type: mediaType,
    path: "records/event.json",
    required_for: ["integrity-test"],
    role: "minimal test record",
    sensitivity: "synthetic",
    sha256: sha256(payload),
    size: payload.length,
  };
  await writeFile(path.join(root, "bundle.json"), canonicalize(manifestFor([descriptor])));
  return root;
}

async function fixtureFiles(files) {
  const root = await mkdtemp(path.join(os.tmpdir(), "cab-js-many-"));
  await mkdir(path.join(root, "records"));
  const descriptors = [];
  for (const [name, content] of files) {
    const filePath = path.join(root, "records", name);
    await writeFile(filePath, content);
    descriptors.push({
      media_type: "application/octet-stream",
      path: `records/${name}`,
      required_for: ["integrity-test"],
      role: `fixture ${name}`,
      sensitivity: "synthetic",
      sha256: sha256(content),
      size: content.length,
    });
  }
  descriptors.sort((left, right) =>
    left.path < right.path ? -1 : left.path > right.path ? 1 : 0,
  );
  const manifest = canonicalize(manifestFor(descriptors));
  await writeFile(path.join(root, "bundle.json"), manifest);
  return { manifest, root };
}

const codes = (verification) => verification.issues.map((entry) => entry.code);

test("matches the RFC 8785 example for values inside the project's I-JSON profile", () => {
  const input = Buffer.from(
    '{"numbers":[333333333.33333329,4.50,2e-3,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/","literals":[null,true,false]}',
  );
  assert.equal(
    canonicalize(parseStrictJson(input)).toString("utf8"),
    '{"literals":[null,true,false],"numbers":[333333333.3333333,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}',
  );
});

test("uses Python code-point order for canonical JSONL ids", async () => {
  const pythonOrdered = Buffer.from('{"id":""}\n{"id":"𐀀"}\n');
  const root = await fixture(pythonOrdered, "application/jsonl");

  const verification = await verifyBundle(root);

  assert.equal(verification.status, "integrity_verified");
});

test("enforces the Python JSONL record-count boundary", async () => {
  const records = Array.from(
    { length: 100_001 },
    (_unused, index) => `{"id":"${String(index).padStart(6, "0")}"}\n`,
  );
  const root = await fixture(Buffer.from(records.join("")), "application/jsonl");

  const verification = await verifyBundle(root);

  assert.equal(verification.status, "corrupt");
  assert.ok(codes(verification).includes("invalid-canonical-artifact"));
  assert.match(
    verification.issues.find((entry) => entry.code === "invalid-canonical-artifact").detail,
    /record count/,
  );
});

test("verifies a minimal canonical CAB and emits its content address", async () => {
  const root = await fixture();
  const verification = await verifyBundle(root);
  const manifest = await readFile(path.join(root, "bundle.json"));

  assert.equal(verification.status, "integrity_verified");
  assert.equal(verification.bundle_id, `cab:sha256:${sha256(manifest)}`);
  assert.deepEqual(verification.observed, {
    manifest_sha256: sha256(manifest),
    payload_count: 1,
    payload_bytes: 20,
  });
  assert.deepEqual(verification.issues, []);
});

test("streams payloads without FileHandle.readFile or a file-sized read buffer", async () => {
  const root = await fixture(Buffer.alloc(2 * 1024 * 1024, 0x47), "application/octet-stream");
  const originalOpen = fsPromises.open;
  let readFileCalls = 0;
  let largestReadBuffer = 0;
  fsPromises.open = async (...arguments_) => {
    const handle = await originalOpen(...arguments_);
    const originalReadFile = handle.readFile.bind(handle);
    const originalRead = handle.read.bind(handle);
    handle.readFile = async (...readArguments) => {
      readFileCalls += 1;
      return originalReadFile(...readArguments);
    };
    handle.read = async (buffer, ...readArguments) => {
      largestReadBuffer = Math.max(largestReadBuffer, buffer.length);
      return originalRead(buffer, ...readArguments);
    };
    return handle;
  };

  let verification;
  try {
    verification = await verifyBundle(root);
  } finally {
    fsPromises.open = originalOpen;
  }

  assert.equal(verification.status, "integrity_verified");
  assert.equal(readFileCalls, 0);
  assert.ok(largestReadBuffer > 0);
  assert.ok(largestReadBuffer <= 64 * 1024);
});

test("rejects oversized canonical payloads from stat before reading their bytes", async () => {
  const payload = canonicalize({ id: "oversized", value: "x".repeat(4 * 1024) });
  const root = await fixture(payload);
  const originalOpen = fsPromises.open;
  let payloadReadCalls = 0;
  fsPromises.open = async (filePath, ...arguments_) => {
    const handle = await originalOpen(filePath, ...arguments_);
    if (path.basename(filePath.toString()) === "event.json") {
      const originalReadFile = handle.readFile.bind(handle);
      const originalRead = handle.read.bind(handle);
      handle.readFile = async (...readArguments) => {
        payloadReadCalls += 1;
        return originalReadFile(...readArguments);
      };
      handle.read = async (buffer, ...readArguments) => {
        payloadReadCalls += 1;
        return originalRead(buffer, ...readArguments);
      };
    }
    return handle;
  };
  const limits = {
    ...DEFAULT_BUNDLE_LIMITS,
    json: {
      ...DEFAULT_BUNDLE_LIMITS.json,
      maxBytes: 1024,
      maxLineBytes: 1024,
    },
  };

  let verification;
  try {
    verification = await verifyBundle(root, limits);
  } finally {
    fsPromises.open = originalOpen;
  }

  assert.equal(verification.status, "corrupt");
  assert.equal(payloadReadCalls, 0);
  assert.ok(codes(verification).includes("unreadable-payload"));
});

test("globally aborts before payload I/O when total bundle bytes exceed the limit", async () => {
  const { manifest, root } = await fixtureFiles([
    ["a.bin", Buffer.alloc(300, 0x41)],
    ["b.bin", Buffer.alloc(300, 0x42)],
  ]);
  const originalOpen = fsPromises.open;
  let payloadOpenCalls = 0;
  fsPromises.open = async (filePath, ...arguments_) => {
    if (String(filePath).endsWith(".bin")) payloadOpenCalls += 1;
    return originalOpen(filePath, ...arguments_);
  };
  const limits = {
    ...DEFAULT_BUNDLE_LIMITS,
    maxTotalBytes: manifest.length + 500,
  };

  let verification;
  try {
    verification = await verifyBundle(root, limits);
  } finally {
    fsPromises.open = originalOpen;
  }

  assert.equal(verification.status, "corrupt");
  assert.equal(payloadOpenCalls, 0);
  assert.deepEqual(
    verification.issues.filter((entry) => entry.code === "resource-limit"),
    [
      {
        code: "resource-limit",
        detail: "bundle traversal exceeded a configured resource limit",
        path: null,
      },
    ],
  );
  assert.equal(verification.observed.payload_bytes, 0);
});

test("normalizes traversal-limit failures independently of directory enumeration order", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "cab-js-order-"));
  await writeFile(path.join(root, "bundle.json"), canonicalize(manifestFor([])));
  await writeFile(path.join(root, "a.bin"), "a");
  await writeFile(path.join(root, "b.bin"), "b");
  await mkdir(path.join(root, "first"));
  await mkdir(path.join(root, "second"));
  const originalOpendir = fsPromises.opendir;
  let directoriesFirst = true;
  fsPromises.opendir = async (directory, ...arguments_) => {
    const handle = await originalOpendir(directory, ...arguments_);
    if (String(directory) !== root) return handle;
    const entries = [];
    for await (const entry of handle) entries.push(entry);
    entries.sort((left, right) => {
      if (left.isDirectory() !== right.isDirectory()) {
        const direction = directoriesFirst ? -1 : 1;
        return left.isDirectory() ? direction : -direction;
      }
      return left.name < right.name ? -1 : left.name > right.name ? 1 : 0;
    });
    return {
      async close() {},
      async *[Symbol.asyncIterator]() {
        yield* entries;
      },
    };
  };
  const limits = {
    ...DEFAULT_BUNDLE_LIMITS,
    maxDirectories: 1,
    maxFiles: 2,
  };

  let first;
  let second;
  try {
    first = await verifyBundle(root, limits);
    directoriesFirst = false;
    second = await verifyBundle(root, limits);
  } finally {
    fsPromises.opendir = originalOpendir;
  }

  assert.deepEqual(first, second);
  assert.deepEqual(first.issues, [
    {
      code: "resource-limit",
      detail: "bundle traversal exceeded a configured resource limit",
      path: null,
    },
  ]);
});

test("scans directories with bounded opendir iteration instead of readdir", async () => {
  const root = await fixture();
  const originalOpendir = fsPromises.opendir;
  const originalReaddir = fsPromises.readdir;
  let opendirCalls = 0;
  let readdirCalls = 0;
  fsPromises.opendir = async (...arguments_) => {
    opendirCalls += 1;
    return originalOpendir(...arguments_);
  };
  fsPromises.readdir = async (...arguments_) => {
    readdirCalls += 1;
    return originalReaddir(...arguments_);
  };

  let verification;
  try {
    verification = await verifyBundle(root);
  } finally {
    fsPromises.opendir = originalOpendir;
    fsPromises.readdir = originalReaddir;
  }

  assert.equal(verification.status, "integrity_verified");
  assert.ok(opendirCalls > 0);
  assert.equal(readdirCalls, 0);
});

test("reports an unreadable subtree distinctly and does no payload I/O", async () => {
  const root = await fixture();
  const originalOpendir = fsPromises.opendir;
  const originalOpen = fsPromises.open;
  let payloadOpenCalls = 0;
  fsPromises.opendir = async (directory, ...arguments_) => {
    if (path.basename(String(directory)) === "records") {
      const error = new Error("injected access failure");
      error.code = "EACCES";
      throw error;
    }
    return originalOpendir(directory, ...arguments_);
  };
  fsPromises.open = async (filePath, ...arguments_) => {
    if (path.basename(String(filePath)) === "event.json") {
      payloadOpenCalls += 1;
    }
    return originalOpen(filePath, ...arguments_);
  };

  let verification;
  try {
    verification = await verifyBundle(root);
  } finally {
    fsPromises.opendir = originalOpendir;
    fsPromises.open = originalOpen;
  }

  assert.equal(verification.status, "corrupt");
  assert.equal(payloadOpenCalls, 0);
  assert.deepEqual(verification.issues, [
    {
      code: "unreadable-subtree",
      detail: "entry is not readable",
      path: "records",
    },
  ]);
});

test("returns before payload I/O when the tree exceeds the depth limit", async () => {
  const root = await fixture();
  const originalOpen = fsPromises.open;
  let payloadOpenCalls = 0;
  fsPromises.open = async (filePath, ...arguments_) => {
    if (path.basename(String(filePath)) === "event.json") {
      payloadOpenCalls += 1;
    }
    return originalOpen(filePath, ...arguments_);
  };

  let verification;
  try {
    verification = await verifyBundle(root, {
      ...DEFAULT_BUNDLE_LIMITS,
      maxDepth: 1,
    });
  } finally {
    fsPromises.open = originalOpen;
  }

  assert.equal(verification.status, "corrupt");
  assert.equal(payloadOpenCalls, 0);
  assert.deepEqual(verification.issues, [
    {
      code: "resource-limit",
      detail: "directory depth exceeds the configured limit",
      path: null,
    },
  ]);
});

test("stops opendir iteration as soon as the entry budget is exceeded", async () => {
  const root = await fixture();
  const originalOpendir = fsPromises.opendir;
  let yieldedEntries = 0;
  fsPromises.opendir = async (...arguments_) => {
    const directory = await originalOpendir(...arguments_);
    return {
      async close() {
        try {
          await directory.close();
        } catch (error) {
          if (error?.code !== "ERR_DIR_CLOSED") throw error;
        }
      },
      async *[Symbol.asyncIterator]() {
        for await (const entry of directory) {
          yieldedEntries += 1;
          yield entry;
        }
      },
    };
  };
  const limits = {
    ...DEFAULT_BUNDLE_LIMITS,
    maxFiles: 1,
    maxDirectories: 1,
  };

  let verification;
  try {
    verification = await verifyBundle(root, limits);
  } finally {
    fsPromises.opendir = originalOpendir;
  }

  assert.equal(verification.status, "corrupt");
  assert.ok(codes(verification).includes("resource-limit"));
  assert.equal(yieldedEntries, 3);
  assert.equal(
    verification.issues.find((entry) => entry.code === "resource-limit").path,
    null,
  );
});

test("rejects malformed or incoherent verifier limits before touching the bundle", async () => {
  const root = await fixture();
  const cases = [
    { ...DEFAULT_BUNDLE_LIMITS, maxFiles: 0 },
    { ...DEFAULT_BUNDLE_LIMITS, maxFiles: Number.POSITIVE_INFINITY },
    { ...DEFAULT_BUNDLE_LIMITS, maxFiles: 1.5 },
    { ...DEFAULT_BUNDLE_LIMITS, maxFiles: "10" },
    { ...DEFAULT_BUNDLE_LIMITS, maxFiles: undefined },
    {
      ...DEFAULT_BUNDLE_LIMITS,
      maxComponentBytes: DEFAULT_BUNDLE_LIMITS.maxPathBytes + 1,
    },
    {
      ...DEFAULT_BUNDLE_LIMITS,
      json: {
        ...DEFAULT_BUNDLE_LIMITS.json,
        maxLineBytes: DEFAULT_BUNDLE_LIMITS.json.maxBytes + 1,
      },
    },
    { ...DEFAULT_BUNDLE_LIMITS, unexpected: 1 },
  ];

  for (const limits of cases) {
    await assert.rejects(
      verifyBundle(root, limits),
      (error) => error.name === "VerifierConfigurationError",
    );
  }
});

test("treats type-invalid root selectors as corrupt and unknown strings as unsupported", async () => {
  const cases = [
    ["profile", null, "corrupt"],
    ["profile", "integrity-only-v2", "unsupported"],
    ["schema_version", false, "corrupt"],
    ["schema_version", "2.0.0", "unsupported"],
    ["media_type", ["application/json"], "corrupt"],
    ["media_type", "application/vnd.example.future+json", "unsupported"],
  ];
  for (const [field, value, expected] of cases) {
    const root = await fixture();
    const manifest = parseStrictJson(await readFile(path.join(root, "bundle.json")));
    manifest[field] = value;
    await writeFile(path.join(root, "bundle.json"), canonicalize(manifest));

    const verification = await verifyBundle(root);

    assert.equal(verification.status, expected, `${field}=${JSON.stringify(value)}`);
  }
});

test("gives unsupported selectors precedence over mixed type and future-shape errors", async () => {
  const root = await fixture();
  const manifest = parseStrictJson(await readFile(path.join(root, "bundle.json")));
  manifest.schema_version = "2.0.0";
  manifest.profile = null;
  manifest.future_extension = { introduced_in: "2.0.0" };
  await writeFile(path.join(root, "bundle.json"), canonicalize(manifest));

  const verification = await verifyBundle(root);

  assert.equal(verification.status, "unsupported");
  assert.deepEqual(codes(verification), ["unsupported-schema-version"]);
});

test("rejects a byte-level payload change", async () => {
  const root = await fixture();
  await writeFile(path.join(root, "records", "event.json"), canonicalize({ id: "a", value: 2 }));

  const verification = await verifyBundle(root);

  assert.equal(verification.status, "corrupt");
  assert.ok(codes(verification).includes("digest-mismatch"));
});

test("accepts changed bytes when an attacker also rebuilds the integrity manifest", async () => {
  const root = await fixture();
  const changed = canonicalize({ id: "a", value: 2 });
  await writeFile(path.join(root, "records", "event.json"), changed);
  const descriptor = {
    media_type: "application/json",
    path: "records/event.json",
    required_for: ["integrity-test"],
    role: "minimal test record",
    sensitivity: "synthetic",
    sha256: sha256(changed),
    size: changed.length,
  };
  await writeFile(path.join(root, "bundle.json"), canonicalize(manifestFor([descriptor])));

  const verification = await verifyBundle(root);

  assert.equal(verification.status, "integrity_verified");
  assert.equal(verification.claim_scope, "integrity-only");
});

test("matches Python's prohibited display-text boundary", async () => {
  const root = await fixture();
  const manifest = parseStrictJson(await readFile(path.join(root, "bundle.json")));
  manifest.experiment.id = "invisible\u200bseparator";
  await writeFile(path.join(root, "bundle.json"), canonicalize(manifest));

  const verification = await verifyBundle(root);

  assert.equal(verification.status, "corrupt");
  assert.ok(codes(verification).includes("invalid-root-manifest"));
});

test("preserves Python's current unbounded required_for item domain", async () => {
  const root = await fixture();
  const manifest = parseStrictJson(await readFile(path.join(root, "bundle.json")));
  manifest.files[0].required_for = [""];
  await writeFile(path.join(root, "bundle.json"), canonicalize(manifest));

  const verification = await verifyBundle(root);

  assert.equal(verification.status, "integrity_verified");
});

test("rejects duplicate object keys before JSON.parse can erase them", async () => {
  const root = await fixture();
  const raw = Buffer.from('{"as_of":"2026-07-29T00:00:00.000000Z","as_of":"2026-07-29T00:00:00.000000Z"}');
  await writeFile(path.join(root, "bundle.json"), raw);

  const verification = await verifyBundle(root);

  assert.equal(verification.status, "corrupt");
  assert.ok(codes(verification).includes("invalid-root-manifest"));
});

test("rejects a valid but noncanonical root manifest", async () => {
  const root = await fixture();
  const manifest = parseStrictJson(await readFile(path.join(root, "bundle.json")));
  await writeFile(path.join(root, "bundle.json"), JSON.stringify(manifest, null, 2));

  const verification = await verifyBundle(root);

  assert.equal(verification.status, "corrupt");
  assert.ok(codes(verification).includes("invalid-root-manifest"));
});

test("rejects duplicate manifested paths", async () => {
  const root = await fixture();
  const manifest = parseStrictJson(await readFile(path.join(root, "bundle.json")));
  manifest.files.push({ ...manifest.files[0] });
  await writeFile(path.join(root, "bundle.json"), canonicalize(manifest));

  const verification = await verifyBundle(root);

  assert.equal(verification.status, "corrupt");
  assert.ok(codes(verification).includes("invalid-root-manifest"));
});

test("rejects symbolic links in the exact bundle tree", async () => {
  const root = await fixture();
  await symlink("event.json", path.join(root, "records", "alias.json"));

  const verification = await verifyBundle(root);

  assert.equal(verification.status, "corrupt");
  assert.ok(codes(verification).includes("unsafe-symlink"));
});

test("deterministically binds the opened payload inode to the scanned inode", async () => {
  const expected = Buffer.alloc(64 * 1024, 0x47);
  const actual = Buffer.alloc(expected.length, 0x42);
  const root = await fixture(expected, "application/octet-stream");
  const payloadPath = path.join(root, "records", "event.json");
  const replacementPath = `${root}-barrier-replacement`;
  await writeFile(payloadPath, actual);
  await writeFile(replacementPath, expected);

  const originalOpen = fsPromises.open;
  let injected = false;
  let observedFlags = null;
  fsPromises.open = async (filePath, flags, ...arguments_) => {
    if (!injected && String(filePath) === payloadPath) {
      injected = true;
      observedFlags = flags;
      return originalOpen(replacementPath, flags, ...arguments_);
    }
    return originalOpen(filePath, flags, ...arguments_);
  };

  let verification;
  try {
    verification = await verifyBundle(root);
  } finally {
    fsPromises.open = originalOpen;
  }

  assert.equal(injected, true);
  assert.equal(
    (observedFlags & fileConstants.O_NOFOLLOW) === fileConstants.O_NOFOLLOW,
    true,
  );
  assert.equal(verification.status, "corrupt");
  assert.deepEqual(verification.issues, [
    {
      code: "entry-changed",
      detail: "payload read did not come from the enumerated file",
      path: "records/event.json",
    },
  ]);
});

test("pins payload reads to no-follow file handles during replacement races", async () => {
  const expected = Buffer.alloc(256 * 1024, 0x47);
  const actual = Buffer.alloc(expected.length, 0x42);
  const root = await fixture(expected, "application/octet-stream");
  const payloadPath = path.join(root, "records", "event.json");
  const heldPath = `${root}-held-payload`;
  const targetPath = `${root}-outside-payload`;
  await writeFile(payloadPath, actual);
  await writeFile(targetPath, expected);

  let running = true;
  const turn = () => new Promise((resolve) => setImmediate(resolve));
  const racer = (async () => {
    while (running) {
      await rename(payloadPath, heldPath);
      await symlink(targetPath, payloadPath);
      await turn();
      await unlink(payloadPath);
      await rename(heldPath, payloadPath);
      await turn();
    }
  })();

  const results = [];
  try {
    for (let attempt = 0; attempt < 100; attempt += 1) {
      results.push(await verifyBundle(root));
    }
  } finally {
    running = false;
    await racer;
  }

  assert.equal(
    results.some((verification) => verification.status === "integrity_verified"),
    false,
  );
  assert.equal(sha256(await readFile(payloadPath)), sha256(actual));
});

test("binds an opened payload handle back to the enumerated inode", async () => {
  const expected = Buffer.alloc(256 * 1024, 0x47);
  const actual = Buffer.alloc(expected.length, 0x42);
  const root = await fixture(expected, "application/octet-stream");
  const payloadPath = path.join(root, "records", "event.json");
  const heldPath = `${root}-held-regular`;
  const targetPath = `${root}-outside-regular`;
  await writeFile(payloadPath, actual);
  await writeFile(targetPath, expected);

  let running = true;
  const turn = () => new Promise((resolve) => setImmediate(resolve));
  const racer = (async () => {
    while (running) {
      await rename(payloadPath, heldPath);
      await rename(targetPath, payloadPath);
      await turn();
      await rename(payloadPath, targetPath);
      await rename(heldPath, payloadPath);
      await turn();
    }
  })();

  const results = [];
  try {
    for (let attempt = 0; attempt < 100; attempt += 1) {
      results.push(await verifyBundle(root));
    }
  } finally {
    running = false;
    await racer;
  }

  assert.equal(
    results.some((verification) => verification.status === "integrity_verified"),
    false,
  );
  assert.equal(sha256(await readFile(payloadPath)), sha256(actual));
});

test("reports a hard-link condition once", async () => {
  const root = await fixture();
  await link(path.join(root, "records", "event.json"), `${root}-outside-hard-link`);

  const verification = await verifyBundle(root);
  const hardLinkIssues = verification.issues.filter(
    (entry) => entry.code === "unsafe-hardlink",
  );

  assert.equal(verification.status, "corrupt");
  assert.equal(hardLinkIssues.length, 1);
});

test("reports a case-folding collision once", async () => {
  const root = await fixture();
  await copyFile(
    path.join(root, "records", "event.json"),
    path.join(root, "records", "Event.json"),
  );

  const verification = await verifyBundle(root);
  const collisionIssues = verification.issues.filter(
    (entry) => entry.code === "path-collision",
  );

  assert.equal(verification.status, "corrupt");
  assert.equal(collisionIssues.length, 1);
});

test("rejects an unlisted extra file", async () => {
  const root = await fixture();
  await writeFile(path.join(root, "records", "extra.bin"), "extra");

  const verification = await verifyBundle(root);

  assert.equal(verification.status, "corrupt");
  assert.ok(codes(verification).includes("unlisted-file"));
});

test("normalizes filesystem failures independently of the root path", async () => {
  const first = await mkdtemp(path.join(os.tmpdir(), "cab-js-missing-a-"));
  const second = await mkdtemp(path.join(os.tmpdir(), "cab-js-missing-b-"));

  const firstVerification = await verifyBundle(first);
  const secondVerification = await verifyBundle(second);

  assert.deepEqual(firstVerification, secondVerification);
  assert.equal(firstVerification.status, "corrupt");
  assert.equal(firstVerification.issues[0].detail, "entry is absent");
});

test("bounds, commits to, and deterministically orders a large unique issue set", () => {
  const issues = Array.from({ length: 7_000 }, (_unused, index) => ({
    code: index % 2 === 0 ? "unsafe-path" : "unlisted-file",
    detail: index % 2 === 0 ? "filesystem path is not portable" : "file is not declared",
    path: `records/${String(index).padStart(5, "0")}-${"x".repeat(1_200)}`,
  }));
  const forward = summarizeIssues(issues);
  const reverse = summarizeIssues([...issues].reverse());
  const expectedDigest = `sha256:${sha256(canonicalize(issues))}`;

  assert.deepEqual(forward, reverse);
  assert.equal(forward.summary.total_unique, 7_000);
  assert.equal(
    forward.summary.reported + forward.summary.suppressed,
    forward.summary.total_unique,
  );
  assert.ok(forward.summary.reported <= ISSUE_REPORT_COUNT_LIMIT);
  assert.ok(forward.summary.reported_canonical_bytes <= ISSUE_REPORT_BYTE_LIMIT);
  assert.ok(forward.summary.suppressed > 0);
  assert.equal(forward.summary.canonical_set_digest, expectedDigest);
  assert.deepEqual(forward.summary.by_code, [
    { code: "unlisted-file", count: 3_500 },
    { code: "unsafe-path", count: 3_500 },
  ]);

  const verification = {
    bundle_id: null,
    claim_scope: "integrity-only",
    issue_summary: forward.summary,
    issues: forward.issues,
    observed: null,
    schema_version: "1.1.0",
    status: "corrupt",
    verifier: { name: "cab-integrity-verifier", version: "0.2.0" },
  };
  const encoded = canonicalResult(verification);
  assert.ok(encoded.length <= RESULT_BYTE_LIMIT);
  assert.equal(parseStrictJson(encoded).issue_summary.canonical_set_digest, expectedDigest);
});

test("returns one fixed machine-readable verifier error without leaking exceptions", async () => {
  const secret = "do-not-leak-this-exception";
  const verificationFailure = await executeVerification("unused", {
    verify: async () => {
      throw new Error(secret);
    },
  });
  const serializationFailure = await executeVerification("unused", {
    serialize: () => {
      throw new Error(secret);
    },
    verify: async () => ({ status: "integrity_verified" }),
  });

  assert.equal(verificationFailure.exitCode, 3);
  assert.equal(serializationFailure.exitCode, 3);
  assert.deepEqual(verificationFailure.stdout, serializationFailure.stdout);
  assert.equal(verificationFailure.stdout.includes(Buffer.from(secret)), false);
  const parsed = JSON.parse(verificationFailure.stdout.toString("utf8"));
  assert.equal(parsed.status, "verifier_error");
  assert.deepEqual(parsed.issues, [
    {
      code: "verifier-error",
      detail: "verification did not complete",
      path: null,
    },
  ]);
});

test("rejects traversal in a manifested payload path", async () => {
  const root = await fixture();
  const payload = await readFile(path.join(root, "records", "event.json"));
  const descriptor = {
    media_type: "application/json",
    path: "records/../event.json",
    required_for: ["integrity-test"],
    role: "unsafe record",
    sensitivity: "synthetic",
    sha256: sha256(payload),
    size: payload.length,
  };
  await writeFile(path.join(root, "bundle.json"), canonicalize(manifestFor([descriptor])));

  const verification = await verifyBundle(root);

  assert.equal(verification.status, "corrupt");
  assert.ok(codes(verification).includes("invalid-root-manifest"));
});

test("rejects noncanonical JSON payload bytes", async () => {
  const raw = Buffer.from('{ "id": "a", "value": 1 }');
  const root = await fixture(raw);

  const verification = await verifyBundle(root);

  assert.equal(verification.status, "corrupt");
  assert.ok(codes(verification).includes("invalid-canonical-artifact"));
});

test("rejects noncanonical JSONL order and line JSON", async () => {
  const raw = Buffer.from('{"id":"b"}\n{ "id":"a" }\n');
  const root = await fixture(raw, "application/x-ndjson");

  const verification = await verifyBundle(root);

  assert.equal(verification.status, "corrupt");
  assert.ok(codes(verification).includes("invalid-canonical-artifact"));
});

test("rejects canonical JSONL records that are not ordered by unique id", async () => {
  const raw = Buffer.from('{"id":"b"}\n{"id":"a"}\n');
  const root = await fixture(raw, "application/x-ndjson");

  const verification = await verifyBundle(root);

  assert.equal(verification.status, "corrupt");
  assert.ok(codes(verification).includes("invalid-canonical-artifact"));
});

test("rejects non-UTF8 JSON and trailing data", async (context) => {
  await context.test("non-UTF8", async () => {
    const root = await fixture();
    await writeFile(path.join(root, "bundle.json"), Buffer.from([0xff, 0xfe]));
    const verification = await verifyBundle(root);
    assert.equal(verification.status, "corrupt");
  });
  await context.test("trailing data", async () => {
    const root = await fixture();
    const manifest = await readFile(path.join(root, "bundle.json"));
    await writeFile(path.join(root, "bundle.json"), Buffer.concat([manifest, Buffer.from("\n{}")]));
    const verification = await verifyBundle(root);
    assert.equal(verification.status, "corrupt");
  });
});
