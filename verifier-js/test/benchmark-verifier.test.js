import assert from "node:assert/strict";
import {
  cp,
  link,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { executeBenchmarkVerification } from "../src/benchmark-cli.js";
import {
  BENCHMARK_VERIFIER_ID,
  verifyBenchmarkReleaseBytes,
} from "../src/benchmark-verifier.js";
import {
  deriveVerifierSourceIdentity,
  VERIFIER_IMPLEMENTATION_ID,
} from "../src/source-identity.js";

const PACKAGE_ROOT = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
);

test("source identity deterministically closes package.json and every shipped source", async () => {
  const first = await deriveVerifierSourceIdentity();
  const second = await deriveVerifierSourceIdentity();
  const expectedSources = (await readdir(join(PACKAGE_ROOT, "src")))
    .filter((name) => name.endsWith(".js"))
    .sort()
    .map((name) => `src/${name}`);

  assert.equal(first.id, VERIFIER_IMPLEMENTATION_ID);
  assert.equal(first.id, BENCHMARK_VERIFIER_ID);
  assert.match(first.digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(first.version, "0.2.0");
  assert.deepEqual(first, second);
  assert.deepEqual(
    first.manifest.files.map((entry) => entry.path),
    ["package.json", ...expectedSources],
  );
  assert.ok(
    first.manifest.files.every(
      (entry) =>
        Number.isSafeInteger(entry.size) &&
        entry.size > 0 &&
        /^sha256:[0-9a-f]{64}$/.test(entry.sha256),
    ),
  );
});

test("source identity rejects a symlinked source directory", async (context) => {
  const directory = await mkdtemp(join(tmpdir(), "verifier-source-symlink-"));
  context.after(() => rm(directory, { recursive: true, force: true }));
  await writeFile(
    join(directory, "package.json"),
    await readFile(join(PACKAGE_ROOT, "package.json")),
  );
  await symlink(join(PACKAGE_ROOT, "src"), join(directory, "src"));

  await assert.rejects(
    deriveVerifierSourceIdentity(directory),
    /ELOOP|ENOTDIR|symbolic link|not a directory/i,
  );
});

test("source identity rejects a hard-linked shipped source", async (context) => {
  const directory = await mkdtemp(join(tmpdir(), "verifier-source-hardlink-"));
  context.after(() => rm(directory, { recursive: true, force: true }));
  await cp(join(PACKAGE_ROOT, "package.json"), join(directory, "package.json"));
  await cp(join(PACKAGE_ROOT, "src"), join(directory, "src"), {
    recursive: true,
  });
  await link(
    join(directory, "src", "strict-json.js"),
    join(directory, "strict-json-hardlink"),
  );

  await assert.rejects(
    deriveVerifierSourceIdentity(directory),
    /single-link regular file/,
  );
});

test("source identity rejects an unaddressed foreign source member", async (context) => {
  const directory = await mkdtemp(join(tmpdir(), "verifier-source-foreign-"));
  context.after(() => rm(directory, { recursive: true, force: true }));
  await cp(join(PACKAGE_ROOT, "package.json"), join(directory, "package.json"));
  await cp(join(PACKAGE_ROOT, "src"), join(directory, "src"), {
    recursive: true,
  });
  await writeFile(
    join(directory, "src", "mutable-loader.mjs"),
    "export default false;\n",
  );

  await assert.rejects(
    deriveVerifierSourceIdentity(directory),
    /foreign member/,
  );
});

test("source identity rejects a source file-count bomb", async (context) => {
  const directory = await mkdtemp(join(tmpdir(), "verifier-source-count-"));
  context.after(() => rm(directory, { recursive: true, force: true }));
  await cp(join(PACKAGE_ROOT, "package.json"), join(directory, "package.json"));
  await cp(join(PACKAGE_ROOT, "src"), join(directory, "src"), {
    recursive: true,
  });
  await Promise.all(
    Array.from(
      { length: 65 },
      (_unused, index) =>
        writeFile(
          join(directory, "src", `extra-${String(index).padStart(2, "0")}.js`),
          "export {};\n",
        ),
    ),
  );

  await assert.rejects(
    deriveVerifierSourceIdentity(directory),
    /file bound/,
  );
});

test("source identity detects an in-place source mutation after every read", async (context) => {
  const directory = await mkdtemp(join(tmpdir(), "verifier-source-race-"));
  context.after(() => rm(directory, { recursive: true, force: true }));
  await cp(join(PACKAGE_ROOT, "package.json"), join(directory, "package.json"));
  await cp(join(PACKAGE_ROOT, "src"), join(directory, "src"), {
    recursive: true,
  });
  const victim = join(directory, "src", "strict-json.js");

  await assert.rejects(
    deriveVerifierSourceIdentity(directory, {
      beforeFinalIdentityCheck: async () => {
        const bytes = await readFile(victim);
        await writeFile(victim, Buffer.concat([bytes, Buffer.from("\n")]));
      },
    }),
    /changed while its identity was derived/,
  );
});

test("source identity detects an atomic same-name replacement after every read", async (context) => {
  const directory = await mkdtemp(join(tmpdir(), "verifier-source-rebind-"));
  context.after(() => rm(directory, { recursive: true, force: true }));
  await cp(join(PACKAGE_ROOT, "package.json"), join(directory, "package.json"));
  await cp(join(PACKAGE_ROOT, "src"), join(directory, "src"), {
    recursive: true,
  });
  const victim = join(directory, "src", "strict-json.js");
  const replacement = join(directory, "replacement.js");

  await assert.rejects(
    deriveVerifierSourceIdentity(directory, {
      beforeFinalIdentityCheck: async () => {
        await writeFile(replacement, await readFile(victim));
        await rename(replacement, victim);
      },
    }),
    /changed while its identity was derived|name no longer binds|source set changed/,
  );
});

test("CLI rejects caller-supplied implementation identity options", async () => {
  const outcome = await executeBenchmarkVerification([
    "--implementation-id",
    "forged",
  ]);
  const receipt = JSON.parse(outcome.stdout.toString("utf8"));

  assert.equal(outcome.exitCode, 3);
  assert.equal(receipt.status, "rejected");
  assert.equal(receipt.issues[0].code, "verifier-error");
});

test("CLI returns one bounded rejection receipt for malformed arguments", async () => {
  const outcome = await executeBenchmarkVerification(["--index"]);
  const receipt = JSON.parse(outcome.stdout.toString("utf8"));

  assert.equal(outcome.exitCode, 3);
  assert.equal(receipt.status, "rejected");
  assert.equal(receipt.issues.length, 1);
  assert.equal(receipt.issues[0].code, "verifier-error");
  assert.ok(outcome.stdout.length < 4_096);
});

test("CLI refuses a symlinked indexed input before parsing its bytes", async (context) => {
  const directory = await mkdtemp(join(tmpdir(), "benchmark-input-symlink-"));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const target = join(directory, "target.json");
  const indexPath = join(directory, "index.json");
  const semanticPath = join(directory, "semantic.json");
  await writeFile(target, "{}");
  await symlink(target, indexPath);
  await writeFile(semanticPath, "{}");
  const arguments_ = [
    "--index",
    indexPath,
    "--semantic",
    semanticPath,
  ];
  for (const scenario of [
    "financial-entitlement-recovery",
    "financial-exact-correlation-detection",
    "financial-exact-session-response",
  ]) {
    const sourcePath = join(directory, `${scenario}.cab.snapshot`);
    await writeFile(sourcePath, "not-a-snapshot");
    arguments_.push("--source", `${scenario}=${sourcePath}`);
  }

  const outcome = await executeBenchmarkVerification(arguments_);
  const receipt = JSON.parse(outcome.stdout.toString("utf8"));

  assert.equal(outcome.exitCode, 3);
  assert.equal(receipt.status, "rejected");
  assert.equal(receipt.issues[0].code, "verifier-error");
});

test("library entry point refuses a foreign implementation label", () => {
  const result = verifyBenchmarkReleaseBytes({
    implementation: {
      id: "control-assurance/forged-verifier",
      digest: `sha256:${"0".repeat(64)}`,
      version: "0.2.0",
    },
    indexBytes: Buffer.from("{}"),
    semanticResultBytes: Buffer.from("{}"),
    sourceBundles: new Map(),
  });

  assert.equal(result.receipt.status, "rejected");
  assert.equal(
    result.receipt.issues[0].code,
    "verifier-identity-mismatch",
  );
});
