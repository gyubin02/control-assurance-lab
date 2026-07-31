#!/usr/bin/env node

import { constants as fsConstants } from "node:fs";
import { open } from "node:fs/promises";
import { pathToFileURL } from "node:url";

import {
  DEFENDER_XDR_RECEIPT_LIMITS,
  defenderXDRVerificationSummary,
  verifyDefenderXDRCapture,
} from "./defender-xdr-verifier.js";
import { deriveVerifierSourceIdentity } from "./source-identity.js";
import { canonicalize } from "./strict-json.js";

const EXPECTED_REQUEST_MAX_BYTES = 64 * 1024;
const FAILURE = Buffer.from(
  '{"status":"verification_error"}\n',
  "utf8",
);

async function readPinnedRegularFile(path, maximumBytes) {
  if (typeof fsConstants.O_NOFOLLOW !== "number") {
    throw new Error("O_NOFOLLOW is unavailable");
  }
  const handle = await open(
    path,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
  );
  try {
    const before = await handle.stat({ bigint: true });
    if (
      !before.isFile() ||
      before.nlink !== 1n ||
      before.size < 0n ||
      before.size > BigInt(maximumBytes)
    ) {
      throw new Error("input is not a bounded single-link regular file");
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    for (const name of [
      "dev",
      "ino",
      "mode",
      "nlink",
      "size",
      "mtimeNs",
      "ctimeNs",
    ]) {
      if (before[name] !== after[name]) {
        throw new Error("input changed while being read");
      }
    }
    if (bytes.length !== Number(before.size)) {
      throw new Error("input length changed while being read");
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

function parseArguments(argv) {
  const values = Object.create(null);
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (
      value === undefined ||
      ![
        "--receipt",
        "--expected-request",
        "--expected-endpoint-origin-digest",
        "--expected-connector-version",
        "--records-output",
      ].includes(flag) ||
      Object.hasOwn(values, flag)
    ) {
      return null;
    }
    values[flag] = value;
  }
  for (const required of [
    "--receipt",
    "--expected-request",
    "--expected-endpoint-origin-digest",
    "--expected-connector-version",
  ]) {
    if (!Object.hasOwn(values, required)) return null;
  }
  return values;
}

export async function executeDefenderXDRVerification(argv) {
  const args = parseArguments(argv);
  if (args === null) return { exitCode: 2, stdout: Buffer.alloc(0) };
  try {
    const sourceIdentityBefore = await deriveVerifierSourceIdentity();
    const [receipt, expectedRequest] = await Promise.all([
      readPinnedRegularFile(
        args["--receipt"],
        DEFENDER_XDR_RECEIPT_LIMITS.maxBytes,
      ),
      readPinnedRegularFile(
        args["--expected-request"],
        EXPECTED_REQUEST_MAX_BYTES,
      ),
    ]);
    const verification = verifyDefenderXDRCapture(receipt, {
      expectedConnectorVersion: args["--expected-connector-version"],
      expectedEndpointOriginDigest:
        args["--expected-endpoint-origin-digest"],
      expectedRequest,
    });
    const sourceIdentityAfter = await deriveVerifierSourceIdentity();
    if (
      sourceIdentityBefore.digest !== sourceIdentityAfter.digest ||
      sourceIdentityBefore.version !== sourceIdentityAfter.version
    ) {
      throw new Error("verifier source set changed during verification");
    }
    if (Object.hasOwn(args, "--records-output")) {
      const outputHandle = await open(
        args["--records-output"],
        fsConstants.O_WRONLY |
          fsConstants.O_CREAT |
          fsConstants.O_EXCL |
          fsConstants.O_NOFOLLOW,
        0o600,
      );
      try {
        await outputHandle.writeFile(verification.recordsJsonl);
        await outputHandle.sync();
      } finally {
        await outputHandle.close();
      }
    }
    return {
      exitCode: 0,
      stdout: Buffer.concat([
        canonicalize(
          defenderXDRVerificationSummary(verification, {
            verifierPackageVersion: sourceIdentityAfter.version,
            verifierSourceSetDigest: sourceIdentityAfter.digest,
          }),
        ),
        Buffer.from("\n"),
      ]),
    };
  } catch {
    return { exitCode: 1, stdout: FAILURE };
  }
}

async function main() {
  const outcome = await executeDefenderXDRVerification(
    process.argv.slice(2),
  );
  if (outcome.exitCode === 2) {
    process.stderr.write(
      "usage: defender-xdr-capture-verify --receipt FILE " +
        "--expected-request FILE " +
        "--expected-endpoint-origin-digest sha256:HEX " +
        "--expected-connector-version VERSION " +
        "[--records-output NEW_FILE]\n",
    );
  } else {
    process.stdout.write(outcome.stdout);
  }
  process.exitCode = outcome.exitCode;
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  await main();
}
