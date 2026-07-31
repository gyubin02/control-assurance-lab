#!/usr/bin/env node

import { pathToFileURL } from "node:url";

import {
  canonicalResult,
  verifierErrorResult,
  verifyBundle,
} from "./verifier.js";

const FIXED_VERIFIER_ERROR = Buffer.concat([
  canonicalResult(verifierErrorResult()),
  Buffer.from("\n"),
]);

export async function executeVerification(
  root,
  {
    verify = verifyBundle,
    serialize = canonicalResult,
  } = {},
) {
  try {
    const verification = await verify(root);
    const encoded = serialize(verification);
    return {
      exitCode: verification.status === "integrity_verified" ? 0 : 1,
      stdout: Buffer.concat([encoded, Buffer.from("\n")]),
    };
  } catch {
    return {
      exitCode: 3,
      stdout: FIXED_VERIFIER_ERROR,
    };
  }
}

async function main() {
  const [root, ...rest] = process.argv.slice(2);
  if (root === undefined || rest.length !== 0) {
    process.stderr.write("usage: cab-verify BUNDLE_DIRECTORY\n");
    process.exitCode = 2;
    return;
  }
  const outcome = await executeVerification(root);
  process.stdout.write(outcome.stdout);
  process.exitCode = outcome.exitCode;
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  await main();
}
