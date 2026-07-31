#!/usr/bin/env node

import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { pathToFileURL } from "node:url";

import {
  canonicalBenchmarkReceipt,
  verifyBenchmarkReleaseBytes,
} from "./benchmark-verifier.js";
import { deriveVerifierSourceIdentity } from "./source-identity.js";

const MAX_INPUT_BYTES = 16 * 1024 * 1024;

async function boundedRead(filePath) {
  if (!Number.isInteger(constants.O_NOFOLLOW)) {
    throw new Error("O_NOFOLLOW is required for benchmark input reads");
  }
  const handle = await open(
    filePath,
    constants.O_RDONLY | constants.O_NOFOLLOW,
  );
  try {
    const metadata = await handle.stat();
    if (
      !metadata.isFile() ||
      metadata.nlink !== 1 ||
      metadata.size < 1 ||
      metadata.size > MAX_INPUT_BYTES
    ) {
      throw new Error("input is not a bounded regular file");
    }
    const bytes = Buffer.alloc(metadata.size);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(
        bytes,
        offset,
        bytes.length - offset,
        offset,
      );
      if (bytesRead === 0) throw new Error("input ended before its declared size");
      offset += bytesRead;
    }
    const closing = await handle.stat();
    if (
      closing.dev !== metadata.dev ||
      closing.ino !== metadata.ino ||
      closing.mode !== metadata.mode ||
      closing.nlink !== metadata.nlink ||
      closing.size !== metadata.size ||
      closing.mtimeMs !== metadata.mtimeMs ||
      closing.ctimeMs !== metadata.ctimeMs
    ) {
      throw new Error("input changed while it was read");
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

function parseArguments(arguments_) {
  const parsed = {
    sources: new Map(),
  };
  for (let index = 0; index < arguments_.length; index += 1) {
    const option = arguments_[index];
    const value = arguments_[index + 1];
    if (value === undefined) throw new Error(`missing value for ${option}`);
    if (option === "--source") {
      const separator = value.indexOf("=");
      if (separator < 1 || separator === value.length - 1) {
        throw new Error("--source requires SCENARIO=SNAPSHOT");
      }
      const scenario = value.slice(0, separator);
      if (parsed.sources.has(scenario)) {
        throw new Error(`duplicate source scenario: ${scenario}`);
      }
      parsed.sources.set(scenario, value.slice(separator + 1));
    } else {
      const field = {
        "--index": "index",
        "--semantic": "semantic",
      }[option];
      if (field === undefined || parsed[field] !== undefined) {
        throw new Error(`unknown or duplicate option: ${option}`);
      }
      parsed[field] = value;
    }
    index += 1;
  }
  if (
    parsed.index === undefined ||
    parsed.semantic === undefined ||
    parsed.sources.size !== 3
  ) {
    throw new Error("required benchmark inputs are missing");
  }
  return parsed;
}

export async function executeBenchmarkVerification(arguments_) {
  try {
    const parsed = parseArguments(arguments_);
    const sourceIdentity = await deriveVerifierSourceIdentity();
    const implementation = {
      id: sourceIdentity.id,
      digest: sourceIdentity.digest,
      version: sourceIdentity.version,
    };
    const sourceBundles = new Map();
    for (const [scenario, filePath] of parsed.sources) {
      sourceBundles.set(scenario, await boundedRead(filePath));
    }
    const { receipt } = verifyBenchmarkReleaseBytes({
      implementation,
      indexBytes: await boundedRead(parsed.index),
      semanticResultBytes: await boundedRead(parsed.semantic),
      sourceBundles,
    });
    return {
      exitCode:
        receipt.status === "verified"
          ? 0
          : receipt.status === "unsupported"
            ? 4
            : 1,
      stdout: Buffer.concat([canonicalBenchmarkReceipt(receipt), Buffer.from("\n")]),
    };
  } catch {
    return {
      exitCode: 3,
      stdout: Buffer.from(
        '{"agreement":"not-compared","issues":[{"code":"verifier-error","detail":"independent semantic verification did not complete","path":null}],"status":"rejected","wire_schema":"assurance-lab.benchmark.semantic-verification-cli-error/v1"}\n',
      ),
    };
  }
}

async function main() {
  if (process.argv.length === 2) {
    process.stderr.write(
      "usage: benchmark-verify --index INDEX.json --semantic RESULT.json " +
        "--source SCENARIO=SOURCE.cab.snapshot (three times)\n",
    );
    process.exitCode = 2;
    return;
  }
  const outcome = await executeBenchmarkVerification(process.argv.slice(2));
  process.stdout.write(outcome.stdout);
  process.exitCode = outcome.exitCode;
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  await main();
}
