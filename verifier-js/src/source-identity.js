import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, opendir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

import { canonicalize } from "./strict-json.js";

export const VERIFIER_IMPLEMENTATION_ID =
  "control-assurance/independent-lifecycle-semantic-verifier-js";

const SOURCE_SET_SCHEMA = "assurance-lab.verifier-source-set/v1";
const PACKAGE_NAME = "cab-integrity-verifier";
const MAX_SOURCE_BYTES = 16 * 1024 * 1024;
const MAX_SOURCE_FILES = 64;
const MAX_SOURCE_SET_BYTES = 64 * 1024 * 1024;
const SOURCE_NAME = /^[A-Za-z0-9._-]+\.js$/;
const DEFAULT_PACKAGE_ROOT = fileURLToPath(new URL("../", import.meta.url));

function digest(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function sameOpenedIdentity(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

async function securelyOpenAndReadSingleLinkFile(filePath) {
  if (!Number.isInteger(constants.O_NOFOLLOW)) {
    throw new Error("O_NOFOLLOW is required to derive verifier source identity");
  }
  const flags = constants.O_RDONLY | constants.O_NOFOLLOW;
  const handle = await open(filePath, flags);
  try {
    const before = await handle.stat();
    if (
      !before.isFile() ||
      before.nlink !== 1 ||
      before.size < 1 ||
      before.size > MAX_SOURCE_BYTES
    ) {
      throw new Error("verifier source is not a bounded single-link regular file");
    }
    const bytes = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(
        bytes,
        offset,
        bytes.length - offset,
        offset,
      );
      if (bytesRead === 0) {
        throw new Error("verifier source ended before its opened size");
      }
      offset += bytesRead;
    }
    return { before, bytes, filePath, handle };
  } catch (error) {
    await handle.close();
    throw error;
  }
}

function sameDirectoryIdentity(left, right) {
  return (
    left.isDirectory() &&
    right.isDirectory() &&
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

function exactSourceNames(entries, label) {
  if (entries.length === 0 || entries.length > MAX_SOURCE_FILES) {
    throw new Error(`verifier source set ${label} exceeds its file bound`);
  }
  const names = [];
  for (const entry of entries) {
    if (!entry.isFile() || !SOURCE_NAME.test(entry.name)) {
      throw new Error(
        `verifier source set ${label} contains a foreign member`,
      );
    }
    names.push(entry.name);
  }
  names.sort();
  if (new Set(names).size !== names.length) {
    throw new Error(`verifier source set ${label} is ambiguous`);
  }
  return names;
}

async function boundedSourceEntries(sourceDescriptorPath, label) {
  const directory = await opendir(sourceDescriptorPath);
  const entries = [];
  try {
    while (true) {
      const entry = await directory.read();
      if (entry === null) {
        break;
      }
      entries.push(entry);
      if (entries.length > MAX_SOURCE_FILES) {
        throw new Error(`verifier source set ${label} exceeds its file bound`);
      }
    }
  } finally {
    await directory.close();
  }
  return entries;
}

export async function deriveVerifierSourceIdentity(
  packageRoot = DEFAULT_PACKAGE_ROOT,
  options = {},
) {
  if (
    options === null ||
    Array.isArray(options) ||
    typeof options !== "object" ||
    Object.keys(options).some(
      (key) => key !== "beforeFinalIdentityCheck",
    ) ||
    (
      options.beforeFinalIdentityCheck !== undefined &&
      typeof options.beforeFinalIdentityCheck !== "function"
    )
  ) {
    throw new Error("verifier identity options are invalid");
  }
  if (
    !Number.isInteger(constants.O_NOFOLLOW) ||
    !Number.isInteger(constants.O_DIRECTORY)
  ) {
    throw new Error(
      "O_NOFOLLOW and O_DIRECTORY are required to derive verifier identity",
    );
  }
  const directoryFlags =
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;
  const packageHandle = await open(packageRoot, directoryFlags);
  try {
    const packageBefore = await packageHandle.stat();
    if (!packageBefore.isDirectory()) {
      throw new Error("verifier package root is not a directory");
    }
    const packageDescriptorPath = `/proc/self/fd/${String(packageHandle.fd)}`;
    const sourceHandle = await open(
      join(packageDescriptorPath, "src"),
      directoryFlags,
    );
    const openedFiles = [];
    try {
      const directoryBefore = await sourceHandle.stat();
      if (!directoryBefore.isDirectory()) {
        throw new Error("verifier source directory is not a directory");
      }
      const sourceDescriptorPath = `/proc/self/fd/${String(sourceHandle.fd)}`;
      const entries = await boundedSourceEntries(
        sourceDescriptorPath,
        "before hashing",
      );
      const sourceNames = exactSourceNames(entries, "before hashing");
      const files = [];
      const openedPackage = await securelyOpenAndReadSingleLinkFile(
        join(packageDescriptorPath, "package.json"),
      );
      openedFiles.push(openedPackage);
      const packageBytes = openedPackage.bytes;
      let totalSourceBytes = packageBytes.length;
      files.push({
        path: "package.json",
        size: packageBytes.length,
        sha256: digest(packageBytes),
      });
      for (const sourceName of sourceNames) {
        const openedSource = await securelyOpenAndReadSingleLinkFile(
          join(sourceDescriptorPath, sourceName),
        );
        openedFiles.push(openedSource);
        const { bytes } = openedSource;
        totalSourceBytes += bytes.length;
        if (totalSourceBytes > MAX_SOURCE_SET_BYTES) {
          throw new Error("verifier source set exceeds its byte bound");
        }
        files.push({
          path: `src/${sourceName}`,
          size: bytes.length,
          sha256: digest(bytes),
        });
      }
      if (options.beforeFinalIdentityCheck !== undefined) {
        await options.beforeFinalIdentityCheck();
      }
      const finalEntries = await boundedSourceEntries(
        sourceDescriptorPath,
        "after hashing",
      );
      const finalSourceNames = exactSourceNames(
        finalEntries,
        "after hashing",
      );
      if (
        finalSourceNames.length !== sourceNames.length ||
        finalSourceNames.some((name, index) => name !== sourceNames[index])
      ) {
        throw new Error(
          "verifier source entry set changed while its identity was derived",
        );
      }
      for (const openedFile of openedFiles) {
        const after = await openedFile.handle.stat();
        if (!sameOpenedIdentity(openedFile.before, after)) {
          throw new Error(
            "verifier source changed while its identity was derived",
          );
        }
        const rebound = await open(
          openedFile.filePath,
          constants.O_RDONLY | constants.O_NOFOLLOW,
        );
        try {
          const reboundIdentity = await rebound.stat();
          if (!sameOpenedIdentity(after, reboundIdentity)) {
            throw new Error(
              "verifier source name no longer binds the hashed file",
            );
          }
        } finally {
          await rebound.close();
        }
      }
      const directoryAfter = await sourceHandle.stat();
      const packageAfter = await packageHandle.stat();
      if (
        !sameDirectoryIdentity(directoryBefore, directoryAfter) ||
        !sameDirectoryIdentity(packageBefore, packageAfter)
      ) {
        throw new Error("verifier source set changed while its identity was derived");
      }
      const reboundSource = await open(
        join(packageDescriptorPath, "src"),
        directoryFlags,
      );
      try {
        if (
          !sameDirectoryIdentity(
            directoryAfter,
            await reboundSource.stat(),
          )
        ) {
          throw new Error(
            "verifier source directory name no longer binds the opened directory",
          );
        }
      } finally {
        await reboundSource.close();
      }
      const reboundPackage = await open(packageRoot, directoryFlags);
      try {
        if (
          !sameDirectoryIdentity(
            packageAfter,
            await reboundPackage.stat(),
          )
        ) {
          throw new Error(
            "verifier package name no longer binds the opened directory",
          );
        }
      } finally {
        await reboundPackage.close();
      }
      let packageDocument;
      try {
        packageDocument = JSON.parse(packageBytes.toString("utf8"));
      } catch {
        throw new Error("verifier package manifest is not valid JSON");
      }
      if (
        packageDocument === null ||
        Array.isArray(packageDocument) ||
        typeof packageDocument !== "object" ||
        packageDocument.name !== PACKAGE_NAME ||
        typeof packageDocument.version !== "string" ||
        !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(packageDocument.version)
      ) {
        throw new Error("verifier package manifest has a foreign identity");
      }
      const manifest = {
        schema: SOURCE_SET_SCHEMA,
        implementation_id: VERIFIER_IMPLEMENTATION_ID,
        package: {
          name: packageDocument.name,
          version: packageDocument.version,
        },
        files,
      };
      return {
        id: VERIFIER_IMPLEMENTATION_ID,
        digest: digest(canonicalize(manifest)),
        version: packageDocument.version,
        manifest,
      };
    } finally {
      await Promise.allSettled(
        openedFiles.map(({ handle }) => handle.close()),
      );
      await sourceHandle.close();
    }
  } finally {
    await packageHandle.close();
  }
}
