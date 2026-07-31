#!/usr/bin/env node

import { spawn, spawnSync } from "node:child_process";
import {
  access,
  mkdir,
  mkdtemp,
  rm,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const DEFAULT_URL = "http://127.0.0.1:8000/web/";
const DEFAULT_OUTPUT = "docs/assets/readme-hero.png";
const DEFAULT_WIDTH = 1440;
const DEFAULT_HEIGHT = 960;
const LOAD_TIMEOUT_MS = 20_000;

const usage = () => {
  process.stdout.write(`\
Capture the README image from the evidence-verifying case page.

Usage:
  node scripts/capture-readme-hero.mjs [--url URL] [--out PATH]
    [--width PIXELS] [--height PIXELS]

Defaults:
  --url ${DEFAULT_URL}
  --out ${DEFAULT_OUTPUT}
  --width ${DEFAULT_WIDTH}
  --height ${DEFAULT_HEIGHT}

The device scale is fixed at 1.
Set CHROME_BIN to override automatic Chromium/Chrome discovery.
`);
};

const parseArguments = (argv) => {
  let url = DEFAULT_URL;
  let output = DEFAULT_OUTPUT;
  let width = DEFAULT_WIDTH;
  let height = DEFAULT_HEIGHT;

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help" || argument === "-h") {
      usage();
      process.exit(0);
    }
    if (
      argument === "--url" ||
      argument === "--out" ||
      argument === "--width" ||
      argument === "--height"
    ) {
      const value = argv[index + 1];
      if (!value) throw new Error(`${argument} requires a value`);
      if (argument === "--url") url = value;
      else if (argument === "--out") output = value;
      else if (argument === "--width") width = Number(value);
      else height = Number(value);
      index += 1;
      continue;
    }
    throw new Error(`Unknown argument: ${argument}`);
  }

  const parsedUrl = new URL(url);
  if (
    parsedUrl.protocol !== "http:" ||
    !["127.0.0.1", "localhost", "[::1]"].includes(parsedUrl.hostname)
  ) {
    throw new Error("--url must point to a local HTTP server");
  }
  if (!Number.isInteger(width) || width < 640 || width > 2400) {
    throw new Error("--width must be an integer from 640 through 2400");
  }
  if (!Number.isInteger(height) || height < 320 || height > 1600) {
    throw new Error("--height must be an integer from 320 through 1600");
  }
  return { url: parsedUrl.href, output: resolve(output), width, height };
};

const findChrome = async () => {
  if (process.env.CHROME_BIN) {
    await access(process.env.CHROME_BIN);
    return process.env.CHROME_BIN;
  }
  for (const name of [
    "chromium-browser",
    "chromium",
    "google-chrome",
    "google-chrome-stable",
  ]) {
    const result = spawnSync("sh", ["-c", `command -v ${name}`], {
      encoding: "utf8",
    });
    if (result.status === 0 && result.stdout.trim()) return result.stdout.trim();
  }
  throw new Error("No Chromium or Chrome executable found; set CHROME_BIN");
};

class CdpClient {
  constructor(input, output) {
    this.nextId = 1;
    this.pending = new Map();
    this.input = input;
    this.output = output;
    this.buffer = Buffer.alloc(0);
    this.output.on("data", (chunk) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      for (;;) {
        const boundary = this.buffer.indexOf(0);
        if (boundary === -1) break;
        const bytes = this.buffer.subarray(0, boundary);
        this.buffer = this.buffer.subarray(boundary + 1);
        if (bytes.length === 0) continue;
        const message = JSON.parse(bytes.toString("utf8"));
        if (!message.id) continue;
        const request = this.pending.get(message.id);
        if (!request) continue;
        this.pending.delete(message.id);
        if (message.error) {
          request.reject(new Error(message.error.message));
        } else {
          request.resolve(message.result);
        }
      }
    });
    this.output.on("error", (error) => {
      for (const request of this.pending.values()) request.reject(error);
      this.pending.clear();
    });
  }

  send(method, params = {}, sessionId) {
    const id = this.nextId;
    this.nextId += 1;
    return new Promise((resolveRequest, rejectRequest) => {
      this.pending.set(id, {
        resolve: resolveRequest,
        reject: rejectRequest,
      });
      const message = { id, method, params };
      if (sessionId) message.sessionId = sessionId;
      this.input.write(`${JSON.stringify(message)}\0`, (error) => {
        if (!error) return;
        this.pending.delete(id);
        rejectRequest(error);
      });
    });
  }

  close() {
    this.input.end();
  }
}

const evaluate = async (client, sessionId, expression) => {
  const result = await client.send(
    "Runtime.evaluate",
    {
      expression,
      returnByValue: true,
      awaitPromise: true,
    },
    sessionId,
  );
  if (result.exceptionDetails) {
    throw new Error(result.exceptionDetails.text ?? "Browser evaluation failed");
  }
  return result.result.value;
};

const waitForVerifiedCase = async (client, sessionId) => {
  const deadline = Date.now() + LOAD_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const state = await evaluate(
      client,
      sessionId,
      `(() => {
        const status = document.querySelector("#integrity-status");
        const finding = document.querySelector("#finding");
        return {
          ready: status?.dataset.state === "verified" && !finding?.hidden,
          status: status?.textContent?.trim() ?? "",
          error: document.querySelector("#load-error-detail")?.textContent?.trim() ?? "",
        };
      })()`,
    );
    if (state.ready) return state.status;
    if (state.error) throw new Error(`Case page rejected its evidence: ${state.error}`);
    await delay(100);
  }
  throw new Error("Timed out before the case page verified its evidence");
};

const capture = async ({ url, output, width, height }) => {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`Local case page returned HTTP ${response.status}: ${url}`);
  }

  const chrome = await findChrome();
  const cacheRoot = join(homedir(), ".cache");
  await mkdir(cacheRoot, { recursive: true });
  const profileDirectory = await mkdtemp(
    join(cacheRoot, "control-assurance-readme-"),
  );
  const chromeProcess = spawn(
    chrome,
    [
      "--headless",
      "--disable-gpu",
      "--no-sandbox",
      "--hide-scrollbars",
      "--no-first-run",
      "--no-default-browser-check",
      "--force-device-scale-factor=1",
      "--remote-debugging-pipe",
      `--user-data-dir=${profileDirectory}`,
      "about:blank",
    ],
    { stdio: ["ignore", "ignore", "ignore", "pipe", "pipe"] },
  );

  let client;
  try {
    client = new CdpClient(chromeProcess.stdio[3], chromeProcess.stdio[4]);
    const { targetId } = await client.send("Target.createTarget", {
      url: "about:blank",
    });
    const { sessionId } = await client.send("Target.attachToTarget", {
      targetId,
      flatten: true,
    });
    await client.send("Page.enable", {}, sessionId);
    await client.send("Runtime.enable", {}, sessionId);
    await client.send(
      "Emulation.setDeviceMetricsOverride",
      {
        width,
        height,
        deviceScaleFactor: 1,
        mobile: false,
      },
      sessionId,
    );
    await client.send("Page.navigate", { url }, sessionId);
    const verifiedStatus = await waitForVerifiedCase(client, sessionId);
    const visibleFacts = await evaluate(
      client,
      sessionId,
      `({
        headline: document.querySelector("#case-headline")?.textContent?.trim() ?? "",
        classification:
          document.querySelector("#case-classification")?.textContent?.trim() ?? "",
        bundle: document.querySelector("#case-meta")?.textContent?.trim() ?? "",
      })`,
    );
    if (
      visibleFacts.headline !==
        "Nothing left the system. The first control still failed." ||
      visibleFacts.classification !== "Masked Target Failure" ||
      !visibleFacts.bundle.startsWith("Bundle …") ||
      !visibleFacts.bundle.endsWith(" · simulated")
    ) {
      throw new Error(
        `Refusing to capture an unexpected case state: ${JSON.stringify(visibleFacts)}`,
      );
    }

    const screenshot = await client.send(
      "Page.captureScreenshot",
      {
        format: "png",
        fromSurface: true,
        captureBeyondViewport: false,
      },
      sessionId,
    );
    const bytes = Buffer.from(screenshot.data, "base64");
    if (
      bytes.readUInt32BE(16) !== width ||
      bytes.readUInt32BE(20) !== height
    ) {
      throw new Error("Chrome returned a screenshot with unexpected dimensions");
    }
    await mkdir(dirname(output), { recursive: true });
    await writeFile(output, bytes);
    process.stdout.write(
      [
        `Captured ${output}`,
        `Source: ${url}`,
        `State: ${verifiedStatus}`,
        `Viewport: ${width}x${height} @ 1x`,
        `Bytes: ${bytes.length}`,
      ].join("\n") + "\n",
    );
  } finally {
    client?.close();
    if (chromeProcess.exitCode === null) {
      chromeProcess.kill("SIGTERM");
      await Promise.race([
        new Promise((resolveExit) => {
          chromeProcess.once("exit", resolveExit);
        }),
        delay(2_000),
      ]);
    }
    if (chromeProcess.exitCode === null) {
      chromeProcess.kill("SIGKILL");
    }
    await rm(profileDirectory, {
      recursive: true,
      force: true,
      maxRetries: 5,
      retryDelay: 100,
    });
  }
};

try {
  await capture(parseArguments(process.argv.slice(2)));
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
