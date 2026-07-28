"use strict";

const CASE_URL = "./case.json";
const BUNDLE_ROOT = "../examples/masked-export.cab/";
const CASE_SCHEMA = "assurance-lab.financial-support-case-result/v2";
const BUNDLE_MEDIA_TYPE = "application/vnd.control-assurance.bundle.v1+json";
const BUNDLE_SCHEMA_VERSION = "1.0.0";
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const BUNDLE_ID_PATTERN = /^cab:sha256:[a-f0-9]{64}$/;
const SAFE_PATH_COMPONENT = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const SAFE_PATH_ROOTS = new Set(["spec", "records", "artifacts", "derived"]);
const MAX_MANIFEST_BYTES = 2 * 1024 * 1024;
const MAX_MANIFEST_FILES = 10_000;
const MAX_FILE_BYTES = 512 * 1024 * 1024;
const MAX_TOTAL_BYTES = 1024 * 1024 * 1024;

const required = (value, path) => {
  if (value === undefined || value === null || value === "") {
    throw new Error(`Missing required case field: ${path}`);
  }
  return value;
};

const requireObject = (value, path) => {
  required(value, path);
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${path} must be an object`);
  }
  return value;
};

const requireArray = (value, path) => {
  if (!Array.isArray(value)) {
    throw new Error(`${path} must be an array`);
  }
  return value;
};

const byId = (id) => document.getElementById(id);

const setText = (id, value) => {
  byId(id).textContent = value;
};

const setIntegrityStatus = (message, state) => {
  const status = byId("integrity-status");
  status.textContent = message;
  if (state) status.dataset.state = state;
};

const appendText = (parent, tag, className, value) => {
  const element = document.createElement(tag);
  element.className = className;
  element.textContent = value;
  parent.append(element);
  return element;
};

const humanize = (value) =>
  String(value)
    .replaceAll("_", " ")
    .replaceAll("-", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());

const toneFor = (truth) => {
  if (truth === "refuted") return "refuted";
  if (truth === "supported") return "supported";
  return "observed";
};

const decodeUtf8 = (bytes, label) => {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error(`${label} is not valid UTF-8`);
  }
};

const parseJsonBytes = (bytes, label) => {
  try {
    return JSON.parse(decodeUtf8(bytes, label));
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new Error(`${label} is not valid JSON`);
    }
    throw error;
  }
};

const fetchBytes = async (url, label) => {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`${label} returned HTTP ${response.status}`);
  }
  return new Uint8Array(await response.arrayBuffer());
};

const sha256Hex = async (bytes) => {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle || typeof subtle.digest !== "function") {
    throw new Error(
      "WebCrypto SHA-256 is unavailable. This page will not render unverified evidence.",
    );
  }
  const digest = new Uint8Array(await subtle.digest("SHA-256", bytes));
  return [...digest].map((value) => value.toString(16).padStart(2, "0")).join("");
};

const validateManifestPath = (path) => {
  if (typeof path !== "string" || path.length === 0 || path.length > 1024) {
    throw new Error("Bundle manifest contains an invalid path length");
  }
  if (
    path.startsWith("/") ||
    path.includes("\\") ||
    !/^[\x20-\x7e]+$/.test(path)
  ) {
    throw new Error(`Bundle manifest contains an unsafe path: ${String(path)}`);
  }
  const parts = path.split("/");
  if (
    !SAFE_PATH_ROOTS.has(parts[0]) ||
    parts.some(
      (part) =>
        part === "" ||
        part === "." ||
        part === ".." ||
        part.startsWith(".") ||
        part.length > 255 ||
        !SAFE_PATH_COMPONENT.test(part),
    )
  ) {
    throw new Error(`Bundle manifest contains an unsafe path: ${path}`);
  }
};

const validateManifest = (manifest, caseData) => {
  requireObject(manifest, "bundle.json");
  if (manifest.media_type !== BUNDLE_MEDIA_TYPE) {
    throw new Error("Bundle manifest media type is unsupported");
  }
  if (manifest.schema_version !== BUNDLE_SCHEMA_VERSION) {
    throw new Error("Bundle manifest schema version is unsupported");
  }
  if (manifest.profile !== caseData.profile) {
    throw new Error("Case profile does not match the verified bundle profile");
  }
  const experiment = requireObject(manifest.experiment, "bundle.experiment");
  if (!DIGEST_PATTERN.test(experiment.spec_digest)) {
    throw new Error("Bundle experiment spec digest is malformed");
  }

  const files = requireArray(manifest.files, "bundle.files");
  if (files.length === 0 || files.length > MAX_MANIFEST_FILES) {
    throw new Error("Bundle manifest file count is outside browser verification limits");
  }

  let previous = "";
  let totalBytes = 0;
  const exactPaths = new Set();
  const foldedPaths = new Set();
  for (const [index, descriptorValue] of files.entries()) {
    const descriptor = requireObject(
      descriptorValue,
      `bundle.files[${index}]`,
    );
    validateManifestPath(descriptor.path);
    if (index > 0 && descriptor.path <= previous) {
      throw new Error("Bundle manifest paths must be sorted and unique");
    }
    previous = descriptor.path;
    const folded = descriptor.path.toLowerCase();
    if (exactPaths.has(descriptor.path) || foldedPaths.has(folded)) {
      throw new Error("Bundle manifest paths collide");
    }
    exactPaths.add(descriptor.path);
    foldedPaths.add(folded);
    if (!/^[a-f0-9]{64}$/.test(descriptor.sha256)) {
      throw new Error(`Bundle file digest is malformed: ${descriptor.path}`);
    }
    if (
      !Number.isSafeInteger(descriptor.size) ||
      descriptor.size < 0 ||
      descriptor.size > MAX_FILE_BYTES
    ) {
      throw new Error(`Bundle file size is unsafe: ${descriptor.path}`);
    }
    totalBytes += descriptor.size;
    if (totalBytes > MAX_TOTAL_BYTES) {
      throw new Error("Bundle payload exceeds the browser verification limit");
    }
  }
  return files;
};

const verifyBundle = async (caseData) => {
  if (!globalThis.crypto?.subtle) {
    throw new Error(
      "WebCrypto SHA-256 is unavailable. This page will not render unverified evidence.",
    );
  }
  const bundleRoot = new URL(BUNDLE_ROOT, window.location.href);
  const manifestBytes = await fetchBytes(
    new URL("bundle.json", bundleRoot),
    "Evidence bundle manifest",
  );
  if (manifestBytes.byteLength > MAX_MANIFEST_BYTES) {
    throw new Error("Evidence bundle manifest exceeds the browser verification limit");
  }
  const manifestHex = await sha256Hex(manifestBytes);
  const observedBundleId = `cab:sha256:${manifestHex}`;
  if (!BUNDLE_ID_PATTERN.test(caseData.bundle_id)) {
    throw new Error("Case bundle identifier is malformed");
  }
  if (observedBundleId !== caseData.bundle_id) {
    throw new Error("Case result is not bound to the fetched evidence bundle");
  }

  const manifest = parseJsonBytes(manifestBytes, "bundle.json");
  const descriptors = validateManifest(manifest, caseData);
  const payloadEntries = await Promise.all(
    descriptors.map(async (descriptor) => {
      const payloadUrl = new URL(descriptor.path, bundleRoot);
      if (
        payloadUrl.origin !== bundleRoot.origin ||
        !payloadUrl.pathname.startsWith(bundleRoot.pathname)
      ) {
        throw new Error(`Bundle path escaped its root: ${descriptor.path}`);
      }
      const bytes = await fetchBytes(payloadUrl, descriptor.path);
      if (bytes.byteLength !== descriptor.size) {
        throw new Error(`Bundle file size mismatch: ${descriptor.path}`);
      }
      const observed = await sha256Hex(bytes);
      if (observed !== descriptor.sha256) {
        throw new Error(`Bundle file digest mismatch: ${descriptor.path}`);
      }
      return [descriptor.path, bytes];
    }),
  );
  const payloads = new Map(payloadEntries);
  const specBytes = required(payloads.get("spec/experiment.json"), "verified experiment spec");
  const stageBytes = required(
    payloads.get("records/stage-events.jsonl"),
    "verified stage events",
  );
  const fixtureBytes = required(
    payloads.get("spec/fixture-manifest.json"),
    "verified fixture manifest",
  );
  const attestationBytes = required(
    payloads.get("artifacts/trial-attestations.jsonl"),
    "verified trial attestations",
  );
  const specDigest = `sha256:${await sha256Hex(specBytes)}`;
  if (
    specDigest !== manifest.experiment.spec_digest ||
    specDigest !== caseData.comparison?.spec_digest
  ) {
    throw new Error("Verified experiment spec does not match the case result");
  }

  return {
    bundleRoot,
    manifest,
    payloads,
    specBytes,
    spec: parseJsonBytes(specBytes, "spec/experiment.json"),
    fixture: parseJsonBytes(fixtureBytes, "spec/fixture-manifest.json"),
    stageIndex: await parseStageEvents(stageBytes, manifest, caseData),
    attestations: parseTrialAttestations(attestationBytes, manifest, caseData),
  };
};

const splitJsonLines = (bytes) => {
  const lines = [];
  let start = 0;
  for (let index = 0; index <= bytes.length; index += 1) {
    if (index !== bytes.length && bytes[index] !== 0x0a) continue;
    if (index === start) {
      if (index === bytes.length) break;
      throw new Error("records/stage-events.jsonl contains a blank line");
    }
    const line = bytes.slice(start, index);
    if (line[line.length - 1] === 0x0d) {
      throw new Error("records/stage-events.jsonl is not canonical JSONL");
    }
    lines.push(line);
    start = index + 1;
  }
  return lines;
};

const stageKey = (trialKey, stage) => `${trialKey}\u0000${stage}`;

const typedSelectorValue = (value, expectedType, path) => {
  const typed = requireObject(value, path);
  if (typed.type !== expectedType || typeof typed.value !== expectedType) {
    throw new Error(`${path} has an invalid typed value`);
  }
  return typed.value;
};

const parseTrialAttestations = (bytes, manifest, caseData) => {
  const attestations = new Map();
  const lines = splitJsonLines(bytes);
  if (lines.length === 0) {
    throw new Error("artifacts/trial-attestations.jsonl is empty");
  }
  for (const [index, lineBytes] of lines.entries()) {
    const label = `trial attestation ${index + 1}`;
    const attestation = parseJsonBytes(lineBytes, label);
    requireObject(attestation, label);
    if (
      attestation.schema_name !==
        "assurance-lab.financial-support-attestation/v1" ||
      !DIGEST_PATTERN.test(attestation.trial_key) ||
      !DIGEST_PATTERN.test(attestation.action_digest) ||
      attestation.spec_digest !== manifest.experiment.spec_digest ||
      attestation.time_basis !== caseData.time_basis ||
      attestation.block !== "sqlite-fresh-clone" ||
      typeof attestation.clone_unique_instance_id !== "string" ||
      attestation.clone_unique_instance_id.length === 0
    ) {
      throw new Error(`${label} is outside the displayed experiment`);
    }
    if (attestations.has(attestation.trial_key)) {
      throw new Error(`Duplicate trial attestation for ${attestation.trial_key}`);
    }
    const selector = requireObject(
      attestation.observed_selector,
      `${label}.observed_selector`,
    );
    attestation.selectorValues = {
      input: typedSelectorValue(
        selector.input,
        "string",
        `${label}.observed_selector.input`,
      ),
      target: typedSelectorValue(
        selector.target,
        "string",
        `${label}.observed_selector.target`,
      ),
      compensator: typedSelectorValue(
        selector.compensator,
        "string",
        `${label}.observed_selector.compensator`,
      ),
      sham: typedSelectorValue(
        selector.sham,
        "boolean",
        `${label}.observed_selector.sham`,
      ),
    };
    attestations.set(attestation.trial_key, attestation);
  }
  return attestations;
};

const parseStageEvents = async (bytes, manifest, caseData) => {
  const byTrialAndStage = new Map();
  const seenDigests = new Set();
  const lines = splitJsonLines(bytes);
  if (lines.length === 0) {
    throw new Error("records/stage-events.jsonl is empty");
  }
  for (const [index, lineBytes] of lines.entries()) {
    const event = parseJsonBytes(
      lineBytes,
      `records/stage-events.jsonl line ${index + 1}`,
    );
    requireObject(event, `stage event ${index + 1}`);
    if (
      !DIGEST_PATTERN.test(event.trial_key) ||
      !["input", "target", "compensator", "outcome"].includes(event.stage)
    ) {
      throw new Error(`Stage event ${index + 1} has an invalid identity`);
    }
    if (
      event.spec_digest !== manifest.experiment.spec_digest ||
      event.time_basis !== caseData.time_basis
    ) {
      throw new Error(`Stage event ${index + 1} is outside the displayed scope`);
    }
    const payload = requireArray(event.payload, `stage event ${index + 1}.payload`);
    const names = new Set();
    for (const datumValue of payload) {
      const datum = requireObject(datumValue, `stage event ${index + 1}.payload`);
      if (typeof datum.name !== "string" || names.has(datum.name)) {
        throw new Error(`Stage event ${index + 1} has an invalid payload`);
      }
      names.add(datum.name);
    }
    const key = stageKey(event.trial_key, event.stage);
    if (byTrialAndStage.has(key)) {
      throw new Error(`Duplicate raw stage event for ${event.trial_key}/${event.stage}`);
    }
    const digest = `sha256:${await sha256Hex(lineBytes)}`;
    if (seenDigests.has(digest)) {
      throw new Error("Raw stage event digests must be unique");
    }
    seenDigests.add(digest);
    byTrialAndStage.set(key, { digest, event });
  }
  return byTrialAndStage;
};

const payloadValue = (event, name) => {
  const matches = event.payload.filter((datum) => datum.name === name);
  if (matches.length !== 1) {
    throw new Error(`Raw ${event.stage} event is missing payload field ${name}`);
  }
  return matches[0].value;
};

const assertPrimitiveEqual = (actual, expected, label) => {
  if (typeof actual !== typeof expected || !Object.is(actual, expected)) {
    throw new Error(`${label} disagrees with the verified raw stage event`);
  }
};

const caseStageReference = (caseData, trialKey, stage, allowMissing = false) => {
  const references = requireArray(
    caseData.stage_artifacts,
    "case.stage_artifacts",
  ).filter(
    (reference) =>
      reference.trial_key === trialKey && reference.stage === stage,
  );
  if (references.length === 0 && allowMissing) return null;
  if (references.length !== 1 || !DIGEST_PATTERN.test(references[0].artifact_digest)) {
    throw new Error(`Case has no unique ${stage} artifact for ${trialKey}`);
  }
  return references[0];
};

const verifiedStage = (
  caseData,
  verification,
  trialKey,
  stage,
  suppliedDigest,
) => {
  if (!DIGEST_PATTERN.test(suppliedDigest)) {
    throw new Error(`Displayed ${stage} artifact digest is malformed`);
  }
  const reference = caseStageReference(caseData, trialKey, stage);
  if (reference.artifact_digest !== suppliedDigest) {
    throw new Error(`Displayed ${stage} digest disagrees with the case reference`);
  }
  const raw = verification.stageIndex.get(stageKey(trialKey, stage));
  if (!raw || raw.digest !== suppliedDigest) {
    throw new Error(`Displayed ${stage} fact is not bound to its raw stage line`);
  }
  return raw.event;
};

const verifiedAttestedInput = (
  caseData,
  verification,
  trialKey,
  expectedActionDigest,
) => {
  const attestation = verification.attestations.get(trialKey);
  if (!attestation) {
    throw new Error(`Displayed trial has no verified attestation: ${trialKey}`);
  }
  if (attestation.action_digest !== expectedActionDigest) {
    throw new Error(`Displayed trial has the wrong attested action: ${trialKey}`);
  }
  const inputReference = caseStageReference(caseData, trialKey, "input");
  const input = verifiedStage(
    caseData,
    verification,
    trialKey,
    "input",
    inputReference.artifact_digest,
  );
  assertPrimitiveEqual(
    input.action_digest,
    attestation.action_digest,
    `Attested input action for ${trialKey}`,
  );
  assertPrimitiveEqual(
    payloadValue(input, "action_digest"),
    attestation.action_digest,
    `Raw input action for ${trialKey}`,
  );
  assertPrimitiveEqual(
    payloadValue(input, "sham_redeploy"),
    attestation.selectorValues.sham,
    `Raw sham selector for ${trialKey}`,
  );
  return attestation;
};

const selectorSignature = (selector) =>
  JSON.stringify([
    selector.input,
    selector.target,
    selector.compensator,
    selector.sham,
  ]);

const requireExactSelectorSet = (observed, expected, label) => {
  if (
    observed.size !== expected.size ||
    [...expected].some((signature) => !observed.has(signature))
  ) {
    throw new Error(`${label} does not match the verified intervention design`);
  }
};

const metricPayloadName = (metricId, label) => {
  if (
    typeof metricId !== "string" ||
    !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(metricId)
  ) {
    throw new Error(`${label} metric identifier is unsupported`);
  }
  return metricId.replaceAll("-", "_");
};

const verifyRequestSummary = async (
  caseData,
  verification,
  currentInput,
  profile,
) => {
  const fixture = requireObject(verification.fixture, "fixture manifest");
  if (fixture.schema !== "assurance-lab.financial-support-fixture/v2") {
    throw new Error("Fixture manifest does not expose a verified request summary");
  }
  const attack = requireObject(fixture.attack_action, "fixture.attack_action");
  const benign = requireObject(fixture.benign_action, "fixture.benign_action");
  const request = requireObject(caseData.current_request, "case.current_request");
  const inputProfile = requireObject(profile.input, "verified profile.input");
  const specAttack = typedSelectorValue(
    inputProfile.attack,
    "string",
    "verified profile.input.attack",
  );
  const specBenign = typedSelectorValue(
    inputProfile.benign,
    "string",
    "verified profile.input.benign",
  );
  const customerIds = requireArray(
    attack.requested_customer_ids,
    "fixture.attack_action.requested_customer_ids",
  );
  const expected = {
    action: attack.action,
    action_digest: fixture.attack_action_digest,
    data_class: attack.data_class,
    principal_id: attack.principal_id,
    records_per_customer: attack.records_per_customer,
    requested_customer_count: customerIds.length,
    requested_customer_ids: customerIds,
    role: attack.role,
  };
  for (const key of [
    "action",
    "action_digest",
    "data_class",
    "principal_id",
    "records_per_customer",
    "requested_customer_count",
    "role",
  ]) {
    assertPrimitiveEqual(request[key], expected[key], `Current request ${key}`);
  }
  if (
    JSON.stringify(request.requested_customer_ids) !==
    JSON.stringify(expected.requested_customer_ids)
  ) {
    throw new Error("Current request customer identifiers disagree with the fixture");
  }
  const canonicalAttack = new TextEncoder().encode(JSON.stringify(attack));
  const attackDigest = `sha256:${await sha256Hex(canonicalAttack)}`;
  const canonicalBenign = new TextEncoder().encode(JSON.stringify(benign));
  const benignDigest = `sha256:${await sha256Hex(canonicalBenign)}`;
  if (
    attackDigest !== fixture.attack_action_digest ||
    attackDigest !== request.action_digest ||
    attackDigest !== inputProfile.attack_action_digest ||
    attack.action !== specAttack ||
    request.action !== specAttack
  ) {
    throw new Error(
      "Current request is not bound to the verified experiment input",
    );
  }
  if (
    benignDigest !== fixture.benign_action_digest ||
    benignDigest !== inputProfile.benign_action_digest ||
    benign.action !== specBenign
  ) {
    throw new Error(
      "Benign request is not bound to the verified experiment input",
    );
  }
  assertPrimitiveEqual(
    payloadValue(currentInput, "action_digest"),
    request.action_digest,
    "Current request action digest",
  );
  assertPrimitiveEqual(
    currentInput.action_digest,
    request.action_digest,
    "Current input envelope action digest",
  );
  return request;
};

const verifyDisplayedFacts = async (caseData, verification) => {
  const contract = requireObject(verification.spec.contract, "verified contract");
  const profile = requireObject(contract.profile, "verified contract profile");
  const current = requireObject(caseData.current, "case.current");
  if (
    !DIGEST_PATTERN.test(current.trial_key) ||
    !Number.isSafeInteger(current.selected_records) ||
    !Number.isSafeInteger(current.delivered_records) ||
    typeof current.guard_blocked !== "boolean"
  ) {
    throw new Error("Current case observation is malformed");
  }

  const inputReference = caseStageReference(
    caseData,
    current.trial_key,
    "input",
  );
  const currentInput = verifiedStage(
    caseData,
    verification,
    current.trial_key,
    "input",
    inputReference.artifact_digest,
  );
  const request = await verifyRequestSummary(
    caseData,
    verification,
    currentInput,
    profile,
  );

  const targetField = metricPayloadName(
    profile.target_metric_id,
    "target",
  );
  const guardField = metricPayloadName(
    profile.compensator_metric_id,
    "compensator",
  );
  const outcomeField = metricPayloadName(
    profile.outcome_metric_id,
    "outcome",
  );
  const benignField = metricPayloadName(
    profile.benign_outcome_metric_id,
    "benign outcome",
  );
  const selectorDesign = {
    attack: typedSelectorValue(
      profile.input?.attack,
      "string",
      "verified profile.input.attack",
    ),
    benign: typedSelectorValue(
      profile.input?.benign,
      "string",
      "verified profile.input.benign",
    ),
    targetEffective: typedSelectorValue(
      profile.target?.effective,
      "string",
      "verified profile.target.effective",
    ),
    targetIneffective: typedSelectorValue(
      profile.target?.ineffective,
      "string",
      "verified profile.target.ineffective",
    ),
    targetCurrent: typedSelectorValue(
      profile.target?.current,
      "string",
      "verified profile.target.current",
    ),
    guardOn: typedSelectorValue(
      profile.compensator?.on,
      "string",
      "verified profile.compensator.on",
    ),
    guardOff: typedSelectorValue(
      profile.compensator?.off,
      "string",
      "verified profile.compensator.off",
    ),
    guardCurrent: typedSelectorValue(
      profile.compensator?.current,
      "string",
      "verified profile.compensator.current",
    ),
    shamSteady: typedSelectorValue(
      profile.sham?.steady,
      "boolean",
      "verified profile.sham.steady",
    ),
    shamRedeploy: typedSelectorValue(
      profile.sham?.redeploy,
      "boolean",
      "verified profile.sham.redeploy",
    ),
  };
  if (
    selectorDesign.attack === selectorDesign.benign ||
    selectorDesign.targetEffective === selectorDesign.targetIneffective ||
    selectorDesign.guardOn === selectorDesign.guardOff ||
    selectorDesign.shamSteady === selectorDesign.shamRedeploy ||
    ![
      selectorDesign.targetEffective,
      selectorDesign.targetIneffective,
    ].includes(selectorDesign.targetCurrent) ||
    ![selectorDesign.guardOn, selectorDesign.guardOff].includes(
      selectorDesign.guardCurrent,
    )
  ) {
    throw new Error("Verified experiment selector levels are not distinguishable");
  }
  const fixtureAttackDigest = verification.fixture.attack_action_digest;
  const fixtureBenignDigest = verification.fixture.benign_action_digest;

  const currentTargetReference = caseStageReference(
    caseData,
    current.trial_key,
    "target",
  );
  const currentGuardReference = caseStageReference(
    caseData,
    current.trial_key,
    "compensator",
  );
  const currentOutcomeReference = caseStageReference(
    caseData,
    current.trial_key,
    "outcome",
  );
  const currentTarget = verifiedStage(
    caseData,
    verification,
    current.trial_key,
    "target",
    currentTargetReference.artifact_digest,
  );
  const currentGuard = verifiedStage(
    caseData,
    verification,
    current.trial_key,
    "compensator",
    currentGuardReference.artifact_digest,
  );
  const currentOutcome = verifiedStage(
    caseData,
    verification,
    current.trial_key,
    "outcome",
    currentOutcomeReference.artifact_digest,
  );
  assertPrimitiveEqual(
    payloadValue(currentTarget, targetField),
    current.selected_records,
    "Current selected-record count",
  );
  assertPrimitiveEqual(
    payloadValue(currentGuard, guardField),
    current.guard_blocked,
    "Current release decision",
  );
  assertPrimitiveEqual(
    payloadValue(currentOutcome, outcomeField),
    current.delivered_records,
    "Current delivered-record count",
  );

  const matrix = requireArray(
    caseData.steady_attack_matrix,
    "case.steady_attack_matrix",
  );
  if (matrix.length !== 4) {
    throw new Error("Displayed attack matrix must contain four cells");
  }
  const matrixTrials = new Set();
  const displayedCloneIds = new Set();
  const observedAttackSelectors = new Set();
  const expectedAttackSelectors = new Set();
  for (const target of [
    selectorDesign.targetEffective,
    selectorDesign.targetIneffective,
  ]) {
    for (const compensator of [
      selectorDesign.guardOn,
      selectorDesign.guardOff,
    ]) {
      expectedAttackSelectors.add(
        selectorSignature({
          input: selectorDesign.attack,
          target,
          compensator,
          sham: selectorDesign.shamSteady,
        }),
      );
    }
  }
  for (const [index, cellValue] of matrix.entries()) {
    const cell = requireObject(cellValue, `attack matrix cell ${index + 1}`);
    if (matrixTrials.has(cell.trial_key)) {
      throw new Error("Displayed attack matrix trial keys must be unique");
    }
    matrixTrials.add(cell.trial_key);
    const attestation = verifiedAttestedInput(
      caseData,
      verification,
      cell.trial_key,
      fixtureAttackDigest,
    );
    if (displayedCloneIds.has(attestation.clone_unique_instance_id)) {
      throw new Error("Displayed cells reuse a supposedly fresh SQLite clone");
    }
    displayedCloneIds.add(attestation.clone_unique_instance_id);
    const selector = attestation.selectorValues;
    if (
      selector.input !== selectorDesign.attack ||
      selector.sham !== selectorDesign.shamSteady ||
      selector.target !== cell.target_level ||
      selector.compensator !== cell.compensator_level
    ) {
      throw new Error(
        `Attack matrix cell ${index + 1} is mislabeled against its verified selector`,
      );
    }
    observedAttackSelectors.add(selectorSignature(selector));
    const target = verifiedStage(
      caseData,
      verification,
      cell.trial_key,
      "target",
      cell.target_artifact_digest,
    );
    const outcome = verifiedStage(
      caseData,
      verification,
      cell.trial_key,
      "outcome",
      cell.outcome_artifact_digest,
    );
    assertPrimitiveEqual(
      payloadValue(target, targetField),
      cell.selected_records,
      `Attack matrix cell ${index + 1} selected-record count`,
    );
    assertPrimitiveEqual(
      payloadValue(outcome, outcomeField),
      cell.delivered_records,
      `Attack matrix cell ${index + 1} delivered-record count`,
    );
    if (cell.guard_state === "skipped_by_target") {
      if (
        cell.compensator_artifact_digest !== null ||
        caseStageReference(caseData, cell.trial_key, "compensator", true) !== null ||
        verification.stageIndex.has(stageKey(cell.trial_key, "compensator")) ||
        target.blocks_downstream !== true
      ) {
        throw new Error(`Attack matrix cell ${index + 1} has an invalid causal skip`);
      }
    } else {
      const expectedBlocked =
        cell.guard_state === "executed_blocked"
          ? true
          : cell.guard_state === "executed_allowed"
            ? false
            : null;
      if (expectedBlocked === null) {
        throw new Error(`Attack matrix cell ${index + 1} guard state is invalid`);
      }
      const guard = verifiedStage(
        caseData,
        verification,
        cell.trial_key,
        "compensator",
        cell.compensator_artifact_digest,
      );
      assertPrimitiveEqual(
        payloadValue(guard, guardField),
        expectedBlocked,
        `Attack matrix cell ${index + 1} release decision`,
      );
    }
  }
  requireExactSelectorSet(
    observedAttackSelectors,
    expectedAttackSelectors,
    "Displayed attack matrix",
  );
  const currentCells = matrix.filter((cell) => cell.trial_key === current.trial_key);
  if (currentCells.length !== 1) {
    throw new Error("Current observation has no unique displayed matrix cell");
  }
  const currentCell = currentCells[0];
  if (
    currentCell.selected_records !== current.selected_records ||
    currentCell.delivered_records !== current.delivered_records ||
    currentCell.guard_state !==
      (current.guard_blocked ? "executed_blocked" : "executed_allowed")
  ) {
    throw new Error("Current observation disagrees with its displayed matrix cell");
  }
  const currentSelector =
    verification.attestations.get(current.trial_key)?.selectorValues;
  if (
    !currentSelector ||
    currentSelector.input !== selectorDesign.attack ||
    currentSelector.target !== selectorDesign.targetCurrent ||
    currentSelector.compensator !== selectorDesign.guardCurrent ||
    currentSelector.sham !== selectorDesign.shamSteady
  ) {
    throw new Error("Current observation is not the verified current intervention cell");
  }

  const benignOutcomes = requireArray(
    caseData.benign_outcomes,
    "case.benign_outcomes",
  );
  if (benignOutcomes.length !== 8) {
    throw new Error("Displayed benign service envelope must contain eight cells");
  }
  const benignTrials = new Set();
  const observedBenignSelectors = new Set();
  const expectedBenignSelectors = new Set();
  for (const target of [
    selectorDesign.targetEffective,
    selectorDesign.targetIneffective,
  ]) {
    for (const compensator of [
      selectorDesign.guardOn,
      selectorDesign.guardOff,
    ]) {
      for (const sham of [
        selectorDesign.shamSteady,
        selectorDesign.shamRedeploy,
      ]) {
        expectedBenignSelectors.add(
          selectorSignature({
            input: selectorDesign.benign,
            target,
            compensator,
            sham,
          }),
        );
      }
    }
  }
  for (const [index, observationValue] of benignOutcomes.entries()) {
    const observation = requireObject(
      observationValue,
      `benign outcome ${index + 1}`,
    );
    if (benignTrials.has(observation.trial_key)) {
      throw new Error("Displayed benign trials must be unique");
    }
    benignTrials.add(observation.trial_key);
    const attestation = verifiedAttestedInput(
      caseData,
      verification,
      observation.trial_key,
      fixtureBenignDigest,
    );
    if (displayedCloneIds.has(attestation.clone_unique_instance_id)) {
      throw new Error("Displayed cells reuse a supposedly fresh SQLite clone");
    }
    displayedCloneIds.add(attestation.clone_unique_instance_id);
    if (attestation.selectorValues.input !== selectorDesign.benign) {
      throw new Error(`Benign cell ${index + 1} has the wrong verified input`);
    }
    observedBenignSelectors.add(
      selectorSignature(attestation.selectorValues),
    );
    const outcome = verifiedStage(
      caseData,
      verification,
      observation.trial_key,
      "outcome",
      observation.artifact_digest,
    );
    assertPrimitiveEqual(
      payloadValue(outcome, benignField),
      observation.assigned_records_delivered,
      `Benign cell ${index + 1} delivered-record count`,
    );
  }
  requireExactSelectorSet(
    observedBenignSelectors,
    expectedBenignSelectors,
    "Displayed benign service envelope",
  );

  return {
    profile,
    request,
    currentRaw: {
      selected: payloadValue(currentTarget, targetField),
      blocked: payloadValue(currentGuard, guardField),
      delivered: payloadValue(currentOutcome, outcomeField),
    },
    benignRaw: benignOutcomes.map(
      (observation) => observation.assigned_records_delivered,
    ),
  };
};

const typedSafeValue = (value, expectedType, path) => {
  const typed = requireObject(value, path);
  if (typed.type !== expectedType) {
    throw new Error(`${path} has an unexpected type`);
  }
  if (
    (expectedType === "integer" &&
      (!Number.isSafeInteger(typed.value) || typeof typed.value !== "number")) ||
    (expectedType === "boolean" && typeof typed.value !== "boolean")
  ) {
    throw new Error(`${path} has an invalid value`);
  }
  return typed.value;
};

const verifyPrimaryDecision = (caseData, verification, facts) => {
  const profile = facts.profile;
  const targetSafe = typedSafeValue(
    profile.target_safe_value,
    "integer",
    "profile.target_safe_value",
  );
  const guardSafe = typedSafeValue(
    profile.compensator_safe_value,
    "boolean",
    "profile.compensator_safe_value",
  );
  const outcomeSafe = typedSafeValue(
    profile.outcome_safe_value,
    "integer",
    "profile.outcome_safe_value",
  );
  const benignSafe = typedSafeValue(
    profile.benign_safe_value,
    "integer",
    "profile.benign_safe_value",
  );
  const truths = {
    target:
      facts.currentRaw.selected === targetSafe ? "supported" : "refuted",
    guard:
      facts.currentRaw.blocked === guardSafe ? "supported" : "refuted",
    path:
      facts.currentRaw.delivered === outcomeSafe ? "supported" : "refuted",
    benign: facts.benignRaw.every((value) => value === benignSafe)
      ? "supported"
      : "refuted",
  };
  const baselineVerdict =
    facts.currentRaw.delivered === outcomeSafe ? "pass" : "fail";
  const residual =
    baselineVerdict === "pass" &&
    truths.target === "refuted" &&
    truths.guard === "supported" &&
    truths.path === "supported"
      ? "masked_target_failure"
      : null;
  if (residual === null) {
    throw new Error("This exhibit only renders the verified masked-target case");
  }

  const claims = requireArray(
    caseData.primary_claims,
    "case.primary_claims",
  );
  if (claims.length !== 4) {
    throw new Error("Case primary claim summaries are incomplete");
  }
  const claimsByRole = new Map();
  for (const claim of claims) {
    if (claimsByRole.has(claim.role)) {
      throw new Error("Case primary claim roles must be unique");
    }
    claimsByRole.set(claim.role, claim);
  }
  const expectedObligationIds = {
    target: profile.primary_target_obligation_id,
    guard: profile.primary_compensator_obligation_id,
    path: profile.primary_path_obligation_id,
    benign: profile.primary_benign_obligation_id,
  };
  for (const role of ["target", "guard", "path", "benign"]) {
    const claim = requireObject(
      claimsByRole.get(role),
      `case.primary_claims.${role}`,
    );
    if (
      claim.obligation_id !== expectedObligationIds[role] ||
      claim.truth !== truths[role] ||
      claim.exercise !== "exercised"
    ) {
      throw new Error(`Primary ${role} claim disagrees with the browser check`);
    }
  }

  const comparison = requireObject(caseData.comparison, "case.comparison");
  const baseline = requireObject(comparison.baseline, "case.comparison.baseline");
  const v3 = requireObject(comparison.v3, "case.comparison.v3");
  if (
    baseline.verdict !== baselineVerdict ||
    baseline.outcome_metric_id !== profile.outcome_metric_id ||
    typedSafeValue(
      baseline.safe_value,
      "integer",
      "comparison.baseline.safe_value",
    ) !== outcomeSafe
  ) {
    throw new Error("Final-outcome-only verdict disagrees with verified facts");
  }
  const currentBaselineObservations = requireArray(
    baseline.evaluated_observations,
    "comparison.baseline.evaluated_observations",
  ).filter(
    (observation) =>
      observation.trial_key === caseData.current.trial_key &&
      observation.metric_id === profile.outcome_metric_id &&
      observation.stage === "outcome",
  );
  if (
    currentBaselineObservations.length !== 1 ||
    typedSafeValue(
      currentBaselineObservations[0].value,
      "integer",
      "comparison.baseline.current_observation.value",
    ) !== facts.currentRaw.delivered
  ) {
    throw new Error("Baseline observation is not bound to the current raw outcome");
  }
  if (
    v3.target_truth !== truths.target ||
    v3.residual_classification !== residual
  ) {
    throw new Error("Control-specific summary disagrees with the browser check");
  }
  if (
    caseData.invariant?.holds !== true ||
    caseData.invariant?.name !==
      "baseline_pass_vs_refuted_masked_target"
  ) {
    throw new Error("Case masking invariant disagrees with verified facts");
  }
  const residualSummary = requireObject(
    caseData.evaluation?.residual_summary,
    "evaluation.residual_summary",
  );
  const residualRoles = {
    target: "target",
    guard: "compensator",
    path: "path",
    benign: "benign",
  };
  for (const [role, summaryPrefix] of Object.entries(residualRoles)) {
    if (
      residualSummary[`${summaryPrefix}_truth`] !== truths[role] ||
      residualSummary[`${summaryPrefix}_exercise`] !== "exercised" ||
      residualSummary[`${summaryPrefix}_obligation_id`] !==
        expectedObligationIds[role]
    ) {
      throw new Error(
        `CLI residual ${summaryPrefix} summary disagrees with the browser check`,
      );
    }
  }
  if (
    caseData.evaluation?.compiled_experiment?.spec_digest !==
      verification.manifest.experiment.spec_digest ||
    caseData.evaluation?.compiled_experiment?.canonical_spec !==
      decodeUtf8(verification.specBytes, "spec/experiment.json") ||
    residualSummary.classification !== residual
  ) {
    throw new Error("CLI evaluation is not bound to the verified experiment");
  }
  return { truths, baselineVerdict, residual };
};

const renderPipeline = (steps) => {
  const list = byId("pipeline");
  steps.forEach((step, index) => {
    const item = document.createElement("li");
    item.className = "pipeline-step";
    item.dataset.tone = required(step.tone, `pipeline[${index}].tone`);

    appendText(item, "span", "pipeline-step-index", String(index + 1).padStart(2, "0"));
    appendText(item, "span", "pipeline-step-label", required(step.label, `pipeline[${index}].label`));
    appendText(item, "strong", "pipeline-step-value", required(step.value, `pipeline[${index}].value`));
    appendText(item, "span", "pipeline-step-status", required(step.status, `pipeline[${index}].status`));
    appendText(item, "p", "pipeline-step-detail", required(step.detail, `pipeline[${index}].detail`));
    list.append(item);
  });
};

const renderReading = (prefix, reading) => {
  setText(`${prefix}-kicker`, reading.kicker);
  setText(`${prefix}-title`, reading.title);
  setText(`${prefix}-verdict`, reading.verdict);
  setText(`${prefix}-reason`, reading.reason);
};

const unique = (values) => [...new Set(values)];

const renderMatrix = (cells, currentTrialKey) => {
  setText(
    "matrix-caption",
    "Changing one control at a time reveals who caused the safe outcome.",
  );
  setText(
    "matrix-note",
    "Attack input at the steady sham level; one fresh SQLite clone per shown cell. The full sham contrast remains part of CLI evaluation.",
  );

  const targets = unique(cells.map((cell) => cell.target_level));
  const guards = unique(cells.map((cell) => cell.compensator_level));
  if (targets.length !== 2 || guards.length !== 2 || cells.length !== 4) {
    throw new Error("steady_attack_matrix must contain one complete 2×2 design");
  }

  const table = byId("attack-matrix");
  const headRow = document.createElement("tr");
  appendText(headRow, "th", "", "Entitlement / release").scope = "col";
  guards.forEach((guard) => {
    const header = appendText(headRow, "th", "", humanize(guard));
    header.scope = "col";
  });
  table.tHead.append(headRow);

  targets.forEach((target) => {
    const tr = document.createElement("tr");
    const rowHeader = appendText(tr, "th", "", humanize(target));
    rowHeader.scope = "row";

    guards.forEach((guard) => {
      const cell = cells.find(
        (candidate) =>
          candidate.target_level === target && candidate.compensator_level === guard,
      );
      if (!cell) throw new Error(`Missing matrix cell for ${target}/${guard}`);

      const current = cell.trial_key === currentTrialKey;
      const td = document.createElement("td");
      td.dataset.current = String(current);
      appendText(td, "span", "matrix-cell-current", current ? "Observed run" : "");
      appendText(td, "strong", "matrix-cell-value", `${cell.delivered_records} delivered`);
      appendText(
        td,
        "span",
        "matrix-cell-detail",
        `${cell.selected_records} selected · ${humanize(cell.guard_state)}`,
      );
      tr.append(td);
    });
    table.tBodies[0].append(tr);
  });
};

const renderBenign = (outcomes) => {
  const values = outcomes.map((item) => item.assigned_records_delivered);
  setText("benign-title", "The legitimate path stayed intact.");
  setText(
    "benign-result",
    `${values.every((value) => value === 1) ? "1 assigned record" : "Service changed"} · all ${values.length} cells`,
  );
  setText(
    "benign-detail",
    "Every combination of entitlement, guard and sham intervention still delivered the single record assigned to the support case.",
  );

  const series = byId("benign-series");
  values.forEach((value) => appendText(series, "span", "", String(value)));
  series.setAttribute(
    "aria-label",
    `Assigned records delivered across benign cells: ${values.join(", ")}`,
  );
};

const findArtifact = (artifacts, trialKey, stage) =>
  artifacts.find(
    (artifact) => artifact.trial_key === trialKey && artifact.stage === stage,
  );

const artifactDigest = (artifact, label) =>
  required(artifact?.artifact_digest, `stage_artifacts.${label}.artifact_digest`);

const renderEvidence = (data, verification) => {
  const evidence = [
    {
      label: "Entitlement query",
      raw: `out_of_scope_records_selected = ${data.current.selected_records}`,
      digests: [
        artifactDigest(
          findArtifact(data.stage_artifacts, data.current.trial_key, "target"),
          "current.target",
        ),
      ],
    },
    {
      label: "Release decision",
      raw: `unapproved_release_blocked = ${data.current.guard_blocked}`,
      digests: [
        artifactDigest(
          findArtifact(data.stage_artifacts, data.current.trial_key, "compensator"),
          "current.compensator",
        ),
      ],
    },
    {
      label: "Outside boundary",
      raw: `out_of_scope_records_delivered = ${data.current.delivered_records}`,
      digests: [
        artifactDigest(
          findArtifact(data.stage_artifacts, data.current.trial_key, "outcome"),
          "current.outcome",
        ),
      ],
    },
    {
      label: "Benign service envelope",
      raw: `assigned_case_records_delivered = [${data.benign_outcomes
        .map((item) => item.assigned_records_delivered)
        .join(",")}]`,
      digests: data.benign_outcomes.map((item) => item.artifact_digest),
    },
  ];

  setText(
    "evidence-boundary",
    "Browser: verified the raw manifest and every listed file, matched every displayed fact to its hashed stage line and attested selector, and checked the primary current-cell verdict against the verified safe values. Run the CLI to recompute the full semantic decision, including 16-cell protocol and contrast completeness. Integrity-only: source origin is not authenticated.",
  );

  const meta = byId("evidence-meta");
  [
    ["Bundle ID", data.bundle_id],
    ["Spec digest", data.comparison.spec_digest],
    ["Time basis", data.time_basis],
    ["Profile", verification.manifest.profile],
  ].forEach(([term, value]) => {
    const group = document.createElement("div");
    appendText(group, "dt", "", term);
    appendText(group, "dd", "", value);
    meta.append(group);
  });

  const artifacts = byId("evidence-artifacts");
  evidence.forEach((artifact) => {
    const item = document.createElement("li");
    appendText(item, "span", "artifact-label", artifact.label);
    appendText(item, "code", "artifact-raw", artifact.raw);
    appendText(item, "code", "artifact-digest", artifact.digests.join("\n"));
    artifacts.append(item);
  });
};

const renderLimitations = (limitations) => {
  const list = byId("limitations");
  const values = requireArray(limitations, "case.limitations");
  if (values.length === 0 || values.some((value) => typeof value !== "string")) {
    throw new Error("Case limitations are missing or malformed");
  }
  values.forEach((value) => appendText(list, "li", "", value));
};

const render = (data, verification, facts, decision) => {
  const current = data.current;
  const request = facts.request;
  const claims = Object.fromEntries(
    data.primary_claims.map((claim) => [claim.role, claim]),
  );

  document.title = "Nothing left. The first control still failed. — Control Assurance";
  const bundleSuffix = data.bundle_id.slice(-12);
  setText("case-meta", `Bundle …${bundleSuffix} · ${data.time_basis}`);
  setText(
    "case-eyebrow",
    "Synthetic financial reference case · customer support export",
  );
  setText("case-headline", "Nothing left the system. The first control still failed.");
  setText(
    "case-dek",
    `A release guard prevented disclosure after a broken entitlement boundary selected ${current.selected_records} out-of-scope records. The safe final outcome was real. So was the control failure it concealed.`,
  );
  setText("case-classification", humanize(decision.residual));
  setText(
    "pipeline-caption",
    "The current intervention cell, read from the initiating request to the outside boundary.",
  );

  const recordWord = request.records_per_customer === 1 ? "record" : "records";
  renderPipeline([
    {
      label: "Support request",
      value: `${request.requested_customer_count} requested`,
      status: "Observed",
      tone: "observed",
      detail:
        `${request.principal_id} requested ${request.records_per_customer} ${recordWord} from each of ${request.requested_customer_count} customers outside its assigned case.`,
    },
    {
      label: "Entitlement boundary",
      value: `${current.selected_records} selected`,
      status: humanize(claims.target.truth),
      tone: toneFor(claims.target.truth),
      detail:
        "The authorization boundary selected records outside the assigned case.",
    },
    {
      label: "Release guard",
      value: current.guard_blocked ? "Blocked" : "Allowed",
      status: humanize(claims.guard.truth),
      tone: toneFor(claims.guard.truth),
      detail: current.guard_blocked
        ? "The downstream guard withheld the selected release."
        : "The downstream guard allowed the selected release.",
    },
    {
      label: "Outside",
      value: `${current.delivered_records} delivered`,
      status: humanize(claims.path.truth),
      tone: toneFor(claims.path.truth),
      detail: "No customer record crossed the system boundary in the observed run.",
    },
  ]);

  renderReading("baseline", {
    kicker: "Final-outcome-only reading",
    title: "Did any customer data leave?",
    verdict: humanize(decision.baselineVerdict),
    reason:
      "Zero records were delivered. This answer is correct—and insufficient—because it cannot say which control produced it.",
  });
  renderReading("specific", {
    kicker: "Control-specific reading",
    title: "Did each boundary do its own job?",
    verdict: humanize(decision.residual),
    reason:
      "The entitlement boundary failed while the release guard succeeded. Treating the final zero as shared success would preserve a silent single point of failure.",
  });

  renderMatrix(data.steady_attack_matrix, current.trial_key);
  renderBenign(data.benign_outcomes);
  renderEvidence(data, verification);
  renderLimitations(data.limitations);

  if (window.location.hash === "#evidence") {
    byId("evidence").open = true;
  }
  byId("finding").hidden = false;
  byId("case-view").setAttribute("aria-busy", "false");
};

const fail = (error) => {
  setText("case-meta", "Case evidence unavailable");
  setIntegrityStatus("Browser integrity check failed", "failed");
  setText("load-error-detail", error instanceof Error ? error.message : String(error));
  byId("load-error").hidden = false;
  byId("finding").hidden = true;
  byId("case-view").setAttribute("aria-busy", "false");
};

const start = async () => {
  if (!globalThis.crypto?.subtle) {
    throw new Error(
      "WebCrypto SHA-256 is unavailable. This page will not render unverified evidence.",
    );
  }
  const response = await fetch(CASE_URL, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`${CASE_URL} returned HTTP ${response.status}`);
  }
  const data = await response.json();
  if (data.schema_name !== CASE_SCHEMA) {
    throw new Error(`Unsupported case schema: ${data.schema_name}`);
  }
  setIntegrityStatus("Checking manifest and listed files…");
  const verification = await verifyBundle(data);
  setIntegrityStatus("Checking displayed facts against raw stage lines…");
  const facts = await verifyDisplayedFacts(data, verification);
  const decision = verifyPrimaryDecision(data, verification, facts);
  setIntegrityStatus(
    `Browser verified manifest, ${verification.manifest.files.length} files and displayed facts`,
    "verified",
  );
  render(data, verification, facts, decision);
};

start().catch(fail);
