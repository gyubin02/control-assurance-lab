"use strict";

const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { readFile } = require("node:fs/promises");
const path = require("node:path");
const test = require("node:test");

const {
  canonicalJsonBytes,
  parseRuntimeObservations,
  parseStageEvents,
  parseTrialAttestations,
  verifyDisplayedFacts,
  verifyFixtureAndDataset,
} = require("./app.js");

const repositoryRoot = path.resolve(__dirname, "..");
const bundleRoot = path.join(
  repositoryRoot,
  "examples",
  "masked-export.cab",
);

const bytes = (relativePath) => readFile(path.join(bundleRoot, relativePath));
const digest = (value) =>
  `sha256:${createHash("sha256").update(value).digest("hex")}`;

const loadRawEvidence = async () => {
  const [
    manifestBytes,
    fixtureBytes,
    datasetManifestBytes,
    runtimeDatasetBytes,
    runtimeObservationBytes,
    stageBytes,
    attestationBytes,
    specBytes,
    caseBytes,
  ] = await Promise.all([
    bytes("bundle.json"),
    bytes("spec/fixture-manifest.json"),
    bytes("spec/dataset-manifest.json"),
    bytes("spec/runtime-dataset.json"),
    bytes("records/runtime-observations.jsonl"),
    bytes("records/stage-events.jsonl"),
    bytes("artifacts/trial-attestations.jsonl"),
    bytes("spec/experiment.json"),
    readFile(path.join(repositoryRoot, "web", "case.json")),
  ]);
  const manifest = JSON.parse(manifestBytes);
  const fixture = JSON.parse(fixtureBytes);
  const spec = JSON.parse(specBytes);
  const caseData = JSON.parse(caseBytes);
  const dataset = await verifyFixtureAndDataset({
    fixture,
    fixtureBytes,
    datasetManifestBytes,
    runtimeDatasetBytes,
    spec,
  });
  const attestations = parseTrialAttestations(
    attestationBytes,
    manifest,
    caseData,
  );
  return {
    manifest,
    fixture,
    fixtureBytes,
    datasetManifestBytes,
    runtimeDatasetBytes,
    runtimeObservationBytes,
    stageBytes,
    attestations,
    spec,
    caseData,
    dataset,
  };
};

test("current v3 fixture reconstructs the displayed current cell from raw SQLite receipts", async () => {
  const evidence = await loadRawEvidence();
  const runtimeIndex = await parseRuntimeObservations(
    evidence.runtimeObservationBytes,
    evidence.manifest,
    evidence.attestations,
    evidence.fixture,
    evidence.dataset,
    evidence.spec,
  );

  assert.equal(runtimeIndex.size, 16);
  const current = runtimeIndex.get(evidence.caseData.current.trial_key);
  assert.ok(current);
  assert.equal(current.selectedRecords, 10);
  assert.equal(current.guardBlocked, true);
  assert.equal(current.deliveredRecords, 0);
  assert.deepEqual(
    current.action.requested_customer_ids,
    Array.from({ length: 10 }, (_, offset) =>
      `SYNTH-CUSTOMER-${String(21 + offset).padStart(6, "0")}`),
  );
});

test("display values are recomputed from raw receipts, not accepted from case.json", async () => {
  const evidence = await loadRawEvidence();
  const runtimeIndex = await parseRuntimeObservations(
    evidence.runtimeObservationBytes,
    evidence.manifest,
    evidence.attestations,
    evidence.fixture,
    evidence.dataset,
    evidence.spec,
  );
  const stageIndex = await parseStageEvents(
    evidence.stageBytes,
    evidence.manifest,
    evidence.caseData,
  );
  const verification = {
    manifest: evidence.manifest,
    spec: evidence.spec,
    fixture: evidence.fixture,
    runtimeIndex,
    stageIndex,
    attestations: evidence.attestations,
  };
  const facts = await verifyDisplayedFacts(evidence.caseData, verification);
  assert.equal(facts.current.selected_records, 10);

  const falseSummary = structuredClone(evidence.caseData);
  falseSummary.current.selected_records = 0;
  await assert.rejects(
    verifyDisplayedFacts(falseSummary, verification),
    /CLI current observation disagrees with the verified raw runtime evidence/,
  );
});

test("fixture schema drift is rejected instead of silently falling back to case.json", async () => {
  const evidence = await loadRawEvidence();
  const legacyFixture = { ...evidence.fixture, schema: "assurance-lab.financial-support-fixture/v2" };

  await assert.rejects(
    verifyFixtureAndDataset({
      fixture: legacyFixture,
      fixtureBytes: canonicalJsonBytes(legacyFixture),
      datasetManifestBytes: evidence.datasetManifestBytes,
      runtimeDatasetBytes: evidence.runtimeDatasetBytes,
      spec: evidence.spec,
    }),
    /Unsupported fixture manifest schema/,
  );
});

test("a coherently rehashed false selection receipt still fails semantic reconstruction", async () => {
  const evidence = await loadRawEvidence();
  const lines = evidence.runtimeObservationBytes
    .toString("utf8")
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line));
  const current = lines.find(
    (observation) =>
      observation.trial_key === evidence.caseData.current.trial_key,
  );
  assert.ok(current);
  current.selection.row_count = 9;

  const rewrittenLines = lines.map((observation) =>
    Buffer.from(canonicalJsonBytes(observation)),
  );
  const rewritten = Buffer.concat(
    rewrittenLines.flatMap((line) => [line, Buffer.from("\n")]),
  );
  evidence.attestations.get(current.trial_key).runtime_observation_digest =
    digest(rewrittenLines[lines.indexOf(current)]);

  await assert.rejects(
    parseRuntimeObservations(
      rewritten,
      evidence.manifest,
      evidence.attestations,
      evidence.fixture,
      evidence.dataset,
      evidence.spec,
    ),
    /Selection receipt .* disagrees with the verified raw runtime evidence/,
  );
});

test("runtime rows cannot drift away from the fixture and experiment digest", async () => {
  const evidence = await loadRawEvidence();
  const changedDataset = JSON.parse(evidence.runtimeDatasetBytes);
  changedDataset.customers[20].email = "rewritten@example.invalid";

  await assert.rejects(
    verifyFixtureAndDataset({
      fixture: evidence.fixture,
      fixtureBytes: evidence.fixtureBytes,
      datasetManifestBytes: evidence.datasetManifestBytes,
      runtimeDatasetBytes: canonicalJsonBytes(changedDataset),
      spec: evidence.spec,
    }),
    /Fixture, dataset and experiment scope are not digest-bound/,
  );
});
