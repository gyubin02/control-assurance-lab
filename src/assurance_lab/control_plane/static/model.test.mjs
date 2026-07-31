import assert from "node:assert/strict";
import test from "node:test";

import {
  availableDeploymentActions,
  availableActions,
  captureOperationTarget,
  configurationDiff,
  configurationFromEntries,
  deploymentPresentation,
  hasEffectiveRole,
  normalizeControlId,
  recentControlStorageKey,
  rememberControl,
  revisionComparisons,
  shortDigest,
} from "./model.js";

const digest = `sha256:${"a".repeat(64)}`;

test("normalizes only portable control ids", () => {
  assert.equal(normalizeControlId("  Alert-Window_1  "), "alert-window_1");
  assert.throws(() => normalizeControlId("../escape"));
  assert.throws(() => normalizeControlId("1-starts-with-number"));
  assert.equal(shortDigest(digest), "aaaaaaaaaa…aaaaaa");
});

test("produces a stable leaf-level configuration difference", () => {
  assert.deepEqual(
    configurationDiff(
      { enabled: true, source: { alias: "old", fixed: 1 } },
      { enabled: false, source: { alias: "new", fixed: 1 } },
    ),
    [
      { after: false, before: true, path: "enabled" },
      { after: "new", before: "old", path: "source.alias" },
    ],
  );
});

test("workflow actions preserve maker-checker separation", () => {
  const identity = {
    mfa: true,
    roles: ["editor", "approver", "deployer"],
    subject: "oidc:alice",
  };
  assert.deepEqual(
    availableActions({ created_by: "oidc:alice", state: "draft" }, identity),
    ["submit"],
  );
  assert.deepEqual(
    availableActions({ created_by: "oidc:alice", state: "submitted" }, identity),
    [],
  );
  assert.deepEqual(
    availableActions({ created_by: "oidc:bob", state: "submitted" }, identity),
    ["approve", "reject"],
  );
  assert.deepEqual(
    availableActions(
      { created_by: "oidc:bob", state: "approved" },
      { ...identity, mfa: false },
    ),
    [],
  );
});

test("administrator receives role parity without bypassing maker-checker or MFA", () => {
  const administrator = {
    mfa: true,
    roles: ["administrator"],
    subject: "oidc:admin",
  };
  assert.equal(hasEffectiveRole(administrator, "editor"), true);
  assert.equal(hasEffectiveRole(administrator, "auditor"), true);
  assert.deepEqual(
    availableActions(
      { created_by: "oidc:maker", state: "submitted" },
      administrator,
    ),
    ["approve", "reject"],
  );
  assert.deepEqual(
    availableActions(
      { created_by: "oidc:admin", state: "submitted" },
      administrator,
    ),
    [],
  );
  assert.deepEqual(
    availableActions(
      { created_by: "oidc:maker", state: "approved" },
      { ...administrator, mfa: false },
    ),
    [],
  );
});

test("captures an immutable operation target before asynchronous work", () => {
  const revision = {
    control_id: "alert-window",
    revision_id: digest,
    state_version: 7,
  };
  const target = captureOperationTarget(revision, { deployment_version: 3 });
  revision.control_id = "changed-after-click";
  assert.deepEqual(target, {
    activePointerVersion: 3,
    controlId: "alert-window",
    revisionId: digest,
    stateVersion: 7,
  });
  assert.equal(Object.isFrozen(target), true);
});

test("compares a candidate to the active pointer and its direct parent separately", () => {
  const active = {
    configuration: { enabled: true, source: { alias: "active" } },
    generation: 1,
    revision_id: `sha256:${"b".repeat(64)}`,
  };
  const parent = {
    configuration: { enabled: false, source: { alias: "parent" } },
    generation: 2,
    revision_id: `sha256:${"c".repeat(64)}`,
  };
  const candidate = {
    configuration: { enabled: true, source: { alias: "candidate" } },
    generation: 3,
    revision_id: `sha256:${"d".repeat(64)}`,
  };
  const comparisons = revisionComparisons(
    candidate,
    [candidate, parent, active],
    active,
  );
  assert.equal(comparisons.activeStatus, "compared");
  assert.deepEqual(comparisons.active, [
    { after: "candidate", before: "active", path: "source.alias" },
  ]);
  assert.deepEqual(comparisons.lineage, [
    { after: true, before: false, path: "enabled" },
    { after: "candidate", before: "parent", path: "source.alias" },
  ]);
});

test("keeps desired, queued, and last applied deployment states distinct", () => {
  const desired = {
    configuration_digest: digest,
    revision_id: `sha256:${"b".repeat(64)}`,
  };
  const previous = {
    applied_configuration_digest: `sha256:${"c".repeat(64)}`,
    operation_id: `sha256:${"d".repeat(64)}`,
    revision_id: `sha256:${"e".repeat(64)}`,
    state: "applied",
  };
  const pending = {
    configuration_digest: digest,
    operation_sequence: 2,
    revision_id: desired.revision_id,
    state: "pending",
  };
  const view = deploymentPresentation(desired, previous, [previous, pending]);
  assert.equal(view.code, "queued");
  assert.equal(view.poll, true);
  assert.equal(view.applied.operation_id, previous.operation_id);
  assert.equal(view.latest, pending);
});

test("reports applied only when the receipt-backed operation matches desired state", () => {
  const desired = {
    configuration_digest: digest,
    revision_id: `sha256:${"b".repeat(64)}`,
  };
  const applied = {
    applied_configuration_digest: digest,
    configuration_digest: digest,
    operation_id: `sha256:${"c".repeat(64)}`,
    operation_sequence: 3,
    revision_id: desired.revision_id,
    state: "applied",
  };
  assert.equal(
    deploymentPresentation(desired, applied, [applied]).code,
    "applied",
  );
  assert.equal(
    deploymentPresentation(
      desired,
      { ...applied, applied_configuration_digest: `sha256:${"f".repeat(64)}` },
      [applied],
    ).code,
    "unverified",
  );
});

test("surfaces a missing operation and a terminal failure without false success", () => {
  const desired = {
    configuration_digest: digest,
    revision_id: `sha256:${"b".repeat(64)}`,
  };
  assert.equal(
    deploymentPresentation(desired, null, []).code,
    "operation-missing",
  );
  const failed = {
    configuration_digest: digest,
    operation_sequence: 7,
    revision_id: desired.revision_id,
    state: "failed",
  };
  const view = deploymentPresentation(desired, null, [failed]);
  assert.equal(view.code, "failed");
  assert.equal(view.poll, false);
});

test("deployment actions require fresh MFA and preserve rollback maker-checker", () => {
  const identity = {
    mfa: true,
    roles: ["deployer"],
    subject: "oidc:carol",
  };
  const desired = {
    configuration_digest: digest,
    revision_id: `sha256:${"b".repeat(64)}`,
  };
  const failed = {
    configuration_digest: digest,
    operation_id: `sha256:${"c".repeat(64)}`,
    operation_sequence: 4,
    revision_id: desired.revision_id,
    state: "failed",
  };
  const applied = {
    applied_configuration_digest: `sha256:${"d".repeat(64)}`,
    operation_id: `sha256:${"e".repeat(64)}`,
    revision_id: `sha256:${"f".repeat(64)}`,
    state: "applied",
  };
  const retired = {
    created_by: "oidc:alice",
    revision_id: `sha256:${"1".repeat(64)}`,
    state: "retired",
  };
  assert.deepEqual(
    availableDeploymentActions({
      applied,
      desired,
      identity,
      operations: [failed],
      selected: retired,
    }),
    ["retry-deployment", "rollback-deployment"],
  );
  assert.deepEqual(
    availableDeploymentActions({
      applied,
      desired,
      identity: { ...identity, mfa: false },
      operations: [failed],
      selected: retired,
    }),
    [],
  );
  assert.deepEqual(
    availableDeploymentActions({
      applied,
      desired,
      identity,
      operations: [failed],
      selected: { ...retired, created_by: identity.subject },
    }),
    ["retry-deployment"],
  );
});

test("builds the exact secret-reference-only Elastic configuration", () => {
  const fields = new FormData();
  const values = {
    collection_lag_seconds: "120",
    control_id: "elastic-alert-window",
    control_profile_digest: digest,
    control_profile_id: "alert-window-v1",
    custody_ref: "s3-object-lock://evidence/acme/elastic",
    description: "Close the exact alert window.",
    display_name: "Elastic alert window",
    elastic_ca_bundle_ref: "",
    elastic_endpoint_origin: "https://elastic.example",
    elastic_index_alias: ".alerts-security.alerts-default",
    elastic_lease_ttl_seconds: "900",
    elastic_parent_credential_ref: "vault://kv/secops/elastic-parent",
    enabled: "on",
    environment: "production",
    interval_seconds: "900",
    legal_hold: "on",
    owner_group: "secops/platform",
    retention_days: "365",
    signing_key_ref: "vault-transit://assurance/signing/elastic",
    source_kind: "elastic-security",
    tenant_id: "acme-bank",
    window_seconds: "900",
  };
  for (const [key, value] of Object.entries(values)) fields.set(key, value);
  const configuration = configurationFromEntries(fields);
  assert.equal(configuration.source.kind, "elastic-security");
  assert.equal(configuration.source.ca_bundle_ref, null);
  assert.equal(configuration.source.pam_mode, "elastic-jit-api-key");
  assert.equal(configuration.evidence.snapshot_format, "cab-stream-v2");
  assert.equal(configuration.evidence.legal_hold, true);
  assert.equal(JSON.stringify(configuration).includes("password"), false);
});

test("rejects raw credentials where a reference is required", () => {
  const fields = new FormData();
  for (const [key, value] of Object.entries({
    collection_lag_seconds: "120",
    control_id: "elastic-alert-window",
    control_profile_digest: digest,
    control_profile_id: "alert-window-v1",
    custody_ref: "s3-object-lock://evidence/acme/elastic",
    description: "Close the exact alert window.",
    display_name: "Elastic alert window",
    elastic_endpoint_origin: "https://elastic.example",
    elastic_index_alias: ".alerts-security.alerts-default",
    elastic_lease_ttl_seconds: "900",
    elastic_parent_credential_ref: "super-secret-token",
    environment: "production",
    interval_seconds: "900",
    owner_group: "secops/platform",
    retention_days: "365",
    signing_key_ref: "vault-transit://assurance/signing/elastic",
    source_kind: "elastic-security",
    tenant_id: "acme-bank",
    window_seconds: "900",
  })) {
    fields.set(key, value);
  }
  assert.throws(
    () => configurationFromEntries(fields),
    /승인된 저장소 참조/,
  );
});

test("rejects credential-bearing references exactly as the server boundary does", () => {
  const base = {
    collection_lag_seconds: "120",
    control_id: "elastic-alert-window",
    control_profile_digest: digest,
    control_profile_id: "alert-window-v1",
    custody_ref: "s3-object-lock://evidence/acme/elastic",
    description: "Close the exact alert window.",
    display_name: "Elastic alert window",
    elastic_endpoint_origin: "https://elastic.example",
    elastic_index_alias: ".alerts-security.alerts-default",
    elastic_lease_ttl_seconds: "900",
    environment: "production",
    interval_seconds: "900",
    owner_group: "secops/platform",
    retention_days: "365",
    signing_key_ref: "vault-transit://assurance/signing/elastic",
    source_kind: "elastic-security",
    tenant_id: "acme-bank",
    window_seconds: "900",
  };
  for (const reference of [
    "vault://user:password@kv/secops/elastic-parent",
    "vault://token@kv/secops/elastic-parent",
  ]) {
    const fields = new FormData();
    for (const [key, value] of Object.entries({
      ...base,
      elastic_parent_credential_ref: reference,
    })) {
      fields.set(key, value);
    }
    assert.throws(
      () => configurationFromEntries(fields),
      /승인된 저장소 참조/,
    );
  }
});

test("recent list is bounded and de-duplicated", () => {
  assert.deepEqual(
    rememberControl(["one", "two", "one"], "two", 2),
    ["two", "one"],
  );
});

test("recent-control keys are isolated by both tenant and subject", () => {
  const alice = recentControlStorageKey({
    subject: "oidc:alice",
    tenant_id: "acme-bank",
  });
  const bob = recentControlStorageKey({
    subject: "oidc:bob",
    tenant_id: "acme-bank",
  });
  const otherTenant = recentControlStorageKey({
    subject: "oidc:alice",
    tenant_id: "other-bank",
  });
  assert.notEqual(alice, bob);
  assert.notEqual(alice, otherTenant);
  assert.match(alice, /acme-bank:oidc%3Aalice$/);
});
