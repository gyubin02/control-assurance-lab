import { createHash } from "node:crypto";

import {
  DEFAULT_JSON_LIMITS,
  canonicalize,
  verifyCanonicalJson,
} from "./strict-json.js";
import { VERIFIER_IMPLEMENTATION_ID } from "./source-identity.js";

export const BENCHMARK_VERIFIER_ID =
  VERIFIER_IMPLEMENTATION_ID;
export const BENCHMARK_VERIFIER_VERSION = "0.2.0";
export const BENCHMARK_RECEIPT_SCHEMA =
  "assurance-lab.benchmark.semantic-verification-receipt/v1";

const SNAPSHOT_MAGIC = Buffer.from(
  "CONTROL-ASSURANCE-CAB-SNAPSHOT\u0000\u0001",
  "binary",
);
const MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024;
const MAX_SNAPSHOT_FILES = 4_096;
const SPEC_PATH = "spec/benchmark-compiled-spec.json";
const PLAN_PATH = "records/benchmark-frozen-plan.json";
const RAW_PATH = "records/benchmark-raw-trial-set.json";
const RECOVERY_PROOF_MEMBER_PATHS = Object.freeze([
  "records/lifecycle/admitted-receipts.json",
  "records/lifecycle/incident-lifecycle.json",
  "records/lifecycle/verified-lifecycle.json",
]);
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const CAB_ID = /^cab:sha256:[0-9a-f]{64}$/;
const DETECTION_CLOCK_ID = "financial-detection-clock-v1";
const DETECTION_CLOCK_SPEC_DIGEST =
  "sha256:9f2fd834bd719f93866af2e0c30552cb791f936f6a37790a1b1d54534ad810df";
const DETECTION_SOURCE_ID = "SYNTH-SOURCE-SUPPORT-GATEWAY-01";
const DETECTION_NAMED_RULE =
  "financial.session-replay.exact-correlation.v1";
const DETECTION_FALLBACK_RULE =
  "financial.support-risk.broad-fallback.v1";
const DETECTION_DIRECT_ROUTE = "SYNTH-ROUTE-DIRECT-SOURCE-01";
const DETECTION_FALLBACK_ROUTE = "SYNTH-ROUTE-FALLBACK-01";
const RESPONSE_RUNNER_RESOURCE_ID = "financial-response-sqlite-runner";
const RESPONSE_CONFIG_DIGEST =
  "sha256:0b39d7077bbe10dc71a8a5edf59d082bd28a104f62b90502a86c1742839d843b";
const RESPONSE_COMPROMISED_PRINCIPAL = "support-017";
const RESPONSE_UNRELATED_PRINCIPAL = "support-042";
const RESPONSE_COMPROMISED_SESSION = "SYNTH-SESSION-SUPPORT-017-OLD";
const RESPONSE_SIBLING_SESSION = "SYNTH-SESSION-SUPPORT-017-CURRENT";
const RESPONSE_UNRELATED_SESSION = "SYNTH-SESSION-SUPPORT-042-CURRENT";
const BENCHMARK_ID = "financial-control-lifecycle";
const BENCHMARK_VERSION = "1.0.0";
const SCENARIOS = Object.freeze([
  "financial-entitlement-recovery",
  "financial-exact-correlation-detection",
  "financial-exact-session-response",
]);
const RECOVERY_RESULT_KEYS = Object.freeze([
  "action_digest", "action_session_role", "assigned_case_records_delivered",
  "assigned_customer_ids", "assignment_basis_canonical", "assignment_basis_digest",
  "clone_cleanup_probe_canonical", "clone_cleanup_probe_digest",
  "clone_cleanup_verified", "clone_id", "clone_nonce",
  "clone_readback_canonical", "clone_readback_digest", "clone_storage_kind",
  "cutover_fixture_valid", "delivered_assigned_customer_ids",
  "delivered_customer_ids", "delivered_out_of_scope_customer_ids",
  "delivery_receipts_canonical", "delivery_receipts_digest",
  "entitlement_set_canonical", "entitlement_set_digest", "events",
  "guard_level", "input_level", "lifecycle_bound_branch_head_digest",
  "lifecycle_branch_id", "lifecycle_branch_kind", "lifecycle_bundle_digest",
  "lifecycle_bundle_locator", "lifecycle_bundle_verification",
  "lifecycle_snapshot_canonical", "lifecycle_snapshot_digest",
  "old_session_id", "old_session_revoked", "old_session_state",
  "out_of_scope_records_delivered", "out_of_scope_records_selected",
  "prior_admitted_disclosure_count_after",
  "prior_admitted_disclosure_count_before",
  "prior_disclosure_entry_ids_canonical_after",
  "prior_disclosure_entry_ids_canonical_before",
  "prior_disclosure_entry_ids_digest_after",
  "prior_disclosure_entry_ids_digest_before",
  "prior_disclosure_ledger_canonical_after",
  "prior_disclosure_ledger_canonical_before",
  "prior_disclosure_ledger_digest_after",
  "prior_disclosure_ledger_digest_before",
  "prior_disclosure_reference_unchanged", "release_decision",
  "release_guard_reached", "release_reason", "replacement_session_active",
  "replacement_session_entitlement_digest_bound",
  "replacement_session_entitlement_set_digest", "replacement_session_id",
  "replacement_session_state", "requested_customer_ids",
  "selected_customer_ids", "selected_out_of_scope_customer_ids",
  "session_resolution_canonical", "session_resolution_digest",
  "session_resolution_lifecycle_snapshot_digest",
  "session_resolution_verified_lifecycle_digest",
  "session_rotation_transition_id", "sham_level",
  "snapshot_authorized_action", "snapshot_digest", "snapshot_id",
  "snapshot_identity_matches_declared_target",
  "snapshot_reapply_entitlement_rows_deleted",
  "snapshot_reapply_entitlement_rows_inserted",
  "snapshot_reapply_mutation_rows_canonical",
  "snapshot_reapply_mutation_rows_digest", "snapshot_reapply_operation_id",
  "snapshot_reapply_performed", "snapshot_reapply_receipt_valid",
  "snapshot_reapply_semantics_unchanged",
  "snapshot_reapply_snapshot_rows_deleted",
  "snapshot_reapply_snapshot_rows_inserted", "target_level", "trace_id",
  "unapproved_release_blocked", "verified_lifecycle_canonical",
  "verified_lifecycle_digest",
]);
const DETECTION_RESULT_KEYS = Object.freeze([
  "action_digest", "alert_query", "alert_query_completed", "alerts",
  "any_alert_within_slo", "clock_readback", "collector_completed",
  "collector_healthy", "collector_run_readback", "compensator_level",
  "detector_run", "detector_run_completed", "events",
  "fallback_alert_binding_valid", "fallback_telemetry_forwarded",
  "first_alert_causal_latency_ms", "first_alert_offset_from_window_open_ms",
  "forwarded_event_ids", "forwarded_events", "input_level",
  "named_alert_identity_unique", "named_alert_rule_identity_bound",
  "named_alert_trace_source_action_bound",
  "named_correlation_evidence_valid", "named_exact_correlation_alert_proven",
  "named_rule_active", "observation_window_closed", "reload_attestation",
  "sham_level", "simulated_clock_bound", "source_events", "source_healthy",
  "source_sequence_coverage_complete", "source_trace_action_bound",
  "target_level", "tested_benign_action_unalerted", "trace_id",
  "window_closure",
]);
const RESPONSE_RESULT_KEYS = Object.freeze([
  "action_digest", "compensator_mutation", "gateway_decisions", "id",
  "principals_after_compensator", "principals_after_target",
  "principals_before_target", "resource_identity", "responder_after_sham",
  "responder_before_sham", "response_action", "schema_name",
  "sessions_after_compensator", "sessions_after_target",
  "sessions_before_target", "sham_operation", "spec_digest",
  "target_mutation", "trace_id", "trial_key",
]);
const SCENARIO_PROFILES = Object.freeze({
  [SCENARIOS[0]]: Object.freeze({
    actionSchema: "assurance-lab.recovery-export-action/v1",
    attack: "out-of-scope-export-retest",
    benign: "assigned-case-export-retest",
    block: "sqlite-fresh-clone",
    compensatorOff: "monitor-only",
    compensatorOn: "enforce",
    orderSeed: "financial-recovery-public-benchmark-v1",
    shamRedeploy: "snapshot-reapply",
    shamSteady: "steady",
    specDigest:
      "sha256:576ca68430c5d3d6cd5fd1ae342096f0a17a3fad9c88b4af29424c329fcff1d7",
    targetEffective: "approved-case-scoped",
    targetIneffective: "stale-wildcard",
  }),
  [SCENARIOS[1]]: Object.freeze({
    actionSchema: "assurance-lab.financial-detection-action/v1",
    attack: "compromised-session-sensitive-replay",
    benign: "assigned-case-summary-read",
    block: "sqlite-fresh-clone",
    compensatorOff: "fallback-drop",
    compensatorOn: "fallback-forward",
    orderSeed: "financial-detection-corruption-v1",
    shamRedeploy: "collector-reload",
    shamSteady: "collector-steady",
    specDigest:
      "sha256:dd91cf4cbd780470284b8c2733f3c06b4bea45a436762d6fb9b2c647133970b3",
    targetEffective: "exact-rule-active",
    targetIneffective: "exact-rule-inactive",
  }),
  [SCENARIOS[2]]: Object.freeze({
    actionSchema: "assurance-lab.identity-session-action/v1",
    attack: "compromised-old-session-replay",
    benign: "unrelated-support-normal-action",
    block: "sqlite-fresh-clone",
    compensatorOff: "quarantine-off",
    compensatorOn: "quarantine-on",
    orderSeed: "financial-response-corruption-v1",
    shamRedeploy: "responder-reload",
    shamSteady: "steady",
    specDigest:
      "sha256:9de286c178b8bf6d99781562286f59712766c83d3d74fe720160cd72825c0651",
    targetEffective: "revoke-exact",
    targetIneffective: "report-only",
  }),
});
const PUBLIC_AUGMENTED_SOURCE_DESCRIPTORS = Object.freeze({
  [SCENARIOS[0]]: Object.freeze({
    "records/lifecycle/admitted-receipts.json": Object.freeze({
      media_type: "application/json",
      role: "lifecycle-admitted-receipts",
      sensitivity: "synthetic",
      required_for: Object.freeze(["financial-recovery-cutover"]),
    }),
    "records/lifecycle/incident-lifecycle.json": Object.freeze({
      media_type: "application/json",
      role: "lifecycle-verifier-input",
      sensitivity: "synthetic",
      required_for: Object.freeze(["financial-recovery-cutover"]),
    }),
  }),
  [SCENARIOS[1]]: Object.freeze({
    "records/runtime-observations.jsonl": Object.freeze({
      media_type: "application/x-ndjson",
      role: "lossless financial detection runtime readbacks",
      sensitivity: "synthetic",
      required_for: Object.freeze([
        "runtime-reconstruction",
        "corruption-replay",
      ]),
    }),
    "spec/compiled-experiment.json": Object.freeze({
      media_type: "application/json",
      role: "compiler-owned detection cells and execution plan",
      sensitivity: "synthetic",
      required_for: Object.freeze([
        "design",
        "protocol-coverage",
        "corruption-replay",
      ]),
    }),
  }),
  [SCENARIOS[2]]: Object.freeze({
    "artifacts/cleanup-observations.jsonl": Object.freeze({
      media_type: "application/x-ndjson",
      role: "post-close SQLite operation probes",
      sensitivity: "synthetic",
      required_for: Object.freeze(["cleanup-admission"]),
    }),
    "artifacts/trial-attestations.jsonl": Object.freeze({
      media_type: "application/x-ndjson",
      role: "response trial attestations bound to runtime observations",
      sensitivity: "synthetic",
      required_for: Object.freeze(["trial-admission"]),
    }),
    "records/runtime-observations.jsonl": Object.freeze({
      media_type: "application/x-ndjson",
      role: "raw SQLite rows and gateway query receipts",
      sensitivity: "synthetic",
      required_for: Object.freeze([
        "runtime-reconstruction",
        "trace-lineage",
        "cleanup-admission",
      ]),
    }),
    "records/stage-events.jsonl": Object.freeze({
      media_type: "application/x-ndjson",
      role: "stage summaries derived from raw runtime observations",
      sensitivity: "synthetic",
      required_for: Object.freeze([
        "trace-lineage",
        "metric-validation",
      ]),
    }),
    "records/trial-records.jsonl": Object.freeze({
      media_type: "application/x-ndjson",
      role: "metric-free response trial records",
      sensitivity: "synthetic",
      required_for: Object.freeze(["evaluation"]),
    }),
  }),
});
const EMBEDDED_PRODUCER_SNAPSHOT_DIGESTS = Object.freeze({
  [SCENARIOS[0]]:
    "sha256:c45c95c8433b34500f1c566ddcec2ffd19148e8d6abcb29e1728bcd26d1b7f2c",
  [SCENARIOS[1]]:
    "sha256:f4af312d3bb7521ad1d3f8dbffa5ba430be4c36f0a05e06100e17c0fda4b21c2",
  [SCENARIOS[2]]:
    "sha256:39d0be2bd6f83ce9d84a93e0ad504ddf8cb5ffc20161aeacedffec99227bf83c",
});
const PRIMARY_SEMANTIC_EVALUATOR_ID =
  "control-assurance/python-primary-semantic-verifier";
const CLAIMS = new Set([
  "supported",
  "refuted",
  "indeterminate",
  "conflicting",
  "non-repeatable",
  "not-exercised",
]);
const BASELINES = new Set([
  "pass",
  "fail",
  "indeterminate",
  "conflicting",
  "non-repeatable",
]);
const RESIDUALS = new Set([
  "masked-target-failure",
  "exposed-path",
  "target-effective",
  "unresolved",
  "conflicting",
  "non-repeatable",
]);

export class BenchmarkVerificationError extends Error {
  constructor(code, message, path = null) {
    super(message);
    this.name = "BenchmarkVerificationError";
    this.code = code;
    this.path = path;
  }
}

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function canonicalDigest(value) {
  return sha256(canonicalize(value, DEFAULT_JSON_LIMITS));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function isObject(value) {
  return value !== null && !Array.isArray(value) && typeof value === "object";
}

function requireObject(value, label) {
  if (!isObject(value)) {
    throw new BenchmarkVerificationError("malformed", `${label} must be an object`);
  }
  return value;
}

function requireArray(value, length, label) {
  if (!Array.isArray(value) || (length !== null && value.length !== length)) {
    throw new BenchmarkVerificationError(
      "malformed",
      `${label} must contain exactly ${String(length)} items`,
    );
  }
  return value;
}

function exactKeys(value, keys, label) {
  requireObject(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new BenchmarkVerificationError(
      "malformed",
      `${label} has missing or unknown fields`,
    );
  }
}

function requireString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new BenchmarkVerificationError("malformed", `${label} must be text`);
  }
  return value;
}

function requireDigest(value, label) {
  if (typeof value !== "string" || !DIGEST.test(value)) {
    throw new BenchmarkVerificationError(
      "malformed",
      `${label} must be a lowercase SHA-256 content address`,
    );
  }
  return value;
}

function requireInteger(value, minimum, maximum, label) {
  if (
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw new BenchmarkVerificationError(
      "malformed",
      `${label} is outside the supported integer range`,
    );
  }
  return value;
}

function equalJson(left, right) {
  return canonicalize(left).equals(canonicalize(right));
}

function pinnedActionDescriptor(scenarioId, inputLevel) {
  if (scenarioId === SCENARIOS[0]) {
    const common = {
      schema: "assurance-lab.recovery-export-action/v1",
      principal_id: "support-017",
      session_role: "active-replacement",
      data_class: "synthetic-customer-confidential",
      purpose: "post-restore-control-retest",
    };
    if (inputLevel === "out-of-scope-export-retest") {
      return {
        ...common,
        action: inputLevel,
        request_id: "SYNTH-RECOVERY-RETEST-ATTACK-000001",
        requested_customer_ids: Array.from(
          { length: 10 },
          (_unused, index) => `SYNTH-CUSTOMER-${String(index + 21).padStart(6, "0")}`,
        ),
      };
    }
    if (inputLevel === "assigned-case-export-retest") {
      return {
        ...common,
        action: inputLevel,
        request_id: "SYNTH-RECOVERY-RETEST-BENIGN-000001",
        assigned_case_id: "CASE-000017",
        requested_customer_ids: ["SYNTH-CUSTOMER-000017"],
      };
    }
  } else if (scenarioId === SCENARIOS[1]) {
    const common = {
      schema: "assurance-lab.financial-detection-action/v1",
      source_id: "SYNTH-SOURCE-SUPPORT-GATEWAY-01",
      data_class: "synthetic-customer-confidential",
    };
    if (inputLevel === "compromised-session-sensitive-replay") {
      return {
        ...common,
        action: inputLevel,
        principal_id: "support-017",
        session_id: "SYNTH-SESSION-SUPPORT-017-OLD",
        request_id: "SYNTH-REQUEST-REPLAY-000001",
        source_event_plan: [
          {
            event_id: "SYNTH-SOURCE-REPLAY-01",
            sequence: 7301,
            event_type: "session-authenticated",
          },
          {
            event_id: "SYNTH-SOURCE-REPLAY-02",
            sequence: 7302,
            event_type: "revoked-session-replay-observed",
          },
          {
            event_id: "SYNTH-SOURCE-REPLAY-03",
            sequence: 7303,
            event_type: "out-of-assignment-sensitive-read",
          },
        ],
      };
    }
    if (inputLevel === "assigned-case-summary-read") {
      return {
        ...common,
        action: inputLevel,
        principal_id: "support-042",
        session_id: "SYNTH-SESSION-SUPPORT-042-CURRENT",
        request_id: "SYNTH-REQUEST-ASSIGNED-000001",
        source_event_plan: [
          {
            event_id: "SYNTH-SOURCE-ASSIGNED-01",
            sequence: 8301,
            event_type: "session-authenticated",
          },
          {
            event_id: "SYNTH-SOURCE-ASSIGNED-02",
            sequence: 8302,
            event_type: "assigned-case-opened",
          },
          {
            event_id: "SYNTH-SOURCE-ASSIGNED-03",
            sequence: 8303,
            event_type: "assigned-case-summary-read",
          },
        ],
      };
    }
  } else if (scenarioId === SCENARIOS[2]) {
    const common = {
      schema: "assurance-lab.identity-session-action/v1",
      data_class: "synthetic-customer-confidential",
    };
    if (inputLevel === "compromised-old-session-replay") {
      return {
        ...common,
        action: inputLevel,
        principal_id: "support-017",
        session_id: "SYNTH-SESSION-SUPPORT-017-OLD",
        request_id: "SYNTH-REQUEST-REPLAY-000001",
        operation: "read-support-workbench",
      };
    }
    if (inputLevel === "unrelated-support-normal-action") {
      return {
        ...common,
        action: inputLevel,
        principal_id: "support-042",
        session_id: "SYNTH-SESSION-SUPPORT-042-CURRENT",
        request_id: "SYNTH-REQUEST-NORMAL-000001",
        operation: "read-assigned-case-summary",
      };
    }
  }
  throw new BenchmarkVerificationError(
    "unsupported-profile",
    "action is outside the pinned public lifecycle benchmark",
  );
}

function validatePinnedContract(contract, scenarioId) {
  const expected = SCENARIO_PROFILES[scenarioId];
  if (expected === undefined) {
    throw new BenchmarkVerificationError(
      "unsupported-profile",
      "scenario is outside the pinned public lifecycle benchmark",
    );
  }
  exactKeys(
    contract,
    ["id", "metrics", "obligations", "plan", "profile", "scope", "version"],
    "contract",
  );
  const profile = requireObject(contract.profile, "contract.profile");
  exactKeys(
    profile,
    [
      "benign_outcome_metric_id",
      "benign_safe_value",
      "compensator",
      "compensator_attack_relation",
      "compensator_metric_id",
      "compensator_safe_value",
      "input",
      "outcome_component",
      "outcome_metric_id",
      "outcome_safe_value",
      "primary_benign_obligation_id",
      "primary_compensator_obligation_id",
      "primary_path_obligation_id",
      "primary_target_obligation_id",
      "sham",
      "sham_relation",
      "target",
      "target_attack_relation",
      "target_benign_relation",
      "target_metric_id",
      "target_safe_value",
    ],
    "contract.profile",
  );
  const input = requireObject(profile.input, "contract.profile.input");
  const target = requireObject(profile.target, "contract.profile.target");
  const compensator = requireObject(
    profile.compensator,
    "contract.profile.compensator",
  );
  const sham = requireObject(profile.sham, "contract.profile.sham");
  exactKeys(
    input,
    [
      "attack",
      "attack_action_digest",
      "benign",
      "benign_action_digest",
      "component",
    ],
    "contract.profile.input",
  );
  exactKeys(
    target,
    ["component", "current", "effective", "ineffective"],
    "contract.profile.target",
  );
  exactKeys(
    compensator,
    ["component", "current", "off", "on"],
    "contract.profile.compensator",
  );
  exactKeys(sham, ["redeploy", "steady"], "contract.profile.sham");
  exactKeys(contract.plan, ["blocks", "order_seed", "replicates"], "contract.plan");
  exactKeys(
    contract.scope,
    [
      "assessment_as_of",
      "build_digest",
      "dataset_digest",
      "evidence_policy",
      "evidence_window",
      "fixture_digest",
      "scenario_id",
    ],
    "contract.scope",
  );
  exactKeys(
    contract.scope.evidence_policy,
    ["digest", "id", "version"],
    "contract.scope.evidence_policy",
  );
  exactKeys(
    contract.scope.evidence_window,
    ["end", "start"],
    "contract.scope.evidence_window",
  );
  const metrics = requireArray(contract.metrics, null, "contract.metrics");
  const obligations = requireArray(
    contract.obligations,
    null,
    "contract.obligations",
  );
  metrics.forEach((metric, index) =>
    exactKeys(
      metric,
      [
        "component",
        "evidence_class",
        "extractor_id",
        "id",
        "stage",
        "unit",
        "value_type",
      ],
      `contract metric ${String(index + 1)}`,
    ),
  );
  obligations.forEach((obligation, index) =>
    exactKeys(
      obligation,
      ["id", "predicate", "quantifier", "scope", "selector", "subject"],
      `contract obligation ${String(index + 1)}`,
    ),
  );
  const requiredValues = [
    [input.attack, expected.attack, "input.attack"],
    [input.benign, expected.benign, "input.benign"],
    [target.ineffective, expected.targetIneffective, "target.ineffective"],
    [target.effective, expected.targetEffective, "target.effective"],
    [compensator.off, expected.compensatorOff, "compensator.off"],
    [compensator.on, expected.compensatorOn, "compensator.on"],
    [sham.steady, expected.shamSteady, "sham.steady"],
    [sham.redeploy, expected.shamRedeploy, "sham.redeploy"],
  ];
  for (const [typed, value, label] of requiredValues) {
    if (
      !isObject(typed) ||
      typed.type !== "string" ||
      typed.value !== value ||
      Object.keys(typed).length !== 2
    ) {
      throw new BenchmarkVerificationError(
        "unsupported-profile",
        `contract ${label} differs from the pinned public profile`,
      );
    }
  }
  if (
    contract.id !== scenarioId ||
    contract.version !== "3.0.0" ||
    contract.scope.scenario_id !== scenarioId ||
    !equalJson(contract.plan.blocks, [expected.block]) ||
    contract.plan.replicates !== 3 ||
    contract.plan.order_seed !== expected.orderSeed
  ) {
    throw new BenchmarkVerificationError(
      "unsupported-profile",
      "contract plan differs from the pinned public profile",
    );
  }
  const attack = pinnedActionDescriptor(scenarioId, expected.attack);
  const benign = pinnedActionDescriptor(scenarioId, expected.benign);
  if (
    input.attack_action_digest !== canonicalDigest(attack) ||
    input.benign_action_digest !== canonicalDigest(benign)
  ) {
    throw new BenchmarkVerificationError(
      "action-substitution",
      "contract action addresses differ from the pinned public actions",
    );
  }
}

function requireCanonicalDocument(bytes, label) {
  if (!Buffer.isBuffer(bytes)) {
    throw new BenchmarkVerificationError(
      "malformed",
      `${label} must be immutable bytes`,
    );
  }
  try {
    return verifyCanonicalJson(bytes, DEFAULT_JSON_LIMITS);
  } catch (error) {
    throw new BenchmarkVerificationError(
      "malformed",
      `${label} is not exact bounded canonical JSON: ${error.message}`,
    );
  }
}

function validateSnapshotPath(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 1_024 ||
    !/^[\x20-\x7e]+$/.test(value) ||
    value.startsWith("/") ||
    value.includes("\\")
  ) {
    throw new BenchmarkVerificationError(
      "invalid-snapshot",
      "snapshot path is not portable ASCII",
    );
  }
  const components = value.split("/");
  if (
    components.some(
      (component) =>
        component.length === 0 ||
        component === "." ||
        component === ".." ||
        Buffer.byteLength(component, "ascii") > 255 ||
        !/^[A-Za-z0-9._-]+$/.test(component),
    )
  ) {
    throw new BenchmarkVerificationError(
      "invalid-snapshot",
      "snapshot path contains an unsafe component",
    );
  }
}

export function decodeCabSnapshot(snapshotBytes) {
  if (
    !Buffer.isBuffer(snapshotBytes) ||
    snapshotBytes.length > MAX_SNAPSHOT_BYTES ||
    !snapshotBytes.subarray(0, SNAPSHOT_MAGIC.length).equals(SNAPSHOT_MAGIC)
  ) {
    throw new BenchmarkVerificationError(
      "invalid-snapshot",
      "CAB snapshot has the wrong marker or exceeds the byte limit",
    );
  }
  let offset = SNAPSHOT_MAGIC.length;
  if (offset + 4 > snapshotBytes.length) {
    throw new BenchmarkVerificationError("invalid-snapshot", "truncated snapshot header");
  }
  const count = snapshotBytes.readUInt32BE(offset);
  offset += 4;
  if (count < 1 || count > MAX_SNAPSHOT_FILES) {
    throw new BenchmarkVerificationError(
      "invalid-snapshot",
      "snapshot file count is outside the fixed profile",
    );
  }
  const entries = new Map();
  const caseFoldedPaths = new Set();
  let previous = "";
  for (let index = 0; index < count; index += 1) {
    if (offset + 2 > snapshotBytes.length) {
      throw new BenchmarkVerificationError(
        "invalid-snapshot",
        "truncated snapshot path length",
      );
    }
    const pathLength = snapshotBytes.readUInt16BE(offset);
    offset += 2;
    if (
      pathLength < 1 ||
      pathLength > 1_024 ||
      offset + pathLength + 8 > snapshotBytes.length
    ) {
      throw new BenchmarkVerificationError(
        "invalid-snapshot",
        "snapshot entry header is invalid",
      );
    }
    const pathBytes = snapshotBytes.subarray(offset, offset + pathLength);
    offset += pathLength;
    if (pathBytes.some((byte) => byte > 0x7f)) {
      throw new BenchmarkVerificationError(
        "invalid-snapshot",
        "snapshot path is not ASCII",
      );
    }
    const entryPath = pathBytes.toString("ascii");
    validateSnapshotPath(entryPath);
    const foldedPath = entryPath.toLowerCase();
    if (caseFoldedPaths.has(foldedPath)) {
      throw new BenchmarkVerificationError(
        "invalid-snapshot",
        "snapshot contains a case-folding path collision",
      );
    }
    caseFoldedPaths.add(foldedPath);
    if (
      (index === 0 && entryPath !== "bundle.json") ||
      (index > 0 && (entryPath === "bundle.json" || entryPath <= previous))
    ) {
      throw new BenchmarkVerificationError(
        "invalid-snapshot",
        "snapshot paths are not in the canonical bundle-first order",
      );
    }
    const size = snapshotBytes.readBigUInt64BE(offset);
    offset += 8;
    if (size > BigInt(MAX_SNAPSHOT_BYTES)) {
      throw new BenchmarkVerificationError(
        "invalid-snapshot",
        "snapshot member exceeds the fixed byte limit",
      );
    }
    const end = offset + Number(size);
    if (end > snapshotBytes.length) {
      throw new BenchmarkVerificationError(
        "invalid-snapshot",
        "snapshot member is truncated",
      );
    }
    entries.set(entryPath, snapshotBytes.subarray(offset, end));
    offset = end;
    if (index > 0) {
      previous = entryPath;
    }
  }
  if (offset !== snapshotBytes.length) {
    throw new BenchmarkVerificationError(
      "invalid-snapshot",
      "snapshot has trailing bytes",
    );
  }
  return entries;
}

function requireCanonicalTimestamp(value, label) {
  requireString(value, label);
  const match =
    /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{6})Z$/.exec(
      value,
    );
  if (match === null) {
    throw new BenchmarkVerificationError(
      "invalid-manifest",
      `${label} is not a canonical UTC timestamp`,
    );
  }
  const [year, month, day, hour, minute, second] = match
    .slice(1, 7)
    .map(Number);
  const instant = new Date(0);
  instant.setUTCFullYear(year, month - 1, day);
  instant.setUTCHours(hour, minute, second, 0);
  if (
    year < 1 ||
    instant.getUTCFullYear() !== year ||
    instant.getUTCMonth() !== month - 1 ||
    instant.getUTCDate() !== day ||
    instant.getUTCHours() !== hour ||
    instant.getUTCMinutes() !== minute ||
    instant.getUTCSeconds() !== second
  ) {
    throw new BenchmarkVerificationError(
      "invalid-manifest",
      `${label} is not a real UTC date and time`,
    );
  }
}

function validateGenericManifestEnvelope(manifest) {
  exactKeys(
    manifest,
    [
      "as_of",
      "created_at",
      "evaluation",
      "experiment",
      "files",
      "media_type",
      "parent_bundles",
      "profile",
      "schema_version",
    ],
    "bundle manifest",
  );
  exactKeys(
    manifest.experiment,
    ["id", "spec_digest", "spec_version"],
    "bundle manifest experiment",
  );
  exactKeys(
    manifest.evaluation,
    ["evaluator", "policy_digest", "policy_id"],
    "bundle manifest evaluation",
  );
  exactKeys(
    manifest.evaluation.evaluator,
    ["image_digest", "name", "source_revision", "version"],
    "bundle manifest evaluator",
  );
  if (
    manifest.media_type !==
      "application/vnd.control-assurance.bundle.v1+json" ||
    manifest.schema_version !== "1.0.0" ||
    manifest.profile !== "integrity-only"
  ) {
    throw new BenchmarkVerificationError(
      "invalid-manifest",
      "bundle manifest declares an unsupported CAB envelope",
    );
  }
  requireCanonicalTimestamp(manifest.created_at, "bundle manifest created_at");
  requireCanonicalTimestamp(manifest.as_of, "bundle manifest as_of");
  if (manifest.created_at < manifest.as_of) {
    throw new BenchmarkVerificationError(
      "invalid-manifest",
      "bundle manifest predates its evaluation time",
    );
  }
  requireString(manifest.experiment.id, "bundle manifest experiment id");
  requireString(
    manifest.experiment.spec_version,
    "bundle manifest experiment version",
  );
  requireDigest(
    manifest.experiment.spec_digest,
    "bundle manifest experiment digest",
  );
  requireString(
    manifest.evaluation.policy_id,
    "bundle manifest evaluation policy id",
  );
  requireDigest(
    manifest.evaluation.policy_digest,
    "bundle manifest evaluation policy digest",
  );
  const evaluator = manifest.evaluation.evaluator;
  requireString(evaluator.name, "bundle manifest evaluator name");
  requireString(evaluator.version, "bundle manifest evaluator version");
  requireString(
    evaluator.source_revision,
    "bundle manifest evaluator source revision",
  );
  if (evaluator.image_digest !== null) {
    requireDigest(
      evaluator.image_digest,
      "bundle manifest evaluator image digest",
    );
  }
  const parents = requireArray(
    manifest.parent_bundles,
    null,
    "bundle manifest parent_bundles",
  );
  if (
    parents.length > 1_000 ||
    parents.some((parent) => typeof parent !== "string" || parent.length === 0) ||
    new Set(parents).size !== parents.length
  ) {
    throw new BenchmarkVerificationError(
      "invalid-manifest",
      "bundle manifest parent identifiers are invalid or repeated",
    );
  }
  requireArray(manifest.files, null, "bundle manifest files");
}

function descriptorMetadataMatches(descriptor, expected) {
  return (
    descriptor.media_type === expected.media_type &&
    descriptor.role === expected.role &&
    descriptor.sensitivity === expected.sensitivity &&
    equalJson(descriptor.required_for, expected.required_for)
  );
}

function validatePublicManifestProfile(manifest, expectedScenario) {
  const profile = SCENARIO_PROFILES[expectedScenario];
  if (profile === undefined || manifest.experiment.id !== expectedScenario) {
    throw new BenchmarkVerificationError(
      "invalid-manifest",
      "public source manifest has a foreign scenario identity",
    );
  }
  const expectedEvaluation = {
    evaluator: {
      image_digest: null,
      name: "assurance-lab-public-benchmark-generator",
      source_revision: "public-lifecycle-benchmark-v1",
      version: "1.0.0",
    },
    policy_digest:
      "sha256:d282093d2e31f3329cb67334fe110231a543398d626826d1dff11a58cd79cb4f",
    policy_id: "public-lifecycle-benchmark-source-v1",
  };
  if (
    manifest.created_at !== "2026-07-29T04:00:00.000000Z" ||
    manifest.as_of !== "2026-07-29T04:00:00.000000Z" ||
    !equalJson(manifest.parent_bundles, []) ||
    manifest.experiment.spec_version !== "1.0.0" ||
    manifest.experiment.spec_digest !== profile.specDigest ||
    !equalJson(manifest.evaluation, expectedEvaluation)
  ) {
    throw new BenchmarkVerificationError(
      "invalid-manifest",
      "public source manifest differs from the pinned v1 profile",
    );
  }
}

function validatePublicDescriptorProfile(
  descriptor,
  entryPath,
  expectedScenario,
) {
  const embeddedProducerPath =
    `artifacts/producers/${expectedScenario}/source.cab.snapshot`;
  if (entryPath === embeddedProducerPath) {
    if (
      !descriptorMetadataMatches(descriptor, {
        media_type: "application/vnd.control-assurance.cab-snapshot.v1",
        role: "embedded real financial producer CAB snapshot",
        sensitivity: "synthetic",
        required_for: ["benchmark-replay", "semantic-verification"],
      })
    ) {
      throw new BenchmarkVerificationError(
        "invalid-manifest",
        `embedded producer metadata differs for ${entryPath}`,
        entryPath,
      );
    }
    return "embedded";
  }
  const augmented =
    PUBLIC_AUGMENTED_SOURCE_DESCRIPTORS[expectedScenario][entryPath];
  if (augmented !== undefined) {
    if (!descriptorMetadataMatches(descriptor, augmented)) {
      throw new BenchmarkVerificationError(
        "invalid-manifest",
        `augmented producer witness metadata differs for ${entryPath}`,
        entryPath,
      );
    }
    return "augmented";
  }
  const objectMatch =
    /^records\/objects\/([0-9a-f]{64})\.json$/.exec(entryPath);
  const coreMember =
    entryPath === SPEC_PATH ||
    entryPath === PLAN_PATH ||
    entryPath === RAW_PATH;
  if (
    (!coreMember && objectMatch === null) ||
    !descriptorMetadataMatches(descriptor, {
      media_type: "application/json",
      role: "content-addressed benchmark source member",
      sensitivity: "synthetic",
      required_for: ["benchmark-replay", "semantic-verification"],
    })
  ) {
    throw new BenchmarkVerificationError(
      "invalid-manifest",
      `public source contains a foreign member profile at ${entryPath}`,
      entryPath,
    );
  }
  if (objectMatch !== null && objectMatch[1] !== descriptor.sha256) {
    throw new BenchmarkVerificationError(
      "content-address-mismatch",
      `object-store path does not address its bytes at ${entryPath}`,
      entryPath,
    );
  }
  return objectMatch === null ? "core" : "object";
}

function verifyManifestedSnapshot(
  snapshotBytes,
  expectedDigest,
  expectedPublicScenario = null,
) {
  if (sha256(snapshotBytes) !== expectedDigest) {
    throw new BenchmarkVerificationError(
      "source-substitution",
      "source snapshot bytes do not match the indexed digest",
    );
  }
  const entries = decodeCabSnapshot(snapshotBytes);
  const manifestBytes = entries.get("bundle.json");
  const manifest = requireCanonicalDocument(manifestBytes, "bundle manifest");
  validateGenericManifestEnvelope(manifest);
  if (expectedPublicScenario !== null) {
    validatePublicManifestProfile(manifest, expectedPublicScenario);
  }
  const expectedPaths = [...entries.keys()].slice(1);
  const described = [];
  const digests = new Map();
  const publicKinds = new Map();
  for (const descriptor of manifest.files) {
    exactKeys(
      descriptor,
      [
        "media_type",
        "path",
        "required_for",
        "role",
        "sensitivity",
        "sha256",
        "size",
      ],
      "bundle file descriptor",
    );
    const entryPath = requireString(descriptor.path, "bundle file path");
    validateSnapshotPath(entryPath);
    requireString(descriptor.media_type, "bundle file media type");
    requireString(descriptor.role, "bundle file role");
    if (
      !["synthetic", "lab-internal"].includes(descriptor.sensitivity)
    ) {
      throw new BenchmarkVerificationError(
        "invalid-manifest",
        `bundle sensitivity is unsupported for ${entryPath}`,
        entryPath,
      );
    }
    const requiredFor = requireArray(
      descriptor.required_for,
      null,
      `bundle required_for for ${entryPath}`,
    );
    if (
      requiredFor.length > 128 ||
      requiredFor.some(
        (purpose) => typeof purpose !== "string" || purpose.length === 0,
      ) ||
      new Set(requiredFor).size !== requiredFor.length
    ) {
      throw new BenchmarkVerificationError(
        "invalid-manifest",
        `bundle required_for is invalid for ${entryPath}`,
        entryPath,
      );
    }
    if (entryPath === "bundle.json") {
      throw new BenchmarkVerificationError(
        "invalid-manifest",
        "bundle manifest cannot describe itself",
      );
    }
    const payload = entries.get(entryPath);
    if (payload === undefined) {
      throw new BenchmarkVerificationError(
        "missing-artifact",
        `manifested member ${entryPath} is absent`,
        entryPath,
      );
    }
    if (
      !/^[0-9a-f]{64}$/.test(descriptor.sha256) ||
      descriptor.sha256 !== sha256(payload).slice(7) ||
      descriptor.size !== payload.length
    ) {
      throw new BenchmarkVerificationError(
        "manifest-mismatch",
        `manifest digest or size differs for ${entryPath}`,
        entryPath,
      );
    }
    const contentDigest = `sha256:${descriptor.sha256}`;
    const prior = digests.get(contentDigest);
    if (prior !== undefined && !prior.equals(payload)) {
      throw new BenchmarkVerificationError(
        "digest-collision",
        "CAB contains two different byte strings at one digest",
      );
    }
    digests.set(contentDigest, payload);
    if (expectedPublicScenario !== null) {
      publicKinds.set(
        entryPath,
        validatePublicDescriptorProfile(
          descriptor,
          entryPath,
          expectedPublicScenario,
        ),
      );
    }
    described.push(entryPath);
  }
  if (
    described.length !== new Set(described).size ||
    described.some((value, index) => value !== [...described].sort()[index]) ||
    described.length !== expectedPaths.length ||
    described.some((value, index) => value !== expectedPaths[index])
  ) {
    throw new BenchmarkVerificationError(
      "invalid-manifest",
      "manifest descriptors do not exactly cover the canonical snapshot members",
    );
  }
  if (expectedPublicScenario !== null) {
    const augmentedPaths = Object.keys(
      PUBLIC_AUGMENTED_SOURCE_DESCRIPTORS[expectedPublicScenario],
    ).sort();
    const presentAugmented = [...publicKinds]
      .filter(([_path, kind]) => kind === "augmented")
      .map(([path]) => path)
      .sort();
    const objectCount = [...publicKinds.values()].filter(
      (kind) => kind === "object",
    ).length;
    const expectedObjectCount =
      expectedPublicScenario === SCENARIOS[0] ? 102 : 98;
    if (
      !equalJson(presentAugmented, augmentedPaths) ||
      [...publicKinds.values()].filter((kind) => kind === "embedded").length !==
        1 ||
      [...publicKinds.values()].filter((kind) => kind === "core").length !== 3 ||
      objectCount !== expectedObjectCount
    ) {
      throw new BenchmarkVerificationError(
        "invalid-manifest",
        "public source does not contain the exact v1 core and producer witness set",
      );
    }
  }
  let embeddedProducer = null;
  if (expectedPublicScenario !== null) {
    const producerPath =
      `artifacts/producers/${expectedPublicScenario}/source.cab.snapshot`;
    const producerBytes = entries.get(producerPath);
    const expectedProducerDigest =
      EMBEDDED_PRODUCER_SNAPSHOT_DIGESTS[expectedPublicScenario];
    if (producerBytes === undefined || expectedProducerDigest === undefined) {
      throw new BenchmarkVerificationError(
        "missing-artifact",
        "public source lacks its pinned embedded producer CAB",
        producerPath,
      );
    }
    embeddedProducer = verifyManifestedSnapshot(
      producerBytes,
      expectedProducerDigest,
    );
    for (const witnessPath of Object.keys(
      PUBLIC_AUGMENTED_SOURCE_DESCRIPTORS[expectedPublicScenario],
    )) {
      const outerWitness = entries.get(witnessPath);
      const producerWitness = embeddedProducer.entries.get(witnessPath);
      if (
        outerWitness === undefined ||
        producerWitness === undefined ||
        !outerWitness.equals(producerWitness)
      ) {
        throw new BenchmarkVerificationError(
          "producer-witness-substitution",
          `augmented witness differs from the pinned producer at ${witnessPath}`,
          witnessPath,
        );
      }
    }
  }
  const manifestDigest = sha256(manifestBytes);
  const objectDigests = new Set(
    [...publicKinds]
      .filter(([_path, kind]) => kind === "object")
      .map(([path]) =>
        `sha256:${path.slice("records/objects/".length, -".json".length)}`,
      ),
  );
  return {
    cabId: `cab:${manifestDigest}`,
    entries,
    embeddedProducer,
    byDigest: digests,
    manifest,
    manifestDigest,
    objectDigests,
    resolvedObjectDigests: new Set(),
    snapshotDigest: expectedDigest,
  };
}

function semanticSpecDigest(contract) {
  const document = clone(contract);
  requireArray(document.metrics, null, "contract.metrics");
  requireArray(document.obligations, null, "contract.obligations");
  requireObject(document.plan, "contract.plan");
  requireArray(document.plan.blocks, null, "contract.plan.blocks");
  document.metrics.sort((left, right) =>
    String(left.id).localeCompare(String(right.id), "en", { sensitivity: "variant" }),
  );
  document.obligations.sort((left, right) =>
    String(left.id).localeCompare(String(right.id), "en", { sensitivity: "variant" }),
  );
  document.plan.blocks.sort();
  return canonicalDigest({
    contract_schema: "assurance-lab.preventive-non-masking.v3",
    contract: document,
  });
}

function typedValue(value, label) {
  requireObject(value, label);
  if (
    typeof value.type !== "string" ||
    !Object.prototype.hasOwnProperty.call(value, "value")
  ) {
    throw new BenchmarkVerificationError(
      "malformed-spec",
      `${label} is not a compiler typed value`,
    );
  }
  return value;
}

function compilerCells(contract) {
  const profile = requireObject(contract.profile, "contract.profile");
  const levels = [
    [
      ["attack", typedValue(profile.input.attack, "profile.input.attack")],
      ["benign", typedValue(profile.input.benign, "profile.input.benign")],
    ],
    [
      ["ineffective", typedValue(profile.target.ineffective, "profile.target.ineffective")],
      ["effective", typedValue(profile.target.effective, "profile.target.effective")],
    ],
    [
      ["off", typedValue(profile.compensator.off, "profile.compensator.off")],
      ["on", typedValue(profile.compensator.on, "profile.compensator.on")],
    ],
    [
      ["steady", typedValue(profile.sham.steady, "profile.sham.steady")],
      ["redeploy", typedValue(profile.sham.redeploy, "profile.sham.redeploy")],
    ],
  ];
  const cells = [];
  for (const input of levels[0]) {
    for (const target of levels[1]) {
      for (const compensator of levels[2]) {
        for (const sham of levels[3]) {
          const key = [
            `input=${input[0]}`,
            `target=${target[0]}`,
            `compensator=${compensator[0]}`,
            `sham=${sham[0]}`,
          ].join(";");
          cells.push({
            key,
            selector: {
              input: input[1],
              target: target[1],
              compensator: compensator[1],
              sham: sham[1],
            },
          });
        }
      }
    }
  }
  return cells;
}

function compilerLabels(cellKey) {
  const matches = /^input=(attack|benign);target=(ineffective|effective);compensator=(off|on);sham=(steady|redeploy)$/.exec(
    cellKey,
  );
  if (matches === null) {
    throw new BenchmarkVerificationError(
      "malformed-spec",
      "compiler cell key is outside the fixed four-factor profile",
    );
  }
  return {
    input: matches[1],
    target: matches[2],
    compensator: matches[3],
    sham: matches[4],
  };
}

function trialKey(specDigest, cellKey, block, replicate) {
  return sha256(
    Buffer.from(
      [specDigest, cellKey, block, String(replicate)].join("\u0000"),
      "utf8",
    ),
  );
}

function compileCoordinates(contract, specDigest) {
  const blocks = requireArray(contract.plan.blocks, 1, "contract.plan.blocks");
  if (contract.plan.replicates !== 3) {
    throw new BenchmarkVerificationError(
      "unsupported-design",
      "benchmark requires exactly three replicates",
    );
  }
  const orderSeed = requireString(contract.plan.order_seed, "contract.plan.order_seed");
  const rows = [];
  for (const cell of compilerCells(contract)) {
    for (const block of [...blocks].sort()) {
      for (let replicate = 1; replicate <= 3; replicate += 1) {
        const key = trialKey(specDigest, cell.key, block, replicate);
        rows.push({
          block,
          cell_key: cell.key,
          order: createHash("sha256")
            .update(Buffer.from(`${orderSeed}\u0000${key}`, "utf8"))
            .digest("hex"),
          replicate,
          trial_key: key,
        });
      }
    }
  }
  rows.sort(
    (left, right) =>
      left.order.localeCompare(right.order) ||
      left.trial_key.localeCompare(right.trial_key),
  );
  return rows.map((row, index) => ({
    block: row.block,
    cell_key: row.cell_key,
    ordinal: index + 1,
    replicate: row.replicate,
    trial_key: row.trial_key,
  }));
}

function validateArtifactReference(reference, label) {
  exactKeys(reference, ["artifact_digest", "schema_name"], label);
  requireDigest(reference.artifact_digest, `${label}.artifact_digest`);
  if (
    typeof reference.schema_name !== "string" ||
    !/^[a-z][a-z0-9.-]*\/v[1-9][0-9]*$/.test(reference.schema_name)
  ) {
    throw new BenchmarkVerificationError(
      "malformed",
      `${label}.schema_name is outside the frozen schema profile`,
    );
  }
  return reference;
}

function validateCompiledSpecification(specification, scenarioId) {
  exactKeys(
    specification,
    [
      "actions",
      "benchmark_specification_digest",
      "contract",
      "scenario_id",
      "spec_digest",
      "wire_schema",
    ],
    "compiled benchmark specification",
  );
  if (
    specification.wire_schema !== "assurance-lab.benchmark.compiled-spec/v1" ||
    specification.scenario_id !== scenarioId ||
    specification.contract.id !== scenarioId
  ) {
    throw new BenchmarkVerificationError(
      "relabelled-scenario",
      "compiled specification scenario identity is inconsistent",
    );
  }
  validatePinnedContract(specification.contract, scenarioId);
  const calculatedSpecDigest = semanticSpecDigest(specification.contract);
  if (
    specification.spec_digest !== calculatedSpecDigest ||
    specification.spec_digest !== SCENARIO_PROFILES[scenarioId].specDigest
  ) {
    throw new BenchmarkVerificationError(
      "spec-digest-mismatch",
      "compiler specification digest does not match the pinned canonical contract",
    );
  }
  const body = clone(specification);
  delete body.benchmark_specification_digest;
  if (
    specification.benchmark_specification_digest !== canonicalDigest(body)
  ) {
    throw new BenchmarkVerificationError(
      "spec-wrapper-mismatch",
      "benchmark specification wrapper digest is invalid",
    );
  }
  const coordinates = compileCoordinates(
    specification.contract,
    specification.spec_digest,
  );
  const actions = requireArray(
    specification.actions,
    48,
    "compiled specification actions",
  );
  const inputProfile = requireObject(
    specification.contract.profile.input,
    "contract.profile.input",
  );
  const attackActionDigest = requireDigest(
    inputProfile.attack_action_digest,
    "contract.profile.input.attack_action_digest",
  );
  const benignActionDigest = requireDigest(
    inputProfile.benign_action_digest,
    "contract.profile.input.benign_action_digest",
  );
  if (attackActionDigest === benignActionDigest) {
    throw new BenchmarkVerificationError(
      "malformed-spec",
      "attack and benign action content addresses must be distinct",
    );
  }
  actions.forEach((action, index) => {
    exactKeys(
      action,
      ["action", "block", "cell_key", "ordinal", "replicate", "trial_key"],
      `compiled action ${String(index + 1)}`,
    );
    const expected = coordinates[index];
    for (const field of [
      "block",
      "cell_key",
      "ordinal",
      "replicate",
      "trial_key",
    ]) {
      if (action[field] !== expected[field]) {
        throw new BenchmarkVerificationError(
          "compiler-coordinate-mismatch",
          `compiled action ${String(index + 1)} differs at ${field}`,
        );
      }
    }
    validateArtifactReference(action.action, `compiled action ${String(index + 1)} artifact`);
    const expectedActionDigest =
      compilerLabels(action.cell_key).input === "attack"
        ? attackActionDigest
        : benignActionDigest;
    if (action.action.artifact_digest !== expectedActionDigest) {
      throw new BenchmarkVerificationError(
        "action-substitution",
        `compiled action ${String(index + 1)} does not match its input-axis content address`,
      );
    }
  });
  return { actions, coordinates };
}

function validateFrozenPlan(plan, specification, compiled) {
  exactKeys(plan, ["entries", "scenario_id", "spec_digest", "wire_schema"], "frozen plan");
  if (
    plan.wire_schema !== "assurance-lab.benchmark.frozen-plan/v1" ||
    plan.scenario_id !== specification.scenario_id ||
    plan.spec_digest !== specification.spec_digest
  ) {
    throw new BenchmarkVerificationError(
      "plan-binding-mismatch",
      "frozen plan does not bind the compiled specification",
    );
  }
  const entries = requireArray(plan.entries, 48, "frozen plan entries");
  entries.forEach((entry, index) => {
    exactKeys(
      entry,
      [
        "action",
        "block",
        "cell_key",
        "entry_schema",
        "ordinal",
        "replicate",
        "trial_key",
      ],
      `frozen plan entry ${String(index + 1)}`,
    );
    if (entry.entry_schema !== "assurance-lab.benchmark.frozen-plan-entry/v1") {
      throw new BenchmarkVerificationError("malformed-plan", "unknown plan entry schema");
    }
    const coordinate = compiled.coordinates[index];
    const action = compiled.actions[index];
    for (const field of [
      "block",
      "cell_key",
      "ordinal",
      "replicate",
      "trial_key",
    ]) {
      if (entry[field] !== coordinate[field]) {
        throw new BenchmarkVerificationError(
          "plan-coordinate-mismatch",
          `frozen plan entry differs from compiler output at ${field}`,
        );
      }
    }
    if (!equalJson(entry.action, action.action)) {
      throw new BenchmarkVerificationError(
        "action-substitution",
        "frozen plan action differs from the compiler-owned action",
      );
    }
  });
  return entries;
}

function contentAddressedBody(value, digestField, label) {
  const body = clone(value);
  const observed = body[digestField];
  delete body[digestField];
  if (observed !== canonicalDigest(body)) {
    throw new BenchmarkVerificationError(
      "content-address-mismatch",
      `${label} content address is invalid`,
    );
  }
}

function resolveArtifact(cab, reference, label) {
  validateArtifactReference(reference, label);
  const bytes = cab.byDigest.get(reference.artifact_digest);
  if (bytes === undefined) {
    throw new BenchmarkVerificationError(
      "missing-artifact",
      `${label} does not resolve inside its source CAB`,
    );
  }
  if (cab.objectDigests.has(reference.artifact_digest)) {
    cab.resolvedObjectDigests.add(reference.artifact_digest);
  }
  const document = requireCanonicalDocument(bytes, label);
  requireObject(document, label);
  const declared = document.schema ?? document.wire_schema;
  if (declared !== reference.schema_name) {
    throw new BenchmarkVerificationError(
      "schema-substitution",
      `${label} declares a different schema`,
    );
  }
  return { bytes, document, reference };
}

function validateRecoveryLifecycleProof(cab, resolvedProof) {
  const proof = resolvedProof.document;
  exactKeys(
    proof,
    [
      "actual_branch_digest",
      "comparison_branch_digest",
      "members",
      "schema",
      "source_bundle_id",
      "source_snapshot_digest",
    ],
    "recovery lifecycle proof",
  );
  if (
    proof.schema !== "assurance-lab.recovery-lifecycle-proof/v1" ||
    typeof proof.source_bundle_id !== "string" ||
    !CAB_ID.test(proof.source_bundle_id)
  ) {
    throw new BenchmarkVerificationError(
      "malformed-proof",
      "recovery lifecycle proof has an unsupported identity",
    );
  }
  requireDigest(
    proof.source_snapshot_digest,
    "recovery lifecycle proof source_snapshot_digest",
  );
  requireDigest(
    proof.actual_branch_digest,
    "recovery lifecycle proof actual_branch_digest",
  );
  requireDigest(
    proof.comparison_branch_digest,
    "recovery lifecycle proof comparison_branch_digest",
  );
  if (proof.actual_branch_digest === proof.comparison_branch_digest) {
    throw new BenchmarkVerificationError(
      "malformed-proof",
      "recovery lifecycle proof reuses one branch head",
    );
  }
  const producer = cab.embeddedProducer;
  if (producer === null) {
    throw new BenchmarkVerificationError(
      "missing-artifact",
      "recovery source CAB lacks its independently verified producer snapshot",
    );
  }
  if (
    producer.snapshotDigest !== proof.source_snapshot_digest ||
    producer.cabId !== proof.source_bundle_id
  ) {
    throw new BenchmarkVerificationError(
      "proof-substitution",
      "recovery proof identity differs from its pinned embedded producer CAB",
    );
  }
  const members = requireArray(
    proof.members,
    RECOVERY_PROOF_MEMBER_PATHS.length,
    "recovery lifecycle proof members",
  );
  const documents = new Map();
  members.forEach((member, position) => {
    exactKeys(
      member,
      ["artifact_digest", "document", "path"],
      `recovery lifecycle proof member ${String(position + 1)}`,
    );
    if (member.path !== RECOVERY_PROOF_MEMBER_PATHS[position]) {
      throw new BenchmarkVerificationError(
        "proof-substitution",
        "recovery lifecycle proof members are not the exact sorted producer paths",
      );
    }
    requireDigest(
      member.artifact_digest,
      `recovery lifecycle proof member ${member.path} digest`,
    );
    const memberBytes = canonicalize(member.document, DEFAULT_JSON_LIMITS);
    if (sha256(memberBytes) !== member.artifact_digest) {
      throw new BenchmarkVerificationError(
        "proof-substitution",
        `recovery lifecycle proof member ${member.path} has a false content address`,
      );
    }
    const manifestedBytes = producer.entries.get(member.path);
    if (
      manifestedBytes === undefined ||
      !manifestedBytes.equals(memberBytes)
    ) {
      throw new BenchmarkVerificationError(
        "proof-substitution",
        `recovery lifecycle proof member ${member.path} differs from its embedded producer CAB member`,
      );
    }
    const outerBytes = cab.byDigest.get(member.artifact_digest);
    if (outerBytes === undefined || !outerBytes.equals(memberBytes)) {
      throw new BenchmarkVerificationError(
        "proof-substitution",
        `recovery lifecycle proof member ${member.path} is not preserved as a content-addressed benchmark member`,
      );
    }
    if (cab.objectDigests.has(member.artifact_digest)) {
      cab.resolvedObjectDigests.add(member.artifact_digest);
    }
    documents.set(member.path, member.document);
  });
  const lifecycle = requireObject(
    documents.get("records/lifecycle/incident-lifecycle.json"),
    "incident lifecycle document",
  );
  const actual = requireObject(lifecycle.actual, "incident actual branch");
  const comparison = requireObject(
    lifecycle.matched_comparison,
    "incident matched-comparison branch",
  );
  const actualSnapshots = requireArray(
    actual.snapshots,
    null,
    "incident actual snapshots",
  );
  const comparisonSnapshots = requireArray(
    comparison.snapshots,
    null,
    "incident comparison snapshots",
  );
  if (actualSnapshots.length === 0 || comparisonSnapshots.length === 0) {
    throw new BenchmarkVerificationError(
      "malformed-proof",
      "recovery lifecycle proof contains an empty branch",
    );
  }
  const actualHead = canonicalDigest(actualSnapshots.at(-1));
  const comparisonHead = canonicalDigest(comparisonSnapshots.at(-1));
  const verified = requireObject(
    documents.get("records/lifecycle/verified-lifecycle.json"),
    "verified lifecycle document",
  );
  if (
    actualHead !== proof.actual_branch_digest ||
    comparisonHead !== proof.comparison_branch_digest ||
    lifecycle.current_snapshot_digest !== actualHead ||
    verified.actual_head_digest !== actualHead ||
    verified.current_snapshot_digest !== actualHead ||
    verified.matched_comparison_head_digest !== comparisonHead
  ) {
    throw new BenchmarkVerificationError(
      "proof-substitution",
      "recovery branch heads do not close over the embedded producer documents",
    );
  }
  return {
    actualHead,
    actualHeadDocument: actualSnapshots.at(-1),
    comparisonHead,
    comparisonHeadDocument: comparisonSnapshots.at(-1),
    lifecycleDocument: lifecycle,
    sourceBundleId: proof.source_bundle_id,
    sourceBundleManifest: producer.manifest,
    sourceSnapshotDigest: proof.source_snapshot_digest,
    verifiedDocument: verified,
  };
}

function expectedTrialTraceId(scenarioId, trial) {
  const prefix = {
    [SCENARIOS[0]]: "financial-recovery-trace",
    [SCENARIOS[1]]: "financial-detection-trace",
    [SCENARIOS[2]]: "financial-response-trace",
  }[scenarioId];
  return `${prefix}-${String(trial.ordinal).padStart(4, "0")}-${trial.trial_key.slice(-12)}`;
}

function validateSyntheticCloneAttestation({
  attestation,
  runtime,
  scenarioId,
  specification,
  trial,
}) {
  exactKeys(
    attestation,
    [
      "attestation_kind",
      "block",
      "cell_key",
      "clone_identity",
      "external_attestation",
      "hardware_attestation",
      "observation_digests",
      "ordinal",
      "replicate",
      "runner_resource_id",
      "scenario_id",
      "schema",
      "spec_digest",
      "trace_id",
      "trial_key",
      "virtual_machine_clone",
    ],
    "synthetic clone attestation",
  );
  const selector = selectorForCell(specification.contract, trial.cell_key);
  let cloneIdentity;
  let runnerResourceId;
  let baseSnapshotDigest;
  let covariate;
  let observationDigests;
  if (scenarioId === SCENARIOS[0]) {
    cloneIdentity = runtime.clone_id;
    runnerResourceId = "financial-recovery-sqlite-memory";
    baseSnapshotDigest = runtime.lifecycle_snapshot_digest;
    covariate = {
      schema: "assurance-lab.financial-recovery-covariate/v1",
      lifecycle_snapshot_digest: runtime.lifecycle_snapshot_digest,
      snapshot_digest: runtime.snapshot_digest,
      selector,
      block: trial.block,
      replicate: trial.replicate,
    };
    observationDigests = {
      "clone-cleanup-probe": runtime.clone_cleanup_probe_digest,
      "clone-readback": runtime.clone_readback_digest,
      "delivery-receipts": runtime.delivery_receipts_digest,
      "lifecycle-snapshot": runtime.lifecycle_snapshot_digest,
      "session-resolution": runtime.session_resolution_digest,
    };
  } else {
    cloneIdentity = `detection-sqlite-memory-${trial.trial_key.slice(-24)}`;
    runnerResourceId = runtime.collector_run_readback?.collector_run_id;
    baseSnapshotDigest = specification.contract.scope.dataset_digest;
    covariate = {
      schema: "assurance-lab.financial-detection-covariate/v1",
      clock_readback_digest: runtime.clock_readback?.readback_digest,
      collector_instance_id: runnerResourceId,
      selector,
      block: trial.block,
      replicate: trial.replicate,
    };
    observationDigests = {
      "alert-query": runtime.alert_query?.readback_digest,
      "collector-run": runtime.collector_run_readback?.readback_digest,
      "detector-run": runtime.detector_run?.readback_digest,
      "window-closure": runtime.window_closure?.artifact_digest,
    };
  }
  for (const [name, digest] of Object.entries(observationDigests)) {
    requireDigest(digest, `synthetic attestation observation ${name}`);
  }
  if (
    attestation.schema !== "assurance-lab.synthetic-sqlite-attestation/v1" ||
    attestation.scenario_id !== scenarioId ||
    attestation.spec_digest !== trial.spec_digest ||
    attestation.trial_key !== trial.trial_key ||
    attestation.cell_key !== trial.cell_key ||
    attestation.block !== trial.block ||
    attestation.replicate !== trial.replicate ||
    attestation.ordinal !== trial.ordinal ||
    attestation.trace_id !== trial.trace_id ||
    attestation.trace_id !== expectedTrialTraceId(scenarioId, trial) ||
    attestation.clone_identity !== cloneIdentity ||
    attestation.runner_resource_id !== runnerResourceId ||
    attestation.attestation_kind !==
      "deterministic-in-process-sqlite-readback" ||
    attestation.external_attestation !== false ||
    attestation.hardware_attestation !== false ||
    attestation.virtual_machine_clone !== false ||
    !equalJson(attestation.observation_digests, observationDigests) ||
    trial.clone_readback.unique_instance_id !== cloneIdentity ||
    trial.clone_readback.runner_resource_id !== runnerResourceId ||
    trial.clone_readback.base_snapshot_digest !== baseSnapshotDigest ||
    trial.clone_readback.covariate_digest !== canonicalDigest(covariate)
  ) {
    throw new BenchmarkVerificationError(
      "attestation-substitution",
      "synthetic clone attestation does not bind the exact trial execution",
    );
  }
}

function validateResponseCloneAttestation({
  attestation,
  runtime,
  specification,
  trial,
}) {
  exactKeys(
    attestation,
    [
      "action_digest",
      "base_snapshot_digest",
      "block",
      "cell_key",
      "clone_unique_instance_id",
      "covariate_digest",
      "ended_at",
      "id",
      "intervention_digest",
      "observed_build_digest",
      "observed_dataset_digest",
      "observed_fixture_digest",
      "observed_selector",
      "ordinal",
      "replicate",
      "runner_resource_id",
      "runtime_observation_digest",
      "schema_name",
      "spec_digest",
      "started_at",
      "time_basis",
      "trace_id",
      "trial_key",
    ],
    "response clone attestation",
  );
  const selector = selectorForCell(specification.contract, trial.cell_key);
  const scope = requireObject(
    specification.contract.scope,
    "response experiment scope",
  );
  const cloneIdentity =
    `response-sqlite-clone-${String(trial.ordinal).padStart(4, "0")}-` +
    trial.trial_key.slice(-12);
  const runnerResourceId = "financial-response-sqlite-runner";
  const actionDigest = sha256(
    canonicalize(
      pinnedActionDescriptor(
        SCENARIOS[2],
        valueOf(selector.input, "response attestation input"),
      ),
      DEFAULT_JSON_LIMITS,
    ),
  );
  const covariateDigest = canonicalDigest({
    schema: "assurance-lab.financial-response-covariate/v1",
    fixture_digest: scope.fixture_digest,
    block: trial.block,
    replicate: trial.replicate,
  });
  const interventionDigest = canonicalDigest({
    schema: "assurance-lab.financial-response-intervention/v1",
    selector,
  });
  if (
    attestation.schema_name !==
      "assurance-lab.financial-response-attestation/v1" ||
    attestation.id !==
      `response-attestation-${String(trial.ordinal).padStart(4, "0")}` ||
    attestation.spec_digest !== trial.spec_digest ||
    attestation.trial_key !== trial.trial_key ||
    attestation.cell_key !== trial.cell_key ||
    attestation.block !== trial.block ||
    attestation.replicate !== trial.replicate ||
    attestation.ordinal !== trial.ordinal ||
    attestation.trace_id !== trial.trace_id ||
    attestation.trace_id !== expectedTrialTraceId(SCENARIOS[2], trial) ||
    attestation.action_digest !== actionDigest ||
    attestation.clone_unique_instance_id !== cloneIdentity ||
    attestation.runner_resource_id !== runnerResourceId ||
    attestation.observed_build_digest !== scope.build_digest ||
    attestation.observed_dataset_digest !== scope.dataset_digest ||
    attestation.observed_fixture_digest !== scope.fixture_digest ||
    !equalJson(attestation.observed_selector, selector) ||
    attestation.base_snapshot_digest !== scope.dataset_digest ||
    attestation.covariate_digest !== covariateDigest ||
    attestation.intervention_digest !== interventionDigest ||
    attestation.runtime_observation_digest !== canonicalDigest(runtime) ||
    attestation.time_basis !== "simulated" ||
    typeof attestation.started_at !== "string" ||
    typeof attestation.ended_at !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(
      attestation.started_at,
    ) ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(
      attestation.ended_at,
    ) ||
    !Number.isFinite(Date.parse(attestation.started_at)) ||
    !Number.isFinite(Date.parse(attestation.ended_at)) ||
    Date.parse(attestation.started_at) >= Date.parse(attestation.ended_at) ||
    Date.parse(attestation.started_at) <
      Date.parse(scope.evidence_window.start) ||
    Date.parse(attestation.ended_at) > Date.parse(scope.evidence_window.end) ||
    Date.parse(attestation.ended_at) > Date.parse(scope.assessment_as_of) ||
    trial.clone_readback.unique_instance_id !== cloneIdentity ||
    trial.clone_readback.runner_resource_id !== runnerResourceId ||
    trial.clone_readback.base_snapshot_digest !== scope.dataset_digest ||
    trial.clone_readback.covariate_digest !== covariateDigest
  ) {
    throw new BenchmarkVerificationError(
      "attestation-substitution",
      "response clone attestation does not bind the exact trial execution",
    );
  }
}

function validateCloneAttestation({
  cab,
  runtime,
  scenarioId,
  specification,
  trial,
}) {
  const bytes = cab.byDigest.get(
    trial.clone_readback.attestation_bundle_digest,
  );
  if (bytes === undefined) {
    throw new BenchmarkVerificationError(
      "missing-artifact",
      "clone attestation does not resolve inside its source CAB",
    );
  }
  if (cab.objectDigests.has(trial.clone_readback.attestation_bundle_digest)) {
    cab.resolvedObjectDigests.add(
      trial.clone_readback.attestation_bundle_digest,
    );
  }
  const attestation = requireCanonicalDocument(bytes, "clone attestation");
  requireObject(attestation, "clone attestation");
  if (scenarioId === SCENARIOS[2]) {
    validateResponseCloneAttestation({
      attestation,
      runtime,
      specification,
      trial,
    });
  } else {
    validateSyntheticCloneAttestation({
      attestation,
      runtime,
      scenarioId,
      specification,
      trial,
    });
  }
}

function validateRawTrialSet(raw, specification, planEntries, cab) {
  exactKeys(raw, ["scenario_id", "spec_digest", "trials", "wire_schema"], "raw trial set");
  if (
    raw.wire_schema !== "assurance-lab.benchmark.raw-trial-set/v1" ||
    raw.scenario_id !== specification.scenario_id ||
    raw.spec_digest !== specification.spec_digest
  ) {
    throw new BenchmarkVerificationError(
      "raw-binding-mismatch",
      "raw trial set does not bind the compiled specification",
    );
  }
  const trials = requireArray(raw.trials, 48, "raw trials");
  const unique = {
    trial: new Set(),
    trace: new Set(),
    clone: new Set(),
    readback: new Set(),
    attestation: new Set(),
    runtime: new Set(),
  };
  const resolved = [];
  trials.forEach((trial, index) => {
    exactKeys(
      trial,
      [
        "action",
        "block",
        "cell_key",
        "clone_readback",
        "ordinal",
        "replicate",
        "runtime_artifact",
        "scenario_id",
        "shared_lifecycle_proof",
        "spec_digest",
        "trace_id",
        "trial_key",
        "wire_schema",
      ],
      `raw trial ${String(index + 1)}`,
    );
    const plan = planEntries[index];
    if (
      trial.wire_schema !== "assurance-lab.benchmark.raw-trial/v1" ||
      trial.scenario_id !== raw.scenario_id ||
      trial.spec_digest !== raw.spec_digest
    ) {
      throw new BenchmarkVerificationError(
        "raw-binding-mismatch",
        `raw trial ${String(index + 1)} has a foreign scenario or specification`,
      );
    }
    for (const field of [
      "block",
      "cell_key",
      "ordinal",
      "replicate",
      "trial_key",
    ]) {
      if (trial[field] !== plan[field]) {
        throw new BenchmarkVerificationError(
          "raw-coordinate-mismatch",
          `raw trial ${String(index + 1)} differs from its plan at ${field}`,
        );
      }
    }
    exactKeys(
      trial.action,
      ["artifact", "binding_digest", "binding_schema", "spec_digest", "trial_key"],
      "frozen action binding",
    );
    if (
      trial.action.binding_schema !==
        "assurance-lab.benchmark.frozen-action-binding/v1" ||
      trial.action.spec_digest !== trial.spec_digest ||
      trial.action.trial_key !== trial.trial_key ||
      !equalJson(trial.action.artifact, plan.action)
    ) {
      throw new BenchmarkVerificationError(
        "action-substitution",
        "raw action binding differs from its compiler-owned plan entry",
      );
    }
    contentAddressedBody(trial.action, "binding_digest", "frozen action binding");
    exactKeys(
      trial.clone_readback,
      [
        "attestation_bundle_digest",
        "base_snapshot_digest",
        "covariate_digest",
        "readback_digest",
        "readback_schema",
        "runner_resource_id",
        "unique_instance_id",
      ],
      "clone readback",
    );
    if (trial.clone_readback.readback_schema !== "assurance-lab.clone-readback/v1") {
      throw new BenchmarkVerificationError("malformed", "unknown clone readback schema");
    }
    contentAddressedBody(trial.clone_readback, "readback_digest", "clone readback");
    const identities = [
      ["trial", trial.trial_key],
      ["trace", trial.trace_id],
      ["clone", trial.clone_readback.unique_instance_id],
      ["readback", trial.clone_readback.readback_digest],
      ["attestation", trial.clone_readback.attestation_bundle_digest],
      ["runtime", trial.runtime_artifact.artifact_digest],
    ];
    for (const [name, identity] of identities) {
      if (unique[name].has(identity)) {
        throw new BenchmarkVerificationError(
          "duplicate-lineage",
          `raw trial ${name} identity is reused`,
        );
      }
      unique[name].add(identity);
    }
    if (!cab.byDigest.has(trial.clone_readback.attestation_bundle_digest)) {
      throw new BenchmarkVerificationError(
        "missing-artifact",
        "clone attestation does not resolve inside its source CAB",
      );
    }
    const action = resolveArtifact(cab, trial.action.artifact, "trial action");
    const runtime = resolveArtifact(cab, trial.runtime_artifact, "trial runtime");
    const inputLevel =
      compilerLabels(trial.cell_key).input === "attack"
        ? SCENARIO_PROFILES[raw.scenario_id].attack
        : SCENARIO_PROFILES[raw.scenario_id].benign;
    if (
      trial.action.artifact.schema_name !==
        SCENARIO_PROFILES[raw.scenario_id].actionSchema ||
      !equalJson(
        action.document,
        pinnedActionDescriptor(raw.scenario_id, inputLevel),
      )
    ) {
      throw new BenchmarkVerificationError(
        "action-substitution",
        "trial action differs from the pinned public action",
      );
    }
    let proof = null;
    if (raw.scenario_id === SCENARIOS[0]) {
      if (
        trial.shared_lifecycle_proof === null ||
        trial.shared_lifecycle_proof.schema_name !==
          "assurance-lab.recovery-lifecycle-proof/v1"
      ) {
        throw new BenchmarkVerificationError(
          "missing-artifact",
          "recovery trial lacks its shared lifecycle proof",
        );
      }
      proof = resolveArtifact(cab, trial.shared_lifecycle_proof, "recovery lifecycle proof");
      proof.lifecycle = validateRecoveryLifecycleProof(cab, proof);
    } else if (trial.shared_lifecycle_proof !== null) {
      throw new BenchmarkVerificationError(
        "proof-substitution",
        "non-recovery trial carries a lifecycle proof",
      );
    }
    validateCloneAttestation({
      cab,
      runtime: requireObject(runtime.document.result, "runtime result"),
      scenarioId: raw.scenario_id,
      specification,
      trial,
    });
    resolved.push({ action, proof, runtime, trial });
  });
  return resolved;
}

function validateScenarioIndex(index) {
  exactKeys(
    index,
    [
      "benchmark_id",
      "benchmark_version",
      "cell_count",
      "corpus_digest",
      "corruption_count",
      "corruptions",
      "replicates_per_cell",
      "scenario_count",
      "scenarios",
      "semantic_result_digest",
      "trial_count",
      "wire_schema",
    ],
    "benchmark index",
  );
  if (
    index.wire_schema !== "assurance-lab.benchmark.index/v1" ||
    index.benchmark_id !== BENCHMARK_ID ||
    index.benchmark_version !== BENCHMARK_VERSION ||
    index.scenario_count !== 3 ||
    index.cell_count !== 48 ||
    index.trial_count !== 144 ||
    index.replicates_per_cell !== 3 ||
    index.corruption_count !== 20
  ) {
    throw new BenchmarkVerificationError(
      "unsupported-index",
      "benchmark index does not declare the frozen 3×16×3 design",
    );
  }
  requireDigest(index.corpus_digest, "index.corpus_digest");
  requireDigest(index.semantic_result_digest, "index.semantic_result_digest");
  const scenarios = requireArray(index.scenarios, 3, "index.scenarios");
  if (
    scenarios.map((entry) => entry.scenario_id).some(
      (value, index_) => value !== SCENARIOS[index_],
    )
  ) {
    throw new BenchmarkVerificationError(
      "relabelled-scenario",
      "benchmark index does not contain the frozen lifecycle scenarios in order",
    );
  }
  const seen = new Set();
  for (const scenario of scenarios) {
    exactKeys(
      scenario,
      [
        "cell_count",
        "raw_trial_set_digest",
        "scenario_id",
        "semantic_result_digest",
        "source_bundle_digest",
        "spec_digest",
        "trial_count",
      ],
      "scenario index entry",
    );
    if (scenario.cell_count !== 16 || scenario.trial_count !== 48) {
      throw new BenchmarkVerificationError(
        "unsupported-index",
        "scenario index counts differ from the frozen design",
      );
    }
    for (const field of [
      "raw_trial_set_digest",
      "semantic_result_digest",
      "source_bundle_digest",
      "spec_digest",
    ]) {
      requireDigest(scenario[field], `scenario.${field}`);
      if (seen.has(scenario[field])) {
        throw new BenchmarkVerificationError(
          "duplicate-lineage",
          `scenario index reuses ${field}`,
        );
      }
      seen.add(scenario[field]);
    }
  }
  const corruptions = requireArray(index.corruptions, 20, "index.corruptions");
  const scenarioDigestById = new Map(
    scenarios.map((entry) => [entry.scenario_id, entry.source_bundle_digest]),
  );
  const corruptedDigests = new Set();
  const receiptDigests = new Set();
  corruptions.forEach((entry, position) => {
    exactKeys(
      entry,
      [
        "corrupted_bundle_digest",
        "corruption_id",
        "receipt_digest",
        "source_bundle_digest",
        "source_scenario_id",
      ],
      `corruption index entry ${String(position + 1)}`,
    );
    if (entry.corruption_id !== `C${String(position + 1).padStart(2, "0")}`) {
      throw new BenchmarkVerificationError(
        "unsupported-index",
        "corruption index is not exactly C01 through C20",
      );
    }
    for (const field of [
      "corrupted_bundle_digest",
      "receipt_digest",
      "source_bundle_digest",
    ]) {
      requireDigest(entry[field], `corruption.${field}`);
    }
    if (
      scenarioDigestById.get(entry.source_scenario_id) !==
      entry.source_bundle_digest
    ) {
      throw new BenchmarkVerificationError(
        "source-substitution",
        "corruption index references a foreign source CAB",
      );
    }
    if (
      corruptedDigests.has(entry.corrupted_bundle_digest) ||
      receiptDigests.has(entry.receipt_digest)
    ) {
      throw new BenchmarkVerificationError(
        "duplicate-lineage",
        "corruption index reuses a corrupted bundle or receipt digest",
      );
    }
    corruptedDigests.add(entry.corrupted_bundle_digest);
    receiptDigests.add(entry.receipt_digest);
  });
  return scenarios;
}

function valueOf(typed, label) {
  typedValue(typed, label);
  return typed.value;
}

function selectorForCell(contract, cellKey) {
  const matches = compilerCells(contract).filter((cell) => cell.key === cellKey);
  if (matches.length !== 1) {
    throw new BenchmarkVerificationError(
      "relabelled-selector",
      "trial cell key does not identify one compiler-owned selector",
    );
  }
  return matches[0].selector;
}

function disposition(value) {
  return value ? "supported" : "refuted";
}

function baseline(value) {
  return value ? "pass" : "fail";
}

function semanticVector({
  target,
  compensator,
  path,
  benign,
  baseline: baselineValue,
  residual,
}) {
  const value = {
    target,
    compensator,
    path,
    benign,
    baseline: baselineValue,
    residual,
  };
  if (
    !CLAIMS.has(target) ||
    !CLAIMS.has(compensator) ||
    !CLAIMS.has(path) ||
    !CLAIMS.has(benign) ||
    !BASELINES.has(baselineValue) ||
    !RESIDUALS.has(residual)
  ) {
    throw new BenchmarkVerificationError(
      "internal-error",
      "semantic evaluator produced an invalid normalized vector",
    );
  }
  return value;
}

function unwrapRuntime(input, expectedSchema) {
  const document = input.runtime.document;
  const declared = document.schema ?? document.wire_schema;
  if (declared !== expectedSchema) {
    throw new BenchmarkVerificationError(
      "unsupported-runtime-schema",
      `semantic evaluator does not support ${String(declared)}`,
    );
  }
  exactKeys(
    document,
    [
      "block",
      "cell_key",
      "ordinal",
      "replicate",
      "result",
      "schema",
      "spec_digest",
      "trial_key",
    ],
    "runtime observation envelope",
  );
  if (
    document.spec_digest !== input.trial.spec_digest ||
    document.trial_key !== input.trial.trial_key ||
    document.cell_key !== input.trial.cell_key ||
    document.block !== input.trial.block ||
    document.replicate !== input.trial.replicate ||
    document.ordinal !== input.trial.ordinal
  ) {
    throw new BenchmarkVerificationError(
      "runtime-binding-mismatch",
      "runtime envelope does not bind the exact raw trial coordinates",
    );
  }
  return requireObject(document.result, "runtime observation result");
}

function rowBy(rows, field, value, label) {
  if (!Array.isArray(rows)) {
    throw new BenchmarkVerificationError("malformed-runtime", `${label} is not an array`);
  }
  const matches = rows.filter((row) => isObject(row) && row[field] === value);
  if (matches.length !== 1) {
    throw new BenchmarkVerificationError(
      "malformed-runtime",
      `${label} does not contain one exact ${field}`,
    );
  }
  return matches[0];
}

function responseResponderId(cloneNonce, generation) {
  const digest = canonicalDigest({
    schema: "assurance-lab.responder-instance-id/v1",
    clone_nonce: cloneNonce,
    generation,
    config_digest: RESPONSE_CONFIG_DIGEST,
  });
  return `response-responder-${digest.slice(7, 39)}-g${String(generation)}`;
}

function responseShamOperationId(operation, before, after) {
  const digest = canonicalDigest({
    schema: "assurance-lab.responder-sham-operation-id/v1",
    operation,
    clone_nonce: before.clone_nonce,
    before_instance_id: before.instance_id,
    after_instance_id: after.instance_id,
    before_generation: before.generation,
    after_generation: after.generation,
    config_digest: before.config_digest,
  });
  return `response-sham-${digest.slice(7, 39)}`;
}

function responseActionOperationId({
  actionDigest,
  responderInstanceId,
  targetLevel,
  traceId,
}) {
  const digest = canonicalDigest({
    schema: "assurance-lab.response-action-operation-id/v1",
    trace_id: traceId,
    action_digest: actionDigest,
    target_mode: targetLevel,
    responder_instance_id: responderInstanceId,
  });
  return `response-action-${digest.slice(7, 39)}`;
}

function responseSessionRows(compromisedActive) {
  return [
    {
      active: true,
      principal_id: RESPONSE_COMPROMISED_PRINCIPAL,
      session_id: RESPONSE_SIBLING_SESSION,
    },
    {
      active: compromisedActive,
      principal_id: RESPONSE_COMPROMISED_PRINCIPAL,
      session_id: RESPONSE_COMPROMISED_SESSION,
    },
    {
      active: true,
      principal_id: RESPONSE_UNRELATED_PRINCIPAL,
      session_id: RESPONSE_UNRELATED_SESSION,
    },
  ];
}

function responsePrincipalRows(compromisedQuarantined) {
  return [
    {
      principal_id: RESPONSE_COMPROMISED_PRINCIPAL,
      quarantined: compromisedQuarantined,
      role: "support",
    },
    {
      principal_id: RESPONSE_UNRELATED_PRINCIPAL,
      quarantined: false,
      role: "support",
    },
  ];
}

function validateResponseRows(rows, expected, keys, label) {
  requireArray(rows, expected.length, label);
  rows.forEach((row, index) =>
    exactKeys(row, keys, `${label} ${String(index + 1)}`),
  );
  if (!equalJson(rows, expected)) {
    throw new BenchmarkVerificationError(
      "runtime-contradiction",
      `${label} differs from the fixed persisted row set`,
    );
  }
}

function evaluateResponse(input, selector) {
  const action = input.action.document;
  const result = unwrapRuntime(
    input,
    "assurance-lab.financial-response-runtime-observation/v1",
  );
  exactKeys(result, RESPONSE_RESULT_KEYS, "response runtime result");
  const actionDigest = sha256(input.action.bytes);
  if (
    result.spec_digest !== input.trial.spec_digest ||
    result.trial_key !== input.trial.trial_key ||
    result.trace_id !== input.trial.trace_id ||
    result.action_digest !== actionDigest
  ) {
    throw new BenchmarkVerificationError(
      "runtime-binding-mismatch",
      "response runtime does not bind the raw trial and action bytes",
    );
  }
  if (
    result.id !== `${input.trial.trial_key}:runtime-observation` ||
    result.schema_name !==
      "assurance-lab.financial-response-runtime-observation/v1"
  ) {
    throw new BenchmarkVerificationError(
      "runtime-binding-mismatch",
      "response runtime observation has a foreign artifact identity",
    );
  }
  const inputLevel = valueOf(selector.input, "response input selector");
  const targetLevel = valueOf(selector.target, "response target selector");
  const compensatorLevel = valueOf(
    selector.compensator,
    "response compensator selector",
  );
  const shamLevel = valueOf(selector.sham, "response sham selector");
  const isBenign =
    inputLevel ===
    valueOf(
      input.specification.contract.profile.input.benign,
      "response benign axis",
    );
  const isAttack = !isBenign;
  const exactRevocation =
    isAttack &&
    targetLevel === SCENARIO_PROFILES[SCENARIOS[2]].targetEffective;
  const quarantineApplied =
    isAttack &&
    compensatorLevel === SCENARIO_PROFILES[SCENARIOS[2]].compensatorOn;
  const reload =
    shamLevel === SCENARIO_PROFILES[SCENARIOS[2]].shamRedeploy;
  const cloneNonce =
    `response-sqlite-clone-${String(input.trial.ordinal).padStart(4, "0")}-` +
    input.trial.trial_key.slice(-12);
  const runnerResourceId = RESPONSE_RUNNER_RESOURCE_ID;
  exactKeys(
    result.resource_identity,
    [
      "observed_clone_nonce",
      "observed_runner_resource_id",
      "requested_clone_nonce",
      "requested_runner_resource_id",
    ],
    "response resource identity",
  );
  if (
    !equalJson(result.resource_identity, {
      observed_clone_nonce: cloneNonce,
      observed_runner_resource_id: runnerResourceId,
      requested_clone_nonce: cloneNonce,
      requested_runner_resource_id: runnerResourceId,
    }) ||
    input.trial.clone_readback.unique_instance_id !== cloneNonce ||
    input.trial.clone_readback.runner_resource_id !== runnerResourceId
  ) {
    throw new BenchmarkVerificationError(
      "runtime-contradiction",
      "response resource identity does not bind the requested clone",
    );
  }
  const before = {
    clone_nonce: cloneNonce,
    config_digest: RESPONSE_CONFIG_DIGEST,
    generation: 0,
    instance_id: responseResponderId(cloneNonce, 0),
  };
  const afterGeneration = reload ? 1 : 0;
  const after = {
    clone_nonce: cloneNonce,
    config_digest: RESPONSE_CONFIG_DIGEST,
    generation: afterGeneration,
    instance_id: responseResponderId(cloneNonce, afterGeneration),
  };
  exactKeys(
    result.responder_before_sham,
    ["clone_nonce", "config_digest", "generation", "instance_id"],
    "response responder before sham",
  );
  exactKeys(
    result.responder_after_sham,
    ["clone_nonce", "config_digest", "generation", "instance_id"],
    "response responder after sham",
  );
  if (
    !equalJson(result.responder_before_sham, before) ||
    !equalJson(result.responder_after_sham, after)
  ) {
    throw new BenchmarkVerificationError(
      "runtime-contradiction",
      "response responder generations differ from the requested sham",
    );
  }
  const shamOperation = reload ? "reload" : "steady-observation";
  const expectedSham = {
    after_generation: after.generation,
    after_instance_id: after.instance_id,
    before_generation: before.generation,
    before_instance_id: before.instance_id,
    clone_nonce: cloneNonce,
    config_digest: RESPONSE_CONFIG_DIGEST,
    operation: shamOperation,
    operation_id: responseShamOperationId(shamOperation, before, after),
    rows_affected: reload ? 1 : 0,
  };
  exactKeys(
    result.sham_operation,
    [
      "after_generation",
      "after_instance_id",
      "before_generation",
      "before_instance_id",
      "clone_nonce",
      "config_digest",
      "operation",
      "operation_id",
      "rows_affected",
    ],
    "response sham operation",
  );
  if (!equalJson(result.sham_operation, expectedSham)) {
    throw new BenchmarkVerificationError(
      "runtime-contradiction",
      "response sham receipt differs from its generation transition",
    );
  }
  const beforeSessions = responseSessionRows(true);
  const afterTargetSessions = responseSessionRows(!exactRevocation);
  const afterCompensatorSessions = responseSessionRows(!exactRevocation);
  const unquarantinedPrincipals = responsePrincipalRows(false);
  const afterCompensatorPrincipals = responsePrincipalRows(quarantineApplied);
  const sessionKeys = ["active", "principal_id", "session_id"];
  const principalKeys = ["principal_id", "quarantined", "role"];
  validateResponseRows(
    result.sessions_before_target,
    beforeSessions,
    sessionKeys,
    "response sessions before target",
  );
  validateResponseRows(
    result.sessions_after_target,
    afterTargetSessions,
    sessionKeys,
    "response sessions after target",
  );
  validateResponseRows(
    result.sessions_after_compensator,
    afterCompensatorSessions,
    sessionKeys,
    "response sessions after compensator",
  );
  validateResponseRows(
    result.principals_before_target,
    unquarantinedPrincipals,
    principalKeys,
    "response principals before target",
  );
  validateResponseRows(
    result.principals_after_target,
    unquarantinedPrincipals,
    principalKeys,
    "response principals after target",
  );
  validateResponseRows(
    result.principals_after_compensator,
    afterCompensatorPrincipals,
    principalKeys,
    "response principals after compensator",
  );
  const targetOperation = isBenign
    ? "not-triggered"
    : exactRevocation
      ? "revoke-exact"
      : "report-only";
  const targetRows = exactRevocation ? 1 : 0;
  const responseStatus = isBenign ? "not-triggered" : "reported-success";
  const expectedAction = {
    action_digest: actionDigest,
    operation: targetOperation,
    operation_id: responseActionOperationId({
      actionDigest,
      responderInstanceId: after.instance_id,
      targetLevel,
      traceId: input.trial.trace_id,
    }),
    principal_id: RESPONSE_COMPROMISED_PRINCIPAL,
    responder_instance_id: after.instance_id,
    rows_affected: targetRows,
    session_id: RESPONSE_COMPROMISED_SESSION,
    status: responseStatus,
    target_mode: targetLevel,
    trace_id: input.trial.trace_id,
  };
  exactKeys(
    result.response_action,
    [
      "action_digest",
      "operation",
      "operation_id",
      "principal_id",
      "responder_instance_id",
      "rows_affected",
      "session_id",
      "status",
      "target_mode",
      "trace_id",
    ],
    "response action receipt",
  );
  if (!equalJson(result.response_action, expectedAction)) {
    throw new BenchmarkVerificationError(
      "runtime-contradiction",
      "response action receipt differs from the selected control operation",
    );
  }
  const expectedTargetMutation = {
    component: "session-revoker",
    operation: targetOperation,
    principal_id: RESPONSE_COMPROMISED_PRINCIPAL,
    rows_affected: targetRows,
    session_id: RESPONSE_COMPROMISED_SESSION,
  };
  const expectedCompensatorMutation = {
    component: "principal-quarantine",
    operation: quarantineApplied ? "quarantine" : "not-triggered",
    principal_id: RESPONSE_COMPROMISED_PRINCIPAL,
    rows_affected: quarantineApplied ? 1 : 0,
    session_id: null,
  };
  for (const [label, actual, expected] of [
    ["response target mutation", result.target_mutation, expectedTargetMutation],
    [
      "response compensator mutation",
      result.compensator_mutation,
      expectedCompensatorMutation,
    ],
  ]) {
    exactKeys(
      actual,
      ["component", "operation", "principal_id", "rows_affected", "session_id"],
      label,
    );
    if (!equalJson(actual, expected)) {
      throw new BenchmarkVerificationError(
        "runtime-contradiction",
        `${label} differs from the fixed state transition`,
      );
    }
  }
  const replayAvailable = !exactRevocation && !quarantineApplied;
  const expectedDecisions = [
    {
      available: replayAvailable,
      principal_found: true,
      principal_id: RESPONSE_COMPROMISED_PRINCIPAL,
      principal_quarantined: quarantineApplied,
      query_id: "probe-compromised-session-replay",
      session_found: true,
      session_id: RESPONSE_COMPROMISED_SESSION,
      session_revoked: exactRevocation,
    },
    {
      available: true,
      principal_found: true,
      principal_id: RESPONSE_UNRELATED_PRINCIPAL,
      principal_quarantined: false,
      query_id: "probe-unrelated-support-action",
      session_found: true,
      session_id: RESPONSE_UNRELATED_SESSION,
      session_revoked: false,
    },
  ];
  validateResponseRows(
    result.gateway_decisions,
    expectedDecisions,
    [
      "available",
      "principal_found",
      "principal_id",
      "principal_quarantined",
      "query_id",
      "session_found",
      "session_id",
      "session_revoked",
    ],
    "response gateway decisions",
  );
  const targetSupported = exactRevocation;
  const compensatorSupported = quarantineApplied;
  const pathSupported = !replayAvailable;
  const benignSupported = true;
  const baselinePasses = responseStatus === "reported-success" && pathSupported;
  let residual = "unresolved";
  if (
    !targetSupported &&
    compensatorSupported &&
    pathSupported &&
    benignSupported
  ) {
    residual = "masked-target-failure";
  } else if (!pathSupported) {
    residual = "exposed-path";
  } else if (targetSupported && pathSupported && benignSupported) {
    residual = "target-effective";
  }
  return semanticVector(
    isBenign
      ? {
          target: "not-exercised",
          compensator: "not-exercised",
          path: "not-exercised",
          benign: disposition(replayAvailable),
          baseline: baseline(replayAvailable),
          residual: "unresolved",
        }
      : {
          target: disposition(targetSupported),
          compensator: disposition(compensatorSupported),
          path: disposition(pathSupported),
          benign: disposition(benignSupported),
          baseline: baseline(baselinePasses),
          residual,
        },
  );
}

function sourceEventPayload(event) {
  return {
    schema: "assurance-lab.source-event/v1",
    event_id: event.event_id,
    trace_id: event.trace_id,
    action_digest: event.action_digest,
    source_id: event.source_id,
    source_sequence: event.source_sequence,
    event_type: event.event_type,
    observed_at_ms: event.observed_at_ms,
    clock_id: event.clock_id,
    clock_spec_digest: event.clock_spec_digest,
  };
}

function exactCanonicalString(value, canonicalText, digestValue, label) {
  if (typeof canonicalText !== "string" || typeof digestValue !== "string") {
    return false;
  }
  try {
    const bytes = Buffer.from(canonicalText, "utf8");
    const parsed = requireCanonicalDocument(bytes, label);
    return equalJson(parsed, value) && sha256(bytes) === digestValue;
  } catch {
    return false;
  }
}

function detectionIdentifier(label, traceId, prefix) {
  const suffix = createHash("sha256")
    .update(`${label}\u0000${traceId}`, "utf8")
    .digest("hex")
    .slice(0, 16)
    .toUpperCase();
  return `${prefix}${suffix}`;
}

function detectionAlertId(kind, traceId) {
  return detectionIdentifier(
    kind,
    traceId,
    kind === "named-exact"
      ? "SYNTH-ALERT-NAMED-"
      : "SYNTH-ALERT-FALLBACK-",
  );
}

function detectionClockValid(clock, expectsFallbackAlert) {
  if (!isObject(clock) || !Array.isArray(clock.transitions)) return false;
  try {
    exactKeys(
      clock,
      [
        "clock_id",
        "clock_spec_digest",
        "current_time_ms",
        "readback_canonical",
        "readback_digest",
        "transitions",
      ],
      "detection clock readback",
    );
  } catch {
    return false;
  }
  let previous = 0;
  const transitions = [];
  for (const transition of clock.transitions) {
    if (
      !Array.isArray(transition) ||
      transition.length !== 2 ||
      !Number.isSafeInteger(transition[0]) ||
      !Number.isSafeInteger(transition[1]) ||
      transition[0] !== previous ||
      transition[1] <= transition[0]
    ) {
      return false;
    }
    previous = transition[1];
    transitions.push({ from_ms: transition[0], to_ms: transition[1] });
  }
  const payload = {
    schema: "assurance-lab.simulated-clock-readback/v1",
    clock_id: clock.clock_id,
    current_time_ms: clock.current_time_ms,
    transitions,
    clock_spec_digest: clock.clock_spec_digest,
  };
  const expectedTransitions = expectsFallbackAlert
    ? [[0, 100], [100, 200], [200, 300], [300, 800], [800, 1_200], [1_200, 2_000]]
    : [[0, 100], [100, 200], [200, 300], [300, 800], [800, 2_000]];
  return (
    clock.clock_id === DETECTION_CLOCK_ID &&
    clock.clock_spec_digest === DETECTION_CLOCK_SPEC_DIGEST &&
    equalJson(clock.transitions, expectedTransitions) &&
    previous === 2_000 &&
    clock.current_time_ms === 2_000 &&
    exactCanonicalString(
      payload,
      clock.readback_canonical,
      clock.readback_digest,
      "detection clock readback",
    )
  );
}

function detectionCollectorValid(collector, events, traceId) {
  if (!isObject(collector)) return false;
  try {
    exactKeys(
      collector,
      [
        "clock_id",
        "clock_spec_digest",
        "collected_event_count",
        "collected_event_ids",
        "collected_source_sequences",
        "collector_run_id",
        "healthy",
        "readback_canonical",
        "readback_digest",
        "source_healthy",
        "source_id",
        "status",
        "trace_id",
      ],
      "detection collector readback",
    );
  } catch {
    return false;
  }
  const payload = {
    schema: "assurance-lab.collector-run-readback/v1",
    collector_run_id: collector.collector_run_id,
    trace_id: collector.trace_id,
    source_id: collector.source_id,
    status: collector.status,
    healthy: collector.healthy,
    source_healthy: collector.source_healthy,
    collected_event_count: collector.collected_event_count,
    collected_event_ids: collector.collected_event_ids,
    collected_source_sequences: collector.collected_source_sequences,
    clock_id: collector.clock_id,
    clock_spec_digest: collector.clock_spec_digest,
  };
  return (
    collector.collector_run_id ===
      detectionIdentifier("collector", traceId, "SYNTH-COLLECTOR-") &&
    collector.trace_id === traceId &&
    collector.source_id === DETECTION_SOURCE_ID &&
    collector.clock_id === DETECTION_CLOCK_ID &&
    collector.clock_spec_digest === DETECTION_CLOCK_SPEC_DIGEST &&
    collector.status === "complete" &&
    collector.healthy === true &&
    collector.source_healthy === true &&
    collector.collected_event_count === events.length &&
    equalJson(
      collector.collected_event_ids,
      events.map((event) => event.event_id),
    ) &&
    equalJson(
      collector.collected_source_sequences,
      events.map((event) => event.source_sequence),
    ) &&
    exactCanonicalString(
      payload,
      collector.readback_canonical,
      collector.readback_digest,
      "detection collector readback",
    )
  );
}

function detectionDetectorValid(
  detector,
  events,
  alerts,
  traceId,
  expectedRuleActive,
) {
  if (!isObject(detector)) return false;
  try {
    exactKeys(
      detector,
      [
        "clock_id",
        "clock_spec_digest",
        "completed_at_ms",
        "detector_run_id",
        "evaluated_event_count",
        "observed_named_alert_ids",
        "pending_event_count",
        "processed_event_ids",
        "processed_source_event_digests",
        "processed_source_sequences",
        "readback_canonical",
        "readback_digest",
        "rule_active",
        "rule_id",
        "source_high_watermark",
        "started_at_ms",
        "status",
        "trace_id",
      ],
      "detection detector readback",
    );
  } catch {
    return false;
  }
  const payload = {
    schema: "assurance-lab.detector-run-readback/v2",
    detector_run_id: detector.detector_run_id,
    trace_id: detector.trace_id,
    rule_id: detector.rule_id,
    rule_active: detector.rule_active,
    status: detector.status,
    started_at_ms: detector.started_at_ms,
    evaluated_event_count: detector.evaluated_event_count,
    source_high_watermark: detector.source_high_watermark,
    pending_event_count: detector.pending_event_count,
    completed_at_ms: detector.completed_at_ms,
    processed_event_ids: detector.processed_event_ids,
    processed_source_sequences: detector.processed_source_sequences,
    processed_source_event_digests: detector.processed_source_event_digests,
    observed_named_alert_ids: detector.observed_named_alert_ids,
    clock_id: detector.clock_id,
    clock_spec_digest: detector.clock_spec_digest,
  };
  const namedIds = alerts
    .filter(
      (alert) =>
        alert.rule_id === DETECTION_NAMED_RULE &&
        alert.detector_run_id === detector.detector_run_id,
    )
    .map((alert) => alert.alert_id);
  return (
    detector.detector_run_id ===
      detectionIdentifier(
        "detector-run",
        traceId,
        "SYNTH-DETECTOR-RUN-",
      ) &&
    detector.trace_id === traceId &&
    detector.rule_id === DETECTION_NAMED_RULE &&
    detector.rule_active === expectedRuleActive &&
    detector.clock_id === DETECTION_CLOCK_ID &&
    detector.clock_spec_digest === DETECTION_CLOCK_SPEC_DIGEST &&
    detector.status === "complete" &&
    detector.started_at_ms === 300 &&
    detector.completed_at_ms === 800 &&
    detector.pending_event_count === 0 &&
    detector.evaluated_event_count === events.length &&
    detector.source_high_watermark ===
      Math.max(...events.map((event) => event.source_sequence)) &&
    equalJson(
      detector.processed_event_ids,
      events.map((event) => event.event_id),
    ) &&
    equalJson(
      detector.processed_source_sequences,
      events.map((event) => event.source_sequence),
    ) &&
    equalJson(
      detector.processed_source_event_digests,
      events.map((event) => event.event_digest),
    ) &&
    equalJson(detector.observed_named_alert_ids, namedIds) &&
    exactCanonicalString(
      payload,
      detector.readback_canonical,
      detector.readback_digest,
      "detection detector readback",
    )
  );
}

function detectionQueryValid(query, alerts, traceId, clock) {
  if (!isObject(query)) return false;
  try {
    exactKeys(
      query,
      [
        "as_of_ms",
        "clock_id",
        "clock_spec_digest",
        "completed",
        "completed_at_ms",
        "observed_alert_ids",
        "query_id",
        "readback_canonical",
        "readback_digest",
        "started_at_ms",
        "trace_id",
      ],
      "detection alert query readback",
    );
  } catch {
    return false;
  }
  const payload = {
    schema: "assurance-lab.alert-query-readback/v2",
    query_id: query.query_id,
    trace_id: query.trace_id,
    completed: query.completed,
    started_at_ms: query.started_at_ms,
    completed_at_ms: query.completed_at_ms,
    as_of_ms: query.as_of_ms,
    observed_alert_ids: query.observed_alert_ids,
    clock_id: query.clock_id,
    clock_spec_digest: query.clock_spec_digest,
  };
  const observed = [...alerts]
    .filter((alert) => alert.triggered_at_ms <= query.as_of_ms)
    .sort(
      (left, right) =>
        left.triggered_at_ms - right.triggered_at_ms ||
        left.alert_id.localeCompare(right.alert_id),
    )
    .map((alert) => alert.alert_id);
  return (
    query.query_id ===
      detectionIdentifier(
        "alert-query",
        traceId,
        "SYNTH-ALERT-QUERY-",
      ) &&
    query.trace_id === traceId &&
    query.completed === true &&
    query.started_at_ms === 2_000 &&
    query.completed_at_ms === 2_000 &&
    query.as_of_ms === 2_000 &&
    query.clock_id === clock.clock_id &&
    query.clock_spec_digest === clock.clock_spec_digest &&
    query.clock_id === DETECTION_CLOCK_ID &&
    query.clock_spec_digest === DETECTION_CLOCK_SPEC_DIGEST &&
    equalJson(query.observed_alert_ids, observed) &&
    exactCanonicalString(
      payload,
      query.readback_canonical,
      query.readback_digest,
      "detection alert query readback",
    )
  );
}

function detectionCollectorConfigDigest(ruleActive) {
  return canonicalDigest({
    schema: "assurance-lab.collector-config/v1",
    sources: [{ source_id: DETECTION_SOURCE_ID, healthy: true }],
    rules: [
      {
        rule_id: DETECTION_NAMED_RULE,
        rule_kind: "named-exact",
        active: ruleActive,
      },
      {
        rule_id: DETECTION_FALLBACK_RULE,
        rule_kind: "broad-fallback",
        active: true,
      },
    ],
  });
}

function detectionReloadValid(reload, traceId, shouldReload, ruleActive) {
  if (!isObject(reload)) return false;
  try {
    exactKeys(
      reload,
      [
        "attestation_canonical",
        "attestation_digest",
        "attestation_id",
        "instance_rows_canonical",
        "instance_rows_digest",
        "post_config_digest",
        "post_instance_id",
        "pre_config_digest",
        "pre_instance_id",
        "reload_operation_canonical",
        "reload_operation_digest",
        "reload_performed",
      ],
      "detection reload attestation",
    );
  } catch {
    return false;
  }
  const payload = {
    schema: "assurance-lab.collector-reload-attestation/v2",
    attestation_id: reload.attestation_id,
    reload_performed: reload.reload_performed,
    pre_instance_id: reload.pre_instance_id,
    post_instance_id: reload.post_instance_id,
    pre_config_digest: reload.pre_config_digest,
    post_config_digest: reload.post_config_digest,
    instance_rows_digest: reload.instance_rows_digest,
    reload_operation_digest: reload.reload_operation_digest,
  };
  let instances;
  let operation;
  try {
    instances = requireCanonicalDocument(
      Buffer.from(reload.instance_rows_canonical, "utf8"),
      "detection collector instance readback",
    );
    operation = requireCanonicalDocument(
      Buffer.from(reload.reload_operation_canonical, "utf8"),
      "detection reload operation readback",
    );
  } catch {
    return false;
  }
  const preInstanceId = detectionIdentifier(
    "collector-instance\u0000pre",
    traceId,
    "SYNTH-COLLECTOR-INSTANCE-",
  );
  const postInstanceId = shouldReload
    ? detectionIdentifier(
        "collector-instance\u0000post",
        traceId,
        "SYNTH-COLLECTOR-INSTANCE-",
      )
    : preInstanceId;
  const configDigest = detectionCollectorConfigDigest(ruleActive);
  const expectedRows = [
    {
      collector_instance_id: preInstanceId,
      generation: 1,
      lifecycle_state: shouldReload ? "closed" : "active",
      created_at_ms: 0,
      closed_at_ms: shouldReload ? 0 : null,
      config_digest: configDigest,
    },
  ];
  let expectedOperation = null;
  if (shouldReload) {
    expectedRows.push({
      collector_instance_id: postInstanceId,
      generation: 2,
      lifecycle_state: "active",
      created_at_ms: 0,
      closed_at_ms: null,
      config_digest: configDigest,
    });
    expectedOperation = {
      operation_id: detectionIdentifier(
        "reload-operation",
        traceId,
        "SYNTH-RELOAD-OP-",
      ),
      trace_id: traceId,
      pre_instance_id: preInstanceId,
      post_instance_id: postInstanceId,
      status: "complete",
      started_at_ms: 0,
      completed_at_ms: 0,
    };
  }
  return (
    reload.attestation_id ===
      detectionIdentifier(
        "reload-attestation",
        traceId,
        "SYNTH-RELOAD-",
      ) &&
    reload.reload_performed === shouldReload &&
    reload.pre_instance_id === preInstanceId &&
    reload.post_instance_id === postInstanceId &&
    reload.pre_config_digest === configDigest &&
    reload.post_config_digest === configDigest &&
    sha256(Buffer.from(reload.instance_rows_canonical, "utf8")) ===
      reload.instance_rows_digest &&
    sha256(Buffer.from(reload.reload_operation_canonical, "utf8")) ===
      reload.reload_operation_digest &&
    equalJson(instances, {
      schema: "assurance-lab.collector-instance-readback/v1",
      rows: expectedRows,
    }) &&
    equalJson(operation, {
      schema: "assurance-lab.collector-reload-operation-readback/v1",
      operation: expectedOperation,
    }) &&
    exactCanonicalString(
      payload,
      reload.attestation_canonical,
      reload.attestation_digest,
      "detection reload attestation",
    )
  );
}

function forwardedEventValid(forwarded, source, collectorRunId) {
  if (!isObject(forwarded) || !isObject(source)) return false;
  try {
    exactKeys(
      forwarded,
      [
        "action_digest",
        "collector_run_id",
        "event_id",
        "event_type",
        "forwarding_digest",
        "route_id",
        "source_event_digest",
        "source_id",
        "source_sequence",
        "trace_id",
      ],
      "detection forwarded event",
    );
  } catch {
    return false;
  }
  const payload = {
    schema: "assurance-lab.forwarded-event/v1",
    event_id: source.event_id,
    trace_id: source.trace_id,
    action_digest: source.action_digest,
    source_id: source.source_id,
    source_sequence: source.source_sequence,
    event_type: source.event_type,
    source_event_digest: source.event_digest,
    route_id: DETECTION_FALLBACK_ROUTE,
    collector_run_id: collectorRunId,
  };
  return (
    forwarded.event_id === source.event_id &&
    forwarded.trace_id === source.trace_id &&
    forwarded.action_digest === source.action_digest &&
    forwarded.source_id === source.source_id &&
    forwarded.source_sequence === source.source_sequence &&
    forwarded.event_type === source.event_type &&
    forwarded.source_event_digest === source.event_digest &&
    forwarded.route_id === DETECTION_FALLBACK_ROUTE &&
    forwarded.collector_run_id === collectorRunId &&
    forwarded.forwarding_digest === canonicalDigest(payload)
  );
}

function alertCorrelationValid(alert, sourceEvents) {
  if (!isObject(alert)) return false;
  const payload = {
    schema: "assurance-lab.alert-correlation/v1",
    alert_id: alert.alert_id,
    alert_kind: alert.alert_kind,
    rule_id: alert.rule_id,
    trace_id: alert.trace_id,
    action_digest: alert.action_digest,
    source_id: alert.source_id,
    source_event_ids: sourceEvents.map((event) => event.event_id),
    source_sequences: sourceEvents.map((event) => event.source_sequence),
    source_event_digests: sourceEvents.map((event) => event.event_digest),
    evidence_route_id: alert.evidence_route_id,
    forwarded_event_digests: alert.forwarded_event_digests,
    detector_run_id: alert.detector_run_id,
  };
  return exactCanonicalString(
    payload,
    alert.correlation_evidence_canonical,
    alert.correlation_evidence_digest,
    "detection alert correlation evidence",
  );
}

function detectionAlertValid({
  actionDigest,
  alert,
  detector,
  events,
  forwarded,
  kind,
  traceId,
}) {
  if (!isObject(alert)) return false;
  try {
    exactKeys(
      alert,
      [
        "action_digest",
        "alert_id",
        "alert_kind",
        "clock_id",
        "clock_spec_digest",
        "correlation_evidence_canonical",
        "correlation_evidence_digest",
        "detector_run_id",
        "evidence_route_id",
        "forwarded_event_digests",
        "rule_id",
        "source_event_ids",
        "source_id",
        "source_sequences",
        "trace_id",
        "triggered_at_ms",
      ],
      "detection alert",
    );
  } catch {
    return false;
  }
  const named = kind === "named-exact";
  if (!named && (!isObject(forwarded[2]) || !isObject(events[2]))) {
    return false;
  }
  const sources = named ? events : [events[2]];
  const forwardedDigests = named
    ? []
    : [forwarded[2].forwarding_digest];
  return (
    alert.alert_id === detectionAlertId(kind, traceId) &&
    alert.alert_kind === kind &&
    alert.rule_id ===
      (named ? DETECTION_NAMED_RULE : DETECTION_FALLBACK_RULE) &&
    alert.trace_id === traceId &&
    alert.action_digest === actionDigest &&
    alert.source_id === DETECTION_SOURCE_ID &&
    equalJson(
      alert.source_event_ids,
      sources.map((event) => event.event_id),
    ) &&
    equalJson(
      alert.source_sequences,
      sources.map((event) => event.source_sequence),
    ) &&
    alert.evidence_route_id ===
      (named ? DETECTION_DIRECT_ROUTE : DETECTION_FALLBACK_ROUTE) &&
    equalJson(alert.forwarded_event_digests, forwardedDigests) &&
    alert.detector_run_id === (named ? detector.detector_run_id : null) &&
    alert.triggered_at_ms === (named ? 800 : 1_200) &&
    alert.clock_id === DETECTION_CLOCK_ID &&
    alert.clock_spec_digest === DETECTION_CLOCK_SPEC_DIGEST &&
    alertCorrelationValid(alert, sources)
  );
}

function canonicalText(value) {
  return canonicalize(value, DEFAULT_JSON_LIMITS).toString("utf8");
}

function detectionExpectedEvents({
  action,
  actionDigest,
  alerts,
  closure,
  collector,
  compensatorLevel,
  detector,
  events,
  expectedFallback,
  expectedNamed,
  firstAlertLatency,
  firstAlertOffset,
  forwarded,
  isBenign,
  reload,
  shamLevel,
  targetEffective,
  targetLevel,
  traceId,
}) {
  const named = alerts.filter((alert) => alert.rule_id === DETECTION_NAMED_RULE);
  const fallback = alerts.filter(
    (alert) => alert.rule_id === DETECTION_FALLBACK_RULE,
  );
  const event = (sequence, stage, component, eventType, payload) => ({
    trace_id: traceId,
    sequence,
    stage,
    component,
    event_type: eventType,
    payload,
  });
  return [
    event(1, "input", "detection-observer", "source-sequence-observed", [
      ["action", action.action],
      ["action_digest", actionDigest],
      ["source_id", DETECTION_SOURCE_ID],
      ["source_event_ids_canonical", canonicalText(events.map((item) => item.event_id))],
      ["source_event_count", events.length],
      ["source_trace_action_bound", true],
      ["source_sequence_coverage_complete", true],
      ["sham", shamLevel],
      ["collector_reload_performed", reload.reload_performed],
      ["collector_pre_instance_id", reload.pre_instance_id],
      ["collector_post_instance_id", reload.post_instance_id],
      [
        "collector_config_preserved",
        reload.pre_config_digest === reload.post_config_digest,
      ],
      ["collector_reload_attestation", reload.attestation_digest],
    ]),
    event(2, "target", "exact-correlation-detector", "named-alert-readback", [
      ["target_mode", targetLevel],
      ["named_rule_id", DETECTION_NAMED_RULE],
      ["named_rule_active", targetEffective],
      ["named_alert_count", named.length],
      ["named_alert_ids_canonical", canonicalText(named.map((item) => item.alert_id))],
      ["named_alert_identity_unique", expectedNamed],
      ["named_alert_rule_identity_bound", expectedNamed],
      ["named_alert_trace_source_action_bound", expectedNamed],
      ["named_correlation_evidence_valid", expectedNamed],
      [
        "named_correlation_artifacts_canonical",
        canonicalText(named.map((item) => item.correlation_evidence_digest)),
      ],
      ["named_exact_correlation_alert_proven", expectedNamed],
      ["detector_run_id", detector.detector_run_id],
      ["detector_run_completed", true],
      ["detector_source_high_watermark", detector.source_high_watermark],
      ["detector_pending_event_count", detector.pending_event_count],
      ["detector_run_readback", detector.readback_digest],
    ]),
    event(
      3,
      "compensator",
      "fallback-telemetry-path",
      "fallback-forwarding-readback",
      [
        ["compensator_mode", compensatorLevel],
        ["fallback_rule_id", DETECTION_FALLBACK_RULE],
        ["fallback_route_id", DETECTION_FALLBACK_ROUTE],
        [
          "fallback_alert_ids_canonical",
          canonicalText(fallback.map((item) => item.alert_id)),
        ],
        [
          "fallback_alert_forwarding_digests_canonical",
          canonicalText(fallback.map((item) => item.forwarded_event_digests)),
        ],
        [
          "forwarded_event_ids_canonical",
          canonicalText(forwarded.map((item) => item.event_id)),
        ],
        ["forwarded_event_count", forwarded.length],
        ["fallback_telemetry_forwarded", forwarded.length === events.length],
        ["fallback_alert_binding_valid", expectedFallback],
      ],
    ),
    event(4, "outcome", "detection-observer", "closed-window-readback", [
      ["alert_ids_canonical", canonicalText(alerts.map((item) => item.alert_id))],
      ["alert_count", alerts.length],
      ["any_alert_within_slo", alerts.length > 0],
      ["first_alert_offset_from_window_open_ms", firstAlertOffset ?? -1],
      ["first_alert_causal_latency_ms", firstAlertLatency ?? -1],
      ["tested_benign_action_unalerted", isBenign],
      ["source_trace_action_binding_proven", true],
      ["source_sequence_coverage_complete", true],
      ["source_healthy", true],
      ["collector_healthy", true],
      ["collector_completed", true],
      ["simulated_clock_bound", true],
      ["observation_window_closed", true],
      ["alert_query_completed", true],
      ["alert_query_as_of_ms", 2_000],
      ["alert_query_readback", collector.query.readback_digest],
      ["named_alert_absence", expectedNamed ? "present" : "concluded"],
      ["window_closure_artifact", closure.artifact_digest],
      ["window_closure_canonical", closure.artifact_canonical],
    ]),
  ];
}

function detectionClosureValid({
  action,
  actionDigest,
  alerts,
  clock,
  closure,
  collector,
  detector,
  events,
  forwarded,
  query,
  reload,
  traceId,
}) {
  try {
    exactKeys(
      closure,
      [
        "action_digest",
        "alert_query_digest",
        "alert_query_id",
        "artifact_canonical",
        "artifact_digest",
        "clock_id",
        "clock_readback_digest",
        "clock_spec_digest",
        "closed_at_ms",
        "collected_event_count",
        "collector_completed",
        "collector_healthy",
        "collector_run_id",
        "collector_run_readback_digest",
        "detector_run_digest",
        "detector_run_id",
        "expected_event_ids",
        "expected_source_sequences",
        "observed_event_ids",
        "observed_source_sequences",
        "opened_at_ms",
        "reload_attestation_digest",
        "source_healthy",
        "source_id",
        "trace_id",
      ],
      "detection window closure",
    );
  } catch {
    return false;
  }
  const plan = action.source_event_plan;
  const payload = {
    schema: "assurance-lab.detection-window-closure/v1",
    trace_id: closure.trace_id,
    action_digest: closure.action_digest,
    source_id: closure.source_id,
    expected_event_ids: closure.expected_event_ids,
    observed_event_ids: closure.observed_event_ids,
    expected_source_sequences: closure.expected_source_sequences,
    observed_source_sequences: closure.observed_source_sequences,
    source_healthy: closure.source_healthy,
    collector_run_id: closure.collector_run_id,
    collector_healthy: closure.collector_healthy,
    collector_completed: closure.collector_completed,
    collected_event_count: closure.collected_event_count,
    collector_run_readback_digest: closure.collector_run_readback_digest,
    opened_at_ms: closure.opened_at_ms,
    closed_at_ms: closure.closed_at_ms,
    clock_id: closure.clock_id,
    clock_spec_digest: closure.clock_spec_digest,
    clock_readback_digest: closure.clock_readback_digest,
    detector_run_id: closure.detector_run_id,
    detector_run_digest: closure.detector_run_digest,
    alert_query_id: closure.alert_query_id,
    alert_query_digest: closure.alert_query_digest,
    reload_attestation_digest: closure.reload_attestation_digest,
  };
  const expectedEventIds = plan.map((item) => item.event_id);
  const expectedSequences = plan.map((item) => item.sequence);
  const forwardedValid =
    forwarded.length === 0 ||
    (forwarded.length === events.length &&
      forwarded.every((item, index) =>
        forwardedEventValid(item, events[index], collector.collector_run_id),
      ));
  const alertGraphValid =
    new Set(alerts.map((alert) => alert.alert_id)).size === alerts.length &&
    alerts.every((alert) => {
      const sources = alert.source_event_ids.map((eventId) =>
        events.find((event) => event.event_id === eventId),
      );
      return (
        sources.every((event) => event !== undefined) &&
        alertCorrelationValid(alert, sources)
      );
    });
  return (
    exactCanonicalString(
      payload,
      closure.artifact_canonical,
      closure.artifact_digest,
      "detection window closure",
    ) &&
    closure.trace_id === traceId &&
    closure.action_digest === actionDigest &&
    closure.source_id === action.source_id &&
    equalJson(closure.expected_event_ids, expectedEventIds) &&
    equalJson(closure.observed_event_ids, expectedEventIds) &&
    equalJson(closure.expected_source_sequences, expectedSequences) &&
    equalJson(closure.observed_source_sequences, expectedSequences) &&
    closure.source_healthy === true &&
    closure.collector_healthy === true &&
    closure.collector_completed === true &&
    closure.collected_event_count === events.length &&
    closure.opened_at_ms === 0 &&
    closure.closed_at_ms === 2_000 &&
    closure.collector_run_id === collector.collector_run_id &&
    closure.collector_run_readback_digest === collector.readback_digest &&
    closure.clock_id === clock.clock_id &&
    closure.clock_spec_digest === clock.clock_spec_digest &&
    closure.clock_readback_digest === clock.readback_digest &&
    closure.detector_run_id === detector.detector_run_id &&
    closure.detector_run_digest === detector.readback_digest &&
    closure.alert_query_id === query.query_id &&
    closure.alert_query_digest === query.readback_digest &&
    closure.reload_attestation_digest === reload.attestation_digest &&
    forwardedValid &&
    alertGraphValid
  );
}

function evaluateDetection(input, selector) {
  const action = input.action.document;
  const result = unwrapRuntime(
    input,
    "assurance-lab.financial-detection-runtime-observation/v1",
  );
  exactKeys(result, DETECTION_RESULT_KEYS, "detection runtime result");
  const actionDigest = sha256(input.action.bytes);
  if (
    result.trace_id !== input.trial.trace_id ||
    result.action_digest !== actionDigest ||
    result.input_level !== valueOf(selector.input, "detection input selector") ||
    result.target_level !== valueOf(selector.target, "detection target selector") ||
    result.compensator_level !==
      valueOf(selector.compensator, "detection compensator selector") ||
    result.sham_level !== valueOf(selector.sham, "detection sham selector")
  ) {
    throw new BenchmarkVerificationError(
      "runtime-binding-mismatch",
      "detection runtime does not bind the raw action and compiler selector",
    );
  }
  const inputLevel = valueOf(selector.input, "detection input selector");
  const targetLevel = valueOf(selector.target, "detection target selector");
  const compensatorLevel = valueOf(
    selector.compensator,
    "detection compensator selector",
  );
  const shamLevel = valueOf(selector.sham, "detection sham selector");
  const isBenign =
    inputLevel ===
    valueOf(
      input.specification.contract.profile.input.benign,
      "detection benign axis",
    );
  const isAttack = !isBenign;
  const targetEffective =
    targetLevel === SCENARIO_PROFILES[SCENARIOS[1]].targetEffective;
  const compensatorOn =
    compensatorLevel === SCENARIO_PROFILES[SCENARIOS[1]].compensatorOn;
  const shouldReload =
    shamLevel === SCENARIO_PROFILES[SCENARIOS[1]].shamRedeploy;
  const expectedNamed = isAttack && targetEffective;
  const expectedFallback = isAttack && compensatorOn;
  const plan = requireArray(action.source_event_plan, null, "detection source event plan");
  const events = requireArray(result.source_events, plan.length, "detection source events");
  const sourceValid = events.every((event, index) => {
    const expected = plan[index];
    try {
      exactKeys(
        event,
        [
          "action_digest",
          "clock_id",
          "clock_spec_digest",
          "event_digest",
          "event_id",
          "event_type",
          "observed_at_ms",
          "source_id",
          "source_sequence",
          "trace_id",
        ],
        "detection source event",
      );
      return (
        event.event_id === expected.event_id &&
        event.source_sequence === expected.sequence &&
        event.event_type === expected.event_type &&
        event.observed_at_ms === (index + 1) * 100 &&
        event.trace_id === input.trial.trace_id &&
        event.action_digest === actionDigest &&
        event.source_id === DETECTION_SOURCE_ID &&
        event.clock_id === DETECTION_CLOCK_ID &&
        event.clock_spec_digest === DETECTION_CLOCK_SPEC_DIGEST &&
        event.event_digest === canonicalDigest(sourceEventPayload(event))
      );
    } catch {
      return false;
    }
  });
  const alerts = requireArray(result.alerts, null, "detection alerts");
  const forwarded = requireArray(
    result.forwarded_events,
    null,
    "detection forwarded events",
  );
  const clock = requireObject(result.clock_readback, "detection clock readback");
  const collector = requireObject(
    result.collector_run_readback,
    "detection collector readback",
  );
  const detector = requireObject(
    result.detector_run,
    "detection detector readback",
  );
  const query = requireObject(
    result.alert_query,
    "detection alert query readback",
  );
  const reload = requireObject(
    result.reload_attestation,
    "detection reload attestation",
  );
  const closure = requireObject(result.window_closure, "detection window closure");
  const forwardingValid =
    forwarded.length === (compensatorOn ? events.length : 0) &&
    forwarded.every((item, index) =>
      forwardedEventValid(item, events[index], collector.collector_run_id),
    );
  const expectedAlerts = [];
  if (expectedNamed) expectedAlerts.push("named-exact");
  if (expectedFallback) expectedAlerts.push("broad-fallback");
  const alertsValid =
    alerts.length === expectedAlerts.length &&
    alerts.every((alert, index) =>
      detectionAlertValid({
        actionDigest,
        alert,
        detector,
        events,
        forwarded,
        kind: expectedAlerts[index],
        traceId: input.trial.trace_id,
      }),
    );
  const closureValid =
    sourceValid &&
    forwardingValid &&
    alertsValid &&
    detectionClockValid(clock, expectedFallback) &&
    detectionCollectorValid(collector, events, input.trial.trace_id) &&
    detectionDetectorValid(
      detector,
      events,
      alerts,
      input.trial.trace_id,
      targetEffective,
    ) &&
    detectionQueryValid(query, alerts, input.trial.trace_id, clock) &&
    detectionReloadValid(
      reload,
      input.trial.trace_id,
      shouldReload,
      targetEffective,
    ) &&
    detectionClosureValid({
      action,
      actionDigest,
      alerts,
      clock,
      closure,
      collector,
      detector,
      events,
      forwarded,
      query,
      reload,
      traceId: input.trial.trace_id,
    });
  if (!closureValid) {
    throw new BenchmarkVerificationError(
      "runtime-contradiction",
      "detection runtime evidence does not close over the pinned event graph",
    );
  }
  const firstAlertOffset = expectedNamed
    ? 800
    : expectedFallback
      ? 1_200
      : null;
  const firstAlertLatency = expectedNamed
    ? 500
    : expectedFallback
      ? 900
      : null;
  const summaryValid =
    result.source_healthy === true &&
    result.collector_healthy === true &&
    result.collector_completed === true &&
    result.detector_run_completed === true &&
    result.alert_query_completed === true &&
    result.observation_window_closed === true &&
    result.simulated_clock_bound === true &&
    result.source_sequence_coverage_complete === true &&
    result.source_trace_action_bound === true &&
    result.named_rule_active === targetEffective &&
    result.named_alert_identity_unique === expectedNamed &&
    result.named_alert_rule_identity_bound === expectedNamed &&
    result.named_alert_trace_source_action_bound === expectedNamed &&
    result.named_correlation_evidence_valid === expectedNamed &&
    result.named_exact_correlation_alert_proven === expectedNamed &&
    result.fallback_telemetry_forwarded === compensatorOn &&
    result.fallback_alert_binding_valid === expectedFallback &&
    equalJson(
      result.forwarded_event_ids,
      compensatorOn ? events.map((item) => item.event_id) : [],
    ) &&
    result.any_alert_within_slo === (alerts.length > 0) &&
    result.first_alert_offset_from_window_open_ms === firstAlertOffset &&
    result.first_alert_causal_latency_ms === firstAlertLatency &&
    result.tested_benign_action_unalerted === isBenign;
  const expectedRuntimeEvents = detectionExpectedEvents({
    action,
    actionDigest,
    alerts,
    closure,
    collector: { query },
    compensatorLevel,
    detector,
    events,
    expectedFallback,
    expectedNamed,
    firstAlertLatency,
    firstAlertOffset,
    forwarded,
    isBenign,
    reload,
    shamLevel,
    targetEffective,
    targetLevel,
    traceId: input.trial.trace_id,
  });
  if (!summaryValid || !equalJson(result.events, expectedRuntimeEvents)) {
    throw new BenchmarkVerificationError(
      "runtime-contradiction",
      "detection runtime summaries or audit events differ from raw evidence",
    );
  }
  const targetSupported = expectedNamed;
  const compensatorSupported = expectedFallback;
  const pathSupported = alerts.length > 0;
  const benignSupported = isBenign;
  const baselinePasses = pathSupported;
  let residual = "unresolved";
  if (!targetSupported && compensatorSupported && pathSupported) {
    residual = "masked-target-failure";
  } else if (!targetSupported && !pathSupported) {
    residual = "exposed-path";
  } else if (targetSupported) {
    residual = "target-effective";
  }
  return semanticVector({
    target: isBenign ? "not-exercised" : disposition(targetSupported),
    compensator: isBenign
      ? "not-exercised"
      : disposition(compensatorSupported),
    path: isBenign ? "not-exercised" : disposition(pathSupported),
    benign: isBenign ? disposition(benignSupported) : "not-exercised",
    baseline: isBenign ? baseline(benignSupported) : baseline(baselinePasses),
    residual: isBenign ? "unresolved" : residual,
  });
}

function parseCanonicalEvidence(canonicalText, digestValue, label) {
  if (typeof canonicalText !== "string") {
    throw new BenchmarkVerificationError(
      "malformed-runtime",
      `${label} canonical value is not text`,
    );
  }
  const bytes = Buffer.from(canonicalText, "utf8");
  const document = requireCanonicalDocument(bytes, label);
  if (sha256(bytes) !== digestValue) {
    throw new BenchmarkVerificationError(
      "runtime-contradiction",
      `${label} digest does not address its canonical bytes`,
    );
  }
  return document;
}

function recoverySnapshotDescriptor(targetLevel) {
  const ineffective = targetLevel === "stale-wildcard";
  return {
    schema: "assurance-lab.recovery-entitlement-snapshot/v1",
    snapshot_id: ineffective
      ? "SYNTH-ENTITLEMENT-SNAPSHOT-STALE"
      : "SYNTH-ENTITLEMENT-SNAPSHOT-APPROVED",
    principal_id: "support-017",
    restore_operation_id: "SYNTH-RESTORE-OPERATION-000001",
    entitlement_set: {
      schema: "assurance-lab.recovery-entitlement-set/v1",
      principal_id: "support-017",
      entitlements: [
        ineffective
          ? "customer:*"
          : "customer:SYNTH-CUSTOMER-000017",
      ],
    },
  };
}

function recoverySessionIdentityDigest(sessionId) {
  return canonicalDigest({
    schema: "assurance-lab.synthetic-session-identity/v1",
    session_id: sessionId,
  });
}

function identifierSetEvidence(schemaName, identifiers) {
  const document = {
    schema: `assurance-lab.${schemaName}/v1`,
    identifiers,
  };
  const canonical = canonicalize(document, DEFAULT_JSON_LIMITS).toString("utf8");
  return { canonical, digest: sha256(Buffer.from(canonical, "utf8")) };
}

function recoverySnapshotMutationEvidence({
  snapshot,
  targetLevel,
  traceId,
  operationId,
}) {
  if (operationId === null) {
    const document = {
      schema: "assurance-lab.snapshot-apply-mutation-set/v1",
      trace_id: traceId,
      operation_id: null,
      mutations: [],
    };
    const canonical = canonicalize(document).toString("utf8");
    return { canonical, digest: sha256(Buffer.from(canonical, "utf8")) };
  }
  const rows = [];
  const append = ({
    entity_type,
    operation,
    row_key,
    snapshot_id,
    row_target_level,
    principal_id,
    restore_operation_id,
    entitlement,
  }) => {
    rows.push({
      sequence: rows.length + 1,
      trace_id: traceId,
      operation_id: operationId,
      entity_type,
      operation,
      row_key,
      snapshot_id,
      target_level: row_target_level,
      principal_id,
      restore_operation_id,
      entitlement,
    });
  };
  for (const entitlement of snapshot.entitlement_set.entitlements) {
    append({
      entity_type: "entitlement",
      operation: "delete",
      row_key: `${snapshot.snapshot_id}:${entitlement}`,
      snapshot_id: snapshot.snapshot_id,
      row_target_level: null,
      principal_id: null,
      restore_operation_id: null,
      entitlement,
    });
  }
  append({
    entity_type: "snapshot",
    operation: "delete",
    row_key: snapshot.snapshot_id,
    snapshot_id: snapshot.snapshot_id,
    row_target_level: targetLevel,
    principal_id: snapshot.principal_id,
    restore_operation_id: snapshot.restore_operation_id,
    entitlement: null,
  });
  append({
    entity_type: "snapshot",
    operation: "insert",
    row_key: snapshot.snapshot_id,
    snapshot_id: snapshot.snapshot_id,
    row_target_level: targetLevel,
    principal_id: snapshot.principal_id,
    restore_operation_id: snapshot.restore_operation_id,
    entitlement: null,
  });
  for (const entitlement of snapshot.entitlement_set.entitlements) {
    append({
      entity_type: "entitlement",
      operation: "insert",
      row_key: `${snapshot.snapshot_id}:${entitlement}`,
      snapshot_id: snapshot.snapshot_id,
      row_target_level: null,
      principal_id: null,
      restore_operation_id: null,
      entitlement,
    });
  }
  const document = {
    schema: "assurance-lab.snapshot-apply-mutation-set/v1",
    trace_id: traceId,
    operation_id: operationId,
    mutations: rows,
  };
  const canonical = canonicalize(document).toString("utf8");
  return { canonical, digest: sha256(Buffer.from(canonical, "utf8")) };
}

function recoveryRuntimeEvent({
  traceId,
  sequence,
  stage,
  component,
  eventType,
  payload,
}) {
  return {
    trace_id: traceId,
    sequence,
    stage,
    component,
    event_type: eventType,
    payload,
  };
}

function validateRecoveryRuntime(input, selector) {
  const result = unwrapRuntime(
    input,
    "assurance-lab.financial-recovery-runtime-observation/v1",
  );
  exactKeys(result, RECOVERY_RESULT_KEYS, "recovery runtime result");
  const inputLevel = valueOf(selector.input, "recovery input selector");
  const targetLevel = valueOf(selector.target, "recovery target selector");
  const guardLevel = valueOf(
    selector.compensator,
    "recovery compensator selector",
  );
  const shamLevel = valueOf(selector.sham, "recovery sham selector");
  const action = pinnedActionDescriptor(SCENARIOS[0], inputLevel);
  const actionCanonical = canonicalize(action).toString("utf8");
  const actionDigest = sha256(Buffer.from(actionCanonical, "utf8"));
  if (
    result.trace_id !== input.trial.trace_id ||
    result.trace_id !== expectedTrialTraceId(SCENARIOS[0], input.trial) ||
    result.action_digest !== actionDigest ||
    result.input_level !== inputLevel ||
    result.target_level !== targetLevel ||
    result.guard_level !== guardLevel ||
    result.sham_level !== shamLevel ||
    !equalJson(result.requested_customer_ids, action.requested_customer_ids)
  ) {
    throw new BenchmarkVerificationError(
      "runtime-binding-mismatch",
      "recovery runtime does not bind the exact action, trial, and selector",
    );
  }

  const snapshot = recoverySnapshotDescriptor(targetLevel);
  const snapshotCanonical = canonicalize(snapshot).toString("utf8");
  const snapshotDigest = sha256(Buffer.from(snapshotCanonical, "utf8"));
  const entitlementCanonical = canonicalize(
    snapshot.entitlement_set,
  ).toString("utf8");
  const entitlementDigest = sha256(Buffer.from(entitlementCanonical, "utf8"));
  const proofLifecycle = requireObject(
    input.proof?.lifecycle,
    "validated recovery lifecycle proof",
  );
  const ineffective = targetLevel === "stale-wildcard";
  const lifecycleHead = ineffective
    ? proofLifecycle.actualHeadDocument
    : proofLifecycle.comparisonHeadDocument;
  const lifecycleSnapshotDigest = canonicalDigest(lifecycleHead);
  const lifecycleSnapshotCanonical = canonicalize(lifecycleHead).toString(
    "utf8",
  );
  const verifiedLifecycle = proofLifecycle.verifiedDocument;
  const verifiedLifecycleCanonical = canonicalize(
    verifiedLifecycle,
  ).toString("utf8");
  const verifiedLifecycleDigest = sha256(
    Buffer.from(verifiedLifecycleCanonical, "utf8"),
  );
  const lifecycleBranch = ineffective
    ? proofLifecycle.lifecycleDocument.actual
    : proofLifecycle.lifecycleDocument.matched_comparison;
  const transitionId = lifecycleBranch.transitions?.at(-1)?.transition_id;
  const replacementSessionId = ineffective
    ? "SYNTH-SESSION-SUPPORT-017-REPLACEMENT"
    : "SYNTH-SESSION-SUPPORT-017-REPLACEMENT-COMPARISON";
  const replacementSessionDigest =
    recoverySessionIdentityDigest(replacementSessionId);
  const expectedBundleVerification = {
    status: "integrity_verified",
    bundle_id: proofLifecycle.sourceBundleId,
    manifest: proofLifecycle.sourceBundleManifest,
    issues: [],
  };
  if (
    result.snapshot_id !== snapshot.snapshot_id ||
    result.snapshot_digest !== snapshotDigest ||
    result.entitlement_set_canonical !== entitlementCanonical ||
    result.entitlement_set_digest !== entitlementDigest ||
    result.snapshot_identity_matches_declared_target !== true ||
    result.lifecycle_bundle_digest !== proofLifecycle.sourceBundleId ||
    !equalJson(
      result.lifecycle_bundle_locator,
      {
        kind: "embedded-cab-snapshot",
        snapshot_digest: proofLifecycle.sourceSnapshotDigest,
      },
    ) ||
    !equalJson(result.lifecycle_bundle_verification, expectedBundleVerification) ||
    result.lifecycle_snapshot_canonical !== lifecycleSnapshotCanonical ||
    result.lifecycle_snapshot_digest !== lifecycleSnapshotDigest ||
    result.lifecycle_bound_branch_head_digest !== lifecycleSnapshotDigest ||
    result.verified_lifecycle_canonical !== verifiedLifecycleCanonical ||
    result.verified_lifecycle_digest !== verifiedLifecycleDigest ||
    result.lifecycle_branch_id !== lifecycleHead.branch_id ||
    result.lifecycle_branch_kind !== lifecycleHead.branch_kind ||
    result.lifecycle_branch_kind !==
      (ineffective ? "actual" : "matched-comparison") ||
    result.session_rotation_transition_id !== transitionId ||
    !Array.isArray(
      ineffective
        ? verifiedLifecycle.actual_transition_ids
        : verifiedLifecycle.matched_comparison_transition_ids,
    ) ||
    !(
      ineffective
        ? verifiedLifecycle.actual_transition_ids
        : verifiedLifecycle.matched_comparison_transition_ids
    ).includes(transitionId) ||
    lifecycleHead.principal_id !== "support-017" ||
    lifecycleHead.phase !== "session_rotated" ||
    lifecycleHead.compromised_session_state !== "revoked" ||
    lifecycleHead.replacement_session_state !== "active" ||
    lifecycleHead.entitlement_set_digest !== entitlementDigest ||
    lifecycleHead.replacement_entitlement_digest !== entitlementDigest ||
    lifecycleHead.replacement_session_digest !== replacementSessionDigest ||
    result.old_session_id !== "SYNTH-SESSION-SUPPORT-017-OLD" ||
    result.old_session_state !== "revoked" ||
    result.old_session_revoked !== true ||
    result.replacement_session_id !== replacementSessionId ||
    result.replacement_session_state !== "active" ||
    result.replacement_session_active !== true ||
    result.replacement_session_entitlement_set_digest !== entitlementDigest ||
    result.replacement_session_entitlement_digest_bound !== true ||
    result.cutover_fixture_valid !== true
  ) {
    throw new BenchmarkVerificationError(
      "proof-substitution",
      "recovery runtime does not reproduce the embedded lifecycle cutover",
    );
  }

  const sessionResolution = {
    schema: "assurance-lab.session-role-resolution/v1",
    session_role: "active-replacement",
    resolved_session_id: replacementSessionId,
    resolved_session_digest: replacementSessionDigest,
    lifecycle_snapshot_digest: lifecycleSnapshotDigest,
    verified_lifecycle_digest: verifiedLifecycleDigest,
  };
  const sessionResolutionCanonical =
    canonicalize(sessionResolution).toString("utf8");
  const sessionResolutionDigest = sha256(
    Buffer.from(sessionResolutionCanonical, "utf8"),
  );
  if (
    result.action_session_role !== "active-replacement" ||
    result.session_resolution_canonical !== sessionResolutionCanonical ||
    result.session_resolution_digest !== sessionResolutionDigest ||
    result.session_resolution_lifecycle_snapshot_digest !==
      lifecycleSnapshotDigest ||
    result.session_resolution_verified_lifecycle_digest !==
      verifiedLifecycleDigest
  ) {
    throw new BenchmarkVerificationError(
      "runtime-contradiction",
      "recovery session-role resolution is not bound to the lifecycle head",
    );
  }

  const cloneNonce = createHash("sha256")
    .update(`recovery-clone\\0${input.trial.trial_key}`, "utf8")
    .digest("hex")
    .slice(0, 32);
  const cloneId = canonicalDigest({
    schema: "assurance-lab.sqlite-recovery-clone/v1",
    trace_id: result.trace_id,
    clone_nonce: cloneNonce,
    storage_kind: "sqlite-memory",
    selector,
    lifecycle_bundle_digest: proofLifecycle.sourceBundleId,
    lifecycle_snapshot_digest: lifecycleSnapshotDigest,
    verified_lifecycle_digest: verifiedLifecycleDigest,
  });
  const cloneReadback = {
    schema: "assurance-lab.sqlite-recovery-run-control/v1",
    clone_id: cloneId,
    clone_nonce: cloneNonce,
    trace_id: result.trace_id,
    storage_kind: "sqlite-memory",
  };
  const cleanupProbe = {
    schema: "assurance-lab.sqlite-clone-cleanup-probe/v1",
    trace_id: result.trace_id,
    clone_id: cloneId,
    clone_nonce: cloneNonce,
    probe: "execute-select-one-after-close",
    outcome: "closed-connection-programming-error",
  };
  if (
    result.clone_nonce !== cloneNonce ||
    result.clone_id !== cloneId ||
    result.clone_storage_kind !== "sqlite-memory" ||
    !equalJson(
      parseCanonicalEvidence(
        result.clone_readback_canonical,
        result.clone_readback_digest,
        "recovery clone readback",
      ),
      cloneReadback,
    ) ||
    !equalJson(
      parseCanonicalEvidence(
        result.clone_cleanup_probe_canonical,
        result.clone_cleanup_probe_digest,
        "recovery clone cleanup probe",
      ),
      cleanupProbe,
    ) ||
    result.clone_cleanup_verified !== true
  ) {
    throw new BenchmarkVerificationError(
      "runtime-contradiction",
      "recovery clone identity or post-close cleanup probe is invalid",
    );
  }

  const assignments = parseCanonicalEvidence(
    result.assignment_basis_canonical,
    result.assignment_basis_digest,
    "recovery assignment basis",
  );
  exactKeys(
    assignments,
    ["assignments", "principal_id", "schema"],
    "recovery assignment basis",
  );
  const assignmentRows = requireArray(
    assignments.assignments,
    10,
    "recovery assignment rows",
  );
  const expectedAssigned = Array.from(
    { length: 10 },
    (_unused, index) =>
      `SYNTH-CUSTOMER-${String(17 + index * 20).padStart(6, "0")}`,
  );
  assignmentRows.forEach((row, index) => {
    exactKeys(
      row,
      ["case_id", "customer_id", "principal_id", "status"],
      "recovery assignment row",
    );
    const customerId = expectedAssigned[index];
    if (
      row.case_id !== `CASE-${customerId.slice(-6)}` ||
      row.customer_id !== customerId ||
      row.principal_id !== "support-017" ||
      row.status !== "active"
    ) {
      throw new BenchmarkVerificationError(
        "runtime-contradiction",
        "recovery assignment rows differ from the fixed synthetic dataset",
      );
    }
  });
  if (
    assignments.schema !==
      "assurance-lab.active-support-assignment-set/v1" ||
    assignments.principal_id !== "support-017" ||
    !equalJson(result.assigned_customer_ids, expectedAssigned)
  ) {
    throw new BenchmarkVerificationError(
      "runtime-contradiction",
      "recovery assigned-customer summary is not derived from assignment rows",
    );
  }

  const requested = action.requested_customer_ids;
  const authorized =
    ineffective ||
    requested.every(
      (customerId) => customerId === "SYNTH-CUSTOMER-000017",
    );
  const selected = authorized ? requested : [];
  const assigned = new Set(expectedAssigned);
  const selectedOutside = selected.filter(
    (customerId) => !assigned.has(customerId),
  );
  const guardReached = authorized;
  const shouldBlock =
    guardReached && guardLevel === "enforce" && selectedOutside.length > 0;
  const releaseDecision = !guardReached
    ? "not-reached"
    : shouldBlock
      ? "block"
      : "allow";
  const releaseReason = !guardReached
    ? "restored-entitlement-denied"
    : shouldBlock
      ? "unapproved-or-bulk-export"
      : selectedOutside.length > 0
        ? "monitor-only-observation"
        : "approved-assigned-case";
  const delivered = releaseDecision === "allow" ? selected : [];
  const deliveredOutside = delivered.filter(
    (customerId) => !assigned.has(customerId),
  );
  const deliveredAssigned = delivered.filter((customerId) =>
    assigned.has(customerId),
  );
  const blocked =
    guardReached &&
    releaseDecision === "block" &&
    selectedOutside.length > 0 &&
    deliveredOutside.length === 0;
  const receipts = {
    schema: "assurance-lab.recovery-delivery-receipt-set/v1",
    receipts: delivered.map((customerId) => ({
      receipt_id: canonicalDigest({
        schema: "assurance-lab.recovery-delivery-receipt/v1",
        trace_id: result.trace_id,
        request_id: action.request_id,
        customer_id: customerId,
      }),
      trace_id: result.trace_id,
      request_id: action.request_id,
      customer_id: customerId,
    })),
  };
  if (
    result.snapshot_authorized_action !== authorized ||
    !equalJson(result.selected_customer_ids, selected) ||
    !equalJson(result.selected_out_of_scope_customer_ids, selectedOutside) ||
    result.out_of_scope_records_selected !== selectedOutside.length ||
    result.release_guard_reached !== guardReached ||
    result.release_decision !== releaseDecision ||
    result.release_reason !== releaseReason ||
    result.unapproved_release_blocked !== blocked ||
    !equalJson(result.delivered_customer_ids, delivered) ||
    !equalJson(result.delivered_out_of_scope_customer_ids, deliveredOutside) ||
    !equalJson(result.delivered_assigned_customer_ids, deliveredAssigned) ||
    result.out_of_scope_records_delivered !== deliveredOutside.length ||
    result.assigned_case_records_delivered !== deliveredAssigned.length ||
    !equalJson(
      parseCanonicalEvidence(
        result.delivery_receipts_canonical,
        result.delivery_receipts_digest,
        "recovery delivery receipts",
      ),
      receipts,
    )
  ) {
    throw new BenchmarkVerificationError(
      "runtime-contradiction",
      "recovery summaries do not reproduce the fixed selection and delivery receipts",
    );
  }

  const expectsReapply = shamLevel === "snapshot-reapply";
  const reapplyOperationId = expectsReapply
    ? canonicalDigest({
        schema: "assurance-lab.snapshot-reapply-operation/v1",
        trace_id: result.trace_id,
        target_level: targetLevel,
        before_snapshot_digest: snapshotDigest,
      })
    : null;
  const mutationEvidence = recoverySnapshotMutationEvidence({
    snapshot,
    targetLevel,
    traceId: result.trace_id,
    operationId: reapplyOperationId,
  });
  if (
    result.snapshot_reapply_performed !== expectsReapply ||
    result.snapshot_reapply_operation_id !== reapplyOperationId ||
    result.snapshot_reapply_snapshot_rows_deleted !==
      (expectsReapply ? 1 : 0) ||
    result.snapshot_reapply_entitlement_rows_deleted !==
      (expectsReapply ? snapshot.entitlement_set.entitlements.length : 0) ||
    result.snapshot_reapply_snapshot_rows_inserted !==
      (expectsReapply ? 1 : 0) ||
    result.snapshot_reapply_entitlement_rows_inserted !==
      (expectsReapply ? snapshot.entitlement_set.entitlements.length : 0) ||
    result.snapshot_reapply_mutation_rows_canonical !==
      mutationEvidence.canonical ||
    result.snapshot_reapply_mutation_rows_digest !== mutationEvidence.digest ||
    result.snapshot_reapply_semantics_unchanged !== true ||
    result.snapshot_reapply_receipt_valid !== true
  ) {
    throw new BenchmarkVerificationError(
      "runtime-contradiction",
      "recovery snapshot reapply receipt does not reproduce the fixed mutation",
    );
  }

  const ledgerCanonical = canonicalize(
    lifecycleHead.disclosure_ledger,
  ).toString("utf8");
  const ledgerDigest = sha256(Buffer.from(ledgerCanonical, "utf8"));
  const entryIds = lifecycleHead.disclosure_ledger.entries.map((entry) =>
    canonicalDigest(entry),
  );
  const entryEvidence = identifierSetEvidence(
    "lifecycle-disclosure-entry-id-set",
    entryIds,
  );
  if (
    result.prior_disclosure_ledger_canonical_before !== ledgerCanonical ||
    result.prior_disclosure_ledger_canonical_after !== ledgerCanonical ||
    result.prior_disclosure_ledger_digest_before !== ledgerDigest ||
    result.prior_disclosure_ledger_digest_after !== ledgerDigest ||
    result.prior_disclosure_entry_ids_canonical_before !==
      entryEvidence.canonical ||
    result.prior_disclosure_entry_ids_canonical_after !==
      entryEvidence.canonical ||
    result.prior_disclosure_entry_ids_digest_before !== entryEvidence.digest ||
    result.prior_disclosure_entry_ids_digest_after !== entryEvidence.digest ||
    result.prior_admitted_disclosure_count_before !== entryIds.length ||
    result.prior_admitted_disclosure_count_after !== entryIds.length ||
    result.prior_disclosure_reference_unchanged !== true
  ) {
    throw new BenchmarkVerificationError(
      "runtime-contradiction",
      "recovery disclosure history is not bound to the lifecycle snapshot",
    );
  }

  const requestedEvidence = identifierSetEvidence(
    "requested-customer-set",
    requested,
  );
  const assignedEvidence = identifierSetEvidence(
    "assigned-customer-set",
    expectedAssigned,
  );
  const selectedEvidence = identifierSetEvidence(
    "selected-customer-set",
    selected,
  );
  const selectedOutsideEvidence = identifierSetEvidence(
    "selected-out-of-scope-customer-set",
    selectedOutside,
  );
  const deliveredEvidence = identifierSetEvidence(
    "delivered-customer-set",
    delivered,
  );
  const deliveredOutsideEvidence = identifierSetEvidence(
    "delivered-out-of-scope-customer-set",
    deliveredOutside,
  );
  const deliveredAssignedEvidence = identifierSetEvidence(
    "delivered-assigned-customer-set",
    deliveredAssigned,
  );
  const expectedEvents = [
    recoveryRuntimeEvent({
      traceId: result.trace_id,
      sequence: 1,
      stage: "input",
      component: "recovery-client",
      eventType: "recovery-retest-issued",
      payload: [
        ["action", action.action],
        ["request_id", action.request_id],
        ["principal_id", "support-017"],
        ["session_role", "active-replacement"],
        ["resolved_session_id", replacementSessionId],
        ["resolved_session_digest", replacementSessionDigest],
        ["session_resolution_canonical", sessionResolutionCanonical],
        ["session_resolution_digest", sessionResolutionDigest],
        [
          "session_resolution_lifecycle_snapshot_digest",
          lifecycleSnapshotDigest,
        ],
        [
          "session_resolution_verified_lifecycle_digest",
          verifiedLifecycleDigest,
        ],
        ["clone_id", cloneId],
        ["clone_nonce", cloneNonce],
        ["storage_kind", "sqlite-memory"],
        ["clone_readback_canonical", result.clone_readback_canonical],
        ["clone_readback_digest", result.clone_readback_digest],
        ["action_canonical", actionCanonical],
        ["action_digest", actionDigest],
        ["requested_customer_ids_canonical", requestedEvidence.canonical],
        ["requested_customer_ids_digest", requestedEvidence.digest],
      ],
    }),
    recoveryRuntimeEvent({
      traceId: result.trace_id,
      sequence: 2,
      stage: "input",
      component: "recovery-access-session",
      eventType: "lifecycle-cutover-reference-readback",
      payload: [
        ["lifecycle_bundle_digest", proofLifecycle.sourceBundleId],
        ["lifecycle_snapshot_digest", lifecycleSnapshotDigest],
        ["lifecycle_snapshot_canonical", lifecycleSnapshotCanonical],
        ["session_rotation_transition_id", transitionId],
        ["verified_lifecycle_digest", verifiedLifecycleDigest],
        ["lifecycle_branch_id", lifecycleHead.branch_id],
        ["lifecycle_branch_kind", lifecycleHead.branch_kind],
        ["lifecycle_bound_branch_head_digest", lifecycleSnapshotDigest],
        ["old_session_id", "SYNTH-SESSION-SUPPORT-017-OLD"],
        ["old_session_state", "revoked"],
        ["old_session_revoked", true],
        ["replacement_session_id", replacementSessionId],
        ["replacement_session_state", "active"],
        ["replacement_session_active", true],
        ["replacement_session_entitlement_set_digest", entitlementDigest],
        ["replacement_session_entitlement_digest_bound", true],
        ["cutover_fixture_valid", true],
        ["prior_disclosure_ledger_canonical", ledgerCanonical],
        ["prior_disclosure_ledger_digest", ledgerDigest],
        ["prior_disclosure_entry_ids_canonical", entryEvidence.canonical],
        ["prior_disclosure_entry_ids_digest", entryEvidence.digest],
        ["prior_admitted_disclosure_count", entryIds.length],
      ],
    }),
    recoveryRuntimeEvent({
      traceId: result.trace_id,
      sequence: 3,
      stage: "target",
      component: "restored-entitlement-boundary",
      eventType: "snapshot-and-selection-readback",
      payload: [
        ["target_mode", targetLevel],
        ["snapshot_id", snapshot.snapshot_id],
        ["snapshot_canonical", snapshotCanonical],
        ["snapshot_digest", snapshotDigest],
        ["entitlement_set_canonical", entitlementCanonical],
        ["entitlement_set_digest", entitlementDigest],
        ["snapshot_identity_matches_declared_target", true],
        ["snapshot_reapply_performed", expectsReapply],
        ["snapshot_reapply_receipt_valid", true],
        ["snapshot_reapply_operation_id", reapplyOperationId],
        ["snapshot_rows_deleted", expectsReapply ? 1 : 0],
        [
          "entitlement_rows_deleted",
          expectsReapply ? snapshot.entitlement_set.entitlements.length : 0,
        ],
        ["snapshot_rows_inserted", expectsReapply ? 1 : 0],
        [
          "entitlement_rows_inserted",
          expectsReapply ? snapshot.entitlement_set.entitlements.length : 0,
        ],
        ["snapshot_apply_mutation_rows_canonical", mutationEvidence.canonical],
        ["snapshot_apply_mutation_rows_digest", mutationEvidence.digest],
        ["pre_reapply_snapshot_digest", snapshotDigest],
        ["post_reapply_snapshot_digest", snapshotDigest],
        ["snapshot_reapply_semantics_unchanged", true],
        ["snapshot_authorized_action", authorized],
        ["assignment_basis_canonical", result.assignment_basis_canonical],
        ["assignment_basis_digest", result.assignment_basis_digest],
        ["assigned_customer_ids_canonical", assignedEvidence.canonical],
        ["assigned_customer_ids_digest", assignedEvidence.digest],
        ["selected_customer_ids_canonical", selectedEvidence.canonical],
        ["selected_customer_ids_digest", selectedEvidence.digest],
        [
          "selected_out_of_scope_customer_ids_canonical",
          selectedOutsideEvidence.canonical,
        ],
        [
          "selected_out_of_scope_customer_ids_digest",
          selectedOutsideEvidence.digest,
        ],
        ["out_of_scope_records_selected", selectedOutside.length],
      ],
    }),
    recoveryRuntimeEvent({
      traceId: result.trace_id,
      sequence: 4,
      stage: "compensator",
      component: "release-gateway",
      eventType: "release-decision-readback",
      payload: [
        ["guard_mode", guardLevel],
        ["release_guard_reached", guardReached],
        ["release_decision", releaseDecision],
        ["release_reason", releaseReason],
        ["unapproved_release_blocked", blocked],
      ],
    }),
    recoveryRuntimeEvent({
      traceId: result.trace_id,
      sequence: 5,
      stage: "outcome",
      component: "recovery-client",
      eventType: "delivery-and-history-readback",
      payload: [
        ["delivery_receipts_canonical", result.delivery_receipts_canonical],
        ["delivery_receipts_digest", result.delivery_receipts_digest],
        ["delivered_customer_ids_canonical", deliveredEvidence.canonical],
        ["delivered_customer_ids_digest", deliveredEvidence.digest],
        [
          "delivered_out_of_scope_customer_ids_canonical",
          deliveredOutsideEvidence.canonical,
        ],
        [
          "delivered_out_of_scope_customer_ids_digest",
          deliveredOutsideEvidence.digest,
        ],
        [
          "delivered_assigned_customer_ids_canonical",
          deliveredAssignedEvidence.canonical,
        ],
        [
          "delivered_assigned_customer_ids_digest",
          deliveredAssignedEvidence.digest,
        ],
        ["out_of_scope_records_delivered", deliveredOutside.length],
        ["assigned_case_records_delivered", deliveredAssigned.length],
        ["prior_disclosure_ledger_canonical_after", ledgerCanonical],
        ["prior_disclosure_ledger_digest_before", ledgerDigest],
        ["prior_disclosure_ledger_digest_after", ledgerDigest],
        ["prior_disclosure_entry_ids_digest_before", entryEvidence.digest],
        ["prior_disclosure_entry_ids_digest_after", entryEvidence.digest],
        ["prior_admitted_disclosure_count_before", entryIds.length],
        ["prior_admitted_disclosure_count_after", entryIds.length],
        ["prior_disclosure_reference_unchanged", true],
      ],
    }),
    recoveryRuntimeEvent({
      traceId: result.trace_id,
      sequence: 6,
      stage: "cleanup",
      component: "recovery-runtime",
      eventType: "sqlite-clone-cleanup-attested",
      payload: [
        ["clone_id", cloneId],
        ["clone_nonce", cloneNonce],
        ["cleanup_probe_canonical", result.clone_cleanup_probe_canonical],
        ["cleanup_probe_digest", result.clone_cleanup_probe_digest],
        ["connection_closed", true],
      ],
    }),
  ];
  if (!equalJson(result.events, expectedEvents)) {
    throw new BenchmarkVerificationError(
      "runtime-contradiction",
      "recovery event stream does not reproduce the admitted raw readbacks",
    );
  }
  return {
    result,
    selectedOutside,
    deliveredOutside,
    deliveredAssigned,
    targetSupported: selectedOutside.length === 0,
    compensatorSupported: blocked,
    pathSupported: deliveredOutside.length === 0,
    benignSupported: deliveredAssigned.length === 1,
    support: true,
  };
}

function recoveryResult(input, selector) {
  return validateRecoveryRuntime(input, selector);
}

function evaluateRecovery(input, pairInput, selector, pairSelector) {
  const subject = recoveryResult(input, selector);
  const counterpart = recoveryResult(pairInput, pairSelector);
  const subjectIsAttack =
    valueOf(selector.input, "recovery input selector") ===
    valueOf(input.specification.contract.profile.input.attack, "recovery attack axis");
  const attack = subjectIsAttack ? subject : counterpart;
  const benign = subjectIsAttack ? counterpart : subject;
  if (
    input.proof.reference.artifact_digest !==
    pairInput.proof.reference.artifact_digest
  ) {
    throw new BenchmarkVerificationError(
      "proof-substitution",
      "recovery pair does not share the exact referenced lifecycle proof",
    );
  }
  const sharedFields = [
    "snapshot_digest",
    "entitlement_set_digest",
    "replacement_session_entitlement_set_digest",
    "lifecycle_snapshot_digest",
    "lifecycle_bundle_digest",
    "prior_disclosure_ledger_digest_before",
    "prior_disclosure_entry_ids_digest_before",
    "prior_admitted_disclosure_count_before",
  ];
  if (
    sharedFields.some(
      (field) => attack.result[field] !== benign.result[field],
    )
  ) {
    throw new BenchmarkVerificationError(
      "pair-substitution",
      "matched recovery observations disagree on shared lifecycle state",
    );
  }
  const targetSupported = attack.targetSupported;
  const compensatorSupported = attack.compensatorSupported;
  const pathSupported = attack.pathSupported;
  const benignSupported = benign.benignSupported;
  const support = attack.support && benign.support;
  const baselinePasses = pathSupported && benignSupported && support;
  let residual = "unresolved";
  if (
    !targetSupported &&
    compensatorSupported &&
    pathSupported &&
    benignSupported &&
    support
  ) {
    residual = "masked-target-failure";
  } else if (!pathSupported) {
    residual = "exposed-path";
  } else if (targetSupported && pathSupported && benignSupported && support) {
    residual = "target-effective";
  }
  return semanticVector({
    target: disposition(targetSupported),
    compensator: disposition(compensatorSupported),
    path: disposition(pathSupported),
    benign: disposition(benignSupported),
    baseline: baseline(baselinePasses),
    residual,
  });
}

function pairRecoveryTrials(inputs, specification) {
  const byCoordinates = new Map();
  for (const input of inputs) {
    byCoordinates.set(
      [
        input.trial.cell_key,
        input.trial.block,
        input.trial.replicate,
      ].join("\u0000"),
      input,
    );
  }
  const cells = compilerCells(specification.contract);
  const bySelector = new Map(
    cells.map((cell) => [canonicalize(cell.selector).toString("utf8"), cell.key]),
  );
  const result = new Map();
  for (const input of inputs) {
    const selector = selectorForCell(specification.contract, input.trial.cell_key);
    const counterpartSelector = clone(selector);
    const attack = specification.contract.profile.input.attack;
    const benign = specification.contract.profile.input.benign;
    if (equalJson(selector.input, attack)) {
      counterpartSelector.input = benign;
    } else if (equalJson(selector.input, benign)) {
      counterpartSelector.input = attack;
    } else {
      throw new BenchmarkVerificationError(
        "relabelled-selector",
        "recovery input is outside the frozen attack/benign axis",
      );
    }
    const counterpartCell = bySelector.get(
      canonicalize(counterpartSelector).toString("utf8"),
    );
    const counterpart = byCoordinates.get(
      [
        counterpartCell,
        input.trial.block,
        input.trial.replicate,
      ].join("\u0000"),
    );
    if (counterpart === undefined) {
      throw new BenchmarkVerificationError(
        "missing-pair",
        "recovery trial lacks its exact compiler-matched counterpart",
      );
    }
    result.set(input.trial.trial_key, counterpart);
  }
  return result;
}

function lineageFor(input, pairInput = null) {
  if (pairInput === null) {
    const body = {
      mode: "single-trial",
      lineage_schema: "assurance-lab.benchmark.single-trial-lineage/v1",
      subject_trial_key: input.trial.trial_key,
      action_artifact: input.trial.action.artifact,
      runtime_artifact: input.trial.runtime_artifact,
    };
    return { ...body, lineage_digest: canonicalDigest(body) };
  }
  const specification = input.specification;
  const selector = selectorForCell(specification.contract, input.trial.cell_key);
  const inputIsAttack = equalJson(
    selector.input,
    specification.contract.profile.input.attack,
  );
  const attack = inputIsAttack ? input : pairInput;
  const benign = inputIsAttack ? pairInput : input;
  if (!equalJson(attack.trial.shared_lifecycle_proof, benign.trial.shared_lifecycle_proof)) {
    throw new BenchmarkVerificationError(
      "proof-substitution",
      "matched recovery pair references different lifecycle proofs",
    );
  }
  const body = {
    mode: "matched-pair",
    lineage_schema: "assurance-lab.benchmark.matched-pair-lineage/v1",
    subject_trial_key: input.trial.trial_key,
    attack_trial_key: attack.trial.trial_key,
    benign_trial_key: benign.trial.trial_key,
    attack_action_artifact: attack.trial.action.artifact,
    benign_action_artifact: benign.trial.action.artifact,
    attack_runtime_artifact: attack.trial.runtime_artifact,
    benign_runtime_artifact: benign.trial.runtime_artifact,
    shared_lifecycle_proof: attack.trial.shared_lifecycle_proof,
  };
  return { ...body, lineage_digest: canonicalDigest(body) };
}

function semanticTrial(input, semantics, pairInput = null) {
  const raw = input.trial;
  return {
    scenario_id: raw.scenario_id,
    spec_digest: raw.spec_digest,
    trial_key: raw.trial_key,
    cell_key: raw.cell_key,
    block: raw.block,
    replicate: raw.replicate,
    ordinal: raw.ordinal,
    trace_id: raw.trace_id,
    clone_unique_instance_id: raw.clone_readback.unique_instance_id,
    clone_readback_digest: raw.clone_readback.readback_digest,
    attestation_bundle_digest: raw.clone_readback.attestation_bundle_digest,
    runner_resource_id: raw.clone_readback.runner_resource_id,
    lineage: lineageFor(input, pairInput),
    semantics,
    issues: [],
  };
}

function aggregateScenario(resolvedScenario) {
  const { inputs, raw, specification } = resolvedScenario;
  const recoveryPairs =
    raw.scenario_id === SCENARIOS[0]
      ? pairRecoveryTrials(inputs, specification)
      : null;
  const semanticTrials = inputs.map((input) => {
    input.specification = specification;
    const selector = selectorForCell(specification.contract, input.trial.cell_key);
    if (raw.scenario_id === SCENARIOS[0]) {
      const pair = recoveryPairs.get(input.trial.trial_key);
      const pairSelector = selectorForCell(specification.contract, pair.trial.cell_key);
      return semanticTrial(
        input,
        evaluateRecovery(input, pair, selector, pairSelector),
        pair,
      );
    }
    if (raw.scenario_id === SCENARIOS[1]) {
      return semanticTrial(input, evaluateDetection(input, selector));
    }
    return semanticTrial(input, evaluateResponse(input, selector));
  });
  const byCell = new Map();
  for (const trial of semanticTrials) {
    if (!byCell.has(trial.cell_key)) byCell.set(trial.cell_key, []);
    byCell.get(trial.cell_key).push(trial);
  }
  const cells = [...byCell.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([cellKey, trials]) => {
      trials.sort((left, right) => left.replicate - right.replicate);
      const semanticDigests = [...new Set(
        trials.map((trial) => canonicalDigest(trial.semantics)),
      )].sort();
      let semantics;
      let agreement;
      if (semanticDigests.length === 1) {
        semantics = trials[0].semantics;
        agreement = {
          disposition: "agreed",
          semantic_digests: semanticDigests,
          divergent_trial_keys: [],
        };
      } else {
        semantics = semanticVector({
          target: "non-repeatable",
          compensator: "non-repeatable",
          path: "non-repeatable",
          benign: "non-repeatable",
          baseline: "non-repeatable",
          residual: "non-repeatable",
        });
        agreement = {
          disposition: "non-repeatable",
          semantic_digests: semanticDigests,
          divergent_trial_keys: trials.map((trial) => trial.trial_key).sort(),
        };
      }
      return {
        scenario_id: raw.scenario_id,
        spec_digest: raw.spec_digest,
        cell_key: cellKey,
        trials,
        agreement,
        semantics,
        issues: [],
      };
    });
  return {
    scenario_id: raw.scenario_id,
    spec_digest: raw.spec_digest,
    raw_trial_set_digest: resolvedScenario.rawDigest,
    cells,
    issues: [],
  };
}

function semanticProjection(result) {
  return {
    wire_schema: result.wire_schema,
    benchmark_id: result.benchmark_id,
    benchmark_version: result.benchmark_version,
    scenarios: result.scenarios,
    issues: result.issues,
  };
}

function normalizeError(error) {
  if (error instanceof BenchmarkVerificationError) {
    return {
      code: error.code,
      detail: error.message,
      path: error.path,
    };
  }
  return {
    code: "verifier-error",
    detail: "independent semantic verification did not complete",
    path: null,
  };
}

function receiptBody({
  agreement,
  implementation,
  index,
  indexDigest,
  issues,
  claimedDigest,
  claimedProjectionDigest,
  recomputedDigest,
  recomputedProjectionDigest,
  sources,
  status,
}) {
  return {
    wire_schema: BENCHMARK_RECEIPT_SCHEMA,
    verifier: {
      implementation_id: implementation.id,
      implementation_digest: implementation.digest,
      version: implementation.version,
    },
    benchmark_id: index?.benchmark_id ?? null,
    benchmark_version: index?.benchmark_version ?? null,
    benchmark_index_digest: indexDigest,
    corpus_digest: index?.corpus_digest ?? null,
    source_snapshot_digests: sources,
    claimed_semantic_result_digest: claimedDigest,
    recomputed_semantic_result_digest: recomputedDigest,
    claimed_semantic_projection_digest: claimedProjectionDigest,
    recomputed_semantic_projection_digest: recomputedProjectionDigest,
    agreement,
    status,
    issues,
  };
}

function addressedReceipt(body) {
  return { ...body, receipt_digest: canonicalDigest(body) };
}

export function verifyBenchmarkReleaseBytes({
  implementation,
  indexBytes,
  semanticResultBytes,
  sourceBundles,
}) {
  let index = null;
  let indexDigest = null;
  let claimedDigest = null;
  const sourceDigests = [];
  try {
    exactKeys(
      implementation,
      ["digest", "id", "version"],
      "verifier implementation",
    );
    requireString(implementation.id, "verifier implementation id");
    requireString(implementation.version, "verifier implementation version");
    requireDigest(implementation.digest, "verifier implementation digest");
    if (
      implementation.id !== BENCHMARK_VERIFIER_ID ||
      implementation.version !== BENCHMARK_VERIFIER_VERSION
    ) {
      throw new BenchmarkVerificationError(
        "verifier-identity-mismatch",
        "verifier implementation id or version is not the pinned independent implementation",
      );
    }
    index = requireCanonicalDocument(indexBytes, "benchmark index");
    indexDigest = sha256(indexBytes);
    const scenarioEntries = validateScenarioIndex(index);
    const claimed = requireCanonicalDocument(
      semanticResultBytes,
      "claimed semantic result",
    );
    claimedDigest = sha256(semanticResultBytes);
    if (claimedDigest !== index.semantic_result_digest) {
      throw new BenchmarkVerificationError(
        "semantic-result-substitution",
        "claimed semantic result bytes do not match the index",
      );
    }
    if (!(sourceBundles instanceof Map) || sourceBundles.size !== 3) {
      throw new BenchmarkVerificationError(
        "missing-source",
        "verification requires exactly three scenario snapshot byte strings",
      );
    }
    const resolved = [];
    for (const scenarioEntry of scenarioEntries) {
      const snapshot = sourceBundles.get(scenarioEntry.scenario_id);
      if (!Buffer.isBuffer(snapshot)) {
        throw new BenchmarkVerificationError(
          "missing-source",
          `source snapshot is missing for ${scenarioEntry.scenario_id}`,
        );
      }
      const cab = verifyManifestedSnapshot(
        snapshot,
        scenarioEntry.source_bundle_digest,
        scenarioEntry.scenario_id,
      );
      sourceDigests.push(cab.snapshotDigest);
      const specBytes = cab.entries.get(SPEC_PATH);
      const planBytes = cab.entries.get(PLAN_PATH);
      const rawBytes = cab.entries.get(RAW_PATH);
      if (
        specBytes === undefined ||
        planBytes === undefined ||
        rawBytes === undefined
      ) {
        throw new BenchmarkVerificationError(
          "missing-artifact",
          `source CAB for ${scenarioEntry.scenario_id} lacks a benchmark core member`,
        );
      }
      const specification = requireCanonicalDocument(
        specBytes,
        `${scenarioEntry.scenario_id} specification`,
      );
      const compiled = validateCompiledSpecification(
        specification,
        scenarioEntry.scenario_id,
      );
      if (specification.spec_digest !== scenarioEntry.spec_digest) {
        throw new BenchmarkVerificationError(
          "spec-digest-mismatch",
          "scenario index and compiled specification digests differ",
        );
      }
      const plan = requireCanonicalDocument(
        planBytes,
        `${scenarioEntry.scenario_id} plan`,
      );
      const planEntries = validateFrozenPlan(
        plan,
        specification,
        compiled,
      );
      const raw = requireCanonicalDocument(
        rawBytes,
        `${scenarioEntry.scenario_id} raw trial set`,
      );
      const rawDigest = sha256(rawBytes);
      if (rawDigest !== scenarioEntry.raw_trial_set_digest) {
        throw new BenchmarkVerificationError(
          "raw-substitution",
          "raw trial set bytes do not match the scenario index",
        );
      }
      const inputs = validateRawTrialSet(
        raw,
        specification,
        planEntries,
        cab,
      );
      if (
        cab.objectDigests.size !== cab.resolvedObjectDigests.size ||
        [...cab.objectDigests].some(
          (digest) => !cab.resolvedObjectDigests.has(digest),
        )
      ) {
        throw new BenchmarkVerificationError(
          "unreferenced-artifact",
          "public source object store is not the exact resolved v1 evidence closure",
        );
      }
      resolved.push({
        cab,
        compiled,
        inputs,
        plan,
        raw,
        rawDigest,
        specification,
      });
    }
    const corpusBody = clone(index);
    delete corpusBody.corpus_digest;
    corpusBody.frozen_plan_digests = resolved.map((item) =>
      canonicalDigest(item.plan),
    );
    if (index.corpus_digest !== canonicalDigest(corpusBody)) {
      throw new BenchmarkVerificationError(
        "corpus-digest-mismatch",
        "benchmark corpus digest does not close the index and frozen plans",
      );
    }
    exactKeys(
      claimed,
      [
        "benchmark_id",
        "benchmark_version",
        "evaluator_digest",
        "evaluator_id",
        "issues",
        "scenarios",
        "wire_schema",
      ],
      "claimed semantic result",
    );
    if (
      claimed.wire_schema !== "assurance-lab.benchmark.semantic-result/v1" ||
      claimed.benchmark_id !== index.benchmark_id ||
      claimed.benchmark_version !== index.benchmark_version
    ) {
      throw new BenchmarkVerificationError(
        "semantic-result-substitution",
        "claimed semantic result has a foreign benchmark identity",
      );
    }
    requireDigest(claimed.evaluator_digest, "claimed evaluator digest");
    requireString(claimed.evaluator_id, "claimed evaluator id");
    if (claimed.evaluator_id !== PRIMARY_SEMANTIC_EVALUATOR_ID) {
      throw new BenchmarkVerificationError(
        "semantic-result-substitution",
        "claimed semantic result has a foreign evaluator identity",
      );
    }
    if (!Array.isArray(claimed.issues) || claimed.issues.length !== 0) {
      throw new BenchmarkVerificationError(
        "unsupported-semantic-result",
        "benchmark-wide producer issues are unsupported by this verifier profile",
      );
    }
    const claimedScenarios = requireArray(
      claimed.scenarios,
      3,
      "claimed semantic scenarios",
    );
    claimedScenarios.forEach((scenario, position) => {
      requireObject(scenario, `claimed scenario ${String(position + 1)}`);
      const indexed = scenarioEntries[position];
      if (
        scenario.scenario_id !== indexed.scenario_id ||
        scenario.spec_digest !== indexed.spec_digest
      ) {
        throw new BenchmarkVerificationError(
          "semantic-result-substitution",
          "claimed scenario identity differs from the indexed source",
        );
      }
      if (
        canonicalDigest(scenario) !== indexed.semantic_result_digest
      ) {
        throw new BenchmarkVerificationError(
          "semantic-result-substitution",
          "claimed scenario bytes do not match their indexed content address",
        );
      }
    });
    const scenarios = resolved.map(aggregateScenario);
    const recomputed = {
      wire_schema: "assurance-lab.benchmark.semantic-result/v1",
      benchmark_id: index.benchmark_id,
      benchmark_version: index.benchmark_version,
      evaluator_id: implementation.id,
      evaluator_digest: implementation.digest,
      scenarios,
      issues: [],
    };
    const recomputedBytes = canonicalize(recomputed);
    const claimedProjection = semanticProjection(claimed);
    const recomputedProjection = semanticProjection(recomputed);
    const claimedProjectionDigest = canonicalDigest(claimedProjection);
    const recomputedProjectionDigest = canonicalDigest(recomputedProjection);
    const agreement = claimedProjectionDigest === recomputedProjectionDigest;
    const issues = agreement
      ? []
      : [
          {
            code: "semantic-disagreement",
            detail:
              "claimed semantic projection differs from independent recomputation",
            path: null,
          },
        ];
    const body = receiptBody({
      agreement: agreement ? "agreed" : "disagreed",
      implementation,
      index,
      indexDigest,
      issues,
      claimedDigest,
      claimedProjectionDigest,
      recomputedDigest: sha256(recomputedBytes),
      recomputedProjectionDigest,
      sources: sourceDigests,
      status: agreement ? "verified" : "rejected",
    });
    return {
      receipt: addressedReceipt(body),
      recomputedResult: recomputed,
    };
  } catch (error) {
    const normalized = normalizeError(error);
    const unsupported = normalized.code === "unsupported-runtime-schema";
    const body = receiptBody({
      agreement: unsupported ? "unsupported" : "not-compared",
      implementation: {
        id:
          isObject(implementation) && typeof implementation.id === "string"
            ? implementation.id
            : BENCHMARK_VERIFIER_ID,
        digest:
          isObject(implementation) &&
          typeof implementation.digest === "string" &&
          DIGEST.test(implementation.digest)
            ? implementation.digest
            : `sha256:${"0".repeat(64)}`,
        version:
          isObject(implementation) &&
          typeof implementation.version === "string"
            ? implementation.version
            : BENCHMARK_VERIFIER_VERSION,
      },
      index,
      indexDigest,
      issues: [normalized],
      claimedDigest,
      claimedProjectionDigest: null,
      recomputedDigest: null,
      recomputedProjectionDigest: null,
      sources: sourceDigests,
      status: unsupported ? "unsupported" : "rejected",
    });
    return { receipt: addressedReceipt(body), recomputedResult: null };
  }
}

export function canonicalBenchmarkReceipt(receipt) {
  return canonicalize(receipt, DEFAULT_JSON_LIMITS);
}
