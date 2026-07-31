const PORTABLE_ID = /^[a-z][a-z0-9._-]{0,127}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const REFERENCE_SYNTAX = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]+)(\/[^?#]*)$/i;
const SECRET_REFERENCE_SCHEMES = new Set([
  "aws-secretsmanager",
  "azure-keyvault",
  "gcp-secretmanager",
  "vault",
]);
const SIGNER_REFERENCE_SCHEMES = new Set([
  "aws-kms",
  "azure-keyvault",
  "gcp-kms",
  "vault-transit",
]);
const CUSTODY_REFERENCE_SCHEMES = new Set(["s3-object-lock"]);

export function normalizeControlId(value) {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (!PORTABLE_ID.test(normalized)) {
    throw new Error("통제 ID는 소문자로 시작하고 영문·숫자·점·밑줄·대시만 쓸 수 있습니다.");
  }
  return normalized;
}

export function shortDigest(value, width = 10) {
  if (!DIGEST.test(String(value ?? ""))) return "—";
  return `${value.slice(7, 7 + width)}…${value.slice(-6)}`;
}

export function stateLabel(state) {
  return {
    approved: "APPROVED",
    draft: "DRAFT",
    rejected: "REJECTED",
    retired: "RETIRED",
    submitted: "IN REVIEW",
  }[state] ?? "UNKNOWN";
}

export function flattenObject(value, prefix = "", target = new Map()) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    target.set(prefix || "(root)", value);
    return target;
  }
  for (const key of Object.keys(value).sort()) {
    const path = prefix ? `${prefix}.${key}` : key;
    flattenObject(value[key], path, target);
  }
  return target;
}

export function configurationDiff(previous, current) {
  const before = flattenObject(previous ?? {});
  const after = flattenObject(current ?? {});
  const paths = [...new Set([...before.keys(), ...after.keys()])].sort();
  return paths
    .filter((path) => JSON.stringify(before.get(path)) !== JSON.stringify(after.get(path)))
    .map((path) => ({
      after: after.has(path) ? after.get(path) : undefined,
      before: before.has(path) ? before.get(path) : undefined,
      path,
    }));
}

export function hasEffectiveRole(identity, role) {
  const roles = new Set(identity?.roles ?? []);
  return roles.has("administrator") || roles.has(role);
}

export function availableActions(revision, identity) {
  if (!revision || !identity) return [];
  const ownRevision = revision.created_by === identity.subject;
  const actions = [];
  if (
    revision.state === "draft" &&
    hasEffectiveRole(identity, "editor") &&
    ownRevision
  ) {
    actions.push("submit");
  }
  if (
    revision.state === "submitted" &&
    hasEffectiveRole(identity, "approver") &&
    !ownRevision &&
    identity.mfa
  ) {
    actions.push("approve", "reject");
  }
  if (
    revision.state === "approved" &&
    hasEffectiveRole(identity, "deployer") &&
    !ownRevision &&
    identity.mfa
  ) {
    actions.push("activate");
  }
  return actions;
}

export function captureOperationTarget(revision, activePointer) {
  if (
    !revision ||
    !DIGEST.test(String(revision.revision_id ?? "")) ||
    !PORTABLE_ID.test(String(revision.control_id ?? "")) ||
    !Number.isSafeInteger(revision.state_version) ||
    revision.state_version < 0
  ) {
    throw new Error("작업 대상 리비전이 올바르지 않습니다.");
  }
  const activePointerVersion = activePointer?.deployment_version ?? null;
  if (
    activePointerVersion !== null &&
    (!Number.isSafeInteger(activePointerVersion) || activePointerVersion < 1)
  ) {
    throw new Error("활성 포인터 버전이 올바르지 않습니다.");
  }
  return Object.freeze({
    activePointerVersion,
    controlId: revision.control_id,
    revisionId: revision.revision_id,
    stateVersion: revision.state_version,
  });
}

export function revisionComparisons(selected, revisions, activeRevision) {
  if (!selected) {
    return Object.freeze({
      active: [],
      activeStatus: "no-selection",
      lineage: [],
      lineageStatus: "no-selection",
    });
  }
  const previous = (revisions ?? []).find(
    (revision) => revision.generation === selected.generation - 1,
  );
  const activeStatus =
    activeRevision === null || activeRevision === undefined
      ? "no-active-pointer"
      : activeRevision.revision_id === selected.revision_id
        ? "selected-is-active"
        : "compared";
  return Object.freeze({
    active:
      activeRevision === null || activeRevision === undefined
        ? []
        : configurationDiff(
            activeRevision.configuration,
            selected.configuration,
          ),
    activeStatus,
    lineage:
      previous === undefined
        ? []
        : configurationDiff(previous.configuration, selected.configuration),
    lineageStatus: previous === undefined ? "no-parent" : "compared",
  });
}

export function deploymentPresentation(desired, applied, operations) {
  const ordered = [...(operations ?? [])].sort(
    (left, right) =>
      Number(right.operation_sequence ?? -1) -
      Number(left.operation_sequence ?? -1),
  );
  const latest = ordered[0] ?? null;
  const desiredMatchesLatest =
    desired !== null &&
    desired !== undefined &&
    latest !== null &&
    latest.revision_id === desired.revision_id &&
    latest.configuration_digest === desired.configuration_digest;
  const desiredMatchesApplied =
    desired !== null &&
    desired !== undefined &&
    applied !== null &&
    applied !== undefined &&
    applied.revision_id === desired.revision_id &&
    applied.applied_configuration_digest === desired.configuration_digest;

  if (desired === null || desired === undefined) {
    return Object.freeze({
      applied,
      code: "not-configured",
      detail: "승인된 리비전을 배포 대상으로 지정하지 않았습니다.",
      latest,
      poll: false,
      tone: "neutral",
    });
  }
  if (latest === null || !desiredMatchesLatest) {
    return Object.freeze({
      applied,
      code: "operation-missing",
      detail:
        "희망 상태와 연결된 배포 작업을 찾지 못했습니다. 자동 반영으로 간주하지 마세요.",
      latest,
      poll: false,
      tone: "failed",
    });
  }
  if (latest.state === "pending") {
    return Object.freeze({
      applied,
      code: "queued",
      detail:
        applied === null || applied === undefined
          ? "배포 작업이 대기열에 기록됐습니다. 아직 실행 시스템에 적용되지 않았습니다."
          : "새 희망 상태가 대기 중입니다. 현재 실행 시스템에는 직전 성공 상태가 유지됩니다.",
      latest,
      poll: true,
      tone: "pending",
    });
  }
  if (latest.state === "leased") {
    return Object.freeze({
      applied,
      code: "applying",
      detail: "조정기가 이 작업을 임대해 실행 시스템에 적용하고 있습니다.",
      latest,
      poll: true,
      tone: "pending",
    });
  }
  if (latest.state === "failed") {
    return Object.freeze({
      applied,
      code: "failed",
      detail:
        applied === null || applied === undefined
          ? "배포가 실패했습니다. 적용 완료 상태는 확인되지 않았습니다."
          : "새 배포가 실패했습니다. 직전 성공 상태와 실패 증적은 그대로 보존됩니다.",
      latest,
      poll: false,
      tone: "failed",
    });
  }
  if (latest.state === "applied" && desiredMatchesApplied) {
    return Object.freeze({
      applied,
      code: "applied",
      detail: "희망 상태와 실행 시스템의 확인된 적용 상태가 일치합니다.",
      latest,
      poll: false,
      tone: "verified",
    });
  }
  return Object.freeze({
    applied,
    code: "unverified",
    detail:
      "작업 기록만으로 현재 적용 상태를 증명할 수 없습니다. 조정기와 적용 영수증을 확인하세요.",
    latest,
    poll: false,
    tone: "failed",
  });
}

export function availableDeploymentActions({
  applied,
  desired,
  identity,
  operations,
  selected,
}) {
  if (
    !identity?.mfa ||
    !hasEffectiveRole(identity, "deployer") ||
    desired === null ||
    desired === undefined
  ) {
    return [];
  }
  const presentation = deploymentPresentation(desired, applied, operations);
  const actions = [];
  if (presentation.code === "failed" && presentation.latest !== null) {
    actions.push("retry-deployment");
  }
  const inFlight = ["pending", "leased"].includes(presentation.latest?.state);
  if (
    !inFlight &&
    selected?.state === "retired" &&
    selected.created_by !== identity.subject &&
    applied !== null &&
    applied !== undefined &&
    selected.revision_id !== applied.revision_id
  ) {
    actions.push("rollback-deployment");
  }
  return actions;
}

export function recentControlStorageKey(identity) {
  if (
    !identity ||
    !PORTABLE_ID.test(String(identity.tenant_id ?? "")) ||
    typeof identity.subject !== "string" ||
    identity.subject.length < 1 ||
    identity.subject.length > 255
  ) {
    throw new Error("최근 통제 목록을 분리할 사용자 경계가 없습니다.");
  }
  return (
    "control-assurance.recent-controls.v2:" +
    `${encodeURIComponent(identity.tenant_id)}:${encodeURIComponent(identity.subject)}`
  );
}

function integer(form, name) {
  const value = Number(form.get(name));
  if (!Number.isSafeInteger(value)) throw new Error(`${name} 값은 정수여야 합니다.`);
  return value;
}

function optional(form, name) {
  const value = String(form.get(name) ?? "").trim();
  return value || null;
}

function requireReference(value, schemes, label) {
  const match =
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 2048 &&
    !value.includes("\\") &&
    !/\s/.test(value)
      ? REFERENCE_SYNTAX.exec(value)
      : null;
  const scheme = match?.[1].toLowerCase();
  const authority = match?.[2] ?? "";
  const path = match?.[3] ?? "";
  if (
    !match ||
    !schemes.has(scheme) ||
    authority.includes("@") ||
    path === "/"
  ) {
    throw new Error(`${label}에는 비밀값이 아닌 승인된 저장소 참조를 입력해야 합니다.`);
  }
  return value;
}

export function configurationFromEntries(entries) {
  const form = entries instanceof FormData ? entries : new FormData(entries);
  const sourceKind = String(form.get("source_kind"));
  let source;
  if (sourceKind === "elastic-security") {
    const caBundle = optional(form, "elastic_ca_bundle_ref");
    source = {
      ca_bundle_ref:
        caBundle === null
          ? null
          : requireReference(
              caBundle,
              SECRET_REFERENCE_SCHEMES,
              "CA bundle ref",
            ),
      endpoint_origin: String(form.get("elastic_endpoint_origin") ?? "").trim(),
      index_alias: String(form.get("elastic_index_alias") ?? "").trim(),
      kind: "elastic-security",
      lease_ttl_seconds: integer(form, "elastic_lease_ttl_seconds"),
      pam_mode: "elastic-jit-api-key",
      parent_credential_ref: requireReference(
        String(form.get("elastic_parent_credential_ref") ?? "").trim(),
        SECRET_REFERENCE_SCHEMES,
        "JIT parent credential ref",
      ),
    };
  } else if (sourceKind === "defender-xdr") {
    source = {
      client_credential_ref: requireReference(
        String(form.get("defender_client_credential_ref") ?? "").trim(),
        SECRET_REFERENCE_SCHEMES,
        "Defender client credential ref",
      ),
      client_id: String(form.get("defender_client_id") ?? "").trim().toLowerCase(),
      cloud: String(form.get("defender_cloud") ?? ""),
      kind: "defender-xdr",
      permission: "ThreatHunting.Read.All",
      table: "AlertInfo",
      tenant_id: String(form.get("defender_tenant_id") ?? "").trim().toLowerCase(),
    };
  } else {
    throw new Error("지원하지 않는 탐지 원천입니다.");
  }

  const controlProfileDigest = String(form.get("control_profile_digest") ?? "").trim();
  if (!DIGEST.test(controlProfileDigest)) {
    throw new Error("Control profile digest는 sha256: 다음 64자리 소문자 16진수여야 합니다.");
  }
  return {
    control_id: normalizeControlId(form.get("control_id")),
    control_profile_digest: controlProfileDigest,
    control_profile_id: normalizeControlId(form.get("control_profile_id")),
    description: String(form.get("description") ?? "").trim(),
    display_name: String(form.get("display_name") ?? "").trim(),
    enabled: form.get("enabled") === "on",
    environment: String(form.get("environment") ?? ""),
    evidence: {
      custody_ref: requireReference(
        String(form.get("custody_ref") ?? "").trim(),
        CUSTODY_REFERENCE_SCHEMES,
        "Object Lock custody ref",
      ),
      legal_hold: form.get("legal_hold") === "on",
      retention_days: integer(form, "retention_days"),
      signing_key_ref: requireReference(
        String(form.get("signing_key_ref") ?? "").trim(),
        SIGNER_REFERENCE_SCHEMES,
        "Signing key ref",
      ),
      snapshot_format: "cab-stream-v2",
    },
    owner_group: String(form.get("owner_group") ?? "").trim(),
    schedule: {
      collection_lag_seconds: integer(form, "collection_lag_seconds"),
      interval_seconds: integer(form, "interval_seconds"),
      timezone: "UTC",
      window_seconds: integer(form, "window_seconds"),
    },
    schema_version: "1.0.0",
    source,
    tenant_id: normalizeControlId(form.get("tenant_id")),
  };
}

export function rememberControl(existing, controlId, limit = 12) {
  const normalized = normalizeControlId(controlId);
  return [normalized, ...existing.filter((item) => item !== normalized)].slice(0, limit);
}
