import {
  availableDeploymentActions,
  availableActions,
  captureOperationTarget,
  configurationFromEntries,
  deploymentPresentation,
  formatUiDate,
  formatUiDateTime,
  hasEffectiveRole,
  normalizeControlId,
  recentControlStorageKey,
  rememberControl,
  revisionComparisons,
  shortDigest,
  stateLabel,
} from "/control/assets/model.js";

const LEGACY_RECENT_KEY = "control-assurance.recent-controls.v1";
const state = {
  activeDeployment: null,
  activeRevision: null,
  appliedOperation: null,
  controlId: null,
  csrf: null,
  editing: false,
  expectedParent: null,
  identity: null,
  mutating: false,
  navigationEpoch: 0,
  operationTarget: null,
  deploymentOperations: [],
  deploymentPollCount: 0,
  deploymentPollTimer: null,
  revisions: [],
  selected: null,
  serverControls: [],
};

const element = (id) => document.getElementById(id);
const form = element("configuration-form");

function setText(id, value) {
  element(id).textContent = value;
}

function showNotice(message, error = false) {
  const notice = element("notice");
  notice.classList.toggle("error", error);
  notice.setAttribute("role", error ? "alert" : "status");
  notice.textContent = message;
  notice.hidden = false;
  if (error) notice.focus();
}

function clearNotice() {
  const notice = element("notice");
  notice.hidden = true;
  notice.textContent = "";
  notice.setAttribute("role", "status");
}

function clearDeploymentPoll() {
  if (state.deploymentPollTimer !== null) {
    window.clearTimeout(state.deploymentPollTimer);
    state.deploymentPollTimer = null;
  }
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers ?? {});
  if (options.body !== undefined) {
    headers.set("content-type", "application/json");
    headers.set("x-csrf-token", state.csrf ?? "");
  }
  const response = await fetch(path, {
    ...options,
    credentials: "same-origin",
    headers,
  });
  let body = null;
  const mediaType = response.headers.get("content-type")?.split(";", 1)[0];
  if (mediaType === "application/json") {
    body = await response.json();
  }
  if (!response.ok) {
    const failure = new Error(
      body?.error?.message ?? `The request could not be completed (HTTP ${response.status}).`,
    );
    failure.status = response.status;
    failure.code = body?.error?.code ?? "unknown";
    throw failure;
  }
  return body;
}

async function optionalApi(path) {
  try {
    return await api(path);
  } catch (error) {
    if (error.status === 404) return null;
    throw error;
  }
}

function recentControls() {
  if (!state.identity) return [];
  try {
    const parsed = JSON.parse(
      localStorage.getItem(recentControlStorageKey(state.identity)) ?? "[]",
    );
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter((value) => typeof value === "string")
      .map((value) => {
        try {
          return normalizeControlId(value);
        } catch {
          return null;
        }
      })
      .filter((value) => value !== null)
      .slice(0, 12);
  } catch {
    return [];
  }
}

function storeRecent(controlId) {
  if (!state.identity) return;
  try {
    localStorage.setItem(
      recentControlStorageKey(state.identity),
      JSON.stringify(rememberControl(recentControls(), controlId)),
    );
  } catch {
    // Recent controls are a convenience only; server state remains authoritative.
  }
  renderRecentControls();
}

function renderRecentControls() {
  const list = element("recent-controls");
  list.replaceChildren();
  const serverIds = state.serverControls.map(
    (summary) => summary.latest_revision.control_id,
  );
  const controls = [
    ...serverIds,
    ...recentControls().filter((controlId) => !serverIds.includes(controlId)),
  ];
  element("recent-empty").hidden = controls.length > 0;
  for (const controlId of controls) {
    const item = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    const summary = state.serverControls.find(
      (item) => item.latest_revision.control_id === controlId,
    );
    button.textContent = summary
      ? `${controlId} · ${stateLabel(summary.latest_revision.state)}`
      : controlId;
    button.disabled = state.mutating;
    button.addEventListener("click", () => void loadControl(controlId));
    item.append(button);
    list.append(item);
  }
}

async function loadControlIndex() {
  const response = await api("/api/v1/controls?limit=1000");
  state.serverControls = response.items;
  renderRecentControls();
}

function can(role) {
  return hasEffectiveRole(state.identity, role);
}

function setOperationBusy(busy, target = null) {
  state.mutating = busy;
  state.operationTarget = busy ? target : null;
  element("workspace").setAttribute("aria-busy", String(busy));
  element("new-control").disabled = busy || !can("editor");
  for (const control of element("control-search").elements) {
    control.disabled = busy || !state.identity;
  }
  element("refresh-audit").disabled = busy || !can("auditor");
  element("refresh-deployment").disabled =
    busy || state.controlId === null || !can("viewer");
  element("review-comment").disabled = busy;
  setEditing(state.editing);
  renderRecentControls();
  renderRevisions();
  renderWorkflow();
  renderDeployment();
  if (!busy && state.controlId !== null) {
    scheduleDeploymentPoll(state.controlId, state.navigationEpoch);
  }
}

function renderRevisions() {
  const list = element("revision-list");
  list.replaceChildren();
  setText("revision-count", String(state.revisions.length));
  element("revision-empty").hidden = state.revisions.length > 0;
  for (const revision of state.revisions) {
    const item = document.createElement("li");
    const button = document.createElement("button");
    const top = document.createElement("span");
    const bottom = document.createElement("span");
    const generation = document.createElement("strong");
    const status = document.createElement("span");
    const digest = document.createElement("span");
    const time = document.createElement("span");

    button.type = "button";
    button.disabled = state.mutating;
    button.setAttribute(
      "aria-current",
      String(state.selected?.revision_id === revision.revision_id),
    );
    top.className = "revision-top";
    bottom.className = "revision-bottom";
    generation.textContent = `GEN ${String(revision.generation).padStart(2, "0")}`;
    status.textContent = stateLabel(revision.state);
    digest.textContent = shortDigest(revision.revision_id, 8);
    time.textContent = formatUiDate(revision.created_at);
    top.append(generation, status);
    bottom.append(digest, time);
    button.append(top, bottom);
    button.addEventListener("click", () => selectRevision(revision));
    item.append(button);
    list.append(item);
  }
}

function input(name) {
  return form.elements.namedItem(name);
}

function setValue(name, value) {
  const control = input(name);
  if (!control) return;
  if (control instanceof RadioNodeList) {
    control.value = String(value ?? "");
  } else if (control.type === "checkbox") {
    control.checked = Boolean(value);
  } else {
    control.value = value ?? "";
  }
}

function fillConfiguration(configuration) {
  setValue("tenant_id", configuration.tenant_id);
  setValue("control_id", configuration.control_id);
  setValue("display_name", configuration.display_name);
  setValue("description", configuration.description);
  setValue("environment", configuration.environment);
  setValue("owner_group", configuration.owner_group);
  setValue("control_profile_id", configuration.control_profile_id);
  setValue("control_profile_digest", configuration.control_profile_digest);
  setValue("interval_seconds", configuration.schedule.interval_seconds);
  setValue("window_seconds", configuration.schedule.window_seconds);
  setValue("collection_lag_seconds", configuration.schedule.collection_lag_seconds);
  setValue("retention_days", configuration.evidence.retention_days);
  setValue("signing_key_ref", configuration.evidence.signing_key_ref);
  setValue("custody_ref", configuration.evidence.custody_ref);
  setValue("legal_hold", configuration.evidence.legal_hold);
  setValue("enabled", configuration.enabled);
  setValue("source_kind", configuration.source.kind);
  if (configuration.source.kind === "elastic-security") {
    setValue("elastic_endpoint_origin", configuration.source.endpoint_origin);
    setValue("elastic_index_alias", configuration.source.index_alias);
    setValue(
      "elastic_parent_credential_ref",
      configuration.source.parent_credential_ref,
    );
    setValue("elastic_lease_ttl_seconds", configuration.source.lease_ttl_seconds);
    setValue("elastic_ca_bundle_ref", configuration.source.ca_bundle_ref);
  } else {
    setValue("defender_tenant_id", configuration.source.tenant_id);
    setValue("defender_client_id", configuration.source.client_id);
    setValue("defender_cloud", configuration.source.cloud);
    setValue(
      "defender_client_credential_ref",
      configuration.source.client_credential_ref,
    );
  }
  toggleSource(configuration.source.kind);
}

function toggleSource(kind) {
  const elastic = kind === "elastic-security";
  element("elastic-fields").hidden = !elastic;
  element("defender-fields").hidden = elastic;
  for (const name of [
    "elastic_endpoint_origin",
    "elastic_index_alias",
    "elastic_parent_credential_ref",
    "elastic_lease_ttl_seconds",
  ]) {
    input(name).required = elastic;
  }
  for (const name of [
    "defender_tenant_id",
    "defender_client_id",
    "defender_client_credential_ref",
  ]) {
    input(name).required = !elastic;
  }
}

function setEditing(editing) {
  state.editing = Boolean(editing && can("editor"));
  for (const control of form.elements) {
    if (!(control instanceof HTMLButtonElement)) {
      control.disabled = state.mutating || !state.editing;
    }
  }
  input("tenant_id").disabled = state.mutating;
  input("tenant_id").readOnly = true;
  element("save-draft").disabled = state.mutating || !state.editing;
  element("save-draft").hidden = !state.editing;
}

function newControl(initialControlId = null) {
  if (state.mutating || !can("editor")) return;
  clearDeploymentPoll();
  clearNotice();
  form.reset();
  form.hidden = false;
  state.controlId = null;
  state.expectedParent = null;
  state.selected = null;
  state.activeDeployment = null;
  state.activeRevision = null;
  state.appliedOperation = null;
  state.deploymentOperations = [];
  state.deploymentPollCount = 0;
  state.revisions = [];
  setValue("tenant_id", state.identity.tenant_id);
  if (initialControlId !== null) setValue("control_id", initialControlId);
  element("review-comment").value = "";
  toggleSource("elastic-security");
  setEditing(true);
  setText("desk-kicker", "NEW CONFIGURATION");
  setText("desk-title", "New control definition");
  setText(
    "desk-subtitle",
    "Credentials are never stored here. Only approved secret-store references are recorded.",
  );
  renderState("draft");
  renderRevisions();
  renderSelection();
  renderDeployment();
  renderWorkflow();
  input("control_id").focus();
}

function reviseSelected() {
  if (state.mutating || !state.selected || !can("editor")) return;
  state.expectedParent = state.selected.revision_id;
  fillConfiguration(state.selected.configuration);
  element("review-comment").value = "";
  setEditing(true);
  setText("desk-kicker", `NEXT GENERATION · ${state.selected.control_id}`);
  setText("desk-title", "New generation draft");
  setText(
    "desk-subtitle",
    "Create a new immutable revision from the selected generation. Existing records remain unchanged.",
  );
  renderState("draft");
  renderWorkflow();
  input("display_name").focus();
}

function renderState(revisionState) {
  const stamp = element("revision-state");
  stamp.textContent = stateLabel(revisionState);
  stamp.className = `state-stamp ${revisionState}`;
}

function selectRevision(revision, { duringMutation = false } = {}) {
  if (state.mutating && !duringMutation) return;
  const previousSelection = state.selected?.revision_id;
  state.selected = revision;
  state.expectedParent = null;
  form.hidden = false;
  if (previousSelection !== revision.revision_id) {
    element("review-comment").value = "";
  }
  fillConfiguration(revision.configuration);
  setEditing(false);
  setText("desk-kicker", `${revision.control_id} · GENERATION ${revision.generation}`);
  setText("desk-title", revision.configuration.display_name);
  setText("desk-subtitle", revision.configuration.description);
  renderState(revision.state);
  renderRevisions();
  renderSelection();
  renderDeployment();
  renderWorkflow();
}

function valueText(value) {
  if (value === undefined) return "(missing)";
  if (value === null) return "null";
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

function renderDifferenceList({
  countId,
  differences,
  emptyId,
  emptyText,
  listId,
}) {
  const differenceList = element(listId);
  differenceList.replaceChildren();
  setText(countId, String(differences.length));
  const empty = element(emptyId);
  empty.textContent = emptyText;
  empty.hidden = differences.length > 0;
  for (const difference of differences.slice(0, 100)) {
    const item = document.createElement("li");
    const path = document.createElement("code");
    const valuesNode = document.createElement("div");
    const before = document.createElement("span");
    const arrow = document.createElement("span");
    const after = document.createElement("span");
    path.textContent = difference.path;
    valuesNode.className = "difference-values";
    before.textContent = valueText(difference.before);
    arrow.textContent = "→";
    arrow.setAttribute("aria-hidden", "true");
    after.textContent = valueText(difference.after);
    valuesNode.append(before, arrow, after);
    item.append(path, valuesNode);
    differenceList.append(item);
  }
}

function renderSelection() {
  const facts = element("selection-facts");
  const activePointer = state.activeDeployment
    ? `${shortDigest(state.activeDeployment.revision_id, 8)} · desired state v${state.activeDeployment.deployment_version}`
    : "None";
  const values = state.selected
    ? [
        shortDigest(state.selected.revision_id),
        shortDigest(state.selected.configuration_digest),
        state.selected.created_by,
        String(state.selected.generation),
        activePointer,
      ]
    : ["Not selected", "—", "—", "—", activePointer];
  [...facts.querySelectorAll("dd")].forEach((node, index) => {
    node.textContent = values[index];
  });

  const comparisons = revisionComparisons(
    state.selected,
    state.revisions,
    state.activeRevision,
  );
  const activeEmptyText = {
    "no-active-pointer":
      "No active pointer exists. Selecting this revision would not prove runtime application.",
    "no-selection": "Select a revision to compare it with the current desired state.",
    "selected-is-active": "The selected revision is the current active pointer.",
  }[comparisons.activeStatus] ?? "No configuration differences from the active pointer.";
  renderDifferenceList({
    countId: "difference-count",
    differences: comparisons.active,
    emptyId: "difference-empty",
    emptyText: activeEmptyText,
    listId: "difference-list",
  });
  renderDifferenceList({
    countId: "lineage-difference-count",
    differences: comparisons.lineage,
    emptyId: "lineage-difference-empty",
    emptyText:
      comparisons.lineageStatus === "no-parent"
        ? "No previous generation exists."
        : "No configuration differences from the previous generation.",
    listId: "lineage-difference-list",
  });
}

function deploymentStateLabel(code) {
  return {
    applied: "Applied state verified",
    applying: "Applying",
    failed: "Deployment failed",
    "not-configured": "No target",
    "operation-missing": "Operation missing",
    queued: "Queued",
    unverified: "Verification required",
  }[code] ?? "Verification required";
}

function operationSummary(operation) {
  if (!operation) return "None";
  const kind =
    operation.retry_of_operation_id !== null &&
    operation.retry_of_operation_id !== undefined
      ? "RETRY"
      : operation.kind === "rollback"
        ? "ROLLBACK"
        : "APPLY";
  return `#${operation.operation_sequence} · ${kind} · ${String(operation.state).toUpperCase()}`;
}

function renderDeployment() {
  const presentation = deploymentPresentation(
    state.activeDeployment,
    state.appliedOperation,
    state.deploymentOperations,
  );
  const status = element("deployment-status");
  const light = element("deployment-light");
  status.className = `deployment-status ${presentation.tone}`;
  light.className =
    presentation.tone === "verified"
      ? "status-light"
      : presentation.tone === "failed"
        ? "status-light failed"
        : "status-light pending";
  setText("deployment-label", deploymentStateLabel(presentation.code));
  setText("deployment-detail", presentation.detail);

  const desired = state.activeDeployment
    ? `${shortDigest(state.activeDeployment.revision_id, 8)} · v${state.activeDeployment.deployment_version}`
    : "None";
  const applied = state.appliedOperation
    ? `${shortDigest(state.appliedOperation.revision_id, 8)} · #${state.appliedOperation.operation_sequence}`
    : "None";
  const receipt = state.appliedOperation?.target_receipt_digest
    ? shortDigest(state.appliedOperation.target_receipt_digest, 8)
    : "None";
  const values = [
    desired,
    applied,
    operationSummary(presentation.latest),
    receipt,
  ];
  [...element("deployment-facts").querySelectorAll("dd")].forEach(
    (node, index) => {
      node.textContent = values[index];
    },
  );

  const list = element("deployment-operation-list");
  list.replaceChildren();
  element("deployment-operation-empty").hidden =
    state.deploymentOperations.length > 0;
  for (const operation of state.deploymentOperations.slice(0, 8)) {
    const item = document.createElement("li");
    const title = document.createElement("strong");
    const details = document.createElement("span");
    const digest = document.createElement("span");
    title.textContent = operationSummary(operation);
    details.textContent =
      `${formatUiDateTime(operation.requested_at)} · ` +
      `${shortDigest(operation.operation_id, 8)}`;
    const lineage =
      operation.retry_of_operation_id !== null &&
      operation.retry_of_operation_id !== undefined
        ? ` · retry of ${shortDigest(operation.retry_of_operation_id, 8)}`
        : "";
    digest.textContent =
      (operation.state === "failed"
        ? `failure ${shortDigest(operation.failure_digest, 8)}`
        : operation.target_receipt_digest
          ? `receipt ${shortDigest(operation.target_receipt_digest, 8)}`
          : `configuration ${shortDigest(operation.configuration_digest, 8)}`) +
      lineage;
    item.append(title, details, digest);
    list.append(item);
  }

  const actions = element("deployment-actions");
  actions.replaceChildren();
  const deploymentActions = state.mutating
    ? []
    : availableDeploymentActions({
        applied: state.appliedOperation,
        desired: state.activeDeployment,
        identity: state.identity,
        operations: state.deploymentOperations,
        selected: state.selected,
      });
  if (deploymentActions.includes("retry-deployment")) {
    const retry = document.createElement("button");
    retry.type = "button";
    retry.textContent = "Retry failed operation";
    retry.addEventListener("click", () => void runDeploymentAction("retry"));
    actions.append(retry);
  }
  if (deploymentActions.includes("rollback-deployment")) {
    const rollback = document.createElement("button");
    rollback.type = "button";
    rollback.className = "danger";
    rollback.textContent = "Roll back to selected revision";
    rollback.addEventListener("click", () => void runDeploymentAction("rollback"));
    actions.append(rollback);
  }
  actions.hidden = actions.childElementCount === 0;
  element("refresh-deployment").disabled =
    state.mutating || state.controlId === null || !can("viewer");
}

function actionButton(label, action, className = "") {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  button.className = className;
  button.disabled = state.mutating;
  button.addEventListener("click", () => void runWorkflow(action));
  return button;
}

function renderWorkflow() {
  const container = element("workflow-actions");
  container.replaceChildren();
  const actions = availableActions(state.selected, state.identity);
  const canRevise =
    state.selected &&
    ["approved", "rejected", "retired"].includes(state.selected.state) &&
    can("editor") &&
    (can("administrator") ||
      state.identity.groups.includes(state.selected.configuration.owner_group));
  if (canRevise) actions.push("revise");
  const labels = {
    activate: ["Set as active pointer", "primary"],
    approve: ["Approve", "primary"],
    reject: ["Reject", "danger"],
    revise: ["Create next generation", ""],
    submit: ["Submit for review", "primary"],
  };
  for (const action of actions) {
    container.append(actionButton(labels[action][0], action, labels[action][1]));
  }
  if (actions.length === 0) {
    const note = document.createElement("p");
    note.className = "empty-note";
    note.textContent = "No actions are available for your role in the current state.";
    container.append(note);
  }
  element("review-comment-wrap").hidden = !(
    actions.includes("approve") || actions.includes("reject")
  );
  element("review-comment").disabled =
    state.mutating ||
    !(actions.includes("approve") || actions.includes("reject"));
}

async function runWorkflow(action) {
  if (state.mutating || !state.selected) return;
  clearNotice();
  if (action === "revise") {
    reviseSelected();
    return;
  }
  let target;
  try {
    target = captureOperationTarget(state.selected, state.activeDeployment);
  } catch (error) {
    showNotice(error.message, true);
    return;
  }
  const base = `/api/v1/revisions/${encodeURIComponent(target.revisionId)}`;
  let path;
  let body;
  if (action === "submit") {
    path = `${base}/submit`;
    body = { expected_state_version: target.stateVersion };
  } else if (action === "approve" || action === "reject") {
    const comment = element("review-comment").value.trim();
    if (!comment) {
      showNotice("A decision rationale is required to approve or reject.", true);
      element("review-comment").focus();
      return;
    }
    path = `${base}/decision`;
    body = {
      comment,
      decision: action === "approve" ? "approved" : "rejected",
      expected_state_version: target.stateVersion,
    };
  } else if (action === "activate") {
    path = `${base}/activate`;
    body = {
      expected_deployment_version: target.activePointerVersion,
    };
  } else {
    return;
  }
  setOperationBusy(true, target);
  showNotice(
    `Recording a change to revision ${shortDigest(target.revisionId, 8)} of ${target.controlId}.`,
  );
  let mutationRecorded = false;
  try {
    await api(path, { body: JSON.stringify(body), method: "POST" });
    mutationRecorded = true;
    await loadControl(target.controlId, target.revisionId, {
      clear: false,
      duringMutation: true,
      propagate: true,
    });
    await loadControlIndex();
    if (can("auditor")) await loadAudit({ propagate: true });
    element("review-comment").value = "";
    showNotice(
      action === "activate"
        ? "The active pointer was recorded. This does not prove runtime application."
        : "The change was recorded and the latest server state was loaded.",
    );
  } catch (error) {
    const message =
      mutationRecorded
        ? `The change was recorded, but the latest state could not be loaded: ${error.message}`
        : error.code === "state-conflict"
          ? "Another user changed the state first. Reload the latest revision."
          : error.message;
    showNotice(
      message,
      true,
    );
  } finally {
    setOperationBusy(false);
  }
}

async function runDeploymentAction(action) {
  if (state.mutating || state.controlId === null) return;
  clearNotice();
  const latest = deploymentPresentation(
    state.activeDeployment,
    state.appliedOperation,
    state.deploymentOperations,
  ).latest;
  let target;
  let path;
  let body;
  if (
    action === "retry" &&
    latest?.state === "failed" &&
    can("deployer") &&
    state.identity?.mfa
  ) {
    target = Object.freeze({
      controlId: state.controlId,
      operationId: latest.operation_id,
      revisionId: latest.revision_id,
    });
    path = `/api/v1/deployment-operations/${encodeURIComponent(target.operationId)}/retry`;
    body = {};
  } else if (
    action === "rollback" &&
    state.selected?.state === "retired" &&
    state.appliedOperation !== null &&
    state.selected.created_by !== state.identity?.subject &&
    can("deployer") &&
    state.identity?.mfa
  ) {
    const revisionTarget = captureOperationTarget(
      state.selected,
      state.activeDeployment,
    );
    target = Object.freeze({
      controlId: revisionTarget.controlId,
      operationId: state.appliedOperation.operation_id,
      revisionId: revisionTarget.revisionId,
    });
    path = `/api/v1/revisions/${encodeURIComponent(target.revisionId)}/rollback`;
    body = { expected_predecessor_operation_id: target.operationId };
  } else {
    showNotice("This deployment action is not valid for the latest state.", true);
    return;
  }

  setOperationBusy(true, target);
  showNotice(
    action === "retry"
      ? `Recording a new retry for failed operation ${shortDigest(target.operationId, 8)}.`
      : `Recording an intent to roll back to revision ${shortDigest(target.revisionId, 8)}.`,
  );
  let mutationRecorded = false;
  try {
    await api(path, { body: JSON.stringify(body), method: "POST" });
    mutationRecorded = true;
    await loadControl(target.controlId, target.revisionId, {
      clear: false,
      duringMutation: true,
      propagate: true,
    });
    if (can("auditor")) await loadAudit({ propagate: true });
    showNotice(
      action === "retry"
        ? "A new deployment operation was queued. The previous failure record remains intact."
        : "The rollback was queued. It will not be marked complete until a deployment receipt is recorded.",
    );
  } catch (error) {
    showNotice(
      mutationRecorded
        ? `The deployment intent was recorded, but the latest state could not be loaded: ${error.message}`
        : error.code === "state-conflict"
          ? "Another operation changed the deployment state first. Reload the latest state."
          : error.message,
      true,
    );
  } finally {
    setOperationBusy(false);
  }
}

async function fetchDeploymentSnapshot(controlId) {
  const encoded = encodeURIComponent(controlId);
  const [desired, operations, applied] = await Promise.all([
    optionalApi(`/api/v1/controls/${encoded}/desired`),
    api(`/api/v1/controls/${encoded}/deployment-operations?limit=100`),
    optionalApi(`/api/v1/controls/${encoded}/applied`),
  ]);
  return {
    applied,
    desired,
    operations: operations.items,
  };
}

async function applyDeploymentSnapshot(snapshot, navigationEpoch) {
  if (navigationEpoch !== state.navigationEpoch) return false;
  let activeRevision = null;
  if (snapshot.desired !== null) {
    activeRevision =
      state.revisions.find(
        (revision) => revision.revision_id === snapshot.desired.revision_id,
      ) ?? null;
    if (activeRevision === null) {
      activeRevision = await api(
        `/api/v1/revisions/${encodeURIComponent(snapshot.desired.revision_id)}`,
      );
    }
  }
  if (navigationEpoch !== state.navigationEpoch) return false;
  state.activeDeployment = snapshot.desired;
  state.activeRevision = activeRevision;
  state.appliedOperation = snapshot.applied;
  state.deploymentOperations = snapshot.operations;
  renderSelection();
  renderDeployment();
  renderWorkflow();
  return true;
}

function scheduleDeploymentPoll(controlId, navigationEpoch) {
  clearDeploymentPoll();
  const presentation = deploymentPresentation(
    state.activeDeployment,
    state.appliedOperation,
    state.deploymentOperations,
  );
  if (
    !presentation.poll ||
    state.deploymentPollCount >= 40 ||
    state.mutating ||
    controlId !== state.controlId ||
    navigationEpoch !== state.navigationEpoch
  ) {
    return;
  }
  state.deploymentPollTimer = window.setTimeout(() => {
    state.deploymentPollTimer = null;
    void refreshDeploymentState({
      controlId,
      navigationEpoch,
      polling: true,
    });
  }, 3_000);
}

async function refreshDeploymentState({
  controlId = state.controlId,
  navigationEpoch = state.navigationEpoch,
  polling = false,
} = {}) {
  if (
    controlId === null ||
    controlId !== state.controlId ||
    navigationEpoch !== state.navigationEpoch ||
    state.mutating
  ) {
    return;
  }
  if (!polling) {
    clearDeploymentPoll();
    state.deploymentPollCount = 0;
  } else {
    state.deploymentPollCount += 1;
  }
  try {
    const snapshot = await fetchDeploymentSnapshot(controlId);
    if (!(await applyDeploymentSnapshot(snapshot, navigationEpoch))) return;
    scheduleDeploymentPoll(controlId, navigationEpoch);
  } catch (error) {
    if (
      controlId === state.controlId &&
      navigationEpoch === state.navigationEpoch
    ) {
      showNotice(`The deployment state could not be refreshed: ${error.message}`, true);
    }
  }
}

async function loadControl(
  controlId,
  preferredRevision = null,
  { clear = true, duringMutation = false, propagate = false } = {},
) {
  if (state.mutating && !duringMutation) return;
  if (clear) clearNotice();
  let normalized;
  try {
    normalized = normalizeControlId(controlId);
  } catch (error) {
    showNotice(error.message, true);
    return;
  }
  clearDeploymentPoll();
  state.deploymentPollCount = 0;
  const navigationEpoch = ++state.navigationEpoch;
  try {
    const [result, deploymentSnapshot] = await Promise.all([
      api(
        `/api/v1/controls/${encodeURIComponent(normalized)}/revisions?limit=100`,
      ),
      fetchDeploymentSnapshot(normalized),
    ]);
    if (navigationEpoch !== state.navigationEpoch) return;
    state.controlId = normalized;
    state.revisions = result.items;
    state.selected = null;
    if (!(await applyDeploymentSnapshot(deploymentSnapshot, navigationEpoch))) {
      return;
    }
    storeRecent(normalized);
    element("control-id-search").value = normalized;
    renderRevisions();
    if (state.revisions.length === 0) {
      state.selected = null;
      state.expectedParent = null;
      renderSelection();
      renderWorkflow();
      if (can("editor") && !state.mutating) {
        newControl(normalized);
      } else {
        form.hidden = true;
        showNotice("This control has no revisions to display.");
      }
      scheduleDeploymentPoll(normalized, navigationEpoch);
      return;
    }
    const selected =
      state.revisions.find((revision) => revision.revision_id === preferredRevision) ??
      state.revisions[0];
    selectRevision(selected, { duringMutation });
    scheduleDeploymentPoll(normalized, navigationEpoch);
  } catch (error) {
    if (navigationEpoch !== state.navigationEpoch) return;
    if (propagate) throw error;
    showNotice(error.message, true);
  }
}

async function loadAudit({ propagate = false } = {}) {
  if (!can("auditor")) return;
  const verificationNode = element("audit-verification");
  verificationNode.className = "audit-verification pending";
  verificationNode.textContent = "Verifying audit chain";
  try {
    const [response, verification] = await Promise.all([
      api("/api/v1/audit?limit=200"),
      api("/api/v1/audit/verification"),
    ]);
    const list = element("audit-list");
    list.replaceChildren();
    for (const event of [...response.items].reverse()) {
      const item = document.createElement("li");
      const title = document.createElement("strong");
      const time = document.createElement("time");
      const digest = document.createElement("span");
      title.textContent = event.action;
      time.dateTime = event.occurred_at;
      time.textContent = formatUiDateTime(event.occurred_at);
      digest.textContent = `#${event.sequence} · ${shortDigest(event.event_digest, 8)}`;
      item.append(title, time, digest);
      list.append(item);
    }
    verificationNode.className = "audit-verification";
    verificationNode.textContent =
      `Verified · ${verification.event_count} events · head ` +
      shortDigest(verification.head_event_digest, 8);
  } catch (error) {
    verificationNode.className = "audit-verification failed";
    verificationNode.textContent = "Verification failed · do not trust the event list";
    if (propagate) throw error;
    showNotice(`The audit chain could not be loaded: ${error.message}`, true);
  }
}

async function saveDraft(event) {
  event.preventDefault();
  if (state.mutating || !can("editor")) return;
  clearNotice();
  if (!form.reportValidity()) return;
  let configuration;
  try {
    configuration = configurationFromEntries(new FormData(form));
  } catch (error) {
    showNotice(error.message, true);
    return;
  }
  const target = Object.freeze({
    controlId: configuration.control_id,
    expectedParent: state.expectedParent,
    kind: "create-revision",
  });
  setOperationBusy(true, target);
  showNotice(`Recording an immutable draft for ${target.controlId}.`);
  let mutationRecorded = false;
  try {
    const created = await api("/api/v1/revisions", {
      body: JSON.stringify({
        configuration,
        expected_parent_revision_id: target.expectedParent,
      }),
      method: "POST",
    });
    mutationRecorded = true;
    await loadControl(target.controlId, created.revision_id, {
      clear: false,
      duringMutation: true,
      propagate: true,
    });
    await loadControlIndex();
    showNotice("The immutable draft was recorded and reloaded from the server.");
  } catch (error) {
    showNotice(
      mutationRecorded
        ? `The draft was recorded, but the latest state could not be loaded: ${error.message}`
        : error.message,
      true,
    );
  } finally {
    setOperationBusy(false);
  }
}

async function initialize() {
  clearDeploymentPoll();
  state.identity = null;
  state.csrf = null;
  state.serverControls = [];
  state.revisions = [];
  state.selected = null;
  state.activeDeployment = null;
  state.activeRevision = null;
  state.appliedOperation = null;
  state.deploymentOperations = [];
  state.deploymentPollCount = 0;
  state.navigationEpoch += 1;
  form.hidden = true;
  element("new-control").hidden = true;
  element("auth-required").hidden = true;
  element("service-unavailable").hidden = true;
  element("access-denied").hidden = true;
  element("audit-section").hidden = true;
  element("refresh-deployment").disabled = true;
  element("audit-verification").className = "audit-verification pending";
  element("audit-verification").textContent = "Awaiting chain verification";
  clearNotice();
  setOperationBusy(false);
  renderDeployment();
  const pendingSummary = element("session-summary");
  pendingSummary.replaceChildren();
  const pendingLight = document.createElement("span");
  const pendingLabel = document.createElement("span");
  pendingLight.className = "status-light pending";
  pendingLight.setAttribute("aria-hidden", "true");
  pendingLabel.textContent = "Checking SSO session";
  pendingSummary.append(pendingLight, pendingLabel);
  setText(
    "connection-state",
    "Checking API · the active pointer is desired state, not proof of runtime application",
  );
  try {
    const session = await api("/api/v1/session");
    state.identity = session.identity;
    state.csrf = session.csrf_token;
    try {
      localStorage.removeItem(LEGACY_RECENT_KEY);
    } catch {
      // Failure to remove a convenience-only legacy key cannot affect authority.
    }
    element("session-summary").replaceChildren();
    const light = document.createElement("span");
    const label = document.createElement("span");
    light.className = "status-light";
    light.setAttribute("aria-hidden", "true");
    const roleSummary = state.identity.roles
      .map((role) => role.toUpperCase())
      .sort()
      .join("/");
    label.textContent =
      `${state.identity.display_name} · ${state.identity.tenant_id} · ` +
      `${roleSummary}${state.identity.mfa ? " · MFA" : ""}`;
    element("session-summary").append(light, label);
    setText(
      "connection-state",
      "API connected · SSO verified · the active pointer represents desired state",
    );
    if (!can("viewer")) {
      element("access-denied").hidden = false;
      light.className = "status-light failed";
      setText("connection-state", "SSO authenticated · no permission to view controls");
      return;
    }
    element("new-control").hidden = !can("editor");
    for (const control of element("control-search").elements) {
      control.disabled = false;
    }
    element("audit-section").hidden = !can("auditor");
    element("refresh-audit").disabled = !can("auditor");
    setValue("tenant_id", state.identity.tenant_id);
    await loadControlIndex();
    if (!can("editor")) {
      setEditing(false);
    } else {
      newControl();
    }
    const firstControl =
      state.serverControls[0]?.latest_revision.control_id ?? recentControls()[0];
    if (firstControl) await loadControl(firstControl);
    if (can("auditor")) await loadAudit();
  } catch (error) {
    form.hidden = true;
    element("new-control").hidden = true;
    for (const control of element("control-search").elements) {
      control.disabled = true;
    }
    const summary = element("session-summary");
    summary.replaceChildren();
    const light = document.createElement("span");
    const label = document.createElement("span");
    light.className = "status-light failed";
    light.setAttribute("aria-hidden", "true");
    const authenticationFailure =
      error.status === 401 || error.code === "authentication-required";
    const authorizationFailure =
      error.status === 403 || error.code === "access-denied";
    if (authenticationFailure) {
      element("auth-required").hidden = false;
      label.textContent = "SSO authentication required";
      setText("connection-state", "Authentication required");
    } else if (authorizationFailure) {
      element("access-denied").hidden = false;
      label.textContent = "Access denied";
      setText("connection-state", "SSO authenticated · no permission to view controls");
    } else {
      element("service-unavailable").hidden = false;
      label.textContent = "Control API unavailable";
      setText("connection-state", "Service unavailable · not classified as an SSO failure");
    }
    summary.append(light, label);
  }
}

for (const source of document.querySelectorAll('input[name="source_kind"]')) {
  source.addEventListener("change", () => toggleSource(source.value));
}
form.addEventListener("submit", (event) => void saveDraft(event));
element("new-control").addEventListener("click", () => newControl());
element("control-search").addEventListener("submit", (event) => {
  event.preventDefault();
  if (state.mutating) return;
  void loadControl(new FormData(event.currentTarget).get("control_id"));
});
element("refresh-audit").addEventListener("click", () => void loadAudit());
element("refresh-deployment").addEventListener("click", () =>
  void refreshDeploymentState(),
);
element("retry-initialize").addEventListener("click", () => void initialize());

void initialize();
