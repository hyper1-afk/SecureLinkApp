const token = sessionStorage.getItem("securelink.accessToken");
let organizationId = sessionStorage.getItem("securelink.organizationId");
const byId = (id) => document.getElementById(id);
let apiBase = organizationId ? `/organizations/${encodeURIComponent(organizationId)}` : "";
const caseTransitions = {
  open: ["investigating", "resolved", "false_positive"],
  investigating: ["open", "awaiting_approval", "resolved", "false_positive"],
  awaiting_approval: ["open", "investigating", "resolved", "false_positive"],
  resolved: ["investigating"],
  false_positive: ["investigating"],
};
let canScan = false;
let canManageAssets = false;
let canTransferOwnership = false;
let caseScanIds = new Set();
let caseSignalIds = new Set();
let casesCache = [];

function setStatus(id, message) {
  byId(id).textContent = message;
}

function clearSession() {
  sessionStorage.removeItem("securelink.accessToken");
  sessionStorage.removeItem("securelink.organizationId");
  window.location.replace("/");
}

async function request(path, options = {}) {
  return fetch(path, {
    ...options,
    headers: {
      ...(options.headers || {}),
      Authorization: `Bearer ${token}`,
    },
    credentials: "omit",
    cache: "no-store",
    referrerPolicy: "no-referrer",
  });
}

function makeButton(label, handler, className = "button-secondary", statusId = "case-status") {
  const button = document.createElement("button");
  button.type = "button";
  button.className = className;
  button.textContent = label;
  button.addEventListener("click", () => {
    Promise.resolve().then(handler).catch(() => setStatus(statusId, "SecureLink could not be reached."));
  });
  return button;
}

function renderScans(scans) {
  const list = byId("scan-history");
  list.replaceChildren();
  if (!scans.length) {
    setStatus("history-status", "No link checks yet.");
    return;
  }
  setStatus("history-status", `${scans.length} recent check(s).`);
  for (const scan of scans) {
    const item = document.createElement("li");
    item.className = "data-card";
    const heading = document.createElement("h3");
    heading.textContent = scan.display_url;
    const meta = document.createElement("p");
    meta.className = "muted";
    meta.textContent = `Checked ${new Date(scan.created_at).toLocaleString()} · ${scan.status}`;
    item.append(heading, meta);
    if (scan.findings.length === 0) {
      const empty = document.createElement("p");
      empty.textContent = "No URL hygiene indicators were detected. This is not a safety verdict.";
      item.append(empty);
    } else {
      const findings = document.createElement("ul");
      for (const finding of scan.findings) {
        const row = document.createElement("li");
        const title = document.createElement("strong");
        title.textContent = `${finding.severity}: ${finding.title}`;
        const description = document.createElement("p");
        description.textContent = finding.description;
        row.append(title, description);
        findings.append(row);
      }
      item.append(findings);
      if (!caseScanIds.has(scan.id) && canScan) {
        item.append(makeButton("Open case", () => openCase(scan.id)));
      } else if (caseScanIds.has(scan.id)) {
        const linked = document.createElement("p");
        linked.className = "muted";
        linked.textContent = "Case opened for these findings.";
        item.append(linked);
      }
    }
    list.append(item);
  }
}

function renderCases(cases) {
  const list = byId("case-list");
  list.replaceChildren();
  casesCache = cases;
  caseScanIds = new Set(cases.map((item) => item.scan_id));
  caseSignalIds = new Set(cases.flatMap((item) => (item.signals || []).map((signal) => signal.id)));
  if (!cases.length) {
    setStatus("case-status", "No cases yet. Open a case from a link check that has findings.");
    return;
  }
  setStatus("case-status", `${cases.length} case(s).`);
  for (const incident of cases) {
    const item = document.createElement("li");
    item.className = "data-card";
    const heading = document.createElement("h3");
    heading.textContent = incident.title;
    const meta = document.createElement("p");
    meta.className = "case-meta";
    meta.textContent = `${incident.severity} · ${incident.status.replaceAll("_", " ")} · ${incident.hostname}`;
    const summary = document.createElement("p");
    summary.textContent = incident.summary;
    item.append(heading, meta, summary);

    const findings = document.createElement("ul");
    for (const finding of incident.findings) {
      const row = document.createElement("li");
      const title = document.createElement("strong");
      title.textContent = `${finding.severity}: ${finding.title}`;
      const description = document.createElement("p");
      description.textContent = finding.description;
      row.append(title, description);
      findings.append(row);
    }
    item.append(findings);

    const notes = document.createElement("ol");
    notes.className = "case-notes";
    for (const note of incident.notes || []) {
      const row = document.createElement("li");
      const content = document.createElement("p");
      content.textContent = note.content;
      const created = document.createElement("p");
      created.className = "muted";
      created.textContent = new Date(note.created_at).toLocaleString();
      row.append(content, created);
      notes.append(row);
    }
    item.append(notes);

    if (canScan) {
      const controls = document.createElement("div");
      controls.className = "form-row case-controls";
      const label = document.createElement("label");
      const select = document.createElement("select");
      select.setAttribute("aria-label", `Change status for ${incident.title}`);
      for (const value of caseTransitions[incident.status] || []) {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = value.replaceAll("_", " ");
        select.append(option);
      }
      label.append(select);
      controls.append(label, makeButton("Update case", () => updateCase(incident.id, select.value), ""));
      const noteInput = document.createElement("textarea");
      noteInput.maxLength = 4000;
      noteInput.setAttribute("aria-label", `Investigation note for ${incident.title}`);
      noteInput.placeholder = "Add an investigation note (4,000 characters max)";
      controls.append(noteInput, makeButton(
        "Add note",
        () => addCaseNote(incident.id, noteInput.value),
        "button-secondary",
        "case-status",
      ));
      item.append(controls);
    }
    list.append(item);
  }
}

function renderSignals(signals) {
  const list = byId("signal-list");
  list.replaceChildren();
  if (!signals.length) {
    setStatus("signal-status", "No security signals recorded yet.");
    return;
  }
  setStatus("signal-status", `${signals.length} recent signal(s).`);
  for (const signal of signals) {
    const item = document.createElement("li");
    item.className = "data-card";
    const heading = document.createElement("h3");
    heading.textContent = signal.title;
    const meta = document.createElement("p");
    meta.className = "muted";
    meta.textContent = `${signal.severity} · ${signal.source_type.replaceAll("_", " ")} · ${signal.subject} · ${new Date(signal.observed_at).toLocaleString()}`;
    const summary = document.createElement("p");
    summary.textContent = signal.summary;
    item.append(heading, meta, summary);
    if (caseSignalIds.has(signal.id)) {
      const linked = document.createElement("p");
      linked.className = "muted";
      linked.textContent = "Linked to a case.";
      item.append(linked);
    } else if (canScan) {
      const openCases = casesCache.filter((incident) => !["resolved", "false_positive"].includes(incident.status));
      if (openCases.length) {
        const select = document.createElement("select");
        select.setAttribute("aria-label", `Choose a case for ${signal.title}`);
        for (const incident of openCases) {
          const option = document.createElement("option");
          option.value = incident.id;
          option.textContent = `${incident.severity}: ${incident.title}`;
          select.append(option);
        }
        item.append(select, makeButton(
          "Link to case",
          () => attachSignalToCase(select.value, signal.id),
          "button-secondary",
          "signal-status",
        ));
      }
      // URL and extension signals use the scan-history action, which only offers
      // case creation when findings exist. Domain/integration signals can be
      // triaged directly even when they have no URL scan record.
      if (!["url_scan", "extension_scan"].includes(signal.source_type)) {
        item.append(makeButton("Open case", () => openCaseFromSignal(signal.id)));
      }
    }
    list.append(item);
  }
}

function renderAssets(assets) {
  const list = byId("asset-list");
  list.replaceChildren();
  if (!assets.length) {
    const empty = document.createElement("li");
    empty.className = "empty-state";
    empty.textContent = "No domains added yet.";
    list.append(empty);
    return;
  }
  for (const asset of assets) {
    const item = document.createElement("li");
    item.className = "data-card";
    const heading = document.createElement("h3");
    heading.textContent = asset.hostname;
    const state = document.createElement("p");
    state.className = asset.status === "verified" ? "state-verified" : "state-pending";
    state.textContent = asset.status === "verified" ? "Ownership verified" : "Verification required";
    item.append(heading, state);
    if (asset.status === "pending" && canManageAssets) {
      item.append(makeButton("Show DNS challenge", () => renewChallenge(asset.id), "button-secondary", "asset-status"));
      item.append(makeButton("Verify DNS", () => verifyAsset(asset.id), "button-secondary", "asset-status"));
    }
    if (asset.status === "verified") {
      const monitoring = document.createElement("p");
      monitoring.className = asset.monitoring_enabled ? "state-verified" : "muted";
      const monitoringLabels = {
        paused: "paused",
        pending: "waiting for the first check",
        healthy: "no SPF/DMARC indicators in the latest check",
        findings: `${asset.monitoring_finding_count} active SPF/DMARC indicator(s)`,
        error: "last check failed; retry scheduled",
      };
      monitoring.textContent = `SPF/DMARC DNS monitoring ${monitoringLabels[asset.monitoring_state] || "status unavailable"}.`;
      if (asset.monitoring_last_checked_at) {
        monitoring.textContent += ` Last checked ${new Date(asset.monitoring_last_checked_at).toLocaleString()}.`;
      }
      item.append(monitoring);
      if (canManageAssets) {
        item.append(makeButton(
          asset.monitoring_enabled ? "Pause monitoring" : "Enable monitoring",
          () => setDomainMonitoring(asset.id, !asset.monitoring_enabled),
          "button-secondary",
          "asset-status",
        ));
      }
    }
    if (canManageAssets) {
      item.append(makeButton("Remove", () => deleteAsset(asset.id, asset.hostname), "button-danger", "asset-status"));
    }
    list.append(item);
  }
}

function renderMembers(members) {
  const list = byId("member-list");
  const target = byId("owner-transfer-target");
  list.replaceChildren();
  target.replaceChildren();
  const admins = [];
  for (const member of members) {
    const item = document.createElement("li");
    item.className = "data-card";
    const identity = document.createElement("h3");
    identity.textContent = member.email;
    const role = document.createElement("p");
    role.className = "muted";
    role.textContent = `Role: ${member.role}`;
    item.append(identity, role);
    list.append(item);
    if (member.role === "admin") admins.push(member);
  }
  for (const admin of admins) {
    const option = document.createElement("option");
    option.value = admin.membership_id;
    option.textContent = admin.email;
    target.append(option);
  }
  byId("owner-transfer-panel").hidden = !canTransferOwnership || admins.length === 0;
  if (canTransferOwnership && admins.length === 0) {
    setStatus("owner-transfer-status", "Promote an existing teammate to admin before transferring ownership.");
  }
  setStatus("member-status", `${members.length} organization member(s).`);
}

async function loadMembers() {
  if (!canManageAssets) return;
  setStatus("member-status", "Loading organization members…");
  const response = await request(`${apiBase}/members`);
  if (response.status === 401) return clearSession();
  if (!response.ok) {
    setStatus("member-status", "Organization members could not be loaded.");
    return;
  }
  renderMembers(await response.json());
}

function showChallenge(asset) {
  byId("challenge-name").textContent = asset.dns_name;
  byId("challenge-value").textContent = asset.dns_value;
  byId("challenge-panel").hidden = false;
  byId("challenge-panel").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function loadOrganization() {
  const response = await request(apiBase);
  if (response.status === 401) {
    clearSession();
    return false;
  }
  if (!response.ok) {
    setStatus("scan-status", response.status === 403
      ? "Owner/admin access needs MFA. Return to the account page to enable it, then reopen the dashboard."
      : "Organization details are unavailable. Return to the account page and sign in again.");
    return false;
  }
  const organization = await response.json();
  byId("organization-name").textContent = organization.name;
  byId("organization-role").textContent = `Role: ${organization.role}`;
  canScan = ["owner", "admin", "analyst"].includes(organization.role);
  canManageAssets = ["owner", "admin"].includes(organization.role);
  canTransferOwnership = organization.role === "owner";
  byId("team-panel").hidden = !canManageAssets;
  byId("scan-submit").disabled = !canScan;
  byId("asset-submit").disabled = !canManageAssets;
  if (!canScan) setStatus("scan-status", "Your viewer role can review results but cannot scan or update cases.");
  if (!canManageAssets) setStatus("asset-status", "Only organization owners and admins can add or verify domains.");
  const preferenceResponse = await request(`${apiBase}/notification-preferences`);
  if (preferenceResponse.ok) {
    const preferences = await preferenceResponse.json();
    byId("priority-email-enabled").checked = preferences.priority_email_enabled;
    setStatus("notification-preference-status", canManageAssets
      ? "Enabled alerts are emailed to verified owners and admins in this organization."
      : "Only organization owners and admins receive these alerts.");
  } else {
    setStatus("notification-preference-status", "Email alert preferences could not be loaded.");
  }
  const deliveryStatus = byId("notification-delivery-status");
  deliveryStatus.hidden = !canManageAssets;
  byId("refresh-notification-status").hidden = !canManageAssets;
  if (canManageAssets) {
    await loadNotificationDeliveryStatus();
  }
  return true;
}

async function loadNotificationDeliveryStatus() {
  if (!canManageAssets) return;
  const response = await request(`${apiBase}/notification-status`);
  if (response.status === 401) return clearSession();
  const status = byId("notification-delivery-status");
  if (!response.ok) {
    status.textContent = "Alert delivery status is unavailable.";
    return;
  }
  const delivery = await response.json();
  status.textContent = `${delivery.pending_count} pending, ${delivery.failed_count} failed alert email(s).`;
  if (delivery.oldest_pending_at) {
    status.textContent += ` Oldest pending since ${new Date(delivery.oldest_pending_at).toLocaleString()}.`;
  }
}

byId("refresh-notification-status").addEventListener("click", () => {
  loadNotificationDeliveryStatus().catch(() => {
    setStatus("notification-preference-status", "Alert delivery status is unavailable.");
  });
});

byId("priority-email-enabled").addEventListener("change", async (event) => {
  const checkbox = event.currentTarget;
  checkbox.disabled = true;
  try {
    const response = await request(`${apiBase}/notification-preferences`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ priority_email_enabled: checkbox.checked }),
    });
    if (!response.ok) throw new Error("preference_update_failed");
    const result = await response.json();
    checkbox.checked = result.priority_email_enabled;
    setStatus("notification-preference-status", "Email alert preference saved.");
  } catch {
    checkbox.checked = !checkbox.checked;
    setStatus("notification-preference-status", "Preference could not be saved. Try again.");
  } finally {
    checkbox.disabled = false;
  }
});

async function loadMyOrganizations() {
  const response = await request("/auth/organizations");
  if (response.status === 401) return clearSession();
  if (!response.ok) {
    setStatus("scan-status", "Your organizations could not be loaded.");
    return false;
  }
  const organizations = await response.json();
  if (!organizations.length) return clearSession();
  const switcher = byId("organization-switcher");
  switcher.replaceChildren();
  for (const organization of organizations) {
    const option = document.createElement("option");
    option.value = organization.id;
    option.textContent = organization.name;
    switcher.append(option);
  }
  if (!organizations.some((item) => item.id === organizationId)) {
    organizationId = organizations[0].id;
    sessionStorage.setItem("securelink.organizationId", organizationId);
    apiBase = `/organizations/${encodeURIComponent(organizationId)}`;
  }
  switcher.value = organizationId;
  switcher.disabled = organizations.length < 2;
  switcher.addEventListener("change", () => {
    sessionStorage.setItem("securelink.organizationId", switcher.value);
    window.location.reload();
  });
  return true;
}

async function loadCases() {
  setStatus("case-status", "Loading cases…");
  const response = await request(`${apiBase}/cases?limit=50`);
  if (response.status === 401) return clearSession();
  if (!response.ok) {
    setStatus("case-status", "Cases could not be loaded.");
    return;
  }
  renderCases(await response.json());
}

async function loadAssets() {
  const response = await request(`${apiBase}/assets/domains`);
  if (response.status === 401) return clearSession();
  if (!response.ok) {
    setStatus("asset-status", "Domain inventory could not be loaded.");
    return;
  }
  renderAssets(await response.json());
}

async function loadScans() {
  setStatus("history-status", "Loading link check history…");
  const response = await request(`${apiBase}/scans?limit=50`);
  if (response.status === 401) return clearSession();
  if (!response.ok) {
    setStatus("history-status", "Link check history could not be loaded.");
    return;
  }
  renderScans(await response.json());
}

async function loadSignals() {
  setStatus("signal-status", "Loading security signals…");
  const response = await request(`${apiBase}/signals?limit=50`);
  if (response.status === 401) return clearSession();
  if (!response.ok) {
    setStatus("signal-status", "Security signals could not be loaded.");
    return;
  }
  renderSignals(await response.json());
}

function renderExtensionSessions(sessions) {
  const list = byId("extension-session-list");
  list.replaceChildren();
  if (!sessions.length) {
    setStatus("extension-session-status", "No browser extension sessions are connected to this account.");
    return;
  }
  for (const extensionSession of sessions) {
    const item = document.createElement("li");
    item.className = "data-card";
    const heading = document.createElement("h3");
    heading.textContent = "SecureLink Chrome extension";
    const organization = document.createElement("p");
    organization.textContent = `Organization: ${extensionSession.organization_name}`;
    const expiry = document.createElement("p");
    expiry.className = "muted";
    expiry.textContent = `Connected ${new Date(extensionSession.created_at).toLocaleString()} · Expires ${new Date(extensionSession.expires_at).toLocaleString()}`;
    const active = extensionSession.status === "active";
    const state = document.createElement("p");
    state.className = active ? "state-verified" : "state-pending";
    const labels = {
      active: "Connected",
      revoked: "Disconnected",
      expired: "Expired",
      invalidated: "No longer authorized",
    };
    state.textContent = labels[extensionSession.status] || "Status unavailable";
    item.append(heading, organization, expiry, state);
    if (active) {
      item.append(makeButton(
        "Disconnect",
        () => revokeExtensionSession(extensionSession.id),
        "button-danger",
        "extension-session-status",
      ));
    }
    list.append(item);
  }
  setStatus("extension-session-status", `${sessions.length} extension session(s).`);
}

async function loadExtensionSessions() {
  setStatus("extension-session-status", "Loading browser extension sessions…");
  const response = await request("/extension/oauth/sessions");
  if (response.status === 401) return clearSession();
  if (!response.ok) {
    setStatus("extension-session-status", "Browser extension sessions could not be loaded.");
    return;
  }
  renderExtensionSessions(await response.json());
}

async function revokeExtensionSession(sessionId) {
  if (!window.confirm("Disconnect this SecureLink browser extension session?")) return;
  const response = await request(`/extension/oauth/sessions/${encodeURIComponent(sessionId)}`, {
    method: "DELETE",
  });
  if (response.status === 401) return clearSession();
  if (!response.ok) {
    setStatus("extension-session-status", "This extension session could not be disconnected.");
    return;
  }
  setStatus("extension-session-status", "Browser extension disconnected.");
  await loadExtensionSessions();
}

async function refreshAll() {
  await loadCases();
  await Promise.all([loadAssets(), loadExtensionSessions(), loadMembers(), loadSignals(), loadScans()]);
}

async function openCaseFromSignal(signalId) {
  setStatus("signal-status", "Opening case from signal…");
  const response = await request(`${apiBase}/cases/from-signal/${encodeURIComponent(signalId)}`, { method: "POST" });
  if (response.status === 401) return clearSession();
  if (!response.ok) {
    setStatus("signal-status", "A case could not be opened for this signal.");
    return;
  }
  setStatus("signal-status", "Signal linked to a case for review.");
  await Promise.all([loadCases(), loadSignals()]);
}

async function attachSignalToCase(caseId, signalId) {
  const response = await request(
    `${apiBase}/cases/${encodeURIComponent(caseId)}/signals/${encodeURIComponent(signalId)}`,
    { method: "POST" },
  );
  if (response.status === 401) return clearSession();
  if (!response.ok) {
    setStatus("signal-status", response.status === 409
      ? "Reopen the case or choose another case before linking this signal."
      : "The signal could not be linked to that case.");
    return;
  }
  setStatus("signal-status", "Signal linked to the case and recorded in the audit history.");
  await Promise.all([loadCases(), loadSignals()]);
}

async function openCase(scanId) {
  setStatus("case-status", "Opening case…");
  const response = await request(`${apiBase}/cases/from-scan/${encodeURIComponent(scanId)}`, { method: "POST" });
  if (response.status === 401) return clearSession();
  if (!response.ok) {
    setStatus("case-status", response.status === 409
      ? "This scan has no findings to open as a case."
      : "The case could not be opened.");
    return;
  }
  setStatus("case-status", "Case is ready for review.");
  await Promise.all([loadCases(), loadSignals(), loadScans()]);
}

async function updateCase(caseId, nextStatus) {
  const response = await request(`${apiBase}/cases/${encodeURIComponent(caseId)}/status`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status: nextStatus }),
  });
  if (response.status === 401) return clearSession();
  if (!response.ok) {
    setStatus("case-status", response.status === 409
      ? "That case status change is not allowed. Refresh and try again."
      : "The case could not be updated.");
    return;
  }
  setStatus("case-status", "Case updated and recorded in the audit history.");
  await loadCases();
}

async function addCaseNote(caseId, content) {
  const response = await request(`${apiBase}/cases/${encodeURIComponent(caseId)}/notes`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content }),
  });
  if (response.status === 401) return clearSession();
  if (!response.ok) {
    setStatus("case-status", response.status === 422
      ? "Notes must contain text and stay within 4,000 characters."
      : "The investigation note could not be saved.");
    return;
  }
  renderCases(await response.json());
  setStatus("case-status", "Investigation note saved to the append-only case history.");
}

async function renewChallenge(assetId) {
  byId("challenge-panel").hidden = true;
  const response = await request(`${apiBase}/assets/domains/${encodeURIComponent(assetId)}/challenge`, { method: "POST" });
  if (response.status === 401) return clearSession();
  if (!response.ok) {
    setStatus("asset-status", "A new DNS challenge could not be generated.");
    return;
  }
  showChallenge(await response.json());
  setStatus("asset-status", "Publish the DNS TXT record shown below, then select Verify DNS.");
}

async function verifyAsset(assetId) {
  setStatus("asset-status", "Checking the domain TXT record…");
  const response = await request(`${apiBase}/assets/domains/${encodeURIComponent(assetId)}/verify`, { method: "POST" });
  if (response.status === 401) return clearSession();
  if (response.ok) {
    byId("challenge-panel").hidden = true;
    setStatus("asset-status", "Domain ownership verified. SPF and DMARC monitoring remains off until enabled.");
    await loadAssets();
    return;
  }
  setStatus("asset-status", response.status === 409
    ? "The TXT record was not found or did not match yet. Check DNS propagation and try again."
    : "DNS verification could not be completed.");
}

async function deleteAsset(assetId, hostname) {
  if (!window.confirm(`Remove ${hostname} from this organization's domain inventory?`)) return;
  const response = await request(`${apiBase}/assets/domains/${encodeURIComponent(assetId)}`, { method: "DELETE" });
  if (response.status === 401) return clearSession();
  if (!response.ok) {
    setStatus("asset-status", "The domain could not be removed.");
    return;
  }
  byId("challenge-panel").hidden = true;
  setStatus("asset-status", `${hostname} removed from the inventory.`);
  await loadAssets();
}

async function setDomainMonitoring(assetId, enabled) {
  setStatus("asset-status", enabled ? "Enabling DNS monitoring…" : "Pausing DNS monitoring…");
  const response = await request(`${apiBase}/assets/domains/${encodeURIComponent(assetId)}/monitoring`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled }),
  });
  if (response.status === 401) return clearSession();
  if (!response.ok) {
    setStatus("asset-status", response.status === 409
      ? "Verify domain ownership before enabling monitoring."
      : "The monitoring preference could not be saved.");
    return;
  }
  setStatus("asset-status", enabled
    ? "SPF and DMARC DNS monitoring enabled. Initial results will appear in Security signals."
    : "Domain DNS monitoring paused.");
  await loadAssets();
}

byId("scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = byId("scan-submit");
  button.disabled = true;
  setStatus("scan-status", "Inspecting URL structure…");
  try {
    const response = await request(`${apiBase}/scans`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: byId("scan-url").value }),
    });
    if (response.status === 401) return clearSession();
    if (response.status === 403) {
      setStatus("scan-status", "Your role cannot start scans.");
      return;
    }
    if (!response.ok) {
      setStatus("scan-status", response.status === 429
        ? "Scan limit reached. Wait before trying again."
        : "This URL could not be inspected. Check the format and try again.");
      return;
    }
    await response.json();
    setStatus("scan-status", "URL structure inspection complete. This is not a malware or safety verdict.");
    byId("scan-form").reset();
    await Promise.all([loadCases(), loadSignals(), loadScans(), loadNotificationDeliveryStatus()]);
  } catch {
    setStatus("scan-status", "SecureLink could not be reached. The URL was not confirmed or classified.");
  } finally {
    button.disabled = !canScan;
  }
});

byId("asset-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!canManageAssets) return;
  const button = byId("asset-submit");
  button.disabled = true;
  setStatus("asset-status", "Adding domain and preparing a DNS ownership challenge…");
  try {
    const response = await request(`${apiBase}/assets/domains`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hostname: byId("asset-hostname").value }),
    });
    if (response.status === 401) return clearSession();
    if (!response.ok) {
      setStatus("asset-status", response.status === 409
        ? "That domain is already in the inventory."
        : "The domain could not be added. Check the domain name and your permissions.");
      return;
    }
    const asset = await response.json();
    byId("asset-form").reset();
    showChallenge(asset);
    setStatus("asset-status", "Publish this TXT record to verify that your organization controls the domain.");
    await loadAssets();
  } catch {
    setStatus("asset-status", "SecureLink could not be reached. The domain was not added.");
  } finally {
    button.disabled = !canManageAssets;
  }
});

byId("refresh-cases").addEventListener("click", loadCases);
byId("refresh-signals").addEventListener("click", loadSignals);
byId("refresh-assets").addEventListener("click", loadAssets);
byId("refresh-members").addEventListener("click", loadMembers);
byId("refresh-scans").addEventListener("click", loadScans);
byId("refresh-extension-sessions").addEventListener("click", loadExtensionSessions);
byId("owner-transfer-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const select = byId("owner-transfer-target");
  const selectedAdmin = select.options[select.selectedIndex];
  if (!selectedAdmin || !window.confirm(`Transfer ownership to ${selectedAdmin.textContent}? You will become an admin.`)) return;
  const button = event.submitter;
  button.disabled = true;
  setStatus("owner-transfer-status", "Verifying and transferring ownership…");
  try {
    const response = await request(`${apiBase}/owner-transfer`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target_membership_id: select.value,
        password: byId("owner-transfer-password").value,
        mfa_code: byId("owner-transfer-code").value,
      }),
    });
    byId("owner-transfer-password").value = "";
    byId("owner-transfer-code").value = "";
    if (response.status === 401) return clearSession();
    if (!response.ok) {
      setStatus("owner-transfer-status", response.status === 403
        ? "Enable MFA before transferring ownership, then try again."
        : "Transfer failed. Check your password, authentication code, and selected admin.");
      return;
    }
    setStatus("owner-transfer-status", "Ownership transferred. Refreshing your organization role…");
    window.location.reload();
  } catch {
    byId("owner-transfer-password").value = "";
    byId("owner-transfer-code").value = "";
    setStatus("owner-transfer-status", "SecureLink could not be reached; ownership was not transferred.");
  } finally {
    button.disabled = false;
  }
});
byId("sign-out").addEventListener("click", async () => {
  if (token) {
    try {
      await request("/auth/logout", { method: "POST" });
    } catch {
      // Clear the browser session even if the service is unreachable.
    }
  }
  clearSession();
});

if (!token) {
  setStatus("scan-status", "Sign in from the account page to use the dashboard.");
  byId("scan-submit").disabled = true;
  byId("asset-submit").disabled = true;
} else {
  loadMyOrganizations().then(async (ok) => {
    if (ok && await loadOrganization()) await refreshAll();
  }).catch(() => setStatus("scan-status", "SecureLink could not be reached."));
}
