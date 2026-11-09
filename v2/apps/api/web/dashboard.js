const token = sessionStorage.getItem("securelink.accessToken");
const organizationId = sessionStorage.getItem("securelink.organizationId");
const byId = (id) => document.getElementById(id);
const apiBase = organizationId ? `/organizations/${encodeURIComponent(organizationId)}` : "";

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

function renderScans(scans) {
  const list = byId("scan-history");
  list.replaceChildren();
  if (!scans.length) {
    setStatus("history-status", "No scans yet.");
    return;
  }
  setStatus("history-status", `${scans.length} recent scan(s).`);
  for (const scan of scans) {
    const item = document.createElement("li");
    item.className = "scan-item";
    const heading = document.createElement("h3");
    heading.textContent = scan.display_url;
    const meta = document.createElement("p");
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
        row.className = "finding";
        const severity = document.createElement("span");
        severity.className = "severity";
        severity.textContent = finding.severity;
        const title = document.createElement("strong");
        title.textContent = finding.title;
        const description = document.createElement("p");
        description.textContent = finding.description;
        row.append(severity, title, description);
        findings.append(row);
      }
      item.append(findings);
    }
    list.append(item);
  }
}

async function loadOrganization() {
  const response = await request(apiBase);
  if (response.status === 401) {
    clearSession();
    return false;
  }
  if (!response.ok) {
    setStatus("scan-status", "Organization details are unavailable. Return to the account page and sign in again.");
    return false;
  }
  const organization = await response.json();
  byId("organization-name").textContent = organization.name;
  byId("organization-role").textContent = `Role: ${organization.role}`;
  const canScan = ["owner", "admin", "analyst"].includes(organization.role);
  byId("scan-submit").disabled = !canScan;
  if (!canScan) setStatus("scan-status", "Your viewer role can review history but cannot start scans.");
  return true;
}

async function loadScans() {
  setStatus("history-status", "Loading scan history…");
  const response = await request(`${apiBase}/scans?limit=50`);
  if (response.status === 401) {
    clearSession();
    return;
  }
  if (!response.ok) {
    setStatus("history-status", "Scan history could not be loaded.");
    return;
  }
  renderScans(await response.json());
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
    if (response.status === 401) {
      clearSession();
      return;
    }
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
    await loadScans();
  } catch {
    setStatus("scan-status", "SecureLink could not be reached. Your URL was not confirmed or classified.");
  } finally {
    button.disabled = false;
  }
});

byId("refresh-scans").addEventListener("click", loadScans);
byId("sign-out").addEventListener("click", async () => {
  if (token) {
    try {
      await request("/auth/logout", { method: "POST" });
    } catch {
      // Clear local credentials even if the service is unreachable.
    }
  }
  clearSession();
});

if (!token || !organizationId) {
  setStatus("scan-status", "Sign in from the account page to use the dashboard.");
  byId("scan-submit").disabled = true;
} else {
  loadOrganization().then((ok) => ok && loadScans()).catch(() => {
    setStatus("scan-status", "SecureLink could not be reached.");
  });
}
