const byId = (id) => document.getElementById(id);
const connection = byId("connection");
const connectButton = byId("connect");
const disconnectButton = byId("disconnect");
const status = byId("status");

async function send(message) {
  const response = await chrome.runtime.sendMessage(message);
  if (!response?.ok) throw new Error(response?.error || "SecureLink request failed.");
  return response.result;
}

async function refreshConnection() {
  const { extensionAccessToken: token, tokenExpiresAt: expiry } =
    await chrome.storage.session.get(["extensionAccessToken", "tokenExpiresAt"]);
  const connected = Boolean(token && expiry > Date.now());
  connection.textContent = connected ? "Connected to SecureLink" : "Not connected";
  connectButton.hidden = connected;
  disconnectButton.hidden = !connected;
}

connectButton.addEventListener("click", async () => {
  connectButton.disabled = true;
  status.textContent = "Requesting Chrome identity accessâ€¦";
  try {
    const granted = await new Promise((resolve) => {
      chrome.permissions.request({ permissions: ["identity"] }, resolve);
    });
    if (chrome.runtime.lastError || !granted) {
      throw new Error("Chrome identity access was not granted.");
    }
    status.textContent = "Opening SecureLink authorizationâ€¦";
    await send({ type: "connect" });
    status.textContent = "Account connected.";
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : "Could not connect.";
  } finally {
    await new Promise((resolve) => {
      chrome.permissions.remove({ permissions: ["identity"] }, () => {
        void chrome.runtime.lastError;
        resolve();
      });
    });
    connectButton.disabled = false;
    await refreshConnection();
  }
});

disconnectButton.addEventListener("click", async () => {
  disconnectButton.disabled = true;
  try {
    await send({ type: "disconnect" });
    status.textContent = "SecureLink session disconnected.";
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : "Could not disconnect.";
  } finally {
    disconnectButton.disabled = false;
    await refreshConnection();
  }
});

byId("scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = byId("scan");
  button.disabled = true;
  status.textContent = "Submitting linkâ€¦";
  byId("result").hidden = true;
  try {
    const result = await send({ type: "scan", url: byId("url").value.trim() });
    const findings = Array.isArray(result.findings) ? result.findings : [];
    byId("result-summary").textContent =
      `${result.status === "completed" ? "Scan recorded" : "Scan status: " + result.status}`
      + ` for ${result.hostname || "the submitted host"}. `
      + `${findings.length} structural finding${findings.length === 1 ? "" : "s"}.`;
    const coverage = document.createElement("p");
    coverage.className = "note";
    const intel = result.threat_intelligence;
    if (intel?.status === "current") {
      const updated = intel.source_updated_at
        ? `updated ${new Date(intel.source_updated_at).toLocaleString()}`
        : "update time unavailable";
      coverage.textContent = `${intel.source}: current snapshot (${updated}); checks literal public IP addresses only.`;
    } else {
      coverage.textContent = `${intel?.source || "Spamhaus DROP"}: reputation coverage unavailable; checks literal public IP addresses only.`;
    }
    if (intel?.match) {
      coverage.textContent += ` Listed network match: ${intel.match.cidr} (${intel.match.sblid}); review this indicator, it is not proof the page is malicious.`;
    }
    byId("result-coverage").replaceChildren(coverage);
    const list = byId("finding-list");
    list.replaceChildren();
    for (const finding of findings) {
      const item = document.createElement("li");
      item.textContent = `${finding.severity}: ${finding.title} â€” ${finding.description}`;
      list.append(item);
    }
    byId("result").hidden = false;
    status.textContent = "Structural review complete.";
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : "Could not scan this link.";
  } finally {
    button.disabled = false;
  }
});

refreshConnection().catch(() => {
  connection.textContent = "Could not read SecureLink session.";
});

