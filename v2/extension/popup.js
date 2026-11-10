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
  status.textContent = "Opening SecureLink authorization…";
  try {
    await send({ type: "connect" });
    status.textContent = "Account connected.";
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : "Could not connect.";
  } finally {
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
  status.textContent = "Submitting link…";
  byId("result").hidden = true;
  try {
    const result = await send({ type: "scan", url: byId("url").value.trim() });
    const findings = Array.isArray(result.findings) ? result.findings : [];
    byId("result-summary").textContent =
      `${result.status === "completed" ? "Scan recorded" : "Scan status: " + result.status}`
      + ` for ${result.hostname || "the submitted host"}. `
      + `${findings.length} structural finding${findings.length === 1 ? "" : "s"}.`;
    const list = byId("finding-list");
    list.replaceChildren();
    for (const finding of findings) {
      const item = document.createElement("li");
      item.textContent = `${finding.severity}: ${finding.title} — ${finding.description}`;
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
