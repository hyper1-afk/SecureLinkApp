import { validateApiOrigin } from "./v2-oauth.js";

const byId = (id) => document.getElementById(id);
const V2_TOKEN_KEY = "v2ExtensionAccessToken";
const V2_ORIGIN_KEY = "v2ApiOrigin";
const V2_EXPIRY_KEY = "v2TokenExpiresAt";
let configuredV2ApiOrigin = "";

function sendV2(action, payload = {}) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ action, ...payload }, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else if (response?.error) {
        reject(new Error(response.error));
      } else {
        resolve(response?.result);
      }
    });
  });
}

function showV2Status(message) {
  byId("v2-status").textContent = message;
}

async function refreshV2Status() {
  try {
    const status = await sendV2("v2Status");
    if (status?.error) showV2Status(status.error);
    else showV2Status(status?.connected
      ? "Connected — manual reviews only"
      : configuredV2ApiOrigin ? "Not connected" : "Set the V2 API origin in Settings to connect.");
    byId("v2-connect-btn").classList.toggle("hidden", status?.connected);
    byId("v2-disconnect-btn").classList.toggle("hidden", !status?.connected);
    byId("v2-scan-btn").classList.toggle("hidden", !status?.connected);
  } catch (error) {
    showV2Status(error instanceof Error ? error.message : "Could not check V2 connection.");
  }
}

function initializeV2Settings() {
  const input = byId("v2-api-url-input");
  const message = byId("v2-settings-msg");
  chrome.storage.local.get("v2ApiBase", (stored) => {
    try {
      configuredV2ApiOrigin = stored.v2ApiBase ? validateApiOrigin(stored.v2ApiBase).origin : "";
      input.value = configuredV2ApiOrigin;
    } catch {
      configuredV2ApiOrigin = "";
      input.value = stored.v2ApiBase || "";
    }
    byId("v2-api-display").textContent = configuredV2ApiOrigin
      ? `API: ${configuredV2ApiOrigin}`
      : "Set an API origin in Settings to connect.";
    refreshV2Status();
  });

  byId("v2-api-url-save-btn").addEventListener("click", async () => {
    message.className = "settings-msg hidden";
    const value = input.value.trim().replace(/\/$/, "");
    let newOrigin = "";
    try {
      if (value) newOrigin = validateApiOrigin(value).origin;
      const session = await chrome.storage.session.get([V2_TOKEN_KEY, V2_ORIGIN_KEY]);
      if (session[V2_TOKEN_KEY] && newOrigin !== session[V2_ORIGIN_KEY]) {
        throw new Error("Disconnect the current V2 session before changing its API origin.");
      }
      await chrome.storage.local.set({ v2ApiBase: newOrigin });
      configuredV2ApiOrigin = newOrigin;
      input.value = newOrigin;
      byId("v2-api-display").textContent = newOrigin
        ? `API: ${newOrigin}`
        : "Set an API origin in Settings to connect.";
      message.textContent = newOrigin ? "V2 API origin saved." : "V2 connection disabled.";
      message.className = "settings-msg";
      refreshV2Status();
    } catch (error) {
      message.textContent = error instanceof Error ? error.message : "Could not save the V2 API origin.";
      message.className = "settings-msg error";
    }
    message.classList.remove("hidden");
  });
}

function connectV2FromClick() {
  const button = byId("v2-connect-btn");
  if (!configuredV2ApiOrigin) {
    showV2Status("Save a valid V2 API origin in extension Settings first.");
    return;
  }
  button.disabled = true;
  showV2Status("Requesting optional Chrome identity permission…");
  chrome.permissions.request({ permissions: ["identity"] }, (granted) => {
    if (chrome.runtime.lastError || !granted) {
      showV2Status("Chrome identity permission was not granted.");
      button.disabled = false;
      return;
    }
    showV2Status("Opening SecureLink authorization…");
    sendV2("v2Connect").then(
      () => showV2Status("V2 workspace connected."),
      (error) => showV2Status(error instanceof Error ? error.message : "Could not connect to V2."),
    ).finally(() => {
      button.disabled = false;
      refreshV2Status();
    });
  });
}

function disconnectV2FromClick() {
  const button = byId("v2-disconnect-btn");
  button.disabled = true;
  sendV2("v2Disconnect").then((result) => {
    byId("v2-connect-btn").classList.remove("hidden");
    byId("v2-disconnect-btn").classList.add("hidden");
    byId("v2-scan-btn").classList.add("hidden");
    showV2Status(result?.serverRevoked
      ? "V2 session disconnected and revoked."
      : "V2 token cleared here. If its account session is still active, revoke it from the dashboard.");
  }, (error) => {
    showV2Status(error instanceof Error ? error.message : "Could not disconnect V2.");
  }).finally(() => {
    button.disabled = false;
  });
}

function submitManualV2Review() {
  const input = byId("url-input");
  let url = input.value.trim();
  if (!url) {
    showV2Status("Enter a link in the scan field first.");
    return;
  }
  if (!/^https?:\/\//i.test(url)) url = `https://${url}`;
  try {
    const parsed = new URL(url);
    if (!new Set(["http:", "https:"]).has(parsed.protocol)) throw new Error("Unsupported URL scheme.");
  } catch {
    showV2Status("Enter a valid HTTP or HTTPS link to review.");
    return;
  }

  const button = byId("v2-scan-btn");
  const result = byId("v2-result");
  button.disabled = true;
  result.classList.add("hidden");
  showV2Status("Submitting manual V2 review…");
  sendV2("v2Scan", { url }).then((scan) => {
    const findings = Array.isArray(scan.findings) ? scan.findings : [];
    byId("v2-result-summary").textContent =
      `Structural review of ${scan.hostname || "the submitted host"}: `
      + `${findings.length} finding${findings.length === 1 ? "" : "s"}.`;
    const list = byId("v2-findings");
    list.replaceChildren();
    for (const finding of findings) {
      const item = document.createElement("li");
      item.textContent = `${finding.severity}: ${finding.title} — ${finding.description}`;
      list.append(item);
    }
    result.classList.remove("hidden");
    showV2Status("V2 structural review complete. This is not a malware or reputation verdict.");
  }, (error) => {
    showV2Status(error instanceof Error ? error.message : "V2 could not review this link.");
  }).finally(() => {
    button.disabled = false;
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initializeV2Settings();
  byId("v2-connect-btn").addEventListener("click", connectV2FromClick);
  byId("v2-disconnect-btn").addEventListener("click", disconnectV2FromClick);
  byId("v2-scan-btn").addEventListener("click", submitManualV2Review);
});
