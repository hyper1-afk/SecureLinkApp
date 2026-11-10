import {
  buildAuthorizationUrl,
  createPkcePair,
  randomBase64Url,
  readAuthorizationCallback,
  validateApiOrigin,
} from "./oauth.js";
import { API_BASE_URL } from "./api-config.js";
import { redactUrlForSubmission } from "./url-privacy.js";
const TOKEN_KEY = "extensionAccessToken";
const ORG_KEY = "organizationId";
const TOKEN_META_KEY = "tokenExpiresAt";
const CLIENT_ID = "securelink-chrome-extension";

function assertApiUrl() {
  return validateApiOrigin(API_BASE_URL);
}

async function connect() {
  const api = assertApiUrl();
  const redirectUri = chrome.identity.getRedirectURL();
  const state = randomBase64Url(32);
  const { verifier, challenge } = await createPkcePair();
  const authorizeUrl = buildAuthorizationUrl(api.origin, redirectUri, state, challenge);

  const callbackUrl = await chrome.identity.launchWebAuthFlow({
    url: authorizeUrl,
    interactive: true,
  });
  if (!callbackUrl) throw new Error("Authorization was cancelled.");
  const code = readAuthorizationCallback(callbackUrl, redirectUri, state);

  const response = await fetch(new URL("/extension/oauth/token", api), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    cache: "no-store",
    credentials: "omit",
    referrerPolicy: "no-referrer",
    body: JSON.stringify({
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
    }),
  });
  if (!response.ok) throw new Error("SecureLink could not complete authorization.");
  const token = await response.json();
  await chrome.storage.session.set({
    [TOKEN_KEY]: token.access_token,
    [ORG_KEY]: token.organization_id,
    [TOKEN_META_KEY]: Date.now() + token.expires_in * 1000,
  });
  return { connected: true };
}

async function disconnect() {
  const { [TOKEN_KEY]: accessToken } = await chrome.storage.session.get(TOKEN_KEY);
  if (accessToken) {
    try {
      await fetch(new URL("/extension/oauth/revoke", assertApiUrl()), {
        method: "POST",
        headers: { Authorization: `Bearer ${accessToken}` },
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
      });
    } finally {
      await chrome.storage.session.remove([TOKEN_KEY, ORG_KEY, TOKEN_META_KEY]);
    }
  }
  return { connected: false };
}

async function scanUrl(rawUrl) {
  const api = assertApiUrl();
  const sanitized = redactUrlForSubmission(rawUrl);
  const { [TOKEN_KEY]: accessToken, [TOKEN_META_KEY]: expiresAt } =
    await chrome.storage.session.get([TOKEN_KEY, TOKEN_META_KEY]);
  if (!accessToken || !expiresAt || expiresAt <= Date.now()) {
    await chrome.storage.session.remove([TOKEN_KEY, ORG_KEY, TOKEN_META_KEY]);
    throw new Error("Connect your SecureLink account to scan links.");
  }
  const response = await fetch(new URL("/extension/v1/scans", api), {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ url: sanitized.url, redactions: sanitized.redactions }),
    cache: "no-store",
    credentials: "omit",
    referrerPolicy: "no-referrer",
  });
  if (response.status === 401 || response.status === 403) {
    await chrome.storage.session.remove([TOKEN_KEY, ORG_KEY, TOKEN_META_KEY]);
    throw new Error(response.status === 401
      ? "Your SecureLink session expired. Connect again to continue."
      : "Your account no longer has permission to scan. Check your organization role and MFA settings.");
  }
  if (!response.ok) throw new Error("SecureLink could not scan this link.");
  return response.json();
}

function isPopupSender(sender) {
  return sender.id === chrome.runtime.id
    && sender.url === chrome.runtime.getURL("popup.html")
    && !sender.tab;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!isPopupSender(sender)) {
    sendResponse({ ok: false, error: "SecureLink actions must come from the extension popup." });
    return false;
  }
  const operation = message?.type === "connect"
    ? connect()
    : message?.type === "disconnect"
      ? disconnect()
      : message?.type === "scan"
        ? scanUrl(message.url)
        : null;
  if (!operation) return false;
  operation.then(
    (result) => sendResponse({ ok: true, result }),
    (error) => sendResponse({ ok: false, error: error instanceof Error ? error.message : "Request failed." }),
  );
  return true;
});
