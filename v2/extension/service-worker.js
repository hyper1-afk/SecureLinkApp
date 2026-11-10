// Local preview default. Change this origin when preparing a staging package.
const API_BASE_URL = "http://localhost:8000";
const TOKEN_KEY = "extensionAccessToken";
const ORG_KEY = "organizationId";
const TOKEN_META_KEY = "tokenExpiresAt";
const CLIENT_ID = "securelink-chrome-extension";

function randomBase64Url(byteLength = 32) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

async function sha256Base64Url(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function assertApiUrl() {
  const api = new URL(API_BASE_URL);
  if (api.username || api.password || api.search || api.hash || api.pathname !== "/") {
    throw new Error("The API origin in config.js is invalid.");
  }
  if (api.protocol !== "https:" && api.hostname !== "localhost") {
    throw new Error("SecureLink requires HTTPS outside localhost.");
  }
  return api;
}

async function connect() {
  const api = assertApiUrl();
  const redirectUri = chrome.identity.getRedirectURL();
  const state = randomBase64Url(32);
  const verifier = randomBase64Url(48);
  const challenge = await sha256Base64Url(verifier);
  const authorizeUrl = new URL("/extension/authorize", api);
  authorizeUrl.search = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: redirectUri,
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });

  const callbackUrl = await chrome.identity.launchWebAuthFlow({
    url: authorizeUrl.href,
    interactive: true,
  });
  if (!callbackUrl) throw new Error("Authorization was cancelled.");
  const callback = new URL(callbackUrl);
  if (callback.origin + callback.pathname !== redirectUri) {
    throw new Error("SecureLink returned an unexpected authorization address.");
  }
  if (callback.searchParams.get("state") !== state) {
    throw new Error("Authorization state did not match. Please try again.");
  }
  const code = callback.searchParams.get("code");
  if (!code) throw new Error("SecureLink did not return an authorization code.");

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
    body: JSON.stringify({ url: rawUrl }),
    cache: "no-store",
    credentials: "omit",
    referrerPolicy: "no-referrer",
  });
  if (response.status === 401) {
    await chrome.storage.session.remove([TOKEN_KEY, ORG_KEY, TOKEN_META_KEY]);
    throw new Error("Your SecureLink session expired. Connect again to continue.");
  }
  if (!response.ok) throw new Error("SecureLink could not scan this link.");
  return response.json();
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
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
