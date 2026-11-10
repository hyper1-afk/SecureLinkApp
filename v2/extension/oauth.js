const CLIENT_ID = "securelink-chrome-extension";

export function validateApiOrigin(value) {
  const api = new URL(value);
  if (api.username || api.password || api.search || api.hash || api.pathname !== "/") {
    throw new Error("The API origin is invalid.");
  }
  if (api.protocol !== "https:" && api.hostname !== "localhost") {
    throw new Error("SecureLink requires HTTPS outside localhost.");
  }
  return api;
}

export function randomBase64Url(byteLength = 32, cryptoApi = globalThis.crypto) {
  const bytes = cryptoApi.getRandomValues(new Uint8Array(byteLength));
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

export async function createPkcePair(cryptoApi = globalThis.crypto) {
  const verifier = randomBase64Url(48, cryptoApi);
  const digest = await cryptoApi.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
  return { verifier, challenge };
}

export function buildAuthorizationUrl(apiOrigin, redirectUri, state, challenge) {
  const url = new URL("/extension/authorize", validateApiOrigin(apiOrigin));
  url.search = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: redirectUri,
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  return url.href;
}

export function readAuthorizationCallback(callbackUrl, redirectUri, expectedState) {
  let callback;
  let expectedRedirect;
  try {
    callback = new URL(callbackUrl);
    expectedRedirect = new URL(redirectUri);
  } catch {
    throw new Error("SecureLink returned an invalid authorization address.");
  }
  if (callback.origin !== expectedRedirect.origin || callback.pathname !== expectedRedirect.pathname) {
    throw new Error("SecureLink returned an unexpected authorization address.");
  }
  if (callback.searchParams.getAll("state").length !== 1
      || callback.searchParams.get("state") !== expectedState) {
    throw new Error("Authorization state did not match. Please try again.");
  }
  if (callback.searchParams.has("error") || callback.searchParams.getAll("code").length !== 1) {
    throw new Error("SecureLink did not return an authorization code.");
  }
  const code = callback.searchParams.get("code");
  if (!code || code.length < 32 || code.length > 128) {
    throw new Error("SecureLink returned an invalid authorization code.");
  }
  return code;
}
