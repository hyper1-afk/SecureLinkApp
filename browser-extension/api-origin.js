export function validateApiOrigin(value) {
  let api;
  try {
    api = new URL(value);
  } catch {
    throw new Error("Enter a valid API origin.");
  }
  if (api.username || api.password || api.search || api.hash || api.pathname !== "/") {
    throw new Error("Enter only an API origin, without a path or credentials.");
  }
  if (api.protocol !== "https:" && !(api.protocol === "http:" && api.hostname === "localhost")) {
    throw new Error("HTTPS is required outside localhost.");
  }
  return api;
}

export function configuredApiOrigin(value, fallback = "") {
  if (typeof value !== "string" || !value.trim()) return fallback;
  try {
    return validateApiOrigin(value.trim()).origin;
  } catch {
    return "";
  }
}

export function requestApiOriginPermission(origin) {
  return new Promise((resolve) => {
    chrome.permissions.request({ origins: [`${origin}/*`] }, (granted) => {
      resolve(Boolean(granted) && !chrome.runtime.lastError);
    });
  });
}
