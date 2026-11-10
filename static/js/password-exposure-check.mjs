const HASH_SUFFIX = /^[A-F0-9]{35}$/;

export async function checkPasswordExposure(password, endpoint, headers = {}, options = {}) {
  if (typeof password !== "string" || password.length === 0) {
    throw new Error("Enter a password to check.");
  }
  if (typeof endpoint !== "string" || !endpoint.startsWith("/") || endpoint.startsWith("//")
      || endpoint.includes("\\")) {
    throw new Error("Password lookup endpoint must be same-origin.");
  }

  const cryptoApi = options.cryptoApi ?? globalThis.crypto;
  const fetchApi = options.fetchApi ?? globalThis.fetch;
  if (!cryptoApi?.subtle || typeof fetchApi !== "function") {
    throw new Error("This browser cannot run a private password check.");
  }

  const passwordBytes = new TextEncoder().encode(password);
  password = "";
  let digest;
  try {
    digest = await cryptoApi.subtle.digest("SHA-1", passwordBytes);
  } finally {
    passwordBytes.fill(0);
  }

  let hash = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  hash = "";

  const response = await fetchApi(endpoint, {
    method: "POST",
    headers: { ...headers, "Content-Type": "application/json" },
    body: JSON.stringify({ prefix }),
    cache: "no-store",
    credentials: "omit",
  });

  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error("Password lookup returned an invalid response.");
  }
  if (!response.ok) {
    throw new Error(payload?.error || "Password lookup is temporarily unavailable.");
  }
  if (!Array.isArray(payload.hash_suffixes)) {
    throw new Error("Password lookup returned an invalid response.");
  }

  const match = payload.hash_suffixes.find((entry) =>
    entry && typeof entry.suffix === "string" && HASH_SUFFIX.test(entry.suffix.toUpperCase())
      && entry.suffix.toUpperCase() === suffix
      && Number.isSafeInteger(entry.count) && entry.count > 0,
  );
  const count = match ? match.count : 0;
  return { breached: count > 0, is_compromised: count > 0, count, times_seen: count };
}
