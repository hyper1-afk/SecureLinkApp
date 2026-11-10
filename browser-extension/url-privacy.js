const SENSITIVE_QUERY_KEYS = new Set([
  "access_token", "auth", "authorization", "code", "continue", "email", "key",
  "next", "password", "redirect", "redirect_uri", "return", "returnto", "secret",
  "session", "sessionid", "token", "url",
]);

function isSensitiveQueryKey(key) {
  const normalized = key.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
  return SENSITIVE_QUERY_KEYS.has(normalized)
    || /(?:^|[_-])(auth|authorization|code|email|key|password|secret|session|token)(?:$|[_-])/.test(normalized);
}

export function redactUrlForSubmission(rawUrl) {
  const url = new URL(rawUrl);
  if (!new Set(["http:", "https:"]).has(url.protocol) || !url.hostname) {
    throw new Error("Enter an absolute HTTP or HTTPS link.");
  }
  const credentialsRemoved = Boolean(url.username || url.password);
  const fragmentRemoved = rawUrl.includes("#");
  url.username = "";
  url.password = "";
  url.hash = "";

  let sensitiveQueryValuesRemoved = 0;
  const sanitizedEntries = [];
  for (const [key, value] of url.searchParams) {
    if (isSensitiveQueryKey(key)) {
      sensitiveQueryValuesRemoved += 1;
      sanitizedEntries.push([key, "[REDACTED]"]);
    } else {
      sanitizedEntries.push([key, value]);
    }
  }
  url.search = new URLSearchParams(sanitizedEntries).toString();
  return {
    url: url.href,
    redactions: {
      credentials_removed: credentialsRemoved,
      fragment_removed: fragmentRemoved,
      sensitive_query_values_removed: sensitiveQueryValuesRemoved,
    },
  };
}

export function redactUrlForAutomaticScan(rawUrl) {
  const result = redactUrlForSubmission(rawUrl);
  const url = new URL(result.url);
  url.search = new URLSearchParams(
    [...url.searchParams.keys()].map((key) => [key, "[REDACTED]"]),
  ).toString();
  return url.href;
}
