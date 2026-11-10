export function legacyScanFailure(message) {
  return { error: true, riskScore: 0, threats: [], message };
}

function isNonPublicIpv4(hostname) {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname)) return false;
  const octets = hostname.split(".").map(Number);
  if (octets.some((octet) => octet > 255)) return false;
  const [a, b, c] = octets;
  return a === 0 || a === 10 || a === 127 || a >= 224
    || (a === 100 && b >= 64 && b <= 127)
    || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && (b === 168 || (b === 0 && c === 0) || (b === 0 && c === 2) || (b === 88 && c === 99)))
    || (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100)) )
    || (a === 203 && b === 0 && c === 113);
}

export function shouldSkipCloudScan(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return true;
  }
  if (!new Set(["http:", "https:"]).has(url.protocol) || !url.hostname) return true;

  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  if (hostname === "localhost" || hostname.endsWith(".localhost")
      || hostname.endsWith(".local") || hostname.endsWith(".internal")) return true;
  if (hostname.startsWith("[") && hostname.endsWith("]")) return true;
  return isNonPublicIpv4(hostname);
}

export function normalizeLegacyScan(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return legacyScanFailure("Legacy scanner returned an invalid response.");
  }
  const rawScore = Number(data.risk_score);
  let riskScore = Number.isFinite(rawScore) ? rawScore : 0;
  if (riskScore <= 1) riskScore = Math.round(riskScore * 100);
  riskScore = Math.max(0, Math.min(100, riskScore));

  const threats = Array.isArray(data.threats_detected)
    ? data.threats_detected
    : Array.isArray(data.threats) ? data.threats : [];
  const warnings = Array.isArray(data.warnings) ? data.warnings : [];
  const isSafe = typeof data.is_safe === "boolean" ? data.is_safe : null;
  // Preserve an explicit unsafe verdict even when its score is absent or malformed.
  if (isSafe === false) riskScore = Math.max(50, riskScore);

  return {
    riskScore,
    threats,
    warnings,
    isSafe,
    scansRemaining: data.scans_remaining,
    subscriptionTier: data.subscription_tier,
    message: typeof data.message === "string" ? data.message : "",
  };
}
