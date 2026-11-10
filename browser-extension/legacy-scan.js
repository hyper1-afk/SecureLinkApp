export function legacyScanFailure(message) {
  return { error: true, riskScore: 0, threats: [], message };
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
