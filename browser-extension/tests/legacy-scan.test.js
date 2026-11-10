import assert from "node:assert/strict";
import test from "node:test";

import { legacyScanFailure, normalizeLegacyScan } from "../legacy-scan.js";

test("an explicit unsafe verdict cannot become a low-risk result", () => {
  const result = normalizeLegacyScan({ is_safe: false, risk_score: 0, threats_detected: ["phishing"] });
  assert.equal(result.isSafe, false);
  assert.equal(result.riskScore, 50);
  assert.deepEqual(result.threats, ["phishing"]);
});

test("normalizes fractional scores and leaves missing verdicts unknown", () => {
  const result = normalizeLegacyScan({ risk_score: 0.42, warnings: ["redirect"] });
  assert.equal(result.riskScore, 42);
  assert.equal(result.isSafe, null);
  assert.deepEqual(result.warnings, ["redirect"]);
});

test("clamps scores and marks invalid payloads as unavailable", () => {
  assert.equal(normalizeLegacyScan({ risk_score: 1000 }).riskScore, 100);
  assert.equal(normalizeLegacyScan({ risk_score: "invalid" }).riskScore, 0);
  assert.equal(normalizeLegacyScan(null).error, true);
  assert.equal(legacyScanFailure("offline").error, true);
});
