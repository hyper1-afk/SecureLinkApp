import assert from "node:assert/strict";
import test from "node:test";

import { legacyScanFailure, normalizeLegacyScan, shouldSkipCloudScan } from "../legacy-scan.js";

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

test("does not send browser-internal, local, or non-public targets to the cloud", () => {
  for (const url of [
    "chrome://settings/",
    "file:///private/report.html",
    "javascript:alert(1)",
    "http://app.local/",
    "http://service.internal/",
    "http://127.4.5.6/",
    "http://10.2.3.4/",
    "http://172.20.1.2/",
    "http://192.168.1.20/",
    "http://169.254.2.1/",
    "http://[::1]/",
    "http://2130706433/",
    "not a URL",
  ]) {
    assert.equal(shouldSkipCloudScan(url), true, `${url} must remain local`);
  }
});

test("does not bypass automatic checks for popular or lookalike domains", () => {
  for (const url of [
    "https://www.google.com/",
    "https://securelinkapp.com/",
    "https://www.google.com.attacker.test/",
    "https://localhost.evil.test/",
    "http://localhost.evil.test/",
    "https://8.8.8.8/",
  ]) {
    assert.equal(shouldSkipCloudScan(url), false, `${url} should be eligible for scanning`);
  }
});
