import assert from "node:assert/strict";
import test from "node:test";

import {
  createTabBypass,
  createWarningPageUrl,
  matchesTabBypass,
  warningBypassKey,
  warningIncidentKey,
} from "../warning-state.js";

const INCIDENT = "123e4567-e89b-42d3-a456-426614174000";

test("warning URL contains only a validated incident id", () => {
  const url = new URL(createWarningPageUrl("chrome-extension://abcdefghijklmnop/", INCIDENT));
  assert.equal(url.pathname, "/warning.html");
  assert.deepEqual([...url.searchParams.keys()], ["incident"]);
  assert.equal(url.searchParams.get("incident"), INCIDENT);
  assert.equal(warningIncidentKey(INCIDENT), `warningIncident_${INCIDENT}`);
  assert.throws(() => warningIncidentKey("https://secret.example/path"));
  assert.throws(() => createWarningPageUrl("https://example.test/", INCIDENT));
});

test("proceed bypass is short-lived and matches only its tab and exact destination", () => {
  const destination = "https://example.test/account?token=private";
  const bypass = createTabBypass(destination, 1000);
  assert.equal(warningBypassKey(17), "warningBypass_17");
  assert.equal(matchesTabBypass(bypass, destination, 9999), true);
  assert.equal(matchesTabBypass(bypass, "https://example.test/other", 9999), false);
  assert.equal(matchesTabBypass(bypass, destination, 11000), false);
  assert.throws(() => createTabBypass("javascript:alert(1)", 1000));
  assert.throws(() => warningBypassKey(-1));
});
