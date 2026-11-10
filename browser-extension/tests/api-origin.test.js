import assert from "node:assert/strict";
import test from "node:test";

import { configuredApiOrigin, validateApiOrigin } from "../api-origin.js";

test("accepts HTTPS API origins and localhost development", () => {
  assert.equal(validateApiOrigin("https://api.example.test").origin, "https://api.example.test");
  assert.equal(validateApiOrigin("http://localhost:8000").origin, "http://localhost:8000");
});

test("falls back only for an unset custom origin and disables malformed saved values", () => {
  assert.equal(configuredApiOrigin("", "https://securelinkapp.com"), "https://securelinkapp.com");
  assert.equal(configuredApiOrigin(undefined, ""), "");
  assert.equal(configuredApiOrigin("http://api.example.test", "https://securelinkapp.com"), "");
});

test("rejects API origins that can expose credentials or target an unexpected endpoint", () => {
  for (const value of [
    "http://api.example.test",
    "http://127.0.0.1:8000",
    "ftp://localhost",
    "https://user:pass@example.test",
    "https://example.test/api",
    "https://example.test/?token=x",
    "https://example.test/#fragment",
  ]) {
    assert.throws(() => validateApiOrigin(value), `${value} should be rejected`);
  }
});
