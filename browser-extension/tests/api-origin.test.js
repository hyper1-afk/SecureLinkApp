import assert from "node:assert/strict";
import test from "node:test";

import { configuredApiOrigin, requestApiOriginPermission, validateApiOrigin } from "../api-origin.js";

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

test("requests permission only for the configured API origin and reports denial", async () => {
  const originalChrome = globalThis.chrome;
  const requests = [];
  globalThis.chrome = {
    permissions: {
      request(options, callback) {
        requests.push(options);
        callback(requests.length === 1);
      },
    },
    runtime: {},
  };
  try {
    assert.equal(await requestApiOriginPermission("https://api.example.test"), true);
    assert.equal(await requestApiOriginPermission("http://localhost:8000"), false);
    assert.deepEqual(requests, [
      { origins: ["https://api.example.test/*"] },
      { origins: ["http://localhost:8000/*"] },
    ]);
  } finally {
    if (originalChrome === undefined) delete globalThis.chrome;
    else globalThis.chrome = originalChrome;
  }
});
