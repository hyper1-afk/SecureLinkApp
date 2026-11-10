import assert from "node:assert/strict";
import test from "node:test";

import {
  configuredApiOrigin,
  removeApiOriginPermission,
  requestApiOriginPermission,
  validateApiOrigin,
} from "../api-origin.js";

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


test("removes only an optional permission for the previous API origin", async () => {
  const originalChrome = globalThis.chrome;
  const calls = [];
  globalThis.chrome = {
    permissions: {
      contains(options, callback) {
        calls.push(["contains", options]);
        callback(true);
      },
      remove(options, callback) {
        calls.push(["remove", options]);
        callback(true);
      },
    },
    runtime: {
      getManifest: () => ({ host_permissions: ["https://securelinkapp.com/*"] }),
    },
  };
  try {
    assert.equal(await removeApiOriginPermission("https://staging.example.test"), true);
    assert.deepEqual(calls, [
      ["contains", { origins: ["https://staging.example.test/*"] }],
      ["remove", { origins: ["https://staging.example.test/*"] }],
    ]);
    assert.equal(await removeApiOriginPermission("https://securelinkapp.com"), true);
    assert.equal(calls.length, 2);
  } finally {
    if (originalChrome === undefined) delete globalThis.chrome;
    else globalThis.chrome = originalChrome;
  }
});

test("does not claim success if an old optional origin cannot be revoked", async () => {
  const originalChrome = globalThis.chrome;
  globalThis.chrome = {
    permissions: {
      contains(_options, callback) { callback(true); },
      remove(_options, callback) { callback(false); },
    },
    runtime: { getManifest: () => ({ host_permissions: [] }) },
  };
  try {
    assert.equal(await removeApiOriginPermission("https://old-staging.example.test"), false);
  } finally {
    if (originalChrome === undefined) delete globalThis.chrome;
    else globalThis.chrome = originalChrome;
  }
});
