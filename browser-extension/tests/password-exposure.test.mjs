import assert from "node:assert/strict";
import test from "node:test";
import { webcrypto } from "node:crypto";

import { checkPasswordExposure } from "../../static/js/password-exposure-check.mjs";

test("sends only the SHA-1 prefix and matches the suffix in the browser", async () => {
  let request;
  const result = await checkPasswordExposure("password", "/api/breach/password", {
    Authorization: "Bearer test-token",
  }, {
    cryptoApi: webcrypto,
    fetchApi: async (url, options) => {
      request = { url, options };
      return {
        ok: true,
        async json() {
          return {
            hash_suffixes: [
              { suffix: "1E4C9B93F3F0682250B6CF8331B7EE68FD8", count: 3 },
              { suffix: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", count: 0 },
            ],
          };
        },
      };
    },
  });

  assert.equal(result.breached, true);
  assert.equal(result.count, 3);
  assert.equal(request.url, "/api/breach/password");
  assert.deepEqual(JSON.parse(request.options.body), { prefix: "5BAA6" });
  assert.equal(request.options.body.includes("password"), false);
  assert.equal(request.options.body.includes("1E4C9B93F3F0682250B6CF8331B7EE68FD8"), false);
  assert.equal(request.options.headers.Authorization, "Bearer test-token");
  assert.equal(request.options.cache, "no-store");
  assert.equal(request.options.credentials, "omit");
});

test("returns a clean result when the suffix is not present", async () => {
  const result = await checkPasswordExposure("not-in-range", "/api/dark-web/password-check", {}, {
    cryptoApi: webcrypto,
    fetchApi: async () => ({ ok: true, async json() { return { hash_suffixes: [] }; } }),
  });
  assert.equal(result.breached, false);
  assert.equal(result.count, 0);
});

test("rejects external lookup endpoints", async () => {
  await assert.rejects(
    checkPasswordExposure("password", "//attacker.example/collect", {}, { cryptoApi: webcrypto }),
    /same-origin/,
  );
});
