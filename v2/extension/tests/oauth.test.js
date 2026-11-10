import assert from "node:assert/strict";
import test from "node:test";
import { webcrypto } from "node:crypto";

import {
  buildAuthorizationUrl,
  createPkcePair,
  readAuthorizationCallback,
  validateApiOrigin,
} from "../oauth.js";

const redirectUri = "https://abcdefghijklmnopabcdefghijklmnop.chromiumapp.org/";
const state = "a".repeat(43);
const code = "c".repeat(43);

test("creates an RFC 7636 S256 verifier and challenge", async () => {
  const { verifier, challenge } = await createPkcePair(webcrypto);
  assert.match(verifier, /^[A-Za-z0-9_-]{64}$/);
  assert.match(challenge, /^[A-Za-z0-9_-]{43}$/);
  const digest = await webcrypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  const expected = Buffer.from(digest).toString("base64url");
  assert.equal(challenge, expected);
});

test("accepts HTTPS API origins and local development only", () => {
  assert.equal(validateApiOrigin("https://staging.example.test").origin, "https://staging.example.test");
  assert.equal(validateApiOrigin("http://localhost:8000").port, "8000");
  assert.throws(() => validateApiOrigin("http://staging.example.test"), /requires HTTPS/);
  assert.throws(() => validateApiOrigin("https://user:pass@example.test"), /API origin is invalid/);
  assert.throws(() => validateApiOrigin("https://example.test/api"), /API origin is invalid/);
});

test("builds a first-party authorization URL with the exact callback and S256", () => {
  const url = new URL(buildAuthorizationUrl("https://staging.example.test", redirectUri, state, "b".repeat(43)));
  assert.equal(url.origin, "https://staging.example.test");
  assert.equal(url.pathname, "/extension/authorize");
  assert.equal(url.searchParams.get("client_id"), "securelink-chrome-extension");
  assert.equal(url.searchParams.get("redirect_uri"), redirectUri);
  assert.equal(url.searchParams.get("state"), state);
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
});

test("accepts a callback only when origin, path, state, and code are valid", () => {
  const callback = `${redirectUri}?code=${code}&state=${state}`;
  assert.equal(readAuthorizationCallback(callback, redirectUri, state), code);
  assert.throws(() => readAuthorizationCallback(callback, redirectUri, "d".repeat(43)), /state/);
  assert.throws(() => readAuthorizationCallback(callback, "https://different.chromiumapp.org/", state), /unexpected/);
  assert.throws(() => readAuthorizationCallback(`${redirectUri}?code=${code}`, redirectUri, state), /state/);
  assert.throws(() => readAuthorizationCallback(`${redirectUri}?code=${code}&code=${code}&state=${state}`, redirectUri, state), /authorization code/);
  assert.throws(() => readAuthorizationCallback(`${redirectUri}?error=access_denied&state=${state}`, redirectUri, state), /authorization code/);
});
