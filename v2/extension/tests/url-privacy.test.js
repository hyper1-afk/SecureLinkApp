import assert from "node:assert/strict";
import test from "node:test";

import { redactUrlForSubmission } from "../url-privacy.js";

test("removes user information and fragments before the request", () => {
  const result = redactUrlForSubmission(
    "https://alice:password@example.com/path?view=full#private-fragment",
  );
  assert.equal(result.url, "https://example.com/path?view=full");
  assert.deepEqual(result.redactions, {
    credentials_removed: true,
    fragment_removed: true,
    sensitive_query_values_removed: 0,
  });
  assert.equal(result.url.includes("alice"), false);
  assert.equal(result.url.includes("password"), false);
  assert.equal(result.url.includes("private-fragment"), false);
});

test("redacts sensitive values while preserving keys and ordinary query values", () => {
  const result = redactUrlForSubmission(
    "https://example.com/?session=abc&next=https%3A%2F%2Fprivate.test&color=blue&email=me%40example.com",
  );
  const url = new URL(result.url);
  assert.deepEqual(url.searchParams.getAll("session"), ["[REDACTED]"]);
  assert.deepEqual(url.searchParams.getAll("next"), ["[REDACTED]"]);
  assert.deepEqual(url.searchParams.getAll("email"), ["[REDACTED]"]);
  assert.deepEqual(url.searchParams.getAll("color"), ["blue"]);
  assert.equal(result.redactions.sensitive_query_values_removed, 3);
  assert.equal(result.url.includes("private.test"), false);
  assert.equal(result.url.includes("me%40example.com"), false);
});

test("keeps duplicate parameters and redacts each sensitive value", () => {
  const result = redactUrlForSubmission("https://example.com/?token=one&token=two&tag=a&tag=b");
  const url = new URL(result.url);
  assert.deepEqual(url.searchParams.getAll("token"), ["[REDACTED]", "[REDACTED]"]);
  assert.deepEqual(url.searchParams.getAll("tag"), ["a", "b"]);
  assert.equal(result.redactions.sensitive_query_values_removed, 2);
});

test("rejects non-HTTP schemes", () => {
  assert.throws(() => redactUrlForSubmission("javascript:alert(1)"), /HTTP or HTTPS/);
});
