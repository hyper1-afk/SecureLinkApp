import assert from "node:assert/strict";
import test from "node:test";

import { redactUrlForSubmission } from "../url-privacy.js";

test("removes credentials and fragments and masks sensitive query data", () => {
  const result = redactUrlForSubmission(
    "https://alice:secret@example.com/path?apiKey=private&next=https%3A%2F%2Fx.test&view=full#fragment",
  );
  assert.equal(result.url, "https://example.com/path?apiKey=%5BREDACTED%5D&next=%5BREDACTED%5D&view=full");
  assert.deepEqual(result.redactions, {
    credentials_removed: true,
    fragment_removed: true,
    sensitive_query_values_removed: 2,
  });
  for (const privateValue of ["alice", "secret", "private", "x.test", "fragment"]) {
    assert.equal(result.url.includes(privateValue), false);
  }
});

test("preserves ordinary and duplicate query parameters", () => {
  const result = redactUrlForSubmission("https://example.com/?tag=a&tag=b&session=x&session=y");
  const url = new URL(result.url);
  assert.deepEqual(url.searchParams.getAll("tag"), ["a", "b"]);
  assert.deepEqual(url.searchParams.getAll("session"), ["[REDACTED]", "[REDACTED]"]);
  assert.equal(result.redactions.sensitive_query_values_removed, 2);
});

test("rejects non-HTTP schemes", () => {
  assert.throws(() => redactUrlForSubmission("javascript:alert(1)"), /HTTP or HTTPS/);
});
