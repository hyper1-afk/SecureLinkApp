import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const manifest = JSON.parse(await readFile(new URL("../manifest.json", import.meta.url), "utf8"));
const popup = await readFile(new URL("../popup.js", import.meta.url), "utf8");
const serviceWorker = await readFile(new URL("../service-worker.js", import.meta.url), "utf8");

test("identity permission is optional and requested for the connect action", () => {
  assert.equal(manifest.permissions.includes("identity"), false);
  assert.ok(manifest.optional_permissions.includes("identity"));
  assert.match(popup, /permissions\.request\(\{ permissions: \["identity"\] \}/);
  assert.match(popup, /permissions\.remove\(\{ permissions: \["identity"\] \}/);
});

test("extension messages are accepted only from its own popup page", () => {
  assert.match(serviceWorker, /sender\.url === chrome\.runtime\.getURL\("popup\.html"\)/);
  assert.match(serviceWorker, /if \(!isPopupSender\(sender\)\)/);
});
