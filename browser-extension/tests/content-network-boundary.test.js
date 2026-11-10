import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const contentScript = await readFile(new URL("../content.js", import.meta.url), "utf8");
const serviceWorker = await readFile(new URL("../background.js", import.meta.url), "utf8");
const manifest = JSON.parse(await readFile(new URL("../manifest.json", import.meta.url), "utf8"));

test("content-script scanning delegates all network work to the service worker", () => {
  assert.match(contentScript, /chrome\.runtime\.sendMessage\(\{ action: 'checkUrl'/);
  assert.doesNotMatch(contentScript, /\bfetch\s*\(/);
});

test("the service worker redacts scan URLs and validates extension message senders", () => {
  assert.match(serviceWorker, /redactUrlForAutomaticScan\(url\)/);
  assert.match(serviceWorker, /extensionContentScriptSender\(sender\)/);
  assert.match(serviceWorker, /extensionPageSender\(sender\)/);
});

test("site-wide page access is user-initiated and the manifest avoids broad host grants", () => {
  assert.equal(manifest.host_permissions.includes("<all_urls>"), false);
  assert.deepEqual(manifest.host_permissions, ["https://securelinkapp.com/*"]);
  assert.equal(manifest.content_scripts, undefined);
  assert.ok(manifest.permissions.includes("activeTab"));
  assert.ok(manifest.permissions.includes("scripting"));
  assert.ok(manifest.optional_host_permissions.includes("https://*/*"));
  assert.match(serviceWorker, /scanCurrentPage\(\)/);
  assert.match(serviceWorker, /extensionPageSender\(sender\)/);
  assert.match(contentScript, /MAX_PAGE_LINK_SCANS = 25/);
  assert.doesNotMatch(contentScript, /addEventListener\(['"]mouseover['"]/);
  assert.doesNotMatch(contentScript, /chrome\.storage\.sync\.get/);
});
