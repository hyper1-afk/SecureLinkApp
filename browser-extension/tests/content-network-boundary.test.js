import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const contentScript = await readFile(new URL("../content.js", import.meta.url), "utf8");
const serviceWorker = await readFile(new URL("../background.js", import.meta.url), "utf8");

test("content-script scanning delegates all network work to the service worker", () => {
  assert.match(contentScript, /chrome\.runtime\.sendMessage\(\{ action: 'checkUrl'/);
  assert.doesNotMatch(contentScript, /\bfetch\s*\(/);
});

test("the service worker redacts scan URLs and validates extension message senders", () => {
  assert.match(serviceWorker, /redactUrlForAutomaticScan\(url\)/);
  assert.match(serviceWorker, /extensionContentScriptSender\(sender\)/);
  assert.match(serviceWorker, /extensionPageSender\(sender\)/);
});
