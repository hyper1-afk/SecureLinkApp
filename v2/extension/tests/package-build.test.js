import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const extensionDirectory = resolve(fileURLToPath(new URL("..", import.meta.url)));
const packagingScript = resolve(extensionDirectory, "../scripts/package-extension.mjs");

test("packages a staging client with only its configured API origin", async (context) => {
  const temporaryDirectory = await mkdtemp(join(os.tmpdir(), "securelink-extension-"));
  context.after(() => rm(temporaryDirectory, { recursive: true, force: true }));
  const outputDirectory = join(temporaryDirectory, "package");
  const result = spawnSync(process.execPath, [
    packagingScript,
    "--api-origin",
    "https://staging.example.test",
    "--output",
    outputDirectory,
  ], { encoding: "utf8" });

  assert.equal(result.status, 0, result.stderr);
  const manifest = JSON.parse(await readFile(join(outputDirectory, "manifest.json"), "utf8"));
  const apiConfig = await readFile(join(outputDirectory, "api-config.js"), "utf8");
  const sourceManifest = JSON.parse(await readFile(join(extensionDirectory, "manifest.json"), "utf8"));

  assert.deepEqual(manifest.host_permissions, ["https://staging.example.test/*"]);
  assert.deepEqual(sourceManifest.host_permissions, ["http://localhost:8000/*"]);
  assert.equal(apiConfig, 'export const API_BASE_URL = "https://staging.example.test";\n');
});

test("rejects insecure remote API origins and output inside source", async (context) => {
  const temporaryDirectory = await mkdtemp(join(os.tmpdir(), "securelink-extension-"));
  context.after(() => rm(temporaryDirectory, { recursive: true, force: true }));
  const insecure = spawnSync(process.execPath, [
    packagingScript,
    "--api-origin",
    "http://staging.example.test",
    "--output",
    join(temporaryDirectory, "insecure"),
  ], { encoding: "utf8" });
  const insideSource = spawnSync(process.execPath, [
    packagingScript,
    "--api-origin",
    "https://staging.example.test",
    "--output",
    join(extensionDirectory, "generated"),
  ], { encoding: "utf8" });

  assert.notEqual(insecure.status, 0);
  assert.match(insecure.stderr, /requires HTTPS/);
  assert.notEqual(insideSource.status, 0);
  assert.match(insideSource.stderr, /cannot be inside/);
});


test("refuses to mix a package with files already in the output directory", async (context) => {
  const temporaryDirectory = await mkdtemp(join(os.tmpdir(), "securelink-extension-"));
  context.after(() => rm(temporaryDirectory, { recursive: true, force: true }));
  const outputDirectory = join(temporaryDirectory, "package");
  const sentinelPath = join(outputDirectory, "stale-file.js");
  await mkdir(outputDirectory);
  await writeFile(sentinelPath, "keep this file untouched");

  const result = spawnSync(process.execPath, [
    packagingScript,
    "--api-origin",
    "https://staging.example.test",
    "--output",
    outputDirectory,
  ], { encoding: "utf8" });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /must be empty/);
  assert.equal(await readFile(sentinelPath, "utf8"), "keep this file untouched");
});
