import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { validateApiOrigin } from "../extension/oauth.js";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const extensionDirectory = resolve(scriptDirectory, "../extension");
const extensionFiles = [
  "manifest.json",
  "popup.html",
  "popup.css",
  "popup.js",
  "service-worker.js",
  "oauth.js",
  "url-privacy.js",
];

function parseArguments(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument !== "--api-origin" && argument !== "--output") {
      throw new Error(`Unknown option: ${argument}`);
    }
    const value = args[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`Missing value for ${argument}`);
    const key = argument === "--api-origin" ? "apiOrigin" : "output";
    if (options[key]) throw new Error(`Duplicate option: ${argument}`);
    options[key] = value;
    index += 1;
  }
  if (!options.apiOrigin) {
    throw new Error("Usage: npm run package -- --api-origin <HTTPS-origin> [--output <directory>]");
  }
  return options;
}

async function packageExtension(args = process.argv.slice(2)) {
  const options = parseArguments(args);
  const api = validateApiOrigin(options.apiOrigin);
  const outputDirectory = options.output
    ? resolve(process.cwd(), options.output)
    : resolve(scriptDirectory, "../dist/extension");
  const outputRelativeToSource = relative(extensionDirectory, outputDirectory);
  if (!outputRelativeToSource || (outputRelativeToSource !== ".."
      && !outputRelativeToSource.startsWith(`..${sep}`))) {
    throw new Error("The output directory cannot be inside the source extension directory.");
  }
  const manifest = JSON.parse(await readFile(resolve(extensionDirectory, "manifest.json"), "utf8"));
  manifest.host_permissions = [`${api.origin}/*`];

  await mkdir(outputDirectory, { recursive: true });
  if ((await readdir(outputDirectory)).length > 0) {
    throw new Error("The output directory must be empty; choose a new package directory.");
  }
  for (const filename of extensionFiles) {
    const source = resolve(extensionDirectory, filename);
    const destination = resolve(outputDirectory, filename);
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, await readFile(source));
  }
  await writeFile(resolve(outputDirectory, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  await writeFile(
    resolve(outputDirectory, "api-config.js"),
    `export const API_BASE_URL = ${JSON.stringify(api.origin)};\n`,
  );
  return { outputDirectory, apiOrigin: api.origin };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = await packageExtension();
    process.stdout.write(`Packaged SecureLink extension for ${result.apiOrigin}\n${result.outputDirectory}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "Packaging failed."}\n`);
    process.exitCode = 1;
  }
}

export { packageExtension };
