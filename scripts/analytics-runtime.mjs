import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const RUNTIME_FILES = ["analytics-contract.ts", "analytics-client.ts", "analytics.ts"];

function run() {
  const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
  let stale = false;

  for (const filename of RUNTIME_FILES) {
    const source = join(repoRoot, "website", "src", "lib", filename);
    const target = join(repoRoot, "docs", "src", "lib", filename);
    const expected = readFileSync(source, "utf8");

    if (process.argv.includes("--check")) {
      if (!existsSync(target) || readFileSync(target, "utf8") !== expected) stale = true;
    } else {
      writeFileSync(target, expected);
    }
  }

  if (stale) {
    console.error("Analytics runtimes are stale. Run: npm run sync:analytics-runtime");
    process.exitCode = 1;
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) run();
