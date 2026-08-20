#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

// Match on package + path only, not pinned versions: Next vendors its own
// postcss under next/node_modules and the workspaces hoist a newer one, so
// npm dedupe always reports this churn. Hardcoding the versions here meant
// every postcss bump silently broke the guard until the literals were
// updated by hand.
export function isIgnoredPostcssOverrideDrift(entry) {
  const from = entry.from ?? entry;
  const to = entry.to ?? entry;
  const postcssOverridePath = "/node_modules/next/node_modules/postcss";
  const workspacePostcssPaths = ["/docs/node_modules/postcss", "/website/node_modules/postcss"];
  const isNextOverrideDowngrade =
    from.name === "postcss" &&
    to.name === "postcss" &&
    from.path?.endsWith(postcssOverridePath) &&
    to.path?.endsWith(postcssOverridePath);
  const isWorkspacePostcssHoist =
    entry.name === "postcss" && workspacePostcssPaths.some((path) => entry.path?.endsWith(path));
  return isNextOverrideDowngrade || isWorkspacePostcssHoist;
}

export function collectDrift(report, { ignorePostcss }) {
  const entries = [...(report.add ?? []), ...(report.remove ?? []), ...(report.change ?? [])];
  return ignorePostcss ? entries.filter((entry) => !isIgnoredPostcssOverrideDrift(entry)) : entries;
}

// The postcss allowance only ever applies to the dedupe report, never to the
// install report. It exists because npm dedupe always reports the postcss
// hoisting churn described above, which is a dedupe artifact, not an install
// delta -- npm install --dry-run against an in-sync tree reports nothing at
// all (verified). Filtering the install probe too would risk masking a
// genuinely missing vendored copy.
export function classify({ installReport, dedupeReport }) {
  const staleInstallEntries = collectDrift(installReport, { ignorePostcss: false });
  if (staleInstallEntries.length > 0) {
    // A stale install makes the dedupe report meaningless: it would just be
    // diffing a dedupe against node_modules that's already wrong. Report the
    // install problem alone and stop, even if dedupeReport also has entries.
    return { kind: "stale-install", entries: staleInstallEntries };
  }

  const dedupeEntries = collectDrift(dedupeReport, { ignorePostcss: true });
  if (dedupeEntries.length > 0) {
    return { kind: "lockfile-drift", entries: dedupeEntries };
  }

  return { kind: "ok", entries: [] };
}

// npm prefixes JSON output with lifecycle-script noise (deprecation
// warnings, etc), so the JSON payload doesn't start at offset 0. Find the
// first "{" and parse from there.
export function parseNpmJson(text) {
  const jsonStart = text.indexOf("{");
  if (jsonStart === -1) {
    throw new Error(`npm produced no JSON output:\n${text}`);
  }

  try {
    return JSON.parse(text.slice(jsonStart));
  } catch (error) {
    throw new Error(`npm produced malformed JSON output: ${error.message}\n${text}`);
  }
}

function formatEntry(entry) {
  const from = entry.from ?? entry;
  const to = entry.to ?? entry;
  const name = to.name ?? from.name;
  const path = to.path ?? from.path;
  const versions = from.version === to.version ? to.version : `${from.version} -> ${to.version}`;
  return `  ${name} (${path}) ${versions}`;
}

const repoRoot = resolve(import.meta.dirname, "..");

function runNpmJson(args) {
  // npm exits non-zero in some of these cases while still emitting usable
  // JSON, so don't treat a non-zero exit as fatal here -- parse first and
  // let parseNpmJson decide whether the output is usable.
  const result = spawnSync("npm", args, { cwd: repoRoot, encoding: "utf8" });
  const stdout = result.stdout ?? "";
  const stderr = result.stderr ?? "";
  try {
    // stdout alone, not stdout+stderr: --json puts the report on stdout, and
    // parseNpmJson keys off the first "{" it sees. An npm warning containing
    // a brace would otherwise be parsed as the report.
    return parseNpmJson(stdout);
  } catch (error) {
    throw new Error(`${error.message}\n--- npm stderr ---\n${stderr}`);
  }
}

function printResult(result) {
  if (result.kind === "stale-install") {
    console.error(
      "Installed node_modules doesn't match package-lock.json. That's an environment\n" +
        "problem, not lockfile drift — run `npm ci`.",
    );
    for (const entry of result.entries) {
      console.error(formatEntry(entry));
    }
    console.error(
      '\nIf `npm ci` refuses with "lock file does not satisfy", package.json and\n' +
        "package-lock.json genuinely disagree: run `npm install` and commit the lockfile.",
    );
  } else if (result.kind === "lockfile-drift") {
    console.error("Lockfile drift detected — run 'npm dedupe' and commit the result:");
    for (const entry of result.entries) {
      console.error(formatEntry(entry));
    }
  }
}

function main() {
  const installReport = runNpmJson([
    "install",
    "--dry-run",
    "--json",
    "--no-audit",
    "--no-fund",
    "--ignore-scripts",
  ]);

  // Classify against an empty dedupe report first, so the short-circuit lives
  // only in classify() and the second npm probe is skipped when the install is
  // already known stale.
  const installOnly = classify({ installReport, dedupeReport: {} });
  if (installOnly.kind === "stale-install") {
    printResult(installOnly);
    process.exitCode = 1;
    return;
  }

  const dedupeReport = runNpmJson(["dedupe", "--dry-run", "--json"]);
  const result = classify({ installReport, dedupeReport });

  printResult(result);
  process.exitCode = result.kind === "ok" ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
