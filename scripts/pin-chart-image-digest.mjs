#!/usr/bin/env node

// Pins chart/sockguard/values.yaml's image.tag to
// `<appVersion>@sha256:<multi-arch manifest-list digest>` after a stable
// release publishes, the second stage of the two-stage flow RELEASING.md's
// Helm chart section describes. Every cut through v2.2.0 did this by hand
// (#430, #492); release-from-tag.yml's pin-chart-digest job runs this
// instead.
//
// It rewrites exactly the one `tag:` line inside the top-level `image:`
// block, and refuses anything it cannot prove is that: a digest that is not
// 64 lowercase hexadecimal characters, a version that disagrees with
// Chart.yaml's appVersion, a values file with no single image.tag line, and
// any existing tag other than the empty prepublication value, the bare
// appVersion, or the exact pin it was going to write.

import { readFileSync, writeFileSync } from "node:fs";
import { extractChartImageConfig } from "./chart-image-tag.mjs";

const DIGEST_PATTERN = /^(?:sha256:)?(?<hex>[0-9a-f]{64})$/u;
const VERSION_PATTERN = /^\d+\.\d+\.\d+$/u;

export function readChartAppVersion(source) {
  const match = String(source ?? "").match(/^appVersion:\s*"([^"]*)"\s*$/mu);
  if (!match) {
    throw new Error("Could not read appVersion from chart/sockguard/Chart.yaml");
  }
  return match[1];
}

export function normalizeDigest(digest) {
  const match = String(digest ?? "")
    .trim()
    .match(DIGEST_PATTERN);
  if (!match?.groups) {
    throw new Error(
      `Invalid manifest digest ${JSON.stringify(String(digest ?? ""))}: expected sha256: followed by 64 lowercase hexadecimal characters`,
    );
  }
  return `sha256:${match.groups.hex}`;
}

export function normalizeVersion(version) {
  const candidate = String(version ?? "")
    .trim()
    .replace(/^v/u, "");
  if (!VERSION_PATTERN.test(candidate)) {
    throw new Error(
      `Invalid release version ${JSON.stringify(String(version ?? ""))}: expected a stable X.Y.Z semver`,
    );
  }
  return candidate;
}

// The single `tag:` entry at the child indent of the top-level `image:`
// block. Anything else -- no match, or more than one -- is refused rather
// than guessed at, because the caller is about to rewrite whichever line
// this returns.
function locateImageTagLine(lines) {
  const found = [];
  let inImageBlock = false;
  let childIndent;

  for (const [index, line] of lines.entries()) {
    const content = line.trimStart();
    if (content === "" || content.startsWith("#")) {
      continue;
    }
    const indent = line.length - content.length;

    if (indent === 0) {
      inImageBlock = /^image\s*:/u.test(content);
      childIndent = undefined;
      continue;
    }
    if (!inImageBlock) {
      continue;
    }

    childIndent ??= indent;
    if (indent !== childIndent) {
      continue;
    }
    if (/^tag\s*:/u.test(content)) {
      found.push(index);
    }
  }

  if (found.length !== 1) {
    throw new Error(
      `Expected exactly one image.tag line in chart/sockguard/values.yaml, found ${found.length}`,
    );
  }
  return found[0];
}

export function pinChartImageTag({ values, appVersion, version, digest }) {
  const releaseVersion = normalizeVersion(version);
  const normalizedDigest = normalizeDigest(digest);

  if (releaseVersion !== appVersion) {
    throw new Error(
      `Refusing to pin ${releaseVersion}: chart/sockguard/Chart.yaml declares appVersion ${JSON.stringify(appVersion)}`,
    );
  }

  const desired = `${releaseVersion}@${normalizedDigest}`;
  const current = extractChartImageConfig(values);

  if (current.tag === desired) {
    return { values, changed: false, tag: desired };
  }
  if (current.tag !== "" && current.tag !== releaseVersion) {
    throw new Error(
      `Refusing to overwrite image.tag ${JSON.stringify(current.tag)}: expected the empty prepublication value, ${releaseVersion}, or ${desired}`,
    );
  }

  const lines = values.split("\n");
  const index = locateImageTagLine(lines);
  const line = lines[index];
  const indent = line.slice(0, line.length - line.trimStart().length);
  const rewritten = [...lines];
  rewritten[index] = `${indent}tag: "${desired}"`;
  const next = rewritten.join("\n");

  // Independent readback through the same parser the chart-image-pin
  // contract uses, so a rewrite that landed on the wrong line fails here
  // instead of being committed.
  const after = extractChartImageConfig(next);
  if (after.tag !== desired || after.repository !== current.repository) {
    throw new Error(`Rewrite did not produce the expected image pin: got ${JSON.stringify(after)}`);
  }

  return { values: next, changed: true, tag: desired };
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i];
    const value = argv[i + 1];
    if (!key.startsWith("--")) {
      continue;
    }
    if (value === undefined || value.startsWith("--")) {
      throw new Error(`Missing value for argument: ${key}`);
    }
    args[key.slice(2)] = value;
    i += 1;
  }
  return args;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const valuesPath = args.values ?? "chart/sockguard/values.yaml";
  const chartPath = args.chart ?? "chart/sockguard/Chart.yaml";

  if (!args.version) {
    throw new Error("--version is required");
  }
  if (!args.digest) {
    throw new Error("--digest is required");
  }

  const appVersion = readChartAppVersion(readFileSync(chartPath, "utf8"));
  const result = pinChartImageTag({
    values: readFileSync(valuesPath, "utf8"),
    appVersion,
    version: args.version,
    digest: args.digest,
  });

  if (!result.changed) {
    console.log(`${valuesPath}: image.tag is already ${result.tag} -- nothing to write`);
    return;
  }

  writeFileSync(valuesPath, result.values);
  console.log(`${valuesPath}: pinned image.tag to ${result.tag}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}
