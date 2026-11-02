#!/usr/bin/env node

// Gate for release-from-tag.yml's publish-chart job. Given the Chart.yaml and
// values.yaml read back out of the packaged chart, it proves the artifact
// about to be pushed to ghcr.io is the one the release contract describes:
// chart version == appVersion == the tag (without the `v`), and image.tag is
// `<version>@<the multi-arch manifest-list digest the release published>`.
// A chart that falls back to a mutable tag, or one pinned to a different
// digest than the image this pipeline pushed, fails before anything is pushed.

import { readFileSync } from "node:fs";
import { extractChartImageConfig } from "./chart-image-tag.mjs";
import {
  normalizeDigest,
  normalizeVersion,
  readChartAppVersion,
} from "./pin-chart-image-digest.mjs";

export function readChartVersion(source) {
  const match = String(source ?? "").match(/^version:\s*"?([^"\s]+)"?\s*$/mu);
  if (!match) {
    throw new Error("Could not read version from Chart.yaml");
  }
  return match[1];
}

export function assertChartRelease({ chart, values, tag, digest }) {
  const version = normalizeVersion(tag);
  const pinnedDigest = normalizeDigest(digest);

  const chartVersion = readChartVersion(chart);
  const appVersion = readChartAppVersion(chart);
  if (chartVersion !== version || appVersion !== version) {
    throw new Error(
      `Chart version ${JSON.stringify(chartVersion)} and appVersion ${JSON.stringify(appVersion)} must both equal the tag version ${JSON.stringify(version)}`,
    );
  }

  const expected = `${version}@${pinnedDigest}`;
  const { tag: imageTag } = extractChartImageConfig(values);
  if (imageTag !== expected) {
    throw new Error(
      `Chart image.tag is ${JSON.stringify(imageTag)}; expected the immutable pin ${JSON.stringify(expected)}`,
    );
  }
  return { version, imageTag };
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    const value = argv[i + 1];
    if (!key.startsWith("--") || value === undefined || value.startsWith("--")) {
      throw new Error(`Missing value for argument: ${key}`);
    }
    args[key.slice(2)] = value;
  }
  return args;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  for (const required of ["tag", "digest", "chart", "values"]) {
    if (!args[required]) {
      throw new Error(`--${required} is required`);
    }
  }
  const result = assertChartRelease({
    chart: readFileSync(args.chart, "utf8"),
    values: readFileSync(args.values, "utf8"),
    tag: args.tag,
    digest: args.digest,
  });
  console.log(`Chart ${result.version} pins image.tag ${result.imageTag}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}
