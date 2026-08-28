#!/usr/bin/env node
/**
 * Fails a release when the pushed/computed tag disagrees with the
 * release-facing metadata files at that commit.
 *
 * scripts/release-metadata.test.mjs already asserts the website version,
 * Helm chart version/appVersion, empty prepublication image pin, README banner,
 * and CHANGELOG heading agree
 * with EACH OTHER -- it never reads the tag actually being released. All
 * four files can agree with each other while being stale relative to what's
 * being tagged: that's exactly how v1.7.1 shipped claiming 1.7.0 (#304).
 * This script closes that gap by comparing the tag itself against the same
 * files.
 *
 * Stable tags (vX.Y.Z) require exact agreement: SITE_CONFIG.version, the
 * Helm chart's version and appVersion, an empty prepublication image pin, and
 * a dated CHANGELOG heading.
 *
 * Prerelease tags (vX.Y.Z-rc.N) are cut while the website/chart still show
 * the current *stable* version -- that's correct, not stale, since the
 * prerelease isn't the released version yet. Only the CHANGELOG heading is
 * required to exist for a prerelease tag, matching what release-cut.yml's
 * "Validate CHANGELOG entry for release tag" step already enforces.
 */
import { readFileSync } from "node:fs";
import { extractChartImageConfig, extractChartImageTag } from "./chart-image-tag.mjs";
import { extractChangelogEntry } from "./extract-changelog-entry.mjs";

export { extractChartImageTag };

const STABLE_VERSION_PATTERN = /^\d+\.\d+\.\d+$/u;
const TAG_PATTERN = /^v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)$/u;
const EXPECTED_CHART_IMAGE_REPOSITORY = "codeswhat/sockguard";

export function normalizeTag(tag) {
  const match = String(tag ?? "")
    .trim()
    .match(TAG_PATTERN);
  if (!match) {
    throw new Error(`Invalid tag '${tag}'. Expected vMAJOR.MINOR.PATCH[-prerelease].`);
  }
  return match[1];
}

export function extractSiteConfigVersion(source) {
  const match = String(source ?? "").match(/^\s*version:\s*"([^"]+)",?\s*$/mu);
  if (!match) {
    throw new Error("Could not find SITE_CONFIG.version in website/src/lib/site-config.ts");
  }
  return match[1];
}

export function extractChartVersions(source) {
  const content = String(source ?? "");
  const version = content.match(/^version:\s*(\S+)\s*$/mu);
  const appVersion = content.match(/^appVersion:\s*"([^"]+)"\s*$/mu);
  if (!version || !appVersion) {
    throw new Error("Could not find version/appVersion in chart/sockguard/Chart.yaml");
  }
  return { version: version[1], appVersion: appVersion[1] };
}

/**
 * Pure check: compares a tag against the release-facing file contents.
 * Returns { version, isPrerelease, errors }. Never throws for a metadata
 * mismatch -- errors accumulate so a caller can report every disagreement
 * at once instead of failing on the first one found. Still throws for a
 * malformed tag or unparseable file, since those aren't "the tag disagrees
 * with reality", they're "this script can't tell".
 */
export function checkTagReleaseMetadata({ tag, siteConfig, chart, values, changelog }) {
  const version = normalizeTag(tag);
  const isPrerelease = !STABLE_VERSION_PATTERN.test(version);
  const errors = [];

  if (isPrerelease) {
    try {
      extractChangelogEntry(changelog, version);
    } catch (error) {
      errors.push(
        `CHANGELOG.md has no dated heading for prerelease tag v${version}: ${error.message}`,
      );
    }
    return { version, isPrerelease, errors };
  }

  const siteVersion = extractSiteConfigVersion(siteConfig);
  if (siteVersion !== version) {
    errors.push(
      `website/src/lib/site-config.ts SITE_CONFIG.version is '${siteVersion}', tag is 'v${version}'.`,
    );
  }

  const { version: chartVersion, appVersion: chartAppVersion } = extractChartVersions(chart);
  if (chartVersion !== version) {
    errors.push(`chart/sockguard/Chart.yaml version is '${chartVersion}', tag is 'v${version}'.`);
  }
  if (chartAppVersion !== version) {
    errors.push(
      `chart/sockguard/Chart.yaml appVersion is '${chartAppVersion}', tag is 'v${version}'.`,
    );
  }

  const chartImage = extractChartImageConfig(values);
  if (chartImage.repository !== EXPECTED_CHART_IMAGE_REPOSITORY) {
    errors.push(
      `chart/sockguard/values.yaml image.repository must be '${EXPECTED_CHART_IMAGE_REPOSITORY}'; found '${chartImage.repository}'.`,
    );
  }
  if (chartImage.tag !== "") {
    errors.push(
      `chart/sockguard/values.yaml image.tag must be empty before stable tag v${version} is created; found '${chartImage.tag}'.`,
    );
  }

  try {
    extractChangelogEntry(changelog, version);
  } catch (error) {
    errors.push(`CHANGELOG.md has no dated heading for tag v${version}: ${error.message}`);
  }

  return { version, isPrerelease, errors };
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i];
    if (!key.startsWith("--")) {
      continue;
    }
    const value = argv[i + 1];
    if (value === undefined || value.startsWith("--")) {
      throw new Error(`Missing value for argument: ${key}`);
    }
    args[key.slice(2)] = value;
    i += 1;
  }
  return args;
}

export function formatCLIError(error) {
  return error instanceof Error ? error.message : String(error);
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const tag = args.tag;
  if (!tag) {
    throw new Error("--tag is required");
  }

  const siteConfigPath = args["site-config"] ?? "website/src/lib/site-config.ts";
  const chartPath = args.chart ?? "chart/sockguard/Chart.yaml";
  const valuesPath = args.values ?? "chart/sockguard/values.yaml";
  const changelogPath = args.changelog ?? "CHANGELOG.md";

  const siteConfig = readFileSync(siteConfigPath, "utf8");
  const chart = readFileSync(chartPath, "utf8");
  const values = readFileSync(valuesPath, "utf8");
  const changelog = readFileSync(changelogPath, "utf8");

  const { version, isPrerelease, errors } = checkTagReleaseMetadata({
    tag,
    siteConfig,
    chart,
    values,
    changelog,
  });

  if (errors.length > 0) {
    throw new Error(
      [
        `Tag v${version} disagrees with release metadata (${errors.length} mismatch${errors.length === 1 ? "" : "es"}):`,
        ...errors.map((error) => `  - ${error}`),
      ].join("\n"),
    );
  }

  console.log(
    isPrerelease
      ? `Tag v${version} is a prerelease; CHANGELOG heading present.`
      : `Tag v${version} agrees with website, chart, Helm image, and CHANGELOG metadata.`,
  );
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    main();
  } catch (error) {
    console.error(formatCLIError(error));
    process.exit(1);
  }
}
