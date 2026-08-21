import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import {
  checkTagReleaseMetadata,
  extractChartVersions,
  extractSiteConfigVersion,
  formatCLIError,
  normalizeTag,
} from "./verify-tag-release-metadata.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "..");
const scriptPath = resolve(scriptDir, "verify-tag-release-metadata.mjs");

const SITE_CONFIG = `
export const SITE_CONFIG = {
  name: "Sockguard",
  version: "1.7.4",
  tagline: "Control what gets through",
} as const;
`;

const CHART = `apiVersion: v2
name: sockguard
version: 1.7.4
appVersion: "1.7.4"
`;

const CHANGELOG = `# Changelog

## [Unreleased]

## [1.7.4] - 2026-08-21

### Changed

- Something changed.

## [1.7.3] - 2026-08-21

### Fixed

- Something fixed.
`;

const PRERELEASE_CHANGELOG = `# Changelog

## [Unreleased]

## [1.8.0-rc.1] - 2026-08-22

### Added

- Something new, unreleased.

## [1.7.4] - 2026-08-21

### Changed

- Something changed.
`;

describe("normalizeTag", () => {
  it("strips the leading v", () => {
    assert.equal(normalizeTag("v1.7.4"), "1.7.4");
  });

  it("keeps a prerelease suffix", () => {
    assert.equal(normalizeTag("v1.8.0-rc.1"), "1.8.0-rc.1");
  });

  it("rejects a tag with no leading v", () => {
    assert.throws(() => normalizeTag("1.7.4"), /Invalid tag/);
  });

  it("rejects a malformed version", () => {
    assert.throws(() => normalizeTag("vnext"), /Invalid tag/);
  });
});

describe("extractSiteConfigVersion", () => {
  it("extracts the version field", () => {
    assert.equal(extractSiteConfigVersion(SITE_CONFIG), "1.7.4");
  });

  it("throws when the field is missing", () => {
    assert.throws(
      () => extractSiteConfigVersion("export const SITE_CONFIG = {};"),
      /Could not find/,
    );
  });
});

describe("extractChartVersions", () => {
  it("extracts version and appVersion", () => {
    assert.deepEqual(extractChartVersions(CHART), { version: "1.7.4", appVersion: "1.7.4" });
  });

  it("throws when appVersion is missing", () => {
    assert.throws(() => extractChartVersions("version: 1.7.4\n"), /Could not find/);
  });
});

describe("checkTagReleaseMetadata: stable tags", () => {
  it("reports no errors when everything agrees", () => {
    const result = checkTagReleaseMetadata({
      tag: "v1.7.4",
      siteConfig: SITE_CONFIG,
      chart: CHART,
      changelog: CHANGELOG,
    });
    assert.equal(result.isPrerelease, false);
    assert.deepEqual(result.errors, []);
  });

  it("flags a site-config mismatch (the v1.7.1 shape: tag ahead of metadata)", () => {
    const result = checkTagReleaseMetadata({
      tag: "v1.7.5",
      siteConfig: SITE_CONFIG,
      chart: CHART,
      changelog: CHANGELOG.replace("1.7.4", "1.7.5"),
    });
    assert.ok(result.errors.some((e) => e.includes("site-config.ts") && e.includes("1.7.4")));
  });

  it("flags a chart version mismatch independently of site-config", () => {
    const result = checkTagReleaseMetadata({
      tag: "v1.7.4",
      siteConfig: SITE_CONFIG,
      chart: CHART.replace("version: 1.7.4", "version: 1.7.3"),
      changelog: CHANGELOG,
    });
    assert.ok(result.errors.some((e) => e.includes("Chart.yaml version")));
    assert.ok(!result.errors.some((e) => e.includes("site-config.ts")));
  });

  it("flags a chart appVersion mismatch independently of chart version", () => {
    const result = checkTagReleaseMetadata({
      tag: "v1.7.4",
      siteConfig: SITE_CONFIG,
      chart: CHART.replace('appVersion: "1.7.4"', 'appVersion: "1.7.3"'),
      changelog: CHANGELOG,
    });
    assert.ok(result.errors.some((e) => e.includes("Chart.yaml appVersion")));
  });

  it("flags a missing CHANGELOG heading for the tag", () => {
    const result = checkTagReleaseMetadata({
      tag: "v1.7.5",
      siteConfig: SITE_CONFIG.replace("1.7.4", "1.7.5"),
      chart: CHART.replace(/1\.7\.4/g, "1.7.5"),
      changelog: CHANGELOG,
    });
    assert.ok(result.errors.some((e) => e.includes("CHANGELOG.md has no dated heading")));
  });

  it("reports every mismatch at once, not just the first", () => {
    const result = checkTagReleaseMetadata({
      tag: "v9.9.9",
      siteConfig: SITE_CONFIG,
      chart: CHART,
      changelog: CHANGELOG,
    });
    assert.equal(result.errors.length, 4);
  });
});

describe("checkTagReleaseMetadata: prerelease tags", () => {
  it("passes when the CHANGELOG heading exists, even though site/chart still show the prior stable version", () => {
    const result = checkTagReleaseMetadata({
      tag: "v1.8.0-rc.1",
      siteConfig: SITE_CONFIG, // still "1.7.4" -- correct for an unreleased rc
      chart: CHART, // still "1.7.4" -- correct for an unreleased rc
      changelog: PRERELEASE_CHANGELOG,
    });
    assert.equal(result.isPrerelease, true);
    assert.deepEqual(result.errors, []);
  });

  it("fails when the CHANGELOG has no heading for the prerelease tag", () => {
    const result = checkTagReleaseMetadata({
      tag: "v1.9.0-rc.1",
      siteConfig: SITE_CONFIG,
      chart: CHART,
      changelog: PRERELEASE_CHANGELOG,
    });
    assert.equal(result.errors.length, 1);
    assert.ok(result.errors[0].includes("prerelease tag v1.9.0-rc.1"));
  });
});

describe("formatCLIError", () => {
  it("returns the message for an Error", () => {
    assert.equal(formatCLIError(new Error("boom")), "boom");
  });

  it("stringifies a non-Error", () => {
    assert.equal(formatCLIError("boom"), "boom");
  });
});

// CLI self-test against the real repository files, run from repo root the
// same way the release-cut and release-from-tag workflow steps invoke it.
// This is the check the workflow gate depends on: prove it actually fails a
// mismatch and actually passes agreement, not just that the pure function
// does.
function runCLI(args) {
  return spawnSync("node", [scriptPath, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
  });
}

describe("CLI: real repository files", () => {
  it("fails for a tag nothing in the repo claims (v9.9.9)", () => {
    const result = runCLI(["--tag", "v9.9.9"]);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /disagrees with release metadata/);
  });

  it("passes for the tag the repo's own release metadata currently agrees on", () => {
    const currentVersion = extractSiteConfigVersion(
      readFileSync(resolve(repoRoot, "website/src/lib/site-config.ts"), "utf8"),
    );
    const result = runCLI(["--tag", `v${currentVersion}`]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /agrees with website, chart, and CHANGELOG metadata/);
  });

  it("requires --tag", () => {
    const result = runCLI([]);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /--tag is required/);
  });
});
