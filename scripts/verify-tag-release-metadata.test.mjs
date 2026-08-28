import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import {
  checkTagReleaseMetadata,
  extractChartImageTag,
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

const VALUES = `image:
  repository: codeswhat/sockguard
  tag: ""
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

describe("extractChartImageTag", () => {
  it("extracts an empty quoted image tag", () => {
    assert.equal(extractChartImageTag(VALUES), "");
  });

  it("ignores a sidecar tag before the top-level image block", () => {
    assert.equal(
      extractChartImageTag(`sidecar:
  tag: "old"
image:
  repository: codeswhat/sockguard
  tag: ""
`),
      "",
    );
  });

  it("does not let an empty sidecar tag hide a pinned primary image", () => {
    assert.equal(
      extractChartImageTag(`sidecar:
  tag: ""
image:
  repository: codeswhat/sockguard
  tag: "2.0.0@sha256:${"a".repeat(64)}"
`),
      `2.0.0@sha256:${"a".repeat(64)}`,
    );
  });

  it("throws when image.tag is missing", () => {
    assert.throws(() => extractChartImageTag("image: {}\n"), /block mapping|Could not find/);
  });

  it("rejects duplicate top-level image blocks instead of trusting the first tag", () => {
    assert.throws(
      () =>
        extractChartImageTag(`image:
  tag: ""
image:
  tag: "2.0.0@sha256:${"a".repeat(64)}"
`),
      /unique|duplicate/iu,
    );
  });

  it("rejects a quoted duplicate top-level image key", () => {
    assert.throws(
      () =>
        extractChartImageTag(`image:
  tag: ""
"image":
  tag: "evil"
`),
      /unique|duplicate/iu,
    );
  });

  it("rejects an escaped duplicate top-level image key", () => {
    assert.throws(
      () =>
        extractChartImageTag(`image:
  repository: codeswhat/sockguard
  tag: ""
"\\u0069mage":
  repository: attacker.invalid/sockguard
  tag: "evil"
`),
      /unique|duplicate/iu,
    );
  });

  it("rejects duplicate image.tag keys instead of trusting the first value", () => {
    assert.throws(
      () =>
        extractChartImageTag(`image:
  tag: "2.0.0@sha256:${"a".repeat(64)}"
  tag: ""
`),
      /unique|duplicate/iu,
    );
  });

  it("rejects a quoted duplicate image.tag key", () => {
    assert.throws(
      () =>
        extractChartImageTag(`image:
  tag: ""
  "tag": "evil"
`),
      /unique|duplicate/iu,
    );
  });

  it("rejects a quoted duplicate image.repository key", () => {
    assert.throws(
      () =>
        extractChartImageTag(`image:
  repository: codeswhat/sockguard
  "repository": attacker.invalid/sockguard
  tag: ""
`),
      /unique|duplicate/iu,
    );
  });
});

describe("checkTagReleaseMetadata: stable tags", () => {
  it("reports no errors when everything agrees", () => {
    const result = checkTagReleaseMetadata({
      tag: "v1.7.4",
      siteConfig: SITE_CONFIG,
      chart: CHART,
      values: VALUES,
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
      values: VALUES,
      changelog: CHANGELOG.replace("1.7.4", "1.7.5"),
    });
    assert.ok(result.errors.some((e) => e.includes("site-config.ts") && e.includes("1.7.4")));
  });

  it("flags a chart version mismatch independently of site-config", () => {
    const result = checkTagReleaseMetadata({
      tag: "v1.7.4",
      siteConfig: SITE_CONFIG,
      chart: CHART.replace("version: 1.7.4", "version: 1.7.3"),
      values: VALUES,
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
      values: VALUES,
      changelog: CHANGELOG,
    });
    assert.ok(result.errors.some((e) => e.includes("Chart.yaml appVersion")));
  });

  it("flags a missing CHANGELOG heading for the tag", () => {
    const result = checkTagReleaseMetadata({
      tag: "v1.7.5",
      siteConfig: SITE_CONFIG.replace("1.7.4", "1.7.5"),
      chart: CHART.replace(/1\.7\.4/g, "1.7.5"),
      values: VALUES,
      changelog: CHANGELOG,
    });
    assert.ok(result.errors.some((e) => e.includes("CHANGELOG.md has no dated heading")));
  });

  it("reports every mismatch at once, not just the first", () => {
    const result = checkTagReleaseMetadata({
      tag: "v9.9.9",
      siteConfig: SITE_CONFIG,
      chart: CHART,
      values: VALUES,
      changelog: CHANGELOG,
    });
    assert.equal(result.errors.length, 4);
  });

  it("rejects a non-empty Helm image pin before a stable tag is created", () => {
    const result = checkTagReleaseMetadata({
      tag: "v1.7.4",
      siteConfig: SITE_CONFIG,
      chart: CHART,
      values: VALUES.replace('tag: ""', `tag: "1.7.4@sha256:${"a".repeat(64)}"`),
      changelog: CHANGELOG,
    });
    assert.ok(
      result.errors.some(
        (error) => error.includes("chart/sockguard/values.yaml") && error.includes("must be empty"),
      ),
    );
  });

  it("rejects a different default Helm image repository", () => {
    const result = checkTagReleaseMetadata({
      tag: "v1.7.4",
      siteConfig: SITE_CONFIG,
      chart: CHART,
      values: VALUES.replace(
        "repository: codeswhat/sockguard",
        "repository: attacker.invalid/sockguard",
      ),
      changelog: CHANGELOG,
    });
    assert.ok(
      result.errors.some(
        (error) =>
          error.includes("chart/sockguard/values.yaml") && error.includes("image.repository"),
      ),
    );
  });

  it("does not truncate an unspaced hash in the default Helm image repository", () => {
    const result = checkTagReleaseMetadata({
      tag: "v1.7.4",
      siteConfig: SITE_CONFIG,
      chart: CHART,
      values: VALUES.replace(
        "repository: codeswhat/sockguard",
        "repository: codeswhat/sockguard#evil",
      ),
      changelog: CHANGELOG,
    });
    assert.ok(
      result.errors.some(
        (error) =>
          error.includes("chart/sockguard/values.yaml") && error.includes("image.repository"),
      ),
    );
  });
});

describe("checkTagReleaseMetadata: prerelease tags", () => {
  it("passes when the CHANGELOG heading exists, even though site/chart still show the prior stable version", () => {
    const result = checkTagReleaseMetadata({
      tag: "v1.8.0-rc.1",
      siteConfig: SITE_CONFIG, // still "1.7.4" -- correct for an unreleased rc
      chart: CHART, // still "1.7.4" -- correct for an unreleased rc
      values: VALUES.replace('tag: ""', `tag: "1.7.4@sha256:${"a".repeat(64)}"`),
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

  it("passes for the tag the repo's own metadata and a prepublication image state agree on", (t) => {
    const currentVersion = extractSiteConfigVersion(
      readFileSync(resolve(repoRoot, "website/src/lib/site-config.ts"), "utf8"),
    );
    const fixtureRoot = mkdtempSync(join(tmpdir(), "sockguard-release-values-"));
    t.after(() => rmSync(fixtureRoot, { recursive: true, force: true }));
    const valuesPath = resolve(fixtureRoot, "values.yaml");
    writeFileSync(valuesPath, VALUES);

    const result = runCLI(["--tag", `v${currentVersion}`, "--values", valuesPath]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /agrees with website, chart, Helm image, and CHANGELOG metadata/);
  });

  it("requires --tag", () => {
    const result = runCLI([]);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /--tag is required/);
  });
});
