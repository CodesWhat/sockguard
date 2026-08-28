import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, it } from "node:test";
import { extractChartImageTag } from "./chart-image-tag.mjs";

const repoRoot = resolve(import.meta.dirname, "..");
const valuesPath = resolve(repoRoot, "chart/sockguard/values.yaml");
const chartPath = resolve(repoRoot, "chart/sockguard/Chart.yaml");

// Regression test for #305: the chart's default image.tag pinned a stale
// release for four releases. The digest itself can't be verified offline
// (that requires a registry round-trip — see RELEASING.md's Helm chart
// section), but this contract rejects every local state except the empty
// prepublication value or the exact appVersion plus a valid digest shape.
function readAppVersion(chart) {
  const match = chart.match(/^appVersion:\s*"([^"]*)"\s*$/m);
  assert.ok(match, "chart/sockguard/Chart.yaml must set appVersion");
  return match[1];
}

function assertValidReleaseImageTag(tag, appVersion) {
  if (tag === "") {
    return;
  }

  const escapedAppVersion = appVersion.replaceAll(".", "\\.");
  assert.match(
    tag,
    new RegExp(`^${escapedAppVersion}@sha256:[0-9a-f]{64}$`),
    `image.tag must be empty before publication or exactly ${appVersion}@sha256:<64 lowercase hex characters> after publication`,
  );
}

describe("chart default image pin", () => {
  it("is empty before publication or pins the exact appVersion and manifest digest", () => {
    const tag = extractChartImageTag(readFileSync(valuesPath, "utf8"));
    const appVersion = readAppVersion(readFileSync(chartPath, "utf8"));

    assertValidReleaseImageTag(tag, appVersion);
  });

  it("renders the complete expected default image reference", () => {
    const tag = extractChartImageTag(readFileSync(valuesPath, "utf8"));
    const appVersion = readAppVersion(readFileSync(chartPath, "utf8"));
    const effectiveTag = tag || appVersion;
    const result = spawnSync(
      "helm",
      ["template", "sockguard", resolve(repoRoot, "chart/sockguard")],
      {
        encoding: "utf8",
      },
    );

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, new RegExp(`image: "codeswhat/sockguard:${effectiveTag}"`, "u"));
  });

  it("rejects stale bare tags", () => {
    assert.throws(
      () => assertValidReleaseImageTag("1.7.5", "2.0.0"),
      /image\.tag must be empty before publication or exactly/u,
    );
  });

  it("rejects a stale tag paired with a well-shaped digest", () => {
    assert.throws(
      () => assertValidReleaseImageTag(`1.7.5@sha256:${"a".repeat(64)}`, "2.0.0"),
      /image\.tag must be empty before publication or exactly/u,
    );
  });

  it("accepts the exact appVersion paired with a lowercase digest", () => {
    assert.doesNotThrow(() =>
      assertValidReleaseImageTag(`2.0.0@sha256:${"a".repeat(64)}`, "2.0.0"),
    );
  });

  it("rejects malformed and uppercase digests", () => {
    assert.throws(() => assertValidReleaseImageTag("2.0.0@sha256:abc", "2.0.0"));
    assert.throws(() => assertValidReleaseImageTag(`2.0.0@sha256:${"A".repeat(64)}`, "2.0.0"));
  });
});
