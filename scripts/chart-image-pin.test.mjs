import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, it } from "node:test";

const repoRoot = resolve(import.meta.dirname, "..");
const valuesPath = resolve(repoRoot, "chart/sockguard/values.yaml");
const chartPath = resolve(repoRoot, "chart/sockguard/Chart.yaml");

// Regression test for #305: the chart's default image.tag pinned a digest
// belonging to codeswhat/sockguard:1.5.1 for four releases (v1.6.0 through
// v1.7.2) because nothing checked that the pinned tag component still
// agreed with Chart.yaml's appVersion. The digest itself can't be verified
// offline (that requires a registry round-trip — see RELEASING.md's Helm
// chart section), but the tag/appVersion agreement is checkable here and is
// exactly the drift that rotted silently.
function readImageTag(values) {
  const match = values.match(/^\s*tag:\s*"([^"]*)"\s*$/m);
  assert.ok(match, "chart/sockguard/values.yaml must set image.tag as a quoted string");
  return match[1];
}

function readAppVersion(chart) {
  const match = chart.match(/^appVersion:\s*"([^"]*)"\s*$/m);
  assert.ok(match, "chart/sockguard/Chart.yaml must set appVersion");
  return match[1];
}

describe("chart default image pin", () => {
  it("pins the tag component to Chart.yaml's appVersion wherever tag@digest is used", () => {
    const tag = readImageTag(readFileSync(valuesPath, "utf8"));
    const appVersion = readAppVersion(readFileSync(chartPath, "utf8"));

    if (!tag.includes("@sha256:")) {
      // Not a digest pin (e.g. left empty to fall back to appVersion, or set
      // to a bare tag) — nothing to check here.
      return;
    }

    const [tagComponent] = tag.split("@sha256:");
    assert.equal(
      tagComponent,
      appVersion,
      `chart/sockguard/values.yaml pins image.tag="${tag}", whose tag component ` +
        `("${tagComponent}") does not match Chart.yaml's appVersion ("${appVersion}"). ` +
        "The digest has to move together with the tag on every release — see " +
        "RELEASING.md's Helm chart section.",
    );
  });
});
