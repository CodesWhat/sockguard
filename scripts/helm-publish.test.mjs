import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { assertChartRelease, readChartVersion } from "./assert-chart-release.mjs";
import { pinChartImageTag, readChartAppVersion } from "./pin-chart-image-digest.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "..");
const read = (path) => readFileSync(resolve(repoRoot, path), "utf8");

const workflowJob = (workflow, name) => {
  const lines = workflow.split("\n");
  const start = lines.indexOf(`  ${name}:`);
  assert.notEqual(start, -1, `workflow job ${name} must exist`);
  const relativeEnd = lines.slice(start + 1).findIndex((line) => /^ {2}[a-z0-9_-]+:$/.test(line));
  const end = relativeEnd === -1 ? lines.length : start + 1 + relativeEnd;
  return lines.slice(start, end).join("\n");
};

const jobNames = (workflow) =>
  [...workflow.matchAll(/^ {2}([a-z0-9_-]+):$/gm)].map((match) => match[1]);

const DIGEST = `sha256:${"a".repeat(64)}`;
const chartYaml = (version, appVersion = version) =>
  `apiVersion: v2\nname: sockguard\nversion: ${version}\nappVersion: "${appVersion}"\n`;
const valuesYaml = (tag) => `image:\n  repository: codeswhat/sockguard\n  tag: "${tag}"\n`;

describe("publish-chart job gating", () => {
  const workflow = read(".github/workflows/release-from-tag.yml");
  const job = workflowJob(workflow, "publish-chart");

  it("runs only where latest and the Homebrew cask do: stable tags from the default branch", () => {
    // verify-ci's `latest` is false for prereleases and maintenance lines.
    assert.match(
      job,
      /^ {4}if: \$\{\{ needs\.verify-ci\.outputs\.latest == 'true' && !contains\(github\.ref_name, '-'\) \}\}$/m,
    );
    assert.match(job, /^ {4}needs: \[verify-ci, release\]$/m);

    const homebrew = workflowJob(workflow, "verify-homebrew");
    assert.match(homebrew, /^ {4}if: \$\{\{ needs\.verify-ci\.outputs\.latest == 'true' \}\}$/m);

    const verifyCi = workflowJob(workflow, "verify-ci");
    assert.match(
      verifyCi,
      /if \[\[ "\$\{matched_branch\}" == maintenance\/\* \]\]; then[\s\S]*?elif \[\[ "\$\{GITHUB_REF_NAME\}" != \*-\* \]\]; then\n\s+latest=true/,
    );
  });

  it("is the only job besides the image release that can write packages", () => {
    const writers = jobNames(workflow).filter((name) =>
      /^ {6}packages: write\b/m.test(workflowJob(workflow, name)),
    );
    assert.deepEqual(writers.sort(), ["publish-chart", "release"]);
    assert.match(job, /^ {6}packages: write\b/m);
    assert.match(job, /^ {6}contents: read\b/m);
    assert.match(job, /^ {6}id-token: write\b/m);
    assert.doesNotMatch(job, /contents: write/);
  });

  it("pushes to the charts namespace and never persists checkout credentials", () => {
    assert.match(job, /registry="ghcr\.io\/\$\{owner\}\/charts"/);
    assert.match(job, /helm push "\$\{CHART_PACKAGE\}" "oci:\/\/\$\{registry\}"/);
    assert.doesNotMatch(job, /persist-credentials: true/);
    assert.doesNotMatch(job, /--no-verify/);
  });

  it("packages a chart that pins the digest this pipeline published", () => {
    assert.match(job, /BUILD_DIGEST: \$\{\{ needs\.release\.outputs\.digest \}\}/);
    assert.match(job, /node scripts\/pin-chart-image-digest\.mjs/);
    assert.match(job, /node scripts\/assert-chart-release\.mjs/);
    assert.ok(
      job.indexOf("node scripts/pin-chart-image-digest.mjs") < job.indexOf("helm package chart"),
      "the pin must be applied before the chart is packaged",
    );
    assert.ok(
      job.indexOf("node scripts/assert-chart-release.mjs") <
        job.indexOf(`helm push "${"$"}{CHART_PACKAGE}"`),
      "the packaged chart must be checked before it is pushed",
    );
    assert.doesNotMatch(job, /git (commit|push)/);
  });

  it("pins Helm by version and SHA-256 and refuses a mismatch", () => {
    assert.match(job, /HELM_VERSION: v\d+\.\d+\.\d+$/m);
    assert.match(job, /HELM_SHA256: [0-9a-f]{64}$/m);
    assert.match(job, /sha256sum --check --strict -/);
  });

  it("signs keyless and verifies with the documented identity", () => {
    assert.match(job, /cosign sign --yes "\$\{CHART_REF\}@\$\{CHART_DIGEST\}"/);
    assert.match(job, /release-from-tag\.yml@refs\/tags\/\.\+\$/);
    assert.match(job, /token\.actions\.githubusercontent\.com/);
  });

  it("uses block mode, a pinned runner action and retries on network steps", () => {
    assert.match(job, /egress-policy: block/);
    assert.match(job, /get\.helm\.sh:443/);
    assert.match(job, /ghcr\.io:443/);
    assert.match(job, /Checkout \(final retry\)/);
    assert.match(job, /retry_network helm registry login/);
    assert.match(job, /retry_network push_chart/);
    for (const use of job.matchAll(/uses: ([^\s]+)/g)) {
      assert.match(use[1], /@[0-9a-f]{40}$/, `${use[1]} must be pinned to a commit SHA`);
    }
  });
});

describe("QA-6 chart verification", () => {
  const workflow = read(".github/workflows/release-from-tag.yml");
  const verify = workflowJob(workflow, "verify-published");

  it("waits for publish-chart and treats a skipped one as fine", () => {
    assert.match(verify, /^ {4}needs: \[verify-ci, release, publish-chart\]$/m);
    assert.match(verify, /needs\.publish-chart\.result == 'skipped'/);
    assert.match(verify, /needs\.publish-chart\.result == 'success'/);
  });

  it("passes --chart only when the chart was published", () => {
    assert.match(
      verify,
      /VERIFY_CHART: \$\{\{ needs\.publish-chart\.result == 'success' && 'true' \|\| 'false' \}\}/,
    );
    assert.match(verify, /verify_args\+=\(--chart\)/);
  });

  it("the verify script plans the documented cosign verify for the chart", () => {
    const result = spawnSync(
      "bash",
      [
        resolve(scriptDir, "verify-published-release.sh"),
        "--dry-run",
        "--chart",
        "--tag",
        "v3.0.0",
      ],
      { cwd: repoRoot, encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /ghcr\.io\/codeswhat\/charts\/sockguard:3\.0\.0/);
  });

  it("keeps pin-chart-digest behind QA-6 so an unverifiable chart holds the pin back", () => {
    const pin = workflowJob(workflow, "pin-chart-digest");
    assert.match(pin, /needs\.verify-published\.result == 'success'/);
  });
});

describe("chart version contract", () => {
  it("the repo chart's version equals appVersion", () => {
    const chart = read("chart/sockguard/Chart.yaml");
    assert.equal(readChartVersion(chart), readChartAppVersion(chart));
  });

  it("a release-shaped chart packaged from the repo passes the gate for its own tag", () => {
    const chart = read("chart/sockguard/Chart.yaml");
    const version = readChartVersion(chart);
    const pinned = pinChartImageTag({
      values: valuesYaml(""),
      appVersion: readChartAppVersion(chart),
      version,
      digest: DIGEST,
    });
    const result = assertChartRelease({
      chart,
      values: pinned.values,
      tag: `v${version}`,
      digest: DIGEST,
    });
    assert.equal(result.imageTag, `${version}@${DIGEST}`);
  });

  it("accepts version == appVersion == tag with the digest pin", () => {
    assertChartRelease({
      chart: chartYaml("3.0.0"),
      values: valuesYaml(`3.0.0@${DIGEST}`),
      tag: "v3.0.0",
      digest: DIGEST,
    });
  });

  it("rejects a chart version that is not the tag", () => {
    assert.throws(
      () =>
        assertChartRelease({
          chart: chartYaml("2.4.3"),
          values: valuesYaml(`2.4.3@${DIGEST}`),
          tag: "v3.0.0",
          digest: DIGEST,
        }),
      /must both equal the tag version/,
    );
  });

  it("rejects an appVersion that is not the tag", () => {
    assert.throws(
      () =>
        assertChartRelease({
          chart: chartYaml("3.0.0", "2.4.3"),
          values: valuesYaml(`3.0.0@${DIGEST}`),
          tag: "v3.0.0",
          digest: DIGEST,
        }),
      /must both equal the tag version/,
    );
  });

  it("rejects a chart that still uses a mutable tag or a different digest", () => {
    for (const tag of ["", "3.0.0", `3.0.0@sha256:${"b".repeat(64)}`, "latest"]) {
      assert.throws(
        () =>
          assertChartRelease({
            chart: chartYaml("3.0.0"),
            values: valuesYaml(tag),
            tag: "v3.0.0",
            digest: DIGEST,
          }),
        /expected the immutable pin/,
        `image.tag ${JSON.stringify(tag)} must be refused`,
      );
    }
  });

  it("rejects prerelease tags", () => {
    assert.throws(
      () =>
        assertChartRelease({
          chart: chartYaml("3.0.0"),
          values: valuesYaml(`3.0.0@${DIGEST}`),
          tag: "v3.0.0-rc.5",
          digest: DIGEST,
        }),
      /expected a stable X\.Y\.Z semver/,
    );
  });
});
