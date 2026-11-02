import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import {
  assertChartRelease,
  readChartVersion,
  readPackagedAppVersion,
} from "./assert-chart-release.mjs";
import { pinChartImageTag, readChartAppVersion } from "./pin-chart-image-digest.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "..");
const read = (path) => readFileSync(resolve(repoRoot, path), "utf8");
const words = (text) => text.split(/[\s"'`]+/u).filter(Boolean);

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
    assert.match(
      job,
      /CHART_REGISTRY="ghcr\.io\/\$\{owner\}\/charts" bash scripts\/ci\/chart-oci\.sh push/,
    );
    assert.match(
      job,
      /CHART_REGISTRY="ghcr\.io\/\$\{owner\}\/charts" bash scripts\/ci\/chart-oci\.sh verify-contents/,
    );
    assert.match(
      read("scripts/ci/chart-oci.sh"),
      /helm push "\$\{CHART_PACKAGE\}" "oci:\/\/\$\{CHART_REGISTRY\}"/,
    );
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
        job.indexOf("scripts/ci/chart-oci.sh push"),
      "the packaged chart must be checked before it is pushed",
    );
    assert.ok(
      job.indexOf("scripts/ci/chart-oci.sh push") <
        job.indexOf("scripts/ci/chart-oci.sh verify-contents"),
      "the pushed chart is read back after the push",
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
    assert.match(job, /cosign verify \\/);
    assert.match(job, /release-from-tag\.yml@refs\/tags\/\.\+\$/);
    assert.ok(
      words(job).some((w) => /^https:\/\/token\.actions\.githubusercontent\.com$/u.test(w)),
      "verify must name the exact GitHub OIDC issuer",
    );
  });

  it("uses block mode, a pinned runner action and retries on network steps", () => {
    assert.match(job, /egress-policy: block/);
    assert.ok(words(job).includes("get.helm.sh:443"), "get.helm.sh:443 must be allowed");
    assert.ok(words(job).includes("ghcr.io:443"), "ghcr.io:443 must be allowed");
    assert.match(job, /Checkout \(final retry\)/);
    assert.match(job, /retry_network curl/);
    for (const use of job.matchAll(/uses: ([^\s]+)/g)) {
      assert.match(use[1], /@[0-9a-f]{40}$/, `${use[1]} must be pinned to a commit SHA`);
    }
  });
});

describe("publish-chart login, visibility and rerun handling", () => {
  const workflow = read(".github/workflows/release-from-tag.yml");
  const job = workflowJob(workflow, "publish-chart");

  it("runs the whole helm login, password included, inside the retried function", () => {
    assert.match(
      job,
      /helm_login\(\) \{\n\s+printf '%s' "\$\{GH_TOKEN\}" \| helm registry login ghcr\.io/,
    );
    assert.doesNotMatch(job, /printf '%s' "\$\{GH_TOKEN\}" \| retry_network/);
  });

  it("fails clearly unless the package is public and linked to the repository", () => {
    assert.match(job, /orgs\/\$\{owner\}\/packages\/container\/charts%2Fsockguard/);
    assert.match(job, /\.visibility/);
    assert.match(job, /\.repository\.full_name/);
    assert.match(job, /Change visibility: Public; Connect repository/);
    assert.ok(
      job.indexOf("charts%2Fsockguard") < job.indexOf("cosign sign --yes"),
      "visibility is checked before the chart is signed",
    );
  });

  it("signs an adopted version only when its signature does not already verify", () => {
    assert.match(job, /ALREADY_PUBLISHED: \$\{\{ steps\.push\.outputs\.exists \}\}/);
    assert.match(job, /"\$\{ALREADY_PUBLISHED\}" = "true" \] && verify_signature/);
  });

  it("checks the pulled chart's contents even for a version this run did not push", () => {
    assert.match(job, /name: Check the published chart contents/);
  });
});

describe("chart isolation from the image release", () => {
  const workflow = read(".github/workflows/release-from-tag.yml");
  const needsOf = (name) => workflowJob(workflow, name).match(/^ {4}needs: (.+)$/m)?.[1] ?? "";

  it("no image, tarball, Homebrew or pin job depends on publish-chart", () => {
    for (const name of jobNames(workflow).filter(
      (n) => n !== "verify-chart" && n !== "publish-chart",
    )) {
      assert.doesNotMatch(
        workflowJob(workflow, name).replace(/^\s*#.*$/gm, ""),
        /publish-chart/,
        `${name} must not reference publish-chart`,
      );
    }
  });

  it("leaves verify-published as it was before the chart existed", () => {
    const verify = workflowJob(workflow, "verify-published");
    assert.equal(needsOf("verify-published"), "[release]");
    assert.doesNotMatch(verify, /^ {4}if:/m);
    assert.doesNotMatch(verify, /--chart|VERIFY_CHART/);
  });

  it("keeps pin-chart-digest behind QA-6 and Homebrew only", () => {
    assert.equal(needsOf("pin-chart-digest"), "[release, verify-published, verify-homebrew]");
  });

  it("verifies the chart in its own job that only runs after a successful publish", () => {
    const verify = workflowJob(workflow, "verify-chart");
    assert.equal(needsOf("verify-chart"), "[publish-chart]");
    assert.match(
      verify,
      /^ {4}if: \$\{\{ !cancelled\(\) && needs\.publish-chart\.result == 'success' \}\}$/m,
    );
    assert.doesNotMatch(verify, /always\(\)/);
    assert.match(verify, /verify-published-release\.sh --chart-only --tag/);
    assert.match(verify, /egress-policy: block/);
    assert.doesNotMatch(verify, /packages: write|id-token/);
    for (const use of verify.matchAll(/uses: ([^\s]+)/g)) {
      assert.match(use[1], /@[0-9a-f]{40}$/, `${use[1]} must be pinned to a commit SHA`);
    }
  });

  it("the verify script plans only the documented cosign verify for --chart-only", () => {
    const result = spawnSync(
      "bash",
      [
        resolve(scriptDir, "verify-published-release.sh"),
        "--dry-run",
        "--chart-only",
        "--tag",
        "v3.0.0",
      ],
      { cwd: repoRoot, encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /chart only:\s+yes/);
    assert.ok(
      result.stdout
        .split(/\s+/u)
        .some((w) => /^ghcr\.io\/codeswhat\/charts\/sockguard:3\.0\.0$/u.test(w)),
      "dry-run must plan the exact chart ref",
    );
  });

  it("the verify script's --chart still plans the chart alongside the images", () => {
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
    assert.match(result.stdout, /chart only:\s+no/);
  });
});

describe("chart publish rehearsal workflow", () => {
  const rehearsal = read(".github/workflows/chart-publish-rehearsal.yml");
  const release = read(".github/workflows/release-from-tag.yml");

  it("runs on pull requests, path-filtered, and is not a required check", () => {
    assert.match(rehearsal, /^on:\n {2}pull_request:\n {4}paths:/m);
    for (const path of [
      "chart/**",
      ".github/workflows/release-from-tag.yml",
      "scripts/ci/chart-oci.sh",
      "scripts/assert-chart-release.mjs",
    ]) {
      assert.ok(rehearsal.includes(`"${path}"`), `${path} must trigger the rehearsal`);
    }
    assert.match(rehearsal, /Deliberately NOT a required context/);
    const required = read(".github/workflows/ci-verify.yml");
    assert.doesNotMatch(required, /Rehearse chart publish/);
  });

  it("pushes to a registry:2 service container through the release script", () => {
    assert.match(rehearsal, /image: registry:2/);
    assert.match(rehearsal, /CHART_REGISTRY: localhost:5000\/charts/);
    assert.match(rehearsal, /bash scripts\/ci\/chart-oci\.sh push/);
    assert.match(rehearsal, /bash scripts\/ci\/chart-oci\.sh verify-contents/);
    assert.match(rehearsal, /node scripts\/pin-chart-image-digest\.mjs/);
  });

  it("installs Helm with the same pinned version and checksum as the release job", () => {
    const pick = (text, key) => text.match(new RegExp(`${key}: (\\S+)`))?.[1];
    assert.ok(pick(rehearsal, "HELM_VERSION"));
    assert.equal(pick(rehearsal, "HELM_VERSION"), pick(release, "HELM_VERSION"));
    assert.equal(pick(rehearsal, "HELM_SHA256"), pick(release, "HELM_SHA256"));
    assert.match(rehearsal, /sha256sum --check --strict -/);
  });

  it("pins every action to a commit SHA and does not persist credentials", () => {
    for (const use of rehearsal.matchAll(/uses: ([^\s]+)/g)) {
      assert.match(use[1], /@[0-9a-f]{40}$/, `${use[1]} must be pinned to a commit SHA`);
    }
    assert.match(rehearsal, /persist-credentials: false/);
    assert.match(rehearsal, /^permissions: \{\}$/m);
  });
});

describe("scripts/ci/chart-oci.sh push", () => {
  const script = resolve(scriptDir, "ci/chart-oci.sh");
  const fakeDigest = `sha256:${"c".repeat(64)}`;

  // A stand-in helm that records pushes and answers show/pull from files.
  const FAKE_HELM = `#!/usr/bin/env bash
set -u
dir="\${FAKE_DIR}"
case "$1" in
  show)
    if [ -f "\${dir}/published" ]; then echo "name: sockguard"; exit 0; fi
    if [ "\${FAKE_SHOW_ERROR:-}" = "denied" ]; then echo "Error: unauthorized: denied"; exit 1; fi
    echo "Error: failed to perform FetchReference: not found"; exit 1 ;;
  push)
    echo x >> "\${dir}/pushes"
    n=$(wc -l < "\${dir}/pushes" | tr -d ' ')
    if [ "$n" -le "\${FAKE_PUSH_FAILURES:-0}" ]; then
      [ "\${FAKE_PUSH_LANDS:-}" = "1" ] && touch "\${dir}/published"
      echo "Error: connection reset"; exit 1
    fi
    touch "\${dir}/published"
    echo "Pushed: reg/charts/sockguard:1.2.3"
    [ "\${FAKE_NO_DIGEST:-}" = "1" ] || echo "Digest: \${FAKE_DIGEST}"
    exit 0 ;;
  pull)
    echo "Pulled: reg/charts/sockguard:1.2.3"
    echo "Digest: \${FAKE_DIGEST}"
    exit 0 ;;
esac
exit 1
`;

  const run = (extraEnv = {}, { published = false } = {}) => {
    const dir = mkdtempSync(join(tmpdir(), "chart-oci-"));
    if (published) {
      writeFileSync(join(dir, "published"), "");
    }
    const bin = join(dir, "bin");
    spawnSync("mkdir", ["-p", bin]);
    writeFileSync(join(bin, "helm"), FAKE_HELM);
    chmodSync(join(bin, "helm"), 0o755);
    const outFile = join(dir, "github-output");
    writeFileSync(outFile, "");
    const result = spawnSync("bash", [script, "push"], {
      encoding: "utf8",
      env: {
        PATH: `${bin}:${process.env.PATH}`,
        FAKE_DIR: dir,
        FAKE_DIGEST: fakeDigest,
        CHART_REGISTRY: "reg/charts",
        CHART_VERSION: "1.2.3",
        CHART_PACKAGE: join(dir, "sockguard-1.2.3.tgz"),
        CHART_RETRY_DELAY: "0",
        GITHUB_OUTPUT: outFile,
        ...extraEnv,
      },
    });
    const pushFile = join(dir, "pushes");
    return {
      ...result,
      outputs: readFileSync(outFile, "utf8"),
      pushes: existsSync(pushFile) ? readFileSync(pushFile, "utf8").trim().split("\n").length : 0,
    };
  };

  it("pushes a version the registry definitely does not have and parses the Digest line", () => {
    const result = run();
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.pushes, 1);
    assert.match(result.outputs, new RegExp(`^digest=${fakeDigest}$`, "m"));
    assert.match(result.outputs, /^exists=false$/m);
    assert.match(result.outputs, /^ref=reg\/charts\/sockguard$/m);
  });

  it("adopts an already-published version without pushing over it", () => {
    const result = run({}, { published: true });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.pushes, 0);
    assert.match(result.outputs, /^exists=true$/m);
    assert.match(result.outputs, new RegExp(`^digest=${fakeDigest}$`, "m"));
  });

  it("fails, without pushing, on any error that is not a definite not-found", () => {
    const result = run({ FAKE_SHOW_ERROR: "denied" });
    assert.notEqual(result.status, 0);
    assert.equal(result.pushes, 0);
    assert.match(result.stderr, /refusing to push on an unclear answer/);
  });

  it("re-checks for the version between attempts and adopts one that landed", () => {
    const result = run({ FAKE_PUSH_FAILURES: "1", FAKE_PUSH_LANDS: "1" });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.pushes, 1, "a landed push must not be pushed again");
    assert.match(result.outputs, /^exists=true$/m);
  });

  it("retries a push that failed without landing", () => {
    const result = run({ FAKE_PUSH_FAILURES: "2" });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.pushes, 3);
    assert.match(result.outputs, /^exists=false$/m);
  });

  it("gives up after five failed pushes", () => {
    const result = run({ FAKE_PUSH_FAILURES: "9" });
    assert.notEqual(result.status, 0);
    assert.equal(result.pushes, 5);
  });

  it("fails when helm reports no chart digest", () => {
    const result = run({ FAKE_NO_DIGEST: "1" });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Did not get a chart digest/);
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

  it("reads the unquoted appVersion that helm show chart prints from a package", () => {
    assert.equal(
      readPackagedAppVersion("apiVersion: v2\nappVersion: 3.0.0\nname: sockguard\n"),
      "3.0.0",
    );
    assert.equal(readPackagedAppVersion('appVersion: "3.0.0"\n'), "3.0.0");
    assertChartRelease({
      chart: "apiVersion: v2\nappVersion: 3.0.0\nname: sockguard\nversion: 3.0.0\n",
      values: valuesYaml(`3.0.0@${DIGEST}`),
      tag: "v3.0.0",
      digest: DIGEST,
    });
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
