import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { after, describe, it } from "node:test";
import {
  normalizeDigest,
  pinChartImageTag,
  readChartAppVersion,
} from "./pin-chart-image-digest.mjs";

const repoRoot = resolve(import.meta.dirname, "..");
const pinScript = resolve(repoRoot, "scripts/pin-chart-image-digest.mjs");
const tempRoot = mkdtempSync(resolve(tmpdir(), "sockguard-chart-pin-"));

after(() => rmSync(tempRoot, { recursive: true, force: true }));

const DIGEST = `sha256:${"a".repeat(64)}`;

const VALUES = [
  "# Default values for the sockguard Helm chart.",
  "",
  "image:",
  "  repository: codeswhat/sockguard",
  "  # Leave empty before publication so the DaemonSet falls back to appVersion.",
  '  tag: ""',
  "  pullPolicy: IfNotPresent",
  "",
  "healthPath: /health",
  "",
].join("\n");

function chartFixture(name, { values = VALUES, appVersion = "2.2.0" } = {}) {
  const dir = resolve(tempRoot, name);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(resolve(dir, "chart/sockguard"), { recursive: true });
  writeFileSync(resolve(dir, "chart/sockguard/values.yaml"), values);
  writeFileSync(
    resolve(dir, "chart/sockguard/Chart.yaml"),
    `apiVersion: v2\nname: sockguard\nversion: ${appVersion}\nappVersion: "${appVersion}"\n`,
  );
  return dir;
}

function runPin(dir, args) {
  return spawnSync("node", [pinScript, ...args], { cwd: dir, encoding: "utf8" });
}

describe("chart image digest pin", () => {
  it("rejects a digest that is not 64 lowercase hexadecimal characters", () => {
    for (const digest of [
      "sha256:abc",
      `sha256:${"a".repeat(63)}`,
      `sha256:${"a".repeat(65)}`,
      `sha256:${"A".repeat(64)}`,
      `sha512:${"a".repeat(64)}`,
      "",
    ]) {
      assert.throws(
        () => pinChartImageTag({ values: VALUES, appVersion: "2.2.0", version: "2.2.0", digest }),
        /Invalid manifest digest/u,
        `digest ${JSON.stringify(digest)} must be rejected`,
      );
    }
  });

  it("rejects a version that does not match Chart.yaml appVersion", () => {
    assert.throws(
      () =>
        pinChartImageTag({
          values: VALUES,
          appVersion: "2.2.0",
          version: "2.3.0",
          digest: DIGEST,
        }),
      /Refusing to pin 2\.3\.0: chart\/sockguard\/Chart\.yaml declares appVersion "2\.2\.0"/u,
    );
    assert.throws(
      () =>
        pinChartImageTag({ values: VALUES, appVersion: "2.2.0", version: "2.2", digest: DIGEST }),
      /Invalid release version/u,
    );
  });

  it("rewrites only the image.tag line", () => {
    const result = pinChartImageTag({
      values: VALUES,
      appVersion: "2.2.0",
      version: "v2.2.0",
      digest: DIGEST,
    });

    assert.equal(result.changed, true);
    assert.equal(result.tag, `2.2.0@${DIGEST}`);

    const before = VALUES.split("\n");
    const after = result.values.split("\n");
    assert.equal(after.length, before.length);
    const differing = before.flatMap((line, index) => (line === after[index] ? [] : [index]));
    assert.deepEqual(differing, [5]);
    assert.equal(after[5], `  tag: "2.2.0@${DIGEST}"`);
  });

  it("is a no-op when the pin is already present", () => {
    const pinned = pinChartImageTag({
      values: VALUES,
      appVersion: "2.2.0",
      version: "2.2.0",
      digest: DIGEST,
    }).values;

    const again = pinChartImageTag({
      values: pinned,
      appVersion: "2.2.0",
      version: "2.2.0",
      digest: DIGEST,
    });

    assert.equal(again.changed, false);
    assert.equal(again.values, pinned);
  });

  it("refuses to overwrite an unrelated existing tag", () => {
    const stale = VALUES.replace('tag: ""', 'tag: "2.1.0@sha256:' + "b".repeat(64) + '"');

    assert.throws(
      () =>
        pinChartImageTag({ values: stale, appVersion: "2.2.0", version: "2.2.0", digest: DIGEST }),
      /Refusing to overwrite image\.tag/u,
    );
  });

  it("refuses a values file without exactly one image.tag line", () => {
    const noTag = VALUES.replace('  tag: ""\n', "");

    assert.throws(
      () =>
        pinChartImageTag({ values: noTag, appVersion: "2.2.0", version: "2.2.0", digest: DIGEST }),
      /Could not find string image\.tag/u,
    );
  });

  it("accepts a bare hex digest and normalizes it", () => {
    assert.equal(normalizeDigest("a".repeat(64)), DIGEST);
    assert.equal(normalizeDigest(` ${DIGEST} `), DIGEST);
  });

  it("reads appVersion out of Chart.yaml", () => {
    assert.equal(readChartAppVersion('name: sockguard\nappVersion: "2.2.0"\n'), "2.2.0");
    assert.throws(() => readChartAppVersion("name: sockguard\n"), /Could not read appVersion/u);
  });

  it("writes the pin and then reports the second run as a no-op", () => {
    const dir = chartFixture("cli");
    const valuesPath = resolve(dir, "chart/sockguard/values.yaml");

    const first = runPin(dir, ["--version", "2.2.0", "--digest", DIGEST]);
    assert.equal(first.status, 0, first.stderr);
    assert.match(first.stdout, /pinned image\.tag to 2\.2\.0@sha256:a{64}/u);
    assert.match(readFileSync(valuesPath, "utf8"), new RegExp(`tag: "2\\.2\\.0@${DIGEST}"`, "u"));

    const second = runPin(dir, ["--version", "2.2.0", "--digest", DIGEST]);
    assert.equal(second.status, 0, second.stderr);
    assert.match(second.stdout, /is already 2\.2\.0@sha256:a{64} -- nothing to write/u);
  });

  it("exits non-zero and leaves the file alone on a bad digest or version", () => {
    const dir = chartFixture("cli-reject");
    const valuesPath = resolve(dir, "chart/sockguard/values.yaml");

    const badDigest = runPin(dir, ["--version", "2.2.0", "--digest", "sha256:not-hex"]);
    assert.notEqual(badDigest.status, 0);
    assert.match(badDigest.stderr, /Invalid manifest digest/u);

    const badVersion = runPin(dir, ["--version", "2.3.0", "--digest", DIGEST]);
    assert.notEqual(badVersion.status, 0);
    assert.match(badVersion.stderr, /declares appVersion "2\.2\.0"/u);

    assert.equal(readFileSync(valuesPath, "utf8"), VALUES);
  });
});
