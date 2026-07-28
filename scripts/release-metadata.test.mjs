import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { SITE_CONFIG } from "../website/src/lib/site-config.ts";
import { roadmap } from "../website/src/lib/site-content.ts";

const stableVersion = SITE_CONFIG.version;
const stableTag = `v${stableVersion}`;
const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

test("release-facing metadata agrees on the current stable version", () => {
  assert.match(stableVersion, /^\d+\.\d+\.\d+$/, "website version must be a stable semver");

  const chart = read("chart/sockguard/Chart.yaml");
  assert.match(chart, new RegExp(`^version: ${stableVersion.replaceAll(".", "\\.")}$`, "m"));
  assert.match(chart, new RegExp(`^appVersion: "${stableVersion.replaceAll(".", "\\.")}"$`, "m"));

  const readme = read("README.md");
  assert.match(readme, new RegExp(`\\*\\*${stableTag.replaceAll(".", "\\.")} is the latest stable release\\.\\*\\*`));

  const changelog = read("CHANGELOG.md");
  assert.match(changelog, new RegExp(`^## \\[${stableVersion.replaceAll(".", "\\.")}\\] - \\d{4}-\\d{2}-\\d{2}$`, "m"));
});

test("the current stable version is the roadmap HEAD", () => {
  const milestone = roadmap.find(({ version }) => version === stableTag);
  assert.ok(milestone, `roadmap must include ${stableTag}`);
  assert.equal(milestone.status, "released", `${stableTag} roadmap milestone must be released`);

  const released = roadmap.filter(({ status }) => status === "released");
  assert.equal(released.at(-1)?.version, stableTag, `${stableTag} must be the latest released milestone`);
});
