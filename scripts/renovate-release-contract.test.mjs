import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { after, describe, it } from "node:test";

const repoRoot = resolve(import.meta.dirname, "..");
const renovatePath = resolve(repoRoot, "renovate.json");
const releaseWorkflowPath = resolve(repoRoot, ".github/workflows/release-cut.yml");
const tempRoot = mkdtempSync(resolve(tmpdir(), "sockguard-renovate-contract-"));

after(() => rmSync(tempRoot, { recursive: true, force: true }));

function renovateConfig() {
  return JSON.parse(readFileSync(renovatePath, "utf8"));
}

function renovateGuardScript() {
  const workflow = readFileSync(releaseWorkflowPath, "utf8");
  const stepStart = workflow.indexOf("      - name: Assert Renovate targets release branch");
  assert.notEqual(stepStart, -1, "Renovate release-branch guard step not found");

  const runStart = workflow.indexOf("        run: |\n", stepStart);
  assert.notEqual(runStart, -1, "Renovate guard run block not found");

  const nextStep = workflow.indexOf("\n      - name:", runStart + 1);
  assert.notEqual(nextStep, -1, "step after Renovate guard not found");

  return workflow
    .slice(runStart + "        run: |\n".length, nextStep)
    .split("\n")
    .map((line) => line.replace(/^ {10}/, ""))
    .join("\n");
}

function runGuard(baseBranchPatterns, releaseTag = "v1.7.0") {
  const fixture = resolve(tempRoot, baseBranchPatterns.join("-").replaceAll("/", "-"));
  rmSync(fixture, { recursive: true, force: true });
  mkdirSync(fixture);
  writeFileSync(resolve(fixture, "renovate.json"), JSON.stringify({ baseBranchPatterns }), {
    flag: "wx",
  });

  return spawnSync("bash", ["-c", renovateGuardScript()], {
    cwd: fixture,
    encoding: "utf8",
    env: { ...process.env, RELEASE_TAG: releaseTag },
  });
}

describe("Renovate release branch contract", () => {
  it("targets exactly the active integration branch", () => {
    const config = renovateConfig();

    assert.deepEqual(config.baseBranchPatterns, ["dev/v1.7"]);
    assert.equal(config.baseBranches, undefined);
  });

  it("accepts the branch derived from the release tag", () => {
    const result = runGuard(["dev/v1.7"]);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /renovate\.json targets dev\/v1\.7/);
  });

  it("rejects a stale or multi-branch Renovate target", () => {
    const stale = runGuard(["dev/v1.6"]);
    const multiple = runGuard(["dev/v1.7", "dev/v1.6"]);

    assert.notEqual(stale.status, 0);
    assert.match(stale.stdout, /targets 'dev\/v1\.6' but this cut is for dev\/v1\.7/);
    assert.notEqual(multiple.status, 0);
    assert.match(multiple.stdout, /targets 'dev\/v1\.7,dev\/v1\.6' but this cut is for dev\/v1\.7/);
  });
});
