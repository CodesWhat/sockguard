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

function workflowStepScript(stepName) {
  const workflow = readFileSync(releaseWorkflowPath, "utf8");
  const stepStart = workflow.indexOf(`      - name: ${stepName}`);
  assert.notEqual(stepStart, -1, `${stepName} step not found`);

  const runStart = workflow.indexOf("        run: |\n", stepStart);
  assert.notEqual(runStart, -1, `${stepName} run block not found`);

  const nextStep = workflow.indexOf("\n      - name:", runStart + 1);
  assert.notEqual(nextStep, -1, `step after ${stepName} not found`);

  return workflow
    .slice(runStart + "        run: |\n".length, nextStep)
    .split("\n")
    .map((line) => line.replace(/^ {10}/, ""))
    .join("\n");
}

function renovateGuardScript() {
  return workflowStepScript("Assert Renovate targets release branch");
}

function runGuard(baseBranchPatterns, releaseTag = "v2.0.0", refName = "main") {
  const fixture = resolve(tempRoot, baseBranchPatterns.join("-").replaceAll("/", "-"));
  rmSync(fixture, { recursive: true, force: true });
  mkdirSync(fixture);
  writeFileSync(resolve(fixture, "renovate.json"), JSON.stringify({ baseBranchPatterns }), {
    flag: "wx",
  });

  return spawnSync("bash", ["-c", renovateGuardScript()], {
    cwd: fixture,
    encoding: "utf8",
    env: { ...process.env, REF_NAME: refName, RELEASE_TAG: releaseTag },
  });
}

function runReleaseBranchGuard(releaseTag, refName, defaultBranch = "main") {
  return spawnSync("bash", ["-c", workflowStepScript("Validate release source branch")], {
    cwd: repoRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      DEFAULT_BRANCH: defaultBranch,
      REF_NAME: refName,
      RELEASE_TAG: releaseTag,
    },
  });
}

describe("Renovate release branch contract", () => {
  it("targets exactly the active integration branch", () => {
    const config = renovateConfig();

    assert.deepEqual(config.baseBranchPatterns, ["dev/v2.2"]);
    assert.equal(config.baseBranches, undefined);
  });

  it("accepts the branch derived from the release tag", () => {
    const result = runGuard(["dev/v2.0"], "v2.0.0", "main");

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /renovate\.json targets dev\/v2\.0/);
  });

  it("accepts the selected maintenance branch for a maintenance candidate", () => {
    const result = runGuard(["maintenance/1.6.x"], "v1.6.4-rc.1", "maintenance/1.6.x");

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /renovate\.json targets maintenance\/1\.6\.x/);
  });

  it("rejects a stale or multi-branch Renovate target", () => {
    const stale = runGuard(["dev/v1.6"]);
    const multiple = runGuard(["dev/v2.0", "dev/v1.7"]);

    assert.notEqual(stale.status, 0);
    assert.match(stale.stdout, /targets 'dev\/v1\.6' but this cut is for dev\/v2\.0/);
    assert.notEqual(multiple.status, 0);
    assert.match(multiple.stdout, /targets 'dev\/v2\.0,dev\/v1\.7' but this cut is for dev\/v2\.0/);
  });

  it("rejects a development Renovate target for a maintenance candidate", () => {
    const result = runGuard(["dev/v1.6"], "v1.6.4-rc.1", "maintenance/1.6.x");

    assert.notEqual(result.status, 0);
    assert.match(result.stdout, /targets 'dev\/v1\.6' but this cut is for maintenance\/1\.6\.x/);
  });
});

// scripts/ci/active-dev-branch.sh is what the two committing workflows
// (quality-mutation-monthly.yml's badge job, release-from-tag.yml's
// pin-chart-digest job) resolve their push target with. `main` rejects a
// direct push, so a resolver that ever answers `main` -- or answers at all
// when renovate.json is stale, empty, or names two branches -- would send
// those jobs at a branch they cannot write.
function runResolver(baseBranchPatterns, defaultBranch = "main") {
  const slug = (baseBranchPatterns ?? ["absent"]).join("-").replaceAll("/", "-") || "empty";
  const fixture = resolve(tempRoot, `resolver-${slug}`);
  rmSync(fixture, { recursive: true, force: true });
  mkdirSync(fixture);
  const config = resolve(fixture, "renovate.json");
  writeFileSync(config, JSON.stringify(baseBranchPatterns ? { baseBranchPatterns } : {}));

  return spawnSync("bash", [resolve(repoRoot, "scripts/ci/active-dev-branch.sh"), config], {
    cwd: fixture,
    encoding: "utf8",
    env: { ...process.env, DEFAULT_BRANCH: defaultBranch },
  });
}

describe("active development branch resolution", () => {
  it("resolves the repository's own configured branch", () => {
    const result = spawnSync("bash", [resolve(repoRoot, "scripts/ci/active-dev-branch.sh")], {
      cwd: repoRoot,
      encoding: "utf8",
    });

    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), renovateConfig().baseBranchPatterns[0]);
  });

  it("accepts a development or a maintenance branch", () => {
    for (const branch of ["dev/v2.2", "dev/v10.11", "maintenance/1.6.x"]) {
      const result = runResolver([branch]);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout.trim(), branch);
    }
  });

  it("refuses to resolve to the default branch", () => {
    for (const branch of ["main", "master"]) {
      const result = runResolver([branch], branch);
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /is not a single dev\/vX\.Y or maintenance\/X\.Y\.x branch/u);
    }
  });

  it("refuses an empty, multi-branch, or unrecognized target", () => {
    for (const patterns of [undefined, [], ["dev/v2.2", "dev/v2.1"], ["release-2.2"], ["dev/v2"]]) {
      const result = runResolver(patterns);
      assert.notEqual(result.status, 0, `${JSON.stringify(patterns)} must be refused`);
      assert.match(result.stderr, /::error::/u);
    }
  });

  it("refuses a missing renovate.json", () => {
    const result = spawnSync(
      "bash",
      [resolve(repoRoot, "scripts/ci/active-dev-branch.sh"), resolve(tempRoot, "absent.json")],
      { encoding: "utf8" },
    );

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /not found; cannot resolve the active development branch/u);
  });
});

describe("release source branch contract", () => {
  it("accepts stable tags on main and prereleases on matching release branches", () => {
    assert.equal(runReleaseBranchGuard("v2.0.0", "main").status, 0);
    assert.equal(runReleaseBranchGuard("v2.0.0-rc.1", "dev/v2.0").status, 0);
    assert.equal(runReleaseBranchGuard("v1.6.4-rc.1", "maintenance/1.6.x").status, 0);
  });

  it("rejects stable tags off main and prereleases on main or a mismatched branch", () => {
    for (const result of [
      runReleaseBranchGuard("v2.0.0", "dev/v2.0"),
      runReleaseBranchGuard("v2.0.0-rc.1", "main"),
      runReleaseBranchGuard("v2.0.0-rc.1", "dev/v1.7"),
      runReleaseBranchGuard("v1.6.4-rc.1", "maintenance/1.7.x"),
    ]) {
      assert.notEqual(result.status, 0);
    }
  });
});
