import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, describe, it } from "node:test";

const repoRoot = resolve(import.meta.dirname, "..");
const workflowPath = resolve(repoRoot, ".github/workflows/release-from-tag.yml");
const fixtureRoot = mkdtempSync(join(tmpdir(), "sockguard-release-source-"));

after(() => rmSync(fixtureRoot, { recursive: true, force: true }));

function workflowStepScript(stepName) {
  const workflow = readFileSync(workflowPath, "utf8");
  const stepStart = workflow.indexOf(`      - name: ${stepName}`);
  assert.notEqual(stepStart, -1, `${stepName} step not found`);

  const runStart = workflow.indexOf("        run: |\n", stepStart);
  assert.notEqual(runStart, -1, `${stepName} run block not found`);

  const nextStep = workflow.indexOf("\n      - name:", runStart + 1);
  assert.notEqual(nextStep, -1, `step after ${stepName} not found`);

  return workflow
    .slice(runStart + "        run: |\n".length, nextStep)
    .split("\n")
    .map((line) => line.replace(/^ {10}/u, ""))
    .join("\n");
}

function branchRecord(sha, ref) {
  return `${sha}\trefs/heads/${ref}`;
}

function runGuard({ releaseTag, tagSha, remoteRecords, gitExit = 0 }) {
  const fakeGit = resolve(fixtureRoot, "git");
  writeFileSync(
    fakeGit,
    `#!/bin/sh
if [ "${gitExit}" -ne 0 ]; then
  exit "${gitExit}"
fi
printf '%s\\n' "\${MOCK_REMOTE_RECORDS}"
`,
  );
  chmodSync(fakeGit, 0o755);

  return spawnSync("bash", ["-c", workflowStepScript("Verify release tag is branch HEAD")], {
    cwd: repoRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      DEFAULT_BRANCH: "main",
      GITHUB_REF_NAME: releaseTag,
      GITHUB_SHA: tagSha,
      MOCK_REMOTE_RECORDS: remoteRecords,
      PATH: `${fixtureRoot}:${process.env.PATH}`,
    },
  });
}

describe("tag-triggered stable release source guard", () => {
  const stableSha = "a".repeat(40);

  it("accepts a stable tag only when it points at the default-branch head", () => {
    const result = runGuard({
      releaseTag: "v2.0.0",
      tagSha: stableSha,
      remoteRecords: branchRecord(stableSha, "main"),
    });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Stable tag v2\.0\.0 points at main HEAD/u);
  });

  it("rejects a stable tag outside the default-branch head", () => {
    const result = runGuard({
      releaseTag: "v2.0.0",
      tagSha: "b".repeat(40),
      remoteRecords: branchRecord(stableSha, "main"),
    });

    assert.notEqual(result.status, 0);
    assert.match(result.stdout, /must equal main HEAD/u);
  });

  it("fails closed when the default-branch head cannot be resolved", () => {
    const missing = runGuard({
      releaseTag: "v2.0.0",
      tagSha: stableSha,
      remoteRecords: "",
      gitExit: 2,
    });
    const malformed = runGuard({
      releaseTag: "v2.0.0",
      tagSha: stableSha,
      remoteRecords: branchRecord("not-a-sha", "main"),
    });

    assert.notEqual(missing.status, 0);
    assert.notEqual(malformed.status, 0);
  });

  it("accepts prerelease tags only at the matching development or maintenance head", () => {
    const development = runGuard({
      releaseTag: "v2.0.0-rc.5",
      tagSha: stableSha,
      remoteRecords: branchRecord(stableSha, "dev/v2.0"),
    });
    const maintenance = runGuard({
      releaseTag: "v1.7.6-rc.1",
      tagSha: stableSha,
      remoteRecords: branchRecord(stableSha, "maintenance/1.7.x"),
    });

    assert.equal(development.status, 0, development.stderr);
    assert.match(development.stdout, /dev\/v2\.0 HEAD/u);
    assert.equal(maintenance.status, 0, maintenance.stderr);
    assert.match(maintenance.stdout, /maintenance\/1\.7\.x HEAD/u);
  });

  it("rejects prerelease tags at an arbitrary commit", () => {
    const result = runGuard({
      releaseTag: "v2.0.0-rc.5",
      tagSha: "b".repeat(40),
      remoteRecords: branchRecord(stableSha, "dev/v2.0"),
    });

    assert.notEqual(result.status, 0);
    assert.match(result.stdout, /must equal the head of dev\/v2\.0 or maintenance\/2\.0\.x/u);
  });

  it("rejects extra or malformed remote records", () => {
    const extra = runGuard({
      releaseTag: "v2.0.0",
      tagSha: stableSha,
      remoteRecords: `${branchRecord(stableSha, "main")}\nmalformed`,
    });
    const unexpected = runGuard({
      releaseTag: "v2.0.0-rc.5",
      tagSha: stableSha,
      remoteRecords: branchRecord(stableSha, "feature/not-a-release-line"),
    });
    const duplicate = runGuard({
      releaseTag: "v2.0.0-rc.5",
      tagSha: stableSha,
      remoteRecords: `${branchRecord(stableSha, "dev/v2.0")}\n${branchRecord(stableSha, "dev/v2.0")}`,
    });

    assert.notEqual(extra.status, 0);
    assert.notEqual(unexpected.status, 0);
    assert.notEqual(duplicate.status, 0);
  });
});
