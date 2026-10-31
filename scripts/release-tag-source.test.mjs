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

function runGuard({
  releaseTag,
  tagSha,
  remoteRecords,
  gitExit = 0,
  security = "| Version | Supported |\n| --- | --- |\n| 3.0.x | :white_check_mark: |\n| 2.4.x | :white_check_mark: |",
}) {
  const fakeGit = resolve(fixtureRoot, "git");
  writeFileSync(
    fakeGit,
    `#!/bin/sh
if [ "${gitExit}" -ne 0 ]; then
  exit "${gitExit}"
fi
case "$1" in
  fetch) exit 0 ;;
  show) printf '%s\\n' "\${MOCK_SECURITY}" ;;
  *) printf '%s\\n' "\${MOCK_REMOTE_RECORDS}" ;;
esac
`,
  );
  chmodSync(fakeGit, 0o755);

  writeFileSync(resolve(fixtureRoot, "output"), "");
  return spawnSync("bash", ["-c", workflowStepScript("Verify release tag is branch HEAD")], {
    cwd: repoRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      DEFAULT_BRANCH: "main",
      GITHUB_REF_NAME: releaseTag,
      GITHUB_SHA: tagSha,
      MOCK_REMOTE_RECORDS: remoteRecords,
      MOCK_SECURITY: security,
      GITHUB_OUTPUT: resolve(fixtureRoot, "output"),
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
    assert.equal(readFileSync(resolve(fixtureRoot, "output"), "utf8"), "latest=true\n");
  });

  it("accepts a supported older maintenance line without promoting latest", () => {
    const result = runGuard({
      releaseTag: "v2.4.2",
      tagSha: stableSha,
      remoteRecords: `${branchRecord("b".repeat(40), "main")}\n${branchRecord(stableSha, "maintenance/2.4.x")}`,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /maintenance\/2\.4\.x HEAD/u);
    assert.match(readFileSync(resolve(fixtureRoot, "output"), "utf8"), /latest=false/u);
  });

  it("rejects maintenance releases absent from the default branch support policy", () => {
    for (const security of [
      "| Version | Supported |\n| --- | --- |\n| 3.0.x | :white_check_mark: |\n| 2.4.x | :x: |",
      "| Version | Supported |\n| --- | --- |\n| 2.4.x | :white_check_mark: |",
      "malformed",
    ]) {
      const result = runGuard({
        releaseTag: "v2.4.2",
        tagSha: stableSha,
        security,
        remoteRecords: `${branchRecord("b".repeat(40), "main")}\n${branchRecord(stableSha, "maintenance/2.4.x")}`,
      });
      assert.notEqual(result.status, 0);
    }
  });

  it("never publishes a prerelease as latest, including when only main matches", () => {
    const accepted = runGuard({
      releaseTag: "v3.0.0-rc.4",
      tagSha: stableSha,
      remoteRecords: branchRecord(stableSha, "dev/v3.0"),
    });
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.equal(readFileSync(resolve(fixtureRoot, "output"), "utf8"), "latest=false\n");
    assert.notEqual(
      runGuard({
        releaseTag: "v3.0.0-rc.4",
        tagSha: stableSha,
        remoteRecords: branchRecord(stableSha, "main"),
      }).status,
      0,
    );
  });

  it("keeps the development branch authoritative for a shared prerelease head", () => {
    const result = runGuard({
      releaseTag: "v3.0.0-rc.4",
      tagSha: stableSha,
      remoteRecords: `${branchRecord(stableSha, "dev/v3.0")}\n${branchRecord(stableSha, "maintenance/3.0.x")}`,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /dev\/v3\.0 HEAD/u);
  });

  it("keeps main authoritative when maintenance shares the same head", () => {
    const result = runGuard({
      releaseTag: "v3.0.1",
      tagSha: stableSha,
      remoteRecords: `${branchRecord(stableSha, "main")}\n${branchRecord(stableSha, "maintenance/3.0.x")}`,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(readFileSync(resolve(fixtureRoot, "output"), "utf8"), "latest=true\n");
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
      releaseTag: "v2.4.2-rc.1",
      tagSha: stableSha,
      remoteRecords: `${branchRecord("b".repeat(40), "main")}\n${branchRecord(stableSha, "maintenance/2.4.x")}`,
    });

    assert.equal(development.status, 0, development.stderr);
    assert.match(development.stdout, /dev\/v2\.0 HEAD/u);
    assert.equal(maintenance.status, 0, maintenance.stderr);
    assert.match(maintenance.stdout, /maintenance\/2\.4\.x HEAD/u);
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
