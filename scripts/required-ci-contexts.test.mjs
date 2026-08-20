import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, it } from "node:test";

const ciVerify = readFileSync(
  resolve(import.meta.dirname, "../.github/workflows/ci-verify.yml"),
  "utf8",
);

const securityGrype = readFileSync(
  resolve(import.meta.dirname, "../.github/workflows/security-grype.yml"),
  "utf8",
);

// The seventeen contexts the main branch-protection ruleset requires after
// the X1 migration to reusable workflows, the PR-gate closure that added
// dependency-review, gitleaks, actionlint, and shellcheck, the Commit
// Message job becoming genuinely blocking, and security-grype.yml's PR jobs
// joining the gate now that its `paths:` filter moved off the trigger (a
// required check on a job inside a workflow that never triggers produces no
// check run at all, which deadlocks branch protection forever — see that
// file's `changes` job for the fix). CodeQL Analysis, Docker Build,
// Dependency Review, Gitleaks, Actionlint, Shellcheck, and Commit Message
// stay local to ci-verify.yml and publish their own `name:` field, as do the
// three Security: * jobs in security-grype.yml. The other seven are the
// go-ci/node-ci reusable callers' nested check results, which GitHub
// reports as "<caller job name> / <check name>". Update this list only
// alongside a ruleset change.
const REQUIRED_CONTEXTS = [
  "CodeQL Analysis",
  "Docker Build",
  "Go CI / Go Lint",
  "Go CI / Go Test",
  "Go CI / GoReleaser Config",
  "Go CI / Workflow Security",
  "Node CI / Biome Lint",
  "Node CI / Build Workspaces",
  "Node CI / TS Test",
  "Actionlint",
  "Dependency Review",
  "Gitleaks",
  "Shellcheck",
  "Commit Message",
  "Security: Govulncheck",
  "Security: Grype Dependency Scan (Go + npm)",
  "Security: Gosec SAST",
];

function jobSection(workflow, jobId) {
  const jobStart = workflow.indexOf(`  ${jobId}:\n`);
  assert.notEqual(jobStart, -1, `missing required CI job ${jobId}`);

  const nextJob = workflow.slice(jobStart + 1).search(/^  [a-z0-9-]+:\n/m);
  return nextJob === -1
    ? workflow.slice(jobStart)
    : workflow.slice(jobStart, jobStart + 1 + nextJob);
}

function jobName(workflow, jobId) {
  const match = jobSection(workflow, jobId).match(/^    name: "([^"]+)"$/m);
  assert.ok(match, `required CI job ${jobId} must have an explicit name`);
  return match[1];
}

describe("required CI contexts", () => {
  it("requires exactly the seventeen post-gate-closure contexts", () => {
    assert.equal(REQUIRED_CONTEXTS.length, 17);
    assert.equal(new Set(REQUIRED_CONTEXTS).size, 17);
  });

  it("publishes the stable local context for CodeQL Analysis, Docker Build, Dependency Review, Gitleaks, Actionlint, Shellcheck, and Commit Message", () => {
    assert.equal(jobName(ciVerify, "codeql"), "CodeQL Analysis");
    assert.equal(jobName(ciVerify, "docker"), "Docker Build");
    assert.equal(jobName(ciVerify, "dependency-review"), "Dependency Review");
    assert.equal(jobName(ciVerify, "gitleaks"), "Gitleaks");
    assert.equal(jobName(ciVerify, "actionlint"), "Actionlint");
    assert.equal(jobName(ciVerify, "shellcheck"), "Shellcheck");
    assert.equal(jobName(ciVerify, "commit-message"), "Commit Message");
  });

  it("publishes the caller job name every composite context is prefixed with", () => {
    assert.equal(jobName(ciVerify, "go-ci"), "Go CI");
    assert.equal(jobName(ciVerify, "node-ci"), "Node CI");
  });

  it("pins the check-name input behind every configurable composite context", () => {
    const goCi = jobSection(ciVerify, "go-ci");
    assert.ok(
      goCi.includes("      lint-check-name: Go Lint"),
      'go-ci must pin lint-check-name for "Go CI / Go Lint"',
    );
    assert.ok(
      goCi.includes("      test-check-name: Go Test"),
      'go-ci must pin test-check-name for "Go CI / Go Test"',
    );
    assert.ok(
      goCi.includes("      run-workflow-security: true"),
      'go-ci must enable Workflow Security for "Go CI / Workflow Security"',
    );
    assert.match(
      goCi,
      /run-goreleaser:/u,
      'go-ci must gate GoReleaser Config for "Go CI / GoReleaser Config"',
    );

    const nodeCi = jobSection(ciVerify, "node-ci");
    assert.ok(
      nodeCi.includes("      lint-check-name: Biome Lint"),
      'node-ci must pin lint-check-name for "Node CI / Biome Lint"',
    );
    assert.ok(
      nodeCi.includes("      test-check-name: TS Test"),
      'node-ci must pin test-check-name for "Node CI / TS Test"',
    );
    assert.ok(
      nodeCi.includes("      build-check-name: Build Workspaces"),
      'node-ci must pin build-check-name for "Node CI / Build Workspaces"',
    );
  });

  it("makes the Commit Message job genuinely blocking", () => {
    const commitMessage = jobSection(ciVerify, "commit-message");
    assert.doesNotMatch(
      commitMessage,
      /continue-on-error:\s*true/u,
      "commit-message must not be advisory-only (continue-on-error: true)",
    );
    assert.match(
      commitMessage,
      /\bexit 1\b/u,
      "commit-message must exit non-zero on a non-conventional commit",
    );
  });

  it("exempts the promotion PR from the Commit Message gate", () => {
    // `dev/vX.Y -> main` re-presents every commit on the dev branch as
    // "introduced by this PR". This repo's history predates the gate — the
    // #185 BuildKit series landed eight gitmoji subjects that are on
    // dev/v1.7 and not on main — and published history is never rewritten,
    // so without this exemption a blocking gate deadlocks every release
    // cut. Those commits are validated when they land on the dev branch,
    // which is where the gate belongs.
    const commitMessage = jobSection(ciVerify, "commit-message");
    assert.match(
      commitMessage,
      /main:dev\/\*\|main:maintenance\/\*/u,
      "commit-message must skip promotion PRs into main from a dev/ or maintenance/ branch",
    );
  });

  it("publishes the stable local context for every PR-gated Security: * job", () => {
    assert.equal(jobName(securityGrype, "govulncheck"), "Security: Govulncheck");
    assert.equal(
      jobName(securityGrype, "grype-deps"),
      "Security: Grype Dependency Scan (Go + npm)",
    );
    assert.equal(jobName(securityGrype, "gosec"), "Security: Gosec SAST");
  });

  it("gates every required Security: * job on the changes job instead of a trigger-level paths filter", () => {
    // A required status check on a job inside a workflow that never
    // triggers produces no check run at all, which deadlocks branch
    // protection on a doc-only PR forever — so security-grype.yml's
    // `pull_request:` trigger must stay unfiltered, and the path scoping
    // must live in the `changes` job's `if:` gate instead.
    const trigger = securityGrype.slice(
      securityGrype.indexOf("pull_request:"),
      securityGrype.indexOf("schedule:"),
    );
    assert.doesNotMatch(
      trigger,
      /paths:/u,
      "security-grype.yml must not filter pull_request by paths: at the trigger level",
    );

    for (const jobId of ["govulncheck", "grype-deps", "gosec"]) {
      const section = jobSection(securityGrype, jobId);
      assert.match(section, /needs:\s*changes/u, `${jobId} must depend on the changes job`);
      assert.match(
        section,
        /if:\s*needs\.changes\.outputs\.security\s*==\s*'true'/u,
        `${jobId} must be gated on changes.outputs.security`,
      );
    }
  });

  it("does not publish emoji in any required context", () => {
    for (const context of REQUIRED_CONTEXTS) {
      assert.doesNotMatch(context, /\p{Extended_Pictographic}/u, context);
    }
  });

  it("keeps emoji out of every workflow and job name", () => {
    // A check context is matched by exact string, so an emoji in a job
    // name is a decorative character that's load-bearing for merges — and
    // the whole set has to stay clean, not just the names that happen to
    // be required today, or promoting one later silently orphans it.
    // security-zap-baseline.yml landed with emoji one merge after the
    // original sweep, which is why this is a test and not a one-off edit.
    const dir = resolve(import.meta.dirname, "../.github/workflows");
    const offenders = [];
    for (const file of readdirSync(dir).filter((f) => f.endsWith(".yml"))) {
      const lines = readFileSync(resolve(dir, file), "utf8").split("\n");
      lines.forEach((line, i) => {
        if (!/^\s*(name|run-name):/u.test(line)) return;
        if (/\p{Extended_Pictographic}/u.test(line)) {
          offenders.push(`${file}:${i + 1} ${line.trim()}`);
        }
      });
    }
    assert.deepEqual(offenders, [], `emoji in workflow names:\n${offenders.join("\n")}`);
  });
});
