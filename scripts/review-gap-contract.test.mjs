import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, it } from "node:test";

const workflow = readFileSync(
  resolve(import.meta.dirname, "../.github/workflows/ci-verify.yml"),
  "utf8",
);

const requiredContexts = [
  {
    upstream: "zizmor",
    legacyName: "🔒 Workflow Security",
    bridge: "bridge-workflow-security",
    requiredName: "Workflow Security",
    pullRequestCondition: null,
  },
  {
    upstream: "codeql",
    legacyName: "🔍 CodeQL Analysis",
    bridge: "bridge-codeql-analysis",
    requiredName: "CodeQL Analysis",
    pullRequestCondition: "github.event_name == 'pull_request'",
  },
  {
    upstream: "goreleaser-check",
    legacyName: "📦 GoReleaser Config",
    bridge: "bridge-goreleaser-config",
    requiredName: "GoReleaser Config",
    pullRequestCondition: "github.event_name != 'schedule'",
  },
  {
    upstream: "go-lint",
    legacyName: "🧹 Go Lint",
    bridge: "bridge-go-lint",
    requiredName: "Go Lint",
    pullRequestCondition: "github.event_name != 'schedule'",
  },
  {
    upstream: "go-test",
    legacyName: "🧪 Go Test",
    bridge: "bridge-go-test",
    requiredName: "Go Test",
    pullRequestCondition: "github.event_name != 'schedule'",
  },
  {
    upstream: "ts-lint",
    legacyName: "🎨 Biome Lint",
    bridge: "bridge-biome-lint",
    requiredName: "Biome Lint",
    pullRequestCondition: "github.event_name != 'schedule'",
  },
  {
    upstream: "ts-test",
    legacyName: "🧪 TS Test",
    bridge: "bridge-ts-test",
    requiredName: "TS Test",
    pullRequestCondition: "github.event_name != 'schedule'",
  },
  {
    upstream: "ts-build",
    legacyName: "🏗️ Build Workspaces",
    bridge: "bridge-build-workspaces",
    requiredName: "Build Workspaces",
    pullRequestCondition: "github.event_name != 'schedule'",
  },
  {
    upstream: "docker",
    legacyName: "🐳 Docker Build",
    bridge: "bridge-docker-build",
    requiredName: "Docker Build",
    pullRequestCondition: "github.event_name != 'schedule'",
  },
];

function jobBlock(jobId) {
  const jobStart = workflow.indexOf(`  ${jobId}:\n`);
  assert.notEqual(jobStart, -1, `missing CI job ${jobId}`);

  const nextJob = workflow.slice(jobStart + 1).search(/^  [a-z0-9-]+:\n/m);
  return nextJob === -1
    ? workflow.slice(jobStart)
    : workflow.slice(jobStart, jobStart + 1 + nextJob);
}

function jobName(jobId) {
  const match = jobBlock(jobId).match(/^    name: "([^"]+)"$/m);
  assert.ok(match, `CI job ${jobId} must have an explicit literal name`);
  return match[1];
}

describe("temporary review-gap CI bridges", () => {
  it("keeps the reverted upstream jobs under their legacy names", () => {
    for (const entry of requiredContexts) {
      assert.equal(jobName(entry.upstream), entry.legacyName, entry.upstream);
    }
  });

  it("keeps every guarded upstream job runnable on pull requests", () => {
    for (const entry of requiredContexts) {
      const block = jobBlock(entry.upstream);
      if (entry.pullRequestCondition === null) {
        assert.doesNotMatch(block, /^    if:/m, entry.upstream);
      } else {
        assert.match(block, new RegExp(entry.pullRequestCondition.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
      }
    }
  });

  it("emits each required plain context exactly once through a fail-closed bridge", () => {
    const emittedNames = [...workflow.matchAll(/^    name: "([^"]+)"$/gm)].map(
      (match) => match[1],
    );

    for (const entry of requiredContexts) {
      const bridge = jobBlock(entry.bridge);
      assert.equal(jobName(entry.bridge), entry.requiredName, entry.bridge);
      assert.equal(
        emittedNames.filter((name) => name === entry.requiredName).length,
        1,
        entry.requiredName,
      );
      assert.match(bridge, /^    if: \$\{\{ always\(\) \}\}$/m, entry.bridge);
      assert.match(bridge, new RegExp(`^    needs: ${entry.upstream}$`, "m"), entry.bridge);
      assert.match(bridge, /^    permissions: \{\}$/m, entry.bridge);
      assert.match(
        bridge,
        new RegExp(`^          UPSTREAM_RESULT: \\$\\{\\{ needs\\.${entry.upstream}\\.result \\}\\}$`, "m"),
        entry.bridge,
      );
      assert.match(
        bridge,
        /^        run: test "\$\{UPSTREAM_RESULT\}" = success$/m,
        entry.bridge,
      );
    }
  });
});
