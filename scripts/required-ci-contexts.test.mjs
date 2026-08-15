import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it } from 'node:test';

const workflow = readFileSync(
  resolve(import.meta.dirname, '../.github/workflows/ci-verify.yml'),
  'utf8',
);

// The nine contexts the main branch-protection ruleset requires after the
// X1 migration to reusable workflows. CodeQL Analysis and Docker Build stay
// local and publish their own `name:` field. The other seven are the
// go-ci/node-ci reusable callers' nested check results, which GitHub
// reports as "<caller job name> / <check name>". Update this list only
// alongside a ruleset change.
const REQUIRED_CONTEXTS = [
  'CodeQL Analysis',
  'Docker Build',
  'Go CI / Go Lint',
  'Go CI / Go Test',
  'Go CI / GoReleaser Config',
  'Go CI / Workflow Security',
  'Node CI / Biome Lint',
  'Node CI / Build Workspaces',
  'Node CI / TS Test',
];

function jobSection(jobId) {
  const jobStart = workflow.indexOf(`  ${jobId}:\n`);
  assert.notEqual(jobStart, -1, `missing required CI job ${jobId}`);

  const nextJob = workflow.slice(jobStart + 1).search(/^  [a-z0-9-]+:\n/m);
  return nextJob === -1
    ? workflow.slice(jobStart)
    : workflow.slice(jobStart, jobStart + 1 + nextJob);
}

function jobName(jobId) {
  const match = jobSection(jobId).match(/^    name: "([^"]+)"$/m);
  assert.ok(match, `required CI job ${jobId} must have an explicit name`);
  return match[1];
}

describe('required CI contexts', () => {
  it('requires exactly the nine post-X1 contexts', () => {
    assert.equal(REQUIRED_CONTEXTS.length, 9);
    assert.equal(new Set(REQUIRED_CONTEXTS).size, 9);
  });

  it('publishes the stable local context for CodeQL Analysis and Docker Build', () => {
    assert.equal(jobName('codeql'), 'CodeQL Analysis');
    assert.equal(jobName('docker'), 'Docker Build');
  });

  it('publishes the caller job name every composite context is prefixed with', () => {
    assert.equal(jobName('go-ci'), 'Go CI');
    assert.equal(jobName('node-ci'), 'Node CI');
  });

  it('pins the check-name input behind every configurable composite context', () => {
    const goCi = jobSection('go-ci');
    assert.ok(
      goCi.includes('      lint-check-name: Go Lint'),
      'go-ci must pin lint-check-name for "Go CI / Go Lint"',
    );
    assert.ok(
      goCi.includes('      test-check-name: Go Test'),
      'go-ci must pin test-check-name for "Go CI / Go Test"',
    );
    assert.ok(
      goCi.includes('      run-workflow-security: true'),
      'go-ci must enable Workflow Security for "Go CI / Workflow Security"',
    );
    assert.match(
      goCi,
      /run-goreleaser:/u,
      'go-ci must gate GoReleaser Config for "Go CI / GoReleaser Config"',
    );

    const nodeCi = jobSection('node-ci');
    assert.ok(
      nodeCi.includes('      lint-check-name: Biome Lint'),
      'node-ci must pin lint-check-name for "Node CI / Biome Lint"',
    );
    assert.ok(
      nodeCi.includes('      test-check-name: TS Test'),
      'node-ci must pin test-check-name for "Node CI / TS Test"',
    );
    assert.ok(
      nodeCi.includes('      build-check-name: Build Workspaces'),
      'node-ci must pin build-check-name for "Node CI / Build Workspaces"',
    );
  });

  it('does not publish emoji in any required context', () => {
    for (const context of REQUIRED_CONTEXTS) {
      assert.doesNotMatch(context, /\p{Extended_Pictographic}/u, context);
    }
  });
});
