import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it } from 'node:test';

const workflow = readFileSync(
  resolve(import.meta.dirname, '../.github/workflows/ci-verify.yml'),
  'utf8',
);

const requiredJobs = new Map([
  ['zizmor', 'Workflow Security'],
  ['codeql', 'CodeQL Analysis'],
  ['goreleaser-check', 'GoReleaser Config'],
  ['go-lint', 'Go Lint'],
  ['go-test', 'Go Test'],
  ['ts-lint', 'Biome Lint'],
  ['ts-test', 'TS Test'],
  ['ts-build', 'Build Workspaces'],
  ['docker', 'Docker Build'],
]);

function jobName(jobId) {
  const jobStart = workflow.indexOf(`  ${jobId}:\n`);
  assert.notEqual(jobStart, -1, `missing required CI job ${jobId}`);

  const nextJob = workflow.slice(jobStart + 1).search(/^  [a-z0-9-]+:\n/m);
  const job = nextJob === -1
    ? workflow.slice(jobStart)
    : workflow.slice(jobStart, jobStart + 1 + nextJob);
  const match = job.match(/^    name: "([^"]+)"$/m);
  assert.ok(match, `required CI job ${jobId} must have an explicit name`);
  return match[1];
}

describe('required CI contexts', () => {
  it('publishes the stable plain context for every required job', () => {
    for (const [jobId, expectedName] of requiredJobs) {
      assert.equal(jobName(jobId), expectedName, jobId);
    }
  });

  it('does not publish emoji in any required context', () => {
    for (const jobId of requiredJobs.keys()) {
      assert.doesNotMatch(jobName(jobId), /\p{Extended_Pictographic}/u, jobId);
    }
  });
});
