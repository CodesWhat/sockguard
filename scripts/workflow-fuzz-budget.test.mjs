import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it } from 'node:test';

const repoRoot = resolve(import.meta.dirname, '..');

const workflowPaths = [
  '.github/workflows/quality-fuzz-nightly.yml',
  '.github/workflows/quality-fuzz-monthly.yml',
];

function resolveBudgetRunBlock(source) {
  const start = source.indexOf('      - name: Resolve fuzz budget');
  assert.notEqual(start, -1, 'Resolve fuzz budget step not found');

  const runStart = source.indexOf('        run: |', start);
  assert.notEqual(runStart, -1, 'Resolve fuzz budget run block not found');

  const nextStep = source.indexOf('\n      - name:', runStart + 1);
  assert.notEqual(nextStep, -1, 'next workflow step not found');

  return source.slice(runStart, nextStep);
}

describe('quality fuzz workflows', () => {
  for (const workflowPath of workflowPaths) {
    it(`${workflowPath} writes outputs only after fuzz budget validation succeeds`, () => {
      const source = readFileSync(resolve(repoRoot, workflowPath), 'utf8');
      const lines = resolveBudgetRunBlock(source).split('\n');

      const timeoutLineIndex = lines.findIndex((line) =>
        line.includes('fuzz_timeout_for_budget "${FUZZTIME}" 600'),
      );
      const firstOutputLineIndex = lines.findIndex((line) => line.includes('>> "$GITHUB_OUTPUT"'));

      assert.notEqual(timeoutLineIndex, -1, 'fuzz_timeout_for_budget line not found');
      assert.notEqual(firstOutputLineIndex, -1, 'GITHUB_OUTPUT write not found');
      assert.ok(
        firstOutputLineIndex > timeoutLineIndex,
        'GITHUB_OUTPUT writes must come after fuzz_timeout_for_budget',
      );
      assert.match(
        lines[timeoutLineIndex],
        /\|\| exit 1/,
        'fuzz_timeout_for_budget must be guarded before writing GITHUB_OUTPUT',
      );
    });
  }
});
