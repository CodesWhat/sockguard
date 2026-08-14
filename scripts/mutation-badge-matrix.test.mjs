import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it } from 'node:test';

const repoRoot = resolve(import.meta.dirname, '..');
const workflowPath = '.github/workflows/quality-mutation-monthly.yml';

describe('quality mutation workflow', () => {
  it('publishes a badge only when every matrix package reported', () => {
    const source = readFileSync(resolve(repoRoot, workflowPath), 'utf8');

    // The aggregation step hardcodes how many reports a complete run produces.
    // If someone adds or drops a package from the matrix without updating it,
    // the badge either never publishes or publishes a partial score.
    const declared = source.match(/^\s*expected_reports=(\d+)$/mu);
    assert.ok(declared, 'expected_reports assignment not found');

    const matrixStart = source.indexOf('      matrix:');
    assert.notEqual(matrixStart, -1, 'mutation matrix not found');
    const steps = source.indexOf('\n    steps:', matrixStart);
    assert.notEqual(steps, -1, 'end of matrix block not found');
    const packages = source.slice(matrixStart, steps).match(/^\s+- name: /gmu) ?? [];

    assert.equal(
      Number(declared[1]),
      packages.length,
      `expected_reports=${declared[1]} does not match the ${packages.length} packages in the mutation matrix`,
    );
  });

  it('reports the parsed count when the report set is incomplete', () => {
    const source = readFileSync(resolve(repoRoot, workflowPath), 'utf8');
    const incompleteStart = source.indexOf(
      '          if [ "$reports_found" -ne "$expected_reports" ]; then',
    );
    assert.notEqual(incompleteStart, -1, 'incomplete-report branch not found');
    const incompleteEnd = source.indexOf('          fi', incompleteStart);
    assert.notEqual(incompleteEnd, -1, 'end of incomplete-report branch not found');
    const incompleteBranch = source.slice(incompleteStart, incompleteEnd);

    assert.match(
      incompleteBranch,
      /echo "reports_found=\$\{reports_found\}" >> "\$GITHUB_OUTPUT"/u,
      'incomplete-report branch does not export reports_found',
    );
    assert.match(
      incompleteBranch,
      /echo "expected_reports=\$\{expected_reports\}" >> "\$GITHUB_OUTPUT"/u,
      'incomplete-report branch does not export expected_reports',
    );
    assert.match(
      source,
      /EXPECTED_REPORTS: \$\{\{ steps\.score\.outputs\.expected_reports \}\}/u,
      'summary does not consume expected_reports',
    );
    assert.match(
      source,
      /Incomplete report set: \$\{REPORTS_FOUND\} of \$\{EXPECTED_REPORTS\}; badge left unchanged\./u,
      'summary does not distinguish an incomplete report set from an empty one',
    );
  });
});
