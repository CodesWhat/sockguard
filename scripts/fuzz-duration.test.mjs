import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, '..');
const helperPath = resolve(scriptDir, 'fuzz-duration.sh');

function runHelper(command) {
  return spawnSync('bash', ['-c', `source "${helperPath}"; ${command}`], {
    cwd: repoRoot,
    encoding: 'utf8',
  });
}

describe('fuzz-duration.sh', () => {
  it('round-trips zero seconds as a Go duration', () => {
    const parsed = runHelper('fuzz_duration_to_seconds 0s');
    assert.equal(parsed.status, 0, parsed.stderr);
    assert.equal(parsed.stdout, '0\n');

    const formatted = runHelper('fuzz_seconds_to_go_duration 0');
    assert.equal(formatted.status, 0, formatted.stderr);
    assert.equal(formatted.stdout, '0s\n');
  });
});
