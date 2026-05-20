import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, '..');
const scriptPath = resolve(scriptDir, 'soak.sh');

function runSoak(args) {
  return spawnSync('bash', [scriptPath, ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
  });
}

describe('soak.sh', () => {
  it('prints the resolved soak plan in dry-run mode', () => {
    const result = runSoak(['--dry-run']);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /duration:\s+1h/);
    assert.match(result.stdout, /concurrency:\s+20/);
    assert.match(result.stdout, /rss-growth-threshold:\s+67108864 bytes/);
    assert.match(result.stdout, /sample interval:\s+60s/);
    assert.match(result.stdout, /load mix:\s+allow.*GET \/_ping/);
    assert.match(result.stdout, /deny POST \/exec\/x\/start/);
  });

  it('honors --duration, --concurrency, and --rss-growth-threshold-bytes', () => {
    const result = runSoak([
      '--dry-run',
      '--duration', '5m',
      '--concurrency', '10',
      '--rss-growth-threshold-bytes', '1048576',
    ]);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /duration:\s+5m/);
    assert.match(result.stdout, /concurrency:\s+10/);
    assert.match(result.stdout, /rss-growth-threshold:\s+1048576 bytes/);
  });

  it('rejects --duration without an s/m/h suffix', () => {
    const result = runSoak(['--dry-run', '--duration', '1x']);

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /--duration must end in s\/m\/h/);
  });

  it('rejects non-positive --concurrency', () => {
    const result = runSoak(['--dry-run', '--concurrency', '0']);

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /--concurrency must be > 0/);
  });

  it('rejects non-numeric --rss-growth-threshold-bytes', () => {
    const result = runSoak(['--dry-run', '--rss-growth-threshold-bytes', '64MiB']);

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /--rss-growth-threshold-bytes must be a non-negative integer/);
  });

  it('rejects unknown flags', () => {
    const result = runSoak(['--dry-run', '--whatever']);

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /unknown flag --whatever/);
  });
});
