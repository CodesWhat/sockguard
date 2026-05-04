import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, '..');
const scriptPath = resolve(scriptDir, 'local-fuzz.sh');

function runLocalFuzz(args) {
  return spawnSync('bash', [scriptPath, ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
  });
}

describe('local-fuzz.sh', () => {
  it('prints CI-suite native fuzz commands in dry-run mode', () => {
    const result = runLocalFuzz([
      '--dry-run',
      '--suite',
      'ci',
      '--fuzztime',
      '1s',
      '--timeout',
      '5m',
      '--parallel',
      '2',
      '--jobs',
      '2',
    ]);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /FuzzHijackHeadersAndBody/);
    assert.ok(result.stdout.includes("go test -run='^$'"));
    assert.match(result.stdout, /-fuzztime=1s/);
    assert.match(result.stdout, /-timeout=5m/);
    assert.match(result.stdout, /-parallel=2/);
  });

  it('prints Docker Linux fuzz commands in dry-run mode', () => {
    const result = runLocalFuzz([
      '--dry-run',
      '--docker',
      '--platform',
      'linux/amd64',
      '--suite',
      'proxy',
      '--fuzztime',
      '1s',
    ]);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /docker run --rm --platform linux\/amd64/);
    assert.match(result.stdout, /golang:1\.26\.2/);
    assert.match(result.stdout, /\/usr\/local\/go\/bin\/go test/);
    assert.match(result.stdout, /-timeout='10m1s'/);
    assert.match(result.stdout, /FuzzHijackBidirectionalStream/);
  });

  it('rejects unknown suites', () => {
    const result = runLocalFuzz(['--dry-run', '--suite', 'missing']);

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /unknown suite "missing"/);
  });

  it('rejects invalid fuzztime syntax', () => {
    const result = runLocalFuzz(['--dry-run', '--fuzztime', '10minutes']);

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /--fuzztime must use h\/m\/s components/);
  });

  it('rejects invalid timeout syntax', () => {
    const result = runLocalFuzz([
      '--dry-run',
      '--fuzztime',
      '1s',
      '--timeout',
      'five-minutes',
    ]);

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /--timeout must use h\/m\/s components/);
  });

  it('does not duplicate fuzzers in the all suite', () => {
    const result = runLocalFuzz(['--dry-run', '--suite', 'all', '--fuzztime', '1s']);

    assert.equal(result.status, 0, result.stderr);

    const fuzzerLines = result.stdout.split('\n').filter((line) => line.startsWith('[Fuzz'));
    assert.equal(new Set(fuzzerLines).size, fuzzerLines.length);
  });

  it('supports ultra as an alias for the full suite', () => {
    const result = runLocalFuzz(['--dry-run', '--suite', 'ultra', '--fuzztime', '1s']);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /FuzzFilterModifyResponse/);
    assert.match(result.stdout, /FuzzHijackBidirectionalStream/);
  });
});
