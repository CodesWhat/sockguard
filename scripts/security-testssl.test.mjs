import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, '..');
const scriptPath = resolve(scriptDir, 'security-testssl.sh');

function runTestssl(args) {
  return spawnSync('bash', [scriptPath, ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
  });
}

describe('security-testssl.sh', () => {
  it('prints the resolved plan in dry-run mode', () => {
    const result = runTestssl(['--dry-run']);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /listen host:\s+127\.0\.0\.1/);
    assert.match(result.stdout, /listen port:\s+18443/);
    assert.match(result.stdout, /testssl\.sh image:\s+drwetter\/testssl\.sh:3\.2/);
    assert.match(result.stdout, /HIGH\/CRITICAL/);
  });

  it('honors SOCKGUARD_TESTSSL_PORT for an alternate listen port', () => {
    const result = spawnSync('bash', [scriptPath, '--dry-run'], {
      cwd: repoRoot,
      encoding: 'utf8',
      env: { ...process.env, SOCKGUARD_TESTSSL_PORT: '19443' },
    });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /listen port:\s+19443/);
  });

  it('honors TESTSSL_IMAGE for an alternate image tag', () => {
    const result = spawnSync('bash', [scriptPath, '--dry-run'], {
      cwd: repoRoot,
      encoding: 'utf8',
      env: { ...process.env, TESTSSL_IMAGE: 'example.com/testssl:custom' },
    });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /testssl\.sh image:\s+example\.com\/testssl:custom/);
  });

  it('rejects unknown flags', () => {
    const result = runTestssl(['--dry-run', '--bogus']);

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /unknown flag --bogus/);
  });
});
