import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, '..');
const scriptPath = resolve(scriptDir, 'verify-published-release.sh');

function runVerify(args, env = {}) {
  return spawnSync('bash', [scriptPath, ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
}

describe('verify-published-release.sh', () => {
  it('prints the resolved plan in dry-run mode', () => {
    const result = runVerify(['--dry-run', '--tag', 'v1.2.3']);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /release tag:\s+v1\.2\.3/);
    assert.match(result.stdout, /ghcr\.io\/codeswhat\/sockguard:1\.2\.3/);
    assert.match(result.stdout, /docker\.io\/codeswhat\/sockguard:1\.2\.3/);
    assert.match(result.stdout, /quay\.io\/codeswhat\/sockguard:1\.2\.3/);
    assert.match(result.stdout, /sockguard-v1\.2\.3\.tar\.gz/);
  });

  it('embeds the documented identity regex and issuer', () => {
    const result = runVerify(['--dry-run', '--tag', 'v1.2.3']);

    assert.equal(result.status, 0, result.stderr);
    // The two strings that *must* match docs/content/docs/verification.mdx.
    assert.match(
      result.stdout,
      /\^https:\/\/github\.com\/CodesWhat\/sockguard\/\.github\/workflows\/release-from-tag\.yml@refs\/tags\/\.\+\$/,
    );
    assert.match(result.stdout, /https:\/\/token\.actions\.githubusercontent\.com/);
  });

  it('lowercases GITHUB_REPOSITORY for the ghcr path', () => {
    // GHCR rejects mixed case in image paths; if someone passes an
    // organization name that contains capitals, the script must
    // normalize it for the ghcr.io tag while leaving the identity regex
    // (which is matched against the workflow run URL) in its original
    // case.
    const result = runVerify(['--dry-run', '--tag', 'v0.1.0'], {
      GITHUB_REPOSITORY: 'CodesWhat/Sockguard',
    });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /ghcr\.io\/codeswhat\/sockguard:0\.1\.0/);
    assert.match(
      result.stdout,
      /\^https:\/\/github\.com\/CodesWhat\/Sockguard\/\.github\/workflows\/release-from-tag\.yml@refs\/tags\/\.\+\$/,
    );
  });

  it('requires --tag', () => {
    const result = runVerify(['--dry-run']);

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /--tag .* is required/);
  });

  it('rejects unknown flags', () => {
    const result = runVerify(['--dry-run', '--tag', 'v1.2.3', '--bogus']);

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /unknown flag --bogus/);
  });

  it('accepts --tag=value form', () => {
    const result = runVerify(['--dry-run', '--tag=v9.9.9-rc.1']);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /release tag:\s+v9\.9\.9-rc\.1/);
    assert.match(result.stdout, /sockguard-v9\.9\.9-rc\.1\.tar\.gz/);
  });
});
