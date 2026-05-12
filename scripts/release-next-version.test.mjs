import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { inferReleaseLevel, bumpSemver, formatCLIError } from './release-next-version.mjs';

const scriptPath = fileURLToPath(new URL('./release-next-version.mjs', import.meta.url));

describe('inferReleaseLevel', () => {
  it('returns null for empty commit list', () => {
    assert.equal(inferReleaseLevel([]), null);
  });

  it('returns null for non-conventional commits', () => {
    assert.equal(inferReleaseLevel(['random commit message']), null);
  });

  it('returns null for empty/whitespace commits', () => {
    assert.equal(inferReleaseLevel(['', '  ', null, undefined]), null);
  });

  it('returns patch for fix commits', () => {
    assert.equal(inferReleaseLevel(['🐛 fix: resolve crash']), 'patch');
  });

  it('returns patch for docs commits', () => {
    assert.equal(inferReleaseLevel(['📝 docs: update readme']), 'patch');
  });

  it('returns patch for refactor commits', () => {
    assert.equal(inferReleaseLevel(['🔄 refactor: simplify logic']), 'patch');
  });

  it('returns patch for other patch types', () => {
    for (const type of ['style', 'perf', 'test', 'chore', 'security', 'deps', 'revert']) {
      assert.equal(
        inferReleaseLevel([`🔧 ${type}: something`]),
        'patch',
        `expected patch for type: ${type}`,
      );
    }
  });

  it('returns minor for feat commits', () => {
    assert.equal(inferReleaseLevel(['✨ feat: new feature']), 'minor');
  });

  it('returns minor when feat mixed with patch types', () => {
    assert.equal(
      inferReleaseLevel(['🐛 fix: a fix', '✨ feat: a feature']),
      'minor',
    );
  });

  it('returns major for bang after type', () => {
    assert.equal(inferReleaseLevel(['✨ feat!: breaking feature']), 'major');
  });

  it('returns major for bang after scope', () => {
    assert.equal(
      inferReleaseLevel(['✨ feat(api)!: breaking change']),
      'major',
    );
  });

  it('returns major for BREAKING CHANGE in body', () => {
    assert.equal(
      inferReleaseLevel(['✨ feat: something\n\nBREAKING CHANGE: removed api']),
      'major',
    );
  });

  it('returns major for BREAKING-CHANGE in body', () => {
    assert.equal(
      inferReleaseLevel(['✨ feat: something\n\nBREAKING-CHANGE: removed api']),
      'major',
    );
  });

  it('returns major immediately even if other commits follow', () => {
    assert.equal(
      inferReleaseLevel([
        '🐛 fix: minor fix',
        '✨ feat!: breaking',
        '✨ feat: another feature',
      ]),
      'major',
    );
  });

  it('ignores commits without conventional prefix', () => {
    assert.equal(
      inferReleaseLevel(['merge branch main', '🐛 fix: actual fix']),
      'patch',
    );
  });

  it('handles commit without emoji prefix', () => {
    assert.equal(inferReleaseLevel(['feat: no emoji']), 'minor');
  });

  it('handles scope in parentheses', () => {
    assert.equal(inferReleaseLevel(['✨ feat(core): scoped']), 'minor');
  });
});

describe('bumpSemver', () => {
  it('bumps major version', () => {
    assert.equal(bumpSemver('1.2.3', 'major'), '2.0.0');
  });

  it('bumps minor version', () => {
    assert.equal(bumpSemver('1.2.3', 'minor'), '1.3.0');
  });

  it('bumps patch version', () => {
    assert.equal(bumpSemver('1.2.3', 'patch'), '1.2.4');
  });

  it('handles v-prefixed version', () => {
    assert.equal(bumpSemver('v1.2.3', 'major'), '2.0.0');
  });

  it('handles whitespace around version', () => {
    assert.equal(bumpSemver('  1.2.3  ', 'patch'), '1.2.4');
  });

  it('bumps from 0.x correctly', () => {
    assert.equal(bumpSemver('0.1.0', 'minor'), '0.2.0');
    assert.equal(bumpSemver('0.0.1', 'major'), '1.0.0');
  });

  it('throws on invalid version', () => {
    assert.throws(() => bumpSemver('not-a-version', 'patch'), /Invalid current version/);
  });

  it('throws on null/undefined version', () => {
    assert.throws(() => bumpSemver(null, 'patch'), /Invalid current version/);
    assert.throws(() => bumpSemver(undefined, 'patch'), /Invalid current version/);
  });

  it('throws on empty version', () => {
    assert.throws(() => bumpSemver('', 'patch'), /Invalid current version/);
  });

  it('throws on invalid level', () => {
    assert.throws(() => bumpSemver('1.0.0', 'invalid'), /Invalid release level/);
  });

  it('throws on prerelease version', () => {
    assert.throws(() => bumpSemver('1.0.0-beta.1', 'patch'), /Invalid current version/);
  });
});

describe('release-next-version CLI', () => {
  it('prints a manual bump result', () => {
    const result = spawnSync(process.execPath, [scriptPath, 'ignored', '--current', '1.2.3', '--bump', 'minor'], {
      encoding: 'utf8',
    });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /release_level=minor/);
    assert.match(result.stdout, /next_version=1\.3\.0/);
  });

  it('fails when a CLI flag is missing its value', () => {
    const result = spawnSync(process.execPath, [scriptPath, '--current'], {
      encoding: 'utf8',
    });

    assert.equal(result.status, 1);
    assert.match(result.stderr, /Missing value for argument: --current/);
  });

  it('fails when a CLI flag is followed by another flag', () => {
    const result = spawnSync(process.execPath, [scriptPath, '--current', '--bump', 'patch'], {
      encoding: 'utf8',
    });

    assert.equal(result.status, 1);
    assert.match(result.stderr, /Missing value for argument: --current/);
  });

  it('fails when current version is missing', () => {
    const result = spawnSync(process.execPath, [scriptPath, '--bump', 'patch'], {
      encoding: 'utf8',
    });

    assert.equal(result.status, 1);
    assert.match(result.stderr, /--current is required/);
  });

  it('fails when auto bump is missing the from ref', () => {
    const result = spawnSync(process.execPath, [scriptPath, '--current', '1.2.3'], {
      encoding: 'utf8',
    });

    assert.equal(result.status, 1);
    assert.match(result.stderr, /--from is required when --bump auto/);
  });

  it('computes an auto bump from git history', () => {
    const repoDir = createTempGitRepo();
    writeFileSync(path.join(repoDir, 'README.md'), 'initial\n', 'utf8');
    git(repoDir, ['add', 'README.md']);
    git(repoDir, ['commit', '-m', 'chore: initial']);
    const fromRef = git(repoDir, ['rev-parse', 'HEAD']).trim();

    writeFileSync(path.join(repoDir, 'README.md'), 'initial\nfix\n', 'utf8');
    git(repoDir, ['add', 'README.md']);
    git(repoDir, ['commit', '-m', '🐛 fix: patch release']);

    const result = spawnSync(process.execPath, [scriptPath, '--current', '1.2.3', '--from', fromRef], {
      cwd: repoDir,
      encoding: 'utf8',
    });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /release_level=patch/);
    assert.match(result.stdout, /next_version=1\.2\.4/);
  });

  it('computes an auto bump with an explicit to ref', () => {
    const repoDir = createTempGitRepo();
    writeFileSync(path.join(repoDir, 'README.md'), 'initial\n', 'utf8');
    git(repoDir, ['add', 'README.md']);
    git(repoDir, ['commit', '-m', 'chore: initial']);
    const fromRef = git(repoDir, ['rev-parse', 'HEAD']).trim();

    writeFileSync(path.join(repoDir, 'README.md'), 'initial\nfeature\n', 'utf8');
    git(repoDir, ['add', 'README.md']);
    git(repoDir, ['commit', '-m', '✨ feat: minor release']);
    const toRef = git(repoDir, ['rev-parse', 'HEAD']).trim();

    const result = spawnSync(process.execPath, [scriptPath, '--current', '1.2.3', '--from', fromRef, '--to', toRef], {
      cwd: repoDir,
      encoding: 'utf8',
    });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /release_level=minor/);
    assert.match(result.stdout, /next_version=1\.3\.0/);
  });

  it('fails when auto bump finds no releasable commits', () => {
    const repoDir = createTempGitRepo();
    writeFileSync(path.join(repoDir, 'README.md'), 'initial\n', 'utf8');
    git(repoDir, ['add', 'README.md']);
    git(repoDir, ['commit', '-m', 'chore: initial']);
    const fromRef = git(repoDir, ['rev-parse', 'HEAD']).trim();

    writeFileSync(path.join(repoDir, 'README.md'), 'initial\nnoise\n', 'utf8');
    git(repoDir, ['add', 'README.md']);
    git(repoDir, ['commit', '-m', 'merge branch main']);

    const result = spawnSync(process.execPath, [scriptPath, '--current', '1.2.3', '--from', fromRef], {
      cwd: repoDir,
      encoding: 'utf8',
    });

    assert.equal(result.status, 1);
    assert.match(result.stderr, /No releasable commits found between refs/);
  });

  it('formats non-Error CLI failures', () => {
    assert.equal(formatCLIError('plain failure'), 'plain failure');
  });
});

function createTempGitRepo() {
  const repoDir = mkdtempSync(path.join(os.tmpdir(), 'sockguard-release-'));
  git(repoDir, ['init']);
  git(repoDir, ['config', 'user.name', 'Sockguard Tests']);
  git(repoDir, ['config', 'user.email', 'sockguard-tests@example.com']);
  return repoDir;
}

function git(cwd, args) {
  const env = { ...process.env };
  delete env.GIT_DIR;
  delete env.GIT_WORK_TREE;
  return execFileSync('git', args, {
    cwd,
    env,
    encoding: 'utf8',
  });
}
