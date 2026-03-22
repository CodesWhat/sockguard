import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { inferReleaseLevel, bumpSemver } from './release-next-version.mjs';

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
