import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { extractChangelogEntry, formatCLIError } from './extract-changelog-entry.mjs';

const scriptPath = fileURLToPath(new URL('./extract-changelog-entry.mjs', import.meta.url));

const SAMPLE_CHANGELOG = `# Changelog

## [1.2.0] - 2026-03-20

### Added

- New feature A
- New feature B

### Fixed

- Bug fix C

## [1.1.0] - 2026-03-10

### Added

- Feature D

## [1.0.0] - 2026-01-01

### Added

- Initial release
`;

describe('extractChangelogEntry', () => {
  it('extracts entry for a specific version', () => {
    const entry = extractChangelogEntry(SAMPLE_CHANGELOG, '1.2.0');
    assert.ok(entry.startsWith('## [1.2.0] - 2026-03-20'));
    assert.ok(entry.includes('New feature A'));
    assert.ok(entry.includes('Bug fix C'));
  });

  it('does not include content from other versions', () => {
    const entry = extractChangelogEntry(SAMPLE_CHANGELOG, '1.2.0');
    assert.ok(!entry.includes('Feature D'));
    assert.ok(!entry.includes('Initial release'));
  });

  it('extracts a middle entry correctly', () => {
    const entry = extractChangelogEntry(SAMPLE_CHANGELOG, '1.1.0');
    assert.ok(entry.startsWith('## [1.1.0] - 2026-03-10'));
    assert.ok(entry.includes('Feature D'));
    assert.ok(!entry.includes('New feature A'));
    assert.ok(!entry.includes('Initial release'));
  });

  it('extracts the last entry', () => {
    const entry = extractChangelogEntry(SAMPLE_CHANGELOG, '1.0.0');
    assert.ok(entry.startsWith('## [1.0.0] - 2026-01-01'));
    assert.ok(entry.includes('Initial release'));
  });

  it('handles v-prefixed version input', () => {
    const entry = extractChangelogEntry(SAMPLE_CHANGELOG, 'v1.2.0');
    assert.ok(entry.startsWith('## [1.2.0] - 2026-03-20'));
  });

  it('throws when version is empty', () => {
    assert.throws(() => extractChangelogEntry(SAMPLE_CHANGELOG, ''), /Version is required/);
  });

  it('throws when version is null', () => {
    assert.throws(() => extractChangelogEntry(SAMPLE_CHANGELOG, null), /Version is required/);
  });

  it('throws when version is not found', () => {
    assert.throws(
      () => extractChangelogEntry(SAMPLE_CHANGELOG, '9.9.9'),
      /Changelog entry not found.*9\.9\.9/,
    );
  });

  it('lists available versions in not-found error', () => {
    try {
      extractChangelogEntry(SAMPLE_CHANGELOG, '9.9.9');
      assert.fail('Expected error');
    } catch (error) {
      assert.ok(error.message.includes('1.2.0'));
      assert.ok(error.message.includes('1.1.0'));
      assert.ok(error.message.includes('1.0.0'));
    }
  });

  it('throws for heading without date format', () => {
    const changelog = '## [2.0.0] no date here\n\nSome content\n';
    assert.throws(
      () => extractChangelogEntry(changelog, '2.0.0'),
      /Invalid changelog heading/,
    );
  });

  it('handles empty changelog gracefully', () => {
    assert.throws(
      () => extractChangelogEntry('', '1.0.0'),
      /Changelog entry not found/,
    );
  });

  it('mentions no versions found for empty changelog', () => {
    try {
      extractChangelogEntry('', '1.0.0');
      assert.fail('Expected error');
    } catch (error) {
      assert.ok(error.message.includes('No version headings found'));
    }
  });

  it('handles null changelog input', () => {
    assert.throws(
      () => extractChangelogEntry(null, '1.0.0'),
      /Changelog entry not found/,
    );
  });

  it('returns trimmed content', () => {
    const entry = extractChangelogEntry(SAMPLE_CHANGELOG, '1.2.0');
    assert.equal(entry, entry.trim());
  });

  it('prints an entry from the CLI', () => {
    const tempDir = mkdtempSync(path.join(os.tmpdir(), 'sockguard-changelog-'));
    const changelogPath = path.join(tempDir, 'CHANGELOG.md');
    writeFileSync(changelogPath, SAMPLE_CHANGELOG, 'utf8');

    const result = spawnSync(process.execPath, [scriptPath, 'ignored', '--file', changelogPath, '--version', '1.1.0'], {
      encoding: 'utf8',
    });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /## \[1\.1\.0\] - 2026-03-10/);
    assert.match(result.stdout, /Feature D/);
  });

  it('fails from the CLI when a flag is missing its value', () => {
    const result = spawnSync(process.execPath, [scriptPath, '--file'], {
      encoding: 'utf8',
    });

    assert.equal(result.status, 1);
    assert.match(result.stderr, /Missing value for argument: --file/);
  });

  it('fails from the CLI when a flag is followed by another flag', () => {
    const result = spawnSync(process.execPath, [scriptPath, '--file', '--version', '1.2.0'], {
      encoding: 'utf8',
    });

    assert.equal(result.status, 1);
    assert.match(result.stderr, /Missing value for argument: --file/);
  });

  it('fails from the CLI when version is missing', () => {
    const tempDir = mkdtempSync(path.join(os.tmpdir(), 'sockguard-changelog-'));
    const changelogPath = path.join(tempDir, 'CHANGELOG.md');
    writeFileSync(changelogPath, SAMPLE_CHANGELOG, 'utf8');

    const result = spawnSync(process.execPath, [scriptPath, '--file', changelogPath], {
      encoding: 'utf8',
    });

    assert.equal(result.status, 1);
    assert.match(result.stderr, /--version is required/);
  });

  it('uses CHANGELOG.md by default from the working directory', () => {
    const tempDir = mkdtempSync(path.join(os.tmpdir(), 'sockguard-changelog-'));
    writeFileSync(path.join(tempDir, 'CHANGELOG.md'), SAMPLE_CHANGELOG, 'utf8');

    const result = spawnSync(process.execPath, [scriptPath, '--version', '1.0.0'], {
      cwd: tempDir,
      encoding: 'utf8',
    });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /## \[1\.0\.0\] - 2026-01-01/);
  });

  it('formats non-Error CLI failures', () => {
    assert.equal(formatCLIError('plain failure'), 'plain failure');
  });
});
