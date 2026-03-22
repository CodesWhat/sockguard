import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { extractChangelogEntry } from './extract-changelog-entry.mjs';

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
});
