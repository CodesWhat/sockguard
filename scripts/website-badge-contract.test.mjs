import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { test } from 'node:test';

const repoRoot = resolve(import.meta.dirname, '..');
const githubBadgesPath = resolve(repoRoot, 'website/src/components/github-badges.tsx');

test('website quality badges do not expose Go Report Card', () => {
  const source = readFileSync(githubBadgesPath, 'utf8');

  const qualityLabels = [...source.matchAll(/alt: "([^"]+)"/gu)].map((match) => match[1]);
  assert.deepEqual(qualityLabels, [
    'License Apache-2.0',
    'CI',
    'Go Reference',
    'OpenSSF Scorecard',
  ]);
});
