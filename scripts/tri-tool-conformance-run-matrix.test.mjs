// scripts/tri-tool-conformance-run-matrix.test.mjs
//
// Wires scripts/tri-tool-conformance/run-matrix.sh --self-test into `npm
// test` (package.json's test script globs scripts/*.test.mjs, not the
// tri-tool-conformance/ subdirectory, so this thin wrapper lives one level
// up rather than renaming the harness's own layout). --self-test exercises
// the route normalizer (normalize-routes.jq) and the known-routes.json
// tripwire diff against testdata/access-log-fixture.jsonl -- pure jq, no
// Docker, no network -- so it can run on every push the same way
// verify-published-release.sh's --dry-run does.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, '..');
const scriptPath = resolve(scriptDir, 'tri-tool-conformance', 'run-matrix.sh');

function runSelfTest() {
  return spawnSync('bash', [scriptPath, '--self-test'], {
    cwd: repoRoot,
    encoding: 'utf8',
  });
}

describe('tri-tool-conformance/run-matrix.sh --self-test', () => {
  it('passes the route normalizer + tripwire diff self-test', () => {
    const result = runSelfTest();

    assert.equal(result.status, 0, `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
    assert.match(result.stdout, /== self-test OK ==/);
    assert.match(result.stdout, /PASS: known-routes\.json parses as valid JSON/);
    assert.match(result.stdout, /PASS: normalizer produced the expected 6 route shapes from the fixture/);
    assert.match(
      result.stdout,
      /PASS: diff logic isolated the fixture's one deliberately-unknown route \(GET \/containers\/\*\/attach\)/,
    );
    assert.match(
      result.stdout,
      /PASS: every other fixture route is already recognized in known-routes\.json/,
    );
  });

  it('requires either --row or --self-test', () => {
    const result = spawnSync('bash', [scriptPath], { cwd: repoRoot, encoding: 'utf8' });

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /--row is required/);
  });

  it('rejects an unknown --row value', () => {
    const result = spawnSync('bash', [scriptPath, '--row', 'bogus'], { cwd: repoRoot, encoding: 'utf8' });

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /unknown --row 'bogus'/);
  });
});
