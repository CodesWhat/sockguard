import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { describe, it } from 'node:test';

const repoRoot = resolve(import.meta.dirname, '..');
const chartPath = resolve(repoRoot, 'chart/sockguard');

function renderChart(args = []) {
  const result = spawnSync('helm', ['template', 'sockguard', chartPath, ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
  });

  assert.equal(result.error, undefined, `helm is required to test the rendered chart: ${result.error}`);
  assert.equal(result.status, 0, result.stderr);

  const daemonSet = result.stdout
    .split(/^---\s*$/m)
    .find((document) => /^kind: DaemonSet$/m.test(document));
  assert.ok(daemonSet, 'rendered chart must contain a DaemonSet');
  return daemonSet;
}

function indentedBlock(source, heading, indentation) {
  const prefix = ' '.repeat(indentation);
  const startMarker = `${prefix}${heading}:`;
  const lines = source.split('\n');
  const start = lines.findIndex((line) => line === startMarker);
  assert.notEqual(start, -1, `${heading} block at indentation ${indentation} not found`);

  const endOffset = lines
    .slice(start + 1)
    .findIndex((line) => line.trim() !== '' && line.length - line.trimStart().length <= indentation);
  const end = endOffset === -1 ? lines.length : start + 1 + endOffset;
  return lines.slice(start + 1, end).join('\n');
}

describe('rendered Helm security context', () => {
  it('pins a non-root identity and runtime-default seccomp profile', () => {
    const daemonSet = renderChart();
    const podSecurityContext = indentedBlock(daemonSet, 'securityContext', 6);

    assert.match(podSecurityContext, /^        runAsNonRoot: true$/m);
    assert.match(podSecurityContext, /^        runAsUser: 65532$/m);
    assert.match(podSecurityContext, /^        runAsGroup: 65532$/m);
    assert.match(podSecurityContext, /^        seccompProfile:$/m);
    assert.match(podSecurityContext, /^          type: RuntimeDefault$/m);
  });

  it('keeps the container filesystem, privilege, and capability restrictions', () => {
    const daemonSet = renderChart();
    const containerSecurityContext = indentedBlock(daemonSet, 'securityContext', 10);

    assert.match(containerSecurityContext, /^            readOnlyRootFilesystem: true$/m);
    assert.match(containerSecurityContext, /^            allowPrivilegeEscalation: false$/m);
    assert.match(containerSecurityContext, /^            capabilities:$/m);
    assert.match(containerSecurityContext, /^                - ALL$/m);
  });

  it('retains the secure identity when the Docker socket group is added', () => {
    const daemonSet = renderChart(['--set', 'podSecurityContext.supplementalGroups[0]=999']);
    const podSecurityContext = indentedBlock(daemonSet, 'securityContext', 6);

    assert.match(podSecurityContext, /^        runAsNonRoot: true$/m);
    assert.match(podSecurityContext, /^        runAsUser: 65532$/m);
    assert.match(podSecurityContext, /^        runAsGroup: 65532$/m);
    assert.match(podSecurityContext, /^        supplementalGroups:$/m);
    assert.match(podSecurityContext, /^        - 999$/m);
  });
});
