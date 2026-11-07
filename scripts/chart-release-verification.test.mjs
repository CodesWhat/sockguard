import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";

const root = resolve(import.meta.dirname, "..");
const digest = `sha256:${"a".repeat(64)}`;
for (const layout of ["space", "symlink"]) {
  test(`chart CLI checks invalid metadata through a ${layout} path`, (t) => {
    const dir = mkdtempSync(join(tmpdir(), "sockguard-chart-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    let cli;
    if (layout === "space") {
      const scripts = join(dir, "space path");
      cpSync(join(root, "scripts"), scripts, { recursive: true });
      cli = join(scripts, "assert-chart-release.mjs");
    } else {
      cli = join(dir, "gate.mjs");
      symlinkSync(join(root, "scripts/assert-chart-release.mjs"), cli);
    }
    const chart = join(dir, "Chart.yaml");
    const values = join(dir, "values.yaml");
    writeFileSync(chart, 'apiVersion: v2\nname: sockguard\nversion: 9.9.9\nappVersion: "9.9.9"\n');
    writeFileSync(values, `image:\n  tag: "1.2.3@${digest}"\n`);
    const result = spawnSync(
      process.execPath,
      [cli, "--tag", "v1.2.3", "--digest", digest, "--chart", chart, "--values", values],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 1, result.stdout + result.stderr);
    assert.match(result.stderr, /must both equal/);
  });
}

const chartYaml = 'apiVersion: v2\nname: sockguard\nversion: 1.2.3\nappVersion: "1.2.3"\n';
const valuesYaml = `image:\n  repository: codeswhat/sockguard\n  tag: "1.2.3@${digest}"\n`;
const files = [
  ["sockguard/Chart.yaml", chartYaml],
  ["sockguard/values.yaml", valuesYaml],
  ["sockguard/templates/policy.yaml", "kind: ConfigMap\ndata:\n  allowed: false\n"],
];
function archive(path, entries, mtime) {
  const result = spawnSync(
    "python3",
    [
      "-c",
      `
import io,json,sys,tarfile
with tarfile.open(sys.argv[1], "w:gz") as chart:
    for name, text, *kind in json.loads(sys.argv[2]):
        entry = tarfile.TarInfo(name)
        entry.mtime = int(sys.argv[3])
        if kind:
            entry.type = tarfile.SYMTYPE
            entry.linkname = text
            chart.addfile(entry)
        else:
            content = text.encode()
            entry.size = len(content)
            chart.addfile(entry, io.BytesIO(content))
`,
      path,
      JSON.stringify(entries),
      String(mtime),
    ],
    { encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);
}
for (const [label, entries, expected] of [
  ["same files with different archive metadata", files, 0],
  [
    "changed policy template",
    [...files.slice(0, 2), [files[2][0], "kind: ConfigMap\ndata:\n  allowed: true\n"]],
    1,
  ],
  ["extra template", [...files, ["sockguard/templates/rbac.yaml", "kind: ClusterRole\n"]], 1],
  ["missing template", files.slice(0, 2), 1],
  [
    "changed other values",
    [files[0], [files[1][0], `${valuesYaml}privileged: true\n`], files[2]],
    1,
  ],
  [
    "changed other metadata",
    [[files[0][0], `${chartYaml}description: replaced\n`], ...files.slice(1)],
    1,
  ],
  ["symbolic link", [...files.slice(0, 2), [files[2][0], "/etc/passwd", "link"]], 1],
  ["duplicate path", [...files, files[2]], 1],
  ["missing expected package", files, 1],
]) {
  test(`published chart verification: ${label}`, (t) => {
    const dir = mkdtempSync(join(tmpdir(), "sockguard-chart-contents-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const local = join(dir, "expected.tgz");
    const remote = join(dir, "published.tgz");
    archive(local, files, 1);
    archive(remote, entries, 100);
    const bin = join(dir, "bin");
    mkdirSync(bin);
    writeFileSync(join(dir, "chart"), chartYaml);
    writeFileSync(join(dir, "values"), valuesYaml);
    writeFileSync(
      join(bin, "helm"),
      `#!/bin/sh
case "$1" in
  pull)
    while [ "$#" -gt 0 ]; do
      if [ "$1" = --destination ]; then shift; dest="$1"; fi
      shift
    done
    cp "$REMOTE_PACKAGE" "$dest/sockguard-1.2.3.tgz"
    echo "Digest: $CHART_DIGEST" ;;
  show)
    case "$2" in
      chart) cat "$FIXTURE_DIR/chart" ;;
      values) cat "$FIXTURE_DIR/values" ;;
      *) exit 1 ;;
    esac ;;
  *) exit 1 ;;
esac
`,
      { mode: 0o755 },
    );
    const result = spawnSync("bash", [join(root, "scripts/ci/chart-oci.sh"), "verify-contents"], {
      encoding: "utf8",
      timeout: 10000,
      env: {
        PATH: `${bin}:${process.env.PATH}`,
        TMPDIR: dir,
        FIXTURE_DIR: dir,
        REMOTE_PACKAGE: remote,
        CHART_PACKAGE: label === "missing expected package" ? "" : local,
        CHART_REGISTRY: "fixture/charts",
        CHART_VERSION: "1.2.3",
        CHART_DIGEST: digest,
        RELEASE_TAG: "v1.2.3",
        IMAGE_DIGEST: digest,
      },
    });
    assert.equal(result.status, expected, result.stdout + result.stderr);
    if (expected) assert.match(result.stderr, /differ|regular|duplicate|CHART_PACKAGE/);
  });
}
