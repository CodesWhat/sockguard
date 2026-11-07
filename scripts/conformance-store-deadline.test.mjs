import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";

const root = resolve(import.meta.dirname, "..");
const source = readFileSync(join(root, "scripts/tri-tool-conformance/run-matrix.sh"), "utf8");
const start = source.indexOf('  local doc="" dd_id="" dd_agent="" remaining');
const end = source.indexOf('  dd_id="$(jq', start);
assert.ok(start > 0 && end > start);
const polling = source.slice(start, end);

for (const [label, delay, expected] of [
  ["in time", "0", 0],
  ["after deadline", "1.2", 1],
]) {
  test(`store poll accepts a matching document only ${label}`, (t) => {
    const dir = mkdtempSync(join(tmpdir(), "sockguard-store-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const result = spawnSync(
      "bash",
      [
        "-c",
        `
      set -euo pipefail
      SCRATCH_DIR="$1"
      STORE_SYNC_TIMEOUT=1
      sentinel=fixture
      curl() {
        printf '%s\\n' "$@" > "$SCRATCH_DIR/curl-args"
        sleep "${delay}"
        printf '%s' '{"data":[{"name":"fixture","id":"id","agent":"agent"}]}' > "$SCRATCH_DIR/containers-response.json"
        printf 200
      }
      record_result() { printf '%s\\n' "$*"; }
      poll() {
        local name=store-sync
        ${polling}
      }
      poll
    `,
        "fixture",
        dir,
      ],
      { cwd: root, encoding: "utf8", timeout: 5000 },
    );
    assert.equal(result.status, expected, result.stdout + result.stderr);
    const args = readFileSync(join(dir, "curl-args"), "utf8").trim().split("\n");
    assert.equal(
      args[args.indexOf("--max-time") + 1],
      "1",
      "curl must fit inside the remaining window",
    );
    if (expected) assert.match(result.stdout, /never appeared/);
  });
}
