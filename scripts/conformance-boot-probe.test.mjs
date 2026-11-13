import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";

const root = resolve(import.meta.dirname, "..");
const source = readFileSync(join(root, "scripts/tri-tool-conformance/run-matrix.sh"), "utf8");
const boot = source.match(/^assert_pristine_boot\(\) \{[\s\S]*?^\}/m)?.[0];
assert.ok(boot);
for (const [label, mode, expected, detail] of [
  ["pinned prepared image", "ok", 0, /PASS.*_ping OK/],
  ["probe cannot execute", "error", 1, /FAIL.*setup/],
  ["wrong socket ownership", "wrong", 1, /FAIL.*socket owner\/mode/],
]) {
  test(`fresh boot ownership probe: ${label}`, (t) => {
    const dir = mkdtempSync(join(tmpdir(), "sockguard-boot-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const result = spawnSync(
      "bash",
      [
        "-c",
        `
      set -euo pipefail
      SCRATCH_DIR="$1"
      PROJECT=fixture
      SOCKGUARD_IMAGE_RESOLVED=fixture
      PORTWING_IMAGE_RESOLVED=fixture
      DRYDOCK_IMAGE_RESOLVED=fixture
      OLD_BUSYBOX_REF=busybox:fixture@sha256:prepared
      compose() { :; }
      wait_until() { :; }
      record_result() { printf '%s\\n' "$*"; }
      docker() {
        case "$1" in
          image) echo fixture@sha256:fixture ;;
          volume) echo fixture-sockguard-socket ;;
          run)
            case " $* " in *" $OLD_BUSYBOX_REF "*) ;; *) return 1 ;; esac
            case "${mode}" in
              error) return 1 ;;
              wrong) echo '0:0 666' ;;
              *) echo '65532:65532 600' ;;
            esac ;;
        esac
      }
      ${boot}
      assert_pristine_boot
    `,
        "fixture",
        dir,
      ],
      { cwd: root, encoding: "utf8", timeout: 5000 },
    );
    assert.equal(result.status, expected, result.stdout + result.stderr);
    assert.match(result.stdout, detail);
  });
}

for (const [name, expected] of [
  ["assert_lifecycle", ["lifecycle SKIP"]],
  ["assert_exec", ["exec-policy-allowed SKIP", "exec-policy-denied SKIP"]],
]) {
  test(`${name} skips dependent probes when sentinel creation failed`, () => {
    const fn = source.match(new RegExp(`^${name}\\(\\) \\{[\\s\\S]*?^\\}`, "m"))?.[0];
    assert.ok(fn);
    const result = spawnSync(
      "bash",
      [
        "-c",
        `
      set -euo pipefail
      PRIMARY_SENTINEL_ID=""
      EXEC_ROW=1
      record_result() { printf '%s\\n' "$1 $2"; }
      ${fn}
      ${name}
    `,
      ],
      { cwd: root, encoding: "utf8", timeout: 5000 },
    );
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.deepEqual(result.stdout.trim().split("\n"), expected);
  });
}
