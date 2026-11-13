import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";

const root = resolve(import.meta.dirname, "..");
const source = readFileSync(resolve(root, "scripts/tri-tool-conformance/run-matrix.sh"), "utf8");
const inventory = source.match(/^assert_inventory_inspect\(\) \{[\s\S]*?^\}/m)?.[0];
assert.ok(inventory);
for (const [label, firstWait, status] of [
  ["no routes", 120, "FAIL"],
  ["late second route", 100, "FAIL"],
  ["both in time", 5, "PASS"],
]) {
  test(`inventory uses one shared deadline: ${label}`, () => {
    const result = spawnSync(
      "bash",
      [
        "-c",
        `
      set -uo pipefail
      SECONDS=0
      calls=0
      record_result() { printf '%s\\n' "$2"; }
      wait_for_access_log_route() {
        calls=$((calls + 1))
        if [ "$calls" -eq 1 ]; then
          SECONDS=$((SECONDS + ${firstWait}))
          [ "${firstWait}" -lt 120 ]
        else
          SECONDS=$((SECONDS + ($4 < 30 ? $4 : 30)))
          [ "$4" -gt 30 ]
        fi
      }
      ${inventory}
      assert_inventory_inspect
      printf '%s\\n' "$SECONDS"
    `,
      ],
      { cwd: root, encoding: "utf8", timeout: 5000 },
    );
    assert.equal(result.status, 0, result.stderr);
    const lines = result.stdout.trim().split("\n");
    assert.equal(lines[0], status);
    assert.ok(Number(lines[1]) <= 120, `used ${lines[1]} seconds`);
  });
}

test("access route wait caps its last sleep at the elapsed deadline", () => {
  const result = spawnSync(
    "bash",
    [
      "-c",
      `
    set -uo pipefail
    source scripts/tri-tool-conformance/lib.sh
    SECONDS=0
    sockguard_access_log() { printf '{}\\n'; }
    sleep() { SECONDS=$((SECONDS + $1)); }
    wait_for_access_log_route GET allow '^/containers/json$' 3
    status=$?
    printf '%s %s\\n' "$status" "$SECONDS"
  `,
    ],
    { cwd: root, encoding: "utf8", timeout: 5000 },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), "1 3");
});

test("access route wait refuses a matching log response after its deadline", () => {
  const result = spawnSync(
    "bash",
    [
      "-c",
      `
    set -uo pipefail
    source scripts/tri-tool-conformance/lib.sh
    sockguard_access_log() { sleep 1.2; printf '{}\\n'; }
    access_log_stream_has_route() { cat >/dev/null; return 0; }
    wait_for_access_log_route GET allow '^/containers/json$' 1
    printf '%s\\n' "$?"
  `,
    ],
    { cwd: root, encoding: "utf8", timeout: 5000 },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), "1");
});
