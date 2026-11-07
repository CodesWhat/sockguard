import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { test } from "node:test";

const root = resolve(import.meta.dirname, "..");
for (const [label, producer, expected] of [
  [
    "early match and large remaining log",
    "printf 'HTTP status 401\\n'; printf '%0200000d\\n' 0",
    0,
  ],
  ["no match", "printf 'startup healthy\\n'", 1],
  ["failed log retrieval", "printf 'HTTP status 401\\n'; return 1", 1],
]) {
  test(`negative-auth log wait: ${label}`, () => {
    const result = spawnSync(
      "bash",
      [
        "-c",
        `
      set -o pipefail
      source scripts/tri-tool-conformance/lib.sh
      docker() { ${producer}; }
      sleep() { :; }
      wait_for_container_log_line fixture 'HTTP status 401' 1
    `,
      ],
      { cwd: root, encoding: "utf8", timeout: 5000 },
    );
    assert.equal(result.status, expected, result.stderr);
  });
}
