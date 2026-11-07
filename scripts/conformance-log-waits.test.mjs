import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
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

const source = readFileSync(resolve(root, "scripts/tri-tool-conformance/run-matrix.sh"), "utf8");
const wrongSecretPattern = source.match(
  /wait_for_container_log_line "\$bad_container" '([^']+)'/,
)[1];
for (const [line, expected] of [
  ["Request failed with status code 401", 0],
  ["HTTP status: 401 Unauthorized", 0],
  ["received 401 bytes", 1],
  ["listening on port 4010", 1],
  ["2026-11-07T20:03:01.401Z startup", 1],
]) {
  test(`wrong-secret probe requires an auth error: ${line}`, () => {
    const result = spawnSync(
      "bash",
      [
        "-c",
        `
      set -o pipefail
      source scripts/tri-tool-conformance/lib.sh
      LOG_LINE="$1"
      docker() { printf '%s\\n' "$LOG_LINE"; }
      sleep() { :; }
      wait_for_container_log_line fixture "$2" 1
    `,
        "fixture",
        line,
        wrongSecretPattern,
      ],
      { cwd: root, encoding: "utf8", timeout: 5000 },
    );
    assert.equal(result.status, expected, result.stderr);
  });
}
