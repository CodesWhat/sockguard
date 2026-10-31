import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

const ACTION = path.join(
  import.meta.dirname,
  "..",
  ".github",
  "actions",
  "verify-ci-success",
  "action.yml",
);
const source = fs.readFileSync(ACTION, "utf8");

// Every curl invocation, with its line continuations folded back together.
function curlCommands(text) {
  return text
    .replace(/\\\n\s*/gu, " ")
    .split("\n")
    .filter((line) => /\bcurl\b/u.test(line) && !/^\s*#/u.test(line));
}

describe("verify-ci-success action", () => {
  it("holds every curl and its retries to the remaining time budget", () => {
    const curls = curlCommands(source);
    assert.equal(curls.length, 2, "resolve request and poll request");
    for (const cmd of curls) {
      assert.match(cmd, /--max-time "\$\{request_max_time\}"/u, cmd);
      assert.match(cmd, /--retry-max-time "\$\{remaining\}"/u, cmd);
      assert.doesNotMatch(cmd, /--max-time 30\b/u, cmd);
    }
  });

  it("computes the remaining budget from the deadline before each request", () => {
    assert.match(source, /remaining=\$\(\( deadline - \$\(date \+%s\) \)\)/u);
    assert.match(source, /request_max_time=\$\(\( remaining < 30 \? remaining : 30 \)\)/u);
  });

  it("caps the sleep at the remaining budget", () => {
    assert.match(
      source,
      /sleep "\$\(\( remaining < sleep_seconds \? remaining : sleep_seconds \)\)"/u,
    );
  });

  it("keeps the timed-out error for an exhausted budget", () => {
    assert.match(source, /Timed out waiting for successful .* wall-clock budget/u);
  });
});

for (const step of [
  "Resolve CI workflow reference",
  "Wait for successful branch CI on target SHA",
]) {
  it(`${step} enforces the polling deadline during a curl retry`, () => {
    const at = source.indexOf(`    - name: ${step}\n`);
    assert.notEqual(at, -1);
    const start = source.indexOf("      run: |\n", at) + "      run: |\n".length;
    const next = source.indexOf("\n    - name:", start);
    const script = source
      .slice(start, next < 0 ? undefined : next)
      .split("\n")
      .map((line) => (line.startsWith("        ") ? line.slice(8) : line))
      .join("\n");
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ci-deadline-"));
    try {
      const bin = path.join(tmp, "bin");
      fs.mkdirSync(bin);
      const clock = path.join(tmp, "clock");
      const started = path.join(tmp, "started");
      const bound = path.join(tmp, "bound");
      fs.writeFileSync(clock, "4\n");
      const command = (name, body) =>
        fs.writeFileSync(path.join(bin, name), `#!/bin/sh\n${body}\n`, { mode: 0o755 });
      command(
        "date",
        'if [ ! -e "$FIXTURE_STARTED" ]; then touch "$FIXTURE_STARTED"; echo 0; else cat "$FIXTURE_CLOCK"; fi',
      );
      command("sleep", 'now=$(cat "$FIXTURE_CLOCK"); echo "$((now + $1))" > "$FIXTURE_CLOCK"');
      command(
        "timeout",
        [
          '[ "$1" != "--signal=KILL" ] || shift',
          'budget="${1%s}"; shift',
          'echo "$budget" > "$FIXTURE_BOUND"',
          'FIXTURE_CURL_BUDGET="$budget" "$@"',
        ].join("\n"),
      );
      command(
        "curl",
        [
          'now=$(cat "$FIXTURE_CLOCK")',
          'advance="${FIXTURE_CURL_BUDGET:-2}"',
          'echo "$((now + advance))" > "$FIXTURE_CLOCK"',
          `echo '{"id":7,"name":"CI: Verify","path":".github/workflows/ci-verify.yml","workflow_runs":[{"status":"queued","head_branch":"dev/v2.4","conclusion":null}]}'`,
          'if [ -n "${FIXTURE_CURL_BUDGET-}" ]; then exit 124; fi',
        ].join("\n"),
      );
      const result = spawnSync("bash", ["-c", script], {
        encoding: "utf8",
        timeout: 10000,
        env: {
          ...process.env,
          PATH: `${bin}:${process.env.PATH}`,
          FIXTURE_CLOCK: clock,
          FIXTURE_STARTED: started,
          FIXTURE_BOUND: bound,
          MAX_WAIT_SECONDS: "5",
          MAX_ATTEMPTS: "2",
          GH_TOKEN: "test-auth",
          CI_VERIFY_WORKFLOW_FILE: "ci-verify.yml",
          CI_WORKFLOW_ID: "7",
          CI_WORKFLOW_NAME: "CI: Verify",
          TARGET_SHA: "a".repeat(40),
          GITHUB_API_URL: "https://api.github.invalid",
          GITHUB_SERVER_URL: "https://github.invalid",
          GITHUB_REPOSITORY: "CodesWhat/sockguard",
          GITHUB_OUTPUT: path.join(tmp, "output"),
        },
      });
      assert.equal(result.error, undefined);
      assert.notEqual(result.status, 0, result.stdout);
      assert.equal(
        Number(fs.readFileSync(clock, "utf8")),
        5,
        "curl retry must stop at the deadline",
      );
      assert.equal(
        Number(fs.readFileSync(bound, "utf8")),
        1,
        "only one second remained before the request",
      );
      assert.match(result.stdout, /::error::.*(?:Timed out|Failed to resolve)/u);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
}
