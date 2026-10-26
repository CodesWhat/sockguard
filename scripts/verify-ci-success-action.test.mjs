import assert from "node:assert/strict";
import fs from "node:fs";
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
