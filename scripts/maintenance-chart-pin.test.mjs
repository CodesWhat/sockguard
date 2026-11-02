import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

const root = resolve(import.meta.dirname, "..");
const workflow = readFileSync(join(root, ".github/workflows/release-from-tag.yml"), "utf8");
const step = workflow.indexOf("      - name: Commit the pin");
const start = workflow.indexOf("        run: |\n", step) + "        run: |\n".length;
const end = workflow.indexOf("\n      - name:", start);
assert.ok(step >= 0 && end > start);
const script = workflow
  .slice(start, end)
  .split("\n")
  .map((line) => line.replace(/^ {10}/u, ""))
  .join("\n");

function runPin(t, options = {}) {
  const fixture = mkdtempSync(join(tmpdir(), "sockguard-chart-pin-"));
  t.after(() => rmSync(fixture, { recursive: true, force: true }));
  const calls = join(fixture, "calls");
  const config = join(fixture, "config.json");
  writeFileSync(calls, "");
  writeFileSync(config, JSON.stringify(options));
  const common = `#!/usr/bin/env node
const fs = require("node:fs");
const args = process.argv.slice(2);
const config = JSON.parse(fs.readFileSync(process.env.PIN_CONFIG,"utf8"));
const record = { tool: process.argv[1].split("/").at(-1), args };
`;
  writeFileSync(
    join(fixture, "git"),
    common +
      `
fs.appendFileSync(process.env.PIN_CALLS, JSON.stringify(record)+"\\n");
if(args[0]==="diff") process.exit(args.includes("--cached") ? (config.noChange ? 0 : 1) : (config.conflict ? 1 : 0));
if(args[0]==="ls-remote") {
 if(config.remoteFailure) process.exit(1);
 if(config.existingBranch) process.stdout.write("a".repeat(40)+"\\trefs/heads/chore/chart-pin-2.4.3\\n");
}
if(args[0]==="push" && args.some(arg => arg.startsWith("HEAD:refs/heads/maintenance/"))) process.exit(1);
`,
    { mode: 0o755 },
  );
  writeFileSync(
    join(fixture, "gh"),
    common +
      `
if(args[1]==="create") record.body = fs.readFileSync(args[args.indexOf("--body-file")+1],"utf8");
fs.appendFileSync(process.env.PIN_CALLS,JSON.stringify(record)+"\\n");
if(args[1]==="list" && config.existingPr) process.stdout.write("https://github.com/CodesWhat/sockguard/pull/900\\n");
if(args[1]==="create") process.stdout.write("https://github.com/CodesWhat/sockguard/pull/900\\n");
if(args[1]==="view") process.stdout.write(JSON.stringify({url:"https://github.com/CodesWhat/sockguard/pull/900",baseRefName:config.badReadback ? "main" : process.env.TARGET_BRANCH,headRefName:"chore/chart-pin-2.4.3"}));
`,
    { mode: 0o755 },
  );
  const result = spawnSync("bash", ["-c", script], {
    cwd: root,
    encoding: "utf8",
    timeout: 10_000,
    env: {
      ...process.env,
      PATH: `${fixture}:${process.env.PATH}`,
      PIN_CONFIG: config,
      PIN_CALLS: calls,
      GH_TOKEN: options.noCredential ? "" : "fixture-credential",
      GITHUB_REPOSITORY: "CodesWhat/sockguard",
      GITHUB_OUTPUT: join(fixture, "output"),
      TARGET_BRANCH: options.branch ?? "maintenance/2.4.x",
      RELEASE_VERSION: "2.4.3",
      IMAGE_DIGEST: `sha256:${"a".repeat(64)}`,
    },
  });
  return {
    ...result,
    calls: readFileSync(calls, "utf8")
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line)),
  };
}

test("maintenance chart pins use a reviewed branch and fetch the PR back", (t) => {
  const result = runPin(t);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const pushes = result.calls.filter((call) => call.tool === "git" && call.args[0] === "push");
  assert.deepEqual(
    pushes.map((call) => call.args),
    [["push", "origin", "HEAD:refs/heads/chore/chart-pin-2.4.3"]],
  );
  assert.equal(
    result.calls.filter((call) => call.tool === "gh" && call.args[1] === "create").length,
    1,
  );
  assert.equal(
    result.calls.filter((call) => call.tool === "gh" && call.args[1] === "view").length,
    1,
  );
  assert.ok(
    result.calls
      .find((call) => call.tool === "gh" && call.args[1] === "create")
      .body.includes(`sha256:${"a".repeat(64)}`),
  );
});
test("development pins retain their normal direct branch push", (t) => {
  const result = runPin(t, { branch: "dev/v2.4" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(
    result.calls.filter((call) => call.args[0] === "push").map((call) => call.args),
    [["push", "origin", "HEAD:refs/heads/dev/v2.4"]],
  );
  assert.equal(result.calls.filter((call) => call.tool === "gh").length, 0);
});
test("matching maintenance branches and PRs are reused without force pushes", (t) => {
  const result = runPin(t, { existingBranch: true, existingPr: true });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(
    result.calls.filter((call) => call.args[0] === "push" || call.args[1] === "create").length,
    0,
  );
  assert.equal(
    result.calls.filter((call) => call.tool === "gh" && call.args[1] === "view").length,
    1,
  );
});
for (const [name, options] of [
  ["conflicting branch", { existingBranch: true, conflict: true }],
  ["remote failure", { remoteFailure: true }],
  ["missing credential", { noCredential: true }],
]) {
  test(`maintenance pin fails closed on ${name}`, (t) => {
    const result = runPin(t, options);
    assert.notEqual(result.status, 0);
    assert.equal(
      result.calls.filter((call) => call.args[0] === "push" || call.args[1] === "create").length,
      0,
    );
  });
}
test("maintenance PR readback must match the intended protected branch", (t) => {
  const result = runPin(t, { badReadback: true });
  assert.notEqual(result.status, 0);
  assert.match(result.stdout, /maintenance pin PR did not match/u);
});
test("an already-landed pin creates no new branch or PR", (t) => {
  const result = runPin(t, { noChange: true });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(
    result.calls.filter((call) => call.args[0] === "push" || call.tool === "gh").length,
    0,
  );
});
