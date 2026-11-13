import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";

const root = resolve(import.meta.dirname, "..");
const workflow = readFileSync(join(root, ".github/workflows/ci-verify.yml"), "utf8");
const job = workflow.match(/^ {2}commit-message:\n([\s\S]*?)(?=^ {2}[\w-]+:)/m)?.[1];
assert.ok(job, "commit-message job not found in ci-verify.yml");
const runMatch = job.match(/ {8}run: \|\n([\s\S]*)/);
assert.ok(runMatch, "commit-message run block not found in ci-verify.yml");
const run = runMatch[1]
  .split("\n")
  .map((line) => line.replace(/^ {10}/, ""))
  .join("\n");

for (const [subject, valid] of [
  ["feat: add feature", true],
  ["fix(api)!: handle v2", true],
  ["fix: accept version 1.2.3", true],
  ["feat: 🚀 update", false],
  ["fix: flag 🇺🇸", false],
  ["fix: key 1️⃣", false],
  ["Merge branch 'old'", true],
  ['Revert "old"', true],
  ["fixup! historic subject", true],
  ["squash! historic subject", true],
  ["invalid subject", false],
]) {
  test(`commit validator and CI agree: ${subject}`, (t) => {
    const dir = mkdtempSync(join(tmpdir(), "sockguard-commit-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const msg = join(dir, "message");
    writeFileSync(msg, `${subject}\n\nBody may contain emoji 🚀.\n`);
    const local = spawnSync(
      process.execPath,
      [join(root, "scripts/validate-commit-msg.mjs"), msg],
      { encoding: "utf8" },
    );
    assert.equal(local.status, valid ? 0 : 1, local.stderr);
    writeFileSync(join(dir, "git"), '#!/bin/sh\nprintf "%s\\n" "$TEST_SUBJECT"\n', { mode: 0o755 });
    const ci = spawnSync("bash", ["-c", run], {
      cwd: root,
      encoding: "utf8",
      env: {
        PATH: `${dir}:${process.env.PATH}`,
        TEST_SUBJECT: subject,
        BASE_REF: "dev/v3.1",
        HEAD_REF: "fix/example",
        HEAD_REPO: "CodesWhat/sockguard",
        REPOSITORY: "CodesWhat/sockguard",
      },
    });
    assert.equal(ci.status, valid ? 0 : 1, ci.stdout + ci.stderr);
  });
}

for (const prefix of ["dev", "maintenance"]) {
  for (const sameRepo of [false, true]) {
    test(`CI promotion ${prefix} same repository ${sameRepo}`, (t) => {
      const dir = mkdtempSync(join(tmpdir(), "sockguard-promotion-"));
      t.after(() => rmSync(dir, { recursive: true, force: true }));
      writeFileSync(join(dir, "git"), '#!/bin/sh\nprintf "%s\\n" "invalid subject"\n', {
        mode: 0o755,
      });
      const result = spawnSync("bash", ["-c", run], {
        cwd: root,
        encoding: "utf8",
        env: {
          PATH: `${dir}:${process.env.PATH}`,
          BASE_REF: "main",
          HEAD_REF: `${prefix}/example`,
          HEAD_REPO: sameRepo ? "CodesWhat/sockguard" : "attacker/sockguard",
          REPOSITORY: "CodesWhat/sockguard",
        },
      });
      if (sameRepo) assert.equal(result.status, 0, result.stderr);
      else assert.notEqual(result.status, 0, "fork must run validation, not skip it");
    });
  }
}
