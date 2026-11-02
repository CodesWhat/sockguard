import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const ROOT = path.resolve(import.meta.dirname, "..");
const RUN = 40099590235;
const SHA = "5d5190032c7abbfe3bd506c215c75770918bcc41";

function artifact(attempt, overrides = {}) {
  return {
    id: 12562888948 + attempt,
    name: `go-test-${RUN}-${attempt}`,
    expired: false,
    workflow_run: { id: RUN, head_sha: SHA },
    ...overrides,
  };
}

function resolve(t, artifacts, { attempt = "2", run = { id: RUN, head_sha: SHA } } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "sg-coverage-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bin = path.join(root, "bin");
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(root, "run.json"), JSON.stringify(run));
  fs.writeFileSync(path.join(root, "artifacts.json"), JSON.stringify(artifacts));
  fs.writeFileSync(
    path.join(bin, "gh"),
    `#!/usr/bin/env bash
set -eu
case "$*" in
"api repos/CodesWhat/sockguard/actions/runs/${RUN}") cat "$FIXTURE_ROOT/run.json" ;;
"api --paginate --slurp repos/CodesWhat/sockguard/actions/runs/${RUN}/artifacts?per_page=100") cat "$FIXTURE_ROOT/artifacts.json" ;;
*) echo "unexpected API arguments" >&2; exit 92 ;;
esac
`,
    { mode: 0o755 },
  );
  const output = path.join(root, "output");
  const summary = path.join(root, "summary");
  const result = spawnSync("/bin/bash", [path.join(ROOT, "scripts/ci/resolve-go-coverage.sh")], {
    cwd: root,
    encoding: "utf8",
    timeout: 10_000,
    env: {
      ...process.env,
      PATH: `${bin}:${process.env.PATH}`,
      FIXTURE_ROOT: root,
      GITHUB_REPOSITORY: "CodesWhat/sockguard",
      GITHUB_RUN_ID: String(RUN),
      GITHUB_RUN_ATTEMPT: attempt,
      COVERAGE_EXPECTED_SHA: SHA,
      GITHUB_OUTPUT: output,
      GITHUB_STEP_SUMMARY: summary,
    },
  });
  return {
    ...result,
    output: fs.existsSync(output) ? fs.readFileSync(output, "utf8") : "",
    summary: fs.existsSync(summary) ? fs.readFileSync(summary, "utf8") : "",
  };
}

test("partial rerun resolves the reused test producer from the same run and head", (t) => {
  const result = resolve(t, [{ artifacts: [artifact(1)] }]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.output, /artifact_id=12562888949/u);
  assert.match(result.output, /producer_attempt=1/u);
  assert.match(result.summary, new RegExp(SHA, "u"));
});

test("a full rerun selects the latest available producer across artifact pages", (t) => {
  const result = resolve(t, [{ artifacts: [artifact(1)] }, { artifacts: [artifact(2)] }]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.output, /artifact_id=12562888950/u);
  assert.match(result.output, /producer_attempt=2/u);
});

test("expired, future, unrelated, wrong-run and wrong-head artifacts cannot replace the report", (t) => {
  const result = resolve(t, [
    {
      artifacts: [
        artifact(1),
        artifact(2, { expired: true }),
        artifact(3),
        artifact(2, { name: `go-test-${RUN}-2-extra` }),
        artifact(2, { workflow_run: { id: RUN + 1, head_sha: SHA } }),
        artifact(2, { workflow_run: { id: RUN, head_sha: "0".repeat(40) } }),
      ],
    },
  ]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.output, /producer_attempt=1/u);
});

test("missing usable coverage fails explicitly without emitting a download identity", (t) => {
  for (const candidates of [[], [artifact(1, { expired: true })], [artifact(3)]]) {
    const result = resolve(t, [{ artifacts: candidates }]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /No usable Go coverage artifact/u);
    assert.equal(result.output, "");
  }
});

test("the run identity must match the intended commit before artifacts can be used", (t) => {
  const result = resolve(t, [{ artifacts: [artifact(1)] }], {
    run: { id: RUN, head_sha: "0".repeat(40) },
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Run identity does not match/u);
  assert.equal(result.output, "");
});

test("invalid attempt and artifact identifiers cannot enter action outputs", (t) => {
  const invalid = resolve(t, [{ artifacts: [artifact(1)] }], { attempt: "2/../3" });
  assert.notEqual(invalid.status, 0);
  assert.match(invalid.stderr, /Invalid run attempt/u);
  assert.equal(invalid.output, "");

  const badId = resolve(t, [{ artifacts: [artifact(1, { id: "1\nother=2" })] }]);
  assert.notEqual(badId.status, 0);
  assert.match(badId.stderr, /No usable Go coverage artifact/u);
  assert.equal(badId.output, "");
});

function exerciseProfileGuard(t, script) {
  for (const state of ["missing", "empty", "present"]) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "sg-profile-"));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    if (state !== "missing") {
      const report = path.join(root, "artifacts/go-test/coverage.prod.txt");
      fs.mkdirSync(path.dirname(report), { recursive: true });
      fs.writeFileSync(
        report,
        state === "empty" ? "" : "mode: atomic\nexample.invalid/a.go:1.1,1.2 1 1\n",
      );
    }
    const result = spawnSync("/bin/bash", ["-eu", "-c", script], {
      cwd: root,
      encoding: "utf8",
      timeout: 5_000,
    });
    assert.equal(result.status, state === "present" ? 0 : 1, `${state}: ${result.stderr}`);
    if (state !== "present") assert.match(result.stdout, /coverage profile is missing or empty/u);
  }
}

test("the actual workflow rejects missing and empty profiles while accepting a produced report", (t) => {
  const workflow = fs.readFileSync(path.join(ROOT, ".github/workflows/ci-verify.yml"), "utf8");
  const step = workflow
    .split("      - name: Validate Go coverage profile\n")[1]
    ?.split("\n      - name:")[0];
  assert.ok(step, "coverage profile validation step is missing");
  const run = step.split("        run: |\n")[1]?.split("\n        continue-on-error:")[0];
  assert.ok(run, "coverage profile validation command is missing");
  exerciseProfileGuard(
    t,
    run
      .split("\n")
      .map((line) => line.slice(10))
      .join("\n"),
  );
});

test("profile fixtures expose a guard that silently accepts missing coverage", (t) => {
  assert.throws(() => exerciseProfileGuard(t, "true"), /missing:/u);
});
