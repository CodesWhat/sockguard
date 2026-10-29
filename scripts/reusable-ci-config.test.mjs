import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORKFLOW = path.join(ROOT, ".github", "workflows", "ci-verify.yml");
const LEFTHOOK = path.join(ROOT, "lefthook.yml");
const SHARED_SHA = "01bf40b06b110946f12a49b82e407d77c6480df7";

// Every fixed adapter the reusable go-ci/node-ci jobs invoke by convention
// (./scripts/ci/<name>.sh). Markers are substrings that must survive in the
// script body — enough to catch someone hollowing the script out without
// requiring an exact-text match.
const FIXED_SCRIPTS = new Map([
  ["go-test.sh", ["go test -race", "COVERAGE_MIN", "internal/buildkitproto"]],
  ["go-lint.sh", ["golangci-lint/v2/cmd/golangci-lint@v2.14.0", "gofmt -l", "GOLANGCI_LINT_CACHE"]],
  [
    "go-release-check.sh",
    [
      "goreleaser/goreleaser/v2@v2.15.3",
      // `sign` is load-bearing, not cosmetic: the signs: blocks use keyless
      // cosign, which needs an OIDC identity only the tagged release run has.
      // Dropping it back to just "publish" fails this dry-run on any machine
      // that has cosign installed, which includes CI.
      'skip="publish,sign"',
      "command -v syft",
      // biome-ignore lint/suspicious/noTemplateCurlyInString: literal bash from go-release-check.sh, matched as text; no `skip` binding exists here so biome's fix would throw
      'release --snapshot --clean --skip="${skip}"',
      "cask ",
    ],
  ],
  ["go-fuzz.sh", ["FUZZER", "PKG", "fuzztime=60s"]],
  // The Qlty adapter is a thin wrapper on purpose: the gate itself lives in
  // scripts/qlty-check-gate.sh so the pre-push hook and CI run the same code.
  ["go-qlty.sh", ["MODULE_DIRECTORY", "./scripts/qlty-check-gate.sh all"]],
  [
    "shellcheck.sh",
    // biome-ignore lint/suspicious/noTemplateCurlyInString: literal bash from shellcheck.sh, matched as text; `scripts[@]` isn't valid in a template literal so biome's fix would not parse
    ["command -v shellcheck", "git ls-files -z '*.sh'", 'shellcheck "${scripts[@]}"'],
  ],
  ["node-lint.sh", ["npm ci", "biome check"]],
  ["node-test.sh", ["npm ci", "npm test"]],
  ["node-build.sh", ["npm ci", "turbo build"]],
]);

// The exact 28-fuzzer inventory currently scheduled in the branch-CI fuzz
// matrix (Tier 1). This lives only as the go-ci caller's fuzzers-json input
// — never hardcoded inside scripts/ci/go-fuzz.sh, which is caller-agnostic.
const FUZZERS = [
  ["FuzzPathMatch", "./internal/filter/"],
  ["FuzzGlobToRegex", "./internal/filter/"],
  ["FuzzGlobToRegexString", "./internal/filter/"],
  ["FuzzNormalizePath", "./internal/filter/"],
  ["FuzzCompileRule", "./internal/filter/"],
  ["FuzzBuild", "./internal/filter/"],
  ["FuzzContainerCreate", "./internal/filter/"],
  ["FuzzExec", "./internal/filter/"],
  ["FuzzImagePull", "./internal/filter/"],
  ["FuzzVolume", "./internal/filter/"],
  ["FuzzSecret", "./internal/filter/"],
  ["FuzzConfigWrite", "./internal/filter/"],
  ["FuzzService", "./internal/filter/"],
  ["FuzzSwarm", "./internal/filter/"],
  ["FuzzPlugin", "./internal/filter/"],
  ["FuzzNetwork", "./internal/filter/"],
  ["FuzzReadUnaryGRPCMessage", "./internal/buildkitproxy/"],
  ["FuzzControlRefFrame", "./internal/buildkitproxy/"],
  ["FuzzEvaluateGatewayRequest", "./internal/buildkitproxy/"],
  ["FuzzFilterGatewayPong", "./internal/buildkitproxy/"],
  ["FuzzEvaluateGetSecretRequest", "./internal/buildkitproxy/"],
  ["FuzzEvaluateSolveRequest", "./internal/buildkitproxy/"],
  ["FuzzEvaluateStatusRequest", "./internal/buildkitproxy/"],
  ["FuzzRewriteSessionAdvertisement", "./internal/buildkitproxy/"],
  ["FuzzValidateUpgradeRequest", "./internal/buildkitproxy/"],
  ["FuzzFilterControlResponseMessage", "./internal/buildkitproxy/"],
  ["FuzzDecode", "./internal/dockerfilters/"],
  ["FuzzProxyHeadersAndBody", "./internal/proxy/"],
  ["FuzzHijackHeadersAndBody", "./internal/proxy/"],
  ["FuzzPathRoutingDifferential", "./internal/differential/"],
  ["FuzzVisibilityFilter", "./internal/visibility/"],
  ["FuzzLibpodPathIdentifiers", "./internal/visibility/"],
];

// The X1 canary promoted; branch protection now requires only the reusable
// "Go CI / ..." / "Node CI / ..." contexts. These legacy plain-name bridge
// jobs must stay removed.
const RETIRED_BRIDGES = new Map([
  ["legacy-workflow-security", "Workflow Security"],
  ["legacy-goreleaser", "GoReleaser Config"],
  ["legacy-go-lint", "Go Lint"],
  ["legacy-go-test", "Go Test"],
  ["legacy-biome-lint", "Biome Lint"],
  ["legacy-ts-test", "TS Test"],
  ["legacy-build-workspaces", "Build Workspaces"],
]);

const RETIRED_LOCAL_JOBS = [
  "zizmor",
  "goreleaser-check",
  "go-lint",
  "go-test",
  "go-fuzz",
  "ts-lint",
  "ts-test",
  "ts-build",
];

const GO_INPUTS = [
  "module-directory: app",
  "go-version-file: go.mod",
  "go-cache-dependency-path: go.sum",
  "lint-check-name: Go Lint",
  "test-check-name: Go Test",
  "run-workflow-security: true",
  `run-goreleaser: \${{ github.event_name != 'schedule' }}`,
  `run-qlty: \${{ github.event_name != 'schedule' }}`,
  "qlty-egress-policy: audit",
  "workflow-security-egress-policy: audit",
];

const NODE_INPUTS = [
  "node-version: 24",
  "lockfile-path: package-lock.json",
  "lint-check-name: Biome Lint",
  "test-check-name: TS Test",
  "build-check-name: Build Workspaces",
  "run-lint: true",
  "run-test: true",
  "run-build: true",
];

function jobSection(source, jobId) {
  const lines = source.split("\n");
  const start = lines.indexOf(`  ${jobId}:`);
  if (start === -1) return "";
  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    if (/^ {2}[a-z][a-z0-9-]*:$/u.test(lines[index])) {
      end = index;
      break;
    }
  }
  return lines.slice(start, end).join("\n");
}

function mappingSection(source, mappingName) {
  const lines = source.split("\n");
  const start = lines.indexOf(`    ${mappingName}:`);
  if (start === -1) return "";
  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    if (/^ {4}[a-z][a-z0-9-]*:/u.test(lines[index])) {
      end = index;
      break;
    }
  }
  return lines.slice(start, end).join("\n");
}

function assertReusableCaller(source) {
  const go = jobSection(source, "go-ci");
  const node = jobSection(source, "node-ci");
  assert.ok(go, "missing go-ci reusable caller");
  assert.ok(node, "missing node-ci reusable caller");

  const goWith = mappingSection(go, "with");
  const nodeWith = mappingSection(node, "with");
  assert.ok(goWith, "go-ci is missing its with mapping");
  assert.ok(nodeWith, "node-ci is missing its with mapping");
  const goWithLines = new Set(goWith.split("\n"));
  const nodeWithLines = new Set(nodeWith.split("\n"));

  assert.match(
    go,
    new RegExp(`uses: CodesWhat/\\.github/\\.github/workflows/go-ci\\.yml@${SHARED_SHA}`),
  );
  assert.match(
    node,
    new RegExp(`uses: CodesWhat/\\.github/\\.github/workflows/node-ci\\.yml@${SHARED_SHA}`),
  );
  assert.doesNotMatch(
    source,
    /CodesWhat\/\.github\/\.github\/workflows\/[^\s@]+@(?![0-9a-f]{40}\b)/u,
  );
  assert.doesNotMatch(source, /secrets:\s*inherit/u);

  for (const input of GO_INPUTS) {
    assert.ok(goWithLines.has(`      ${input}`), `go-ci is missing ${input}`);
  }
  for (const input of NODE_INPUTS) {
    assert.ok(nodeWithLines.has(`      ${input}`), `node-ci is missing ${input}`);
  }

  // go-ci.yml's nested codeql job declares security-events: write
  // regardless of whether run-codeql is set — GitHub validates a called
  // workflow's job-level permissions statically, even for gated-off jobs.
  assert.match(
    go,
    /^ {6}security-events: write$/mu,
    "go-ci caller must grant the nested CodeQL job's statically validated permission",
  );
  assert.doesNotMatch(
    go,
    /run-codeql:\s*true/u,
    "CodeQL must stay local, not routed through go-ci",
  );

  assert.ok(
    jobSection(source, "codeql"),
    "CodeQL must remain local to keep javascript-typescript coverage",
  );
  assert.ok(jobSection(source, "dependency-review"), "dependency review must remain local");
  assert.ok(jobSection(source, "commit-message"), "commit-message must remain local");
  assert.ok(jobSection(source, "docker"), "Docker Build must remain local");

  const inventory = go.match(/&& '(\[.*?\])' \|\| '\[\]'/u)?.[1];
  assert.ok(inventory, "go-ci must keep its conditional fuzz inventory in the caller");
  assert.deepEqual(
    JSON.parse(inventory),
    FUZZERS.map(([name, pkg]) => ({ name, pkg })),
  );

  for (const retired of RETIRED_LOCAL_JOBS) {
    assert.equal(jobSection(source, retired), "", `${retired} must move behind a reusable caller`);
  }
}

function assertFixedScripts() {
  for (const [name, markers] of FIXED_SCRIPTS) {
    const scriptPath = path.join(ROOT, "scripts", "ci", name);
    // Open once and reuse the same file descriptor for the stat and the
    // read below, instead of a separate existsSync/statSync check followed
    // by a path-based readFileSync — the latter is a check-then-use race
    // (the file on disk could change between the check and the read).
    let fd;
    try {
      fd = fs.openSync(scriptPath, "r");
    } catch {
      assert.fail(`missing fixed script scripts/ci/${name}`);
    }
    try {
      const stat = fs.fstatSync(fd);
      assert.ok((stat.mode & 0o111) !== 0, `scripts/ci/${name} must be executable`);
      const source = fs.readFileSync(fd, "utf8");
      assert.match(source, /^#!\/usr\/bin\/env bash\nset -euo pipefail\n/u);
      for (const marker of markers) {
        assert.ok(source.includes(marker), `scripts/ci/${name} is missing ${marker}`);
      }
      assert.doesNotMatch(source, /\beval\b/u, `scripts/ci/${name} must not evaluate caller text`);
    } finally {
      fs.closeSync(fd);
    }
  }

  const fuzzScript = fs.readFileSync(path.join(ROOT, "scripts", "ci", "go-fuzz.sh"), "utf8");
  for (const [name] of FUZZERS) {
    assert.ok(!fuzzScript.includes(name), `${name} belongs in the caller, not the fixed runner`);
  }
}

function assertBridgesAbsent(source) {
  for (const [jobId, checkName] of RETIRED_BRIDGES) {
    assert.equal(jobSection(source, jobId), "", `${jobId} bridge job must stay removed`);
    const escaped = checkName.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
    assert.doesNotMatch(
      source,
      new RegExp(`^[ \\t]*name:\\s*["']?${escaped}["']?\\s*$`, "mu"),
      `workflow must not report the retired "${checkName}" context`,
    );
  }
}

function assertReleaseBranchTriggers(source) {
  assert.match(
    source,
    /^ {2}push:\n {4}branches: \[main, 'dev\/\*', 'maintenance\/\*', 'release\/\*'\]$/mu,
    "CI must run after merges to release branches so release-cut can verify the exact tag target SHA",
  );
  assert.match(
    source,
    /^ {2}pull_request:\n {4}branches: \[main, 'dev\/\*', 'maintenance\/\*'\]$/mu,
    "CI must run on pull requests into every protected integration branch family",
  );
}

test("sockguard calls the reusable workflows at the frozen organization SHA", () => {
  assertReusableCaller(fs.readFileSync(WORKFLOW, "utf8"));
});

test("required go-ci and node-ci inputs must be exact YAML lines", () => {
  const source = fs.readFileSync(WORKFLOW, "utf8");
  for (const [jobId, inputs] of [
    ["go-ci", GO_INPUTS],
    ["node-ci", NODE_INPUTS],
  ]) {
    for (const input of inputs) {
      assert.throws(() =>
        assertReusableCaller(source.replace(`      ${input}`, `      # ${input}`)),
      );
      assert.throws(() =>
        assertReusableCaller(source.replace(`      ${input}`, `      decoy-${input}`)),
      );
      const job = jobSection(source, jobId);
      const blockScalarDecoy = job
        .replace(`      ${input}\n`, "")
        .replace("    with:\n", `    decoy: |-\n      ${input}\n    with:\n`);
      assert.throws(() => assertReusableCaller(source.replace(job, blockScalarDecoy)));
    }
  }
});

test("reusable jobs invoke fixed repository-owned scripts", () => {
  assertFixedScripts();
});

test("the local lint and release gates use the same isolated fixed adapters", () => {
  const lefthook = fs.readFileSync(LEFTHOOK, "utf8");
  assert.match(lefthook, /^ {4}go-lint:\n {6}run: \.\/scripts\/ci\/go-lint\.sh$/mu);
  assert.match(
    lefthook,
    /^ {4}goreleaser-snapshot:\n {6}run: \.\/scripts\/ci\/go-release-check\.sh$/mu,
  );
  assert.doesNotMatch(lefthook, /^ {6}run: golangci-lint run$/mu);
});

function prePushPriorities(lefthook) {
  const section = lefthook.slice(lefthook.indexOf("\npre-push:"));
  const priorities = new Map();
  let command = null;
  for (const line of section.split("\n")) {
    const name = line.match(/^ {4}([a-z][a-z0-9-]*):$/u);
    if (name) command = name[1];
    const priority = line.match(/^ {6}priority: (\d+)$/u);
    if (priority && command) priorities.set(command, Number(priority[1]));
  }
  return priorities;
}

test("the repository-run Qlty gate is wired into CI, the pre-push hook, and one shared script", () => {
  // "Go CI / Qlty Check" is the enforced gate. It is not the Qlty Cloud
  // GitHub App's `qlty check` status, which errors organization-wide on
  // billing minutes and must never become a required context.
  const gatePath = path.join(ROOT, "scripts", "qlty-check-gate.sh");
  const gate = fs.readFileSync(gatePath, "utf8");
  assert.ok(
    (fs.statSync(gatePath).mode & 0o111) !== 0,
    "scripts/qlty-check-gate.sh must be executable",
  );
  assert.match(gate, /^#!\/usr\/bin\/env bash\nset -euo pipefail\n/u);
  assert.ok(gate.includes("qlty check --no-progress"), "the gate must run the Qlty CLI");
  assert.ok(gate.includes("cmd+=(--all)"), "the gate must support a whole-repository run");
  assert.ok(
    gate.includes("command -v qlty"),
    "a missing qlty CLI must fail with an install hint, not be skipped",
  );

  // The CI adapter must delegate to that same script rather than reimplement
  // the gate, so the local hook and the hosted job can never drift.
  const adapter = fs.readFileSync(path.join(ROOT, "scripts", "ci", "go-qlty.sh"), "utf8");
  assert.ok(adapter.includes("./scripts/qlty-check-gate.sh all"));

  const lefthook = fs.readFileSync(LEFTHOOK, "utf8");
  assert.match(lefthook, /^ {4}qlty:\n {6}run: \.\/scripts\/qlty-check-gate\.sh all$/mu);

  const priorities = prePushPriorities(lefthook);
  assert.equal(
    new Set(priorities.values()).size,
    priorities.size,
    "every pre-push command needs a distinct priority or the piped order is ambiguous",
  );
  assert.ok(
    priorities.get("go-lint") < priorities.get("qlty"),
    "qlty runs after go-lint, matching the portwing gate order",
  );
  assert.ok(
    priorities.get("qlty") < priorities.get("go-test"),
    "qlty runs before go-test, matching the portwing gate order",
  );
});

function workflowFiles() {
  const dir = path.join(ROOT, ".github", "workflows");
  return fs
    .readdirSync(dir)
    .filter((name) => name.endsWith(".yml"))
    .sort();
}

const BLOCK_MODE_WORKFLOWS = ["release-cut.yml", "release-from-tag.yml"];
const HARDEN_RUNNER_USES = /^(\s*)(?:-\s+)?uses:\s*step-security\/harden-runner@/u;
const ENDPOINT_TOKEN = /^[A-Za-z0-9*.-]+:\d+$/u;

function indentOf(line) {
  return line.length - line.trimStart().length;
}

// Returns one violation string per problem found in any harden-runner step of
// a release workflow. Each step is checked on its own, so a good step cannot
// vouch for a bad one. Parsed by indentation; the workflows use no anchors or
// flow-style maps for these steps.
function releaseHardenRunnerViolations(yamlText) {
  const lines = yamlText.split("\n").filter((line) => !/^\s*#/u.test(line));
  const violations = [];
  let steps = 0;
  lines.forEach((line, i) => {
    const m = HARDEN_RUNNER_USES.exec(line);
    if (!m) return;
    steps += 1;
    const label = `harden-runner step ${steps} (line ${i + 1} of comment-stripped source)`;
    const keyIndent = indentOf(line) + (/^\s*-\s/u.test(line) ? 2 : 0);
    const body = [];
    for (let j = i + 1; j < lines.length; j += 1) {
      if (lines[j].trim() === "") continue;
      if (indentOf(lines[j]) < keyIndent) break;
      body.push(lines[j]);
    }
    const withAt = body.findIndex((l) => indentOf(l) === keyIndent && /^\s*with:\s*$/u.test(l));
    if (withAt === -1) {
      violations.push(`${label}: no with: block`);
      return;
    }
    const withLines = [];
    for (let j = withAt + 1; j < body.length && indentOf(body[j]) > keyIndent; j += 1) {
      withLines.push(body[j]);
    }
    const childIndent = withLines.length ? indentOf(withLines[0]) : keyIndent + 2;
    const children = withLines.filter((l) => indentOf(l) === childIndent);
    if (!children.some((l) => /^\s*egress-policy:\s*block\s*$/u.test(l))) {
      violations.push(`${label}: egress-policy must be block`);
    }
    const epAt = withLines.findIndex(
      (l) => /^\s*allowed-endpoints:/u.test(l) && indentOf(l) === childIndent,
    );
    if (epAt === -1) {
      violations.push(`${label}: missing allowed-endpoints`);
      return;
    }
    const value = withLines[epAt].replace(/^\s*allowed-endpoints:/u, "").trim();
    const scalar = /^[>|][-+]?$/u.test(value);
    const parts = scalar ? [] : [value];
    if (scalar) {
      for (let j = epAt + 1; j < withLines.length && indentOf(withLines[j]) > childIndent; j += 1) {
        parts.push(withLines[j]);
      }
    }
    const tokens = parts.join(" ").split(/\s+/u).filter(Boolean);
    if (!tokens.some((t) => ENDPOINT_TOKEN.test(t))) {
      violations.push(`${label}: allowed-endpoints needs at least one host:port`);
    }
  });
  if (steps === 0) violations.push("no harden-runner steps found");
  return violations;
}

const RETRIED_STEP_USES =
  /^\s*uses:\s*(actions\/checkout|docker\/setup-buildx-action|docker\/setup-qemu-action|actions\/upload-artifact|actions\/download-artifact)@/u;

// Splits a workflow into jobs (children of the top-level `jobs:` key), then
// each job into steps by indentation. `steps.<id>` is scoped per job, so the
// first-attempt/retry matching runs inside one job at a time.
function retryJobs(yamlText) {
  const lines = yamlText.split("\n").filter((line) => !/^\s*#/u.test(line));
  const jobs = [];
  let inJobs = false;
  let job = null;
  for (const line of lines) {
    if (/^jobs:\s*$/u.test(line)) {
      inJobs = true;
      continue;
    }
    if (!inJobs) continue;
    if (line.trim() !== "" && indentOf(line) === 0) {
      inJobs = false;
      job = null;
      continue;
    }
    const m = /^ {2}([A-Za-z0-9_-]+):\s*$/u.exec(line);
    if (m) {
      job = { name: m[1], lines: [] };
      jobs.push(job);
    } else if (job) {
      job.lines.push(line);
    }
  }
  // A bare steps fragment (no `jobs:` key) is checked as one anonymous job.
  if (jobs.length === 0) jobs.push({ name: "(no jobs)", lines });
  return jobs;
}

function releaseRetryViolations(yamlText) {
  const jobs = retryJobs(yamlText);
  const violations = [];
  let retried = 0;
  for (const j of jobs) {
    const found = jobRetryViolations(j.lines);
    retried += found.retried;
    for (const v of found.violations) violations.push(`job ${j.name}: ${v}`);
  }
  if (retried === 0) violations.push("no retried checkout, Buildx, upload or download steps found");
  return violations;
}

function jobRetryViolations(lines) {
  const steps = [];
  let current = null;
  for (const line of lines) {
    if (/^\s*-\s+\S/u.test(line) && indentOf(line) === 6) {
      current = { lines: [line] };
      steps.push(current);
    } else if (current && (line.trim() === "" || indentOf(line) > 6)) {
      current.lines.push(line);
    } else {
      current = null;
    }
  }
  const field = (step, key) =>
    step.lines
      .filter((l) => indentOf(l.replace(/^(\s*)-\s/u, "$1  ")) === 8)
      .map((l) => l.replace(/^\s*(?:-\s+)?/u, ""))
      .find((l) => l.startsWith(`${key}:`))
      ?.slice(key.length + 1)
      .trim();
  const violations = [];
  const targets = [];
  steps.forEach((step, i) => {
    const usesLine = step.lines.find((l) => RETRIED_STEP_USES.test(l));
    if (!usesLine) return;
    targets.push({
      i,
      step,
      uses: usesLine.trim(),
      id: field(step, "id"),
      cond: field(step, "if"),
      coe: field(step, "continue-on-error"),
      label: `step ${i + 1} (${field(step, "name")})`,
    });
  });
  const claimed = new Set();
  let chains = 0;
  for (const first of targets) {
    if (first.cond !== undefined || !first.id || first.coe !== "true") continue;
    claimed.add(first);
    const second = targets.find(
      (t) => t.i > first.i && t.cond === `steps.${first.id}.outcome == 'failure'`,
    );
    if (!second) {
      violations.push(`${first.label}: no second attempt guarded by steps.${first.id}.outcome`);
      continue;
    }
    claimed.add(second);
    const hasWait = (from, to, guard, seconds) =>
      steps.some(
        (w, wi) =>
          wi > from.i &&
          wi < to.i &&
          field(w, "if") === guard &&
          field(w, "run") === `sleep ${seconds}`,
      );
    let waitsOk = true;
    if (!hasWait(first, second, `steps.${first.id}.outcome == 'failure'`, 30)) {
      violations.push(
        `${first.label}: missing 'sleep 30' step between attempt 1 and 2 guarded by steps.${first.id}.outcome`,
      );
      waitsOk = false;
    }
    if (!second.id || second.coe !== "true") {
      violations.push(`${second.label}: second attempt needs an id and continue-on-error: true`);
      continue;
    }
    const finalGuard = `steps.${first.id}.outcome == 'failure' && steps.${second.id}.outcome == 'failure'`;
    const third = targets.find((t) => t.i > second.i && t.cond === finalGuard);
    if (!third) {
      violations.push(`${first.label}: no third attempt guarded by both failed attempts`);
      continue;
    }
    claimed.add(third);
    let ok = waitsOk;
    if (
      !hasWait(
        second,
        third,
        `steps.${first.id}.outcome == 'failure' && steps.${second.id}.outcome == 'failure'`,
        60,
      )
    ) {
      violations.push(
        `${first.label}: missing 'sleep 60' step between attempt 2 and 3 guarded by both failed attempts`,
      );
      ok = false;
    }
    if (third.coe !== undefined) {
      violations.push(`${third.label}: final attempt must not set continue-on-error`);
      ok = false;
    }
    if (second.uses !== first.uses || third.uses !== first.uses) {
      violations.push(`${first.label}: all three attempts must use the same pinned action`);
      ok = false;
    }
    if (/actions\/upload-artifact@/u.test(first.uses)) {
      for (const retry of [second, third]) {
        if (!retry.step.lines.some((l) => l.trim() === "overwrite: true")) {
          violations.push(`${retry.label}: upload retry needs overwrite: true`);
          ok = false;
        }
      }
    }
    if (ok) chains += 1;
  }
  for (const t of targets) {
    if (claimed.has(t)) continue;
    violations.push(`${t.label}: not part of a complete three-attempt retry chain`);
  }
  return { violations, retried: chains };
}

// Builds one three-attempt chain for the fixtures below. `omit` drops the
// final attempt; `noOverwrite` leaves overwrite: true off the upload retries.
function chainFixture(
  action,
  base,
  {
    omit = false,
    noOverwrite = false,
    wait1 = "sleep 30",
    wait2 = "sleep 60",
    waitOrder = "",
  } = {},
) {
  const uses = `        uses: ${action}@abc\n`;
  const ow =
    action.includes("upload-artifact") && !noOverwrite
      ? "        with:\n          overwrite: true\n"
      : "";
  const g1 = `steps.${base}.outcome == 'failure'`;
  const g2 = `${g1} && steps.${base}_retry.outcome == 'failure'`;
  const wait = (guard, run) =>
    run === null ? "" : `      - name: Wait\n        if: ${guard}\n        run: ${run}\n`;
  const first = `      - name: A\n        id: ${base}\n        continue-on-error: true\n${uses}`;
  const second = `      - name: A (retry)\n        id: ${base}_retry\n        if: ${g1}\n        continue-on-error: true\n${uses}${ow}`;
  const third = `      - name: A (final retry)\n        id: ${base}_final\n        if: ${g2}\n${uses}${ow}`;
  const w1 = wait(waitOrder === "w1-guard" ? g2 : g1, wait1);
  const w2 = wait(waitOrder === "w2-guard" ? g1 : g2, wait2);
  if (waitOrder === "w1-after") return first + second + w1 + w2 + (omit ? "" : third);
  return first + w1 + second + w2 + (omit ? "" : third);
}

test("release workflows retry network steps three times after 30 s and 60 s waits", () => {
  const dir = path.join(ROOT, ".github", "workflows");
  for (const name of BLOCK_MODE_WORKFLOWS) {
    const raw = fs.readFileSync(path.join(dir, name), "utf8");
    assert.deepEqual(releaseRetryViolations(raw), [], `${name} retried steps`);
  }
  const bad = "    steps:\n      - name: Checkout\n        uses: actions/checkout@abc\n";
  assert.equal(releaseRetryViolations(bad).length, 2);
});

test("release retry chains must be complete", () => {
  const wrap = (body) => `on: push\njobs:\n  one:\n    steps:\n${body}`;
  assert.deepEqual(releaseRetryViolations(wrap(chainFixture("actions/checkout", "checkout"))), []);
  const two = releaseRetryViolations(
    wrap(chainFixture("actions/checkout", "checkout", { omit: true })),
  );
  assert.ok(
    two.some((v) => /no third attempt/u.test(v)),
    two.join("\n"),
  );
  assert.deepEqual(
    releaseRetryViolations(wrap(chainFixture("actions/upload-artifact", "upload"))),
    [],
  );
  const noOverwrite = releaseRetryViolations(
    wrap(chainFixture("actions/upload-artifact", "upload", { noOverwrite: true })),
  );
  assert.equal(noOverwrite.filter((v) => /needs overwrite: true/u.test(v)).length, 2);
  const download = releaseRetryViolations(
    wrap("      - name: Download\n        uses: actions/download-artifact@abc\n"),
  );
  assert.ok(
    download.some((v) => /not part of a complete/u.test(v)),
    download.join("\n"),
  );
  assert.deepEqual(
    releaseRetryViolations(wrap(chainFixture("actions/download-artifact", "dl"))),
    [],
  );
  assert.deepEqual(
    releaseRetryViolations(wrap(chainFixture("docker/setup-buildx-action", "buildx"))),
    [],
  );
});

test("release retry chains must have the 30 s and 60 s waits", () => {
  const wrap = (body) => `on: push\njobs:\n  one:\n    steps:\n${body}`;
  const check = (opts) =>
    releaseRetryViolations(wrap(chainFixture("actions/checkout", "checkout", opts)));
  assert.deepEqual(check({}), []);
  assert.ok(check({ wait1: null }).some((v) => /missing 'sleep 30'/u.test(v)));
  assert.ok(check({ wait2: null }).some((v) => /missing 'sleep 60'/u.test(v)));
  assert.ok(check({ wait1: "sleep 5" }).some((v) => /missing 'sleep 30'/u.test(v)));
  assert.ok(check({ wait2: "sleep 5" }).some((v) => /missing 'sleep 60'/u.test(v)));
  assert.ok(check({ waitOrder: "w1-guard" }).some((v) => /missing 'sleep 30'/u.test(v)));
  assert.ok(check({ waitOrder: "w2-guard" }).some((v) => /missing 'sleep 60'/u.test(v)));
  assert.ok(check({ waitOrder: "w1-after" }).some((v) => /missing 'sleep 30'/u.test(v)));
});

test("release workflow jobs leave at least half their timeout after retry waits", () => {
  const dir = path.join(ROOT, ".github", "workflows");
  for (const name of BLOCK_MODE_WORKFLOWS) {
    const raw = fs.readFileSync(path.join(dir, name), "utf8");
    for (const j of retryJobs(raw)) {
      const chains = jobRetryViolations(j.lines).retried;
      const m = /^ {4}timeout-minutes:\s*(\d+)/mu.exec(j.lines.join("\n"));
      const minutes = m ? Number(m[1]) : 360;
      assert.ok(
        minutes * 60 >= 2 * (90 * chains),
        `${name} job ${j.name}: ${chains} chains need ${90 * chains} s of waits, timeout is ${minutes} min`,
      );
    }
  }
});

test("release retry matching is scoped per job", () => {
  const full = chainFixture("actions/checkout", "checkout");
  const partial = chainFixture("actions/checkout", "checkout", { omit: true });
  const wf = `on: push\njobs:\n  one:\n    steps:\n${partial}  two:\n    steps:\n${full}`;
  const found = releaseRetryViolations(wf);
  assert.equal(found.length, 1);
  assert.match(found[0], /^job one: .*no third attempt/u);
  const both = `on: push\njobs:\n  one:\n    steps:\n${full}  two:\n    steps:\n${full}`;
  assert.deepEqual(releaseRetryViolations(both), []);
});

const HR = "step-security/harden-runner@abc  # v2";

// Splits a workflow into { id, text } per job (children of the top-level
// `jobs:` key) by indentation, comments stripped. `header` is everything
// before `jobs:`, so a workflow-level permissions block can be inspected.
function splitJobs(yamlText) {
  const lines = yamlText.split("\n").filter((line) => !/^\s*#/u.test(line));
  const jobsAt = lines.findIndex((l) => /^jobs:\s*$/u.test(l));
  if (jobsAt === -1) return { header: lines.join("\n"), jobs: [] };
  const jobs = [];
  for (let i = jobsAt + 1; i < lines.length; i += 1) {
    if (lines[i].trim() === "") continue;
    if (indentOf(lines[i]) === 0) break;
    const m = /^ {2}([A-Za-z0-9_-]+):\s*$/u.exec(lines[i]);
    if (m) jobs.push({ id: m[1], lines: [] });
    else if (jobs.length) jobs.at(-1).lines.push(lines[i]);
  }
  return {
    header: lines.slice(0, jobsAt).join("\n"),
    jobs: jobs.map((j) => ({ id: j.id, text: j.lines.join("\n") })),
  };
}

const WRITE_PERMISSION = /^\s*contents:\s*write\b/mu;
const PERSISTED_CREDENTIAL = /^\s*persist-credentials:\s*true\b/mu;

// Block mode is for jobs that can write: a contents: write permission (job or
// workflow level) or a checkout that persists its credential. Every
// harden-runner step in such a job must be block with an allow list; any other
// job must not carry block or an allow list (DEP-19). Returns violations.
function hardenRunnerPolicyViolations(yamlText) {
  const { header, jobs } = splitJobs(yamlText);
  const workflowWrite = WRITE_PERMISSION.test(header);
  const violations = [];
  for (const job of jobs) {
    // A caller of a reusable workflow has no steps here; its harden-runner
    // steps live in the called workflow.
    if (/^ {4}uses:/mu.test(job.text)) continue;
    const writes =
      workflowWrite || WRITE_PERMISSION.test(job.text) || PERSISTED_CREDENTIAL.test(job.text);
    if (writes) {
      for (const v of releaseHardenRunnerViolations(job.text)) {
        violations.push(`job ${job.id} holds a write credential: ${v}`);
      }
    } else if (/egress-policy: block/u.test(job.text) || /allowed-endpoints:/u.test(job.text)) {
      violations.push(
        `job ${job.id} is read-only and must run harden-runner in audit mode (DEP-19)`,
      );
    }
  }
  return violations;
}

test("harden-runner block mode is kept on write-credential jobs only, with an allow list", () => {
  const dir = path.join(ROOT, ".github", "workflows");
  for (const name of workflowFiles()) {
    const raw = fs.readFileSync(path.join(dir, name), "utf8");
    if (BLOCK_MODE_WORKFLOWS.includes(name)) {
      assert.deepEqual(releaseHardenRunnerViolations(raw), [], `${name} harden-runner steps`);
      continue;
    }
    assert.deepEqual(hardenRunnerPolicyViolations(raw), [], `${name} harden-runner policy`);
  }
});

test("the harden-runner policy follows the write credential, not the workflow name", () => {
  const job = (id, perms, persist, mode, allow) =>
    [
      `  ${id}:`,
      "    runs-on: ubuntu-latest",
      ...(perms ? ["    permissions:", `      contents: ${perms}`] : []),
      "    steps:",
      "      - name: Harden Runner",
      `        uses: ${HR}`,
      "        with:",
      `          egress-policy: ${mode}`,
      ...(allow ? ["          allowed-endpoints: >", "            github.com:443"] : []),
      "      - uses: actions/checkout@abc",
      "        with:",
      `          persist-credentials: ${persist}`,
    ].join("\n");
  const wf = (...jobs) => `on: push\njobs:\n${jobs.join("\n")}\n`;

  // write job in block mode with a list, read-only job in audit: clean
  assert.deepEqual(
    hardenRunnerPolicyViolations(
      wf(
        job("badge", "write", "false", "block", true),
        job("scan", "read", "false", "audit", false),
      ),
    ),
    [],
  );
  // a persisted checkout credential counts as a write job even without the permission
  assert.deepEqual(
    hardenRunnerPolicyViolations(wf(job("push", "read", "true", "block", true))),
    [],
  );
  // write job left in audit mode
  const audit = hardenRunnerPolicyViolations(wf(job("badge", "write", "false", "audit", false)));
  assert.equal(audit.length, 2);
  assert.match(audit[0], /job badge .*egress-policy must be block/u);
  // write job in block mode without an allow list
  const noList = hardenRunnerPolicyViolations(wf(job("badge", "write", "false", "block", false)));
  assert.equal(noList.length, 1);
  assert.match(noList[0], /missing allowed-endpoints/u);
  // read-only job in block mode
  const readBlock = hardenRunnerPolicyViolations(wf(job("scan", "read", "false", "block", true)));
  assert.equal(readBlock.length, 1);
  assert.match(readBlock[0], /job scan is read-only/u);
});

const goodStep = (name) =>
  [
    `      - name: ${name}`,
    `        uses: ${HR}`,
    "        with:",
    "          egress-policy: block",
    "          allowed-endpoints: >",
    "            github.com:443",
    "            *.actions.githubusercontent.com:443",
  ].join("\n");

test("release harden-runner checker accepts good steps and rejects bad ones", () => {
  assert.deepEqual(releaseHardenRunnerViolations(`${goodStep("one")}\n\n${goodStep("two")}\n`), []);

  // (a) second step in audit mode
  const audit = goodStep("two").replace("egress-policy: block", "egress-policy: audit");
  const a = releaseHardenRunnerViolations(`${goodStep("one")}\n${audit}\n`);
  assert.equal(a.length, 1);
  assert.match(a[0], /step 2.*egress-policy must be block/u);

  // (b) empty block scalar followed directly by the next key, same or lower indent
  for (const next of ["          other-key: value", "        env:\n          A: b:1"]) {
    const empty = [
      `      - uses: ${HR}`,
      "        with:",
      "          egress-policy: block",
      "          allowed-endpoints: >",
      next,
    ].join("\n");
    const b = releaseHardenRunnerViolations(empty);
    assert.equal(b.length, 1, next);
    assert.match(b[0], /host:port/u);
  }

  // (c) block mode with no allowed-endpoints
  const noList = [
    `      - uses: ${HR}`,
    "        with:",
    "          egress-policy: block",
    "      - name: next",
    "        run: echo hi:80",
  ].join("\n");
  const c = releaseHardenRunnerViolations(noList);
  assert.equal(c.length, 1);
  assert.match(c[0], /missing allowed-endpoints/u);

  // no harden-runner steps at all fails loudly
  assert.deepEqual(releaseHardenRunnerViolations("steps: []\n"), ["no harden-runner steps found"]);
});

test("retired X1 bridge jobs must not be reintroduced", () => {
  assertBridgesAbsent(fs.readFileSync(WORKFLOW, "utf8"));
});

test("retired local job ids stay retired", () => {
  const source = fs.readFileSync(WORKFLOW, "utf8");
  for (const jobId of RETIRED_LOCAL_JOBS) {
    assert.equal(jobSection(source, jobId), "", `${jobId} must stay removed`);
  }
});

test("development and maintenance release branches run exact-SHA CI", () => {
  const source = fs.readFileSync(WORKFLOW, "utf8");
  assertReleaseBranchTriggers(source);
  assert.throws(() => assertReleaseBranchTriggers(source.replaceAll("'dev/*', ", "")));
  assert.throws(() => assertReleaseBranchTriggers(source.replaceAll("'maintenance/*', ", "")));
});

test("the contract rejects a moving reusable ref, a dropped permission, and a reintroduced bridge", () => {
  const source = fs.readFileSync(WORKFLOW, "utf8");
  assert.throws(() => assertReusableCaller(source.replaceAll(SHARED_SHA, "main")));

  const goJob = jobSection(source, "go-ci");
  const droppedPermission = goJob.replace("      security-events: write\n", "");
  assert.throws(() => assertReusableCaller(source.replace(goJob, droppedPermission)));

  const reintroducedRetiredJob = [
    "  go-lint:",
    '    name: "Go Lint"',
    "    runs-on: ubuntu-latest",
    "",
    "",
  ].join("\n");
  assert.throws(
    () => assertReusableCaller(source.replace("  codeql:", `${reintroducedRetiredJob}  codeql:`)),
    /go-lint must move behind a reusable caller/u,
  );

  const reintroducedBridge = [
    "  legacy-go-test:",
    '    name: "Go Test"',
    "    needs: go-ci",
    "    runs-on: ubuntu-latest",
    "",
    "",
  ].join("\n");
  assert.throws(
    () => assertBridgesAbsent(source.replace("  codeql:", `${reintroducedBridge}  codeql:`)),
    /legacy-go-test bridge job must stay removed/u,
  );

  const renamedUnquotedBridge = [
    "  shadow-go-test:",
    "    name: Go Test",
    "    needs: go-ci",
    "    runs-on: ubuntu-latest",
    "",
    "",
  ].join("\n");
  assert.throws(
    () => assertBridgesAbsent(source.replace("  codeql:", `${renamedUnquotedBridge}  codeql:`)),
    /must not report the retired "Go Test" context/u,
  );
});

// REL-19: Rekor answers 409 when cosign signs the same repository@digest
// twice, so the publisher signs and verifies each repository once, not each tag.
function stepRunScript(yamlText, stepName) {
  const lines = yamlText.split("\n");
  const at = lines.findIndex((l) => l.trim() === `- name: ${stepName}`);
  assert.notEqual(at, -1, `step ${stepName} not found`);
  const runAt = lines.findIndex((l, i) => i > at && l.trim() === "run: |");
  assert.notEqual(runAt, -1, `${stepName} has no run block`);
  const body = [];
  for (let i = runAt + 1; i < lines.length; i += 1) {
    if (lines[i].trim() !== "" && indentOf(lines[i]) <= indentOf(lines[runAt])) break;
    body.push(lines[i]);
  }
  return body.join("\n");
}

test("release publisher signs and verifies each image repository once", () => {
  const raw = fs.readFileSync(
    path.join(ROOT, ".github", "workflows", "release-from-tag.yml"),
    "utf8",
  );
  const digest = `sha256:${"a".repeat(64)}`;
  const tags = [
    "ghcr.io/codeswhat/sockguard:2.3.3",
    "ghcr.io/codeswhat/sockguard:2.3",
    "ghcr.io/codeswhat/sockguard:2",
    "ghcr.io/codeswhat/sockguard:latest",
    "ghcr.io/codeswhat/sockguard:latest",
    "docker.io/codeswhat/sockguard:2.3.3",
    "docker.io/codeswhat/sockguard:latest",
    "docker.io/codeswhat/sockguard:latest",
    "quay.io/codeswhat/sockguard:2.3.3",
    "quay.io/codeswhat/sockguard:latest",
    "localhost:5000/codeswhat/sockguard:1.0",
  ].join("\n");
  const expected = [
    `ghcr.io/codeswhat/sockguard@${digest}`,
    `docker.io/codeswhat/sockguard@${digest}`,
    `quay.io/codeswhat/sockguard@${digest}`,
    `localhost:5000/codeswhat/sockguard@${digest}`,
  ];
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "rel19-"));
  try {
    const bin = path.join(tmp, "bin");
    fs.mkdirSync(bin);
    const record = path.join(tmp, "calls.txt");
    fs.writeFileSync(
      path.join(bin, "cosign"),
      `#!/usr/bin/env bash\nprintf '%s\\n' "$*" >> "${record}"\n`,
      { mode: 0o755 },
    );
    fs.writeFileSync(path.join(bin, "sleep"), "#!/usr/bin/env bash\nexit 0\n", { mode: 0o755 });
    for (const [step, mode] of [
      ["Sign container images", "sign"],
      ["Verify container image signatures", "verify"],
    ]) {
      fs.rmSync(record, { force: true });
      const script = path.join(tmp, `${mode}.sh`);
      fs.writeFileSync(script, stepRunScript(raw, step));
      const result = spawnSync("bash", [script], {
        encoding: "utf8",
        env: {
          PATH: `${bin}:${process.env.PATH}`,
          DIGEST: digest,
          TAGS: tags,
          GITHUB_REPOSITORY: "CodesWhat/sockguard",
        },
      });
      assert.equal(result.status, 0, `${step}: ${result.stderr}`);
      const calls = fs.readFileSync(record, "utf8").trim().split("\n");
      if (mode === "sign") {
        assert.equal(calls.length, 1, "one cosign sign call");
        const args = calls[0].split(" ");
        assert.deepEqual(args.slice(0, 2), ["sign", "--yes"]);
        assert.deepEqual(args.slice(2), expected);
      } else {
        const refs = calls.map((c) => c.split(" ").at(-1));
        assert.deepEqual(refs, expected);
        assert.ok(calls.every((c) => c.startsWith("verify ")));
      }
    }
    // Retry: a fake cosign that fails the first N sign calls.
    const flaky = path.join(tmp, "flaky-bin");
    fs.mkdirSync(flaky);
    const counter = path.join(tmp, "count.txt");
    fs.writeFileSync(path.join(flaky, "sleep"), "#!/usr/bin/env bash\nexit 0\n", { mode: 0o755 });
    fs.writeFileSync(
      path.join(flaky, "cosign"),
      [
        "#!/usr/bin/env bash",
        `echo x >> "${counter}"`,
        `n=$(wc -l < "${counter}")`,
        'if [ "$n" -le "${FAKE_COSIGN_FAIL_SIGNS:-0}" ]; then exit 1; fi',
        "",
      ].join("\n"),
      { mode: 0o755 },
    );
    for (const [fails, wantStatus, wantCalls] of [
      [1, 0, 2],
      [3, 1, 3],
    ]) {
      fs.rmSync(counter, { force: true });
      const r = spawnSync("bash", [path.join(tmp, "sign.sh")], {
        encoding: "utf8",
        env: {
          PATH: `${flaky}:${process.env.PATH}`,
          DIGEST: digest,
          TAGS: tags,
          FAKE_COSIGN_FAIL_SIGNS: String(fails),
        },
      });
      const calls = fs.readFileSync(counter, "utf8").trim().split("\n").length;
      assert.equal(r.status === 0 ? 0 : 1, wantStatus, `fail ${fails}: ${r.stderr}`);
      assert.equal(calls, wantCalls, `fail ${fails}: sign call count`);
      if (wantStatus !== 0) assert.match(r.stdout, /cosign sign failed after 3 attempts/u);
    }
    const empty = spawnSync("bash", [path.join(tmp, "sign.sh")], {
      encoding: "utf8",
      env: { PATH: `${bin}:${process.env.PATH}`, DIGEST: digest, TAGS: "" },
    });
    assert.notEqual(empty.status, 0, "empty tag set must fail");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("release publisher retries Set up QEMU like Set up Docker Buildx", () => {
  const raw = fs.readFileSync(
    path.join(ROOT, ".github", "workflows", "release-from-tag.yml"),
    "utf8",
  );
  for (const name of [
    "Set up QEMU",
    "Wait before Set up QEMU retry",
    "Set up QEMU (retry)",
    "Wait before Set up QEMU final retry",
    "Set up QEMU (final retry)",
  ]) {
    assert.ok(raw.includes(`- name: ${name}\n`), `${name} missing`);
  }
});
