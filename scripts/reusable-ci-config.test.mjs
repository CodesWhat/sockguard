import assert from "node:assert/strict";
import fs from "node:fs";
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

test("only the release workflows keep harden-runner block mode, with an allow list", () => {
  const dir = path.join(ROOT, ".github", "workflows");
  for (const name of workflowFiles()) {
    const raw = fs.readFileSync(path.join(dir, name), "utf8");
    if (BLOCK_MODE_WORKFLOWS.includes(name)) {
      assert.deepEqual(releaseHardenRunnerViolations(raw), [], `${name} harden-runner steps`);
      continue;
    }
    // Comments may legitimately discuss block mode; only live config counts.
    const source = raw
      .split("\n")
      .filter((line) => !/^\s*#/u.test(line))
      .join("\n");
    assert.doesNotMatch(
      source,
      /egress-policy: block/u,
      `${name} must run harden-runner in audit mode (DEP-19)`,
    );
    assert.doesNotMatch(
      source,
      /allowed-endpoints:/u,
      `${name} is audit mode, so an allow list is dead config`,
    );
  }
});

const HR = "step-security/harden-runner@abc  # v2";
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
