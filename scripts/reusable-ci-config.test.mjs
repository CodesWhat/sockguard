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
  [
    "go-lint.sh",
    ["golangci-lint/v2/cmd/golangci-lint@v2.12.2", "gofmt -l", "GOLANGCI_LINT_CACHE"],
  ],
  [
    "go-release-check.sh",
    ["goreleaser/goreleaser/v2@v2.15.3", "release --snapshot --clean --skip=publish", "cask "],
  ],
  ["go-fuzz.sh", ["FUZZER", "PKG", "fuzztime=60s"]],
  ["shellcheck.sh", ["command -v shellcheck", "git ls-files -z '*.sh'", "shellcheck \"${scripts[@]}\""]],
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
  ["FuzzDecode", "./internal/dockerfilters/"],
  ["FuzzProxyHeadersAndBody", "./internal/proxy/"],
  ["FuzzHijackHeadersAndBody", "./internal/proxy/"],
  ["FuzzPathRoutingDifferential", "./differential/"],
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

const RETIRED_LOCAL_JOBS = ["zizmor", "goreleaser-check", "go-lint", "go-test", "go-fuzz", "ts-lint", "ts-test", "ts-build"];

const GO_INPUTS = [
  "module-directory: app",
  "go-version-file: go.mod",
  "go-cache-dependency-path: go.sum",
  "lint-check-name: Go Lint",
  "test-check-name: Go Test",
  "run-workflow-security: true",
  `run-goreleaser: \${{ github.event_name != 'schedule' }}`,
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
  assert.doesNotMatch(go, /run-codeql:\s*true/u, "CodeQL must stay local, not routed through go-ci");

  assert.ok(jobSection(source, "codeql"), "CodeQL must remain local to keep javascript-typescript coverage");
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
      assert.throws(() => assertReusableCaller(source.replace(`      ${input}`, `      # ${input}`)));
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
  assert.match(lefthook, /^ {4}goreleaser-snapshot:\n {6}run: \.\/scripts\/ci\/go-release-check\.sh$/mu);
  assert.doesNotMatch(lefthook, /^ {6}run: golangci-lint run$/mu);
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

test("the contract rejects a moving reusable ref, a dropped permission, and a reintroduced bridge", () => {
  const source = fs.readFileSync(WORKFLOW, "utf8");
  assert.throws(() => assertReusableCaller(source.replaceAll(SHARED_SHA, "main")));

  const goJob = jobSection(source, "go-ci");
  const droppedPermission = goJob.replace("      security-events: write\n", "");
  assert.throws(() => assertReusableCaller(source.replace(goJob, droppedPermission)));

  const reintroducedRetiredJob = ["  go-lint:", '    name: "Go Lint"', "    runs-on: ubuntu-latest", "", ""].join(
    "\n",
  );
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
