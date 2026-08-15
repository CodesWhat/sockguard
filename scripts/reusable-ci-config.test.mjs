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

// The nine required plain contexts a branch-protection ruleset (out of
// scope for this migration) still demands. Two stay entirely local
// (CodeQL Analysis, Docker Build); the other seven are produced by a
// "legacy-*" bridge job that mirrors a reusable-workflow result. Remove
// this map (and the bridge jobs) only when the ruleset itself has been
// migrated to require the "Go CI / ..." / "Node CI / ..." contexts instead.
const BRIDGES = new Map([
  ["legacy-workflow-security", { checkName: "Workflow Security", needs: "go-ci", resultVar: "GO_CI_RESULT" }],
  ["legacy-goreleaser", { checkName: "GoReleaser Config", needs: "go-ci", resultVar: "GO_CI_RESULT" }],
  ["legacy-go-lint", { checkName: "Go Lint", needs: "go-ci", resultVar: "GO_CI_RESULT" }],
  ["legacy-go-test", { checkName: "Go Test", needs: "go-ci", resultVar: "GO_CI_RESULT" }],
  ["legacy-biome-lint", { checkName: "Biome Lint", needs: "node-ci", resultVar: "NODE_CI_RESULT" }],
  ["legacy-ts-test", { checkName: "TS Test", needs: "node-ci", resultVar: "NODE_CI_RESULT" }],
  ["legacy-build-workspaces", { checkName: "Build Workspaces", needs: "node-ci", resultVar: "NODE_CI_RESULT" }],
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

const HARDEN_RUNNER = "step-security/harden-runner@bf7454d06d71f1098171f2acdf0cd4708d7b5920";

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

function assertTemporaryBridges(source) {
  for (const [jobId, { checkName, needs, resultVar }] of BRIDGES) {
    const bridge = jobSection(source, jobId);
    assert.ok(bridge, `missing temporary ${checkName} bridge (${jobId})`);
    assert.ok(bridge.includes(`name: "${checkName}"`), `${jobId} has the wrong check name`);
    assert.match(bridge, new RegExp(`^ {4}needs: ${needs}$`, "mu"));
    assert.match(bridge, /^ {4}if: \$\{\{ always\(\) \}\}$/mu);
    assert.match(
      bridge,
      new RegExp(
        `^ {8}env:\\n {10}${resultVar}: \\$\\{\\{ needs\\.${needs}\\.result \\}\\}\\n {8}run: test "\\$\\{${resultVar}\\}" = "success"$`,
        "mu",
      ),
    );
    assert.doesNotMatch(bridge, /^ {8}run:.*\$\{\{/mu);
    const hardenRunnerUses = bridge.split("\n").filter((line) => {
      const withoutComment = line.trim().split(/\s+#/u, 1)[0];
      return withoutComment === `uses: ${HARDEN_RUNNER}`;
    });
    assert.equal(hardenRunnerUses.length, 1, `${jobId} must pin one harden-runner step`);
    assert.match(bridge, /^ {10}egress-policy: block$/mu);
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

test("temporary bridges keep every required legacy context fail-closed", () => {
  assertTemporaryBridges(fs.readFileSync(WORKFLOW, "utf8"));
});

test("retired local job ids stay retired", () => {
  const source = fs.readFileSync(WORKFLOW, "utf8");
  for (const jobId of RETIRED_LOCAL_JOBS) {
    assert.equal(jobSection(source, jobId), "", `${jobId} must stay removed`);
  }
});

test("the contract rejects a moving reusable ref, a dropped permission, and a fail-open bridge", () => {
  const source = fs.readFileSync(WORKFLOW, "utf8");
  assert.throws(() => assertReusableCaller(source.replaceAll(SHARED_SHA, "main")));

  const goJob = jobSection(source, "go-ci");
  const droppedPermission = goJob.replace("      security-events: write\n", "");
  assert.throws(() => assertReusableCaller(source.replace(goJob, droppedPermission)));

  assert.throws(() =>
    assertTemporaryBridges(
      source.replace(
        `test "\${GO_CI_RESULT}" = "success"`,
        `test "\${GO_CI_RESULT}" != "cancelled"`,
      ),
    ),
  );

  const legacyGoTest = jobSection(source, "legacy-go-test");
  assert.throws(
    () =>
      assertTemporaryBridges(
        source.replace(legacyGoTest, legacyGoTest.replace(HARDEN_RUNNER, "example")),
      ),
    /legacy-go-test must pin one harden-runner step/u,
  );
  assert.throws(
    () =>
      assertTemporaryBridges(
        source.replace(
          legacyGoTest,
          legacyGoTest.replace(`uses: ${HARDEN_RUNNER}`, `# ${HARDEN_RUNNER}`),
        ),
      ),
    /legacy-go-test must pin one harden-runner step/u,
  );

  const reintroducedRetiredJob = ["  go-lint:", '    name: "Go Lint"', "    runs-on: ubuntu-latest", "", ""].join(
    "\n",
  );
  assert.throws(
    () => assertReusableCaller(source.replace("  codeql:", `${reintroducedRetiredJob}  codeql:`)),
    /go-lint must move behind a reusable caller/u,
  );
});
