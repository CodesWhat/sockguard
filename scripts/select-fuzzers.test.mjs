import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "..");
const selector = resolve(repoRoot, "scripts", "ci", "select-fuzzers.sh");

const LIST = [
  { name: "FuzzA", pkg: "./internal/filter/" },
  { name: "FuzzB", pkg: "./internal/filter/" },
  { name: "FuzzC", pkg: "./internal/buildkitproxy/" },
  { name: "FuzzD", pkg: "./internal/proxy/" },
];

// Hooks (lefthook pre-push) export GIT_DIR and friends. Inherited into a
// fixture repo they would point git at the real checkout.
function cleanEnv() {
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!key.startsWith("GIT_")) env[key] = value;
  }
  env.GIT_CONFIG_NOSYSTEM = "1";
  env.GIT_CONFIG_GLOBAL = "/dev/null";
  return env;
}

function git(cwd, ...args) {
  const result = spawnSync(
    "git",
    [
      "-c",
      "user.name=test",
      "-c",
      "user.email=test@example.invalid",
      "-c",
      "commit.gpgsign=false",
      ...args,
    ],
    { cwd, env: cleanEnv(), encoding: "utf8" },
  );
  assert.equal(result.status, 0, `git ${args.join(" ")}: ${result.stderr}`);
  return result.stdout;
}

describe("select-fuzzers.sh", () => {
  let dir;
  let listPath;

  before(() => {
    dir = mkdtempSync(join(tmpdir(), "select-fuzzers-"));
    listPath = join(dir, "list.json");
    writeFileSync(listPath, JSON.stringify(LIST));
    git(dir, "init", "-q", "-b", "base");
    for (const file of [
      "app/internal/filter/a.go",
      "app/internal/buildkitproxy/b.go",
      "app/internal/proxy/c.go",
      "app/internal/other/d.go",
      "go.mod",
      "go.sum",
    ]) {
      mkdirSync(dirname(join(dir, file)), { recursive: true });
      writeFileSync(join(dir, file), "v0\n");
    }
    git(dir, "add", ".");
    git(dir, "commit", "-q", "-m", "base");
  });

  after(() => rmSync(dir, { recursive: true, force: true }));

  // Branch off base, touch the files, commit, and run the selector.
  function select(files, { base = "base", list = listPath } = {}) {
    git(dir, "checkout", "-q", "-B", "pr", "base");
    for (const file of files) {
      mkdirSync(dirname(join(dir, file)), { recursive: true });
      writeFileSync(join(dir, file), `${Math.random()}\n`);
    }
    if (files.length > 0) {
      git(dir, "add", ".");
      git(dir, "commit", "-q", "-m", "change");
    }
    return spawnSync("bash", [selector, base, list], {
      cwd: dir,
      env: cleanEnv(),
      encoding: "utf8",
    });
  }

  const names = (result) => JSON.parse(result.stdout).map((entry) => entry.name);

  it("selects only the filter fuzzers for a filter change", () => {
    const result = select(["app/internal/filter/a.go"]);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(names(result), ["FuzzA", "FuzzB"]);
    assert.equal(result.stdout.trim().split("\n").length, 1, "output must be one line");
  });

  it("selects only the buildkitproxy fuzzers for a buildkitproxy change", () => {
    const result = select(["app/internal/buildkitproxy/new_test.go"]);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(names(result), ["FuzzC"]);
  });

  it("selects both packages when both change", () => {
    const result = select(["app/internal/proxy/c.go", "app/internal/buildkitproxy/b.go"]);
    assert.deepEqual(names(result).sort(), ["FuzzC", "FuzzD"]);
  });

  it("runs everything when go.mod, go.sum or the CI wiring changes", () => {
    for (const file of [
      "go.mod",
      "go.sum",
      ".github/workflows/ci-verify.yml",
      ".github/ci-fuzzers.json",
      "scripts/ci/select-fuzzers.sh",
      "scripts/ci/go-fuzz.sh",
    ]) {
      const result = select([file]);
      assert.equal(result.status, 0, result.stderr);
      assert.deepEqual(names(result), ["FuzzA", "FuzzB", "FuzzC", "FuzzD"], file);
    }
  });

  it("runs everything when the base ref cannot be read", () => {
    const result = select(["app/internal/other/d.go"], { base: "origin/does-not-exist" });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(names(result), ["FuzzA", "FuzzB", "FuzzC", "FuzzD"]);
    assert.match(result.stderr, /::warning::/);
  });

  it("runs everything when the diff is empty", () => {
    const result = select([]);
    assert.deepEqual(names(result), ["FuzzA", "FuzzB", "FuzzC", "FuzzD"]);
  });

  it("selects nothing for an unrelated app change", () => {
    const result = select(["app/internal/other/d.go", "README.md"]);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), "[]");
  });

  it("does not match a sibling directory that shares a name prefix", () => {
    const result = select(["app/internal/filterx/e.go"]);
    assert.equal(result.stdout.trim(), "[]");
  });

  it("fails loudly when the list is unreadable", () => {
    const result = select(["app/internal/filter/a.go"], { list: join(dir, "missing.json") });
    assert.notEqual(result.status, 0);
  });

  it("selects from the real fuzzer list", () => {
    const real = resolve(repoRoot, ".github", "ci-fuzzers.json");
    const result = select(["app/internal/dockerfilters/x.go"], { list: real });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(names(result), ["FuzzDecode"]);
  });
});
