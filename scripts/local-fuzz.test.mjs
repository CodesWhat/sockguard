import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "..");
const scriptPath = resolve(scriptDir, "local-fuzz.sh");
const copyScriptPath = resolve(scriptDir, "copy-fuzz-source.sh");

function runLocalFuzz(args) {
  return spawnSync("bash", [scriptPath, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
  });
}

function cleanGitEnvironment() {
  const result = spawnSync("git", ["rev-parse", "--local-env-vars"], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);

  const environment = { ...process.env };
  for (const name of result.stdout.trim().split("\n")) {
    delete environment[name];
  }
  return environment;
}

describe("local-fuzz.sh", () => {
  it("stages tracked and nonignored working files without ignored local state", (t) => {
    const fixtureRoot = mkdtempSync(join(tmpdir(), "sockguard-fuzz-copy-"));
    t.after(() => rmSync(fixtureRoot, { recursive: true, force: true }));

    const source = join(fixtureRoot, "source");
    const destination = join(fixtureRoot, "destination");
    mkdirSync(join(source, ".claude", "worktrees"), { recursive: true });
    mkdirSync(join(source, ".secrets"), { recursive: true });
    writeFileSync(join(source, ".gitignore"), ".claude/\n.secrets/\nignored.txt\n*.env\n");
    writeFileSync(join(source, "tracked.txt"), "committed\n");
    writeFileSync(join(source, ".claude", "worktrees", "nested.txt"), "ignored\n");
    writeFileSync(join(source, ".secrets", "credential.env"), "ignored\n");
    writeFileSync(join(source, "ignored.txt"), "ignored\n");

    for (const args of [
      ["init", "--quiet", source],
      ["-C", source, "add", ".gitignore", "tracked.txt"],
      ["init", "--quiet", join(source, "nested")],
    ]) {
      const result = spawnSync("git", args, {
        encoding: "utf8",
        env: cleanGitEnvironment(),
      });
      assert.equal(result.status, 0, result.stderr);
    }

    writeFileSync(join(source, "tracked.txt"), "working tree\n");
    writeFileSync(join(source, "untracked.txt"), "untracked\n");
    writeFileSync(join(source, "nested", "source.txt"), "tracked by nested repo\n");
    const nestedAdd = spawnSync("git", ["-C", join(source, "nested"), "add", "source.txt"], {
      encoding: "utf8",
      env: cleanGitEnvironment(),
    });
    assert.equal(nestedAdd.status, 0, nestedAdd.stderr);

    const outerGitDirectory = spawnSync("git", ["rev-parse", "--absolute-git-dir"], {
      cwd: repoRoot,
      encoding: "utf8",
    }).stdout.trim();
    const result = spawnSync("bash", [copyScriptPath, source, destination], {
      encoding: "utf8",
      env: { ...process.env, GIT_DIR: outerGitDirectory, GIT_WORK_TREE: repoRoot },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(readFileSync(join(destination, "tracked.txt"), "utf8"), "working tree\n");
    assert.equal(readFileSync(join(destination, "untracked.txt"), "utf8"), "untracked\n");
    assert.equal(existsSync(join(destination, ".claude")), false);
    assert.equal(existsSync(join(destination, ".secrets")), false);
    assert.equal(existsSync(join(destination, "ignored.txt")), false);
    assert.equal(existsSync(join(destination, "nested")), false);
  });

  it("prints CI-suite native fuzz commands in dry-run mode", () => {
    const result = runLocalFuzz([
      "--dry-run",
      "--suite",
      "ci",
      "--fuzztime",
      "1s",
      "--timeout",
      "5m",
      "--parallel",
      "2",
      "--jobs",
      "2",
    ]);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /FuzzHijackHeadersAndBody/);
    assert.ok(result.stdout.includes("go test -run='^$'"));
    assert.match(result.stdout, /-fuzztime=1s/);
    assert.match(result.stdout, /-timeout=5m/);
    assert.match(result.stdout, /-parallel=2/);
  });

  it("prints Docker Linux fuzz commands in dry-run mode", () => {
    const result = runLocalFuzz([
      "--dry-run",
      "--docker",
      "--platform",
      "linux/amd64",
      "--suite",
      "proxy",
      "--fuzztime",
      "1s",
      "--parallel",
      "2",
    ]);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /docker run --rm --platform linux\/amd64/);
    assert.match(result.stdout, /golang:1\.26\.2/);
    assert.match(result.stdout, /\/usr\/local\/go\/bin\/go test/);
    assert.match(result.stdout, /-timeout='10m1s'/);
    assert.match(result.stdout, /-parallel=2/);
    assert.doesNotMatch(result.stdout, /-parallel='2'/);
    assert.match(result.stdout, /FuzzHijackBidirectionalStream/);
  });

  it("rejects unknown suites", () => {
    const result = runLocalFuzz(["--dry-run", "--suite", "missing"]);

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /unknown suite "missing"/);
  });

  it("rejects invalid fuzztime syntax", () => {
    const result = runLocalFuzz(["--dry-run", "--fuzztime", "10minutes"]);

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /--fuzztime must use h\/m\/s components/);
  });

  it("rejects invalid timeout syntax", () => {
    const result = runLocalFuzz(["--dry-run", "--fuzztime", "1s", "--timeout", "five-minutes"]);

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /--timeout must use h\/m\/s components/);
  });

  it("does not duplicate fuzzers in the all suite", () => {
    const result = runLocalFuzz(["--dry-run", "--suite", "all", "--fuzztime", "1s"]);

    assert.equal(result.status, 0, result.stderr);

    const fuzzerLines = result.stdout.split("\n").filter((line) => line.startsWith("[Fuzz"));
    assert.equal(new Set(fuzzerLines).size, fuzzerLines.length);
  });

  it("supports ultra as an alias for the full suite", () => {
    const result = runLocalFuzz(["--dry-run", "--suite", "ultra", "--fuzztime", "1s"]);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /FuzzFilterModifyResponse/);
    assert.match(result.stdout, /FuzzHijackBidirectionalStream/);
  });

  it("keeps the Docker fuzzer runtime command in a single branch", () => {
    const source = readFileSync(scriptPath, "utf8");
    const [, body] = source.match(/run_docker_fuzzer\(\) \{([\s\S]*?)\n\}/) ?? [];

    assert.ok(body, "run_docker_fuzzer body not found");
    assert.equal(body.match(/docker run --rm/g)?.length, 1);
    assert.equal(body.match(/sh -lc "mkdir -p \/tmp\/sockguard-fuzz-cache/g)?.length, 1);
  });
});
