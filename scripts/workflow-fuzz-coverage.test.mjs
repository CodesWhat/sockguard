import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { describe, it } from "node:test";

const repoRoot = resolve(import.meta.dirname, "..");
const appRoot = resolve(repoRoot, "app");
const workflowPaths = [
  ".github/workflows/ci-verify.yml",
  ".github/workflows/quality-fuzz-nightly.yml",
  ".github/workflows/quality-fuzz-monthly.yml",
];

function walkGoFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = resolve(directory, entry.name);

    if (entry.isDirectory()) {
      return walkGoFiles(path);
    }

    return entry.isFile() && entry.name.endsWith(".go") ? [path] : [];
  });
}

function sourceFuzzers() {
  const fuzzers = new Map();

  for (const path of walkGoFiles(appRoot)) {
    const packagePath = `./${relative(appRoot, dirname(path))}/`;

    for (const match of readFileSync(path, "utf8").matchAll(/^func (Fuzz\w+)\(/gm)) {
      assert.ok(!fuzzers.has(match[1]), `duplicate fuzz function ${match[1]}`);
      fuzzers.set(match[1], packagePath);
    }
  }

  return fuzzers;
}

// Matches both the inline YAML fuzz matrix used by the nightly/monthly
// quality workflows (`- { name: Foo, pkg: ./bar/ }`) and the JSON
// fuzzers-json array the branch-CI reusable Go CI caller passes
// (`{"name":"Foo","pkg":"./bar/"}`).
const FUZZ_ENTRY_PATTERN =
  /(?:- \{ name: (Fuzz\w+),\s+pkg: ([^ }]+) \}|"name":"(Fuzz\w+)","pkg":"([^"]+)")/g;

function workflowFuzzers(workflowPath) {
  const source = readFileSync(resolve(repoRoot, workflowPath), "utf8");
  const fuzzers = new Map();

  for (const match of source.matchAll(FUZZ_ENTRY_PATTERN)) {
    const name = match[1] ?? match[3];
    const packagePath = match[2] ?? match[4];
    assert.ok(!fuzzers.has(name), `${workflowPath} repeats ${name}`);
    fuzzers.set(name, packagePath);
  }

  return fuzzers;
}

describe("fuzz workflow coverage", () => {
  const source = sourceFuzzers();
  const tiers = new Map(
    workflowPaths.map((workflowPath) => [workflowPath, workflowFuzzers(workflowPath)]),
  );

  it("registers only in-tree fuzz targets with their source package", () => {
    for (const [workflowPath, tier] of tiers) {
      for (const [name, packagePath] of tier) {
        assert.equal(
          source.get(name),
          packagePath,
          `${workflowPath} registers unknown or mis-mapped target ${name}`,
        );
      }
    }
  });

  it("schedules every in-tree fuzz target in at least one tier", () => {
    const uncovered = [];

    for (const [name, packagePath] of source) {
      const scheduledPackages = [...tiers.values()]
        .filter((tier) => tier.has(name))
        .map((tier) => tier.get(name));

      if (scheduledPackages.length === 0) {
        uncovered.push(name);
        continue;
      }

      assert.deepEqual(
        [...new Set(scheduledPackages)],
        [packagePath],
        `${name} must use its source package ${packagePath}`,
      );
    }

    assert.deepEqual(
      uncovered.sort(),
      [],
      `uncovered fuzz targets: ${uncovered.sort().join(", ")}`,
    );
  });

  it("keeps every nightly Docker filter target in the monthly deep tier", () => {
    const nightly = tiers.get(".github/workflows/quality-fuzz-nightly.yml");
    const monthly = tiers.get(".github/workflows/quality-fuzz-monthly.yml");
    const missing = [...nightly]
      .filter(([, packagePath]) => packagePath === "./internal/filter/")
      .map(([name]) => name)
      .filter((name) => !monthly.has(name))
      .sort();

    assert.deepEqual(
      missing,
      [],
      `monthly fuzz is missing nightly Docker filter targets: ${missing.join(", ")}`,
    );
  });
});
