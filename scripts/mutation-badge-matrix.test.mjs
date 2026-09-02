import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, it } from "node:test";

const repoRoot = resolve(import.meta.dirname, "..");
const workflowPath = ".github/workflows/quality-mutation-monthly.yml";

describe("quality mutation workflow", () => {
  it("derives the matrix and the expected report count from one discover step", () => {
    const source = readFileSync(resolve(repoRoot, workflowPath), "utf8");

    // The matrix and the badge's expected-report count both come from the
    // discover job. If either side is hardcoded again they can drift, and
    // the badge either never publishes or publishes a partial score.
    assert.match(
      source,
      /^\s+matrix: \$\{\{ fromJSON\(needs\.discover\.outputs\.matrix\) \}\}$/mu,
      "gremlins matrix is not read from the discover job",
    );
    assert.match(
      source,
      /^\s+EXPECTED_REPORTS: \$\{\{ needs\.discover\.outputs\.count \}\}$/mu,
      "expected report count is not read from the discover job",
    );
    assert.match(
      source,
      /^\s+expected_reports=\$\{EXPECTED_REPORTS\}$/mu,
      "expected_reports is not assigned from EXPECTED_REPORTS",
    );
    assert.match(
      source,
      /bash scripts\/ci\/mutation-matrix\.sh/u,
      "discover job does not run scripts/ci/mutation-matrix.sh",
    );
  });

  it("lists every tested app/internal package at any depth exactly once", () => {
    const out = execFileSync("bash", [resolve(repoRoot, "scripts/ci/mutation-matrix.sh")], {
      encoding: "utf8",
    });
    const parsed = JSON.parse(out);

    // fromJSON() feeds this straight into strategy.matrix, where any key
    // other than include/exclude is read as a matrix dimension. A stray
    // scalar key made the whole gremlins job fail to expand once already.
    assert.deepEqual(
      Object.keys(parsed),
      ["include"],
      "matrix JSON must carry only an include key",
    );
    const { include } = parsed;
    assert.ok(include.length > 0, "matrix is empty");
    const names = include.map((entry) => entry.name);
    assert.equal(new Set(names).size, names.length, "a package is listed twice");

    // The six packages the badge has always covered can never fall out.
    for (const name of ["filter", "proxy", "config", "httpjson", "logging", "cmd"]) {
      assert.ok(names.includes(name), `${name} missing from the mutation matrix`);
    }

    // Independent derivation of the eligible set: every directory under
    // app/internal, at any depth, with a source file and a test file,
    // skipping testdata trees and the two test-fixture packages.
    const fixtures = new Set(["testcert", "testhelp"]);
    const eligible = [];
    const walk = (rel) => {
      const dir = resolve(repoRoot, "app", "internal", rel);
      const entries = readdirSync(dir, { withFileTypes: true });
      const files = entries.filter((e) => e.isFile() && e.name.endsWith(".go")).map((e) => e.name);
      if (
        rel !== "" &&
        !fixtures.has(rel) &&
        files.some((f) => f.endsWith("_test.go")) &&
        files.some((f) => !f.endsWith("_test.go"))
      ) {
        eligible.push(rel);
      }
      for (const e of entries) {
        if (!e.isDirectory() || e.name === "testdata") continue;
        walk(rel === "" ? e.name : `${rel}/${e.name}`);
      }
    };
    walk("");

    assert.equal(
      include.length,
      eligible.length,
      "matrix entry count differs from the eligible set",
    );
    const packages = include.map((entry) => entry.package);
    assert.equal(new Set(packages).size, packages.length, "a package path is listed twice");

    const byPackage = new Map(include.map((entry) => [entry.package, entry.name]));
    assert.deepEqual(
      [...byPackage.keys()].sort(),
      eligible.map((rel) => `./app/internal/${rel}`).sort(),
      "matrix packages differ from the recursively derived eligible set",
    );
    for (const rel of eligible) {
      assert.equal(
        byPackage.get(`./app/internal/${rel}`),
        rel.replaceAll("/", "-"),
        `${rel} has an unexpected matrix name`,
      );
    }
  });

  it("keeps the write credential out of every job a branch run can reach", () => {
    const source = readFileSync(resolve(repoRoot, workflowPath), "utf8");
    const jobsStart = source.indexOf("\njobs:\n");
    assert.notEqual(jobsStart, -1, "jobs: block not found");
    const jobsSource = source.slice(jobsStart);

    // A job header is a two-space-indented key under `jobs:` (`  discover:`,
    // `  update-badge:`, ...). Slicing the file into job bodies this way,
    // rather than searching the whole file, means a marker string anywhere
    // outside `update-badge` -- including in a comment or in another job's
    // `on:`-block lookalike -- is caught instead of only checked by position.
    const headerRe = /^ {2}([a-z-]+):$/gmu;
    const headers = [...jobsSource.matchAll(headerRe)];
    assert.ok(headers.length > 0, "no job headers found under jobs:");
    assert.ok(
      headers.some((m) => m[1] === "update-badge"),
      "update-badge job not found",
    );

    const sections = headers.map((m, i) => {
      const end = i + 1 < headers.length ? headers[i + 1].index : jobsSource.length;
      return { name: m[1], body: jobsSource.slice(m.index, end) };
    });

    // `mutation/*` branch pushes run this file as authored on the branch.
    // Only the badge job may hold contents: write or a persisted
    // credential, and it must be gated off non-default branches at job
    // level so it is never scheduled for such a run.
    for (const { name, body } of sections) {
      for (const marker of ["contents: write", "persist-credentials: true"]) {
        const present = body.includes(marker);
        if (name === "update-badge") {
          assert.ok(present, `update-badge section is missing ${marker}`);
        } else {
          assert.ok(!present, `${marker} found in the ${name} job, not just update-badge`);
        }
      }
    }

    const badgeSection = sections.find((s) => s.name === "update-badge").body;
    const jobIf = badgeSection.match(/^\s{4}if: (.+)$/mu);
    assert.ok(jobIf, "update-badge has no job-level if");
    assert.match(
      jobIf[1],
      /github\.event\.repository\.default_branch/u,
      "update-badge is not gated to the default branch",
    );
    assert.match(
      jobIf[1],
      /github\.ref\s*==\s*format\('refs\/heads\/\{0\}',\s*github\.event\.repository\.default_branch\)/u,
      "update-badge if does not compare github.ref against the default branch",
    );
  });

  it("reports the parsed count when the report set is incomplete", () => {
    const source = readFileSync(resolve(repoRoot, workflowPath), "utf8");
    const incompleteStart = source.indexOf(
      '          if [ "$reports_found" -ne "$expected_reports" ]; then',
    );
    assert.notEqual(incompleteStart, -1, "incomplete-report branch not found");
    const incompleteEnd = source.indexOf("          fi", incompleteStart);
    assert.notEqual(incompleteEnd, -1, "end of incomplete-report branch not found");
    const incompleteBranch = source.slice(incompleteStart, incompleteEnd);
    const exitIndex = incompleteBranch.indexOf("            exit 0");
    assert.notEqual(exitIndex, -1, "incomplete-report exit not found");

    for (const output of ["reports_found", "expected_reports"]) {
      const exportIndex = incompleteBranch.indexOf(
        `            echo "${output}=\${${output}}" >> "$GITHUB_OUTPUT"`,
      );
      assert.ok(
        exportIndex !== -1 && exportIndex < exitIndex,
        `${output} is not exported before the incomplete-report exit`,
      );
    }

    const summaryStart = source.indexOf("      - name: Summary\n");
    assert.notEqual(summaryStart, -1, "mutation summary step not found");
    const summary = source.slice(summaryStart);
    assert.match(
      summary,
      /EXPECTED_REPORTS: \$\{\{ steps\.score\.outputs\.expected_reports \}\}/u,
      "summary does not consume expected_reports",
    );
    assert.match(
      summary,
      /Incomplete report set: \$\{REPORTS_FOUND\} of \$\{EXPECTED_REPORTS\}; badge left unchanged\./u,
      "summary does not distinguish an incomplete report set from an empty one",
    );
  });
});
