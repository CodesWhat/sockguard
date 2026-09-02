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

  it("lists every tested app/internal package exactly once", () => {
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

    for (const { name, package: pkg } of include) {
      assert.equal(pkg, `./internal/${name}`, `${name} has an unexpected package path`);
      const dir = resolve(repoRoot, "app", "internal", name);
      const files = readdirSync(dir).filter((f) => f.endsWith(".go"));
      assert.ok(
        files.some((f) => f.endsWith("_test.go")),
        `${name} is in the matrix but has no test file`,
      );
      assert.ok(
        files.some((f) => !f.endsWith("_test.go")),
        `${name} is in the matrix but has no source file`,
      );
    }

    // Fixture-only packages support other packages' tests; mutating them is noise.
    for (const name of ["testcert", "testhelp"]) {
      assert.ok(!names.includes(name), `${name} is a test fixture and must not be in the matrix`);
    }
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
