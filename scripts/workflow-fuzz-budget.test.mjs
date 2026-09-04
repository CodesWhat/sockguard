import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, it } from "node:test";

const repoRoot = resolve(import.meta.dirname, "..");

const workflowPaths = [
  ".github/workflows/quality-fuzz-nightly.yml",
  ".github/workflows/quality-fuzz-monthly.yml",
];

function resolveBudgetRunBlock(source) {
  const start = source.indexOf("      - name: Resolve fuzz budget");
  assert.notEqual(start, -1, "Resolve fuzz budget step not found");

  const runStart = source.indexOf("        run: |", start);
  assert.notEqual(runStart, -1, "Resolve fuzz budget run block not found");

  const nextStep = source.indexOf("\n      - name:", runStart + 1);
  assert.notEqual(nextStep, -1, "next workflow step not found");

  return source.slice(runStart, nextStep);
}

describe("quality fuzz workflows", () => {
  for (const workflowPath of workflowPaths) {
    it(`${workflowPath} writes outputs only after fuzz budget validation succeeds`, () => {
      const source = readFileSync(resolve(repoRoot, workflowPath), "utf8");
      const lines = resolveBudgetRunBlock(source).split("\n");

      const timeoutLineIndex = lines.findIndex((line) =>
        // biome-ignore lint/suspicious/noTemplateCurlyInString: literal bash from the workflow's own `run:` block, matched as text; no FUZZTIME binding exists here
        line.includes('fuzz_timeout_for_budget "${FUZZTIME}" 600'),
      );
      const firstOutputLineIndex = lines.findIndex((line) => line.includes('>> "$GITHUB_OUTPUT"'));

      assert.notEqual(timeoutLineIndex, -1, "fuzz_timeout_for_budget line not found");
      assert.notEqual(firstOutputLineIndex, -1, "GITHUB_OUTPUT write not found");
      assert.ok(
        firstOutputLineIndex > timeoutLineIndex,
        "GITHUB_OUTPUT writes must come after fuzz_timeout_for_budget",
      );
      assert.match(
        lines[timeoutLineIndex],
        /\|\| exit 1/,
        "fuzz_timeout_for_budget must be guarded before writing GITHUB_OUTPUT",
      );
    });
  }

  it("caps the nightly matrix so it fits the Free plan's concurrent-job ceiling", () => {
    // 20 concurrent jobs org-wide, and portwing's Deep Fuzz shares this
    // workflow's `30 9 * * *` minute with 7 jobs of its own. Anything admitted
    // over the ceiling is starved and then reclaimed with exit 143, which
    // reads as a fuzz failure but produces no crasher. See the comment on
    // max-parallel in the workflow.
    const source = readFileSync(
      resolve(repoRoot, ".github/workflows/quality-fuzz-nightly.yml"),
      "utf8",
    );

    const cap = source.match(/^ {6}max-parallel: (\d+)$/m);
    assert.ok(cap, "quality-fuzz-nightly.yml must set max-parallel on the fuzz matrix");
    assert.ok(
      Number(cap[1]) <= 13,
      `max-parallel must leave room for portwing's 7 jobs under the 20-job ceiling, got ${cap[1]}`,
    );

    const targets = source.match(/^ {10}- \{ name: Fuzz/gm) ?? [];
    assert.ok(
      targets.length > Number(cap[1]),
      "the cap only matters while the matrix is wider than it; drop this test if that stops being true",
    );
  });
});
