import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { isDocsOnlyChange, isDocsOnlyPath, parsePaths } from "./docs-only-paths.mjs";

const SCRIPT_PATH = fileURLToPath(new URL("./docs-only-paths.mjs", import.meta.url));

// The literal string git prints for a filename containing a real newline
// byte: quoted, with the newline escaped as a backslash followed by "n" —
// two characters, not an actual line break.
const QUOTED_NEWLINE_PATH = '"docs/a\\nb.md"';

test("isDocsOnlyPath: true cases carried over from #466", () => {
  assert.equal(isDocsOnlyPath("LICENSE"), true);
  assert.equal(isDocsOnlyPath("docs/src/foo.tsx"), true);
  assert.equal(isDocsOnlyPath("app/internal/README.md"), true);
  assert.equal(isDocsOnlyPath("CHANGELOG.md"), true);
});

test("isDocsOnlyPath: the website's copied Fumadocs export counts", () => {
  assert.equal(isDocsOnlyPath("website/public/docs/x.html"), true);
});

test("isDocsOnlyPath: false cases carried over from #466", () => {
  assert.equal(isDocsOnlyPath("go.mod"), false);
  // A directory named docs under the Go module is code: Docker Build and
  // the fuzz matrix consume it, so it must never read as docs-only.
  assert.equal(isDocsOnlyPath("app/internal/docs/backdoor.go"), false);
  assert.equal(isDocsOnlyPath("scripts/docs/helper.mjs"), false);
  assert.equal(isDocsOnlyPath("docs"), false);
  assert.equal(isDocsOnlyPath("renovate.json"), false);
  assert.equal(isDocsOnlyPath("Dockerfile"), false);
  assert.equal(isDocsOnlyPath("app/internal/filter/rules.go"), false);
  assert.equal(isDocsOnlyPath(".github/workflows/ci-verify.yml"), false);
});

test("isDocsOnlyPath: the predicate script itself is not documentation", () => {
  assert.equal(isDocsOnlyPath("scripts/docs-only-paths.mjs"), false);
});

test("isDocsOnlyPath: a git-quoted path with an escaped newline is not documentation", () => {
  assert.equal(isDocsOnlyPath(QUOTED_NEWLINE_PATH), false);
});

test("isDocsOnlyChange: true only when every changed path is documentation", () => {
  assert.equal(isDocsOnlyChange(["LICENSE", "docs/src/foo.tsx"]), true);
  assert.equal(isDocsOnlyChange(["CHANGELOG.md", "app/internal/filter/rules.go"]), false);
});

test("isDocsOnlyChange: an empty change list fails open (not docs-only)", () => {
  assert.equal(isDocsOnlyChange([]), false);
});

test("parsePaths: splits on real newlines and drops the trailing blank line", () => {
  assert.deepEqual(parsePaths("a.md\nb.md\n"), ["a.md", "b.md"]);
  assert.deepEqual(parsePaths("a.md\nb.md"), ["a.md", "b.md"]);
  assert.deepEqual(parsePaths(""), []);
});

test("parsePaths: preserves paths with spaces intact", () => {
  assert.deepEqual(parsePaths("docs/a file.md\nCHANGELOG.md\n"), [
    "docs/a file.md",
    "CHANGELOG.md",
  ]);
});

test("parsePaths: does not split a git-quoted escaped newline into two lines", () => {
  assert.deepEqual(parsePaths(`${QUOTED_NEWLINE_PATH}\n`), [QUOTED_NEWLINE_PATH]);
});

test("CLI mode: prints docs_only=true for an all-documentation diff on stdin", () => {
  const out = execFileSync(process.execPath, [SCRIPT_PATH], {
    input: "LICENSE\ndocs/src/foo.tsx\nCHANGELOG.md\n",
    encoding: "utf8",
  });
  assert.equal(out.trim(), "docs_only=true");
});

test("CLI mode: prints docs_only=false when any changed path is code", () => {
  const out = execFileSync(process.execPath, [SCRIPT_PATH], {
    input: "CHANGELOG.md\napp/internal/filter/rules.go\n",
    encoding: "utf8",
  });
  assert.equal(out.trim(), "docs_only=false");
});

test("CLI mode: prints docs_only=false for a git-quoted escaped-newline path", () => {
  const out = execFileSync(process.execPath, [SCRIPT_PATH], {
    input: `${QUOTED_NEWLINE_PATH}\n`,
    encoding: "utf8",
  });
  assert.equal(out.trim(), "docs_only=false");
});

test("CLI mode: prints docs_only=false for empty stdin (fails open)", () => {
  const out = execFileSync(process.execPath, [SCRIPT_PATH], {
    input: "",
    encoding: "utf8",
  });
  assert.equal(out.trim(), "docs_only=false");
});
