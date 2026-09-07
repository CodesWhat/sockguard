#!/usr/bin/env node
//
// The docs-only predicate for ci-verify.yml's "Changed Paths" gate job.
//
// Extracted from the inline `docs='^(docs/.*|LICENSE|.*\.mdx?)$'` regex that
// job used to grep the changed-file list against (CI-7, #466), plus one
// addition: a nested `docs/` directory anywhere in the path also counts, so
// website/public/docs/ — where website/package.json's build:docs-content
// script copies the Fumadocs static export before it ships under
// getsockguard.com/docs — reads as documentation the same way the top-level
// docs/ workspace does. That directory is gitignored (generated at build
// time), so it never actually appears in a PR diff today; the rule exists so
// the predicate does not have to change if that ever stops being true.
//
// A single garbled or unusual path (e.g. one `git diff --name-only` prints
// quoted because it contains a literal newline) is deliberately NOT
// documentation: isDocsOnlyPath only recognizes a clean path, so anything
// git had to escape falls through to `false` and the full CI matrix runs.

import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export function isDocsOnlyPath(path) {
  if (path === "LICENSE") return true;
  if (/\.mdx?$/.test(path)) return true;

  // Any directory component named exactly "docs" — not just a top-level
  // docs/ — counts. The path's own final segment (the filename) is excluded
  // so a file merely named "docs" or "docs-something.ext" doesn't count.
  const segments = path.split("/");
  segments.pop();
  return segments.includes("docs");
}

// paths.length === 0 (no changed files at all) is deliberately NOT
// docs-only: an empty diff means something upstream failed to produce a
// real file list, and the gate must fail open — same reasoning as the
// workflow's own empty-diff check before this predicate ever runs.
export function isDocsOnlyChange(paths) {
  return paths.length > 0 && paths.every((path) => isDocsOnlyPath(path));
}

// Splits on '\n' only — never on a literal "\n" (backslash-n) two-character
// sequence. `git diff --name-only` prints an unusual filename quoted with
// escapes, so a path containing a real newline byte comes back as one line
// like `"docs/a\nb.md"` (a literal backslash and "n", not a newline). If a
// naive parser unescaped that into two lines, both would look like clean
// docs paths and the predicate would wrongly report docs_only=true.
// Leaving it as one un-decoded line falls through to `false` above instead.
export function parsePaths(text) {
  if (text === "") return [];
  const lines = text.split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  return lines;
}

function main() {
  const stdin = readFileSync(0, "utf8");
  const paths = parsePaths(stdin);
  console.log(`docs_only=${isDocsOnlyChange(paths)}`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main();
}
