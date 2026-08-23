import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { findConflictMarkers, scanTrackedFiles } from "./check-conflict-markers.mjs";

// Markers are built programmatically so this test file contains no literal
// seven-character marker at the start of a line — otherwise the live-tree
// scan below would flag this very file.
const marker = (ch) => ch.repeat(7);
const OURS = marker("<");
const BASE = marker("|");
const THEIRS = marker(">");
const SEP = marker("=");

test("detects the three unambiguous conflict markers, bare and labelled", () => {
  assert.deepEqual(
    findConflictMarkers([`${OURS} HEAD`, "a"].join("\n")).map((h) => h.line),
    [1],
  );
  assert.equal(findConflictMarkers([`x`, `${BASE} merged common ancestors`].join("\n")).length, 1);
  assert.equal(findConflictMarkers([`${THEIRS} feature-branch`].join("\n")).length, 1);
  assert.equal(findConflictMarkers(OURS).length, 1); // bare, no label
});

test("catches the real-world stray diff3 base marker (the CHANGELOG defect)", () => {
  const changelog = [
    "### Changed",
    "",
    "- something",
    `${BASE} parent of 34b344e (a commit subject)`,
    "",
    "### Added",
  ].join("\n");
  const hits = findConflictMarkers(changelog);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].line, 4);
});

test("does not flag a markdown setext heading underline of seven equals", () => {
  assert.deepEqual(findConflictMarkers(["Heading", SEP, ""].join("\n")), []);
});

test("does not flag near-misses: wrong length or not at line start", () => {
  assert.deepEqual(findConflictMarkers("<".repeat(6)), []); // six, not seven
  assert.deepEqual(findConflictMarkers("<".repeat(8)), []); // eight, not seven
  assert.deepEqual(findConflictMarkers(`code ${OURS} inline`), []); // not at column 0
  assert.deepEqual(findConflictMarkers(`${OURS}x`), []); // seven then non-space
});

test("skips tracked symbolic links instead of reading through them", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sockguard-conflict-"));
  // Under a git hook, GIT_DIR/GIT_INDEX_FILE point at the outer repo and
  // would make these git calls mutate its index despite cwd — scrub them.
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([k]) => !k.startsWith("GIT_")),
  );
  try {
    execFileSync("git", ["init", "-q"], { cwd: dir, env });
    // The link's target is untracked and contains a marker; unfixed code
    // follows the link, reads the marker, and reports a finding for "link".
    writeFileSync(path.join(dir, "target.txt"), `${OURS} ours\n`);
    symlinkSync("target.txt", path.join(dir, "link"));
    execFileSync("git", ["add", "link"], { cwd: dir, env });
    assert.deepEqual(scanTrackedFiles(dir), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the tracked tree contains no unresolved conflict markers", () => {
  const findings = scanTrackedFiles();
  assert.deepEqual(
    findings,
    [],
    `conflict markers present in tracked files:\n${findings
      .map((f) => `  ${f.file}:${f.line}: ${f.text}`)
      .join("\n")}`,
  );
});
