// Fails when any tracked text file contains an unresolved git conflict marker.
//
// This exists because a stray `|||||||` diff3 base marker once merged into
// CHANGELOG.md and shipped undetected: conflict markers are valid text, so no
// linter flagged it. The three markers checked here (`<<<<<<<`, `|||||||`,
// `>>>>>>>`) have no legitimate use at the start of a line, so matching them is
// unambiguous. `=======` is deliberately excluded: a markdown setext H1
// underline can be exactly seven `=`, and every real conflict already carries
// the surrounding `<<<<<<<`/`>>>>>>>` this catches.

import { execFileSync } from "node:child_process";
import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

// A conflict marker line is seven or more of the marker character, optionally
// followed by a space and a label (branch name, "merged common ancestors").
// Seven is the usual length, but git lengthens the run when a nested or
// criss-cross merge conflicts inside an already-conflicted region, so a
// fixed-length match silently misses the nine-character markers those emit.
const MARKER_RE = /^(?:<{7,}|\|{7,}|>{7,})(?: .*)?$/;

export function findConflictMarkers(text) {
  const hits = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    if (MARKER_RE.test(lines[i])) {
      hits.push({ line: i + 1, text: lines[i] });
    }
  }
  return hits;
}

// Repo-location env vars (set by git when running hooks) would override cwd
// and point ls-files at a different repo; drop them so cwd is authoritative.
const GIT_LOCATION_VARS = [
  "GIT_DIR",
  "GIT_WORK_TREE",
  "GIT_INDEX_FILE",
  "GIT_COMMON_DIR",
  "GIT_PREFIX",
];

export function listTrackedFiles(cwd = process.cwd()) {
  const env = { ...process.env };
  for (const name of GIT_LOCATION_VARS) delete env[name];
  const out = execFileSync("git", ["ls-files", "-z"], {
    cwd,
    env,
    maxBuffer: 64 * 1024 * 1024,
  });
  return out.toString("utf8").split("\0").filter(Boolean);
}

// Git's own heuristic: a NUL byte in the first 8000 bytes means binary.
function isProbablyBinary(buf) {
  const n = Math.min(buf.length, 8000);
  for (let i = 0; i < n; i += 1) {
    if (buf[i] === 0) return true;
  }
  return false;
}

export function scanTrackedFiles(cwd = process.cwd()) {
  const findings = [];
  for (const file of listTrackedFiles(cwd)) {
    let buf;
    try {
      // O_NOFOLLOW rejects a tracked symlink at open (following one could
      // read an unbounded target like /dev/zero), and fstat on the fd we
      // read from can't race a swap of the path between check and read.
      const fd = openSync(path.join(cwd, file), constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        if (!fstatSync(fd).isFile()) continue;
        buf = readFileSync(fd);
      } finally {
        closeSync(fd);
      }
    } catch {
      continue; // deleted-but-tracked, a symlink, or unreadable; not our concern
    }
    if (isProbablyBinary(buf)) continue;
    for (const hit of findConflictMarkers(buf.toString("utf8"))) {
      findings.push({ file, ...hit });
    }
  }
  return findings;
}

function main() {
  const findings = scanTrackedFiles();
  if (findings.length === 0) {
    return;
  }
  console.error("Unresolved git conflict markers found:");
  for (const f of findings) {
    console.error(`  ${f.file}:${f.line}: ${f.text}`);
  }
  process.exit(1);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
