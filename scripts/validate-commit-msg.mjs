#!/usr/bin/env node

/**
 * Validates commit messages follow Conventional Commits format.
 * Format: <type>(<scope>): <description>
 *
 * Usage: node scripts/validate-commit-msg.mjs <commit-msg-file>
 */

import { readFileSync } from "node:fs";

const msgFile = process.argv[2];
if (!msgFile) {
  console.error("Usage: validate-commit-msg.mjs <commit-msg-file>");
  process.exit(1);
}

const ALLOWED_TYPES = [
  "feat",
  "fix",
  "docs",
  "style",
  "refactor",
  "perf",
  "test",
  "build",
  "ci",
  "chore",
  "revert",
];

const raw = readFileSync(msgFile, "utf8").trim();
const lines = raw.split("\n");
const msg = lines[0];

// Git-generated subjects are exempt: merge commits, `Revert "..."` commits,
// and fixup!/squash! autosquash commits. Hand-written subjects that merely
// start with "Revert " still validate (use the `revert` type for those).
const isMerge = /^Merge /.test(msg);
const isRevert = /^Revert ".+"$/.test(msg);
const isAutosquash = /^(fixup|squash)! /.test(msg);

if (isMerge || isRevert || isAutosquash) {
  process.exit(0);
}

// Match: type(optional-scope)!: description
const typePattern = `(?:${ALLOWED_TYPES.join("|")})`;
const pattern = new RegExp(`^${typePattern}(\\([\\w-]+\\))?!?: .+$`);

if (!pattern.test(msg)) {
  console.error("");
  console.error("AI_ACTION_REQUIRED: Commit message does not follow convention.");
  console.error("");
  console.error("Expected: <type>(<scope>): <description>");
  console.error(`Got:      ${msg}`);
  console.error("");
  console.error(`Allowed types: ${ALLOWED_TYPES.join(", ")}`);
  console.error("");
  console.error('Use "!" before the colon for breaking changes: feat(api)!: drop v1 tokens');
  console.error('Or add a "BREAKING CHANGE:" footer.');
  console.error("");
  console.error("Examples:");
  console.error("  feat(filter): add request body inspection");
  console.error("  fix: resolve socket EACCES (#38)");
  console.error("  refactor(proxy): simplify middleware chain");
  console.error("");
  console.error("No emoji — plain Conventional Commits only.");
  console.error("");
  process.exit(1);
}
