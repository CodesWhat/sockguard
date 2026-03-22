#!/usr/bin/env node

/**
 * Validates commit messages follow Gitmoji + Conventional Commits format.
 * Format: <emoji> <type>(<scope>): <description>
 *
 * Usage: node scripts/validate-commit-msg.mjs <commit-msg-file>
 */

import { readFileSync } from "node:fs";

const msgFile = process.argv[2];
if (!msgFile) {
  console.error("Usage: validate-commit-msg.mjs <commit-msg-file>");
  process.exit(1);
}

const msg = readFileSync(msgFile, "utf8").trim().split("\n")[0];

// Match: emoji + space + type(optional-scope): description
const pattern =
  /^[\p{Emoji_Presentation}\p{Extended_Pictographic}]+ \w+(\(\w[\w-]*\))?!?: .+$/u;

if (!pattern.test(msg)) {
  console.error("");
  console.error("AI_ACTION_REQUIRED: Commit message does not follow convention.");
  console.error("");
  console.error("Expected: <emoji> <type>(<scope>): <description>");
  console.error(`Got:      ${msg}`);
  console.error("");
  console.error("Examples:");
  console.error('  \u2728 feat(filter): add request body inspection');
  console.error('  \uD83D\uDC1B fix: resolve socket EACCES (#38)');
  console.error('  \u267B\uFE0F refactor(proxy): simplify middleware chain');
  console.error("");
  process.exit(1);
}
