#!/usr/bin/env node
import { readFileSync } from "node:fs";
import {
  extractSecurityFirstSupportedVersion,
  normalizeTag,
} from "./verify-tag-release-metadata.mjs";

export function verifyMaintenanceLine(tag, security) {
  const [major, minor] = normalizeTag(tag).split(".").map(Number);
  const line = `${major}.${minor}.x`;
  const latest = extractSecurityFirstSupportedVersion(security);
  const latestParts = latest.version.match(/^(\d+)\.(\d+)\.x$/u);
  if (!latestParts || !latest.supported) {
    throw new Error("Default-branch SECURITY.md must lead with a supported release line.");
  }
  const [, latestMajor, latestMinor] = latestParts.map(Number);
  if (major > latestMajor || (major === latestMajor && minor >= latestMinor)) {
    throw new Error(
      `Maintenance ${line} must be older than the default branch's ${latest.version}.`,
    );
  }
  const rows = security.split("\n").map((row) =>
    row
      .trim()
      .split("|")
      .slice(1, -1)
      .map((cell) => cell.trim()),
  );
  const matching = rows.filter((row) => row[0]?.replace(/\s*\(.*\)\s*$/u, "") === line);
  if (matching.length !== 1 || matching[0][1] !== ":white_check_mark:") {
    throw new Error(`Default-branch SECURITY.md does not support maintenance ${line}.`);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    verifyMaintenanceLine(process.argv[2], readFileSync(0, "utf8"));
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
