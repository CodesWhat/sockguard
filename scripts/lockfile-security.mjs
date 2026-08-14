#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const ADVISORY = "GHSA-2v37-7h3g-55p8";
const NANOID_NODE = /(?:^|\/)node_modules\/nanoid$/;

function parseStableVersion(path, value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${path} is missing a version`);
  }

  const match = value.match(/^(\d+)\.(\d+)\.(\d+)$/);
  if (!match) {
    throw new Error(`${path} has malformed version ${JSON.stringify(value)}`);
  }

  return match.slice(1).map(Number);
}

function compareVersion(left, right) {
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) {
      return left[index] - right[index];
    }
  }
  return 0;
}

function isPatched(version) {
  const [major] = version;
  if (major < 3) return false;
  if (major === 3) return compareVersion(version, [3, 3, 18]) >= 0;
  if (major === 4) return false;
  if (major === 5) return compareVersion(version, [5, 1, 6]) >= 0;
  return true;
}

export function assertSafeNanoidVersions(lockfile) {
  if (lockfile === null || typeof lockfile !== "object" || Array.isArray(lockfile)) {
    throw new Error("package-lock root must be an object");
  }
  if (
    lockfile.packages === null ||
    typeof lockfile.packages !== "object" ||
    Array.isArray(lockfile.packages)
  ) {
    throw new Error("package-lock packages map is missing or malformed");
  }

  const nodes = Object.entries(lockfile.packages).filter(([path]) => NANOID_NODE.test(path));
  if (nodes.length === 0) {
    throw new Error("package-lock contains no resolved nanoid nodes");
  }

  for (const [path, metadata] of nodes) {
    if (metadata === null || typeof metadata !== "object" || Array.isArray(metadata)) {
      throw new Error(`${path} metadata is malformed`);
    }

    const version = parseStableVersion(path, metadata.version);
    if (!isPatched(version)) {
      throw new Error(
        `${ADVISORY}: ${path} resolves vulnerable version ${metadata.version}`,
      );
    }
  }

  return nodes.map(([path, metadata]) => ({ path, version: metadata.version }));
}

function validateFile(path) {
  const source = path === "-" ? readFileSync(0, "utf8") : readFileSync(resolve(path), "utf8");
  let lockfile;
  try {
    lockfile = JSON.parse(source);
  } catch (error) {
    throw new Error(`package-lock JSON is malformed: ${error.message}`);
  }

  const nodes = assertSafeNanoidVersions(lockfile);
  for (const node of nodes) {
    console.log(`safe nanoid lock node: ${node.path}@${node.version}`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length > 3) {
      throw new Error("usage: node scripts/lockfile-security.mjs [package-lock.json|-]");
    }
    validateFile(process.argv[2] ?? "package-lock.json");
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
