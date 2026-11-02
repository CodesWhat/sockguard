import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";

const repoRoot = resolve(import.meta.dirname, "..");
const heroPath = resolve(repoRoot, "website/src/components/hero.tsx");

test("website quality badges do not expose Go Report Card", () => {
  const source = readFileSync(heroPath, "utf8");

  const qualityLabels = [...source.matchAll(/alt: "([^"]+)"/gu)].map((match) => match[1]);
  assert.deepEqual(qualityLabels, [
    "License MIT",
    "CI",
    "OpenSSF Scorecard",
    "OpenSSF Best Practices",
    "Maintainability",
    "Coverage",
    "Mutation score",
  ]);
  assert.doesNotMatch(source, /goreportcard|go report card/iu);
  // Go Reference is a footer text link now; no badge image may load from pkg.go.dev.
  assert.doesNotMatch(source, /src: [`"]https:\/\/pkg\.go\.dev/u);
});
