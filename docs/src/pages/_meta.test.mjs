import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import meta from "./_meta.ts";

const pagesDir = path.dirname(fileURLToPath(import.meta.url));

test("_meta matches the top-level docs pages", () => {
  const pageSlugs = readdirSync(pagesDir)
    .filter((name) => name.endsWith(".mdx"))
    .map((name) => name.replace(/\.mdx$/, ""))
    .sort();

  assert.deepEqual(Object.keys(meta).sort(), pageSlugs);
});

test("_meta titles are non-empty strings", () => {
  for (const [slug, title] of Object.entries(meta)) {
    assert.equal(typeof title, "string", `${slug} should map to a string title`);
    assert.notEqual(title.trim(), "", `${slug} should not have an empty title`);
  }
});
