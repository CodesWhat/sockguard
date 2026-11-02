import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildIndex, outFile, render } from "../../scripts/docs-search-index.mjs";

test("docs search index is in sync with docs/content", () => {
  assert.equal(
    readFileSync(outFile, "utf8"),
    render(buildIndex()),
    "run: node scripts/docs-search-index.mjs",
  );
});

test("docs search index covers pages and headings", () => {
  const { pages, items } = buildIndex();
  assert.equal(pages[0][1], "/docs");
  assert.ok(pages.some(([, url]) => url === "/docs/getting-started"));
  assert.ok(
    items.some(
      ([, heading, anchor]) =>
        heading === "Docker Compose (recommended)" && anchor === "docker-compose-recommended",
    ),
  );
  assert.ok(items.every(([page]) => page >= 0 && page < pages.length));
});
