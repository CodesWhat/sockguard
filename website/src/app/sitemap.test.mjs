import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

// sitemap.ts imports through the "@/" alias, which node --test cannot resolve,
// so this reads the hardcoded slug literal out of the source. That is also the
// thing that actually drifts: the list silently lost "podman" and "roadmap"
// while both pages stayed live and linked.
const SITEMAP_PATH = fileURLToPath(new URL("./sitemap.ts", import.meta.url));
const META_PATH = fileURLToPath(new URL("../../../docs/content/docs/meta.json", import.meta.url));

function sitemapDocsSlugs() {
  const source = readFileSync(SITEMAP_PATH, "utf8");
  const block = source.match(/\.\.\.\[([\s\S]*?)\]\.map\(\(slug\)/u);
  assert.ok(block, "could not locate the docs slug list in sitemap.ts");
  return [...block[1].matchAll(/"([^"]+)"/gu)].map((match) => match[1]);
}

function metaDocsSlugs() {
  return JSON.parse(readFileSync(META_PATH, "utf8")).pages.filter((page) => page !== "index");
}

test("the sitemap's docs slugs match meta.json exactly", () => {
  assert.deepEqual(sitemapDocsSlugs(), metaDocsSlugs());
});

test("the sitemap lists every docs slug exactly once", () => {
  const slugs = sitemapDocsSlugs();
  assert.equal(new Set(slugs).size, slugs.length);
});
