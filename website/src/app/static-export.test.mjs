import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

// Source-side checks of the static export: canonical URLs, sitemap coverage,
// robots policy, vercel.json headers and the hero install CTA. The export
// checks need `npm run build` (and build:docs-content for the docs pages)
// first; without out/ they skip, and the vercel.json checks still run.
const SITE = "https://www.getsockguard.com";
const OUT = fileURLToPath(new URL("../../out/", import.meta.url));
const VERCEL_JSON = fileURLToPath(new URL("../../vercel.json", import.meta.url));
const HAS_EXPORT = existsSync(join(OUT, "index.html"));
const skip = HAS_EXPORT ? false : "static export missing, run npm run build first";

// Error pages are noindex fallbacks, never canonical content.
const ERROR_PAGES = new Set([
  "404.html",
  "_not-found.html",
  "docs/404.html",
  "docs/_not-found.html",
]);

function htmlFiles(dir = OUT) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return entry.name === "_next" ? [] : htmlFiles(path);
    return entry.name.endsWith(".html") ? [path] : [];
  });
}

function contentPages() {
  return htmlFiles()
    .map((file) => ({ file, rel: relative(OUT, file) }))
    .filter(({ rel }) => !ERROR_PAGES.has(rel));
}

function canonicalOf(html) {
  const tags = [...html.matchAll(/<link\b[^>]*>/gu)].map((m) => m[0]);
  const found = tags.filter((tag) => /\brel="canonical"/u.test(tag));
  assert.equal(found.length, 1, "expected exactly one canonical link");
  return found[0].match(/\bhref="([^"]+)"/u)?.[1];
}

function expectedCanonical(rel) {
  const path = rel.replace(/\.html$/u, "").replace(/(^|\/)index$/u, "");
  return path ? `${SITE}/${path}` : SITE;
}

function sitemapUrls() {
  const xml = readFileSync(join(OUT, "sitemap.xml"), "utf8");
  return [...xml.matchAll(/<loc>([^<]+)<\/loc>/gu)].map((m) => m[1]);
}

test("every exported page has exactly one canonical URL matching its own path", { skip }, () => {
  const pages = contentPages();
  assert.ok(pages.length >= 20, `expected a full export, found ${pages.length} pages`);
  for (const { file, rel } of pages) {
    assert.equal(canonicalOf(readFileSync(file, "utf8")), expectedCanonical(rel), rel);
  }
});

test("error pages are noindex", { skip }, () => {
  for (const rel of ERROR_PAGES) {
    const file = join(OUT, rel);
    if (!existsSync(file)) continue;
    assert.match(readFileSync(file, "utf8"), /<meta name="robots" content="noindex/u, rel);
  }
});

test("sitemap.xml covers every exported page and only canonical URLs", { skip }, () => {
  const urls = sitemapUrls();
  assert.equal(new Set(urls).size, urls.length, "duplicate sitemap entries");
  const canonicals = contentPages().map(({ file }) => canonicalOf(readFileSync(file, "utf8")));
  assert.deepEqual([...urls].sort(), [...canonicals].sort());
  for (const url of urls) {
    assert.ok(url === SITE || url.startsWith(`${SITE}/`), `${url} is not on the canonical host`);
    assert.ok(!url.endsWith("/") && !/[?#]/u.test(url), `${url} is not a canonical form`);
  }
});

test("robots.txt allows crawlers, blocks only /api/ and /_next/, and names the sitemap", {
  skip,
}, () => {
  const lines = readFileSync(join(OUT, "robots.txt"), "utf8")
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
  assert.deepEqual(lines, [
    "User-Agent: *",
    "Allow: /",
    "Disallow: /api/",
    "Disallow: /_next/",
    `Sitemap: ${SITE}/sitemap.xml`,
  ]);
});

test("the landing hero carries the install CTA and its target exists", { skip }, () => {
  const html = readFileSync(join(OUT, "index.html"), "utf8");
  const hero = html.match(/<section[^>]*id="hero"[\s\S]*?<\/section>/u)?.[0];
  assert.ok(hero, "hero section missing");
  const cta = hero.match(/<a[^>]*class="btn primary"[^>]*href="#get-started"[^>]*>[\s\S]*?<\/a>/u);
  assert.ok(cta, "hero primary CTA must link to #get-started");
  assert.match(cta[0], /Get started/u);
  assert.match(html, /id="get-started"/u, "the CTA target section is missing");
  const target = html.slice(html.indexOf('id="get-started"'));
  assert.match(target, /docker/iu, "the get-started section must show an install command");
});

test("vercel.json sets the security headers on every route", () => {
  const rules = JSON.parse(readFileSync(VERCEL_JSON, "utf8")).headers;
  const all = rules.find((rule) => rule.source === "/(.*)");
  assert.ok(all, "missing catch-all header rule");
  const headers = new Map(all.headers.map((h) => [h.key, h.value]));
  for (const key of [
    "Content-Security-Policy",
    "Permissions-Policy",
    "Referrer-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
  ]) {
    assert.ok(headers.get(key), `${key} missing`);
  }
  assert.equal(headers.get("X-Content-Type-Options"), "nosniff");
  assert.equal(headers.get("X-Frame-Options"), "DENY");
  assert.match(headers.get("Strict-Transport-Security"), /max-age=(\d{8,})/u);
});

test("the CSP is default-deny with no wildcard or eval sources", () => {
  const rules = JSON.parse(readFileSync(VERCEL_JSON, "utf8")).headers;
  const csp = rules
    .flatMap((r) => r.headers)
    .find((h) => h.key === "Content-Security-Policy").value;
  const directives = new Map(
    csp.split(";").map((d) => {
      const [name, ...values] = d.trim().split(/\s+/u);
      return [name, values];
    }),
  );
  assert.deepEqual(directives.get("default-src"), ["'self'"]);
  assert.deepEqual(directives.get("object-src"), ["'none'"]);
  assert.deepEqual(directives.get("frame-ancestors"), ["'none'"]);
  assert.deepEqual(directives.get("base-uri"), ["'self'"]);
  assert.ok(directives.has("upgrade-insecure-requests"));
  for (const [name, values] of directives) {
    assert.ok(!values.includes("*"), `${name} allows a bare wildcard`);
    assert.ok(!values.includes("'unsafe-eval'"), `${name} allows unsafe-eval`);
    for (const value of values) assert.ok(!value.startsWith("http:"), `${name} allows ${value}`);
  }
});
