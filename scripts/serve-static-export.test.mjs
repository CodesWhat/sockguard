import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, before, describe, it } from "node:test";
import {
  compileSource,
  createHandler,
  headersForPath,
  loadHeaderRules,
  resolveRoute,
} from "./ci/serve-static-export.mjs";

const vercelConfig = JSON.parse(
  readFileSync(resolve(import.meta.dirname, "..", "website", "vercel.json"), "utf8"),
);

describe("compileSource", () => {
  it("matches the catch-all and literal sources", () => {
    assert.ok(compileSource("/(.*)").test("/"));
    assert.ok(compileSource("/(.*)").test("/docs/configuration"));
    assert.ok(compileSource("/.well-known/security.txt").test("/.well-known/security.txt"));
    assert.ok(!compileSource("/.well-known/security.txt").test("/xwell-known/security.txt"));
    assert.ok(!compileSource("/.well-known/security.txt").test("/.well-known/security.txt/x"));
  });

  it("handles named segments", () => {
    assert.ok(compileSource("/blog/:slug").test("/blog/a"));
    assert.ok(!compileSource("/blog/:slug").test("/blog/a/b"));
    assert.ok(compileSource("/blog/:path*").test("/blog/a/b"));
    assert.ok(compileSource("/blog/:path*").test("/blog/"));
    assert.ok(!compileSource("/blog/:path+").test("/blog/"));
  });
});

describe("headersForPath", () => {
  const rules = loadHeaderRules(vercelConfig);
  const names = (path) => headersForPath(rules, path).map(([k]) => k.toLowerCase());

  it("applies vercel.json catch-all headers to every route", () => {
    for (const path of ["/", "/docs/", "/docs/configuration"]) {
      for (const header of [
        "content-security-policy",
        "permissions-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
      ]) {
        assert.ok(names(path).includes(header), `${path} missing ${header}`);
      }
    }
  });

  it("adds the security.txt content type only on that route", () => {
    assert.ok(names("/.well-known/security.txt").includes("content-type"));
    assert.ok(!names("/").includes("content-type"));
  });

  it("lets a later rule override an earlier one case-insensitively", () => {
    const merged = headersForPath(
      loadHeaderRules({
        headers: [
          { source: "/(.*)", headers: [{ key: "X-Test", value: "a" }] },
          { source: "/x", headers: [{ key: "x-test", value: "b" }] },
        ],
      }),
      "/x",
    );
    assert.deepEqual(merged, [["x-test", "b"]]);
  });
});

describe("serving", () => {
  let root;
  let server;
  let base;

  before(async () => {
    root = mkdtempSync(join(tmpdir(), "static-export-"));
    mkdirSync(join(root, "docs", "guide"), { recursive: true });
    mkdirSync(join(root, ".well-known"));
    writeFileSync(join(root, "index.html"), "home");
    writeFileSync(join(root, "about.html"), "about");
    writeFileSync(join(root, "docs", "index.html"), "docs index");
    writeFileSync(join(root, "docs", "guide", "index.html"), "guide");
    writeFileSync(join(root, "docs", "configuration.html"), "config");
    writeFileSync(join(root, "404.html"), "custom 404");
    writeFileSync(join(root, "app.js"), "x");
    writeFileSync(join(root, ".well-known", "security.txt"), "Contact: x");
    server = createServer(createHandler({ rootDir: root, rules: loadHeaderRules(vercelConfig) }));
    await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
    base = `http://127.0.0.1:${server.address().port}`;
  });

  after(() => {
    server.close();
    rmSync(root, { recursive: true, force: true });
  });

  it("routes like a Next static export", () => {
    const route = (p) => resolveRoute(root, p);
    assert.equal(route("/").file, join(root, "index.html"));
    assert.equal(route("/about").file, join(root, "about.html"));
    assert.equal(route("/docs").file, join(root, "docs", "index.html"));
    assert.equal(route("/docs/").file, join(root, "docs", "index.html"));
    assert.equal(route("/docs/configuration").file, join(root, "docs", "configuration.html"));
    assert.equal(route("/docs/guide").file, join(root, "docs", "guide", "index.html"));
    assert.equal(route("/app.js").file, join(root, "app.js"));
    assert.deepEqual(route("/missing"), { file: join(root, "404.html"), status: 404 });
  });

  it("never lets encoded traversal reach the filesystem", () => {
    for (const path of [
      "/v1.45/containers/%2e%2e/images/json",
      "/%2e%2e/%2e%2e/etc/passwd",
      "/docs/../../etc/passwd",
      "/a%2f..%2fb",
      "/%00",
      "/%zz",
      "/a%5c..%5cb",
    ]) {
      assert.equal(resolveRoute(root, path).status, 404, path);
      assert.equal(resolveRoute(root, path).file, join(root, "404.html"), path);
    }
  });

  it("serves files with headers, content types and status codes", async () => {
    const home = await fetch(`${base}/`);
    assert.equal(home.status, 200);
    assert.equal(home.headers.get("content-type"), "text/html; charset=utf-8");
    assert.match(home.headers.get("content-security-policy"), /default-src 'self'/);
    assert.equal(home.headers.get("x-frame-options"), "DENY");
    assert.equal(await home.text(), "home");

    const js = await fetch(`${base}/app.js`);
    assert.equal(js.headers.get("content-type"), "text/javascript; charset=utf-8");

    const security = await fetch(`${base}/.well-known/security.txt`);
    assert.equal(security.headers.get("content-type"), "text/plain; charset=utf-8");
  });

  it("serves the 404 page with security headers", async () => {
    const res = await fetch(`${base}/v1.45/containers/%2e%2e/images/json`);
    assert.equal(res.status, 404);
    assert.equal(await res.text(), "custom 404");
    assert.ok(res.headers.get("permissions-policy"));
  });

  it("supports HEAD and rejects other methods", async () => {
    const head = await fetch(`${base}/about`, { method: "HEAD" });
    assert.equal(head.status, 200);
    assert.equal(await head.text(), "");
    const post = await fetch(`${base}/about`, { method: "POST" });
    assert.equal(post.status, 405);
  });
});
