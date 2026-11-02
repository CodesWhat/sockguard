import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, it } from "node:test";

const repoRoot = resolve(import.meta.dirname, "..");
const deployedProjectRoot = resolve(repoRoot, "website");
const vercelConfigPath = resolve(deployedProjectRoot, "vercel.json");

function catchAllHeaders() {
  assert.ok(
    existsSync(vercelConfigPath),
    "website/vercel.json must live in the configured Vercel project root",
  );
  const vercelConfig = JSON.parse(readFileSync(vercelConfigPath, "utf8"));
  const route = vercelConfig.headers?.find(({ source }) => source === "/(.*)");
  assert.ok(route, "website/vercel.json must define response headers for every route");
  return new Map(route.headers.map(({ key, value }) => [key.toLowerCase(), value]));
}

describe("Vercel security headers", () => {
  it("applies browser hardening headers to every website and docs route", () => {
    const headers = catchAllHeaders();

    assert.equal(headers.get("x-content-type-options"), "nosniff");
    assert.equal(headers.get("x-frame-options"), "DENY");
    assert.equal(headers.get("referrer-policy"), "strict-origin-when-cross-origin");
    assert.equal(
      headers.get("permissions-policy"),
      "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
    );
  });

  it("enforces a restrictive content security policy", () => {
    const csp = catchAllHeaders().get("content-security-policy");
    assert.ok(csp, "Content-Security-Policy header is required");

    for (const directive of [
      "default-src 'self'",
      "base-uri 'self'",
      "object-src 'none'",
      "frame-ancestors 'none'",
      "form-action 'self'",
      "script-src 'self' 'unsafe-inline' https://e.codeswhat.com",
      "connect-src 'self' https://e.codeswhat.com",
      "font-src 'self' data:",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https://api.star-history.com https://github.com https://img.shields.io https://qlty.sh https://www.bestpractices.dev",
    ]) {
      assert.match(
        csp,
        new RegExp(`(?:^|; )${directive.replaceAll(/[.*+?^${}()|[\\]\\\\]/g, "\\$&")}(?:;|$)`),
      );
    }

    assert.doesNotMatch(csp, /'unsafe-eval'/);
    // The Go Reference badge image is gone (footer text link only), so
    // pkg.go.dev must not stay allowed as an image host.
    assert.doesNotMatch(csp, /pkg\.go\.dev/u);
    // Star History (X55) is the one allowed chart host, image-only. The
    // other retired hosts from #303 stay out.
    assert.match(csp, /(?:^|; )img-src [^;]*https:\/\/api\.star-history\.com(?:[ ;]|$)/u);
    const sources = (directives) =>
      csp
        .split(/;\s*/u)
        .filter((d) => directives(d.split(/\s+/u)[0]))
        .flatMap((d) => d.split(/\s+/u).slice(1));
    const isHost = (pattern) => (source) => pattern.test(source);
    assert.ok(
      !sources(() => true).some(
        isHost(/^https?:\/\/(?:[^/]*\.)?(?:warpchart\.dev|www\.star-history\.com)(?:\/|$)/iu),
      ),
    );
    assert.ok(
      !sources((name) => name !== "img-src").some(
        isHost(/^https?:\/\/(?:[^/]*\.)?star-history\.com(?:\/|$)/iu),
      ),
    );
    const scriptSrc = csp.match(/(?:^|; )script-src ([^;]+)/)?.[1];
    const connectSrc = csp.match(/(?:^|; )connect-src ([^;]+)/)?.[1];
    assert.equal(scriptSrc, "'self' 'unsafe-inline' https://e.codeswhat.com");
    assert.equal(connectSrc, "'self' https://e.codeswhat.com");
    assert.doesNotMatch(
      csp,
      /(?:\*\.posthog\.com|us\.posthog\.com|va\.vercel-scripts\.com|https:\/\/\*)/u,
    );
  });
});
