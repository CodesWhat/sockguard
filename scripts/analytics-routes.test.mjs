import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  collectAnalyticsRoutes,
  manifestMatches,
  renderAnalyticsRouteManifest,
} from "./analytics-routes.mjs";

const repoRoot = new URL("..", import.meta.url);
const websiteManifest = new URL(
  "../website/src/lib/analytics-routes.generated.ts",
  import.meta.url,
);
const docsManifest = new URL("../docs/src/lib/analytics-routes.generated.ts", import.meta.url);

test("route manifest covers every finite marketing, comparison, and docs page", () => {
  const routes = collectAnalyticsRoutes({ repoRoot });

  for (const route of [
    "/",
    "/compare",
    "/compare/tecnativa",
    "/compare/linuxserver",
    "/docs",
    "/docs/getting-started",
    "/docs/security",
  ]) {
    assert.equal(routes.includes(route), true, `missing analytics route ${route}`);
  }

  assert.equal(
    routes.some((route) => route.startsWith("/api/")),
    false,
  );
  assert.equal(
    routes.some((route) => route.includes("[")),
    false,
  );
  assert.equal(new Set(routes).size, routes.length);
  assert.deepEqual(routes, [...routes].sort());
});

test("both checked-in analytics route manifests exactly match route and docs sources", () => {
  const expected = renderAnalyticsRouteManifest(collectAnalyticsRoutes({ repoRoot }));

  assert.equal(readFileSync(websiteManifest, "utf8"), expected);
  assert.equal(readFileSync(docsManifest, "utf8"), expected);
});

test("manifest checks read the target directly and fail closed for missing or invalid targets", () => {
  const root = mkdtempSync(join(tmpdir(), "sockguard-analytics-routes-"));

  try {
    const target = join(root, "manifest.ts");
    assert.equal(manifestMatches(target, "expected"), false);

    mkdirSync(target);
    assert.equal(manifestMatches(target, "expected"), false);
    rmSync(target, { recursive: true });

    writeFileSync(target, "stale", "utf8");
    assert.equal(manifestMatches(target, "expected"), false);

    writeFileSync(target, "expected", "utf8");
    assert.equal(manifestMatches(target, "expected"), true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
