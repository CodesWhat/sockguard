import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { collectAnalyticsRoutes, renderAnalyticsRouteManifest } from "./analytics-routes.mjs";

const repoRoot = new URL("..", import.meta.url);
const websiteManifest = new URL("../website/src/lib/analytics-routes.generated.ts", import.meta.url);
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

  assert.equal(routes.some((route) => route.startsWith("/api/")), false);
  assert.equal(routes.some((route) => route.includes("[")), false);
  assert.equal(new Set(routes).size, routes.length);
  assert.deepEqual(routes, [...routes].sort());
});

test("both checked-in analytics route manifests exactly match route and docs sources", () => {
  const expected = renderAnalyticsRouteManifest(collectAnalyticsRoutes({ repoRoot }));

  assert.equal(readFileSync(websiteManifest, "utf8"), expected);
  assert.equal(readFileSync(docsManifest, "utf8"), expected);
});
