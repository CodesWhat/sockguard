import assert from "node:assert/strict";
import { test } from "node:test";

import {
  canonicalizePathname,
  createBeforeSend,
  getAnalyticsConfig,
  getSurface,
  isAllowedCta,
  POSTHOG_API_HOST,
  POSTHOG_UI_HOST,
  PRODUCTION_ORIGIN,
  toPublicDocsPathname,
} from "../website/src/lib/analytics-contract.ts";

const ROUTES = new Set(["/", "/compare", "/docs", "/docs/security"]);

test("analytics requires the complete exact public environment contract", () => {
  assert.deepEqual(
    getAnalyticsConfig({
      NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN: "phc_public-token_123",
      NEXT_PUBLIC_POSTHOG_HOST: POSTHOG_API_HOST,
      NEXT_PUBLIC_POSTHOG_UI_HOST: POSTHOG_UI_HOST,
    }),
    {
      token: "phc_public-token_123",
      apiHost: POSTHOG_API_HOST,
      uiHost: POSTHOG_UI_HOST,
    },
  );

  for (const env of [
    {},
    { NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN: "phc_public-token_123" },
    {
      NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN: "public-token",
      NEXT_PUBLIC_POSTHOG_HOST: POSTHOG_API_HOST,
      NEXT_PUBLIC_POSTHOG_UI_HOST: POSTHOG_UI_HOST,
    },
    {
      NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN: "phc_public-token_123",
      NEXT_PUBLIC_POSTHOG_HOST: "https://us.i.posthog.com",
      NEXT_PUBLIC_POSTHOG_UI_HOST: POSTHOG_UI_HOST,
    },
    {
      NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN: "phc_public-token_123",
      NEXT_PUBLIC_POSTHOG_HOST: POSTHOG_API_HOST,
      NEXT_PUBLIC_POSTHOG_UI_HOST: "https://eu.posthog.com",
    },
  ]) {
    assert.equal(getAnalyticsConfig(env), null);
  }
});

test("canonical paths never retain hostile URL data or unknown path text", () => {
  assert.equal(canonicalizePathname("/", ROUTES), "/");
  assert.equal(canonicalizePathname("/compare/", ROUTES), "/compare");
  assert.equal(canonicalizePathname("/compare/?utm_source=secret#secret", ROUTES), "/compare");
  assert.equal(canonicalizePathname("/private/decoded-secret", ROUTES), "/_other");
  assert.equal(canonicalizePathname("/%64ocs", ROUTES), "/_other");
  assert.equal(canonicalizePathname("https://evil.example/compare", ROUTES), "/_other");
  assert.equal(canonicalizePathname(undefined, ROUTES), "/_other");

  assert.equal(getSurface("/docs"), "docs");
  assert.equal(getSurface("/docs/security"), "docs");
  assert.equal(getSurface("/docs-secret"), "marketing");
  assert.equal(getSurface("/"), "marketing");
});

test("docs pathnames restore the public base path stripped by Next", () => {
  assert.equal(toPublicDocsPathname("/"), "/docs");
  assert.equal(toPublicDocsPathname("/security"), "/docs/security");
  assert.equal(toPublicDocsPathname("/docs"), "/docs");
  assert.equal(toPublicDocsPathname("/docs/security"), "/docs/security");
  assert.equal(toPublicDocsPathname(undefined), undefined);
});

test("CTA tuples exactly cover the approved marketing and docs surfaces", () => {
  const expected = new Set([
    "marketing\0docs_root\0header",
    "marketing\0github_repository\0header",
    "marketing\0docs_root\0hero",
    "marketing\0github_repository\0hero",
    "marketing\0docs_root\0comparison",
    "marketing\0github_repository\0comparison",
    "marketing\0install_quick\0get_started",
    "marketing\0install_secure\0get_started",
    "marketing\0docs_root\0get_started",
    "marketing\0docs_root\0footer",
    "marketing\0github_repository\0footer",
    "marketing\0community_discord\0footer",
    "marketing\0github_repository\0star_history",
    "docs\0docs_root\0header",
    "docs\0github_repository\0header",
    "docs\0docs_root\0footer",
    "docs\0github_repository\0footer",
  ]);
  const surfaces = ["marketing", "docs"];
  const ids = [
    "docs_root",
    "github_repository",
    "community_discord",
    "install_quick",
    "install_secure",
  ];
  const placements = ["header", "hero", "comparison", "get_started", "footer", "star_history"];
  const actual = new Set();

  for (const surface of surfaces) {
    for (const id of ids) {
      for (const placement of placements) {
        if (isAllowedCta(surface, id, placement)) {
          actual.add(`${surface}\0${id}\0${placement}`);
        }
      }
    }
  }

  assert.deepEqual(actual, expected);
  assert.equal(isAllowedCta("docs", "github_repository", "hero"), false);
  assert.equal(isAllowedCta("marketing", "live_demo", "hero"), false);
  assert.equal(isAllowedCta("marketing", "github_repository", "unknown"), false);
});

test("pageviews are rebuilt from the canonical production URL and a minimal envelope", () => {
  const timestamp = new Date("2026-08-14T12:00:00.000Z");
  const beforeSend = createBeforeSend("phc_public-token_123", ROUTES);
  const result = beforeSend({
    uuid: "018f0000-0000-7000-8000-000000000001",
    event: "$pageview",
    timestamp,
    $set: { email: "secret@example.com" },
    properties: {
      token: "attacker-token",
      distinct_id: "$posthog_cookieless",
      $cookieless_mode: true,
      $process_person_profile: false,
      path: "/compare/?utm_source=secret#secret",
      surface: "docs",
      title: "Private title",
      $referrer: "https://secret.example",
      $set: { plan: "secret" },
    },
  });

  assert.deepEqual(result, {
    uuid: "018f0000-0000-7000-8000-000000000001",
    event: "$pageview",
    timestamp,
    properties: {
      token: "phc_public-token_123",
      distinct_id: "$posthog_cookieless",
      $cookieless_mode: true,
      $process_person_profile: false,
      schema_version: 1,
      site: "sockguard",
      surface: "marketing",
      path: "/compare",
      $current_url: `${PRODUCTION_ORIGIN}/compare`,
    },
  });
});

test("surface is derived from the canonical path instead of hostile raw path data", () => {
  const beforeSend = createBeforeSend("phc_public-token_123", ROUTES);

  assert.deepEqual(
    beforeSend({
      uuid: "018f0000-0000-7000-8000-000000000005",
      event: "$pageview",
      properties: { path: "/docs?utm_source=secret#private" },
    }),
    {
      uuid: "018f0000-0000-7000-8000-000000000005",
      event: "$pageview",
      properties: {
        token: "phc_public-token_123",
        schema_version: 1,
        site: "sockguard",
        surface: "docs",
        path: "/docs",
        $current_url: `${PRODUCTION_ORIGIN}/docs`,
      },
    },
  );
});

test("CTA events require an allowlisted tuple and retain no extra properties", () => {
  const beforeSend = createBeforeSend("phc_public-token_123", ROUTES);
  const base = {
    uuid: "018f0000-0000-7000-8000-000000000002",
    event: "cta activated",
    properties: {
      path: "/docs/security",
      cta_id: "github_repository",
      placement: "footer",
      element_text: "secret",
    },
  };

  assert.deepEqual(beforeSend(base), {
    uuid: base.uuid,
    event: "cta activated",
    properties: {
      token: "phc_public-token_123",
      schema_version: 1,
      site: "sockguard",
      surface: "docs",
      path: "/docs/security",
      cta_id: "github_repository",
      placement: "footer",
    },
  });
  assert.equal(
    beforeSend({
      ...base,
      properties: { ...base.properties, cta_id: "live_demo", placement: "hero" },
    }),
    null,
  );
});

test("web vitals keep only finite nonnegative allowlisted metric values", () => {
  const beforeSend = createBeforeSend("phc_public-token_123", ROUTES);
  const result = beforeSend({
    uuid: "018f0000-0000-7000-8000-000000000003",
    event: "$web_vitals",
    properties: {
      $current_url: `${PRODUCTION_ORIGIN}/docs?secret=yes#private`,
      $web_vitals_CLS_value: 0.01,
      $web_vitals_FCP_value: 123.4,
      $web_vitals_INP_value: -1,
      $web_vitals_LCP_value: Number.POSITIVE_INFINITY,
      $web_vitals_TTFB_value: 2,
      $web_vitals_LCP_event: { navigationEntry: "secret" },
    },
  });

  assert.deepEqual(result, {
    uuid: "018f0000-0000-7000-8000-000000000003",
    event: "$web_vitals",
    properties: {
      token: "phc_public-token_123",
      schema_version: 1,
      site: "sockguard",
      surface: "docs",
      path: "/docs",
      $web_vitals_CLS_value: 0.01,
      $web_vitals_FCP_value: 123.4,
    },
  });
  assert.equal(
    beforeSend({
      uuid: "018f0000-0000-7000-8000-000000000004",
      event: "$web_vitals",
      properties: { $current_url: PRODUCTION_ORIGIN },
    }),
    null,
  );
});

test("unknown events and invalid capture results are dropped", () => {
  const beforeSend = createBeforeSend("phc_public-token_123", ROUTES);

  assert.equal(beforeSend(null), null);
  assert.equal(beforeSend({ uuid: "018f", event: "$pageview", properties: null }), null);
  assert.equal(beforeSend({ uuid: "018f", event: "$pageview", properties: [] }), null);
  assert.equal(
    beforeSend({ uuid: "018f", event: "$autocapture", properties: { path: "/" } }),
    null,
  );
});
