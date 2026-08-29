import assert from "node:assert/strict";
import { test } from "node:test";

import {
  createAnalyticsRuntime as createDocsAnalyticsRuntime,
  createPostHogOptions as createDocsPostHogOptions,
} from "../docs/src/lib/analytics-client.ts";
import {
  createAnalyticsRuntime,
  createPostHogOptions,
  getOrCreateAnalyticsRuntime,
} from "../website/src/lib/analytics-client.ts";
import { POSTHOG_API_HOST, POSTHOG_UI_HOST } from "../website/src/lib/analytics-contract.ts";

const ROUTES = new Set(["/", "/compare", "/docs"]);
const VALID_ENV = {
  NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN: "phc_public-token_123",
  NEXT_PUBLIC_POSTHOG_HOST: POSTHOG_API_HOST,
  NEXT_PUBLIC_POSTHOG_UI_HOST: POSTHOG_UI_HOST,
};

test("PostHog options pin the privacy posture and cookieless web vitals", () => {
  assert.equal(typeof createDocsAnalyticsRuntime, "function");
  const options = createPostHogOptions("phc_public-token_123", ROUTES);

  assert.deepEqual(
    { ...options, before_send: "function" },
    {
      api_host: POSTHOG_API_HOST,
      ui_host: POSTHOG_UI_HOST,
      autocapture: false,
      rageclick: false,
      capture_pageview: false,
      capture_pageleave: true,
      disable_session_recording: true,
      capture_heatmaps: false,
      capture_dead_clicks: false,
      capture_exceptions: false,
      disable_surveys: true,
      disable_surveys_automatic_display: true,
      disable_product_tours: true,
      disable_web_experiments: true,
      advanced_disable_flags: true,
      person_profiles: "never",
      cookieless_mode: "always",
      persistence: "memory",
      disable_persistence: true,
      respect_dnt: true,
      // Acquisition attribution. save_referrer is what populates
      // $referring_domain; the sanitizer forwards only that hostname and
      // never $referrer, so the full URL stays in the browser.
      save_referrer: true,
      save_campaign_params: true,
      disable_capture_url_hashes: true,
      disable_scroll_properties: true,
      mask_all_element_attributes: true,
      mask_all_text: true,
      capture_performance: {
        network_timing: false,
        web_vitals: true,
        web_vitals_allowed_metrics: ["CLS", "FCP", "INP", "LCP"],
        web_vitals_attribution: false,
      },
      before_send: "function",
    },
  );
  assert.equal("disable_external_dependency_loading" in options, false);
  assert.equal(typeof options.before_send, "function");
  assert.deepEqual(
    { ...createDocsPostHogOptions("phc_public-token_123", ROUTES), before_send: "function" },
    { ...options, before_send: "function" },
  );
});

test("valid initialization queues until the SDK is ready and emits canonical events", async () => {
  const calls = [];
  let finishLoading;
  const posthog = {
    init(token, options) {
      calls.push(["init", token, options]);
    },
    capture(event, properties) {
      calls.push(["capture", event, properties]);
    },
  };
  const runtime = createAnalyticsRuntime({
    env: VALID_ENV,
    routes: ROUTES,
    getDoNotTrack: () => null,
    loadPostHog: () =>
      new Promise((resolve) => {
        finishLoading = () => resolve(posthog);
      }),
  });

  const initialized = runtime.initialize();
  runtime.capturePageview("/compare/?utm_source=secret#secret");
  runtime.captureCta("/compare", "github_repository", "comparison");
  runtime.captureCta("/compare", "live_demo", "hero");
  assert.deepEqual(calls, []);

  finishLoading();
  await initialized;

  assert.equal(calls[0][0], "init");
  assert.equal(calls[0][1], "phc_public-token_123");
  assert.deepEqual(calls.slice(1), [
    [
      "capture",
      "$pageview",
      {
        path: "/compare",
        surface: "marketing",
        $current_url: "https://getsockguard.com/compare",
      },
    ],
    [
      "capture",
      "cta activated",
      {
        path: "/compare",
        surface: "marketing",
        cta_id: "github_repository",
        placement: "comparison",
      },
    ],
  ]);
});

test("captures queued before initialization use canonical paths for their surfaces", async () => {
  const calls = [];
  const runtime = createAnalyticsRuntime({
    env: VALID_ENV,
    routes: ROUTES,
    getDoNotTrack: () => null,
    loadPostHog: async () => ({
      init(token) {
        calls.push(["init", token]);
      },
      capture(event, properties) {
        calls.push(["capture", event, properties]);
      },
    }),
  });

  runtime.capturePageview("/docs?utm_source=secret#private");
  runtime.captureCta("/docs?utm_source=secret#private", "github_repository", "footer");
  assert.deepEqual(calls, []);

  await runtime.initialize();

  assert.deepEqual(calls, [
    ["init", "phc_public-token_123"],
    [
      "capture",
      "$pageview",
      { path: "/docs", surface: "docs", $current_url: "https://getsockguard.com/docs" },
    ],
    [
      "capture",
      "cta activated",
      {
        path: "/docs",
        surface: "docs",
        cta_id: "github_repository",
        placement: "footer",
      },
    ],
  ]);
});

test("missing, partial, malformed, and DNT environments never load or capture", async () => {
  for (const { env, dnt } of [
    { env: {}, dnt: null },
    { env: { NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN: "phc_partial" }, dnt: null },
    {
      env: {
        ...VALID_ENV,
        NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN: "private-token",
      },
      dnt: null,
    },
    { env: VALID_ENV, dnt: "1" },
  ]) {
    let loadCount = 0;
    const runtime = createAnalyticsRuntime({
      env,
      routes: ROUTES,
      getDoNotTrack: () => dnt,
      loadPostHog: async () => {
        loadCount += 1;
        throw new Error("must not load");
      },
    });

    await runtime.initialize();
    runtime.capturePageview("/");
    runtime.captureCta("/", "github_repository", "hero");
    assert.equal(loadCount, 0);
  }
});

test("SDK load failures fail closed without leaking queued events", async () => {
  let loadCount = 0;
  const runtime = createAnalyticsRuntime({
    env: VALID_ENV,
    routes: ROUTES,
    getDoNotTrack: () => null,
    loadPostHog: async () => {
      loadCount += 1;
      throw new Error("provider unavailable");
    },
  });

  const initialized = runtime.initialize();
  runtime.capturePageview("/");
  await assert.doesNotReject(initialized);
  runtime.capturePageview("/compare");
  assert.equal(loadCount, 1);
});

test("separate client bundles share one initialized browser runtime", async () => {
  const scope = {};
  const calls = [];
  let loadCount = 0;
  const options = {
    env: VALID_ENV,
    routes: ROUTES,
    getDoNotTrack: () => null,
    loadPostHog: async () => {
      loadCount += 1;
      return {
        init(token) {
          calls.push(["init", token]);
        },
        capture(event, properties) {
          calls.push(["capture", event, properties]);
        },
      };
    },
  };

  const instrumentationRuntime = getOrCreateAnalyticsRuntime(options, scope);
  const componentRuntime = getOrCreateAnalyticsRuntime(options, scope);

  assert.equal(componentRuntime, instrumentationRuntime);
  await instrumentationRuntime.initialize();
  componentRuntime.capturePageview("/");
  assert.equal(loadCount, 1);
  assert.deepEqual(calls, [
    ["init", "phc_public-token_123"],
    [
      "capture",
      "$pageview",
      { path: "/", surface: "marketing", $current_url: "https://getsockguard.com/" },
    ],
  ]);
});
