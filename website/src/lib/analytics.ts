import { detectPrivacyOptOut, getOrCreateAnalyticsRuntime } from "./analytics-client.ts";
import { ANALYTICS_ROUTES } from "./analytics-routes.generated.ts";

const runtime = getOrCreateAnalyticsRuntime({
  env: {
    NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN: process.env.NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN,
    NEXT_PUBLIC_POSTHOG_HOST: process.env.NEXT_PUBLIC_POSTHOG_HOST,
    NEXT_PUBLIC_POSTHOG_UI_HOST: process.env.NEXT_PUBLIC_POSTHOG_UI_HOST,
  },
  routes: ANALYTICS_ROUTES,
  hasPrivacyOptOut: () =>
    detectPrivacyOptOut(
      typeof navigator === "undefined" ? undefined : navigator,
      typeof window === "undefined" ? undefined : (window as { doNotTrack?: string | null }),
    ),
  loadPostHog: async () => (await import("posthog-js")).default,
});

export const initializeAnalytics = runtime.initialize;
export const capturePageview = runtime.capturePageview;
export const captureCta = runtime.captureCta;
