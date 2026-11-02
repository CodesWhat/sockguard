import type { MetadataRoute } from "next";
import { getComparisonRouteSlugs } from "@/lib/comparison-route-data";
import { BASE_URL } from "@/lib/site-config";

export const dynamic = "force-static";

export default function sitemap(): MetadataRoute.Sitemap {
  const comparePages = getComparisonRouteSlugs().map((slug) => ({
    url: `${BASE_URL}/compare/${slug}`,
    changeFrequency: "monthly" as const,
    priority: 0.8,
  }));

  return [
    {
      url: BASE_URL,
      changeFrequency: "weekly" as const,
      priority: 1,
    },
    {
      url: `${BASE_URL}/compare`,
      changeFrequency: "monthly" as const,
      priority: 0.9,
    },
    ...comparePages,
    {
      url: `${BASE_URL}/docs`,
      changeFrequency: "weekly" as const,
      priority: 0.7,
    },
    // Mirrors docs/content/docs/meta.json's page list, minus "index" (served
    // as /docs above). sitemap.test.mjs fails if the two drift apart — this
    // list silently lost "podman" and "roadmap" once already.
    ...[
      "getting-started",
      "configuration",
      "frontend-runner",
      "multi-host",
      "presets",
      "podman",
      "cis-docker-benchmark",
      "observability",
      "admin",
      "migration",
      "deprecations",
      "roadmap",
      "security",
      "verification",
    ].map((slug) => ({
      url: `${BASE_URL}/docs/${slug}`,
      changeFrequency: "weekly" as const,
      priority: 0.7,
    })),
  ];
}
