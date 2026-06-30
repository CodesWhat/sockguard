import type { MetadataRoute } from "next";
import { getComparisonRouteSlugs } from "@/lib/comparison-route-data";
import { BASE_URL } from "@/lib/site-config";

export const dynamic = "force-static";

export default function sitemap(): MetadataRoute.Sitemap {
  const comparePages = getComparisonRouteSlugs().map((slug) => ({
    url: `${BASE_URL}/compare/${slug}`,
    lastModified: new Date(),
    changeFrequency: "monthly" as const,
    priority: 0.8,
  }));

  return [
    {
      url: BASE_URL,
      lastModified: new Date(),
      changeFrequency: "weekly" as const,
      priority: 1,
    },
    {
      url: `${BASE_URL}/compare`,
      lastModified: new Date(),
      changeFrequency: "monthly" as const,
      priority: 0.9,
    },
    ...comparePages,
    {
      url: `${BASE_URL}/docs`,
      lastModified: new Date(),
      changeFrequency: "weekly" as const,
      priority: 0.7,
    },
  ];
}
