import type { Metadata } from "next";
import { CompareMatrix } from "@/components/compare-matrix";
import { MarketingShell } from "@/components/marketing-shell";
import { BASE_URL, SITE_CONFIG } from "@/lib/site-config";

export const metadata: Metadata = {
  // absolute: this title already carries the brand; opt out of the root template.
  title: { absolute: "Sockguard vs Alternatives — Docker Socket Proxy Comparisons" },
  description:
    "Compare Sockguard to Tecnativa, LinuxServer, wollomatic, 11notes, and CetusGuard. Feature-by-feature breakdowns for Docker socket proxy tools.",
  keywords: [
    "docker-socket-proxy alternative",
    "tecnativa alternative",
    "linuxserver alternative",
    "wollomatic alternative",
    "cetusguard alternative",
    "11notes alternative",
    "docker socket proxy comparison",
    "docker socket proxy body inspection",
    "docker socket proxy signed policies",
  ],
  openGraph: {
    title: "Sockguard vs Alternatives — Docker Socket Proxy Comparisons",
    description:
      "Compare Sockguard to Tecnativa, LinuxServer, wollomatic, 11notes, and CetusGuard. Feature-by-feature breakdowns.",
    url: `${BASE_URL}/compare`,
    siteName: SITE_CONFIG.name,
    locale: SITE_CONFIG.locale,
    type: "website",
    images: [{ url: SITE_CONFIG.ogImage, width: 1200, height: 630 }],
  },
  twitter: {
    card: "summary_large_image",
    title: "Sockguard vs Alternatives — Docker Socket Proxy Comparisons",
    description:
      "Compare Sockguard to Tecnativa, LinuxServer, wollomatic, 11notes, and CetusGuard.",
    creator: SITE_CONFIG.twitterCreator,
    images: [SITE_CONFIG.ogImage],
  },
  alternates: {
    canonical: `${BASE_URL}/compare`,
  },
};

const tools = [
  { name: "Tecnativa", slug: "tecnativa" },
  { name: "LinuxServer", slug: "linuxserver" },
  { name: "wollomatic", slug: "wollomatic" },
  { name: "11notes", slug: "11notes" },
  { name: "CetusGuard", slug: "cetusguard" },
];

export default function ComparePage() {
  const jsonLd = {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "CollectionPage",
        name: "Sockguard vs Alternatives — Docker Socket Proxy Comparisons",
        description:
          "Compare Sockguard to Tecnativa, LinuxServer, wollomatic, 11notes, and CetusGuard.",
        url: `${BASE_URL}/compare`,
        mainEntity: {
          "@type": "ItemList",
          numberOfItems: tools.length,
          itemListElement: tools.map((tool, i) => ({
            "@type": "ListItem",
            position: i + 1,
            url: `${BASE_URL}/compare/${tool.slug}`,
            name: `${tool.name} vs Sockguard`,
          })),
        },
      },
      {
        "@type": "BreadcrumbList",
        itemListElement: [
          {
            "@type": "ListItem",
            position: 1,
            name: "Home",
            item: BASE_URL,
          },
          {
            "@type": "ListItem",
            position: 2,
            name: "Compare",
            item: `${BASE_URL}/compare`,
          },
        ],
      },
    ],
  };

  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
      <MarketingShell>
        {/* Hero */}
        <section className="px-4 pt-16 pb-12">
          <div className="mx-auto max-w-4xl text-center">
            <h1 className="mb-4 text-4xl font-bold tracking-tight text-neutral-900 sm:text-5xl dark:text-neutral-100">
              Sockguard vs Alternatives
            </h1>
            <p className="mx-auto max-w-2xl text-lg text-neutral-600 dark:text-neutral-400">
              We built Sockguard to go further than any existing Docker socket proxy. Click any tool
              to see exactly how we compare.
            </p>
          </div>
        </section>

        {/* Full comparison matrix */}
        <section className="px-4 pb-24">
          <div className="mx-auto max-w-5xl">
            <CompareMatrix />
          </div>
        </section>
      </MarketingShell>
    </>
  );
}
