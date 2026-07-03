import type { Metadata } from "next";
import Image from "next/image";
import { CliDemo } from "@/components/cli-demo";
import { CompareSection } from "@/components/compare-section";
import { CtaButtons } from "@/components/cta-buttons";
import { Ecosystem } from "@/components/ecosystem";
import { FAQ } from "@/components/faq";
import { GetStarted } from "@/components/get-started";
import { GitHubBadges } from "@/components/github-badges";
import { MarketingShell } from "@/components/marketing-shell";
import { Roadmap } from "@/components/roadmap";
import { SectionHeading } from "@/components/section-heading";
import { StarHistory } from "@/components/star-history";
import { Badge } from "@/components/ui/badge";
import { BASE_URL, GITHUB_RELEASES_URL, GITHUB_URL, SITE_CONFIG } from "@/lib/site-config";
import { faqItems } from "./data/faq";
import { type FeatureCategory, features } from "./data/features";

export const metadata: Metadata = {
  alternates: {
    canonical: BASE_URL,
  },
};

const categoryLabels: Record<FeatureCategory, { label: string; color: string; border: string }> = {
  security: {
    label: "Security",
    color: "text-rose-600 dark:text-rose-400",
    border: "border-rose-500/30",
  },
  control: {
    label: "Control",
    color: "text-blue-600 dark:text-blue-400",
    border: "border-blue-500/30",
  },
  operations: {
    label: "Operations",
    color: "text-amber-600 dark:text-amber-400",
    border: "border-amber-500/30",
  },
};

const stats = [
  { value: String(features.length), label: "features" },
  { value: "5", label: "alternatives compared" },
  { value: "96%+", label: "coverage" },
  { value: "Apache-2.0", label: "license" },
];

export default function Home() {
  const softwareAppJsonLd = {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    name: SITE_CONFIG.name,
    url: BASE_URL,
    description:
      "A default-deny Docker socket proxy built in Go. Filter Docker API requests by method, path, and body with signed policy bundles and per-profile rollout modes.",
    applicationCategory: "DeveloperApplication",
    operatingSystem: "Docker",
    license: SITE_CONFIG.licenseUrl,
    downloadUrl: GITHUB_RELEASES_URL,
    installUrl: GITHUB_RELEASES_URL,
    offers: {
      "@type": "Offer",
      price: "0",
      priceCurrency: "USD",
    },
    sameAs: [GITHUB_URL, SITE_CONFIG.twitterUrl],
    author: {
      "@type": "Organization",
      name: "CodesWhat",
      url: "https://codeswhat.com",
      sameAs: ["https://github.com/CodesWhat"],
    },
    softwareHelp: {
      "@type": "WebPage",
      url: `${BASE_URL}/docs`,
    },
  };

  const websiteJsonLd = {
    "@context": "https://schema.org",
    "@type": "WebSite",
    name: SITE_CONFIG.name,
    url: BASE_URL,
    publisher: {
      "@type": "Organization",
      name: "CodesWhat",
    },
  };

  const faqPageJsonLd = {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    mainEntity: faqItems.map((item) => ({
      "@type": "Question",
      name: item.question,
      acceptedAnswer: {
        "@type": "Answer",
        text: item.answer,
      },
    })),
  };

  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(softwareAppJsonLd) }}
      />
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(websiteJsonLd) }}
      />
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(faqPageJsonLd) }}
      />
      <MarketingShell aurora="ember">
        {/* ── Hero ──────────────────────────────────────────────────────────────── */}
        <section className="relative px-4 py-20">
          {/* Background glow */}
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-0 -z-10 overflow-hidden"
          >
            <div className="absolute left-1/2 top-0 h-96 w-96 -translate-x-1/2 -translate-y-1/4 rounded-full bg-[var(--au-glow)] blur-3xl opacity-60" />
          </div>

          <div className="mx-auto max-w-6xl px-4">
            <div className="flex flex-col items-center gap-6 text-center">
              <Badge variant="secondary" className="font-mono text-xs">
                v{SITE_CONFIG.version} &middot; Open Source &middot; Apache-2.0
              </Badge>

              <h1 className="max-w-3xl text-6xl font-bold tracking-tight text-neutral-900 dark:text-neutral-100 sm:text-7xl lg:text-8xl">
                Control what
                <br />
                <span className="text-neutral-400 dark:text-neutral-500">gets through</span>
              </h1>

              <p className="max-w-2xl text-lg text-neutral-600 dark:text-neutral-400">
                We put a default-deny proxy in front of your Docker socket. Every request is
                filtered by method, path, and body before it reaches the daemon — then we layer on
                signed policy bundles, per-profile rollout modes, rate limits, hot-reload, and
                Prometheus metrics.
              </p>

              <CtaButtons align="center" />

              {/* Stat strip */}
              <div className="flex flex-wrap items-center justify-center gap-0 divide-x divide-neutral-200 dark:divide-neutral-700">
                {stats.map((stat) => (
                  <div key={stat.label} className="px-4 first:pl-0">
                    <span className="font-mono text-xs font-semibold uppercase tracking-widest text-neutral-900 dark:text-neutral-100">
                      {stat.value}
                    </span>
                    <span className="ml-1 font-mono text-xs uppercase tracking-widest text-neutral-400 dark:text-neutral-500">
                      {stat.label}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Logo moment */}
            <div className="relative mt-12 flex justify-center">
              <div
                aria-hidden="true"
                className="pointer-events-none absolute inset-0 -z-10 flex items-center justify-center"
              >
                <div className="h-72 w-72 rounded-full bg-[var(--au-glow)] opacity-50 blur-3xl" />
              </div>
              <Image
                src={SITE_CONFIG.logo}
                alt=""
                aria-hidden="true"
                width={200}
                height={200}
                className="animate-dog-bark drop-shadow-2xl"
                priority
              />
            </div>

            {/* Badges */}
            <div className="mt-12">
              <GitHubBadges />
            </div>
          </div>
        </section>

        {/* ── CLI Demo ──────────────────────────────────────────────────────────── */}
        <div className="reveal" suppressHydrationWarning>
          <section className="border-t border-border/60 px-4 py-16">
            <div className="mx-auto max-w-5xl">
              <SectionHeading
                eyebrow="In the real CLI"
                title="See it work"
                subtitle="A looping recreation of the real CLI — inspect a config, dry-run a single request through the rules, and watch the proxy stream access logs."
              />
              <CliDemo />
            </div>
          </section>
        </div>

        {/* ── Features ──────────────────────────────────────────────────────────── */}
        <div className="reveal" suppressHydrationWarning>
          <section className="border-t border-border/60 px-4 py-16">
            <div className="mx-auto max-w-5xl">
              <SectionHeading
                eyebrow="Batteries included"
                title="What we enforce"
                subtitle="We ship a lean Go binary with a stdlib request hot path and zero daemon dependencies. Default-deny, ready to drop in front of your socket."
              />

              <div className="overflow-hidden rounded-xl border border-neutral-300 dark:border-neutral-700">
                <div className="flex items-center gap-2 border-b border-neutral-300 bg-neutral-100 px-5 py-3 dark:border-neutral-700 dark:bg-neutral-900">
                  <div className="h-2.5 w-2.5 rounded-full bg-amber-500" />
                  <span className="font-mono text-xs text-neutral-500 dark:text-neutral-400">
                    sockguard capabilities
                  </span>
                  <span className="ml-auto font-mono text-xs text-neutral-400 dark:text-neutral-600">
                    {features.length} modules
                  </span>
                </div>
                <div className="divide-y divide-neutral-200 bg-white dark:divide-neutral-800 dark:bg-neutral-950">
                  {features.map((feature, i) => {
                    const cat = categoryLabels[feature.category];
                    return (
                      <div
                        key={feature.title}
                        className="group flex items-center gap-5 px-5 py-4 transition-colors hover:bg-neutral-50 dark:hover:bg-neutral-900/50"
                      >
                        <span className="w-6 shrink-0 text-right font-mono text-xs tabular-nums text-neutral-300 dark:text-neutral-700">
                          {String(i + 1).padStart(2, "0")}
                        </span>
                        <div
                          className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-md ${feature.bg}`}
                        >
                          <feature.icon className={`h-4 w-4 ${feature.color}`} />
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="flex items-baseline gap-3">
                            <h3 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
                              {feature.title}
                            </h3>
                            <span
                              className={`rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${cat.border} ${cat.color}`}
                            >
                              {cat.label}
                            </span>
                          </div>
                          <p className="mt-0.5 text-xs text-neutral-500 dark:text-neutral-400">
                            {feature.description}
                          </p>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </section>
        </div>

        {/* ── Quick Start ───────────────────────────────────────────────────────── */}
        <div className="reveal" suppressHydrationWarning>
          <GetStarted />
        </div>

        {/* ── Roadmap ───────────────────────────────────────────────────────────── */}
        <div className="reveal" suppressHydrationWarning>
          <Roadmap />
        </div>

        {/* ── Star History ──────────────────────────────────────────────────────── */}
        <div className="reveal" suppressHydrationWarning>
          <StarHistory />
        </div>

        {/* ── Compare ───────────────────────────────────────────────────────────── */}
        <div className="reveal" suppressHydrationWarning>
          <CompareSection />
        </div>

        {/* ── Ecosystem ─────────────────────────────────────────────────────────── */}
        <div className="reveal" suppressHydrationWarning>
          <Ecosystem />
        </div>

        {/* ── FAQ ───────────────────────────────────────────────────────────────── */}
        <div className="reveal" suppressHydrationWarning>
          <FAQ />
        </div>
      </MarketingShell>
    </>
  );
}
