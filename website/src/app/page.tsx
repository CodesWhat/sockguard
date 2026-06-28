import { Check, Clock, Minus, Terminal } from "lucide-react";
import type { Metadata } from "next";
import Image from "next/image";
import { CliDemo } from "@/components/cli-demo";
import { CtaButtons } from "@/components/cta-buttons";
import { GitHubBadges } from "@/components/github-badges";
import { MarketingShell } from "@/components/marketing-shell";
import { SectionHeading } from "@/components/section-heading";
import { Badge } from "@/components/ui/badge";
import { BASE_URL, GITHUB_RELEASES_URL, GITHUB_URL, SITE_CONFIG } from "@/lib/site-config";
import { comparisonRows } from "./data/comparison-rows";
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
    color: "text-emerald-600 dark:text-emerald-400",
    border: "border-emerald-500/30",
  },
};

const dockerCompose = `services:
  sockguard:
    image: ${SITE_CONFIG.dockerImage}:latest
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - sockguard-socket:/var/run/sockguard
    environment:
      - SOCKGUARD_LISTEN_SOCKET=/var/run/sockguard/sockguard.sock
      - SOCKGUARD_INSECURE_ALLOW_READ_EXFILTRATION=true
      - CONTAINERS=1
      - EVENTS=1

  your-app:
    depends_on:
      - sockguard
    volumes:
      - sockguard-socket:/var/run/sockguard:ro
    environment:
      - DOCKER_HOST=unix:///var/run/sockguard/sockguard.sock

volumes:
  sockguard-socket:`;

const stats = [
  { value: String(features.length), label: "features" },
  { value: "5", label: "alternatives compared" },
  { value: "96%+", label: "coverage" },
  { value: "Apache-2.0", label: "license" },
];

function ComparisonCell({ value, planned }: { value: string; planned?: boolean }) {
  if (planned) {
    return (
      <Badge variant="outline" className="border-amber-500/30 text-amber-600 dark:text-amber-400">
        <Clock className="size-3" />
        {value}
      </Badge>
    );
  }
  if (value === "Yes") {
    return (
      <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
        <Check className="size-4" />
        Yes
      </span>
    );
  }
  if (value === "No") {
    return (
      <span className="inline-flex items-center gap-1 text-neutral-400 dark:text-neutral-600">
        <Minus className="size-4" />
        No
      </span>
    );
  }
  return <span className="text-neutral-600 dark:text-neutral-400">{value}</span>;
}

export default function Home() {
  const softwareAppJsonLd = {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    name: SITE_CONFIG.name,
    url: BASE_URL,
    description:
      "A default-deny Docker socket proxy built in Go. Filter requests by method, path, and body with signed policy bundles and per-profile rollout modes.",
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

  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(softwareAppJsonLd) }}
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
        <div className="reveal">
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
        <div className="reveal">
          <section className="border-t border-border/60 px-4 py-16">
            <div className="mx-auto max-w-5xl">
              <SectionHeading
                eyebrow="Batteries included"
                title="What we enforce"
                subtitle="We ship a lean Go binary with a stdlib request hot path and zero daemon dependencies. Default-deny, ready to drop in front of your socket."
              />

              <div className="overflow-hidden rounded-xl border border-neutral-300 dark:border-neutral-700">
                <div className="flex items-center gap-2 border-b border-neutral-300 bg-neutral-100 px-5 py-3 dark:border-neutral-700 dark:bg-neutral-900">
                  <div className="h-2.5 w-2.5 rounded-full bg-emerald-500" />
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
        <div className="reveal">
          <section className="border-t border-border/60 px-4 py-16">
            <div className="mx-auto max-w-3xl">
              <SectionHeading
                eyebrow="Get running"
                title="Get started in minutes"
                subtitle="Add sockguard to your compose file and point your app at its scoped socket."
                align="right"
              />

              <div className="overflow-hidden rounded-xl border border-neutral-800 bg-neutral-950 shadow-2xl">
                <div className="flex items-center gap-2 border-b border-neutral-800 px-4 py-3">
                  <Terminal className="h-4 w-4 text-neutral-500" />
                  <span className="text-xs font-medium text-neutral-500">docker-compose.yml</span>
                </div>
                <pre className="overflow-x-auto p-6 font-[family-name:var(--font-mono)] text-sm leading-relaxed text-neutral-300">
                  {dockerCompose}
                </pre>
              </div>

              <p className="mt-4 text-center text-sm text-neutral-500 dark:text-neutral-400">
                We own the real socket. Your app only sees what you allow.{" "}
                <a
                  href="/docs"
                  className="font-medium text-neutral-900 underline-offset-4 hover:underline dark:text-neutral-100"
                >
                  Full configuration docs →
                </a>
              </p>
            </div>
          </section>
        </div>

        {/* ── Comparison ────────────────────────────────────────────────────────── */}
        <div className="reveal">
          <section className="border-t border-border/60 px-4 py-16">
            <div className="mx-auto max-w-5xl">
              <SectionHeading
                eyebrow="vs. the field"
                title="How we stack up"
                subtitle="Compared against the five most common Docker socket proxies. We built sockguard because none of them did request body inspection or per-client policy routing."
              />

              <div className="overflow-x-auto rounded-xl border border-neutral-200 bg-white/50 backdrop-blur-sm dark:border-neutral-800 dark:bg-neutral-900/50">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-neutral-200 dark:border-neutral-800">
                      <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-neutral-500">
                        Feature
                      </th>
                      <th className="px-4 py-3 text-center text-xs font-semibold uppercase tracking-wider text-neutral-500">
                        Tecnativa
                      </th>
                      <th className="px-4 py-3 text-center text-xs font-semibold uppercase tracking-wider text-neutral-500">
                        LinuxServer
                      </th>
                      <th className="px-4 py-3 text-center text-xs font-semibold uppercase tracking-wider text-neutral-500">
                        wollomatic
                      </th>
                      <th className="px-4 py-3 text-center text-xs font-semibold uppercase tracking-wider text-neutral-500">
                        11notes
                      </th>
                      <th className="px-4 py-3 text-center text-xs font-semibold uppercase tracking-wider text-neutral-500">
                        CetusGuard
                      </th>
                      <th className="px-4 py-3 text-center text-xs font-semibold uppercase tracking-wider text-neutral-900 dark:text-neutral-50">
                        Sockguard
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {comparisonRows.map((row) => (
                      <tr
                        key={row.feature}
                        className="border-b border-neutral-100 transition-colors hover:bg-neutral-50 last:border-0 dark:border-neutral-800/50 dark:hover:bg-neutral-900/50"
                      >
                        <td className="px-4 py-3 font-medium text-neutral-900 dark:text-neutral-100">
                          {row.feature}
                        </td>
                        <td className="px-4 py-3 text-center">
                          <ComparisonCell value={row.tecnativa} />
                        </td>
                        <td className="px-4 py-3 text-center">
                          <ComparisonCell value={row.linuxserver} />
                        </td>
                        <td className="px-4 py-3 text-center">
                          <ComparisonCell value={row.wollomatic} />
                        </td>
                        <td className="px-4 py-3 text-center">
                          <ComparisonCell value={row.elevenNotes} />
                        </td>
                        <td className="px-4 py-3 text-center">
                          <ComparisonCell value={row.cetusguard} />
                        </td>
                        <td className="px-4 py-3 text-center">
                          <ComparisonCell value={row.sockguard} planned={row.planned} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </section>
        </div>
      </MarketingShell>
    </>
  );
}
