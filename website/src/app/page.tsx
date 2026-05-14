import { BookOpen, BookOpenText, Check, ChevronDown, Clock, Minus, Terminal } from "lucide-react";
import Image from "next/image";
import Link from "next/link";
import { CliDemo } from "@/components/cli-demo";
import { ThemeToggle } from "@/components/theme-toggle";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { comparisonRows } from "./data/comparison-rows";
import { type FeatureCategory, features } from "./data/features";

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
    image: codeswhat/sockguard:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - sockguard-socket:/var/run/sockguard
    environment:
      - SOCKGUARD_LISTEN_SOCKET=/var/run/sockguard/sockguard.sock
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
  return (
    <main className="relative min-h-screen bg-gradient-to-br from-neutral-50 to-neutral-100 dark:from-neutral-950 dark:to-neutral-900">
      {/* Background Pattern */}
      <div className="bg-grid-neutral-200/50 dark:bg-grid-neutral-800/50 fixed inset-0" />

      <div className="relative z-10">
        {/* Theme Toggle */}
        <div className="fixed top-4 right-4 z-50">
          <ThemeToggle />
        </div>

        {/* Hero Section */}
        <section className="relative flex min-h-screen flex-col items-center justify-center px-4 py-10">
          <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_center,_white_20%,_transparent_70%)] dark:bg-[radial-gradient(ellipse_at_center,_rgb(10,10,10)_20%,_transparent_70%)]" />

          <div className="relative z-10 flex flex-col items-center">
            <div className="animate-wiggle mb-8">
              <Image
                src="/sockguard-logo.png"
                alt="Sockguard Logo"
                width={160}
                height={160}
                className="drop-shadow-2xl dark:invert"
                priority
              />
            </div>

            <Badge variant="secondary" className="mb-6 px-4 py-1.5 text-sm font-medium">
              Open Source &middot; Apache-2.0
            </Badge>

            <div className="max-w-4xl text-center">
              <h1 className="mb-4 text-5xl font-bold tracking-tight text-neutral-900 dark:text-neutral-100 sm:text-6xl lg:text-7xl">
                Docker Socket
                <br />
                <span className="text-neutral-600 dark:text-neutral-400">Proxy</span>
              </h1>

              <p className="mx-auto mb-10 max-w-2xl text-lg text-neutral-600 sm:text-xl dark:text-neutral-400">
                Control what gets through. Filter Docker API requests by method, path, and request
                body with default-deny posture — then layer on signed policy bundles, per-profile
                rollout modes for staged enforcement, rate limits and concurrency caps, hot-reload
                with an admin API, Prometheus metrics, and drop-in Tecnativa compatibility.
              </p>

              <div className="flex flex-col items-center justify-center gap-4 sm:flex-row">
                <Button size="lg" asChild>
                  <a
                    href="https://github.com/CodesWhat/sockguard"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <svg
                      className="h-4 w-4"
                      viewBox="0 0 24 24"
                      fill="currentColor"
                      aria-label="GitHub"
                      role="img"
                    >
                      <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
                    </svg>
                    View on GitHub
                  </a>
                </Button>
                <Button variant="outline" size="lg" asChild>
                  <Link href="/docs">
                    <BookOpen className="h-4 w-4" />
                    Documentation
                  </Link>
                </Button>
              </div>

              {/* Distribution Badges */}
              <div className="mt-10 flex flex-wrap items-center justify-center gap-2">
                <a
                  href="https://github.com/orgs/CodesWhat/packages/container/package/sockguard"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {/* biome-ignore lint/performance/noImgElement: external badge */}
                  <img
                    src="https://img.shields.io/badge/GHCR-image-2ea44f?logo=github&logoColor=white"
                    alt="GHCR"
                  />
                </a>
                <a
                  href="https://hub.docker.com/r/codeswhat/sockguard"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {/* biome-ignore lint/performance/noImgElement: external badge */}
                  <img
                    src="https://img.shields.io/docker/pulls/codeswhat/sockguard?logo=docker&logoColor=white&label=Docker%20Hub"
                    alt="Docker Hub pulls"
                  />
                </a>
                <a
                  href="https://github.com/orgs/CodesWhat/packages/container/package/sockguard"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {/* biome-ignore lint/performance/noImgElement: external badge */}
                  <img
                    src="https://img.shields.io/badge/platforms-amd64%20%7C%20arm64-informational?logo=linux&logoColor=white"
                    alt="Multi-arch"
                  />
                </a>
                <a
                  href="https://github.com/orgs/CodesWhat/packages/container/package/sockguard"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {/* biome-ignore lint/performance/noImgElement: external badge */}
                  <img
                    src="https://img.shields.io/docker/image-size/codeswhat/sockguard/latest?label=image%20size"
                    alt="Container size"
                  />
                </a>
              </div>
              {/* Community Badges */}
              <div className="mt-3 flex flex-wrap items-center justify-center gap-2">
                <a
                  href="https://github.com/CodesWhat/sockguard/stargazers"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {/* biome-ignore lint/performance/noImgElement: external badge */}
                  <img
                    src="https://img.shields.io/github/stars/CodesWhat/sockguard?style=flat"
                    alt="Stars"
                  />
                </a>
                <a
                  href="https://github.com/CodesWhat/sockguard/forks"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {/* biome-ignore lint/performance/noImgElement: external badge */}
                  <img
                    src="https://img.shields.io/github/forks/CodesWhat/sockguard?style=flat"
                    alt="Forks"
                  />
                </a>
                <a
                  href="https://github.com/CodesWhat/sockguard/issues"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {/* biome-ignore lint/performance/noImgElement: external badge */}
                  <img
                    src="https://img.shields.io/github/issues/CodesWhat/sockguard?style=flat"
                    alt="Issues"
                  />
                </a>
                <a href="LICENSE" target="_blank" rel="noopener noreferrer">
                  {/* biome-ignore lint/performance/noImgElement: external badge */}
                  <img
                    src="https://img.shields.io/badge/license-Apache--2.0-C9A227"
                    alt="License Apache-2.0"
                  />
                </a>
                <a
                  href="https://github.com/CodesWhat/sockguard/commits/main"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {/* biome-ignore lint/performance/noImgElement: external badge */}
                  <img
                    src="https://img.shields.io/github/last-commit/CodesWhat/sockguard?style=flat"
                    alt="Last commit"
                  />
                </a>
              </div>
              {/* Quality Badges */}
              <div className="mt-3 flex flex-wrap items-center justify-center gap-2">
                <a
                  href="https://github.com/CodesWhat/sockguard/actions/workflows/ci-verify.yml"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {/* biome-ignore lint/performance/noImgElement: external badge */}
                  <img
                    src="https://github.com/CodesWhat/sockguard/actions/workflows/ci-verify.yml/badge.svg?branch=main"
                    alt="CI"
                  />
                </a>
                <a
                  href="https://goreportcard.com/report/github.com/CodesWhat/sockguard"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {/* biome-ignore lint/performance/noImgElement: external badge */}
                  <img
                    src="https://goreportcard.com/badge/github.com/CodesWhat/sockguard"
                    alt="Go Report Card"
                  />
                </a>
                <a
                  href="https://pkg.go.dev/github.com/CodesWhat/sockguard"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {/* biome-ignore lint/performance/noImgElement: external badge */}
                  <img
                    src="https://pkg.go.dev/badge/github.com/CodesWhat/sockguard.svg"
                    alt="Go Reference"
                  />
                </a>
              </div>
            </div>

            {/* Scroll Indicator */}
            <div className="mt-20 animate-bounce">
              <ChevronDown className="h-10 w-10 text-rose-500 drop-shadow-[0_0_8px_rgba(244,63,94,0.5)]" />
            </div>
          </div>
        </section>

        {/* CLI Tour Section */}
        <section className="px-4 py-24">
          <div className="mx-auto max-w-5xl">
            <div className="relative mb-10 text-center">
              <h2 className="text-3xl font-bold tracking-tight text-neutral-900 sm:text-4xl dark:text-neutral-50">
                See it work
              </h2>
              <p className="mt-4 text-neutral-600 dark:text-neutral-400">
                A looping recreation of the real CLI — inspect a config, dry-run a single request
                through the rules, and watch the proxy stream access logs.
              </p>
            </div>
            <CliDemo />
          </div>
        </section>

        {/* Features Section */}
        <section className="px-4 py-24">
          <div className="mx-auto max-w-5xl">
            <div className="relative mb-16 text-center">
              <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_center,_white_20%,_transparent_50%)] dark:bg-[radial-gradient(ellipse_at_center,_rgb(10,10,10)_20%,_transparent_50%)]" />
              <h2 className="relative text-3xl font-bold tracking-tight text-neutral-900 sm:text-4xl dark:text-neutral-50">
                Features
              </h2>
              <p className="relative mt-4 text-neutral-600 dark:text-neutral-400">
                Security-first Docker socket proxy with zero external dependencies
              </p>
            </div>

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

        {/* Quick Start Section */}
        <section className="px-4 py-24">
          <div className="mx-auto max-w-3xl">
            <div className="relative mb-16 text-center">
              <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_center,_white_20%,_transparent_50%)] dark:bg-[radial-gradient(ellipse_at_center,_rgb(10,10,10)_20%,_transparent_50%)]" />
              <h2 className="relative text-3xl font-bold tracking-tight text-neutral-900 sm:text-4xl dark:text-neutral-50">
                Quick Start
              </h2>
              <p className="relative mt-4 text-neutral-600 dark:text-neutral-400">
                Add to your docker-compose.yml and you&apos;re done
              </p>
            </div>

            <div className="overflow-hidden rounded-xl border border-neutral-800 bg-neutral-950 shadow-2xl">
              <div className="flex items-center gap-2 border-b border-neutral-800 px-4 py-3">
                <Terminal className="h-4 w-4 text-neutral-500" />
                <span className="text-xs font-medium text-neutral-500">docker-compose.yml</span>
              </div>
              <pre className="overflow-x-auto p-6 font-[family-name:var(--font-mono)] text-sm leading-relaxed text-neutral-300">
                {dockerCompose}
              </pre>
            </div>
          </div>
        </section>

        {/* Comparison Section */}
        <section className="px-4 py-24">
          <div className="mx-auto max-w-5xl">
            <div className="relative mb-16 text-center">
              <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_center,_white_20%,_transparent_50%)] dark:bg-[radial-gradient(ellipse_at_center,_rgb(10,10,10)_20%,_transparent_50%)]" />
              <h2 className="relative text-3xl font-bold tracking-tight text-neutral-900 sm:text-4xl dark:text-neutral-50">
                Comparison
              </h2>
              <p className="relative mt-4 text-neutral-600 dark:text-neutral-400">
                How Sockguard stacks up against other Docker socket proxies
              </p>
            </div>

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
                        <ComparisonCell value={row.sockguard} planned={row.planned} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        {/* Footer */}
        <footer className="px-4 py-8">
          <div className="mx-auto flex max-w-5xl items-center justify-between">
            <div className="flex items-center gap-3">
              <a href="https://codeswhat.com" target="_blank" rel="noopener noreferrer">
                <Image
                  src="/codeswhat-logo.png"
                  alt="CodesWhat"
                  width={28}
                  height={28}
                  className="dark:invert"
                />
              </a>
              <span className="text-sm text-neutral-500">
                &copy; {new Date().getFullYear()} CodesWhat. Apache-2.0 License.
              </span>
            </div>
            <div className="flex items-center gap-4">
              {/* biome-ignore lint/a11y/useAnchorContent: aria-label provides accessible name */}
              <a
                href="https://github.com/CodesWhat/sockguard"
                target="_blank"
                rel="noopener noreferrer"
                className="text-neutral-400 transition-colors hover:text-neutral-900 dark:hover:text-neutral-100"
                aria-label="GitHub"
              >
                <svg className="h-5 w-5" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                  <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
                </svg>
              </a>
              <Link
                href="/docs"
                className="text-neutral-400 transition-colors hover:text-neutral-900 dark:hover:text-neutral-100"
                aria-label="Documentation"
              >
                <BookOpenText className="h-5 w-5" />
              </Link>
            </div>
          </div>
        </footer>
      </div>
    </main>
  );
}
