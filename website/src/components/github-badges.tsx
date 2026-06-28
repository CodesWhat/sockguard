import { Download, GitFork, Star } from "lucide-react";
import { DOCKER_HUB_URL, GITHUB_URL, REPO_SLUG } from "@/lib/site-config";

type Badge = { href: string; src: string; alt: string };

// Quality + distribution badges (shields.io — verifiable trust)
const quality: Badge[] = [
  {
    href: `${GITHUB_URL}/blob/main/LICENSE`,
    src: "https://img.shields.io/badge/license-Apache--2.0-C9A227",
    alt: "License Apache-2.0",
  },
  {
    href: `${GITHUB_URL}/actions/workflows/ci-verify.yml`,
    src: `${GITHUB_URL}/actions/workflows/ci-verify.yml/badge.svg?branch=main`,
    alt: "CI",
  },
  {
    href: `https://goreportcard.com/report/github.com/${REPO_SLUG}`,
    src: `https://goreportcard.com/badge/github.com/${REPO_SLUG}`,
    alt: "Go Report Card",
  },
  {
    href: `https://pkg.go.dev/github.com/${REPO_SLUG}`,
    src: `https://pkg.go.dev/badge/github.com/${REPO_SLUG}.svg`,
    alt: "Go Reference",
  },
  {
    href: `https://securityscorecards.dev/viewer/?uri=github.com/${REPO_SLUG}`,
    src: `https://img.shields.io/ossf-scorecard/github.com/${REPO_SLUG}?label=openssf+scorecard&style=flat`,
    alt: "OpenSSF Scorecard",
  },
];

type Stat = {
  href: string;
  icon: typeof Star;
  iconClass: string;
  value: string;
  label: string;
};

const stats: Stat[] = [
  {
    href: `${GITHUB_URL}/stargazers`,
    icon: Star,
    iconClass: "fill-amber-400 text-amber-400",
    value: "★",
    label: "stars",
  },
  {
    href: DOCKER_HUB_URL,
    icon: Download,
    iconClass: "text-sky-500",
    value: "⬇",
    label: "pulls",
  },
  {
    href: `${GITHUB_URL}/forks`,
    icon: GitFork,
    iconClass: "text-violet-500",
    value: "⑂",
    label: "forks",
  },
];

function QualityRow() {
  return (
    <div className="flex flex-wrap items-center justify-center gap-2">
      {quality.map((b) => (
        <a key={b.alt} href={b.href} target="_blank" rel="noopener noreferrer">
          {/* biome-ignore lint/performance/noImgElement: external shield badge */}
          <img src={b.src} alt={b.alt} loading="lazy" className="h-5 w-auto" />
        </a>
      ))}
    </div>
  );
}

function StatTiles() {
  return (
    <div className="flex flex-wrap items-center justify-center gap-2.5">
      {stats.map((s) => {
        const Icon = s.icon;
        return (
          <a
            key={s.label}
            href={s.href}
            target="_blank"
            rel="noopener noreferrer"
            className="group flex items-center gap-2.5 rounded-xl border border-neutral-200 bg-white/50 px-4 py-2.5 backdrop-blur-sm transition-colors hover:border-neutral-300 hover:bg-white/80 dark:border-neutral-800 dark:bg-neutral-900/50 dark:hover:border-neutral-700 dark:hover:bg-neutral-900/80"
          >
            <Icon className={`h-4 w-4 shrink-0 ${s.iconClass}`} />
            <span className="text-xs font-medium text-neutral-600 dark:text-neutral-400">
              {s.label}
            </span>
          </a>
        );
      })}
    </div>
  );
}

export function GitHubBadges() {
  return (
    <div className="flex flex-col items-center gap-4">
      <QualityRow />
      <StatTiles />
    </div>
  );
}
