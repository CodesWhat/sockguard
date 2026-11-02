import Image from "next/image";
import { features } from "@/app/data/features";
import { ALTERNATIVES_COMPARED, COVERAGE_FLOOR, PROOF_SNAPSHOT } from "@/app/data/proof";
import { Icon } from "@/components/icon";
import { TrackedLink } from "@/components/tracked-link";
import { GITHUB_URL, REPO_SLUG, SITE_CONFIG } from "@/lib/site-config";

// The README's badges, linked where the README links them.
const BADGES: { href: string; src: string; alt: string }[] = [
  {
    href: `${GITHUB_URL}/blob/main/LICENSE`,
    src: "https://img.shields.io/badge/license-MIT-C9A227",
    alt: "License MIT",
  },
  {
    href: `${GITHUB_URL}/actions/workflows/ci-verify.yml`,
    src: `${GITHUB_URL}/actions/workflows/ci-verify.yml/badge.svg?branch=main`,
    alt: "CI",
  },
  {
    href: `https://securityscorecards.dev/viewer/?uri=github.com/${REPO_SLUG}`,
    src: `https://img.shields.io/ossf-scorecard/github.com/${REPO_SLUG}?label=openssf+scorecard&style=flat`,
    alt: "OpenSSF Scorecard",
  },
  {
    href: "https://www.bestpractices.dev/projects/14030",
    src: "https://www.bestpractices.dev/projects/14030/badge",
    alt: "OpenSSF Best Practices",
  },
  {
    href: "https://qlty.sh/gh/CodesWhat/projects/sockguard",
    src: "https://qlty.sh/badges/5a115b54-7404-4e0e-b09d-2652fb1816e5/maintainability.svg",
    alt: "Maintainability",
  },
  {
    href: "https://qlty.sh/gh/CodesWhat/projects/sockguard",
    src: "https://qlty.sh/badges/5a115b54-7404-4e0e-b09d-2652fb1816e5/coverage.svg",
    alt: "Coverage",
  },
  {
    href: `${GITHUB_URL}/actions/workflows/quality-mutation-monthly.yml`,
    src: `https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/${REPO_SLUG}/main/.github/badges/mutation-score.json`,
    alt: "Mutation score",
  },
];

export function Hero() {
  return (
    <section className="hero" id="hero" aria-labelledby="h1" style={{ paddingTop: 64 }}>
      <div className="wrap">
        <div className="grid">
          <div className="lcol">
            <p className="ver">
              <span className="chip t-neutral">v{SITE_CONFIG.version} · Open Source · MIT</span>
            </p>
            <h1 className="display" id="h1">
              <span>Control what</span> <span className="mut">gets through</span>
            </h1>
            <p className="lede">
              We put a default-deny proxy in front of your Docker socket. Every request is filtered
              by method, path, and body before it reaches the daemon, then we layer on signed policy
              bundles, per-profile rollout modes, rate limits, hot-reload, and Prometheus metrics.
            </p>
            <div className="ctas">
              <TrackedLink
                className="btn primary"
                href={GITHUB_URL}
                ctaId="github_repository"
                placement="hero"
                target="_blank"
                rel="noopener noreferrer"
              >
                <Icon name="github-logo" />
                View on GitHub
              </TrackedLink>
              <TrackedLink className="btn" href="/docs" ctaId="docs_root" placement="hero">
                <Icon name="book-open" />
                Documentation
              </TrackedLink>
            </div>
          </div>
          <div className="heroobj">
            <Image
              className="mascot"
              src="/img/dog-800.webp"
              alt="Sockguard mascot, an orange toy dog with a studded collar"
              width={800}
              height={800}
              priority
              unoptimized
            />
          </div>
        </div>

        <div className="proof2">
          <ul className="pstats" aria-label="At a glance">
            <li>
              <b>{features.length}</b>
              <span className="micro">features</span>
            </li>
            <li>
              <b>{ALTERNATIVES_COMPARED}</b>
              <span className="micro">alternatives compared</span>
            </li>
            <li>
              <b>{COVERAGE_FLOOR}</b>
              <span className="micro">coverage</span>
            </li>
            <li>
              <a href={`${GITHUB_URL}/stargazers`} target="_blank" rel="noopener noreferrer">
                <b>{PROOF_SNAPSHOT.stars}</b>
                <span className="micro">stars</span>
              </a>
            </li>
            <li>
              <a
                href={`https://hub.docker.com/r/${SITE_CONFIG.dockerImage}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                <b>{PROOF_SNAPSHOT.pulls}</b>
                <span className="micro">pulls</span>
              </a>
            </li>
            <li>
              <a href={`${GITHUB_URL}/forks`} target="_blank" rel="noopener noreferrer">
                <b>{PROOF_SNAPSHOT.forks}</b>
                <span className="micro">forks</span>
              </a>
            </li>
            <li className="sp">
              <a
                href="https://github.com/sponsors/CodesWhat"
                target="_blank"
                rel="noopener noreferrer"
              >
                <Icon name="heart" />
                Sponsor
              </a>
            </li>
          </ul>
          <p className="pasof micro">
            Stars, pulls and forks: snapshot of {PROOF_SNAPSHOT.checkedAt}
          </p>
          <ul className="pbadges" aria-label="Project badges">
            {BADGES.map((b) => (
              <li key={b.alt}>
                <a href={b.href} target="_blank" rel="noopener noreferrer">
                  {/* biome-ignore lint/performance/noImgElement: external badge SVG */}
                  <img src={b.src} alt={b.alt} height={20} loading="lazy" decoding="async" />
                </a>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}
