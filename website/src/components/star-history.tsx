import { GithubIcon } from "@/components/github-icon";
import { SectionHeading } from "@/components/section-heading";
import { TrackedLink } from "@/components/tracked-link";
import { GITHUB_URL } from "@/lib/site-config";

// Star History = clean framed card, title above the chart (left-aligned).

// A committed first-party SVG pair, not a third-party embed. Both previous
// options failed silently at HTTP 200 (see #303), which is the argument for
// a committed artifact: it needs nothing at runtime, a stale chart is
// visible, and a missing one is a visibly broken image. It also keeps the
// cookieless posture — no visitor IPs leave our infrastructure.
// Regenerated at each release cut by .github/workflows/starchart.yml.
const LIGHT_SRC = "/star-history.svg";
const DARK_SRC = "/star-history-dark.svg";
const CHART_HREF = `${GITHUB_URL}/stargazers`;

function StarChart({ className }: { className?: string }) {
  return (
    <a href={CHART_HREF} target="_blank" rel="noopener" className={className}>
      {/* Swap on the .dark class (theme toggle), not prefers-color-scheme */}
      <img src={LIGHT_SRC} alt="Star history chart" className="w-full dark:hidden" />
      <img src={DARK_SRC} alt="Star history chart" className="hidden w-full dark:block" />
    </a>
  );
}

function GithubCta({ label = "Star on GitHub" }: { label?: string }) {
  return (
    <TrackedLink
      href={GITHUB_URL}
      ctaId="github_repository"
      placement="star_history"
      target="_blank"
      rel="noopener"
      className="inline-flex items-center gap-2 rounded-lg border border-neutral-200 bg-white/60 px-5 py-2.5 text-sm font-medium text-neutral-900 backdrop-blur-sm transition-all hover:border-neutral-300 hover:bg-white/90 dark:border-neutral-700 dark:bg-neutral-800/60 dark:text-neutral-100 dark:hover:border-neutral-600 dark:hover:bg-neutral-800/90"
    >
      <GithubIcon className="h-4 w-4" />
      {label}
    </TrackedLink>
  );
}

export function StarHistory() {
  return (
    <section className="border-t border-border/60 py-16">
      <div className="mx-auto max-w-4xl px-4">
        <SectionHeading
          eyebrow="Community"
          title="Star History"
          subtitle="Growing every week — join us on GitHub."
          align="left"
        />

        <StarChart className="block overflow-hidden rounded-2xl border border-neutral-200 bg-white/50 backdrop-blur-sm transition-all duration-300 hover:border-neutral-300 hover:shadow-lg dark:border-neutral-800 dark:bg-neutral-900/50 dark:hover:border-neutral-700" />

        <div className="mt-6 flex">
          <GithubCta />
        </div>
      </div>
    </section>
  );
}
