import Image from "next/image";
import { Icon } from "@/components/icon";
import { TrackedLink } from "@/components/tracked-link";
import { GITHUB_URL } from "@/lib/site-config";

// A committed first-party SVG pair, not a third-party embed. Both previous
// options failed silently at HTTP 200 (see #303), which is the argument for
// a committed artifact: it needs nothing at runtime, a stale chart is
// visible, and a missing one is a visibly broken image. It also keeps the
// cookieless posture: no visitor IPs leave our infrastructure.
// Regenerated at each release cut by .github/workflows/starchart.yml.

export function StarHistory() {
  return (
    <>
      <a
        className="starcard"
        href={`${GITHUB_URL}/stargazers`}
        target="_blank"
        rel="noopener"
        aria-label="Star history chart for CodesWhat/sockguard"
      >
        <Image
          className="sl"
          src="/star-history.svg"
          alt="Star history chart"
          width={900}
          height={460}
          loading="lazy"
          unoptimized
        />
        <Image
          className="sd"
          src="/star-history-dark.svg"
          alt="Star history chart"
          width={900}
          height={460}
          loading="lazy"
          unoptimized
        />
      </a>
      <div className="more">
        <TrackedLink
          className="btn primary"
          href={GITHUB_URL}
          ctaId="github_repository"
          placement="star_history"
          target="_blank"
          rel="noopener"
        >
          <Icon name="star" />
          Star on GitHub
        </TrackedLink>
      </div>
    </>
  );
}
