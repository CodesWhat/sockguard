import Image from "next/image";
import { Icon } from "@/components/icon";
import { TrackedLink } from "@/components/tracked-link";
import { GITHUB_URL } from "@/lib/site-config";

// Star History's hosted chart (api.star-history.com), light and dark. The
// committed SVG pair failed the ops rule (X55); the earlier hosted options
// failed silently at HTTP 200 (#303), so the contract test pins the exact
// embed and the rendered chart is checked by eye. This is the one third-party
// image request on the page: the host is allowed in img-src (vercel.json) and
// the response sets no cookies, but the visitor's IP and User-Agent reach it.

const CHART =
  "https://api.star-history.com/chart?repos=codeswhat/sockguard&type=date&legend=top-left";

export function StarHistory() {
  return (
    <>
      <a
        className="starcard"
        href="https://www.star-history.com/?type=date&repos=CodesWhat%2Fsockguard"
        target="_blank"
        rel="noopener"
        aria-label="Star history chart for CodesWhat/sockguard"
      >
        <Image
          className="sl"
          src={CHART}
          alt="Star history chart"
          width={800}
          height={533}
          loading="lazy"
          unoptimized
        />
        <Image
          className="sd"
          src={`${CHART}&theme=dark`}
          alt="Star history chart"
          width={800}
          height={533}
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
