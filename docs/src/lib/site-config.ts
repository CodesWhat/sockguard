/**
 * Single source of truth for site identity, branding, and external URLs.
 *
 * This is the per-site config consumed by the shared CodesWhat shell chrome
 * (header, footer, background, layout, metadata). To re-skin the shell for
 * another site, edit only this file — every component and route reads from here.
 */

const githubOwner = "CodesWhat";
const githubRepo = "sockguard";

/**
 * Deploy base path for this app — must match `basePath` in next.config.ts.
 * Next.js does NOT prepend basePath to metadata asset URLs or string
 * `<Image src>` values, so anything served from /public must carry this
 * prefix explicitly to resolve both in standalone dev and when the static
 * export is served under getsockguard.com/docs.
 */
export const BASE_PATH = "/docs";

export type AuroraPalette = "ember" | "ocean" | "violet" | "forest" | "mono";

export const SITE_CONFIG = {
  /** Brand name shown in the header, footer, and metadata. */
  name: "Sockguard",
  /** Default meta / OpenGraph / Twitter description. */
  description:
    "We built a default-deny Docker socket proxy in Go. Filter Docker API requests by method, path, and body, then layer on signed policy bundles, per-profile rollout modes, rate limits, hot-reload, and Prometheus metrics.",
  /** Production domain (no protocol, no trailing slash). */
  domain: "getsockguard.com",
  /** GitHub owner/org. */
  githubOwner,
  /** GitHub repository name. */
  githubRepo,
  /** Default OpenGraph / Twitter share image in /public (1200x630 banner). */
  ogImage: `${BASE_PATH}/og-image.png`,
  /** OpenGraph locale. */
  locale: "en_US",
  /** Logo asset in /public. */
  logo: `${BASE_PATH}/sockguard-logo.png`,
  /** Whether the logo inverts in dark mode (adds `dark:invert`). */
  logoInvertOnDark: false,
  /** License link shown in the footer. */
  licenseUrl: "https://www.apache.org/licenses/LICENSE-2.0",
  /** Aurora background palette token (see globals.css `[data-bg]`). */
  aurora: "ember" as AuroraPalette,
} as const;

/** "owner/repo" slug — intermediate value for GITHUB_URL. */
const REPO_SLUG = `${SITE_CONFIG.githubOwner}/${SITE_CONFIG.githubRepo}`;
/** Canonical GitHub repository URL. */
export const GITHUB_URL = `https://github.com/${REPO_SLUG}`;
/** GitHub releases page. */
export const GITHUB_RELEASES_URL = `${GITHUB_URL}/releases`;

/**
 * Site base URL. Prefers NEXT_PUBLIC_SITE_URL (Vercel/preview deploys),
 * falls back to the configured production domain. `||` (not `??`) so a
 * set-but-empty env var falls back too.
 */
export const BASE_URL = process.env.NEXT_PUBLIC_SITE_URL || `https://${SITE_CONFIG.domain}`;
