import Image from "next/image";
import Link from "next/link";
import { Icon } from "@/components/icon";
import { TrackedLink } from "@/components/tracked-link";
import type { AnalyticsCtaId } from "@/lib/analytics-contract";
import {
  DOCKER_HUB_URL,
  GITHUB_RELEASES_URL,
  GITHUB_URL,
  REPO_SLUG,
  SITE_CONFIG,
} from "@/lib/site-config";

const CODESWHAT = "https://github.com/CodesWhat";
const YEAR = new Date().getFullYear();
const BLURB =
  "We built an open-source Docker socket proxy that blocks every request by default. Drop it in front of your socket and control exactly what gets through. Signed policy bundles, per-profile rollout modes, Prometheus metrics, all in one lean Go binary with zero daemon dependencies.";

type FooterLink = { label: string; href: string; external?: boolean; ctaId?: AnalyticsCtaId };

const projectLinks: FooterLink[] = [
  { label: "Documentation", href: "/docs", ctaId: "docs_root" },
  { label: "GitHub", href: GITHUB_URL, external: true, ctaId: "github_repository" },
  { label: "Releases", href: GITHUB_RELEASES_URL, external: true },
  { label: "License", href: SITE_CONFIG.licenseUrl, external: true },
  { label: "Sponsor", href: "https://github.com/sponsors/CodesWhat", external: true },
  { label: "Discord", href: SITE_CONFIG.discordUrl, external: true, ctaId: "community_discord" },
  { label: "Docker Hub", href: DOCKER_HUB_URL, external: true },
  {
    label: "Go Reference",
    href: `https://pkg.go.dev/github.com/${REPO_SLUG.toLowerCase()}/v2`,
    external: true,
  },
];

const compareLinks: FooterLink[] = [
  { label: "All comparisons", href: "/compare" },
  { label: "Tecnativa vs Sockguard", href: "/compare/tecnativa" },
  { label: "LinuxServer vs Sockguard", href: "/compare/linuxserver" },
  { label: "wollomatic vs Sockguard", href: "/compare/wollomatic" },
  { label: "11notes vs Sockguard", href: "/compare/11notes" },
  { label: "CetusGuard vs Sockguard", href: "/compare/cetusguard" },
];

const docsLinks: FooterLink[] = [
  { label: "Introduction", href: "/docs" },
  { label: "Getting started", href: "/docs/getting-started" },
  { label: "Configuration", href: "/docs/configuration" },
  { label: "External frontend runner", href: "/docs/frontend-runner" },
  { label: "Remote Upstreams & Failover", href: "/docs/multi-host" },
  { label: "Presets", href: "/docs/presets" },
  { label: "Podman", href: "/docs/podman" },
  { label: "CIS Docker Benchmark", href: "/docs/cis-docker-benchmark" },
  { label: "Observability", href: "/docs/observability" },
  { label: "Admin API", href: "/docs/admin" },
  { label: "Migration", href: "/docs/migration" },
  { label: "Roadmap", href: "/docs/roadmap" },
  { label: "Security Model", href: "/docs/security" },
  { label: "Artifact Verification", href: "/docs/verification" },
];

const securityLinks: FooterLink[] = [
  { label: "Security Model", href: "/docs/security" },
  { label: "Artifact Verification", href: "/docs/verification" },
  { label: "CIS Docker Benchmark", href: "/docs/cis-docker-benchmark" },
  { label: "Report a vulnerability", href: "mailto:security@getsockguard.com" },
];

function FooterLinkEl({ link }: { link: FooterLink }) {
  const external = link.external
    ? { target: "_blank", rel: "noopener noreferrer" }
    : { target: undefined, rel: undefined };
  if (link.ctaId) {
    return (
      <TrackedLink href={link.href} ctaId={link.ctaId} placement="footer" {...external}>
        {link.label}
      </TrackedLink>
    );
  }
  if (link.external || link.href.startsWith("mailto:")) {
    return (
      <a href={link.href} {...external}>
        {link.label}
      </a>
    );
  }
  if (link.href === "/docs" || link.href.startsWith("/docs/")) {
    return <a href={link.href}>{link.label}</a>;
  }
  return <Link href={link.href}>{link.label}</Link>;
}

function Column({ heading, links }: { heading: string; links: FooterLink[] }) {
  return (
    <div>
      <p className="fh micro">{heading}</p>
      <ul>
        {links.map((l) => (
          <li key={`${l.label}-${l.href}`}>
            <FooterLinkEl link={l} />
          </li>
        ))}
      </ul>
    </div>
  );
}

export function Footer() {
  return (
    <footer className="sg-footer" id="footer">
      <div className="wrap">
        <div className="fgrid">
          <div>
            <Link className="brand" href="/">
              <Image src="/img/dog-64.webp" alt="" width={28} height={28} unoptimized />
              <span>{SITE_CONFIG.name}</span>
            </Link>
            <p className="fblurb">{BLURB}</p>
            <div className="icons">
              <TrackedLink
                href={GITHUB_URL}
                ctaId="github_repository"
                placement="footer"
                target="_blank"
                rel="noopener noreferrer"
                aria-label="GitHub"
              >
                <Icon name="github-logo" />
              </TrackedLink>
              <TrackedLink
                href={SITE_CONFIG.discordUrl}
                ctaId="community_discord"
                placement="footer"
                target="_blank"
                rel="noopener noreferrer"
                aria-label="Discord"
              >
                <Icon name="discord-logo" />
              </TrackedLink>
              <TrackedLink
                href="/docs"
                ctaId="docs_root"
                placement="footer"
                aria-label="Documentation"
              >
                <Icon name="book-open" />
              </TrackedLink>
            </div>
          </div>
          <Column heading="Project" links={projectLinks} />
          <Column heading="Compare" links={compareLinks} />
          <Column heading="Docs" links={docsLinks} />
          <Column heading="Security" links={securityLinks} />
        </div>
        <div className="fbot">
          <span>
            &copy; {YEAR} CodesWhat. Released under the{" "}
            <a href={SITE_CONFIG.licenseUrl} target="_blank" rel="noopener noreferrer">
              MIT License
            </a>
            .
          </span>
          <a className="pill" href={CODESWHAT} target="_blank" rel="noopener noreferrer">
            <Image src="/img/codeswhat-52.webp" alt="" width={26} height={26} unoptimized />A
            CodesWhat project
          </a>
        </div>
      </div>
    </footer>
  );
}
