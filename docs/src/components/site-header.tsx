import Image from "next/image";
import { HeaderMenu } from "@/components/header-menu";
import { Icon } from "@/components/icon";
import { SearchButton } from "@/components/search-button";
import { ThemeToggle } from "@/components/theme-toggle";
import { TrackedAnchor } from "@/components/tracked-anchor";
import { BASE_PATH, GITHUB_URL, SITE_CONFIG } from "@/lib/site-config";

// All navigation links here are plain <a> anchors, not Next <Link>.
// The docs app runs under basePath="/docs", which causes Next <Link> to prefix
// every href with /docs — sending the logo to /docs/ and nav links to /docs/...
// Plain <a> tags resolve at the origin root and are not affected by basePath.

export function SiteHeader() {
  return (
    <header className="top" id="top">
      <div className="wrap">
        <a className="brand" href="/" aria-label={`${SITE_CONFIG.name} home`}>
          <Image
            src={`${BASE_PATH}/img/dog-64.webp`}
            alt=""
            width={28}
            height={28}
            priority
            unoptimized
          />
          <span>{SITE_CONFIG.name}</span>
        </a>
        <nav className="nav" aria-label="Main">
          <TrackedAnchor href="/docs" ctaId="docs_root" placement="header" aria-current="page">
            <Icon name="book-open" />
            Docs
          </TrackedAnchor>
          <TrackedAnchor
            href={GITHUB_URL}
            ctaId="github_repository"
            placement="header"
            target="_blank"
            rel="noopener noreferrer"
          >
            <Icon name="github-logo" />
            GitHub
          </TrackedAnchor>
        </nav>
        <SearchButton />
        <ThemeToggle />
        <HeaderMenu />
      </div>
    </header>
  );
}
