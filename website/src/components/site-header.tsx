import Image from "next/image";
import Link from "next/link";
import { HeaderMenu } from "@/components/header-menu";
import { Icon } from "@/components/icon";
import { ThemeToggle } from "@/components/theme-toggle";
import { TrackedLink } from "@/components/tracked-link";
import { GITHUB_URL, SITE_CONFIG } from "@/lib/site-config";

export function SiteHeader() {
  return (
    <header className="top" id="top">
      <div className="wrap">
        <Link className="brand" href="/" aria-label={`${SITE_CONFIG.name} home`}>
          <Image src="/img/dog-64.webp" alt="" width={28} height={28} priority unoptimized />
          <span>{SITE_CONFIG.name}</span>
        </Link>
        <nav className="nav" aria-label="Main">
          <TrackedLink href="/docs" ctaId="docs_root" placement="header">
            <Icon name="book-open" />
            Docs
          </TrackedLink>
          <Link href="/compare">
            <Icon name="arrows-clockwise" />
            Compare
          </Link>
          <TrackedLink
            href={GITHUB_URL}
            ctaId="github_repository"
            placement="header"
            target="_blank"
            rel="noopener noreferrer"
          >
            <Icon name="github-logo" />
            GitHub
          </TrackedLink>
        </nav>
        <ThemeToggle />
        <HeaderMenu />
      </div>
    </header>
  );
}
