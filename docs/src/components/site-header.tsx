import Image from "next/image";
import { GithubIcon } from "@/components/github-icon";
import { ThemeToggle } from "@/components/theme-toggle";
import { iconButtonCn, navLinkCn } from "@/lib/class-names";
import { GITHUB_URL, SITE_CONFIG } from "@/lib/site-config";

// NOTE: All navigation links here are plain <a> anchors, not Next <Link>.
// The docs app runs under basePath="/docs", which causes Next <Link> to prefix
// every href with /docs — sending the logo to /docs/ and nav links to /docs/...
// Plain <a> tags resolve at the origin root and are not affected by basePath.

export function SiteHeader({ maxWidthClassName = "max-w-6xl" }: { maxWidthClassName?: string }) {
  return (
    <header className="sticky top-0 z-50 border-b border-border/60 bg-white/70 backdrop-blur-md dark:bg-neutral-950/70">
      <div className={`mx-auto flex h-14 items-center justify-between px-4 ${maxWidthClassName}`}>
        <a href="/" className="flex items-center gap-2.5">
          <Image
            src={SITE_CONFIG.logo}
            alt=""
            width={36}
            height={36}
            className={SITE_CONFIG.logoInvertOnDark ? "dark:invert" : undefined}
          />
          <span className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">
            {SITE_CONFIG.name}
          </span>
        </a>
        <nav className="flex items-center gap-1 sm:gap-2">
          <a href="/docs" className={`hidden px-3 py-2 sm:inline-block ${navLinkCn}`}>
            Docs
          </a>
          <a
            href={GITHUB_URL}
            target="_blank"
            rel="noopener noreferrer"
            aria-label="GitHub"
            className={iconButtonCn}
          >
            <GithubIcon className="h-5 w-5" />
          </a>
          <ThemeToggle />
        </nav>
      </div>
    </header>
  );
}
