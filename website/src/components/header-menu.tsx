"use client";

import Link from "next/link";
import { useEffect, useRef } from "react";
import { Icon, type IconName } from "@/components/icon";
import { TrackedLink } from "@/components/tracked-link";
import { GITHUB_URL, SITE_CONFIG } from "@/lib/site-config";

type Item = { href: string; label: string; icon: IconName; external?: boolean };

const ITEMS: Item[] = [
  { href: "/compare", label: "Compare", icon: "arrows-clockwise" },
  { href: "/#demo", label: "See it in action", icon: "terminal-window" },
  { href: "/#roadmap", label: "Roadmap", icon: "git-branch" },
  { href: "/#faq", label: "FAQ", icon: "lifebuoy" },
  { href: "/docs/security", label: "Security", icon: "shield-check" },
  { href: SITE_CONFIG.discordUrl, label: "Discord", icon: "discord-logo", external: true },
];

// Mobile menu: a native <details> that also closes on Escape, outside click,
// and link activation.
export function HeaderMenu() {
  const ref = useRef<HTMLDetailsElement>(null);

  useEffect(() => {
    const close = () => {
      if (ref.current) ref.current.open = false;
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && ref.current?.open) {
        close();
        ref.current.querySelector("summary")?.focus();
      }
    };
    const onClick = (e: MouseEvent) => {
      if (ref.current?.open && !ref.current.contains(e.target as Node)) close();
    };
    document.addEventListener("keydown", onKey);
    document.addEventListener("click", onClick);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("click", onClick);
    };
  }, []);

  const close = () => {
    if (ref.current) ref.current.open = false;
  };

  return (
    <details className="menu" ref={ref}>
      <summary aria-label="Open menu">
        <Icon name="list" />
        Menu
      </summary>
      <div className="panel">
        <TrackedLink href="/docs" ctaId="docs_root" placement="header" onClick={close}>
          <Icon name="book-open" />
          Docs
        </TrackedLink>
        {ITEMS.slice(0, 1).map((i) => (
          <Link key={i.href} href={i.href} onClick={close}>
            <Icon name={i.icon} />
            {i.label}
          </Link>
        ))}
        <TrackedLink
          href={GITHUB_URL}
          ctaId="github_repository"
          placement="header"
          target="_blank"
          rel="noopener noreferrer"
          onClick={close}
        >
          <Icon name="github-logo" />
          GitHub
        </TrackedLink>
        {ITEMS.slice(1).map((i) =>
          i.external ? (
            <a key={i.href} href={i.href} target="_blank" rel="noopener noreferrer" onClick={close}>
              <Icon name={i.icon} />
              {i.label}
            </a>
          ) : (
            <Link key={i.href} href={i.href} onClick={close}>
              <Icon name={i.icon} />
              {i.label}
            </Link>
          ),
        )}
      </div>
    </details>
  );
}
