"use client";

import { useEffect, useRef } from "react";
import { Icon } from "@/components/icon";
import { TrackedAnchor } from "@/components/tracked-anchor";
import { GITHUB_URL, SITE_CONFIG } from "@/lib/site-config";

// Mobile site menu: a native <details> that also closes on Escape, outside
// click, and link activation. Plain anchors, because next/link would prefix
// every href with the /docs basePath.
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
        <TrackedAnchor href="/docs" ctaId="docs_root" placement="header" onClick={close}>
          <Icon name="book-open" />
          Docs
        </TrackedAnchor>
        <TrackedAnchor
          href={GITHUB_URL}
          ctaId="github_repository"
          placement="header"
          target="_blank"
          rel="noopener noreferrer"
          onClick={close}
        >
          <Icon name="github-logo" />
          GitHub
        </TrackedAnchor>
        <a href={SITE_CONFIG.discordUrl} target="_blank" rel="noopener noreferrer" onClick={close}>
          <Icon name="discord-logo" />
          Discord
        </a>
      </div>
    </details>
  );
}
