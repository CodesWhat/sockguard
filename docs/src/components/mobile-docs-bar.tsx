"use client";

import { useTreePath } from "fumadocs-ui/contexts/tree";
import { useDocsLayout } from "fumadocs-ui/layouts/docs";
import { ChevronDown } from "lucide-react";

// Phone-width docs nav: one row under the site header that opens Fumadocs'
// own sidebar drawer. Hidden from md up, where the sidebar is always shown.
export function MobileDocsBar() {
  const { slots } = useDocsLayout();
  const Trigger = slots.sidebar.trigger;
  const path = useTreePath();
  const current = path.at(-1);
  const label = typeof current?.name === "string" ? current.name : "Docs";

  return (
    <header id="nd-subnav" className="docs-bar">
      <Trigger className="docs-bar-btn">
        <span className="docs-bar-lb">Docs</span>
        <span className="docs-bar-cur">{label}</span>
        <ChevronDown className="docs-bar-cv" aria-hidden="true" />
      </Trigger>
    </header>
  );
}
