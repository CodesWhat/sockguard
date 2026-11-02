"use client";

import { useId, useMemo, useState } from "react";
import { Icon } from "@/components/icon";
import { DOCS_SEARCH_ITEMS, DOCS_SEARCH_PAGES } from "@/lib/docs-search-index.generated";

type Result = { score: number; title: string; sub: string; href: string };

function search(query: string): Result[] {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return [];
  const joined = terms.join(" ");
  const results: Result[] = [];

  DOCS_SEARCH_ITEMS.forEach(([pageIdx, heading, anchor], i) => {
    const [pageTitle, url] = DOCS_SEARCH_PAGES[pageIdx];
    const title = pageTitle.toLowerCase();
    const head = heading.toLowerCase();
    const hay = heading ? `${head} ${title}` : title;
    if (!terms.every((t) => hay.includes(t))) return;

    let score = 0;
    if (!heading) {
      score += 50;
      if (title === joined) score += 100;
      else if (title.startsWith(joined)) score += 60;
      else if (title.includes(joined)) score += 30;
    } else {
      score += 10;
      if (head === joined) score += 60;
      else if (head.startsWith(joined)) score += 35;
      else if (head.includes(joined)) score += 20;
    }
    results.push({
      score: score - i / 10000,
      title: heading || pageTitle,
      sub: heading ? `Heading in ${pageTitle}` : "Page · Docs",
      href: anchor ? `${url}#${anchor}` : url,
    });
  });

  return results.sort((a, b) => b.score - a.score).slice(0, 8);
}

// Searches the docs page titles and h2-h4 headings. Results are plain links
// into the docs, which are a separate static export, so these are real anchors
// and not client-side navigations.
export function NotFoundSearch() {
  const [query, setQuery] = useState("");
  const id = useId();
  const q = query.trim();
  const results = useMemo(() => search(q), [q]);

  let note = "";
  if (q) {
    note =
      results.length > 0
        ? `${results.length} ${results.length === 1 ? "result" : "results"} in the Sockguard docs`
        : `No docs match "${q}".`;
  }

  return (
    <search className="nf-s" aria-label="Search the Sockguard docs">
      <label className="sr" htmlFor={`${id}-q`}>
        Search the Sockguard docs
      </label>
      <div className="nf-in">
        <Icon name="magnifying-glass" />
        <input
          id={`${id}-q`}
          type="search"
          placeholder="Search the Sockguard docs…"
          autoComplete="off"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>
      <ul className="nf-r" aria-label="Search results">
        {results.map((r) => (
          <li key={r.href}>
            <a href={r.href}>
              <span className="t">{r.title}</span>
              <span className="s">{r.sub}</span>
            </a>
          </li>
        ))}
      </ul>
      <p className="nf-n" aria-live="polite">
        {note}
      </p>
    </search>
  );
}
