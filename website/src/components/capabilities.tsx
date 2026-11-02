"use client";

import { type KeyboardEvent, useMemo, useRef, useState } from "react";
import type { FeatureCategory } from "@/app/data/features";
import { features } from "@/app/data/features";
import { Icon } from "@/components/icon";
import { InlineCode } from "@/components/inline-code";

const TONE: Record<FeatureCategory, string> = {
  security: "t-danger",
  control: "t-info",
  operations: "t-warning",
};

const searchText = (f: (typeof features)[number]) =>
  `${f.title} ${f.description.replaceAll("`", "")} ${f.category}`.toLowerCase();

// "What we enforce": a command-palette style list with a live filter. The full
// list is server-rendered, so it reads fine without JS.
export function Capabilities() {
  const [query, setQuery] = useState("");
  const [sel, setSel] = useState(-1);
  const listRef = useRef<HTMLUListElement>(null);

  const rows = useMemo(() => features.map((f, i) => ({ f, n: i + 1, text: searchText(f) })), []);
  const q = query.trim().toLowerCase();
  const visible = rows.filter((r) => !q || r.text.includes(q));

  const move = (next: number) => {
    setSel(next);
    const el = listRef.current?.querySelectorAll("li.it:not([hidden])")[next];
    el?.scrollIntoView({ block: "nearest" });
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      move(Math.min(visible.length - 1, sel + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      move(Math.max(0, sel - 1));
    } else if (e.key === "Escape") {
      setQuery("");
      setSel(-1);
      e.currentTarget.blur();
    }
  };

  const visibleIds = new Set(visible.map((r) => r.n));

  return (
    <search className="pal">
      <div className="pal-in">
        <Icon name="magnifying-glass" />
        <input
          type="search"
          placeholder="Search capabilities…"
          aria-label="Search capabilities"
          autoComplete="off"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setSel(-1);
          }}
          onKeyDown={onKeyDown}
        />
      </div>
      <div className="pal-t">
        <Icon name="terminal-window" />
        <b>sockguard capabilities</b>
        <span>{features.length} modules</span>
      </div>
      <ul aria-label="Capabilities" ref={listRef}>
        {rows.map(({ f, n }) => {
          const shown = visibleIds.has(n);
          const idx = visible.findIndex((r) => r.n === n);
          return (
            <li
              key={f.title}
              className={`it ${TONE[f.category]}${idx === sel && shown ? " sel" : ""}`}
              hidden={!shown}
            >
              <span className="tn">
                <Icon name={f.icon} />
              </span>
              <span>
                <span className="hd2">
                  <b>
                    <span className="num">{String(n).padStart(2, "0")}</span>
                    {f.title}
                  </b>
                  <span className={`chip ${TONE[f.category]}`}>{f.category}</span>
                </span>
                <span className="d">
                  <InlineCode text={f.description} />
                </span>
              </span>
            </li>
          );
        })}
      </ul>
      {visible.length === 0 ? (
        <div className="empty">No capabilities match &quot;{query}&quot;</div>
      ) : null}
      <div className="pal-f">
        <span aria-live="polite">
          {visible.length} of {features.length} capabilities
        </span>
        <span aria-hidden="true">
          <kbd>↑↓</kbd> navigate &nbsp; <kbd>esc</kbd> close
        </span>
      </div>
    </search>
  );
}
