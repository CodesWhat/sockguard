"use client";

import { useSearchContext } from "fumadocs-ui/contexts/search";
import { Icon } from "@/components/icon";

// Opens the Fumadocs search dialog. Cmd/Ctrl+K is the RootProvider default
// hotkey, so the button and the shortcut drive the same dialog.
export function SearchButton() {
  const { enabled, setOpenSearch } = useSearchContext();
  if (!enabled) return null;

  return (
    <button
      type="button"
      className="sbtn"
      aria-label="Search docs"
      onClick={() => setOpenSearch(true)}
    >
      <Icon name="magnifying-glass" />
      <span className="st">Search docs...</span>
      <kbd className="sk">Ctrl K</kbd>
    </button>
  );
}
