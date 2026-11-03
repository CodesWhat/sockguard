"use client";

import { useSearchContext } from "fumadocs-ui/contexts/search";
import { useSyncExternalStore } from "react";
import { Icon } from "@/components/icon";

const subscribe = () => () => {};
const isMacClient = () => /Mac|iPhone|iPad|iPod/.test(navigator.platform || navigator.userAgent);

// Opens the Fumadocs search dialog from the sidebar, or as an icon in the
// phone docs bar. Cmd/Ctrl+K is the RootProvider default
// hotkey, so the button and the shortcut drive the same dialog.
export function SearchButton() {
  const { enabled, setOpenSearch } = useSearchContext();
  // Server render and first hydration pass use "Ctrl K"; Macs swap to the
  // command glyph once on the client.
  const isMac = useSyncExternalStore(subscribe, isMacClient, () => false);
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
      <kbd className="sk">{isMac ? "\u2318K" : "Ctrl K"}</kbd>
    </button>
  );
}
