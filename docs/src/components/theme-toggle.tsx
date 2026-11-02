"use client";

import { useTheme } from "next-themes";
import { Icon } from "@/components/icon";

// Server and client render identical markup: which icon and label show is
// decided by CSS from <html data-mode>, which next-themes sets before first
// paint. Same next-themes storage key as the marketing site, so the choice
// carries between getsockguard.com and /docs.
export function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme();

  return (
    <button
      type="button"
      className="modetog"
      aria-label="Switch between dark and light mode"
      onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
    >
      <Icon name="moon" className="i-moon" />
      <Icon name="sun" className="i-sun" />
      <span className="ml">
        <span className="ml-dark">Dark</span>
        <span className="ml-light">Light</span>
      </span>
    </button>
  );
}
