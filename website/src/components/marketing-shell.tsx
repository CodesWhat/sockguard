import type { ReactNode } from "react";
import { Footer } from "@/components/footer";
import { SiteHeader } from "@/components/site-header";

// Shared marketing shell: sticky header, main, footer. Used by the home page,
// the compare pages and the not-found page so every marketing page shares the
// same chrome.
export function MarketingShell({ children }: { children: ReactNode }) {
  return (
    <div className="sg">
      <a className="skip" href="#main-content">
        Skip to content
      </a>
      <SiteHeader />
      <main id="main-content">{children}</main>
      <Footer />
    </div>
  );
}
