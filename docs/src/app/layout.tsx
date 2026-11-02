import { DocsLayout } from "fumadocs-ui/layouts/docs";
import { RootProvider } from "fumadocs-ui/provider/next";
import type { Metadata, Viewport } from "next";
import localFont from "next/font/local";
import type { CSSProperties } from "react";
import { AnalyticsPageview } from "@/components/analytics-pageview";
import { Footer } from "@/components/footer";
import { MobileDocsBar } from "@/components/mobile-docs-bar";
import { SearchButton } from "@/components/search-button";
import { SidebarBrand } from "@/components/sidebar-brand";
import { SiteHeader } from "@/components/site-header";
import { ThemeToggle } from "@/components/theme-toggle";
import { BASE_PATH, BASE_URL, SITE_CONFIG } from "@/lib/site-config";
import { source } from "@/lib/source";
import "./globals.css";

const spaceGrotesk = localFont({
  src: [
    { path: "../fonts/space-grotesk-latin-500-normal.woff2", weight: "500", style: "normal" },
    { path: "../fonts/space-grotesk-latin-700-normal.woff2", weight: "700", style: "normal" },
  ],
  display: "swap",
  variable: "--font-space-grotesk",
});

const jetbrainsMono = localFont({
  src: [
    { path: "../fonts/jetbrains-mono-latin-400-normal.woff2", weight: "400", style: "normal" },
    { path: "../fonts/jetbrains-mono-latin-500-normal.woff2", weight: "500", style: "normal" },
    { path: "../fonts/jetbrains-mono-latin-600-normal.woff2", weight: "600", style: "normal" },
    { path: "../fonts/jetbrains-mono-latin-700-normal.woff2", weight: "700", style: "normal" },
  ],
  display: "swap",
  variable: "--font-jetbrains-mono",
});

// Bump this whenever the favicon/app icons change so browsers re-fetch them
// instead of serving a stale cached icon (favicons cache aggressively).
const ICON_VERSION = "20260630";

export const metadata: Metadata = {
  title: {
    default: SITE_CONFIG.docsTitleSuffix,
    template: `%s | ${SITE_CONFIG.docsTitleSuffix}`,
  },
  description: SITE_CONFIG.description,
  metadataBase: new URL(BASE_URL),
  openGraph: {
    siteName: SITE_CONFIG.name,
    type: "website",
    locale: SITE_CONFIG.locale,
    images: [{ url: SITE_CONFIG.ogImage, width: 1200, height: 630 }],
  },
  twitter: {
    card: "summary_large_image",
    images: [SITE_CONFIG.ogImage],
  },
  icons: {
    icon: [
      { url: `${BASE_PATH}/favicon.ico?v=${ICON_VERSION}`, sizes: "any" },
      {
        url: `${BASE_PATH}/favicon-96x96.png?v=${ICON_VERSION}`,
        sizes: "96x96",
        type: "image/png",
      },
    ],
    apple: [{ url: `${BASE_PATH}/apple-touch-icon.png?v=${ICON_VERSION}`, sizes: "180x180" }],
  },
  manifest: `${BASE_PATH}/site.webmanifest?v=${ICON_VERSION}`,
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#eae4da" },
    { media: "(prefers-color-scheme: dark)", color: "#2c2927" },
  ],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      data-product="sockguard"
      className={`${spaceGrotesk.variable} ${jetbrainsMono.variable}`}
      suppressHydrationWarning
    >
      <body>
        {/*
          RootProvider owns next-themes. `class` keeps Fumadocs' dark: variant
          working, `data-mode` drives the skin tokens in skin.css, and the default
          storage key matches the marketing site so the preference is shared.
        */}
        <RootProvider
          theme={{ attribute: ["class", "data-mode"] }}
          search={{ options: { type: "static", api: `${BASE_PATH}/api/search` } }}
        >
          <div className="sg">
            <a className="skip" href="#nd-page">
              Skip to content
            </a>
            <SiteHeader />
            <DocsLayout
              tree={source.pageTree}
              nav={{ component: <MobileDocsBar /> }}
              themeSwitch={{ enabled: false }}
              searchToggle={{ enabled: false }}
              sidebar={{
                collapsible: false,
                banner: (
                  <>
                    <SidebarBrand />
                    <div className="sb-s">
                      <SearchButton />
                    </div>
                  </>
                ),
                footer: (
                  <div className="sb-f">
                    <ThemeToggle />
                  </div>
                ),
              }}
              containerProps={{
                style: { "--fd-docs-row-1": "var(--site-header-h)" } as CSSProperties,
              }}
            >
              {children}
            </DocsLayout>
            <Footer />
          </div>
        </RootProvider>
        <AnalyticsPageview />
      </body>
    </html>
  );
}
