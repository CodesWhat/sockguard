import type { Metadata, Viewport } from "next";
import localFont from "next/font/local";
import { AnalyticsPageview } from "@/components/analytics-pageview";
import { ThemeProvider } from "@/components/theme-provider";
import { BASE_URL, SITE_CONFIG } from "@/lib/site-config";
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
    default: SITE_CONFIG.title,
    template: `%s | ${SITE_CONFIG.name}`,
  },
  description: SITE_CONFIG.description,
  metadataBase: new URL(BASE_URL),
  openGraph: {
    title: SITE_CONFIG.title,
    description: SITE_CONFIG.description,
    url: BASE_URL,
    siteName: SITE_CONFIG.name,
    locale: SITE_CONFIG.locale,
    type: "website",
    images: [
      {
        url: SITE_CONFIG.ogImage,
        width: 1200,
        height: 630,
        alt: SITE_CONFIG.title,
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: SITE_CONFIG.title,
    description: SITE_CONFIG.description,
    creator: SITE_CONFIG.twitterCreator,
    images: [SITE_CONFIG.ogImage],
  },
  icons: {
    icon: [
      { url: `/favicon.ico?v=${ICON_VERSION}`, sizes: "any" },
      { url: `/favicon.svg?v=${ICON_VERSION}`, type: "image/svg+xml" },
      { url: `/favicon-96x96.png?v=${ICON_VERSION}`, sizes: "96x96", type: "image/png" },
    ],
    apple: [{ url: `/apple-touch-icon.png?v=${ICON_VERSION}`, sizes: "180x180" }],
  },
  manifest: `/site.webmanifest?v=${ICON_VERSION}`,
  appleWebApp: {
    title: SITE_CONFIG.name,
  },
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#eae4da" },
    { media: "(prefers-color-scheme: dark)", color: "#2c2927" },
  ],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      data-product="sockguard"
      className={`${spaceGrotesk.variable} ${jetbrainsMono.variable}`}
      suppressHydrationWarning
    >
      <body>
        <ThemeProvider>{children}</ThemeProvider>
        <AnalyticsPageview />
      </body>
    </html>
  );
}
