import { Analytics } from "@vercel/analytics/next";
import { DocsLayout } from "fumadocs-ui/layouts/docs";
import { RootProvider } from "fumadocs-ui/provider/next";
import type { Metadata, Viewport } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import { Footer } from "@/components/footer";
import { SiteBackground } from "@/components/site-background";
import { SiteHeader } from "@/components/site-header";
import { BASE_URL, SITE_CONFIG } from "@/lib/site-config";
import { source } from "@/lib/source";
import "./globals.css";

const ibmPlexSans = IBM_Plex_Sans({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
});

const ibmPlexMono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  variable: "--font-mono",
});

export const metadata: Metadata = {
  title: {
    default: `${SITE_CONFIG.name} Docs`,
    template: `%s | ${SITE_CONFIG.name} Docs`,
  },
  description: SITE_CONFIG.description,
  metadataBase: new URL(BASE_URL),
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
    { media: "(prefers-color-scheme: dark)", color: "#0a0a0a" },
  ],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${ibmPlexSans.className} ${ibmPlexMono.variable}`}>
        {/*
          fumadocs RootProvider includes next-themes (attribute="class") internally.
          ThemeToggle uses useTheme from the same next-themes instance — no double
          provider needed.

          data-bg drives the aurora CSS variable palette (--au-* vars in globals.css).
        */}
        <RootProvider>
          <div data-bg={SITE_CONFIG.aurora} className="relative flex min-h-screen flex-col">
            <SiteBackground />
            <SiteHeader />
            <main className="flex-1">
              <DocsLayout
                tree={source.pageTree}
                nav={{ enabled: false }}
                themeSwitch={{ enabled: false }}
                searchToggle={{ enabled: false }}
              >
                {children}
              </DocsLayout>
            </main>
            <Footer />
          </div>
        </RootProvider>
        <Analytics />
      </body>
    </html>
  );
}
