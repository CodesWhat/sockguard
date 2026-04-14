import { Analytics } from "@vercel/analytics/next";
import { DocsLayout } from "fumadocs-ui/layouts/docs";
import { RootProvider } from "fumadocs-ui/provider/next";
import type { Metadata, Viewport } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
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
  title: "Sockguard Docs",
  description: "Documentation for sockguard, the inspecting Docker socket proxy.",
  metadataBase: new URL(process.env.NEXT_PUBLIC_SITE_URL || "https://getsockguard.com"),
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
        <RootProvider>
          <DocsLayout
            tree={source.pageTree}
            nav={{
              title: <span className="font-semibold tracking-tight">Sockguard</span>,
              url: "/",
            }}
            links={[
              {
                text: "GitHub",
                url: "https://github.com/CodesWhat/sockguard",
                external: true,
              },
            ]}
          >
            {children}
          </DocsLayout>
        </RootProvider>
        <Analytics />
      </body>
    </html>
  );
}
