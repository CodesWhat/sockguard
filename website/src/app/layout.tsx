import type { Metadata, Viewport } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
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
  title: "Sockguard - Docker Socket Proxy",
  description:
    "Guide what gets through. A Docker socket proxy that filters by method, path, and request body. Default-deny posture with structured audit logging.",
  metadataBase: new URL("https://getsockguard.com"),
  openGraph: {
    title: "Sockguard - Docker Socket Proxy",
    description:
      "Guide what gets through. A Docker socket proxy that filters by method, path, and request body. Default-deny posture with structured audit logging.",
    url: "https://getsockguard.com",
    siteName: "Sockguard",
    locale: "en_US",
    type: "website",
  },
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
    { media: "(prefers-color-scheme: dark)", color: "#0a0a0a" },
  ],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${ibmPlexSans.className} ${ibmPlexMono.variable}`}>{children}</body>
    </html>
  );
}
