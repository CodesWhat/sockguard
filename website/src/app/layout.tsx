import { Analytics } from "@vercel/analytics/next";
import type { Metadata, Viewport } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import { ThemeProvider } from "@/components/theme-provider";
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
    "Control what gets through. A Docker socket proxy that filters by method, path, and request body. Default-deny posture with structured access logging.",
  metadataBase: new URL("https://getsockguard.com"),
  openGraph: {
    title: "Sockguard - Docker Socket Proxy",
    description:
      "Control what gets through. A Docker socket proxy that filters by method, path, and request body. Default-deny posture with structured access logging.",
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
      <head>
        <link rel="icon" type="image/png" href="/favicon-96x96.png?v=20260408" sizes="96x96" />
        <link rel="icon" type="image/svg+xml" href="/favicon.svg?v=20260408" />
        <link rel="shortcut icon" href="/favicon.ico?v=20260408" />
        <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png?v=20260408" />
        <meta name="apple-mobile-web-app-title" content="sockguard" />
        <link rel="manifest" href="/site.webmanifest?v=20260408" />
      </head>
      <body className={`${ibmPlexSans.className} ${ibmPlexMono.variable}`}>
        <ThemeProvider>{children}</ThemeProvider>
        <Analytics />
      </body>
    </html>
  );
}
