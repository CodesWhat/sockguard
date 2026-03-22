import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Sockguard — Docker Socket Proxy",
  description: "Guide what gets through. A Docker socket proxy with body inspection, per-client policies, and structured audit logging.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
