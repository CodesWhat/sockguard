import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Sockguard Rule Tester",
  description: "Interactive Docker API request filter rule tester for sockguard.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
