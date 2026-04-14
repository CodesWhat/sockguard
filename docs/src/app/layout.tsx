import { Analytics } from "@vercel/analytics/next";
import { Head } from "nextra/components";
import { getPageMap } from "nextra/page-map";
import { Footer, Layout, Navbar } from "nextra-theme-docs";
import "nextra-theme-docs/style.css";

export const metadata = {
  title: "Sockguard Docs",
  description: "Documentation for sockguard, the Docker socket proxy",
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" dir="ltr" suppressHydrationWarning>
      <Head />
      <body>
        <Layout
          navbar={<Navbar logo={<b>Sockguard</b>} />}
          footer={<Footer>Apache-2.0 {new Date().getFullYear()} © Sockguard</Footer>}
          pageMap={await getPageMap()}
        >
          {children}
        </Layout>
        <Analytics />
      </body>
    </html>
  );
}
