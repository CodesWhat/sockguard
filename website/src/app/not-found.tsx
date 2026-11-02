import type { Metadata } from "next";
import Image from "next/image";
import Link from "next/link";
import { Icon } from "@/components/icon";
import { MarketingShell } from "@/components/marketing-shell";
import { NotFoundSearch } from "@/components/not-found-search";

export const metadata: Metadata = {
  title: "Page not found",
  robots: { index: false, follow: true },
};

export default function NotFound() {
  return (
    <MarketingShell>
      <div className="nf-wrap">
        <section className="nf" aria-labelledby="nf-h">
          <Image
            className="nf-m"
            src="/img/dog-256.webp"
            alt="Sockguard mascot, an orange toy dog"
            width={128}
            height={128}
            unoptimized
          />
          <p className="nf-c micro">Error 404 · Sockguard</p>
          <h1 id="nf-h">404</h1>
          <p className="nf-p">
            No page lives at this path. Sockguard denies by default, and this site has nothing to
            let through here.
          </p>
          <NotFoundSearch />
          <div className="nf-l">
            <Link className="btn primary" href="/">
              <Icon name="arrow-right" />
              Back to Sockguard
            </Link>
            <a className="btn" href="/docs">
              <Icon name="book-open" />
              Docs
            </a>
            <Link className="btn" href="/compare">
              <Icon name="arrows-clockwise" />
              Compare
            </Link>
          </div>
        </section>
      </div>
    </MarketingShell>
  );
}
