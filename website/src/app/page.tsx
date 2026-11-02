import type { Metadata } from "next";
import { Capabilities } from "@/components/capabilities";
import { CompareTeaser } from "@/components/compare-section";
import { Ecosystem } from "@/components/ecosystem";
import { FAQ } from "@/components/faq";
import { GetStarted } from "@/components/get-started";
import { Hero } from "@/components/hero";
import { MarketingShell } from "@/components/marketing-shell";
import { RecordedTerminal } from "@/components/recorded-terminal";
import { RoadmapLog, roadmapHasPlanned } from "@/components/roadmap";
import { Section } from "@/components/section";
import { StarHistory } from "@/components/star-history";
import { BASE_URL, GITHUB_RELEASES_URL, GITHUB_URL, SITE_CONFIG } from "@/lib/site-config";
import { faqItems } from "./data/faq";

export const metadata: Metadata = {
  alternates: {
    canonical: BASE_URL,
  },
};

export default function Home() {
  const softwareAppJsonLd = {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    name: SITE_CONFIG.name,
    url: BASE_URL,
    description:
      "A default-deny Docker socket proxy built in Go. Filter Docker API requests by method, path, and body with signed policy bundles and per-profile rollout modes.",
    applicationCategory: "DeveloperApplication",
    operatingSystem: "Docker",
    license: SITE_CONFIG.licenseUrl,
    downloadUrl: GITHUB_RELEASES_URL,
    installUrl: GITHUB_RELEASES_URL,
    offers: {
      "@type": "Offer",
      price: "0",
      priceCurrency: "USD",
    },
    sameAs: [GITHUB_URL, SITE_CONFIG.twitterUrl],
    author: {
      "@type": "Organization",
      name: "CodesWhat",
      url: "https://codeswhat.com",
      sameAs: ["https://github.com/CodesWhat"],
    },
    softwareHelp: {
      "@type": "WebPage",
      url: `${BASE_URL}/docs`,
    },
  };

  const websiteJsonLd = {
    "@context": "https://schema.org",
    "@type": "WebSite",
    name: SITE_CONFIG.name,
    url: BASE_URL,
    publisher: {
      "@type": "Organization",
      name: "CodesWhat",
    },
  };

  const faqPageJsonLd = {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    mainEntity: faqItems.map((item) => ({
      "@type": "Question",
      name: item.question,
      acceptedAnswer: {
        "@type": "Answer",
        text: item.answer,
      },
    })),
  };

  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(softwareAppJsonLd) }}
      />
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(websiteJsonLd) }}
      />
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(faqPageJsonLd) }}
      />
      <MarketingShell>
        <Hero />

        <Section
          id="features"
          eyebrow="Batteries included"
          title="What we enforce"
          sub="We ship a lean Go binary with a stdlib request hot path and zero daemon dependencies. Default-deny, ready to drop in front of your socket."
        >
          <Capabilities />
        </Section>

        <Section
          id="get-started"
          variant="b"
          eyebrow="Get running"
          title="Get started in minutes"
          sub="Add sockguard to your compose file and point your app at its scoped socket."
        >
          <GetStarted />
        </Section>

        <Section
          id="demo"
          strikeEyebrow
          eyebrow="In the real CLI"
          title="See it in action!"
          sub="Recorded from the real CLI: watch the proxy stream audit logs, harvest a policy, dry-run requests through the rules, and flip to enforce."
        >
          <RecordedTerminal />
        </Section>

        <Section
          id="roadmap"
          eyebrow={roadmapHasPlanned ? "On the horizon" : "Release history"}
          title="Roadmap"
          sub={
            roadmapHasPlanned
              ? "Where we've been and where we're headed."
              : "The committed roadmap through v1.5 is complete."
          }
        >
          <RoadmapLog />
        </Section>

        <Section
          id="star-history"
          variant="b"
          eyebrow="Community"
          title="Star History"
          sub="Growing every week. Join us on GitHub."
        >
          <StarHistory />
        </Section>

        <Section
          id="compare"
          variant="c"
          stack
          eyebrow={`Why ${SITE_CONFIG.name}`}
          title="How we compare"
          sub="A quick look at what we support that Tecnativa, CetusGuard, and wollomatic don't."
        >
          <CompareTeaser />
        </Section>

        <Section
          id="ecosystem"
          variant="b"
          stack
          eyebrow="Ecosystem"
          title="Part of the CodesWhat stack"
          sub="Sockguard is one piece of a small, focused toolkit. Each tool does one job, and they compose."
        >
          <Ecosystem />
        </Section>

        <Section
          id="faq"
          eyebrow="FAQ"
          title="Frequently asked questions"
          sub="Common questions about how Sockguard works and how we compare."
        >
          <FAQ />
        </Section>
      </MarketingShell>
    </>
  );
}
