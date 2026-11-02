import type { ComparisonTool } from "@/app/data/comparison-rows";
import { COMPETITOR_VERSIONS, COMPETITOR_VERSIONS_CHECKED_AT } from "@/app/data/comparison-rows";
import { ComparisonCellIcon } from "@/components/comparison-cell-icon";
import { Icon, type IconName } from "@/components/icon";
import { MarketingShell } from "@/components/marketing-shell";
import { TrackedLink } from "@/components/tracked-link";
import { GITHUB_URL, SITE_CONFIG } from "@/lib/site-config";

export type ComparisonRow = {
  feature: string;
  competitor: string;
  self: string;
  verdict: "self" | "competitor" | "tie";
};

export type Highlight = {
  icon: IconName;
  title: string;
  description: string;
};

type Props = {
  competitorName: string;
  competitorTool: Exclude<ComparisonTool, "sockguard">;
  heroTitle: string;
  heroDescription: React.ReactNode;
  comparisonData: ComparisonRow[];
  highlights: Highlight[];
  migrationTitle: string;
  migrationDescription: string;
  jsonLd: Record<string, unknown>;
};

const isNo = (value: string) => value === "No" || value === "None";

type Tone = "good" | "gap" | "tie";

function CompetitorCell({ row, name }: { row: ComparisonRow; name: string }) {
  if (isNo(row.competitor)) {
    return (
      <span className="v">
        <ComparisonCellIcon value="no" />
        <span className="sr">{name} does not offer this</span>
      </span>
    );
  }
  const tone: Tone = row.verdict === "competitor" ? "good" : row.verdict === "self" ? "gap" : "tie";
  return <VerdictCell tone={tone} text={row.competitor} />;
}

function SelfCell({ row }: { row: ComparisonRow }) {
  const tone: Tone = row.verdict === "self" ? "good" : row.verdict === "competitor" ? "gap" : "tie";
  return <VerdictCell tone={tone} text={row.self} />;
}

const TONE_LABEL: Record<Tone, string> = {
  good: "Stronger: ",
  gap: "Weaker: ",
  tie: "On par: ",
};

const TONE_ICON: Record<Tone, IconName> = {
  good: "check",
  gap: "warning",
  tie: "minus",
};

function VerdictCell({ tone, text }: { tone: Tone; text: string }) {
  return (
    <span className={`v ${tone}`}>
      <Icon name={TONE_ICON[tone]} />
      <span className="sr">{TONE_LABEL[tone]}</span>
      <span>{text}</span>
    </span>
  );
}

export function ComparisonPage({
  competitorName,
  competitorTool,
  heroTitle,
  heroDescription,
  comparisonData,
  highlights,
  migrationTitle,
  migrationDescription,
  jsonLd,
}: Props) {
  const regionLabel = `${competitorName} vs ${SITE_CONFIG.name} feature table. Scroll sideways if it does not fit.`;
  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
      <MarketingShell>
        <section className="cmp-hero cs" aria-labelledby="cmp-h1">
          <div className="wrap">
            <h1 className="cp long" id="cmp-h1">
              {heroTitle}
            </h1>
            <div className="cp-sub">{heroDescription}</div>
            <div className="badges2">
              <span className="chip t-info nocase">
                <Icon name="check" />
                {competitorName}: Active
              </span>
              <span className="chip t-primary nocase">
                <Icon name="check" />
                {SITE_CONFIG.name}: Active
              </span>
            </div>
          </div>
        </section>

        <section className="cs" aria-labelledby="cmp-ft">
          <div className="wrap">
            <div className="sec-h">
              <h2 className="title" id="cmp-ft">
                Feature Comparison
              </h2>
              <p className="sub">Here&apos;s how we compare on the features that matter most.</p>
            </div>
            <div className="mx">
              {/* biome-ignore lint/a11y/noNoninteractiveTabindex: a horizontally scrollable region must be keyboard reachable */}
              <section className="scroll" tabIndex={0} aria-label={regionLabel}>
                <table className="cmp vs mxt">
                  <caption className="sr">
                    {competitorName} vs {SITE_CONFIG.name}: {comparisonData.length} features
                  </caption>
                  <thead>
                    <tr>
                      <th scope="col">Feature</th>
                      <th scope="col">{competitorName}</th>
                      <th scope="col" className="me">
                        {SITE_CONFIG.name}
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {comparisonData.map((row) => (
                      <tr key={row.feature}>
                        <th scope="row">{row.feature}</th>
                        <td>
                          <CompetitorCell row={row} name={competitorName} />
                        </td>
                        <td className="me">
                          <SelfCell row={row} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </section>
            </div>
            <p className="src">
              Claims on this page were checked {COMPETITOR_VERSIONS_CHECKED_AT} against{" "}
              {competitorName} {COMPETITOR_VERSIONS[competitorTool]}. Re-checked at every release
              cut.
            </p>
          </div>
        </section>

        <section className="cs" aria-labelledby="cmp-d">
          <div className="wrap">
            <div className="sec-h">
              <h2 className="title" id="cmp-d">
                Key Differentiators
              </h2>
              <p className="sub">What we built that {competitorName} doesn&apos;t cover.</p>
            </div>
            <ul className="cards3">
              {highlights.map((item) => (
                <li key={item.title} className="hc">
                  <div className="hh">
                    <span className="tn">
                      <Icon name={item.icon} />
                    </span>
                    <h3>{item.title}</h3>
                  </div>
                  <p>{item.description}</p>
                </li>
              ))}
            </ul>
          </div>
        </section>

        <section className="cs" aria-labelledby="cmp-m">
          <div className="wrap">
            <div className="mig">
              <span className="tn">
                <Icon name="clock-counter-clockwise" />
              </span>
              <div className="migc">
                <h2 id="cmp-m">{migrationTitle}</h2>
                <p>{migrationDescription}</p>
                <div className="code">
                  <div className="lab">
                    <Icon name="terminal-window" />
                    Quick start
                  </div>
                  <pre>
                    <code>
                      <span className="y-c">$</span> <span className="y-v">docker run</span> -d \
                      {"\n"}
                      {"  "}--name sockguard \{"\n"}
                      {"  "}-v /var/run/docker.sock:/var/run/docker.sock:ro \{"\n"}
                      {"  "}-v /var/run/sockguard:/var/run/sockguard \{"\n"}
                      {"  "}-e SOCKGUARD_LISTEN_SOCKET=/var/run/sockguard/sockguard.sock \{"\n"}
                      {"  "}
                      <span className="y-v">{SITE_CONFIG.dockerImage}</span>
                    </code>
                  </pre>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="cs last" aria-labelledby="cmp-cta">
          <div className="wrap">
            <div className="cta2">
              <h2 id="cmp-cta">{`Ready to try ${SITE_CONFIG.name}?`}</h2>
              <p>
                Default-deny, MIT, no SaaS required. Drop it in front of your socket in minutes.
              </p>
              <div className="ctas">
                <TrackedLink
                  className="btn primary"
                  href={GITHUB_URL}
                  ctaId="github_repository"
                  placement="comparison"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <Icon name="github-logo" />
                  View on GitHub
                </TrackedLink>
                <TrackedLink className="btn" href="/docs" ctaId="docs_root" placement="comparison">
                  <Icon name="book-open" />
                  Documentation
                </TrackedLink>
              </div>
            </div>
          </div>
        </section>
      </MarketingShell>
    </>
  );
}
